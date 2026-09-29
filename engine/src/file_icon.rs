//! The icon of an executable, for the UI to show beside the traffic it routes.
//!
//! Electron's `app.getFileIcon` answers some executables that do have an icon
//! with the stock one (BsgLauncher.exe, for one), which is indistinguishable
//! from having none. Reading the icon resource directly has neither problem:
//! `ExtractIconExW` returns zero for a file with no icon group.

use base64::Engine as _;
use serde_json::{Value, json};
use std::mem::{size_of, zeroed};
use std::ptr::null_mut;
use windows_sys::Win32::Graphics::Gdi::{
    BI_RGB, BITMAP, BITMAPINFO, BITMAPINFOHEADER, CreateCompatibleDC, DIB_RGB_COLORS, DeleteDC,
    DeleteObject, GetDIBits, GetObjectW, HBITMAP, HDC,
};
use windows_sys::Win32::UI::Shell::ExtractIconExW;
use windows_sys::Win32::UI::WindowsAndMessaging::{DestroyIcon, GetIconInfo, HICON, ICONINFO};

/// Larger than any icon a resource holds; guards the pixel buffer size.
const MAX_ICON_EDGE: i32 = 256;

pub fn file_icon(payload: Value) -> Result<Value, String> {
    let path = payload["path"].as_str().ok_or("file-icon needs a path")?;
    Ok(match executable_icon(path) {
        Some(icon) => json!({
            "width": icon.width,
            "height": icon.height,
            "bgra": base64::engine::general_purpose::STANDARD.encode(icon.pixels),
        }),
        None => Value::Null,
    })
}

/// Top-down, premultiplied BGRA: the layout Electron's
/// `nativeImage.createFromBitmap` expects.
struct IconPixels {
    width: i32,
    height: i32,
    pixels: Vec<u8>,
}

/// The first icon group, which is the one Explorer shows for an executable.
fn executable_icon(path: &str) -> Option<IconPixels> {
    let wide = path.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
    let mut icon: HICON = 0;
    // Zero means the file has no icon; `u32::MAX` means it could not be read.
    let extracted = unsafe { ExtractIconExW(wide.as_ptr(), 0, &mut icon, null_mut(), 1) };
    if extracted == 0 || extracted == u32::MAX || icon == 0 {
        return None;
    }
    let pixels = icon_pixels(icon);
    unsafe { DestroyIcon(icon) };
    pixels
}

fn icon_pixels(icon: HICON) -> Option<IconPixels> {
    let mut info: ICONINFO = unsafe { zeroed() };
    if unsafe { GetIconInfo(icon, &mut info) } == 0 {
        return None;
    }
    // A monochrome icon has no colour bitmap; the placeholder reads better.
    let pixels = (info.hbmColor != 0)
        .then(|| color_icon_pixels(&info))
        .flatten();
    // GetIconInfo hands the caller its own copies of both bitmaps.
    for bitmap in [info.hbmColor, info.hbmMask] {
        if bitmap != 0 {
            unsafe { DeleteObject(bitmap) };
        }
    }
    pixels
}

fn color_icon_pixels(info: &ICONINFO) -> Option<IconPixels> {
    let mut bitmap: BITMAP = unsafe { zeroed() };
    let size = size_of::<BITMAP>() as i32;
    if unsafe { GetObjectW(info.hbmColor, size, (&raw mut bitmap).cast()) } == 0 {
        return None;
    }
    let (width, height) = (bitmap.bmWidth, bitmap.bmHeight);
    if !(1..=MAX_ICON_EDGE).contains(&width) || !(1..=MAX_ICON_EDGE).contains(&height) {
        return None;
    }
    let dc = unsafe { CreateCompatibleDC(0) };
    if dc == 0 {
        return None;
    }
    let mut pixels = read_bgra(dc, info.hbmColor, width, height);
    // An icon without an alpha channel keeps its transparency in the AND
    // mask instead, where a set bit is a transparent pixel.
    if let Some(pixels) = pixels
        .as_mut()
        .filter(|pixels| pixels.chunks_exact(4).all(|px| px[3] == 0))
    {
        let mask = read_bgra(dc, info.hbmMask, width, height);
        for (index, px) in pixels.chunks_exact_mut(4).enumerate() {
            let transparent = mask.as_ref().is_some_and(|mask| mask[index * 4] != 0);
            px[3] = if transparent { 0 } else { 255 };
        }
    }
    unsafe { DeleteDC(dc) };
    let mut pixels = pixels?;
    for px in pixels.chunks_exact_mut(4) {
        let alpha = u32::from(px[3]);
        for channel in &mut px[..3] {
            *channel = ((u32::from(*channel) * alpha + 127) / 255) as u8;
        }
    }
    Some(IconPixels {
        width,
        height,
        pixels,
    })
}

fn read_bgra(dc: HDC, bitmap: HBITMAP, width: i32, height: i32) -> Option<Vec<u8>> {
    let mut info: BITMAPINFO = unsafe { zeroed() };
    info.bmiHeader = BITMAPINFOHEADER {
        biSize: size_of::<BITMAPINFOHEADER>() as u32,
        biWidth: width,
        // Negative asks for top-down rows.
        biHeight: -height,
        biPlanes: 1,
        biBitCount: 32,
        biCompression: BI_RGB,
        ..unsafe { zeroed() }
    };
    let mut pixels = vec![0_u8; (width * height * 4) as usize];
    let lines = unsafe {
        GetDIBits(
            dc,
            bitmap,
            0,
            height as u32,
            pixels.as_mut_ptr().cast(),
            &mut info,
            DIB_RGB_COLORS,
        )
    };
    (lines == height).then_some(pixels)
}
