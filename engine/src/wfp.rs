use serde::Serialize;
use std::path::Path;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WfpCapability {
    pub backend: String,
    pub library_available: bool,
    pub library_loaded: bool,
    pub driver_available: bool,
    pub administrator_required: bool,
    pub message: String,
}

#[cfg(windows)]
pub fn inspect_backend(library_path: &Path, driver_path: &Path) -> WfpCapability {
    let library_available = library_path.is_file();
    let driver_available = driver_path.is_file();
    if !library_available || !driver_available {
        return WfpCapability {
            backend: "windivert-2.2.2".into(),
            library_available,
            library_loaded: false,
            driver_available,
            administrator_required: true,
            message: "WinDivert runtime files are incomplete".into(),
        };
    }

    // SAFETY: the project loads the official WinDivert DLL by absolute path.
    // Its companion driver signature and package provenance are recorded under vendor/windivert.
    let loaded = unsafe {
        libloading::Library::new(library_path).and_then(|library| {
            library.get::<*const ()>(b"WinDivertOpen\0")?;
            library.get::<*const ()>(b"WinDivertRecv\0")?;
            library.get::<*const ()>(b"WinDivertSend\0")?;
            Ok(())
        })
    };
    WfpCapability {
        backend: "windivert-2.2.2".into(),
        library_available,
        library_loaded: loaded.is_ok(),
        driver_available,
        administrator_required: true,
        message: loaded.map_or_else(
            |error| format!("WinDivert could not be loaded: {error}"),
            |_| "Signed WFP capture runtime is ready".into(),
        ),
    }
}

#[cfg(not(windows))]
pub fn inspect_backend(library_path: &Path, driver_path: &Path) -> WfpCapability {
    WfpCapability {
        backend: "windivert-2.2.2".into(),
        library_available: library_path.is_file(),
        library_loaded: false,
        driver_available: driver_path.is_file(),
        administrator_required: true,
        message: "WFP capture is supported only on Windows".into(),
    }
}
