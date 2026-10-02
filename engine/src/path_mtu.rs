//! The largest packet that reaches a tunnel endpoint unfragmented.
//!
//! The interface MTU only describes the first hop. A PPPoE or mobile uplink
//! behind the router commonly carries 1492 bytes or less while Windows still
//! reports 1500, and every full-size tunnel packet then fragments on the way
//! out, or vanishes where fragments are filtered. This measures the path the
//! way Windscribe's `PacketSizeController` does: echo requests that may not be
//! fragmented, narrowed until one gets through.

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

/// Nothing below this is worth knowing: the tunnel never goes under it.
const FLOOR: u16 = crate::mtu::MIN_TUNNEL_MTU;
/// Close enough: a few bytes of headroom cost nothing measurable.
const PRECISION: u16 = 8;
/// IPv4 and ICMP headers around the echoed payload.
const ECHO_HEADERS: u16 = 28;
const FIRST_ECHO_TIMEOUT: Duration = Duration::from_millis(800);
const MIN_ECHO_TIMEOUT: Duration = Duration::from_millis(150);

/// The path MTU to `destination`, at most `link_mtu`, or `None` when it could
/// not be established inside `budget` (an endpoint that ignores echo requests
/// is the common case).
pub fn measure(destination: Ipv4Addr, link_mtu: u16, budget: Duration) -> Option<u16> {
    let deadline = Instant::now() + budget;
    let mut timeout = FIRST_ECHO_TIMEOUT;
    search(link_mtu, |size| {
        let remaining = deadline.checked_duration_since(Instant::now())?;
        let answered = echo(destination, size, timeout.min(remaining))?;
        if let Some(round_trip) = answered {
            timeout = (round_trip * 3).clamp(MIN_ECHO_TIMEOUT, FIRST_ECHO_TIMEOUT);
        }
        Some(answered.is_some())
    })
}

/// `fits(size)` says whether a `size`-byte packet got through, or `None` to
/// give up. Full size is tried first because it is almost always the answer.
fn search(link_mtu: u16, mut fits: impl FnMut(u16) -> Option<bool>) -> Option<u16> {
    if link_mtu <= FLOOR || fits(link_mtu)? {
        return Some(link_mtu);
    }
    // Nothing at the floor either means echo is filtered, not that the path
    // carries nothing: the answer is unknown, not small.
    if !fits(FLOOR)? {
        return None;
    }
    let (mut fitting, mut too_big) = (FLOOR, link_mtu);
    while too_big - fitting > PRECISION {
        let middle = fitting + (too_big - fitting) / 2;
        if fits(middle)? {
            fitting = middle;
        } else {
            too_big = middle;
        }
    }
    Some(fitting)
}

/// One echo of a `size`-byte packet with Don't Fragment set: `Some(Some(rtt))`
/// when it came back whole, `Some(None)` when it did not.
#[cfg(windows)]
fn echo(destination: Ipv4Addr, size: u16, timeout: Duration) -> Option<Option<Duration>> {
    use std::ffi::c_void;

    /// `IP_OPTION_INFORMATION`.
    #[repr(C)]
    struct Options {
        ttl: u8,
        tos: u8,
        flags: u8,
        options_size: u8,
        options_data: *mut u8,
    }
    const IP_FLAG_DF: u8 = 0x2;

    #[link(name = "iphlpapi")]
    unsafe extern "system" {
        fn IcmpCreateFile() -> isize;
        fn IcmpCloseHandle(handle: isize) -> i32;
        fn IcmpSendEcho(
            handle: isize,
            destination: u32,
            request: *const c_void,
            request_size: u16,
            options: *const c_void,
            reply: *mut c_void,
            reply_size: u32,
            timeout: u32,
        ) -> u32;
    }

    let payload = usize::from(size.checked_sub(ECHO_HEADERS)?);
    let request = vec![0x61_u8; payload];
    // ICMP_ECHO_REPLY, the echoed data, room for an ICMP error and the
    // IO_STATUS_BLOCK, as IcmpSendEcho's documentation asks.
    let mut reply = vec![0_u8; payload + 128];
    let options = Options {
        ttl: 128,
        tos: 0,
        flags: IP_FLAG_DF,
        options_size: 0,
        options_data: std::ptr::null_mut(),
    };
    let timeout_ms = u32::try_from(timeout.as_millis())
        .unwrap_or(u32::MAX)
        .max(1);
    let replies = unsafe {
        let handle = IcmpCreateFile();
        if handle == -1 {
            return None;
        }
        let replies = IcmpSendEcho(
            handle,
            u32::from_le_bytes(destination.octets()),
            request.as_ptr().cast(),
            payload as u16,
            (&options as *const Options).cast(),
            reply.as_mut_ptr().cast(),
            reply.len() as u32,
            timeout_ms,
        );
        IcmpCloseHandle(handle);
        replies
    };
    // ICMP_ECHO_REPLY: Address, Status, RoundTripTime, DataSize.
    let status = u32::from_ne_bytes(reply[4..8].try_into().unwrap());
    let round_trip = u32::from_ne_bytes(reply[8..12].try_into().unwrap());
    let echoed = u16::from_ne_bytes(reply[12..14].try_into().unwrap());
    Some(
        (replies > 0 && status == 0 && usize::from(echoed) == payload)
            .then(|| Duration::from_millis(u64::from(round_trip))),
    )
}

#[cfg(not(windows))]
fn echo(_destination: Ipv4Addr, _size: u16, _timeout: Duration) -> Option<Option<Duration>> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(real: u16) -> impl FnMut(u16) -> Option<bool> {
        move |size| Some(size <= real)
    }

    #[test]
    fn a_clean_path_costs_one_echo() {
        let mut echoes = 0;
        let result = search(1500, |size| {
            echoes += 1;
            Some(size <= 1500)
        });
        assert_eq!((result, echoes), (Some(1500), 1));
    }

    #[test]
    fn a_pppoe_uplink_behind_the_router_is_found() {
        let found = search(1500, path(1492)).unwrap();
        assert!((1492 - PRECISION..=1492).contains(&found), "{found}");
    }

    #[test]
    fn a_narrow_mobile_path_is_found_within_a_few_echoes() {
        let mut echoes = 0;
        let mut real = path(1380);
        let found = search(1500, |size| {
            echoes += 1;
            real(size)
        })
        .unwrap();
        assert!((1380 - PRECISION..=1380).contains(&found), "{found}");
        assert!(echoes <= 7, "{echoes} echoes");
    }

    #[test]
    fn an_endpoint_that_ignores_echoes_is_unknown_not_small() {
        assert_eq!(search(1500, |_| Some(false)), None);
    }

    #[test]
    fn running_out_of_time_is_unknown() {
        let mut echoes = 0;
        let result = search(1500, |size| {
            echoes += 1;
            (echoes < 4).then_some(size <= 1400)
        });
        assert_eq!(result, None);
    }

    #[test]
    fn a_link_already_at_the_floor_is_not_probed() {
        assert_eq!(search(FLOOR, |_| panic!("probed")), Some(FLOOR));
    }
}
