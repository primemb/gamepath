use std::ffi::c_void;
use std::mem::{offset_of, size_of};
use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID,
    MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID, TCP_TABLE_CLASS, TCP_TABLE_OWNER_PID_ALL,
    TCP_TABLE_OWNER_PID_CONNECTIONS, TCP_TABLE_OWNER_PID_LISTENER, UDP_TABLE_OWNER_PID,
};
use windows_sys::Win32::Networking::WinSock::AF_INET;

pub(crate) fn tcp_rows(class: TCP_TABLE_CLASS) -> Option<Vec<MIB_TCPROW_OWNER_PID>> {
    if !matches!(
        class,
        TCP_TABLE_OWNER_PID_ALL | TCP_TABLE_OWNER_PID_CONNECTIONS | TCP_TABLE_OWNER_PID_LISTENER
    ) {
        return None;
    }
    let buffer = read_table(|table, size| unsafe {
        GetExtendedTcpTable(table, size, 0, u32::from(AF_INET), class, 0)
    })?;
    // Both owner-PID row types contain only DWORDs, so every bit pattern is valid.
    unsafe { rows(&buffer, offset_of!(MIB_TCPTABLE_OWNER_PID, table)) }
}

pub(crate) fn udp_rows() -> Option<Vec<MIB_UDPROW_OWNER_PID>> {
    let buffer = read_table(|table, size| unsafe {
        GetExtendedUdpTable(table, size, 0, u32::from(AF_INET), UDP_TABLE_OWNER_PID, 0)
    })?;
    unsafe { rows(&buffer, offset_of!(MIB_UDPTABLE_OWNER_PID, table)) }
}

fn read_table(call: impl Fn(*mut c_void, *mut u32) -> u32) -> Option<Vec<u8>> {
    let mut size = 0_u32;
    let status = call(std::ptr::null_mut(), &mut size);
    if !matches!(status, NO_ERROR | ERROR_INSUFFICIENT_BUFFER) || size < size_of::<u32>() as u32 {
        return None;
    }
    let mut buffer = vec![0_u8; size as usize];
    // Socket inventories can grow between the size probe and the read.
    for _ in 0..3 {
        let status = call(buffer.as_mut_ptr().cast(), &mut size);
        if status == NO_ERROR {
            return Some(buffer);
        }
        if status != ERROR_INSUFFICIENT_BUFFER || size < size_of::<u32>() as u32 {
            return None;
        }
        buffer.resize(size as usize, 0);
    }
    None
}

/// `Row` must be a plain-data SDK row for which every bit pattern is valid.
unsafe fn rows<Row: Copy>(buffer: &[u8], offset: usize) -> Option<Vec<Row>> {
    let count = u32::from_ne_bytes(buffer.get(..size_of::<u32>())?.try_into().ok()?) as usize;
    let length = count.checked_mul(size_of::<Row>())?;
    let data = buffer.get(offset..offset.checked_add(length)?)?;
    Some(
        data.chunks_exact(size_of::<Row>())
            // A byte buffer does not promise the alignment of an SDK structure.
            .map(|bytes| unsafe { bytes.as_ptr().cast::<Row>().read_unaligned() })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn a_growing_inventory_is_retried_and_keeps_its_socket_owner() {
        let calls = Cell::new(0);
        let buffer = read_table(|table, size| {
            let call = calls.get();
            calls.set(call + 1);
            unsafe {
                if call == 0 {
                    assert!(table.is_null());
                    *size = 4;
                    return ERROR_INSUFFICIENT_BUFFER;
                }
                if call == 1 {
                    *size = 16;
                    return ERROR_INSUFFICIENT_BUFFER;
                }
                assert_eq!(*size, 16);
                let data = [1_u32, 0x0100007f, u32::from(2080_u16.to_be()), 42];
                std::ptr::copy_nonoverlapping(data.as_ptr().cast::<u8>(), table.cast(), 16);
                NO_ERROR
            }
        })
        .unwrap();
        let sockets = unsafe {
            rows::<MIB_UDPROW_OWNER_PID>(&buffer, offset_of!(MIB_UDPTABLE_OWNER_PID, table))
        }
        .unwrap();
        assert_eq!(calls.get(), 3);
        assert_eq!(sockets.len(), 1);
        assert_eq!(sockets[0].dwOwningPid, 42);
        assert_eq!(u16::from_be(sockets[0].dwLocalPort as u16), 2080);
    }

    #[test]
    fn an_incomplete_inventory_is_not_reported_as_empty() {
        let count = 1_u32.to_ne_bytes();
        assert!(unsafe { rows::<MIB_TCPROW_OWNER_PID>(&count, 4) }.is_none());
        assert!(unsafe { rows::<MIB_UDPROW_OWNER_PID>(&count, 4) }.is_none());
        let excessive_count = u32::MAX.to_ne_bytes();
        assert!(unsafe { rows::<MIB_TCPROW_OWNER_PID>(&excessive_count, 4) }.is_none());
    }
}
