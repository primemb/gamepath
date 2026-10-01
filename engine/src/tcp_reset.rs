//! Ends established TCP connections so their applications reconnect at once.
//!
//! A connection opened before a session started is carried by it from the
//! next packet on, but from the session's address: the server no longer
//! recognises it, and the application only notices when its own timeout
//! fires, often a minute or more later. Ending it makes the application
//! reconnect straight away, and the new connection goes through the session.
//! Windscribe does the same when its split tunnel changes
//! (`close_tcp_connections.cpp`).

use std::net::{Ipv4Addr, SocketAddrV4};

/// `MIB_TCP_STATE_ESTAB`.
const ESTABLISHED: u32 = 5;
/// `MIB_TCP_STATE_DELETE_TCB`: the one state `SetTcpEntry` accepts. It sends
/// the peer a reset and fails the application's socket.
const DELETE_TCB: u32 = 12;
/// `TCP_TABLE_OWNER_PID_CONNECTIONS`: connections only, no listeners.
const OWNER_PID_CONNECTIONS: u32 = 4;
const AF_INET: u32 = 2;

#[repr(C)]
struct MibTcpRow {
    state: u32,
    local_address: u32,
    local_port: u32,
    remote_address: u32,
    remote_port: u32,
}

#[link(name = "iphlpapi")]
unsafe extern "system" {
    fn GetExtendedTcpTable(
        table: *mut std::ffi::c_void,
        size: *mut u32,
        order: i32,
        family: u32,
        table_class: u32,
        reserved: u32,
    ) -> u32;
    fn SetTcpEntry(row: *const MibTcpRow) -> u32;
}

pub(crate) struct Connection {
    pub(crate) local: SocketAddrV4,
    pub(crate) remote: SocketAddrV4,
    pub(crate) process_id: u32,
    /// Address and port fields exactly as the table gave them, for
    /// `SetTcpEntry`, which matches on them.
    raw: [u32; 4],
}

/// Every established IPv4 TCP connection, with the process that owns it.
pub(crate) fn established() -> Vec<Connection> {
    let Some(buffer) = crate::split_capture::ip_table(|table, size| unsafe {
        GetExtendedTcpTable(table, size, 0, AF_INET, OWNER_PID_CONNECTIONS, 0)
    }) else {
        return Vec::new();
    };
    // MIB_TCPROW_OWNER_PID: state, local address and port, remote address and
    // port, process id. Addresses are in network order, ports in the low word.
    crate::split_capture::dword_rows(&buffer, 6)
        .into_iter()
        .filter(|row| row[0] == ESTABLISHED && row[5] != 0)
        .map(|row| Connection {
            local: SocketAddrV4::new(
                Ipv4Addr::from(row[1].to_ne_bytes()),
                crate::split_capture::port_from_dword(row[2]),
            ),
            remote: SocketAddrV4::new(
                Ipv4Addr::from(row[3].to_ne_bytes()),
                crate::split_capture::port_from_dword(row[4]),
            ),
            process_id: row[5],
            raw: [row[1], row[2], row[3], row[4]],
        })
        .collect()
}

/// Ends `connection`. Needs administrator rights, which the session engine
/// has. A connection that closed meanwhile is simply not found.
pub(crate) fn close(connection: &Connection) -> bool {
    let row = MibTcpRow {
        state: DELETE_TCB,
        local_address: connection.raw[0],
        local_port: connection.raw[1],
        remote_address: connection.raw[2],
        remote_port: connection.raw[3],
    };
    unsafe { SetTcpEntry(&row) == 0 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};

    /// Addresses, ports and the owner come back as the socket API sees them.
    #[test]
    fn an_open_connection_is_listed_with_its_ends_and_owner() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let _server = listener.accept().unwrap();
        let std::net::SocketAddr::V4(local) = client.local_addr().unwrap() else {
            unreachable!()
        };
        let std::net::SocketAddr::V4(remote) = client.peer_addr().unwrap() else {
            unreachable!()
        };
        let found = established()
            .into_iter()
            .find(|connection| connection.local == local && connection.remote == remote)
            .expect("the connection is listed");
        assert_eq!(found.process_id, std::process::id());
    }
}
