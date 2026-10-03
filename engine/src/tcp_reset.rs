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
use windows_sys::Win32::Foundation::NO_ERROR;
use windows_sys::Win32::NetworkManagement::IpHelper::{
    MIB_TCP_STATE_DELETE_TCB, MIB_TCP_STATE_ESTAB, MIB_TCPROW_LH, MIB_TCPROW_LH_0, SetTcpEntry,
    TCP_TABLE_OWNER_PID_CONNECTIONS,
};

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
    let Some(rows) = crate::socket_table::tcp_rows(TCP_TABLE_OWNER_PID_CONNECTIONS) else {
        return Vec::new();
    };
    rows.into_iter()
        .filter(|row| row.dwState == MIB_TCP_STATE_ESTAB as u32 && row.dwOwningPid != 0)
        .map(|row| Connection {
            local: SocketAddrV4::new(
                Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes()),
                crate::split_capture::port_from_dword(row.dwLocalPort),
            ),
            remote: SocketAddrV4::new(
                Ipv4Addr::from(row.dwRemoteAddr.to_ne_bytes()),
                crate::split_capture::port_from_dword(row.dwRemotePort),
            ),
            process_id: row.dwOwningPid,
            raw: [
                row.dwLocalAddr,
                row.dwLocalPort,
                row.dwRemoteAddr,
                row.dwRemotePort,
            ],
        })
        .collect()
}

/// Ends `connection`. Needs administrator rights, which the session engine
/// has. A connection that closed meanwhile is simply not found.
pub(crate) fn close(connection: &Connection) -> bool {
    let row = MIB_TCPROW_LH {
        Anonymous: MIB_TCPROW_LH_0 {
            State: MIB_TCP_STATE_DELETE_TCB,
        },
        dwLocalAddr: connection.raw[0],
        dwLocalPort: connection.raw[1],
        dwRemoteAddr: connection.raw[2],
        dwRemotePort: connection.raw[3],
    };
    unsafe { SetTcpEntry(&row) == NO_ERROR }
}

pub(crate) fn close_matching(matches: impl Fn(&Connection) -> bool) -> usize {
    established()
        .iter()
        .filter(|connection| matches(connection) && close(connection))
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::time::Duration;

    #[test]
    #[ignore = "SetTcpEntry requires an elevated shell; uses only temporary loopback sockets"]
    fn closing_a_selected_connection_wakes_its_app_and_leaves_other_sockets_open() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut selected = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let _selected_server = listener.accept().unwrap();
        let mut untouched = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut untouched_server, _) = listener.accept().unwrap();
        selected
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        untouched
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let local = selected.local_addr().unwrap();
        let remote = selected.peer_addr().unwrap();
        let selected_only = |connection: &Connection| {
            std::net::SocketAddr::V4(connection.local) == local
                && std::net::SocketAddr::V4(connection.remote) == remote
                && connection.process_id == std::process::id()
        };
        assert_eq!(close_matching(selected_only), 1);
        assert!(!established().iter().any(selected_only));
        let mut buffer = [0];
        match selected.read(&mut buffer) {
            Ok(0) => {}
            Err(error) => assert!(matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::NotConnected
            )),
            result => panic!("the application should see its connection ended: {result:?}"),
        }
        untouched_server.write_all(b"x").unwrap();
        untouched.read_exact(&mut buffer).unwrap();
        assert_eq!(buffer, *b"x");
    }

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
