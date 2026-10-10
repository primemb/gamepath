use super::*;
use gamepath_engine::path_policy::{self, PathPolicy};

#[test]
fn authenticated_selection_controls_both_data_and_repair_fanout() {
    let relay = UdpSocket::bind("127.0.0.1:0").unwrap();
    let paths: Vec<_> = (0..5)
        .map(|_| {
            let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            socket
        })
        .collect();
    let crypto = SessionCrypto::new(&[5; 32], 9).unwrap();
    let mut session = SessionState::new();
    let mut sequence = 0;
    let mut announce = |session: &mut SessionState, path: usize, selected| {
        sequence += 1;
        let header = FrameHeader {
            flags: FLAG_CONTROL,
            client_id: [1; 16],
            session_id: 9,
            sequence,
        };
        let request = crypto
            .seal_client(
                header,
                &PathPolicy {
                    path: path as u8,
                    selected,
                }
                .request(),
            )
            .unwrap();
        let (header, plaintext) = crypto.open_client(&request).unwrap();
        let address = paths[path].local_addr().unwrap();
        session.observe_endpoint(address);
        assert!(session.replay.accept(header.sequence));
        assert!(apply_path_policy(
            session, &relay, &crypto, &header, &plaintext, address
        ));
        let mut frame = [0; 256];
        let length = paths[path].recv(&mut frame).unwrap();
        let (reply, payload) = crypto.open_server(&frame[..length]).unwrap();
        assert_eq!(reply.flags, FLAG_CONTROL | FLAG_SERVER_TO_CLIENT);
        assert!(path_policy::accepted(&payload));
    };
    let verify = |session: &mut SessionState, selected: &[usize], flags| {
        let sequence = session
            .fan_out(&relay, &crypto, [1; 16], 9, flags, b"reply")
            .unwrap();
        for (index, socket) in paths.iter().enumerate() {
            let mut frame = [0; 256];
            if selected.contains(&index) {
                let length = socket.recv(&mut frame).unwrap();
                let (header, payload) = crypto.open_server(&frame[..length]).unwrap();
                assert_eq!(header.sequence, sequence);
                assert_eq!(header.flags, flags | FLAG_SERVER_TO_CLIENT);
                assert_eq!(payload, b"reply");
            } else {
                socket.set_nonblocking(true).unwrap();
                assert_eq!(
                    socket.recv(&mut frame).unwrap_err().kind(),
                    io::ErrorKind::WouldBlock
                );
                socket.set_nonblocking(false).unwrap();
            }
        }
    };
    for path in 0..paths.len() {
        announce(&mut session, path, path < 2);
    }
    verify(&mut session, &[0, 1], 0);
    announce(&mut session, 2, true);
    verify(&mut session, &[0, 1, 2], 0);
    verify(&mut session, &[0, 1, 2], FLAG_REPAIR);
    announce(&mut session, 3, true);
    verify(&mut session, &[0, 1, 2, 3], 0);
    verify(&mut session, &[0, 1, 2, 3], FLAG_REPAIR);
    announce(&mut session, 3, false);
    verify(&mut session, &[0, 1, 2], 0);
    verify(&mut session, &[0, 1, 2], FLAG_REPAIR);
    announce(&mut session, 2, false);
    // Probes and repairs from standby paths cannot re-enable full fan-out.
    for socket in &paths {
        session.observe_endpoint(socket.local_addr().unwrap());
    }
    verify(&mut session, &[0, 1], 0);
    verify(&mut session, &[0, 1], FLAG_REPAIR);
}
