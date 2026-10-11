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
    let mut announce = |session: &mut SessionState, path: usize, selected, healthy| {
        sequence += 1;
        let header = FrameHeader {
            flags: FLAG_CONTROL | if healthy { 0 } else { FLAG_PATH_UNHEALTHY },
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
        announce(&mut session, path, path < 2, true);
    }
    verify(&mut session, &[0, 1], 0);
    announce(&mut session, 2, true, true);
    verify(&mut session, &[0, 1, 2], 0);
    verify(&mut session, &[3], FLAG_REPAIR);
    announce(&mut session, 3, true, true);
    verify(&mut session, &[0, 1, 2, 3], 0);
    verify(&mut session, &[4], FLAG_REPAIR);
    announce(&mut session, 3, false, true);
    verify(&mut session, &[0, 1, 2], 0);
    verify(&mut session, &[3], FLAG_REPAIR);
    announce(&mut session, 2, false, true);
    // Probes and repairs from standby paths cannot re-enable full fan-out.
    for socket in &paths {
        session.observe_endpoint(socket.local_addr().unwrap());
    }
    verify(&mut session, &[0, 1], 0);
    verify(&mut session, &[2], FLAG_REPAIR);
    announce(&mut session, 3, false, false);
    // A fresh heartbeat from a failed node cannot attract recovery packets.
    verify(&mut session, &[2], FLAG_REPAIR);
    verify(&mut session, &[4], FLAG_REPAIR);
    verify(&mut session, &[0, 1], 0);
}

#[test]
fn standby_repair_recovers_a_packet_dropped_on_both_selected_routes() {
    use gamepath_engine::fec::{Encoder, GROUP_MAX_AGE};

    let relay = UdpSocket::bind("127.0.0.1:0").unwrap();
    let paths: Vec<_> = (0..3)
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
    let now = Instant::now();
    for (path, socket) in paths.iter().enumerate() {
        session.endpoints.apply(
            socket.local_addr().unwrap(),
            PathPolicy {
                path: path as u8,
                selected: path < 2,
            },
            true,
            path as u64 + 1,
            now,
        );
    }
    let mut encoder = Encoder::new(4, 1341);
    let mut received = Vec::new();
    let mut lost_sequence = 0;
    for index in 0..4 {
        let packet = vec![0x45, index, 0, 20];
        let sequence = session
            .fan_out(&relay, &crypto, [1; 16], 9, 0, &packet)
            .unwrap();
        assert!(encoder.push(sequence, &packet, now).is_none());
        for socket in &paths[..2] {
            let mut frame = [0; 256];
            let length = socket.recv(&mut frame).unwrap();
            let (header, plaintext) = crypto.open_server(&frame[..length]).unwrap();
            assert_eq!(header.sequence, sequence);
            assert_eq!(plaintext, packet);
        }
        if index == 1 {
            lost_sequence = sequence;
        } else {
            received.push((sequence, packet));
        }
    }
    let repair = encoder.flush_due(now + GROUP_MAX_AGE).unwrap();
    session
        .fan_out(&relay, &crypto, [1; 16], 9, FLAG_REPAIR, &repair)
        .unwrap();
    let mut frame = [0; 256];
    let length = paths[2].recv(&mut frame).unwrap();
    let (header, payload) = crypto.open_server(&frame[..length]).unwrap();
    assert_eq!(header.flags, FLAG_REPAIR | FLAG_SERVER_TO_CLIENT);
    let mut decoder = Decoder::default();
    let mut replay = ReplayWindow::default();
    assert!(replay.accept(header.sequence));
    assert!(
        decoder
            .accept_repair(&payload, now, |seq| !replay.would_accept(seq))
            .is_none()
    );
    let mut rebuilt = None;
    for (sequence, packet) in received {
        assert!(replay.accept(sequence));
        decoder.remember(sequence, &packet);
        if let Some(recovered) = decoder.retry_pending(now, |seq| !replay.would_accept(seq)) {
            assert!(replay.accept(recovered.0));
            rebuilt = Some(recovered);
        }
    }
    assert_eq!(rebuilt, Some((lost_sequence, vec![0x45, 1, 0, 20])));
    assert_eq!(decoder.unrecoverable, 0);
    assert!(
        !replay.accept(lost_sequence),
        "late data must remain deduplicated"
    );
    for socket in &paths[..2] {
        socket.set_nonblocking(true).unwrap();
        assert_eq!(
            socket.recv(&mut frame).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }
}
