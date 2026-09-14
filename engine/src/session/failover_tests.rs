//! Fault injection for the scheduler, sealed overlay and production ingress.
//! These tests use simulated transport arrival times, not provider networks.

use super::health::{mask_for_decision, selected_paths};
use super::state::RelayIngress;
use gamepath_engine::auth::SessionCrypto;
use gamepath_engine::protocol::{FLAG_SERVER_TO_CLIENT, FrameHeader};
use gamepath_engine::replay::ReplayWindow;
use gamepath_engine::scheduler::{PathMetrics, Strategy, choose_paths};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;

fn ingress() -> RelayIngress {
    RelayIngress {
        client_id: [7; 16],
        session_id: 123,
        server_replay: Mutex::new(ReplayWindow::default()),
    }
}

fn header(sequence: u64) -> FrameHeader {
    FrameHeader {
        flags: FLAG_SERVER_TO_CLIENT,
        client_id: [7; 16],
        session_id: 123,
        sequence,
    }
}

#[test]
fn slow_duplicate_bursts_cannot_fill_the_game_queue() {
    let ingress = ingress();
    let (tx, rx) = mpsc::sync_channel(2);
    assert!(
        ingress
            .enqueue_authenticated(&header(1), vec![1], &tx)
            .unwrap()
    );
    // The first fast reply occupies one slot. A TCP tunnel then releases a
    // burst of copies of that reply: they must consume no additional slots.
    for _ in 0..4096 {
        assert!(
            !ingress
                .enqueue_authenticated(&header(1), vec![1], &tx)
                .unwrap()
        );
    }
    assert!(
        ingress
            .enqueue_authenticated(&header(2), vec![2], &tx)
            .unwrap()
    );
    assert_eq!(rx.try_recv().unwrap(), vec![1]);
    assert_eq!(rx.try_recv().unwrap(), vec![2]);
    assert!(rx.try_recv().is_err());
}

#[test]
fn a_backup_can_rescue_a_copy_rejected_by_a_full_queue() {
    let ingress = ingress();
    let (tx, rx) = mpsc::sync_channel(1);
    ingress
        .enqueue_authenticated(&header(1), vec![1], &tx)
        .unwrap();
    assert!(matches!(
        ingress.enqueue_authenticated(&header(2), vec![2], &tx),
        Err(mpsc::TrySendError::Full(_))
    ));
    assert_eq!(rx.try_recv().unwrap(), vec![1]);
    // Retry the exact same sealed sequence through another worker.
    assert!(
        ingress
            .enqueue_authenticated(&header(2), vec![2], &tx)
            .unwrap()
    );
    assert_eq!(rx.try_recv().unwrap(), vec![2]);
}

#[test]
fn concurrent_paths_deliver_each_packet_exactly_once() {
    let ingress = Arc::new(ingress());
    let (tx, rx) = mpsc::sync_channel(512);
    let barrier = Arc::new(std::sync::Barrier::new(3));
    let workers: Vec<_> = (0..3)
        .map(|_| {
            let (ingress, tx, barrier) = (Arc::clone(&ingress), tx.clone(), Arc::clone(&barrier));
            thread::spawn(move || {
                barrier.wait();
                for sequence in 1..=512 {
                    ingress
                        .enqueue_authenticated(
                            &header(sequence),
                            sequence.to_be_bytes().to_vec(),
                            &tx,
                        )
                        .unwrap();
                }
            })
        })
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
    let mut packets: Vec<_> = rx
        .try_iter()
        .map(|packet| u64::from_be_bytes(packet.try_into().unwrap()))
        .collect();
    packets.sort_unstable();
    assert_eq!(packets, (1..=512).collect::<Vec<_>>());
}

#[test]
fn a_first_copy_from_any_path_is_useful_even_after_a_selection_change() {
    let ingress = ingress();
    let (tx, rx) = mpsc::sync_channel(3);
    // Fast path delivers packet 2; packet 1 was lost there. Its backup copy
    // remains useful even if the outbound scheduler has since deselected it.
    assert!(
        ingress
            .enqueue_authenticated(&header(2), vec![2], &tx)
            .unwrap()
    );
    assert!(
        ingress
            .enqueue_authenticated(&header(1), vec![1], &tx)
            .unwrap()
    );
    assert!(
        !ingress
            .enqueue_authenticated(&header(2), vec![2], &tx)
            .unwrap()
    );
    assert_eq!(rx.try_iter().collect::<Vec<_>>(), vec![vec![2], vec![1]]);
}

#[test]
fn wrong_session_client_or_direction_cannot_poison_replay_state() {
    let ingress = ingress();
    let (tx, rx) = mpsc::sync_channel(1);
    let mut wrong = header(1);
    wrong.session_id += 1;
    assert!(!ingress.enqueue_authenticated(&wrong, vec![0], &tx).unwrap());
    wrong = header(1);
    wrong.client_id = [0; 16];
    assert!(!ingress.enqueue_authenticated(&wrong, vec![0], &tx).unwrap());
    wrong = header(1);
    wrong.flags = 0;
    assert!(!ingress.enqueue_authenticated(&wrong, vec![0], &tx).unwrap());
    wrong.flags = FLAG_SERVER_TO_CLIENT | gamepath_engine::protocol::FLAG_CONTROL;
    assert!(!ingress.enqueue_authenticated(&wrong, vec![0], &tx).unwrap());
    assert!(
        ingress
            .enqueue_authenticated(&header(1), vec![1], &tx)
            .unwrap()
    );
    assert_eq!(rx.try_recv().unwrap(), vec![1]);
}

#[test]
fn sudden_primary_loss_and_tcp_stalls_preserve_the_working_path() {
    let crypto = SessionCrypto::new(&[9; 32], 123).unwrap();
    let ingress = ingress();
    let (tx, rx) = mpsc::sync_channel(256);
    let mut paths = [
        PathMetrics::new("0"),
        PathMetrics::new("1"),
        PathMetrics::new("2"),
    ];
    for (path, latency) in paths.iter_mut().zip([50.0, 60.0, 80.0]) {
        path.record_probe(latency);
    }
    let mut healthy = 0b111;
    let mut arrivals = Vec::new();
    // The same client identity/session remains in use throughout: the game
    // never changes its source by bypassing the relay during route failure.
    for sequence in 1..=200_u64 {
        let mask = selected_paths(
            mask_for_decision(choose_paths(&paths, Strategy::Adaptive), 0b111),
            healthy,
        );
        let h = FrameHeader {
            flags: 0,
            ..header(sequence)
        };
        let frame = crypto.seal_client(h, &sequence.to_be_bytes()).unwrap();
        for index in 0..3 {
            if mask & (1 << index) == 0 {
                continue;
            }
            // Path 0 disappears without advance warning, then recovers.
            if index == 0 && (40..120).contains(&sequence) {
                continue;
            }
            // Path 1 stalls by 500 ms on every fifth packet (TCP recovery).
            let delay = if index == 1 && sequence >= 45 && sequence % 5 == 0 {
                500
            } else {
                [25, 30, 40][index]
            };
            arrivals.push((sequence * 10 + delay, frame.clone()));
        }
        // Feedback intentionally follows the affected send. Backup copies
        // must already exist during the first unobserved failure.
        if (40..43).contains(&sequence) {
            paths[0].record_loss();
        }
        if sequence == 42 {
            healthy &= !1;
        }
        if sequence == 120 {
            healthy |= 1;
        }
        if sequence >= 120 {
            paths[0].record_probe(50.0);
        }
    }
    arrivals.sort_by_key(|(at, _)| *at);
    let mut relay_replay = ReplayWindow::default();
    let mut delivered = Vec::new();
    for (at, frame) in arrivals {
        let (h, payload) = crypto.open_client(&frame).unwrap();
        if !relay_replay.accept(h.sequence) {
            continue;
        }
        let reply = crypto.seal_server(header(h.sequence), &payload).unwrap();
        // Return copies can race or arrive in reverse order; ingress must
        // enqueue only one without waiting for either route's health probe.
        let (h, payload) = crypto.open_server(&reply).unwrap();
        assert!(
            ingress
                .enqueue_authenticated(&h, payload.clone(), &tx)
                .unwrap()
        );
        assert!(!ingress.enqueue_authenticated(&h, payload, &tx).unwrap());
        delivered.push((h.sequence, at - h.sequence * 10));
    }
    delivered.sort_by_key(|(sequence, _)| *sequence);
    assert_eq!(delivered.len(), 200, "a packet fell into the failover gap");
    assert!(
        delivered.iter().all(|(_, delay)| *delay <= 40),
        "a stalled path delayed a working copy"
    );
    assert_eq!(rx.try_iter().count(), 200);
}
