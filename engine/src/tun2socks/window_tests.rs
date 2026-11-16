use super::*;
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{
    IpProtocol, Ipv4Packet, Ipv4Repr, TcpControl, TcpPacket, TcpRepr, TcpSeqNumber,
};

fn incoming(
    sequence: TcpSeqNumber,
    ack: Option<TcpSeqNumber>,
    control: TcpControl,
    payload: &[u8],
) -> Vec<u8> {
    let tcp = TcpRepr {
        src_port: 40_102,
        dst_port: 80,
        control,
        seq_number: sequence,
        ack_number: ack,
        window_len: 65_535,
        window_scale: (control == TcpControl::Syn).then_some(0),
        max_seg_size: (control == TcpControl::Syn).then_some(1460),
        sack_permitted: false,
        sack_ranges: [None; 3],
        timestamp: None,
        payload,
    };
    let ip = Ipv4Repr {
        src_addr: CLIENT_ADDRESS,
        dst_addr: GATEWAY_ADDRESS,
        next_header: IpProtocol::Tcp,
        payload_len: tcp.buffer_len(),
        hop_limit: 64,
    };
    let mut packet = vec![0; ip.buffer_len() + tcp.buffer_len()];
    ip.emit(
        &mut Ipv4Packet::new_unchecked(&mut packet),
        &ChecksumCapabilities::default(),
    );
    tcp.emit(
        &mut TcpPacket::new_unchecked(&mut packet[ip.buffer_len()..]),
        &IpAddress::Ipv4(CLIENT_ADDRESS),
        &IpAddress::Ipv4(GATEWAY_ADDRESS),
        &ChecksumCapabilities::default(),
    );
    packet
}

#[test]
fn an_upload_crossing_a_scaled_receive_window_edge_does_not_crash() {
    let mut device = AppDevice {
        rx: VecDeque::new(),
        tx: Vec::new(),
    };
    let mut iface = Interface::new(
        Config::new(HardwareAddress::Ip),
        &mut device,
        StackInstant::from_millis(0),
    );
    iface.update_ip_addrs(|addresses| {
        addresses
            .push(IpCidr::new(IpAddress::Ipv4(GATEWAY_ADDRESS), 24))
            .unwrap();
    });
    let mut receiver = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; 128 * 1024]),
        tcp::SocketBuffer::new(vec![0; 1024]),
    );
    receiver.set_ack_delay(None);
    receiver.listen(80).unwrap();
    let mut sockets = SocketSet::new(Vec::new());
    let handle = sockets.add(receiver);
    let first = TcpSeqNumber(-2);
    device
        .rx
        .push_back(incoming(first, None, TcpControl::Syn, &[]));
    iface.poll(StackInstant::from_millis(0), &mut device, &mut sockets);
    let syn_ack = device.tx.pop().unwrap();
    let syn_ack = TcpPacket::new_checked(&syn_ack[20..]).unwrap();
    let ack = syn_ack.seq_number() + 1;
    device
        .rx
        .push_back(incoming(first + 1, Some(ack), TcpControl::None, &[]));
    iface.poll(StackInstant::from_millis(1), &mut device, &mut sockets);
    device
        .rx
        .push_back(incoming(first + 1, Some(ack), TcpControl::None, &[7]));
    iface.poll(StackInstant::from_millis(2), &mut device, &mut sockets);
    let update = device.tx.pop().unwrap();
    let update = TcpPacket::new_checked(&update[20..]).unwrap();
    assert_eq!(update.window_len(), 32_767);
    let advertised = usize::from(update.window_len()) << 2;
    // Scaling rounded the advertised free window down by three bytes. Data
    // beyond that edge must not underflow the window or be acknowledged early.
    let payload = vec![7; 128 * 1024 - 1];
    let mut sequence = first + 2;
    for chunk in payload.chunks(60_000) {
        device
            .rx
            .push_back(incoming(sequence, Some(ack), TcpControl::None, chunk));
        sequence += chunk.len();
    }
    for _ in 0..3 {
        iface.poll_ingress_single(StackInstant::from_millis(3), &mut device, &mut sockets);
    }
    let _ = iface.poll_delay(StackInstant::from_millis(3), &sockets);
    iface.poll_egress(StackInstant::from_millis(3), &mut device, &mut sockets);
    let accepted = sockets.get::<tcp::Socket>(handle).recv_queue();
    assert_eq!(accepted, 1 + advertised);
    let reply = device.tx.pop().unwrap();
    let reply = TcpPacket::new_checked(&reply[20..]).unwrap();
    assert_eq!(reply.window_len(), 0);
    assert_eq!(reply.ack_number(), first + 1 + accepted);
    // Once the application reads, retransmitting the unacknowledged tail
    // completes the upload rather than leaving it stuck at the window edge.
    assert_eq!(
        sockets
            .get_mut::<tcp::Socket>(handle)
            .recv_slice(&mut [0; 4])
            .unwrap(),
        4
    );
    iface.poll_egress(StackInstant::from_millis(4), &mut device, &mut sockets);
    device.rx.push_back(incoming(
        first + 1 + accepted,
        Some(ack),
        TcpControl::None,
        &[7; 3],
    ));
    iface.poll(StackInstant::from_millis(5), &mut device, &mut sockets);
    let reply = device.tx.pop().unwrap();
    assert_eq!(
        TcpPacket::new_checked(&reply[20..]).unwrap().ack_number(),
        sequence
    );
    assert_eq!(
        sockets.get::<tcp::Socket>(handle).recv_queue() + 4,
        128 * 1024
    );
}
