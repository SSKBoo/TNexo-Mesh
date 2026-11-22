use nexomesh_core::derp::{
    build_icmp_echo_request, try_build_icmp_echo_reply, Node, NodeEvent,
};
use nexomesh_core::session;
use std::net::SocketAddr;

#[test]
fn userspace_node_falls_back_to_relay_when_no_udp_peer() {
    let key_a = "NODE_A_KEY";
    let key_b = "NODE_B_KEY";
    // Las sesiones se registran por IP virtual: el frame NM1 lleva senderVip
    // y el receptor abre con esa clave (igual que en Android).
    session::ensure_session("10.0.0.2", key_a, key_b).unwrap();
    session::ensure_session("10.0.0.3", key_b, key_a).unwrap();

    let mut node = Node::bind("10.0.0.2", "10.0.0.3", 0).unwrap();
    let rx = node.enable_relay();

    // Sin peer UDP configurado: debe publicar el frame NM1 en el relay.
    let packet = [0x45u8, 0x00, 0x00, 0x14];
    node.send_packet(&packet).unwrap();
    let frame = rx.try_recv().expect("debe haber frame en el relay");
    assert_eq!(&frame[0..3], b"NM1");
    assert_eq!(frame[3] as usize, "10.0.0.2".len());
    assert!(!node.using_direct());

    // El otro extremo puede abrirlo usando el senderVip del frame.
    let sender_len = frame[3] as usize;
    let sender_vip = std::str::from_utf8(&frame[4..4 + sender_len]).unwrap();
    assert_eq!(sender_vip, "10.0.0.2");
    let opened = session::open(sender_vip, &frame[4 + sender_len..]).unwrap();
    assert_eq!(&opened[..], &packet);
}

#[test]
fn direct_udp_hello_and_icmp_echo_roundtrip() {
    let key_a = "DIRECT_KEY_A";
    let key_b = "DIRECT_KEY_B";
    session::ensure_session("10.0.0.10", key_b, key_a).unwrap();
    session::ensure_session("10.0.0.11", key_a, key_b).unwrap();

    let mut node_a = Node::bind("10.0.0.10", "10.0.0.11", 0).unwrap();
    let mut node_b = Node::bind("10.0.0.11", "10.0.0.10", 0).unwrap();

    let addr_b: SocketAddr = format!("127.0.0.1:{}", node_b.local_port().unwrap())
        .parse()
        .unwrap();
    node_a.set_peer(addr_b);
    node_a.send_hello("node-a").unwrap();

    // B recibe NM_HELLO y responde NM_ACK aprendiendo el endpoint de A
    match node_b.poll_udp_once().unwrap() {
        Some(NodeEvent::Hello { vip, .. }) => assert_eq!(vip, "10.0.0.10"),
        other => panic!("esperaba Hello en B, obtuve {other:?}"),
    }
    match node_a.poll_udp_once().unwrap() {
        Some(NodeEvent::Ack { vip, .. }) => assert_eq!(vip, "10.0.0.11"),
        other => panic!("esperaba Ack en A, obtuve {other:?}"),
    }
    assert!(node_a.using_direct());
    assert!(node_b.using_direct());

    // A envía ICMP Echo Request cifrado a B, B responde Echo Reply cifrado
    let req = build_icmp_echo_request("10.0.0.10", "10.0.0.11", 7).unwrap();
    node_a.send_packet(&req).unwrap();

    let rx_req = match node_b.poll_udp_once().unwrap() {
        Some(NodeEvent::Packet { sender_vip, packet }) => {
            assert_eq!(sender_vip, "10.0.0.10");
            packet
        }
        other => panic!("esperaba Packet en B, obtuve {other:?}"),
    };
    let reply = try_build_icmp_echo_reply(&rx_req, "10.0.0.11").expect("ICMP Echo Reply válido");
    node_b.send_packet(&reply).unwrap();

    match node_a.poll_udp_once().unwrap() {
        Some(NodeEvent::Packet { sender_vip, packet }) => {
            assert_eq!(sender_vip, "10.0.0.11");
            assert_eq!(packet[20], 0); // Echo Reply (type=0)
            assert_eq!(u16::from_be_bytes([packet[26], packet[27]]), 7);
        }
        other => panic!("esperaba Echo Reply en A, obtuve {other:?}"),
    }
}
