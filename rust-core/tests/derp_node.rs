use nexomesh_core::derp::Node;
use nexomesh_core::session;

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
