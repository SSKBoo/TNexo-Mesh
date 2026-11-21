//! Verifica el formato de frame que usa MeshVpnService.kt:
//! NM1 | len(senderVip) | senderVip | ciphertext(AEAD)
//! y que el payload IP viaja cifrado (no en texto plano).

use nexomesh_core::session;

#[test]
fn android_tunnel_frame_roundtrip() {
    let key_a = "XkKcWKIU2YEziA4EO7T178Btu5RDt6qiN8KH7VpChfU="; // host 10.0.0.2
    let key_b = "hpb4zZ2UlOMWmdOXquOO8H/5DjMtvQAE84+Y4MFpM08="; // par 10.0.0.3

    session::clear();
    // Cada extremo inicializa con su clave local y la del par
    session::ensure_session("10.0.0.3", key_a, key_b).unwrap(); // A -> B
    session::ensure_session("10.0.0.2", key_b, key_a).unwrap(); // B -> A

    // Un paquete IP ICMP simulado (20 bytes cabecera + 8 payload)
    let ip_packet = [
        0x45u8, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00,
        10, 0, 0, 2, 10, 0, 0, 3, 0x08, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01,
    ];

    // A sella para B
    let ciphertext = session::seal("10.0.0.3", &ip_packet).unwrap();
    assert!(ciphertext.len() > ip_packet.len(), "debe incluir nonce + tag");
    // El payload NO debe aparecer en claro
    assert!(!ciphertext.windows(ip_packet.len()).any(|w| w == ip_packet));

    // Construir el frame exacto de Android
    let sender = b"10.0.0.2";
    let mut frame = Vec::new();
    frame.extend_from_slice(b"NM1");
    frame.push(sender.len() as u8);
    frame.extend_from_slice(sender);
    frame.extend_from_slice(&ciphertext);

    // B extrae senderVip y abre con su sesión
    let sender_len = frame[3] as usize;
    let sender_vip = std::str::from_utf8(&frame[4..4 + sender_len]).unwrap();
    assert_eq!(sender_vip, "10.0.0.2");
    let ct = &frame[4 + sender_len..];
    let opened = session::open(sender_vip, ct).unwrap();
    assert_eq!(&opened[..], &ip_packet);
}
