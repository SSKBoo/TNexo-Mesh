use nexomesh_core::session;

#[test]
fn two_peers_derive_mirror_transport_keys() {
    let key_a = "AAA_PUBLIC_KEY";
    let key_b = "ZZZ_PUBLIC_KEY";

    // Cada dispositivo guarda su sesión bajo su propio id; el par de llaves
    // (local, peer) es lo que define el handshake, no el id del mapa.
    session::clear();
    session::ensure_session("A-view", key_a, key_b).unwrap();
    session::ensure_session("B-view", key_b, key_a).unwrap();

    // A sella -> B abre
    let frame = session::seal("A-view", b"ping from A").unwrap();
    assert_ne!(&frame[1..], b"ping from A");
    let opened = session::open("B-view", &frame).unwrap();
    assert_eq!(&opened[..], b"ping from A");

    // B sella -> A abre
    let frame_b = session::seal("B-view", b"pong from B").unwrap();
    let opened_b = session::open("A-view", &frame_b).unwrap();
    assert_eq!(&opened_b[..], b"pong from B");
}

#[test]
fn tampered_frame_is_rejected() {
    session::clear();
    session::ensure_session("A-view", "KEY_AAA", "KEY_ZZZ").unwrap();
    session::ensure_session("B-view", "KEY_ZZZ", "KEY_AAA").unwrap();
    let mut frame = session::seal("A-view", b"secret").unwrap();
    frame[5] ^= 0xFF;
    assert!(session::open("B-view", &frame).is_err());
}
