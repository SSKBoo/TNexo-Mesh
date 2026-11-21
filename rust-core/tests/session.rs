use nexomesh_core::session;

#[test]
fn two_peers_derive_mirror_transport_keys() {
    // IDs únicos por test: los tests corren en paralelo y comparten el registro
    // global de sesiones, así que no deben usar clear() ni solaparse.
    let key_a = "AAA_PUBLIC_KEY";
    let key_b = "ZZZ_PUBLIC_KEY";
    let a = "mirror-A";
    let b = "mirror-B";

    session::ensure_session(a, key_a, key_b).unwrap();
    session::ensure_session(b, key_b, key_a).unwrap();

    // A sella -> B abre
    let frame = session::seal(a, b"ping from A").unwrap();
    assert_ne!(&frame[1..], b"ping from A");
    let opened = session::open(b, &frame).unwrap();
    assert_eq!(&opened[..], b"ping from A");

    // B sella -> A abre
    let frame_b = session::seal(b, b"pong from B").unwrap();
    let opened_b = session::open(a, &frame_b).unwrap();
    assert_eq!(&opened_b[..], b"pong from B");
}

#[test]
fn tampered_frame_is_rejected() {
    let a = "tamper-A";
    let b = "tamper-B";
    session::ensure_session(a, "KEY_AAA", "KEY_ZZZ").unwrap();
    session::ensure_session(b, "KEY_ZZZ", "KEY_AAA").unwrap();
    let mut frame = session::seal(a, b"secret").unwrap();
    frame[5] ^= 0xFF;
    assert!(session::open(b, &frame).is_err());
}
