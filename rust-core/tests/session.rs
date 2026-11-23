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

#[test]
fn anti_replay_rejects_duplicate_and_allows_out_of_order_window() {
    let a = "replay-A";
    let b = "replay-B";
    session::ensure_session(a, "REP_KEY_A", "REP_KEY_B").unwrap();
    session::ensure_session(b, "REP_KEY_B", "REP_KEY_A").unwrap();

    let f0 = session::seal(a, b"pkt-0").unwrap();
    let f1 = session::seal(a, b"pkt-1").unwrap();
    let f2 = session::seal(a, b"pkt-2").unwrap();

    // Llega primero pkt-2, luego pkt-0 fuera de orden (debe aceptarse)
    assert_eq!(session::open(b, &f2).unwrap(), b"pkt-2");
    assert_eq!(session::open(b, &f0).unwrap(), b"pkt-0");
    // Reinyectar pkt-2 o pkt-0 debe rechazarse
    assert!(session::open(b, &f2).is_err());
    assert!(session::open(b, &f0).is_err());
    // pkt-1 todavía no había llegado -> aceptado una vez, rechazado la segunda
    assert_eq!(session::open(b, &f1).unwrap(), b"pkt-1");
    assert!(session::open(b, &f1).is_err());
}

#[test]
fn pfs_ephemeral_rekey_rotates_transport_key() {
    let a = "pfs-A";
    let b = "pfs-B";
    session::ensure_session(a, "PFS_KEY_A", "PFS_KEY_B").unwrap();
    session::ensure_session(b, "PFS_KEY_B", "PFS_KEY_A").unwrap();

    let eph_a = session::begin_pfs_rekey(a).unwrap();
    let eph_b = session::begin_pfs_rekey(b).unwrap();
    session::finish_pfs_rekey(a, &eph_b).unwrap();
    session::finish_pfs_rekey(b, &eph_a).unwrap();

    let msg = session::seal(a, b"after-pfs-rekey").unwrap();
    assert_eq!(session::open(b, &msg).unwrap(), b"after-pfs-rekey");
}
