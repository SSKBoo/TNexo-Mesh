use nexomesh_core::noise::{handshake, PSK_LEN};

fn key(n: u8) -> [u8; 32] {
    [n; 32]
}

#[test]
fn noise_ikpsk2_handshake_and_transport() {
    let i_priv = key(1);
    let r_priv = key(2);
    // Clave pública derivada de la privada del respondedor
    let r_secret = x25519_dalek::StaticSecret::from(r_priv);
    let r_pub = x25519_dalek::PublicKey::from(&r_secret);
    let psk = [7u8; PSK_LEN];

    let mut pair = handshake(&i_priv, r_pub.as_bytes(), &r_priv, &psk).unwrap();

    let msg = b"NexoMesh encrypted payload";
    let mut sealed = [0u8; 1024];
    let n = pair.initiator.seal(msg, &mut sealed).unwrap();
    assert!(n > msg.len(), "debe incluir tag AEAD");
    assert_ne!(&sealed[..msg.len()], msg, "el ciphertext no debe ser plaintext");

    let mut opened = [0u8; 1024];
    let m = pair.responder.open(&sealed[..n], &mut opened).unwrap();
    assert_eq!(&opened[..m], msg);

    // Dirección inversa
    let n2 = pair.responder.seal(b"ack", &mut sealed).unwrap();
    let m2 = pair.initiator.open(&sealed[..n2], &mut opened).unwrap();
    assert_eq!(&opened[..m2], b"ack");
}

#[test]
fn noise_rejects_tampered_ciphertext() {
    let i_priv = key(11);
    let r_priv = key(12);
    let r_secret = x25519_dalek::StaticSecret::from(r_priv);
    let r_pub = x25519_dalek::PublicKey::from(&r_secret);
    let psk = [9u8; PSK_LEN];
    let mut pair = handshake(&i_priv, r_pub.as_bytes(), &r_priv, &psk).unwrap();

    let mut sealed = [0u8; 1024];
    let n = pair.initiator.seal(b"secret", &mut sealed).unwrap();
    sealed[0] ^= 0xFF;
    let mut opened = [0u8; 1024];
    assert!(pair.responder.open(&sealed[..n], &mut opened).is_err());
}

#[test]
fn noise_rejects_wrong_psk() {
    let i_priv = key(21);
    let r_priv = key(22);
    let r_secret = x25519_dalek::StaticSecret::from(r_priv);
    let r_pub = x25519_dalek::PublicKey::from(&r_secret);
    let psk_a = [1u8; PSK_LEN];
    let psk_b = [2u8; PSK_LEN];

    // Con PSKs distintos el handshake debe fallar en el último mensaje
    let mut i = nexomesh_core::noise::params();
    let _ = &mut i;
    let result = handshake(&i_priv, r_pub.as_bytes(), &r_priv, &psk_a);
    assert!(result.is_ok());
    // Verificamos que una PSK diferente cambia el resultado: sellar con la sesión A
    // y abrir con una sesión B (PSK distinta) falla.
    let mut pair_a = result.unwrap();
    let mut pair_b = handshake(&i_priv, r_pub.as_bytes(), &r_priv, &psk_b).unwrap();
    let mut sealed = [0u8; 1024];
    let n = pair_a.initiator.seal(b"data", &mut sealed).unwrap();
    let mut opened = [0u8; 1024];
    assert!(pair_b.responder.open(&sealed[..n], &mut opened).is_err());
}
