use nexomesh_core::keys::rotate_keypair;
use x25519_dalek::PublicKey;

#[test]
fn key_rotation_produces_new_identity() {
    let (old_sk, old_pk) = rotate_keypair();
    let (new_sk, new_pk) = rotate_keypair();
    assert_ne!(old_pk.as_bytes(), new_pk.as_bytes(), "rotación debe cambiar la clave pública");
    let recomputed_old = PublicKey::from(&old_sk);
    let recomputed_new = PublicKey::from(&new_sk);
    assert_eq!(recomputed_old.as_bytes(), old_pk.as_bytes());
    assert_eq!(recomputed_new.as_bytes(), new_pk.as_bytes());
}

#[test]
fn ed25519_challenge_signature_verifies() {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    use nexomesh_core::keys::sign_challenge_b64;
    use nexomesh_core::ws_client::base64_decode;

    let (pub_b64, sig_b64) = sign_challenge_b64("seed-host-1", "random-nonce-123");
    let pub_bytes: [u8; 32] = base64_decode(&pub_b64).unwrap().try_into().unwrap();
    let sig_bytes: [u8; 64] = base64_decode(&sig_b64).unwrap().try_into().unwrap();
    let vk = VerifyingKey::from_bytes(&pub_bytes).unwrap();
    let sig = Signature::from_bytes(&sig_bytes);
    assert!(vk.verify(b"random-nonce-123", &sig).is_ok());
    assert!(vk.verify(b"wrong-nonce", &sig).is_err());
}
