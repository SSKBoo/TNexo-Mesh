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
