use rand_core::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

pub fn generate_keypair() -> (StaticSecret, PublicKey) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    (secret, public)
}
