use nexomesh_core::crypto::generate_keypair;
use nexomesh_core::keys::{save_key_encrypted, load_key_encrypted};

#[test]
fn roundtrip_key() {
    let (sk, pk) = generate_keypair();
    let path = std::env::temp_dir().join("nx.key");
    save_key_encrypted(path.to_str().unwrap(), &sk, "pass").unwrap();
    let loaded = load_key_encrypted(path.to_str().unwrap(), "pass").unwrap();
    assert_eq!(loaded.to_bytes(), sk.to_bytes());
    let _ = pk;
}
