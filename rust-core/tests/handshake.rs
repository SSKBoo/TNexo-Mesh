use nexomesh_core::noise::NOISE_PATTERN;

#[test]
fn pattern_name() {
    assert_eq!(NOISE_PATTERN, "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s");
}
