use rust_cipher_toy::kdf::hkdf::Hkdf;

#[test]
fn test_hkdf_derivation() {
    let salt = b"salt1234";
    let ikm = b"input_key_material_raw";
    let prk = Hkdf::extract(salt, ikm);
    let okm = Hkdf::expand(&prk, b"handshake_info", 64);
    assert_eq!(okm.len(), 64);
}
