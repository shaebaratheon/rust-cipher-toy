use rust_cipher_toy::modes::gcm::AesGcm128;

#[test]
fn test_aes_gcm_encryption_tagging() {
    let key = [0x42u8; 16];
    let iv = [0x07u8; 12];
    let gcm = AesGcm128::new(&key);
    let (ct, tag) = gcm.encrypt(&iv, b"confidential payload data", b"aad-metadata");
    assert_eq!(ct.len(), 25);
    assert_eq!(tag.len(), 16);
}
