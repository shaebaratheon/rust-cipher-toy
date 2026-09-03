use rust_cipher_toy::rsa::pkcs1::Pkcs1v15;

#[test]
fn test_pkcs1_padding_roundtrip() {
    let secret = b"super_secret_session_token_12345";
    let padded = Pkcs1v15::pad_for_encryption(secret, 128).expect("padding should succeed");
    assert_eq!(padded.len(), 128);

    let recovered = Pkcs1v15::unpad_for_encryption(&padded).expect("unpadding should succeed");
    assert_eq!(&recovered[..], secret);
}
