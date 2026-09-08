use rust_cipher_toy::padding::{Pkcs7, PaddingError};

#[test]
fn test_pkcs7_roundtrip() {
    let data = b"Yellow Submarine";
    let padded = Pkcs7::pad(data, 16).unwrap();
    assert_eq!(padded.len(), 32);
    let unpadded = Pkcs7::unpad(&padded, 16).unwrap();
    assert_eq!(unpadded, data);
}

#[test]
fn test_pkcs7_corrupt_padding() {
    let mut bad = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0];
    assert_eq!(Pkcs7::unpad(&bad, 16), Err(PaddingError::InvalidPadding));
}
