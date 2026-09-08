use rust_cipher_toy::pbkdf2::Pbkdf2;

#[test]
fn test_pbkdf2_derivation() {
    let password = b"password";
    let salt = b"salt";
    let mut key1 = [0u8; 32];
    let mut key2 = [0u8; 32];

    Pbkdf2::derive(password, salt, 10, &mut key1);
    Pbkdf2::derive(password, salt, 10, &mut key2);

    assert_eq!(key1, key2);
    assert_ne!(key1, [0u8; 32]);
}
