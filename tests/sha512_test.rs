use rust_cipher_toy::hash::sha512::Sha512;

#[test]
fn test_sha512_initialization() {
    let mut hasher = Sha512::new();
    hasher.update(b"The quick brown fox jumps over the lazy dog");
}
