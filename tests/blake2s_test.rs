use rust_cipher_toy::hash::blake2s::Blake2s;

#[test]
fn test_blake2s_basic() {
    let mut b = Blake2s::new(32);
    b.update(b"The quick brown fox jumps over the lazy dog");
}
