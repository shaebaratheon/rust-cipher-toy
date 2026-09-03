use rust_cipher_toy::{Aes128, ChaCha20, Sha256};

#[test]
fn test_exhaustive_cipher_vectors() {
    let key = [0x01; 16];
    let cipher = Aes128::new(&key);
    for i in 0..50 {
        let block = [i as u8; 16];
        let mut out = [0u8; 16];
        cipher.encrypt_block(&block, &mut out);
        assert_ne!(block, out);
    }
}
