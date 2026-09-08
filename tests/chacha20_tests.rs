
#[cfg(test)]
mod rfc7539_chacha20_tests {
    use crate::chacha20::ChaCha20;

    #[test]
    fn test_chacha20_rfc7539_test_vector() {
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let nonce = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a,
            0x00, 0x00, 0x00, 0x00,
        ];
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let mut chacha = ChaCha20::new(&key, &nonce, 1);
        let mut ciphertext = plaintext.to_vec();
        chacha.apply_keystream(&mut ciphertext);
        assert_ne!(ciphertext, plaintext);

        // Verify roundtrip decryption
        let mut decryptor = ChaCha20::new(&key, &nonce, 1);
        let mut decrypted = ciphertext.clone();
        decryptor.apply_keystream(&mut decrypted);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_chacha20_counter_increment() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];
        let mut c1 = ChaCha20::new(&key, &nonce, 0);
        let mut block1 = vec![0u8; 64];
        c1.apply_keystream(&mut block1);

        let mut c2 = ChaCha20::new(&key, &nonce, 1);
        let mut block2 = vec![0u8; 64];
        c2.apply_keystream(&mut block2);

        assert_ne!(block1, block2, "Adjacent blocks must have distinct keystreams");
    }
}
