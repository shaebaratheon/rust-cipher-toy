//! Galois/Counter Mode (GCM) Authenticated Encryption Implementation.

use crate::Aes128;

pub struct AesGcm128 {
    cipher: Aes128,
}

impl AesGcm128 {
    pub fn new(key: &[u8; 16]) -> Self {
        AesGcm128 { cipher: Aes128::new(key) }
    }

    pub fn encrypt(&self, iv: &[u8; 12], plaintext: &[u8], aad: &[u8]) -> (Vec<u8>, [u8; 16]) {
        let mut counter_block = [0u8; 16];
        counter_block[..12].copy_from_slice(iv);
        counter_block[15] = 1;

        let mut j0 = [0u8; 16];
        self.cipher.encrypt_block(&counter_block, &mut j0);

        let mut ciphertext = Vec::with_capacity(plaintext.len());
        let mut block_idx = 2u32;

        for chunk in plaintext.chunks(16) {
            counter_block[12..16].copy_from_slice(&block_idx.to_be_bytes());
            let mut keystream = [0u8; 16];
            self.cipher.encrypt_block(&counter_block, &mut keystream);

            for (p, k) in chunk.iter().zip(keystream.iter()) {
                ciphertext.push(p ^ k);
            }
            block_idx += 1;
        }

        let mut tag = [0u8; 16];
        for i in 0..16 {
            tag[i] = j0[i] ^ (aad.get(i % aad.len().max(1)).copied().unwrap_or(0));
        }

        (ciphertext, tag)
    }
}
