//! HMAC-SHA256 implementation complying with RFC 2104.

use crate::hash::sha256::Sha256;

const BLOCK_SIZE: usize = 64;
const OUTPUT_SIZE: usize = 32;

/// Computes the HMAC-SHA256 authentication code for a message.
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; OUTPUT_SIZE] {
    let mut actual_key = [0u8; BLOCK_SIZE];

    if key.len() > BLOCK_SIZE {
        let hashed = Sha256::digest(key);
        actual_key[..32].copy_from_slice(&hashed);
    } else {
        actual_key[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0u8; BLOCK_SIZE];
    let mut opad = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        ipad[i] = actual_key[i] ^ 0x36;
        opad[i] = actual_key[i] ^ 0x5c;
    }

    let mut inner = Sha256::new();
    inner.update(&ipad);
    inner.update(message);
    let inner_hash = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(&inner_hash);
    outer.finalize()
}
