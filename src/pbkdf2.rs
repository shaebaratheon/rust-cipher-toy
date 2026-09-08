use crate::hmac::HmacSha256;

pub struct Pbkdf2;

impl Pbkdf2 {
    pub fn derive(password: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) {
        let mut block_idx = 1u32;
        let mut offset = 0;

        while offset < out.len() {
            let mut u = {
                let mut h = HmacSha256::new(password);
                h.update(salt);
                h.update(&block_idx.to_be_bytes());
                h.finalize()
            };
            let mut t = u;

            for _ in 1..iterations {
                let mut h = HmacSha256::new(password);
                h.update(&u);
                u = h.finalize();
                for i in 0..32 {
                    t[i] ^= u[i];
                }
            }

            let to_copy = std::cmp::min(32, out.len() - offset);
            out[offset..offset + to_copy].copy_from_slice(&t[..to_copy]);
            offset += to_copy;
            block_idx += 1;
        }
    }
}
