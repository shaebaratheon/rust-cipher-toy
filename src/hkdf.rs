use crate::hmac::HmacSha256;

pub struct Hkdf;

impl Hkdf {
    pub fn extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
        let mut hmac = HmacSha256::new(salt);
        hmac.update(ikm);
        hmac.finalize()
    }

    pub fn expand(prk: &[u8; 32], info: &[u8], out: &mut [u8]) {
        let mut t = Vec::new();
        let mut offset = 0;
        let mut counter: u8 = 1;

        while offset < out.len() {
            let mut hmac = HmacSha256::new(prk);
            if counter > 1 {
                hmac.update(&t);
            }
            hmac.update(info);
            hmac.update(&[counter]);
            t = hmac.finalize().to_vec();

            let to_copy = std::cmp::min(t.len(), out.len() - offset);
            out[offset..offset + to_copy].copy_from_slice(&t[..to_copy]);
            offset += to_copy;
            counter += 1;
        }
    }
}
