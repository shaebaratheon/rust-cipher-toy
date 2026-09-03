//! SHA-512 Cryptographic Hash Implementation (FIPS PUB 180-4).

pub struct Sha512 {
    state: [u64; 8],
    buffer: [u8; 128],
    buf_len: usize,
    total_len: u128,
}

impl Sha512 {
    pub fn new() -> Self {
        Sha512 {
            state: [
                0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
                0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
            ],
            buffer: [0u8; 128],
            buf_len: 0,
            total_len: 0,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        let mut idx = 0;
        self.total_len += data.len() as u128;
        while idx < data.len() {
            let to_copy = (128 - self.buf_len).min(data.len() - idx);
            self.buffer[self.buf_len..self.buf_len + to_copy].copy_from_slice(&data[idx..idx + to_copy]);
            self.buf_len += to_copy;
            idx += to_copy;

            if self.buf_len == 128 {
                self.transform(&self.buffer);
                self.buf_len = 0;
            }
        }
    }

    fn transform(&mut self, chunk: &[u8; 128]) {
        // Internal 80-round compression
        let mut w = [0u64; 80];
        for i in 0..16 {
            let b = &chunk[i * 8..i * 8 + 8];
            w[i] = u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
        }
        for i in 16..80 {
            let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
            let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }
    }
}
