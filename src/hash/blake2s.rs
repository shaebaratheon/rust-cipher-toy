//! BLAKE2s Cryptographic Hash Function (RFC 7693).

pub struct Blake2s {
    h: [u32; 8],
    t: [u32; 2],
    f: [u32; 2],
    buf: [u8; 64],
    buflen: usize,
}

pub const BLAKE2S_IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

impl Blake2s {
    pub fn new(outlen: usize) -> Self {
        let mut h = BLAKE2S_IV;
        h[0] ^= 0x01010000 ^ (outlen as u32);
        Blake2s {
            h,
            t: [0, 0],
            f: [0, 0],
            buf: [0u8; 64],
            buflen: 0,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        for &b in data {
            if self.buflen == 64 {
                self.t[0] = self.t[0].wrapping_add(64);
                self.buflen = 0;
            }
            self.buf[self.buflen] = b;
            self.buflen += 1;
        }
    }
}
