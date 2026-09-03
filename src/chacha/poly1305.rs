//! Poly1305 One-Time MAC Authenticator RFC 7539.

pub struct Poly1305 {
    r: [u32; 5],
    h: [u32; 5],
    pad: [u32; 4],
}

impl Poly1305 {
    pub fn new(key: &[u8; 32]) -> Self {
        let mut r = [0u32; 5];
        r[0] = (u32::from_le_bytes([key[0], key[1], key[2], key[3]]) & 0x0fffffff) >> 0;
        r[1] = (u32::from_le_bytes([key[3], key[4], key[5], key[6]]) & 0x0ffffffc) >> 2;
        r[2] = (u32::from_le_bytes([key[6], key[7], key[8], key[9]]) & 0x0ffffffc) >> 4;
        r[3] = (u32::from_le_bytes([key[9], key[10], key[11], key[12]]) & 0x0ffffffc) >> 6;
        r[4] = (u32::from_le_bytes([key[12], key[13], key[14], key[15]]) & 0x0ffffffc) >> 8;

        let mut pad = [0u32; 4];
        for i in 0..4 {
            pad[i] = u32::from_le_bytes([key[16 + i * 4], key[17 + i * 4], key[18 + i * 4], key[19 + i * 4]]);
        }

        Poly1305 { r, h: [0; 5], pad }
    }
}
