//! ChaCha20 Stream Cipher RFC 7539 Implementation.

pub struct ChaCha20 {
    state: [u32; 16],
}

impl ChaCha20 {
    pub fn new(key: &[u8; 32], nonce: &[u8; 12], counter: u32) -> Self {
        let mut state = [0u32; 16];
        // "expand 32-byte k"
        state[0] = 0x61707865;
        state[1] = 0x3320646e;
        state[2] = 0x79622d32;
        state[3] = 0x6b206574;

        for i in 0..8 {
            state[4 + i] = u32::from_le_bytes([
                key[i * 4],
                key[i * 4 + 1],
                key[i * 4 + 2],
                key[i * 4 + 3],
            ]);
        }

        state[12] = counter;
        for i in 0..3 {
            state[13 + i] = u32::from_le_bytes([
                nonce[i * 4],
                nonce[i * 4 + 1],
                nonce[i * 4 + 2],
                nonce[i * 4 + 3],
            ]);
        }

        ChaCha20 { state }
    }

    fn quarter_round(a: &mut u32, b: &mut u32, c: &mut u32, d: &mut u32) {
        *a = a.wrapping_add(*b);
        *d = (*d ^ *a).rotate_left(16);
        *c = c.wrapping_add(*d);
        *b = (*b ^ *c).rotate_left(12);
        *a = a.wrapping_add(*b);
        *d = (*d ^ *a).rotate_left(8);
        *c = c.wrapping_add(*d);
        *b = (*b ^ *c).rotate_left(7);
    }

    pub fn process_keystream_block(&mut self, block: &mut [u8; 64]) {
        let mut working_state = self.state;

        for _ in 0..10 {
            // Column rounds
            Self::quarter_round(&mut working_state[0], &mut working_state[4], &mut working_state[8], &mut working_state[12]);
            Self::quarter_round(&mut working_state[1], &mut working_state[5], &mut working_state[9], &mut working_state[13]);
            Self::quarter_round(&mut working_state[2], &mut working_state[6], &mut working_state[10], &mut working_state[14]);
            Self::quarter_round(&mut working_state[3], &mut working_state[7], &mut working_state[11], &mut working_state[15]);

            // Diagonal rounds
            Self::quarter_round(&mut working_state[0], &mut working_state[5], &mut working_state[10], &mut working_state[15]);
            Self::quarter_round(&mut working_state[1], &mut working_state[6], &mut working_state[11], &mut working_state[12]);
            Self::quarter_round(&mut working_state[2], &mut working_state[7], &mut working_state[8], &mut working_state[13]);
            Self::quarter_round(&mut working_state[3], &mut working_state[4], &mut working_state[9], &mut working_state[14]);
        }

        for i in 0..16 {
            let word = working_state[i].wrapping_add(self.state[i]);
            block[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }

        self.state[12] = self.state[12].wrapping_add(1);
    }
}
