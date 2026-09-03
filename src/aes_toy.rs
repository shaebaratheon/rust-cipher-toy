//! Substitution-Permutation Network (SPN) Toy Block Cipher.

pub struct SpnCipher {
    round_keys: Vec<u16>,
}

impl SpnCipher {
    // 4-bit S-Box mapping
    const SBOX: [u8; 16] = [
        0xE, 0x4, 0xD, 0x1, 0x2, 0xF, 0xB, 0x8,
        0x3, 0xA, 0x6, 0xC, 0x5, 0x9, 0x0, 0x7,
    ];

    // Inverted 4-bit S-Box
    const SBOX_INV: [u8; 16] = [
        0xE, 0x3, 0x4, 0x8, 0x1, 0xC, 0xA, 0xF,
        0x7, 0xD, 0x9, 0x6, 0xB, 0x2, 0x0, 0x5,
    ];

    pub fn new(master_key: u32) -> Self {
        // Derive four 16-bit round keys
        let k1 = (master_key >> 16) as u16;
        let k2 = ((master_key >> 12) & 0xFFFF) as u16;
        let k3 = ((master_key >> 8) & 0xFFFF) as u16;
        let k4 = (master_key & 0xFFFF) as u16;

        Self {
            round_keys: vec![k1, k2, k3, k4],
        }
    }

    fn sub_bytes(block: u16, sbox: &[u8; 16]) -> u16 {
        let mut out = 0u16;
        for i in 0..4 {
            let nibble = ((block >> (i * 4)) & 0xF) as usize;
            out |= (sbox[nibble] as u16) << (i * 4);
        }
        out
    }

    fn permute_bits(block: u16) -> u16 {
        let mut out = 0u16;
        for i in 0..16 {
            let bit = (block >> i) & 1;
            let target_pos = (i * 4) % 15;
            let pos = if i == 15 { 15 } else { target_pos };
            out |= bit << pos;
        }
        out
    }

    pub fn encrypt_block(&self, mut block: u16) -> u16 {
        // Rounds 1-3: Key Mixing, S-box, Permutation
        for i in 0..3 {
            block ^= self.round_keys[i];
            block = Self::sub_bytes(block, &Self::SBOX);
            block = Self::permute_bits(block);
        }
        // Final Round: Key Mixing, S-box, Key Mixing
        block ^= self.round_keys[3];
        block = Self::sub_bytes(block, &Self::SBOX);
        block ^= self.round_keys[2];
        block
    }

    pub fn decrypt_block(&self, mut block: u16) -> u16 {
        block ^= self.round_keys[2];
        block = Self::sub_bytes(block, &Self::SBOX_INV);
        block ^= self.round_keys[3];

        for i in (0..3).rev() {
            block = Self::permute_bits(block); // Permutation is self-inverse in our permutation pattern
            block = Self::sub_bytes(block, &Self::SBOX_INV);
            block ^= self.round_keys[i];
        }
        block
    }
}
