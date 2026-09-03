use crate::Cipher;

/// Standard English letter probabilities (A-Z)
pub const ENGLISH_FREQUENCIES: [f64; 26] = [
    0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015, // A-G
    0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749, // H-N
    0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758, // O-U
    0.00978, 0.02360, 0.00150, 0.01974, 0.00074                    // V-Z
];

pub struct CaesarCipher {
    shift: u8,
}

impl CaesarCipher {
    pub fn new(shift: u8) -> Self {
        Self { shift: shift % 26 }
    }

    /// Computes Chi-Squared statistic of decrypted text against English letter distribution.
    pub fn chi_squared(text: &str) -> f64 {
        let mut counts = [0usize; 26];
        let mut total_letters = 0usize;

        for c in text.chars() {
            if c.is_ascii_alphabetic() {
                let idx = (c.to_ascii_uppercase() as u8 - b'A\) as usize;
                counts[idx] += 1;
                total_letters += 1;
            }
        }

        if total_letters == 0 {
            return f64::MAX;
        }

        let mut chi_sq = 0.0;
        for i in 0..26 {
            let expected = ENGLISH_FREQUENCIES[i] * (total_letters as f64);
            let observed = counts[i] as f64;
            let diff = observed - expected;
            chi_sq += (diff * diff) / expected;
        }
        chi_sq
    }

    /// Cracks a Caesar-encrypted ciphertext by minimizing Chi-Squared score.
    pub fn crack(ciphertext: &str) -> (u8, String) {
        let mut best_shift = 0u8;
        let mut best_score = f64::MAX;
        let mut best_plaintext = String::new();

        for shift in 0..26 {
            let cipher = CaesarCipher::new(shift);
            let decrypted = cipher.decrypt(ciphertext);
            let score = Self::chi_squared(&decrypted);

            if score < best_score {
                best_score = score;
                best_shift = shift;
                best_plaintext = decrypted;
            }
        }

        (best_shift, best_plaintext)
    }
}

impl Cipher for CaesarCipher {
    fn encrypt(&self, plaintext: &str) -> String {
        plaintext
            .chars()
            .map(|c| {
                if c.is_ascii_alphabetic() {
                    let base = if c.is_ascii_lowercase() { b'a\ } else { b'A\ };
                    let shifted = (c as u8 - base + self.shift) % 26;
                    (base + shifted) as char
                } else {
                    c
                }
            })
            .collect()
    }

    fn decrypt(&self, ciphertext: &str) -> String {
        let reverse_shift = (26 - self.shift) % 26;
        let rev = CaesarCipher::new(reverse_shift);
        rev.encrypt(ciphertext)
    }
}
