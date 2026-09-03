use crate::caesar::{CaesarCipher, ENGLISH_FREQUENCIES};
use crate::Cipher;

pub struct VigenereCipher {
    key: Vec<u8>,
}

impl VigenereCipher {
    pub fn new(key_str: &str) -> Self {
        let key: Vec<u8> = key_str
            .chars()
            .filter(|c| c.is_ascii_alphabetic())
            .map(|c| c.to_ascii_lowercase() as u8 - b'a\)
            .collect();
        assert!(!key.is_empty(), "Key must contain at least one alphabetic character.");
        Self { key }
    }

    /// Calculates the Index of Coincidence (IoC) for a given text slice.
    pub fn index_of_coincidence(text: &str) -> f64 {
        let mut counts = [0usize; 26];
        let mut n = 0usize;

        for c in text.chars() {
            if c.is_ascii_alphabetic() {
                let idx = (c.to_ascii_lowercase() as u8 - b'a\) as usize;
                counts[idx] += 1;
                n += 1;
            }
        }

        if n <= 1 {
            return 0.0;
        }

        let sum: usize = counts.iter().map(|&cnt| cnt.saturating_sub(1) * cnt).sum();
        (sum as f64) / ((n * (n - 1)) as f64)
    }

    /// Estimates the key length by analyzing average IoC across interleaved slices.
    pub fn estimate_key_length(ciphertext: &str, max_len: usize) -> usize {
        let letters: Vec<char> = ciphertext.chars().filter(|c| c.is_ascii_alphabetic()).collect();
        let mut best_len = 1;
        let mut best_ioc_diff = f64::MAX;

        for k in 1..=max_len {
            let mut slice_iocs = Vec::new();
            for i in 0..k {
                let slice: String = letters.iter().skip(i).step_by(k).collect();
                slice_iocs.push(Self::index_of_coincidence(&slice));
            }
            let avg_ioc: f64 = slice_iocs.iter().sum::<f64>() / (slice_iocs.len() as f64);
            // English plaintext IoC is approximately 0.0667
            let diff = (avg_ioc - 0.0667).abs();
            if diff < best_ioc_diff {
                best_ioc_diff = diff;
                best_len = k;
            }
        }
        best_len
    }

    /// Automatically cracks a Vigenere ciphertext using IoC and Caesar slice frequency recovery.
    pub fn crack(ciphertext: &str, max_key_len: usize) -> (String, String) {
        let estimated_len = Self::estimate_key_length(ciphertext, max_key_len);
        let letters: Vec<char> = ciphertext.chars().filter(|c| c.is_ascii_alphabetic()).collect();
        let mut key_chars = Vec::new();

        for i in 0..estimated_len {
            let slice: String = letters.iter().skip(i).step_by(estimated_len).collect();
            let (shift, _) = CaesarCipher::crack(&slice);
            key_chars.push((b'a\ + shift) as char);
        }

        let key_str: String = key_chars.into_iter().collect();
        let cipher = VigenereCipher::new(&key_str);
        let plaintext = cipher.decrypt(ciphertext);
        (key_str, plaintext)
    }
}

impl Cipher for VigenereCipher {
    fn encrypt(&self, plaintext: &str) -> String {
        let mut result = String::new();
        let mut idx = 0;

        for c in plaintext.chars() {
            if c.is_ascii_alphabetic() {
                let base = if c.is_ascii_lowercase() { b'a\ } else { b'A\ };
                let shift = self.key[idx % self.key.len()];
                let shifted = (c as u8 - base + shift) % 26;
                result.push((base + shifted) as char);
                idx += 1;
            } else {
                result.push(c);
            }
        }
        result
    }

    fn decrypt(&self, ciphertext: &str) -> String {
        let mut result = String::new();
        let mut idx = 0;

        for c in ciphertext.chars() {
            if c.is_ascii_alphabetic() {
                let base = if c.is_ascii_lowercase() { b'a\ } else { b'A\ };
                let shift = self.key[idx % self.key.len()];
                let shifted = (c as u8 - base + 26 - shift) % 26;
                result.push((base + shifted) as char);
                idx += 1;
            } else {
                result.push(c);
            }
        }
        result
    }
}
