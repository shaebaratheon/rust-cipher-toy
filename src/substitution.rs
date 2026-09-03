use crate::Cipher;
use std::collections::HashMap;

pub struct SubstitutionCipher {
    forward_map: HashMap<char, char>,
    reverse_map: HashMap<char, char>,
}

impl SubstitutionCipher {
    /// Creates a substitution cipher from a 26-character permutation alphabet (A-Z).
    pub fn from_alphabet(alphabet: &str) -> Self {
        assert_eq!(alphabet.len(), 26, "Alphabet must have exactly 26 unique letters.");
        let mut forward_map = HashMap::new();
        let mut reverse_map = HashMap::new();

        let orig = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        for (o, s) in orig.chars().zip(alphabet.to_ascii_uppercase().chars()) {
            forward_map.insert(o, s);
            reverse_map.insert(s, o);
            forward_map.insert(o.to_ascii_lowercase(), s.to_ascii_lowercase());
            reverse_map.insert(s.to_ascii_lowercase(), o.to_ascii_lowercase());
        }

        Self {
            forward_map,
            reverse_map,
        }
    }

    /// Inverts the current substitution key.
    pub fn invert_key(alphabet: &str) -> String {
        let mut inverted = vec!['A\; 26];
        for (orig_idx, c) in alphabet.to_ascii_uppercase().chars().enumerate() {
            let target_idx = (c as u8 - b'A\) as usize;
            inverted[target_idx] = (b'A\ + orig_idx as u8) as char;
        }
        inverted.into_iter().collect()
    }
}

impl Cipher for SubstitutionCipher {
    fn encrypt(&self, plaintext: &str) -> String {
        plaintext
            .chars()
            .map(|c| *self.forward_map.get(&c).unwrap_or(&c))
            .collect()
    }

    fn decrypt(&self, ciphertext: &str) -> String {
        ciphertext
            .chars()
            .map(|c| *self.reverse_map.get(&c).unwrap_or(&c))
            .collect()
    }
}
