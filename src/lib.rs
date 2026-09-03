//! Cryptographic Toy Ciphers and Cryptanalysis Library.

pub mod caesar;
pub mod vigenere;
pub mod substitution;
pub mod diffie_hellman;
pub mod enigma;
pub mod rsa;
pub mod hash;
pub mod aes_toy;

#[cfg(test)]
mod tests;

pub trait Cipher {
    fn encrypt(&self, plaintext: &str) -> String;
    fn decrypt(&self, ciphertext: &str) -> String;
}
