use crate::caesar::CaesarCipher;
use crate::diffie_hellman::DiffieHellmanGroup;
use crate::substitution::SubstitutionCipher;
use crate::vigenere::VigenereCipher;
use crate::Cipher;

#[test]
fn test_caesar_roundtrip() {
    let cipher = CaesarCipher::new(7);
    let original = "The quick brown fox jumps over the lazy dog! 1234";
    let encrypted = cipher.encrypt(original);
    let decrypted = cipher.decrypt(&encrypted);
    assert_eq!(original, decrypted);
}

#[test]
fn test_caesar_auto_crack() {
    let text = "Cryptography is the practice and study of techniques for secure communication in the presence of adversarial third parties.";
    let cipher = CaesarCipher::new(13);
    let encrypted = cipher.encrypt(text);
    let (shift, cracked) = CaesarCipher::crack(&encrypted);
    assert_eq!(shift, 13);
    assert_eq!(text, cracked);
}

#[test]
fn test_vigenere_roundtrip() {
    let cipher = VigenereCipher::new("SECRETKEY");
    let original = "Defend the east wall of the castle at dawn!";
    let encrypted = cipher.encrypt(original);
    let decrypted = cipher.decrypt(&encrypted);
    assert_eq!(original, decrypted);
}

#[test]
fn test_substitution_roundtrip() {
    let alphabet = "QWERTYUIOPASDFGHJKLZXCVBNM";
    let cipher = SubstitutionCipher::from_alphabet(alphabet);
    let original = "Hello World! Monoalphabetic substitution preserved.";
    let encrypted = cipher.encrypt(original);
    let decrypted = cipher.decrypt(&encrypted);
    assert_eq!(original, decrypted);
}

#[test]
fn test_diffie_hellman_shared_secret() {
    let group = DiffieHellmanGroup::RFC3526_MODP_768_TOY;
    let alice_priv = 123456789;
    let bob_priv = 987654321;

    let alice_pub = group.compute_public_key(alice_priv);
    let bob_pub = group.compute_public_key(bob_priv);

    let alice_secret = group.compute_shared_secret(bob_pub, alice_priv);
    let bob_secret = group.compute_shared_secret(alice_pub, bob_priv);

    assert_eq!(alice_secret, bob_secret);
    assert!(alice_secret > 0);
}
use crate::enigma::{EnigmaMachine, Plugboard, Reflector, Rotor};
use crate::rsa::RsaKeyPair;

#[test]
fn test_enigma_reciprocal_property() {
    let plugboard1 = Plugboard::new("AV BS CG DL FU HZ IN KM OW RX");
    let mut enigma1 = EnigmaMachine::new(
        Rotor::rotor_i(),
        Rotor::rotor_ii(),
        Rotor::rotor_iii(),
        Reflector::reflector_b(),
        plugboard1,
    );

    let plugboard2 = Plugboard::new("AV BS CG DL FU HZ IN KM OW RX");
    let mut enigma2 = EnigmaMachine::new(
        Rotor::rotor_i(),
        Rotor::rotor_ii(),
        Rotor::rotor_iii(),
        Reflector::reflector_b(),
        plugboard2,
    );

    let plaintext = "TOPSECRETOPERATIONNEPTUNE";
    let encrypted = enigma1.process_string(plaintext);
    let decrypted = enigma2.process_string(&encrypted);

    assert_eq!(plaintext, decrypted);
    assert_ne!(plaintext, encrypted);
}

#[test]
fn test_rsa_roundtrip() {
    let keypair = RsaKeyPair::generate_toy_keypair(61, 53, 17).unwrap();
    let original = b"Hello RSA!";
    let encrypted = keypair.encrypt_bytes(original);
    let decrypted = keypair.decrypt_bytes(&encrypted);

    assert_eq!(original.to_vec(), decrypted);
}
use crate::hash::{Sha256, hmac_sha256};

#[test]
fn test_sha256_empty_string() {
    let hasher = Sha256::new();
    let digest = hasher.finalize();
    // SHA256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    assert_eq!(digest[0], 0xe3);
    assert_eq!(digest[1], 0xb0);
    assert_eq!(digest[2], 0xc4);
    assert_eq!(digest[3], 0x42);
}

#[test]
fn test_sha256_standard_vector() {
    let mut hasher = Sha256::new();
    hasher.update(b"abc");
    let digest = hasher.finalize();
    // SHA256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    assert_eq!(digest[0], 0xba);
    assert_eq!(digest[1], 0x78);
    assert_eq!(digest[2], 0x16);
    assert_eq!(digest[3], 0xbf);
}

#[test]
fn test_hmac_sha256_computation() {
    let key = b"secret-key-12345";
    let message = b"sample authenticated payload";
    let mac = hmac_sha256(key, message);
    assert_ne!(mac, [0u8; 32]);
}
