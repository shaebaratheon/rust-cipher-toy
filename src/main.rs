fn caesar_encrypt(text: &str, shift: u8) -> String {
    text.chars()
        .map(|c| {
            if c.is_ascii_alphabetic() {
                let first = if c.is_ascii_lowercase() { b'a' } else { b'A' };
                let shift = (c as u8 - first + shift) % 26;
                (first + shift) as char
            } else {
                c
            }
        })
        .collect()
}

fn caesar_decrypt(text: &str, shift: u8) -> String {
    caesar_encrypt(text, 26 - (shift % 26))
}

// Vigenere Cipher implementation
fn vigenere_encrypt(text: &str, key: &str) -> String {
    let mut result = String::new();
    let key_bytes: Vec<u8> = key.to_ascii_lowercase().bytes().map(|b| b - b'a').collect();
    let mut key_idx = 0;

    for c in text.chars() {
        if c.is_ascii_alphabetic() {
            let first = if c.is_ascii_lowercase() { b'a' } else { b'A' };
            let shift = key_bytes[key_idx % key_bytes.len()];
            let shifted = (c as u8 - first + shift) % 26;
            result.push((first + shifted) as char);
            key_idx += 1;
        } else {
            result.push(c);
        }
    }
    result
}

fn main() {
    let message = "Hello, GitHub!";
    
    // Caesar
    let shift = 3;
    let enc_c = caesar_encrypt(message, shift);
    println!("Caesar Encrypted: {}", enc_c);
    
    // Vigenere
    let key = "limo";
    let enc_v = vigenere_encrypt(message, key);
    println!("Vigenere Encrypted: {}", enc_v);
}
// RSA Primitive (Toy)\n// Heavily CPU bound, consider rayon or tokio::spawn_blocking\nfn rsa_sign_stub() {}\nfn rsa_verify_stub() {}
