// Basic Caesar Cipher implementation
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

fn main() {
    let message = "Hello, GitHub!";
    let shift = 3;
    
    let encrypted = caesar_encrypt(message, shift);
    let decrypted = caesar_decrypt(&encrypted, shift);
    
    println!("Original:  {}", message);
    println!("Encrypted: {}", encrypted);
    println!("Decrypted: {}", decrypted);
}
