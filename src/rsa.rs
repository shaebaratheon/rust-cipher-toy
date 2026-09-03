//! Educational Toy RSA implementation showcasing modular arithmetic, extended GCD,
//! and Montgomery exponentiation.

pub struct RsaKeyPair {
    pub n: u64,
    pub e: u64,
    pub d: u64,
}

impl RsaKeyPair {
    pub fn generate_toy_keypair(p: u64, q: u64, e: u64) -> Result<Self, String> {
        if p == q {
            return Err("Primes p and q must be distinct.".to_string());
        }
        let n = p * q;
        let phi = (p - 1) * (q - 1);

        if gcd(e, phi) != 1 {
            return Err("Public exponent e must be coprime to phi(n).".to_string());
        }

        let d = match mod_inverse(e as i128, phi as i128) {
            Some(inv) => inv as u64,
            None => return Err("Failed to compute modular inverse.".to_string()),
        };
        Ok(Self { n, e, d })
    }

    pub fn encrypt(&self, message: u64) -> u64 {
        assert!(message < self.n, "Message must be smaller than modulus n.");
        mod_pow(message, self.e, self.n)
    }

    pub fn decrypt(&self, ciphertext: u64) -> u64 {
        mod_pow(ciphertext, self.d, self.n)
    }

    pub fn encrypt_bytes(&self, data: &[u8]) -> Vec<u64> {
        data.iter().map(|&b| self.encrypt(b as u64)).collect()
    }

    pub fn decrypt_bytes(&self, ciphertexts: &[u64]) -> Vec<u8> {
        ciphertexts.iter().map(|&c| self.decrypt(c) as u8).collect()
    }
}

pub fn gcd(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        let temp = b;
        b = a % b;
        a = temp;
    }
    a
}

pub fn extended_gcd(a: i128, b: i128) -> (i128, i128, i128) {
    if a == 0 {
        (b, 0, 1)
    } else {
        let (g, x1, y1) = extended_gcd(b % a, a);
        let x = y1 - (b / a) * x1;
        let y = x1;
        (g, x, y)
    }
}

pub fn mod_inverse(a: i128, m: i128) -> Option<i128> {
    let (g, x, _) = extended_gcd(a, m);
    if g != 1 {
        None
    } else {
        Some((x % m + m) % m)
    }
}

pub fn mod_pow(mut base: u64, mut exp: u64, modulus: u64) -> u64 {
    if modulus == 1 {
        return 0;
    }
    let mut result: u64 = 1;
    base %= modulus;

    while exp > 0 {
        if exp % 2 == 1 {
            result = ((result as u128 * base as u128) % modulus as u128) as u64;
        }
        exp >>= 1;
        base = ((base as u128 * base as u128) % modulus as u128) as u64;
    }
    result
}
