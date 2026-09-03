//! Diffie-Hellman Key Exchange toy implementation using 64-bit arithmetic.

pub struct DiffieHellmanGroup {
    pub prime: u64,
    pub generator: u64,
}

impl DiffieHellmanGroup {
    pub const RFC3526_MODP_768_TOY: Self = Self {
        prime: 1000000007,
        generator: 5,
    };

    /// Modular exponentiation: (base^exp) % modulus in O(log exp) time.
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

    pub fn compute_public_key(&self, private_key: u64) -> u64 {
        Self::mod_pow(self.generator, private_key, self.prime)
    }

    pub fn compute_shared_secret(&self, peer_public_key: u64, own_private_key: u64) -> u64 {
        Self::mod_pow(peer_public_key, own_private_key, self.prime)
    }
}
