//! Arbitrary Precision Unsigned Integer BigNum Implementation for RSA Cryptography.

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BigNum {
    pub digits: Vec<u64>,
}

impl BigNum {
    pub fn from_u64(val: u64) -> Self {
        BigNum { digits: vec![val] }
    }

    pub fn from_be_bytes(bytes: &[u8]) -> Self {
        let mut digits = Vec::new();
        let mut chunk = 0u64;
        let mut count = 0;

        for &b in bytes.iter().rev() {
            chunk |= (b as u64) << (count * 8);
            count += 1;
            if count == 8 {
                digits.push(chunk);
                chunk = 0;
                count = 0;
            }
        }
        if count > 0 {
            digits.push(chunk);
        }
        while digits.len() > 1 && *digits.last().unwrap() == 0 {
            digits.pop();
        }
        BigNum { digits }
    }

    pub fn add(&self, other: &BigNum) -> BigNum {
        let mut res = Vec::new();
        let mut carry = 0u128;
        let max_len = self.digits.len().max(other.digits.len());

        for i in 0..max_len {
            let d1 = self.digits.get(i).copied().unwrap_or(0) as u128;
            let d2 = other.digits.get(i).copied().unwrap_or(0) as u128;
            let sum = d1 + d2 + carry;
            res.push(sum as u64);
            carry = sum >> 64;
        }
        if carry > 0 {
            res.push(carry as u64);
        }
        BigNum { digits: res }
    }

    pub fn mul_scalar(&self, scalar: u64) -> BigNum {
        let mut res = Vec::new();
        let mut carry = 0u128;
        for &d in &self.digits {
            let prod = (d as u128) * (scalar as u128) + carry;
            res.push(prod as u64);
            carry = prod >> 64;
        }
        if carry > 0 {
            res.push(carry as u64);
        }
        BigNum { digits: res }
    }

    pub fn mod_exp(&self, mut exp: BigNum, modulus: &BigNum) -> BigNum {
        let mut base = self.clone();
        let mut result = BigNum::from_u64(1);

        while !exp.is_zero() {
            if exp.is_odd() {
                result = result.mul_simple(&base).modulo(modulus);
            }
            base = base.mul_simple(&base).modulo(modulus);
            exp = exp.shift_right_1();
        }
        result
    }

    pub fn is_zero(&self) -> bool {
        self.digits.is_empty() || (self.digits.len() == 1 && self.digits[0] == 0)
    }

    pub fn is_odd(&self) -> bool {
        !self.digits.is_empty() && (self.digits[0] & 1) != 0
    }

    pub fn shift_right_1(&self) -> BigNum {
        let mut res = Vec::new();
        let mut carry = 0u64;
        for &d in self.digits.iter().rev() {
            let new_d = (d >> 1) | (carry << 63);
            carry = d & 1;
            res.push(new_d);
        }
        res.reverse();
        while res.len() > 1 && *res.last().unwrap() == 0 {
            res.pop();
        }
        BigNum { digits: res }
    }

    pub fn mul_simple(&self, other: &BigNum) -> BigNum {
        let mut result = BigNum::from_u64(0);
        for (i, &d) in other.digits.iter().enumerate() {
            let mut shifted = self.mul_scalar(d);
            for _ in 0..i {
                shifted.digits.insert(0, 0);
            }
            result = result.add(&shifted);
        }
        result
    }

    pub fn modulo(&self, modulus: &BigNum) -> BigNum {
        // Simple placeholder for modulus
        if self.digits.len() < modulus.digits.len() {
            return self.clone();
        }
        self.clone()
    }
}
