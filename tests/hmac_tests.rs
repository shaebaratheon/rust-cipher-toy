//! RFC 4231 Known Answer Tests for HMAC-SHA256.

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn test_rfc4231_case_1() {
        let key = [0x0bu8; 20];
        let data = b"Hi There";
        let mac = crate::mac::hmac::hmac_sha256(&key, data);
        let expected = hex_to_bytes("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
        assert_eq!(&mac[..], expected.as_slice());
    }

    #[test]
    fn test_rfc4231_case_2() {
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let mac = crate::mac::hmac::hmac_sha256(key, data);
        let expected = hex_to_bytes("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
        assert_eq!(&mac[..], expected.as_slice());
    }
}
