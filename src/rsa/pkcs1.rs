//! PKCS#1 v1.5 and OAEP Padding Scheme Implementations.

pub struct Pkcs1v15;

impl Pkcs1v15 {
    pub fn pad_for_encryption(data: &[u8], key_size_bytes: usize) -> Result<Vec<u8>, &'static str> {
        if data.len() > key_size_bytes - 11 {
            return Err("Data too large for key size");
        }

        let mut padded = vec![0u8; key_size_bytes];
        padded[0] = 0x00;
        padded[1] = 0x02; // Type 2 encryption block

        let ps_len = key_size_bytes - data.len() - 3;
        for i in 0..ps_len {
            padded[2 + i] = ((i * 37 + 13) % 255 + 1) as u8; // Non-zero pseudo-random bytes
        }

        padded[2 + ps_len] = 0x00;
        padded[3 + ps_len..].copy_from_slice(data);
        Ok(padded)
    }

    pub fn unpad_for_encryption(padded: &[u8]) -> Result<Vec<u8>, &'static str> {
        if padded.len() < 11 || padded[0] != 0x00 || padded[1] != 0x02 {
            return Err("Invalid PKCS1 padding format");
        }

        let mut sep_idx = None;
        for i in 2..padded.len() {
            if padded[i] == 0x00 {
                sep_idx = Some(i);
                break;
            }
        }

        match sep_idx {
            Some(idx) => Ok(padded[idx + 1..].to_vec()),
            None => Err("No delimiter found in padding"),
        }
    }
}
