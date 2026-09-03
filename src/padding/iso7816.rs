//! ISO/IEC 7816-4 Bit Padding (0x80 followed by 0x00).

pub struct Iso7816;

impl Iso7816 {
    pub fn pad(data: &[u8], block_size: usize) -> Vec<u8> {
        let pad_len = block_size - (data.len() % block_size);
        let mut out = Vec::with_capacity(data.len() + pad_len);
        out.extend_from_slice(data);
        out.push(0x80);
        for _ in 1..pad_len {
            out.push(0x00);
        }
        out
    }

    pub fn unpad(padded: &[u8]) -> Result<&[u8], &'static str> {
        if padded.is_empty() { return Err("Empty buffer"); }
        let mut idx = padded.len();
        while idx > 0 && padded[idx - 1] == 0x00 {
            idx -= 1;
        }
        if idx == 0 || padded[idx - 1] != 0x80 {
            return Err("Invalid ISO7816 padding byte");
        }
        Ok(&padded[..idx - 1])
    }
}
