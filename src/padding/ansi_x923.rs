//! ANSI X9.23 and ISO/IEC 7816-4 Cryptographic Block Padding.

pub struct AnsiX923;

impl AnsiX923 {
    pub fn pad(data: &[u8], block_size: usize) -> Vec<u8> {
        let pad_len = block_size - (data.len() % block_size);
        let mut out = Vec::with_capacity(data.len() + pad_len);
        out.extend_from_slice(data);
        for _ in 0..(pad_len - 1) {
            out.push(0x00);
        }
        out.push(pad_len as u8);
        out
    }

    pub fn unpad(padded: &[u8]) -> Result<&[u8], &'static str> {
        if padded.is_empty() { return Err("Empty buffer"); }
        let pad_len = padded[padded.len() - 1] as usize;
        if pad_len == 0 || pad_len > padded.len() { return Err("Invalid padding length"); }
        for i in (padded.len() - pad_len)..(padded.len() - 1) {
            if padded[i] != 0x00 { return Err("Corrupt padding bytes"); }
        }
        Ok(&padded[..padded.len() - pad_len])
    }
}
