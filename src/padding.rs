#[derive(Debug, PartialEq, Eq)]
pub enum PaddingError {
    InvalidBlockSize,
    EmptyBuffer,
    InvalidPadding,
}

pub struct Pkcs7;

impl Pkcs7 {
    pub fn pad(data: &[u8], block_size: usize) -> Result<Vec<u8>, PaddingError> {
        if block_size == 0 || block_size > 255 {
            return Err(PaddingError::InvalidBlockSize);
        }
        let pad_len = block_size - (data.len() % block_size);
        let mut out = data.to_vec();
        out.extend(std::iter::repeat(pad_len as u8).take(pad_len));
        Ok(out)
    }

    pub fn unpad(data: &[u8], block_size: usize) -> Result<Vec<u8>, PaddingError> {
        if block_size == 0 || block_size > 255 {
            return Err(PaddingError::InvalidBlockSize);
        }
        if data.is_empty() || data.len() % block_size != 0 {
            return Err(PaddingError::InvalidPadding);
        }
        let pad_len = *data.last().ok_or(PaddingError::EmptyBuffer)? as usize;
        if pad_len == 0 || pad_len > block_size {
            return Err(PaddingError::InvalidPadding);
        }
        for &b in &data[data.len() - pad_len..] {
            if b as usize != pad_len {
                return Err(PaddingError::InvalidPadding);
            }
        }
        Ok(data[..data.len() - pad_len].to_vec())
    }
}
