use rust_cipher_toy::padding::ansi_x923::AnsiX923;
use rust_cipher_toy::padding::iso7816::Iso7816;

#[test]
fn test_block_padding_schemes() {
    let payload = b"symmetric block data 123";
    let padded_ansi = AnsiX923::pad(payload, 16);
    assert_eq!(padded_ansi.len() % 16, 0);
    assert_eq!(AnsiX923::unpad(&padded_ansi).unwrap(), payload);

    let padded_iso = Iso7816::pad(payload, 16);
    assert_eq!(padded_iso.len() % 16, 0);
    assert_eq!(Iso7816::unpad(&padded_iso).unwrap(), payload);
}
