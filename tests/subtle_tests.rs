use rust_cipher_toy::subtle::constant_time_eq;

#[test]
fn test_constant_time_eq_matching() {
    let buf1 = [1, 2, 3, 4, 5];
    let buf2 = [1, 2, 3, 4, 5];
    assert!(constant_time_eq(&buf1, &buf2));
}

#[test]
fn test_constant_time_eq_mismatch() {
    let buf1 = [1, 2, 3, 4, 5];
    let buf2 = [1, 2, 3, 4, 6];
    assert!(!constant_time_eq(&buf1, &buf2));
}

#[test]
fn test_constant_time_eq_different_length() {
    let buf1 = [1, 2, 3];
    let buf2 = [1, 2, 3, 4];
    assert!(!constant_time_eq(&buf1, &buf2));
}
