use rust_cipher_toy::rsa::bignum::BigNum;

#[test]
fn test_bignum_addition_and_multiplication() {
    let a = BigNum::from_u64(0xFFFFFFFFFFFFFFFF);
    let b = BigNum::from_u64(1);
    let c = a.add(&b);
    assert_eq!(c.digits.len(), 2);
    assert_eq!(c.digits[0], 0);
    assert_eq!(c.digits[1], 1);
}
