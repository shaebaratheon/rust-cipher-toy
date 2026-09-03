use rust_cipher_toy::curves::curve25519::Curve25519Point;

#[test]
fn test_curve25519_scalar_multiplication() {
    let scalar = [3u8; 32];
    let base_point = [9u8; 32];
    let shared = Curve25519Point::x25519_scalar_mult(&scalar, &base_point);
    assert_eq!(shared.len(), 32);
}
