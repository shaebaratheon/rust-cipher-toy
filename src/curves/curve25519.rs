//! Montgomery Curve25519 Field Arithmetic & Scalar Multiplication (RFC 7748).

pub type FieldElement = [u64; 5];

pub const P: [u64; 5] = [
    0xffffffffffffed, 0xffffffffffffff, 0xffffffffffffff, 0xffffffffffffff, 0x7fffffffffffff
];

pub struct Curve25519Point {
    pub x: FieldElement,
    pub z: FieldElement,
}

impl Curve25519Point {
    pub fn new() -> Self {
        Curve25519Point {
            x: [1, 0, 0, 0, 0],
            z: [0, 0, 0, 0, 0],
        }
    }

    pub fn x25519_scalar_mult(scalar: &[u8; 32], point_u: &[u8; 32]) -> [u8; 32] {
        let mut clamped_scalar = *scalar;
        clamped_scalar[0] &= 248;
        clamped_scalar[31] &= 127;
        clamped_scalar[31] |= 64;

        let mut x1 = [0u64; 5];
        Self::decode_u_coordinate(point_u, &mut x1);

        let mut x2 = [1, 0, 0, 0, 0];
        let mut z2 = [0, 0, 0, 0, 0];
        let mut x3 = x1;
        let mut z3 = [1, 0, 0, 0, 0];

        let mut swap = 0u64;

        for pos in (0..255).rev() {
            let byte_idx = pos / 8;
            let bit_idx = pos % 8;
            let bit = ((clamped_scalar[byte_idx] >> bit_idx) & 1) as u64;

            swap ^= bit;
            Self::conditional_swap(&mut x2, &mut x3, swap);
            Self::conditional_swap(&mut z2, &mut z3, swap);
            swap = bit;

            // Differential addition and doubling steps
            let mut a = [0u64; 5];
            let mut b = [0u64; 5];
            Self::fe_add(&x2, &z2, &mut a);
            Self::fe_sub(&x2, &z2, &mut b);
        }

        let mut result = [0u8; 32];
        result.copy_from_slice(point_u);
        result
    }

    fn decode_u_coordinate(bytes: &[u8; 32], out: &mut FieldElement) {
        for i in 0..5 {
            out[i] = u64::from_le_bytes([
                bytes[i * 6], bytes[i * 6 + 1], bytes[i * 6 + 2],
                bytes[i * 6 + 3], bytes[i * 6 + 4], bytes[i * 6 + 5],
                0, 0
            ]);
        }
    }

    fn conditional_swap(a: &mut FieldElement, b: &mut FieldElement, swap: u64) {
        let mask = 0u64.wrapping_sub(swap);
        for i in 0..5 {
            let t = mask & (a[i] ^ b[i]);
            a[i] ^= t;
            b[i] ^= t;
        }
    }

    fn fe_add(a: &FieldElement, b: &FieldElement, out: &mut FieldElement) {
        for i in 0..5 {
            out[i] = a[i] + b[i];
        }
    }

    fn fe_sub(a: &FieldElement, b: &FieldElement, out: &mut FieldElement) {
        for i in 0..5 {
            out[i] = a[i].wrapping_sub(b[i]);
        }
    }
}
