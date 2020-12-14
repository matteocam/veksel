// Do not edit manually!
// This file was automatically generated by Sage (and cargo fmt).

use super::*;
use curve25519_dalek::scalar::Scalar;
use gridiron::*;

// size of inner field in bits
pub const FP_INNER_BITS: usize = 250;

pub use fp_inner::Fp256 as Fp;

// p = 1809251394333065553493296640760748560179195344757230816271751023405726101733
fp31!(
    fp_inner, // name of mode
    Fp256,    // name of class
    250,      // length of prime in bits
    9,        // length of prime in 2^31 limbs
    // prime number in limbs, least significant first
    [
        1932194021, 231403454, 2125940840, 1452728904, 2147483646, 2147483647, 2147483647,
        2147483647, 3
    ],
    // barrett
    [
        1783702321, 1334379781, 1814196019, 839442423, 829345052, 150706063, 526121713, 1347383704,
        0
    ],
    // montgomery R mod p
    [1610612736, 590693318, 2089632784, 1615998437, 710559597, 0, 0, 0, 0],
    // montgomery R^2 mod p
    [
        1893742786, 1346617643, 1315369536, 1112938958, 1285264874, 829345052, 150706063,
        526121713, 0
    ],
    1105244947
);

pub fn param_d() -> Scalar {
    Scalar::from_bits([
        0x33, 0xd1, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10,
    ])
}

pub fn identity() -> PointValue {
    PointValue {
        x: Scalar::zero(),
        y: Scalar::one(),
    }
}

pub fn generator() -> PointValue {
    PointValue {
        x: Scalar::from_bits([
            0xdb, 0x1e, 0x0a, 0x52, 0x13, 0x69, 0x32, 0x98, 0x03, 0x1a, 0x82, 0x2a, 0xbf, 0x67,
            0x1a, 0x52, 0xf1, 0x13, 0x27, 0x1b, 0x1f, 0xc3, 0xad, 0x18, 0x6d, 0x67, 0xd5, 0x34,
            0xa2, 0xec, 0x9e, 0x0f,
        ]),
        y: Scalar::from_bits([
            0x46, 0x69, 0xe7, 0xe0, 0xa7, 0x47, 0x35, 0x27, 0xc9, 0x33, 0xdc, 0x8c, 0x75, 0xd0,
            0xd0, 0xaa, 0x7f, 0xc7, 0x54, 0xe4, 0x18, 0x64, 0x96, 0xdd, 0xf4, 0x65, 0xaa, 0x66,
            0x85, 0xc2, 0x0f, 0x07,
        ]),
    }
}