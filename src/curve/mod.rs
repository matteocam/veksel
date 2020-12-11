mod curve;
mod permissible;
mod rerandomize;
mod windows;

use rand::Rng;
use rand::RngCore;

use bulletproofs::r1cs::*;
use curve25519_dalek::scalar::Scalar;

pub use windows::fp_inner::Fp256 as FpInner;

impl FpInner {
    pub fn random<R: RngCore>(rng: &mut R) -> Self {
        let limbs: [u8; 32] = rng.gen();
        limbs.into()
    }
}

pub use rerandomize::{RandomizationWitness, Rerandomization};

#[derive(Copy, Clone, Debug)]
pub struct PointValue {
    pub x: Scalar,
    pub y: Scalar,
}

#[derive(Copy, Clone, Debug)]
pub struct Point {
    pub x: Variable,
    pub y: Variable,
}

impl Point {
    fn free<CS: ConstraintSystem>(cs: &mut CS) -> Result<Self, R1CSError> {
        let x = cs.allocate(None)?;
        let y = cs.allocate(None)?;
        Ok(Point { x, y })
    }
}

impl PointValue {
    fn check(&self, d: Scalar) -> bool {
        let x2 = self.x * self.x;
        let y2 = self.y * self.y;
        x2 + y2 == Scalar::one() + d * x2 * y2
    }

    fn assign<CS: ConstraintSystem>(&self, cs: &mut CS) -> Result<Point, R1CSError> {
        let x = cs.allocate(Some(self.x))?;
        let y = cs.allocate(Some(self.y))?;
        Ok(Point { x, y })
    }
}

// convert a scalar into little-endian bits
pub fn bits(s: Scalar) -> Vec<bool> {
    let mut v: Vec<bool> = Vec::with_capacity(256);
    for byte in s.as_bytes().iter() {
        let mut bits: u8 = *byte;
        // low nibble
        v.push((bits & 1) != 0);
        bits >>= 1;
        v.push((bits & 1) != 0);
        bits >>= 1;
        v.push((bits & 1) != 0);
        bits >>= 1;
        v.push((bits & 1) != 0);
        bits >>= 1;

        // high nibble
        v.push((bits & 1) != 0);
        bits >>= 1;
        v.push((bits & 1) != 0);
        bits >>= 1;
        v.push((bits & 1) != 0);
        bits >>= 1;
        v.push((bits & 1) != 0);
        debug_assert_eq!(bits >> 1, 0);
    }
    v
}
