mod curve;
mod permissible;
mod window;

use rand::{Rng, RngCore};

use bulletproofs::r1cs::*;
use curve25519_dalek::scalar::Scalar;

pub use curve::fp_inner::Fp256 as FpInner;
pub use permissible::{Permissible, PermissibleWitness};
pub use window::{FixScalarMult, FixScalarMultWitness};

impl curve::Fp {
    pub fn random<R: RngCore>(rng: &mut R) -> Self {
        let limbs: [u8; 32] = rng.gen();
        limbs.into()
    }
}

pub struct Statement {
    rerandomize: FixScalarMult,
    permissible: Permissible,
}

pub struct StatementWitness {}

impl Statement {
    pub fn find_permissible_randomness<R: RngCore>(
        &self,
        rng: &mut R,
        xy: PointValue,
    ) -> curve::Fp {
        loop {
            let r = curve::Fp::random(rng); // commitment randomness
            let c = self.rerandomize.compute(r, xy); // randomized commitment
            if self.permissible.is_permissible(c) {
                break r;
            }
        }
    }

    pub fn witness(
        &self,
        xy: PointValue, // commitment without randomness
        r: curve::Fp,   // randomness for Pedersen commitment
    ) -> StatementWitness {
        let permissble = self.permissible.witness(xy);
        unimplemented!()
    }

    pub fn gadget<CS: ConstraintSystem>() {}
}

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
    pub fn identity() -> Self {
        Self {
            x: Scalar::one(),
            y: Scalar::zero(),
        }
    }

    pub fn check(&self, d: Scalar) -> bool {
        let x2 = self.x * self.x;
        let y2 = self.y * self.y;
        x2 + y2 == Scalar::one() + d * x2 * y2
    }

    pub fn assign<CS: ConstraintSystem>(&self, cs: &mut CS) -> Result<Point, R1CSError> {
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
