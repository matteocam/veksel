use bulletproofs::r1cs::*;
use curve25519_dalek::scalar::Scalar;

use std::iter::FromIterator;

use crate::misc::{one, Bit};

use super::*;

// x must be in a "small" range
pub const SIZE_X_BITS: usize = 250;

// the entire field
pub const SIZE_Y_BITS: usize = 253;

pub struct Permissible {
    powers: Vec<Scalar>,
    d: Scalar,
}

pub struct PermissibleWitness {
    x_bits: Vec<bool>,
    y_bits: Vec<bool>,
    point: PointValue,
}

impl Permissible {
    pub fn new(d: Scalar) -> Permissible {
        // pre-compute 2^i scalars
        let mut power = Scalar::one();
        let mut powers = Vec::with_capacity(255);
        for _ in 0..255 {
            powers.push(power);
            power = power + power;
        }
        Permissible { d, powers }
    }

    pub fn is_permissible(&self, p: PointValue) -> bool {
        let x_bytes = p.x.as_bytes();
        let y_bytes = p.y.as_bytes();

        // x[31] \in {0, 1} -> x \in [0, 2^250]
        // y mod 2 == 0
        p.check(self.d) && (x_bytes[31] < 4) && (y_bytes[0] & 1 == 0)
    }

    pub fn compute(&self, point: PointValue) -> PermissibleWitness {
        let mut x_bits = bits(point.x);
        let mut y_bits = bits(point.y);

        x_bits.truncate(SIZE_X_BITS);
        y_bits.truncate(SIZE_Y_BITS);

        debug_assert!(self.is_permissible(point));
        debug_assert_eq!(y_bits[0], false);

        PermissibleWitness {
            x_bits,
            y_bits,
            point,
        }
    }

    /// Checks that:
    ///
    /// x \in [0, 2^250)
    /// y = 0 \mod 2
    /// x^2 + y^2 = 1 - d * x^2 * y^2
    ///
    /// i.e. that (x, y) lies on the curve,
    /// x is "small" and y is canonical.
    pub fn gadget<CS: ConstraintSystem>(
        &self,
        cs: &mut CS,
        witness: Option<&PermissibleWitness>,
    ) -> Result<Point, R1CSError> {
        // restrict x and y bits
        let (x_bits, y_bits, m1, m2) = match witness {
            Some(w) => {
                // x_bits
                let mut x_bits = Vec::with_capacity(SIZE_X_BITS);
                for b in w.x_bits.iter().cloned() {
                    x_bits.push(Bit::new(cs, b)?);
                }

                // y_bits
                let mut y_bits = Vec::with_capacity(SIZE_Y_BITS);
                for b in w.y_bits.iter().cloned().skip(1) {
                    y_bits.push(Bit::new(cs, b)?);
                }

                // x_1, x_2, x2
                (
                    x_bits,
                    y_bits,
                    cs.allocate_multiplier(Some((w.point.x, w.point.x)))?,
                    cs.allocate_multiplier(Some((w.point.y, w.point.y)))?,
                )
            }
            None => {
                // x_bits
                let mut x_bits = Vec::with_capacity(SIZE_X_BITS);
                for _ in 0..SIZE_X_BITS {
                    x_bits.push(Bit::free(cs)?);
                }

                // y_bits
                let mut y_bits = Vec::with_capacity(SIZE_Y_BITS);
                for _ in 1..SIZE_Y_BITS {
                    y_bits.push(Bit::free(cs)?);
                }
                (
                    x_bits,
                    y_bits,
                    cs.allocate_multiplier(None)?,
                    cs.allocate_multiplier(None)?,
                )
            }
        };

        // compute x as a linear combination
        let x: LinearCombination = LinearCombination::from_iter(
            x_bits
                .into_iter()
                .map(|b| b.into())
                .zip(self.powers.iter().cloned()), // \sum_{i} y_i * 2^{i}
        );
        let (x_1, x_2, xx) = m1;
        cs.constrain(x_1 - x);
        cs.constrain(LinearCombination::from(x_1) - x_2);

        // compute y as a linear combination
        let y: LinearCombination = LinearCombination::from_iter(
            y_bits
                .into_iter()
                .map(|b| b.into())
                .zip(self.powers.iter().skip(1).cloned()), // \sum_{i} y_i * 2^{i + 1}
        );
        let (y_1, y_2, yy) = m2;
        cs.constrain(y_1 - y);
        cs.constrain(LinearCombination::from(y_1) - y_2);

        // check that x^2 + y^2 = 1 + d x^2 y^2
        let (_, _, xxyy) = cs.multiply(xx.into(), yy.into());
        cs.constrain((xx + yy) - one() - self.d * xxyy);
        Ok(Point { x: x_1, y: y_1 })
    }
}

mod tests {
    /*
    #[test]
    fn test_permissible() {
        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(2100, 1);
        let transcript = Transcript::new(b"Test");
        let mut prover = Prover::new(&pc_gens, transcript);

        let transcript = Transcript::new(b"Test");
        let mut verifier = Verifier::new(transcript);

        let randomize = Rerandomization::new();

        // compute witness

        let input = PointValue {
            x: Scalar::one(),
            y: Scalar::zero(),
        };

        // pick random scalar

        let mut rng = thread_rng();
        let scalar = Scalar::random(&mut rng);
        let witness = randomize.compute(input, scalar);

        // prove

        let blind_x = Scalar::random(&mut rng); // clearly a dummy
        let blind_y = Scalar::random(&mut rng);

        let (comm_x, input_x) = prover.commit(input.x, blind_x);
        let (comm_y, input_y) = prover.commit(input.y, blind_y);

        let input = Point {
            x: input_x,
            y: input_y,
        };

        randomize
            .gadget(&mut prover, Some(&witness), input)
            .unwrap();

        // println!("{:?}", prover.multipliers_len());

        let proof = prover.prove(&bp_gens).unwrap();

        // verify

        let input_x = verifier.commit(comm_x);
        let input_y = verifier.commit(comm_y);

        let input = Point {
            x: input_x,
            y: input_y,
        };

        randomize.gadget(&mut verifier, None, input).unwrap();

        verifier.verify(&proof, &pc_gens, &bp_gens).unwrap()
    }
    */
}
