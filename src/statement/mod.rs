pub mod curve;
mod misc;
mod permissible;
mod window;

use rand::{Rng, RngCore};

use bulletproofs::r1cs::*;
use curve25519_dalek::scalar::Scalar;

use misc::*;

pub use permissible::{Permissible, PermissibleWitness};
pub use window::{FixScalarMult, FixScalarMultWitness};

impl curve::Fp {
    pub fn random<R: RngCore>(rng: &mut R) -> Self {
        let limbs: [u8; 32] = rng.gen();
        limbs.into()
    }
}

fn curve_add(d: Scalar, a: PointValue, b: PointValue) -> PointValue {
    debug_assert!(a.check(d));
    debug_assert!(b.check(d));
    let p = d * a.x * a.y * b.x * b.y;
    let x = (a.x * b.y + b.x * a.y) * (Scalar::one() + p).invert();
    let y = (a.y * b.y - a.x * b.x) * (Scalar::one() - p).invert();
    let p = PointValue { x, y };
    debug_assert!(p.check(d));
    p
}

#[test]
fn test_identity() {
    assert_eq!(
        curve_add(curve::param_d(), curve::identity(), curve::generator()),
        curve::generator()
    );
}

pub struct Statement {
    pub rerandomize: FixScalarMult,
    pub permissible: Permissible,
}

pub struct StatementWitness {
    rerandomize: FixScalarMultWitness,
    permissible: PermissibleWitness,
}

impl Statement {
    pub fn new(d: Scalar) -> Self {
        Statement {
            rerandomize: FixScalarMult::new(d, curve::generator()),
            permissible: Permissible::new(d),
        }
    }

    pub fn find_permissible_randomness<R: RngCore>(
        &self,
        rng: &mut R,
        xy: PointValue,
    ) -> (curve::Fp, PointValue) {
        loop {
            let r = curve::Fp::random(rng); // commitment randomness
            let comm = self.rerandomize.compute(r, xy); // randomized commitment
            if self.permissible.is_permissible(comm) {
                break (r, comm);
            }
        }
    }

    pub fn witness(
        &self,
        comm: PointValue,
        r: curve::Fp, // randomness for Pedersen commitment
    ) -> StatementWitness {
        assert!(self.permissible.is_permissible(comm), "not a valid witness");
        let permissible = self.permissible.witness(comm);
        let rerandomize = self.rerandomize.witness(comm, r);
        StatementWitness {
            permissible,
            rerandomize,
        }
    }

    pub fn gadget<CS: ConstraintSystem>(
        &self,
        cs: &mut CS,
        witness: Option<&StatementWitness>,
        x: Variable,      // input point (hidden, described by x coordinate only)
        xy_r: PointValue, // rerandomized point (public)
    ) -> Result<(), R1CSError> {
        // check permissible
        let point = self
            .permissible
            .gadget(cs, witness.map(|x| &x.permissible))?;
        cs.constrain(point.x - x);

        // apply re-randomization
        let point_r = self
            .rerandomize
            .gadget(cs, witness.map(|x| &x.rerandomize), point)?;
        // cs.constrain(point_r.x - xy_r.x);
        // cs.constrain(point_r.y - xy_r.y);
        Ok(())
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
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

mod tests {
    use super::*;

    use bulletproofs::r1cs::ConstraintSystem;
    use bulletproofs::{BulletproofGens, PedersenGens};
    use curve25519_dalek::ristretto::CompressedRistretto;
    use curve25519_dalek::scalar::Scalar;
    use merlin::Transcript;

    use rand::thread_rng;
    use rand::Rng;

    use test::Bencher;

    #[bench]
    fn verify_statement(b: &mut Bencher) {
        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(2100, 1);
        let transcript = Transcript::new(b"Test");
        let mut prover = Prover::new(&pc_gens, transcript);

        let mut rng = thread_rng();
        let xy = curve::identity();
        let statement = Statement::new(curve::param_d());

        let (r, comm) = statement.find_permissible_randomness(&mut rng, xy);

        let witness = statement.witness(comm, -r);

        let blind_x = Scalar::random(&mut rng);

        let (comm_x, input_x) = prover.commit(comm.x, blind_x);

        statement
            .gadget(&mut prover, Some(&witness), input_x, xy)
            .unwrap();

        let proof = prover.prove(&bp_gens).unwrap();

        b.iter(|| {
            let transcript = Transcript::new(b"Test");
            let mut verifier = Verifier::new(transcript);
            let input_x = verifier.commit(comm_x);
            statement.gadget(&mut verifier, None, input_x, xy).unwrap();
            verifier.verify(&proof, &pc_gens, &bp_gens).unwrap();
        })
    }

    #[test]
    fn test_statement() {
        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(2100, 1);
        let transcript = Transcript::new(b"Test");
        let mut prover = Prover::new(&pc_gens, transcript);

        let transcript = Transcript::new(b"Test");
        let mut verifier = Verifier::new(transcript);

        let mut rng = thread_rng();
        let xy = curve::identity();
        let statement = Statement::new(curve::param_d());

        let (r, comm) = statement.find_permissible_randomness(&mut rng, xy);

        println!("{:?} {:?}", r, comm);

        let witness = statement.witness(comm, -r);

        let blind_x = Scalar::random(&mut rng);

        let (comm_x, input_x) = prover.commit(comm.x, blind_x);

        statement
            .gadget(&mut prover, Some(&witness), input_x, xy)
            .unwrap();

        let proof = prover.prove(&bp_gens).unwrap();

        // verify

        let input_x = verifier.commit(comm_x);

        statement.gadget(&mut verifier, None, input_x, xy).unwrap();

        verifier.verify(&proof, &pc_gens, &bp_gens).unwrap();

        println!("{:?}", proof.serialized_size());
    }
}
