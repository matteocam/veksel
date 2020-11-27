use bulletproofs::r1cs::*;
use bulletproofs::{BulletproofGens, PedersenGens};

use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;

use merlin::Transcript;

struct RandomizedOpening(R1CSProof);

impl RandomizedOpening {
    fn gadget_edwards_window<CS: ConstraintSystem>(
        cs: &mut CS,
        s0: Variable,
        s1: Variable,
        s2: Variable, // s = s0 + 2 * s1 + 4 * s2
    ) -> Result<(), R1CSError> {
        // do window lookup
        Ok(())
    }

    fn gadget<CS: ConstraintSystem>(
        cs: &mut CS,
        x: Variable,
        y: Variable,
    ) -> Result<(), R1CSError> {
        // Baby's first Bulletproof: y = x^2
        let (_, _, r) = cs.multiply(x.into(), x.into());
        cs.constrain(r - y);
        Ok(())
    }

    pub fn prove<'a, 'b>(
        pc_gens: &'b PedersenGens,
        bp_gens: &'b BulletproofGens,
        transcript: &'a mut Transcript,
        scalar_x: Scalar,
        scalar_y: Scalar,
        blind_x: Scalar,
        blind_y: Scalar,
        output: &[Scalar],
    ) -> Result<
        (
            RandomizedOpening,
            Vec<CompressedRistretto>, // input commitments
            Vec<CompressedRistretto>, // output commitments
        ),
        R1CSError,
    > {
        transcript.commit_bytes(b"dom-sep", b"Rerandomization");

        let mut prover = Prover::new(&pc_gens, transcript);

        let (comm_x, var_x) = prover.commit(scalar_x, blind_y);
        let (comm_y, var_y) = prover.commit(scalar_y, blind_y);

        Self::gadget(&mut prover, var_x, var_y);

        let proof = prover.prove(&bp_gens)?;

        Ok((Self(proof), vec![comm_x, comm_y], vec![]))
    }
}

#[test]
fn test_proof() {}
