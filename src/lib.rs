#![feature(test)]

extern crate test;

use bulletproofs::r1cs::*;
use bulletproofs::{BulletproofGens, PedersenGens};

use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;

use merlin::Transcript;

mod curve;
mod misc;
mod randomization;

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
        f: Variable,
        x: Variable,
        y: Variable,
    ) -> Result<(), R1CSError> {
        // Baby's first Bulletproof: y = x^2
        let (_, _, r) = cs.multiply(x.into(), x.into());
        cs.constrain(r - y);
        cs.constrain(r - f);
        Ok(())
    }

    pub fn to_bytes(self) -> Vec<u8> {
        self.0.to_bytes()
    }

    pub fn from_bytes(slice: &[u8]) -> Result<Self, R1CSError> {
        let proof = R1CSProof::from_bytes(slice)?;
        Ok(Self(proof))
    }

    pub fn prove<'a, 'b>(
        pc_gens: &'b PedersenGens,
        bp_gens: &'b BulletproofGens,
        transcript: &'a mut Transcript,
        scalar_x: Scalar,
        scalar_y: Scalar,
        blind_x: Scalar,
        blind_y: Scalar,
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

        let f = prover.allocate(Some(Scalar::from(4u64))).unwrap();

        let b = misc::Bit::new(&mut prover, true);

        let (comm_x, var_x) = prover.commit(scalar_x, blind_y);
        let (comm_y, var_y) = prover.commit(scalar_y, blind_y);

        Self::gadget(&mut prover, f, var_x, var_y)?;

        let proof = prover.prove(&bp_gens)?;

        Ok((Self(proof), vec![comm_x, comm_y], vec![]))
    }

    /// Attempt to verify a `ShuffleProof`.
    pub fn verify<'a, 'b>(
        &self,
        pc_gens: &'b PedersenGens,
        bp_gens: &'b BulletproofGens,
        transcript: &'a mut Transcript,
        comm_x: CompressedRistretto,
        comm_y: CompressedRistretto,
    ) -> Result<(), R1CSError> {
        transcript.commit_bytes(b"dom-sep", b"Rerandomization");

        let mut verifier = Verifier::new(transcript);

        let f = verifier.allocate(None).unwrap();

        let b = misc::Bit::free(&mut verifier);

        let var_x = verifier.commit(comm_x);
        let var_y = verifier.commit(comm_y);

        Self::gadget(&mut verifier, f, var_x, var_y)?;

        verifier.verify(&self.0, &pc_gens, &bp_gens)
    }
}

#[test]
fn test_proof() {
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(6, 1);

    let scalar_x = Scalar::from(2u64);
    let scalar_y = Scalar::from(4u64);

    let blind_x = Scalar::from(53753735735u64); // clearly a dummy
    let blind_y = Scalar::from(46713612753u64);

    let mut prover_transcript = Transcript::new(b"Randomization");

    let (proof, in_commitments, out_commitments) = RandomizedOpening::prove(
        &pc_gens,
        &bp_gens,
        &mut prover_transcript,
        scalar_x,
        scalar_y,
        blind_x,
        blind_y,
    )
    .expect("error during proving");

    let bs = proof.to_bytes();

    println!("{:?} {:?} {:?}", bs.len(), in_commitments, out_commitments);

    let proofP = RandomizedOpening::from_bytes(&bs[..]).unwrap();

    let mut verifier_transcript = Transcript::new(b"Randomization");

    assert!(proofP
        .verify(
            &pc_gens,
            &bp_gens,
            &mut verifier_transcript,
            in_commitments[0].clone(),
            in_commitments[1].clone(),
        )
        .is_ok());
}
