#![feature(test)]

extern crate test;

mod statement;

use merlin::Transcript;

use bulletproofs::r1cs::{Prover, R1CSProof, Verifier};
use bulletproofs::{BulletproofGens, PedersenGens};

use statement::{curve, PointValue, Statement};

use rand::RngCore;
use rand_core::OsRng;

use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;

pub struct Rerandomization {
    bp_gens: BulletproofGens,
    pc_gens: PedersenGens,
    statement: Statement,
}

pub struct Proof(R1CSProof);

impl Rerandomization {
    pub fn new() -> Self {
        Self {
            pc_gens: PedersenGens::default(),
            bp_gens: BulletproofGens::new(2100, 1),
            statement: Statement::new(curve::param_d()),
        }
    }

    pub fn find_permissible(&self, xy: PointValue) -> (curve::Fp, PointValue) {
        self.statement.find_permissible_randomness(&mut OsRng, xy)
    }

    pub fn prove(
        &self,
        comm_r: Scalar,
        r: curve::Fp,
        xy: PointValue,
    ) -> (Proof, CompressedRistretto) {
        let transcript = Transcript::new(b"Randomize");
        let mut prover = Prover::new(&self.pc_gens, transcript);

        let comm = self.statement.rerandomize.compute(r, xy);

        let witness = self.statement.witness(comm, -r);

        let (comm_x, input_x) = prover.commit(comm.x, comm_r);

        self.statement
            .gadget(&mut prover, Some(&witness), input_x, xy)
            .unwrap();

        (Proof(prover.prove(&self.bp_gens).unwrap()), comm_x)
    }

    pub fn verify(&self, proof: &Proof, comm: CompressedRistretto, xy: PointValue) -> bool {
        let transcript = Transcript::new(b"Randomize");
        let mut verifier = Verifier::new(transcript);

        let comm_x = verifier.commit(comm);

        self.statement
            .gadget(&mut verifier, None, comm_x, xy)
            .unwrap();

        verifier
            .verify(&proof.0, &self.pc_gens, &self.bp_gens)
            .is_ok()
    }
}

/*
mod tests {
    use super::*;

    fn test_proof() {
        let r = Rerandomization::new();

        // let (proof, comm) = r.prove(Scalar::one(), )
    }
}
*/
