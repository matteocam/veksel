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



/* 
    NB: This implementation carries out set membership assuming a range test
        has been done somewhere else
*/
pub struct SetMembership {

}

pub struct SetMemProof(R1CSProof);

impl SetMembership {

}

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


#[cfg(test)]
mod tests {
    use cpsnarks_set::commitments::Commitment;
    use cpsnarks_set::parameters::Parameters;
    use cpsnarks_set::protocols::membership_simple::*;
    use cpsnarks_set::protocols::membership_simple::transcript::*;


    use accumulator::group::{Rsa2048};
    use accumulator::{group::Group, AccumulatorWithoutHashToPrime};
    use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
    use merlin::Transcript;
    use rand::thread_rng;
    use rug::rand::RandState;
    use rug::Integer;
    use std::cell::RefCell;

    const LARGE_PRIMES: [u64; 4] = [
        553_525_575_239_331_913,
        12_702_637_924_034_044_211,
        378_373_571_372_703_133,
        8_640_171_141_336_142_787,
    ];


    #[test]
    fn test_proof() {
        let params = Parameters::from_security_level(128).unwrap();
        let mut rng1 = RandState::new();
        rng1.seed(&Integer::from(13));
        let mut rng2 = thread_rng();

        let crs = Protocol::<
            Rsa2048,
            RistrettoPoint,
        >::setup(&params, &mut rng1, &mut rng2)
        .unwrap()
        .crs;
        let protocol = Protocol::<Rsa2048, RistrettoPoint>::from_crs(&crs);

        let value = Integer::from(Integer::u_pow_u(
            2,
            (crs.parameters.hash_to_prime_bits) as u32,
        )) - &Integer::from(245);
        let randomness = Integer::from(5);
        let commitment = protocol
            .crs
            .crs_modeq
            .pedersen_commitment_parameters
            .commit(&value, &randomness)
            .unwrap();

        let accum =
            accumulator::Accumulator::<Rsa2048, Integer, AccumulatorWithoutHashToPrime>::empty();
        let accum = accum.add(
            &LARGE_PRIMES
                .iter()
                .skip(1)
                .map(|p| Integer::from(*p))
                .collect::<Vec<_>>(),
        );

        let accum = accum.add_with_proof(&[value.clone()]);
        let acc = accum.0.value;
        let w = accum.1.witness.0.value;
        assert_eq!(Rsa2048::exp(&w, &value), acc);

        let proof_transcript = RefCell::new(Transcript::new(b"membership"));
        let mut verifier_channel = TranscriptVerifierChannel::new(&crs, &proof_transcript);
        let statement = Statement {
            c_e_q: commitment,
            c_p: acc,
        };
        protocol
            .prove(
                &mut verifier_channel,
                &mut rng1,
                &mut rng2,
                &statement,
                &Witness {
                    e: value,
                    r_q: randomness,
                    w,
                },
            )
            .unwrap();
        let proof = verifier_channel.proof().unwrap();
        let verification_transcript = RefCell::new(Transcript::new(b"membership"));
        let mut prover_channel =
            TranscriptProverChannel::new(&crs, &verification_transcript, &proof);
        protocol.verify(&mut prover_channel, &statement).unwrap();
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
