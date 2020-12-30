#![feature(test)]

extern crate test;

mod statement;

use merlin::Transcript;

use bulletproofs::r1cs::{Prover, R1CSProof, Verifier};
use bulletproofs::{BulletproofGens, PedersenGens};

use statement::{curve, PointValue, Statement};

use rand_core::OsRng;
use rand::{CryptoRng, RngCore, thread_rng};

use rand::rngs::*;

use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};

use cpsnarks_set::commitments::Commitment;
use cpsnarks_set::parameters::Parameters;
use cpsnarks_set::protocols::membership_simple::Protocol;
use cpsnarks_set::protocols::membership_simple::Statement as SetMemStatementGen;
use cpsnarks_set::protocols::membership_simple::Witness as SetMemWitnessGen;
use cpsnarks_set::protocols::membership_simple::Proof as SetMemProofGen;

use cpsnarks_set::protocols::membership_simple::transcript::*;

use accumulator::group::{Rsa2048};
use accumulator::{group::Group, AccumulatorWithoutHashToPrime};

use std::cell::RefCell;


use rug::rand::{RandState,MutRandState};
use rug::Integer;

type SetMemStatement = SetMemStatementGen<Rsa2048, RistrettoPoint>;
type SetMemWitness = SetMemWitnessGen<Rsa2048>;
type SetMemProof = SetMemProofGen<Rsa2048, RistrettoPoint>;



// NEXT: Add specific generics to SetMemStatement,etc.


// TODO: (at some point) Abstract curves we are using through generics


/* 
    NB: This implementation carries out set membership assuming a range test
        has been done somewhere else
*/
pub struct SetMembership<R1: MutRandState, R2: RngCore + CryptoRng> {

    protocol: Protocol<Rsa2048, RistrettoPoint>, // contains crs

    rng1: R1,
    rng2: R2
}


impl<>
 SetMembership<RandState<'_>, ThreadRng> {

    // performs a setup
    pub fn new() -> Self
     {
        // Generate parameters and crs
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

        SetMembership {
            protocol: Protocol::<Rsa2048, RistrettoPoint>::from_crs(&crs),
            rng1,
            rng2
        }
     }
}

impl<R1: MutRandState, R2: RngCore + CryptoRng> 
    SetMembership<R1, R2> {

    // Generate some (statement, witness) pair
    pub fn random_xw(&mut self) -> (SetMemStatement, SetMemWitness)
    {
        let value = Integer::from(Integer::u_pow_u(
            2,
            (self.protocol.crs.parameters.hash_to_prime_bits) as u32,
        )) - &Integer::from(245);
        let randomness = Integer::from(5);
        let commitment = self.protocol
            .crs
            .crs_modeq
            .pedersen_commitment_parameters
            .commit(&value, &randomness)
            .unwrap();


        const LARGE_PRIMES: [u64; 4] = [
            553_525_575_239_331_913,
            12_702_637_924_034_044_211,
            378_373_571_372_703_133,
            8_640_171_141_336_142_787,
        ];


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

        let statement = SetMemStatement {
            c_e_q: commitment,
            c_p: acc,
        };

        let witness = SetMemWitness {
            e: value,
            r_q: randomness,
            w,
        };
        (statement, witness)
    }

    pub fn prove(
        &mut self, // mut is required for rng-s
        statement: &SetMemStatement,
        witness: &SetMemWitness
    ) -> SetMemProof {
        let proof_transcript = RefCell::new(Transcript::new(b"membership"));
        let mut verifier_channel = TranscriptVerifierChannel::new(&self.protocol.crs, &proof_transcript);

        self.protocol
            .prove(
                &mut verifier_channel,
                &mut self.rng1,
                &mut self.rng2,
                statement,
                witness,
            )
            .unwrap();
        let proof = verifier_channel.proof().unwrap();
        proof
    }

    pub fn verify(
        &self,
        statement: &SetMemStatement,
        proof: &SetMemProof,
    ) -> bool {
        let verification_transcript = RefCell::new(Transcript::new(b"membership"));
        let mut prover_channel =
            TranscriptProverChannel::new(&self.protocol.crs, &verification_transcript, proof);
        self.protocol.verify(&mut prover_channel, &statement).unwrap();

        // unwrap above fails if something goes wrong
        true
    }

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
    use super::*;

    #[test]
    fn test_set_mem_proof() {
       let mut setmem = SetMembership::<RandState<'_>, ThreadRng>::new();
       let (statement, witness) = setmem.random_xw();
       let prf = setmem.prove(&statement, &witness);
       assert!(setmem.verify(&statement, &prf));
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
