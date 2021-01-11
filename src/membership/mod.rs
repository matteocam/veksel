extern crate test;

use merlin::Transcript;

use bulletproofs::r1cs::{Prover, R1CSProof, Verifier};
use bulletproofs::{BulletproofGens, PedersenGens};

use rand::{thread_rng, CryptoRng, RngCore};
use rand_core::OsRng;

use rand::rngs::*;

use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};

use cpsnarks_set::commitments::{Commitment,pedersen::PedersenCommitment};
use cpsnarks_set::parameters::Parameters;

// export some types as "Gen"-erics; specialized later
use cpsnarks_set::protocols::membership_simple::Proof as SetMemProofGen;
use cpsnarks_set::protocols::membership_simple::Protocol as ProtocolGen;
use cpsnarks_set::protocols::membership_simple::Statement as SetMemStatementGen;
use cpsnarks_set::protocols::membership_simple::Witness as SetMemWitnessGen;

use cpsnarks_set::utils::ConvertibleUnknownOrderGroup;

use cpsnarks_set::protocols::membership_simple::transcript::*;

use accumulator::group::Rsa2048;
use accumulator::{group::Group, AccumulatorWithoutHashToPrime};



use std::cell::RefCell;

use rug::rand::{MutRandState, RandState};
use rug::Integer;

// TODO: (at some point) Abstract curves we are using through generics
pub type SetMemStatement = SetMemStatementGen<Rsa2048, RistrettoPoint>;
pub type SetMemWitness = SetMemWitnessGen<Rsa2048>;
pub type SetMemProof = SetMemProofGen<Rsa2048, RistrettoPoint>;
pub type SetMemProtocol = ProtocolGen<Rsa2048, RistrettoPoint>;
pub type Accumulator = accumulator::Accumulator::<Rsa2048, Integer, AccumulatorWithoutHashToPrime>;

pub type AccumulatorWitness = <Rsa2048 as Group> ::Elem;

pub type ElemCommitment = <PedersenCommitment<RistrettoPoint> as Commitment>::Instance;
pub type ElemCommRandomness = Integer;



// NEXT: Add specific generics to SetMemStatement,etc.


/*
    NB: This implementation carries out set membership assuming a range test
        has been done somewhere else
*/
pub struct SetMembership<R1: MutRandState, R2: RngCore + CryptoRng> {
    protocol: SetMemProtocol, // contains crs

    rng1: R1,
    rng2: R2,
}

impl SetMembership<RandState<'_>, ThreadRng> {
    // performs a setup
    pub fn new() -> Self {
        // Generate parameters and crs
        //let params = Parameters::from_security_level(128).unwrap();
        let params = Parameters::from_curve::<Scalar>().unwrap().0;
        let mut rng1 = RandState::new();
        rng1.seed(&Integer::from(13));
        let mut rng2 = thread_rng();

        let crs = SetMemProtocol::setup_default(&params, &mut rng1, &mut rng2)
            .unwrap()
            .crs;

        SetMembership {
            protocol: SetMemProtocol::from_crs(&crs),
            rng1,
            rng2,
        }
    }
}

impl<R1: MutRandState, R2: RngCore + CryptoRng> SetMembership<R1, R2> {

    pub fn commit_to_set_element(&self, value: &Integer, randomness: &ElemCommRandomness) -> ElemCommitment {
        self.protocol
            .crs
            .crs_modeq
            .pedersen_commitment_parameters
            .commit(value,randomness)
            .unwrap()
    }
    

    pub fn prove(
        &mut self, // mut is required for rng-s
        statement: &SetMemStatement,
        witness: &SetMemWitness,
    ) -> SetMemProof {
        let proof_transcript = RefCell::new(Transcript::new(b"membership"));
        let mut verifier_channel =
            TranscriptVerifierChannel::new(&self.protocol.crs, &proof_transcript);

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

    pub fn verify(&self, statement: &SetMemStatement, proof: &SetMemProof) -> bool {
        let verification_transcript = RefCell::new(Transcript::new(b"membership"));
        let mut prover_channel =
            TranscriptProverChannel::new(&self.protocol.crs, &verification_transcript, proof);
        self.protocol
            .verify(&mut prover_channel, &statement)
            .unwrap();

        // unwrap above fails if something goes wrong
        true
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    // Generate some (statement, witness) pair
    pub fn random_xw<R1: MutRandState, R2: RngCore + CryptoRng>
        (setmem:&mut SetMembership<R1, R2>) -> (SetMemStatement, SetMemWitness)
    {
        let value = Integer::from(Integer::u_pow_u(
            2,
            (setmem.protocol.crs.parameters.hash_to_prime_bits) as u32,
        )) - &Integer::from(245);
        let randomness = Integer::from(5);
        let commitment = setmem.commit_to_set_element(&value, &randomness);

        const LARGE_PRIMES: [u64; 4] = [
            553_525_575_239_331_913,
            12_702_637_924_034_044_211,
            378_373_571_372_703_133,
            8_640_171_141_336_142_787,
        ];

        let accum = Accumulator::empty();
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

    #[test]
    fn membership_proof() {
        let mut setmem = SetMembership::<RandState<'_>, ThreadRng>::new();
        let (statement, witness) = random_xw(&mut setmem);
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
