#![feature(test)]

extern crate test;

mod membership;
mod randomize;
#[cfg(test)]
mod tests;

use rand::rngs::*;
use rand::{thread_rng, CryptoRng, Rng, RngCore};
use rand_core::OsRng;

use serde::{Deserialize, Serialize};

use std::cell::RefCell;

use crate::membership::{
    Accumulator, AccumulatorWitness, ElemCommRandomness, ElemCommitment, SetMemProof,
    SetMemStatement, SetMemWitness, SetMembership,
};
use randomize::{dummy_comm, InnerCommRandomness, InnerCommitment, Rerandomization};

use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;

use rug::rand::{MutRandState, RandState};
use rug::{integer, Integer};

use rug_binserial::*;
use proofsize_derive::*;

pub type OuterCommitment = ElemCommitment;
pub type OuterCommRandomness = ElemCommRandomness;

//pub type InnerCommitment = rug::Integer; // XXX

pub type Coin = InnerCommitment;

use bulletproofs::{BulletproofGens, PedersenGens};

pub fn bytes_to_integer(bytes:&[u8]) -> Integer {
    Integer::from_digits(bytes, integer::Order::Lsf)
}

/// Joins a membership proof and a re-randomization proof
///
/// Implements Serde::Serialize for serialization.
#[derive(Serialize, ProofSize)]
struct Proof {
    outer_comm_ristretto: CompressedRistretto, // outer commitment (group of known order)
    setmembership_proof: SetMemProof, // proof of membership for outer commitment
    rerandomize_proof: randomize::Proof, // proof that opening is a rerandomization of the nested commitment
}

struct Statement<'a> {
    opening: Vec<&'a [u8]>, // opening of inner commitment (hashed to Jabberwock scalars)
    accumulator: Accumulator, // accumulator (against which membership is proved)
}

struct Witness {
    inner_r: InnerCommRandomness, // inner randomness
    outer_r: OuterCommRandomness, // outer randomness
}

struct Coins {
    accum: Accumulator,
}

impl Coins {
    pub fn new() -> Self {
        Self {
            accum: Accumulator::empty(),
        }
    }
    pub fn add_coin_with_proof(self, coin: &Coin) -> (Self, AccumulatorWitness) {
        let (new_acc, prf) = self.accum.add_with_proof(&[Integer::from(coin.clone())]);
        (
            Self { accum: new_acc }, // new acc
            prf.witness.0.value,     // witness
        )
    }
}

// Public parameters
struct Veksel<'a> {
    rerand: Rerandomization,
    setmem: RefCell<SetMembership<RandState<'a>, ThreadRng>>,
}

fn integer_to_scalar(item: Integer) -> Scalar {
    // XXX: u64 is only for simplicity here
    Scalar::from(item.to_u64().unwrap())
}

impl<'a> Veksel<'a> {
    pub fn new() -> Self {
        Self {
            rerand: Rerandomization::new(),
            setmem: RefCell::new(SetMembership::<RandState<'a>, ThreadRng>::new()), // XXX: Should be made generic
        }
    }

    // XXX: Should be changed to proper "make_coin" with a target at some point
    pub fn make_dummy_coin(&self) -> (InnerCommRandomness, Coin) {
        let coin_tgt = dummy_comm();
        self.rerand.find_permissible(coin_tgt)
    }

    /// Returns rerandomized coin + a related proof.
    ///
    /// Takes:
    ///
    /// * `coins`: An accumulated set of coins
    /// * `coin`: The coin (commitment) to spend
    /// *
    ///
    pub fn spend_coin(
        &self,
        coins: &Coins,
        coin: &Coin,
        coin_w: &AccumulatorWitness,
    ) -> (Coin, Proof) {
        debug_assert!(
            self.rerand.is_permissible(*coin),
            "coin is not permissible, the proof will not be valid"
        );

        

        // commit to the coin in the RSA group
        let coin_as_acc_elem = Integer::from(coin.clone());

        // commit to the coin in the ristretto25519 group
        let outer_r_ristretto = Scalar::random(&mut OsRng); // randomness for the field commitment (in the group of known order)
        //let outer_comm = (self.setmem.borrow()).commit_to_set_element(coin.into(), outer_r_ristretto);

        // randomness to "add" to inner commitment
        let inner_delta_random = InnerCommRandomness::random(&mut OsRng);

        // prove re-randomization
        let (rerandomize_proof, rerandomized_coin, outer_comm_ristretto) = self.rerand.prove(
            outer_r_ristretto,            // outer commitment randomness
            inner_delta_random.clone(), // randomness to "add"
            coin.clone(),               // coin inside outer commitment (original coin)
        );

        // prove set membership
        let setmem_x = SetMemStatement {
            c_e_q: outer_comm_ristretto.decompress().unwrap(),
            c_p: coins.accum.value.clone(),
        };

        let setmem_w = SetMemWitness {
            e: coin_as_acc_elem.clone(),
            r_q: bytes_to_integer(outer_r_ristretto.as_bytes()),
            w: coin_w.clone(),
        };


        /*
         * setmembership_proof shows that:
         * 
         * outer_comm_rsa = G^outer_r_rsa H^A
         * outer_comm_ristretto = g^outer_r_ristretto h^B
         *
         * With A = B mod |ristretto25519-Group|
         *
         * 
         */

        let setmembership_proof = (self.setmem.borrow_mut()).prove(&setmem_x, &setmem_w);

        let proof = Proof {
            outer_comm_ristretto, // outer commitment (ristretto25519 point)
            setmembership_proof,
            rerandomize_proof,
        };

        (rerandomized_coin, proof)
    }
    pub fn verify_spent_coin(&self, coins: &Coins, rerand_coin: Coin, prf: &Proof) -> bool {
        let setmem_x = SetMemStatement {
            c_e_q: prf.outer_comm_ristretto.decompress().unwrap(),
            c_p: coins.accum.value.clone(),
        };
        let setmem_ok = (self.setmem.borrow()).verify(&setmem_x, &prf.setmembership_proof);
        let rerand_ok = self
            .rerand
            .verify(&prf.rerandomize_proof, prf.outer_comm_ristretto, rerand_coin);
        setmem_ok && rerand_ok
    }
}

