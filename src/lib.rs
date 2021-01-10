#![feature(test)]

extern crate test;

mod membership;
mod randomize;

use rand::{thread_rng, CryptoRng, RngCore, Rng};
use rand::rngs::*;


use serde::{Deserialize, Serialize};

use std::cell::RefCell;

use crate::membership::{SetMemStatement, SetMemWitness, SetMembership,Accumulator, ElemCommitment, ElemCommRandomness, SetMemProof, AccumulatorWitness};
use randomize::{Rerandomization, InnerCommRandomness, InnerCommitment};

use curve25519_dalek::scalar::Scalar;

use rug::rand::{MutRandState, RandState};
use rug::Integer;

pub type OuterCommitment = ElemCommitment;
pub type OuterCommRandomness = ElemCommRandomness;

//pub type InnerCommitment = rug::Integer; // XXX

pub type Coin = InnerCommitment;

use bulletproofs::{BulletproofGens, PedersenGens};

/// Joins a membership proof and a re-randomization proof
///
/// Implements Serde::Serialize for serialization.
// #[derive(Deserialize, Serialize)] // XXX: Temporarily removed: SetMemProof does not have a serializable implementation yet
struct Proof {
    outer_comm: OuterCommitment,              // outer commitment (Risetto25519 point)
    membership: SetMemProof,              // proof of membership for outer commitment
    randomize: randomize::Proof, //
}

struct Statement<'a> {
    opening: Vec<&'a [u8]>, // opening of inner commitment (hashed to Jabberwock scalars)
    accumulator: Accumulator,        // accumulator (against which membership is proved)
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
        let (new_acc, prf) = 
            self.accum.add_with_proof (&[ Integer::from(coin.clone()) ] );
        (
            Self { accum: new_acc }, // new acc
            prf.witness.0.value // witness
        )
    }

   
}


// Public parameters
struct Veksel<'a> {
    rerand: Rerandomization,
    setmem: RefCell<SetMembership<RandState<'a>, ThreadRng>>
}


fn integer_to_scalar(item: Integer) -> Scalar {
    // XXX: u64 is only for simplicity here
    Scalar::from(item.to_u64().unwrap())
}


impl<'a> Veksel<'a> {
    pub fn new() -> Self {
        Self { 
            rerand: Rerandomization::new(),
            setmem: RefCell::new(SetMembership::<RandState<'a>, ThreadRng>::new() ), // XXX: Should be made generic
        }
    }


     // Returns rerandomized coin + a related proof
     pub fn spend_coin<R: RngCore>(&self, mut rng: R, coins: &Coins, coin: &Coin, coin_w: &AccumulatorWitness, ) -> (Coin, Proof) {
        // make inner commitment
        let blinding = InnerCommRandomness::random(&mut rng);
        let inner_comm = self.rerand.rerandomize_comm(blinding.clone(), coin.clone());

        // make outer commitment
        let coin_as_acc_elem = Integer::from(coin.clone());
        let outer_r = Integer::from(5); // XXX: fixed randomness

        let outer_comm = (self.setmem.borrow_mut()).
            commit_to_set_element(&coin_as_acc_elem, &outer_r);
        
        // prove set membership 
        let setmem_x = SetMemStatement {
            c_e_q: outer_comm.clone(),
            c_p: coins.accum.value.clone(),
        };

        let setmem_w = SetMemWitness {
            e: coin_as_acc_elem.clone(),
            r_q: outer_r.clone(),
            w: coin_w.clone(),
        };

        let setmem_prf = (self.setmem.borrow_mut()).prove(&setmem_x, &setmem_w);


        // prove rereandomization
        let rerand_prf = self.rerand.prove(integer_to_scalar(outer_r), blinding.clone(), coin.clone()).0;

        let proof =  Proof {
            outer_comm: outer_comm,              // outer commitment (Risetto25519 point)
            membership: setmem_prf,              // proof of membership for outer commitment
            randomize: rerand_prf, //
        };

        (inner_comm, proof)
    }
    
}


#[cfg(test)]
mod tests {
    use super::membership::*;
    use rand::{thread_rng, CryptoRng, RngCore};
    use rand::rngs::*;

    use rug::rand::{MutRandState, RandState};
    use rug::Integer;

    use super::membership::tests::*;

    #[test]
      fn tst() {
        let mut setmem = SetMembership::<RandState<'_>, ThreadRng>::new();
        let (statement, witness) = random_xw(&mut setmem);
        let prf = setmem.prove(&statement, &witness);
        assert!(setmem.verify(&statement, &prf));
    }

}