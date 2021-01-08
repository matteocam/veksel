#![feature(test)]

extern crate test;

mod membership;
mod randomize;

use serde::{Deserialize, Serialize};

use crate::membership::{Accumulator, ElemCommitment, ElemCommRandomness, SetMemProof};


pub type OuterCommitment = ElemCommitment;
pub type OuterCommRandomness = ElemCommRandomness;


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
    inner_r: (), // inner randomness
    outer_r: OuterCommRandomness, // outer randomness
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