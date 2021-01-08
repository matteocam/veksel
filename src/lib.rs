#![feature(test)]

extern crate test;

mod membership;
mod randomize;

use serde::{Deserialize, Serialize};

use crate::membership::Accumulator;

/// Joins a membership proof and a re-randomization proof
///
/// Implements Serde::Serialize for serialization.
#[derive(Deserialize, Serialize)]
struct Proof {
    outer_comm: (),              // outer commitment (Risetto25519 point)
    membership: (),              // proof of membership for outer commitment
    randomize: randomize::Proof, //
}

struct Statement<'a> {
    opening: Vec<&'a [u8]>, // opening of inner commitment (hashed to Jabberwock scalars)
    accumulator: Accumulator,        // accumulator (against which membership is proved)
}

struct Witness {
    inner_r: (), // inner randomness
    outer_r: (), // outer randomness
}

#[cfg(test)]
mod tests {
    use super::membership::*;
    use rand::{thread_rng, CryptoRng, RngCore};
    use rand::rngs::*;

    use rug::rand::{MutRandState, RandState};
    use rug::Integer;


    #[test]
    fn test_set_mem_proof() {
        let mut setmem = SetMembership::<RandState<'_>, ThreadRng>::new();
        let (statement, witness) = setmem.random_xw();
        let prf = setmem.prove(&statement, &witness);
        assert!(setmem.verify(&statement, &prf));
    }
}