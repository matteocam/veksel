#![feature(test)]

extern crate test;

mod membership;
mod randomize;

use serde::{Deserialize, Serialize};

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
    accumulator: (),        // accumulator (against which membership is proved)
}

struct Witness {
    inner_r: (), // inner randomness
    outer_r: (), // outer randomness
}
