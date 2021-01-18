use test::Bencher;

use crate::membership::*;
use super::*;
use rand::rngs::*;
use rand::{thread_rng, CryptoRng, RngCore};

use rug::rand::{MutRandState, RandState};
use rug::Integer;

use super::membership::tests::*;
use std::{println as info, println as warn};

use crate::*;

#[bench]
fn bench_spend_coin(b: &mut Bencher) {
    // setup
    let veksel = Veksel::new();
    let coins = Coins::new();

    let (coin_r, coin) = veksel.make_dummy_coin();
    println!("{:?} {:?}", coin_r, coin);
    let (coins, coin_w) = coins.add_coin_with_proof(&coin);
    b.iter(|| {
        let (rerand_coin, proof) = veksel.spend_coin(&coins, &coin, &coin_w);
    });
    
}

#[bench]
fn bench_vfy_spend_coin(b: &mut Bencher) {
    // setup
    let veksel = Veksel::new();
    let coins = Coins::new();

    let (coin_r, coin) = veksel.make_dummy_coin();
    println!("{:?} {:?}", coin_r, coin);
    let (coins, coin_w) = coins.add_coin_with_proof(&coin);
    let (rerand_coin, proof) = veksel.spend_coin(&coins, &coin, &coin_w);
  
    
    b.iter(|| {
        assert!(veksel.verify_spent_coin(&coins, rerand_coin, &proof));
    })
}




#[test]
fn spend_coin() {
    // setup
    let veksel = Veksel::new();
    let coins = Coins::new();

    let (coin_r, coin) = veksel.make_dummy_coin();
    println!("{:?} {:?}", coin_r, coin);
    let (coins, coin_w) = coins.add_coin_with_proof(&coin);
    let (rerand_coin, proof) = veksel.spend_coin(&coins, &coin, &coin_w);
    assert!(veksel.verify_spent_coin(&coins, rerand_coin, &proof));
}

#[test]
fn prf_size() {
    // setup
    let veksel = Veksel::new();
    let coins = Coins::new();

    let (coin_r, coin) = veksel.make_dummy_coin();
    println!("{:?} {:?}", coin_r, coin);
    let (coins, coin_w) = coins.add_coin_with_proof(&coin);
    let (rerand_coin, proof) = veksel.spend_coin(&coins, &coin, &coin_w);
    
    let sz = proof.proof_size();
    println!("proof_size(): {}", sz);
    println!("serializing size: {}", bincode::serialize(&proof).unwrap().len());
}
