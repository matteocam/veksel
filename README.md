# Veksel

This is a benchmarking implementation for the anonymous payment system [Veksel](link). It is not for production purposes.

This repository contains:
- Sage scripts to generate the Jabberwock curve over Ristretto25519 scalar field (`curve` folder)
- Bulletproof constraints to check rerandomization of coins and whether they are permissible (`randomize` folder)
- A simplified version of the set membership schemes from [CBFGK19](https://eprint.iacr.org/2019/1255) (`membership` folder as well as [this repo](https://github.com/matteocam/cpsnarks-set))
- an implementation of proofs "coin collection" (depositing a coin into your account) transaction from the above (`lib.rs`)

## Build Instructions

Run `cargo test` or `cargo bench` in folder.

## Acknowledgements

We rely on the [Bulletproofs implementation from dalek](https://github.com/dalek/bulletproofs). 

Most of our implementation for set membership depends on code written by [Kobi Gurkan](https://github.com/kobigurk).

We rely on the implementation of cryptographic [accumulators](https://github.com/cambrian/accumulator) from cambrian.

## LICENSE

This code is released under the MIT License.