use bulletproofs::r1cs::*;

use super::curve::{EdwardsWindow, WindowWitness, WINDOW_SIZE};
use super::windows::*;
use super::*;

use crate::misc::Bit;

pub struct RandomizationWitness {
    input: PointValue,
    window_witness: Vec<WindowWitness>,
}

pub struct Rerandomization {
    windows: Vec<EdwardsWindow>,
}

impl Rerandomization {
    pub fn len(&self) -> usize {
        self.windows.len() * WINDOW_SIZE
    }

    pub fn new() -> Rerandomization {
        Rerandomization { windows: windows() }
    }

    pub fn compute(&self, input: PointValue, scalar: Scalar) -> RandomizationWitness {
        let bits = bits(scalar);

        let mut intermediate = input;
        let mut window_witness = Vec::with_capacity(self.windows.len());
        for (i, window) in self.windows.iter().enumerate() {
            let j = i * WINDOW_SIZE;
            let b0 = bits[j];
            let b1 = bits[j + 1];
            let b2 = bits[j + 2];
            let w = window.compute(intermediate, b0, b1, b2);
            intermediate = w.output();
            window_witness.push(w);
        }

        RandomizationWitness {
            input,
            window_witness,
        }
    }

    fn gadget<CS: ConstraintSystem>(
        &self,
        cs: &mut CS,
        witness: Option<&RandomizationWitness>,
        input: Point,
    ) -> Result<Point, R1CSError> {
        let mut bits: Vec<(Bit, Bit, Bit)> = Vec::with_capacity(self.windows.len() / WINDOW_SIZE);
        match witness {
            Some(w) => {
                for i in 0..self.windows.len() {
                    let b = w.window_witness[i].bits();
                    bits.push((Bit::new(cs, b.0)?, Bit::new(cs, b.1)?, Bit::new(cs, b.2)?));
                }
            }
            None => {
                for _ in 0..self.windows.len() {
                    bits.push((Bit::free(cs)?, Bit::free(cs)?, Bit::free(cs)?));
                }
            }
        }

        let mut intermediate = input;
        for (i, window) in self.windows.iter().enumerate() {
            let b = bits[i];
            let w = witness.map(|x| &x.window_witness[i]);
            intermediate = window.gadget(cs, w, intermediate, b.0, b.1, b.2)?;
        }
        Ok(intermediate)
    }
}

mod tests {
    use super::*;

    use bulletproofs::r1cs::ConstraintSystem;
    use bulletproofs::{BulletproofGens, PedersenGens};
    use curve25519_dalek::ristretto::CompressedRistretto;
    use curve25519_dalek::scalar::Scalar;
    use merlin::Transcript;

    use rand::thread_rng;
    use rand::Rng;

    use test::Bencher;

    #[bench]
    fn randomize_prove(b: &mut Bencher) {
        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(2100, 1);

        let randomize = Rerandomization::new();

        // compute witness

        let input = PointValue {
            x: Scalar::one(),
            y: Scalar::zero(),
        };

        // pick random scalar

        let mut rng = thread_rng();
        let scalar = Scalar::random(&mut rng);
        let witness = randomize.compute(input, scalar);

        b.iter(|| {
            let transcript = Transcript::new(b"Test");
            let mut prover = Prover::new(&pc_gens, transcript);
            let blind_x = Scalar::random(&mut rng);
            let blind_y = Scalar::random(&mut rng);
            let (comm_x, input_x) = prover.commit(input.x, blind_x);
            let (comm_y, input_y) = prover.commit(input.y, blind_y);
            let input = Point {
                x: input_x,
                y: input_y,
            };
            randomize
                .gadget(&mut prover, Some(&witness), input)
                .unwrap();
            let proof = prover.prove(&bp_gens).unwrap();
        })
    }

    #[bench]
    fn randomize_verify(b: &mut Bencher) {
        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(2100, 1);

        let randomize = Rerandomization::new();

        // compute witness

        let input = PointValue {
            x: Scalar::one(),
            y: Scalar::zero(),
        };

        // pick random scalar

        let mut rng = thread_rng();
        let scalar = Scalar::random(&mut rng);
        let witness = randomize.compute(input, scalar);

        let transcript = Transcript::new(b"Test");
        let mut prover = Prover::new(&pc_gens, transcript);
        let blind_x = Scalar::from(53753735735u64); // clearly a dummy
        let blind_y = Scalar::from(46713612753u64);
        let (comm_x, input_x) = prover.commit(input.x, blind_x);
        let (comm_y, input_y) = prover.commit(input.y, blind_y);
        let input = Point {
            x: input_x,
            y: input_y,
        };
        randomize
            .gadget(&mut prover, Some(&witness), input)
            .unwrap();

        let proof = prover.prove(&bp_gens).unwrap();

        b.iter(|| {
            let transcript = Transcript::new(b"Test");
            let mut verifier = Verifier::new(transcript);
            let input_x = verifier.commit(comm_x);
            let input_y = verifier.commit(comm_y);
            let input = Point {
                x: input_x,
                y: input_y,
            };
            randomize.gadget(&mut verifier, None, input).unwrap();
            verifier.verify(&proof, &pc_gens, &bp_gens).unwrap()
        })
    }

    #[test]
    fn test_randomize() {
        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(2100, 1);
        let transcript = Transcript::new(b"Test");
        let mut prover = Prover::new(&pc_gens, transcript);

        let transcript = Transcript::new(b"Test");
        let mut verifier = Verifier::new(transcript);

        let randomize = Rerandomization::new();

        // compute witness

        let input = PointValue {
            x: Scalar::one(),
            y: Scalar::zero(),
        };

        // pick random scalar

        let mut rng = thread_rng();
        let scalar = Scalar::random(&mut rng);
        let witness = randomize.compute(input, scalar);

        // prove

        let blind_x = Scalar::random(&mut rng); // clearly a dummy
        let blind_y = Scalar::random(&mut rng);

        let (comm_x, input_x) = prover.commit(input.x, blind_x);
        let (comm_y, input_y) = prover.commit(input.y, blind_y);

        let input = Point {
            x: input_x,
            y: input_y,
        };

        randomize
            .gadget(&mut prover, Some(&witness), input)
            .unwrap();

        // println!("{:?}", prover.multipliers_len());

        let proof = prover.prove(&bp_gens).unwrap();

        // verify

        let input_x = verifier.commit(comm_x);
        let input_y = verifier.commit(comm_y);

        let input = Point {
            x: input_x,
            y: input_y,
        };

        randomize.gadget(&mut verifier, None, input).unwrap();

        verifier.verify(&proof, &pc_gens, &bp_gens).unwrap()
    }
}
