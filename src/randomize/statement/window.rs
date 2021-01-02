use bulletproofs::r1cs::*;

use curve25519_dalek::scalar::Scalar;

use super::*;

const WINDOW_SIZE: usize = 3;
const WINDOW_ELEMS: usize = 1 << WINDOW_SIZE;
const WINDOWS: usize = (curve::FP_INNER_BITS + WINDOW_SIZE - 1) / WINDOW_SIZE;

pub struct WindowWitness {
    input: PointValue,
    output: PointValue,
    window: PointValue,
    b0: bool,
    b1: bool,
    b2: bool,
    b: Scalar,
    a: Scalar,
    c: Scalar,
}

pub struct FixScalarMultWitness {
    window_witness: Vec<WindowWitness>,
}

pub struct FixScalarMult {
    d: Scalar,
    windows: Vec<EdwardsWindow>,
}

impl FixScalarMult {
    pub fn new(d: Scalar, base: PointValue) -> Self {
        let mut current = base;
        let mut windows = Vec::with_capacity(WINDOWS);
        for _ in 0..WINDOWS {
            let win = EdwardsWindow::new(d, current);
            current = curve_add(
                d,
                current,
                PointValue {
                    x: win.u[WINDOW_ELEMS - 1],
                    y: win.v[WINDOW_ELEMS - 1],
                },
            );
            windows.push(win);
        }
        Self { d, windows }
    }

    pub fn compute(&self, scalar: curve::Fp, mut point: PointValue) -> PointValue {
        let mut bits = scalar.iter_bit().map(|b| b.0);
        for j in 0..WINDOWS {
            let b0 = bits.next().unwrap_or(0) as usize;
            let b1 = bits.next().unwrap_or(0) as usize;
            let b2 = bits.next().unwrap_or(0) as usize;
            debug_assert!(b0 < 2);
            debug_assert!(b1 < 2);
            debug_assert!(b2 < 2);
            let i = b0 + b1 * 2 + b2 * 4;
            let p = PointValue {
                x: self.windows[j].u[i],
                y: self.windows[j].v[i],
            };
            point = curve_add(self.d, p, point);
        }
        debug_assert!(bits.next().is_none());
        point
    }

    pub fn witness(&self, input: PointValue, scalar: curve::Fp) -> FixScalarMultWitness {
        let mut bits = scalar.iter_bit().map(|b| b.0 != 0);

        let mut intermediate = input;
        let mut window_witness = Vec::with_capacity(self.windows.len());
        for (i, window) in self.windows.iter().enumerate() {
            let b0 = bits.next().unwrap_or(false);
            let b1 = bits.next().unwrap_or(false);
            let b2 = bits.next().unwrap_or(false);
            let w = window.compute(intermediate, b0, b1, b2);
            intermediate = w.output();
            window_witness.push(w);
        }

        FixScalarMultWitness { window_witness }
    }

    pub fn gadget<CS: ConstraintSystem>(
        &self,
        cs: &mut CS,
        witness: Option<&FixScalarMultWitness>,
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

impl WindowWitness {
    pub fn output(&self) -> PointValue {
        self.output
    }

    pub fn bits(&self) -> (bool, bool, bool) {
        (self.b0, self.b1, self.b2)
    }
}

pub struct EdwardsWindow {
    d: Scalar,
    u: [Scalar; WINDOW_ELEMS],
    v: [Scalar; WINDOW_ELEMS],
}

// constrain u = u[s0 + s1*2 + s2*4] with sa = s1 * s2
#[inline(always)]
fn lookup<CS: ConstraintSystem>(
    cs: &mut CS,
    sa: Bit,
    s0: Bit,
    s1: Bit,
    s2: Bit,
    e: LinearCombination,
    u: &[Scalar; 8],
) {
    let sa: Variable = sa.into();
    let s0: Variable = s0.into();
    let s1: Variable = s1.into();
    let s2: Variable = s2.into();

    // left side
    let (_, _, left): (Variable, Variable, Variable) = cs.multiply(s0.into(), {
        let f = -(u[0] * sa) + (u[0] * s2) + (u[0] * s1) - u[0] + (u[2] * sa);
        let f = f - (u[2] * s1) + (u[4] * sa) - (u[4] * s2) - (u[6] * sa);
        let f = f + (u[1] * sa) - (u[1] * s2) - (u[1] * s1) + u[1] - (u[3] * sa);
        let f = f + (u[3] * s1) - (u[5] * sa) + (u[5] * s2) + (u[7] * sa);
        f
    });

    // right size
    let right: LinearCombination = e - (u[0] * sa) + (u[0] * s2) + (u[0] * s1) - u[0] + (u[2] * sa);
    let right = right - (u[2] * s1) + (u[4] * sa) - (u[4] * s2) - (u[6] * sa);

    // left == right
    cs.constrain(left - right)
}

impl EdwardsWindow {
    pub fn new(d: Scalar, p1: PointValue) -> Self {
        let p0 = curve::identity();
        let p2 = curve_add(d, p1, p1);
        let p3 = curve_add(d, p2, p1);
        let p4 = curve_add(d, p3, p1);
        let p5 = curve_add(d, p4, p1);
        let p6 = curve_add(d, p5, p1);
        let p7 = curve_add(d, p6, p1);
        EdwardsWindow {
            d,
            u: [p0.x, p1.x, p2.x, p3.x, p4.x, p5.x, p6.x, p7.x],
            v: [p0.y, p1.y, p2.y, p3.y, p4.y, p5.y, p6.y, p7.y],
        }
    }

    /*
    /// Takes:
    ///
    /// - d: Curve parameter
    /// - u: first coordinates for points in the window
    /// - v: second coordinates for points in the window
    pub fn new(d: Scalar, u: [Scalar; 8], v: [Scalar; 8]) -> Self {
        #[cfg(debug_assertions)]
        {
            for i in 0..8 {
                let p = PointValue { x: u[i], y: v[i] };
                assert!(p.check(d));
            }
        }
        EdwardsWindow { d, u, v }
    }
    */

    /// Compute assignments to intermediate wires.
    /// Computes:
    ///
    /// - uv   (lookup result)
    /// - xy_r (resulting point)
    ///
    /// From:
    ///
    /// - xy (input point)
    /// - s0, s1, s2 (bit decomposition of 3-bit scalar)
    pub fn compute(
        &self,
        input: PointValue, // input
        b0: bool,          // scalar (0th bit)
        b1: bool,          // scalar (1st bit)
        b2: bool,          // scalar (2nd bit)
    ) -> WindowWitness {
        let i0: usize = b0 as usize;
        let i1: usize = b1 as usize;
        let i2: usize = b2 as usize;
        let i = i0 + i1 * 2 + i2 * 4;
        let window = PointValue {
            x: self.u[i],
            y: self.v[i],
        };
        let output = curve_add(self.d, input, window);
        let a = input.x * window.y;
        let b = input.y * window.x;
        let c = self.d * a * b;
        WindowWitness {
            input,
            window,
            output,
            b0,
            b1,
            b2,
            a,
            b,
            c,
        }
    }

    /// Checks that:
    ///
    /// - uv = window[s0 + 2*s1 + 4*s2]
    /// - xy_r = xy <Edwards Addition> uv
    pub fn gadget<CS: ConstraintSystem>(
        &self,
        cs: &mut CS,
        witness: Option<&WindowWitness>,
        input: Point, // input point
        s0: Bit,
        s1: Bit,
        s2: Bit, // s = s0 + 2 * s1 + 4 * s2
    ) -> Result<Point, R1CSError> {
        // do edwards addition
        let (m1, m2, m3, m4) = match witness {
            Some(w) => {
                let m1 = cs.allocate_multiplier(Some((w.input.x, w.window.y)))?;
                let m2 = cs.allocate_multiplier(Some((w.input.y, w.window.x)))?;
                let m3 = cs.allocate_multiplier(Some((Scalar::one() + w.c, w.output.x)))?;
                let m4 = cs.allocate_multiplier(Some((Scalar::one() - w.c, w.output.y)))?;
                (m1, m2, m3, m4)
            }
            None => {
                let m1 = cs.allocate_multiplier(None)?;
                let m2 = cs.allocate_multiplier(None)?;
                let m3 = cs.allocate_multiplier(None)?;
                let m4 = cs.allocate_multiplier(None)?;
                (m1, m2, m3, m4)
            }
        };

        let (input_x, window_y, a) = m1;
        let (input_y, window_x, b) = m2;
        let (one_p_c, output_x, left1) = m3;
        let (one_m_c, output_y, left2) = m4;

        let (_, _, t) = cs.multiply(input.x + input.y, window_y - window_x);
        let (_, _, c) = cs.multiply(self.d * a, b.into());

        cs.constrain(input_x - input.x);
        cs.constrain(input_y - input.y);
        cs.constrain(one() + c - one_p_c);
        cs.constrain(one() - c - one_m_c);
        cs.constrain(left1 - (a + b));
        cs.constrain(left2 - (t - a + b));

        // constrain "window" to window lookup
        let sa = Bit::mul(cs, s1, s2);
        lookup(cs, sa, s0, s1, s2, window_x.into(), &self.u);
        lookup(cs, sa, s0, s1, s2, window_y.into(), &self.v);

        // the result should fit on the curve
        // (only checked for each individual window in tests)
        #[cfg(debug_assertions)]
        if cfg!(test) {
            let (_, _, x2) = cs.multiply(output_x.into(), output_x.into());
            let (_, _, y2) = cs.multiply(output_y.into(), output_y.into());
            let (_, _, x2y2) = cs.multiply(x2.into(), y2.into());
            cs.constrain((x2 + y2) - (one() + self.d * x2y2));
        };

        Ok(Point {
            x: output_x,
            y: output_y,
        })
    }
}

mod tests {
    use super::*;

    use bulletproofs::{BulletproofGens, PedersenGens};
    use curve25519_dalek::ristretto::CompressedRistretto;
    use merlin::Transcript;

    use rand::thread_rng;
    use rand::Rng;

    use test::Bencher;

    use num_traits::One;

    fn scalar_mult(d: Scalar, scalar: curve::Fp, p: PointValue) -> PointValue {
        let mut pow = p;
        let mut res = curve::identity();
        for b in scalar.iter_bit().map(|b| b.0 != 0) {
            if b {
                res = curve_add(d, res, pow);
            }
            pow = curve_add(d, pow, pow);
        }
        res
    }

    #[test]
    fn test_randomization_compute() {
        let mut rng = thread_rng();
        let randomize = FixScalarMult::new(curve::param_d(), curve::generator());
        let scalar = curve::Fp::random(&mut rng);
        let point = randomize.compute(scalar, curve::identity());
        let real = scalar_mult(curve::param_d(), scalar, curve::generator());
        println!(
            "scalar = {:?}, -scalar = {:?}, point = {:?}",
            scalar, -scalar, point
        );
        assert_eq!(point, real);
    }

    #[test]
    fn test_lookup_proof() {
        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(128, 1);

        let mut rng = thread_rng();

        let u: [Scalar; 8] = [
            Scalar::random(&mut rng),
            Scalar::random(&mut rng),
            Scalar::random(&mut rng),
            Scalar::random(&mut rng),
            Scalar::random(&mut rng),
            Scalar::random(&mut rng),
            Scalar::random(&mut rng),
            Scalar::random(&mut rng),
        ];

        let b0: bool = rng.gen();
        let b1: bool = rng.gen();
        let b2: bool = rng.gen();

        let i = (b0 as usize) + 2 * (b1 as usize) + 4 * (b2 as usize);

        // happy path
        {
            let mut prover = Prover::new(&pc_gens, Transcript::new(b"Test"));
            let mut verifier = Verifier::new(Transcript::new(b"Test"));

            let s0 = Bit::new(&mut prover, b0).unwrap();
            let s1 = Bit::new(&mut prover, b1).unwrap();
            let s2 = Bit::new(&mut prover, b2).unwrap();
            let sa = Bit::mul(&mut prover, s1, s2);

            let blind_e = Scalar::random(&mut rng);
            let value_e = u[i];

            // prove

            let (comm_e, input_e) = prover.commit(value_e, blind_e);

            lookup(&mut prover, sa, s0, s1, s2, input_e.into(), &u);

            let proof = prover.prove(&bp_gens).unwrap();

            // verify

            let s0 = Bit::free(&mut verifier).unwrap();
            let s1 = Bit::free(&mut verifier).unwrap();
            let s2 = Bit::free(&mut verifier).unwrap();
            let sa = Bit::mul(&mut verifier, s1, s2);

            let input_e = verifier.commit(comm_e);

            lookup(&mut verifier, sa, s0, s1, s2, input_e.into(), &u);

            assert!(verifier.verify(&proof, &pc_gens, &bp_gens).is_ok())
        }

        // error path
        {
            let mut prover = Prover::new(&pc_gens, Transcript::new(b"Test"));
            let mut verifier = Verifier::new(Transcript::new(b"Test"));

            let s0 = Bit::new(&mut prover, b0).unwrap();
            let s1 = Bit::new(&mut prover, b1).unwrap();
            let s2 = Bit::new(&mut prover, b2).unwrap();
            let sa = Bit::mul(&mut prover, s1, s2);

            let blind_e = Scalar::random(&mut rng);
            let value_e = Scalar::random(&mut rng);

            // prove

            let (comm_e, input_e) = prover.commit(value_e, blind_e);

            lookup(&mut prover, sa, s0, s1, s2, input_e.into(), &u);

            let proof = prover.prove(&bp_gens).unwrap();

            // verify

            let s0 = Bit::free(&mut verifier).unwrap();
            let s1 = Bit::free(&mut verifier).unwrap();
            let s2 = Bit::free(&mut verifier).unwrap();
            let sa = Bit::mul(&mut verifier, s1, s2);

            let input_e = verifier.commit(comm_e);

            lookup(&mut verifier, sa, s0, s1, s2, input_e.into(), &u);

            assert!(verifier.verify(&proof, &pc_gens, &bp_gens).is_err())
        }
    }

    #[test]
    fn test_window_proof() {
        let ed_window = EdwardsWindow::new(
            Scalar::from_bytes_mod_order([
                0x33, 0xd1, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
                0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x10,
            ]),
            curve::generator(),
        );

        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(128, 1);
        let transcript = Transcript::new(b"Test");
        let mut prover = Prover::new(&pc_gens, transcript);

        let transcript = Transcript::new(b"Test");
        let mut verifier = Verifier::new(transcript);

        // compute witness

        let input = PointValue {
            x: Scalar::one(),
            y: Scalar::zero(),
        };

        let s0 = Bit::new(&mut prover, true).unwrap();
        let s1 = Bit::new(&mut prover, true).unwrap();
        let s2 = Bit::new(&mut prover, true).unwrap();

        let witness = ed_window.compute(input, true, true, true);

        let blind_x = Scalar::from(53753735735u64); // clearly a dummy
        let blind_y = Scalar::from(46713612753u64);

        // prove

        let (comm_x, input_x) = prover.commit(input.x, blind_x);
        let (comm_y, input_y) = prover.commit(input.y, blind_y);

        let input = Point {
            x: input_x,
            y: input_y,
        };

        ed_window
            .gadget(&mut prover, Some(&witness), input, s0, s1, s2)
            .unwrap();

        let proof = prover.prove(&bp_gens).unwrap();

        // verify

        let s0 = Bit::free(&mut verifier).unwrap();
        let s1 = Bit::free(&mut verifier).unwrap();
        let s2 = Bit::free(&mut verifier).unwrap();

        let input_x = verifier.commit(comm_x);
        let input_y = verifier.commit(comm_y);

        let input = Point {
            x: input_x,
            y: input_y,
        };

        ed_window
            .gadget(&mut verifier, None, input, s0, s1, s2)
            .unwrap();

        verifier.verify(&proof, &pc_gens, &bp_gens).unwrap()
    }

    #[bench]
    fn randomize_prove(b: &mut Bencher) {
        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(2100, 1);

        let randomize = FixScalarMult::new(curve::param_d(), curve::generator());

        // compute witness

        let input = PointValue {
            x: Scalar::one(),
            y: Scalar::zero(),
        };

        // pick random scalar

        let mut rng = thread_rng();
        let scalar = curve::Fp::random(&mut rng);
        let witness = randomize.witness(input, scalar);

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

        let randomize = FixScalarMult::new(curve::param_d(), curve::generator());

        // compute witness

        let input = PointValue {
            x: Scalar::one(),
            y: Scalar::zero(),
        };

        // pick random scalar

        let mut rng = thread_rng();
        let scalar = curve::Fp::random(&mut rng);
        let witness = randomize.witness(input, scalar);

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
    fn test_randomize_proof() {
        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(2100, 1);
        let transcript = Transcript::new(b"Test");
        let mut prover = Prover::new(&pc_gens, transcript);

        let transcript = Transcript::new(b"Test");
        let mut verifier = Verifier::new(transcript);

        let randomize = FixScalarMult::new(curve::param_d(), curve::generator());

        // pick random point

        let mut rng = thread_rng();
        let input = randomize.compute(curve::Fp::random(&mut rng), curve::identity());

        // pick random scalar

        let scalar = curve::Fp::random(&mut rng);
        let witness = randomize.witness(input, scalar);

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
