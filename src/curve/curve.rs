use bulletproofs::r1cs::*;

use curve25519_dalek::scalar::Scalar;

pub const WINDOW_SIZE: usize = 3;

use crate::misc::{one, Bit};

#[derive(Copy, Clone, Debug)]
pub struct PointValue {
    pub x: Scalar,
    pub y: Scalar,
}

#[derive(Copy, Clone, Debug)]
pub struct Point {
    pub x: Variable,
    pub y: Variable,
}

impl Point {
    fn free<CS: ConstraintSystem>(cs: &mut CS) -> Result<Self, R1CSError> {
        let x = cs.allocate(None)?;
        let y = cs.allocate(None)?;
        Ok(Point { x, y })
    }
}

impl PointValue {
    fn check(&self, d: Scalar) -> bool {
        let x2 = self.x * self.x;
        let y2 = self.y * self.y;
        x2 + y2 == Scalar::one() + d * x2 * y2
    }

    fn assign<CS: ConstraintSystem>(&self, cs: &mut CS) -> Result<Point, R1CSError> {
        let x = cs.allocate(Some(self.x))?;
        let y = cs.allocate(Some(self.y))?;
        Ok(Point { x, y })
    }
}

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
    u: [Scalar; 8],
    v: [Scalar; 8],
}

fn curve_add(d: Scalar, a: PointValue, b: PointValue) -> PointValue {
    debug_assert!(a.check(d));
    debug_assert!(b.check(d));
    let p = d * a.x * a.y * b.x * b.y;
    let x = (a.x * b.y + b.x * a.y) * (Scalar::one() + p).invert();
    let y = (a.y * b.y - a.x * b.x) * (Scalar::one() - p).invert();
    let p = PointValue { x, y };
    debug_assert!(p.check(d));
    p
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

    #[test]
    fn test_lookup() {
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
    fn test_window() {
        let ed_window = EdwardsWindow::new(
            Scalar::from_bytes_mod_order([
                0x33, 0xd1, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
                0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x10,
            ]),
            [
                Scalar::from_bytes_mod_order([
                    0xdb, 0x1e, 0x0a, 0x52, 0x13, 0x69, 0x32, 0x98, 0x03, 0x1a, 0x82, 0x2a, 0xbf,
                    0x67, 0x1a, 0x52, 0xf1, 0x13, 0x27, 0x1b, 0x1f, 0xc3, 0xad, 0x18, 0x6d, 0x67,
                    0xd5, 0x34, 0xa2, 0xec, 0x9e, 0x0f,
                ]),
                Scalar::from_bytes_mod_order([
                    0x46, 0x79, 0x99, 0x76, 0x9d, 0x1b, 0xe6, 0x14, 0x16, 0xc4, 0xfc, 0xe5, 0x84,
                    0xe3, 0xbc, 0x89, 0x9e, 0xf6, 0x6c, 0x1b, 0xae, 0xd0, 0x8c, 0xf0, 0x36, 0xaa,
                    0x10, 0x68, 0x6d, 0x5e, 0x6f, 0x07,
                ]),
                Scalar::from_bytes_mod_order([
                    0x18, 0xc8, 0x2f, 0xe0, 0x2f, 0x08, 0x57, 0x29, 0xf4, 0x82, 0x61, 0xc8, 0x60,
                    0x7f, 0xee, 0xd7, 0xf0, 0xc4, 0x52, 0x79, 0x9a, 0x12, 0x92, 0x5b, 0x10, 0xc8,
                    0x5a, 0x73, 0x98, 0xa1, 0x5c, 0x01,
                ]),
                Scalar::from_bytes_mod_order([
                    0x13, 0x9a, 0x09, 0x66, 0xad, 0xc8, 0x54, 0xc3, 0x56, 0x87, 0xc5, 0x26, 0x13,
                    0x1a, 0x00, 0xaa, 0xe8, 0x07, 0x4e, 0x61, 0xe5, 0x97, 0x03, 0x2a, 0x93, 0x9b,
                    0x22, 0xe9, 0xe0, 0x46, 0x94, 0x0b,
                ]),
                Scalar::from_bytes_mod_order([
                    0x41, 0x3c, 0xf9, 0xbc, 0x39, 0x5d, 0x8f, 0x29, 0x2e, 0xc9, 0x9d, 0x7d, 0xf3,
                    0xc0, 0x45, 0x73, 0xae, 0xed, 0x3c, 0x03, 0x19, 0xf7, 0xc9, 0xce, 0xf4, 0x23,
                    0x04, 0xba, 0xf6, 0x1a, 0x3b, 0x01,
                ]),
                Scalar::from_bytes_mod_order([
                    0x8a, 0x28, 0x23, 0xca, 0x30, 0xe8, 0x34, 0xe6, 0xdb, 0x52, 0x4d, 0x4a, 0x8e,
                    0x33, 0xc0, 0xea, 0x81, 0x7f, 0x0f, 0x51, 0x50, 0xcc, 0x63, 0xa7, 0x69, 0xf9,
                    0xb1, 0xa7, 0x0f, 0xd0, 0x0c, 0x02,
                ]),
                Scalar::from_bytes_mod_order([
                    0x54, 0xce, 0xe0, 0x0a, 0x66, 0x8d, 0xc5, 0xb5, 0x65, 0xd5, 0xc1, 0x67, 0xf2,
                    0xc6, 0x8b, 0x3f, 0x3c, 0x13, 0xfc, 0xb8, 0xf1, 0x2e, 0xd3, 0xae, 0xec, 0x95,
                    0xcf, 0xb9, 0xec, 0x5a, 0x10, 0x05,
                ]),
                Scalar::from_bytes_mod_order([
                    0x35, 0x05, 0x91, 0x3c, 0x06, 0x8f, 0x31, 0x70, 0xc0, 0xea, 0x9e, 0x57, 0x1b,
                    0x3b, 0xa3, 0x46, 0xf8, 0x50, 0x45, 0x05, 0xa5, 0xf0, 0xc1, 0x80, 0x01, 0x0b,
                    0xed, 0x36, 0x37, 0xf8, 0x86, 0x0a,
                ]),
            ],
            [
                Scalar::from_bytes_mod_order([
                    0x46, 0x69, 0xe7, 0xe0, 0xa7, 0x47, 0x35, 0x27, 0xc9, 0x33, 0xdc, 0x8c, 0x75,
                    0xd0, 0xd0, 0xaa, 0x7f, 0xc7, 0x54, 0xe4, 0x18, 0x64, 0x96, 0xdd, 0xf4, 0x65,
                    0xaa, 0x66, 0x85, 0xc2, 0x0f, 0x07,
                ]),
                Scalar::from_bytes_mod_order([
                    0xe9, 0xbe, 0x6d, 0x04, 0x21, 0x44, 0x53, 0x95, 0x60, 0x7a, 0x94, 0x25, 0xc4,
                    0x16, 0x5c, 0xe0, 0xe3, 0xad, 0x7a, 0xdc, 0x54, 0x84, 0xd8, 0xb7, 0xd0, 0x62,
                    0xca, 0x9d, 0xf8, 0x37, 0xae, 0x01,
                ]),
                Scalar::from_bytes_mod_order([
                    0x4b, 0x47, 0x1b, 0xd7, 0xe1, 0x0d, 0x8c, 0xa8, 0x22, 0x1b, 0x5c, 0xbb, 0x9c,
                    0x97, 0xb3, 0xf9, 0x62, 0xe0, 0x32, 0xe4, 0x71, 0x09, 0x9d, 0x34, 0x71, 0xb1,
                    0xd6, 0x94, 0x29, 0x57, 0x48, 0x09,
                ]),
                Scalar::from_bytes_mod_order([
                    0xf6, 0x1e, 0xad, 0x4f, 0x6b, 0x4e, 0xc7, 0x1c, 0xfe, 0xef, 0xf7, 0x5a, 0x37,
                    0x3e, 0x78, 0x2d, 0xdf, 0x08, 0x13, 0xe6, 0xb4, 0x73, 0x43, 0x02, 0xc8, 0x2c,
                    0x1f, 0x37, 0xdd, 0x98, 0x95, 0x02,
                ]),
                Scalar::from_bytes_mod_order([
                    0xaf, 0xcf, 0xe1, 0xd5, 0x0c, 0x36, 0x62, 0x2e, 0xa2, 0x9b, 0xf5, 0x3c, 0xb5,
                    0xce, 0x97, 0xd0, 0x34, 0xfa, 0xcd, 0x63, 0xfa, 0x41, 0x16, 0x78, 0x73, 0x4a,
                    0x0a, 0x8b, 0x0c, 0x95, 0xdf, 0x0b,
                ]),
                Scalar::from_bytes_mod_order([
                    0x5d, 0x63, 0xe9, 0xd9, 0x83, 0x12, 0x5d, 0xa2, 0x64, 0x1d, 0x02, 0x08, 0x0b,
                    0x6e, 0x34, 0x66, 0x4d, 0x43, 0x46, 0xdf, 0x69, 0x17, 0xae, 0xc6, 0xae, 0xce,
                    0xd5, 0xfa, 0xa1, 0xaa, 0xfb, 0x0c,
                ]),
                Scalar::from_bytes_mod_order([
                    0x01, 0xee, 0x0f, 0x64, 0x69, 0x63, 0xdd, 0x0b, 0x39, 0x83, 0xdc, 0xcf, 0xb4,
                    0x9b, 0x6d, 0x8a, 0x69, 0xd4, 0x3b, 0x27, 0x48, 0xbb, 0x18, 0xd1, 0x1e, 0x77,
                    0x8e, 0x27, 0x47, 0xeb, 0xa9, 0x05,
                ]),
                Scalar::from_bytes_mod_order([
                    0xfd, 0xde, 0xac, 0xdf, 0xae, 0xae, 0x0b, 0xf3, 0x80, 0xf1, 0x91, 0x6c, 0x00,
                    0xbe, 0x5e, 0xaf, 0x42, 0x37, 0x53, 0xbb, 0x5d, 0xef, 0x4b, 0x8f, 0xb5, 0x52,
                    0xd8, 0xda, 0x09, 0x25, 0x75, 0x07,
                ]),
            ],
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
}
