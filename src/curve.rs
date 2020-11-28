use bulletproofs::r1cs::*;
use bulletproofs::{BulletproofGens, PedersenGens};

use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;

use merlin::Transcript;

use crate::misc::{bit_gadget, one};

struct EdwardsWindow {
    d: Scalar,
    u: [Scalar; 8],
    v: [Scalar; 8],
}

fn curve_add(d: Scalar, xy: (Scalar, Scalar), uv: (Scalar, Scalar)) -> (Scalar, Scalar) {
    debug_assert!(curve_check(d, xy.0, xy.1), "left input not on curve");
    debug_assert!(curve_check(d, uv.0, uv.1), "right input not on curve");
    let p = d * xy.0 * xy.1 * uv.0 * uv.1;
    let x = (xy.0 * uv.1 + uv.0 * xy.1) * (Scalar::one() + p).invert();
    let y = (xy.1 * uv.1 - xy.0 * uv.0) * (Scalar::one() - p).invert();
    debug_assert!(curve_check(d, x, y), "result not on curve");
    (x, y)
}

fn curve_check(d: Scalar, x: Scalar, y: Scalar) -> bool {
    let x2 = x * x;
    let y2 = y * y;
    x2 + y2 == Scalar::one() + d * x2 * y2
}

/// Generate a constraint which verifies that (x, y) is a point on the Edwards curve defined by d.
#[inline(always)]
fn curve_check_gadget<CS: ConstraintSystem>(cs: &mut CS, d: Scalar, x: Scalar, y: Scalar) {
    let (_, _, x2) = cs.multiply(x.into(), x.into());
    let (_, _, y2) = cs.multiply(y.into(), y.into());
    let (_, _, x2y2) = cs.multiply(x2.into(), y2.into());
    cs.constrain(one() + d * x2y2 - x2 - y2);
}

// constrain u = elems[s0 + s1*2 + s2*4] with sA = s1 * s2
#[inline(always)]
fn lookup<CS: ConstraintSystem>(
    cs: &mut CS,
    sa: Variable,
    s0: Variable,
    s1: Variable,
    s2: Variable,
    e: Variable,
    u: &[Scalar; 8],
) {
    // left side
    let (_, _, left): (Variable, Variable, Variable) = cs.multiply(s0.into(), {
        // line 1 in paper
        let f = -u[0] * sa + u[0] * s2 + u[0] * s1 - u[0] + u[2] * sa;
        let f = f - u[2] * s1 + u[4] * sa - u[4] * s2 - u[6] * sa;

        // line 2 in paper
        let f = f + u[1] * sa - u[1] * s2 + u[1] - u[3] * sa + u[3] * s1;
        f - u[5] * sa + u[5] * s2 + u[7] * sa
    });

    // right size
    let right: LinearCombination = e - u[0] * sa + u[0] * s2 + u[0] * s1 - u[0] + u[2] * sa;
    let right = right - u[2] * s1 + u[4] * sa - u[4] * s2 - u[6] * sa;

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
        xy: (Scalar, Scalar), // input
        s0: Scalar,           // scalar (0th bit)
        s1: Scalar,           // scalar (1st bit)
        s2: Scalar,           // scalar (2nd bit)
    ) -> ((Scalar, Scalar), (Scalar, Scalar)) {
        debug_assert!(curve_check(self.d, xy.0, xy.1));

        // do window lookup
        let i0: usize = if s0 == Scalar::one() { 1 } else { 0 };
        let i1: usize = if s1 == Scalar::one() { 1 } else { 0 };
        let i2: usize = if s2 == Scalar::one() { 1 } else { 0 };
        let i = i0 + i1 * 2 + i2 * 4;
        let uv = (self.u[i], self.v[i]);

        // compute edwards sum
        let p = self.d * xy.0 * xy.1 * uv.0 * uv.1;
        let x = (xy.0 * uv.1 + uv.0 * xy.1) * (Scalar::one() + p).invert();
        let y = (xy.1 * uv.1 - xy.0 * uv.0) * (Scalar::one() - p).invert();

        // assert still on curve (sanity check)
        (uv, (x, y))
    }

    /// Checks that:
    ///
    /// - s0 \in {0, 1}
    /// - s1 \in {0, 1}
    /// - s2 \in {0, 1}
    /// - uv = window[s0 + 2*s1 + 4*s2]
    /// - xy_r = xy <Edwards Addition> uv
    pub fn gadget<CS: ConstraintSystem>(
        &self,
        cs: &mut CS,
        xy: (Variable, Variable),   // input point
        xy_r: (Variable, Variable), // output point
        s0: Variable,
        s1: Variable,
        s2: Variable,             // s = s0 + 2 * s1 + 4 * s2
        uv: (Variable, Variable), // window[s]
    ) -> Result<(), R1CSError> {
        // limit s0, s1, s2 \in {0, 1}
        bit_gadget(cs, s0);
        bit_gadget(cs, s1);
        bit_gadget(cs, s2);

        // constrain "uv" to window lookup
        let (_, _, sa) = cs.multiply(s1.into(), s2.into());
        lookup(cs, sa, s0, s1, s2, uv.0, &self.u);
        lookup(cs, sa, s0, s1, s2, uv.1, &self.v);

        // do edwards addition
        let (_, _, t) = cs.multiply(xy.0 + xy.1, uv.1 - uv.0);
        let (_, _, a) = cs.multiply(xy.0.into(), uv.1.into());
        let (_, _, b) = cs.multiply(xy.1.into(), uv.0.into());
        let (_, _, c) = cs.multiply(self.d * a, b.into());

        let (_, _, left) = cs.multiply(one() + c, xy_r.0.into());
        cs.constrain(left - (a + b));

        let (_, _, left) = cs.multiply(one() - c, xy_r.1.into());
        cs.constrain(left - (t - a + b));
        Ok(())
    }
}
