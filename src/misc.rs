use bulletproofs::r1cs::*;
use curve25519_dalek::scalar::Scalar;

pub fn one() -> LinearCombination {
    Scalar::one().into()
}

/// constrain b \in {0, 1} by checking that:
/// b * (1 - b) = 0
#[inline(always)]
pub fn bit_gadget<CS: ConstraintSystem>(cs: &mut CS, b: Variable) {
    let (_, _, m) = cs.multiply(b.into(), one() - b);
    cs.constrain(m.into());
}
