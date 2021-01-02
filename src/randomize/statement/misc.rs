use bulletproofs::r1cs::*;
use curve25519_dalek::scalar::Scalar;

/// A variable which is constraint to be a bit-value
/// (can be converted into a Variable, but not vise versa)
#[derive(Copy, Clone, Debug)]
pub struct Bit(Variable, Option<bool>);

impl Into<Variable> for Bit {
    fn into(self) -> Variable {
        self.0
    }
}

impl Into<LinearCombination> for Bit {
    fn into(self) -> LinearCombination {
        self.0.into()
    }
}

impl Bit {
    pub fn free<CS: ConstraintSystem>(cs: &mut CS) -> Result<Bit, R1CSError> {
        Ok(Bit(bit(cs, None)?, None))
    }

    pub fn new<CS: ConstraintSystem>(cs: &mut CS, v: bool) -> Result<Bit, R1CSError> {
        Ok(Bit(
            bit(cs, Some(if v { Scalar::one() } else { Scalar::zero() }))?,
            Some(v),
        ))
    }

    pub fn value(&self) -> Option<bool> {
        self.1
    }

    pub fn mul<CS: ConstraintSystem>(cs: &mut CS, left: Self, right: Self) -> Self {
        let (_, _, sa) = cs.multiply(left.0.into(), right.0.into());
        Self(sa, None)
    }
}

fn bit<CS: ConstraintSystem>(cs: &mut CS, v: Option<Scalar>) -> Result<Variable, R1CSError> {
    let (a, b, c) = match v {
        Some(bit) => {
            debug_assert!(bit == Scalar::one() || bit == Scalar::zero());
            cs.allocate_multiplier(Some((bit, Scalar::one() - bit)))
        }
        None => cs.allocate_multiplier(None),
    }?;
    let lc: LinearCombination = a.into();
    cs.constrain(lc - (Scalar::one() - b));
    cs.constrain(c.into());
    Ok(a)
}

pub fn one() -> LinearCombination {
    Scalar::one().into()
}
