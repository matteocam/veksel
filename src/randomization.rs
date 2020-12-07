use crate::curve::{EdwardsWindow, WINDOW_SIZE};
use crate::misc::Bit;
use crate::window::windows;

use curve25519_dalek::scalar::Scalar;

/*
pub fn prove(mut xy: (Scalar, Scalar), bits: &[Bit]) -> () {
    let scalar_windows = windows();
    let scalar_bits = bits.chunks(WINDOW_SIZE);
    assert_eq!(bits.len(), WINDOW_SIZE * scalar_windows.len());
    for (w, b) in scalar_windows.iter().zip(scalar_bits) {
        let (uv, p) = w.compute(xy, b[0], b[1], b[2]);
        xy = p;
    }
}
*/
