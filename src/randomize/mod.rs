mod statement;

use merlin::Transcript;

use bulletproofs::r1cs::{Prover, R1CSProof, Verifier};
use bulletproofs::{BulletproofGens, PedersenGens};

use statement::{curve, PointValue, Statement};

use rand_core::OsRng;

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;

use serde::{Deserialize, Serialize};

use proofsize_derive::*;

#[derive(Serialize, Deserialize, Debug, ProofSize)]
pub struct Proof(R1CSProof);

pub type InnerCommRandomness = curve::Fp;
pub type InnerCommitment = PointValue;

pub fn dummy_comm() -> PointValue {
    curve::identity()
}

pub struct Rerandomization {
    bp_gens: BulletproofGens,
    pc_gens: PedersenGens,
    statement: Statement,
}

impl Rerandomization {
    pub fn new() -> Self {
        Self {
            pc_gens: PedersenGens::default(),
            bp_gens: BulletproofGens::new(2100, 1),
            statement: Statement::new(curve::param_d()),
        }
    }

    pub fn commit(&self, value: Scalar, blinding: Scalar) -> RistrettoPoint {
        self.pc_gens.commit(value, blinding)
    }

    pub fn is_permissible(&self, point: PointValue) -> bool {
        self.statement.permissible.is_permissible(point)
    }

    /// Finds a randomness which makes the commitment `inner_open` "permissible".
    ///
    /// e.g. given:
    ///
    /// inner_open = h^v
    ///
    /// Find r st. inner_open * g^r is permissible.
    ///
    /// Arguments:
    ///
    /// * `inner_open`: Binding (non-hiding) Pedersen commitment over Jabberwock
    ///
    /// Returns:
    ///
    /// * The randomness used in the blinding
    /// * The resulting blinded commitment (point on Jabberwock).
    pub fn find_permissible(&self, inner_open: PointValue) -> (InnerCommRandomness, PointValue) {
        self.statement
            .find_permissible_randomness(&mut OsRng, inner_open)
    }

    pub fn rerandomize_comm(
        &self,
        inner_r: InnerCommRandomness,
        inner_open: PointValue,
    ) -> PointValue {
        self.statement.rerandomize.compute(inner_r, inner_open)
    }

    /// Prove that a commitment over Risetto25519, contains a commitment (over Jabberwock)
    /// which opens to a particular value, without revealing any commitment randomness.
    ///
    /// Arguments:
    ///    
    /// * `outer_r`: Commitment randomness for the outer commitment (over Risetto25519)
    /// * `inner_r`: Commitment randomness for the inner commitment (over Jabberwock)
    /// * `inner_open`: Inner commitment (without the randomness)
    ///
    /// `outer_r` and `inner_r` forms the witness.
    ///
    /// While `inner_open` and the outer commitment (implicitly defined in this method):
    /// `comm = g^outer_r h^{g'^inner_r xy}`
    /// Forms the statement.
    ///
    /// In effect opening the both the nested outer and inner commitments without revealing the randomness.
    ///
    /// Returns:
    ///
    /// * A proof of knowledge for `outer_r` and `inner_r`.
    /// * The outer commitment `comm`
    pub fn prove(
        &self,
        outer_r: Scalar,              // witness (outer commitment randomness)
        inner_r: InnerCommRandomness, // witness (inner commitment randomness)
        inner_input: PointValue,      // input point
    ) -> (Proof, PointValue, CompressedRistretto) {
        // input point must be permissible
        debug_assert!(self.is_permissible(inner_input));

        // re-randomized output.
        // output point need not be permissible
        let inner_output = self.rerandomize_comm(inner_r, inner_input);

        let transcript = Transcript::new(b"Randomize");
        let mut prover = Prover::new(&self.pc_gens, transcript);

        // the witness is the input to the re-randomization and the inner_r randomization scalar
        let witness = self.statement.witness(inner_input, inner_r);

        // statement defined by the re-randomized output (a constant in the circuit)
        let (outer_comm, input_x) = prover.commit(inner_input.x, outer_r);
        self.statement
            .gadget(&mut prover, Some(&witness), input_x, inner_output)
            .unwrap();

        (
            Proof(prover.prove(&self.bp_gens).unwrap()),
            inner_output,
            outer_comm,
        )
    }

    /// Verify a previously produced proof
    ///
    /// * `proof`:
    /// * `outer_comm`: Statement, Outer commitment (hiding)
    /// * `inner_open`: Statement, Inner commitment (without the randomness, not hiding)
    ///
    /// Returns:
    ///
    /// True iff. the proof is valid for the statement.
    pub fn verify(
        &self,
        proof: &Proof,                   //
        outer_comm: CompressedRistretto, // outer commitment
        inner_open: PointValue,          // inner commitment (without the randomness)
    ) -> bool {
        let transcript = Transcript::new(b"Randomize");
        let mut verifier = Verifier::new(transcript);

        let comm_x = verifier.commit(outer_comm);

        self.statement
            .gadget(&mut verifier, None, comm_x, inner_open)
            .unwrap();

        verifier
            .verify(&proof.0, &self.pc_gens, &self.bp_gens)
            .is_ok()
    }
}
