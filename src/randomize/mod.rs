mod statement;

use merlin::Transcript;

use bulletproofs::r1cs::{Prover, R1CSProof, Verifier};
use bulletproofs::{BulletproofGens, PedersenGens};

use statement::{curve, PointValue, Statement};

use rand_core::OsRng;

use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct Proof(R1CSProof);

pub type InnerCommRandomness = curve::Fp;
pub type InnerCommitment = PointValue;

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
    pub fn find_permissible(&self, inner_open: PointValue) -> (curve::Fp, PointValue) {
        self.statement
            .find_permissible_randomness(&mut OsRng, inner_open)
    }

    pub fn rerandomize_comm(&self, inner_r:curve::Fp, inner_open:PointValue) -> PointValue {
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
        outer_r: Scalar,        // witness (outer commitment randomness)
        inner_r: InnerCommRandomness,     // witness (inner commitment randomness)
        inner_open: PointValue, // statement
    ) -> (Proof, CompressedRistretto) {
        let transcript = Transcript::new(b"Randomize");
        let mut prover = Prover::new(&self.pc_gens, transcript);

        let comm = self.rerandomize_comm(inner_r, inner_open);

        let witness = self.statement.witness(comm, -inner_r);

        let (comm_x, input_x) = prover.commit(comm.x, outer_r);

        self.statement
            .gadget(&mut prover, Some(&witness), input_x, inner_open)
            .unwrap();

        (Proof(prover.prove(&self.bp_gens).unwrap()), comm_x)
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
