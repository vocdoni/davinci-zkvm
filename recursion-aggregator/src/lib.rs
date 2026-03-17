//! Recursion aggregator for davinci-stark ballot proofs.
//!
//! Aggregates N individual ballot HidingFriPcs (ZK) proofs into a single
//! batch-STARK proof using the Plonky3-recursion library. This enables
//! constant-size verification regardless of how many ballots are aggregated.
//!
//! # Architecture
//!
//! The aggregation follows a binary-tree structure:
//!
//! 1. **Leaf layer**: each ballot UniStark proof is wrapped into a BatchStark
//!    proof via `build_and_prove_next_layer`.
//! 2. **Aggregation layers**: pairs of BatchStark proofs are combined via
//!    `build_and_prove_aggregation_layer` until a single root proof remains.
//!
//! The resulting [`AggregatedBallotProof`] contains the final BatchStark proof
//! and the common data needed to verify it.

use std::rc::Rc;
use std::sync::Arc;

use anyhow::{Context, Result};
use tracing::{debug, info, warn};

// -- davinci-stark types --
use davinci_stark::air::{BallotAir, PV_COUNT};
use davinci_stark::config::{
    BallotConfig, Challenge, Challenger, ChallengeMmcs, MyCompress, MyHash, Pcs, Val, ValMmcs,
};

// -- Plonky3 core --
use p3_commit::Pcs as PcsTrait;
use p3_goldilocks::default_goldilocks_poseidon2_8;
use p3_uni_stark::{Proof, StarkGenericConfig, Val as StarkVal};

// -- Plonky3-recursion circuit --
use p3_circuit::ops::{GoldilocksD2Width8, generate_poseidon2_trace, generate_recompose_trace};
use p3_circuit::{CircuitBuilder, CircuitRunner, NonPrimitiveOpId};

// -- Plonky3-recursion circuit-prover --
use p3_circuit_prover::{
    BatchStarkProver, CircuitProverData, ConstraintProfile, Poseidon2Config, TablePacking,
};

// -- Plonky3-recursion recursion --
use p3_recursion::pcs::{
    HidingFriProofTargets, InputProofTargets, MerkleCapTargets, RecExtensionValMmcs, RecValMmcs,
    Witness, set_hiding_fri_mmcs_private_data,
};
use p3_recursion::traits::{RecursiveAir, RecursivePcs};
use p3_recursion::verifier::VerificationError;
use p3_recursion::{
    AggregationPrepCache, BatchOnly, FriRecursionBackend, FriRecursionConfig, FriVerifierParams,
    ProveNextLayerParams, RecursionInput, RecursionOutput, build_and_prove_aggregation_layer,
    build_and_prove_next_layer,
};

// -- Plonky3-recursion batch-stark types --
use p3_circuit_prover::BatchStarkProof;

use p3_lookup::logup::LogUpGadget;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Extension degree for Goldilocks (D=2).
const D: usize = 2;

/// Number of digest elements in the Merkle tree (matches davinci-stark).
const DIGEST_ELEMS: usize = 4;

// ---------------------------------------------------------------------------
// FRI proof target type aliases
// ---------------------------------------------------------------------------

/// Recursive MMCS type for the base-field Merkle tree.
type BallotRecValMmcs = RecValMmcs<Val, DIGEST_ELEMS, MyHash, MyCompress>;

/// Recursive MMCS type for the extension-field FRI commitment.
type BallotRecExtMmcs = RecExtensionValMmcs<Val, Challenge, DIGEST_ELEMS, BallotRecValMmcs>;

/// Recursive input proof targets for FRI.
type BallotInputProofTargets = InputProofTargets<Val, Challenge, BallotRecValMmcs>;

/// HidingFRI proof targets for the ZK variant.
type InnerFriZk = HidingFriProofTargets<
    Val,
    Challenge,
    BallotRecExtMmcs,
    BallotInputProofTargets,
    Witness<Val>,
>;

// ---------------------------------------------------------------------------
// BallotRecursionConfig
// ---------------------------------------------------------------------------

/// Wrapper around [`BallotConfig`] that carries the FRI verifier parameters
/// required by the Plonky3-recursion API.
///
/// Implements [`FriRecursionConfig`] for the Goldilocks HidingFriPcs (ZK)
/// configuration used by davinci-stark.
#[derive(Clone)]
pub struct BallotRecursionConfig {
    config: Arc<BallotConfig>,
    fri_verifier_params: FriVerifierParams,
}

impl BallotRecursionConfig {
    /// Create a new recursion config wrapping the given ballot STARK config.
    ///
    /// The FRI verifier parameters are derived from the davinci-stark FRI
    /// configuration: log_blowup=3, log_final_poly_len=0, pow_bits=0.
    pub fn new(config: BallotConfig) -> Self {
        let fri_verifier_params = FriVerifierParams::with_mmcs(
            3, // log_blowup (blowup factor 8)
            0, // log_final_poly_len
            0, // commit_pow_bits
            0, // query_pow_bits
            Poseidon2Config::GoldilocksD2Width8,
        );
        Self {
            config: Arc::new(config),
            fri_verifier_params,
        }
    }
}

impl core::ops::Deref for BallotRecursionConfig {
    type Target = BallotConfig;
    fn deref(&self) -> &BallotConfig {
        &self.config
    }
}

impl StarkGenericConfig for BallotRecursionConfig {
    type Challenge = Challenge;
    type Challenger = Challenger;
    type Pcs = Pcs;

    fn pcs(&self) -> &Pcs {
        self.config.pcs()
    }

    fn initialise_challenger(&self) -> Challenger {
        self.config.initialise_challenger()
    }
}

impl FriRecursionConfig for BallotRecursionConfig
where
    Pcs: RecursivePcs<
        BallotRecursionConfig,
        BallotInputProofTargets,
        InnerFriZk,
        MerkleCapTargets<Val, DIGEST_ELEMS>,
        <Pcs as PcsTrait<Challenge, Challenger>>::Domain,
    >,
{
    type Commitment = MerkleCapTargets<Val, DIGEST_ELEMS>;
    type InputProof = BallotInputProofTargets;
    type OpeningProof = InnerFriZk;
    type RawOpeningProof = <Pcs as PcsTrait<Challenge, Challenger>>::Proof;
    const DIGEST_ELEMS: usize = DIGEST_ELEMS;

    fn with_fri_opening_proof<'a, A, R>(
        prev: &RecursionInput<'a, Self, A>,
        f: impl FnOnce(&Self::RawOpeningProof) -> R,
    ) -> R
    where
        A: RecursiveAir<StarkVal<Self>, Self::Challenge, LogUpGadget>,
    {
        match prev {
            RecursionInput::UniStark { proof, .. } => f(&proof.opening_proof),
            RecursionInput::BatchStark { proof, .. } => f(&proof.proof.opening_proof),
        }
    }

    fn prepare_circuit_for_verification(
        &self,
        circuit: &mut CircuitBuilder<Challenge>,
    ) -> Result<(), VerificationError> {
        let perm = default_goldilocks_poseidon2_8();
        circuit.enable_poseidon2_perm_width_8::<GoldilocksD2Width8, _>(
            generate_poseidon2_trace::<Challenge, GoldilocksD2Width8>,
            perm,
        );
        circuit.enable_recompose::<Val>(generate_recompose_trace::<Val, Challenge>);
        Ok(())
    }

    fn pcs_verifier_params(
        &self,
    ) -> &<Pcs as RecursivePcs<
        BallotRecursionConfig,
        BallotInputProofTargets,
        InnerFriZk,
        MerkleCapTargets<Val, DIGEST_ELEMS>,
        <Pcs as PcsTrait<Challenge, Challenger>>::Domain,
    >>::VerifierParams {
        &self.fri_verifier_params
    }

    fn set_fri_private_data(
        runner: &mut CircuitRunner<Challenge>,
        op_ids: &[NonPrimitiveOpId],
        opening_proof: &Self::RawOpeningProof,
    ) -> Result<(), &'static str> {
        set_hiding_fri_mmcs_private_data::<
            Val,
            Challenge,
            ChallengeMmcs,
            ValMmcs,
            MyHash,
            MyCompress,
            DIGEST_ELEMS,
        >(runner, op_ids, opening_proof)
    }
}

// ---------------------------------------------------------------------------
// AggregatedBallotProof
// ---------------------------------------------------------------------------

/// The output of ballot proof aggregation: a single BatchStark proof that
/// attests to the validity of N individual ballot proofs.
pub struct AggregatedBallotProof {
    /// The aggregated batch-STARK proof.
    pub proof: BatchStarkProof<BallotRecursionConfig>,
    /// Circuit prover data needed for verification (contains common data).
    pub prover_data: Rc<CircuitProverData<BallotRecursionConfig>>,
}

impl std::fmt::Debug for AggregatedBallotProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AggregatedBallotProof")
            .field("proof", &"<BatchStarkProof>")
            .field("prover_data", &"<CircuitProverData>")
            .finish()
    }
}

impl AggregatedBallotProof {
    /// Verify the aggregated proof.
    ///
    /// Reconstructs a [`BatchStarkProver`] with the correct table registrations
    /// (Poseidon2 and recompose) and verifies all tables in the batch proof.
    pub fn verify(&self, config: &BallotRecursionConfig) -> Result<()> {
        let table_packing = default_aggregation_table_packing();
        let mut verifier = BatchStarkProver::new(config.clone())
            .with_table_packing(table_packing);
        verifier.register_poseidon2_table_d2(Poseidon2Config::GoldilocksD2Width8);
        verifier.register_recompose_table_d2();
        verifier
            .verify_all_tables(&self.proof, self.prover_data.common_data())
            .context("aggregated ballot proof verification failed")?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors that can occur during ballot proof aggregation.
#[derive(Debug, thiserror::Error)]
pub enum AggregationError {
    #[error("no proofs provided for aggregation")]
    EmptyInput,

    #[error("public values length mismatch: expected {expected}, got {got} (proof index {index})")]
    PublicValuesLength {
        expected: usize,
        got: usize,
        index: usize,
    },

    #[error("recursion layer {layer} failed at pair {pair}: {source}")]
    RecursionFailed {
        layer: u32,
        pair: usize,
        #[source]
        source: VerificationError,
    },

    #[error("leaf wrapping failed for proof {index}: {source}")]
    LeafWrapping {
        index: usize,
        #[source]
        source: VerificationError,
    },
}

// ---------------------------------------------------------------------------
// Default parameters
// ---------------------------------------------------------------------------

/// Default table packing for the leaf (first) recursion layer.
///
/// The leaf layer wraps a single UniStark proof, so we use modest packing.
fn default_leaf_params() -> ProveNextLayerParams {
    ProveNextLayerParams {
        table_packing: TablePacking::new(1, 2).with_fri_params(0, 3),
        use_npos_in_circuit: true,
        constraint_profile: ConstraintProfile::Standard,
    }
}

/// Default table packing for aggregation layers.
fn default_aggregation_params(level: u32) -> ProveNextLayerParams {
    let table_packing = if level == 1 {
        TablePacking::new(2, 2)
    } else {
        TablePacking::new(1, 4)
    };
    ProveNextLayerParams {
        table_packing: table_packing.with_fri_params(0, 3),
        use_npos_in_circuit: true,
        constraint_profile: ConstraintProfile::Standard,
    }
}

/// Default table packing for verification of the final aggregated proof.
fn default_aggregation_table_packing() -> TablePacking {
    TablePacking::new(1, 4).with_fri_params(0, 3)
}

// ---------------------------------------------------------------------------
// Core aggregation
// ---------------------------------------------------------------------------

/// Aggregate N davinci-stark ballot proofs into a single batch-STARK proof.
///
/// Each element of `proofs` is a `(Proof<BallotConfig>, public_values)` pair
/// as produced by [`davinci_stark::prove_full_ballot`].
///
/// # Errors
///
/// Returns [`AggregationError`] if:
/// - The input slice is empty.
/// - Any proof has an incorrect number of public values.
/// - Any recursion layer fails to build or prove.
///
/// # Panics
///
/// None expected under normal operation.
pub fn aggregate_ballot_proofs(
    proofs: &[(Proof<BallotConfig>, Vec<Val>)],
) -> Result<AggregatedBallotProof, AggregationError> {
    if proofs.is_empty() {
        return Err(AggregationError::EmptyInput);
    }

    // Validate public values lengths upfront.
    for (i, (_, pv)) in proofs.iter().enumerate() {
        if pv.len() != PV_COUNT {
            return Err(AggregationError::PublicValuesLength {
                expected: PV_COUNT,
                got: pv.len(),
                index: i,
            });
        }
    }

    let config = BallotRecursionConfig::new(davinci_stark::config::make_verifier_config());
    let backend =
        FriRecursionBackend::<8, 4>::new_d2(Poseidon2Config::GoldilocksD2Width8);
    let leaf_params = default_leaf_params();
    let air = BallotAir::new();

    info!(
        num_proofs = proofs.len(),
        "starting ballot proof aggregation"
    );

    // ---- Leaf layer: wrap each UniStark proof into a BatchStark proof ----
    //
    // Safety: Proof<BallotConfig> and Proof<BallotRecursionConfig> are
    // structurally identical because BallotRecursionConfig delegates all
    // associated types (Pcs, Challenge, Challenger) to BallotConfig.
    // The Proof struct is parameterized only by these associated types.
    let mut current_layer: Vec<RecursionOutput<BallotRecursionConfig>> =
        Vec::with_capacity(proofs.len());

    for (i, (proof, public_values)) in proofs.iter().enumerate() {
        debug!(proof_index = i, "wrapping ballot proof into batch-STARK");

        // SAFETY: Proof<BallotConfig> and Proof<BallotRecursionConfig> have
        // identical layouts because all associated types match. We transmute
        // the reference rather than cloning the entire proof.
        let proof_ref: &Proof<BallotRecursionConfig> =
            unsafe { &*(proof as *const Proof<BallotConfig> as *const Proof<BallotRecursionConfig>) };

        let input = RecursionInput::UniStark {
            proof: proof_ref,
            air: &air,
            public_inputs: public_values.clone(),
            preprocessed_commit: None,
        };

        let output = build_and_prove_next_layer::<BallotRecursionConfig, BallotAir, _, D>(
            &input,
            &config,
            &backend,
            &leaf_params,
        )
        .map_err(|e| AggregationError::LeafWrapping {
            index: i,
            source: e,
        })?;

        current_layer.push(output);
    }

    info!(
        num_wrapped = current_layer.len(),
        "leaf layer complete, starting binary aggregation"
    );

    // ---- Binary tree aggregation ----
    let mut level = 0u32;
    while current_layer.len() > 1 {
        level += 1;
        let pairs = current_layer.len() / 2;
        let has_odd = current_layer.len() % 2 == 1;
        let agg_params = default_aggregation_params(level);

        debug!(
            level,
            pairs,
            has_odd,
            "aggregation layer"
        );

        let mut next_layer = Vec::with_capacity(pairs + usize::from(has_odd));
        let mut prep_cache: Option<AggregationPrepCache<BallotRecursionConfig>> = None;

        for pair_idx in 0..pairs {
            let li = pair_idx * 2;
            let left = current_layer[li].into_recursion_input::<BatchOnly>();
            let right = current_layer[li + 1].into_recursion_input::<BatchOnly>();

            let output = build_and_prove_aggregation_layer::<
                BallotRecursionConfig,
                BatchOnly,
                BatchOnly,
                _,
                D,
            >(
                &left,
                &right,
                &config,
                &backend,
                &agg_params,
                Some(&mut prep_cache),
            )
            .map_err(|e| AggregationError::RecursionFailed {
                layer: level,
                pair: pair_idx,
                source: e,
            })?;

            next_layer.push(output);
        }

        // Carry the odd one forward unchanged.
        if has_odd {
            let last = current_layer.pop().unwrap();
            warn!(
                level,
                "odd proof count — carrying last proof to next level"
            );
            next_layer.push(last);
        }

        current_layer = next_layer;
    }

    let final_output = current_layer.into_iter().next().expect("non-empty after loop");
    info!("aggregation complete — single batch-STARK proof produced");

    Ok(AggregatedBallotProof {
        proof: final_output.0,
        prover_data: final_output.1,
    })
}

/// Verify an aggregated ballot proof.
///
/// This is a convenience wrapper around [`AggregatedBallotProof::verify`].
pub fn verify_aggregated_proof(aggregated: &AggregatedBallotProof) -> Result<()> {
    let config = BallotRecursionConfig::new(davinci_stark::config::make_verifier_config());
    aggregated.verify(&config)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::PrimeCharacteristicRing;

    #[test]
    fn empty_input_returns_error() {
        let result = aggregate_ballot_proofs(&[]);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AggregationError::EmptyInput
        ));
    }

    #[test]
    fn wrong_pv_length_error_variant() {
        // Verify the error variant is constructible with the expected fields.
        let err = AggregationError::PublicValuesLength {
            expected: PV_COUNT,
            got: PV_COUNT + 1,
            index: 0,
        };
        assert!(matches!(err, AggregationError::PublicValuesLength { .. }));
    }
}
