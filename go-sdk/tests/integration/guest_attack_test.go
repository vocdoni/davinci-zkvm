// guest_attack_test.go is the malicious-prover sweep: it starts from an honest
// batch (buildCheatInput*) and tampers one host-controlled value at a time to
// confirm the vote-batch guest refuses states the protocol forbids. Every case
// here targets a guarded check that had no integration cheat test of its own
// (the state-chain shapes of §4.2, the process read-proof inclusion of §4.2.P,
// and the Groth16 VK/proof point validity of §4). Same prerequisites as
// cheat_test.go: ziskemu, gen-input, the circuit ELF.
package integration

import (
	"encoding/hex"
	"math/big"
	"testing"

	davinci "github.com/vocdoni/davinci-zkvm/go-sdk"
)

// nonzeroLeaf is an arbitrary 32-byte LE value used where a leaf must differ
// from the honest one.
func nonzeroLeaf() string {
	b := make([]byte, 32)
	for i := range b {
		b[i] = 0xC3
	}
	return "0x" + hex.EncodeToString(b)
}

// --- §4.2.4: VoteID transitions are INSERTs of the constant leaf value 0 ---

// TestAttackVoteIDNonzeroValue gives a voteID insertion a non-zero leaf value.
// The DA observer rebuilds the tree assuming voteID leaves carry 0, so the
// guest pins new_value == 0; a non-zero value also breaks the SMT new-root
// recomputation. Either way FAIL_SMT_VOTEID.
func TestAttackVoteIDNonzeroValue(t *testing.T) {
	base, _, _ := buildCheatInput(t)
	base.stateData.VoteIDSmt[0].NewValue = nonzeroLeaf()
	assertCircuitFails(t, base.reencodeState(t), failSMTVoteID, "voteid_nonzero_value")
}

// TestAttackVoteIDAsUpdate turns a voteID INSERT into an UPDATE (fnc0=0,
// fnc1=1). VoteIDs are insert-only (§4.2.4); an UPDATE must be rejected.
func TestAttackVoteIDAsUpdate(t *testing.T) {
	base, _, _ := buildCheatInput(t)
	base.stateData.VoteIDSmt[0].Fnc0 = 0
	base.stateData.VoteIDSmt[0].Fnc1 = 1
	assertCircuitFails(t, base.reencodeState(t), failSMTVoteID, "voteid_as_update")
}

// --- §4.2.5: Ballot transitions are INSERT or UPDATE, never DELETE/NOOP ---

// TestAttackBallotDelete marks a ballot transition as a DELETE (fnc0=1,
// fnc1=1). A DELETE would drop a ballot leaf while the batch still claims a
// vote; §4.2.5 forbids it.
func TestAttackBallotDelete(t *testing.T) {
	base, _, _ := buildCheatInput(t)
	base.stateData.BallotSmt[0].Fnc0 = 1
	base.stateData.BallotSmt[0].Fnc1 = 1
	assertCircuitFails(t, base.reencodeState(t), failSMTBallot, "ballot_delete")
}

// TestAttackBallotNoop marks a ballot transition as a NOOP (fnc0=0, fnc1=0).
// A NOOP proves nothing about membership; §4.2.5 forbids it in the ballot
// chain.
func TestAttackBallotNoop(t *testing.T) {
	base, _, _ := buildCheatInput(t)
	base.stateData.BallotSmt[0].Fnc0 = 0
	base.stateData.BallotSmt[0].Fnc1 = 0
	assertCircuitFails(t, base.reencodeState(t), failSMTBallot, "ballot_noop")
}

// --- §4.2.P: process config read-proofs are genuine SMT inclusions ---

// TestAttackProcessProofForgedEncKey forges the encryption-key config leaf
// (0x03) while keeping the read-proof roots read-only. The read-proof is a
// genuine SMTVerifier inclusion, not a NOOP, so a value that is not actually
// in the tree fails to reconstruct OldStateRoot (§4.2.P3). This is the
// property that stops a prover from asserting a forged encryption key — the
// one config value with no external public-output backstop.
func TestAttackProcessProofForgedEncKey(t *testing.T) {
	base, _, _ := buildCheatInput(t)
	forged := nonzeroLeaf()
	base.stateData.ProcessSmt[2].OldValue = forged
	base.stateData.ProcessSmt[2].NewValue = forged
	assertCircuitFails(t, base.reencodeState(t), failSMTProcess, "process_forged_enc_key")
}

// TestAttackProcessProofNotReadOnly points a process read-proof's NewRoot at a
// value other than OldStateRoot. §4.2.P2 requires old_root == new_root ==
// OldStateRoot so a read-proof cannot smuggle a mutation.
func TestAttackProcessProofNotReadOnly(t *testing.T) {
	base, _, _ := buildCheatInput(t)
	base.stateData.ProcessSmt[0].NewRoot = nonzeroLeaf()
	assertCircuitFails(t, base.reencodeState(t), failSMTProcess, "process_not_read_only")
}

// TestAttackProcessProofCountZero drops the process read-proofs entirely (a
// valid 0-count encoding). §4.2.P1 requires exactly 5, so the batch cannot
// prove its config and must fail.
func TestAttackProcessProofCountZero(t *testing.T) {
	base, _, _ := buildCheatInput(t)
	base.stateData.ProcessSmt = nil
	assertCircuitFails(t, base.reencodeState(t), failSMTProcess, "process_count_zero")
}

// TestAttackProcessProofWrongProcessID forges the processID config leaf (0x00)
// so it no longer equals the STATETX header processID (§4.2.P5). Inclusion of
// the forged value also fails, so FAIL_SMT_PROCESS is set either way.
func TestAttackProcessProofWrongProcessID(t *testing.T) {
	base, _, _ := buildCheatInput(t)
	forged := nonzeroLeaf()
	base.stateData.ProcessSmt[0].OldValue = forged
	base.stateData.ProcessSmt[0].NewValue = forged
	assertCircuitFails(t, base.reencodeState(t), failSMTProcess, "process_wrong_pid")
}

// --- §4.1.5 / 4.1.4b: ballot key namespace and upper limbs ---

// TestAttackBallotKeyConfigNamespace rewrites a ballot key into the process
// config namespace (below BallotMin). The slot binding and the namespace rule
// (§4.1.5) both reject it under FAIL_BALLOT_NS.
func TestAttackBallotKeyConfigNamespace(t *testing.T) {
	base, _, _ := buildCheatInput(t)
	k := smtKeyHex(0x05)
	base.stateData.BallotSmt[0].NewKey = k
	base.stateData.BallotSmt[0].OldKey = k
	assertCircuitFails(t, base.reencodeState(t), failBallotNS, "ballot_key_config_ns")
}

// --- §4.4.9: padded ciphertext slots of accumulated ballots are identity ---

// TestAttackOverwrittenPaddedNonIdentity stuffs non-identity data into a
// padded slot of an overwritten (subtracted) ballot. The accumulator skips
// padded slots, so §4.4.9 pins them to the TE identity; the leaf-hash pin
// (§4.4.3) also breaks since the tree's old leaf had identity padding.
func TestAttackOverwrittenPaddedNonIdentity(t *testing.T) {
	election, err := NewElection(1)
	if err != nil {
		t.Fatalf("NewElection: %v", err)
	}
	if election.NumFields >= NumFields {
		t.Skipf("NumFields=%d leaves no padded slot", election.NumFields)
	}
	v0 := election.Voters[0]
	base, _, _ := buildCheatInputBatches(t, election, []*Voter{v0}, []*Voter{v0})
	if base.stateData.OverwrittenCount != 1 || len(base.stateData.BallotProofs.OverwrittenBallots) != 1 {
		t.Fatalf("expected one overwritten ballot, got %d", base.stateData.OverwrittenCount)
	}
	pad := election.NumFields // first padded ciphertext slot
	ob := base.stateData.BallotProofs.OverwrittenBallots[0]
	ob[pad*4] = "0x" + hex.EncodeToString(pad32(big.NewInt(0x99).Bytes())) // C1.x != 0
	assertCircuitFails(t, base.reencodeState(t), failResultAccum, "overwritten_padded_non_identity")
}

// --- §3A.2: all census proofs reference one root ---

// TestAttackCensusOneDifferentRoot changes only the second proof's root. With
// two distinct roots the batch mixes census snapshots; §3A.2 rejects it.
func TestAttackCensusOneDifferentRoot(t *testing.T) {
	base, election, _ := buildCheatInput(t)
	proofs, err := election.BuildCensusProofs(election.Voters)
	if err != nil {
		t.Fatalf("BuildCensusProofs: %v", err)
	}
	if len(proofs) < 2 {
		t.Fatal("need >= 2 census proofs")
	}
	proofs[1].Root = flipHex(t, trimHex(proofs[1].Root))
	census, err := davinci.EncodeCensusBlock(proofs)
	if err != nil {
		t.Fatalf("EncodeCensusBlock: %v", err)
	}
	assertCircuitFails(t, base.assembleWith(census), failCensus, "census_one_diff_root")
}

// --- §4: Groth16 VK and proof point validity (bits beyond the existing
// gamma/A cases) ---

// TestAttackVKAlphaOffCurve pushes the VK alpha_g1 off the curve. §1.1 must
// reject it with FAIL_CURVE before any pairing work.
func TestAttackVKAlphaOffCurve(t *testing.T) {
	base, _, _ := buildCheatInput(t)
	full := base.fullInput()
	// alpha_g1 is the first VK point, right after the 32-byte header.
	full[32] ^= 0x01
	assertCircuitFails(t, full, failCurve, "vk_alpha_off_curve")
}

// TestAttackVKBetaIdentity zeroes the VK beta_g2 point. g2_is_valid rejects
// the identity (a 𝒪 beta would drop the alpha pairing term), §1.1.
func TestAttackVKBetaIdentity(t *testing.T) {
	base, _, _ := buildCheatInput(t)
	full := base.fullInput()
	// Layout: header(32) | alpha(64) | beta(128) | ...
	betaOff := 32 + 64
	for i := betaOff; i < betaOff+128; i++ {
		full[i] = 0
	}
	assertCircuitFails(t, full, failCurve, "vk_beta_identity")
}

// TestAttackVKDeltaIdentity zeroes the VK delta_g2 point (§1.1).
func TestAttackVKDeltaIdentity(t *testing.T) {
	base, _, _ := buildCheatInput(t)
	full := base.fullInput()
	// header(32) | alpha(64) | beta(128) | gamma(128) | delta(128)
	deltaOff := 32 + 64 + 128 + 128
	for i := deltaOff; i < deltaOff+128; i++ {
		full[i] = 0
	}
	assertCircuitFails(t, full, failCurve, "vk_delta_identity")
}

// TestAttackProofCZeroed zeroes proof 0's C point. The pairing precompile
// skips the all-zero (identity) encoding, which would drop the C·delta term;
// g1_is_valid must reject it first (§1.4).
func TestAttackProofCZeroed(t *testing.T) {
	base, _, _ := buildCheatInput(t)
	off, _, _ := proofsSectionOffset(t, base.baseBin)
	full := base.fullInput()
	// Per proof: a(64) b(128) c(64) pubs. Zero c of proof 0.
	cOff := off + 64 + 128
	for i := cOff; i < cOff+64; i++ {
		full[i] = 0
	}
	assertCircuitFails(t, full, failCurve, "proof_c_zeroed")
}

// --- §4.2.1 / 4.2.2: chain length equals n_voters (no silently dropped vote) ---

// TestAttackBallotChainShort drops a ballot-chain entry while leaving n_voters
// unchanged, so a counted vote has no ballot transition. §4.2.2 requires
// ballot_chain.len() == n_voters.
func TestAttackBallotChainShort(t *testing.T) {
	base, _, _ := buildCheatInput(t) // 2 voters
	if len(base.stateData.BallotSmt) < 2 {
		t.Skip("need >= 2 ballot entries")
	}
	base.stateData.BallotSmt = base.stateData.BallotSmt[:1]
	assertCircuitFails(t, base.reencodeState(t), failSMTBallot, "ballot_chain_short")
}

// TestAttackVoteIDChainShort drops a voteID-chain entry while n_voters stays 2
// (§4.2.1): a counted vote with no unique voteID insertion.
func TestAttackVoteIDChainShort(t *testing.T) {
	base, _, _ := buildCheatInput(t)
	if len(base.stateData.VoteIDSmt) < 2 {
		t.Skip("need >= 2 voteID entries")
	}
	base.stateData.VoteIDSmt = base.stateData.VoteIDSmt[:1]
	assertCircuitFails(t, base.reencodeState(t), failSMTVoteID, "voteid_chain_short")
}

// TestAttackOverwriteCountLie claims a ballot UPDATE count other than the
// actual number of UPDATE transitions (§4.2.3). Here a genuine INSERT batch is
// relabelled with n_overwritten = 1.
func TestAttackOverwriteCountLie(t *testing.T) {
	base, _, _ := buildCheatInput(t)
	base.stateData.OverwrittenCount++
	assertCircuitFails(t, base.reencodeState(t), failSMTBallot, "overwrite_count_lie")
}

// TestAttackProofBZeroed zeroes proof 0's B point. B gets only the on-curve
// twist check (no identity rejection); if the all-zero encoding passes it, the
// pairing precompile skips the e(r0·A0, B0) term, so proof 0's A·B
// contribution vanishes and the batch equation can no longer balance. Either
// the curve check or the pairing equation must reject it.
func TestAttackProofBZeroed(t *testing.T) {
	base, _, _ := buildCheatInput(t)
	off, _, _ := proofsSectionOffset(t, base.baseBin)
	full := base.fullInput()
	bOff := off + 64 // after a(64)
	for i := bOff; i < bOff+128; i++ {
		full[i] = 0
	}
	assertCircuitFails(t, full, failCurve|failPairing, "proof_b_zeroed")
}
