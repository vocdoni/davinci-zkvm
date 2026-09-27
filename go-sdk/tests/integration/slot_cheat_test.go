// slot_cheat_test.go attacks the ballot slot binding (spec 4.1.6, 4.1.7,
// 3B.3, 4.5.3) from the sequencer's side: every input that feeds a slot is
// tampered on an otherwise consistent batch, and the guest must refuse to
// settle a ballot anywhere but its signer's slot. Same prerequisites as
// cheat_test.go (ziskemu, gen-input, the circuit ELF).
package integration

import (
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	davinci "github.com/vocdoni/davinci-zkvm/go-sdk"
	leanimt "github.com/vocdoni/lean-imt-go"
)

const failCSP = uint32(1 << 23) // CSP signature, key or duplicate check failed

// CSPBLK layout: magic(8) n(8), then per entry r(32) s(32) recid(8)
// voter_address(32) weight(32) index(8).
const (
	cspHeaderLen   = 16
	cspEntryLen    = 144
	cspAddrOffset  = 72
	cspIndexOffset = 136
)

// bn254R is the BN254 scalar field modulus (Poseidon, Groth16 publics).
var bn254R, _ = new(big.Int).SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)

// addrSlot is the Merkle slot the guest derives for v.
func addrSlot(v *Voter) uint64 {
	return davinci.SlotKey([20]byte(v.AddressBytes))
}

// assembleWith rebuilds the full input with a replacement eligibility block.
func (c *cheatElectionInput) assembleWith(eligibility []byte) []byte {
	var out []byte
	out = append(out, c.baseBin...)
	out = append(out, c.stateBlock...)
	out = append(out, eligibility...)
	out = append(out, c.reencBlock...)
	out = append(out, c.kzgBlock...)
	return out
}

// runAccepted runs input and fails unless overall_ok = 1.
func runAccepted(t *testing.T, input []byte, label string) []uint32 {
	t.Helper()
	out, err := runZiskEmu(input)
	if err != nil {
		t.Fatalf("[%s] ziskemu: %v", label, err)
	}
	if out[davinci.OutputOverallOk] != 1 {
		t.Fatalf("[%s] expected overall_ok=1, got fail_mask=0x%08x", label, out[davinci.OutputFailMask])
	}
	return out
}

// smtValueHex renders a small arbo leaf value (32 LE bytes).
func smtValueHex(v uint64) string {
	var b [32]byte
	binary.LittleEndian.PutUint64(b[:8], v)
	return "0x" + hex.EncodeToString(b[:])
}

// withLimb1 sets limb 1 of a 32-byte LE SMT key to 1, keeping limb 0.
func withLimb1(t *testing.T, key string) string {
	t.Helper()
	b, err := hex.DecodeString(trimHex(key))
	if err != nil || len(b) != 32 {
		t.Fatalf("bad SMT key %q", key)
	}
	b[8] = 0x01
	return "0x" + hex.EncodeToString(b)
}

// shareAddressHigh makes voter b a second census member for voter a's
// address with leaf PackAddressWeight(addr, w) | hi << 248. hi must keep the
// leaf below the field modulus (hi <= 0x2f).
func shareAddressHigh(t *testing.T, e *Election, a, b int, hi int64) {
	t.Helper()
	va, vb := e.Voters[a], e.Voters[b]
	vb.Signer, vb.AddressBytes, vb.AddressBigInt, vb.Weight = va.Signer, va.AddressBytes, va.AddressBigInt, va.Weight
	e.censusLeaves[b] = new(big.Int).Or(packAddressWeight(vb.AddressBigInt, vb.Weight), new(big.Int).Lsh(big.NewInt(hi), 248))
	imt, err := leanimt.New(poseidonHasher, bigIntEq, nil, nil, nil)
	if err != nil {
		t.Fatalf("leanimt.New: %v", err)
	}
	for _, l := range e.censusLeaves {
		imt.Insert(l)
	}
	e.Census = imt
}

// TestCheatSlotSwap swaps the slots of two voters in one batch: each ballot
// lands on the other voter's real slot and everything else is consistent, so
// only the slot binding (4.1.6) rejects it.
func TestCheatSlotSwap(t *testing.T) {
	election, err := NewElection(2)
	if err != nil {
		t.Fatalf("NewElection: %v", err)
	}
	v0, v1 := election.Voters[0], election.Voters[1]
	election.SlotOverride = map[int]uint64{0: addrSlot(v1), 1: addrSlot(v0)}
	base, _, _ := buildCheatInputElection(t, election)
	assertCircuitFailsExactly(t, base.fullInput(), failBallotNS, "slot_swap")
}

// TestCheatSlotSwapWithCensus is TestCheatSlotSwap with the census proofs
// permuted to match the swapped slots, so the slot binding holds. The census
// address of entry i is then not the address of ballot proof i, and only the
// address binding (6.6) ties the slot back to the signer.
func TestCheatSlotSwapWithCensus(t *testing.T) {
	election, err := NewElection(2)
	if err != nil {
		t.Fatalf("NewElection: %v", err)
	}
	v0, v1 := election.Voters[0], election.Voters[1]
	election.SlotOverride = map[int]uint64{0: addrSlot(v1), 1: addrSlot(v0)}
	base, _, _ := buildCheatInputElection(t, election)
	census := eligibilityBlock(t, election, []*Voter{v1, v0})
	assertCircuitFailsExactly(t, base.assembleWith(census), failBinding, "slot_swap_with_census")
}

// TestCheatSlotOverwriteOther writes voter 0's ballot over voter 1's cast
// ballot in a later batch: an UPDATE of slot(v1) with v1's old ballot
// subtracted, so the tally and the overwrite count stay consistent. Only the
// slot binding (4.1.6) stops the sequencer from erasing another voter.
func TestCheatSlotOverwriteOther(t *testing.T) {
	election, err := NewElection(2)
	if err != nil {
		t.Fatalf("NewElection: %v", err)
	}
	v0, v1 := election.Voters[0], election.Voters[1]
	base, _, _ := buildCheatInputBatchesHook(t, election, []*Voter{v1}, []*Voter{v0}, func() {
		election.SlotOverride = map[int]uint64{0: addrSlot(v1)}
	})
	if base.stateData.OverwrittenCount != 1 {
		t.Fatalf("expected the forged write to be an overwrite, got %d", base.stateData.OverwrittenCount)
	}
	assertCircuitFailsExactly(t, base.fullInput(), failBallotNS, "slot_overwrite_other")
}

// TestCheatSlotRevoteFreshSlot counts two ballots of one voter: the revote is
// INSERTed into an empty slot instead of overwriting the first ballot, which
// the batch even refreshes. Only the slot binding (4.1.6) rejects it; the
// honest revote (an UPDATE of the same slot) is accepted.
func TestCheatSlotRevoteFreshSlot(t *testing.T) {
	t.Run("honest_overwrite", func(t *testing.T) {
		election, err := NewElection(1)
		if err != nil {
			t.Fatalf("NewElection: %v", err)
		}
		v0 := election.Voters[0]
		base, _, _ := buildCheatInputBatches(t, election, []*Voter{v0}, []*Voter{v0})
		out := runAccepted(t, base.fullInput(), "revote_overwrite")
		if got := out[davinci.OutputOverwrittenCount]; got != 1 {
			t.Errorf("expected overwritten=1, got %d", got)
		}
	})
	t.Run("fresh_slot", func(t *testing.T) {
		election, err := NewElection(1)
		if err != nil {
			t.Fatalf("NewElection: %v", err)
		}
		v0 := election.Voters[0]
		base, _, _ := buildCheatInputBatchesHook(t, election, []*Voter{v0}, []*Voter{v0}, func() {
			election.SlotOverride = map[int]uint64{0: addrSlot(v0) ^ 1}
		})
		if base.stateData.OverwrittenCount != 0 {
			t.Fatalf("expected the revote to be an INSERT, got %d overwrites", base.stateData.OverwrittenCount)
		}
		assertCircuitFailsExactly(t, base.fullInput(), failBallotNS, "revote_fresh_slot")
	})
}

// TestCheatSlotSharedLeafHighBits covers spec 6.9 / 4.1.6 for a crafted census
// with a second leaf for one address, differing only in leaf bits 248..253
// (bits 160..165 of leaf >> 88). The guest drops those bits, so the second
// leaf can only overwrite its signer's ballot; writing it to a second slot
// is rejected.
func TestCheatSlotSharedLeafHighBits(t *testing.T) {
	build := func(t *testing.T, fresh bool) *cheatElectionInput {
		election, err := NewElection(3)
		if err != nil {
			t.Fatalf("NewElection: %v", err)
		}
		shareAddressHigh(t, election, 1, 2, 0x2f)
		v1, v2 := election.Voters[1], election.Voters[2]
		base, _, _ := buildCheatInputBatchesHook(t, election, []*Voter{v1}, []*Voter{v2}, func() {
			if fresh {
				election.SlotOverride = map[int]uint64{2: addrSlot(v2) ^ 1}
			}
		})
		return base
	}
	t.Run("overwrites_own_slot", func(t *testing.T) {
		out := runAccepted(t, build(t, false).fullInput(), "shared_leaf_overwrite")
		if got := out[davinci.OutputOverwrittenCount]; got != 1 {
			t.Errorf("expected overwritten=1, got %d", got)
		}
	})
	t.Run("second_slot", func(t *testing.T) {
		assertCircuitFailsExactly(t, build(t, true).fullInput(), failBallotNS, "shared_leaf_second_slot")
	})
}

// TestCheatSlotSameLeafTwice puts two ballots of one voter, with the same
// census leaf, in one batch (INSERT then UPDATE of its slot). The duplicate
// leaf (3A.3) and the duplicate slot (4.1.7) both reject it.
func TestCheatSlotSameLeafTwice(t *testing.T) {
	election, err := NewElection(2)
	if err != nil {
		t.Fatalf("NewElection: %v", err)
	}
	v0, v1 := election.Voters[0], election.Voters[1]
	base, _, _ := buildCheatInputBatches(t, election, []*Voter{v1}, []*Voter{v0, v0})
	assertCircuitFailsExactly(t, base.fullInput(), failCensus|failBallotNS, "same_leaf_twice")
}

// TestCheatCensusLeafNonCanonical ships voter 0's census leaf as leaf + r.
// Poseidon reduces it, so the membership proof still verifies and the raw
// duplicate-leaf check does not see it, but the address bits move: the slot
// binding and the address binding (6.6) must both fail.
func TestCheatCensusLeafNonCanonical(t *testing.T) {
	base, election, _ := buildCheatInput(t)
	proofs, err := election.BuildCensusProofs(election.Voters)
	if err != nil {
		t.Fatalf("BuildCensusProofs: %v", err)
	}
	leaf, ok := new(big.Int).SetString(trimHex(proofs[0].Leaf), 16)
	if !ok {
		t.Fatalf("bad leaf %q", proofs[0].Leaf)
	}
	proofs[0].Leaf = bigIntToFr32(leaf.Add(leaf, bn254R))
	census, err := davinci.EncodeCensusBlock(proofs)
	if err != nil {
		t.Fatalf("EncodeCensusBlock: %v", err)
	}
	assertCircuitFailsExactly(t, base.assembleWith(census), failBinding|failBallotNS, "census_leaf_plus_r")
}

// TestCheatProofAddressNonCanonical adds r to ballot proof 0's address
// public input. The pairing and the inputs hash see the same residue, but the
// low 160 bits change, so the ECDSA signer and the census address no longer
// match it (2.6, 6.6).
func TestCheatProofAddressNonCanonical(t *testing.T) {
	base, _, _ := buildCheatInput(t)
	off, _, _ := proofsSectionOffset(t, base.baseBin)
	full := base.fullInput()
	p := off + 64 + 128 + 64 // pubs[0] of proof 0, 4 LE words
	var words [4]uint64
	for i := range words {
		words[i] = binary.LittleEndian.Uint64(full[p+i*8:])
	}
	v := new(big.Int)
	for i := 3; i >= 0; i-- {
		v.Lsh(v, 64).Or(v, new(big.Int).SetUint64(words[i]))
	}
	v.Add(v, bn254R)
	mask := new(big.Int).SetUint64(^uint64(0))
	for i := 0; i < 4; i++ {
		binary.LittleEndian.PutUint64(full[p+i*8:], new(big.Int).And(new(big.Int).Rsh(v, uint(64*i)), mask).Uint64())
	}
	assertCircuitFailsExactly(t, full, failECDSA|failBinding, "proof_address_plus_r")
}

// TestCheatBallotKeyHighLimb keeps the right slot in limb 0 of the ballot key
// and sets limb 1. The 64-level tree hashes and walks limb 0 only, so the SMT
// chain stays valid; only the upper-limb rule (4.1.4b) rejects it.
func TestCheatBallotKeyHighLimb(t *testing.T) {
	base, _, _ := buildCheatInput(t)
	base.stateData.BallotSmt[0].NewKey = withLimb1(t, base.stateData.BallotSmt[0].NewKey)
	assertCircuitFailsExactly(t, base.reencodeState(t), failBallotNS, "ballot_key_limb1")
}

// TestCheatVoteIDKeyHighLimb is the vote-id counterpart of
// TestCheatBallotKeyHighLimb (4.1.4b).
func TestCheatVoteIDKeyHighLimb(t *testing.T) {
	base, _, _ := buildCheatInput(t)
	base.stateData.VoteIDSmt[0].NewKey = withLimb1(t, base.stateData.VoteIDSmt[0].NewKey)
	assertCircuitFailsExactly(t, base.reencodeState(t), failConsistency, "vote_id_key_limb1")
}

// TestCheatSlotInsertOverOccupied turns an honest revote (UPDATE) into an
// INSERT at the same, occupied slot with no overwrite, so both ballots would
// be counted. The slot is right; the SMT processor must refuse to insert an
// existing key.
func TestCheatSlotInsertOverOccupied(t *testing.T) {
	election, err := NewElection(1)
	if err != nil {
		t.Fatalf("NewElection: %v", err)
	}
	v0 := election.Voters[0]
	base, _, _ := buildCheatInputBatches(t, election, []*Voter{v0}, []*Voter{v0})
	sd := base.stateData
	sd.BallotSmt[0].Fnc0, sd.BallotSmt[0].Fnc1 = 1, 0
	sd.OverwrittenCount = 0
	sd.BallotProofs.OverwrittenBallots = nil
	assertCircuitFails(t, base.reencodeState(t), failSMTBallot, "insert_over_occupied")
}

// TestCheatRefreshOverlapsBatchConsistent refreshes a slot the batch itself
// writes, with the refresh built from the tree (valid UPDATE, guest-matching
// scalars, accumulator delta folded in). Only the disjointness rule (4.5.3)
// can reject it; TestCheatRefreshOverlapsBatch also breaks the chain.
func TestCheatRefreshOverlapsBatchConsistent(t *testing.T) {
	election, err := NewElection(4)
	if err != nil {
		t.Fatalf("NewElection: %v", err)
	}
	v := election.Voters
	base, _, _ := buildCheatInputBatchesHook(t, election, v[:2], v[2:4], func() {
		election.RefreshExtra = []uint64{addrSlot(v[2])}
	})
	if len(base.stateData.RefreshSmt) != 3 {
		t.Fatalf("expected 3 refresh entries, got %d", len(base.stateData.RefreshSmt))
	}
	assertCircuitFailsExactly(t, base.fullInput(), failRefresh, "refresh_overlaps_batch_consistent")
}

// buildCSPBatch builds one CSP batch of voters with nothing applied before.
func buildCSPBatch(t *testing.T, e *Election, voters []*Voter) *cheatElectionInput {
	t.Helper()
	base, _, _ := buildCheatInputBatchesHook(t, e, nil, voters, nil)
	return base
}

// TestCheatCSPSanity: an honest CSP batch is accepted on ziskemu and the
// census root register carries the CSP address.
func TestCheatCSPSanity(t *testing.T) {
	election, err := NewCSPElection(2)
	if err != nil {
		t.Fatalf("NewCSPElection: %v", err)
	}
	out := runAccepted(t, buildCSPBatch(t, election, election.Voters).fullInput(), "csp_sanity")
	addr := crypto.PubkeyToAddress(election.CspKey.PublicKey)
	if got, want := censusRootRegs(out), addressRegs(addr[:]); got != want {
		t.Errorf("census root registers %x, want CSP address %x", got, want)
	}
}

// censusRootRegs returns output registers 20..27.
func censusRootRegs(out []uint32) [8]uint32 {
	var r [8]uint32
	copy(r[:], out[davinci.OutputCensusRoot:davinci.OutputCensusRoot+8])
	return r
}

// addressRegs lays a 20-byte address out the way the guest writes the census
// root: uint160 as LE limbs, each limb as two u32 words.
func addressRegs(a []byte) [8]uint32 {
	lo := binary.BigEndian.Uint64(a[12:20])
	mid := binary.BigEndian.Uint64(a[4:12])
	hi := binary.BigEndian.Uint32(a[0:4])
	return [8]uint32{uint32(lo), uint32(lo >> 32), uint32(mid), uint32(mid >> 32), hi, 0, 0, 0}
}

// TestCheatCSPSlotFromAddress writes CSP ballots to the address-derived
// (Merkle) slots instead of BallotMin + signed index (4.1.6).
func TestCheatCSPSlotFromAddress(t *testing.T) {
	election, err := NewCSPElection(2)
	if err != nil {
		t.Fatalf("NewCSPElection: %v", err)
	}
	election.SlotOverride = map[int]uint64{}
	for i, v := range election.Voters {
		election.SlotOverride[i] = addrSlot(v)
	}
	base := buildCSPBatch(t, election, election.Voters)
	assertCircuitFailsExactly(t, base.fullInput(), failBallotNS, "csp_slot_from_address")
}

// TestCheatCSPIndexNotSigned moves voter 0 to index 9 (slot BallotMin + 9)
// while the CSP signed index 0. With a second entry the recovered keys
// disagree (3B.4). With a single entry the guest cannot tell: it accepts and
// reports some other key's address as census root, which is what the
// settlement contract and the fold guest pin.
func TestCheatCSPIndexNotSigned(t *testing.T) {
	forge := func(t *testing.T, n int) (*Election, []byte) {
		election, err := NewCSPElection(n)
		if err != nil {
			t.Fatalf("NewCSPElection: %v", err)
		}
		election.SlotOverride = map[int]uint64{0: davinci.CSPSlotKey(9)}
		base := buildCSPBatch(t, election, election.Voters)
		csp := append([]byte(nil), base.censusBlock...)
		binary.LittleEndian.PutUint64(csp[cspHeaderLen+cspIndexOffset:], 9)
		return election, base.assembleWith(csp)
	}
	t.Run("two_entries", func(t *testing.T) {
		_, forged := forge(t, 2)
		assertCircuitFailsExactly(t, forged, failCSP, "csp_index_not_signed")
	})
	t.Run("single_entry", func(t *testing.T) {
		election, forged := forge(t, 1)
		out := runAccepted(t, forged, "csp_single_forged")
		addr := crypto.PubkeyToAddress(election.CspKey.PublicKey)
		if censusRootRegs(out) == addressRegs(addr[:]) {
			t.Errorf("forged index kept the CSP census root; a consumer could not reject it")
		}
	})
}

// TestCheatCSPDoubleCredential: the CSP signed two indexes (0 and 7) for one
// address and the sequencer puts both ballots of that voter in one batch,
// two slots for one signer. 3B.3 rejects the duplicate address. The
// high_address_bits case sets bit 160 of the second entry's voter_address:
// the CSP message, the proof binding and the ECDSA check all read the low 160
// bits, but 3B.3 compares the raw words, so the duplicate is not seen.
func TestCheatCSPDoubleCredential(t *testing.T) {
	build := func(t *testing.T) *cheatElectionInput {
		election, err := NewCSPElection(1)
		if err != nil {
			t.Fatalf("NewCSPElection: %v", err)
		}
		v0 := election.Voters[0]
		again := *v0
		again.CensusIdx = 7
		return buildCSPBatch(t, election, []*Voter{v0, &again})
	}
	t.Run("same_encoding", func(t *testing.T) {
		assertCircuitFailsExactly(t, build(t).fullInput(), failCSP, "csp_double_credential")
	})
	t.Run("high_address_bits", func(t *testing.T) {
		// Bit 160 would make the address a second one for 3B.3 while the
		// message, binding and ECDSA still read the same 160 bits.
		base := build(t)
		csp := append([]byte(nil), base.censusBlock...)
		csp[cspHeaderLen+cspEntryLen+cspAddrOffset+20] |= 0x01 // limb 2, bit 32
		assertCircuitFailsExactly(t, base.assembleWith(csp), failCSP, "csp_double_credential_high_bits")
	})
}

// TestCheatOriginFlipToCSP: a Merkle election (origin 1 in the tree) proved
// as if it were CSP, with the sequencer's own key as CSP and index slots.
// The origin comes from the inclusion-proved config leaf 0x06, so claiming
// value 4 must fail the process read-proof.
func TestCheatOriginFlipToCSP(t *testing.T) {
	election, err := NewElection(2)
	if err != nil {
		t.Fatalf("NewElection: %v", err)
	}
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	election.CspKey = key // CSP block and BallotMin + index slots
	base, _, _ := buildCheatInputBatchesHook(t, election, nil, election.Voters, nil)
	base.stateData.ProcessSmt[3].NewValue = smtValueHex(4)
	base.stateData.ProcessSmt[3].OldValue = smtValueHex(4)
	assertCircuitFailsExactly(t, base.reencodeState(t), failSMTProcess, "origin_flip_to_csp")
}

// TestCheatOriginFlipToMerkle is the reverse: a CSP election proved with a
// census tree the sequencer built and address slots, claiming origin 1.
func TestCheatOriginFlipToMerkle(t *testing.T) {
	election, err := NewCSPElection(2)
	if err != nil {
		t.Fatalf("NewCSPElection: %v", err)
	}
	election.CspKey = nil
	imt, err := leanimt.New(poseidonHasher, bigIntEq, nil, nil, nil)
	if err != nil {
		t.Fatalf("leanimt.New: %v", err)
	}
	for _, v := range election.Voters {
		leaf := packAddressWeight(v.AddressBigInt, v.Weight)
		election.censusLeaves = append(election.censusLeaves, leaf)
		imt.Insert(leaf)
	}
	election.Census = imt
	base, _, _ := buildCheatInputBatchesHook(t, election, nil, election.Voters, nil)
	base.stateData.ProcessSmt[3].NewValue = smtValueHex(1)
	base.stateData.ProcessSmt[3].OldValue = smtValueHex(1)
	assertCircuitFailsExactly(t, base.reencodeState(t), failSMTProcess, "origin_flip_to_merkle")
}
