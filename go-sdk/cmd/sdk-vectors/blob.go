package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"

	"github.com/iden3/go-iden3-crypto/babyjub"

	davinci "github.com/vocdoni/davinci-zkvm/go-sdk"
)

func blobMain() {
	write("blob.json", blobVectors())
	write("wire_prove.json", wireProveFixture())
}

// teBallotHex returns 64 BE hex TE coords: nf random subgroup points pairs,
// identity-padded.
func teBallotHex(nf int) []string {
	out := make([]string, 0, 64)
	for f := 0; f < 16; f++ {
		for c := 0; c < 2; c++ {
			if f < nf {
				p := babyjub.NewPoint().Mul(randBelow(babyjub.SubOrder), babyjub.B8)
				out = append(out, "0x"+hex32(p.X), "0x"+hex32(p.Y))
			} else {
				out = append(out, "0x"+hex32(big.NewInt(0)), "0x"+hex32(big.NewInt(1)))
			}
		}
	}
	return out
}

type blobUpdate struct {
	Key    uint64   `json:"key"`
	Ballot []string `json:"ballot"` // 64 BE hex
}

type blobVec struct {
	Nf              int          `json:"nf"`
	ProcessID       string       `json:"process_id"`  // decimal
	RootBefore      string       `json:"root_before"` // raw arbo root bytes
	VoteIDs         []uint64     `json:"vote_ids"`    // input order (unsorted)
	Updates         []blobUpdate `json:"updates"`     // input order (unsorted)
	Accumulator     []string     `json:"accumulator"`
	Cells           []string     `json:"cells"`
	Commitments     []string     `json:"commitments"`
	VersionedHashes []string     `json:"versioned_hashes"`
	Zs              []string     `json:"zs"`
	Ys              []string     `json:"ys"`
	Proofs          []string     `json:"proofs"`
	Digest          string       `json:"digest"`
}

func blobVectors() []blobVec {
	var out []blobVec
	for _, c := range []struct{ nf, nVids, nUpdates int }{{2, 5, 21}, {6, 40, 80}, {16, 100, 125}} {
		pid := processID(randBytes(20), [4]byte{0xaa, 0xbb, 0xcc, 0xdd}, uint64(c.nf)).MathBigInt()
		root := randBytes(32)
		vids := make([]uint64, c.nVids)
		for i := range vids {
			vids[i] = 1<<63 | rng.Uint64()
		}
		keySet := map[uint64]bool{}
		var updates []davinci.SlotUpdate
		for len(updates) < c.nUpdates {
			k := 0x10 + uint64(rng.Intn(1<<20))
			if keySet[k] {
				continue
			}
			keySet[k] = true
			updates = append(updates, davinci.SlotUpdate{Key: k, Ballot: teBallotHex(c.nf)})
		}
		acc := teBallotHex(c.nf)
		var pidBE, rootBE [32]byte
		copy(pidBE[:], be32(pid))
		copy(rootBE[:], reverse(root))
		tb, err := davinci.BuildTransitionBlobs(c.nf, pidBE, rootBE, vids, updates, acc)
		must(err)
		v := blobVec{Nf: c.nf, ProcessID: dec(pid), RootBefore: hex.EncodeToString(root), VoteIDs: vids, Accumulator: acc,
			Digest: hex.EncodeToString(tb.Digest[:])}
		for _, u := range updates {
			v.Updates = append(v.Updates, blobUpdate{u.Key, u.Ballot})
		}
		for _, cell := range tb.Cells {
			v.Cells = append(v.Cells, hex.EncodeToString(cell[:]))
		}
		for i := range tb.Commitments {
			v.Commitments = append(v.Commitments, hex.EncodeToString(tb.Commitments[i][:]))
			v.VersionedHashes = append(v.VersionedHashes, hex.EncodeToString(tb.VersionedHashes[i][:]))
			v.Zs = append(v.Zs, hex.EncodeToString(tb.Zs[i][:]))
			v.Ys = append(v.Ys, hex.EncodeToString(tb.Ys[i][:]))
			v.Proofs = append(v.Proofs, hex.EncodeToString(tb.Proofs[i][:]))
		}
		if got := davinci.TransitionBlobCount(c.nVids, c.nUpdates, c.nf); got != len(tb.Commitments) {
			panic(fmt.Sprintf("blob count %d != %d", got, len(tb.Commitments)))
		}
		out = append(out, v)
	}
	return out
}

// wireProveFixture is a /prove body built with the go-sdk types (every block
// present, one voter), so the Rust types can be checked against Go's JSON.
func wireProveFixture() json.RawMessage {
	vk, err := os.ReadFile(*vkAsset)
	must(err)
	var rp struct {
		Proof         map[string]any `json:"proof"`
		PublicSignals []string       `json:"public_signals"`
	}
	raw, err := os.ReadFile(*outDir + "/real_proof.json")
	must(err)
	must(json.Unmarshal(raw, &rp))
	rp.Proof["curve"] = "bn128"
	proof, err := json.Marshal(rp.Proof)
	must(err)
	sig, err := json.Marshal(map[string]any{
		"public_key_x": "0x" + hex32(randField()), "public_key_y": "0x" + hex32(randField()),
		"signature_r": "0x" + hex32(randField()), "signature_s": "0x" + hex32(randField()),
		"signature_v": 1, "vote_id": uint64(1<<63 | 99), "address": rp.PublicSignals[0],
	})
	must(err)
	le := func() string { return "0x" + hex.EncodeToString(randBytes(32)) }
	sibs := func(n int) []string {
		s := make([]string, n)
		for i := range s {
			s[i] = le()
		}
		return s
	}
	entry := func() davinci.SmtEntry {
		return davinci.SmtEntry{OldRoot: le(), NewRoot: le(), OldKey: le(), OldValue: le(), IsOld0: 1,
			NewKey: le(), NewValue: le(), Fnc0: 1, Fnc1: 0, Siblings: sibs(64)}
	}
	results := entry()
	var ct [davinci.NumFields]davinci.BjjCiphertext
	for i := range ct {
		b := teBallotHex(1)
		ct[i] = davinci.BjjCiphertext{C1: davinci.BjjPoint{X: b[0], Y: b[1]}, C2: davinci.BjjPoint{X: b[2], Y: b[3]}}
	}
	req := davinci.ProveRequest{
		VK:           vk,
		Proofs:       []json.RawMessage{proof},
		PublicInputs: [][]string{rp.PublicSignals},
		Sigs:         []json.RawMessage{sig},
		State: &davinci.StateTransitionData{
			VotersCount: 1, OverwrittenCount: 0, OccupiedBefore: 3,
			ProcessID: le(), OldStateRoot: le(), NewStateRoot: le(),
			VoteIDSmt: []davinci.SmtEntry{entry()}, BallotSmt: []davinci.SmtEntry{entry()},
			RefreshSmt: []davinci.SmtEntry{entry(), entry()}, ResultsSmt: &results,
			ProcessSmt: []davinci.SmtEntry{entry(), entry(), entry(), entry(), entry()},
			BallotProofs: &davinci.BallotProofData{
				OldResults: teBallotHex(1), VoterBallots: [][]string{teBallotHex(1)},
				OverwrittenBallots: [][]string{}, RefreshedBallots: [][]string{teBallotHex(1), teBallotHex(1)},
			},
		},
		CensusProofs: []davinci.CensusProof{{Root: "0x" + hex32(randField()), Leaf: "0x" + hex32(randField()), Index: 5, Siblings: []string{"0x" + hex32(randField()), "0x" + hex32(randField()), "0x" + hex32(randField())}}},
		Reencryption: &davinci.ReencryptionData{
			EncryptionKeyX: "0x" + hex32(randField()), EncryptionKeyY: "0x" + hex32(randField()), Seed: "0x" + hex32(randField()),
			Entries: []davinci.ReencryptionEntry{{Original: ct, Reencrypted: ct}},
		},
		CspData: &davinci.CspData{Proofs: []davinci.CspProof{{
			R: "0x" + hex32(randField()), S: "0x" + hex32(randField()), Recid: 1,
			VoterAddress: "0x" + hex.EncodeToString(randBytes(20)), Weight: "0x" + hex32(big.NewInt(42)), Index: 7,
		}}},
		KZG:    davinci.NewKZGRequest(randField(), randField(), [][48]byte{[48]byte(randBytes(48)), [48]byte(randBytes(48))}),
		Output: "plonk",
	}
	b, err := json.Marshal(req)
	must(err)
	return b
}
