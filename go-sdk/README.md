# davinci-zkvm Go SDK

Go client and protocol helpers for the [davinci-zkvm](../README.md) prover:
build and submit vote batches, parse the guest's outputs, lay out the DA
blobs, run a chained-mode election and verify proofs on a simulated chain.

[![Go Reference](https://pkg.go.dev/badge/github.com/vocdoni/davinci-zkvm/go-sdk.svg)](https://pkg.go.dev/github.com/vocdoni/davinci-zkvm/go-sdk)

## Overview

| Package | Content |
|---|---|
| `davinci` (module root) | HTTP client, request types, binary encoders, output parser, DA blob builder, slot keys and protocol limits. |
| `chain` | Chained-mode orchestrator: process state tree, batch assembly, folds, finalize and the digest and vk-binding checks. |
| `solidity` | Compiles the verifier and the reference settlement contract and runs them on go-ethereum's simulated backend. |
| `vocdoni/...` | Parts of davinci-node's crypto (ElGamal, BabyJubJub, Poseidon, ballot types) copied here so the SDK does not depend on the full node. |

## Install

```bash
go get github.com/vocdoni/davinci-zkvm/go-sdk
```

## Usage

### Prove a batch

```go
import davinci "github.com/vocdoni/davinci-zkvm/go-sdk"

client := davinci.NewClient("http://localhost:8080")

batch := &davinci.ProveBatch{
    VerificationKey:  vk,     // Groth16 VK of the ballot circuit
    Voters:           voters, // []davinci.VoterBallot: proof, signature, census proof, re-encryption
    State:            state,  // *davinci.StateTransitionData: SMT chains and ballot data
    EncryptionKey:    encKey, // election key, big-endian hex coordinates
    ReencryptionSeed: seed,   // fresh secret per batch
    KZG:              kzg,    // blob commitments (per-batch mode)
}

result, err := client.Prove(ctx, batch)
if err != nil {
    return err
}
// result.Snark: ProgramVK, RootCVadcopFinal, PublicValues, ProofBytes,
// the arguments of ZiskVerifier.verifySnarkProof.
```

`Prove` submits the batch, polls the job and downloads the proof. The
lower-level calls are:

| Method | Endpoint |
|---|---|
| `SubmitProve(req)` | `POST /prove`, returns the job ID. |
| `GetJob(id)`, `WaitForJob(id, timeout)` | `GET /jobs/{id}`. |
| `FetchSnark(id)` | `GET /jobs/{id}/snark` as a `*PlonkSnark`. |
| `FetchPublics(id)` | `GET /jobs/{id}/publics`, 64 `u32` registers. |
| `FetchInputs(id)` | `GET /jobs/{id}/inputs` (only with `DAVINCI_KEEP_INPUTS=1`). |
| `SubmitFold(req)`, `SubmitFinalize(req)` | `POST /fold`, `POST /finalize`. |
| `FetchStarkInfo(id)` | `GET /jobs/{id}/stark`: `program_vk` and `zisk_vk`. |
| `FetchStarkRaw(id)`, `ImportStark(blob)` | Move a batch STARK to another prover (`/jobs/{id}/snark/raw`, `POST /jobs/import`). |
| `ImportStarkAs(blob, kind)` | `POST /jobs/import?kind=`: `ImportBatch` or `ImportFold` (moves a fold chain to another prover). |
| `FetchStarkProof(id)` | `GET /jobs/{id}/proof/stark`. |
| `Health()` | `GET /health`. |

`NewProveRequestBuilder` builds a `ProveRequest` step by step when you do not
use `ProveBatch`.

### Check the result

A finished job can still be a rejected batch. Parse the registers and check
`OK` before settling:

```go
raw, err := client.FetchPublics(result.JobID)
if err != nil {
    return err
}
regs := make([]uint32, len(raw)/4)
for i := range regs {
    regs[i] = binary.LittleEndian.Uint32(raw[4*i:])
}
out, err := davinci.ParseOutputs(regs)
if err != nil {
    return err
}
if !out.OK {
    return fmt.Errorf("batch rejected: %s", out.FailString())
}
```

### Data-availability blobs

The guest lays out the blob contents itself; the sequencer must publish the
same bytes. `BuildTransitionBlobs` builds the blobs, KZG commitments,
evaluation points, openings and the digest the guest publishes, and
`Request` strips them down to what `/prove` needs:

```go
blobs, err := davinci.BuildTransitionBlobs(numFields, pid, rootBefore, voteIDs, updates, accumulator)
batch.KZG = blobs.Request(pidHex, rootBeforeHex)
```

Ethereum accepts at most six blobs per transaction; `MaxSingleTxBatch(nf)`
is the largest batch that fits.

### Verify on a simulated chain

```go
import davinciSolidity "github.com/vocdoni/davinci-zkvm/go-sdk/solidity"

err := davinciSolidity.VerifyOnSimulated("./solidity", result.Snark)

s, err := davinciSolidity.DeploySettlement("./solidity", snark.ProgramVK, snark.RootCVadcopFinal)
err = s.CreateProcess(pid, genesisRoot, censusRoot)
gas, err := s.SubmitTransition(pid, snark, blobs) // sends a real blob transaction
```

Both compile the contracts in the repository's `solidity/` directory with a
local `solc`, or with `docker run ethereum/solc:0.8.28` when none is
installed.

### Chained mode

```go
import "github.com/vocdoni/davinci-zkvm/go-sdk/chain"

seq, err := chain.NewSequencer(client, chain.Config{
    ProcessID:    processID,
    BallotMode:   ballotMode,
    EncKey:       encKey,       // election public key
    CensusOrigin: 1,            // 1 = Merkle census, 4 = CSP
    CensusRoot:   censusRoot,
    BallotVKHash: ballotVKHash, // davinci.BallotVKLeaf(vkJSON)
}, 4 /* fold every 4 batches */, 30*time.Minute)

// For every batch: votes carry the slot, vote ID and ballot of each voter,
// req the ballot proofs, signatures and census proofs. The sequencer fills
// in the state transition and the re-encryption and proves a STARK.
jobID, err := seq.ProveBatch(votes, req)

// When voting ends and the election key is available:
final, err := seq.Finalize(encPrivKey)
// final.Snark is the single on-chain proof, final.Results the tally.
```

The sequencer keeps the process state tree in memory; `State().Snapshot()`
and `chain.RestoreState` persist it across restarts. `Finalize` checks the
digest against the local state and the vk binding against the pinned
`chain.CircuitRelease`. An independent verifier runs the same checks with
`chain.ParseDigest` and `chain.VerifyDigest`.

## Testing

```bash
go test $(go list ./... | grep -v /tests/integration)
```

The emulator and integration suites under `tests/` are described in
[docs/testing.md](../docs/testing.md).

## License

GNU Affero General Public License v3.0 or later. See [LICENSE](../LICENSE).
