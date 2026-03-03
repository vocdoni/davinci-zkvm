# davinci-zkvm Go SDK

Go client library for the [davinci-zkvm](https://github.com/vocdoni/davinci-zkvm)
proving service. Provides typed data structures and a high-level `Prove()` API
designed to integrate directly with the
[davinci-node](https://github.com/vocdoni/davinci-node) sequencer.

## Install

```sh
go get github.com/vocdoni/davinci-zkvm/go-sdk
```

## Quick start

```go
import (
    "context"
    davinci "github.com/vocdoni/davinci-zkvm/go-sdk"
)

client := davinci.NewClient("http://localhost:8080")

// Build a batch of voter ballots with all auxiliary data
batch := &davinci.ProveBatch{
    VerificationKey: vk,       // *VerificationKey — shared Groth16 BN254 VK
    Voters:          voters,   // []VoterBallot — one per voter
    State:           state,    // *StateTransitionData — SMT chain transitions
    EncryptionKey:   encKey,   // *BjjPoint — ElGamal re-encryption key
    KZG:             kzgData,  // *KZGRequest — blob evaluation (optional)
}

// Submit, wait for proof, and download result
result, err := client.Prove(ctx, batch)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("proof ready (job %s, %s)\n", result.JobID, result.Elapsed)
```

## Core types

### `ProveBatch`

The primary integration type. Contains everything needed for a single
state-transition proof:

```go
type ProveBatch struct {
    VerificationKey     *VerificationKey    // Groth16 BN254 VK (or VerificationKeyJSON)
    Voters              []VoterBallot       // Per-voter ballot proofs
    State               *StateTransitionData // SMT state transitions
    EncryptionKey       *BjjPoint           // ElGamal re-encryption public key
    CspPubKey           *BjjPoint           // CSP secp256k1 public key (censusOrigin=4)
    KZG                 *KZGRequest         // EIP-4844 blob evaluation data
}
```

### `VoterBallot`

One voter's ballot with all per-voter protocol data:

```go
type VoterBallot struct {
    Proof        *Groth16Proof       // Typed Groth16 proof (or ProofJSON)
    PublicInputs *PublicInput        // [address, voteID, inputsHash]
    Signature    *EcdsaSignature     // secp256k1 ECDSA signature
    Census       CensusProof         // Lean-IMT Poseidon (Merkle census)
    Csp          *CspProof           // CSP ECDSA attestation (census origin 4)
    Reencryption *VoterReencryption  // ElGamal re-encryption data
}
```

### `StateTransitionData`

Full state-transition data with typed SMT entries:

```go
type StateTransitionData struct {
    ProcessID       string      // 31-byte process identifier (hex)
    OldStateRoot    string      // 256-bit SHA-256 root before batch (hex)
    NewStateRoot    string      // 256-bit SHA-256 root after batch (hex)
    VotersCount     int         // Non-dummy votes
    OverwrittenCount int        // Overwrite (update) votes
    CensusOrigin    CensusOrigin // 1-3 = Merkle, 4 = CSP
    CensusRoot      string      // 256-bit census root (hex)
    VoteIDSmt       []SmtEntry  // VoteID chain SMT transitions
    BallotSmt       []SmtEntry  // Ballot chain SMT transitions
    ProcessSmt      []SmtEntry  // Process config read-proofs
    ResultsAddSmt   *SmtEntry   // Results accumulator: add
    ResultsSubSmt   *SmtEntry   // Results accumulator: subtract
    BallotProofs    *BallotProofData // Encrypted ballot data for result verification
}
```

### `CensusOrigin`

Census authentication mode matching davinci-node's constants:

| Value | Constant | Description |
|-------|----------|-------------|
| 1-3 | `CensusOriginMerkle` | Lean-IMT Poseidon inclusion proof |
| 4 | `CensusOriginCSP` | ECDSA CSP attestation |

### `PublicOutputs`

Parsed circuit outputs (ABI-compatible with davinci-node's `StateTransitionCircuit`):

```go
type PublicOutputs struct {
    OK                    bool
    FailMask              uint32
    RootHashBefore        *big.Int
    RootHashAfter         *big.Int
    VotersCount           int
    OverwrittenVotesCount int
    CensusRoot            *big.Int
    BlobCommitmentLimbs   [3]*big.Int
}
```

## Client API

| Method | Description |
|--------|-------------|
| `NewClient(url)` | Create a client pointing to the service |
| `client.Prove(ctx, batch)` | Submit, wait, and return proof + outputs |
| `client.Health()` | Service health check |
| `client.SubmitProve(req)` | Low-level: submit a `ProveRequest` |
| `client.GetJob(id)` | Low-level: poll job status |
| `client.WaitForJob(id, timeout)` | Low-level: block until done/failed |
| `client.GetProof(id)` | Low-level: download proof binary |

### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DAVINCI_API_URL` | `http://localhost:8080` | Service base URL |
| `DAVINCI_SKIP_PROVING` | `""` | Set to `1` to skip proving tests |
| `DAVINCI_PROOF_TIMEOUT` | `5m` | Per-proof timeout |
