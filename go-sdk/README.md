# davinci-zkvm Go SDK

Go client for the [davinci-zkvm](https://github.com/vocdoni/davinci-zkvm)
proving service. Typed structs for the request side, a one-call `Prove`
for the happy path, and a helper that hands you a PLONK SNARK ready to
feed to Ethereum. Built to slot directly into the
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

// Build a batch with all the auxiliary data a state transition needs.
batch := &davinci.ProveBatch{
    VerificationKey: vk,       // *VerificationKey — shared Groth16 BN254 VK
    Voters:          voters,   // []VoterBallot — one per voter
    State:           state,    // *StateTransitionData — SMT chain transitions
    EncryptionKey:   encKey,   // *BjjPoint — ElGamal re-encryption key
    KZG:             kzgData,  // *KZGRequest — blob evaluation (optional)
}

// Block until the service returns a ready-to-verify PLONK SNARK.
result, err := client.Prove(ctx, batch)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("snark ready (job %s, %s)\n", result.JobID, result.Elapsed)

// Send these four arguments to ZiskVerifier.verifySnarkProof on Ethereum.
snark := result.Snark
_ = snark.ProgramVK        // bytes32 programVK
_ = snark.RootCVadcopFinal // bytes32 rootCVadcopFinal
_ = snark.PublicValues     // bytes publicValues (256 B)
_ = snark.ProofBytes       // bytes proofBytes   (768 B = uint256[24])
```

## Core types

### `ProveBatch`

The thing you assemble for one state-transition proof — voters, the SMT
chain transitions, the ElGamal re-encryption key, the optional KZG blob:

```go
type ProveBatch struct {
    VerificationKey     *VerificationKey    // Groth16 BN254 VK (or VerificationKeyJSON)
    Voters              []VoterBallot       // Per-voter ballot proofs
    State               *StateTransitionData // SMT state transitions
    EncryptionKey       *BjjPoint           // ElGamal re-encryption public key
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
|---|---|
| `NewClient(url)` | Create a client pointing to the service. |
| `client.Prove(ctx, batch)` | Submit a batch, wait, and return a ready-to-verify [`*PlonkSnark`](#plonksnark). |
| `client.Health()` | Service health check. |
| `client.SubmitProve(req)` | Low-level: submit a `ProveRequest` and get a job ID back. |
| `client.GetJob(id)` | Low-level: snapshot of a job's status. |
| `client.WaitForJob(id, timeout)` | Low-level: block until the job is done or failed. |
| `client.FetchSnark(id)` | Download the Solidity-ready PLONK payload for a completed job. |
| `client.FetchInputs(id)` | Download the raw `input.bin` for audit or re-proving. |

### `PlonkSnark`

`Client.FetchSnark` returns a typed payload ready to pass to
[`ZiskVerifier.verifySnarkProof`](../solidity/ZiskVerifier.sol) on Ethereum:

```go
type PlonkSnark struct {
    ProgramVK        [32]byte // bytes32 programVK
    RootCVadcopFinal [32]byte // bytes32 rootCVadcopFinal
    PublicValues     []byte   // bytes publicValues   (256 B)
    ProofBytes       []byte   // bytes proofBytes     (768 B = uint256[24])
}
```

On-chain, the verifier SHA-256s `programVK || publicValues ||
rootCVadcopFinal`, reduces the digest modulo the BN254 scalar field, and
hands the result to the bare PLONK verifier together with
`abi.decode(proofBytes, (uint256[24]))`.

### Off-chain verification

If you want to verify in a test instead of on a real chain,
[`go-sdk/solidity`](./solidity/solidity.go) has a one-call helper:

```go
import davinciSolidity "github.com/vocdoni/davinci-zkvm/go-sdk/solidity"

snark, _ := client.FetchSnark(jobID)
err := davinciSolidity.VerifyOnSimulated("./solidity", snark)
```

It compiles the verifier contracts with local `solc` (or `docker run
ethereum/solc:stable`) and runs them on
`go-ethereum/ethclient/simulated.NewBackend`.

### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DAVINCI_API_URL` | `http://localhost:8080` | Service base URL |
| `DAVINCI_SKIP_PROVING` | `""` | Set to `1` to skip proving tests |
| `DAVINCI_PROOF_TIMEOUT` | `5m` | Per-proof timeout |
