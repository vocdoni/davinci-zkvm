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
| `client.SubmitFold(req)` | Chained mode: fold completed batch jobs into a chain proof. |
| `client.SubmitFinalize(req)` | Chained mode: results payload → final PLONK. |
| `client.FetchStarkInfo(id)` | Chained mode: program_vk + publics of a STARK job. |

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

## Chained mode: `go-sdk/chain`

For single-sequencer deployments the `chain` package drives the whole
election to one final PLONK: batches are proved STARK-only, recursively
folded server-side, and finalize wraps the last fold (plus the decrypted
results with Chaum-Pedersen proofs) into a single SNARK.

```go
import "github.com/vocdoni/davinci-zkvm/go-sdk/chain"

seq, err := chain.NewSequencer(client, chain.Config{
    ProcessID:    processID,  // *big.Int
    BallotMode:   ballotMode, // *big.Int
    EncKey:       encKey,     // *bjj.BJJ ElGamal pubkey from the DKG
    CensusOrigin: 1,
    CensusRoot:   censusRoot, // *big.Int
}, 4 /* fold every 4 batches */, 30*time.Minute)

// For each batch of incoming votes:
//  - votes: []chain.Vote (census index, voteID, address, ElGamal ballot)
//  - req:   *ProveRequest with the voters' ballot proofs + census proofs
//    (the sequencer fills in State, Reencryption and Output itself)
jobID, err := seq.ProveBatch(votes, req)

// When the election ends and the DKG releases the private key:
final, err := seq.Finalize(encPrivKey)
_ = final.Snark   // the single PLONK for the whole election
_ = final.Results // plaintext results, also committed in the proof publics
```

The `Sequencer` owns the process state tree (genesis matches the
in-circuit genesis), the fold cadence, and the finalize checks: digest
continuity, results match, and the external vk binding
(`digest.fold_vk == snark.ProgramVK`, `digest.batch_vk` == the known
vote-batch vk). See the repository README for the protocol design and
the raw HTTP flow.

### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DAVINCI_API_URL` | `http://localhost:8080` | Service base URL |
| `DAVINCI_SKIP_PROVING` | `""` | Set to `1` to skip proving tests |
| `DAVINCI_PROOF_TIMEOUT` | `5m` | Per-proof timeout |
