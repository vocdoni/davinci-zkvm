# davinci-zkvm Go SDK

Go client library for the [davinci-zkvm](https://github.com/vocdoni/davinci-zkvm) service — a ZisK zkVM prover that batch-verifies Groth16 BN254 ballot proofs together with Ethereum ECDSA signatures and optionally verifies Arbo SHA-256 Sparse Merkle Tree (SMT) state transitions, all inside a STARK proof.

## Install

```sh
go get github.com/vocdoni/davinci-zkvm/go-sdk
```

## Usage

```go
import davinci "github.com/vocdoni/davinci-zkvm/go-sdk"
```

### Create a client

```go
client := davinci.NewClient("http://localhost:8080")
```

### Check service health

```go
health, err := client.Health()
if err != nil {
    log.Fatal(err)
}
fmt.Printf("status: %s, version: %s\n", health.Status, health.Version)
```

### Submit a proving job

A `ProveRequest` contains:
- `VK` — snarkjs verification key (JSON)
- `Proofs` — array of snarkjs Groth16 proof objects (JSON)
- `PublicInputs` — public signals for each proof, in the same order
- `Sigs` — one Ethereum ECDSA signature per proof, in the same order (mandatory)
- `Smt` — optional SMT state transitions (see [SMT transitions](#smt-state-transitions))

```go
req := &davinci.ProveRequest{
    VK:           vkJSON,           // []byte (raw JSON)
    Proofs:       proofJSONs,       // []json.RawMessage
    PublicInputs: publicInputs,     // [][]string
    Sigs:         sigJSONs,         // []json.RawMessage
}

jobID, err := client.SubmitProve(req)
if err != nil {
    log.Fatal(err)
}
fmt.Println("job submitted:", jobID)
```

### SMT state transitions

Optionally pass one or more Arbo SHA-256 SMT transitions to be verified inside the circuit. All hex strings are **little-endian** (matching arbo's `BigIntToBytes` format):

```go
req.Smt = []davinci.SmtEntry{
    {
        OldRoot:  "0x...", // 32-byte LE hex of old root
        NewRoot:  "0x...", // 32-byte LE hex of new root
        OldKey:   "0x...", // displaced leaf key (all zeros if IsOld0=1)
        OldValue: "0x...", // displaced leaf value (all zeros if IsOld0=1)
        IsOld0:   1,       // 1 = empty slot, 0 = displaced leaf
        NewKey:   "0x...", // inserted key (arbo.BigIntToBytes LE)
        NewValue: "0x...", // inserted value
        Fnc0:     1,       // 1=insert/delete, 0=update
        Fnc1:     0,       // 0=insert/update, 1=update/delete
        Siblings: []string{"0x...", ...}, // LE hex siblings, padded to maxLevels
    },
}
```

The circuit output `output[9]` reflects SMT verification:
- `1` — all transitions valid
- `0` — at least one invalid
- `2` — no SMT block present (backward compatible)

Use `arbo.UnpackSiblings` + `arbo.GenProof` to generate the sibling list from a `vocdoni/arbo` tree.

### Poll for completion

```go
job, err := client.WaitForJob(jobID, 20*time.Minute)
if err != nil {
    log.Fatal(err) // job failed or timed out
}
fmt.Printf("done in %dms\n", *job.ElapsedMs)
```

Or poll manually:

```go
job, err := client.GetJob(jobID)
// job.Status: "queued" | "running" | "done" | "failed"
```

### Download the proof

```go
proofBytes, err := client.GetProof(jobID)
```

## Types

| Type | Description |
|---|---|
| `ProveRequest` | POST /prove request body |
| `ProveResponse` | POST /prove response (job_id + status) |
| `JobResponse` | GET /jobs/{id} response |
| `HealthResponse` | GET /health response |
| `SmtEntry` | One SMT state transition (arbo SHA-256 LE format) |

## API reference

| Method | Endpoint | Description |
|---|---|---|
| `Health()` | `GET /health` | Service liveness and version |
| `SubmitProve(req)` | `POST /prove` | Submit a batch proving job |
| `GetJob(id)` | `GET /jobs/{id}` | Get job status |
| `WaitForJob(id, timeout)` | polls `/jobs/{id}` | Block until done or failed |
| `GetProof(id)` | `GET /jobs/{id}/proof` | Download proof binary |

## Input format

Each ballot proof requires:

1. **Groth16 proof** — snarkjs `proof.json` output (BN254 curve, Groth16 protocol)
2. **Public inputs** — snarkjs `public.json` array with at least 2 entries:
   - `pubs[0]` — Ethereum address of the voter (uint160 as BN254 Fr)
   - `pubs[1]` — vote ID (uint64 as BN254 Fr)
3. **ECDSA signature** — JSON object with fields:
   - `public_key_x`, `public_key_y` — secp256k1 public key (0x-prefixed 32-byte BE hex)
   - `signature_r`, `signature_s` — signature components (0x-prefixed 32-byte BE hex)
   - `vote_id` — the uint64 that was signed
   - `address` — Ethereum address (decimal uint160, for reference)

   The circuit verifies `secp256k1.Verify(pk, keccak256(ethSignedMessage(vote_id)), r, s)` and that the public key hashes to the declared address.

The circuit accepts exactly 128 proofs (must be a power of two ≥ 2).

## Circuit outputs

The ZisK circuit produces 10 output values (`output[0..9]`):

| Index | Description |
|---|---|
| `output[0]` | `1` = overall verification passed, `0` = failed |
| `output[1]` | fail mask bits (bit N set → check N failed) |
| `output[2]` | number of proofs processed |
| `output[3]` | Groth16 batch verification result flags |
| `output[4]` | number of ECDSA signatures verified |
| `output[5]` | aggregated nullifier accumulator (low 64 bits) |
| `output[6]` | aggregated nullifier accumulator (high 64 bits) |
| `output[7]` | ECDSA batch result |
| `output[8]` | reserved |
| `output[9]` | SMT result: `1`=valid, `0`=failed, `2`=not present |

## Integration tests

Tests live in `tests/` and use the SDK directly. They require a running davinci-zkvm service:

```sh
# Run lightweight tests (no proving)
cd tests && DAVINCI_SKIP_PROVING=1 go test -v -run "TestHealth|TestInvalid|TestJobNotFound" ./...

# Run all tests including a full proof (requires GPU service)
cd tests && go test -v -timeout 30m ./...
```

Environment variables:

| Variable | Default | Description |
|---|---|---|
| `DAVINCI_API_URL` | `http://localhost:8080` | Service base URL |
| `DAVINCI_SKIP_PROVING` | `` | Set to `1` to skip `TestSubmitAndProve` |
| `DAVINCI_PROOF_TIMEOUT` | `20m` | Go duration string for proof timeout |
| `TEST_DATA_DIR` | `../data/ballot_proof_bn254` | Directory with test fixtures |
