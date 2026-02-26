# davinci-zkvm Go SDK

Go client library for the [davinci-zkvm](https://github.com/vocdoni/davinci-zkvm) service — a ZisK zkVM prover that batch-verifies Groth16 BN254 ballot proofs together with Ethereum ECDSA signatures inside a STARK proof.

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
