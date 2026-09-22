# Solidity verifier for davinci-zkvm PLONK SNARK

The verifier trio (`IZiskVerifier.sol`, `ZiskVerifier.sol`, `PlonkVerifier.sol`)
comes straight from the ZisK PLONK proving-key bundle
(`~/.zisk/provingKeySnark/final/`, installed by `ziskup setup_snark`). We
vendor them here so the Go integration tests can compile and deploy
against `simulated.NewBackend` without reaching into the host machine's
`~/.zisk` directory.

`DavinciSettlement.sol` is the paper's per-batch settlement contract. It
consumes a PLONK proof through `IZiskVerifier`, applies one voting-batch
transition to the tracked process, and re-verifies every DA-blob KZG
opening via the EIP-4844 point-evaluation precompile.

| file | purpose |
|---|---|
| `IZiskVerifier.sol` | Interface for the verifier entry point. |
| `ZiskVerifier.sol` | Thin wrapper that hashes `(programVK, publicValues, rootCVadcopFinal)` into the single PLONK public signal and calls `PlonkVerifier.verifyProof`. |
| `PlonkVerifier.sol` | The snarkjs-generated PLONK verifier for the current ZisK setup. |
| `DavinciSettlement.sol` | Per-batch settlement contract. Constructor pins the verifier + `programVK` + `rootCVadcopFinal`; `createProcess` registers a process; `submitTransition` verifies the proof, walks the fixed 512-byte publics layout, checks the process's stored `stateRoot` / `censusRoot` / silent-refresh floor, recomputes `blobsDigest`, and verifies each blob's opening at `z_i = sha256(processId ‖ rootBeforeBE ‖ com_i) mod BLS_MODULUS` against the versioned hash read from `BLOBHASH`. Owned in-tree — do NOT overwrite from `~/.zisk/`. |

## Updating

When the ZisK PLONK proving key is bumped, copy the new verifier `.sol`
files in (leave `DavinciSettlement.sol` alone — it isn't shipped by ZisK):

```bash
cp ~/.zisk/provingKeySnark/final/{ZiskVerifier.sol,PlonkVerifier.sol,IZiskVerifier.sol} \
   davinci-zkvm/solidity/
```

The Go integration tests pick them up from this directory, compile with
local `solc` (falling back to `docker run ethereum/solc:stable`), and
deploy on `go-ethereum/ethclient/simulated.NewBackend`. No Anvil, no
ganache, no RPC.

## Verifier ABI

```solidity
function verifySnarkProof(
    bytes32 programVK,
    bytes32 rootCVadcopFinal,
    bytes  publicValues,
    bytes  proofBytes
) external view;
```

`proofBytes` is ABI-encoded as `uint256[24]`. The davinci-zkvm service
returns it that way at `GET /jobs/:id/snark` (the `proof_bytes` field),
so you don't have to encode anything yourself. `publicValues` is the
program's `commit_slice` output as 512 raw bytes. `programVK` is a
32-byte constant for the davinci circuit ELF, and `rootCVadcopFinal` is a
32-byte constant from the ZisK verifier setup; both are returned in that
same JSON, so the caller never has to read them off the contract.

## Settlement ABI

```solidity
constructor(IZiskVerifier zisk, bytes32 programVK, bytes32 rootCVadcopFinal);
function createProcess(bytes32 processId, bytes32 genesisRoot, bytes32 censusRoot) external;
function submitTransition(
    bytes32   processId,
    bytes     publicValues,
    bytes     proofBytes,
    bytes[]   commitments,   // 48 bytes each, in guest order
    bytes32[] ys,             // 32-byte BE BLS scalars, one per commitment
    bytes[]   kzgProofs       // 48 bytes each, opening proof at z_i
) external;                    // MUST be a blob tx: n_blobs blob hashes,
                               // same order as commitments.
mapping(bytes32 => Process) public processes;
struct Process { bytes32 stateRoot; bytes32 censusRoot; uint64 voteCount; uint64 overwrittenCount; bool exists; }
```

`publicValues` layout (512 bytes = 64 registers × 8 LE bytes; the guest
writes u32, upper 4 bytes always zero):

| register | field |
|---:|---|
| 0 | `ok` (must be 1) |
| 1 | `fail_mask` (must be 0) |
| 2..9 | `root_before` (256-bit) |
| 10..17 | `root_after` (256-bit) |
| 18 | `voters` |
| 19 | `overwrites` |
| 20..27 | `census_root` (256-bit) |
| 28..35 | `blobs_digest` = `sha256(com_0 ‖ y_0 ‖ ...)` |
| 36 | `n_blobs` |
| 42 | `occupied_before` (must equal `voteCount − overwrittenCount`) |

Compilation needs solc 0.8.24+ with `--via-ir` because `submitTransition`
has more than 16 local stack slots. The Go helper at
`go-sdk/solidity/settlement.go` compiles either with a local `solc` or
`docker run ethereum/solc:0.8.28`.
