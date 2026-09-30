# Solidity contracts

The on-chain side of the davinci-zkvm proofs: the ZisK PLONK verifier and a
reference contract that settles one batch per transaction. The production
contracts live in [davinci-contracts](https://github.com/vocdoni/davinci-contracts).

| File | Purpose |
|---|---|
| `IZiskVerifier.sol` | Interface of the verifier entry point. |
| `ZiskVerifier.sol` | Hashes `programVK`, `publicValues` and `rootCVadcopFinal` into the PLONK public input and calls `PlonkVerifier`. |
| `PlonkVerifier.sol` | The snarkjs PLONK verifier of the ZisK setup. |
| `DavinciSettlement.sol` | Reference per-batch settlement: verifies the proof and the batch's blobs and advances the process state. |

The three verifier files are copied unchanged from the ZisK PLONK proving key
(`~/.zisk/provingKeySnark/final/`). Do not edit them: current `solc` rejects
their `bytes32 calldata` parameters, and the Go helper patches that on a
temporary copy before compiling.

## Verifier

```solidity
function verifySnarkProof(
    bytes32 programVK,
    bytes32 rootCVadcopFinal,
    bytes   publicValues,
    bytes   proofBytes
) external view;
```

It reverts on an invalid proof. `GET /jobs/{id}/snark` returns the four
arguments ready to pass: `proofBytes` is already ABI-encoded as
`uint256[24]` (768 bytes) and `publicValues` is the guest's 64 outputs as
8-byte little-endian words (512 bytes). `programVK` identifies the guest
program and `rootCVadcopFinal` the ZisK setup; a contract should pin both
rather than accept them from the caller.

## Settlement contract

```solidity
constructor(IZiskVerifier zisk, bytes32 programVK, bytes32 rootCVadcopFinal);
function createProcess(bytes32 processId, bytes32 genesisRoot, bytes32 censusRoot) external;
function submitTransition(
    bytes32   processId,
    bytes     publicValues,
    bytes     proofBytes,
    bytes[]   commitments,  // 48 bytes each, in guest order
    bytes32[] ys,           // 32-byte big-endian evaluations, one per commitment
    bytes[]   kzgProofs     // 48 bytes each, opening proof at z_i
) external;
```

`submitTransition` must be sent as a blob transaction carrying the batch's
blobs in the same order as `commitments`. It verifies the PLONK proof, then
checks against the stored process that:

- `ok == 1` and `fail_mask == 0`;
- the root before equals the stored state root and the census root matches;
- the occupied-slot count equals `voteCount - overwrittenCount`;
- there is at least one blob, and the blob count and the digest over the
  `(commitment, y)` pairs match the public values;
- every blob's KZG opening at
  `z_i = sha256(processId ‖ rootBefore ‖ com_i) mod BLS_MODULUS` (root as a
  big-endian integer) verifies against `blobhash(i)` with the
  point-evaluation precompile.

`createProcess` has no access control; it is a reference, not a deployment.

Public values read by the contract (register `k` is the 8-byte word at
`8*k`; 256-bit values span eight registers):

| Register | Field |
|---:|---|
| 0 | `ok` |
| 1 | `fail_mask` |
| 2..9 | state root before |
| 10..17 | state root after |
| 18 | new votes |
| 19 | overwrites |
| 20..27 | census root |
| 28..35 | blob digest `sha256(com_0 ‖ y_0 ‖ …)` |
| 36 | blob count |
| 42 | occupied slots before the batch |

The full register map is in [circuit/CIRCUIT.md](../circuit/CIRCUIT.md#3-output-registers).

## Compiling and testing

The contract needs solc 0.8.24 or newer with `--via-ir`. The Go package
[`go-sdk/solidity`](../go-sdk/solidity) compiles these files with a local
`solc` or `docker run ethereum/solc:0.8.28`, deploys them on
go-ethereum's simulated backend and sends real blob transactions; its tests
cover every settlement check.

## Updating the verifier

After a ZisK setup change, copy the new verifier files from the installed
PLONK key and refreeze the pins listed in
[CONTRIBUTING.md](../CONTRIBUTING.md#changing-a-guest):

```bash
cp ~/.zisk/provingKeySnark/final/{IZiskVerifier.sol,ZiskVerifier.sol,PlonkVerifier.sol} solidity/
```
