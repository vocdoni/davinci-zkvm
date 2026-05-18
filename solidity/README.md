# Solidity verifier for davinci-zkvm PLONK SNARK

These contracts come straight from the ZisK PLONK proving-key bundle
(`~/.zisk/provingKeySnark/final/` after `ziskup --provingkey-plonk`). We
vendor them here so the Go integration tests can compile and deploy
against `simulated.NewBackend` without reaching into the host machine's
`~/.zisk` directory.

| file | purpose |
|---|---|
| `IZiskVerifier.sol` | Interface for the verifier entry point. |
| `ZiskVerifier.sol` | Thin wrapper that hashes `(programVK, publicValues, rootCVadcopFinal)` into the single PLONK public signal and calls `PlonkVerifier.verifyProof`. |
| `PlonkVerifier.sol` | The snarkjs-generated PLONK verifier for the current ZisK setup. |

## Updating

When the ZisK PLONK proving key is bumped, copy the new `.sol` files in:

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
program's `commit_slice` output as 256 raw bytes. `programVK` is a
32-byte constant for the davinci circuit ELF, and `rootCVadcopFinal` is a
32-byte constant from the ZisK verifier setup; both are returned in that
same JSON, so the caller never has to read them off the contract.
