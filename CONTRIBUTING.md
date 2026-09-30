# Contributing

Thanks for helping. This file covers how to build and check a change, and the
rules that keep the guests, their verification keys and the several copies
of each wire format consistent. Read [docs/architecture.md](docs/architecture.md)
first for how the pieces fit.

## Setup

- Rust stable (CI uses 1.95) and Go (version from `go-sdk/go.mod`).
- For guest work: ZisK 1.3.0-alpha, installed with its `ziskup` installer.
  `ziskup -v 1.3.0-alpha --cpu --nokey` is enough to build the guests and run
  the emulator (`cargo-zisk`, `ziskemu` and the guest toolchain under
  `~/.zisk`); it needs no proving keys and no GPU.
- For proving: a GPU host, see [docs/deployment.md](docs/deployment.md).

## Checks

Run what CI runs before opening a pull request:

```bash
cargo fmt --all --check
cargo clippy -p davinci-zkvm-service -p davinci-zkvm-sdk -p davinci-zkvm-input-gen --all-targets -- -D warnings
cargo test -p davinci-zkvm-service -p davinci-zkvm-sdk -p davinci-zkvm-input-gen

cd go-sdk
gofmt -l .
go vet ./...
go test $(go list ./... | grep -v /tests/integration)
go run ./cmd/sdk-vectors -out ../rust-sdk/testdata   # must leave no diff
```

After touching a guest or an input encoder, also run the emulator suites
([docs/testing.md](docs/testing.md#circuit-tests-on-the-emulator)). They take
minutes and catch most soundness regressions.

## Style

- Comments explain why, state invariants and security reasoning. One short
  line on top of a function is usually enough. Do not narrate history.
- Keep documentation plain and short. The guest specs
  ([`circuit/CIRCUIT.md`](circuit/CIRCUIT.md),
  [`circuit-results/RESULTS.md`](circuit-results/RESULTS.md)) describe the
  current rules, not a changelog.
- Commit messages follow Conventional Commits: `fix(service): …`,
  `feat(circuit): …`, `docs(api): …`.

## Changing a guest

The guests are `circuit/`, `circuit-aggregator/` and `circuit-results/`, plus
`circuit-primitives/`, which all three compile in.

**Build with the script.** `scripts/build-guests.sh [guest ...]` builds each
guest from its own directory, remaps the checkout and `$CARGO_HOME` paths
and copies the ELF into `*/elf/`. Panic locations embed source paths and line
numbers, so a plain `cargo-zisk build` produces an ELF that depends on where
the checkout lives, and building from the workspace root pulls in host-only
dependencies. Each guest reaches `circuit-primitives` through a committed
symlink inside the package for the same reason; keep it. CI rebuilds the
guests and fails if the committed ELFs differ.

**Every source change moves the program vk,** including one that only shifts
line numbers. Commit the rebuilt ELF with the source, and refreeze the pins
in the same change:

- `go-sdk/chain/release.go` (`CircuitRelease`: aggregator, vote-batch and
  results vks);
- `rust-sdk/src/release.rs` (`BATCH_PROGRAM_VK`, `RESULTS_PROGRAM_VK`).

`cargo-zisk setup -e <elf> -k ~/.zisk/provingKey` prints the vk as
`Root hash: [w0, w1, w2, w3]` when `ZISK_CACHE_DIR` is empty; the pin is the
four words as big-endian bytes, concatenated. The aggregator setup needs
about 50 GB of RAM. `rust-sdk/src/release.rs` also documents how to refreeze
`ROOT_C_VADCOP_FINAL` and `ZISK_VERIFIER_CODEHASH` after a ZisK upgrade.
Deployed contracts and running sequencers pin these values too.

**Update the spec in the same change.** A new check, fail bit, input field
or output register lands in `CIRCUIT.md` or `RESULTS.md` together with the
code, and gets a cheat test that the guest now rejects.

## Values that exist in several places

These are mirrored by hand. Change every copy in one commit:

| What | Copies |
|---|---|
| Vote-batch input format | `circuit/src/io.rs`, `input-gen/src/lib.rs`, `service/src/types.rs`, `go-sdk` (`types.go`, `encode.go`), `rust-sdk/src/types.rs` |
| Limits (`MAX_BATCH_SIZE`, `MAX_REFRESH`, `NUM_FIELDS`, `MAX_BLOBS`, refresh policy) | `circuit-primitives/src/types.rs`, `input-gen/src/lib.rs`, `go-sdk/types.go`, `rust-sdk/src/limits.rs` |
| Output registers and fail bits | `circuit/src/main.rs`, `circuit-primitives/src/types.rs`, `go-sdk/outputs.go`, `go-sdk/types.go`, `rust-sdk/src/publics.rs`, `solidity/DavinciSettlement.sol` |
| DA blob layout | `circuit-primitives/src/da_blob.rs`, `circuit/src/kzg.rs`, `go-sdk/blob.go`, `rust-sdk/src/blob.rs`, `solidity/DavinciSettlement.sol` |
| Re-encryption scalar chain | `circuit-primitives/src/babyjubjub.rs`, `go-sdk/vocdoni/crypto/elgamal/reenc.go`, `rust-sdk/src/reenc.rs` |
| Aggregator input and proof blob layout | `circuit-aggregator/src/main.rs`, `input-gen/src/aggregator.rs` |
| Results guest frame | `circuit-results/src/main.rs`, `input-gen/src/results.rs` |
| Ballot slot derivation | `circuit/src/consistency.rs`, `go-sdk/types.go`, `rust-sdk/src/census.rs` |

Byte order is the usual trap. Arbo state-tree values (roots, keys, leaf
values, siblings, and every field of the chained-mode config and results
payloads) are little-endian hex. Curve coordinates and the other request
fields are big-endian. [docs/api.md](docs/api.md#encodings) lists which is
which. A process ID sent big-endian where little-endian is expected does not
fail loudly: the guest proves `ok = 0`.

## Invariants a change must keep

Each of these has cheat tests; a change that needs to relax one is a
protocol change and needs review as such.

- **The Groth16 batch check takes no hints from the host.** The random
  linear combination (scaled `A_i`, `sum r_i*C_i`, the aggregated public-input
  term) is computed in-guest from Fiat-Shamir coefficients. One pairing
  equation cannot bind host-supplied aggregate points (CIRCUIT.md section 4).
- **The aggregator's `SETUP_VK` stays a compile-time constant.** A setup key
  read from input would make proof verification self-keyed. The batch and
  fold vks are runtime inputs, bound through `config_commitment` and the
  release pins.
- **Padded ballot fields are asserted to be the identity** before the guest
  skips their curve arithmetic, in re-encryption, refreshes and the tally.
- **Every value the DA blob omits is pinned in-guest**: vote-ID leaves carry
  the value 0, keys have zero upper limbs, and the BLS12-381 inverse hint
  fails closed.
- **The results transition is an update of key `0x04`**, never a no-op or an
  insert at another key.
- **Ballot slots come from the voter address (Merkle census) or the signed
  CSP index**, never from the lean-IMT path, which does not bind a leaf
  index. The guest rejects duplicate slots within a batch.
- **Encodings are canonical where the host chooses them.** Coordinates below
  the field modulus and scalars below the group order wherever a hash or leaf
  sees raw bytes.
- **Refresh selection and the re-encryption seed are private.** They come
  from OS randomness per batch and are never derived from public data or
  persisted; `input.bin` is deleted after proving.

## ZisK notes

- The ZisK version is pinned (`ziskos = "=1.3.0-alpha"` in the guests,
  `ZISK_VERSION` in the Makefile and Dockerfiles). The in-guest STARK
  verifier and the vadcop blob layout are ZisK internals; an upgrade means
  checking `circuit-aggregator/src/main.rs` and `input-gen/src/aggregator.rs`
  against the new release and refreezing every pin.
- `cargo-zisk` builds with the rustup toolchain named `zisk` (`ziskup` links
  it). After changing toolchains, delete the guests' `target/` directories.
- The STARK proving key must be a Poseidon build (the `ziskup` default).
  Blake3 keys cannot be wrapped in PLONK.
- `circuit-primitives/Cargo.toml` depends on `proofman-starks-lib-c` only to
  force its `cpu-only` feature; keep its version equal to `ziskos`'s.
- The worker retries a fixed list of transient prover errors
  (`service/src/prover/worker.rs`). Do not add bare `SIGABRT` or generic
  witness errors: deterministic guest assertions produce those too.

## Solidity

`solidity/IZiskVerifier.sol`, `ZiskVerifier.sol` and `PlonkVerifier.sol` are
byte-identical copies from the ZisK PLONK setup. Do not edit them; the Go
helper patches them on a temporary copy before compiling.
[`solidity/README.md`](solidity/README.md) explains how to update them.

## Test fixtures

The Go integration tests use the ballot circuit of davinci-circom v1.0.0.
The Rust SDK embeds the current davinci-circom verification key
(`rust-sdk/assets/ballot_proof_vkey.json`), which differs, so ballots
generated by the Go tests do not verify under the Rust SDK's key.
