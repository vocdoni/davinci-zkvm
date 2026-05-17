# davinci-zkvm ZisK v0.18.0 upgrade — handoff

Branch: `zisk-v0.18.0`. Continuing the upgrade from v0.17.0 → v0.18.0. Previous machine crashed during the first e2e test prove run.

## Goal

Get the full DAVINCI proving pipeline working on ZisK v0.18.0:

1. STARK aggregated proof for a state transition (primary objective)
2. SNARK PLONK proof on top of the STARK (secondary — see "PLONK key" note below)
3. `go-sdk/tests/integration/TestFullE2E` passing against `docker compose --profile cuda` service

## Status when handoff happened

Committed in this session (see "Commit" below):

- All `v0.15.0` → `v0.18.0` version pins (install.sh, Makefile, Dockerfile, Dockerfile.cuda, .env.example, docker-compose.yml comment, circuit/Cargo.toml)
- ZisK v0.18.0 prebuilt binaries installed at `~/.zisk/bin/` (cargo-zisk-gpu, cargo-zisk-cpu, ziskemu, riscv2zisk, libziskclib.a, zisk-worker-gpu, zisk-coordinator) with `cargo-zisk → cargo-zisk-gpu` symlink. Toolchain installed via `cargo-zisk toolchain install`.
- v0.18.0 proving key downloaded to `~/.zisk/provingKey` (MD5 `8dca1be03fc12a6cf356f46ad0bee8ef`, ~12 GB extracted from 3 GB tarball). Tarball at `~/zisk-provingkey-0.18.0.tar.gz` for reuse.
- GPU constant trees built (79 `.consttree_gpu` files).
- Circuit ELF rebuilt against v0.18.0 toolchain at `circuit/elf/circuit.elf` (380304 bytes, RISC-V).
- Docker image `davinci-zkvm-cuda:latest` rebuilt with all v0.18.0 fixes.
- Service was processing the first prove job when the machine crashed. The Docker logs showed it had gotten past INITIALIZING_PROOFMAN, ROM_SETUP, ASM microservice startup — proof generation was actually running.

The e2e test had submitted job `d2ebeeba-c857-4798-9050-35724b67eaff` (Transition 1/8, 2 voters), proofman was loading const pols. No prove failure observed up to the crash point — the previous mmap and shmem errors were all fixed by adding `ulimits.memlock` to docker-compose.yml.

## Key v0.18.0 API/behaviour changes already adopted

These are the breaking changes that required code edits — listed so the next agent doesn't waste time re-discovering them:

1. **Prebuilt binary split**: tarball ships `cargo-zisk-gpu` and `cargo-zisk-cpu` separately, plus `riscv2zisk`, `libziskclib.a`, `zisk-worker-gpu/cpu`, `zisk-coordinator`, `ziskemu`, `ziskup`. No single `cargo-zisk` binary — install.sh and Dockerfile.cuda symlink `cargo-zisk -> cargo-zisk-gpu`.
2. **Toolchain install command**: `cargo-zisk sdk install-toolchain` → `cargo-zisk toolchain install`.
3. **`prove` flag renames**:
   - `--input` → `--inputs` (`-i`)
   - `--output-dir <dir>` → `--output <file>` (now a file path, not a directory)
   - `--aggregation` removed (aggregation is the default now; `-a/--no-aggregation` disables it)
   - `--gpu` (`-g`) must be passed explicitly to use GPU
   - `--emulator` (`-l`) still works — keep it; it bypasses the ROM setup `make` step
4. **`check-setup` flag rename**: `-a` in v0.17.0 meant "all" (build all trees). In v0.18.0 `-a/--no-aggregation` means the opposite. To build GPU const trees in v0.18.0: `cargo-zisk check-setup --proving-key <pk> --gpu` (no `-a`).
5. **PLONK path**: new `--proving-key-plonk` (`-w`) flag on both `prove` and `wrap-proof`. `cargo-zisk wrap-proof` is the new command to derive a PLONK proof from a STARK proof.
6. **`ziskos` Rust API breaking changes** in the guest circuit:
   - `ziskos::read_input_slice` → `ziskos::io::read_input_slice`
   - `ziskos::set_output(id, value)` is now `pub(crate)`. Replacement: build a `[u32; 46]` buffer, convert to LE bytes, and emit with `ziskos::io::commit_slice(&bytes)`. The circuit now writes all 46 registers as a single byte stream — same byte-for-byte layout, just one call instead of 46.
   - `ziskos::zisklib::secp256k1_ecdsa_verify(pk, z, r, s)` → `ziskos::zisklib::ecdsa_verify_secp256k1(pk, z, r, s)` (same return). Argument `pk` is now `&[u64; 8]` (flat x‖y), not `&SyscallPoint256 { x, y }`. We removed the `SyscallPoint256` imports and now build `pk` as a flat `[u64; 8]`.
   - `ziskos::zisklib::sha256f_compress` → `ziskos::zisklib::sha256f_compress_c` (now `unsafe extern "C"`). Takes raw pointers + a num_blocks count. Wrapped in `unsafe { ... }` in `circuit/src/hash.rs`.
   - `ziskos::syscalls::syscall_keccak_f` now requires `unsafe { ... }` at the call site.
7. **Docker runtime image additions** (Dockerfile.cuda): need `build-essential`, `nasm`, `libgmp-dev` for the emulator-asm ROM setup `make`, plus the `libziskclib.a` library at `/root/.zisk/bin/libziskclib.a` and the `riscv2zisk` binary in `PATH`. The zisk emulator-asm + lib-c source trees must be present under `/root/.zisk/zisk/`.
8. **Docker memlock**: `cargo-zisk prove` calls `mmap(MAP_LOCKED)` for ASM shared memory. Container needs `ulimits.memlock: { soft: -1, hard: -1 }` — already added to docker-compose.yml.

## PLONK key — important blocker for goal #2

The PLONK proving key is NOT yet published in the Google bucket for v0.18.0:

- `https://storage.googleapis.com/zisk-setup/zisk-provingkey-plonk-0.18.0.tar.gz.md5` → 200 (MD5 `1185ef6f60ae2a4a57584f1d2be8e2c1`)
- `https://storage.googleapis.com/zisk-setup/zisk-provingkey-plonk-0.18.0.tar.gz` → **404** (only the `.md5` file is uploaded)

The standard proving key tarball (used for STARK) does not contain `.zkey`/`fflonk`/PLONK artifacts either. So the SNARK PLONK objective is blocked on upstream until the tarball ships. The STARK aggregated objective is unblocked.

## Files changed (committed below as one batch)

- `install.sh` — replaced source build with prebuilt-tarball download; new `download_zisk_prebuilt()` function; updated toolchain command; updated `check-setup` flags; `tar --ignore-zeros` for multi-stream gzip handling
- `Makefile`, `.env.example`, `docker-compose.yml`, `Dockerfile`, `Dockerfile.cuda` — version pins
- `Dockerfile.cuda` — replaced source-build stage 1 with a small `zisk-downloader` stage that pulls the prebuilt tarball; runtime image gained `build-essential`, `nasm`, `libgmp-dev`; copies for `cargo-zisk-gpu`, `cargo-zisk`, `ziskemu`, `riscv2zisk`, `libziskclib.a`, `~/.zisk/zisk` support tree; entrypoint `check-setup` flags fixed for v0.18.0
- `docker-compose.yml` — added `ulimits: memlock: -1` on the cuda service
- `circuit/Cargo.toml`, `circuit/Cargo.lock` — `ziskos` tag bumped to `v0.18.0`
- `circuit/src/hash.rs` — `sha256f_compress` → `sha256f_compress_c` (unsafe), `syscall_keccak_f` wrapped in `unsafe`
- `circuit/src/csp.rs` and `circuit/src/ecdsa.rs` — `secp256k1_ecdsa_verify` → `ecdsa_verify_secp256k1`; flat `[u64; 8]` pk instead of `SyscallPoint256`
- `circuit/src/main.rs` — `read_input_slice`/`set_output` migrated to `ziskos::io::commit_slice` with a `[u32; 46]` buffer; new helper `write_fr_output` replaces `set_fr_output`
- `circuit/elf/circuit.elf` — rebuilt against v0.18.0 toolchain
- `service/src/prover/worker.rs` — `prove` args updated for v0.18.0 (`--inputs`, `--output <file>`, `--emulator`, `--gpu`, no `--aggregation`)
- `service/src/api/jobs.rs` — proof file path changed from `vadcop_final_proof.bin` to `proof.bin` (matches the `--output` arg the worker passes)

## Where to resume

1. **Bring the stack back up**:
   ```bash
   docker compose --profile cuda up -d
   curl -sf http://localhost:8080/health   # should return quickly
   ```
   If the image is missing on the new machine, run `docker compose --profile cuda build` first (10–15 min mostly Rust build of the service).

2. **Re-run the e2e test** with a generous timeout — a single STARK aggregated proof on an RTX 5090 takes minutes, and the test runs 8 transitions:
   ```bash
   cd go-sdk/tests
   DAVINCI_API_URL=http://127.0.0.1:8080 \
     DAVINCI_PROOF_TIMEOUT=30m \
     go test ./integration/... -run TestFullE2E -v -timeout 120m 2>&1 | tee /tmp/e2e.log
   ```
   Last-known state right before crash: first prove job was running normally — ROM setup completed in ~10s, proofman was loading const pols. No remaining known bugs in the pipeline at that point.

3. **If the first prove fails again**:
   - `docker compose logs --tail=200` — look for the actual cargo-zisk error
   - `docker exec davinci-zkvm-davinci-zkvm-1 ls /root/.zisk/bin/` — must contain `libziskclib.a`
   - `docker exec davinci-zkvm-davinci-zkvm-1 which riscv2zisk make nasm gcc` — all four required
   - Output proof should land at `/proofs/<job_id>/proof.bin` inside the named volume `davinci-zkvm_proofs`

4. **Verifying outputs**: the circuit now emits all 46 u32 output registers as a single byte stream via `commit_slice`. The Go SDK `ParseOutputs([]uint32)` expects the same indexed layout — should still work because the bytes are LE-encoded in the same order. If output parsing on the Go side breaks, that's the place to look: `go-sdk/outputs.go`. The byte layout per register is `value.to_le_bytes()` written sequentially for indices 0..=45.

5. **Once STARK is green, attempt PLONK** (only after upstream uploads the key):
   ```bash
   curl -sI https://storage.googleapis.com/zisk-setup/zisk-provingkey-plonk-0.18.0.tar.gz
   # wait until this returns 200
   curl -L https://storage.googleapis.com/zisk-setup/zisk-provingkey-plonk-0.18.0.tar.gz -o ~/zisk-plonk.tar.gz
   md5sum ~/zisk-plonk.tar.gz   # expect 1185ef6f60ae2a4a57584f1d2be8e2c1
   tar --ignore-zeros -xzf ~/zisk-plonk.tar.gz -C ~/.zisk/
   # then either: cargo-zisk wrap-proof --proof <stark.bin> --proving-key <pk> \
   #              --proving-key-plonk <plonk_pk> --plonk --output <plonk.bin> --gpu
   # or pass --plonk + --proving-key-plonk directly to `cargo-zisk prove`
   ```
   The service code in worker.rs currently does NOT wrap the STARK proof into a PLONK. Once the key is available, the plan is:
   - Add a `proving_key_plonk_path` field to `service/src/config.rs` (env var `PROVING_KEY_PLONK_PATH`, optional)
   - In `worker.rs`, after the STARK prove succeeds, optionally run `cargo-zisk wrap-proof ... --plonk` to produce a `proof.plonk.bin`
   - Add an API endpoint to download the PLONK proof, or unify by content negotiation

## Useful re-check commands

```bash
# What ZisK is installed locally
~/.zisk/bin/cargo-zisk --version          # expect: cargo-zisk 0.18.0 [gpu] (790f9e2 ...)
ls ~/.zisk/bin/                           # cargo-zisk*, ziskemu, riscv2zisk, libziskclib.a, ...

# Proving key integrity
du -sh ~/.zisk/provingKey                 # ~12G
find ~/.zisk/provingKey -name "*.consttree_gpu" | wc -l   # 79

# Docker image
docker images davinci-zkvm-cuda
docker compose --profile cuda config | head -40
```

## Notable upstream issues observed

- `~/.zisk/bin/ziskup --version v0.18.0 ...` constructs URL with `vv0.18.0` (double v) — likely a bug in the ziskup shipped inside the v0.18.0 tarball. Workaround: download the tarball directly. Worth filing upstream if it doesn't already have an issue.
- v0.18.0 PLONK proving key `.md5` is uploaded to the bucket but the tarball itself is missing. Likely an upload race; check again after a few days.

## Commit

The patch has been committed in this session with message `upgrade zisk v0.18.0`. See `git log -1`.
