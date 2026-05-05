# davinci-zkvm + ZisK v0.17.0 — Basic AIR proofs fail self-verification

Self-contained reproduction package for the ZisK developers, using the
**davinci-zkvm circuit** (the actual production circuit we are blocked on),
not the canonical `sha-hasher` example.

The same failure mode is reproducible with the canonical `sha-hasher`
example (see `../zisk-bug-repro/`); this bundle gives you a real-world
reproduction with a non-trivial trace.

Empirically validated on **2026-05-05** end-to-end:
1. Wiped `~/.zisk` entirely.
2. `ziskup --gpu --provingkey` (proving-key MD5 `aea291736934ca040d98510006cb84ed` — matches the published `.md5`).
3. `cargo-zisk check-setup -a --gpu --proving-key ~/.zisk/provingKey`.
4. Brought up the davinci-zkvm service (`docker compose --profile cuda up -d --build`).
5. Submitted the first batch of the integration test (`go test -v -run TestFullE2E`); the service wrote the `input.bin` bundled here.
6. Ran the prove command shown below natively against `circuit.elf` + that captured `input.bin`.
7. Got the failure shown in *Expected output*.

---

## What's in this directory

| File | SHA-256 | MD5 | Notes |
|---|---|---|---|
| `circuit.elf` | `c665406d99dcea0bf5c186ad73c3a6aafa674cce16703869e27bea852cd248f7` | `828bce79c08e74347d6816ec3f3969e3` | Davinci-zkvm guest ELF (`circuit/elf/circuit.elf`), built from `circuit/src/` against ZisK 0.17.0 with `cargo-zisk build --release`. RISC-V 64-bit, statically linked, 380 KB. |
| `input.bin` | `e972c2878efbe9a81bd385096cb5213bfca357abdc59467e850ec6b61f17dcfe` | `337b25499711847c09fd6f81f468c236` | 213,808 bytes. Captured from a real submission of the first batch (2 fresh voters) of the integration test `TestFullE2E`. Already in **ZisK input format**: 8-byte LE length prefix + raw payload + zero-pad to 8-byte boundary. The payload is a `bincode`-serialised `ProveRequest` defined in `circuit/src/types.rs`. |
| `SHA256SUMS` | — | — | Both checksums together. |
| `prove.log` | — | — | Captured stdout/stderr from the failing run that produced this README (16/21 AIRs failed, exit non-zero, `Basic proofs were not verified`). |

`file circuit.elf`:
```
ELF 64-bit LSB executable, UCB RISC-V, soft-float ABI, version 1 (SYSV), statically linked, not stripped
```

---

## Running the reproduction

Assumes the ZisK toolchain is installed at `~/.zisk` (commit `b632745`,
built 2026-05-01) and the proving key is at `~/.zisk/provingKey`. If not,
follow Steps 1–2 of `../zisk-bug-repro/README.md` first.

```bash
# Pre-clean any stale shared-memory state from prior runs
sudo rm -f /dev/shm/ZISK_* /dev/shm/sem.ZISK_*
rm -rf ~/.zisk/cache && mkdir -p ~/.zisk/cache

cd /path/to/zisk-davinci-bug

# memlock=unlimited is required for the ASM microservice's mmap;
# we use sudo just to raise the limit, then drop privileges back to $USER.
sudo bash -c "
  ulimit -l unlimited
  sudo -u $USER env PATH=\$PATH HOME=$HOME \
    \$HOME/.zisk/bin/cargo-zisk prove \
      --elf $PWD/circuit.elf \
      --inputs $PWD/input.bin \
      --proving-key \$HOME/.zisk/provingKey \
      --gpu --no-aggregation --verify-proofs \
      --output $PWD/proof
"
echo "exit: $?"
```

Drop `--gpu` for the CPU path — it also fails (with a slightly different
error message) and rules out CUDA / driver / GPU as the cause.

If you have already raised memlock in `/etc/security/limits.conf` and
re-logged-in, the `sudo bash -c "ulimit -l unlimited; sudo -u … "` wrapper
isn't needed.

---

## Expected (buggy) output

```
[ERROR]: Final polynomial is not zero at position 16
[ERROR]: Final polynomial is not zero at position 16
[ERROR]: Final polynomial is not zero at position 16
... (positions 16–31, three times each)
[ERROR]: Invalid evaluations
... ✗ Proof of Rom: Instance #0
... ✗ Proof of Main: Instance #0
... ✗ Proof of Main: Instance #1
... ✗ Proof of Binary: Instance #0
... ✗ Proof of Arith: Instance #0
... ✗ Proof of ArithEq: Instance #0
... ✗ Proof of ArithEq: Instance #1
... ✗ Proof of Keccakf: Instance #0
... ✗ Proof of Sha256f: Instance #0
... ✗ Proof of Sha256f: Instance #1
... ✗ Proof of MemAlign: Instance #0
... ✗ Proof of Dma: Instance #0
... ✗ Proof of Dma64Aligned: Instance #0
... ✗ Proof of DmaUnaligned: Instance #0
... ✗ Proof of Mem: Instance #0
... ✗ Proof of InputData: Instance #0
... ✗ Proof of RomData: Instance #0
... ✓ BinaryExtension, DmaPrePost, SpecifiedRanges, VirtualTable0, VirtualTable1: verified
... ✓ All global constraints were successfully verified

Error: Error executing Prove command
Caused by:
    Error generating proof: Proof error: Basic proofs were not verified
```

Exit code: non-zero.

The exact set of failing AIRs varies between runs (see *Non-determinism*
below); the run captured in `prove.log` is one example.

---

## Non-determinism (key diagnostic)

With **identical** `circuit.elf`, **identical** `input.bin`, **identical**
proving key, and a warm ROM cache, repeated runs produce **different
Fiat–Shamir global challenges**. We observed 5 distinct global challenges
across 9 runs.

This means the stage-1 witness Merkle commitments themselves vary between
runs — the canonical signature of uninitialised-memory undefined behaviour.

### Suspected root cause

`create_buffer_fast` in `pil2-proofman/util/src/lib.rs`:

```rust
pub fn create_buffer_fast<F>(buffer_size: usize) -> Vec<F> {
    let mut buffer: Vec<MaybeUninit<F>> = Vec::with_capacity(buffer_size);
    unsafe { buffer.set_len(buffer_size); }
    let buffer: Vec<F> = unsafe { std::mem::transmute(buffer) };
    buffer
}
```

This returns a `Vec<F>` whose backing storage is uninitialised
(`set_len` after `with_capacity`, then `transmute` away the `MaybeUninit`).
If any consumer reads before writing, the witness columns contain
UB-tainted data and the resulting commitment / FRI evaluations are
non-deterministic and inconsistent.

---

## Variations to confirm the bug is in the prover

| Variation | Still fails? |
|---|---|
| Drop `--gpu` (pure CPU path) | ✅ — same `Final polynomial is not zero` family of errors; rules out CUDA / GPU / driver |
| Run inside `nvidia/cuda:12.8.0-cudnn-runtime-ubuntu22.04` Docker container | ✅ |
| Re-run with warm cache | ✅ — global Fiat–Shamir challenge varies between runs |
| Use the canonical `sha-hasher` example instead of this davinci circuit | ✅ — see `../zisk-bug-repro/` |

So the failure is not davinci-specific, not GPU-specific, and not Docker-specific.

---

## How `input.bin` was produced (for reference)

`input.bin` was captured directly from a live job submission of our
production service:

1. `docker compose --profile cuda up -d --build` (builds the davinci-zkvm Rust service).
2. `cd go-sdk/tests && go test -v -run TestFullE2E ./...` (the integration test driver in this repo).
3. The test's first batch (2 fresh voters, deterministic seed) POSTs a `ProveRequest` JSON to the service's `/prove` endpoint.
4. The service serialises the request with `bincode` and writes a ZisK-formatted `input.bin` (8-byte LE length prefix + payload + zero-pad) to `/proofs/<job_id>/input.bin` inside the container — *before* invoking `cargo-zisk prove`.
5. We copied that `input.bin` out of the docker volume.

So this is a real input that exercises every AIR the davinci circuit uses
(Groth16 batch verification, ECDSA, Poseidon, Keccak, SHA-256, BabyJubJub
ElGamal, lean-IMT census, SMT state transitions, KZG EIP-4844 evaluation).
The guest source is in `../circuit/src/`.

---

## Environment we reproduced on

- Ubuntu 22.04 and 26.04, x86_64
- `cargo-zisk --version` → `cargo-zisk 0.17.0 [gpu] (b632745 2026-05-01)`
- Proving key MD5 `aea291736934ca040d98510006cb84ed` (matches the published `.md5`)
- GPU: NVIDIA RTX 5090 (sm_120), driver 580.142, CUDA 12.8
- Also reproduced inside the official `nvidia/cuda:12.8.0-cudnn-runtime-ubuntu22.04` container
