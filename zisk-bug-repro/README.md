# ZisK v0.17.0 — Basic AIR proofs fail self-verification

Self-contained reproduction package for the ZisK developers.

Empirically validated end-to-end on **2026-05-05** from a fully clean state
(`rm -rf ~/.zisk` → fresh `ziskup --gpu --provingkey` → fresh
`cargo-zisk new sha_hasher` → fresh `cargo-zisk build --release`).
The bundled ELF and the prove command in this README produce the failure
shown in *Expected output* below.

---

## What's in this directory

| File | SHA-256 | MD5 | Notes |
|---|---|---|---|
| `sha_hasher.elf` | `91999003a397de223247e04c6fdce23d552ecb1b72587f959d635c096932585d` | `3c56439930cf69526f1848aad93946b6` | Guest ELF from the **unmodified** `cargo-zisk new sha_hasher` template, built with `cargo-zisk build --release` against ZisK 0.17.0 (commit `b632745`, built 2026-05-01). |
| `input.bin` | `181d9408cee887a97d4c8d97f2f846ab0edc8d9f2c803793daaa119a16fbd824` | `613ba47735363e25f3bc93a4c198783c` | 16 bytes. ZisK input format: `u64 LE length=4` + `u32 LE n=1` + 4-byte zero-pad. Tells the guest to run **one** SHA-256 iteration. |
| `SHA256SUMS` | — | — | Both checksums together. |
| `prove.log` | — | — | Captured stdout/stderr from the failing run that produced this README. |

`file sha_hasher.elf`:
```
ELF 64-bit LSB executable, UCB RISC-V, soft-float ABI, version 1 (SYSV), statically linked, not stripped
```

The build is reproducible — re-scaffolding (`cargo-zisk new sha_hasher`) and
re-building on a different machine yields the same SHA-256 we list above.

---

## Reproducing from scratch

### Prerequisites

- Linux x86_64 (we tested on Ubuntu 22.04 and 26.04)
- ≥ 32 GB RAM, ≥ 30 GB free disk
- Optional: NVIDIA GPU + driver supporting CUDA ≥ 12.8 (we used RTX 5090, driver 580.142). The CPU path also fails — see *Variations* below.
- Standard build deps:
  ```bash
  sudo apt-get install -y xz-utils jq curl build-essential libomp-dev libgmp-dev \
      libsodium-dev nasm libopenmpi-dev openmpi-bin libclang-dev clang
  ```

### Step 1 — Install ZisK 0.17.0

```bash
curl -fsSL https://raw.githubusercontent.com/0xPolygonHermez/zisk/v0.17.0/ziskup/install.sh | bash
source ~/.bashrc 2>/dev/null || export PATH="$HOME/.zisk/bin:$PATH"

~/.zisk/bin/ziskup --gpu --provingkey
```

> **Workaround for `tar: invalid compressed data — crc error`** during proving-key extraction (newer GNU tar is stricter about multi-stream gzip):
> ```bash
> mkdir -p /tmp/pk-extract
> tar --ignore-zeros -xzf <path-to>/zisk-provingkey-0.17.0.tar.gz -C /tmp/pk-extract
> rm -rf ~/.zisk/provingKey
> mv /tmp/pk-extract/provingKey ~/.zisk/
> ```
> Verified MD5 of the official tarball: `aea291736934ca040d98510006cb84ed`
> (matches `https://storage.googleapis.com/zisk-setup/zisk-provingkey-0.17.0.tar.gz.md5`).

Verify the install:
```bash
$ ~/.zisk/bin/cargo-zisk --version
cargo-zisk 0.17.0 [gpu] (b632745 2026-05-01T...)

$ ls ~/.zisk/provingKey/zisk/Zisk/airs/ | wc -l
35
```

### Step 2 — Regenerate GPU constant trees (skip for CPU-only)

```bash
~/.zisk/bin/cargo-zisk check-setup -a --gpu --proving-key ~/.zisk/provingKey
```

Completes in a few minutes, exit 0, prints `WRITING_CONST_TREE` for each AIR.

### Step 3 — Scaffold the canonical sha-hasher example

```bash
mkdir -p ~/basictest && cd ~/basictest
~/.zisk/bin/cargo-zisk new sha_hasher
cd sha_hasher/guest
~/.zisk/bin/cargo-zisk build --release
```

Produces:
```
~/basictest/sha_hasher/guest/target/elf/riscv64ima-zisk-zkvm-elf/release/guest
```

(SHA-256 should match the bundled `sha_hasher.elf` listed above.)

### Step 4 — Create the input file

```bash
printf '\x04\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00' > ~/basictest/input.bin
```

### Step 5 — Run the prover (the bug)

```bash
# Pre-clean any stale shared-memory state from prior runs
sudo rm -f /dev/shm/ZISK_* /dev/shm/sem.ZISK_*
rm -rf ~/.zisk/cache && mkdir -p ~/.zisk/cache

ELF=~/basictest/sha_hasher/guest/target/elf/riscv64ima-zisk-zkvm-elf/release/guest
INPUT=~/basictest/input.bin

# memlock=unlimited is required for the ASM microservice's mmap;
# we use sudo just to raise the limit, then drop privileges back to $USER.
sudo bash -c "
  ulimit -l unlimited
  sudo -u $USER env PATH=\$PATH HOME=$HOME \
    $HOME/.zisk/bin/cargo-zisk prove \
      --elf $ELF \
      --inputs $INPUT \
      --proving-key $HOME/.zisk/provingKey \
      --gpu --no-aggregation --verify-proofs \
      --output $HOME/basictest/proof
"
echo "exit: $?"
```

Drop `--gpu` for the CPU path. If you have already raised memlock in
`/etc/security/limits.conf` and re-logged-in, the `sudo bash -c "ulimit -l
unlimited; sudo -u … "` wrapper isn't needed.

---

## Expected (buggy) output

```
[ERROR]: Final polynomial is not zero at position 16
[ERROR]: Final polynomial is not zero at position 16
[ERROR]: Final polynomial is not zero at position 16
... (positions 16–31, three times each)
[ERROR]: Invalid evaluations
... ✗ Proof of Rom: Instance #0 was not verified
... ✗ Proof of Main: Instance #0 was not verified
... ✗ Proof of Binary: Instance #0 was not verified
... ✗ Proof of Arith: Instance #0 was not verified
... ✗ Proof of Dma: Instance #0 was not verified
... ✗ Proof of MemAlign: Instance #0 was not verified
... ✗ Proof of Dma64AlignedMem: Instance #0 was not verified
... ✗ Proof of DmaUnaligned: Instance #0 was not verified
... ✗ Proof of Mem: Instance #0 was not verified
... ✗ Proof of InputData: Instance #0 was not verified
... ✗ Proof of RomData: Instance #0 was not verified
... ✓ BinaryExtension, DmaPrePost, SpecifiedRanges, VirtualTable0, VirtualTable1: verified
... ✓ All global constraints were successfully verified

Error: Error executing Prove command
Caused by:
    Error generating proof: Proof error: Basic proofs were not verified
```

Exit code: non-zero (typically 1).

The exact set of failing AIRs **varies between runs with identical inputs**
(see *Non-determinism* below). `Main` fails in essentially every run, and at
least one AIR always fails. The verified run captured in `prove.log`
(2026-05-05) had 11/16 AIRs fail.

---

## Variations to confirm the bug is in the prover, not the environment

| Variation | Still fails? |
|---|---|
| Drop `--gpu` (pure CPU path) | ✅ — same `Final polynomial is not zero` error; rules out CUDA / driver / GPU |
| Run inside `nvidia/cuda:12.8.0-cudnn-runtime-ubuntu22.04` Docker container | ✅ |
| Re-run several times with warm cache | ✅ — but the global Fiat–Shamir challenge varies between runs |
| Different guest program with non-trivial trace | ✅ |

---

## Non-determinism (important diagnostic)

With **identical** ELF, **identical** input, **identical** proving key, and a
warm ROM cache, repeated runs produce **different Fiat–Shamir global
challenges**. We observed 5 distinct global challenges across 9 runs.

This means the stage-1 witness Merkle commitments themselves vary between
runs — the canonical signature of uninitialised-memory UB.

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

This returns a `Vec<F>` whose backing storage is uninitialised (set_len after
allocate-with-capacity, then `transmute` away the `MaybeUninit`). If any
consumer reads before writing, the witness columns contain UB-tainted data
and the resulting commitment / FRI evaluations are non-deterministic and
inconsistent.

---

## Environment we reproduced on

- Ubuntu 22.04 and 26.04, x86_64
- `cargo-zisk --version` → `cargo-zisk 0.17.0 [gpu] (b632745 2026-05-01)`
- Proving key MD5 `aea291736934ca040d98510006cb84ed` (matches the published `.md5`)
- GPU: NVIDIA RTX 5090 (sm_120), driver 580.142, CUDA 12.8
- Also reproduced inside the official `nvidia/cuda:12.8.0-cudnn-runtime-ubuntu22.04` container

## Cleanup

```bash
rm -rf ~/basictest
sudo rm -rf ~/.zisk
rm -rf ~/.rustup/toolchains/zisk
sudo rm -f /dev/shm/ZISK_* /dev/shm/sem.ZISK_*
```
