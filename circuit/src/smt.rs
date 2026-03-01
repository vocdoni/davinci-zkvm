//! Sparse Merkle Tree (SMT) state-transition verifier.
//!
//! Implements the Circomlib / gnark-crypto-primitives `Processor` circuit:
//! given an old root, a new root, a key, a value, and Merkle siblings, verifies
//! that inserting / updating / deleting the key transitions the tree correctly.
//!
//! **Hash compatibility**: Arbo `HashFunctionSha256`
//! - Leaf hash  : `SHA256(key_le32 || value_le32 || 0x01)` — 65 bytes
//! - Node hash  : `SHA256(left_le32 || right_le32)`         — 64 bytes
//! All byte arrays are **little-endian** (arbo's `BigIntToBytes` = LE).
//!
//! **Sibling ordering**: index 0 = root level, index n-1 = leaf level (same as arbo).
//! **Path bits**: LSB-first — `bit[level] = key_u256_le[level/64] >> (level%64) & 1`.

use crate::hash::sha256_once;
use crate::io::ParsedInput;
use crate::types::{FrRaw, SmtTransition, ZERO_FR};

// ─── Byte-order helpers ────────────────────────────────────────────────────

/// FrRaw (LE word order) → little-endian 32 bytes (Arbo's byte format).
/// Arbo stores all values (keys, values, hashes) in little-endian byte order.
fn fr_to_le(v: &FrRaw) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[0..8].copy_from_slice(&v[0].to_le_bytes());
    out[8..16].copy_from_slice(&v[1].to_le_bytes());
    out[16..24].copy_from_slice(&v[2].to_le_bytes());
    out[24..32].copy_from_slice(&v[3].to_le_bytes());
    out
}

/// Little-endian 32 bytes → FrRaw (LE word order).
fn le_to_fr(b: &[u8; 32]) -> FrRaw {
    [
        u64::from_le_bytes(b[0..8].try_into().unwrap()),
        u64::from_le_bytes(b[8..16].try_into().unwrap()),
        u64::from_le_bytes(b[16..24].try_into().unwrap()),
        u64::from_le_bytes(b[24..32].try_into().unwrap()),
    ]
}

// ─── Arbo-compatible hash functions ────────────────────────────────────────

/// Arbo leaf hash: `SHA256(key_le32 || value_le32 || 0x01)` — 65 bytes.
fn leaf_hash(key: &FrRaw, value: &FrRaw) -> FrRaw {
    let mut input = [0u8; 65];
    input[0..32].copy_from_slice(&fr_to_le(key));
    input[32..64].copy_from_slice(&fr_to_le(value));
    input[64] = 0x01;
    le_to_fr(&sha256_once(&input))
}

/// Arbo internal node hash: `SHA256(left_le32 || right_le32)` — 64 bytes.
fn node_hash(left: &FrRaw, right: &FrRaw) -> FrRaw {
    let mut input = [0u8; 64];
    input[0..32].copy_from_slice(&fr_to_le(left));
    input[32..64].copy_from_slice(&fr_to_le(right));
    le_to_fr(&sha256_once(&input))
}

// ─── Path helpers ───────────────────────────────────────────────────────────

/// Switcher: `sel=0 → (l, r)`, `sel=1 → (r, l)`.
fn switcher(sel: bool, l: FrRaw, r: FrRaw) -> (FrRaw, FrRaw) {
    if sel { (r, l) } else { (l, r) }
}

/// Get path bit `level` from key (LSB-first, LE word order).
/// `bit[level] = key[level/64] >> (level%64) & 1`
fn get_bit(key: &FrRaw, level: usize) -> bool {
    let word_idx = level / 64;
    let bit_idx = level % 64;
    if word_idx >= 4 { return false; }
    (key[word_idx] >> bit_idx) & 1 == 1
}

// ─── LevIns ─────────────────────────────────────────────────────────────────

/// Detect the insertion level in an SMT Merkle proof.
///
/// Based on circomlib `smtlevins.circom`.  `siblings[0]` = root-level sibling,
/// `siblings[n-1]` = leaf-level sibling (must be zero).
///
/// Returns `(valid, lev_ins[n])` where exactly one `lev_ins[i]` is `true`.
fn lev_ins_flag(siblings: &[FrRaw], enabled: bool) -> (bool, Vec<bool>) {
    let n = siblings.len();
    if n == 0 {
        return (!enabled, vec![]);
    }
    if n == 1 {
        // Single-level tree: levIns[0] = 1 always.
        let valid = if enabled { siblings[0] == [0u64; 4] } else { true };
        return (valid, vec![true]);
    }

    let is_zero: Vec<bool> = siblings.iter().map(|s| *s == [0u64; 4]).collect();

    let mut lev_ins = vec![false; n];
    let mut done = vec![false; n - 1];

    // levIns[n-1] = 1 − isZero[n-2]
    lev_ins[n - 1] = !is_zero[n - 2];
    done[n - 2] = lev_ins[n - 1];

    // levIns[i] = (1 − done[i]) ⋅ (1 − isZero[i-1])  for i = n-2 … 1
    for i in (1..n - 1).rev() {
        lev_ins[i] = !done[i] && !is_zero[i - 1];
        done[i - 1] = lev_ins[i] || done[i];
    }

    // levIns[0] = 1 − done[0]
    lev_ins[0] = !done[0];

    // Validity: leaf-level sibling must be 0, and exactly one levIns is set.
    let leaf_zero_ok = is_zero[n - 1];
    let one_hot = lev_ins.iter().filter(|&&x| x).count() == 1;
    let valid = if enabled { leaf_zero_ok && one_hot } else { true };

    (valid, lev_ins)
}

// ─── Processor state machine ────────────────────────────────────────────────

/// Per-level Processor state machine.
///
/// Direct port of `ProcessorSM` from `smtprocessorsm.circom`.  All values are
/// in {0, 1}; the state is one-hot across (top, old0, bot, new1, na, upd).
#[allow(clippy::too_many_arguments)]
fn processor_sm(
    xor: u8,
    is0: u8,
    lev_ins: u8,
    fnc0: u8,
    prev_top: u8,
    prev_old0: u8,
    prev_bot: u8,
    prev_new1: u8,
    prev_na: u8,
    prev_upd: u8,
) -> (u8, u8, u8, u8, u8, u8) {
    let aux1 = prev_top * lev_ins;
    let aux2 = aux1 * fnc0;
    let st_top = prev_top - aux1;
    let st_old0 = aux2 * is0;
    let inner = (aux2 - st_old0) + prev_bot;
    let st_new1 = inner * xor;
    let st_bot = inner * (1 - xor);
    let st_upd = aux1 - aux2;
    let st_na = prev_new1 + prev_old0 + prev_na + prev_upd;
    (st_top, st_old0, st_bot, st_new1, st_na, st_upd)
}

// ─── Processor level ────────────────────────────────────────────────────────

/// Compute `(old_root, new_root)` for one level of the SMT proof.
///
/// Direct port of `ProcessorLevel` from `smtprocessorlevel.circom`.
#[allow(clippy::too_many_arguments)]
fn processor_level(
    st_top: u8,
    st_old0: u8,
    st_bot: u8,
    st_new1: u8,
    st_upd: u8,
    sibling: &FrRaw,
    old1leaf: &FrRaw,
    new1leaf: &FrRaw,
    new_lr_bit: bool,
    old_child: &FrRaw,
    new_child: &FrRaw,
) -> (FrRaw, FrRaw) {
    // old_root = old1leaf⋅(stBot + stNew1 + stUpd) + node_hash(switcher(bit, oldChild, sibling))⋅stTop
    let old_root = if st_top == 1 {
        let (l, r) = switcher(new_lr_bit, *old_child, *sibling);
        node_hash(&l, &r)
    } else if st_bot == 1 || st_new1 == 1 || st_upd == 1 {
        *old1leaf
    } else {
        [0u64; 4]
    };

    // new_root left arg = newChild⋅(stTop + stBot) + new1leaf⋅stNew1
    let left_val = if st_top == 1 || st_bot == 1 {
        *new_child
    } else if st_new1 == 1 {
        *new1leaf
    } else {
        [0u64; 4]
    };

    // new_root right arg = sibling⋅stTop + old1leaf⋅stNew1
    let right_val = if st_top == 1 {
        *sibling
    } else if st_new1 == 1 {
        *old1leaf
    } else {
        [0u64; 4]
    };

    let (nl, nr) = switcher(new_lr_bit, left_val, right_val);
    let new_proof_hash = node_hash(&nl, &nr);

    // new_root = new_proof_hash⋅(stTop + stBot + stNew1) + new1leaf⋅(stOld0 + stUpd)
    let new_root = if st_top == 1 || st_bot == 1 || st_new1 == 1 {
        new_proof_hash
    } else if st_old0 == 1 || st_upd == 1 {
        *new1leaf
    } else {
        [0u64; 4]
    };

    (old_root, new_root)
}

// ─── Top-level verifier ─────────────────────────────────────────────────────

/// Verify a single SMT state-transition.
///
/// Implements the `Processor` function from `smtprocessor.circom`.
/// Returns `true` iff the transition (old_root → new_root) is valid.
pub fn verify_transition(t: &SmtTransition) -> bool {
    let levels = t.siblings.len();
    if levels == 0 {
        return false;
    }

    let enabled = t.fnc0 || t.fnc1;

    // Precompute leaf hashes.
    let hash1_old = leaf_hash(&t.old_key, &t.old_value);
    let hash1_new = leaf_hash(&t.new_key, &t.new_value);

    // LevIns: find insertion level.
    let (lev_valid, lev_ins) = lev_ins_flag(&t.siblings, enabled);
    if !lev_valid {
        return false;
    }

    // XOR of path bits for old_key vs new_key.
    let xors: Vec<u8> = (0..levels)
        .map(|i| (get_bit(&t.old_key, i) ^ get_bit(&t.new_key, i)) as u8)
        .collect();

    // Per-level state machine.
    let is0 = t.is_old0 as u8;
    let fnc0 = t.fnc0 as u8;
    let enabled_u = enabled as u8;

    let mut st_top_v = vec![0u8; levels];
    let mut st_old0_v = vec![0u8; levels];
    let mut st_bot_v = vec![0u8; levels];
    let mut st_new1_v = vec![0u8; levels];
    let mut st_na_v = vec![0u8; levels];
    let mut st_upd_v = vec![0u8; levels];

    for i in 0..levels {
        let (top, old0, bot, new1, na, upd) = if i == 0 {
            // Initial state: top=enabled, na=1-enabled, rest=0.
            processor_sm(
                xors[i], is0, lev_ins[i] as u8, fnc0,
                enabled_u, 0, 0, 0, 1 - enabled_u, 0,
            )
        } else {
            processor_sm(
                xors[i], is0, lev_ins[i] as u8, fnc0,
                st_top_v[i-1], st_old0_v[i-1], st_bot_v[i-1],
                st_new1_v[i-1], st_na_v[i-1], st_upd_v[i-1],
            )
        };
        st_top_v[i] = top;
        st_old0_v[i] = old0;
        st_bot_v[i] = bot;
        st_new1_v[i] = new1;
        st_na_v[i] = na;
        st_upd_v[i] = upd;
    }

    // Terminal state assertion: exactly one of (na, new1, old0, upd) must be 1.
    let last = levels - 1;
    let terminal = st_na_v[last] + st_new1_v[last] + st_old0_v[last] + st_upd_v[last];
    if terminal != 1 {
        return false;
    }

    // ProcessorLevel: bottom-up reconstruction of (old_root, new_root).
    let zero = [0u64; 4];
    let mut levels_old_root = vec![zero; levels];
    let mut levels_new_root = vec![zero; levels];

    for i in (0..levels).rev() {
        let (old_child, new_child) = if i == levels - 1 {
            (zero, zero)
        } else {
            (levels_old_root[i + 1], levels_new_root[i + 1])
        };
        let new_lr_bit = get_bit(&t.new_key, i);
        let (or, nr) = processor_level(
            st_top_v[i], st_old0_v[i], st_bot_v[i], st_new1_v[i], st_upd_v[i],
            &t.siblings[i], &hash1_old, &hash1_new,
            new_lr_bit,
            &old_child, &new_child,
        );
        levels_old_root[i] = or;
        levels_new_root[i] = nr;
    }

    // Top switcher: for delete (fnc0=1, fnc1=1) swap left/right.
    let del = t.fnc0 && t.fnc1;
    let (top_l, top_r) = switcher(del, levels_old_root[0], levels_new_root[0]);

    // ForceEqualIfEnabled: old_root must match left output.
    if enabled && top_l != t.old_root {
        return false;
    }

    // Key equality constraint: if update (fnc0=0, fnc1=1) old_key == new_key.
    if !t.fnc0 && t.fnc1 && t.old_key != t.new_key {
        return false;
    }

    // Final check: computed new root matches claimed new root.
    let computed_new_root = if enabled { top_r } else { t.old_root };
    computed_new_root == t.new_root
}

// ─── Batch verifier ─────────────────────────────────────────────────────────

/// Verify all SMT transitions in the parsed input.
///
/// Returns:
/// - `2` when no SMT block is present (backward-compatible)
/// - `1` when all transitions are valid
/// - `0` when any transition is invalid (also sets bit 9 in `fail_mask`)
pub fn verify_batch(parsed: &ParsedInput, fail_mask: &mut u32) -> u32 {
    if parsed.smt.is_empty() {
        return 2; // SMT block absent — not a failure
    }
    let mut all_ok = true;
    for t in &parsed.smt {
        if !verify_transition(t) {
            *fail_mask |= 1 << 9;
            all_ok = false;
        }
    }
    all_ok as u32
}

// ─── Chain verifier ──────────────────────────────────────────────────────────

/// Verify a sequence of SMT transitions forms a consistent chain:
/// - `transitions[0].old_root == declared_old_root`
/// - `transitions[i].new_root == transitions[i+1].old_root` for all i
/// - `transitions[N-1].new_root == declared_new_root`
/// - Each individual transition is valid
///
/// Returns `true` if the chain is valid, `false` otherwise.
/// Sets bit `fail_bit` in `fail_mask` on failure.
pub fn verify_chain(
    transitions: &[SmtTransition],
    declared_old: &FrRaw,
    declared_new: &FrRaw,
    fail_mask: &mut u32,
    fail_bit: u8,
) -> bool {
    if transitions.is_empty() {
        // Empty chain: old root must equal new root.
        let ok = declared_old == declared_new;
        if !ok { *fail_mask |= 1 << fail_bit; }
        return ok;
    }

    // Check first transition's old root.
    if &transitions[0].old_root != declared_old {
        *fail_mask |= 1 << fail_bit;
        return false;
    }

    // Verify each transition and check chaining.
    for i in 0..transitions.len() {
        if !verify_transition(&transitions[i]) {
            *fail_mask |= 1 << fail_bit;
            return false;
        }
        if i + 1 < transitions.len() {
            if transitions[i].new_root != transitions[i + 1].old_root {
                *fail_mask |= 1 << fail_bit;
                return false;
            }
        }
    }

    // Check last transition's new root.
    let last_new = &transitions[transitions.len() - 1].new_root;
    if last_new != declared_new {
        *fail_mask |= 1 << fail_bit;
        return false;
    }

    true
}

// ─── State-transition verifier ───────────────────────────────────────────────

/// Verify the full DAVINCI state-transition block (STATETX).
///
/// Returns `(ok, old_root_lo, old_root_hi, new_root_lo, new_root_hi, voters, overwritten)`.
/// When no state block is present, returns `(true, 0, 0, 0, 0, 0, 0)` — absence is not a failure.
pub fn verify_state(
    parsed: &ParsedInput,
    fail_mask: &mut u32,
) -> (bool, u64, u64, u64, u64, u64, u64) {
    let state = match &parsed.state {
        None => return (true, 0, 0, 0, 0, 0, 0),
        Some(s) => s,
    };

    let mut ok = true;

    // Verify VoteID chain: OldStateRoot → intermediate → NewStateRoot via voteIDs.
    // The full state root changes with every chain so each sub-chain shares roots
    // interleaved. For Step 2 we verify the chains independently with their declared roots.
    ok &= verify_chain(
        &state.vote_id_chain,
        &state.old_state_root,
        // After all voteID insertions the intermediate root is the start of ballot chain.
        if state.ballot_chain.is_empty() { &state.new_state_root }
        else { &state.ballot_chain[0].old_root },
        fail_mask, 10,
    );

    ok &= verify_chain(
        &state.ballot_chain,
        if state.vote_id_chain.is_empty() { &state.old_state_root }
        else { state.vote_id_chain.last().map(|t| &t.new_root).unwrap_or(&ZERO_FR) },
        // After ballot chain: start of resultsAdd/Sub (or new_state_root if absent).
        // Process read-proofs are NOT part of the chain (they're separate inclusion checks).
        match &state.results_add {
            Some(r) => &r.old_root,
            None => match &state.results_sub {
                Some(r) => &r.old_root,
                None => &state.new_state_root,
            },
        },
        fail_mask, 11,
    );

    // Verify resultsAdd transition (single transition, not a chain).
    if let Some(r) = &state.results_add {
        if !verify_transition(r) {
            *fail_mask |= 1 << 12;
            ok = false;
        }
    }

    // Verify resultsSub transition.
    if let Some(r) = &state.results_sub {
        if !verify_transition(r) {
            *fail_mask |= 1 << 12;
            ok = false;
        }
    }

    // Verify process read-proofs (fnc0=0, fnc1=0 → no mutation, just inclusion).
    // These all share the OldStateRoot (config keys don't change this batch).
    for p in &state.process_proofs {
        // Read proof: old_root == new_root (no change), both equal OldStateRoot.
        if p.old_root != state.old_state_root {
            *fail_mask |= 1 << 13;
            ok = false;
            break;
        }
        if !verify_transition(p) {
            *fail_mask |= 1 << 13;
            ok = false;
            break;
        }
    }

    let old = &state.old_state_root;
    let new = &state.new_state_root;

    (
        ok,
        old[0], old[1],
        new[0], new[1],
        state.n_voters as u64,
        state.n_overwritten as u64,
    )
}
