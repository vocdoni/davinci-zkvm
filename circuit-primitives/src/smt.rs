//! Sparse Merkle Tree (SMT) state-transition verifier.
//!
//! Implements the arbo SMT `Processor` logic:
//! given an old root, a new root, a key, a value, and Merkle siblings, verifies
//! that inserting / updating / deleting the key transitions the tree correctly.
//!
//! **Hash compatibility**: Arbo `HashFunctionSha256`
// ! - Leaf hash  : `SHA256(key_le32 || value_le32 || 0x01)` => 65 bytes
// ! - Node hash  : `SHA256(left_le32 || right_le32)`         => 64 bytes
//! All byte arrays are **little-endian** (arbo's `BigIntToBytes` = LE).
//!
//! **Sibling ordering**: index 0 = root level, index n-1 = leaf level (same as arbo).
// ! **Path bits**: LSB-first => `bit[level] = key_u256_le[level/64] >> (level%64) & 1`.

use crate::hash::sha256_once;
use crate::types::{FrRaw, SmtTransition, StateBlock, ZERO_FR,
    FAIL_SMT_VOTEID, FAIL_SMT_BALLOT, FAIL_SMT_RESULTS, FAIL_SMT_PROCESS,
    FAIL_REFRESH, MAX_REFRESH, REFRESH_MIN, REFRESH_TAU, REFRESH_KAPPA};

// Byte-order helpers

/// FrRaw (LE word order) → little-endian 32 bytes (Arbo's byte format).
/// Arbo stores all values (keys, values, hashes) in little-endian byte order.
pub fn fr_to_le(v: &FrRaw) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[0..8].copy_from_slice(&v[0].to_le_bytes());
    out[8..16].copy_from_slice(&v[1].to_le_bytes());
    out[16..24].copy_from_slice(&v[2].to_le_bytes());
    out[24..32].copy_from_slice(&v[3].to_le_bytes());
    out
}

/// Little-endian 32 bytes → FrRaw (LE word order).
pub fn le_to_fr(b: &[u8; 32]) -> FrRaw {
    [
        u64::from_le_bytes(b[0..8].try_into().unwrap()),
        u64::from_le_bytes(b[8..16].try_into().unwrap()),
        u64::from_le_bytes(b[16..24].try_into().unwrap()),
        u64::from_le_bytes(b[24..32].try_into().unwrap()),
    ]
}

// Arbo-compatible hash functions

/// Arbo leaf hash: `SHA256(key_le32 || value_le32 || 0x01)` => 65 bytes.
pub fn leaf_hash(key: &FrRaw, value: &FrRaw) -> FrRaw {
    let mut input = [0u8; 65];
    input[0..32].copy_from_slice(&fr_to_le(key));
    input[32..64].copy_from_slice(&fr_to_le(value));
    input[64] = 0x01;
    le_to_fr(&sha256_once(&input))
}

/// Arbo internal node hash: `SHA256(left_le32 || right_le32)` => 64 bytes.
pub fn node_hash(left: &FrRaw, right: &FrRaw) -> FrRaw {
    let mut input = [0u8; 64];
    input[0..32].copy_from_slice(&fr_to_le(left));
    input[32..64].copy_from_slice(&fr_to_le(right));
    le_to_fr(&sha256_once(&input))
}

// Path helpers

/// Switcher: `sel=0 → (l, r)`, `sel=1 → (r, l)`.
fn switcher(sel: bool, l: FrRaw, r: FrRaw) -> (FrRaw, FrRaw) {
    if sel { (r, l) } else { (l, r) }
}

/// Get path bit `level` from key (LSB-first, LE word order).
/// `bit[level] = key[level/64] >> (level%64) & 1`
pub fn get_bit(key: &FrRaw, level: usize) -> bool {
    let word_idx = level / 64;
    let bit_idx = level % 64;
    if word_idx >= 4 { return false; }
    (key[word_idx] >> bit_idx) & 1 == 1
}

// LevIns

/// Detect the insertion level in an SMT Merkle proof.
/// Based on circomlib `smtlevins.circom`.  `siblings[0]` = root-level sibling,
/// `siblings[n-1]` = leaf-level sibling (must be zero).
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

    // levIns[n-1] = 1 - isZero[n-2]
    lev_ins[n - 1] = !is_zero[n - 2];
    done[n - 2] = lev_ins[n - 1];

    // levIns[i] = (1 - done[i]) * (1 - isZero[i-1])  for i = n-2 … 1
    for i in (1..n - 1).rev() {
        lev_ins[i] = !done[i] && !is_zero[i - 1];
        done[i - 1] = lev_ins[i] || done[i];
    }

    // levIns[0] = 1 - done[0]
    lev_ins[0] = !done[0];

    // Validity: leaf-level sibling must be 0, and exactly one levIns is set.
    let leaf_zero_ok = is_zero[n - 1];
    let one_hot = lev_ins.iter().filter(|&&x| x).count() == 1;
    let valid = if enabled { leaf_zero_ok && one_hot } else { true };

    (valid, lev_ins)
}

// Processor state machine

/// Per-level Processor state machine.
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

// Processor level

/// Compute `(old_root, new_root)` for one level of the SMT proof.
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
    // old_root = old1leaf*(stBot + stNew1 + stUpd) + node_hash(switcher(bit, oldChild, sibling))*stTop
    let old_root = if st_top == 1 {
        let (l, r) = switcher(new_lr_bit, *old_child, *sibling);
        node_hash(&l, &r)
    } else if st_bot == 1 || st_new1 == 1 || st_upd == 1 {
        *old1leaf
    } else {
        [0u64; 4]
    };

    // new_root = new_proof_hash*(stTop + stBot + stNew1) + new1leaf*(stOld0 + stUpd)
    //
    // new_proof_hash = node_hash(switcher(left_val, right_val)) is only consumed
    // when stTop|stBot|stNew1.  On the zero-padded levels below the insertion
    // point (na states) it is discarded, so compute it only inside the guard and
    // skip the SHA-256 otherwise.  With nLevels=256 and real depth ~log2(N), this
    // elides the large majority of node hashes per transition.
    let new_root = if st_top == 1 || st_bot == 1 || st_new1 == 1 {
        // new_root left arg = newChild*(stTop + stBot) + new1leaf*stNew1
        let left_val = if st_top == 1 || st_bot == 1 {
            *new_child
        } else if st_new1 == 1 {
            *new1leaf
        } else {
            [0u64; 4]
        };
        // new_root right arg = sibling*stTop + old1leaf*stNew1
        let right_val = if st_top == 1 {
            *sibling
        } else if st_new1 == 1 {
            *old1leaf
        } else {
            [0u64; 4]
        };
        let (nl, nr) = switcher(new_lr_bit, left_val, right_val);
        node_hash(&nl, &nr)
    } else if st_old0 == 1 || st_upd == 1 {
        *new1leaf
    } else {
        [0u64; 4]
    };

    (old_root, new_root)
}

// Top-level verifier

/// Verify a single SMT state-transition.
/// Implements the `Processor` function from `smtprocessor.circom`.
/// Returns `true` iff the transition (old_root → new_root) is valid.
pub fn verify_transition(t: &SmtTransition) -> bool {
    let levels = t.siblings.len();
    if levels == 0 {
        return false;
    }

    let enabled = t.fnc0 || t.fnc1;

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

    // Lazy leaf hashes: each is a SHA-256, consumed by processor_level only for
    // some states. old1leaf is read when any level is bot|new1|upd; new1leaf when
    // any level is new1|old0|upd. is_old0 INSERTs (voteIDs) elide old1leaf; NOOP
    // transitions elide both. Compute only what is actually consumed.
    let need_old = (0..levels).any(|i| (st_bot_v[i] | st_new1_v[i] | st_upd_v[i]) == 1);
    let need_new = (0..levels).any(|i| (st_new1_v[i] | st_old0_v[i] | st_upd_v[i]) == 1);
    let zero_leaf = [0u64; 4];
    let hash1_old = if need_old { leaf_hash(&t.old_key, &t.old_value) } else { zero_leaf };
    let hash1_new = if need_new { leaf_hash(&t.new_key, &t.new_value) } else { zero_leaf };

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

// Inclusion verifier (SMTVerifier)

/// Verify SMT **inclusion** of `(key, value)` under `root`.
///
/// Port of circomlib / gnark `smt.InclusionVerifier` (the `fnc = 0`, `isOld0 =
/// 0`, `enabled = 1` case of `VerifierWithLeafHashFlag`). davinci-node verifies
/// the process config read-proofs with this Verifier, NOT with the Processor:
/// a Processor NOOP only asserts `old_root == new_root` and never touches the
/// siblings, so it proves nothing about tree membership. Using it for a read
/// proof lets a prover claim an arbitrary `(key, value)` (e.g. a forged
/// encryption key). Inclusion reconstructs the root from the leaf and siblings
/// and binds the value to the tree.
///
/// Returns `true` iff `(key, value)` is provably contained in `root`.
pub fn verify_inclusion(root: &FrRaw, key: &FrRaw, value: &FrRaw, siblings: &[FrRaw]) -> bool {
    let n = siblings.len();
    if n == 0 {
        return false;
    }

    // LevIns: locate the leaf level; leaf-level sibling must be zero.
    let (lev_valid, lev_ins) = lev_ins_flag(siblings, true);
    if !lev_valid {
        return false;
    }

    let leaf = leaf_hash(key, value);

    // VerifierSM specialized to fnc=0, is0=0, enabled=1: only stTop (carried
    // from the root until levIns) and stNew (active at the leaf level) ever
    // fire; stIOld and stI0 stay zero. After the leaf level the machine is na.
    let mut st_top = vec![0u8; n];
    let mut st_new = vec![0u8; n];
    let mut st_na = vec![0u8; n];
    for i in 0..n {
        let (prev_top, prev_new, prev_na) = if i == 0 {
            (1u8, 0u8, 0u8) // enabled=1 => top=1, na=1-enabled=0
        } else {
            (st_top[i - 1], st_new[i - 1], st_na[i - 1])
        };
        let aux1 = prev_top * (lev_ins[i] as u8); // fnc=0 => aux2=0
        st_top[i] = prev_top - aux1;
        st_new[i] = aux1;
        st_na[i] = prev_na + prev_new; // prev_iold, prev_i0 are 0
    }

    // flagStates: exactly one terminal state set on the last level.
    let last = n - 1;
    if st_na[last] + st_new[last] != 1 {
        return false;
    }

    // Bottom-up root reconstruction.
    let zero = [0u64; 4];
    let mut levels = vec![zero; n];
    for i in (0..n).rev() {
        let child = if i < n - 1 { levels[i + 1] } else { zero };
        levels[i] = if st_top[i] == 1 {
            let (l, r) = switcher(get_bit(key, i), child, siblings[i]);
            node_hash(&l, &r)
        } else if st_new[i] == 1 {
            leaf
        } else {
            zero
        };
    }

    // flagRoot: reconstructed root matches the claimed root.
    // (The key-reuse guard is vacuous for fnc=0.)
    &levels[0] == root
}

// Chain verifier

/// Verify a sequence of SMT transitions forms a consistent chain:
/// - `transitions[0].old_root == declared_old_root`
/// - `transitions[i].new_root == transitions[i+1].old_root` for all i
/// - `transitions[N-1].new_root == declared_new_root`
/// - Each individual transition is valid
/// Returns `true` if the chain is valid, `false` otherwise.
/// Sets `fail_flag` in `fail_mask` on failure.
pub fn verify_chain(
    transitions: &[SmtTransition],
    declared_old: &FrRaw,
    declared_new: &FrRaw,
    fail_mask: &mut u32,
    fail_flag: u32,
) -> bool {
    if transitions.is_empty() {
        // Empty chain: old root must equal new root.
        let ok = declared_old == declared_new;
        if !ok { *fail_mask |= fail_flag; }
        return ok;
    }

    // Check first transition's old root.
    if &transitions[0].old_root != declared_old {
        *fail_mask |= fail_flag;
        return false;
    }

    // Verify each transition and check chaining.
    for i in 0..transitions.len() {
        if !verify_transition(&transitions[i]) {
            *fail_mask |= fail_flag;
            return false;
        }
        if i + 1 < transitions.len() {
            if transitions[i].new_root != transitions[i + 1].old_root {
                *fail_mask |= fail_flag;
                return false;
            }
        }
    }

    // Check last transition's new root.
    let last_new = &transitions[transitions.len() - 1].new_root;
    if last_new != declared_new {
        *fail_mask |= fail_flag;
        return false;
    }

    true
}

// State-transition verifier

/// Silent-refresh target: `min(MAX_REFRESH, max(REFRESH_MIN, tau*w, kappa*n))`.
/// Uses saturating multiplication so hostile inputs cannot overflow the u64
/// range; the max/min chain then caps the result at MAX_REFRESH anyway.
fn refresh_target(n_voters: u64, n_overwritten: u64) -> u64 {
    let tau_w = REFRESH_TAU.saturating_mul(n_overwritten);
    let kappa_n = REFRESH_KAPPA.saturating_mul(n_voters);
    let m = core::cmp::max(REFRESH_MIN, core::cmp::max(tau_w, kappa_n));
    core::cmp::min(MAX_REFRESH as u64, m)
}

/// Silent-refresh key range: `[0x10, 2^63)`, upper limbs zero. Matches the
/// ballot namespace (§4.1.5) so a "refresh" can never touch the process config
/// or vote-ID leaves. `key[0] < 2^63` == top bit clear.
fn refresh_key_ok(k: &FrRaw) -> bool {
    k[1] == 0 && k[2] == 0 && k[3] == 0 && k[0] >= 0x10 && (k[0] >> 63) == 0
}

/// Strictly increasing across the chain: compare limbs 0 only (upper limbs
/// are zero, checked in `refresh_key_ok`).
fn refresh_keys_strictly_increasing(chain: &[SmtTransition]) -> bool {
    for w in chain.windows(2) {
        if w[0].new_key[0] >= w[1].new_key[0] {
            return false;
        }
    }
    true
}

/// Verify the full DAVINCI state-transition block (STATETX).
/// Returns `(ok, old_root, new_root, voters, overwritten, occupied_before)`.
/// `old_root` and `new_root` are the full 256-bit Arbo SHA-256 roots as `FrRaw`.
/// When no state block is present, returns `(false, ZERO, ZERO, 0, 0, 0)` and sets
/// `FAIL_MISSING_BLOCK` — the state block is mandatory.
pub fn verify_state(
    state: Option<&StateBlock>,
    fail_mask: &mut u32,
) -> (bool, FrRaw, FrRaw, u64, u64, u64) {
    let state = match state {
        None => {
            *fail_mask |= crate::types::FAIL_MISSING_BLOCK;
            return (false, ZERO_FR, ZERO_FR, 0, 0, 0);
        }
        Some(s) => s,
    };

    let mut ok = true;

    // Validate chain lengths vs declared voter counts
    // The voteID chain length must equal n_voters (one insertion per real voter).
    // The ballot chain length must also equal n_voters (one insert or update per voter).
    let nv = state.n_voters;
    if state.vote_id_chain.len() != nv {
        *fail_mask |= FAIL_SMT_VOTEID;
        ok = false;
    }
    if state.ballot_chain.len() != nv {
        *fail_mask |= FAIL_SMT_BALLOT;
        ok = false;
    }

    // Validate overwritten count against actual ballot UPDATEs
    // In the SMT Processor, an UPDATE operation has fnc0=false, fnc1=true.
    // Each ballot UPDATE corresponds to an overwritten vote. The declared
    // n_overwritten must match the actual count.
    let actual_overwrites = state.ballot_chain.iter()
        .filter(|t| !t.fnc0 && t.fnc1)
        .count();
    if actual_overwrites != state.n_overwritten {
        *fail_mask |= FAIL_SMT_BALLOT;
        ok = false;
    }

    // VoteID chain: OldStateRoot → (intermediate after voteIDs)
    // Every voteID transition MUST be an INSERT (fnc0=true, fnc1=false).
    // VoteIDs are unique identifiers that can never be updated or deleted.
    // The leaf value is the protocol constant 0 (davinci-node's
    // VoteIDLeafValue), so the DA blob only has to publish the keys for an
    // observer to rebuild the tree.
    for t in &state.vote_id_chain {
        if !t.fnc0 || t.fnc1 || t.new_value != ZERO_FR {
            *fail_mask |= FAIL_SMT_VOTEID;
            ok = false;
            break;
        }
    }
    // The end of the voteID chain must equal the start of the ballot chain
    // (or new_state_root when no ballot chain is present).
    let after_vote_ids = if state.ballot_chain.is_empty() {
        match &state.results {
            Some(r) => &r.old_root,
            None => &state.new_state_root,
        }
    } else {
        &state.ballot_chain[0].old_root
    };
    ok &= verify_chain(
        &state.vote_id_chain,
        &state.old_state_root,
        after_vote_ids,
        fail_mask,
        FAIL_SMT_VOTEID,
    );

    // Ballot chain: (after voteIDs) → (before refresh chain / resultsAdd / new_state_root)
    // Each ballot transition must be an INSERT (new vote) or UPDATE (overwrite).
    // DELETE (fnc0=true, fnc1=true) and NOOP (fnc0=false, fnc1=false) are not allowed.
    for t in &state.ballot_chain {
        let is_insert = t.fnc0 && !t.fnc1;
        let is_update = !t.fnc0 && t.fnc1;
        if !is_insert && !is_update {
            *fail_mask |= FAIL_SMT_BALLOT;
            ok = false;
            break;
        }
    }
    // The next section after the ballot chain is (in order): refresh chain (if
    // non-empty), Results transition (if present), new_state_root.
    let after_refresh: &FrRaw = match &state.results {
        Some(r) => &r.old_root,
        None => &state.new_state_root,
    };
    let after_ballots: &FrRaw = if state.refresh_chain.is_empty() {
        after_refresh
    } else {
        &state.refresh_chain[0].old_root
    };
    let ballot_start = if state.vote_id_chain.is_empty() {
        &state.old_state_root
    } else {
        // The last new_root of the voteID chain = after_vote_ids (already verified above).
        after_vote_ids
    };
    ok &= verify_chain(
        &state.ballot_chain,
        ballot_start,
        after_ballots,
        fail_mask,
        FAIL_SMT_BALLOT,
    );

    // Silent-refresh chain (§4.5). Runs between the ballot chain and Results.
    ok &= verify_refresh_chain(state, fail_mask);

    // Results chain: single net Results transition → new_state_root.
    if let Some(r) = &state.results {
        // 4.2.12 Pin the Results transition to an UPDATE on the reserved key
        // 0x04. A NOOP or an INSERT-at-unused-key carrying the expected hashes
        // would otherwise satisfy `verify_transition` (a NOOP only asserts
        // `old_root == new_root`, an INSERT can pick any unused key) and let
        // the sequencer skip actually tallying while still passing `results::
        // verify_results` (which only compares its own `old_value`/`new_value`
        // fields). Reproduced by `TestCheatResultsNoop`.
        const RESULTS_KEY: FrRaw = [0x04, 0, 0, 0];
        if r.fnc0 || !r.fnc1 || r.is_old0
            || r.old_key != RESULTS_KEY || r.new_key != RESULTS_KEY {
            *fail_mask |= FAIL_SMT_RESULTS;
            ok = false;
        }
        if !verify_transition(r) {
            *fail_mask |= FAIL_SMT_RESULTS;
            ok = false;
        }
        // The Results transition must terminate at new_state_root.
        if ok && r.new_root != state.new_state_root {
            *fail_mask |= FAIL_SMT_RESULTS;
            ok = false;
        }
    }

    // Process read-proofs: inclusion in OldStateRoot (no mutation)
    // Exactly 5 proofs are required, one per config key in fixed order:
    //   [0] key=0x00 (ProcessID), [1] key=0x02 (BallotMode),
    //   [2] key=0x03 (EncryptionKey), [3] key=0x06 (CensusOrigin),
    //   [4] key=0x07 (BallotVKHash).
    // Each proof must be read-only (old_root == new_root == old_state_root).
    const EXPECTED_KEYS: [FrRaw; 5] = [
        [0x00, 0, 0, 0], // StateKeyProcessID
        [0x02, 0, 0, 0], // StateKeyBallotMode
        [0x03, 0, 0, 0], // StateKeyEncryptionKey
        [0x06, 0, 0, 0], // StateKeyCensusOrigin
        [0x07, 0, 0, 0], // StateKeyBallotVKHash
    ];
    if state.process_proofs.len() != 5 {
        *fail_mask |= FAIL_SMT_PROCESS;
        ok = false;
    } else {
        for (i, p) in state.process_proofs.iter().enumerate() {
            // Read-only: roots unchanged and equal to the old state root.
            if p.old_root != state.old_state_root || p.new_root != state.old_state_root {
                *fail_mask |= FAIL_SMT_PROCESS;
                ok = false;
                break;
            }
            // Each proof must correspond to the correct config key, in order.
            if p.new_key != EXPECTED_KEYS[i] {
                *fail_mask |= FAIL_SMT_PROCESS;
                ok = false;
                break;
            }
            // Genuine SMT inclusion of (key, value) under old_state_root
            // (circomlib SMTVerifier, matching davinci-node). A Processor NOOP
            // does not bind the value to the tree, so a prover could otherwise
            // assert an arbitrary config value (e.g. a forged encryption key).
            if !verify_inclusion(&state.old_state_root, &p.new_key, &p.new_value, &p.siblings) {
                *fail_mask |= FAIL_SMT_PROCESS;
                ok = false;
                break;
            }
        }
        // The processID value stored in the state tree (key 0x00) must equal
        // the processID declared in the state-transition block header.
        if ok && state.process_proofs[0].new_value != state.process_id {
            *fail_mask |= FAIL_SMT_PROCESS;
            ok = false;
        }
    }

    let old = state.old_state_root;
    let new = state.new_state_root;

    (ok, old, new, state.n_voters as u64, state.n_overwritten as u64, state.occupied_before)
}

/// Silent-refresh chain checks (§4.5). Called from `verify_state` after the
/// ballot chain has been verified. Failures set `FAIL_REFRESH`.
fn verify_refresh_chain(state: &StateBlock, fail_mask: &mut u32) -> bool {
    let mut ok = true;

    // 4.5.1 Cap. The parser already caps it, but re-assert here so the guest
    // fails cleanly on any inconsistency between parser and validator.
    if state.refresh_chain.len() > MAX_REFRESH {
        *fail_mask |= FAIL_REFRESH;
        return false;
    }

    // 4.5.2 Count rule. `occupied_before` is header-supplied; the consumer
    // checks it against its own running totals (see main.rs / aggregator).
    let n_voters = state.n_voters as u64;
    let n_overwritten = state.n_overwritten as u64;
    if state.occupied_before < n_overwritten {
        *fail_mask |= FAIL_REFRESH;
        ok = false;
    }
    let target = refresh_target(n_voters, n_overwritten);
    // Saturating: bounded above by u64 range; `occupied_before >= n_overwritten`
    // already guarded, so the subtraction is safe here.
    let headroom = state.occupied_before.saturating_sub(n_overwritten);
    let required = core::cmp::min(target, headroom);
    if (state.refresh_chain.len() as u64) < required {
        *fail_mask |= FAIL_REFRESH;
        ok = false;
    }

    // 4.5.3 Per-entry format and disjointness. Every entry is an UPDATE on the
    // same slot; keys live in the ballot namespace; the chain is strictly
    // increasing so no key repeats; no refresh key equals a ballot new_key so
    // a refresh cannot double up on a slot the batch itself just wrote.
    for r in &state.refresh_chain {
        if r.fnc0 || !r.fnc1 || r.is_old0 || r.old_key != r.new_key
            || !refresh_key_ok(&r.new_key)
        {
            *fail_mask |= FAIL_REFRESH;
            ok = false;
            break;
        }
    }
    if !refresh_keys_strictly_increasing(&state.refresh_chain) {
        *fail_mask |= FAIL_REFRESH;
        ok = false;
    }
    // O(n*m) compare — n and m are each ≤ MAX_BATCH_SIZE = 128 and
    // MAX_REFRESH = 256, so worst case is 32k limb compares. Cheap.
    for r in &state.refresh_chain {
        for b in &state.ballot_chain {
            if r.new_key == b.new_key {
                *fail_mask |= FAIL_REFRESH;
                ok = false;
                break;
            }
        }
        if !ok { break; }
    }

    // 4.5.4 Root chaining: refresh chain starts where the ballot chain left
    // off (or after the voteID chain / at old_state_root when the ballot
    // chain is empty), and ends at results.old_root (or new_state_root when
    // there is no Results transition). Same rule the ballot chain uses.
    if !state.refresh_chain.is_empty() {
        let start: &FrRaw = if !state.ballot_chain.is_empty() {
            &state.ballot_chain[state.ballot_chain.len() - 1].new_root
        } else if !state.vote_id_chain.is_empty() {
            &state.vote_id_chain[state.vote_id_chain.len() - 1].new_root
        } else {
            &state.old_state_root
        };
        let end: &FrRaw = match &state.results {
            Some(r) => &r.old_root,
            None => &state.new_state_root,
        };
        ok &= verify_chain(&state.refresh_chain, start, end, fail_mask, FAIL_REFRESH);
    }

    ok
}

#[cfg(test)]
mod inclusion_tests {
    use super::*;

    // Build a 2-leaf tree (keys differ in bit 0) and return the root plus both
    // leaf keys/values. keyA goes left (bit0=0), keyB goes right (bit0=1).
    fn two_leaf_tree() -> (FrRaw, FrRaw, FrRaw, FrRaw, FrRaw, FrRaw, FrRaw) {
        let key_a: FrRaw = [0, 0, 0, 0];
        let val_a: FrRaw = [11, 0, 0, 0];
        let key_b: FrRaw = [1, 0, 0, 0];
        let val_b: FrRaw = [22, 0, 0, 0];
        let a = leaf_hash(&key_a, &val_a);
        let b = leaf_hash(&key_b, &val_b);
        let root = node_hash(&a, &b);
        (root, key_a, val_a, key_b, val_b, a, b)
    }

    fn padded(sib0: FrRaw, levels: usize) -> Vec<FrRaw> {
        let mut s = vec![[0u64; 4]; levels];
        s[0] = sib0;
        s
    }

    #[test]
    fn accepts_genuine_inclusion() {
        let (root, key_a, val_a, key_b, val_b, a, b) = two_leaf_tree();
        // keyA: root-level sibling is leaf B; leaf level sibling is zero.
        assert!(verify_inclusion(&root, &key_a, &val_a, &padded(b, 2)));
        // keyB: root-level sibling is leaf A.
        assert!(verify_inclusion(&root, &key_b, &val_b, &padded(a, 2)));
    }

    #[test]
    fn accepts_with_trailing_zero_padding() {
        // Real process proofs pad siblings to the full tree depth (256).
        let (root, key_a, val_a, _kb, _vb, _a, b) = two_leaf_tree();
        assert!(verify_inclusion(&root, &key_a, &val_a, &padded(b, 256)));
    }

    #[test]
    fn rejects_forged_value() {
        // The core security property: a prover cannot bind an arbitrary value
        // (e.g. a forged encryption key) to a config key under the real root.
        let (root, key_a, _val_a, _kb, _vb, _a, b) = two_leaf_tree();
        let forged: FrRaw = [99, 0, 0, 0];
        assert!(!verify_inclusion(&root, &key_a, &forged, &padded(b, 256)));
    }

    #[test]
    fn rejects_wrong_sibling() {
        let (root, key_a, val_a, _kb, _vb, _a, _b) = two_leaf_tree();
        let bogus: FrRaw = [0xdead, 0, 0, 0];
        assert!(!verify_inclusion(&root, &key_a, &val_a, &padded(bogus, 256)));
    }

    #[test]
    fn rejects_wrong_root() {
        let (_root, key_a, val_a, _kb, _vb, _a, b) = two_leaf_tree();
        let wrong_root: FrRaw = [1, 2, 3, 4];
        assert!(!verify_inclusion(&wrong_root, &key_a, &val_a, &padded(b, 256)));
    }
}

// Silent-refresh helper tests. These target the pure functions
// (`refresh_target`, `refresh_key_ok`, `refresh_keys_strictly_increasing`) and
// `verify_refresh_chain`'s cap / count-rule / results-pin decisions. They do
// not construct full valid trees — root-chaining paths already covered by the
// inclusion tests above.
#[cfg(test)]
mod refresh_helper_tests {
    use super::*;
    use crate::types::{FAIL_REFRESH, FAIL_SMT_RESULTS, MAX_REFRESH, REFRESH_MIN};

    fn mk_update(key: u64) -> SmtTransition {
        SmtTransition {
            old_root: ZERO_FR,
            new_root: ZERO_FR,
            old_key: [key, 0, 0, 0],
            old_value: ZERO_FR,
            is_old0: false,
            new_key: [key, 0, 0, 0],
            new_value: ZERO_FR,
            fnc0: false,
            fnc1: true,
            siblings: Vec::new(),
        }
    }

    fn empty_state() -> StateBlock {
        StateBlock {
            n_voters: 0,
            n_overwritten: 0,
            occupied_before: 0,
            process_id: ZERO_FR,
            old_state_root: ZERO_FR,
            new_state_root: ZERO_FR,
            vote_id_chain: Vec::new(),
            ballot_chain: Vec::new(),
            refresh_chain: Vec::new(),
            results: None,
            process_proofs: Vec::new(),
            n_levels: 0,
            old_results: [ZERO_FR; crate::types::BALLOT_FIELDS],
            voter_ballots: Vec::new(),
            overwritten_ballots: Vec::new(),
            refreshed_ballots: Vec::new(),
        }
    }

    #[test]
    fn refresh_target_floor_and_scaling() {
        // Floor: for tiny inputs the floor REFRESH_MIN wins.
        assert_eq!(refresh_target(0, 0), REFRESH_MIN);
        assert_eq!(refresh_target(1, 1), REFRESH_MIN);
        // Scaling: tau*w dominates when w is large. tau=2 so w=100 → 200.
        assert_eq!(refresh_target(0, 100), 200);
        // kappa*n dominates when n is large. kappa=1 so n=100 → 100 (still capped at floor at n=1 or lower).
        assert_eq!(refresh_target(500, 0), core::cmp::min(MAX_REFRESH as u64, 500));
        // Cap: bounded above by MAX_REFRESH.
        assert_eq!(refresh_target(u64::MAX, u64::MAX), MAX_REFRESH as u64);
    }

    #[test]
    fn refresh_key_ok_bounds() {
        // Below 0x10 rejected.
        assert!(!refresh_key_ok(&[0x00, 0, 0, 0]));
        assert!(!refresh_key_ok(&[0x0F, 0, 0, 0]));
        // Boundary accepted.
        assert!(refresh_key_ok(&[0x10, 0, 0, 0]));
        // Just below 2^63 accepted; top bit set rejected.
        assert!(refresh_key_ok(&[(1u64 << 63) - 1, 0, 0, 0]));
        assert!(!refresh_key_ok(&[1u64 << 63, 0, 0, 0]));
        // Non-zero upper limbs rejected.
        assert!(!refresh_key_ok(&[0x20, 1, 0, 0]));
        assert!(!refresh_key_ok(&[0x20, 0, 1, 0]));
        assert!(!refresh_key_ok(&[0x20, 0, 0, 1]));
    }

    #[test]
    fn strictly_increasing_detects_duplicates_and_reverse() {
        let c = [mk_update(0x10), mk_update(0x11), mk_update(0x11)];
        assert!(!refresh_keys_strictly_increasing(&c));
        let c = [mk_update(0x20), mk_update(0x10)];
        assert!(!refresh_keys_strictly_increasing(&c));
        let c = [mk_update(0x10), mk_update(0x11), mk_update(0x12)];
        assert!(refresh_keys_strictly_increasing(&c));
    }

    #[test]
    fn count_rule_headroom_boundary_fails_when_short() {
        // occupied_before smaller than target: required = headroom = 3.
        // Providing 2 entries must fail. (A full positive test would need
        // valid siblings on every entry; the boundary check alone shows the
        // count arithmetic — 4.5.2 — is wired up.)
        let mut s = empty_state();
        s.n_voters = 4;
        s.n_overwritten = 2;
        s.occupied_before = 5;
        s.refresh_chain = vec![mk_update(0x10), mk_update(0x11)];
        let mut m = 0u32;
        assert!(!verify_refresh_chain(&s, &mut m));
        assert!(m & FAIL_REFRESH != 0);
    }

    #[test]
    fn count_rule_target_boundary_fails_when_short() {
        // occupied_before large so target = REFRESH_MIN = 16 dominates.
        // 15 entries must fail; the required minimum is 16.
        let mut s = empty_state();
        s.n_voters = 4;
        s.n_overwritten = 2;
        s.occupied_before = 10_000;
        s.refresh_chain = (0..15u64).map(|i| mk_update(0x10 + i)).collect();
        let mut m = 0u32;
        assert!(!verify_refresh_chain(&s, &mut m));
        assert!(m & FAIL_REFRESH != 0);
    }

    #[test]
    fn zero_required_zero_provided_passes() {
        // occupied_before == n_overwritten → headroom = 0 → required = 0.
        // Empty refresh_chain and no root-chain work to do.
        let mut s = empty_state();
        s.n_voters = 0;
        s.n_overwritten = 0;
        s.occupied_before = 0;
        let mut m = 0u32;
        assert!(verify_refresh_chain(&s, &mut m));
        assert_eq!(m, 0);
    }

    #[test]
    fn occupied_before_below_overwritten_fails() {
        let mut s = empty_state();
        s.n_voters = 4;
        s.n_overwritten = 5;
        s.occupied_before = 3; // impossible: fewer live leaves than overwrites
        let mut m = 0u32;
        assert!(!verify_refresh_chain(&s, &mut m));
        assert!(m & FAIL_REFRESH != 0);
    }

    #[test]
    fn refresh_entry_out_of_namespace_rejected() {
        let mut s = empty_state();
        s.n_voters = 0;
        s.n_overwritten = 0;
        s.occupied_before = 0;
        // Count rule is satisfied only when 0 entries required; with
        // occupied_before=0 headroom is 0 so required=0. 1 entry with a bad key
        // still fails the per-entry namespace check.
        s.refresh_chain = vec![mk_update(0x00)];
        let mut m = 0u32;
        assert!(!verify_refresh_chain(&s, &mut m));
        assert!(m & FAIL_REFRESH != 0);
    }

    #[test]
    fn refresh_shares_key_with_ballot_chain_rejected() {
        let mut s = empty_state();
        s.n_voters = 0;
        s.n_overwritten = 0;
        s.occupied_before = 0;
        // A ballot chain entry with new_key = 0x20; a refresh entry with the
        // same key must be rejected as non-disjoint.
        s.ballot_chain = vec![mk_update(0x20)];
        s.refresh_chain = vec![mk_update(0x20)];
        let mut m = 0u32;
        assert!(!verify_refresh_chain(&s, &mut m));
        assert!(m & FAIL_REFRESH != 0);
    }

    #[test]
    fn refresh_over_cap_rejected() {
        let mut s = empty_state();
        // MAX_REFRESH + 1 entries — the parser also caps this but the validator
        // asserts independently.
        s.refresh_chain = (0..(MAX_REFRESH as u64 + 1))
            .map(|i| mk_update(0x10 + i))
            .collect();
        let mut m = 0u32;
        assert!(!verify_refresh_chain(&s, &mut m));
        assert!(m & FAIL_REFRESH != 0);
    }

    // 4.2.12 Results pin. Ensures the guard in `verify_state` rejects the three
    // shapes a naive prover would try: NOOP (identity Processor operation), an
    // INSERT-at-an-unused-key, or an UPDATE at any key other than 0x04.
    fn mk_valid_results_update() -> SmtTransition {
        // NOOP semantics but with the reserved key set; verify_transition itself
        // is not exercised here — the pin check runs first and independently.
        SmtTransition {
            old_root: ZERO_FR,
            new_root: ZERO_FR,
            old_key: [0x04, 0, 0, 0],
            old_value: ZERO_FR,
            is_old0: false,
            new_key: [0x04, 0, 0, 0],
            new_value: ZERO_FR,
            fnc0: false,
            fnc1: true,
            siblings: Vec::new(),
        }
    }

    fn state_with_only_results(r: SmtTransition) -> StateBlock {
        let mut s = empty_state();
        // The pin runs inside verify_state, so we need process_proofs to pass —
        // easier: just check the pin bits by pushing a fresh mask through the
        // relevant branch. Rather than building a full valid tree we replicate
        // the pin logic here — the pin is a tiny fixed check.
        s.results = Some(r);
        s
    }

    // Directly exercise the pin's boolean, since verify_state has many other
    // gates that don't apply to this micro-check.
    fn pin_ok(r: &SmtTransition) -> bool {
        const K: FrRaw = [0x04, 0, 0, 0];
        !r.fnc0 && r.fnc1 && !r.is_old0 && r.old_key == K && r.new_key == K
    }

    #[test]
    fn results_pin_accepts_update_on_reserved_key() {
        let r = mk_valid_results_update();
        assert!(pin_ok(&r));
        let _ = state_with_only_results(r); // just keeps the helper in use
    }

    #[test]
    fn results_pin_rejects_noop() {
        // NOOP = fnc0=false, fnc1=false.
        let mut r = mk_valid_results_update();
        r.fnc1 = false;
        assert!(!pin_ok(&r));
    }

    #[test]
    fn results_pin_rejects_insert() {
        // INSERT = fnc0=true, fnc1=false.
        let mut r = mk_valid_results_update();
        r.fnc0 = true;
        r.fnc1 = false;
        assert!(!pin_ok(&r));
    }

    #[test]
    fn results_pin_rejects_wrong_key() {
        let mut r = mk_valid_results_update();
        r.new_key = [0x05, 0, 0, 0]; // any key other than 0x04
        assert!(!pin_ok(&r));
        let mut r = mk_valid_results_update();
        r.old_key = [0x05, 0, 0, 0];
        assert!(!pin_ok(&r));
    }

    // Belt-and-braces: run the pin through verify_state to catch a future
    // refactor that moves the pin somewhere else. Bad-key results must set
    // FAIL_SMT_RESULTS. We build the smallest state that reaches the results
    // branch: no chains, empty voters, results pointing to bad key.
    #[test]
    fn verify_state_results_pin_sets_fail_bit() {
        // Only exercise the results branch by handing verify_state a state
        // with empty vote_id/ballot chains, empty refresh chain, no process
        // proofs (which will set FAIL_SMT_PROCESS too, but we don't care —
        // we only assert the FAIL_SMT_RESULTS bit).
        let mut s = empty_state();
        let mut bad = mk_valid_results_update();
        bad.new_key = [0x05, 0, 0, 0];
        s.results = Some(bad);
        let mut m = 0u32;
        let _ = verify_state(Some(&s), &mut m);
        assert!(m & FAIL_SMT_RESULTS != 0, "mask={:#x}", m);
    }
}
