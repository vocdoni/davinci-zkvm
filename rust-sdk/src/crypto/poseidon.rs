//! iden3/circomlib Poseidon over BN254 Fr, widths 1..=16 (t = 2..=17). Same
//! algorithm as go-iden3-crypto `poseidon.Hash` and the guest's `poseidon.rs`
//! (optimized constants, initial state 0).

use ark_ff::Field;

use super::field::Fr;
use super::poseidon_constants::{params, N_ROUNDS_F, N_ROUNDS_P};
use crate::Error;

#[inline]
fn exp5(x: Fr) -> Fr {
    let x2 = x.square();
    x2.square() * x
}

fn mix(state: &mut [Fr], m: &[Vec<Fr>]) {
    let t = state.len();
    let mut ns = [Fr::ZERO; 17];
    for (i, n) in ns.iter_mut().enumerate().take(t) {
        for (j, s) in state.iter().enumerate() {
            *n += m[j][i] * s;
        }
    }
    state.copy_from_slice(&ns[..t]);
}

/// Poseidon hash of 1..=16 field elements.
pub fn poseidon(inputs: &[Fr]) -> Result<Fr, Error> {
    let n = inputs.len();
    if n == 0 || n > 16 {
        return Err(Error::Input(format!(
            "poseidon takes 1..=16 inputs, got {n}"
        )));
    }
    let t = n + 1;
    let prm = params()
        .and_then(|p| p.get(t - 2))
        .ok_or_else(|| Error::Input("poseidon constants unavailable".into()))?;
    let rp = N_ROUNDS_P[t - 2];
    let (c, s) = (&prm.c, &prm.s);

    let mut buf = [Fr::ZERO; 17];
    let state = &mut buf[..t];
    state[1..].copy_from_slice(inputs);
    let ark = |state: &mut [Fr], it: usize| {
        for (i, x) in state.iter_mut().enumerate() {
            *x += c[it + i];
        }
    };

    ark(state, 0);
    for i in 0..N_ROUNDS_F / 2 - 1 {
        state.iter_mut().for_each(|x| *x = exp5(*x));
        ark(state, (i + 1) * t);
        mix(state, &prm.m);
    }
    state.iter_mut().for_each(|x| *x = exp5(*x));
    ark(state, (N_ROUNDS_F / 2) * t);
    mix(state, &prm.p);

    for i in 0..rp {
        state[0] = exp5(state[0]) + c[(N_ROUNDS_F / 2 + 1) * t + i];
        let base = (2 * t - 1) * i;
        let mut new0 = Fr::ZERO;
        for (j, x) in state.iter().enumerate() {
            new0 += s[base + j] * x;
        }
        let s0 = state[0];
        for k in 1..t {
            state[k] += s0 * s[base + t + k - 1];
        }
        state[0] = new0;
    }

    for i in 0..N_ROUNDS_F / 2 - 1 {
        state.iter_mut().for_each(|x| *x = exp5(*x));
        ark(state, (N_ROUNDS_F / 2 + 1) * t + rp + i * t);
        mix(state, &prm.m);
    }
    state.iter_mut().for_each(|x| *x = exp5(*x));
    mix(state, &prm.m);
    Ok(state[0])
}

/// davinci `MultiPoseidon`: up to 16 inputs hash directly, more are hashed in
/// chunks of 16 and the chunk digests hashed again (recursively above 256).
pub fn multi_poseidon(inputs: &[Fr]) -> Result<Fr, Error> {
    if inputs.len() <= 16 {
        return poseidon(inputs);
    }
    let chunks = inputs
        .chunks(16)
        .map(poseidon)
        .collect::<Result<Vec<_>, _>>()?;
    multi_poseidon(&chunks)
}
