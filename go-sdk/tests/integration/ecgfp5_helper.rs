use std::env;
use std::io::{self, Read};

use davinci_stark::poseidon2::{poseidon2_hash, Poseidon2Constants};
use ecgfp5::curve::Point;
use ecgfp5::field::GFp5;
use ecgfp5::scalar::Scalar;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
enum Command {
    HashEncKey { pk_hex: String },
    ReencryptBallot { pk_hex: String, k_hex: String, ballot: BallotJson },
    AddBallots { ballots: Vec<BallotJson> },
    SubBallots { base: BallotJson, subtract: Vec<BallotJson> },
    LeafHash { ballot: BallotJson },
}

#[derive(Serialize, Deserialize, Clone)]
struct CipherJson {
    c1: String,
    c2: String,
}

#[derive(Serialize, Deserialize, Clone)]
struct BallotJson {
    fields: Vec<CipherJson>,
}

#[derive(Serialize)]
struct OutBallot {
    ballot: BallotJson,
}

#[derive(Serialize)]
struct OutHash {
    hash_hex: String,
}

fn decode_point(hex_str: &str) -> Point {
    let bytes = hex::decode(hex_str.trim_start_matches("0x")).unwrap();
    let (w, ok) = GFp5::decode(&bytes);
    assert_eq!(ok, u64::MAX);
    let (p, ok2) = Point::decode(w);
    assert_eq!(ok2, u64::MAX);
    p
}

fn encode_point(p: Point) -> String {
    hex::encode(p.encode().encode())
}

fn hash_enc_key(pk: Point) -> String {
    let digest = Sha256::digest(pk.encode().encode());
    hex::encode(digest)
}

fn ballot_leaf_hash(ballot: &BallotJson) -> String {
    let mut h = Sha256::new();
    for f in &ballot.fields {
        h.update(hex::decode(&f.c1).unwrap());
        h.update(hex::decode(&f.c2).unwrap());
    }
    hex::encode(h.finalize())
}

fn reencrypt_ballot(pk: Point, k_hex: &str, ballot: &BallotJson) -> BallotJson {
    let k_bytes = hex::decode(k_hex.trim_start_matches("0x")).unwrap();
    let seed = Scalar::decode_reduce(&k_bytes);
    let mut seed_felts = Vec::with_capacity(5);
    for limb in seed.0 {
        seed_felts.push(davinci_stark::config::Val::from_u64(limb));
    }
    let k_prime_u64 = poseidon2_hash(&seed_felts, 1, &Poseidon2Constants::new())[0].as_canonical_u64();
    let k_prime = Scalar([k_prime_u64, 0, 0, 0, 0]);
    let delta1 = Point::mulgen(k_prime);
    let delta2 = pk * k_prime;
    let fields = ballot.fields.iter().map(|f| {
        let c1 = decode_point(&f.c1) + delta1;
        let c2 = decode_point(&f.c2) + delta2;
        CipherJson { c1: encode_point(c1), c2: encode_point(c2) }
    }).collect();
    BallotJson { fields }
}

fn add_ballots(ballots: &[BallotJson]) -> BallotJson {
    let mut c1 = [Point::NEUTRAL; 8];
    let mut c2 = [Point::NEUTRAL; 8];
    for ballot in ballots {
        for (i, f) in ballot.fields.iter().enumerate() {
            c1[i] = c1[i] + decode_point(&f.c1);
            c2[i] = c2[i] + decode_point(&f.c2);
        }
    }
    BallotJson { fields: (0..8).map(|i| CipherJson { c1: encode_point(c1[i]), c2: encode_point(c2[i]) }).collect() }
}

fn sub_ballots(base: &BallotJson, subtract: &[BallotJson]) -> BallotJson {
    let mut c1 = [Point::NEUTRAL; 8];
    let mut c2 = [Point::NEUTRAL; 8];
    for (i, f) in base.fields.iter().enumerate() {
        c1[i] = decode_point(&f.c1);
        c2[i] = decode_point(&f.c2);
    }
    for ballot in subtract {
        for (i, f) in ballot.fields.iter().enumerate() {
            c1[i] = c1[i] - decode_point(&f.c1);
            c2[i] = c2[i] - decode_point(&f.c2);
        }
    }
    BallotJson { fields: (0..8).map(|i| CipherJson { c1: encode_point(c1[i]), c2: encode_point(c2[i]) }).collect() }
}

fn main() {
    let mut raw = String::new();
    io::stdin().read_to_string(&mut raw).unwrap();
    let cmd: Command = serde_json::from_str(&raw).unwrap();
    match cmd {
        Command::HashEncKey { pk_hex } => {
            let out = OutHash { hash_hex: hash_enc_key(decode_point(&pk_hex)) };
            println!("{}", serde_json::to_string(&out).unwrap());
        }
        Command::ReencryptBallot { pk_hex, k_hex, ballot } => {
            let out = OutBallot { ballot: reencrypt_ballot(decode_point(&pk_hex), &k_hex, &ballot) };
            println!("{}", serde_json::to_string(&out).unwrap());
        }
        Command::AddBallots { ballots } => {
            let out = OutBallot { ballot: add_ballots(&ballots) };
            println!("{}", serde_json::to_string(&out).unwrap());
        }
        Command::SubBallots { base, subtract } => {
            let out = OutBallot { ballot: sub_ballots(&base, &subtract) };
            println!("{}", serde_json::to_string(&out).unwrap());
        }
        Command::LeafHash { ballot } => {
            let out = OutHash { hash_hex: ballot_leaf_hash(&ballot) };
            println!("{}", serde_json::to_string(&out).unwrap());
        }
    }
}
