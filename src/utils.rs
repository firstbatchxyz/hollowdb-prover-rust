use std::any::Any;

use ff::PrimeField;
use num_bigint::BigUint;
use poseidon_rs::{Fr, Poseidon};

/// Compute a key from a given preimage.
pub fn compute_key<'a>(preimage: BigUint) -> String {
    let s = Fr::from_str(preimage.to_string().as_str()).unwrap();

    let hasher = Poseidon::new();
    let digest = hasher.hash(vec![s]).unwrap();

    digest.to_string()
}

/// Given any input, hash it to a circuit-friendly value.
pub fn hash_to_group(input: Box<dyn Any>) {
    unimplemented!()
}
