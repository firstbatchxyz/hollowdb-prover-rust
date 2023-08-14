use std::any::Any;

use num_bigint::BigUint;
use poseidon_rs::{Fr, Poseidon};

/// Compute a key from a given preimage.
pub fn compute_key(preimage: BigUint) {
    let hasher = Poseidon::new();

    // ???
    Fr::from_str(preimage.to_string());
    // Fr::hasher.hash(vec![Fr::from(preimage)]);
    // hasher.hash(inp)
    unimplemented!()
}

/// Given any input, hash it to a circuit-friendly value.
pub fn hash_to_group(input: Box<dyn Any>) {
    unimplemented!()
}
