use std::str::FromStr;

use ripemd::{Digest, Ripemd160};
// use std::string::FromUtf8Error;

use serde::Serialize;

use ff::{hex::ToHex, PrimeField};
use num_bigint::{BigInt, BigUint};
use poseidon_rs::{Fr, Poseidon};

/// Compute a key from a given preimage.
///
/// The return string is an hexadecimal with `0x` prefix and
/// does not have prepended zeros.
pub fn compute_key(preimage: BigUint) -> String {
    // bigint to field element
    let felt = Fr::from_str(preimage.to_string().as_str()).unwrap();

    let trimmed_digest = Poseidon::new()
        .hash(vec![felt])
        .unwrap()
        .to_string()
        .replace("Fr(0x", "")
        .trim_start_matches('0')
        .trim_end_matches(')')
        .to_string();

    "0x".to_string() + &trimmed_digest
}

/// Given any input, hash it to a circuit-friendly value.
pub fn hash_to_group<T: Serialize>(input: &T) -> BigUint {
    // TODO: handle this error too
    let stringified = serde_json::to_string(input).unwrap();

    let mut hasher = Ripemd160::new();
    hasher.update(stringified.as_bytes());
    let digest = hasher.finalize();

    BigUint::from_bytes_be(&digest)
}

#[cfg(test)]
mod tests {
    use ark_bn254::Fr;

    use super::*;
    #[allow(dead_code)]
    #[allow(unused_imports)]
    use std::{fs::File, io::BufReader, str::FromStr};

    #[test]
    fn test_hash_to_group() {
        // #[derive(Serialize)]
        // struct Address {
        //     street: String,
        //     city: String,
        // }

        // let address = Address {
        //     street: "10 Downing Street".to_owned(),
        //     city: "London".to_owned(),
        // };

        let result = hash_to_group(&"hi there".to_string());
        println!("RESULT {:?}", result);
    }

    #[test]
    fn test_compute_key() {
        let preimage = Fr::from_str("123456789").unwrap();
        let expected = "0xfb849f7cf35865c838cef48782e803b2c38263e2f467799c87eff168eb4d897";

        let result = compute_key(BigUint::from(preimage));

        assert_eq!(expected, result.as_str());
    }
}
