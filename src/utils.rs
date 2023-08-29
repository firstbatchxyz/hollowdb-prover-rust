use color_eyre::Result;
use ff::PrimeField;
use num_bigint::BigUint;
use poseidon_rs::{Fr, Poseidon};
use ripemd::{Digest, Ripemd160};
use serde::Serialize;

/// Compute a key from a given preimage.
///
/// The return string is an hexadecimal with `0x` prefix and
/// does not have prepended zeros.
pub fn compute_key(preimage: BigUint) -> Result<String, String> {
    let felt =
        Fr::from_str(preimage.to_string().as_str()).expect("Could not convert preimage to bigint.");

    let trimmed_digest = Poseidon::new()
        .hash(vec![felt])?
        .to_string()
        .replace("Fr(0x", "") // remove "Fr(0x" prefix
        .trim_start_matches('0') // remove prepended zeros
        .trim_end_matches(')') // remove last parentheses
        .to_string();

    let key = "0x".to_string() + &trimmed_digest; // add 0x back again

    Ok(key)
}

/// Given any input, hash it to a circuit-friendly value.
///
/// For this, we use Ripemd160 to obtain a 160-bit value.
pub fn hash_to_group<T: Serialize>(input: &T) -> Result<BigUint, serde_json::Error> {
    let stringified = serde_json::to_string(input)?;

    let mut hasher = Ripemd160::new();
    hasher.update(stringified.as_bytes());
    let digest = hasher.finalize();

    Ok(BigUint::from_bytes_be(&digest))
}

#[cfg(test)]
mod tests {
    use ark_bn254::Fr;

    use super::*;
    #[allow(dead_code)]
    #[allow(unused_imports)]
    use std::{fs::File, io::BufReader, str::FromStr};

    #[test]
    fn test_hash_to_group_string() {
        assert_eq!(
            hash_to_group(&"quick brown fox jumpes over the lazy dog".to_string())
                .unwrap()
                .to_string(),
            "1428051172494059108075242303790827279360348377618"
        );

        assert_eq!(
            hash_to_group(&"hi there".to_string()).unwrap().to_string(),
            "225037454736096360469008883958883233963769495287"
        );
    }

    #[test]
    fn test_hash_to_group_struct() {
        #[derive(Serialize)]
        struct MyStruct {
            foo: i32,
            bar: bool,
            baz: String,
        }

        let obj = MyStruct {
            foo: 123,
            bar: true,
            baz: "zab".to_owned(),
        };

        // note that the order of fields is important!
        // foo-bar-baz struct will have a different hash
        // compared to baz-bar-foo, bar-foo-baz etc.
        assert_eq!(
            hash_to_group(&obj).unwrap().to_string(),
            "456108647815456389709004505861143737447371420350"
        );
    }

    #[test]
    fn test_compute_key() {
        let preimage = Fr::from_str("123456789").unwrap();
        let expected = "0xfb849f7cf35865c838cef48782e803b2c38263e2f467799c87eff168eb4d897";

        let result = compute_key(BigUint::from(preimage)).unwrap();

        assert_eq!(expected, result.as_str());
    }
}
