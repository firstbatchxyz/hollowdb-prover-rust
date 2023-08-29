use crate::{circom, utils::hash_to_group};
use ark_bn254::Bn254;
use ark_circom::CircomConfig;
use ark_groth16::ProvingKey;
use color_eyre::Result;
use num_bigint::BigUint;
use serde::Serialize;

#[derive(Clone, Debug)]
pub struct HollowProver {
    config: CircomConfig<Bn254>,
    prover_key: ProvingKey<Bn254>,
}

impl HollowProver {
    /// Creates a Groth16-based zero-knowledge prover utility to be used with HollowDB.
    ///
    /// You will need to provide paths to a WASM circuit, and a prover key.
    /// You can find these files at: https://github.com/firstbatchxyz/hollowdb-prover-rust/tree/master/circuits
    ///
    /// It is up to you to decide where to place them for your application.
    /// For example, in a web-app you may place under the `public` directory.
    pub fn new(wasm_path: &str, r1cs_path: &str, pkey_path: &str) -> Result<Self> {
        let config = circom::load_circom_config(wasm_path, r1cs_path)?;
        let prover_key = circom::load_prover_key(pkey_path)?;

        Ok(Self { config, prover_key })
    }

    /// Generates a proof, returns `(proof, publicSignals)` in stringified JSON format.
    /// You can verify the resulting proof in SnarkJS.
    ///
    /// Current value and next value can be anything, they will be hashed-to-group
    /// and then `prove_hashed` will be called to generate the actual proof.
    pub fn prove<T: Serialize>(
        &self,
        preimage: BigUint,
        cur_value: T,
        next_value: T,
    ) -> Result<(String, String)> {
        let cur_value_hash = hash_to_group(&cur_value)?;
        let next_value_hash = hash_to_group(&next_value)?;

        self.prove_hashed::<T>(preimage, cur_value_hash, next_value_hash)
    }

    /// Generates a proof, returns `(proof, publicSignals)` in stringified JSON format.
    /// You can verify the resulting proof in SnarkJS.
    ///
    /// Inputs are assumed to be hashed-to-group.
    pub fn prove_hashed<T: Serialize>(
        &self,
        preimage: BigUint,
        cur_value_hash: BigUint,
        next_value_hash: BigUint,
    ) -> Result<(String, String)> {
        let circom = circom::compute_witness(
            self.config.clone(),
            preimage,
            cur_value_hash,
            next_value_hash,
        )?;

        let proof = circom::prove_circuit(circom.clone(), &self.prover_key)?;
        let pubs = circom
            .get_public_inputs()
            .expect("could not read public inputs.");

        Ok((
            circom::export_proof(&proof)?,
            circom::export_public_signals(&pubs)?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::HollowProver;
    use num_bigint::BigUint;
    use serde::Serialize;
    use std::{fs::write, str::FromStr};

    fn export_json(path: &str, data: String) {
        write(path, data).expect("Unable to write file");
    }

    #[test]
    fn test_prover() {
        let prover = HollowProver::new(
            "./circuits/hollow-authz.wasm",
            "./circuits/hollow-authz.r1cs",
            "./circuits/prover-key.zkey",
        )
        .unwrap();

        #[derive(Serialize)]
        struct MyStruct {
            foo: i32,
            bar: bool,
            baz: String,
        }
        let cur_value = MyStruct {
            foo: 123,
            bar: true,
            baz: "zab".to_owned(),
        };
        let next_value = MyStruct {
            foo: 789,
            bar: false,
            baz: "baz".to_owned(),
        };
        let preimage = BigUint::from_str("123456789").unwrap();
        let (proof, public_signals) = prover.prove(preimage, cur_value, next_value).unwrap();

        export_json("./out/proof.json", proof);
        export_json("./out/public.json", public_signals);
    }
}
