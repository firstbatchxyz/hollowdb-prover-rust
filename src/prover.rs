use crate::{circom, utils::hash_to_group};
use ark_bn254::{Bn254, Fr};
use ark_circom::CircomConfig;
use ark_groth16::{Proof, ProvingKey};
use num_bigint::BigUint;
use serde::Serialize;
use std::fs::write;
pub struct HollowProver {
    config: CircomConfig<Bn254>,
    prover_key: ProvingKey<Bn254>,
}

impl HollowProver {
    /// Creates a HollowProver with the provided R1CS, WASM circuit and prover key paths.
    pub fn new(wasm_path: &str, r1cs_path: &str, pkey_path: &str) -> Self {
        let config = circom::load_circom_config(wasm_path, r1cs_path);
        let prover_key = circom::load_prover_key(pkey_path);
        Self { config, prover_key }
    }

    pub fn prove<'life, T: Serialize>(
        &self,
        preimage: BigUint,
        cur_value: T,
        next_value: T,
    ) -> (Proof<Bn254>, Vec<Fr>) {
        let cur_value_hash = hash_to_group(&cur_value);
        let next_value_hash = hash_to_group(&next_value);

        let circom = circom::compute_witness(
            self.config.clone(),
            preimage,
            cur_value_hash,
            next_value_hash,
        )
        .unwrap();

        let proof = circom::prove_circuit(circom.clone(), &self.prover_key).unwrap();
        let pubs = circom.get_public_inputs().unwrap();
        (proof, pubs)
    }

    pub fn prove_hashed<T: Serialize>(
        &self,
        preimage: BigUint,
        cur_value_hash: BigUint,
        next_value_hash: BigUint,
    ) -> (Proof<Bn254>, Vec<Fr>) {
        let circom = circom::compute_witness(
            self.config.clone(),
            preimage,
            cur_value_hash,
            next_value_hash,
        )
        .unwrap();

        let proof = circom::prove_circuit(circom.clone(), &self.prover_key).unwrap();
        let pubs = circom.get_public_inputs().unwrap();
        (proof, pubs)
    }

    pub fn export_proof(&self, proof: &Proof<Bn254>) {
        write("./out/proof.json", circom::export_proof(proof)).expect("Unable to write file");
    }

    pub fn export_public_signals(&self, public_signals: &Vec<Fr>) {
        write(
            "./out/public.json",
            circom::export_public_signals(public_signals),
        )
        .expect("Unable to write file");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigUint;
    use serde::Serialize;

    #[allow(unused_imports)]
    use std::{fs::File, io::BufReader, str::FromStr};

    #[test]
    fn test_prover() {
        #[derive(Serialize)]
        struct MyStruct {
            foo: i32,
            bar: bool,
            baz: String,
        }

        let prover = HollowProver::new(
            "./circuits/circuit.wasm",
            "./circuits/circuit.r1cs",
            "./circuits/proverkey.zkey",
        );

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

        let (proof, public_signals) = prover.prove(preimage, cur_value, next_value);

        prover.export_proof(&proof);
        prover.export_public_signals(&public_signals);
    }
}
