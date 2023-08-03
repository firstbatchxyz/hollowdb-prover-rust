#[allow(dead_code)]
#[allow(unused_imports)]
use std::{fs::File, io::BufReader, str::FromStr};

use ark_bn254::Bn254;
use ark_circom::{read_zkey, CircomBuilder, CircomCircuit, CircomConfig, CircomReduction};
use ark_groth16::{prepare_verifying_key, Groth16, ProvingKey};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_std::rand::thread_rng;
use num_bigint::BigInt;

type GrothBn254 = Groth16<Bn254, CircomReduction>;

pub mod prover;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prover;

    #[test]
    fn test_zk() {
        // load files
        let cfg = prover::load_circom_config("./circuits/circuit.wasm", "./circuits/circuit.r1cs");
        let prover_key = prover::load_prover_key("./circuits/proverkey.zkey");
        let verifier_key = &prover_key.vk; // TODO: can this be imported without prover key?

        // compute witness (also checks constraints)
        let circom = prover::compute_witness(
            cfg,
            "901231230202",
            "3279874327432432781189",
            "9811872342347234789723",
        );

        // generate proof
        let mut rng = thread_rng();
        let public_inputs = circom.get_public_inputs().unwrap();
        let proof =
            GrothBn254::create_random_proof_with_reduction(circom, &prover_key, &mut rng).unwrap();

        // verify proof
        let prepped_verifier_key = prepare_verifying_key(verifier_key);
        let verified =
            GrothBn254::verify_proof(&prepped_verifier_key, &proof, &public_inputs).unwrap();

        assert!(verified, "Proof rejected!");
    }
}
