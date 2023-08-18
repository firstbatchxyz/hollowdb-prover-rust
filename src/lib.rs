pub mod prover;
pub mod utils;
pub mod verifier;

#[cfg(test)]
mod tests {
    #[allow(dead_code)]
    #[allow(unused_imports)]
    use std::{fs::File, io::BufReader, str::FromStr};

    use crate::{prover, verifier};

    #[test]
    fn test_prove_and_verify() {
        let config =
            prover::load_circom_config("./circuits/circuit.wasm", "./circuits/circuit.r1cs");
        let prover_key = prover::load_prover_key("./circuits/proverkey.zkey");

        // compute witness (also checks constraints)
        let circom = prover::compute_witness(
            config,
            "901231230202",
            "3279874327432432781189",
            "9811872342347234789723",
        )
        .unwrap();
        let public_inputs = circom.get_public_inputs().unwrap();

        // generate proof
        let proof = prover::prove_circuit(circom, &prover_key).unwrap();

        println!("{:?}", public_inputs);

        // verify proof
        let verified =
            verifier::verify_proof_with_pkey(&proof, &public_inputs, &prover_key).unwrap();

        assert!(verified, "Proof rejected!");
    }
}
