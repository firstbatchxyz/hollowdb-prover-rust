use std::{fs::File, io::BufReader, str::FromStr};

use ark_bn254::Bn254;
use ark_circom::{read_zkey, CircomBuilder, CircomCircuit, CircomConfig, CircomReduction};
use ark_groth16::{Groth16, Proof, ProvingKey};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, Result as ArkResult};
use ark_std::rand::thread_rng;
// use eyre::Result;
use color_eyre::Result as EyreResult;
use num_bigint::BigUint;

/// Loads Circom files from an existing WASM and R1CS.
pub fn load_circom_config(wasm_path: &str, r1cs_path: &str) -> CircomConfig<Bn254> {
    // TODO: handle error
    CircomConfig::<Bn254>::new(wasm_path, r1cs_path).unwrap()
}

/// Loads proving key (which can generate verification key too) from an existing `zKey` file.
pub fn load_prover_key(pkey_path: &str) -> ProvingKey<Bn254> {
    // TODO: handle error
    let f = File::open(pkey_path).unwrap();
    let mut reader = BufReader::new(f);
    // TODO: handle error
    let (params, _) = read_zkey(&mut reader).unwrap();
    params
}

/// Given a config, will provide the inputs and return the circuit.
/// Will panic if the string arguments are not convertable to a BigInt.
pub fn compute_witness(
    cfg: CircomConfig<Bn254>,
    preimage: BigUint,
    cur_value_hash: BigUint,
    next_value_hash: BigUint,
) -> EyreResult<CircomCircuit<Bn254>> {
    let mut builder = CircomBuilder::new(cfg);

    // set inputs
    builder.push_input("preimage", preimage);
    builder.push_input("curValueHash", cur_value_hash);
    builder.push_input("nextValueHash", next_value_hash);

    // compute witness i.e. building circuit with inputs
    let circom = builder.build()?;
    check_constraints(circom.clone());

    Ok(circom)
}
/// Asserts all constraints to pass.
pub fn check_constraints(circuit: CircomCircuit<Bn254>) {
    let cs = ConstraintSystem::<ark_bn254::Fr>::new_ref();
    // TODO: handle error
    circuit.generate_constraints(cs.clone()).unwrap();
    // TODO: handle error
    assert!(cs.is_satisfied().unwrap());
}

/// Creates an empty instance from the given builder & runs a trusted setup to generate keys.
/// Using `load_prover_key` may have a problem with proof verification, so this is just an alternative
/// that is tested to be working correctly.
///
/// https://github.com/arkworks-rs/circom-compat/issues/35 see this for a related issue
pub fn setup_circuit(builder: CircomBuilder<Bn254>) -> ProvingKey<Bn254> {
    let mut rng = thread_rng();
    // TODO: handle error
    Groth16::<Bn254, CircomReduction>::generate_random_parameters_with_reduction(
        builder.setup(),
        &mut rng,
    )
    .unwrap()
}

/// Creates a proof from a circuit with public inputs fed into.
pub fn prove_circuit(
    circuit: CircomCircuit<Bn254>,
    pkey: &ProvingKey<Bn254>,
) -> ArkResult<Proof<Bn254>> {
    let mut rng = thread_rng();
    Groth16::<Bn254, CircomReduction>::create_random_proof_with_reduction(circuit, pkey, &mut rng)
}

#[cfg(test)]
mod tests {
    #[allow(dead_code)]
    #[allow(unused_imports)]
    use std::{fs::File, io::BufReader, str::FromStr};

    use crate::{circom, verifier};
    use num_bigint::BigUint;

    #[test]
    fn test_prove_and_verify() {
        let config =
            circom::load_circom_config("./circuits/circuit.wasm", "./circuits/circuit.r1cs");
        let prover_key = circom::load_prover_key("./circuits/proverkey.zkey");

        // compute witness (also checks constraints)
        let circom = circom::compute_witness(
            config,
            BigUint::from_str("901231230202").unwrap(),
            BigUint::from_str("3279874327432432781189").unwrap(),
            BigUint::from_str("9811872342347234789723").unwrap(),
        )
        .unwrap();

        // generate proof
        let proof = circom::prove_circuit(circom, &prover_key).unwrap();

        // verify proof
        let verified = verifier::verify_proof_with_pkey_and_inputs(
            &proof,
            "4067124373014308708177105322643381071508707955636716225484979994368986851155",
            "3279874327432432781189",
            "9811872342347234789723",
            &prover_key,
        )
        .unwrap();

        assert!(verified, "Proof rejected!");
    }
}
