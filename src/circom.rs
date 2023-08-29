use ark_bn254::{Bn254, Fr};
use ark_circom::{read_zkey, CircomBuilder, CircomCircuit, CircomConfig, CircomReduction};
use ark_groth16::{Groth16, Proof, ProvingKey};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, SynthesisError};
use ark_std::rand::thread_rng;
use color_eyre::Result;
use num_bigint::BigUint;
use serde::Serialize;
use std::{fs::File, io::BufReader};

/// Loads Circom files from an existing WASM and R1CS.
pub fn load_circom_config(wasm_path: &str, r1cs_path: &str) -> Result<CircomConfig<Bn254>> {
    CircomConfig::<Bn254>::new(wasm_path, r1cs_path)
}

/// Loads proving key (which can generate verification key too) from an existing `zKey` file.
pub fn load_prover_key(pkey_path: &str) -> Result<ProvingKey<Bn254>> {
    let f = File::open(pkey_path)?;
    let mut reader = BufReader::new(f);
    let (params, _) = read_zkey(&mut reader)?;

    Ok(params)
}

/// Given a config, will provide the inputs and return the circuit.
/// Will panic if the string arguments are not convertable to a BigInt.
pub fn compute_witness(
    cfg: CircomConfig<Bn254>,
    preimage: BigUint,
    cur_value_hash: BigUint,
    next_value_hash: BigUint,
) -> Result<CircomCircuit<Bn254>> {
    let mut builder = CircomBuilder::new(cfg);
    builder.push_input("preimage", preimage);
    builder.push_input("curValueHash", cur_value_hash);
    builder.push_input("nextValueHash", next_value_hash);

    // compute witness i.e. building circuit with inputs
    let circom = builder.build()?;
    check_constraints(circom.clone())?;

    Ok(circom)
}

/// Asserts all constraints to pass.
pub fn check_constraints(circuit: CircomCircuit<Bn254>) -> Result<(), SynthesisError> {
    let cs = ConstraintSystem::<Fr>::new_ref();

    circuit.generate_constraints(cs.clone())?;
    assert!(cs.is_satisfied()?);

    Ok(())
}

/// Creates an empty instance from the given builder & runs a trusted setup to generate keys.
/// Using `load_prover_key` may have a problem with proof verification, so this is just an alternative
/// that is tested to be working correctly.
///
/// https://github.com/arkworks-rs/circom-compat/issues/35 see this for a related issue
pub fn setup_circuit(builder: CircomBuilder<Bn254>) -> Result<ProvingKey<Bn254>, SynthesisError> {
    let mut rng = thread_rng();

    Groth16::<Bn254, CircomReduction>::generate_random_parameters_with_reduction(
        builder.setup(),
        &mut rng,
    )
}

/// Creates a proof from a circuit with public inputs fed into.
pub fn prove_circuit(
    circuit: CircomCircuit<Bn254>,
    pkey: &ProvingKey<Bn254>,
) -> Result<Proof<Bn254>, SynthesisError> {
    let mut rng = thread_rng();
    Groth16::<Bn254, CircomReduction>::create_random_proof_with_reduction(circuit, pkey, &mut rng)
}

#[derive(Serialize)]
struct SnarkjsProof {
    pi_a: [String; 2],
    pi_b: [[String; 2]; 2],
    pi_c: [String; 2],
    protocol: String,
}

/// Exports proof as a JSON object.
pub fn export_proof(proof: &Proof<Bn254>) -> Result<String, serde_json::Error> {
    let obj = SnarkjsProof {
        pi_a: [proof.a.x.to_string(), proof.a.y.to_string()],
        pi_b: [
            [proof.b.x.c0.to_string(), proof.b.x.c1.to_string()],
            [proof.b.y.c0.to_string(), proof.b.y.c1.to_string()],
        ],
        pi_c: [proof.c.x.to_string(), proof.c.y.to_string()],
        protocol: "groth16".to_string(),
    };

    serde_json::to_string(&obj)
}

/// Exports public signals as a JSON array of string bigints.
pub fn export_public_signals(pubs: &Vec<Fr>) -> Result<String, serde_json::Error> {
    let signal_strings = pubs.iter().map(|s| s.to_string()).collect::<Vec<String>>();

    serde_json::to_string(&signal_strings)
}

#[cfg(test)]
mod tests {
    #[allow(dead_code)]
    #[allow(unused_imports)]
    use std::{fs::File, io::BufReader, str::FromStr};

    use crate::{circom, verifier};
    use ark_bn254::{Bn254, Fr};
    use ark_groth16::Proof;
    use num_bigint::BigUint;

    #[test]
    fn test_prove_and_verify() {
        let config = circom::load_circom_config(
            "./circuits/hollow-authz.wasm",
            "./circuits/hollow-authz.r1cs",
        )
        .unwrap();
        let prover_key = circom::load_prover_key("./circuits/prover-key.zkey").unwrap();

        let circom = circom::compute_witness(
            config,
            BigUint::from_str("123456789").unwrap(),
            BigUint::from_str("1").unwrap(),
            BigUint::from_str("2").unwrap(),
        )
        .unwrap();

        let proof: Proof<Bn254> = circom::prove_circuit(circom.clone(), &prover_key).unwrap();
        let public_signals: Vec<Fr> = circom.get_public_inputs().unwrap();

        println!("Proof:\n{:?}", circom::export_proof(&proof));
        println!(
            "Public Signals:\n{:?}",
            circom::export_public_signals(&public_signals)
        );

        let verified =
            verifier::verify_proof_with_pkey(&proof, &public_signals, &prover_key).unwrap();

        assert!(verified, "Proof rejected!");
    }

    #[test]
    fn test_prove_and_verify_explicit_inputs() {
        let config = circom::load_circom_config(
            "./circuits/hollow-authz.wasm",
            "./circuits/hollow-authz.r1cs",
        )
        .unwrap();
        let prover_key = circom::load_prover_key("./circuits/prover-key.zkey").unwrap();

        // compute witness (also checks constraints)
        let circom = circom::compute_witness(
            config,
            BigUint::from_str("123456789").unwrap(),
            BigUint::from_str("1").unwrap(),
            BigUint::from_str("2").unwrap(),
        )
        .unwrap();

        let proof = circom::prove_circuit(circom, &prover_key).unwrap();

        let verified = verifier::verify_proof_with_pkey_and_inputs(
            &proof,
            "7110303097080024260800444665787206606103183587082596139871399733998958991511",
            "1",
            "2",
            &prover_key,
        )
        .unwrap();

        assert!(verified, "Proof rejected!");
    }
}
