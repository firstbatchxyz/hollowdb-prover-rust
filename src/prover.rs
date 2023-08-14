use std::{fs::File, io::BufReader, str::FromStr};

use ark_bn254::Bn254;
use ark_circom::{read_zkey, CircomBuilder, CircomCircuit, CircomConfig, CircomReduction};
use ark_groth16::{Groth16, Proof, ProvingKey};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, Result};
use ark_std::rand::thread_rng;
use num_bigint::BigInt;

/// Loads Circom files from an existing WASM and R1CS.
pub fn load_circom_config(wasm_path: &str, r1cs_path: &str) -> CircomConfig<Bn254> {
    CircomConfig::<Bn254>::new(wasm_path, r1cs_path).unwrap()
}

/// Loads proving key (which can generate verification key too) from an existing `zKey` file.
pub fn load_prover_key(pkey_path: &str) -> ProvingKey<Bn254> {
    let f = File::open(pkey_path).unwrap();
    let mut reader = BufReader::new(f);
    let (params, _) = read_zkey(&mut reader).unwrap();
    params
}

/// Sets circuit input signals via the given CircomBuilder.
/// String arguments should be convertable to a BigInt.
pub fn compute_witness(
    cfg: CircomConfig<Bn254>,
    preimage: &str,
    cur_value_hash: &str,
    next_value_hash: &str,
) -> CircomCircuit<Bn254> {
    let mut builder = CircomBuilder::new(cfg);

    // set inputs
    builder.push_input(
        "preimage",
        BigInt::from(BigInt::from_str(preimage).unwrap()),
    );
    builder.push_input(
        "curValueHash",
        BigInt::from(BigInt::from_str(cur_value_hash).unwrap()),
    );
    builder.push_input(
        "nextValueHash",
        BigInt::from(BigInt::from_str(next_value_hash).unwrap()),
    );

    // compute witness i.e. building circuit with inputs
    let circom = builder.build().unwrap();
    check_constraints(circom.clone());

    circom
}
/// Asserts all constraints to pass.
pub fn check_constraints(circuit: CircomCircuit<Bn254>) {
    let cs = ConstraintSystem::<ark_bn254::Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();
    assert!(cs.is_satisfied().unwrap());
}

/// Creates an empty instance from the given builder & runs a trusted setup to generate keys.
/// Using `load_prover_key` may have a problem with proof verification, so this is just an alternative
/// that is tested to be working correctly.
///
/// https://github.com/arkworks-rs/circom-compat/issues/35 see this for a related issue
pub fn setup_circuit(builder: CircomBuilder<Bn254>) -> ProvingKey<Bn254> {
    let mut rng = thread_rng();
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
) -> Result<Proof<Bn254>> {
    let mut rng = thread_rng();

    Groth16::<Bn254, CircomReduction>::create_random_proof_with_reduction(circuit, pkey, &mut rng)
}
