use ark_bn254::{Bn254, Fr};
use ark_circom::CircomReduction;
use ark_groth16::{prepare_verifying_key, Groth16, Proof, ProvingKey};
use ark_relations::r1cs::SynthesisError;
use color_eyre::Result;
use std::str::FromStr;

/// Verify a proof, using a prover key.
///
/// The verification key is derived from the proving key.
pub fn verify_proof_with_pkey(
    proof: &Proof<Bn254>,
    public_inputs: &[Fr],
    proving_key: &ProvingKey<Bn254>,
) -> Result<bool, SynthesisError> {
    Groth16::<Bn254, CircomReduction>::verify_proof(
        &prepare_verifying_key(&proving_key.vk),
        &proof,
        &public_inputs,
    )
}

/// Verify a proof, using a prover key and manually provided public inputs.
///
/// The verification key is derived from the proving key.
pub fn verify_proof_with_pkey_and_inputs(
    proof: &Proof<Bn254>,
    digest: &str,
    cur_value_hash: &str,
    next_value_hash: &str,
    proving_key: &ProvingKey<Bn254>,
) -> Result<bool, SynthesisError> {
    let public_inputs = vec![
        Fr::from_str(cur_value_hash).expect(""),
        Fr::from_str(next_value_hash).expect(""),
        Fr::from_str(digest).expect(""),
    ];

    verify_proof_with_pkey(proof, &public_inputs, proving_key)
}

// TODO: maybe read verification key from file too in the future
// if we really need a Rust verifier
