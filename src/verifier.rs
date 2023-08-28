use ark_bn254::{Bn254, Fr};
use ark_circom::CircomReduction;
use ark_groth16::{prepare_verifying_key, Groth16, Proof, ProvingKey};
use ark_relations::r1cs::SynthesisError;
use std::str::FromStr;

type GrothBn254 = Groth16<Bn254, CircomReduction>;

/// Verify a proof, using a prover key.
///
/// The verification key is derived from the proving key.
pub fn verify_proof_with_pkey(
    proof: &Proof<Bn254>,
    public_inputs: &[Fr],
    proving_key: &ProvingKey<Bn254>,
) -> Result<bool, SynthesisError> {
    let verifier_key = &proving_key.vk;
    GrothBn254::verify_proof(&prepare_verifying_key(verifier_key), &proof, &public_inputs)
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
        Fr::from_str(cur_value_hash).unwrap(),
        Fr::from_str(next_value_hash).unwrap(),
        Fr::from_str(digest).unwrap(),
    ];

    verify_proof_with_pkey(proof, &public_inputs, proving_key)
}
