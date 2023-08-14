use ark_bn254::{Bn254, Fr};
use ark_circom::CircomReduction;
use ark_groth16::{prepare_verifying_key, Groth16, Proof, ProvingKey};
use ark_relations::r1cs::SynthesisError;

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

// couldnt get this to work yet
// pub fn prove(circuit: CircomCircuit<Bn254>, pkey: &ProvingKey<Bn254>) -> Proof<Bn254> {
//     let mut rng = thread_rng();
//     // let public_inputs = circuit.get_public_inputs().unwrap();
//     let proof = Groth16::<Bn254, CircomReduction>::create_random_proof_with_reduction(
//         circuit, pkey, &mut rng,
//     )
//     .unwrap();

//     proof
// }
