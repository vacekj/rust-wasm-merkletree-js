use js_sys::{Array, JsString};
use rand::Rng;
use rs_merkle;
use rs_merkle::algorithms::Sha256;
use rs_merkle::{Hasher, MerkleProof, MerkleTree};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn generate_proof(i: Array) -> bool {
    let input: [String; 40_000] = i;
    let leaves: Vec<[u8; 32]> = input.iter().map(|x| Sha256::hash(x.as_bytes())).collect();

    let merkle_tree = MerkleTree::<Sha256>::from_leaves(&leaves);
    let indices_to_prove = vec![3, 4];
    let leaves_to_prove = leaves.get(3..5).ok_or("can't get leaves to prove").unwrap();
    let merkle_proof = merkle_tree.proof(&indices_to_prove);
    let merkle_root = merkle_tree
        .root()
        .ok_or("couldn't get the merkle root")
        .unwrap();
    // Serialize proof to pass it to the client
    let proof_bytes = merkle_proof.to_bytes();

    // Parse proof back on the client
    let proof = MerkleProof::<Sha256>::try_from(proof_bytes).unwrap();

    assert!(proof.verify(
        merkle_root,
        &indices_to_prove,
        leaves_to_prove,
        leaves.len()
    ));

    true
    // let example: Example = serde_wasm_bindgen::from_value(input).unwrap();
    // let leaves = example
    //     .field1
    //     .into_iter()
    //     .map(|x| Sha256::hash(x.as_bytes()))
    //     .collect();
    // let merkle_tree = MerkleTree::<Sha256>::from_leaves(leaves);
    //
    // /* Pick a random address and prove its membership */
    //
    // let indice = rand::thread_rng().gen_range(0..leaves.len());
    // let address_to_prove = leaves.get(indice).unwrap();
    //
    // let merkle_proof = merkle_tree.proof(&[indice]);
    // let merkle_root = merkle_tree.root().unwrap();
    //
    // // Serialize proof to pass it to the client
    // let proof_bytes = merkle_proof.to_bytes();
    //
    // // Parse proof back on the client
    // let proof = MerkleProof::<Sha256>::try_from(proof_bytes).unwrap();
    //
    // proof.verify(merkle_root, &[indice], &[*address_to_prove], leaves.len())
}
