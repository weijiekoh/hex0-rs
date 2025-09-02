// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_main]
sp1_zkvm::entrypoint!(main);

use hex0_lib::{hex0, PublicInputs};
use sha2_v0_10_9::{Digest, Sha256};

pub fn main() {
    // Read the inputs to the program
    let inputs = sp1_zkvm::io::read::<PublicInputs>();

    // Compile the hex0 source bytes
    let result = hex0(&inputs.source_bytes);

    // Hash the result
    let mut hasher = Sha256::new();
    hasher.update(&result);
    let hash_array: [u8; 32] = hasher.finalize().into();

    // Assert that the hash of the result matches the expected hash.
    assert_eq!(hash_array, inputs.expected_hash, "Hash mismatch");
}
