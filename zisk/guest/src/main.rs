//! Proves one StageX step in ZisK. ZisK limits public values to 256 bytes,
//! so this commits the SHA-256 digest of the complete step claim.
#![no_main]
ziskos::entrypoint!(main);

use hex0_lib::stagex::{run_step, StepInputs};
use sha2::{Digest, Sha256};

fn main() {
    let inputs: StepInputs = ziskos::io::read();
    let (claim, _) = run_step(&inputs);
    let claim = serde_json::to_vec(&claim).unwrap();
    let digest: [u8; 32] = Sha256::digest(claim).into();
    ziskos::io::commit_slice(&digest);
}
