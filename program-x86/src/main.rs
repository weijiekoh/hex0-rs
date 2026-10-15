//! Proves one step of the StageX x86 bootstrap: runs a stage0 binary in the
//! i386 emulator and commits the hashes of the tool, its inputs and its outputs.
#![no_main]
sp1_zkvm::entrypoint!(main);

use hex0_lib::stagex::{run_step, StepInputs};

pub fn main() {
    let inputs = sp1_zkvm::io::read::<StepInputs>();
    let (claim, _) = run_step(&inputs);
    sp1_zkvm::io::commit(&claim);
}
