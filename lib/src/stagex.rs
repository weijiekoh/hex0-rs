//! Proving the StageX x86 bootstrap one step at a time.
//!
//! Each step runs a real stage0 binary in the i386 emulator and commits a
//! [`StepClaim`]. Steps link by hash: a step's tool must be the seed or the
//! output of an earlier step.

use crate::x86;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// StageX's `packages/bootstrap/stage0/hex0-seed`, the only trusted binary.
pub const SEED_PATH: &str = "stagex/hex0-seed";
pub const SEED_SHA256: &str = "f74dcf9cef2aee9eb7723eca755849d474fccd89662947021d1aa08429d23c13";

/// Where StageX's pinned stage0-posix-x86 sources, mounted at `/x86`, are
/// vendored in this repository.
pub const SOURCES_DIR: &str = "stagex/stage0-posix-x86";

pub struct Step {
    /// The command line exactly as StageX runs it: tool, input, output.
    pub argv: [&'static str; 3],
    pub output_sha256: &'static str,
}

/// The first steps of StageX's stage0 build, in order.
pub const STEPS: [Step; 4] = [
    Step {
        argv: ["/hex0-seed", "/x86/hex0_x86.hex0", "hex0"],
        output_sha256: "f74dcf9cef2aee9eb7723eca755849d474fccd89662947021d1aa08429d23c13",
    },
    Step {
        argv: ["./hex0", "/x86/kaem-minimal.hex0", "kaem-minimal"],
        output_sha256: "545f89537f070d7e62b05243be34cbcfdb1e92dbf9d82e2cd15792d880436ac2",
    },
    Step {
        argv: ["./hex0", "/x86/hex1_x86.hex0", "hex1"],
        output_sha256: "30da8f019c21e71d9ea60b374272209956256958d21f698c0b757c8fa560c9cf",
    },
    Step {
        argv: ["./hex1", "/x86/hex2_x86.hex1", "hex2-0"],
        output_sha256: "8aaab3e704f13eac93ffb9649349fdd1d63b47d3d7fe32140db15b853bd4335b",
    },
];

/// The guest's input: a tool binary, its argv, and the files it may read.
#[derive(Serialize, Deserialize)]
pub struct StepInputs {
    pub tool: Vec<u8>,
    pub argv: Vec<String>,
    pub files: Vec<(String, Vec<u8>)>,
}

/// The guest's public output.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct StepClaim {
    pub tool_sha256: [u8; 32],
    pub argv: Vec<String>,
    pub inputs: Vec<(String, [u8; 32])>,
    pub outputs: Vec<(String, [u8; 32])>,
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// Runs the tool to completion, requires it to exit with 0, and returns the
/// claim together with the files it created.
pub fn run_step(inputs: &StepInputs) -> (StepClaim, Vec<(String, Vec<u8>)>) {
    let files = inputs.files.iter().cloned().collect();
    let exit = x86::run(&inputs.tool, &inputs.argv, files);
    assert_eq!(exit.code, 0, "tool exited with code {}", exit.code);
    let claim = StepClaim {
        tool_sha256: sha256(&inputs.tool),
        argv: inputs.argv.clone(),
        inputs: inputs
            .files
            .iter()
            .map(|(p, d)| (p.clone(), sha256(d)))
            .collect(),
        outputs: exit
            .created
            .iter()
            .map(|(p, d)| (p.clone(), sha256(d)))
            .collect(),
    };
    (claim, exit.created.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    /// Runs StageX's first steps from the seed and checks every output hash
    /// against a real run of the same commands.
    #[test]
    fn stagex_chain_from_seed() {
        let seed = std::fs::read(format!("../{SEED_PATH}")).unwrap();
        assert_eq!(hex::encode(sha256(&seed)), SEED_SHA256);
        let mut artifacts = BTreeMap::from([("hex0-seed".to_string(), seed)]);
        for step in STEPS {
            let [tool, input, output] = step.argv;
            let source_name = input.strip_prefix("/x86/").unwrap();
            let source = std::fs::read(format!("../{SOURCES_DIR}/{source_name}")).unwrap();
            let inputs = StepInputs {
                tool: artifacts[tool.trim_start_matches(['.', '/'])].clone(),
                argv: step.argv.map(String::from).to_vec(),
                files: vec![(input.to_string(), source)],
            };
            let (claim, created) = run_step(&inputs);
            assert_eq!(claim.outputs.len(), 1);
            assert_eq!(claim.outputs[0].0, output);
            assert_eq!(
                hex::encode(claim.outputs[0].1),
                step.output_sha256,
                "{output}"
            );
            artifacts.insert(output.to_string(), created.into_iter().next().unwrap().1);
        }
    }
}
