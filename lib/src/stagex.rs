//! Proving the StageX x86 bootstrap one step at a time.
//!
//! Each step runs a real stage0 binary in the i386 emulator and commits a
//! [`StepClaim`]. Steps link by hash: a step's tool and every file it reads
//! must be the seed, a pinned source file, or an earlier step's output.

use crate::x86;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, VecDeque};
use std::path::{Path, PathBuf};

/// StageX's `packages/bootstrap/stage0/hex0-seed`, the only trusted binary.
pub const SEED: &str = "/hex0-seed";
pub const SEED_SHA256: &str = "f74dcf9cef2aee9eb7723eca755849d474fccd89662947021d1aa08429d23c13";

/// StageX's working directory for every step.
pub const CWD: &str = "/build";

/// How many steps of `stagex/steps.txt`, from the top, the emulator supports.
pub const SUPPORTED_STEPS: usize = 60;

/// The guest's input: a tool binary, its argv, and the files it reads.
#[derive(Serialize, Deserialize)]
pub struct StepInputs {
    pub tool: Vec<u8>,
    pub argv: Vec<String>,
    pub files: Vec<(String, Vec<u8>)>,
}

/// The guest's public output. Paths are canonical, relative to [`CWD`].
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

/// Runs the tool on exactly the given files, requires it to exit with 0, and
/// returns the claim together with the files it created.
pub fn run_step(inputs: &StepInputs) -> (StepClaim, Vec<(String, Vec<u8>)>) {
    let mut lookup = |path: &str| {
        inputs
            .files
            .iter()
            .find(|(p, _)| p == path)
            .map(|(_, d)| d.clone())
    };
    let exit = x86::run(&inputs.tool, &inputs.argv, CWD, &mut lookup);
    assert_eq!(exit.code, 0, "tool exited with code {}", exit.code);
    (
        claim(inputs, &exit.created),
        exit.created.into_iter().collect(),
    )
}

fn claim(inputs: &StepInputs, created: &BTreeMap<String, Vec<u8>>) -> StepClaim {
    StepClaim {
        tool_sha256: sha256(&inputs.tool),
        argv: inputs.argv.clone(),
        inputs: inputs
            .files
            .iter()
            .map(|(p, d)| (p.clone(), sha256(d)))
            .collect(),
        outputs: created
            .iter()
            .map(|(p, d)| (p.clone(), sha256(d)))
            .collect(),
    }
}

/// A step run natively, ready to run in the guest.
pub struct Prepared {
    pub inputs: StepInputs,
    /// The claim the guest will make.
    pub claim: StepClaim,
    pub created: Vec<(String, Vec<u8>)>,
    /// Number of x86 instructions the step executes.
    pub instructions: u64,
}

/// The StageX stage0 build as a sequence of steps, with the files built so
/// far. `root` is the repository root, which holds `stagex/`.
pub struct Chain {
    root: PathBuf,
    /// Output hashes from a real run, by path, in the order they were built.
    expected: BTreeMap<String, VecDeque<String>>,
    /// Binaries and other files built so far, by canonical path.
    artifacts: BTreeMap<String, Vec<u8>>,
}

impl Chain {
    pub fn new(root: &Path) -> Chain {
        let seed = std::fs::read(root.join("stagex/hex0-seed")).expect("failed to read the seed");
        assert_eq!(
            hex::encode(sha256(&seed)),
            SEED_SHA256,
            "seed hash mismatch"
        );
        let mut expected: BTreeMap<String, VecDeque<String>> = BTreeMap::new();
        let text = std::fs::read_to_string(root.join("stagex/expected.sha256"))
            .expect("failed to read expected hashes");
        for line in text.lines() {
            let (hash, path) = line.split_once("  ").expect("malformed expected hash");
            expected
                .entry(path.to_string())
                .or_default()
                .push_back(hash.to_string());
        }
        Chain {
            root: root.to_path_buf(),
            expected,
            artifacts: BTreeMap::from([(SEED.to_string(), seed)]),
        }
    }

    /// Every step's argv, in order: StageX's two seed commands followed by
    /// its stage0 kaem script.
    pub fn steps(&self) -> Vec<Vec<String>> {
        std::fs::read_to_string(self.root.join("stagex/steps.txt"))
            .expect("failed to read steps")
            .lines()
            .map(|l| l.split_whitespace().map(String::from).collect())
            .collect()
    }

    /// A pinned source file, vendored under `stagex/sources`.
    fn source(&self, path: &str) -> Option<Vec<u8>> {
        if path.starts_with(&format!("{CWD}/")) {
            return None;
        }
        std::fs::read(self.root.join("stagex/sources").join(&path[1..])).ok()
    }

    fn file(&self, path: &str) -> Option<Vec<u8>> {
        self.artifacts
            .get(path)
            .cloned()
            .or_else(|| self.source(path))
    }

    /// Runs a step natively to find the files it reads.
    pub fn prepare(&self, argv: &[String]) -> Prepared {
        let tool_path = x86::canonical(CWD, &argv[0]);
        let tool = self
            .artifacts
            .get(&tool_path)
            .expect("tool has not been built")
            .clone();
        let exit = x86::run(&tool, argv, CWD, &mut |path| self.file(path));
        assert_eq!(exit.code, 0, "{argv:?} exited with code {}", exit.code);
        let files = exit
            .loaded
            .iter()
            .map(|p| (p.clone(), self.file(p).unwrap()))
            .collect();
        let inputs = StepInputs {
            tool,
            argv: argv.to_vec(),
            files,
        };
        Prepared {
            claim: claim(&inputs, &exit.created),
            inputs,
            created: exit.created.into_iter().collect(),
            instructions: exit.instructions,
        }
    }

    /// The checks a verifier makes on a step's claim: the tool and every
    /// input are the seed, a pinned source or an earlier output, and every
    /// output has the hash a real StageX build produces. Records the outputs
    /// for later steps.
    pub fn accept(&mut self, argv: &[String], claim: &StepClaim, created: Vec<(String, Vec<u8>)>) {
        let known = |chain: &Chain, path: &str| chain.file(path).map(|d| sha256(&d));
        assert_eq!(claim.argv, argv);
        let tool_path = x86::canonical(CWD, &argv[0]);
        assert_eq!(
            Some(claim.tool_sha256),
            known(self, &tool_path),
            "{tool_path}: unknown tool"
        );
        for (path, hash) in &claim.inputs {
            assert_eq!(Some(*hash), known(self, path), "{path}: unknown input");
        }
        assert!(!claim.outputs.is_empty(), "{argv:?} created no files");
        for (path, hash) in &claim.outputs {
            let expected = self
                .expected
                .get_mut(path)
                .and_then(|hashes| hashes.pop_front())
                .unwrap_or_else(|| panic!("{path}: no expected hash"));
            assert_eq!(hex::encode(hash), expected, "{path}: hash mismatch");
        }
        for (path, data) in created {
            assert!(claim.outputs.contains(&(path.clone(), sha256(&data))));
            self.artifacts.insert(path, data);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Runs the first `n` steps of StageX's stage0 build from the seed and
    /// checks every output against a real run of the same commands.
    fn chain_from_seed(n: usize) {
        let mut chain = Chain::new(Path::new(".."));
        for argv in chain.steps().into_iter().take(n) {
            let step = chain.prepare(&argv);
            chain.accept(&argv, &step.claim, step.created);
        }
    }

    /// Up to and including building M2-Planet's bootstrap compiler, `M2`.
    #[test]
    fn stagex_chain_to_m2() {
        chain_from_seed(16);
    }

    /// Every supported step. Takes several minutes.
    #[test]
    #[ignore]
    fn stagex_chain_full() {
        chain_from_seed(SUPPORTED_STEPS);
    }
}
