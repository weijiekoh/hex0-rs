//! Proving the StageX x86 bootstrap one step at a time.
//!
//! Each step runs a real stage0 binary in the i386 emulator and commits a
//! [`StepClaim`]. Steps link by hash: a step's tool and every file it reads
//! must be the seed, a pinned source file, or an earlier step's output, and
//! every path it found missing must not exist in StageX's build.

use crate::x86;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};

/// StageX's `packages/bootstrap/stage0/hex0-seed`, the only trusted binary.
pub const SEED: &str = "/hex0-seed";
pub const SEED_SHA256: &str = "f74dcf9cef2aee9eb7723eca755849d474fccd89662947021d1aa08429d23c13";

/// StageX's working directory for every step.
pub const CWD: &str = "/build";

/// The environment StageX's Containerfile sets, which `kaem-minimal` passes
/// to every command.
pub const ENV: [&str; 3] = ["M2LIBC_PATH=/M2libc", "TMPDIR=/build", "PATH=/build"];

/// The commands StageX runs before handing over to `kaem-minimal`, which
/// runs `stagex/kaem.x86`.
pub const SEED_STEPS: [&str; 2] = [
    "/hex0-seed /x86/hex0_x86.hex0 hex0",
    "./hex0 /x86/kaem-minimal.hex0 kaem-minimal",
];

/// How many steps, from the seed, the emulator supports.
pub const SUPPORTED_STEPS: usize = 73;

/// The guest's input: a tool binary, its command line, and what exists at
/// every path the step looks up.
#[derive(Serialize, Deserialize)]
pub struct StepInputs {
    pub tool: Vec<u8>,
    pub argv: Vec<String>,
    pub env: Vec<String>,
    pub files: Vec<(String, Vec<u8>)>,
    pub dirs: Vec<String>,
    pub missing: Vec<String>,
}

/// The guest's public output. Paths are canonical, relative to [`CWD`].
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct StepClaim {
    pub tool_sha256: [u8; 32],
    pub argv: Vec<String>,
    pub env: Vec<String>,
    pub inputs: Vec<(String, [u8; 32])>,
    pub dirs: Vec<String>,
    pub missing: Vec<String>,
    pub outputs: Vec<(String, [u8; 32])>,
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// Runs the tool on exactly the given files, requires it to exit with 0, and
/// returns the claim together with the files it created.
pub fn run_step(inputs: &StepInputs) -> (StepClaim, Vec<(String, Vec<u8>)>) {
    let mut lookup = |path: &str| {
        if let Some((_, data)) = inputs.files.iter().find(|(p, _)| p == path) {
            x86::Entry::File(data.clone())
        } else if inputs.dirs.iter().any(|p| p == path) {
            x86::Entry::Dir
        } else if inputs.missing.iter().any(|p| p == path) {
            x86::Entry::Missing
        } else {
            panic!("no entry provided for {path}")
        }
    };
    let exit = x86::run(&inputs.tool, &inputs.argv, &inputs.env, CWD, &mut lookup);
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
        env: inputs.env.clone(),
        inputs: inputs
            .files
            .iter()
            .map(|(p, d)| (p.clone(), sha256(d)))
            .collect(),
        dirs: inputs.dirs.clone(),
        missing: inputs.missing.clone(),
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
    /// Every path in StageX's build outside `/build`: the seed and the
    /// contents of the pinned source tarballs. Directories end with `/`.
    manifest: BTreeSet<String>,
    /// Files in `/build` and the seed, by canonical path.
    artifacts: BTreeMap<String, Vec<u8>>,
}

impl Chain {
    pub fn new(root: &Path) -> Chain {
        let read = |path: &str| {
            std::fs::read(root.join(path)).unwrap_or_else(|e| panic!("failed to read {path}: {e}"))
        };
        let seed = read("stagex/hex0-seed");
        assert_eq!(
            hex::encode(sha256(&seed)),
            SEED_SHA256,
            "seed hash mismatch"
        );
        let mut expected: BTreeMap<String, VecDeque<String>> = BTreeMap::new();
        for line in String::from_utf8(read("stagex/expected.sha256"))
            .unwrap()
            .lines()
        {
            let (hash, path) = line.split_once("  ").expect("malformed expected hash");
            expected
                .entry(path.to_string())
                .or_default()
                .push_back(hash.to_string());
        }
        let manifest = String::from_utf8(read("stagex/sources.manifest"))
            .unwrap()
            .lines()
            .map(String::from)
            .collect();
        // StageX writes its stage0 script to /build before running it.
        let script = read("stagex/kaem.x86");
        Chain {
            root: root.to_path_buf(),
            expected,
            manifest,
            artifacts: BTreeMap::from([
                (SEED.to_string(), seed),
                (format!("{CWD}/kaem.x86"), script),
            ]),
        }
    }

    /// Every step's argv, in order: StageX's two seed commands followed by
    /// its stage0 kaem script.
    pub fn steps(&self) -> Vec<Vec<String>> {
        let script = std::fs::read_to_string(self.root.join("stagex/kaem.x86")).unwrap();
        SEED_STEPS
            .into_iter()
            .chain(script.lines())
            .map(|l| l.split_whitespace().map(String::from).collect())
            .filter(|argv: &Vec<String>| !argv.is_empty())
            .collect()
    }

    /// What exists at a canonical path in StageX's build, given the files
    /// built so far. Source files are vendored under `stagex/sources`.
    fn entry(&self, path: &str) -> x86::Entry {
        if let Some(data) = self.artifacts.get(path) {
            x86::Entry::File(data.clone())
        } else if path == "/" || self.manifest.contains(&format!("{path}/")) {
            x86::Entry::Dir
        } else if self.manifest.contains(path) {
            let data = std::fs::read(self.root.join("stagex/sources").join(&path[1..]));
            x86::Entry::File(data.unwrap_or_else(|_| panic!("{path} is not vendored")))
        } else {
            x86::Entry::Missing
        }
    }

    fn known_hash(&self, path: &str) -> Option<[u8; 32]> {
        match self.entry(path) {
            x86::Entry::File(data) => Some(sha256(&data)),
            _ => None,
        }
    }

    /// Runs a step natively to find what it looks up.
    pub fn prepare(&self, argv: &[String]) -> Prepared {
        let tool_path = x86::canonical(CWD, &argv[0]);
        let tool = self
            .artifacts
            .get(&tool_path)
            .expect("tool has not been built")
            .clone();
        let env: Vec<String> = ENV.map(String::from).to_vec();
        let exit = x86::run(&tool, argv, &env, CWD, &mut |path| self.entry(path));
        assert_eq!(exit.code, 0, "{argv:?} exited with code {}", exit.code);
        let mut inputs = StepInputs {
            tool,
            argv: argv.to_vec(),
            env,
            files: Vec::new(),
            dirs: Vec::new(),
            missing: Vec::new(),
        };
        for (path, entry) in exit.lookups {
            match entry {
                x86::Entry::File(data) => inputs.files.push((path, data)),
                x86::Entry::Dir => inputs.dirs.push(path),
                x86::Entry::Missing => inputs.missing.push(path),
            }
        }
        Prepared {
            claim: claim(&inputs, &exit.created),
            inputs,
            created: exit.created.into_iter().collect(),
            instructions: exit.instructions,
        }
    }

    /// The checks a verifier makes on a step's claim: the tool and every
    /// input are the seed, a pinned source or an earlier output, every
    /// directory exists and every missing path does not exist in StageX's
    /// build, and every output has the hash a real StageX build produces.
    /// Records the outputs for later steps.
    pub fn accept(&mut self, argv: &[String], claim: &StepClaim, created: Vec<(String, Vec<u8>)>) {
        assert_eq!(claim.argv, argv);
        assert_eq!(claim.env, ENV);
        let tool_path = x86::canonical(CWD, &argv[0]);
        assert_eq!(
            Some(claim.tool_sha256),
            self.known_hash(&tool_path),
            "{tool_path}: unknown tool"
        );
        for (path, hash) in &claim.inputs {
            assert_eq!(Some(*hash), self.known_hash(path), "{path}: unknown input");
        }
        for path in &claim.dirs {
            assert!(
                matches!(self.entry(path), x86::Entry::Dir),
                "{path}: not a directory"
            );
        }
        for path in &claim.missing {
            assert!(
                matches!(self.entry(path), x86::Entry::Missing),
                "{path}: exists"
            );
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
