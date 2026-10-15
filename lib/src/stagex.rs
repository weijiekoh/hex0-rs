//! Proving the StageX x86 bootstrap one step at a time.
//!
//! Each step runs a real binary built from the seed in the i386 emulator and
//! commits a [`StepClaim`]. Steps link by hash: a step's tool and every file
//! it reads must be the seed, a pinned source file, or an earlier step's
//! output, and every path it found missing must not exist in StageX's build.
//!
//! Stage 0 is StageX's `bootstrap-stage0` package, whose commands run in
//! `/build`. Stage 1 is the start of its `bootstrap-stage1` package, which
//! installs stage 0's binaries in `/usr/bin` and runs live-bootstrap's
//! `pass1.kaem` scripts with stage 0's `kaem`.

use crate::x86;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};

/// StageX's `packages/bootstrap/stage0/hex0-seed`, the only trusted binary.
pub const SEED: &str = "/hex0-seed";
pub const SEED_SHA256: &str = "f74dcf9cef2aee9eb7723eca755849d474fccd89662947021d1aa08429d23c13";

/// StageX's working directory for every stage 0 step.
pub const CWD: &str = "/build";

/// The environment StageX's stage 0 Containerfile sets, which `kaem-minimal`
/// passes to every command.
pub const ENV: [&str; 3] = ["M2LIBC_PATH=/M2libc", "TMPDIR=/build", "PATH=/build"];

/// The files of `/build` that StageX's stage 0 package installs in `/bin`,
/// which stage 1 copies to `/usr/bin`.
pub const STAGE0_BIN: [&str; 20] = [
    "hex2",
    "kaem",
    "M1",
    "M2-Mesoplanet",
    "M2-Planet",
    "blood-elf",
    "get_machine",
    "sha256sum",
    "match",
    "mkdir",
    "untar",
    "ungz",
    "unbz2",
    "unxz",
    "catm",
    "cp",
    "chmod",
    "rm",
    "replace",
    "wrap",
];

/// The commands StageX runs before handing over to `kaem-minimal`, which
/// runs `stagex/kaem.x86`.
pub const SEED_STEPS: [&str; 2] = [
    "/hex0-seed /x86/hex0_x86.hex0 hex0",
    "./hex0 /x86/kaem-minimal.hex0 kaem-minimal",
];

/// How many steps, from the seed, the emulator supports.
pub const SUPPORTED_STEPS: usize = 75;

/// A command StageX runs.
#[derive(Clone, Debug)]
pub struct Step {
    pub stage: usize,
    pub argv: Vec<String>,
    pub cwd: String,
    pub env: Vec<String>,
}

/// The guest's input: a tool binary, its command line, and what exists at
/// every path the step looks up.
#[derive(Serialize, Deserialize)]
pub struct StepInputs {
    pub tool: Vec<u8>,
    pub argv: Vec<String>,
    pub cwd: String,
    pub env: Vec<String>,
    pub files: Vec<(String, Vec<u8>)>,
    pub dirs: Vec<String>,
    /// Symbolic links, with their targets.
    pub links: Vec<(String, String)>,
    pub missing: Vec<String>,
}

/// The guest's public output. Paths are canonical.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct StepClaim {
    pub tool_sha256: [u8; 32],
    pub argv: Vec<String>,
    pub cwd: String,
    pub env: Vec<String>,
    pub inputs: Vec<(String, [u8; 32])>,
    pub dirs: Vec<String>,
    pub links: Vec<(String, String)>,
    pub missing: Vec<String>,
    pub outputs: Vec<(String, [u8; 32])>,
    pub created_dirs: Vec<String>,
    pub created_links: Vec<(String, String)>,
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
        } else if let Some((_, target)) = inputs.links.iter().find(|(p, _)| p == path) {
            x86::Entry::Link(target.clone())
        } else if inputs.missing.iter().any(|p| p == path) {
            x86::Entry::Missing
        } else {
            panic!("no entry provided for {path}")
        }
    };
    let exit = x86::run(
        &inputs.tool,
        &inputs.argv,
        &inputs.env,
        &inputs.cwd,
        &mut lookup,
    );
    assert_eq!(exit.code, 0, "tool exited with code {}", exit.code);
    (claim(inputs, &exit), exit.created.into_iter().collect())
}

fn claim(inputs: &StepInputs, exit: &x86::Exit) -> StepClaim {
    StepClaim {
        tool_sha256: sha256(&inputs.tool),
        argv: inputs.argv.clone(),
        cwd: inputs.cwd.clone(),
        env: inputs.env.clone(),
        inputs: inputs
            .files
            .iter()
            .map(|(p, d)| (p.clone(), sha256(d)))
            .collect(),
        dirs: inputs.dirs.clone(),
        links: inputs.links.clone(),
        missing: inputs.missing.clone(),
        outputs: exit
            .created
            .iter()
            .map(|(p, d)| (p.clone(), sha256(d)))
            .collect(),
        created_dirs: exit.dirs.clone(),
        created_links: exit.links.clone(),
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

/// The StageX build as a sequence of steps, with the files built so far.
/// `root` is the repository root, which holds `stagex/`.
pub struct Chain {
    root: PathBuf,
    /// Output hashes from a real run, by path, in the order they were built.
    expected: BTreeMap<String, VecDeque<String>>,
    /// The stage whose filesystem `manifest` and `artifacts` describe.
    stage: usize,
    /// Every path the stage starts with that is not in `artifacts`: the
    /// contents of the pinned source tarballs, vendored under `sources`,
    /// and directories. Directories end with `/`.
    manifest: BTreeSet<String>,
    /// Symbolic links the stage starts with, with their targets.
    manifest_links: BTreeMap<String, String>,
    sources: PathBuf,
    /// The seed and files built so far, by canonical path.
    artifacts: BTreeMap<String, Vec<u8>>,
    /// Directories and symbolic links created so far.
    dirs: BTreeSet<String>,
    links: BTreeMap<String, String>,
}

impl Chain {
    pub fn new(root: &Path) -> Chain {
        let seed = read(root, "stagex/hex0-seed");
        assert_eq!(
            hex::encode(sha256(&seed)),
            SEED_SHA256,
            "seed hash mismatch"
        );
        let mut expected: BTreeMap<String, VecDeque<String>> = BTreeMap::new();
        for line in String::from_utf8(read(root, "stagex/expected.sha256"))
            .unwrap()
            .lines()
        {
            let (hash, path) = line.split_once("  ").expect("malformed expected hash");
            expected
                .entry(path.to_string())
                .or_default()
                .push_back(hash.to_string());
        }
        // StageX writes its stage0 script to /build before running it.
        let script = read(root, "stagex/kaem.x86");
        let (manifest, manifest_links) = read_manifest(root, "stagex/sources.manifest");
        Chain {
            root: root.to_path_buf(),
            expected,
            stage: 0,
            manifest,
            manifest_links,
            sources: root.join("stagex/sources"),
            artifacts: BTreeMap::from([
                (SEED.to_string(), seed),
                (format!("{CWD}/kaem.x86"), script),
            ]),
            dirs: BTreeSet::new(),
            links: BTreeMap::new(),
        }
    }

    /// Every step, in order: StageX's two seed commands, its stage0 kaem
    /// script, and the kaem `RUN`s of its stage1 Containerfile.
    pub fn steps(&self) -> Vec<Step> {
        let script = String::from_utf8(read(&self.root, "stagex/kaem.x86")).unwrap();
        let stage0 = SEED_STEPS
            .into_iter()
            .chain(script.lines())
            .map(|l| l.split_whitespace().map(String::from).collect())
            .filter(|argv: &Vec<String>| !argv.is_empty())
            .map(|argv| Step {
                stage: 0,
                argv,
                cwd: CWD.to_string(),
                env: ENV.map(String::from).to_vec(),
            });
        let containerfile = read(&self.root, "stagex/stage1/Containerfile");
        stage0
            .chain(stage1_steps(&String::from_utf8(containerfile).unwrap()))
            .collect()
    }

    /// Moves to the next stage's filesystem: stage 1 starts with stage 0's
    /// installed binaries and its own sources.
    fn enter(&mut self, stage: usize) {
        if stage == self.stage {
            return;
        }
        assert_eq!((self.stage, stage), (0, 1), "steps out of order");
        self.artifacts = STAGE0_BIN
            .iter()
            .map(|name| {
                let data = self.artifacts[&format!("{CWD}/{name}")].clone();
                (format!("/usr/bin/{name}"), data)
            })
            .collect();
        (self.manifest, self.manifest_links) = read_manifest(&self.root, "stagex/stage1/manifest");
        self.sources = self.root.join("stagex/stage1/sources");
        self.dirs.clear();
        self.links.clear();
        self.stage = stage;
    }

    /// What exists at a canonical path in StageX's build, given the files
    /// built so far.
    fn entry(&self, path: &str) -> x86::Entry {
        // The emulator only follows links it created among a path's
        // directories, so a path under any other link is unsupported.
        for (i, _) in path.match_indices('/').skip(1) {
            let dir = &path[..i];
            assert!(
                !self.links.contains_key(dir) && !self.manifest_links.contains_key(dir),
                "{path}: under the symbolic link {dir}"
            );
        }
        if let Some(data) = self.artifacts.get(path) {
            x86::Entry::File(data.clone())
        } else if let Some(target) = self.links.get(path).or(self.manifest_links.get(path)) {
            x86::Entry::Link(target.clone())
        } else if path == "/"
            || self.dirs.contains(path)
            || self.manifest.contains(&format!("{path}/"))
        {
            x86::Entry::Dir
        } else if self.manifest.contains(path) {
            let data = std::fs::read(self.sources.join(&path[1..]));
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
    pub fn prepare(&mut self, step: &Step) -> Prepared {
        self.enter(step.stage);
        let tool_path = x86::canonical(&step.cwd, &step.argv[0]);
        let tool = self
            .artifacts
            .get(&tool_path)
            .expect("tool has not been built")
            .clone();
        let mut exit = x86::run(&tool, &step.argv, &step.env, &step.cwd, &mut |path| {
            self.entry(path)
        });
        assert_eq!(
            exit.code, 0,
            "{:?} exited with code {}",
            step.argv, exit.code
        );
        let mut inputs = StepInputs {
            tool,
            argv: step.argv.clone(),
            cwd: step.cwd.clone(),
            env: step.env.clone(),
            files: Vec::new(),
            dirs: Vec::new(),
            links: Vec::new(),
            missing: Vec::new(),
        };
        for (path, entry) in std::mem::take(&mut exit.lookups) {
            match entry {
                x86::Entry::File(data) => inputs.files.push((path, data)),
                x86::Entry::Dir => inputs.dirs.push(path),
                x86::Entry::Link(target) => inputs.links.push((path, target)),
                x86::Entry::Missing => inputs.missing.push(path),
            }
        }
        Prepared {
            claim: claim(&inputs, &exit),
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
    pub fn accept(&mut self, step: &Step, claim: &StepClaim, created: Vec<(String, Vec<u8>)>) {
        self.enter(step.stage);
        assert_eq!(claim.argv, step.argv);
        assert_eq!(claim.cwd, step.cwd);
        assert_eq!(claim.env, step.env);
        let tool_path = x86::canonical(&step.cwd, &step.argv[0]);
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
        for (path, target) in &claim.links {
            assert!(
                matches!(self.entry(path), x86::Entry::Link(t) if t == *target),
                "{path}: not a link to {target}"
            );
        }
        for path in &claim.missing {
            assert!(
                matches!(self.entry(path), x86::Entry::Missing),
                "{path}: exists"
            );
        }
        assert!(
            !claim.outputs.is_empty(),
            "{:?} created no files",
            step.argv
        );
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
        self.dirs.extend(claim.created_dirs.iter().cloned());
        self.links.extend(claim.created_links.iter().cloned());
    }
}

fn read(root: &Path, path: &str) -> Vec<u8> {
    std::fs::read(root.join(path)).unwrap_or_else(|e| panic!("failed to read {path}: {e}"))
}

/// Reads a manifest: one path per line, where directories end with `/` and
/// symbolic links are written `path -> target`.
fn read_manifest(root: &Path, path: &str) -> (BTreeSet<String>, BTreeMap<String, String>) {
    let (mut paths, mut links) = (BTreeSet::new(), BTreeMap::new());
    for line in String::from_utf8(read(root, path)).unwrap().lines() {
        if let Some((link, target)) = line.split_once(" -> ") {
            links.insert(link.to_string(), target.to_string());
        } else {
            paths.insert(line.to_string());
        }
    }
    (paths, links)
}

/// The steps of StageX's stage1 Containerfile while its shell is kaem: each
/// `RUN` runs `kaem --verbose --file` on its argument, with the environment
/// and working directory the `ENV` and `WORKDIR` instructions before it set.
fn stage1_steps(containerfile: &str) -> Vec<Step> {
    const KAEM: &str = r#"SHELL ["/usr/bin/kaem","--verbose","--file"]"#;
    let mut env: Vec<(String, String)> = Vec::new();
    let mut cwd = "/".to_string();
    let mut kaem = false;
    let mut steps = Vec::new();
    let build = containerfile
        .lines()
        .skip_while(|l| *l != "FROM base AS build");
    for line in build {
        let Some((instruction, arg)) = line.split_once(' ') else {
            continue;
        };
        match instruction {
            "ENV" => {
                let (name, value) = arg.split_once('=').expect("malformed ENV");
                let value = expand(value, &env);
                match env.iter_mut().find(|(n, _)| n == name) {
                    Some(var) => var.1 = value,
                    None => env.push((name.to_string(), value)),
                }
            }
            "WORKDIR" => cwd = x86::canonical(&cwd, &expand(arg, &env)),
            "SHELL" if line == KAEM => kaem = true,
            "SHELL" => break,
            "RUN" => {
                assert!(kaem, "RUN before the kaem SHELL");
                steps.push(Step {
                    stage: 1,
                    argv: ["/usr/bin/kaem", "--verbose", "--file", arg]
                        .map(String::from)
                        .to_vec(),
                    cwd: cwd.clone(),
                    env: env.iter().map(|(n, v)| format!("{n}={v}")).collect(),
                });
            }
            _ => {}
        }
    }
    steps
}

/// Expands `${NAME}` references and removes surrounding quotes, as Docker
/// does for `ENV` and `WORKDIR`.
fn expand(value: &str, env: &[(String, String)]) -> String {
    let mut out = String::new();
    let mut rest = value;
    while let Some(start) = rest.find("${") {
        let end = start + rest[start..].find('}').expect("unterminated ${");
        let name = &rest[start + 2..end];
        out += &rest[..start];
        out += env.iter().find(|(n, _)| n == name).map_or("", |(_, v)| v);
        rest = &rest[end + 1..];
    }
    out += rest;
    for quote in ['"', '\''] {
        if out.len() >= 2 && out.starts_with(quote) && out.ends_with(quote) {
            return out[1..out.len() - 1].to_string();
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Runs the first `n` steps of StageX's stage0 build from the seed and
    /// checks every output against a real run of the same commands.
    fn chain_from_seed(n: usize) {
        let mut chain = Chain::new(Path::new(".."));
        for step in chain.steps().into_iter().take(n) {
            let prepared = chain.prepare(&step);
            chain.accept(&step, &prepared.claim, prepared.created);
        }
    }

    /// Up to and including building M2-Planet's bootstrap compiler, `M2`.
    #[test]
    fn stagex_chain_to_m2() {
        chain_from_seed(16);
    }

    /// Stage 1's steps carry the environment and working directory StageX's
    /// Containerfile gives each `RUN`.
    #[test]
    fn stagex_stage1_steps() {
        let steps = Chain::new(Path::new("..")).steps();
        let stage1: Vec<&Step> = steps.iter().filter(|s| s.stage == 1).collect();
        let cwds: Vec<&str> = stage1.iter().map(|s| s.cwd.as_str()).collect();
        assert_eq!(
            cwds[..3],
            [
                "/steps/checksum-transcriber-1.0",
                "/steps/simple-patch-1.0",
                "/steps/mes-0.27"
            ]
        );
        assert_eq!(cwds.last(), Some(&"/steps/bash-2.05b"));
        assert_eq!(
            stage1[0].argv,
            ["/usr/bin/kaem", "--verbose", "--file", "pass1.kaem"]
        );
        let env = &stage1[0].env;
        assert_eq!(env.first().map(String::as_str), Some("ARCH=x86"));
        assert!(env.contains(&"PATH=/usr/bin:/usr/bin".to_string()));
        assert!(env.contains(&"MES_PREFIX=/steps/mes-0.27/build/mes-0.27".to_string()));
        assert_eq!(
            env.last().map(String::as_str),
            Some("pkg=checksum-transcriber-1.0")
        );
        // Setting a variable again keeps its position.
        let tcc = stage1
            .iter()
            .find(|s| s.cwd == "/steps/tcc-0.9.27")
            .unwrap();
        assert_eq!(tcc.env.len(), env.len());
        assert!(tcc.env.contains(&"GUILE_LOAD_PATH=".to_string()));
        assert_eq!(tcc.env.last().map(String::as_str), Some("pkg=tcc-0.9.27"));
    }

    /// Every supported step. Takes several minutes.
    #[test]
    #[ignore]
    fn stagex_chain_full() {
        chain_from_seed(SUPPORTED_STEPS);
    }
}
