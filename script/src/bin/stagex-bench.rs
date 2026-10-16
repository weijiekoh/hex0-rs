//! Benchmarks selected StageX steps in SP1.
//!
//! The selected steps' inputs are discovered by running the preceding
//! chain natively. Each result's public claim must equal the native claim.
//!
//! ```shell
//! cargo run --release --bin stagex-bench -- --steps 1,6,8 --repeat 3 --output execute.jsonl
//! cargo run --release --bin stagex-bench -- --steps 1 --repeat 1 --prove --output prove.jsonl
//! ```

use clap::Parser;
use hex0_lib::stagex::{Chain, StepClaim};
use serde_json::json;
use sha2::{Digest, Sha256};
use sp1_sdk::{
    blocking::{ProveRequest, Prover, ProverClient},
    Elf, ProvingKey, SP1Stdin,
};
use std::{fs::File, io::Write, path::PathBuf, time::Instant};

const ELF_BYTES: &[u8] = include_bytes!(env!("SP1_ELF_stagex-x86-program"));
const ELF: Elf = Elf::Static(ELF_BYTES);

#[derive(Parser)]
struct Args {
    /// Comma-separated step numbers, counting from the seed.
    #[arg(long, value_delimiter = ',', required = true)]
    steps: Vec<usize>,

    #[arg(long, default_value_t = 1)]
    repeat: usize,

    /// Generate and verify CPU core proofs instead of only executing.
    #[arg(long)]
    prove: bool,

    /// JSON Lines output file.
    #[arg(long)]
    output: PathBuf,
}

fn main() {
    sp1_sdk::utils::setup_logger();
    let args = Args::parse();
    assert!(args.repeat > 0, "--repeat must be positive");
    let last = *args.steps.iter().max().unwrap();
    let elf_sha256 = hex::encode(Sha256::digest(ELF_BYTES));
    let mut output = File::create(&args.output).expect("failed to create output");

    let start = Instant::now();
    let mut chain = Chain::new(std::path::Path::new("."));
    let mut cases = Vec::new();
    for (i, step) in chain.steps().into_iter().take(last).enumerate() {
        let n = i + 1;
        let prepared = chain.prepare(&step);
        chain.accept(&step, &prepared.claim, prepared.created);
        if args.steps.contains(&n) {
            cases.push((n, step.argv, prepared.instructions, prepared.inputs, prepared.claim));
        }
    }
    assert_eq!(cases.len(), args.steps.len(), "unknown or duplicate step");
    let native_seconds = start.elapsed().as_secs_f64();

    let start = Instant::now();
    let light = (!args.prove).then(|| ProverClient::builder().light().build());
    let prover = args.prove.then(|| {
        let client = ProverClient::builder().cpu().build();
        let pk = client.setup(ELF).expect("failed to setup ELF");
        (client, pk)
    });
    let setup_seconds = start.elapsed().as_secs_f64();
    let setup = json!({
        "event": "setup", "mode": if args.prove { "core-proof" } else { "execute" },
        "elf_sha256": elf_sha256, "native_preparation_seconds": native_seconds,
        "client_setup_seconds": setup_seconds,
    });
    writeln!(output, "{setup}").unwrap();
    println!("{setup}");

    for (n, argv, instructions, inputs, expected) in cases {
        for trial in 1..=args.repeat {
            let mut stdin = SP1Stdin::new();
            stdin.write(&inputs);
            let start = Instant::now();
            let (mut values, mut row) = if let Some(client) = &light {
                let (values, report) = client.execute(ELF, stdin).run().unwrap();
                let seconds = start.elapsed().as_secs_f64();
                assert_eq!(report.exit_code, 0, "step {n}: guest panicked");
                let row = json!({
                    "event": "step", "mode": "execute", "step": n, "trial": trial,
                    "command": argv, "x86_instructions": instructions,
                    "cycles": report.total_instruction_count(), "gas": report.gas(),
                    "seconds": seconds,
                });
                (values, row)
            } else {
                let (client, pk) = prover.as_ref().unwrap();
                let proof = client.prove(pk, stdin).run().expect("failed to prove");
                let prove_seconds = start.elapsed().as_secs_f64();
                let start = Instant::now();
                client
                    .verify(&proof, pk.verifying_key(), None)
                    .expect("failed to verify");
                let verify_seconds = start.elapsed().as_secs_f64();
                let file = args.output.with_extension(format!("step-{n}-{trial}.proof"));
                proof.save(&file).expect("failed to save proof");
                let row = json!({
                    "event": "step", "mode": "core-proof", "step": n, "trial": trial,
                    "command": argv, "x86_instructions": instructions,
                    "prove_seconds": prove_seconds, "verify_seconds": verify_seconds,
                    "proof_bytes": std::fs::metadata(file).unwrap().len(),
                });
                (proof.public_values, row)
            };
            let claim: StepClaim = values.read();
            assert_eq!(claim, expected, "step {n}: guest and native claims differ");
            row["claim_matches_native"] = json!(true);
            writeln!(output, "{row}").unwrap();
            output.flush().unwrap();
            println!("{row}");
        }
    }
}
