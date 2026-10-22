//! Benchmarks selected StageX steps in ZisK.
//!
//! The selected steps' inputs come from the same native StageX chain as the
//! SP1 benchmark. ZisK commits a SHA-256 digest of the step claim; the host
//! compares that digest with the native claim.

use anyhow::{ensure, Result};
use clap::{Parser, ValueEnum};
use hex0_lib::stagex::Chain;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{fs::File, io::Write, path::PathBuf, time::Instant};
use zisk_sdk::{load_program, EmbeddedOpts, GuestProgram, ProverClient, ZiskStdin};

static PROGRAM: GuestProgram = load_program!("stagex-x86-zisk");

#[derive(Clone, Copy, ValueEnum)]
enum Executor {
    Emulator,
    Assembly,
}

#[derive(Parser)]
struct Args {
    /// Comma-separated step numbers, counting from the seed.
    #[arg(long, value_delimiter = ',', required = true)]
    steps: Vec<usize>,

    #[arg(long, default_value_t = 1)]
    repeat: usize,

    /// Generate and verify proofs instead of only executing.
    #[arg(long)]
    prove: bool,

    #[arg(long, value_enum, default_value_t = Executor::Emulator)]
    executor: Executor,

    /// With --prove, use ZisK's lower-memory, slower proving mode.
    #[arg(long)]
    minimal_memory: bool,

    /// With --prove, cap stored witness memory in GiB.
    #[arg(long)]
    max_witness_gib: Option<u64>,

    /// With --prove, number of witness-generation threads.
    #[arg(long)]
    witness_threads: Option<usize>,

    /// JSON Lines output file.
    #[arg(long)]
    output: PathBuf,
}

fn main() -> Result<()> {
    let args = Args::parse();
    ensure!(args.repeat > 0, "--repeat must be positive");
    let last = *args.steps.iter().max().unwrap();
    let mut output = File::create(&args.output)?;

    let start = Instant::now();
    let mut chain = Chain::new(std::path::Path::new(".."));
    let mut cases = Vec::new();
    for (i, step) in chain.steps().into_iter().take(last).enumerate() {
        let n = i + 1;
        let prepared = chain.prepare(&step);
        chain.accept(&step, &prepared.claim, prepared.created);
        if args.steps.contains(&n) {
            let claim = serde_json::to_vec(&prepared.claim)?;
            let digest: [u8; 32] = Sha256::digest(claim).into();
            cases.push((n, step.argv, prepared.instructions, prepared.inputs, digest));
        }
    }
    ensure!(cases.len() == args.steps.len(), "unknown or duplicate step");
    let native_seconds = start.elapsed().as_secs_f64();
    let executor = match args.executor {
        Executor::Emulator => "emulator",
        Executor::Assembly => "assembly",
    };

    if args.prove {
        let start = Instant::now();
        let builder = ProverClient::embedded();
        let builder = match args.executor {
            Executor::Emulator => builder.emulator(),
            Executor::Assembly => builder.assembly(),
        };
        let mut opts = EmbeddedOpts::default();
        if args.minimal_memory {
            opts = opts.minimal_memory();
        }
        if let Some(gib) = args.max_witness_gib {
            opts = opts.max_witness_stored((gib << 30) as usize);
        }
        if let Some(threads) = args.witness_threads {
            opts = opts.number_threads_witness(threads);
        }
        let client = builder.with_embedded_opts(opts).build()?;
        client.setup(&PROGRAM).run_sync()?;
        let vk = PROGRAM.vk()?;
        let setup = json!({
            "event": "setup", "mode": "proof", "executor": executor,
            "minimal_memory": args.minimal_memory,
            "max_witness_gib": args.max_witness_gib,
            "witness_threads": args.witness_threads,
            "native_preparation_seconds": native_seconds,
            "client_setup_seconds": start.elapsed().as_secs_f64(),
        });
        writeln!(output, "{setup}")?;
        println!("{setup}");

        for (n, argv, instructions, inputs, expected) in cases {
            for trial in 1..=args.repeat {
                let stdin = ZiskStdin::new();
                stdin.write(&inputs);
                let start = Instant::now();
                let proof = client.prove(&PROGRAM, stdin).run_sync()?;
                let prove_seconds = start.elapsed().as_secs_f64();
                let start = Instant::now();
                proof.with_program_vk(&vk).verify()?;
                let verify_seconds = start.elapsed().as_secs_f64();
                let mut digest = [0; 32];
                proof.get_public_values_slice(&mut digest);
                ensure!(digest == expected, "step {n}: guest and native claims differ");
                let file = args.output.with_extension(format!("step-{n}-{trial}.proof"));
                proof.save_proof(&file)?;
                let row = json!({
                    "event": "step", "mode": "proof", "executor": executor,
                    "step": n, "trial": trial, "command": argv,
                    "x86_instructions": instructions,
                    "zisk_steps": proof.get_execution_steps(),
                    "zisk_cost": proof.get_execution_cost(),
                    "zisk_proving_ms": proof.get_proving_time(),
                    "prove_seconds": prove_seconds, "verify_seconds": verify_seconds,
                    "proof_bytes": std::fs::metadata(file)?.len(),
                    "claim_digest": hex::encode(digest), "claim_matches_native": true,
                });
                writeln!(output, "{row}")?;
                output.flush()?;
                println!("{row}");
            }
        }
    } else {
        let start = Instant::now();
        let builder = ProverClient::embedded();
        let builder = match args.executor {
            Executor::Emulator => builder.emulator(),
            Executor::Assembly => builder.assembly(),
        };
        let client = builder.execute_only().build()?;
        client.setup(&PROGRAM, false)?;
        let setup = json!({
            "event": "setup", "mode": "execute", "executor": executor,
            "native_preparation_seconds": native_seconds,
            "client_setup_seconds": start.elapsed().as_secs_f64(),
        });
        writeln!(output, "{setup}")?;
        println!("{setup}");

        for (n, argv, instructions, inputs, expected) in cases {
            for trial in 1..=args.repeat {
                let stdin = ZiskStdin::new();
                stdin.write(&inputs);
                let start = Instant::now();
                let result = client.execute(&PROGRAM, stdin, None)?;
                let seconds = start.elapsed().as_secs_f64();
                let mut digest = [0; 32];
                result.get_public_values_slice(&mut digest);
                ensure!(digest == expected, "step {n}: guest and native claims differ");
                let row = json!({
                    "event": "step", "mode": "execute", "executor": executor,
                    "step": n, "trial": trial, "command": argv,
                    "x86_instructions": instructions,
                    "zisk_steps": result.get_execution_steps(),
                    "zisk_execution_ms": result.get_execution_time(),
                    "seconds": seconds,
                    "claim_digest": hex::encode(digest), "claim_matches_native": true,
                });
                writeln!(output, "{row}")?;
                output.flush()?;
                println!("{row}");
            }
        }
    }
    Ok(())
}
