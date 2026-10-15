//! Runs StageX's x86 stage0 build in the zkVM, starting from the hex0 seed,
//! and checks that the steps link by hash.
//!
//! ```shell
//! cargo run --release --bin stagex -- --execute
//! cargo run --release --bin stagex -- --prove
//! ```

use clap::Parser;
use hex0_lib::stagex::{Chain, StepClaim, SEED_SHA256, SUPPORTED_STEPS};
use sp1_sdk::{
    blocking::{ProveRequest, Prover, ProverClient},
    include_elf, Elf, ProvingKey, SP1Stdin,
};
use std::path::Path;

pub const STAGEX_X86_ELF: Elf = include_elf!("stagex-x86-program");

#[derive(Parser, Debug)]
struct Args {
    #[arg(long)]
    execute: bool,

    #[arg(long)]
    prove: bool,

    /// How many steps to run, from the seed.
    #[arg(long, default_value_t = SUPPORTED_STEPS)]
    steps: usize,

    /// With --execute, the first step to run in the zkVM. Earlier steps run
    /// natively only, so that ranges of steps can be measured in parallel.
    #[arg(long, default_value_t = 1)]
    from: usize,

    /// Where to write proofs, with --prove.
    #[arg(long, default_value = "stagex-out")]
    out_dir: String,
}

fn main() {
    sp1_sdk::utils::setup_logger();
    dotenv::dotenv().ok();
    let args = Args::parse();
    if args.execute == args.prove {
        eprintln!("Error: You must specify either --execute or --prove");
        std::process::exit(1);
    }
    if args.prove && args.from != 1 {
        eprintln!("Error: --from is only supported with --execute");
        std::process::exit(1);
    }
    std::fs::create_dir_all(&args.out_dir).expect("failed to create output directory");

    // SP1's default gas trace chunk makes the executor map about 4.7 GB of
    // shared memory; a smaller chunk fits small machines and does not change
    // cycle counts.
    if std::env::var_os("GAS_TRACE_CHUNK_THRESHOLD").is_none() {
        std::env::set_var("GAS_TRACE_CHUNK_THRESHOLD", "4194304");
    }
    // The light prover executes without initializing the full prover.
    let light = args
        .execute
        .then(|| ProverClient::builder().light().build());
    let prover = args.prove.then(|| {
        let client = ProverClient::from_env();
        let pk = client.setup(STAGEX_X86_ELF).expect("failed to setup elf");
        (client, pk)
    });

    let mut chain = Chain::new(Path::new("."));
    for (i, argv) in chain.steps().into_iter().take(args.steps).enumerate() {
        let step = i + 1;
        // Run natively to find the step's inputs and its output files.
        let prepared = chain.prepare(&argv);
        if step < args.from {
            chain.accept(&argv, &prepared.claim, prepared.created);
            continue;
        }

        let mut stdin = SP1Stdin::new();
        stdin.write(&prepared.inputs);
        let mut public_values = if let Some(light) = &light {
            let (public_values, report) = light.execute(STAGEX_X86_ELF, stdin).run().unwrap();
            // A guest panic is reported as an exit code.
            assert_eq!(report.exit_code, 0, "step {step}: guest panicked");
            println!(
                "step {step}: {} x86 instructions, {} cycles: {}",
                prepared.instructions,
                report.total_instruction_count(),
                argv.join(" ")
            );
            public_values
        } else {
            let (client, pk) = prover.as_ref().unwrap();
            let mut proof = client
                .prove(pk, stdin)
                .run()
                .expect("failed to generate proof");
            client
                .verify(&proof, pk.verifying_key(), None)
                .expect("failed to verify proof");
            proof
                .save(format!("{}/step-{step:02}.proof", args.out_dir))
                .expect("failed to save proof");
            println!("step {step}: proved and verified: {}", argv.join(" "));
            std::mem::take(&mut proof.public_values)
        };
        let claim: StepClaim = public_values.read();
        chain.accept(&argv, &claim, prepared.created);
    }
    if args.from == 1 {
        println!("All steps link from the seed {SEED_SHA256}.");
    }
}
