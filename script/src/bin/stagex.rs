//! Runs the first steps of StageX's x86 bootstrap in the zkVM, starting from
//! the hex0 seed, and checks that the steps link by hash.
//!
//! ```shell
//! cargo run --release --bin stagex -- --execute
//! cargo run --release --bin stagex -- --prove
//! ```

use clap::Parser;
use hex0_lib::stagex::{
    run_step, sha256, StepClaim, StepInputs, SEED_PATH, SEED_SHA256, SOURCES_DIR, STEPS,
};
use sp1_sdk::{include_elf, ProverClient, SP1Stdin};
use std::collections::BTreeMap;

pub const STAGEX_X86_ELF: &[u8] = include_elf!("stagex-x86-program");

#[derive(Parser, Debug)]
struct Args {
    #[arg(long)]
    execute: bool,

    #[arg(long)]
    prove: bool,

    /// Where to write each step's output binary and, with --prove, its proof.
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
    std::fs::create_dir_all(&args.out_dir).expect("failed to create output directory");

    let client = ProverClient::from_env();
    let keys = args.prove.then(|| client.setup(STAGEX_X86_ELF));

    let seed = std::fs::read(SEED_PATH).expect("failed to read the seed");
    assert_eq!(
        hex::encode(sha256(&seed)),
        SEED_SHA256,
        "seed hash mismatch"
    );

    // Binaries available to later steps, and the hashes a verifier trusts.
    let mut artifacts = BTreeMap::from([("hex0-seed".to_string(), seed)]);
    let mut known = BTreeMap::from([("hex0-seed".to_string(), sha256(&artifacts["hex0-seed"]))]);

    for step in STEPS {
        let [tool, input, output] = step.argv;
        let tool = tool.trim_start_matches(['.', '/']);
        let source_path = format!("{SOURCES_DIR}/{}", input.strip_prefix("/x86/").unwrap());
        let source = std::fs::read(&source_path).expect("failed to read source");
        let inputs = StepInputs {
            tool: artifacts[tool].clone(),
            argv: step.argv.map(String::from).to_vec(),
            files: vec![(input.to_string(), source.clone())],
        };

        // Run natively to obtain the output binary for the next step.
        let (_, created) = run_step(&inputs);

        let mut stdin = SP1Stdin::new();
        stdin.write(&inputs);
        let mut public_values = if args.execute {
            let (public_values, report) = client.execute(STAGEX_X86_ELF, &stdin).run().unwrap();
            println!(
                "{output}: executed in {} cycles",
                report.total_instruction_count()
            );
            public_values
        } else {
            let (pk, vk) = keys.as_ref().unwrap();
            let mut proof = client
                .prove(pk, &stdin)
                .run()
                .expect("failed to generate proof");
            client.verify(&proof, vk).expect("failed to verify proof");
            proof
                .save(format!("{}/{output}.proof", args.out_dir))
                .expect("failed to save proof");
            println!("{output}: proved and verified");
            std::mem::take(&mut proof.public_values)
        };
        let claim: StepClaim = public_values.read();

        // The checks a verifier makes: the tool is the seed or an earlier
        // step's output, the input is the pinned source, and the output is
        // what a real StageX build produces.
        assert_eq!(claim.argv, step.argv.map(String::from).to_vec());
        assert_eq!(
            claim.tool_sha256, known[tool],
            "{output}: tool is not a known binary"
        );
        assert_eq!(claim.inputs, vec![(input.to_string(), sha256(&source))]);
        assert_eq!(
            claim.outputs.len(),
            1,
            "{output}: expected exactly one output file"
        );
        assert_eq!(claim.outputs[0].0, output);
        assert_eq!(
            hex::encode(claim.outputs[0].1),
            step.output_sha256,
            "{output}: hash mismatch"
        );
        known.insert(output.to_string(), claim.outputs[0].1);

        let bytes = created.into_iter().next().unwrap().1;
        std::fs::write(format!("{}/{output}", args.out_dir), &bytes)
            .expect("failed to write output");
        artifacts.insert(output.to_string(), bytes);
    }
    println!("All steps link from the seed {SEED_SHA256}.");
}
