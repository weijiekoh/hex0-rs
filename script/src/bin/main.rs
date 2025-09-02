//! You can run this script using the following command:
//! ```shell
//! RUST_LOG=info cargo run --release -- --execute
//! ```
//! or
//! ```shell
//! RUST_LOG=info cargo run --release -- --prove
//! ```

use clap::Parser;
use hex0_lib::hex0;
use sha2::{Digest, Sha256};
use sp1_sdk::{include_elf, ProverClient, SP1Stdin};
use std::os::unix::fs::PermissionsExt;

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const HEX0_ELF: &[u8] = include_elf!("hex0-program");

/// The arguments for the command.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long)]
    execute: bool,

    #[arg(long)]
    prove: bool,

    #[arg(long, default_value = "./hex0_src/hex1_AMD64.hex0")]
    input_hex0_file: String,

    #[arg(
        long,
        default_value = "c264a212d2b0e1f1bcf34217ed7876bb9324bd7e29cd902bb1cad4d9f45f1cf8"
    )]
    expected_hash: String,

    #[arg(long)]
    output_proof: String,

    #[arg(long)]
    output_hex1: String,
}

fn main() {
    // Setup the logger.
    sp1_sdk::utils::setup_logger();
    dotenv::dotenv().ok();

    // Parse the command line arguments.
    let args = Args::parse();

    if args.execute == args.prove {
        eprintln!("Error: You must specify either --execute or --prove");
        std::process::exit(1);
    }

    // Setup the prover client.
    let client = ProverClient::from_env();

    // Open the file and read it as bytes
    let input_bytes = std::fs::read(&args.input_hex0_file).expect("failed to read input file");

    // Setup the inputs.
    let mut stdin = SP1Stdin::new();
    let expected_hash_bytes = hex::decode(&args.expected_hash).expect("Invalid hex string");
    let expected_hash: [u8; 32] = expected_hash_bytes
        .try_into()
        .expect("Expected hash must be 32 bytes");

    let inputs = hex0_lib::PublicInputs {
        source_bytes: input_bytes.clone(),
        expected_hash,
    };
    stdin.write(&inputs);

    if args.execute {
        // Execute the program
        let (output, report) = client.execute(HEX0_ELF, &stdin).run().unwrap();
        println!("Program executed successfully.");

        // Record the number of cycles executed.
        println!("Number of cycles: {}", report.total_instruction_count());

        println!("output: {:?}", output);
    } else {
        // Setup the program for proving.
        let (pk, vk) = client.setup(HEX0_ELF);

        // Generate the proof
        let proof = client
            .prove(&pk, &stdin)
            .run()
            .expect("failed to generate proof");

        println!("Successfully generated proof!");

        // Verify the proof.
        client.verify(&proof, &vk).expect("failed to verify proof");
        println!("Successfully verified proof!");

        // Write the proof to a file.
        proof
            .save(&args.output_proof)
            .expect("failed to save proof");

        // Write the hex1 binary to a file
        let hex1 = hex0(&input_bytes);
        let mut hasher = Sha256::new();
        hasher.update(&hex1);
        let hash_array: [u8; 32] = hasher.finalize().into();

        assert_eq!(hash_array, expected_hash, "Hash mismatch!");

        std::fs::write(&args.output_hex1, &hex1).expect("failed to write hex1 output file");

        // Make the hex1 binary executable
        let mut perms = std::fs::metadata(&args.output_hex1)
            .expect("failed to get file metadata")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&args.output_hex1, perms)
            .expect("failed to set executable permissions");

        println!("Wrote hex1 binary to {}", &args.output_hex1);
    }
}
