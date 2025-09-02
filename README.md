# hex0-rs

## About

The goal of this repository is to allow anyone to generate a succinct
cryptographic proof that they have executed the `hex0` program such that it
correctly compiles the following:

- [`stage0-posix/AMD64/hex1_AMD64.hex0`](https://github.com/oriansj/stage0-posix-amd64/blob/82efa0d6be1c9bb993a7a62af1cccd8d2cda91f6/hex1_AMD64.hex0) to a `hex1` binary with the SHA256 checksum
  `c264a212d2b0e1f1bcf34217ed7876bb9324bd7e29cd902bb1cad4d9f45f1cf8`

- [`stage0-posix/riscv64/hex1_riscv64.hex0`](https://github.com/oriansj/stage0-posix-riscv64/blob/4688bc66bdfd00efd5964350c9d76bdb90a0f72e/hex1_riscv64.hex0) to a `hex1` binary with the SHA256 checksum
  `2c0037d9455f282d5612c1cf280b6a681a33ee1fd633375276e4a816101a3574`

- [`stage0-posix/riscv32/hex1_riscv32.hex0`](https://github.com/oriansj/stage0-posix-riscv32/blob/261c67274cbc396dc211b06c933335c09cc35138/hex1_riscv32.hex0) to a `hex1` binary with the SHA256 checksum
  `35a66d6ca6fedcb8e37d5e521ea22c7eda5cf5962eb1455a9b34b8861797ed89`

- [`stage0-posix/AArch64/hex1_AArch64.hex0`](https://github.com/oriansj/stage0-posix-aarch64/blob/9015b9e048bd969ffc7884399a17952f21d7a039/hex1_AArch64.hex0) to a `hex1` binary with the SHA256 checksum
  `ddcfc3f0c0e40459180e994eaa121e51d79bbdee7fed17b33287fdbf85b1ce76`

Slightly more formally speaking, the relation we prove is that, given the following public inputs:

- the `.hex0` file as a byte array;
- the expected SHA256 checksum of the output `hex1` byte array

and no private inputs, the program:

- processes the `.hex0` file using the same algorithm that the `hex0`
  binary uses (that is, to convert hexadecimal digits into bytes, and ignore
  whitespace and comments);
- computes the SHA256 hash of the resulting byte array;
- and asserts that the computed SHA256 hash matches the expected SHA256 hash.

The `hex0` binary is originally from [Jeremiah Orians's `bootstrap-seeds`
repository](https://github.com/oriansj/bootstrap-seeds/), but rewritten in
Rust (see `lib/src/lib.rs`).

## Motivation

[Bootstrappable software](https://bootstrappable.org/) ensures that users can
trust not only the software they run, but also that the compilers and
toolchains which build said software is trustworthy. Besides auditing the whole
stack, one must be able to deterministically reproduce every stage of the build
process.

The bootstrapped Linux distribution named [StageX](https://stagex.tools/) uses
this approach. It starts from a minimal *bootstrap seed* called `hex0`,
a very small program that simply converts a hexadecimal string into a binary.
`hex0` is used to compile `hex1`, a slightly more complex program, which is in
turn used to compile `hex2`, and so on, until it reaches modern versions of C
and Rust compilers, as well as other common tools such as Bash and
automake, and even NodeJS.

StageX packages are distributed with SHA256 hashes and signatures from trusted
maintainers. The project provides scripts that allows anyone to fully reproduce
the entire stack and verify that they end up with binaries which match those
which others have attested to. 

The goal of this project is to allow anyone to verify that bootstrapped
software is trustworthy *without having to re-build anything*. Rather, it
should be sufficient to simply verify one or more succinct cryptographic proofs
that some binary was correctly built from its source code, and that each
compiler and tool used to build it were themselves correctly built, all the way
down to the start: the `hex0` binary.

At the time of writing, this project only provides a way to prove that a `hex1`
binary is correctly generated from a `hex0` file (for four different
architectures). The goal of this project is to extend this approach up to the
entire StageX toolchain.

### Limitations

Prover performance will be a severe bottleneck for this project. To mitigate
this, proofs are uncompressed at the cost of proof size. Furthermore, the
author is open to exploring more efficient proof systems as they are developed.

Additionally, the SP1 prover and verifier must be boostrapped so that its
outputs can be trusted. A long-term goal of this project is to do so.

## Quick start

First, install [SP1](https://docs.succinct.xyz/). This project has been tested with: 

```
$ cargo +succinct --version
cargo 1.91.0-nightly (840b83a10 2025-07-30)

$ cargo prove --version
cargo-prove sp1 (3209d54 2025-08-05T20:15:44.228807077Z)
```

Next, run:

```bash
./run.sh
```

The script will compile the `hex0` source files into the `hex1` directory, and
generate SP1 proofs that the compilation was done correctly. The proofs will be
in the `proofs` directory.

<!--
# SP1 Project Template

This is a template for creating an end-to-end [SP1](https://github.com/succinctlabs/sp1) project
that can generate a proof of any RISC-V program.

## Requirements

- [Rust](https://rustup.rs/)
- [SP1](https://docs.succinct.xyz/docs/sp1/getting-started/install)

## Running the Project

There are 3 main ways to run this project: execute a program, generate a core proof, and
generate an EVM-compatible proof.

### Build the Program

The program is automatically built through `script/build.rs` when the script is built.

### Execute the Program

To run the program without generating a proof:

```sh
cd script
cargo run --release -- --execute
```

This will execute the program and display the output.

### Generate an SP1 Core Proof

To generate an SP1 [core proof](https://docs.succinct.xyz/docs/sp1/generating-proofs/proof-types#core-default) for your program:

```sh
cd script
cargo run --release -- --prove
```

### Generate an EVM-Compatible Proof

> [!WARNING]
> You will need at least 16GB RAM to generate a Groth16 or PLONK proof. View the [SP1 docs](https://docs.succinct.xyz/docs/sp1/getting-started/hardware-requirements#local-proving) for more information.

Generating a proof that is cheap to verify on the EVM (e.g. Groth16 or PLONK) is more intensive than generating a core proof.

To generate a Groth16 proof:

```sh
cd script
cargo run --release --bin evm -- --system groth16
```

To generate a PLONK proof:

```sh
cargo run --release --bin evm -- --system plonk
```

These commands will also generate fixtures that can be used to test the verification of SP1 proofs
inside Solidity.

### Retrieve the Verification Key

To retrieve your `programVKey` for your on-chain contract, run the following command in `script`:

```sh
cargo run --release --bin vkey
```

## Using the Prover Network

We highly recommend using the [Succinct Prover Network](https://docs.succinct.xyz/docs/network/introduction) for any non-trivial programs or benchmarking purposes. For more information, see the [key setup guide](https://docs.succinct.xyz/docs/network/developers/key-setup) to get started.

To get started, copy the example environment file:

```sh
cp .env.example .env
```

Then, set the `SP1_PROVER` environment variable to `network` and set the `NETWORK_PRIVATE_KEY`
environment variable to your whitelisted private key.

For example, to generate an EVM-compatible proof using the prover network, run the following
command:

```sh
SP1_PROVER=network NETWORK_PRIVATE_KEY=... cargo run --release --bin evm
```
-->
