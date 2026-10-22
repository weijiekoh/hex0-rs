# ZisK StageX benchmark

This separate workspace runs the same StageX step inputs and i386 emulator
under ZisK 1.3.2-alpha. The SP1 project is unchanged.

ZisK limits public values to 256 bytes, so its guest commits the SHA-256 of
the complete `StepClaim`. The host checks that digest against the native,
pinned-hash-checked claim.

Install ZisK 1.3.2-alpha with its CPU proving key, following its
[installation guide](https://0xpolygonhermez.github.io/zisk/getting_started/installation.html).
Then run from this directory:

```sh
cargo build --release --locked --bin stagex-zisk-bench
mkdir -p bench-results

# Execution only. This is ZisK's Rust emulator.
./target/release/stagex-zisk-bench --steps 1,2,3,4,5,6 --repeat 3 \
  --output bench-results/zisk-execute.jsonl

# Prove one small step under a hard memory cap.
systemd-run --user --scope -p MemoryMax=56G -p MemorySwapMax=0 \
  /usr/bin/time -v ./target/release/stagex-zisk-bench --steps 1 --repeat 1 \
  --prove --minimal-memory --witness-threads 8 \
  --output bench-results/zisk-prove-step1.jsonl \
  > bench-results/zisk-prove-step1.stdout \
  2> bench-results/zisk-prove-step1.time
```
