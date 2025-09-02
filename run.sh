#! /bin/env bash

mkdir -p proofs
mkdir -p hex1

cargo run --release -- --prove \
    --output-proof proofs/hex1_AMD64.proof \
    --input-hex0-file ./hex0_src/hex1_AMD64.hex0 \
    --expected-hash c264a212d2b0e1f1bcf34217ed7876bb9324bd7e29cd902bb1cad4d9f45f1cf8 \
    --output-hex1 hex1/hex1_AMD64.hex1

cargo run --release -- --prove \
    --output-proof proofs/hex1_riscv32.proof \
    --input-hex0-file ./hex0_src/hex1_riscv32.hex0 \
    --expected-hash 35a66d6ca6fedcb8e37d5e521ea22c7eda5cf5962eb1455a9b34b8861797ed89 \
    --output-hex1 hex1/hex1_riscv32.hex1

cargo run --release -- --prove \
    --output-proof proofs/hex1_riscv64.proof \
    --input-hex0-file ./hex0_src/hex1_riscv64.hex0 \
    --expected-hash 2c0037d9455f282d5612c1cf280b6a681a33ee1fd633375276e4a816101a3574 \
    --output-hex1 hex1/hex1_riscv64.hex1

cargo run --release -- --prove \
    --output-proof proofs/hex1_x86.proof \
    --input-hex0-file ./hex0_src/hex1_x86.hex0 \
    --expected-hash 30da8f019c21e71d9ea60b374272209956256958d21f698c0b757c8fa560c9cf \
    --output-hex1 hex1/hex1_x86.hex1
