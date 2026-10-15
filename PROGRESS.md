# Progress: proving StageX's bootstrap in SP1

The goal is a chain of SP1 proofs covering every step of
[StageX](https://stagex.tools/)'s x86 bootstrap, starting from its 181-byte
`hex0-seed`. Each step runs StageX's real binary in an i386 Linux emulator
inside the zkVM guest (`program-x86`, `lib/src/x86.rs`), and the steps link by
hash (see the README).

## Status

| Stage | StageX package | Steps | Status |
|---|---|---|---|
| 0 | `bootstrap-stage0` | 1–73 | All 73 steps run in the emulator and reproduce StageX's output hashes. |
| 1 | `bootstrap-stage1`, kaem phase | 74–75 of 14 `RUN`s | `checksum-transcriber` and `simple-patch` reproduce live-bootstrap's published x86 checksums. `mes-0.27` is next; see below. |
| 1 | `bootstrap-stage1`, bash phase | – | Not started (tcc, musl, gcc and the rest of live-bootstrap). |
| 2, 3 | `bootstrap-stage2`, `bootstrap-stage3` | – | Not started. |

Stage 1 runs each `pass1.kaem` script as one step: the guest emulates stage 0's
`kaem` and every process it forks and executes, so the proof also covers the
script's interpretation. The step list comes from StageX's stage1
`Containerfile`, vendored verbatim in `stagex/stage1/Containerfile`.

## SP1 cycles per step

Measured with `cargo run --release --bin stagex -- --execute` (SP1 6.9.0, light
executor), which runs every step in the zkVM without proving it. "SP1 cycles"
is the executor's instruction count for the step. Steps were measured in
parallel ranges with `--from`.

The cost is about 56 SP1 cycles per emulated x86 instruction, plus a fixed
15–90M cycles per step for reading, hashing and committing the step's files.
Pending steps can be estimated from their x86 instruction counts on that basis.

| Step | Tool | Output | x86 instructions | SP1 cycles | Approx. |
|---:|---|---|---:|---:|---:|
| 1 | `/hex0-seed` | `hex0` | 130,316 | 18,620,270 | 18.62M |
| 2 | `hex0` | `kaem-minimal` | 395,783 | 38,077,424 | 38.08M |
| 3 | `hex0` | `hex1` | 234,905 | 26,711,382 | 26.71M |
| 4 | `hex1` | `hex2-0` | 1,247,916 | 88,101,215 | 88.10M |
| 5 | `hex2-0` | `catm` | 410,213 | 49,070,613 | 49.07M |
| 6 | `catm` | `M0.hex2` | 78 | 15,411,259 | 15.41M |
| 7 | `hex2-0` | `M0` | 3,203,550 | 221,972,545 | 221.97M |
| 8 | `M0` | `cc_x86-0.hex2` | 39,351,099 | 2,064,070,950 | 2.06B |
| 9 | `catm` | `cc_x86-1.hex2` | 78 | 15,874,116 | 15.87M |
| 10 | `hex2-0` | `cc_x86` | 9,642,181 | 644,726,931 | 644.73M |
| 11 | `catm` | `M2-0.c` | 286 | 22,728,216 | 22.73M |
| 12 | `cc_x86` | `M2-0.M1` | 139,938,001 | 7,900,972,427 | 7.90B |
| 13 | `catm` | `M2-0-0.M1` | 120 | 89,586,781 | 89.59M |
| 14 | `M0` | `M2-0.hex2` | 238,029,358 | 12,712,127,312 | 12.71B |
| 15 | `catm` | `M2-0-0.hex2` | 78 | 44,656,808 | 44.66M |
| 16 | `hex2-0` | `M2` | 484,854,746 | 28,405,301,643 | 28.41B |
| 17 | `M2` | `blood-elf-0.M1` | 891,500,857 | 49,312,087,637 | 49.31B |
| 18 | `catm` | `blood-elf-0-0.M1` | 104 | 22,715,517 | 22.72M |
| 19 | `M0` | `blood-elf-0.hex2` | 34,179,100 | 1,817,368,981 | 1.82B |
| 20 | `catm` | `blood-elf-0-0.hex2` | 78 | 16,234,140 | 16.23M |
| 21 | `hex2-0` | `blood-elf-0` | 10,296,422 | 679,499,197 | 679.50M |
| 22 | `M2` | `M1-macro-0.M1` | 1,223,195,661 | pending | ≈68.51B |
| 23 | `blood-elf-0` | `M1-macro-0-footer.M1` | 132,874,960 | pending | ≈7.46B |
| 24 | `catm` | `M1-macro-0-0.M1` | 130 | pending | ≈15.01M |
| 25 | `M0` | `M1-macro-0.hex2` | 62,749,641 | pending | ≈3.53B |
| 26 | `catm` | `M1-macro-0-0.hex2` | 78 | pending | ≈15.00M |
| 27 | `hex2-0` | `M1-0` | 76,702,142 | pending | ≈4.31B |
| 28 | `M2` | `hex2_linker-0.M1` | 2,282,630,400 | pending | ≈127.84B |
| 29 | `blood-elf-0` | `hex2_linker-0-footer.M1` | 218,847,343 | pending | ≈12.27B |
| 30 | `M1-0` | `hex2_linker-0.hex2` | 283,338,732 | pending | ≈15.88B |
| 31 | `catm` | `hex2_linker-0-0.hex2` | 78 | pending | ≈15.00M |
| 32 | `hex2-0` | `hex2-1` | 195,068,850 | pending | ≈10.94B |
| 33 | `M2` | `M1-macro-1.M1` | 2,347,720,731 | pending | ≈131.49B |
| 34 | `blood-elf-0` | `M1-macro-1-footer.M1` | 216,142,676 | pending | ≈12.12B |
| 35 | `M1-0` | `M1-macro-1.hex2` | 282,050,671 | pending | ≈15.81B |
| 36 | `hex2-1` | `M1` | 545,150,735 | pending | ≈30.54B |
| 37 | `M2` | `hex2_linker-2.M1` | 2,282,630,400 | pending | ≈127.84B |
| 38 | `blood-elf-0` | `hex2_linker-2-footer.M1` | 218,847,343 | pending | ≈12.27B |
| 39 | `M1` | `hex2_linker-2.hex2` | 370,351,528 | pending | ≈20.75B |
| 40 | `hex2-1` | `hex2` | 540,161,547 | pending | ≈30.26B |
| 41 | `M2` | `kaem.M1` | 2,718,298,532 | pending | ≈152.24B |
| 42 | `blood-elf-0` | `kaem-footer.M1` | 249,867,291 | pending | ≈14.01B |
| 43 | `M1` | `kaem.hex2` | 423,083,374 | pending | ≈23.71B |
| 44 | `hex2` | `kaem` | 633,704,122 | pending | ≈35.50B |
| 45 | `M2` | `M2-Mesoplanet-1.M1` | 3,974,368,244 | pending | ≈222.58B |
| 46 | `blood-elf-0` | `M2-Mesoplanet-1-footer.M1` | 411,682,698 | pending | ≈23.07B |
| 47 | `M1` | `M2-Mesoplanet-1.hex2` | 684,481,107 | pending | ≈38.35B |
| 48 | `hex2` | `M2-Mesoplanet` | 1,025,006,370 | pending | ≈57.42B |
| 49 | `M2` | `blood-elf-1.M1` | 1,752,331,822 | pending | ≈98.15B |
| 50 | `blood-elf-0` | `blood-elf-1-footer.M1` | 155,267,722 | pending | ≈8.71B |
| 51 | `M1` | `blood-elf-1.hex2` | 272,228,272 | pending | ≈15.26B |
| 52 | `hex2` | `blood-elf` | 394,831,981 | pending | ≈22.13B |
| 53 | `M2` | `get_machine.M1` | 1,280,718,415 | pending | ≈71.74B |
| 54 | `blood-elf` | `get_machine-footer.M1` | 134,524,911 | pending | ≈7.55B |
| 55 | `M1` | `get_machine.hex2` | 192,462,060 | pending | ≈10.79B |
| 56 | `hex2` | `get_machine` | 274,284,486 | 15,150,708,294 | 15.15B |
| 57 | `M2` | `M2-1.M1` | 7,077,060,437 | pending | ≈396.33B |
| 58 | `blood-elf` | `M2-1-footer.M1` | 1,243,228,530 | pending | ≈69.64B |
| 59 | `M1` | `M2-1.hex2` | 1,638,519,703 | pending | ≈91.77B |
| 60 | `hex2` | `M2-Planet` | 2,654,152,216 | pending | ≈148.65B |
| 61 | `M2-Mesoplanet` | `sha256sum` | 3,174,870,274 | pending | ≈177.81B |
| 62 | `M2-Mesoplanet` | `match` | 2,321,973,292 | pending | ≈130.05B |
| 63 | `M2-Mesoplanet` | `mkdir` | 2,430,912,713 | pending | ≈136.15B |
| 64 | `M2-Mesoplanet` | `untar` | 2,931,922,087 | pending | ≈164.20B |
| 65 | `M2-Mesoplanet` | `ungz` | 3,896,891,828 | pending | ≈218.24B |
| 66 | `M2-Mesoplanet` | `unbz2` | 3,899,043,400 | pending | ≈218.36B |
| 67 | `M2-Mesoplanet` | `unxz` | 6,871,392,382 | pending | ≈384.81B |
| 68 | `M2-Mesoplanet` | `catm` | 1,675,162,579 | pending | ≈93.82B |
| 69 | `M2-Mesoplanet` | `cp` | 2,753,254,164 | pending | ≈154.20B |
| 70 | `M2-Mesoplanet` | `chmod` | 2,449,909,464 | pending | ≈137.21B |
| 71 | `M2-Mesoplanet` | `rm` | 2,322,351,056 | pending | ≈130.07B |
| 72 | `M2-Mesoplanet` | `replace` | 2,561,935,809 | pending | ≈143.48B |
| 73 | `M2-Mesoplanet` | `wrap` | 2,675,895,849 | pending | ≈149.87B |
| 74 | `kaem checksum-transcriber-1.0/pass1.kaem` | `/usr/bin/checksum-transcriber` | 2,590,889,074 | pending | ≈145.10B |
| 75 | `kaem simple-patch-1.0/pass1.kaem` | `/usr/bin/simple-patch` | 2,610,092,094 | pending | ≈146.18B |

**Total:** 85,488,477,273 x86 instructions (85.49B) over 75 steps; 22 steps measured at 119.36B SP1 cycles; all 75 steps ≈4.79T SP1 cycles including estimates.


Steps 1–73 were measured with the guest at commit `4e7558c`. Steps 74–75 need
the stage1 support added in `85d598c`, whose guest also commits each step's
working directory, links and created directories, and checks that a new
file's directory exists. That guest is up to 3% slower on steps 1–7 (for
example, step 4 takes 90.2M cycles instead of 88.1M).

## Next: `mes-0.27` (stage1 step 76)

live-bootstrap's `mes-0.27/pass1.kaem` unpacks Mes and nyacc with `ungz` and
`untar`, builds `mes-m2` with M2-Planet, regenerates nyacc's parser tables with
`mes-m2`, then compiles Mes's C library with `mescc` running on `mes-m2`.
The emulator now supports what it needs so far (directories, symbolic links,
`chdir`, `getcwd`, and `clock_gettime`, which reads zero) and gets through
building and running `mes-m2`. A native run of the whole step in the emulator is in progress.

The step is much larger than any stage0 step: `mes-m2` is a Scheme
interpreter compiled by M2-Planet, and the step runs it once per file of
Mes's C library. Options for making it practical to prove:

- Split the step at process boundaries: prove each `mescc` invocation as its
  own step, and prove `kaem`'s interpretation of the script separately.
- Lower the per-instruction cost further (dispatch accounts for about half of
  it), or translate hot x86 blocks to RISC-V ahead of time.

## Caveats

- No proofs were generated in this orb: it runs SP1's executor only. Use
  `--prove` on a machine with enough memory for the prover, or the prover
  network.
- Execute mode sets `GAS_TRACE_CHUNK_THRESHOLD=4194304` unless it is already
  set, because SP1's default needs a 4.7 GB `/dev/shm`. It does not change
  cycle counts.
- The emulator does not model the parity and auxiliary-carry flags, and
  panics on any instruction, system call or memory access outside its model,
  so no proof can be made for a run it does not support.
- Forked children run to completion before their parents continue, which
  matches every parent here, since they only wait for their children.
- Opening a file for writing does not look up whether its path is a
  symbolic link from an earlier step. A step that wrote through such a link
  would claim the wrong output path and fail the output hash check.
- The step list stops at stage1's kaem phase. Its bash phase (bash, GNU make,
  pipes) has not been tried in the emulator.
