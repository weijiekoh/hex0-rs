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
| 1 | `bootstrap-stage1`, kaem phase | Steps 74–75: first 2 of 14 `RUN`s | `checksum-transcriber` and `simple-patch` reproduce live-bootstrap's published x86 checksums. `mes-0.27` is next; see below. |
| 1 | `bootstrap-stage1`, bash phase | – | Not started (tcc, musl, gcc and the rest of live-bootstrap). |
| 2, 3 | `bootstrap-stage2`, `bootstrap-stage3` | – | Not started. |

Stage 1 runs each `pass1.kaem` script as one step: the guest emulates stage 0's
`kaem` and every process it forks and executes, so the proof also covers the
script's interpretation. The step list comes from StageX's stage1
`Containerfile`, vendored verbatim in `stagex/stage1/Containerfile`.

## SP1 cycles per step (historical range runs)

Measured with `cargo run --release --bin stagex -- --execute` (SP1 6.9.0, light
executor), which runs every step in the zkVM without proving it. "SP1 cycles"
is the executor's instruction count for the step. Steps were measured in
parallel ranges with `--from`.

The original cost was about 56 SP1 cycles per emulated x86 instruction, plus a fixed
15–90M cycles per step for reading, hashing and committing the step's files.
Pending estimates below use that original guest. The optimization results
below compare exact guests separately; this table is retained as historical
evidence, not mixed with new-guest measurements.

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
| 22 | `M2` | `M1-macro-0.M1` | 1,223,195,661 | 67,630,294,007 | 67.63B |
| 23 | `blood-elf-0` | `M1-macro-0-footer.M1` | 132,874,960 | 7,078,939,935 | 7.08B |
| 24 | `catm` | `M1-macro-0-0.M1` | 130 | 32,378,929 | 32.38M |
| 25 | `M0` | `M1-macro-0.hex2` | 62,749,641 | 3,373,308,062 | 3.37B |
| 26 | `catm` | `M1-macro-0-0.hex2` | 78 | 21,728,164 | 21.73M |
| 27 | `hex2-0` | `M1-0` | 76,702,142 | 4,442,650,102 | 4.44B |
| 28 | `M2` | `hex2_linker-0.M1` | 2,282,630,400 | 126,115,163,296 | 126.12B |
| 29 | `blood-elf-0` | `hex2_linker-0-footer.M1` | 218,847,343 | 11,645,341,137 | 11.65B |
| 30 | `M1-0` | `hex2_linker-0.hex2` | 283,338,732 | 15,972,374,888 | 15.97B |
| 31 | `catm` | `hex2_linker-0-0.hex2` | 78 | 28,239,794 | 28.24M |
| 32 | `hex2-0` | `hex2-1` | 195,068,850 | 11,105,957,170 | 11.11B |
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
| 66 | `M2-Mesoplanet` | `unbz2` | 3,899,043,400 | 215,337,593,384 | 215.34B |
| 67 | `M2-Mesoplanet` | `unxz` | 6,871,392,382 | pending | ≈384.81B |
| 68 | `M2-Mesoplanet` | `catm` | 1,675,162,579 | pending | ≈93.82B |
| 69 | `M2-Mesoplanet` | `cp` | 2,753,254,164 | pending | ≈154.20B |
| 70 | `M2-Mesoplanet` | `chmod` | 2,449,909,464 | pending | ≈137.21B |
| 71 | `M2-Mesoplanet` | `rm` | 2,322,351,056 | pending | ≈130.07B |
| 72 | `M2-Mesoplanet` | `replace` | 2,561,935,809 | pending | ≈143.48B |
| 73 | `M2-Mesoplanet` | `wrap` | 2,675,895,849 | pending | ≈149.87B |
| 74 | `kaem checksum-transcriber-1.0/pass1.kaem` | `/usr/bin/checksum-transcriber` | 2,590,889,074 | 143,565,283,070 | 143.57B |
| 75 | `kaem simple-patch-1.0/pass1.kaem` | `/usr/bin/simple-patch` | 2,610,092,094 | pending | ≈146.18B |

**Total:** 85,488,477,273 x86 instructions (85.49B) over 75 steps; 35 steps measured at 725.71B SP1 cycles in the range runs; all 75 steps ≈4.8T SP1 cycles including estimates.

The recorded range measurements of stage0 use the guest at commit
[`4e7558c`](https://github.com/weijiekoh/hex0-rs/commit/4e7558c).
Steps 74–75 need the stage1 support added in
[`85d598c`](https://github.com/weijiekoh/hex0-rs/commit/85d598c), whose guest also commits each step's
working directory, links and created directories, and checks that a new
file's directory exists. That guest is up to 3% slower on steps 1–7 (for
example, step 4 takes 90.2M cycles instead of 88.1M).

## Isolated orb baseline (2026-10-16)

This is an **execution and guest-cycle profiling baseline**, not a proving
throughput measurement or a benchmark of a ThinkPad. The four background
cycle-measurement jobs and the Mes job were frozen during measurement to
avoid CPU contention, and all five jobs were resumed afterward. The orb
exposes four logical CPUs (two cores, SMT) of
an Intel Xeon at 2.60 GHz, 7.8 GiB physical RAM and a **6 GiB workload cgroup
limit**, with no swap. `RAYON_NUM_THREADS=4` was fixed.

The guest was rebuilt from the current working tree, including the pending
Mes `sal`/`ioctl` support, without any new emulator optimization. This is a
different guest from the earlier range runs above; do not compare their
cycle counts as an optimization result. Source snapshots and the exact ELF
are saved with the benchmark harness.

| Step | Work | Trials | SP1 cycles per trial | Normalized gas | Median execute time | Execute time range |
|---:|---|---:|---:|---:|---:|---:|
| 1 | seed → hex0 | 3 | 18,905,462 | 32,320,104 | 0.357 s | 0.338–0.380 s |
| 6 | catm → M0.hex2 | 3 | 15,421,039 | 48,074,548 | 0.329 s | 0.323–0.367 s |
| 8 | M0 → cc_x86-0.hex2 | 3 | 2,085,215,511 | 1,946,817,228 | 21.095 s | 20.732–21.438 s |
| 17 | M2 → blood-elf-0.M1 | 1 | 49,322,020,830 | 44,882,925,680 | 496.541 s | — (one run) |

Every trial exited successfully and its complete public claim matched the
native run, whose outputs were checked against the pinned chain hashes.
Timing includes the SDK execution call and gas calculation, but excludes
compilation, native input discovery and client initialization. The cycles
and gas were identical across repetitions. Execution uses SP1 6.9.0's light
prover and native executor. `GAS_TRACE_CHUNK_THRESHOLD=4194304` and
`GAS_TRACE_CHUNK_SLOTS=2` were fixed: chunk size does not affect instruction
cycles, but **does affect gas** through memory-boundary accounting. Gas must
not be compared with default-chunk measurements as if the settings matched.

### Guest profiles and optimization priorities

The same ELF was profiled once per step with the SDK's `profiling` feature
and `TRACE_SAMPLE_RATE=1000`. Profiling uses the portable executor, so its
wall times are not execution baselines. These are sampled **guest-cycle**
shares, not host CPU or prover profiles; inclusive percentages overlap.

| Step | Samples | Main observations |
|---:|---:|---|
| 1 | 18,906 | `run_process` self 37.06%; `memset` self 25.41%; decoder table initialization inclusive 21.64%. |
| 6 | 15,422 | `memset` self 34.06%, `memcpy` self 21.74%; decoder table initialization inclusive 26.55%. |
| 8 | 2,085,216 | `run_process` self 93.83%; syscalls inclusive 4.02%; `read_slow` self 1.37%; `decode_new` inclusive 0.23%. |

For reducing the total cost of the large bootstrap steps, prioritize
experiments on the hot interpreter loop and its inlined instruction/memory
handlers. **The 93.83% is not a measurement of dispatch alone**: the compiler
inlines substantial handler work into that function. A finer attribution or
controlled A/B implementation is needed before predicting a speedup.
The earlier direct-op-linking experiment regressed step 8 and is not grounds
for assuming that a new dispatch layout will help.

Reducing allocation/zeroing/copying and decoder startup is the clearer,
lower-risk target for the small steps, but decoder startup alone cannot
materially improve step 8 (all of `decode_new` is only 0.23%). Changes must
retain exact x86 execution and file/hash checks; no host-supplied outputs or
unverified predecoded instruction streams should replace those checks.

### CPU core-proof attempt

A real, explicit CPU prover (not mock or network proving) was attempted for
step 1. Its service had a **3 GiB memory cap** to leave room within the 6 GiB
workload limit for Amp and the frozen jobs. Smaller trace chunks/shards and
single core/setup/splicing workers were configured; exact settings are in
the reproduction instructions. It was killed for exceeding memory during
`initializing cpu prover`, before setup returned or proof generation began.
The service automatically retried twice before it was stopped; the journal
records the OOM failures. **No proof, verification result, or proving-time
baseline was obtained.** This establishes failure under the allocated cap,
not that the workload cannot be proved with more memory or another setup.

### Reproduction and evidence

Artifacts are under `.amp/in/artifacts/baseline/`: `execution.jsonl` and
`execution-large.jsonl`, `execution-summary.csv`, `profile-execution.jsonl`,
`profile-functions.csv`, `profiles.tar.gz` (Gecko profiles), execution logs,
and `proof-attempt-journal.txt`. `reproduce.tar.gz` contains the harness,
lockfile, library snapshot, guest ELF and reproduction instructions (also
saved separately as `REPRODUCE.md`). Run it from the repository root so the
pinned StageX inputs are found. None of these measurements uses new emulator
optimizations.

- Guest ELF SHA-256: `d3a0b65fd3b41e640bbd9a53aa315b8a42744fc24b187ac4a177e7cb9599bbb1`.
- `lib/src/x86.rs` SHA-256: `dbd33701c3afe922acabcd227091ca2174c88c3f2fae0c46f50c43f4cf582713`.
- `lib/src/stagex.rs` SHA-256: `51a5a649201f3ee3b7f83cfce7858f5d1805171cc2278d44b3d1a1503fcde6ba`.

## Emulator optimizations — 2026-10-16

The RV64 guest still executes the same pinned i386 programs, including their
file I/O. No output, syscall result or predecoded instruction stream is
substituted by unverified host computation. These measurements compare the
exact baseline above against the optimized guest, with matching gas settings.
Do not compare them directly with the earlier historical range runs.

### Retained changes

- Widen decoded-cache offset arithmetic before subtraction, avoiding RV64
  truncation/zero-extension in every interpreter iteration. Out-of-image
  addresses still miss the cache.
- Keep the entire 8 MiB stack mapped, but share an immutable zero backing
  page for untouched pages. Allocate private pages on first write. This
  avoids eager zeroing and reduces fork's physical memory copy without
  changing stack size, memory permissions or parent/child isolation.
- Specialize JE/JNE and common base-plus-displacement MOV/MOVZX loads.
  Complex addressing retains its existing checked path; cached instructions
  are still invalidated when their code bytes change.
- Omit iced-x86's VEX, EVEX, XOP and 3DNow decoder tables. The emulator did
  not support those instruction families; supported legacy decoding remains.

An out-of-line generic-executor experiment slightly increased cycles and
was rejected. `experiments.csv` records the incremental experiments.

### Before/after execution costs

| Step | Output | Baseline SP1 cycles | Optimized SP1 cycles | Reduction | Baseline normalized gas | Optimized normalized gas | Reduction |
|---:|---|---:|---:|---:|---:|---:|---:|
| 1 | `hex0` | 18,905,462 | 11,949,887 | 36.79% | 32,320,104 | 15,594,878 | 51.75% |
| 6 | `M0.hex2` | 15,421,039 | 6,693,109 | 56.60% | 48,074,548 | 15,850,927 | 67.03% |
| 8 | `cc_x86-0.hex2` | 2,085,215,511 | 1,882,412,249 | 9.73% | 1,946,817,228 | 1,696,105,667 | 12.88% |
| 17 | `blood-elf-0.M1` | 49,322,020,830 | 46,123,377,109 | 6.49% | 44,882,925,680 | 40,975,823,513 | 8.71% |

All measured claims match the pinned-hash-checked native claims. Emulated
x86 instruction counts are unchanged: 130,316; 78; 39,351,099; and
891,500,857 respectively. Steps 1, 6 and 8 were each repeated three times;
cycles and gas were identical across repeats. Step 17 was measured once.

Isolated median SDK execution times on this orb, with the five background
bootstrap jobs frozen and no concurrent test/build:

| Step | Baseline seconds | Optimized seconds | Reduction |
|---:|---:|---:|---:|
| 1 | 0.356618 | 0.335293 | 5.98% |
| 6 | 0.328540 | 0.213091 | 35.14% |
| 8 | 21.095358 | 20.332980 | 3.61% |

These are three-sample medians, not statistically established speedups or
proving times. Step 17's optimized wall time overlapped a native full-chain
test and is not used for a timing comparison. All five background jobs were
resumed after the isolated measurements. No new proof was attempted: the
baseline prover-initialization memory failure remains unresolved. Cycle and
gas reductions are cost proxies, not a measured proving-time reduction.

### Validation and reproduction

- `cargo test --release -p hex0-lib`: 4 passed, 1 ignored.
- `cargo test --release -p hex0-lib stagex_chain_full -- --ignored --nocapture`:
  passed after a clean package rebuild in 386.64 s; all 75 implemented steps
  retain their output hashes.
- A retained public-interface regression checks untouched stack zeros,
  independent pages, a cross-page word, and fork isolation. A scratch mutant
  that lets direct stores overwrite the shared zero page fails this test.
- Additional scratch diagnostics passed on both original and optimized
  emulators: stack boundaries and unmapped neighbors, read-only protection,
  syscall reads spanning untouched pages, negative displacements/high-byte
  register aliasing, and self-modifying cached code invalidation.

Evidence is in `.amp/in/artifacts/optimization/`, including raw execution
JSONL, comparison CSV, test logs, experiment results, source hashes and
`REPRODUCE.md`. `reproduce.tar.gz` contains the harness, locked dependencies,
exact optimized ELF and library snapshot. The snapshot includes the same
pending Mes SAL/ioctl support as the baseline; it is kept separate from the
optimization-only patch.

- Optimized guest ELF SHA-256: `58fe0a31a31a818bb28495ac86cd2bcd232a006b8ba4222f2a5e99fa4fd64e84`.
- Optimized `lib/src/x86.rs` SHA-256: `ac2992b11a3e3cb69378cf7d0af6032bd296e5f9acace55deabc0357a87d3a31`.

## Interpreter optimizations — batch 2

Native instruction profiles identified common repeated sequences. The
guest now caches a few of these sequences as one decoded operation, while
executing every original x86 instruction's effects and counting each one.
Fusion is restricted to bytes from the instruction fetch and to spans wholly
inside the cached ELF image. Code that continues onto stack or heap pages
uses the original instruction path.

Retained changes:

- CMP/TEST followed by JE/JNE, with the comparison's complete flags.
- POP followed by POP or RET, and immediate/base-load MOV followed by POP.
  ESP and destination aliases retain sequential x86 semantics.
- CMP register, SETcc byte register and MOVZX from that byte into its full
  register. This is fused only when the MOVZX overwrites the SETcc byte.
- Simple base-plus-displacement LEA, pre-scaled register offsets and a
  64-byte decoded-instruction stride. The larger arena avoids slower RV64
  index arithmetic.

| Step | Batch 1 cycles | Batch 2 cycles | Reduction | Batch 1 normalized gas | Batch 2 normalized gas | Reduction | Total cycle reduction from baseline |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 11,949,887 | 11,272,875 | 5.67% | 15,594,878 | 14,916,969 | 4.35% | 40.37% |
| 6 | 6,693,109 | 6,695,122 | -0.03% | 15,850,927 | 15,851,586 | -0.00% | 56.58% |
| 8 | 1,882,412,249 | 1,668,036,134 | 11.39% | 1,696,105,667 | 1,473,421,574 | 13.13% | 20.01% |
| 17 | 46,123,377,109 | 39,126,680,122 | **15.17%** | 40,975,823,513 | 33,818,575,984 | **17.47%** | **20.67%** |

Step 6 is a 78-instruction `catm` control and is essentially flat. All
public claims and emulated x86 instruction counts are unchanged.
Steps 1, 6 and 8 were repeated three times with identical cycles and gas.
Their isolated median execution times were 0.277975 s, 0.209899 s and
17.184692 s: respectively 17.09%, 1.50% and 15.48% below batch 1. These are
three-sample medians on this orb, not proving times. Step 17 was measured
once while native validation ran, so its wall time is not compared.

Validation:

- `cargo test --release -p hex0-lib`: 6 passed, 1 ignored.
- `cargo test --release -p hex0-lib stagex_chain_full -- --ignored --nocapture`:
  passed in 317.18 s after the final boundary guard.
- Generated i386 checks cover 6,272 CMP/SETcc/MOVZX cases and 280
  comparison/branch cases. Expected values come from integer relations,
  not emulator helpers. They cover all modeled conditions, high/low byte
  registers, overflow, taken/untaken branches and 15-byte fetch boundaries.
  The checks pass on actual Linux i386, the pre-batch emulator, and the
  final native emulator and SP1 guest.
- Additional fixtures cover cross-page branch modification, entering the
  second instruction directly, nonmatching boolean conversions, LEA
  wrapping, POP ESP and MOV/POP aliases. A scratch mutant that marks only
  the first instruction's page as code fails the retained regression test.
- An image-to-stack boundary fixture found a candidate-only panic. The
  boundary guard fixed it; the original emulator, final native emulator and
  SP1 guest pass it, and a regression test now covers it.

No new proof was attempted; the earlier prover-initialization memory limit
is unchanged. Cycle and gas reductions are cost proxies, not measured
proving-time reductions. Evidence and reproduction instructions are in
`.amp/in/artifacts/optimization-2/`.

- Final guest ELF SHA-256: `7d5b57c6742cf908e2047d80735345915646930b55b4abc1f1b4c475fc47a662`.
- Final measured `lib/src/x86.rs` SHA-256: `a88bfdd85b3e1d6d38ee9f6957557676e30193e641dcdf87f5e2ef82a4a5e255`.

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
- Lower the per-instruction cost further, or translate hot x86 blocks to
  RISC-V ahead of time. The current profile puts most large-step cycles in
  the interpreter loop, but does not isolate dispatch from inlined handlers.

## Caveats

- No proofs have been successfully generated in this orb. The bounded CPU
  attempt above failed during prover initialization. Use `--prove` on a
  machine with enough memory for the prover, or the prover network.
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
