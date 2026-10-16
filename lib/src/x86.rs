//! A minimal i386 Linux user-mode emulator, sufficient to run the stage0-posix
//! x86 bootstrap binaries.
//!
//! It runs inside the zkVM, so everything a real kernel would do is modelled
//! here: the ELF loader, the initial process stack, and the system calls, which
//! operate on an in-memory filesystem. Anything outside the modelled subset of
//! the CPU or the kernel panics, so a proof can only exist for runs that stay
//! within it.

use iced_x86::{Decoder, DecoderOptions, Instruction, MemorySize, Mnemonic, OpKind, Register};
use std::collections::BTreeMap;

const PAGE: u32 = 0x1000;
const STACK_TOP: u32 = 0xC000_0000;
const STACK_SIZE: u32 = 0x80_0000;
/// The heap may grow up to this far below the stack.
const HEAP_LIMIT: u32 = 0x8000_0000;

const EAX: usize = 0;
const EDX: usize = 2;
const ESP: usize = 4;

const O_WRONLY_CREAT_TRUNC: u32 = 0o1101;
const O_RDWR_CREAT_EXCL: u32 = 0o302;
const ENOENT: i32 = 2;
const EEXIST: i32 = 17;
const ENOTDIR: i32 = 20;
const ERANGE: i32 = 34;

/// What exists at a path outside the files a program has created.
pub enum Entry {
    File(Vec<u8>),
    Dir,
    /// A symbolic link, with its target as written.
    Link(String),
    Missing,
}

/// The result of running a program to completion.
pub struct Exit {
    /// The exit status, as the parent process would see it.
    pub code: u32,
    /// Every path looked up through `lookup` and what was found there, in
    /// order, by canonical path.
    pub lookups: Vec<(String, Entry)>,
    /// Files the programs created and did not delete, by canonical path.
    pub created: BTreeMap<String, Vec<u8>>,
    /// Directories the programs created, by canonical path.
    pub dirs: Vec<String>,
    /// Symbolic links the programs created, by canonical path, with their
    /// targets.
    pub links: Vec<(String, String)>,
    /// Number of x86 instructions executed, across all processes.
    pub instructions: u64,
}

/// Page table entry flags. An entry is the page's offset in `Machine::mem`
/// with these flags in its low bits, or 0 if the page is unmapped.
const MAPPED: u32 = 1;
const WRITABLE: u32 = 2;
/// The page holds bytes of cached decoded instructions, so writes to it must
/// invalidate them.
const CODE: u32 = 4;
/// An untouched stack page shares immutable zero backing until its first write.
const ZERO: u32 = 8;
const FLAGS: u32 = PAGE - 1;
const PAGES: usize = 1 << 20;

/// An operand with its registers and size already resolved.
#[derive(Clone, Copy)]
enum Arg {
    None,
    Reg {
        index: u8,
        shift: u8,
    },
    /// `[base + index << scale + disp]`, where a register number of 8 means
    /// none.
    Mem {
        base: u8,
        index: u8,
        scale: u8,
        disp: u32,
    },
    Imm(u32),
    Branch(u32),
}

/// A decoded instruction in the form the executor uses.
/// A power-of-two stride keeps RV64 arena indexing to a single shift.
#[derive(Clone, Copy)]
#[repr(align(64))]
struct Op {
    mnemonic: Mnemonic,
    next_ip: u32,
    count: u8,
    sizes: [u8; 3],
    args: [Arg; 3],
    fast: Fast,
}

/// A condition of `jcc` and `setcc`.
#[derive(Clone, Copy)]
enum Cond {
    O,
    No,
    B,
    Ae,
    E,
    Ne,
    Be,
    A,
    S,
    Ns,
    L,
    Ge,
    Le,
    G,
}

impl Cond {
    fn of(m: Mnemonic) -> Option<Cond> {
        use Mnemonic::*;
        Some(match m {
            Jo | Seto => Cond::O,
            Jno | Setno => Cond::No,
            Jb | Setb => Cond::B,
            Jae | Setae => Cond::Ae,
            Je | Sete => Cond::E,
            Jne | Setne => Cond::Ne,
            Jbe | Setbe => Cond::Be,
            Ja | Seta => Cond::A,
            Js | Sets => Cond::S,
            Jns | Setns => Cond::Ns,
            Jl | Setl => Cond::L,
            Jge | Setge => Cond::Ge,
            Jle | Setle => Cond::Le,
            Jg | Setg => Cond::G,
            _ => return None,
        })
    }
}

/// Specialized forms of the most frequently executed instructions. Registers
/// are byte offsets (0, 4, ..., 28) into `regs`, with a shift for byte operands,
/// so execution need not scale register indices. Complex memory operands stay
/// in `Op::args`. Every other instruction is `Generic`.
#[derive(Clone, Copy)]
enum Fast {
    Generic,
    MovRR(u8, u8),
    MovRI(u8, u32),
    MovRM(u8),
    MovRMBase(u8, u8, u32),
    MovRIPop(u8, u32, u8),
    MovRMBasePop(u8, u8, u32, u8),
    MovMR(u8),
    MovB8M(u8, u8),
    MovB8MBase(u8, u8, u8, u32),
    MovMB8(u8, u8),
    MovzxRB8(u8, u8, u8),
    MovzxRM8(u8),
    MovzxRM8Base(u8, u8, u32),
    Lea(u8),
    LeaBase(u8, u8, u32),
    PushR(u8),
    PopR(u8),
    Pop2(u8, u8),
    PopRet(u8),
    AddRI(u8, u32),
    AddRR(u8, u8),
    SubRI(u8, u32),
    SubRR(u8, u8),
    CmpRI(u8, u32),
    CmpRR(u8, u8),
    TestRR(u8, u8),
    CmpB8B8(u8, u8, u8, u8),
    CmpB8I(u8, u8, u32),
    CmpRIJump(u8, u32, u32, bool),
    CmpRRJump(u8, u8, u32, bool),
    CmpB8B8Jump(u8, u8, u8, u8, u32, bool),
    CmpB8IJump(u8, u8, u32, u32, bool),
    TestRRJump(u8, u8, u32, bool),
    CmpRRBool(u8, u8, Cond, u8),
    Je(u32),
    Jne(u32),
    Jcc(Cond, u32),
    Jmp(u32),
    Call(u32),
    Ret,
    Setcc(Cond, u8, u8),
}

impl Op {
    fn mnemonic(&self) -> Mnemonic {
        self.mnemonic
    }

    fn op_count(&self) -> u32 {
        self.count as u32
    }

    fn fast_form(&self) -> Fast {
        use Mnemonic::*;
        // A full 32-bit register operand.
        let r = |i: usize| match (self.args[i], self.sizes[i]) {
            (Arg::Reg { index, shift: 0 }, 4) => Some(index * 4),
            _ => None,
        };
        // A byte register operand.
        let b = |i: usize| match (self.args[i], self.sizes[i]) {
            (Arg::Reg { index, shift }, 1) => Some((index * 4, shift)),
            _ => None,
        };
        let m =
            |i: usize, size: u8| matches!(self.args[i], Arg::Mem { .. }) && self.sizes[i] == size;
        let simple_mem = |i: usize| match self.args[i] {
            Arg::Mem {
                base,
                index: 8,
                disp,
                ..
            } if base < 8 => Some((base * 4, disp)),
            _ => None,
        };
        let imm = |i: usize| match self.args[i] {
            Arg::Imm(v) => Some(v),
            _ => None,
        };
        let branch = match self.args[0] {
            Arg::Branch(t) => Some(t),
            _ => None,
        };
        let n = self.count;
        match self.mnemonic {
            Mov if n == 2 => match (r(0), r(1), imm(1), b(0), b(1)) {
                (Some(d), Some(s), ..) => Fast::MovRR(d, s),
                (Some(d), _, Some(v), ..) => Fast::MovRI(d, v),
                (Some(d), ..) if m(1, 4) => simple_mem(1).map_or(Fast::MovRM(d), |(base, disp)| {
                    Fast::MovRMBase(d, base, disp)
                }),
                (_, Some(s), ..) if m(0, 4) => Fast::MovMR(s),
                (_, _, _, Some((i, sh)), _) if m(1, 1) => simple_mem(1)
                    .map_or(Fast::MovB8M(i, sh), |(base, disp)| {
                        Fast::MovB8MBase(i, sh, base, disp)
                    }),
                (_, _, _, _, Some((i, sh))) if m(0, 1) => Fast::MovMB8(i, sh),
                _ => Fast::Generic,
            },
            Movzx => match (r(0), b(1)) {
                (Some(d), Some((i, sh))) => Fast::MovzxRB8(d, i, sh),
                (Some(d), _) if m(1, 1) => simple_mem(1)
                    .map_or(Fast::MovzxRM8(d), |(base, disp)| {
                        Fast::MovzxRM8Base(d, base, disp)
                    }),
                _ => Fast::Generic,
            },
            Lea => r(0).map_or(Fast::Generic, |d| {
                simple_mem(1).map_or(Fast::Lea(d), |(base, disp)| Fast::LeaBase(d, base, disp))
            }),
            Push if n == 1 => r(0).map_or(Fast::Generic, Fast::PushR),
            Pop => r(0).map_or(Fast::Generic, Fast::PopR),
            Add | Sub | Cmp | Test => match (self.mnemonic, r(0), r(1), imm(1)) {
                (Add, Some(d), Some(s), _) => Fast::AddRR(d, s),
                (Add, Some(d), _, Some(v)) => Fast::AddRI(d, v),
                (Sub, Some(d), Some(s), _) => Fast::SubRR(d, s),
                (Sub, Some(d), _, Some(v)) => Fast::SubRI(d, v),
                (Cmp, Some(d), Some(s), _) => Fast::CmpRR(d, s),
                (Cmp, Some(d), _, Some(v)) => Fast::CmpRI(d, v),
                (Test, Some(d), Some(s), _) => Fast::TestRR(d, s),
                (Cmp, None, None, _) => match (b(0), b(1), imm(1)) {
                    (Some((i, sh)), Some((j, sh2)), _) => Fast::CmpB8B8(i, sh, j, sh2),
                    (Some((i, sh)), _, Some(v)) => Fast::CmpB8I(i, sh, v),
                    _ => Fast::Generic,
                },
                _ => Fast::Generic,
            },
            Jmp => branch.map_or(Fast::Generic, Fast::Jmp),
            Call => branch.map_or(Fast::Generic, Fast::Call),
            Ret if n == 0 => Fast::Ret,
            m => match (Cond::of(m), branch, b(0)) {
                (Some(Cond::E), Some(t), _) => Fast::Je(t),
                (Some(Cond::Ne), Some(t), _) => Fast::Jne(t),
                (Some(c), Some(t), _) => Fast::Jcc(c, t),
                (Some(c), None, Some((i, sh))) => Fast::Setcc(c, i, sh),
                _ => Fast::Generic,
            },
        }
    }

    fn translate(ins: &Instruction) -> Op {
        let count = ins.op_count().min(3);
        let mut op = Op {
            mnemonic: ins.mnemonic(),
            next_ip: ins.next_ip32(),
            count: count as u8,
            sizes: [0; 3],
            args: [Arg::None; 3],
            fast: Fast::Generic,
        };
        for i in 0..count {
            let (arg, size) = match ins.op_kind(i) {
                OpKind::Register => {
                    let (index, size, shift) = reg_info(ins.op_register(i));
                    (
                        Arg::Reg {
                            index: index as u8,
                            shift: shift as u8,
                        },
                        size,
                    )
                }
                OpKind::Memory => {
                    assert!(
                        matches!(
                            ins.memory_segment(),
                            Register::DS | Register::SS | Register::ES
                        ),
                        "unsupported segment {:?}",
                        ins.memory_segment()
                    );
                    let reg = |r: Register| match r {
                        Register::None => 8,
                        r => {
                            let (index, size, _) = reg_info(r);
                            assert_eq!(size, 4, "unsupported address register {r:?}");
                            index as u8
                        }
                    };
                    let arg = Arg::Mem {
                        base: reg(ins.memory_base()),
                        index: reg(ins.memory_index()),
                        scale: ins.memory_index_scale().trailing_zeros() as u8,
                        disp: ins.memory_displacement32(),
                    };
                    let size = if ins.mnemonic() == Mnemonic::Lea {
                        4
                    } else {
                        mem_size(ins.memory_size())
                    };
                    (arg, size)
                }
                OpKind::Immediate8
                | OpKind::Immediate16
                | OpKind::Immediate32
                | OpKind::Immediate8to16
                | OpKind::Immediate8to32 => {
                    // An immediate takes the size of the first operand.
                    let size = if i == 0 { 4 } else { op.sizes[0] as u32 };
                    (Arg::Imm(ins.immediate(i) as u32 & mask(size)), size)
                }
                OpKind::NearBranch32 => (Arg::Branch(ins.near_branch32()), 4),
                k => panic!("unsupported operand kind {k:?}"),
            };
            op.args[i as usize] = arg;
            op.sizes[i as usize] = size as u8;
        }
        op.fast = op.fast_form();
        op
    }
}

struct File {
    path: String,
    data: Vec<u8>,
    created: bool,
    /// Unlinked files stay readable through open file descriptors.
    deleted: bool,
}

#[derive(Clone)]
struct OpenFile {
    file: usize,
    pos: usize,
    readable: bool,
    writable: bool,
}

/// State shared by all processes: the filesystem and exit statuses.
struct Kernel<'a> {
    lookup: &'a mut dyn FnMut(&str) -> Entry,
    lookups: Vec<(String, Entry)>,
    files: Vec<File>,
    /// Directories the programs created.
    dirs: Vec<String>,
    /// Symbolic links the programs created and did not delete, with their
    /// targets.
    links: Vec<(String, String)>,
    exited: BTreeMap<u32, u32>,
    next_pid: u32,
}

/// What the run loop must do after an instruction.
enum Step {
    Next,
    Exit(u32),
    Fork,
    Exec(Box<Machine>),
}

/// A process.
#[derive(Clone)]
struct Machine {
    /// The bytes of every mapped page, as little-endian words so that
    /// aligned 32-bit accesses take one load or store.
    mem: Vec<u32>,
    /// The page table, with an entry for each 4 KiB page.
    pages: Box<[u32; PAGES]>,
    /// Offsets in `mem` of pages unmapped by shrinking the heap.
    free: Vec<u32>,
    /// For the ELF image, the decoded instruction at each offset from
    /// `code_start`, as an index into the op arena plus one, or 0.
    code_start: u32,
    decoded: Vec<u32>,
    /// The program break starts at `brk_start` and may lie inside a page.
    brk_start: u32,
    brk: u32,
    cwd: String,
    regs: [u32; 8],
    eip: u32,
    cf: bool,
    zf: bool,
    sf: bool,
    of: bool,
    fds: Vec<Option<OpenFile>>,
}

/// Runs a static i386 Linux ELF with the given argv and environment in the
/// working directory `cwd`. When a program refers to a path it has not
/// created, `lookup` is called with the canonical path.
pub fn run(
    elf: &[u8],
    argv: &[String],
    env: &[String],
    cwd: &str,
    lookup: &mut dyn FnMut(&str) -> Entry,
) -> Exit {
    let mut k = Kernel {
        lookup,
        lookups: Vec::new(),
        files: Vec::new(),
        dirs: Vec::new(),
        links: Vec::new(),
        exited: BTreeMap::new(),
        next_pid: 2,
    };
    let mut instructions = 0u64;
    let code = run_process(
        Machine::load(elf, argv, env, cwd),
        &mut k,
        &mut instructions,
    );
    let created = k
        .files
        .into_iter()
        .filter(|f| f.created && !f.deleted)
        .map(|f| (f.path, f.data))
        .collect();
    Exit {
        code,
        lookups: k.lookups,
        created,
        dirs: k.dirs,
        links: k.links,
        instructions,
    }
}

/// Runs a process until it exits and returns its exit status. A forked
/// child runs to completion before its parent continues, which is a valid
/// schedule for parents that only wait for their children.
fn run_process(mut m: Machine, k: &mut Kernel, instructions: &mut u64) -> u32 {
    // Decoded instructions live outside the machine so that executing one
    // borrows it instead of copying it.
    let mut ops = Vec::new();
    // Counted locally, since the count would otherwise be stored on every
    // instruction.
    let mut count = 0;
    loop {
        let index = m.decode(&mut ops);
        let op = &ops[index];
        m.eip = op.next_ip;
        count += 1;
        if m.execute_fast(op, &mut count) {
            continue;
        }
        match m.execute(op, k) {
            Step::Next => {}
            Step::Exit(code) => {
                *instructions += count;
                return code & 0xff;
            }
            Step::Fork => {
                let pid = k.next_pid;
                k.next_pid += 1;
                let mut child = m.clone();
                child.regs[EAX] = 0;
                // The child has its own op arena.
                child.decoded.fill(0);
                *instructions += std::mem::take(&mut count);
                let code = run_process(child, k, instructions);
                k.exited.insert(pid, code);
                m.regs[EAX] = pid;
            }
            Step::Exec(image) => {
                m = *image;
                ops.clear();
            }
        }
    }
}

/// Resolves `path` against `cwd`, removing `.` and `..` components.
pub fn canonical(cwd: &str, path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    let full = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("{cwd}/{path}")
    };
    for part in full.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            p => parts.push(p),
        }
    }
    format!("/{}", parts.join("/"))
}

fn u16_at(b: &[u8], off: usize) -> u32 {
    u16::from_le_bytes(b[off..off + 2].try_into().unwrap()) as u32
}

fn u32_at(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
}

fn mask(size: u32) -> u32 {
    if size == 4 {
        u32::MAX
    } else {
        (1 << (8 * size)) - 1
    }
}

fn msb(size: u32) -> u32 {
    1 << (8 * size - 1)
}

/// Returns (register index, size in bytes, bit shift) for a general purpose
/// register.
fn reg_info(r: Register) -> (usize, u32, u32) {
    use Register::*;
    match r {
        EAX => (0, 4, 0),
        ECX => (1, 4, 0),
        EDX => (2, 4, 0),
        EBX => (3, 4, 0),
        ESP => (4, 4, 0),
        EBP => (5, 4, 0),
        ESI => (6, 4, 0),
        EDI => (7, 4, 0),
        AX => (0, 2, 0),
        CX => (1, 2, 0),
        DX => (2, 2, 0),
        BX => (3, 2, 0),
        SP => (4, 2, 0),
        BP => (5, 2, 0),
        SI => (6, 2, 0),
        DI => (7, 2, 0),
        AL => (0, 1, 0),
        CL => (1, 1, 0),
        DL => (2, 1, 0),
        BL => (3, 1, 0),
        AH => (0, 1, 8),
        CH => (1, 1, 8),
        DH => (2, 1, 8),
        BH => (3, 1, 8),
        _ => panic!("unsupported register {r:?}"),
    }
}

fn mem_size(ms: MemorySize) -> u32 {
    match ms {
        MemorySize::UInt8 | MemorySize::Int8 => 1,
        MemorySize::UInt16 | MemorySize::Int16 | MemorySize::WordOffset => 2,
        MemorySize::UInt32 | MemorySize::Int32 | MemorySize::DwordOffset => 4,
        _ => panic!("unsupported memory operand size {ms:?}"),
    }
}

impl Machine {
    /// Loads the ELF and sets up the initial process state the way Linux does
    /// for a static i386 executable.
    fn load(elf: &[u8], argv: &[String], env: &[String], cwd: &str) -> Machine {
        assert!(
            elf.len() >= 0x34 && elf[..4] == *b"\x7fELF",
            "not an ELF file"
        );
        assert_eq!(elf[4], 1, "not a 32-bit ELF");
        assert_eq!(elf[5], 1, "not a little-endian ELF");
        assert_eq!(u16_at(elf, 0x10), 2, "not an executable");
        assert_eq!(u16_at(elf, 0x12), 3, "not an i386 ELF");
        let entry = u32_at(elf, 0x18);
        let phoff = u32_at(elf, 0x1c) as usize;
        assert_eq!(u16_at(elf, 0x2a), 32, "unexpected program header size");
        let phnum = u16_at(elf, 0x2c) as usize;

        let mut m = Machine {
            mem: Vec::with_capacity(elf.len() / 4 + PAGE as usize),
            pages: vec![0; PAGES].into_boxed_slice().try_into().unwrap(),
            free: Vec::new(),
            code_start: u32::MAX,
            decoded: Vec::new(),
            brk_start: 0,
            brk: 0,
            cwd: cwd.to_string(),
            regs: [0; 8],
            eip: entry,
            cf: false,
            zf: false,
            sf: false,
            of: false,
            fds: Vec::new(),
        };
        let mut image_end = 0;
        for i in 0..phnum {
            let ph = &elf[phoff + 32 * i..phoff + 32 * (i + 1)];
            let (p_type, offset, vaddr) = (u32_at(ph, 0), u32_at(ph, 4), u32_at(ph, 8));
            let (filesz, memsz, flags) = (u32_at(ph, 16), u32_at(ph, 20), u32_at(ph, 24));
            match p_type {
                1 => {}                      // PT_LOAD
                4 | 0x6474_e551 => continue, // PT_NOTE, PT_GNU_STACK
                _ => panic!("unsupported program header type {p_type:#x}"),
            }
            assert_eq!(vaddr % PAGE, offset % PAGE, "misaligned segment");
            assert!(filesz <= memsz, "segment filesz exceeds memsz");
            // Linux maps whole pages: the file pages covering the segment
            // (bytes past the end of the file read as zero), followed by
            // zeroed anonymous memory up to memsz.
            let start = vaddr - vaddr % PAGE;
            let file_end = (vaddr + filesz).next_multiple_of(PAGE);
            let end = vaddr
                .checked_add(memsz)
                .and_then(|e| e.checked_next_multiple_of(PAGE))
                .filter(|e| *e <= STACK_TOP - STACK_SIZE)
                .expect("segment outside the user address space");
            let writable = if flags & 2 != 0 { WRITABLE } else { 0 };
            for page in start / PAGE..end / PAGE {
                m.map(page, writable);
            }
            let file_off = (offset - offset % PAGE) as usize;
            let n = (file_end - start).min(elf.len().saturating_sub(file_off) as u32) as usize;
            let mut data = elf[file_off..file_off + n].to_vec();
            if memsz > filesz {
                data.truncate((vaddr + filesz - start) as usize);
            }
            for (k, chunk) in data.chunks(PAGE as usize).enumerate() {
                let o = (m.pages[(start / PAGE) as usize + k] & !FLAGS) as usize;
                for (i, b) in chunk.iter().enumerate() {
                    m.set_byte(o + i, *b);
                }
            }
            m.code_start = m.code_start.min(start);
            image_end = image_end.max(end);
        }
        m.decoded = vec![0; (image_end - m.code_start) as usize];
        // The program break starts at the page after the image.
        m.brk_start = image_end;
        m.brk = image_end;
        // Keep the full stack mapped, but back its untouched pages with one
        // immutable zero page. Writes materialize a private page below.
        let stack = ((STACK_TOP - STACK_SIZE) / PAGE) as usize..(STACK_TOP / PAGE) as usize;
        m.map(stack.start as u32, WRITABLE | ZERO);
        let zero = m.pages[stack.start];
        m.pages[stack].fill(zero);

        // Initial stack: argc, argv pointers, NULL, environment pointers,
        // NULL and an auxiliary vector holding only AT_NULL. All registers
        // start at 0.
        let mut sp = STACK_TOP;
        let mut ptrs = Vec::new();
        for s in argv.iter().chain(env).rev() {
            sp -= s.len() as u32 + 1;
            m.write_bytes(sp, s.as_bytes());
            m.write(sp + s.len() as u32, 1, 0);
            ptrs.push(sp);
        }
        ptrs.reverse();
        let mut words = vec![argv.len() as u32];
        words.extend(&ptrs[..argv.len()]);
        words.push(0);
        words.extend(&ptrs[argv.len()..]);
        words.extend([0, 0, 0]);
        sp = (sp - 4 * words.len() as u32) & !15;
        for (i, w) in words.iter().enumerate() {
            m.write(sp + 4 * i as u32, 4, *w);
        }
        m.regs[ESP] = sp;
        m
    }

    /// Maps a zeroed page.
    fn map(&mut self, page: u32, flags: u32) {
        assert_eq!(self.pages[page as usize], 0, "overlapping mappings");
        let off = match self.free.pop() {
            Some(off) => {
                self.mem[(off / 4) as usize..((off + PAGE) / 4) as usize].fill(0);
                off
            }
            None => {
                let off = self.mem.len();
                self.mem.resize(off + (PAGE / 4) as usize, 0);
                (off * 4) as u32
            }
        };
        self.pages[page as usize] = off | MAPPED | flags;
    }

    fn unmap(&mut self, page: u32) {
        self.free.push(self.pages[page as usize] & !FLAGS);
        self.pages[page as usize] = 0;
    }

    #[inline(always)]
    fn read(&self, addr: u32, size: u32) -> u32 {
        // Aligned words and bytes never cross a page boundary.
        let e = self.pages[(addr / PAGE) as usize];
        let o = ((e & !FLAGS) | (addr & FLAGS)) as usize;
        match size {
            4 if e & MAPPED != 0 && addr % 4 == 0 => self.mem[o / 4],
            1 if e & MAPPED != 0 => self.byte(o) as u32,
            _ => self.read_slow(addr, size),
        }
    }

    /// The byte at offset `o` of `mem`.
    #[inline(always)]
    fn byte(&self, o: usize) -> u8 {
        (self.mem[o / 4] >> (o % 4 * 8)) as u8
    }

    #[inline(always)]
    fn set_byte(&mut self, o: usize, b: u8) {
        let shift = o % 4 * 8;
        let w = &mut self.mem[o / 4];
        *w = (*w & !(0xff << shift)) | ((b as u32) << shift);
    }

    /// Reads a value one byte at a time, or panics on unmapped memory.
    #[cold]
    #[inline(never)]
    fn read_slow(&self, addr: u32, size: u32) -> u32 {
        (0..size).rev().fold(0, |v, i| {
            let a = addr.wrapping_add(i);
            let e = self.pages[(a / PAGE) as usize];
            assert!(e & MAPPED != 0, "access to unmapped memory at {a:#x}");
            (v << 8) | self.byte(((e & !FLAGS) + (a & FLAGS)) as usize) as u32
        })
    }

    #[inline(always)]
    fn write(&mut self, addr: u32, size: u32, val: u32) {
        let e = self.pages[(addr / PAGE) as usize];
        let o = ((e & !FLAGS) | (addr & FLAGS)) as usize;
        let plain = e & (MAPPED | WRITABLE | CODE | ZERO) == MAPPED | WRITABLE;
        match size {
            4 if plain && addr % 4 == 0 => self.mem[o / 4] = val,
            1 if plain => self.set_byte(o, val as u8),
            _ => self.write_slow(addr, &val.to_le_bytes()[..size as usize]),
        }
    }

    /// Writes bytes one at a time, invalidating decoded instructions they
    /// overlap and materializing shared zero pages on demand. Panics on
    /// unmapped or read-only memory.
    #[cold]
    #[inline(never)]
    fn write_slow(&mut self, addr: u32, bytes: &[u8]) {
        for (i, b) in bytes.iter().enumerate() {
            let a = addr.wrapping_add(i as u32);
            let page = (a / PAGE) as usize;
            let mut e = self.pages[page];
            assert!(e & MAPPED != 0, "access to unmapped memory at {a:#x}");
            assert!(e & WRITABLE != 0, "write to read-only memory at {a:#x}");
            if e & ZERO != 0 {
                self.pages[page] = 0;
                self.map(page as u32, e & (WRITABLE | CODE));
                e = self.pages[page];
            }
            self.set_byte(((e & !FLAGS) + (a & FLAGS)) as usize, *b);
            if e & CODE != 0 {
                // An x86 instruction is at most 15 bytes long.
                let off = (a - self.code_start) as usize;
                let hi = off.min(self.decoded.len() - 1);
                self.decoded[off.saturating_sub(14)..=hi].fill(0);
            }
        }
    }

    fn read_bytes(&self, addr: u32, len: u32) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(len as usize);
        while bytes.len() < len as usize {
            let a = addr.wrapping_add(bytes.len() as u32);
            let e = self.pages[(a / PAGE) as usize];
            assert!(e & MAPPED != 0, "access to unmapped memory at {a:#x}");
            let n = (len as usize - bytes.len()).min((PAGE - (a & FLAGS)) as usize);
            let o = ((e & !FLAGS) + (a & FLAGS)) as usize;
            bytes.extend((o..o + n).map(|o| self.byte(o)));
        }
        bytes
    }

    fn write_bytes(&mut self, addr: u32, bytes: &[u8]) {
        let mut done = 0;
        while done < bytes.len() {
            let a = addr.wrapping_add(done as u32);
            let e = self.pages[(a / PAGE) as usize];
            let n = (bytes.len() - done).min((PAGE - (a & FLAGS)) as usize);
            if e & (MAPPED | WRITABLE | CODE | ZERO) == MAPPED | WRITABLE {
                let o = ((e & !FLAGS) + (a & FLAGS)) as usize;
                for (i, b) in bytes[done..done + n].iter().enumerate() {
                    self.set_byte(o + i, *b);
                }
            } else {
                self.write_slow(a, &bytes[done..done + n]);
            }
            done += n;
        }
    }

    /// Returns the index in `ops` of the instruction at eip, decoding it if
    /// it is not cached.
    #[inline(always)]
    fn decode(&mut self, ops: &mut Vec<Op>) -> usize {
        // Out-of-image addresses miss the cache either way. Widen first so
        // RV64 need not truncate and zero-extend the difference on every step.
        let off = (self.eip as usize).wrapping_sub(self.code_start as usize);
        if let Some(&n) = self.decoded.get(off) {
            if n != 0 {
                return n as usize - 1;
            }
        }
        self.decode_new(ops)
    }

    #[cold]
    #[inline(never)]
    fn decode_new(&mut self, ops: &mut Vec<Op>) -> usize {
        let mut code = [0u8; 15];
        let mut len = 0;
        while len < 15
            && self.pages[(self.eip.wrapping_add(len as u32) / PAGE) as usize] & MAPPED != 0
        {
            code[len] = self.read(self.eip.wrapping_add(len as u32), 1) as u8;
            len += 1;
        }
        assert!(len > 0, "access to unmapped memory at {:#x}", self.eip);
        let ins =
            Decoder::with_ip(32, &code[..len], self.eip as u64, DecoderOptions::NONE).decode();
        assert!(!ins.is_invalid(), "invalid instruction at {:#x}", self.eip);
        assert!(
            !ins.has_lock_prefix() && !ins.has_rep_prefix() && !ins.has_repne_prefix(),
            "unsupported prefix at {:#x}",
            self.eip
        );
        let mut op = Op::translate(&ins);
        // These comparisons, register MOVs/loads and POPs cannot write code
        // or transfer control.
        // Fuse selected successors only within the same 15-byte fetch: the
        // existing invalidation window then covers every constituent's bytes.
        if matches!(
            op.fast,
            Fast::CmpRI(..)
                | Fast::CmpRR(..)
                | Fast::CmpB8B8(..)
                | Fast::CmpB8I(..)
                | Fast::TestRR(..)
                | Fast::PopR(..)
                | Fast::MovRI(..)
                | Fast::MovRMBase(..)
        ) {
            let next = Decoder::with_ip(
                32,
                &code[ins.len()..len],
                ins.next_ip(),
                DecoderOptions::NONE,
            )
            .decode();
            if !next.is_invalid()
                && !next.has_lock_prefix()
                && !next.has_rep_prefix()
                && !next.has_repne_prefix()
            {
                let mut end_ip = next.next_ip32();
                let fused = if next.op0_kind() == OpKind::NearBranch32
                    && matches!(next.mnemonic(), Mnemonic::Je | Mnemonic::Jne)
                {
                    let target = next.near_branch32();
                    let equal = next.mnemonic() == Mnemonic::Je;
                    match op.fast {
                        Fast::CmpRI(d, v) => Some(Fast::CmpRIJump(d, v, target, equal)),
                        Fast::CmpRR(d, s) => Some(Fast::CmpRRJump(d, s, target, equal)),
                        Fast::CmpB8B8(i, sh, j, sh2) => {
                            Some(Fast::CmpB8B8Jump(i, sh, j, sh2, target, equal))
                        }
                        Fast::CmpB8I(i, sh, v) => Some(Fast::CmpB8IJump(i, sh, v, target, equal)),
                        Fast::TestRR(d, s) => Some(Fast::TestRRJump(d, s, target, equal)),
                        _ => None,
                    }
                } else if next.mnemonic() == Mnemonic::Pop
                    && matches!(
                        next.op0_register(),
                        Register::EAX
                            | Register::ECX
                            | Register::EDX
                            | Register::EBX
                            | Register::ESP
                            | Register::EBP
                            | Register::ESI
                            | Register::EDI
                    )
                {
                    match (op.fast, Op::translate(&next).fast) {
                        (Fast::PopR(d), Fast::PopR(s)) => Some(Fast::Pop2(d, s)),
                        (Fast::MovRI(d, v), Fast::PopR(s)) => Some(Fast::MovRIPop(d, v, s)),
                        (Fast::MovRMBase(d, base, disp), Fast::PopR(s)) => {
                            Some(Fast::MovRMBasePop(d, base, disp, s))
                        }
                        _ => None,
                    }
                } else if let Fast::PopR(d) = op.fast {
                    (next.mnemonic() == Mnemonic::Ret && next.op_count() == 0)
                        .then_some(Fast::PopRet(d))
                } else if let Fast::CmpRR(a, b) = op.fast {
                    if Cond::of(next.mnemonic()).is_some() && next.op0_kind() == OpKind::Register {
                        let after = Decoder::with_ip(
                            32,
                            &code[ins.len() + next.len()..len],
                            next.next_ip(),
                            DecoderOptions::NONE,
                        )
                        .decode();
                        if !after.is_invalid()
                            && !after.has_lock_prefix()
                            && !after.has_rep_prefix()
                            && !after.has_repne_prefix()
                            && after.mnemonic() == Mnemonic::Movzx
                            && after.op0_kind() == OpKind::Register
                            && after.op1_kind() == OpKind::Register
                        {
                            match (Op::translate(&next).fast, Op::translate(&after).fast) {
                                (Fast::Setcc(c, d, sh), Fast::MovzxRB8(out, from, from_sh))
                                    if d == out && d == from && sh == from_sh =>
                                {
                                    // SETcc's byte write is completely overwritten
                                    // by MOVZX to the same full register.
                                    end_ip = after.next_ip32();
                                    Some(Fast::CmpRRBool(a, b, c, out))
                                }
                                _ => None,
                            }
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    None
                };
                // Non-image pages are not covered by the decoded cache's
                // invalidation range; do not extend cached spans onto them.
                if let Some(fast) = fused
                    .filter(|_| end_ip.wrapping_sub(self.code_start) as usize <= self.decoded.len())
                {
                    op.fast = fast;
                    op.next_ip = end_ip;
                }
            }
        }
        ops.push(op);
        let off = self.eip.wrapping_sub(self.code_start) as usize;
        if off < self.decoded.len() {
            self.decoded[off] = ops.len() as u32;
            for a in [self.eip, op.next_ip.wrapping_sub(1)] {
                self.pages[(a / PAGE) as usize] |= CODE;
            }
        }
        ops.len() - 1
    }

    fn addr(&self, arg: Arg) -> u32 {
        let Arg::Mem {
            base,
            index,
            scale,
            disp,
        } = arg
        else {
            unreachable!()
        };
        let mut a = disp;
        if base < 8 {
            a = a.wrapping_add(self.regs[base as usize]);
        }
        if index < 8 {
            a = a.wrapping_add(self.regs[index as usize] << scale);
        }
        a
    }

    /// The address of the instruction's memory operand.
    fn ea(&self, ins: &Op) -> u32 {
        let arg = ins
            .args
            .into_iter()
            .find(|a| matches!(a, Arg::Mem { .. }))
            .unwrap();
        self.addr(arg)
    }

    fn op_size(&self, ins: &Op, i: u32) -> u32 {
        ins.sizes[i as usize] as u32
    }

    fn read_op(&self, ins: &Op, i: u32, size: u32) -> u32 {
        match ins.args[i as usize] {
            Arg::Reg { index, shift } => (self.regs[index as usize] >> shift) & mask(size),
            arg @ Arg::Mem { .. } => self.read(self.addr(arg), size),
            Arg::Imm(v) => v & mask(size),
            _ => panic!("unsupported operand"),
        }
    }

    fn write_op(&mut self, ins: &Op, i: u32, size: u32, v: u32) {
        match ins.args[i as usize] {
            Arg::Reg { index, shift } => {
                let m = mask(size) << shift;
                let r = &mut self.regs[index as usize];
                *r = (*r & !m) | ((v << shift) & m);
            }
            arg @ Arg::Mem { .. } => self.write(self.addr(arg), size, v),
            _ => panic!("unsupported operand"),
        }
    }

    fn set_zs(&mut self, res: u32, size: u32) {
        self.zf = res & mask(size) == 0;
        self.sf = res & msb(size) != 0;
    }

    fn push(&mut self, v: u32) {
        self.regs[ESP] = self.regs[ESP].wrapping_sub(4);
        self.write(self.regs[ESP], 4, v);
    }

    fn pop(&mut self) -> u32 {
        let v = self.read(self.regs[ESP], 4);
        self.regs[ESP] = self.regs[ESP].wrapping_add(4);
        v
    }

    /// Evaluates the condition of a `jcc` or `setcc` instruction.
    fn condition(&self, m: Mnemonic) -> bool {
        use Mnemonic::*;
        match m {
            Jo | Seto => self.of,
            Jno | Setno => !self.of,
            Jb | Setb => self.cf,
            Jae | Setae => !self.cf,
            Je | Sete => self.zf,
            Jne | Setne => !self.zf,
            Jbe | Setbe => self.cf || self.zf,
            Ja | Seta => !self.cf && !self.zf,
            Js | Sets => self.sf,
            Jns | Setns => !self.sf,
            Jl | Setl => self.sf != self.of,
            Jge | Setge => self.sf == self.of,
            Jle | Setle => self.zf || self.sf != self.of,
            Jg | Setg => !self.zf && self.sf == self.of,
            _ => unreachable!(),
        }
    }

    /// The target of a near `call` or `jmp`: relative, register or memory.
    fn branch_target(&self, ins: &Op) -> u32 {
        match ins.args[0] {
            Arg::Branch(target) => target,
            _ => {
                assert_eq!(self.op_size(ins, 0), 4, "unsupported branch size");
                self.read_op(ins, 0, 4)
            }
        }
    }

    #[inline(always)]
    fn cond(&self, c: Cond) -> bool {
        match c {
            Cond::O => self.of,
            Cond::No => !self.of,
            Cond::B => self.cf,
            Cond::Ae => !self.cf,
            Cond::E => self.zf,
            Cond::Ne => !self.zf,
            Cond::Be => self.cf || self.zf,
            Cond::A => !self.cf && !self.zf,
            Cond::S => self.sf,
            Cond::Ns => !self.sf,
            Cond::L => self.sf != self.of,
            Cond::Ge => self.sf == self.of,
            Cond::Le => self.zf || self.sf != self.of,
            Cond::G => !self.zf && self.sf == self.of,
        }
    }

    #[inline(always)]
    fn add_flags(&mut self, a: u32, b: u32, size: u32) -> u32 {
        let res = a.wrapping_add(b) & mask(size);
        self.cf = res < a;
        self.of = (a ^ res) & (b ^ res) & msb(size) != 0;
        self.set_zs(res, size);
        res
    }

    #[inline(always)]
    fn sub_flags(&mut self, a: u32, b: u32, size: u32) -> u32 {
        let res = a.wrapping_sub(b) & mask(size);
        self.cf = a < b;
        self.of = (a ^ b) & (a ^ res) & msb(size) != 0;
        self.set_zs(res, size);
        res
    }

    #[inline(always)]
    fn byte_reg(&self, offset: u8, shift: u8) -> u32 {
        (self.regs[((offset & 28) / 4) as usize] >> shift) & 0xff
    }

    #[inline(always)]
    fn set_byte_reg(&mut self, offset: u8, shift: u8, v: u32) {
        let r = &mut self.regs[((offset & 28) / 4) as usize];
        *r = (*r & !(0xff << shift)) | ((v & 0xff) << shift);
    }

    /// Executes the instruction if it has a specialized form, with the same
    /// semantics as `execute`. Fused pairs also count their second instruction.
    /// Returns false for generic instructions.
    #[inline(always)]
    fn execute_fast(&mut self, op: &Op, count: &mut u64) -> bool {
        let r = |offset: u8| ((offset & 28) / 4) as usize;
        match op.fast {
            Fast::Generic => return false,
            Fast::MovRR(d, s) => self.regs[r(d)] = self.regs[r(s)],
            Fast::MovRI(d, v) => self.regs[r(d)] = v,
            Fast::MovRM(d) => self.regs[r(d)] = self.read(self.addr(op.args[1]), 4),
            Fast::MovRMBase(d, base, disp) => {
                self.regs[r(d)] = self.read(self.regs[r(base)].wrapping_add(disp), 4);
            }
            Fast::MovRIPop(d, v, s) => {
                self.regs[r(d)] = v;
                let v = self.pop();
                self.regs[r(s)] = v;
                *count += 1;
            }
            Fast::MovRMBasePop(d, base, disp, s) => {
                self.regs[r(d)] = self.read(self.regs[r(base)].wrapping_add(disp), 4);
                let v = self.pop();
                self.regs[r(s)] = v;
                *count += 1;
            }
            Fast::MovMR(s) => self.write(self.addr(op.args[0]), 4, self.regs[r(s)]),
            Fast::MovB8M(i, sh) => {
                let v = self.read(self.addr(op.args[1]), 1);
                self.set_byte_reg(i, sh, v);
            }
            Fast::MovB8MBase(i, sh, base, disp) => {
                let v = self.read(self.regs[r(base)].wrapping_add(disp), 1);
                self.set_byte_reg(i, sh, v);
            }
            Fast::MovMB8(i, sh) => self.write(self.addr(op.args[0]), 1, self.byte_reg(i, sh)),
            Fast::MovzxRB8(d, i, sh) => self.regs[r(d)] = self.byte_reg(i, sh),
            Fast::MovzxRM8(d) => self.regs[r(d)] = self.read(self.addr(op.args[1]), 1),
            Fast::MovzxRM8Base(d, base, disp) => {
                self.regs[r(d)] = self.read(self.regs[r(base)].wrapping_add(disp), 1);
            }
            Fast::Lea(d) => self.regs[r(d)] = self.addr(op.args[1]),
            Fast::LeaBase(d, base, disp) => {
                self.regs[r(d)] = self.regs[r(base)].wrapping_add(disp);
            }
            Fast::PushR(s) => self.push(self.regs[r(s)]),
            Fast::PopR(d) => {
                // `pop esp` loads the value read at the old esp.
                let v = self.pop();
                self.regs[r(d)] = v;
            }
            Fast::Pop2(d, s) => {
                let v = self.pop();
                self.regs[r(d)] = v;
                let v = self.pop();
                self.regs[r(s)] = v;
                *count += 1;
            }
            Fast::PopRet(d) => {
                let v = self.pop();
                self.regs[r(d)] = v;
                self.eip = self.pop();
                *count += 1;
            }
            Fast::AddRI(d, v) => self.regs[r(d)] = self.add_flags(self.regs[r(d)], v, 4),
            Fast::AddRR(d, s) => {
                self.regs[r(d)] = self.add_flags(self.regs[r(d)], self.regs[r(s)], 4)
            }
            Fast::SubRI(d, v) => self.regs[r(d)] = self.sub_flags(self.regs[r(d)], v, 4),
            Fast::SubRR(d, s) => {
                self.regs[r(d)] = self.sub_flags(self.regs[r(d)], self.regs[r(s)], 4)
            }
            Fast::CmpRI(d, v) => {
                self.sub_flags(self.regs[r(d)], v, 4);
            }
            Fast::CmpRR(d, s) => {
                self.sub_flags(self.regs[r(d)], self.regs[r(s)], 4);
            }
            Fast::TestRR(d, s) => {
                self.cf = false;
                self.of = false;
                self.set_zs(self.regs[r(d)] & self.regs[r(s)], 4);
            }
            Fast::CmpB8B8(i, sh, j, sh2) => {
                self.sub_flags(self.byte_reg(i, sh), self.byte_reg(j, sh2), 1);
            }
            Fast::CmpB8I(i, sh, v) => {
                self.sub_flags(self.byte_reg(i, sh), v, 1);
            }
            Fast::CmpRIJump(d, v, target, equal) => {
                self.sub_flags(self.regs[r(d)], v, 4);
                *count += 1;
                if self.zf == equal {
                    self.eip = target;
                }
            }
            Fast::CmpRRJump(d, s, target, equal) => {
                self.sub_flags(self.regs[r(d)], self.regs[r(s)], 4);
                *count += 1;
                if self.zf == equal {
                    self.eip = target;
                }
            }
            Fast::CmpB8B8Jump(i, sh, j, sh2, target, equal) => {
                self.sub_flags(self.byte_reg(i, sh), self.byte_reg(j, sh2), 1);
                *count += 1;
                if self.zf == equal {
                    self.eip = target;
                }
            }
            Fast::CmpB8IJump(i, sh, v, target, equal) => {
                self.sub_flags(self.byte_reg(i, sh), v, 1);
                *count += 1;
                if self.zf == equal {
                    self.eip = target;
                }
            }
            Fast::TestRRJump(d, s, target, equal) => {
                self.cf = false;
                self.of = false;
                self.set_zs(self.regs[r(d)] & self.regs[r(s)], 4);
                *count += 1;
                if self.zf == equal {
                    self.eip = target;
                }
            }
            Fast::CmpRRBool(a, b, c, out) => {
                self.sub_flags(self.regs[r(a)], self.regs[r(b)], 4);
                self.regs[r(out)] = self.cond(c) as u32;
                *count += 2;
            }
            Fast::Je(t) => {
                if self.zf {
                    self.eip = t;
                }
            }
            Fast::Jne(t) => {
                if !self.zf {
                    self.eip = t;
                }
            }
            Fast::Jcc(c, t) => {
                if self.cond(c) {
                    self.eip = t;
                }
            }
            Fast::Jmp(t) => self.eip = t,
            Fast::Call(t) => {
                self.push(self.eip);
                self.eip = t;
            }
            Fast::Ret => self.eip = self.pop(),
            Fast::Setcc(c, i, sh) => {
                let v = self.cond(c) as u32;
                self.set_byte_reg(i, sh, v);
            }
        }
        true
    }

    /// Executes one instruction whose eip has already been advanced. Returns
    /// the exit code if the program exited.
    fn execute(&mut self, ins: &Op, k: &mut Kernel) -> Step {
        use Mnemonic::*;
        match ins.mnemonic() {
            Mov => {
                let size = self.op_size(ins, 0);
                let v = self.read_op(ins, 1, size);
                self.write_op(ins, 0, size, v);
            }
            Movzx => {
                let v = self.read_op(ins, 1, self.op_size(ins, 1));
                self.write_op(ins, 0, self.op_size(ins, 0), v);
            }
            Movsx => {
                let size = self.op_size(ins, 1);
                let v = self.read_op(ins, 1, size);
                let v = (((v << (32 - 8 * size)) as i32) >> (32 - 8 * size)) as u32;
                self.write_op(ins, 0, self.op_size(ins, 0), v);
            }
            Lea => {
                let v = self.ea(ins);
                self.write_op(ins, 0, self.op_size(ins, 0), v);
            }
            Add | Sub | Cmp | And | Or | Xor | Test => {
                let size = self.op_size(ins, 0);
                let a = self.read_op(ins, 0, size);
                let b = self.read_op(ins, 1, size);
                let res = match ins.mnemonic() {
                    Add => {
                        let res = a.wrapping_add(b) & mask(size);
                        self.cf = res < a;
                        self.of = (a ^ res) & (b ^ res) & msb(size) != 0;
                        res
                    }
                    Sub | Cmp => {
                        let res = a.wrapping_sub(b) & mask(size);
                        self.cf = a < b;
                        self.of = (a ^ b) & (a ^ res) & msb(size) != 0;
                        res
                    }
                    op => {
                        self.cf = false;
                        self.of = false;
                        match op {
                            And | Test => a & b,
                            Or => a | b,
                            _ => a ^ b,
                        }
                    }
                };
                self.set_zs(res, size);
                if !matches!(ins.mnemonic(), Cmp | Test) {
                    self.write_op(ins, 0, size, res);
                }
            }
            Inc | Dec => {
                let size = self.op_size(ins, 0);
                let a = self.read_op(ins, 0, size);
                let (res, overflow) = if ins.mnemonic() == Inc {
                    (
                        a.wrapping_add(1) & mask(size),
                        a & mask(size) == msb(size) - 1,
                    )
                } else {
                    (a.wrapping_sub(1) & mask(size), a == msb(size))
                };
                self.of = overflow;
                self.set_zs(res, size);
                self.write_op(ins, 0, size, res);
            }
            Neg => {
                let size = self.op_size(ins, 0);
                let a = self.read_op(ins, 0, size);
                let res = a.wrapping_neg() & mask(size);
                self.cf = a != 0;
                self.of = a == msb(size);
                self.set_zs(res, size);
                self.write_op(ins, 0, size, res);
            }
            Not => {
                let size = self.op_size(ins, 0);
                let a = self.read_op(ins, 0, size);
                self.write_op(ins, 0, size, !a);
            }
            Shl | Shr | Sar => {
                let size = self.op_size(ins, 0);
                let a = self.read_op(ins, 0, size);
                let count = self.read_op(ins, 1, 1) & 31;
                assert!(count < 8 * size, "unsupported shift count");
                if count > 0 {
                    let bits = 8 * size;
                    let (res, cf) = match ins.mnemonic() {
                        Shl => (a << count, (a >> (bits - count)) & 1 != 0),
                        Shr => (a >> count, (a >> (count - 1)) & 1 != 0),
                        _ => {
                            let signed = ((a << (32 - bits)) as i32) >> (32 - bits);
                            ((signed >> count) as u32, (signed >> (count - 1)) & 1 != 0)
                        }
                    };
                    let res = res & mask(size);
                    self.cf = cf;
                    // OF is only defined for 1-bit shifts.
                    self.of = match ins.mnemonic() {
                        Shl => (res & msb(size) != 0) != cf,
                        Shr => a & msb(size) != 0,
                        _ => false,
                    };
                    self.set_zs(res, size);
                    self.write_op(ins, 0, size, res);
                }
            }
            Xchg => {
                let size = self.op_size(ins, 0);
                let a = self.read_op(ins, 0, size);
                let b = self.read_op(ins, 1, size);
                self.write_op(ins, 0, size, b);
                self.write_op(ins, 1, size, a);
            }
            Cdq => {
                self.regs[EDX] = if (self.regs[EAX] as i32) < 0 {
                    u32::MAX
                } else {
                    0
                };
            }
            Push => {
                assert_eq!(self.op_size(ins, 0), 4, "unsupported push size");
                let v = self.read_op(ins, 0, 4);
                self.push(v);
            }
            Pop => {
                assert_eq!(self.op_size(ins, 0), 4, "unsupported pop size");
                let v = self.pop();
                self.write_op(ins, 0, 4, v);
            }
            Imul | Mul if ins.op_count() == 1 => {
                // edx:eax = eax * r/m32
                assert_eq!(self.op_size(ins, 0), 4, "unsupported multiply size");
                let b = self.read_op(ins, 0, 4);
                let (a, b) = (self.regs[EAX], b);
                let wide = if ins.mnemonic() == Imul {
                    (a as i32 as i64 * b as i32 as i64) as u64
                } else {
                    a as u64 * b as u64
                };
                self.regs[EAX] = wide as u32;
                self.regs[EDX] = (wide >> 32) as u32;
                let fits = if ins.mnemonic() == Imul {
                    wide as i64 == wide as u32 as i32 as i64
                } else {
                    wide >> 32 == 0
                };
                self.cf = !fits;
                self.of = !fits;
            }
            Imul => {
                // r32 = r/m32 * (r32 or imm)
                assert_eq!(self.op_size(ins, 0), 4, "unsupported multiply size");
                let (a, b) = if ins.op_count() == 2 {
                    (self.read_op(ins, 0, 4), self.read_op(ins, 1, 4))
                } else {
                    (self.read_op(ins, 1, 4), self.read_op(ins, 2, 4))
                };
                let wide = a as i32 as i64 * b as i32 as i64;
                self.cf = wide != wide as i32 as i64;
                self.of = self.cf;
                self.write_op(ins, 0, 4, wide as u32);
            }
            Idiv | Div => {
                // eax = edx:eax / r/m32, edx = remainder
                assert_eq!(self.op_size(ins, 0), 4, "unsupported divide size");
                let divisor = self.read_op(ins, 0, 4);
                assert_ne!(divisor, 0, "divide by zero");
                let dividend = ((self.regs[EDX] as u64) << 32) | self.regs[EAX] as u64;
                let (q, r) = if ins.mnemonic() == Idiv {
                    let (n, d) = (dividend as i64, divisor as i32 as i64);
                    let q = n / d;
                    assert_eq!(q, q as i32 as i64, "divide overflow");
                    (q as u32, (n % d) as u32)
                } else {
                    let q = dividend / divisor as u64;
                    assert_eq!(q >> 32, 0, "divide overflow");
                    (q as u32, (dividend % divisor as u64) as u32)
                };
                self.regs[EAX] = q;
                self.regs[EDX] = r;
            }
            Seto | Setno | Setb | Setae | Sete | Setne | Setbe | Seta | Sets | Setns | Setl
            | Setge | Setle | Setg => {
                let v = self.condition(ins.mnemonic()) as u32;
                self.write_op(ins, 0, 1, v);
            }
            // PF and AF are not modelled; stage0 only saves and restores
            // the flags around calls.
            Pushfd => {
                let flags = 0x202
                    | self.cf as u32
                    | (self.zf as u32) << 6
                    | (self.sf as u32) << 7
                    | (self.of as u32) << 11;
                self.push(flags);
            }
            Popfd => {
                let flags = self.pop();
                self.cf = flags & 1 != 0;
                self.zf = flags & 1 << 6 != 0;
                self.sf = flags & 1 << 7 != 0;
                self.of = flags & 1 << 11 != 0;
            }
            Call => {
                let target = self.branch_target(ins);
                self.push(self.eip);
                self.eip = target;
            }
            Ret => {
                assert_eq!(ins.op_count(), 0, "unsupported ret");
                self.eip = self.pop();
            }
            Jmp => {
                self.eip = self.branch_target(ins);
            }
            Jo | Jno | Jb | Jae | Je | Jne | Jbe | Ja | Js | Jns | Jl | Jge | Jle | Jg => {
                let Arg::Branch(target) = ins.args[0] else {
                    panic!("unsupported jcc")
                };
                if self.condition(ins.mnemonic()) {
                    self.eip = target;
                }
            }
            Int => {
                assert!(
                    matches!(ins.args[0], Arg::Imm(0x80)),
                    "unsupported interrupt"
                );
                return self.syscall(k);
            }
            Nop => {}
            m => panic!("unsupported instruction {m:?} before {:#x}", self.eip),
        }
        Step::Next
    }

    fn c_string(&self, mut addr: u32) -> String {
        let mut bytes = Vec::new();
        loop {
            let b = self.read(addr, 1) as u8;
            if b == 0 {
                break;
            }
            bytes.push(b);
            assert!(bytes.len() < 4096, "path too long");
            addr += 1;
        }
        String::from_utf8(bytes).expect("path is not UTF-8")
    }

    fn fd(&mut self, fd: u32) -> &mut OpenFile {
        fd.checked_sub(3)
            .and_then(|i| self.fds.get_mut(i as usize))
            .and_then(|f| f.as_mut())
            .unwrap_or_else(|| panic!("unsupported file descriptor {fd}"))
    }

    fn path_arg(&self, addr: u32) -> String {
        canonical(&self.cwd, &self.c_string(addr))
    }

    /// Reads a NULL-terminated array of string pointers.
    fn strings_arg(&self, mut addr: u32) -> Vec<String> {
        let mut strings = Vec::new();
        loop {
            let p = self.read(addr, 4);
            if p == 0 {
                return strings;
            }
            strings.push(self.c_string(p));
            addr += 4;
        }
    }

    fn new_fd(&mut self, file: OpenFile) -> i32 {
        let slot = match self.fds.iter().position(|f| f.is_none()) {
            Some(i) => i,
            None => {
                self.fds.push(None);
                self.fds.len() - 1
            }
        };
        self.fds[slot] = Some(file);
        slot as i32 + 3
    }

    /// Handles `int 0x80` using the Linux i386 system call ABI.
    fn syscall(&mut self, k: &mut Kernel) -> Step {
        let [eax, ecx, edx, ebx, ..] = self.regs;
        let ret: i32 = match eax {
            // exit(code)
            1 => return Step::Exit(ebx),
            // fork()
            2 => return Step::Fork,
            // read(fd, buf, count)
            3 => {
                let f = self.fd(ebx);
                assert!(f.readable, "read from write-only file descriptor {ebx}");
                let (file, pos) = (f.file, f.pos);
                let n = (edx as usize).min(k.files[file].data.len().saturating_sub(pos));
                self.fd(ebx).pos += n;
                self.write_bytes(ecx, &k.files[file].data[pos..pos + n]);
                n as i32
            }
            // write(fd, buf, count): stdout and stderr only go to the log.
            4 if ebx == 1 || ebx == 2 => {
                self.read_bytes(ecx, edx);
                edx as i32
            }
            4 => {
                let f = self.fd(ebx);
                assert!(f.writable, "write to read-only file descriptor {ebx}");
                let (file, pos) = (f.file, f.pos);
                f.pos += edx as usize;
                let chunk = self.read_bytes(ecx, edx);
                let data = &mut k.files[file].data;
                if data.len() < pos + chunk.len() {
                    data.resize(pos + chunk.len(), 0);
                }
                data[pos..pos + chunk.len()].copy_from_slice(&chunk);
                edx as i32
            }
            // open(path, flags, mode)
            5 => {
                let path = self.path_arg(ebx);
                let file = match ecx {
                    0 => match k.find(&path) {
                        Some(Found::File(i)) => i,
                        Some(_) => panic!("open of directory {path}"),
                        None => return self.set_return(-ENOENT),
                    },
                    // The result does not depend on whether the file
                    // existed, so this does not look it up.
                    O_WRONLY_CREAT_TRUNC => {
                        // Writing through a link the programs created
                        // writes its target.
                        let mut path = k.follow_dirs(&path);
                        while let Some((l, target)) = k.links.iter().find(|(l, _)| *l == path) {
                            path = k.follow_dirs(&canonical(parent(l), target));
                        }
                        match k.files.iter().position(|f| f.path == path && !f.deleted) {
                            Some(i) => {
                                k.files[i].data.clear();
                                k.files[i].created = true;
                                i
                            }
                            None => match k.create(path) {
                                Ok(i) => i,
                                Err(e) => return self.set_return(e),
                            },
                        }
                    }
                    O_RDWR_CREAT_EXCL => match k.find(&path) {
                        Some(_) => return self.set_return(-EEXIST),
                        None => match k.create(path) {
                            Ok(i) => i,
                            Err(e) => return self.set_return(e),
                        },
                    },
                    _ => panic!("unsupported open flags {ecx:#o}"),
                };
                let open = OpenFile {
                    file,
                    pos: 0,
                    readable: ecx & 3 != 1,
                    writable: ecx & 3 != 0,
                };
                self.new_fd(open)
            }
            // close(fd)
            6 => {
                self.fd(ebx);
                self.fds[ebx as usize - 3] = None;
                0
            }
            // waitpid(pid, status, 0)
            7 => {
                assert_eq!(edx, 0, "unsupported waitpid options {edx}");
                let code = k
                    .exited
                    .remove(&ebx)
                    .unwrap_or_else(|| panic!("waitpid for unknown child {ebx}"));
                if ecx != 0 {
                    self.write(ecx, 4, code << 8);
                }
                ebx as i32
            }
            // unlink(path): only files the programs created may be deleted.
            10 => {
                let path = k.follow_dirs(&self.path_arg(ebx));
                match k.lfind(&path) {
                    Some(Found::File(i)) => {
                        assert!(k.files[i].created, "unlink of input file {path}");
                        k.files[i].deleted = true;
                        0
                    }
                    Some(Found::Link(_)) => {
                        let i = k.links.iter().position(|(l, _)| *l == path);
                        k.links
                            .remove(i.unwrap_or_else(|| panic!("unlink of input link {path}")));
                        0
                    }
                    Some(Found::Dir) => panic!("unlink of directory {path}"),
                    None => -ENOENT,
                }
            }
            // execve(path, argv, envp)
            11 => {
                let path = self.path_arg(ebx);
                let (argv, env) = (self.strings_arg(ecx), self.strings_arg(edx));
                let elf = match k.find(&path) {
                    Some(Found::File(i)) => k.files[i].data.clone(),
                    Some(_) => panic!("execve of directory {path}"),
                    None => return self.set_return(-ENOENT),
                };
                let mut image = Machine::load(&elf, &argv, &env, &self.cwd);
                image.fds = std::mem::take(&mut self.fds);
                return Step::Exec(Box::new(image));
            }
            // chmod(path, mode): permissions are not modelled.
            15 => {
                let path = self.path_arg(ebx);
                match k.find(&path) {
                    Some(_) => 0,
                    None => -ENOENT,
                }
            }
            // lseek(fd, offset, whence)
            19 => {
                let file = self.fd(ebx).file;
                let base = match edx {
                    0 => 0,
                    1 => self.fd(ebx).pos as i64,
                    2 => k.files[file].data.len() as i64,
                    _ => panic!("unsupported lseek whence {edx}"),
                };
                let pos = base + ecx as i32 as i64;
                assert!(
                    (0..i32::MAX as i64).contains(&pos),
                    "unsupported lseek offset"
                );
                self.fd(ebx).pos = pos as usize;
                pos as i32
            }
            // chdir(path)
            12 => {
                let path = self.path_arg(ebx);
                match k.find(&path) {
                    Some(Found::Dir) => {
                        self.cwd = path;
                        0
                    }
                    Some(_) => -ENOTDIR,
                    None => -ENOENT,
                }
            }
            // getcwd(buf, size): returns the length including the NUL.
            183 => {
                let mut path = self.cwd.clone().into_bytes();
                path.push(0);
                if path.len() > ecx as usize {
                    -ERANGE
                } else {
                    self.write_bytes(ebx, &path);
                    path.len() as i32
                }
            }
            // mkdir(path, mode): permissions are not modelled.
            39 => {
                let path = k.follow_dirs(&self.path_arg(ebx));
                if path == "/" || k.lfind(&path).is_some() {
                    -EEXIST
                } else {
                    match k.find(parent(&path)) {
                        Some(Found::Dir) => {
                            k.dirs.push(path);
                            0
                        }
                        Some(_) => -ENOTDIR,
                        None => -ENOENT,
                    }
                }
            }
            // symlink(target, path)
            83 => {
                let target = self.c_string(ebx);
                let path = k.follow_dirs(&self.path_arg(ecx));
                if path == "/" || k.lfind(&path).is_some() {
                    -EEXIST
                } else {
                    match k.find(parent(&path)) {
                        Some(Found::Dir) => {
                            k.links.push((path, target));
                            0
                        }
                        Some(_) => -ENOTDIR,
                        None => -ENOENT,
                    }
                }
            }
            // clock_gettime(clock, ts): the clock always reads zero, so that
            // runs are deterministic.
            265 => {
                assert!(ebx <= 2, "unsupported clock {ebx}");
                self.write_bytes(ecx, &[0; 8]);
                0
            }
            // access(path, mode): permissions are not modelled.
            33 => {
                let path = self.path_arg(ebx);
                match k.find(&path) {
                    Some(_) => 0,
                    None => -ENOENT,
                }
            }
            // brk(addr): returns the new break, or the old one on failure.
            45 => {
                if ebx >= self.brk_start && ebx <= HEAP_LIMIT {
                    // Pages above the break are unmapped, so they read as
                    // zero if the break grows again.
                    let old_end = self.brk.next_multiple_of(PAGE) / PAGE;
                    let new_end = ebx.next_multiple_of(PAGE) / PAGE;
                    for page in new_end..old_end {
                        self.unmap(page);
                    }
                    for page in old_end..new_end {
                        self.map(page, WRITABLE);
                    }
                    self.brk = ebx;
                }
                self.brk as i32
            }
            _ => panic!("unsupported system call {eax}"),
        };
        self.set_return(ret)
    }

    fn set_return(&mut self, ret: i32) -> Step {
        self.regs[EAX] = ret as u32;
        Step::Next
    }
}

enum Found {
    File(usize),
    Dir,
    Link(String),
}

/// The directory part of a canonical path.
fn parent(path: &str) -> &str {
    match path.rfind('/') {
        Some(0) | None => "/",
        Some(i) => &path[..i],
    }
}

impl Kernel<'_> {
    /// Finds what exists at a canonical path, following symbolic links.
    fn find(&mut self, path: &str) -> Option<Found> {
        let mut path = self.follow_dirs(path);
        // Linux gives up after 40 links.
        for _ in 0..40 {
            match self.lfind(&path) {
                Some(Found::Link(target)) => {
                    path = self.follow_dirs(&canonical(parent(&path), &target));
                }
                found => return found,
            }
        }
        panic!("too many levels of symbolic links at {path}")
    }

    /// Resolves the symbolic links the programs created among the
    /// directories of a canonical path, but not its last component.
    fn follow_dirs(&self, path: &str) -> String {
        let mut path = path.to_string();
        for _ in 0..40 {
            let link = self.links.iter().find(|(link, _)| {
                path.len() > link.len()
                    && path.starts_with(link.as_str())
                    && path.as_bytes()[link.len()] == b'/'
            });
            match link {
                Some((link, target)) => {
                    path = canonical(parent(link), &format!("{target}{}", &path[link.len()..]));
                }
                None => return path,
            }
        }
        panic!("too many levels of symbolic links at {path}")
    }

    /// Finds what exists at a canonical path without following a symbolic
    /// link at its last component, asking `lookup` about paths the programs
    /// have not created.
    fn lfind(&mut self, path: &str) -> Option<Found> {
        if let Some(i) = self.files.iter().position(|f| f.path == path && !f.deleted) {
            return Some(Found::File(i));
        }
        if self.dirs.iter().any(|d| d == path) {
            return Some(Found::Dir);
        }
        if let Some((_, target)) = self.links.iter().find(|(l, _)| l == path) {
            return Some(Found::Link(target.clone()));
        }
        if let Some((_, entry)) = self.lookups.iter().find(|(p, _)| p == path) {
            // A file that was looked up but is not in `files` was deleted.
            return match entry {
                Entry::Dir => Some(Found::Dir),
                Entry::Link(target) => Some(Found::Link(target.clone())),
                _ => None,
            };
        }
        let entry = (self.lookup)(path);
        let found = match &entry {
            Entry::File(data) => {
                self.files.push(File {
                    path: path.to_string(),
                    data: data.clone(),
                    created: false,
                    deleted: false,
                });
                Some(Found::File(self.files.len() - 1))
            }
            Entry::Dir => Some(Found::Dir),
            Entry::Link(target) => Some(Found::Link(target.clone())),
            Entry::Missing => None,
        };
        self.lookups.push((path.to_string(), entry));
        found
    }

    /// Creates an empty file in an existing directory.
    fn create(&mut self, path: String) -> Result<usize, i32> {
        match self.find(parent(&path)) {
            Some(Found::Dir) => {}
            Some(_) => return Err(-ENOTDIR),
            None => return Err(-ENOENT),
        }
        self.files.push(File {
            path,
            data: Vec::new(),
            created: true,
            deleted: false,
        });
        Ok(self.files.len() - 1)
    }
}

#[cfg(test)]
mod tests {
    use super::{run, Entry};

    fn image(code: &[u8], base: u32) -> Vec<u8> {
        // A static ELF32/i386 image with one load segment and code at +84.
        let size = 84 + code.len() as u32;
        let mut elf = b"\x7fELF\x01\x01\x01\0\0\0\0\0\0\0\0\0".to_vec();
        for word in [
            0x0003_0002u32,
            1,
            base + 84,
            52,
            0,
            0,
            0x0020_0034,
            1,
            0,
            1,
            0,
            base,
            base,
            size,
            size,
            7,
            4096,
        ] {
            elf.extend_from_slice(&word.to_le_bytes());
        }
        elf.extend_from_slice(code);
        elf
    }

    #[test]
    fn stack_pages_are_zeroed_and_private_across_fork() {
        // i386 code: write 0x89abcdef at 0xbf900000, check the next page
        // still reads zero, then write/read 0x10203040 across the following
        // page boundary. Fork a child that overwrites both a populated and
        // an untouched page; the parent waits and checks its original word
        // and untouched zeros. Any failed comparison exits with status 1.
        let code = hex::decode(concat!(
            "bf000090bfc707efcdab898b870010000083f8000f8580000000c787fe1f0000",
            "403020108b87fe1f00003d4030201075698b073defcdab8975608b8700300000",
            "83f8007555b802000000cd8083f800742d89c331c931d2b807000000cd808b07",
            "3defcdab8975338b870030000083f8007528bb00000000b801000000cd80c707",
            "88776655c78700300000ccbbaa99bb00000000b801000000cd80bb01000000b8",
            "01000000cd80",
        ))
        .unwrap();
        let exit = run(
            &image(&code, 0x0804_8000),
            &["stack-check".into()],
            &[],
            "/",
            &mut |_| Entry::Missing,
        );
        assert_eq!(exit.code, 0);
    }

    #[test]
    fn comparison_flags_and_modified_branch_are_preserved() {
        // Call CMP EAX,0; JE target_one across a page boundary, then patch
        // only JE's displacement on the next page and call it again. It
        // must reach target_two. Call JE directly with ZF=1 but EAX=-1 to
        // check that entering the second instruction does not repeat CMP.
        // Finally CMP 0x80000000,1; JE (not taken) must leave OF=1,CF=SF=0.
        // Each failed check exits 1; the successful path is 33 instructions.
        let mut code = hex::decode(concat!(
            "31c0e8a20f000083fb017541c70502900408adf0ffffe88e0f000083fb02752d",
            "b8ffffffff39c0e8800f000083fb02751cb80000008083f80174127110720e780c",
            "bb00000000b801000000cd80bb01000000b801000000cd80bb01000000c3",
            "bb02000000c3",
        ))
        .unwrap();
        // With the 84-byte ELF header, CMP starts at 0x08048ffd and JE
        // starts at 0x08049000. Neither target executes on JE's page.
        code.resize(4096 - 84 - 3, 0);
        code.extend(hex::decode("83f8000f84a7f0ffffbb03000000c3").unwrap());
        let exit = run(&image(&code, 0x0804_8000), &[], &[], "/", &mut |_| {
            Entry::Missing
        });
        assert_eq!(exit.code, 0);
        assert_eq!(exit.instructions, 33);
    }

    #[test]
    fn code_can_continue_from_image_onto_stack() {
        // The image ends at the bottom of the mapped stack. Write a JE
        // there, execute CMP at the end of the image followed by that JE,
        // then write farther into the stack. This must not mark the stack
        // page as belonging to the image's decoded cache.
        let mut code = hex::decode(concat!(
            "66c705000080bf0f84c705020080bf7bf0ffff31c0e88f0f0000c605640080bf42",
            "bb00000000b801000000cd80c3",
        ))
        .unwrap();
        code.resize(4096 - 84 - 3, 0);
        code.extend([0x83, 0xf8, 0x00]); // CMP EAX,0 at 0xbf7ffffd.
        let exit = run(&image(&code, 0xbf7f_f000), &[], &[], "/", &mut |_| {
            Entry::Missing
        });
        assert_eq!(exit.code, 0);
        assert_eq!(exit.instructions, 11);
    }
}
