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

/// The result of running a program to completion.
pub struct Exit {
    /// The exit status, as the parent process would see it.
    pub code: u32,
    /// Files the program loaded through `lookup`, by canonical path.
    pub loaded: Vec<String>,
    /// Files the program created, by canonical path.
    pub created: BTreeMap<String, Vec<u8>>,
    /// Number of x86 instructions executed.
    pub instructions: u64,
}

struct Region {
    start: u32,
    data: Vec<u8>,
    writable: bool,
    /// For segments loaded from the ELF, the decoded instruction at each
    /// offset, as an index into the op arena plus one, or 0. Writes
    /// invalidate the entries they may overlap.
    decoded: Vec<u32>,
    /// Offsets of the lowest and highest decoded instructions, so that
    /// writes elsewhere can skip invalidation.
    code: (usize, usize),
}

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
#[derive(Clone, Copy)]
struct Op {
    mnemonic: Mnemonic,
    next_ip: u32,
    count: u8,
    sizes: [u8; 3],
    args: [Arg; 3],
}

impl Op {
    fn mnemonic(&self) -> Mnemonic {
        self.mnemonic
    }

    fn op_count(&self) -> u32 {
        self.count as u32
    }

    fn translate(ins: &Instruction) -> Op {
        let count = ins.op_count().min(3);
        let mut op = Op {
            mnemonic: ins.mnemonic(),
            next_ip: ins.next_ip32(),
            count: count as u8,
            sizes: [0; 3],
            args: [Arg::None; 3],
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
        op
    }
}

struct File {
    path: String,
    data: Vec<u8>,
    created: bool,
    loaded: bool,
}

struct OpenFile {
    file: usize,
    pos: usize,
    writable: bool,
}

struct Machine<'a> {
    regions: Vec<Region>,
    /// For each 4 KiB page of the address space, the index of the region
    /// that maps it plus one, or 0.
    pages: Vec<u8>,
    /// Index of the heap region in `regions`; its end is the program break.
    heap: usize,
    /// The program break, which may lie inside the heap's last page.
    brk: u32,
    cwd: String,
    lookup: &'a mut dyn FnMut(&str) -> Option<Vec<u8>>,
    regs: [u32; 8],
    eip: u32,
    cf: bool,
    zf: bool,
    sf: bool,
    of: bool,
    files: Vec<File>,
    fds: Vec<Option<OpenFile>>,
}

/// Runs a static i386 Linux ELF with the given argv in the working directory
/// `cwd`. When the program opens a file it has not created, `lookup` is called
/// with its canonical path; opening a file that does not exist panics.
pub fn run(
    elf: &[u8],
    argv: &[String],
    cwd: &str,
    lookup: &mut dyn FnMut(&str) -> Option<Vec<u8>>,
) -> Exit {
    let mut m = Machine::load(elf, argv, cwd, lookup);
    // Decoded instructions live outside the machine so that executing one
    // borrows it instead of copying it.
    let mut ops = Vec::new();
    let mut instructions = 0u64;
    let code = loop {
        let index = m.decode(&mut ops);
        let op = &ops[index];
        m.eip = op.next_ip;
        instructions += 1;
        if let Some(code) = m.execute(op) {
            break code;
        }
    };
    let loaded = m
        .files
        .iter()
        .filter(|f| f.loaded)
        .map(|f| f.path.clone())
        .collect();
    let created = m
        .files
        .into_iter()
        .filter(|f| f.created)
        .map(|f| (f.path, f.data))
        .collect();
    Exit {
        code: code & 0xff,
        loaded,
        created,
        instructions,
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

impl<'a> Machine<'a> {
    /// Loads the ELF and sets up the initial process state the way Linux does
    /// for a static i386 executable.
    fn load(
        elf: &[u8],
        argv: &[String],
        cwd: &str,
        lookup: &'a mut dyn FnMut(&str) -> Option<Vec<u8>>,
    ) -> Machine<'a> {
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

        let mut regions = Vec::new();
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
            assert!(
                regions
                    .iter()
                    .all(|r: &Region| end <= r.start || start >= r.start + r.data.len() as u32),
                "overlapping segments"
            );
            let mut data = vec![0u8; (end - start) as usize];
            let file_off = (offset - offset % PAGE) as usize;
            let n = (file_end - start).min(elf.len().saturating_sub(file_off) as u32) as usize;
            data[..n].copy_from_slice(&elf[file_off..file_off + n]);
            if memsz > filesz {
                data[(vaddr + filesz - start) as usize..].fill(0);
            }
            regions.push(Region {
                start,
                decoded: vec![0; data.len()],
                code: (usize::MAX, 0),
                data,
                writable: flags & 2 != 0,
            });
        }

        // The program break starts at the page after the last segment.
        let brk_start = regions
            .iter()
            .map(|r| r.start + r.data.len() as u32)
            .max()
            .unwrap();
        regions.push(Region {
            start: STACK_TOP - STACK_SIZE,
            data: vec![0u8; STACK_SIZE as usize],
            writable: true,
            decoded: Vec::new(),
            code: (usize::MAX, 0),
        });
        regions.push(Region {
            start: brk_start,
            data: Vec::new(),
            writable: true,
            decoded: Vec::new(),
            code: (usize::MAX, 0),
        });

        let mut m = Machine {
            pages: vec![0; (1 << 32) / PAGE as usize],
            heap: regions.len() - 1,
            brk: brk_start,
            regions,
            cwd: cwd.to_string(),
            lookup,
            regs: [0; 8],
            eip: entry,
            cf: false,
            zf: false,
            sf: false,
            of: false,
            files: Vec::new(),
            fds: Vec::new(),
        };

        for i in 0..m.regions.len() {
            m.map_pages(i);
        }

        // Initial stack: argc, argv pointers, NULL, an empty environment and
        // an auxiliary vector holding only AT_NULL. All registers start at 0.
        let mut sp = STACK_TOP;
        let mut ptrs = Vec::new();
        for arg in argv.iter().rev() {
            sp -= arg.len() as u32 + 1;
            m.write_bytes(sp, arg.as_bytes());
            m.write(sp + arg.len() as u32, 1, 0);
            ptrs.push(sp);
        }
        ptrs.reverse();
        let mut words = vec![argv.len() as u32];
        words.extend(ptrs);
        words.extend([0, 0, 0, 0]);
        sp = (sp - 4 * words.len() as u32) & !15;
        for (i, w) in words.iter().enumerate() {
            m.write(sp + 4 * i as u32, 4, *w);
        }
        m.regs[ESP] = sp;
        m
    }

    #[inline(always)]
    fn region(&self, addr: u32, len: u32) -> (usize, usize) {
        let i = self.pages[(addr / PAGE) as usize] as usize;
        if i != 0 {
            let r = &self.regions[i - 1];
            let off = (addr - r.start) as usize;
            if off + len as usize <= r.data.len() {
                return (i - 1, off);
            }
        }
        panic!("access to unmapped memory at {addr:#x}");
    }

    fn map_pages(&mut self, i: usize) {
        let r = &self.regions[i];
        let first = (r.start / PAGE) as usize;
        let n = r.data.len() / PAGE as usize;
        self.pages[first..first + n].fill(i as u8 + 1);
    }

    fn read(&self, addr: u32, size: u32) -> u32 {
        let (i, off) = self.region(addr, size);
        let d = &self.regions[i].data;
        match size {
            4 => u32::from_le_bytes(d[off..off + 4].try_into().unwrap()),
            2 => u16::from_le_bytes(d[off..off + 2].try_into().unwrap()) as u32,
            _ => d[off] as u32,
        }
    }

    fn write(&mut self, addr: u32, size: u32, val: u32) {
        let bytes = val.to_le_bytes();
        self.write_bytes(addr, &bytes[..size as usize]);
    }

    fn read_bytes(&self, addr: u32, len: u32) -> &[u8] {
        let (i, off) = self.region(addr, len);
        &self.regions[i].data[off..off + len as usize]
    }

    fn write_bytes(&mut self, addr: u32, bytes: &[u8]) {
        let (i, off) = self.region(addr, bytes.len() as u32);
        let r = &mut self.regions[i];
        assert!(r.writable, "write to read-only memory at {addr:#x}");
        r.data[off..off + bytes.len()].copy_from_slice(bytes);
        // An x86 instruction is at most 15 bytes long.
        if off + bytes.len() > r.code.0 && off <= r.code.1 + 14 {
            r.decoded[off.saturating_sub(14)..off + bytes.len()].fill(0);
        }
    }

    /// Returns the index in `ops` of the instruction at eip, decoding it if
    /// it is not cached.
    #[inline(always)]
    fn decode(&mut self, ops: &mut Vec<Op>) -> usize {
        let (i, off) = self.region(self.eip, 1);
        if let Some(&n) = self.regions[i].decoded.get(off) {
            if n != 0 {
                return n as usize - 1;
            }
        }
        self.decode_new(ops, i, off)
    }

    #[cold]
    #[inline(never)]
    fn decode_new(&mut self, ops: &mut Vec<Op>, i: usize, off: usize) -> usize {
        let data = &self.regions[i].data;
        let code = &data[off..(off + 15).min(data.len())];
        let ins = Decoder::with_ip(32, code, self.eip as u64, DecoderOptions::NONE).decode();
        assert!(!ins.is_invalid(), "invalid instruction at {:#x}", self.eip);
        assert!(
            !ins.has_lock_prefix() && !ins.has_rep_prefix() && !ins.has_repne_prefix(),
            "unsupported prefix at {:#x}",
            self.eip
        );
        ops.push(Op::translate(&ins));
        let r = &mut self.regions[i];
        if let Some(slot) = r.decoded.get_mut(off) {
            *slot = ops.len() as u32;
            r.code = (r.code.0.min(off), r.code.1.max(off));
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

    /// Executes one instruction whose eip has already been advanced. Returns
    /// the exit code if the program exited.
    fn execute(&mut self, ins: &Op) -> Option<u32> {
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
                return self.syscall();
            }
            Nop => {}
            m => panic!("unsupported instruction {m:?} before {:#x}", self.eip),
        }
        None
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

    /// Finds an existing file, loading it through `lookup` if needed.
    fn find_file(&mut self, path: &str) -> Option<usize> {
        if let Some(i) = self.files.iter().position(|f| f.path == path) {
            return Some(i);
        }
        let data = (self.lookup)(path)?;
        self.files.push(File {
            path: path.to_string(),
            data,
            created: false,
            loaded: true,
        });
        Some(self.files.len() - 1)
    }

    /// Handles `int 0x80` using the Linux i386 system call ABI.
    fn syscall(&mut self) -> Option<u32> {
        let [eax, ecx, edx, ebx, ..] = self.regs;
        let ret: i32 = match eax {
            // exit(code)
            1 => return Some(ebx),
            // read(fd, buf, count)
            3 => {
                let f = self.fd(ebx);
                assert!(!f.writable, "read from write-only file descriptor {ebx}");
                let (file, pos) = (f.file, f.pos);
                let n = (edx as usize).min(self.files[file].data.len().saturating_sub(pos));
                self.fd(ebx).pos += n;
                let chunk = std::mem::take(&mut self.files[file].data);
                self.write_bytes(ecx, &chunk[pos..pos + n]);
                self.files[file].data = chunk;
                n as i32
            }
            // write(fd, buf, count)
            4 => {
                let chunk = self.read_bytes(ecx, edx).to_vec();
                let f = self.fd(ebx);
                assert!(f.writable, "write to read-only file descriptor {ebx}");
                let (file, pos) = (f.file, f.pos);
                f.pos += chunk.len();
                let data = &mut self.files[file].data;
                if data.len() < pos + chunk.len() {
                    data.resize(pos + chunk.len(), 0);
                }
                data[pos..pos + chunk.len()].copy_from_slice(&chunk);
                edx as i32
            }
            // open(path, flags, mode)
            5 => {
                let path = canonical(&self.cwd, &self.c_string(ebx));
                let file = match ecx {
                    0 => self
                        .find_file(&path)
                        .unwrap_or_else(|| panic!("open of missing file {path}")),
                    O_WRONLY_CREAT_TRUNC => {
                        let i = self
                            .files
                            .iter()
                            .position(|f| f.path == path)
                            .unwrap_or_else(|| {
                                self.files.push(File {
                                    path,
                                    data: Vec::new(),
                                    created: true,
                                    loaded: false,
                                });
                                self.files.len() - 1
                            });
                        self.files[i].data.clear();
                        self.files[i].created = true;
                        i
                    }
                    _ => panic!("unsupported open flags {ecx:#o}"),
                };
                let open = Some(OpenFile {
                    file,
                    pos: 0,
                    writable: ecx != 0,
                });
                let slot = match self.fds.iter().position(|f| f.is_none()) {
                    Some(i) => i,
                    None => {
                        self.fds.push(None);
                        self.fds.len() - 1
                    }
                };
                self.fds[slot] = open;
                slot as i32 + 3
            }
            // close(fd)
            6 => {
                self.fd(ebx);
                self.fds[ebx as usize - 3] = None;
                0
            }
            // chmod(path, mode): permissions are not modelled.
            15 => {
                let path = canonical(&self.cwd, &self.c_string(ebx));
                self.find_file(&path)
                    .unwrap_or_else(|| panic!("chmod of missing file {path}"));
                0
            }
            // lseek(fd, offset, whence)
            19 => {
                let file = self.fd(ebx).file;
                let base = match edx {
                    0 => 0,
                    1 => self.fd(ebx).pos as i64,
                    2 => self.files[file].data.len() as i64,
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
            // brk(addr): returns the new break, or the old one on failure.
            45 => {
                let heap = &mut self.regions[self.heap];
                if ebx >= heap.start && ebx <= HEAP_LIMIT {
                    // Pages above the break are unmapped, so they read as
                    // zero if the break grows again.
                    let old_end = (heap.start as usize + heap.data.len()) / PAGE as usize;
                    heap.data
                        .resize((ebx.next_multiple_of(PAGE) - heap.start) as usize, 0);
                    let new_end = (heap.start as usize + heap.data.len()) / PAGE as usize;
                    if new_end < old_end {
                        self.pages[new_end..old_end].fill(0);
                    } else {
                        self.pages[old_end..new_end].fill(self.heap as u8 + 1);
                    }
                    self.brk = ebx;
                }
                self.brk as i32
            }
            _ => panic!("unsupported system call {eax}"),
        };
        self.set_return(ret)
    }

    fn set_return(&mut self, ret: i32) -> Option<u32> {
        self.regs[EAX] = ret as u32;
        None
    }
}
