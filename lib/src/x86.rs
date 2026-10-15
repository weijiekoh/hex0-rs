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
const STACK_SIZE: u32 = 0x2_0000;

const EAX: usize = 0;
const EDX: usize = 2;
const ESP: usize = 4;

const O_WRONLY_CREAT_TRUNC: u32 = 0o1101;
const ENOENT: i32 = 2;

/// The result of running a program to completion.
pub struct Exit {
    pub code: u32,
    /// Files the program created, by path.
    pub created: BTreeMap<String, Vec<u8>>,
    /// Number of x86 instructions executed.
    pub instructions: u64,
}

struct Region {
    start: u32,
    data: Vec<u8>,
    writable: bool,
    /// Decoded instructions by offset, for segments loaded from the ELF.
    /// Writes invalidate the entries they may overlap.
    decoded: Vec<Option<Instruction>>,
}

struct File {
    path: String,
    data: Vec<u8>,
    created: bool,
}

struct OpenFile {
    file: usize,
    pos: usize,
    writable: bool,
}

struct Machine {
    regions: Vec<Region>,
    regs: [u32; 8],
    eip: u32,
    cf: bool,
    zf: bool,
    sf: bool,
    of: bool,
    files: Vec<File>,
    fds: Vec<Option<OpenFile>>,
}

/// Runs a static i386 Linux ELF with the given argv. `files` is the
/// filesystem the program can open for reading.
pub fn run(elf: &[u8], argv: &[String], files: BTreeMap<String, Vec<u8>>) -> Exit {
    let mut m = Machine::load(elf, argv, files);
    let mut instructions = 0u64;
    let code = loop {
        let ins = m.decode();
        m.eip = ins.next_ip32();
        instructions += 1;
        if let Some(code) = m.execute(&ins) {
            break code;
        }
    };
    let created = m
        .files
        .into_iter()
        .filter(|f| f.created)
        .map(|f| (f.path, f.data))
        .collect();
    Exit {
        code,
        created,
        instructions,
    }
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
    fn load(elf: &[u8], argv: &[String], files: BTreeMap<String, Vec<u8>>) -> Machine {
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
                decoded: vec![None; data.len()],
                data,
                writable: flags & 2 != 0,
            });
        }

        regions.push(Region {
            start: STACK_TOP - STACK_SIZE,
            data: vec![0u8; STACK_SIZE as usize],
            writable: true,
            decoded: Vec::new(),
        });

        let mut m = Machine {
            regions,
            regs: [0; 8],
            eip: entry,
            cf: false,
            zf: false,
            sf: false,
            of: false,
            files: files
                .into_iter()
                .map(|(path, data)| File {
                    path,
                    data,
                    created: false,
                })
                .collect(),
            fds: Vec::new(),
        };

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

    fn region(&self, addr: u32, len: u32) -> (usize, usize) {
        for (i, r) in self.regions.iter().enumerate() {
            let off = addr.wrapping_sub(r.start) as usize;
            if addr >= r.start && off <= r.data.len() && len as usize <= r.data.len() - off {
                return (i, off);
            }
        }
        panic!("access to unmapped memory at {addr:#x}");
    }

    fn read(&self, addr: u32, size: u32) -> u32 {
        let (i, off) = self.region(addr, size);
        let bytes = &self.regions[i].data[off..off + size as usize];
        bytes.iter().rev().fold(0, |v, b| (v << 8) | *b as u32)
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
        if !r.decoded.is_empty() {
            // An x86 instruction is at most 15 bytes long.
            r.decoded[off.saturating_sub(14)..off + bytes.len()].fill(None);
        }
    }

    fn decode(&mut self) -> Instruction {
        let (i, off) = self.region(self.eip, 1);
        if let Some(Some(ins)) = self.regions[i].decoded.get(off) {
            return *ins;
        }
        let data = &self.regions[i].data;
        let code = &data[off..(off + 15).min(data.len())];
        let ins = Decoder::with_ip(32, code, self.eip as u64, DecoderOptions::NONE).decode();
        assert!(!ins.is_invalid(), "invalid instruction at {:#x}", self.eip);
        assert!(
            !ins.has_lock_prefix() && !ins.has_rep_prefix() && !ins.has_repne_prefix(),
            "unsupported prefix at {:#x}",
            self.eip
        );
        if let Some(slot) = self.regions[i].decoded.get_mut(off) {
            *slot = Some(ins);
        }
        ins
    }

    fn get_reg(&self, r: Register) -> u32 {
        let (i, size, shift) = reg_info(r);
        (self.regs[i] >> shift) & mask(size)
    }

    fn set_reg(&mut self, r: Register, v: u32) {
        let (i, size, shift) = reg_info(r);
        let m = mask(size) << shift;
        self.regs[i] = (self.regs[i] & !m) | ((v << shift) & m);
    }

    fn ea(&self, ins: &Instruction) -> u32 {
        assert!(
            matches!(
                ins.memory_segment(),
                Register::DS | Register::SS | Register::ES
            ),
            "unsupported segment {:?}",
            ins.memory_segment()
        );
        let base = match ins.memory_base() {
            Register::None => 0,
            r => self.get_reg(r),
        };
        let index = match ins.memory_index() {
            Register::None => 0,
            r => self.get_reg(r).wrapping_mul(ins.memory_index_scale()),
        };
        base.wrapping_add(index)
            .wrapping_add(ins.memory_displacement32())
    }

    fn op_size(&self, ins: &Instruction, i: u32) -> u32 {
        match ins.op_kind(i) {
            OpKind::Register => reg_info(ins.op_register(i)).1,
            OpKind::Memory => mem_size(ins.memory_size()),
            k => panic!("unsupported operand kind {k:?}"),
        }
    }

    fn read_op(&self, ins: &Instruction, i: u32, size: u32) -> u32 {
        match ins.op_kind(i) {
            OpKind::Register => self.get_reg(ins.op_register(i)),
            OpKind::Memory => self.read(self.ea(ins), size),
            OpKind::Immediate8
            | OpKind::Immediate16
            | OpKind::Immediate32
            | OpKind::Immediate8to16
            | OpKind::Immediate8to32 => ins.immediate(i) as u32 & mask(size),
            k => panic!("unsupported operand kind {k:?}"),
        }
    }

    fn write_op(&mut self, ins: &Instruction, i: u32, size: u32, v: u32) {
        match ins.op_kind(i) {
            OpKind::Register => self.set_reg(ins.op_register(i), v),
            OpKind::Memory => self.write(self.ea(ins), size, v),
            k => panic!("unsupported operand kind {k:?}"),
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

    fn condition(&self, jcc: Mnemonic) -> bool {
        use Mnemonic::*;
        match jcc {
            Jo => self.of,
            Jno => !self.of,
            Jb => self.cf,
            Jae => !self.cf,
            Je => self.zf,
            Jne => !self.zf,
            Jbe => self.cf || self.zf,
            Ja => !self.cf && !self.zf,
            Js => self.sf,
            Jns => !self.sf,
            Jl => self.sf != self.of,
            Jge => self.sf == self.of,
            Jle => self.zf || self.sf != self.of,
            Jg => !self.zf && self.sf == self.of,
            _ => unreachable!(),
        }
    }

    /// Executes one instruction whose eip has already been advanced. Returns
    /// the exit code if the program exited.
    fn execute(&mut self, ins: &Instruction) -> Option<u32> {
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
                let size = match ins.op_kind(0) {
                    OpKind::Immediate8to32 | OpKind::Immediate32 => 4,
                    _ => self.op_size(ins, 0),
                };
                assert_eq!(size, 4, "unsupported push size");
                let v = self.read_op(ins, 0, 4);
                self.push(v);
            }
            Pop => {
                assert_eq!(self.op_size(ins, 0), 4, "unsupported pop size");
                let v = self.pop();
                self.write_op(ins, 0, 4, v);
            }
            Call => {
                assert_eq!(ins.op_kind(0), OpKind::NearBranch32, "unsupported call");
                self.push(self.eip);
                self.eip = ins.near_branch32();
            }
            Ret => {
                assert_eq!(ins.op_count(), 0, "unsupported ret");
                self.eip = self.pop();
            }
            Jmp => {
                assert_eq!(ins.op_kind(0), OpKind::NearBranch32, "unsupported jmp");
                self.eip = ins.near_branch32();
            }
            Jo | Jno | Jb | Jae | Je | Jne | Jbe | Ja | Js | Jns | Jl | Jge | Jle | Jg => {
                assert_eq!(ins.op_kind(0), OpKind::NearBranch32, "unsupported jcc");
                if self.condition(ins.mnemonic()) {
                    self.eip = ins.near_branch32();
                }
            }
            Int => {
                assert_eq!(ins.immediate(0), 0x80, "unsupported interrupt");
                return self.syscall();
            }
            Nop => {}
            m => panic!("unsupported instruction {m:?} at {:#x}", ins.ip32()),
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

    fn open_file(&mut self, fd: u32, writable: bool) -> &mut OpenFile {
        let f = fd
            .checked_sub(3)
            .and_then(|i| self.fds.get_mut(i as usize))
            .and_then(|f| f.as_mut())
            .unwrap_or_else(|| panic!("unsupported file descriptor {fd}"));
        assert!(
            !writable || f.writable,
            "write to read-only file descriptor {fd}"
        );
        assert!(
            writable || !f.writable,
            "read from write-only file descriptor {fd}"
        );
        f
    }

    /// Handles `int 0x80` using the Linux i386 system call ABI.
    fn syscall(&mut self) -> Option<u32> {
        let [eax, ecx, edx, ebx, ..] = self.regs;
        let ret: i32 = match eax {
            // exit(code)
            1 => return Some(ebx),
            // read(fd, buf, count)
            3 => {
                let f = self.open_file(ebx, false);
                let (file, pos) = (f.file, f.pos);
                let n = (edx as usize).min(self.files[file].data.len() - pos);
                self.open_file(ebx, false).pos += n;
                let chunk = std::mem::take(&mut self.files[file].data);
                self.write_bytes(ecx, &chunk[pos..pos + n]);
                self.files[file].data = chunk;
                n as i32
            }
            // write(fd, buf, count)
            4 => {
                let chunk = self.read_bytes(ecx, edx).to_vec();
                let f = self.open_file(ebx, true);
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
                let path = self.c_string(ebx);
                let writable = match ecx {
                    0 => false,
                    O_WRONLY_CREAT_TRUNC => true,
                    _ => panic!("unsupported open flags {ecx:#o}"),
                };
                let existing = self.files.iter().position(|f| f.path == path);
                let file = match (existing, writable) {
                    (None, false) => return self.set_return(-ENOENT),
                    (None, true) => {
                        self.files.push(File {
                            path,
                            data: Vec::new(),
                            created: true,
                        });
                        self.files.len() - 1
                    }
                    (Some(i), false) => i,
                    (Some(i), true) => {
                        self.files[i].data.clear();
                        self.files[i].created = true;
                        i
                    }
                };
                let open = Some(OpenFile {
                    file,
                    pos: 0,
                    writable,
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
            // lseek(fd, offset, SEEK_SET)
            19 => {
                assert_eq!(edx, 0, "unsupported lseek whence {edx}");
                self.open_file(ebx, false).pos = ecx as usize;
                ecx as i32
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
