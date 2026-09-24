// Disassembly via binutils libopcodes (same engine GDB uses) — not a hand-rolled decoder.
// Flow classification is a mnemonic table over the printed text (GDB layers gdbarch the same way).

use std::ffi::{c_char, c_int, CStr};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Arch {
    X86_64,
    AArch64,
    Riscv64,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FlowKind {
    Normal,
    Call,
    Return,
    CondBranch,
    UncondBranch,
    Syscall,
    Interrupt,
}

#[derive(Clone, Debug)]
pub struct Insn {
    pub len: usize,
    pub text: String,
    pub mnemonic: String,
    pub targets: Vec<u64>,
    pub flow: FlowKind,
    pub branch_target: Option<u64>,
}

#[repr(C)]
struct NndInsnOut {
    text: [c_char; 512],
    len: c_int,
    ntargets: c_int,
    targets: [u64; 4],
    insn_type: c_int,
    branch_hint: u64,
}

extern "C" {
    fn nnd_disasm_one(arch: c_int, addr: u64, buf: *const u8, buflen: c_int, out: *mut NndInsnOut) -> c_int;
}

fn classify(arch: Arch, mnemonic: &str) -> FlowKind {
    match arch {
        Arch::X86_64 => match mnemonic {
            "call" | "callq" | "lcall" => FlowKind::Call,
            "ret" | "retq" | "retn" | "retf" | "retw" | "retl" => FlowKind::Return,
            "jmp" | "jmpq" | "ljmp" => FlowKind::UncondBranch,
            "je" | "jz" | "jne" | "jnz" | "ja" | "jae" | "jb" | "jbe" | "jg" | "jge" | "jl" | "jle"
            | "js" | "jns" | "jo" | "jno" | "jp" | "jnp" | "jpe" | "jpo" | "jecxz" | "jrcxz"
            | "loop" | "loope" | "loopz" | "loopne" | "loopnz" => FlowKind::CondBranch,
            "syscall" | "sysenter" | "syscallq" => FlowKind::Syscall,
            "int" | "int1" | "int3" | "into" | "ud2" => FlowKind::Interrupt,
            _ => FlowKind::Normal,
        },
        Arch::AArch64 => {
            if mnemonic == "bl" || mnemonic == "blr" {
                FlowKind::Call
            } else if mnemonic == "ret" {
                FlowKind::Return
            } else if mnemonic == "b" {
                FlowKind::UncondBranch
            } else if mnemonic.starts_with("b.") || mnemonic.starts_with("bc.") {
                FlowKind::CondBranch
            } else if matches!(mnemonic, "cbz" | "cbnz" | "tbz" | "tbnz") {
                FlowKind::CondBranch
            } else if matches!(mnemonic, "svc" | "hvc" | "smc") {
                FlowKind::Syscall
            } else if matches!(mnemonic, "brk" | "hlt" | "udf") {
                FlowKind::Interrupt
            } else {
                FlowKind::Normal
            }
        }
        Arch::Riscv64 => match mnemonic {
            "call" => FlowKind::Call,
            "tail" => FlowKind::UncondBranch,
            "ret" | "jr" => {
                // `jr ra` / `ret` are returns; `jr` with other regs is an indirect jump.
                // binutils prints `ret` for `jalr x0, ra, 0`; bare `jr` usually means ra.
                if mnemonic == "ret" {
                    FlowKind::Return
                } else {
                    FlowKind::UncondBranch
                }
            }
            "j" | "jal" | "jalr" => {
                // `jal x0` prints as `j`; non-zero rd is a call.
                if mnemonic == "jal" {
                    FlowKind::Call
                } else if mnemonic == "jalr" {
                    FlowKind::Call
                } else {
                    FlowKind::UncondBranch
                }
            }
            "beq" | "bne" | "blt" | "bge" | "bltu" | "bgeu" | "beqz" | "bnez" | "blez" | "bgez"
            | "bltz" | "bgtz" | "bgt" | "ble" | "bgtu" | "bleu" => FlowKind::CondBranch,
            "ecall" => FlowKind::Syscall,
            "ebreak" | "c.ebreak" => FlowKind::Interrupt,
            _ => {
                // Compressed branches.
                if mnemonic.starts_with("c.b") || mnemonic.starts_with("c.beqz") || mnemonic.starts_with("c.bnez") {
                    FlowKind::CondBranch
                } else if mnemonic == "c.j" || mnemonic == "c.jr" {
                    FlowKind::UncondBranch
                } else if mnemonic == "c.jal" || mnemonic == "c.jalr" {
                    FlowKind::Call
                } else {
                    FlowKind::Normal
                }
            }
        },
    }
}

fn first_token(text: &str) -> String {
    text.split_whitespace()
        .next()
        .unwrap_or("")
        .trim_end_matches(':')
        .to_ascii_lowercase()
}

pub fn disassemble(arch: Arch, addr: u64, bytes: &[u8]) -> Insn {
    let empty = Insn {
        len: 0,
        text: String::new(),
        mnemonic: String::new(),
        targets: Vec::new(),
        flow: FlowKind::Normal,
        branch_target: None,
    };
    if bytes.is_empty() {
        return empty;
    }
    let mut out = NndInsnOut {
        text: [0; 512],
        len: 0,
        ntargets: 0,
        targets: [0; 4],
        insn_type: 0,
        branch_hint: 0,
    };
    let arch_i = match arch {
        Arch::X86_64 => 0,
        Arch::AArch64 => 1,
        Arch::Riscv64 => 2,
    };
    let rc = unsafe { nnd_disasm_one(arch_i, addr, bytes.as_ptr(), bytes.len() as c_int, &mut out) };
    if rc != 0 || out.len <= 0 {
        return empty;
    }
    let text = unsafe { CStr::from_ptr(out.text.as_ptr()) }
        .to_string_lossy()
        .into_owned();
    let text = text.trim().to_string();
    let mnemonic = first_token(&text);
    let flow = classify(arch, &mnemonic);
    let n = out.ntargets.max(0).min(4) as usize;
    let targets: Vec<u64> = out.targets[..n].to_vec();
    let branch_target = match flow {
        FlowKind::Call | FlowKind::CondBranch | FlowKind::UncondBranch | FlowKind::Return => {
            targets.first().copied().or(if out.branch_hint != 0 { Some(out.branch_hint) } else { None })
        }
        _ => None,
    };
    Insn { len: out.len as usize, text, mnemonic, targets, flow, branch_target }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x86_64_known_insns() {
        let i = disassemble(Arch::X86_64, 0x1000, &[0x90]);
        assert_eq!(i.mnemonic, "nop");
        assert_eq!(i.len, 1);
        assert_eq!(i.flow, FlowKind::Normal);

        let i = disassemble(Arch::X86_64, 0x1000, &[0xc3]);
        assert_eq!(i.mnemonic, "ret");
        assert_eq!(i.flow, FlowKind::Return);

        let i = disassemble(Arch::X86_64, 0x1000, &[0x0f, 0x05]);
        assert_eq!(i.mnemonic, "syscall");
        assert_eq!(i.flow, FlowKind::Syscall);

        let i = disassemble(Arch::X86_64, 0x1000, &[0xcc]);
        assert_eq!(i.flow, FlowKind::Interrupt);

        // call rel32 +0 → target 0x1005
        let i = disassemble(Arch::X86_64, 0x1000, &[0xe8, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(i.mnemonic, "call");
        assert_eq!(i.len, 5);
        assert_eq!(i.flow, FlowKind::Call);
        assert_eq!(i.branch_target, Some(0x1005));

        // jmp short -2 → target 0x1000
        let i = disassemble(Arch::X86_64, 0x1000, &[0xeb, 0xfe]);
        assert_eq!(i.mnemonic, "jmp");
        assert_eq!(i.flow, FlowKind::UncondBranch);
        assert_eq!(i.branch_target, Some(0x1000));

        // je +0
        let i = disassemble(Arch::X86_64, 0x1000, &[0x74, 0x00]);
        assert_eq!(i.mnemonic, "je");
        assert_eq!(i.flow, FlowKind::CondBranch);
    }

    #[test]
    fn aarch64_known_insns() {
        let i = disassemble(Arch::AArch64, 0x80000, &[0x1f, 0x20, 0x03, 0xd5]);
        assert_eq!(i.mnemonic, "nop");
        assert_eq!(i.len, 4);
        assert_eq!(i.flow, FlowKind::Normal);

        let i = disassemble(Arch::AArch64, 0x80000, &[0xc0, 0x03, 0x5f, 0xd6]);
        assert_eq!(i.mnemonic, "ret");
        assert_eq!(i.flow, FlowKind::Return);

        // bl +4 (imm=1 → +4)
        let i = disassemble(Arch::AArch64, 0x80000, &[0x01, 0x00, 0x00, 0x94]);
        assert_eq!(i.mnemonic, "bl");
        assert_eq!(i.len, 4);
        assert_eq!(i.flow, FlowKind::Call);
        assert_eq!(i.branch_target, Some(0x80004));

        // b 0 → self
        let i = disassemble(Arch::AArch64, 0x80000, &[0x00, 0x00, 0x00, 0x14]);
        assert_eq!(i.mnemonic, "b");
        assert_eq!(i.flow, FlowKind::UncondBranch);

        // svc #0
        let i = disassemble(Arch::AArch64, 0x80000, &[0x01, 0x00, 0x00, 0xd4]);
        assert_eq!(i.mnemonic, "svc");
        assert_eq!(i.flow, FlowKind::Syscall);
    }

    #[test]
    fn riscv64_known_insns() {
        // addi x0,x0,0 = nop
        let i = disassemble(Arch::Riscv64, 0x8000_0000, &[0x13, 0x00, 0x00, 0x00]);
        assert_eq!(i.mnemonic, "nop");
        assert_eq!(i.len, 4);
        assert_eq!(i.flow, FlowKind::Normal);

        // ecall
        let i = disassemble(Arch::Riscv64, 0x8000_0000, &[0x73, 0x00, 0x00, 0x00]);
        assert_eq!(i.mnemonic, "ecall");
        assert_eq!(i.flow, FlowKind::Syscall);

        // jal x0, 0 (j self)
        let i = disassemble(Arch::Riscv64, 0x8000_0000, &[0x6f, 0x00, 0x00, 0x00]);
        assert_eq!(i.len, 4);
        assert!(matches!(i.flow, FlowKind::UncondBranch | FlowKind::Call), "got {:?} ({})", i.flow, i.text);

        // jalr x0, 0(x0)
        let i = disassemble(Arch::Riscv64, 0x8000_0000, &[0x67, 0x00, 0x00, 0x00]);
        assert_eq!(i.len, 4);
        assert!(matches!(i.flow, FlowKind::Return | FlowKind::UncondBranch | FlowKind::Call), "got {:?} ({})", i.flow, i.text);

        // beq x0,x0,0
        let i = disassemble(Arch::Riscv64, 0x8000_0000, &[0x63, 0x00, 0x00, 0x00]);
        assert_eq!(i.flow, FlowKind::CondBranch);

        // c.nop (compressed) — binutils prints the plain mnemonic
        let i = disassemble(Arch::Riscv64, 0x8000_0000, &[0x01, 0x00]);
        assert_eq!(i.len, 2);
        assert_eq!(i.mnemonic, "nop");
        assert_eq!(i.flow, FlowKind::Normal);
    }

    #[test]
    fn invalid_bytes() {
        let i = disassemble(Arch::X86_64, 0x1000, &[]);
        assert_eq!(i.len, 0);
    }
}
