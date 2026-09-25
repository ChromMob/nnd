//! Disassembly via binutils libopcodes (x86-64, aarch64, riscv64).
//! Flow kinds classify printed mnemonics only — not a second decoder.

use std::ffi::c_int;

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
    /// First token, ASCII-lowercased.
    pub mnemonic: String,
    pub targets: Vec<u64>,
    pub flow: FlowKind,
    pub branch_target: Option<u64>,
}

#[repr(C)]
struct RawInsn {
    text: [u8; 512],
    len: c_int,
    ntargets: c_int,
    targets: [u64; 4],
    insn_type: c_int,
}

extern "C" {
    fn nnd_disasm_x86_64(addr: u64, buf: *const u8, buflen: c_int, out: *mut RawInsn) -> c_int;
    fn nnd_disasm_aarch64(addr: u64, buf: *const u8, buflen: c_int, out: *mut RawInsn) -> c_int;
    fn nnd_disasm_riscv64(addr: u64, buf: *const u8, buflen: c_int, out: *mut RawInsn) -> c_int;
}

pub fn disassemble(arch: Arch, addr: u64, bytes: &[u8]) -> Insn {
    if bytes.is_empty() {
        return Insn {
            len: 0,
            text: String::new(),
            mnemonic: String::new(),
            targets: Vec::new(),
            flow: FlowKind::Normal,
            branch_target: None,
        };
    }
    let mut raw = RawInsn {
        text: [0; 512],
        len: 0,
        ntargets: 0,
        targets: [0; 4],
        insn_type: 0,
    };
    let rc = unsafe {
        match arch {
            Arch::X86_64 => nnd_disasm_x86_64(addr, bytes.as_ptr(), bytes.len() as c_int, &mut raw),
            Arch::AArch64 => nnd_disasm_aarch64(addr, bytes.as_ptr(), bytes.len() as c_int, &mut raw),
            Arch::Riscv64 => nnd_disasm_riscv64(addr, bytes.as_ptr(), bytes.len() as c_int, &mut raw),
        }
    };
    if rc != 0 || raw.len <= 0 {
        return Insn {
            len: 0,
            text: String::new(),
            mnemonic: String::new(),
            targets: Vec::new(),
            flow: FlowKind::Normal,
            branch_target: None,
        };
    }
    let text_end = raw.text.iter().position(|&b| b == 0).unwrap_or(raw.text.len());
    // Binutils separates mnemonic and operands with TAB (and can emit other C0
    // controls). Those must never reach the TUI: tabs are written raw to the
    // terminal and break the ANSI cursor stream; they also have width 0 so
    // layout/draw disagree.
    let text: String = String::from_utf8_lossy(&raw.text[..text_end])
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let mnemonic = text
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    let ntargets = raw.ntargets.clamp(0, raw.targets.len() as c_int) as usize;
    let targets: Vec<u64> = raw.targets[..ntargets].to_vec();
    let flow = classify(arch, &mnemonic);
    let branch_target = match flow {
        FlowKind::Call | FlowKind::Return | FlowKind::CondBranch | FlowKind::UncondBranch => {
            targets.first().copied()
        }
        _ => None,
    };
    Insn {
        len: raw.len as usize,
        text,
        mnemonic,
        targets,
        flow,
        branch_target,
    }
}

fn classify(arch: Arch, m: &str) -> FlowKind {
    match arch {
        Arch::X86_64 => {
            // Intel syntax mnemonics as printed by binutils.
            if m == "call" || m == "callq" {
                FlowKind::Call
            } else if m == "ret" || m == "retq" || m == "retn" || m == "retf" {
                FlowKind::Return
            } else if m == "jmp" || m == "jmpq" {
                FlowKind::UncondBranch
            } else if matches!(
                m,
                "je"
                    | "jne"
                    | "jz"
                    | "jnz"
                    | "ja"
                    | "jae"
                    | "jb"
                    | "jbe"
                    | "jg"
                    | "jge"
                    | "jl"
                    | "jle"
                    | "js"
                    | "jns"
                    | "jo"
                    | "jno"
                    | "jp"
                    | "jnp"
                    | "jpe"
                    | "jpo"
                    | "jecxz"
                    | "jrcxz"
                    | "loop"
                    | "loope"
                    | "loopne"
                    | "loopz"
                    | "loopnz"
            ) {
                FlowKind::CondBranch
            } else if m == "syscall" || m == "sysenter" || m == "sysexit" || m == "sysret" {
                FlowKind::Syscall
            } else if matches!(m, "int" | "int1" | "int3" | "into" | "ud2" | "iret" | "iretq") {
                FlowKind::Interrupt
            } else {
                FlowKind::Normal
            }
        }
        Arch::AArch64 => {
            if m == "bl" || m == "blr" {
                FlowKind::Call
            } else if m == "ret" {
                FlowKind::Return
            } else if m == "b" || m == "br" {
                FlowKind::UncondBranch
            } else if m.starts_with("b.")
                || matches!(m, "cbz" | "cbnz" | "tbz" | "tbnz" | "bcz" | "bcnz")
            {
                FlowKind::CondBranch
            } else if matches!(m, "svc" | "hvc" | "smc" | "brk" | "bkpt" | "dcps1" | "dcps2" | "dcps3")
            {
                // svc is the A64 syscall convention.
                FlowKind::Interrupt
            } else {
                FlowKind::Normal
            }
        }
        Arch::Riscv64 => {
            // Match actual binutils printed mnemonics (including c.* compressed forms).
            if m == "ret" {
                FlowKind::Return
            } else if m == "call" {
                FlowKind::Call
            } else if matches!(m, "j" | "jr" | "c.j" | "c.jr" | "tail") {
                FlowKind::UncondBranch
            } else if matches!(m, "jal" | "jalr" | "c.jal" | "c.jalr") {
                // non-ret forms (ret handled above)
                FlowKind::Call
            } else if m.starts_with("beq")
                || m.starts_with("bne")
                || m.starts_with("blt")
                || m.starts_with("bge")
                || m.starts_with("bgeu")
                || m.starts_with("bltu")
                || m == "beqz"
                || m == "bnez"
                || m == "blez"
                || m == "bgez"
                || m == "bltz"
                || m == "bgtz"
                || m.starts_with("c.beqz")
                || m.starts_with("c.bnez")
                || m.starts_with("c.b")
            {
                FlowKind::CondBranch
            } else if matches!(m, "ecall" | "ebreak" | "c.ecall" | "c.ebreak" | "sret" | "mret") {
                FlowKind::Interrupt
            } else {
                FlowKind::Normal
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn x86_64_known_insns() {
        let cases: &[(&str, FlowKind, usize, Option<u64>)] = &[
            ("90", FlowKind::Normal, 1, None),
            ("c3", FlowKind::Return, 1, None),
            ("0f05", FlowKind::Syscall, 2, None),
            ("cc", FlowKind::Interrupt, 1, None),
            ("e800000000", FlowKind::Call, 5, Some(0x1005)),
            ("ebfe", FlowKind::UncondBranch, 2, Some(0x1000)),
            ("7400", FlowKind::CondBranch, 2, Some(0x1002)),
        ];
        for (bytes, flow, len, target) in cases {
            let insn = disassemble(Arch::X86_64, 0x1000, &hex(bytes));
            assert_eq!(insn.len, *len, "len for {bytes}: {insn:?}");
            assert_eq!(insn.flow, *flow, "flow for {bytes}: {insn:?}");
            assert_eq!(insn.branch_target, *target, "target for {bytes}: {insn:?}");
        }
    }

    #[test]
    fn aarch64_known_insns() {
        // svc #0 is 0xd4000001 (bytes 010000d4); the spec's e80300d4 is undefined.
        let cases: &[(&str, FlowKind, usize, Option<u64>)] = &[
            ("1f2003d5", FlowKind::Normal, 4, None),
            ("c0035fd6", FlowKind::Return, 4, None),
            ("01000094", FlowKind::Call, 4, Some(0x80004)),
            ("00000014", FlowKind::UncondBranch, 4, Some(0x80000)),
            ("010000d4", FlowKind::Interrupt, 4, None),
        ];
        for (bytes, flow, len, target) in cases {
            let insn = disassemble(Arch::AArch64, 0x80000, &hex(bytes));
            assert_eq!(insn.len, *len, "len for {bytes}: {insn:?}");
            assert_eq!(insn.flow, *flow, "flow for {bytes}: {insn:?}");
            assert_eq!(insn.mnemonic.split_whitespace().next().unwrap_or(""), match flow {
                FlowKind::Interrupt => "svc",
                FlowKind::Return => "ret",
                FlowKind::Call => "bl",
                FlowKind::UncondBranch => "b",
                FlowKind::Normal => "nop",
                _ => "",
            }, "mnemonic for {bytes}: {insn:?}");
            if let Some(t) = target {
                assert_eq!(insn.branch_target, Some(*t), "target for {bytes}: {insn:?}");
            }
        }
    }

    #[test]
    fn riscv64_known_insns() {
        // nop / ecall
        let insn = disassemble(Arch::Riscv64, 0x80000000, &hex("13000000"));
        assert_eq!(insn.mnemonic, "nop");
        assert_eq!(insn.len, 4);
        assert_eq!(insn.flow, FlowKind::Normal);

        let insn = disassemble(Arch::Riscv64, 0x80000000, &hex("73000000"));
        assert_eq!(insn.mnemonic, "ecall");
        assert_eq!(insn.flow, FlowKind::Interrupt);

        // jal x0, 0 — binutils may print j or jal; accept flow matching printed text.
        let insn = disassemble(Arch::Riscv64, 0x80000000, &hex("6f000000"));
        assert_eq!(insn.len, 4);
        assert!(
            insn.mnemonic == "j" || insn.mnemonic == "jal",
            "unexpected jal mnemonic: {insn:?}"
        );
        let expect = if insn.mnemonic == "j" {
            FlowKind::UncondBranch
        } else {
            FlowKind::Call
        };
        assert_eq!(insn.flow, expect, "{insn:?}");

        // jalr x0, 0(x0) — ret / jr / jalr depending on print.
        let insn = disassemble(Arch::Riscv64, 0x80000000, &hex("67000000"));
        assert_eq!(insn.len, 4);
        let expect = match insn.mnemonic.as_str() {
            "ret" => FlowKind::Return,
            "jr" => FlowKind::UncondBranch,
            "jalr" => FlowKind::Call,
            other => panic!("unexpected jalr mnemonic: {other}"),
        };
        assert_eq!(insn.flow, expect, "{insn:?}");

        // Binutils prints pseudos: beq→beqz, c.nop→nop (no c. prefix by default).
        let insn = disassemble(Arch::Riscv64, 0x80000000, &hex("63000000"));
        assert_eq!(insn.mnemonic, "beqz");
        assert_eq!(insn.flow, FlowKind::CondBranch);
        assert_eq!(insn.branch_target, Some(0x80000000));

        // c.nop (0x0001) prints as nop, 2 bytes.
        let insn = disassemble(Arch::Riscv64, 0x80000000, &hex("0100"));
        assert_eq!(insn.len, 2);
        assert_eq!(insn.mnemonic, "nop");
        assert_eq!(insn.flow, FlowKind::Normal);
    }

    #[test]
    fn text_has_no_control_chars() {
        // Binutils uses TAB between mnemonic and operands; must not reach the TUI.
        for bytes in ["13000000", "73000000", "30529073", "0890c0ef", "0ff0000f", "00008067", "63000000", "0100"] {
            let insn = disassemble(Arch::Riscv64, 0x1000, &hex(bytes));
            if insn.len == 0 {
                continue;
            }
            assert!(
                !insn.text.chars().any(|c| c.is_control()),
                "control char in {:?}: {:?}",
                insn.text,
                insn.text.chars().filter(|c| c.is_control()).collect::<Vec<_>>()
            );
            // mnemonic split still works with spaces instead of tabs
            assert!(!insn.mnemonic.is_empty() || insn.text.trim().is_empty(), "{:?}", insn);
        }
    }

    fn empty_is_invalid() {
        let insn = disassemble(Arch::X86_64, 0, &[]);
        assert_eq!(insn.len, 0);
        assert_eq!(insn.flow, FlowKind::Normal);
    }
}
