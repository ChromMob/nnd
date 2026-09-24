use crate::{*, symbols::*, error::*, symbols_registry::*, util::*, procfs::*, settings::*, common_ui::*, disasm::{self, Arch, FlowKind}};
use std::{fmt::Write, ops::Range, collections::HashSet};

// Upper bound on instruction length across supported arches (x86-64 is the widest at 15).
pub const MAX_X86_INSTRUCTION_BYTES: usize = 15;

// Disassembled function - a sequence of lines.
// For each line, a prefix is formatted by the UI on the fly (with some dynamic elements), a suffix is pre-formatted (in `text`).
//
// Example:
//  text                                                        DisassemblyLineKind       leaf_line   subfunction_idx
//
//  /usr/lib/x86_64-linux-gnu/libc.so.6                         Intro
//  dwarf offset: 0x1bee14                                      Intro
//                                                              Intro
//                         futex-internal.c:138:1               LeafLineNumber            138
//  7ffff7c91030 <  +0>    endbr64                              Instruction               138
//  7ffff7c91034 <  +4>    push r13                             Instruction               138
//  7ffff7c91036 <  +6>    mov r13d,esi                         Instruction               138
//                         futex-internal.c:138:1               LeafLineNumber            138
//  7ffff7c91039 <  +9>    push r12                             Instruction               138
//  7ffff7c9103b <  +b>    push rbx                             Instruction               138
//  7ffff7c9103c <  +c>    sub rsp,20h                          Instruction               138
//                         futex-internal.c:139:10              InlinedCallLineNumber     139         
//                         __futex_abstimed_wait_common         InlinedFunctionName       139
//                         ┆futex-internal.c:77:6               LeafLineNumber            77          42 (or whatever the idx of this inlined __futex_abstimed_wait_common is)
//  7ffff7c91040 < +10>    ┆test rcx,rcx                        Instruction               77          42
//  7ffff7c91043 < +13>  ↓ ┆jne near _+100h                     Instruction               77          42
//                         ┆futex-internal.c:80:6               LeafLineNumber            80          42
//  7ffff7c91049 < +19>    ┆cmp edx,1                           Instruction               80          42

pub struct Disassembly {
    pub text: StyledText,
    pub lines: Vec<DisassemblyLineInfo>, // parallel to `text` lines
    pub error: Option<Error>, // also baked into `lines`

    pub max_abs_relative_addr: usize,
    pub indent_width: usize,
    pub widest_line: usize,

    // Don't want to hold an Arc<Symbols> here, we look it up in SymbolsRegistry every frame. This shard_idx is just to assert that we found the correct one (so `subfunction` indices will match).
    pub symbols_shard: Option<usize>,
}

// Information about one line of text in the disassembly listing.
pub struct DisassemblyLineInfo {
    pub kind: DisassemblyLineKind,

    //  7ffff7c91043 < +13>  ↓ ┆jne near _+100h
    //  ^^^^^^^^^^^^   ^^^   ^  ^^^^^^^^^^^^^^^
    // static_addr     |     | |     `text`
    //     relative_addr     | |
    //          jump_indicator |
    //         subfunction_level

    // Address of the current or next instruction. For Intro: 0. For Error: usize::MAX. Binary-searchable. Should be rendered only for DisassemblyLineKind::Instruction.
    pub static_addr: usize,

    pub relative_addr: isize,
    pub jump_indicator: char,
    pub jump_target: Option<usize>,
    pub is_statement: bool,

    // Line number for the current or previous LeafLineNumber or InlinedCallLineNumber.
    pub leaf_line: Option<LineInfo>,
    // Innermost inlined function containing this line. For InlinedCallLineNumber and InlinedCallFunctionName: the *parent* subfunction (if any). Level always >= 1.
    pub subfunction: Option<usize>,
    pub subfunction_level: u16, // `subfunction` level, 0 if None; indentation level
}
impl Default for DisassemblyLineInfo { fn default() -> Self { Self {kind: DisassemblyLineKind::Error, static_addr: 0, relative_addr: 0, jump_indicator: ' ', jump_target: None, is_statement: false, subfunction_level: 0, leaf_line: None, subfunction: None} } }

#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub enum DisassemblyLineKind {
    Intro,
    InlinedCallLineNumber,
    InlinedFunctionName,
    LeafLineNumber,
    Instruction,
    Separator,
    Error,
}

impl Disassembly {
    pub fn new() -> Self { Self {text: StyledText::default(), lines: Vec::new(), error: None, max_abs_relative_addr: 0, indent_width: 1, widest_line: 0, symbols_shard: None} }

    pub fn static_addr_to_line(&self, static_addr: usize) -> Option<usize> {
        let idx = self.lines.partition_point(|l| l.static_addr <= static_addr);
        if idx > 0 && self.lines[idx-1].static_addr == static_addr && self.lines[idx-1].kind == DisassemblyLineKind::Instruction {
            Some(idx-1)
        } else {
            None
        }
    }

    // If pseudo_addr is in between instructions, round down to the previous instruction.
    // If pseudo_addr is out of range, return either first or last line (whichever is closed), with `found` = false.
    pub fn static_pseudo_addr_to_line(&self, static_pseudo_addr: usize) -> (usize, /*found*/ bool) {
        let idx = self.lines.partition_point(|l| l.static_addr <= static_pseudo_addr);
        if idx == 0 { return (0, false); }
        let l = &self.lines[idx-1];
        // (Would be better to compare to function addr ranges instead of the MAX_X86_INSTRUCTION_BYTES guesswork.)
        if l.kind == DisassemblyLineKind::Instruction && l.static_addr + MAX_X86_INSTRUCTION_BYTES > static_pseudo_addr {
            (idx-1, true)
        } else {
            (idx-1, false)
        }
    }

    pub fn with_error(mut self, e: Error, palette: &Palette) -> Self {
        assert!(self.error.is_none());
        styled_writeln!(self.text, palette.error, "{}", e);
        self.lines.push(DisassemblyLineInfo {kind: DisassemblyLineKind::Error, static_addr: usize::MAX, ..Default::default()});
        self.error = Some(e);
        self.finish()
    }

    pub fn finish(mut self) -> Self {
        assert_eq!(self.text.num_lines(), self.lines.len());
        for i in 0..self.lines.len() {
            self.widest_line = self.widest_line.max(self.lines[i].subfunction_level as usize * self.indent_width + str_width(self.text.get_line_str(i)));
            self.max_abs_relative_addr = self.max_abs_relative_addr.max(self.lines[i].relative_addr.abs() as usize);
        }
        self
    }
}

pub fn disassemble_function(function_idx: usize, mut static_addr_ranges: Vec<Range<usize>>, symbols: Option<&Symbols>, code: Option<&[u8]>, intro: StyledText, palette: &Palette) -> Disassembly {
    clean_up_ranges(&mut static_addr_ranges);

    let mut res = Disassembly {text: intro, lines: Vec::new(), error: None, max_abs_relative_addr: 0, indent_width: str_width(&palette.tree_indent.0), widest_line: 0, symbols_shard: None};
    let mut subfunc_idxs: Vec<Range<usize>> = Vec::new();
    let mut subfunctions: &[Subfunction] = &[];
    let mut seen_subfunction_identities: HashSet<u32> = HashSet::new();

    while res.lines.len() < res.text.num_lines() {
        res.lines.push(DisassemblyLineInfo {kind: DisassemblyLineKind::Intro, static_addr: 0, ..Default::default()});
    }

    if let Some(symbols) = &symbols {
        let function = &symbols.functions[function_idx];
        res.symbols_shard = Some(function.shard_idx());
        subfunc_idxs = (1..function.num_levels()).map(|i| symbols.subfunction_idxs_at_level(i, function)).collect();
        subfunctions = &symbols.shards[function.shard_idx()].subfunctions;
    }

    for (addr_range_idx, static_addr_range) in static_addr_ranges.iter().enumerate() {
        if static_addr_range.len() > 100_000_000 {
            return res.with_error(error!(Sanity, "{} MB to disassemble, suspiciously much", static_addr_range.len() / 1_000_000), palette);
        }

        let code: &[u8] = if let Some(code) = code.clone() {
            assert_eq!(static_addr_ranges.len(), 1);
            code
        } else if let Some(symbols) = &symbols {
            // Read the machine code from file rather than memory so that it doesn't show our breakpoint instructions.
            match symbols.elves[0].addr_range_to_offset_range(static_addr_range.start, static_addr_range.end) {
                None => return res.with_error(error!(Dwarf, "function address range out of bounds of executable: {:x}-{:x}", static_addr_range.start, static_addr_range.end), palette),
                Some((start, end)) => &symbols.elves[0].data()[start..end],
            }
        } else {
            panic!("huh");
        };

        if addr_range_idx != 0 {
            styled_write!(res.text, palette.disas_default,  "──────────");
            res.text.close_line();
            res.lines.push(DisassemblyLineInfo {kind: DisassemblyLineKind::Separator, static_addr: static_addr_range.start, ..Default::default()});
        }

        let arch = symbols.map(|s| s.elves[0].arch()).unwrap_or(Arch::X86_64);
        let mut code_pos = 0usize;
        let mut ip = static_addr_range.start as u64;

        let mut line_iter = if let Some(symbols) = &symbols {
            let mut line_iter = symbols.addr_to_line_iter(static_addr_range.start).peekable();
            line_iter.next_if(|line| line.addr() < static_addr_range.start);
            Some(line_iter)
        } else {
            None
        };

        let mut prev_static_addr = 0usize;
        let mut cur_leaf_line: Option<LineInfo> = None;

        while code_pos < code.len() {
            let insn = disasm::disassemble(arch, ip, &code[code_pos..]);
            if insn.len == 0 {
                // Undecodable: stop this range (error line appended below via with_error on a temp).
                styled_writeln!(res.text, palette.error, "failed to decode instruction at 0x{:x}", ip);
                res.lines.push(DisassemblyLineInfo {kind: DisassemblyLineKind::Error, static_addr: usize::MAX, ..Default::default()});
                res.error = Some(error!(Dwarf, "failed to decode instruction at 0x{:x}", ip));
                break;
            }
            let instruction_ip = ip as usize;

            if let Some(l) = res.lines.last() {
                assert!(instruction_ip >= l.static_addr); // can be == because the "-----[...]" separator above is assigned to address of the first instruction after it
            }
            let static_addr = instruction_ip;
            let mut subfunction_level = 0u16;
            let mut cur_subfunction: Option<usize> = None;
            let mut is_statement = false;

            if let &Some(symbols) = &symbols {
                let write_line_number = |line: LineInfo, kind: DisassemblyLineKind, res: &mut Disassembly, subfunction_level: u16, leaf_line: &mut Option<LineInfo>, subfunction: Option<usize>| {
                    let file = match line.file_idx() {
                        None => return,
                        Some(f) => f };
                    *leaf_line = Some(line.clone());
                    let file = &symbols.files[file];
                    let name = file.filename.as_os_str().to_string_lossy();
                    styled_write!(res.text, palette.disas_filename, "{}", name);
                    if line.line() != 0 {
                        styled_write!(res.text, palette.line_number, ":{}", line.line());
                        if line.column() != 0 {
                            styled_write!(res.text, palette.column_number, ":{}", line.column());
                        }
                    }
                    res.text.close_line();
                    res.lines.push(DisassemblyLineInfo {kind, static_addr, subfunction_level, leaf_line: leaf_line.clone(), subfunction, ..Default::default()});
                };

                // Add inlined function calls information: function names, call line numbers, and indentation.
                let function = &symbols.functions[function_idx];
                for r in subfunc_idxs.iter_mut() {
                    while r.start < r.end && subfunctions[r.start].addr_range.end <= static_addr {
                        r.start += 1;
                    }
                    if r.start == r.end || subfunctions[r.start].addr_range.start > static_addr {
                        break;
                    }
                    cur_subfunction = Some(r.start);
                    let subfunction = &subfunctions[r.start];
                    subfunction_level += 1;
                    if subfunction.addr_range.start > prev_static_addr {
                        let callee_name = if subfunction.callee_idx == usize::MAX {
                            "?".to_string()
                        } else {
                            symbols.functions[subfunction.callee_idx].demangle_name()
                        };

                        write_line_number(subfunction.call_line.clone(), DisassemblyLineKind::InlinedCallLineNumber, &mut res, subfunction_level, &mut cur_leaf_line, cur_subfunction.clone());

                        styled_write!(res.text, palette.default_dim, "{}", callee_name);

                        if !seen_subfunction_identities.insert(subfunction.identity) {
                            // Indicate that the inlined function has multiple address ranges.
                            styled_write!(res.text, palette.default_dim, " [cont]");
                        }
                        res.text.close_line();
                        res.lines.push(DisassemblyLineInfo {kind: DisassemblyLineKind::InlinedFunctionName, static_addr, subfunction_level, leaf_line: cur_leaf_line.clone(), subfunction: cur_subfunction.clone(), ..Default::default()});
                    }
                }

                // Add line number information.
                while let Some(line) = line_iter.as_mut().unwrap().next_if(|line| line.addr() <= static_addr) {
                    write_line_number(line, DisassemblyLineKind::LeafLineNumber, &mut res, subfunction_level, &mut cur_leaf_line, cur_subfunction.clone());

                    if line.addr() == static_addr && line.flags().contains(LineFlags::STATEMENT) {
                        is_statement = true;
                    }
                }
            }

            prev_static_addr = static_addr;

            let mut jump_target: Option<usize> = None;
            let jump_indicator = match insn.flow {
                FlowKind::Normal => ' ',
                FlowKind::Return => '←',
                FlowKind::Call => '→',
                FlowKind::Syscall | FlowKind::Interrupt => '!',
                FlowKind::UncondBranch | FlowKind::CondBranch => match insn.branch_target {
                    None => '↕',
                    Some(t) => {
                        jump_target = Some(t as usize);
                        if t as usize > static_addr { '↓' } else { '↑' }
                    }
                },
            };

            // Instruction text from binutils; lightly substitute branch targets with symbols.
            let mut text_out = insn.text;
            if let (Some(symbols), Some(t)) = (symbols, insn.branch_target) {
                if let Ok((f, _)) = symbols.addr_to_function(t as usize) {
                    let name = if static_addr_range.contains(&(t as usize)) {
                        "_".to_string()
                    } else {
                        f.demangle_name()
                    };
                    let off = (t as usize).wrapping_sub(f.addr.addr().unwrap_or(t as usize));
                    let repl = if off == 0 { name } else if name == "_" { format!("_+0x{:x}", off) } else { format!("{}+0x{:x}", name, off) };
                    for hex in [format!("0x{:x}", t), format!("0x{:X}", t), format!("{:x}", t)] {
                        if text_out.contains(&hex) {
                            text_out = text_out.replace(&hex, &repl);
                            break;
                        }
                    }
                }
            }
            styled_write!(res.text, palette.disas_mnemonic, "{}", text_out);
            res.text.close_line();
            res.lines.push(DisassemblyLineInfo {kind: DisassemblyLineKind::Instruction, static_addr, relative_addr: static_addr as isize - static_addr_range.start as isize, subfunction_level, jump_indicator, jump_target, is_statement, leaf_line: cur_leaf_line.clone(), subfunction: cur_subfunction.clone()});

            code_pos += insn.len;
            ip = static_addr as u64 + insn.len as u64;
        }
    }
    res.finish()
}

fn clean_up_ranges(ranges: &mut Vec<Range<usize>>) {
    if ranges.is_empty() {
        return;
    }
    ranges.sort_unstable_by_key(|r| r.start);
    let mut j = 0;
    for i in 1..ranges.len() {
        if ranges[i].start > ranges[j].end {
            // Normal case.
            j += 1;
            ranges[j] = ranges[i].clone();
        } else if ranges[i].end <= ranges[j].end {
            // This range is contained in another. Discard.
        } else {
            // This range overlaps another. Extend.
            ranges[j].end = ranges[i].end;
        }
    }
    ranges.truncate(j+1);
}
