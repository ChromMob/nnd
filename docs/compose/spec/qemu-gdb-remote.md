---
feature: qemu-gdb-remote
status: delivered
updated: 2026-09-24
branch: qemu-gdb-remote
commits: 93731d2..1188d25
---

# QEMU-system GDB remote + multi-arch (binutils disassembly)

## Report

**What was built** — nnd can attach as a GDB remote client to a stub the user starts (`qemu-system-… -s -S`, then `nnd --remote 127.0.0.1:1234 [vmlinux]`). A full RSP codec/client (`gdbproto`/`gdb_remote`) drives memory, registers, `vCont`, and `Z0–Z4` breakpoints; `RunMode::Remote` branches resume/step/events/breakpoints/shutdown off ptrace. ELF accepts x86-64, aarch64, and riscv64; target.xml (including nested `xi:include`) feeds register layout. Disassembly uses pinned binutils 2.47 libopcodes via `build.rs` + a C shim for all three arches (Intel syntax on x86); iced-x86 is gone from the tree. Listing and step-flow call the shared `disasm::disassemble` API with per-arch mnemonic flow tables.

**Verification** — `cargo build --locked` PASS. `cargo test --locked --bin nnd` — 34/34 PASS, including e2e against `qemu-system-{x86_64,aarch64,riscv64}` asserting connect → read PC → Z0 → continue → stop. One earlier parallel-run flake of the x86 e2e; isolated and subsequent full runs green. Independent re-review approved all five prior critical fixes (remote step `vCont`, data `Z2/Z4`, step Z cleanup, arch-aware analysis, `single_steps`-only step cont).

**Journey log** —
- Two parallel implementation agents were cancelled early; recovered by implementing binutils/GDB paths directly in-session.
- System libopcodes is x86-only; multi-arch requires building pinned binutils (`third_party/build-opcodes.sh`).
- QEMU returns `qXfer` payloads as raw XML (not hex) and nests registers in `xi:include` files — client must fetch includes and accept both encodings.
- aarch64 virt at `-S` reports PC=0 until the first instruction; smokes step once before arming Z0.
- Remote mode must never call ptrace resume paths; all continue/step go through `remote_send_cont` (`vCont;s` only when `single_steps`).

## [S1] Problem

nnd can only debug native Linux x86-64 processes via ptrace (README: "Linux only / x86 only / 64-bit only"). There is no way to attach to a `qemu-system-*` VM through QEMU's GDB stub, and no way to debug aarch64 or riscv64 guests. Disassembly is hardwired to iced-x86, which covers only x86; hand-rolling per-arch decoders is out of the question.

## [S2] Design

**Target model — `RunMode::Remote`.** New CLI form `nnd --remote <host:port> <elf> [more elfs]` connects as a GDB client to an **already-running** stub the user started (e.g. `qemu-system-<arch> … -s -S`, where `-s` is `-gdb tcp::1234`). nnd never spawns or manages QEMU. No pid, no `/proc` maps, no pty, no fork/exec/signal events. Threads are whatever `qfThreadInfo` reports (vCPUs under QEMU); symbols come from the user-supplied ELF(s) laid over their `PT_LOAD` vaddrs (synthetic `MemMapsInfo`); debuggee console is the stub's, not nnd's.

**Transport — GDB remote serial protocol** (`src/gdbproto.rs` codec, `src/gdb_remote.rs` client):

- Framing `$…#cs`, checksum, binary escaping, `QStartNoAckMode`, partial-packet reassembly on a nonblocking TCP stream.
- Ops: `qSupported`, `qXfer:features:read` (target description XML), `?`, `Hg`/`Hc`, `qfThreadInfo`/`qsThreadInfo`/`qC`, `g`/`p`/`P`, `m`/`M`, `vCont;c`/`vCont;s`, `Z0`–`Z4`/`z0`–`z4`, interrupt (`\x03`), `k`, `D`.
- Stop replies (`T05…`, `S05`, `swbreak`/`hwbreak`/`watch`/`rwatch`/`awatch`) map onto semantic events: `BreakpointHit{thread, addr, kind}`, `StepComplete{thread}`, `WatchpointHit`, `AllStopped`.
- Every register/memory access is preceded by `Hg<thread>` so QEMU translates through the right vCPU's page tables (SMP-safe).

**Debugger integration.** `Debugger` gains a backend split (`Ptrace` vs `Remote`): memory r/w, reg r/w, resume/suspend/step/interrupt, event polling, breakpoint arm/disarm, thread enumeration, and shutdown branch on it. Remote mode bypasses ptrace quirks entirely (no RIP−1 after `int3`, no DR6, no SINGLESTEP/group-stop dance) because QEMU reports `swbreak`/`hwbreak` with PC already at the instruction. UI keeps rendering whatever thread list the backend supplies (vCPUs appear in the threads window).

**Disassembly — one engine, binutils/libopcodes, all arches (x86-64, aarch64, riscv64).** Same as GDB: disassembly is client-side; there is no RSP disassemble packet. nnd embeds libopcodes instead of maintaining iced-x86 + per-arch decoders:

- Build multi-arch `libopcodes` from a pinned binutils release (system package is x86-only) via `build.rs` + `third_party/` script; link statically. A C shim (`dis-asm.h` callbacks) exposes: disassemble one instruction at an address → text, length, captured address operands (`print_address_func`), and `insn_type` when the printer sets it.
- x86 listing uses Intel syntax (`disassembler("i386", …, "intel")`) to preserve nnd's current look.
- Flow classification for step-over/range-step (call/ret/cond-branch/uncond-branch/syscall/other) from mnemonic tables per arch (plus `insn_type` as a hint) — this is classification on top of binutils, the same layering as GDB's `gdbarch`, not a second decoder.
- iced-x86 is removed from the dependency tree once call sites move over.

**Registers.** Parse the stub's target-description XML (name, number, size, group) into arch-specific descriptors; keep the fat `[u64; N]` `Registers` storage with semantic aliases (`PC`, `SP`, `FP`, `LR` as available) so existing UI/watch code keeps working. DWARF register maps per arch for unwind (riscv: x0–x31 = 0–31, pc = 32; aarch64 per psABI). XSAVE/`cpuid` paths remain ptrace-only.

**ELF gate.** `elf.rs` accepts `EM_X86_64` (0x3e), `EM_AARCH64` (183), `EM_RISCV` (243).

**Breakpoints.** `Z0` (sw, kind = insn size), `Z1` (hw bp), `Z2`/`Z3`/`Z4` (write/read/access watch) — maps onto nnd's existing software/hardware/data breakpoint model; QEMU inserts/removes the trap bytes itself.

**CLI/docs.** `--remote <addr>` (required host:port; docs show `127.0.0.1:1234` for `qemu -s`); extra ELF paths reuse the supplementary-binaries machinery. `doc.rs`/README document the mode and its limits.

### Testing boundaries

- Unit: packet codec (framing, checksum, escape, reassembly); binutils shim (known byte sequences per arch, length, targets, mnemonic flow); target.xml parser; ELF synthetic maps; flow tables.
- Integration (skipped cleanly when qemu is absent): against `qemu-system-{x86_64,aarch64,riscv64} -s -S -display none` started by the test — connect, read PC/memory at reset, set/clear `Z0`, `vCont` stop-reply; plus one `Debugger`-level smoke (connect → read regs → breakpoint → continue → hit) on the first arch with a bootable payload.
- Baseline: `cargo build --locked` on the worktree before changes must stay green (`PRE-EXISTING` any failures discovered later).

## [S3] Out of Scope

- qemu-user mode; ptrace of the qemu process as a proxy for the guest.
- Native nnd port to aarch64/riscv64 *hosts* (rdtsc/AVX host bits stay x86).
- RV32; 32-bit anything (nnd remains 64-bit-only).
- Guest-Linux process discovery, ASLR slide inference, kernel ORC unwinding, guest signal/syscall event streams.
- Non-stop RSP mode, multiprocess `ppid.tid` extension beyond what QEMU needs, reverse execution, record/replay.
- Phase-3 polish beyond what falls out naturally: memory-read coalescing cache, reconnect UX, deep SMP stop-reason per-vCPU UI.
- DAP/GUI; spawning or managing QEMU (or any stub) from nnd — the user launches it (`qemu … -s -S`) and nnd only connects.

## Tasks

- [x] T1: Multi-arch libopcodes build (pinned binutils, static link via build.rs) — acceptance: `cargo build --locked` succeeds with libopcodes linked; shim disassembles fixed x86-64, aarch64, and riscv64 byte sequences to expected text/length in unit tests (covers: S2 Disassembly)
- [x] T2: Disasm Rust API + flow/mnemonic tables (3 arches, Intel x86) — acceptance: public API returns text, length, targets, flow kind; unit tests cover call/branch/ret/syscall classification per arch (covers: S2 Disassembly; depends: T1)
- [x] T3: `gdbproto` codec + `gdb_remote` client — acceptance: codec unit tests (frame/cksum/escape/no-ack/partial reads); client implements qSupported, target.xml fetch, threads, mem, regs, vCont, Z packets, stop-reply parse — unit-tested against an in-process mock stub (covers: S2 Transport)
- [x] T4: Debugger `Remote` backend + CLI `--remote` + synthetic maps — acceptance: `nnd --remote 127.0.0.1:PORT` connects to a user/test-started stub; integration test starts `qemu-system-x86_64 -s -S`, connects, read PC/memory → set breakpoint → continue → observes stop; ptrace path unchanged (`cargo build --locked` + existing tests green) (covers: S2 Target model, Debugger integration, Breakpoints, CLI; depends: T3)
- [x] T5: Multi-arch registers/ELF/unwind (target.xml parse, e_machine 183/243, DWARF maps) — acceptance: target.xml fixture tests for x86-64/aarch64/riscv64; `elf.rs` accepts the three machines and still rejects others; register names/aliases resolve; integration smoke on `qemu-system-aarch64` and `qemu-system-riscv64` (connect, read PC, Z0+stop) (covers: S2 Registers, ELF gate; depends: T4, T2)
- [x] T6: Move listing + step-flow off iced-x86 onto binutils backend — acceptance: `disassembly.rs`/`debugger.rs` step analysis use the new API; `iced-x86` removed from `Cargo.toml`; unit + integration tests pass (covers: S2 Disassembly; depends: T2, T4)
- [x] T7: Docs (`doc.rs` help, README limitations) — acceptance: `--remote` appears in CLI help; README limitations updated to describe remote mode honestly (covers: S2 CLI/docs; depends: T4)
