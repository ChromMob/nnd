use crate::{*, debugger::*, error::*, util::*, symbols::*, symbols_registry::*, procfs::*, unwind::*, registers::*, log::*, settings::*, elf::*, os::*};
use std::{collections::{HashMap, hash_map::Entry}, time::Instant, fs, os::unix::fs::MetadataExt, sync::Arc, ops::Range, str};
use std::mem;
use libc::pid_t;

pub struct ProcessInfo {
    pub maps: MemMapsInfo,
    pub r_debug: Result<RDebug>,
    pub exe_inode: u64,

    // CPU and memory usage, total across all threads, recalculated periodically.
    pub total_resource_stats: ResourceStats,
}
impl Default for ProcessInfo { fn default() -> Self { Self {maps: Default::default(), r_debug: err!(Loading, "loading"), exe_inode: 0, total_resource_stats: Default::default()} } }

#[derive(Default)]
pub struct ThreadInfo {
    pub regs: Registers,
    pub extra_regs: LazyExtraRegisters,

    // These are calculated lazily and cleared when the thread switches from Running to Suspended. None means it wasn't requested yet.
    // Errors are reported through StackTrace.truncated field.
    //
    // The "partial" stack trace is intended to be shown in the list of threads, for each thread.
    // Usually debuggers show the current function name there, but that function is usually something boring like epoll or futex wait.
    // Maybe we can do better and also show the most "interesting" function from the stack trace - maybe the first function from main
    // binary, or maybe let the user specify a regex for functions to exclude, or something.
    pub partial_stack: Option<StackTrace>,
    pub stack: Option<StackTrace>,

    pub resource_stats: ResourceStats,

    // Remote stub only: GDB-register names + values from the g packet (pc, sp, ra, ...).
    pub remote_gregs: Option<Vec<(String, u64)>>,
}

#[derive(Default)]
pub struct ResourceStatsBucket {
    utime: usize,
    stime: usize,
    duration_ns: usize,
}

// r_debug struct filled out by glibc dynamic linker, containing information about loaded libraries.
// All we need from it is tls_offset for each loaded binary, to locate thread-local variables.
// Doesn't work with musl.
pub struct RDebug {
    link_maps: Vec<RDebugLinkMap>,
}

pub struct RDebugLinkMap {
    ld: usize, // pointer to mapped .dynamic section
    tls_offset: usize,
    tls_modid: usize,
}

// Information about thread's recent CPU usage, excluding periods of time when the thread was suspended by the debugger.
#[derive(Default)]
pub struct ResourceStats {
    pub latest: ProcStat,
    // Time when `latest` was collected. None if the thread is suspended by the debugger.
    time: Option<Instant>,
    pub error: Option<Error>, // if we failed to read /proc/.../stat last time we tried

    // If all stats updates happened by periodic timer every 250ms then calculating current CPU usage would be simple:
    // subtract the stat values between current and previous tick. But we want to (1) exclude periods when the thread
    // was suspended by the debugger, and (2) show updated stats immediately when the thread is suspended or resumed.
    // Suppose the user suspends the program 1ms after a periodic refresh. Should we show CPU usage for the 1ms?
    // Or ignore the 1ms and show usage for previous 250ms? Ideally we'd show usage for the whole 251ms. That's why
    // we're keeping two buckets of history here. If the latest bucket is big enough we show stats from it, otherwise
    // we show merged stats from two buckets.
    // (Perhaps this is overengineered, and it would be better to just have a threshold and ignore the 1ms.)
    bucket: ResourceStatsBucket,
    prev_bucket: ResourceStatsBucket,
}
impl ResourceStats {
    pub fn update(&mut self, s: Result<ProcStat>, now: Instant, suspended: bool, periodic_timer_ns: usize) {
        self.error = None;
        let s = match s {
            Err(e) => {
                self.error = Some(e);
                return;
            }
            Ok(s) => s,
        };
        if let &Some(t) = &self.time {
            let ns = (now - t).as_nanos() as usize;
            if (self.bucket.duration_ns + ns) * 2 > periodic_timer_ns {
                self.prev_bucket = mem::take(&mut self.bucket);
            }
            self.bucket.duration_ns += ns;
            self.bucket.utime += s.utime - self.latest.utime;
            self.bucket.stime += s.stime - self.latest.stime;
        }
        self.latest = s;
        self.time = if suspended {None} else {Some(now)};
    }

    pub fn cpu_percentage(&self, periodic_timer_ns: usize) -> f64 {
        let mut t = self.bucket.duration_ns;
        let mut cpu = self.bucket.utime + self.bucket.stime;
        if self.bucket.duration_ns * 2 <= periodic_timer_ns {
            t += self.prev_bucket.duration_ns;
            cpu += self.prev_bucket.utime + self.prev_bucket.stime;
        }
        if t == 0 {
            return 0.0;
        }
        cpu as f64 * 1e9 / sysconf_SC_CLK_TCK() as f64 / t as f64 * 100.0
    }
}

impl ProcessInfo {
    pub fn addr_to_binary_id(&self, addr: usize) -> Result<usize> {
        let idx = self.maps.maps.partition_point(|m| m.start + m.len <= addr);
        if idx == self.maps.maps.len() || self.maps.maps[idx].start > addr {
            return err!(ProcessState, "address not mapped");
        }
        match self.maps.maps[idx].binary_id.clone() {
            None => err!(ProcessState, "address not mapped to executable file"),
            Some(id) => Ok(id),
        }
    }

    pub fn clear(&mut self) {
        self.maps.clear();
    }

    pub fn drop_caches(&mut self) {
        self.r_debug = err!(Loading, "loading");
    }
}

impl ThreadInfo {
    pub fn invalidate(&mut self, mode: RunMode) {
        if mode != RunMode::CoreDump {
            self.regs = Registers::default();
        }
        self.partial_stack = None;
        self.stack = None;
        // Keep remote_gregs: they refresh with registers, not with drop_caches of stacks.
    }
}

pub fn refresh_maps_and_binaries_info(debugger: &mut Debugger) -> /*binaries_added*/ bool {
    if debugger.info.exe_inode == 0 && debugger.target_state.process_ready() && !debugger.mode.is_remote() {
        let path = format!("/proc/{}/exe", debugger.any_live_tid);
        let m = match fs::metadata(&path) {
            Err(e) => {
                eprintln!("error: failed to read {}: {}", path, e);
                return false;
            }
            Ok(x) => x };
        debugger.info.exe_inode = m.ino();
        if debugger.info.exe_inode == 0 {
            eprintln!("error: stat({}) returned inode number 0", path);
            debugger.info.exe_inode = u64::MAX;
        }
    }

    let mut maps = if debugger.mode == RunMode::CoreDump || debugger.mode.is_remote() {
        // For core dump, we need to do refresh_maps_and_binaries_info() twice even though maps never change.
        // The first time we kick off symbols loading for all mapped binaries.
        // After ELF files for all binaries are loaded, we need to point CoreDumpMemReader to them - that's what subsequent refreshes are for.
        // Why not just parse ELF headers for all binaries synchronously in first refresh?
        // Because the plan is to support downloading binaries from debuginfod, which is not necessarily fast, so we shouldn't lock up the UI.
        // For Remote, maps are synthesized from user-supplied ELFs at connect time and never change.
        debugger.info.maps.clone()
    } else {
        // (any_live_tid rather than pid because for a zombie main thread /proc/<pid>/maps is empty.)
        match MemMapsInfo::read_proc_maps(debugger.any_live_tid) {
            Err(e) => {
                eprintln!("error: failed to read maps: {}", e);
                return false;
            }
            Ok(m) => m
        }
    };

    let prev_mapped = debugger.symbols.mark_all_as_unmapped();

    let mut new_elves: Vec<(Range<usize>, /*offset*/ usize, Arc<ElfFile>)> = Vec::new();
    let mut found_main_binary = false;
    for (idx, map) in maps.maps.iter_mut().enumerate() {
        let locator = match &map.binary_locator {
            None => continue,
            Some(b) => b,
        };
        let bin = match debugger.symbols.locator_to_id.get(locator) {
            Some(id) => debugger.symbols.get_mut(*id).unwrap(),
            None => {
                let mut build_id: Option<Vec<u8>> = None;
                if map.offset == 0 {
                    match extract_build_id_from_mapped_elf(&debugger.memory, map.start, map.len) {
                        Ok(id) => build_id = Some(id),
                        Err(e) => eprintln!("warning: couldn't extract build id from mapped binary {}: {}", locator.path, e),
                    }
                }
                if let Some(id) = &build_id {
                    eprintln!("info: mapped binary {} has build id {}", locator.path, hexdump(id, 1000));
                }
                let custom_path = if matches!(debugger.mode, RunMode::Run | RunMode::Attach) && locator.inode == debugger.info.exe_inode {
                    // Use this special symlink instead of the regular path because it's available even after the file is deleted.
                    // Useful when recompiling the program without closing the debugger.
                    Some(format!("/proc/{}/exe", debugger.any_live_tid))
                } else {
                    None
                };
                // Guess which binary is the main executable. (If this turns out unreliable, we can switch to determining this from ELF header instead (which is less convenient because we currently parse ELF header after we use this info).)
                let is_main_binary = !found_main_binary && if matches!(debugger.mode, RunMode::CoreDump | RunMode::Remote) {
                    locator.special.is_none() // take the first binary on the list, except [vdso]
                } else {
                    locator.inode == debugger.info.exe_inode
                };
                found_main_binary |= is_main_binary;
                debugger.symbols.add(locator.clone(), &debugger.memory, custom_path, build_id, is_main_binary)
            }
        };
        map.binary_id = Some(bin.id);
        bin.is_mapped = true;
        if let Ok(elves) = &bin.elves {
            bin.addr_map.update(map, &elves[0], &locator.path);
        }
        bin.mmap_idx = idx;
        if !map.elf_seen {
            if let Ok(elves) = &bin.elves {
                map.elf_seen = true;
                new_elves.push((map.start..map.start+map.len, map.offset, elves[0].clone()));
            }
        }
    }
    debugger.symbols.update_priority_order();

    debugger.info.maps = maps;

    if !new_elves.is_empty() && debugger.mode == RunMode::CoreDump {
        let mut new_ranges = match &debugger.memory {
            MemReader::CoreDump(x) => x.ranges.clone(),
            _ => panic!("huh"),
        };
        for (range, off, elf) in new_elves {
            // (It's not expected that new_ranges has ranges that partially overlap the mmap range, so we silently ignore them instead of splitting.)
            let mut idx = new_ranges.partition_point(|r| r.start_address < range.start);
            while idx < new_ranges.len() && new_ranges[idx].start_address < range.end {
                let r = &mut new_ranges[idx];
                match &r.source {
                    CoreDumpMemorySource::MissingFile => {
                        // Core dump says that the crashed process had this address range mapped to a file, and we located that file (`elf`). Point MemReader to it.
                        let offset = off + (r.start_address - range.start);
                        r.source = CoreDumpMemorySource::File {file: elf.clone(), offset};
                    }
                    _ => (),
                }
                idx += 1;
            }
        }
        debugger.memory = MemReader::CoreDump(Arc::new(CoreDumpMemReader {ranges: new_ranges}));
    }

    if debugger.info.r_debug.as_ref().is_err_and(|e| e.is_loading()) {
        // How TLS works (in the simpler static models; dynamic TLS models add another indirection through DTV that we don't support):
        //  * .dynamic section of the main executable has DT_DEBUG entry. It's mapped into memory.
        //  * The dynamic linker patches this entry in memory to be a pointer to an r_debug struct.
        //  * The r_debug struct contains a linked list link_map with information about all loaded binaries.
        //    One of the fields of link_map is l_tls_offset, which tells where this binary's thread-local variables start, relative to each thread's fs_base.
        //  * We parse the link_map entries, make a name -> l_tls_offset map, and propagate the l_tls_offset values to our Binary structs.
        //  * Finally, when a DWARF expression asks us to calculate the address of a thread-local variable at offset x, we return `fs_base - l_tls_offset + x`.

        // Find the binary that has DT_DEBUG entry in .dynamic and has a nonzero pointer patched there (it's only patched for the main executable, not for dynamic libraries).
        let mut error = None;
        let mut r_debug = None;
        for bin in debugger.symbols.iter() {
            if !bin.is_mapped {
                continue;
            }
            let elf = match &bin.elves {
                Ok(e) => &e[0],
                Err(e) if e.is_loading() => {
                    error = Some(error!(Loading, "loading"));
                    break;
                }
                Err(e) => {
                    if error.is_none() {
                        error = Some(e.clone());
                    }
                    continue;
                }
            };
            let &Some(static_addr) = &elf.r_debug_ptr_addr else {continue};
            let dynamic_addr = bin.addr_map.static_to_dynamic(static_addr);
            match parse_r_debug(dynamic_addr, &debugger.memory, elf) {
                Ok(Some(r)) => {
                    r_debug = Some(r);
                    break;
                }
                Ok(None) => (),
                Err(e) => error = Some(e),
            }
        }
        if let Some(r_debug) = r_debug {
            eprintln!("info: found r_debug struct with {} loaded binaries", r_debug.link_maps.len());

            // Match r_debug link_map entries to /proc/<pid>/maps entries, by name.
            // The r_debug entry for main executable has empty name, so we have to special-case it.
            let mut addr_to_idx: Vec<(usize, usize)> = r_debug.link_maps.iter().enumerate().map(|(i, m)| (m.ld, i)).collect();
            addr_to_idx.sort();
            let mut binary_to_tls_offset: HashMap<usize, usize> = HashMap::new();
            for map in &debugger.info.maps.maps {
                let &Some(binary_id) = &map.binary_id else {
                    continue
                };
                let i = addr_to_idx.partition_point(|(ld, idx)| *ld < map.start);
                if i == addr_to_idx.len() || addr_to_idx[i].0 >= map.start + map.len {
                    continue;
                }
                let link_map = &r_debug.link_maps[addr_to_idx[i].1];
                binary_to_tls_offset.insert(binary_id, link_map.tls_offset);
            }
            for binary_id in debugger.symbols.priority_order.clone() {
                let bin = debugger.symbols.get_mut(binary_id).unwrap();
                if !bin.is_mapped {
                    continue;
                }
                let tls_offset = match binary_to_tls_offset.get(&binary_id) {
                    Some(&x) => x,
                    None => {
                        eprintln!("warning: binary not found in r_debug link_map: '{}'", bin.locator.path);
                        bin.tls_offset = err!(Dwarf, "binary not found in r_debug link_map");
                        continue;
                    }
                };
                // glibc/include/link.h seems to imply that values 0, -1, and -2 can all be used as missing value marker.
                let tls_offset = if tls_offset == 0 || tls_offset >= usize::MAX - 1 {
                    if !bin.tls_offset.as_ref().is_err_and(|e| e.is_not_implemented()) {
                        eprintln!("info: binary has dynamic or missing tls_offset ({}): '{}'", tls_offset, bin.locator.path);
                    }
                    err!(NotImplemented, "dynamic TLS models are not supported")
                } else {
                    Ok(tls_offset)
                };
                bin.tls_offset = tls_offset;
            }

            debugger.info.r_debug = Ok(r_debug);
        } else {
            let error = match error {
                Some(x) => x,
                None => error!(ProcessState, "no valid DT_DEBUG found"),
            };
            if !error.is_loading() {
                eprintln!("warning: couldn't load r_debug: {}", error);
            }
            debugger.info.r_debug = Err(error);
        }
    }

    // Check if any of the mapped binaries are new or changed address.
    for b in debugger.symbols.iter() {
        if b.is_mapped && prev_mapped.get(&b.id) != Some(&b.addr_map.diff) {
            eprintln!("info: new binaries mapped");
            return true;
        }
    }
    false
}

fn parse_r_debug(ptr_addr: usize, memory: &MemReader, elf: &ElfFile) -> Result<Option<RDebug>> {
    let ptr = memory.read_u64(ptr_addr)? as usize;
    if ptr == 0 {
        return Ok(None);
    }
    if elf.interp.as_ref().is_some_and(|s| s.find("musl").is_some()) {
        return err!(NotImplemented, "musl TLS not supported");
    }
    let mut cached_memory = CachedMemReader::new(memory.clone());
    let mut link_map_ptr = cached_memory.read_usize(ptr + 8)?;
    let mut r_debug = RDebug {link_maps: Vec::new()};
    while link_map_ptr != 0 {
        if r_debug.link_maps.len() >= 50000 {
            return err!(ProcessState, "link_map list too long (>= {}), possibly a cycle", r_debug.link_maps.len());
        }
        // Offsets of fields in link_map struct (extended version of the struct, from glibc/include/link.h).
        const L_LD_OFFSET: usize = 16;
        const L_NEXT_OFFSET: usize = 24;
        const L_TLS_OFFSET_OFFSET: usize = 1112;
        const L_TLS_MODID_OFFSET: usize = 1120;
        let mut buf = [0u8; L_TLS_MODID_OFFSET + 8];
        cached_memory.read(link_map_ptr, &mut buf)?;
        let ld = usize:: from_le_bytes(buf[L_LD_OFFSET..][..8].try_into().unwrap());
        let tls_offset = usize::from_le_bytes(buf[L_TLS_OFFSET_OFFSET..][..8].try_into().unwrap());
        let tls_modid = usize::from_le_bytes(buf[L_TLS_MODID_OFFSET..][..8].try_into().unwrap());
        r_debug.link_maps.push(RDebugLinkMap {ld, tls_offset, tls_modid});

        link_map_ptr = usize::from_le_bytes(buf[L_NEXT_OFFSET..][..8].try_into().unwrap());
    }
    Ok(Some(r_debug))
}

// Must be called when the thread gets suspended (and not immediately resumed) - to assign registers, so we can unwind the stack.
// Should also be called when the thread is created (to assign thread name) or resumed (to update stats).
// We skip calling this if the thread was suspended and immediately resumed, e.g. skipped conditional breakpoints or passed-through user signals.
pub fn refresh_thread_info(pid: pid_t, t: &mut Thread, prof: &mut ProfileBucket, settings: &Settings) {
    if pid == 0 { // core dump
        return;
    }
    if !t.exiting {
        let s = ProcStat::parse(&format!("/proc/{}/task/{}/stat", pid, t.tid), prof);
        t.info.resource_stats.update(s, Instant::now(), t.state == ThreadState::Suspended, settings.periodic_timer_ns);
    }

    if t.state == ThreadState::Suspended {
        t.info.regs = match ptrace_getregs(t.tid) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("error: GETREGS failed: {:?}", e);
                Registers::default()
            }
        };
        t.info.extra_regs.reset_with_tid(t.tid);
    }
}

// Called periodically to refresh stats for all threads, and totals. Stats are also refreshed by refresh_thread_info() when threads are suspended or resumed.
pub fn refresh_all_resource_stats(pid: pid_t, my_stats: &mut ResourceStats, debuggee_stats: &mut ResourceStats, threads: &mut HashMap<pid_t, Thread>, prof: &mut ProfileBucket, settings: &Settings) -> Option<Error> {
    let now = Instant::now();
    my_stats.update(ProcStat::parse("/proc/self/stat", prof), now, false, settings.periodic_timer_ns);
    let mut any_error = my_stats.error.clone();

    // pid 0: core dump or remote stub (remote tids are not host pids — reading /proc would show
    // unrelated host processes like pid 1 = systemd).
    if pid != 0 {
        if !threads.is_empty() {
            debuggee_stats.update(ProcStat::parse(&format!("/proc/{}/stat", pid), prof), now, false, settings.periodic_timer_ns);
            any_error = any_error.or_else(|| debuggee_stats.error.clone());
        } else {
            *debuggee_stats = ResourceStats::default();
        }

        for (tid, t) in threads {
            if !t.exiting {
                let s = ProcStat::parse(&format!("/proc/{}/task/{}/stat", pid, tid), prof);
                t.info.resource_stats.update(s, Instant::now(), t.state == ThreadState::Suspended, settings.periodic_timer_ns);
                any_error = any_error.or_else(|| t.info.resource_stats.error.clone());
            }
        }
    }

    any_error
}

pub fn ptrace_getregs(tid: pid_t) -> Result<Registers> {
    unsafe {
        let mut regs: libc::user_regs_struct = mem::zeroed();
        ptrace(PTRACE_GETREGS, tid, 0, &mut regs as *mut _ as u64)?;
        Ok(Registers::from_ptrace(&regs))
    }
}

pub fn ptrace_get_extra_regs(tid: pid_t) -> ExtraRegisters {
    unsafe {
        let mut buf = [0u8; XSAVE_SIZE_UPPER_BOUND];
        let mut iov = libc::iovec {iov_base: buf.as_mut_ptr() as *mut libc::c_void, iov_len: buf.len()};
        if let Err(e) = ptrace(PTRACE_GETREGSET, tid, NT_X86_XSTATE as u64, &mut iov as *mut libc::iovec as u64) {
            return ExtraRegisters::from_error(e);
        }
        ExtraRegisters::from_xsave(&buf[..iov.iov_len])
    }
}
