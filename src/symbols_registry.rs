use crate::{*, error::*, elf::*, symbols::*, procfs::*, util::*, unwind::*, log::*, context::*, settings::*};
use std::{fs::{File, OpenOptions}, collections::{HashMap, HashSet, hash_map::Entry, VecDeque}, rc::Rc, sync::{Arc, Mutex, Condvar, Weak}, sync::atomic::{AtomicBool, AtomicUsize, Ordering}, thread::{self, JoinHandle}, mem, path::Path, io, str, ops::Range, os::unix::{fs::OpenOptionsExt, ffi::OsStrExt}, os::fd::AsRawFd, ptr, fmt::Write as fmtWrite, io::{Read, Write}, time::{Duration, Instant}};
use std::os::unix::fs::MetadataExt;

#[derive(Clone)]
pub struct Binary {
    pub locator: BinaryLocator,
    pub build_id: Option<Vec<u8>>,
    // Unique identifier of this bundle of ElfFile, Symbols, etc. In particular, this number changes if we destroy and re-load the Symbols.
    pub id: usize,
    pub is_main_binary: bool,

    // These 3 things can be loaded asynchronously separately. While loading, Err(Loading).
    // `elves` is either nonempty or Err; there can be more than one if unstripped binary was found e.g. through debuglink.
    pub elves: Result<Vec<Arc<ElfFile>>>,
    pub symbols: Result<Arc<Symbols>>, // .debug_info, .debug_line, .symtab, etc
    pub unwind: Result<Arc<UnwindInfo>>, // .eh_frame, .eh_frame_hdr, .debug_frame

    // To show in UI.
    pub notices: Vec<String>,
    pub warnings: Vec<String>,

    // If this binary is currently loaded by the debuggee.
    pub is_mapped: bool,
    pub addr_map: AddrMap,
    pub tls_offset: Result<usize>,

    // Last seen index among mapped binaries, in order of first mmap address.
    pub mmap_idx: usize,
    // Index in `priority_order`.
    pub priority_idx: usize,
}
impl Binary {
    pub fn symbols_loaded(&self) -> bool {
        !self.symbols.as_ref().is_err_and(|e| e.is_loading()) && !self.unwind.as_ref().is_err_and(|e| e.is_loading())
    }

    pub fn arch(&self) -> crate::disasm::Arch {
        self.elves.as_ref().ok().and_then(|e| e.first()).map(|e| e.arch()).unwrap_or(crate::disasm::Arch::X86_64)
    }
}

// A binary explicitly provided by the user. We should use it in place of a corresponding binary mapped by the debuggee, if any. Matched by build id.
struct SupplementaryBinary {
    // Contains build id.
    elf: Arc<ElfFile>,
    // If build ids are missing, we fall back to matching by file name.
    path: String,
}

#[derive(Default)]
pub struct SupplementaryBinaries {
    v: Vec<SupplementaryBinary>,
}

pub struct SymbolsRegistry {
    supplementary_binaries: SupplementaryBinaries,

    shared: Arc<Shared>,

    binaries: Vec<Option<(Binary, Arc<SymbolsLoadingStatus>)>>, // id -> binary
    pub locator_to_id: HashMap<BinaryLocator, usize>,
    // Binaries in order in which they should be displayed and searched. E.g. the main executable is usually first, unmapped binaries are after mapped ones, etc.
    pub priority_order: Vec<usize>,
}

impl SymbolsRegistry {
    // Parses ELF headers for all supplementary binaries (from settings) synchronously. Returns error if any of them failed.
    pub fn open_supplementary_binaries(settings: &Settings) -> Result<SupplementaryBinaries> {
        let mut res: Vec<SupplementaryBinary> = Vec::new();
        for (idx, path) in settings.supplementary_binary_paths.iter().enumerate() {
            let file = match File::open(path) {
                Ok(x) => x,
                Err(e) => return err!(Usage, "couldn't open supplementary binary {}: {}", path, e),
            };
            let metadata = match file.metadata() {
                Ok(x) => x,
                Err(e) => return err!(Usage, "couldn't stat supplementary binary {}: {}", path, e),
            };
            let elf = match ElfFile::from_file(path.clone(), &file, metadata.len()) {
                Ok(x) => x,
                Err(e) => return err!(Usage, "couldn't parse supplementary binary {}: {}", path, e),
            };
            if elf.is_core_dump {
                return err!(Usage, "supplementary binary {} is a core dump; to open core dump, use -c instead of -m", path);
            }

            res.push(SupplementaryBinary {elf: Arc::new(elf), path: path.clone()});
        }
        Ok(SupplementaryBinaries {v: res})
    }

    pub fn new(context: Arc<Context>, supplementary_binaries: SupplementaryBinaries) -> Self {
        Self {supplementary_binaries, binaries: Vec::new(), locator_to_id: HashMap::new(), priority_order: Vec::new(), shared: Arc::new(Shared {context, to_main_thread: Mutex::new(VecDeque::new()), wake_main_thread: Arc::new(EventFD::new())})}
    }

    pub fn get(&self, id: usize) -> Option<&Binary> {
        match self.binaries.get(id) {
            Some(Some((b, _))) => Some(b),
            _ => None,
        }
    }
    pub fn get_mut(&mut self, id: usize) -> Option<&mut Binary> {
        match self.binaries.get_mut(id) { Some(Some((b, _))) => Some(b), _ => None }
    }

    pub fn iter<'a>(&'a self) -> impl Iterator<Item = &'a Binary> + 'a {
        assert_eq!(self.priority_order.len(), self.locator_to_id.len());
        self.priority_order.iter().map(|id| &self.binaries[*id].as_ref().unwrap().0)
    }

    pub fn add(&mut self, locator: BinaryLocator, memory: &MemReader, custom_path: Option<String>, build_id: Option<Vec<u8>>, is_main_binary: bool) -> &mut Binary {
        let id = self.binaries.len();
        let mut elf_contents_maybe: Result<Vec<u8>> = err!(Internal, "no contents");
        match &locator.special {
            SpecialSegmentId::None => (),
            SpecialSegmentId::Vdso(range) => {
                let mut buf: Vec<u8> = vec![0; range.len()];
                elf_contents_maybe = match memory.read(range.start, &mut buf) {
                    Err(e) => Err(e),
                    Ok(()) => Ok(buf),
                };
            }
        }

        let mut binary = Binary {locator: locator.clone(), build_id: build_id.clone(), id, elves: err!(Loading, "loading symbols"), symbols: err!(Loading, "loading symbols"), unwind: err!(Loading, "loading symbols"), is_main_binary, is_mapped: false, addr_map: AddrMap::default(), tls_offset: err!(Loading, "TLS offset not known"), mmap_idx: 0, priority_idx: 0, notices: Vec::new(), warnings: Vec::new()};

        if let Some(id) = &build_id {
            binary.notices.push(format!("build id: {}", hexdump(id, 1000)));
        }

        let additional_elves = self.find_matching_supplementary_binaries(&locator, &build_id, is_main_binary, &mut binary.notices, &mut binary.warnings);

        // Kick off symbols loading.
        let status = Arc::new(SymbolsLoadingStatus::new());
        *status.stage.lock().unwrap() = "opening ELF".to_string();
        self.binaries.push(Some((binary, status.clone())));
        let inserted = self.locator_to_id.insert(locator.clone(), id).is_none();
        assert!(inserted);
        let shared_clone = self.shared.clone();
        self.shared.context.executor.add(move || task_load_elf(shared_clone, locator, id, status, elf_contents_maybe, custom_path, build_id, additional_elves));
        &mut self.binaries.last_mut().unwrap().as_mut().unwrap().0
    }

    pub fn mark_all_as_unmapped(&mut self) -> HashMap</*binary_id*/ usize, /*addr_map.diff*/ usize> {
       let mut prev_mapped: HashMap<usize, usize> = HashMap::new();
        for (_, id) in &self.locator_to_id {
            let b = &mut self.binaries[*id].as_mut().unwrap().0;
            if b.is_mapped {
                prev_mapped.insert(b.id, b.addr_map.diff);
                b.is_mapped = false;
            }
            b.addr_map = AddrMap::default();
        }
        prev_mapped
    }

    pub fn update_priority_order(&mut self) {
        self.priority_order.clear();
        for (_, id) in &self.locator_to_id {
            self.priority_order.push(*id);
        }
        self.priority_order.sort_unstable_by_key(|id| {
            let b = &self.binaries[*id].as_ref().unwrap().0;
            (!b.is_mapped, !b.is_main_binary, b.mmap_idx)
        });
        for (idx, id) in self.priority_order.iter().enumerate() {
            self.binaries[*id].as_mut().unwrap().0.priority_idx = idx;
        }
    }

    pub fn get_progress(&self, id: usize) -> (/*ppm*/ usize, String) {
        let s = &self.binaries.get(id).unwrap().as_ref().unwrap().1;
        (s.progress_ppm.load(Ordering::Relaxed), s.stage.lock().unwrap().clone())
    }

    // Put it in the main epoll.
    pub fn event_fd(&self) -> Arc<EventFD> {
        self.shared.wake_main_thread.clone()
    }

    // Call after event_fd() was notified.
    // Returns true if something was loaded and the caller should drop caches.
    pub fn process_events(&mut self) -> bool {
        // (May return 0 on spurious epoll wakeup, that's fine, the message queue will just be empty.)
        self.shared.wake_main_thread.read();
        let mut lock = self.shared.to_main_thread.lock().unwrap();
        while let Some(message) = lock.pop_front() {
            match message {
                Message::Elf {id, elves, mut notices, mut warnings} => if let Some((bin, _)) = &mut self.binaries[id] {
                    bin.elves = elves;
                    bin.notices.append(&mut notices);
                    bin.warnings.append(&mut warnings);
                    if let Err(e) = &bin.elves {
                        bin.symbols = Err(e.clone());
                        bin.unwind = Err(e.clone());
                    }
                }
                Message::Symbols {id, symbols, mut notices, mut warnings} => if let Some((bin, _)) = &mut self.binaries[id] {
                    bin.notices.append(&mut notices);
                    bin.warnings.append(&mut warnings);
                    bin.symbols = symbols.map(|x| Arc::new(x));
                }
                Message::Unwind {id, unwind} => if let Some((bin, _)) = &mut self.binaries[id] {
                    bin.unwind = unwind.map(|x| Arc::new(x));
                }
            }
        }
        true
        //self.binaries.iter().all(|(_, (b, _))| !b.elves.as_ref().is_err_and(|e| e.is_loading()) && !b.symbols.as_ref().is_err_and(|e| e.is_loading()) && !b.unwind.as_ref().is_err_and(|e| e.is_loading()))
    }

    // Considerations:
    //  * If the executable was replaced (e.g. recompiled) and restarted, we want to unload symbols for the old version.
    //    This is to save memory and to prevent duplicate old files/functions/etc from showing up in search dialogs etc.
    //  * If the program exited, we want to keep the symbols loaded, to allow opening files/functions/etc.
    pub fn do_eviction(&mut self) -> /*drop_caches*/ bool {
        let mapped_paths: HashSet<&String> = self.iter().filter(|b| b.is_mapped).map(|b| &b.locator.path).collect();
        // (This handles "[vdso]" correctly: evict previous process's vdso if a new process with vdso exists.)
        let ids_to_evict: Vec<usize> = self.iter().filter(|b| !b.is_mapped && mapped_paths.contains(&b.locator.path)).map(|b| b.id).collect();
        if ids_to_evict.is_empty() {
            return false;
        }
        for id in ids_to_evict {
            let (b, status) = self.binaries[id].as_ref().unwrap();
            status.cancel.store(true, Ordering::SeqCst);
            let removed = self.locator_to_id.remove(&b.locator).is_some();
            assert!(removed);
            self.binaries[id] = None;
        }
        self.update_priority_order();
        true
    }

    fn find_matching_supplementary_binaries(&self, locator: &BinaryLocator, build_id: &Option<Vec<u8>>, is_main_binary: bool, notices: &mut Vec<String>, warnings: &mut Vec<String>) -> Vec<Arc<ElfFile>> {
        let mut res: Vec<Arc<ElfFile>> = Vec::new();
        let file_name = Path::new(&locator.path).file_name();
        for b in &self.supplementary_binaries.v {
            let name_matches = file_name.is_some() && &Path::new(&b.path).file_name() == &file_name;
            if build_id.is_some() {
                if build_id == &b.elf.build_id {
                    res.push(b.elf.clone());
                    notices.push(format!("supplementary binary {} (matching build id)", b.elf.name));
                    break; // use just one supplementary binary, in case the user accidentally passed multiple copies of the same file
                }
                if name_matches {
                    warnings.push(format!("supplementary build id mismatch: {} loaded in the program, {} in supplementary file {:?}", hexdump(build_id.as_ref().unwrap(), 1000), b.elf.build_id.as_ref().map_or("none".to_string(), |x| hexdump(x, 1000)), file_name.clone().unwrap()));
                }
            } else if file_name.is_some() {
                if name_matches {
                    res.push(b.elf.clone());
                    notices.push(format!("supplementary binary {} (build id missing, guessed by name)", b.elf.name));
                    break;
                }
            }
        }

        // If build ids are missing, and file names don't match, we fall back to matching the executable to the first supplementary binary.
        // E.g. maybe the user doesn't know or care that we support passing in multiple binaries and just wants to provide the unstripped main executable to use.
        if res.is_empty() && is_main_binary && !self.supplementary_binaries.v.is_empty() {
            if build_id.is_none() {
                res.push(self.supplementary_binaries.v[0].elf.clone());
                notices.push(format!("supplementary binary {} (build id missing, guessed by order)", res[0].name));
            } else {
                let supp_build_id_str = self.supplementary_binaries.v[0].elf.build_id.as_ref().map_or("none".to_string(), |x| hexdump(x, 1000));
                warnings.push(format!("build id mismatch: {} loaded in the process, {} in supplementary binary {}", hexdump(build_id.as_ref().unwrap(), 1000), supp_build_id_str, self.supplementary_binaries.v[0].path));
            }
        }

        res
    }
}

struct Shared {
    context: Arc<Context>,
    to_main_thread: Mutex<VecDeque<Message>>,
    wake_main_thread: Arc<EventFD>,
}

enum Message {
    Elf {id: usize, elves: Result<Vec<Arc<ElfFile>>>, notices: Vec<String>, warnings: Vec<String>},
    Symbols {id: usize, symbols: Result<Symbols>, notices: Vec<String>, warnings: Vec<String>},
    Unwind {id: usize, unwind: Result<UnwindInfo>},
}

fn task_load_elf(shared: Arc<Shared>, locator: BinaryLocator, id: usize, status: Arc<SymbolsLoadingStatus>, elf_contents_maybe: Result<Vec<u8>>, custom_path: Option<String>, build_id: Option<Vec<u8>>, mut elves: Vec<Arc<ElfFile>>) {
    let mut notices: Vec<String> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();
    let mut errors: Vec<Error> = Vec::new();

    // Collect versions of the file from all sources we can think of, in order of priority:
    //  1. Supplementary binaries provided by the user (matched by build id etc). (Already in `elves`.)
    //  2. The file at locator.path (i.e. path from /proc/<pid>/maps).
    //  3. debuglink.
    //  4. debuginfod.

    match load_elf(&locator, elf_contents_maybe, custom_path.clone()) {
        Ok(elf) => {
            if build_id.is_none() || &build_id == &elf.build_id {
                elves.push(elf);
            } else {
                errors.push(error!(MissingSymbols, "build id mismatch in {}: {} in memory, {} in file", custom_path.as_ref().unwrap_or(&locator.path), hexdump(build_id.as_ref().unwrap(), 1000), elf.build_id.as_ref().map_or("none".to_string(), |x| hexdump(x, 1000))));
            }
        }
        Err(e) => errors.push(e),
    }
    if !elves.is_empty() || build_id.is_some() {
        match open_debuglink(if elves.is_empty() {None} else {Some(&elves[0])}, &build_id) {
            Ok(Some(elf)) => {
                notices.push(format!("debuglink: {}", elf.name));
                elves.push(Arc::new(elf));
            }
            Ok(None) => (),
            Err(_) if elves.is_empty() => (), // looking for debuglink file without seeing .gnu_debuglink section is a shot in the dark, don't report an error if it fails
            Err(e) => errors.push(e),
        }
    }

    // Make sure elves[0] is an actual executable rather than a debug-info-only file (because some code sites read .text section specifically from elves[0]; perhaps we shouldn't do that).
    if !elves.is_empty() {
        for i in 0..elves.len() {
            if elves[i].has_text_section_data() {
                elves[..i+1].rotate_right(1);
                break;
            }
        }
    }

    let have_debug_info = elves.iter().any(|elf| elf.has_section_data(".debug_info"));
    if !have_debug_info && !shared.context.settings.debuginfod_urls.is_empty() {
        if let (Some(build_id), Some(debuginfod_cache_path)) = (&build_id, &shared.context.settings.debuginfod_cache_path) {
            // We need two things: (1) a file that uses the same file offsets for sections as the binary loaded in the debuggee, and (2) a file that has .debug_info etc.
            // Sometimes they're the same file (unstripped executable), sometimes they're separate (exeuctable with debuginfo removed + executable with machine code removed).
            // Debuginfod offers two files: "executable" and "debuginfo"; "executable" satisfies (1), and "debuginfo" satisfies (2),
            // but either of them may also be just the unstripped executable satisfying both (1) and (2).
            // So we have a choice: download both files in parallel for minimum latency, or download in sequence and skip the second file if the first one has all we need.
            // Currently we download in sequence, starting with the "debuginfo" file.
            // Note that latency is not a theoretical concern here: debuginfod takes 2 minutes to respond sometimes for some reason, so waiting for it twice is not very good.
            //
            // TODO: Debuginfod servers can take minutes to respond. This should be asynchronous. First kick off symbols loading without debuginfod, then if debuginfod succeeds generate new Symbols identity and start over.
            match try_to_download_from_debuginfod(build_id, &shared.context.settings.debuginfod_urls, "debuginfo", debuginfod_cache_path, &status) {
                Ok((elf, cache_hit)) => {
                    notices.push(format!("debuginfo {} from debuginfod: {}", if cache_hit {"cached"} else {"downloaded"}, elf.name));
                    elves.push(Arc::new(elf));

                    let have_text = elves.iter().any(|elf| elf.has_section_data(".text"));
                    if !have_text {
                        match try_to_download_from_debuginfod(build_id, &shared.context.settings.debuginfod_urls, "executable", debuginfod_cache_path, &status) {
                            Ok((elf, cache_hit)) => {
                                notices.push(format!("executable {} from debuginfod: {}", if cache_hit {"cached"} else {"downloaded"}, elf.name));
                                elves.insert(0, Arc::new(elf));
                            }
                            Err(e) => warnings.push(format!("debuginfod executable fetch failed: {}", e)),
                        }
                    }
                }
                Err(e) => notices.push(format!("debuginfod fetch failed: {}", e)),
            }
        }
    }

    assert!(!errors.is_empty() || !elves.is_empty());

    let elves = if elves.is_empty() {
        for e in errors.iter().skip(1) {
            warnings.push(format!("{}", e));
        }
        Err(errors[0].clone())
    } else {
        for e in errors {
            notices.push(format!("{}", e));
        }
        let have_debug_info = elves.iter().any(|elf| elf.section_by_name.contains_key(".debug_info"));
        if !have_debug_info {
            warnings.push("no debug info".to_string());
        }
        Ok(elves)
    };

    {
        let mut lock = shared.to_main_thread.lock().unwrap();
        lock.push_back(Message::Elf {id, elves: elves.clone().into(), notices, warnings});
        shared.wake_main_thread.write(1);
    }

    if let Ok(elves) = elves {
        let (shared_clone, elves_clone) = (shared.clone(), elves.clone());
        shared.context.executor.add(move || task_load_unwind(shared_clone, id, elves_clone));
        LoadScheduler::start(id, elves, shared, status);
    }
}

fn open_debuglink(elf: Option<&ElfFile>, build_id: &Option<Vec<u8>>) -> Result<Option<ElfFile>> {
    let (filename, build_id, crc32) = if let Some(elf) = elf {
        let build_id = match &elf.build_id {
            None => return Ok(None),
            Some(x) => &x[..],
        };
        let section_idx = match elf.section_by_name.get(".gnu_debuglink") {
            None => return Ok(None),
            Some(&x) => x,
        };
        let debuglink = elf.section_data(section_idx)?;
        if debuglink.len() <= 4 { return err!(Dwarf, ".gnu_debuglink section is too short: {}", debuglink.len()); }
        let (filename, crc32) = debuglink.split_at(debuglink.len()-4);
        let filename = &filename[..filename.iter().position(|&x| x == b'\0').unwrap_or(filename.len())]; // null-terminated string
        let filename = str::from_utf8(filename)?;
        let crc32 = u32::from_le_bytes(crc32.try_into().unwrap());
        (filename.to_string(), build_id, Some(crc32))
    } else if let Some(build_id) = build_id {
        // We could look for debuglink file even if the binary is not found, like this:
        //   (format!("{}.debug", hexdump(&build_id[1..], 100000)), build_id, None)
        // but debuglink file is not very useful by itself because it has wrong file offsets. So we just do this instead:
        return Ok(None);
    } else {
        panic!("huh");
    };

    let path = format!("/usr/lib/debug/.build-id/{:02x}/{}", build_id[0], filename);
    let file = match File::open(&path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return err!(MissingSymbols, "debuglink file not found: {}", path),
        Err(e) => return Err(e.into()),
    };

    let res = ElfFile::from_file(path.clone(), &file, file.metadata()?.len())?;

    if let Some(crc32) = crc32 {
        let actual_crc32 = crc32fast::hash(res.data());
        if actual_crc32 != crc32 { return err!(Dwarf, "debuglink file checksum mismatch: expected {}, found {} in {}", crc32, actual_crc32, path); }
    }

    Ok(Some(res))
}

fn try_to_download_from_debuginfod(build_id: &[u8], urls: &[String], artifact_type: &str, cache_path: &Path, status: &SymbolsLoadingStatus) -> Result<(ElfFile, /*cache_hit*/ bool)> {
    let mut cached_file_path = cache_path.to_owned();
    cached_file_path.push(format!("{}.{}", hexdump(build_id, 1000), artifact_type));
    let cached_file_path_str = cached_file_path.to_string_lossy().into_owned();

    let file = match File::open(&cached_file_path) {
        Ok(file) => {
            eprintln!("info: debuginfod cache hit: {}", cached_file_path_str);
            let elf = ElfFile::from_file(cached_file_path_str, &file, file.metadata()?.len())?;
            return Ok((elf, true));
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => (),
        Err(e) => return Err(e.into()),
    };

    // TODO: Cache 404 responses. I guess write a file <build_id>.status with list of urls that were tried and last failure timestamp.

    let mut cached_file = OpenOptions::new().read(true).write(true).custom_flags(libc::O_TMPFILE).open(cache_path)?;
    let mut first_error: Option<Error> = None;
    for url in urls {
        let mut full_url = url.clone();
        if !full_url.ends_with("/") {
            full_url.push_str("/");
        }
        write!(full_url, "buildid/{}/{}", hexdump(build_id, 1000), artifact_type).unwrap();

        eprintln!("info: sending request {}", full_url);
        *status.stage.lock().unwrap() = format!("trying {}", url);

        let start_time = Instant::now();
        // I've seen connect() syscall to debuginfod servers take 2 minutes and time out when using IPv6.
        let timeout = Duration::from_secs(3);
        let config = ureq::config::Config::builder().timeout_connect(Some(timeout)).timeout_recv_response(Some(timeout)).user_agent("nnd/1").ip_family(ureq::config::IpFamily::Ipv4Only).build();
        let agent = ureq::Agent::new_with_config(config);
        let mut response = match agent.get(&full_url).call() {
            Ok(x) => x,
            Err(e) => {
                let secs = start_time.elapsed().as_secs_f64();
                eprintln!("info: error {} after {:.3}s: {}", full_url, secs, e);
                if let ureq::Error::StatusCode(404) = e {}
                else if first_error.is_none() {
                    first_error = Some(error!(Network, "{}", e));
                }
                continue;
            }
        };
        let mut reader = response.body_mut().as_reader();
        let mut buf = [0u8; 4096];
        loop {
            let n = match reader.read(&mut buf) {
                Ok(x) => x,
                Err(e) => {
                    eprintln!("warning: error when reading from {} : {}", full_url, e);
                    return err!(Network, "error when reading from {} : {}", full_url, e);
                }
            };
            if n == 0 {
                break;
            }
            let mut pos = 0;
            while pos < n {
                let wrote = match cached_file.write(&buf[pos..n]) {
                    Ok(0) => return err!(Environment, "failed to write to file"),
                    Ok(x) => x,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e.into()),
                };
                assert!(wrote <= n);
                pos += wrote;
            }
        }
        cached_file.flush()?;

        // Turn the anonymous temp file into a real file.
        let mut cached_file_path_c_string = cached_file_path.as_os_str().as_bytes().to_owned();
        cached_file_path_c_string.push(b'\0');
        let fd_path_c_string = format!("/proc/self/fd/{}\0", cached_file.as_raw_fd());
        let r = unsafe {libc::linkat(libc::AT_FDCWD, fd_path_c_string.as_bytes().as_ptr() as *const i8, libc::AT_FDCWD, cached_file_path_c_string.as_ptr() as *const i8, libc::AT_SYMLINK_FOLLOW)};
        if r != 0 {
            return errno_err!("linkat() failed");
        }
        eprintln!("info: downloaded from {} to {}", full_url, cached_file_path_str);
        let elf = ElfFile::from_file(cached_file_path_str, &cached_file, cached_file.metadata()?.len())?;
        return Ok((elf, false));
    }
    if let Some(e) = first_error {
        Err(e)
    } else {
        err!(MissingSymbols, "debuginfod servers don't have it")
    }
}

fn task_load_unwind(shared: Arc<Shared>, id: usize, elves: Vec<Arc<ElfFile>>) {
    let unwind;
    {
        let _prof = ProfileScope::with_threshold(0.01, format!("loading unwind {}", elves[0].name));
        unwind = UnwindInfo::load(elves.clone());
    }
    if let Err(e) = &unwind {
        eprintln!("warning: failed to load unwind for {}: {}", elves[0].name, e);
    }

    let mut lock = shared.to_main_thread.lock().unwrap();
    lock.push_back(Message::Unwind {id, unwind});
    shared.wake_main_thread.write(1);
}

fn load_elf(locator: &BinaryLocator, contents_maybe: Result<Vec<u8>>, custom_path: Option<String>) -> Result<Arc<ElfFile>> {
    let elf = match &locator.special {
        SpecialSegmentId::None => {
            let path = custom_path.as_ref().unwrap_or(&locator.path);
            let file = File::open(path)?;
            let metadata = file.metadata()?;
            if locator.inode != 0 && metadata.ino() != locator.inode && custom_path.is_none() {
                return err!(Usage, "binary changed");
            }
            // TODO: Try madvise()ing the big sections: MADV_WILLNEED all .debug_* sections et al, MADV_SEQUENTIAL the .debug_info, MADV_RANDOM .debug_str, MADV_DONTNEED .debug_info after loading.
            ElfFile::from_file(locator.path.clone(), &file, metadata.len())?
        }
        SpecialSegmentId::Vdso(_) => {
            ElfFile::from_contents(locator.path.clone(), contents_maybe?)?
        }
    };
    if elf.is_core_dump {
        return err!(ProcessState, "unexpected core dump instead of executable");
    }
    Ok(Arc::new(elf))
}

// Drives a SymbolsLoader.
struct LoadScheduler {
    id: usize,
    name: String,
    loader: SyncUnsafeCell<Option<SymbolsLoader>>,
    num_shards: usize,

    shared: Arc<Shared>,
    status: Arc<SymbolsLoadingStatus>,

    failed: AtomicBool,
    stage: AtomicUsize,
    tasks_left: AtomicUsize,
}

impl LoadScheduler {
    fn start(id: usize, elves: Vec<Arc<ElfFile>>, shared: Arc<Shared>, status: Arc<SymbolsLoadingStatus>) {
        let mut scheduler = LoadScheduler {id, name: elves[0].name.clone(), loader: SyncUnsafeCell::new(None), num_shards: 0, shared: shared.clone(), status: status.clone(), failed: AtomicBool::new(false), stage: AtomicUsize::new(0), tasks_left: AtomicUsize::new(1)};
        let max_shards = (shared.context.executor.num_threads - 1).max(1);
        let loader = match SymbolsLoader::new(elves, id, max_shards, status) {
            Ok(l) => l,
            Err(e) => {
                scheduler.handle_fail(e);
                return;
            }
        };
        scheduler.num_shards = loader.num_shards;
        *scheduler.loader.get_mut() = Some(loader);
        let scheduler = Arc::new(scheduler);
        scheduler.schedule();
    }

    fn schedule(self: Arc<Self>) {
        if self.tasks_left.fetch_sub(1, Ordering::SeqCst) != 1 {
            return;
        }
        let stage = self.stage.fetch_add(1, Ordering::Relaxed) + 1;
        if self.check_cancellation() { return; }

        match unsafe {&mut *self.loader.get()}.as_mut().unwrap().prepare_stage(stage) {
            Err(e) => {
                self.handle_fail(e);
                return;
            }
            Ok(false) => { // complete
                let symbols = mem::take(unsafe {&mut *self.loader.get()}).unwrap().into_result();
                self.complete(Ok(symbols));
                return;
            }
            Ok(true) => (),
        }
        if self.check_cancellation() { return; }

        self.tasks_left.store(self.num_shards, Ordering::Relaxed);
        for i in 0..self.num_shards {
            let self_ = self.clone();
            self.shared.context.executor.add(move || {
                match unsafe {&*self_.loader.get()}.as_ref().unwrap().run(stage, i) {
                    Ok(()) => self_.schedule(),
                    Err(e) => self_.handle_fail(e),
                }
            });
        }
    }

    fn handle_fail(&self, e: Error) {
        if !self.failed.swap(true, Ordering::SeqCst) {
            self.status.cancel.store(true, Ordering::SeqCst);
            self.complete(Err(e));
        }
    }

    fn check_cancellation(&self) -> bool {
        if !self.status.cancel.load(Ordering::Relaxed) {
            return false;
        }
        if !self.failed.swap(true, Ordering::SeqCst) {
            // This only does anything if cancellation came from inside SymbolsLoader, which shouldn't happen.
            // Otherwise there's no need to notify the main thread because we either already did it or the main thread is not interested anymore.
            // But why not.
            self.complete(err!(Cancelled, "cancelled"));
        }
        true
    }

    // Called exactly once, by whoever sets self.failed to true, or at the end of successful loading.
    fn complete(&self, res: Result<Symbols>) {
        let mut notices: Vec<String> = Vec::new();
        let mut warnings: Vec<String> = Vec::new();
        match &res {
            Err(e) => eprintln!("warning: failed to load symbols for {}: {}", self.name, e),
            Ok(s) => {
                notices.push(format!("loaded in {:.3}s{}", s.loading_duration_ns as f64 / 1e9, if let &Some(mem) = &s.loading_memory_usage {format!(", peak memory usage {}", PrettySize(mem))} else {String::new()}));
                if !s.unsupported_features.is_empty() {
                    warnings.push(format!("unsupported: {}", s.unsupported_features));
                }
            }
        }
        let mut lock = self.shared.to_main_thread.lock().unwrap();
        lock.push_back(Message::Symbols {id: self.id, symbols: res, notices, warnings});
        self.shared.wake_main_thread.write(1);
    }
}
