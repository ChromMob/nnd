// GDB remote serial protocol client (QEMU gdbstub and gdbserver-compatible).
// Transport only: registers come back as raw bytes; target.xml is fetched but
// parsed elsewhere (registers layer).

use crate::gdbproto::{self, Decoded, Decoder};
use std::collections::VecDeque;
use std::fmt;
use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopKind {
    Signal(u8),
    SwBreak,
    HwBreak,
    Watch { write: bool, read: bool, addr: Option<u64> },
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StopInfo {
    pub thread: Option<u64>,
    pub stop_kind: StopKind,
    pub raw: String,
}

#[derive(Debug)]
pub enum GdbError {
    Io(std::io::Error),
    Protocol(String),
    Unsupported(String),
}

impl fmt::Display for GdbError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            GdbError::Io(e) => write!(f, "gdb remote io: {}", e),
            GdbError::Protocol(s) => write!(f, "gdb remote protocol: {}", s),
            GdbError::Unsupported(s) => write!(f, "gdb remote unsupported: {}", s),
        }
    }
}

impl std::error::Error for GdbError {}

impl From<std::io::Error> for GdbError {
    fn from(e: std::io::Error) -> Self { GdbError::Io(e) }
}

pub type Result<T> = std::result::Result<T, GdbError>;

fn hex_encode(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for &b in data {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn hex_decode(s: &str) -> Result<Vec<u8>> {
    if s.len() % 2 != 0 {
        return Err(GdbError::Protocol(format!("odd-length hex: {}", s)));
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in (0..b.len()).step_by(2) {
        let hi = hex_nibble(b[i])?;
        let lo = hex_nibble(b[i + 1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_nibble(c: u8) -> Result<u8> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(GdbError::Protocol(format!("bad hex digit {:?} ({:#x})", c as char, c))),
    }
}

fn parse_u64_hex(s: &str) -> Result<u64> {
    u64::from_str_radix(s, 16).map_err(|_| GdbError::Protocol(format!("bad hex number: {}", s)))
}

/// qXfer body: either hex-encoded (classic GDB) or raw (QEMU returns raw XML).
fn decode_qxfer_chunk(body: &[u8]) -> Vec<u8> {
    if body.is_empty() {
        return Vec::new();
    }
    // Raw text/XML (QEMU): starts with '<' or whitespace+'<'
    if body[0] == b'<' || body[0] == b' ' || body[0] == b'\n' || body[0] == b'?' {
        return body.to_vec();
    }
    if body.len() % 2 == 0 && body.iter().all(|c| c.is_ascii_hexdigit()) {
        if let Ok(v) = hex_decode(std::str::from_utf8(body).unwrap_or("")) {
            return v;
        }
    }
    body.to_vec()
}

pub struct GdbRemote {
    stream: TcpStream,
    decoder: Decoder,
    no_ack: bool,
    /// Max payload the stub advertised (PacketSize=hex); default if unknown.
    packet_size: usize,
    qsupported: String,
    /// Decoded events already read from the socket but not yet consumed;
    /// a single read() can carry a reply plus an async notification.
    pending: VecDeque<Decoded>,
    /// Non-stop packets seen while awaiting a stop reply (kept so wait_reply can
    /// still surface them if they were command replies).
    orphan_replies: VecDeque<Vec<u8>>,
    /// Set after vCont;c/s until a stop reply is read. While set, the stub's
    /// next bytes are that stop — any Hg/m/g would steal them and desync.
    resume_in_flight: bool,
}

impl GdbRemote {
    pub fn connect(addr: &str) -> std::io::Result<Self> {
        let stream = TcpStream::connect(addr)?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;
        stream.set_nodelay(true)?;
        Ok(GdbRemote {
            stream,
            decoder: Decoder::new(),
            no_ack: false,
            packet_size: 0x4000,
            qsupported: String::new(),
            pending: VecDeque::new(),
            orphan_replies: VecDeque::new(),
            resume_in_flight: false,
        })
    }

    /// True after vCont until the matching stop reply has been observed.
    pub fn resume_in_flight(&self) -> bool {
        self.resume_in_flight
    }

    /// Send a packet and wait for its reply. Auto-acks when in ack mode.
    pub fn send_packet(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
        if self.resume_in_flight {
            // Hitting this means the caller raced a vCont — the next reply on the
            // wire is the stop, not the answer to this command (seen as
            // "Hg failed: 9300…" = stolen `m`/`g` hex payload).
            return Err(GdbError::Protocol(
                "target is running (resume in flight); wait for stop before Hg/m/g".into(),
            ));
        }
        let pkt = gdbproto::encode_packet(payload);
        self.stream.write_all(&pkt)?;
        self.stream.flush()?;
        self.wait_reply()
    }

    fn mark_resume_in_flight(&mut self) {
        self.resume_in_flight = true;
    }

    fn clear_resume_if_stop(&mut self, payload: &[u8]) {
        if !self.resume_in_flight {
            return;
        }
        if payload.first().map(|&b| matches!(b, b'T' | b'S' | b'W' | b'X')).unwrap_or(false) {
            self.resume_in_flight = false;
        }
    }

    /// Read whatever is already queued on the socket (short timeout) into `pending`.
    fn drain_ready(&mut self) -> Result<()> {
        let old = self.stream.read_timeout()?;
        self.stream.set_read_timeout(Some(Duration::from_millis(50)))?;
        let result = loop {
            match self.read_once() {
                Ok(()) => continue,
                Err(GdbError::Io(e)) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => break Ok(()),
                Err(e) => break Err(e),
            }
        };
        self.stream.set_read_timeout(old)?;
        result
    }

    fn read_once(&mut self) -> Result<()> {
        let mut buf = [0u8; 4096];
        let n = self.stream.read(&mut buf)?;
        if n == 0 {
            return Err(GdbError::Protocol("connection closed".into()));
        }
        for d in self.decoder.feed(&buf[..n]) {
            self.pending.push_back(d);
        }
        Ok(())
    }

    fn next_decoded(&mut self) -> Result<Decoded> {
        loop {
            if let Some(d) = self.pending.pop_front() {
                return Ok(d);
            }
            self.read_once()?;
        }
    }

    fn ack_packet(&mut self) -> Result<()> {
        if !self.no_ack {
            self.stream.write_all(b"+")?;
            self.stream.flush()?;
        }
        Ok(())
    }

    /// Read until a data packet arrives (skipping Acks/Nacks/Interrupts).
    fn wait_reply(&mut self) -> Result<Vec<u8>> {
        // Prefer packets stashed while a previous resume was in flight.
        if let Some(p) = self.orphan_replies.pop_front() {
            return Ok(p);
        }
        loop {
            match self.next_decoded()? {
                Decoded::Packet(p) => {
                    self.ack_packet()?;
                    return Ok(p);
                }
                Decoded::Ack | Decoded::Nack | Decoded::Interrupt => {}
            }
        }
    }

    /// Non-blocking-ish: short read timeout, returns Ok(None) if nothing arrived.
    pub fn poll_packet(&mut self, timeout: Duration) -> Result<Option<Vec<u8>>> {
        loop {
            match self.pending.pop_front() {
                Some(Decoded::Packet(p)) => return Ok(Some(p)),
                Some(_) => continue,
                None => break,
            }
        }
        let old = self.stream.read_timeout()?;
        self.stream.set_read_timeout(Some(timeout))?;
        let result = (|| -> Result<Option<Vec<u8>>> {
            match self.read_once() {
                Ok(()) => {
                    while let Some(d) = self.pending.pop_front() {
                        if let Decoded::Packet(p) = d {
                            return Ok(Some(p));
                        }
                    }
                    Ok(None)
                }
                Err(GdbError::Io(e)) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => Ok(None),
                Err(e) => Err(e),
            }
        })();
        self.stream.set_read_timeout(old)?;
        result
    }

    pub fn handshake(&mut self) -> Result<()> {
        // Some stubs emit an unsolicited stop reply before the first request; keep it for wait_stop.
        self.drain_ready()?;
        let reply = self.send_packet(b"qSupported:swbreak+;hwbreak+;qXfer:features:read+;QStartNoAckMode+")?;
        self.qsupported = String::from_utf8_lossy(&reply).into_owned();
        if let Some(sz) = parse_packet_size(&self.qsupported) {
            self.packet_size = sz;
        }
        if self.qsupported.contains("QStartNoAckMode") {
            let r = self.send_packet(b"QStartNoAckMode")?;
            if r == b"OK" {
                self.no_ack = true;
                self.decoder.set_no_ack(true);
            }
        }
        // Query why the target is stopped (also confirms the link).
        let st = self.send_packet(b"?")?;
        let _ = parse_stop_reply(&st)?; // validate format; caller can wait_stop for details
        Ok(())
    }

    pub fn packet_size(&self) -> usize {
        self.packet_size
    }

    pub fn qsupported(&self) -> &str {
        &self.qsupported
    }

    /// Fetch target description XML (`target.xml`), concatenating qXfer chunks.
    /// QEMU returns the payload as raw bytes after `l`/`m` (not hex); GDB stubs often hex-encode.
    /// Accept both.
    pub fn fetch_target_xml(&mut self) -> Result<String> {
        self.fetch_qxfer("target.xml")
    }

    /// Fetch an arbitrary feature file via qXfer:features:read.
    pub fn fetch_qxfer(&mut self, annex: &str) -> Result<String> {
        let mut out = Vec::new();
        let mut offset = 0usize;
        loop {
            let len = (self.packet_size.saturating_sub(64)).min(0xfffe);
            let req = format!("qXfer:features:read:{}:{:x},{:x}", annex, offset, len);
            let reply = self.send_packet(req.as_bytes())?;
            if reply.is_empty() {
                return Err(GdbError::Protocol("empty qXfer reply".into()));
            }
            let (more, body) = match reply[0] {
                b'l' => (false, &reply[1..]),
                b'm' => (true, &reply[1..]),
                other => return Err(GdbError::Protocol(format!("unexpected qXfer lead byte {}", other as char))),
            };
            // Hex if even length and all hex digits and looks encoded (XML starts with '<' = 0x3c when raw).
            let chunk = decode_qxfer_chunk(body);
            offset += chunk.len();
            out.extend_from_slice(&chunk);
            if !more {
                return Ok(String::from_utf8_lossy(&out).into_owned());
            }
        }
    }

    pub fn set_thread(&mut self, tid: u64) -> Result<()> {
        let r = self.send_packet(format!("Hg{:x}", tid).as_bytes())?;
        if r != b"OK" {
            return Err(GdbError::Protocol(format!("Hg failed: {}", String::from_utf8_lossy(&r))));
        }
        Ok(())
    }

    pub fn threads(&mut self) -> Result<Vec<u64>> {
        let mut out = Vec::new();
        let first = self.send_packet(b"qfThreadInfo")?;
        let mut reply = first;
        loop {
            if reply.is_empty() {
                break;
            }
            match reply[0] {
                b'm' => {
                    for part in String::from_utf8_lossy(&reply[1..]).split(',') {
                        if !part.is_empty() {
                            out.push(parse_u64_hex(part)?);
                        }
                    }
                    reply = self.send_packet(b"qsThreadInfo")?;
                }
                b'l' => break,
                _ => return Err(GdbError::Protocol(format!("bad thread info: {}", String::from_utf8_lossy(&reply)))),
            }
        }
        Ok(out)
    }

    pub fn read_mem(&mut self, addr: u64, len: usize) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(len);
        let max_chunk = self.packet_size.saturating_sub(32) / 2; // hex doubles size
        let max_chunk = max_chunk.max(16);
        let mut off = 0usize;
        while off < len {
            let n = (len - off).min(max_chunk);
            let req = format!("m{:x},{:x}", addr + off as u64, n);
            let reply = self.send_packet(req.as_bytes())?;
            if reply.first() == Some(&b'E') {
                return Err(GdbError::Protocol(format!("m error: {}", String::from_utf8_lossy(&reply))));
            }
            let bytes = hex_decode(std::str::from_utf8(&reply).map_err(|_| GdbError::Protocol("mem reply not utf8".into()))?)?;
            if bytes.is_empty() {
                return Err(GdbError::Protocol("empty mem reply".into()));
            }
            out.extend_from_slice(&bytes);
            off += bytes.len();
            if bytes.len() < n {
                // stub returned short read (hole); zero-fill to keep len contract? Treat as error.
                return Err(GdbError::Protocol(format!("short mem read: got {} want {}", bytes.len(), n)));
            }
        }
        Ok(out)
    }

    pub fn write_mem(&mut self, addr: u64, data: &[u8]) -> Result<()> {
        let hex = hex_encode(data);
        let req = format!("M{:x},{:x}:{}", addr, data.len(), hex);
        let r = self.send_packet(req.as_bytes())?;
        if r != b"OK" {
            return Err(GdbError::Protocol(format!("M failed: {}", String::from_utf8_lossy(&r))));
        }
        Ok(())
    }

    pub fn read_regs_raw(&mut self) -> Result<Vec<u8>> {
        let r = self.send_packet(b"g")?;
        if r.first() == Some(&b'E') {
            return Err(GdbError::Protocol(format!("g error: {}", String::from_utf8_lossy(&r))));
        }
        hex_decode(std::str::from_utf8(&r).map_err(|_| GdbError::Protocol("g reply not utf8".into()))?)
    }

    pub fn read_reg_raw(&mut self, regnum: u64) -> Result<Vec<u8>> {
        let r = self.send_packet(format!("p{:x}", regnum).as_bytes())?;
        if r.first() == Some(&b'E') {
            return Err(GdbError::Protocol(format!("p error: {}", String::from_utf8_lossy(&r))));
        }
        if r == b"xxxxxxxxxxxxxxxx" || r.iter().all(|&c| c == b'x') {
            return Err(GdbError::Unsupported("register unavailable".into()));
        }
        hex_decode(std::str::from_utf8(&r).map_err(|_| GdbError::Protocol("p reply not utf8".into()))?)
    }

    pub fn write_reg_raw(&mut self, regnum: u64, val: &[u8]) -> Result<()> {
        let r = self.send_packet(format!("P{:x}={}", regnum, hex_encode(val)).as_bytes())?;
        if r != b"OK" {
            return Err(GdbError::Protocol(format!("P failed: {}", String::from_utf8_lossy(&r))));
        }
        Ok(())
    }

    pub fn cont(&mut self, tid: Option<u64>) -> Result<()> {
        // vCont has no immediate reply; the next packet is a stop reply (wait_stop).
        let pkt = match tid {
            Some(t) => format!("vCont;c:{:x}", t),
            None => "vCont;c".to_string(),
        };
        let frame = gdbproto::encode_packet(pkt.as_bytes());
        self.stream.write_all(&frame)?;
        self.stream.flush()?;
        self.mark_resume_in_flight();
        Ok(())
    }

    pub fn step(&mut self, tid: Option<u64>) -> Result<()> {
        let pkt = match tid {
            Some(t) => format!("vCont;s:{:x}", t),
            None => "vCont;s".to_string(),
        };
        let frame = gdbproto::encode_packet(pkt.as_bytes());
        self.stream.write_all(&frame)?;
        self.stream.flush()?;
        self.mark_resume_in_flight();
        Ok(())
    }

    /// kind: 0 sw, 1 hw, 2 write watch, 3 read watch, 4 access watch.
    pub fn insert_breakpoint(&mut self, kind: u8, addr: u64, size: u64) -> Result<()> {
        let r = self.send_packet(format!("Z{},{:x},{:x}", kind, addr, size).as_bytes())?;
        if r.is_empty() {
            return Err(GdbError::Unsupported(format!("Z{} not supported by stub", kind)));
        }
        if r != b"OK" {
            return Err(GdbError::Protocol(format!("Z{} failed: {}", kind, String::from_utf8_lossy(&r))));
        }
        Ok(())
    }

    pub fn remove_breakpoint(&mut self, kind: u8, addr: u64, size: u64) -> Result<()> {
        let r = self.send_packet(format!("z{},{:x},{:x}", kind, addr, size).as_bytes())?;
        if r.is_empty() {
            return Err(GdbError::Unsupported(format!("z{} not supported by stub", kind)));
        }
        if r != b"OK" {
            return Err(GdbError::Protocol(format!("z{} failed: {}", kind, String::from_utf8_lossy(&r))));
        }
        Ok(())
    }

    /// Interrupt the running target (all-stop Ctrl-C).
    pub fn interrupt(&mut self) -> Result<()> {
        self.stream.write_all(&[0x03])?;
        self.stream.flush()?;
        Ok(())
    }

    /// Block (with read timeout) until a stop-reply packet arrives.
    pub fn wait_stop(&mut self) -> Result<StopInfo> {
        loop {
            match self.next_decoded()? {
                Decoded::Packet(p) => {
                    self.ack_packet()?;
                    self.clear_resume_if_stop(&p);
                    let s = String::from_utf8_lossy(&p);
                    if s.starts_with('T') || s.starts_with('S') {
                        return parse_stop_reply(&p);
                    }
                    if s.starts_with('W') || s.starts_with('X') {
                        let raw = s.into_owned();
                        return Ok(StopInfo { thread: None, stop_kind: StopKind::Other(raw.clone()), raw });
                    }
                    // Ignore other packets (e.g. notifications) while waiting.
                }
                Decoded::Ack | Decoded::Nack | Decoded::Interrupt => {}
            }
        }
    }

    /// Try to read a stop reply without blocking long; Ok(None) on timeout.
    pub fn try_wait_stop(&mut self, timeout: Duration) -> Result<Option<StopInfo>> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            // Always give poll_packet a tiny budget so we can keep scanning pending
            // even when the wall-clock timeout has already elapsed.
            let slice = remaining.max(Duration::from_millis(1));
            match self.poll_packet(slice)? {
                None => {
                    if std::time::Instant::now() >= deadline {
                        return Ok(None);
                    }
                }
                Some(p) => {
                    let s = String::from_utf8_lossy(&p);
                    if s.starts_with('T') || s.starts_with('S') {
                        self.resume_in_flight = false;
                        return Ok(Some(parse_stop_reply(&p)?));
                    }
                    if s.starts_with('W') || s.starts_with('X') {
                        self.resume_in_flight = false;
                        let raw = s.into_owned();
                        return Ok(Some(StopInfo { thread: None, stop_kind: StopKind::Other(raw.clone()), raw }));
                    }
                    // Non-stop while waiting for a resume end: stash aside.
                    // Do NOT push_front — that livelocks poll_packet on the same
                    // packet and never reads the real stop from the socket.
                    eprintln!("warning: unexpected packet while waiting for stop: {}", s);
                    self.orphan_replies.push_back(p);
                }
            }
        }
    }

    pub fn kill(&mut self) -> Result<()> {
        // `k` has no reply.
        let frame = gdbproto::encode_packet(b"k");
        self.stream.write_all(&frame)?;
        self.stream.flush()?;
        Ok(())
    }

    pub fn detach(&mut self) -> Result<()> {
        let r = self.send_packet(b"D")?;
        if r != b"OK" {
            return Err(GdbError::Protocol(format!("D failed: {}", String::from_utf8_lossy(&r))));
        }
        Ok(())
    }
}

fn parse_packet_size(qsupported: &str) -> Option<usize> {
    for part in qsupported.split(';') {
        if let Some(sz) = part.strip_prefix("PacketSize=") {
            if let Ok(n) = usize::from_str_radix(sz, 16) {
                return Some(n);
            }
        }
    }
    None
}

/// Parse `Sxx` or `Txx[;field:value]...` stop replies.
pub fn parse_stop_reply(packet: &[u8]) -> Result<StopInfo> {
    let s = String::from_utf8_lossy(packet).into_owned();
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return Err(GdbError::Protocol("empty stop reply".into()));
    }
    if bytes[0] != b'T' && bytes[0] != b'S' {
        return Err(GdbError::Protocol(format!("not a stop reply: {}", s)));
    }
    if s.len() < 3 {
        return Err(GdbError::Protocol(format!("short stop reply: {}", s)));
    }
    let sig = u8::from_str_radix(&s[1..3], 16)
        .map_err(|_| GdbError::Protocol(format!("bad signal in stop reply: {}", s)))?;

    let mut thread = None;
    let mut kind = StopKind::Signal(sig);

    // Fields after signal: `;name[:value]`
    let rest = &s[3..];
    let mut specific = false;
    for field in rest.split(';').filter(|f| !f.is_empty()) {
        let (name, value) = match field.split_once(':') {
            Some((n, v)) => (n, Some(v)),
            None => (field, None),
        };
        match name {
            "thread" => {
                if let Some(v) = value {
                    // thread id may be `p1.2` with multiprocess — take last component.
                    let t = v.rsplit('.').next().unwrap_or(v);
                    let t = t.strip_prefix('-').unwrap_or(t);
                    if t != "0" && t != "-1" {
                        thread = Some(parse_u64_hex(t)?);
                    }
                }
            }
            "swbreak" => {
                kind = StopKind::SwBreak;
                specific = true;
            }
            "hwbreak" => {
                kind = StopKind::HwBreak;
                specific = true;
            }
            "watch" | "rwatch" | "awatch" => {
                let addr = value.and_then(|v| parse_u64_hex(v).ok());
                kind = StopKind::Watch {
                    write: name != "rwatch",
                    read: name != "watch",
                    addr,
                };
                specific = true;
            }
            _ => {}
        }
    }
    if !specific {
        kind = StopKind::Signal(sig);
    }
    Ok(StopInfo { thread, stop_kind: kind, raw: s })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;

    fn pkt(payload: &str) -> Vec<u8> {
        gdbproto::encode_packet(payload.as_bytes())
    }

    #[test]
    fn parse_stop_variants() {
        let s = parse_stop_reply(b"S05").unwrap();
        assert_eq!(s.stop_kind, StopKind::Signal(5));
        assert_eq!(s.thread, None);

        let s = parse_stop_reply(b"T05thread:1;").unwrap();
        assert_eq!(s.stop_kind, StopKind::Signal(5));
        assert_eq!(s.thread, Some(1));

        let s = parse_stop_reply(b"T05thread:2;swbreak:;").unwrap();
        assert_eq!(s.stop_kind, StopKind::SwBreak);
        assert_eq!(s.thread, Some(2));

        let s = parse_stop_reply(b"T05hwbreak:;thread:1;").unwrap();
        assert_eq!(s.stop_kind, StopKind::HwBreak);
        assert_eq!(s.thread, Some(1));

        let s = parse_stop_reply(b"T05watch:1234abcd;thread:1;").unwrap();
        assert_eq!(
            s.stop_kind,
            StopKind::Watch { write: true, read: false, addr: Some(0x1234abcd) }
        );

        let s = parse_stop_reply(b"T05rwatch:10;thread:3;").unwrap();
        assert_eq!(
            s.stop_kind,
            StopKind::Watch { write: false, read: true, addr: Some(0x10) }
        );

        let s = parse_stop_reply(b"T05awatch:20;thread:3;").unwrap();
        assert_eq!(
            s.stop_kind,
            StopKind::Watch { write: true, read: true, addr: Some(0x20) }
        );
    }

    /// Minimal scripted gdbstub speaking just enough RSP for the client flow.
    fn spawn_mock_stub() -> (std::net::SocketAddr, mpsc::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = mpsc::channel::<String>();
        thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let xml = b"<?xml version=\"1.0\"?><target><architecture>i386:x86-64</architecture></target>";
            let xml_hex: String = xml.iter().map(|b| format!("{:02x}", b)).collect();

            let mut dec = Decoder::new();
            let mut buf = [0u8; 4096];
            let mut no_ack = false;
            let mut xml_sent = false;
            loop {
                let n = match sock.read(&mut buf) {
                    Ok(0) => return,
                    Ok(n) => n,
                    Err(_) => return,
                };
                for d in dec.feed(&buf[..n]) {
                    let payload = match d {
                        Decoded::Packet(p) => p,
                        Decoded::Interrupt => continue,
                        Decoded::Ack | Decoded::Nack => continue,
                    };
                    let s = String::from_utf8_lossy(&payload).into_owned();
                    let _ = tx.send(s.clone());
                    let reply: Option<String> = if s.starts_with("qSupported") {
                        Some("PacketSize=4000;qXfer:features:read+;swbreak+;hwbreak+;QStartNoAckMode+".into())
                    } else if s == "QStartNoAckMode" {
                        no_ack = true;
                        dec.set_no_ack(true);
                        Some("OK".into())
                    } else if s == "?" {
                        Some("S05".into())
                    } else if s.starts_with("qXfer:features:read:target.xml:") {
                        // Single-chunk for simplicity: send whole xml as 'l' if offset 0.
                        let rest = s.split(':').last().unwrap();
                        let off = usize::from_str_radix(rest.split(',').next().unwrap(), 16).unwrap_or(0);
                        if off == 0 && !xml_sent {
                            xml_sent = true;
                            Some(format!("l{}", xml_hex))
                        } else {
                            Some("l".into())
                        }
                    } else if s == "qfThreadInfo" {
                        Some("m1,2".into())
                    } else if s == "qsThreadInfo" {
                        Some("l".into())
                    } else if s.starts_with("Hg") {
                        Some("OK".into())
                    } else if s.starts_with('m') {
                        // Return 8 bytes of 0xab regardless of request (tests only check length/content loosely)
                        Some("abababababababab".into())
                    } else if s == "g" {
                        Some("00000000000000001111111111111111".into())
                    } else if s.starts_with("Z") || s.starts_with("z") {
                        Some("OK".into())
                    } else if s.starts_with("vCont;s") {
                        // Stop reply instead of OK
                        Some("T05thread:1;swbreak:;".into())
                    } else if s == "D" {
                        Some("OK".into())
                    } else {
                        Some("OK".into())
                    };
                    if let Some(r) = reply {
                        let frame = if no_ack {
                            pkt(&r)
                        } else {
                            let mut f = b"+".to_vec();
                            f.extend(pkt(&r));
                            f
                        };
                        // Wait: client expects reply; when !no_ack client also reads '+' then packet.
                        // After handshake client sets no_ack and won't send '+' either.
                        let _ = sock.write_all(&frame);
                        let _ = sock.flush();
                    }
                }
            }
        });
        (addr, rx)
    }

    #[test]
    fn resume_in_flight_blocks_send_packet_until_stop() {
        let (addr, _rx) = spawn_mock_stub();
        let mut c = GdbRemote::connect(&addr.to_string()).unwrap();
        c.handshake().unwrap();
        assert!(!c.resume_in_flight());
        c.step(Some(1)).unwrap();
        assert!(c.resume_in_flight(), "vCont;s must arm resume_in_flight");
        // Hg/m while running would steal the stop reply (the 9300… desync bug).
        let err = c.send_packet(b"Hg1").unwrap_err();
        assert!(err.to_string().contains("resume in flight"), "got: {}", err);
        let stop = c.wait_stop().unwrap();
        assert_eq!(stop.stop_kind, StopKind::SwBreak);
        assert!(!c.resume_in_flight(), "stop must clear resume_in_flight");
        // Now command packets work again.
        c.set_thread(1).unwrap();
    }

    #[test]
    fn client_full_flow_against_mock() {
        let (addr, _rx) = spawn_mock_stub();
        let mut c = GdbRemote::connect(&addr.to_string()).unwrap();
        c.handshake().unwrap();
        assert!(c.qsupported().contains("PacketSize=4000"));

        let xml = c.fetch_target_xml().unwrap();
        assert!(xml.contains("i386:x86-64"), "xml was: {}", xml);

        let threads = c.threads().unwrap();
        assert_eq!(threads, vec![1, 2]);

        c.set_thread(1).unwrap();
        let mem = c.read_mem(0x1000, 8).unwrap();
        assert_eq!(mem.len(), 8);
        assert_eq!(mem[0], 0xab);

        let regs = c.read_regs_raw().unwrap();
        assert_eq!(regs.len(), 16);

        c.insert_breakpoint(0, 0x1000, 1).unwrap();
        c.remove_breakpoint(0, 0x1000, 1).unwrap();

        c.step(Some(1)).unwrap();
        let stop = c.wait_stop().unwrap();
        assert_eq!(stop.stop_kind, StopKind::SwBreak);
        assert_eq!(stop.thread, Some(1));

        c.detach().unwrap();
    }
}
