// GDB remote serial protocol (RSP) framing — pure, no I/O.
// Spec: https://sourceware.org/gdb/current/onlinedocs/gdb.html/Packets.html

pub fn checksum(payload: &[u8]) -> u8 {
    payload.iter().fold(0u8, |a, &b| a.wrapping_add(b))
}

fn hex_digit(n: u8) -> u8 {
    if n < 10 { b'0' + n } else { b'a' + (n - 10) }
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// `$` payload `#` cc — cc is two lowercase hex digits.
pub fn encode_packet(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 4);
    out.push(b'$');
    out.extend_from_slice(payload);
    out.push(b'#');
    let cs = checksum(payload);
    out.push(hex_digit(cs >> 4));
    out.push(hex_digit(cs & 0xf));
    out
}

/// RSP binary escaping used by the `X` (write memory) packet:
/// 0x7d escape character, following byte XOR 0x20.
pub fn escape(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    for &b in data {
        if b == 0x7d || b == 0x7e || b == b'#' || b == b'$' {
            out.push(0x7d);
            out.push(b ^ 0x20);
        } else {
            out.push(b);
        }
    }
    out
}

pub fn unescape(data: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(data.len());
    let mut i = 0;
    while i < data.len() {
        if data[i] == 0x7d {
            if i + 1 >= data.len() {
                return Err("trailing escape byte".into());
            }
            out.push(data[i + 1] ^ 0x20);
            i += 2;
        } else {
            out.push(data[i]);
            i += 1;
        }
    }
    Ok(out)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decoded {
    Packet(Vec<u8>),
    Ack,
    Nack,
    Interrupt,
}

enum State {
    Idle,
    Data,
    /// Saw `#`, collecting two checksum digits.
    Checksum { chars: [u8; 2], n: usize },
}

pub struct Decoder {
    state: State,
    payload: Vec<u8>,
    no_ack: bool,
    /// Number of packets dropped for bad checksum (caller may respond with Nack when !no_ack).
    pub bad_checksums: u64,
}

impl Decoder {
    pub fn new() -> Self {
        Decoder { state: State::Idle, payload: Vec::new(), no_ack: false, bad_checksums: 0 }
    }

    pub fn set_no_ack(&mut self, no_ack: bool) {
        self.no_ack = no_ack;
    }

    pub fn no_ack(&self) -> bool {
        self.no_ack
    }

    /// Feed raw bytes from the socket; returns everything that completed.
    /// Handles packets split arbitrarily across feeds. Bad-checksum packets are dropped.
    pub fn feed(&mut self, bytes: &[u8]) -> Vec<Decoded> {
        let mut out = Vec::new();
        for &b in bytes {
            match &mut self.state {
                State::Idle => match b {
                    b'$' => {
                        self.payload.clear();
                        self.state = State::Data;
                    }
                    b'+' => out.push(Decoded::Ack),
                    b'-' => out.push(Decoded::Nack),
                    0x03 => out.push(Decoded::Interrupt),
                    _ => {} // stray noise between packets
                },
                State::Data => match b {
                    b'#' => {
                        self.state = State::Checksum { chars: [0; 2], n: 0 };
                    }
                    b'$' => {
                        // New packet started without terminator — restart (malformed stream).
                        self.payload.clear();
                    }
                    _ => self.payload.push(b),
                },
                State::Checksum { .. } => {
                    let (chars, n) = match std::mem::replace(&mut self.state, State::Idle) {
                        State::Checksum { chars, n } => (chars, n),
                        _ => unreachable!(),
                    };
                    let mut chars = chars;
                    let mut n = n;
                    chars[n] = b;
                    n += 1;
                    if n < 2 {
                        self.state = State::Checksum { chars, n };
                        continue;
                    }
                    let got = (hex_val(chars[0]).unwrap_or(0) << 4) | hex_val(chars[1]).unwrap_or(0);
                    let expect = checksum(&self.payload);
                    if got == expect {
                        out.push(Decoded::Packet(std::mem::take(&mut self.payload)));
                    } else {
                        self.bad_checksums += 1;
                        self.payload.clear();
                    }
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_known_packet() {
        // checksum('$' excluded): 'O'+'K' = 0x4f+0x4b = 0x9a
        assert_eq!(encode_packet(b"OK"), b"$OK#9a".to_vec());
        assert_eq!(encode_packet(b""), b"$#00".to_vec());
        assert_eq!(checksum(b""), 0);
    }

    #[test]
    fn decode_roundtrip() {
        let mut d = Decoder::new();
        let pkt = encode_packet(b"vCont?");
        let got = d.feed(&pkt);
        assert_eq!(got, vec![Decoded::Packet(b"vCont?".to_vec())]);
    }

    #[test]
    fn decode_byte_by_byte() {
        let pkt = encode_packet(b"qSupported:swbreak+");
        let mut d = Decoder::new();
        let mut acc = Vec::new();
        for b in pkt {
            acc.extend(d.feed(&[b]));
        }
        assert_eq!(acc, vec![Decoded::Packet(b"qSupported:swbreak+".to_vec())]);
    }

    #[test]
    fn bad_checksum_dropped() {
        let mut d = Decoder::new();
        let mut pkt = encode_packet(b"OK");
        let last = pkt.len() - 1;
        pkt[last] = if pkt[last] == b'0' { b'1' } else { b'0' };
        let got = d.feed(&pkt);
        assert!(got.is_empty());
        assert_eq!(d.bad_checksums, 1);
    }

    #[test]
    fn ack_nack_interrupt() {
        let mut d = Decoder::new();
        let got = d.feed(b"+-\x03");
        assert_eq!(got, vec![Decoded::Ack, Decoded::Nack, Decoded::Interrupt]);
    }

    #[test]
    fn escape_roundtrip() {
        let data = [0x00, 0x23, 0x24, 0x7d, 0x7e, 0xff, b'A'];
        let e = escape(&data);
        assert!(!e.contains(&0x23));
        assert!(!e.contains(&0x24));
        assert!(!e.contains(&0x7e));
        assert_eq!(unescape(&e).unwrap(), data);
    }

    #[test]
    fn escape_bad_trailing() {
        assert!(unescape(&[0x7d]).is_err());
    }
}
