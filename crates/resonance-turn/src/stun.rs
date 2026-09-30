//! STUN messages (RFC 8489) and TURN's ChannelData (RFC 8656 §12): parsed in place, written into a
//! reused buffer. Nothing here allocates per packet.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use hmac::{Hmac, Mac};
use sha1::Sha1;

pub const MAGIC: u32 = 0x2112_A442;
pub const HEADER: usize = 20;

pub mod method {
    pub const BINDING: u16 = 0x001;
    pub const ALLOCATE: u16 = 0x003;
    pub const REFRESH: u16 = 0x004;
    pub const SEND: u16 = 0x006;
    pub const DATA: u16 = 0x007;
    pub const CREATE_PERMISSION: u16 = 0x008;
    pub const CHANNEL_BIND: u16 = 0x009;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    Request,
    Indication,
    Success,
    Error,
}

pub mod attr {
    pub const MAPPED_ADDRESS: u16 = 0x0001;
    pub const USERNAME: u16 = 0x0006;
    pub const MESSAGE_INTEGRITY: u16 = 0x0008;
    pub const ERROR_CODE: u16 = 0x0009;
    pub const UNKNOWN_ATTRIBUTES: u16 = 0x000A;
    pub const CHANNEL_NUMBER: u16 = 0x000C;
    pub const LIFETIME: u16 = 0x000D;
    pub const XOR_PEER_ADDRESS: u16 = 0x0012;
    pub const DATA: u16 = 0x0013;
    pub const REALM: u16 = 0x0014;
    pub const NONCE: u16 = 0x0015;
    pub const XOR_RELAYED_ADDRESS: u16 = 0x0016;
    pub const REQUESTED_ADDRESS_FAMILY: u16 = 0x0017;
    pub const EVEN_PORT: u16 = 0x0018;
    pub const REQUESTED_TRANSPORT: u16 = 0x0019;
    pub const DONT_FRAGMENT: u16 = 0x001A;
    pub const MESSAGE_INTEGRITY_SHA256: u16 = 0x001C;
    pub const PASSWORD_ALGORITHM: u16 = 0x001D;
    pub const USERHASH: u16 = 0x001E;
    pub const XOR_MAPPED_ADDRESS: u16 = 0x0020;
    pub const RESERVATION_TOKEN: u16 = 0x0022;
    pub const PRIORITY: u16 = 0x0024;
    pub const USE_CANDIDATE: u16 = 0x0025;
    pub const ADDITIONAL_ADDRESS_FAMILY: u16 = 0x8000;
    pub const SOFTWARE: u16 = 0x8022;
    pub const FINGERPRINT: u16 = 0x8028;
}

/// An error code's reason phrase (RFC 8489 §14.8, RFC 8656 §19).
pub fn reason(code: u16) -> &'static str {
    match code {
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        420 => "Unknown Attribute",
        437 => "Allocation Mismatch",
        438 => "Stale Nonce",
        440 => "Address Family not Supported",
        441 => "Wrong Credentials",
        442 => "Unsupported Transport Protocol",
        443 => "Peer Address Family Mismatch",
        486 => "Allocation Quota Reached",
        508 => "Insufficient Capacity",
        _ => "",
    }
}

/// Comprehension-required attributes (0x0000–0x7FFF) this relay knows. Any other one in a request
/// gets a 420 (RFC 8489 §14); the ones it knows but doesn't act on are harmless to ignore
/// (EVEN-PORT: ports here are only names; USE-CANDIDATE and PRIORITY: ICE's, sent to a peer).
pub fn understood(t: u16) -> bool {
    use attr::*;
    t >= 0x8000
        || matches!(
            t,
            MAPPED_ADDRESS
                | USERNAME
                | MESSAGE_INTEGRITY
                | ERROR_CODE
                | UNKNOWN_ATTRIBUTES
                | CHANNEL_NUMBER
                | LIFETIME
                | XOR_PEER_ADDRESS
                | DATA
                | REALM
                | NONCE
                | XOR_RELAYED_ADDRESS
                | REQUESTED_ADDRESS_FAMILY
                | EVEN_PORT
                | REQUESTED_TRANSPORT
                | DONT_FRAGMENT
                | MESSAGE_INTEGRITY_SHA256
                | PASSWORD_ALGORITHM
                | USERHASH
                | XOR_MAPPED_ADDRESS
                | PRIORITY
                | USE_CANDIDATE
        )
}

/// A first byte of 0b01 starts ChannelData; STUN starts 0b00.
pub fn is_channel_data(b: &[u8]) -> bool {
    b.len() >= 4 && b[0] & 0xC0 == 0x40
}

/// ChannelData: the channel number and the payload (RFC 8656 §12.4). Padding past the length is
/// allowed and ignored.
pub fn parse_channel_data(b: &[u8]) -> Option<(u16, &[u8])> {
    if !is_channel_data(b) {
        return None;
    }
    let channel = u16::from_be_bytes([b[0], b[1]]);
    let len = u16::from_be_bytes([b[2], b[3]]) as usize;
    b.get(4..4 + len).map(|d| (channel, d))
}

pub fn write_channel_data(out: &mut Vec<u8>, channel: u16, data: &[u8]) {
    out.extend_from_slice(&channel.to_be_bytes());
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
}

/// A STUN message, borrowed from the packet it came in.
#[derive(Clone, Copy, Debug)]
pub struct Message<'a> {
    pub raw: &'a [u8],
    pub method: u16,
    pub class: Class,
    pub tx: [u8; 12],
}

/// One attribute: its type, its value, and where it starts (for MESSAGE-INTEGRITY).
#[derive(Clone, Copy, Debug)]
pub struct Attr<'a> {
    pub kind: u16,
    pub value: &'a [u8],
    pub offset: usize,
}

impl<'a> Message<'a> {
    /// A well-formed STUN message: the magic cookie, a length that fits the packet and is a
    /// multiple of 4, and attributes that exactly fill it.
    pub fn parse(b: &'a [u8]) -> Option<Self> {
        if b.len() < HEADER || b[0] & 0xC0 != 0 {
            return None;
        }
        let t = u16::from_be_bytes([b[0], b[1]]);
        let len = u16::from_be_bytes([b[2], b[3]]) as usize;
        if u32::from_be_bytes([b[4], b[5], b[6], b[7]]) != MAGIC
            || len % 4 != 0
            || b.len() < HEADER + len
        {
            return None;
        }
        let raw = &b[..HEADER + len];
        let mut tx = [0u8; 12];
        tx.copy_from_slice(&raw[8..20]);
        let msg = Message {
            raw,
            method: decode_method(t),
            class: decode_class(t),
            tx,
        };
        // Every attribute must fit.
        let mut it = msg.attrs();
        while it.next().is_some() {}
        if !it.clean {
            return None;
        }
        Some(msg)
    }

    pub fn attrs(&self) -> Attrs<'a> {
        Attrs {
            raw: self.raw,
            at: HEADER,
            clean: true,
        }
    }

    /// The first attribute of a kind, before MESSAGE-INTEGRITY (anything after it is unsigned, so
    /// ignored; FINGERPRINT is the only thing allowed there).
    pub fn get(&self, kind: u16) -> Option<&'a [u8]> {
        for a in self.attrs() {
            if a.kind == kind {
                return Some(a.value);
            }
            if a.kind == attr::MESSAGE_INTEGRITY && kind != attr::FINGERPRINT {
                return None;
            }
        }
        None
    }

    pub fn has(&self, kind: u16) -> bool {
        self.get(kind).is_some()
    }

    /// The comprehension-required attributes this relay doesn't know, before MESSAGE-INTEGRITY:
    /// what follows it is unsigned and ignored (an RFC 8489 client puts
    /// MESSAGE-INTEGRITY-SHA256 there, and must not get a 420 for it).
    pub fn unknown_required(&self) -> impl Iterator<Item = u16> + 'a {
        self.attrs()
            .map(|a| a.kind)
            .take_while(|&k| k != attr::MESSAGE_INTEGRITY)
            .filter(|&k| !understood(k))
    }

    /// FINGERPRINT, if present, checks out: CRC-32 of the message up to it, XOR 0x5354554E, with
    /// the length set as if it ended there (RFC 8489 §14.7). Absent is fine.
    pub fn fingerprint_ok(&self) -> bool {
        let Some(fp) = self.attrs().find(|a| a.kind == attr::FINGERPRINT) else {
            return true;
        };
        if fp.value.len() != 4 || fp.offset + 8 != self.raw.len() {
            return false;
        }
        let len = (fp.offset + 8 - HEADER) as u16;
        let mut h = crc32fast::Hasher::new();
        h.update(&self.raw[..2]);
        h.update(&len.to_be_bytes());
        h.update(&self.raw[4..fp.offset]);
        (h.finalize() ^ 0x5354_554E).to_be_bytes() == fp.value
    }

    /// MESSAGE-INTEGRITY checks out against key: HMAC-SHA1 over the message up to the attribute,
    /// with the length set as if it ended there (RFC 8489 §14.5).
    pub fn integrity_ok(&self, key: &[u8]) -> bool {
        let Some(mi) = self.attrs().find(|a| a.kind == attr::MESSAGE_INTEGRITY) else {
            return false;
        };
        if mi.value.len() != 20 {
            return false;
        }
        let covered = &self.raw[..mi.offset];
        let fake_len = (mi.offset + 24 - HEADER) as u16;
        let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(key).expect("any key length");
        mac.update(&covered[..2]);
        mac.update(&fake_len.to_be_bytes());
        mac.update(&covered[4..]);
        mac.verify_slice(mi.value).is_ok()
    }

    pub fn xor_address(&self, kind: u16) -> Option<SocketAddr> {
        decode_xor_address(self.get(kind)?, &self.tx)
    }

    pub fn u32_attr(&self, kind: u16) -> Option<u32> {
        let v = self.get(kind)?;
        (v.len() == 4).then(|| u32::from_be_bytes([v[0], v[1], v[2], v[3]]))
    }

    pub fn str_attr(&self, kind: u16) -> Option<&'a str> {
        std::str::from_utf8(self.get(kind)?).ok()
    }
}

pub struct Attrs<'a> {
    raw: &'a [u8],
    at: usize,
    /// False once an attribute overran the message.
    pub clean: bool,
}

impl<'a> Iterator for Attrs<'a> {
    type Item = Attr<'a>;
    fn next(&mut self) -> Option<Attr<'a>> {
        if self.at >= self.raw.len() {
            return None;
        }
        let Some(head) = self.raw.get(self.at..self.at + 4) else {
            self.clean = false;
            return None;
        };
        let kind = u16::from_be_bytes([head[0], head[1]]);
        let len = u16::from_be_bytes([head[2], head[3]]) as usize;
        let start = self.at + 4;
        let Some(value) = self.raw.get(start..start + len) else {
            self.clean = false;
            self.at = self.raw.len();
            return None;
        };
        let offset = self.at;
        self.at = start + len.next_multiple_of(4);
        if self.at > self.raw.len() {
            self.clean = false;
            self.at = self.raw.len();
            return None;
        }
        Some(Attr {
            kind,
            value,
            offset,
        })
    }
}

fn decode_method(t: u16) -> u16 {
    (t & 0x000F) | ((t & 0x00E0) >> 1) | ((t & 0x3E00) >> 2)
}

fn decode_class(t: u16) -> Class {
    match ((t >> 4) & 1) | ((t >> 7) & 2) {
        0 => Class::Request,
        1 => Class::Indication,
        2 => Class::Success,
        _ => Class::Error,
    }
}

fn encode_type(method: u16, class: Class) -> u16 {
    let c = match class {
        Class::Request => 0,
        Class::Indication => 1,
        Class::Success => 2,
        Class::Error => 3,
    };
    (method & 0x000F)
        | ((method & 0x0070) << 1)
        | ((method & 0x0F80) << 2)
        | ((c & 1) << 4)
        | ((c & 2) << 7)
}

pub fn decode_xor_address(v: &[u8], tx: &[u8; 12]) -> Option<SocketAddr> {
    if v.len() < 4 {
        return None;
    }
    let port = u16::from_be_bytes([v[2], v[3]]) ^ (MAGIC >> 16) as u16;
    let ip = match (v[1], v.len()) {
        (0x01, 8) => {
            let x = u32::from_be_bytes([v[4], v[5], v[6], v[7]]) ^ MAGIC;
            IpAddr::V4(Ipv4Addr::from(x))
        }
        (0x02, 20) => {
            let mut b = [0u8; 16];
            let mut mask = [0u8; 16];
            mask[..4].copy_from_slice(&MAGIC.to_be_bytes());
            mask[4..].copy_from_slice(tx);
            for i in 0..16 {
                b[i] = v[4 + i] ^ mask[i];
            }
            IpAddr::V6(Ipv6Addr::from(b))
        }
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}

/// Writes one STUN message into a buffer: header, attributes, then optionally
/// MESSAGE-INTEGRITY and FINGERPRINT, with the length kept right at each step.
pub struct Writer<'b> {
    buf: &'b mut Vec<u8>,
    start: usize,
    tx: [u8; 12],
}

impl<'b> Writer<'b> {
    pub fn new(buf: &'b mut Vec<u8>, method: u16, class: Class, tx: [u8; 12]) -> Self {
        let start = buf.len();
        buf.extend_from_slice(&encode_type(method, class).to_be_bytes());
        buf.extend_from_slice(&[0, 0]);
        buf.extend_from_slice(&MAGIC.to_be_bytes());
        buf.extend_from_slice(&tx);
        Writer { buf, start, tx }
    }

    fn set_len(&mut self) {
        let len = (self.buf.len() - self.start - HEADER) as u16;
        self.buf[self.start + 2..self.start + 4].copy_from_slice(&len.to_be_bytes());
    }

    pub fn attr(&mut self, kind: u16, value: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(&kind.to_be_bytes());
        self.buf
            .extend_from_slice(&(value.len() as u16).to_be_bytes());
        self.buf.extend_from_slice(value);
        let pad = value.len().next_multiple_of(4) - value.len();
        self.buf.extend_from_slice(&[0u8; 3][..pad]);
        self.set_len();
        self
    }

    pub fn u32(&mut self, kind: u16, v: u32) -> &mut Self {
        self.attr(kind, &v.to_be_bytes())
    }

    pub fn xor_address(&mut self, kind: u16, addr: SocketAddr) -> &mut Self {
        let port = addr.port() ^ (MAGIC >> 16) as u16;
        let mut v = [0u8; 20];
        v[2..4].copy_from_slice(&port.to_be_bytes());
        let n = match addr.ip() {
            IpAddr::V4(ip) => {
                v[1] = 0x01;
                v[4..8].copy_from_slice(&(u32::from(ip) ^ MAGIC).to_be_bytes());
                8
            }
            IpAddr::V6(ip) => {
                v[1] = 0x02;
                let mut mask = [0u8; 16];
                mask[..4].copy_from_slice(&MAGIC.to_be_bytes());
                mask[4..].copy_from_slice(&self.tx);
                for (i, b) in ip.octets().iter().enumerate() {
                    v[4 + i] = b ^ mask[i];
                }
                20
            }
        };
        self.attr(kind, &v[..n])
    }

    pub fn error(&mut self, code: u16, reason: &str) -> &mut Self {
        let mut v = [0u8; 4 + 64];
        v[2] = (code / 100) as u8;
        v[3] = (code % 100) as u8;
        let r = &reason.as_bytes()[..reason.len().min(64)];
        v[4..4 + r.len()].copy_from_slice(r);
        self.attr(attr::ERROR_CODE, &v[..4 + r.len()])
    }

    /// MESSAGE-INTEGRITY with key (the long-term key, RFC 8489 §9.2.2).
    pub fn integrity(&mut self, key: &[u8]) -> &mut Self {
        let len = (self.buf.len() - self.start - HEADER + 24) as u16;
        self.buf[self.start + 2..self.start + 4].copy_from_slice(&len.to_be_bytes());
        let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(key).expect("any key length");
        mac.update(&self.buf[self.start..]);
        let sum = mac.finalize().into_bytes();
        self.attr(attr::MESSAGE_INTEGRITY, &sum)
    }

    pub fn fingerprint(&mut self) {
        let len = (self.buf.len() - self.start - HEADER + 8) as u16;
        self.buf[self.start + 2..self.start + 4].copy_from_slice(&len.to_be_bytes());
        let crc = crc32fast::hash(&self.buf[self.start..]) ^ 0x5354_554E;
        self.u32(attr::FINGERPRINT, crc);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn type_bits_round_trip() {
        for m in [
            method::BINDING,
            method::ALLOCATE,
            method::CHANNEL_BIND,
            0xFFF,
        ] {
            for c in [
                Class::Request,
                Class::Indication,
                Class::Success,
                Class::Error,
            ] {
                let t = encode_type(m, c);
                assert_eq!((decode_method(t), decode_class(t)), (m, c));
            }
        }
        assert_eq!(encode_type(method::BINDING, Class::Request), 0x0001);
        assert_eq!(encode_type(method::BINDING, Class::Success), 0x0101);
        assert_eq!(encode_type(method::ALLOCATE, Class::Error), 0x0113);
    }

    #[test]
    fn written_messages_parse_and_check_out() {
        let tx = [7u8; 12];
        let mut buf = Vec::new();
        let v6: SocketAddr = "[2001:db8::1]:3478".parse().unwrap();
        let v4: SocketAddr = "192.0.2.1:49152".parse().unwrap();
        Writer::new(&mut buf, method::ALLOCATE, Class::Success, tx)
            .xor_address(attr::XOR_RELAYED_ADDRESS, v4)
            .xor_address(attr::XOR_MAPPED_ADDRESS, v6)
            .u32(attr::LIFETIME, 600)
            .attr(attr::USERNAME, b"odd")
            .integrity(b"key")
            .fingerprint();
        let m = Message::parse(&buf).unwrap();
        assert_eq!(
            (m.method, m.class, m.tx),
            (method::ALLOCATE, Class::Success, tx)
        );
        assert_eq!(m.xor_address(attr::XOR_RELAYED_ADDRESS), Some(v4));
        assert_eq!(m.xor_address(attr::XOR_MAPPED_ADDRESS), Some(v6));
        assert_eq!(m.u32_attr(attr::LIFETIME), Some(600));
        assert_eq!(m.str_attr(attr::USERNAME), Some("odd"));
        assert!(m.integrity_ok(b"key"));
        assert!(!m.integrity_ok(b"other"));
        assert!(m.has(attr::FINGERPRINT));
    }

    // RFC 5769 §2.1, the sample request: checks our HMAC framing against someone else's bytes.
    #[test]
    fn rfc5769_sample_request_integrity() {
        let hex = "000100582112a442b7e7a701bc34d686fa87dfae\
                   802200105354554e207465737420636c69656e74\
                   002400046e0001ff80290008932ff9b151263b36\
                   000600096576746a3a68367659202020\
                   000800149aeaa70cbfd8cb56781ef2b5b2d3f249c1b571a2\
                   80280004e57a3bcf";
        let hex: String = hex.split_whitespace().collect();
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        let m = Message::parse(&bytes).unwrap();
        assert_eq!(m.str_attr(attr::USERNAME), Some("evtj:h6vY"));
        assert!(m.integrity_ok(b"VOkJxbRl1RmTxUk/WvJxBt"));
        assert!(!m.integrity_ok(b"VOkJxbRl1RmTxUk/WvJxBu"));
    }

    #[test]
    fn malformed_messages_are_refused() {
        let mut buf = Vec::new();
        Writer::new(&mut buf, method::BINDING, Class::Request, [0; 12]).attr(attr::SOFTWARE, b"x");
        assert!(Message::parse(&buf).is_some());
        assert!(Message::parse(&buf[..buf.len() - 1]).is_none(), "truncated");
        let mut bad = buf.clone();
        bad[4] ^= 1;
        assert!(Message::parse(&bad).is_none(), "no magic cookie");
        let mut bad = buf.clone();
        bad[22..24].copy_from_slice(&200u16.to_be_bytes());
        assert!(Message::parse(&bad).is_none(), "attribute overruns");
        assert!(
            Message::parse(&[0x40, 0, 0, 0]).is_none(),
            "ChannelData isn't STUN"
        );
    }

    #[test]
    fn channel_data() {
        let mut out = Vec::new();
        write_channel_data(&mut out, 0x4001, b"hello");
        assert_eq!(parse_channel_data(&out), Some((0x4001, &b"hello"[..])));
        out.extend_from_slice(&[0, 0, 0]);
        assert_eq!(
            parse_channel_data(&out),
            Some((0x4001, &b"hello"[..])),
            "padding is ignored"
        );
        assert_eq!(
            parse_channel_data(&out[..6]),
            None,
            "shorter than its length"
        );
    }
}
