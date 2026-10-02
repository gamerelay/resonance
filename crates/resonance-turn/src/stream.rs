//! TURN over a stream (TCP or TLS, RFC 8656 §12.5): messages back to back with no other framing.
//! A STUN message says its own length (20 + its header's length field); ChannelData says its
//! data's length, and is padded to a multiple of 4 on a stream (not on UDP). Sans-I/O: bytes in,
//! whole messages out.

/// The largest message a stream carries: a STUN header and its 16-bit length.
pub const MAX_MESSAGE: usize = 20 + 0xFFFF;

/// Bytes read from one stream, cut into messages.
#[derive(Default)]
pub struct Framer {
    buf: Vec<u8>,
    /// Where the next message starts in `buf`.
    at: usize,
    /// A message came out already: until then only STUN is expected (no channel is bound yet).
    started: bool,
}

/// What `Framer::next` found.
#[derive(Debug, PartialEq)]
pub enum Frame<'a> {
    /// A whole message (ChannelData without its padding).
    Message(&'a [u8]),
    /// Not a message's start: the stream is junk and should be closed.
    Junk,
}

impl Framer {
    /// Bytes as they arrived.
    pub fn push(&mut self, bytes: &[u8]) {
        if self.at > 0 && self.at == self.buf.len() {
            self.buf.clear();
            self.at = 0;
        }
        self.buf.extend_from_slice(bytes);
    }

    /// Bytes it holds (its buffer's capacity): at most about one message plus what one read
    /// brought.
    pub fn held(&self) -> usize {
        self.buf.capacity()
    }

    /// The next whole message, `Junk`, or None until more bytes arrive.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Option<Frame<'_>> {
        let rest = &self.buf[self.at..];
        let first = *rest.first()?;
        let need = if first < 0x40 { 8 } else { 4 };
        if rest.len() < need {
            self.compact();
            return None;
        }
        let len = u16::from_be_bytes([rest[2], rest[3]]) as usize;
        let (whole, used) = match first {
            // STUN: the two top bits are 0, its length a multiple of 4, then the magic cookie.
            0x00..=0x3F if len % 4 == 0 && rest[4..8] == [0x21, 0x12, 0xA4, 0x42] => {
                (20 + len, 20 + len)
            }
            // ChannelData: channel numbers 0x4000-0x7FFF, padded to 4 on a stream; never first.
            0x40..=0x7F if self.started => (4 + len, (4 + len).next_multiple_of(4)),
            _ => return Some(Frame::Junk),
        };
        if rest.len() < used {
            self.compact();
            return None;
        }
        let start = self.at;
        self.at += used;
        self.started = true;
        Some(Frame::Message(&self.buf[start..start + whole]))
    }

    /// Bytes waiting for the rest of their message.
    pub fn pending(&self) -> usize {
        self.buf.len() - self.at
    }

    /// Drops what's been handed out, so a long-lived stream's buffer doesn't grow.
    fn compact(&mut self) {
        if self.at > 0 {
            self.buf.drain(..self.at);
            self.at = 0;
        }
    }
}

/// The padding a message needs after it on a stream: ChannelData to a multiple of 4.
pub fn padding(message: &[u8]) -> &'static [u8] {
    const ZEROS: [u8; 3] = [0; 3];
    match message.first() {
        Some(0x40..=0x7F) => &ZEROS[..(4 - message.len() % 4) % 4],
        _ => &[],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stun(body: usize) -> Vec<u8> {
        let mut m = vec![0x00, 0x01];
        m.extend_from_slice(&(body as u16).to_be_bytes());
        m.extend_from_slice(&[0x21, 0x12, 0xA4, 0x42]);
        m.extend_from_slice(&[7; 12]);
        m.extend(std::iter::repeat_n(9, body));
        m
    }

    fn channel(data: &[u8]) -> Vec<u8> {
        let mut m = vec![0x40, 0x00];
        m.extend_from_slice(&(data.len() as u16).to_be_bytes());
        m.extend_from_slice(data);
        m
    }

    fn all(f: &mut Framer) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        while let Some(Frame::Message(m)) = f.next() {
            out.push(m.to_vec());
        }
        out
    }

    #[test]
    fn messages_back_to_back_come_out_whole() {
        let (a, b) = (stun(8), channel(b"hello"));
        // (ChannelData only after a STUN message, as on a real stream.)
        let mut bytes = a.clone();
        bytes.extend_from_slice(&b);
        bytes.extend_from_slice(padding(&b));
        assert_eq!(padding(&b).len(), 3);
        let mut f = Framer::default();
        f.push(&bytes);
        assert_eq!(all(&mut f), vec![a, b], "ChannelData without its padding");
        assert_eq!(f.pending(), 0);
    }

    #[test]
    fn a_message_split_anywhere_waits_for_the_rest() {
        let m = stun(40);
        for cut in 1..m.len() {
            let mut f = Framer::default();
            f.push(&m[..cut]);
            assert_eq!(f.next(), None, "cut at {cut}");
            f.push(&m[cut..]);
            assert_eq!(f.next(), Some(Frame::Message(&m[..])));
            assert_eq!(f.next(), None);
        }
        // Byte by byte, several messages.
        let mut bytes = stun(0);
        for n in [0, 4, 12] {
            let c = channel(&vec![1; n + 1]);
            bytes.extend_from_slice(&c);
            bytes.extend_from_slice(padding(&c));
        }
        let mut f = Framer::default();
        let mut got = 0;
        for b in &bytes {
            f.push(&[*b]);
            got += all(&mut f).len();
        }
        assert_eq!(got, 4);
    }

    #[test]
    fn junk_is_junk() {
        let mut f = Framer::default();
        f.push(b"GET / HTTP/1.1\r\n");
        assert_eq!(f.next(), Some(Frame::Junk));
        // A STUN-looking start with a length that isn't a multiple of 4, or no magic cookie.
        let mut f = Framer::default();
        f.push(&[0x00, 0x01, 0x00, 0x05, 0x21, 0x12, 0xA4, 0x42]);
        assert_eq!(f.next(), Some(Frame::Junk));
        let mut f = Framer::default();
        f.push(&[0x00, 0x01, 0x00, 0x04, 0, 0, 0, 0]);
        assert_eq!(f.next(), Some(Frame::Junk));
        // A TLS ClientHello on the plain TCP port.
        let mut f = Framer::default();
        f.push(&[0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01, 0xFC]);
        assert_eq!(f.next(), Some(Frame::Junk));
        // ChannelData first: no channel can be bound yet.
        let mut f = Framer::default();
        f.push(&channel(b"data"));
        assert_eq!(f.next(), Some(Frame::Junk));
    }

    #[test]
    fn a_long_lived_stream_doesnt_grow() {
        let mut f = Framer::default();
        let m = stun(100);
        for _ in 0..1000 {
            f.push(&m);
            f.push(&m[..10]);
            assert_eq!(all(&mut f).len(), 1);
            f.push(&m[10..]);
            assert_eq!(all(&mut f).len(), 1);
        }
        assert!(f.buf.capacity() < 4 * m.len(), "{}", f.buf.capacity());
    }
}
