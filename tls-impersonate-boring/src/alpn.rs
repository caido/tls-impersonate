use bytes::{BufMut, Bytes, BytesMut};

/// A TLS ALPN protocol.
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct AlpnProtocol(&'static [u8]);

impl AlpnProtocol {
    /// Prefer HTTP/1.1
    pub const HTTP1: AlpnProtocol = AlpnProtocol(b"http/1.1");

    /// Prefer HTTP/2
    pub const HTTP2: AlpnProtocol = AlpnProtocol(b"h2");

    /// Prefer HTTP/3
    pub const HTTP3: AlpnProtocol = AlpnProtocol(b"h3");

    #[inline]
    fn encode(self) -> Bytes {
        Self::encode_sequence(std::iter::once(&self))
    }

    pub fn encode_sequence<'a, I>(items: I) -> Bytes
    where
        I: IntoIterator<Item = &'a AlpnProtocol>,
    {
        let mut buf = BytesMut::new();
        for item in items {
            buf.put_u8(item.0.len() as u8);
            buf.extend_from_slice(item.0);
        }
        buf.freeze()
    }
}

impl PartialEq<[u8]> for AlpnProtocol {
    #[inline]
    fn eq(&self, other: &[u8]) -> bool {
        self.0 == other
    }
}

/// A TLS ALPS protocol.
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct AlpsProtocol(&'static [u8]);

impl AlpsProtocol {
    /// Prefer HTTP/1.1
    pub const HTTP1: AlpsProtocol = AlpsProtocol(b"http/1.1");

    /// Prefer HTTP/2
    pub const HTTP2: AlpsProtocol = AlpsProtocol(b"h2");

    /// Prefer HTTP/3
    pub const HTTP3: AlpsProtocol = AlpsProtocol(b"h3");
}

impl PartialEq<[u8]> for AlpsProtocol {
    #[inline]
    fn eq(&self, other: &[u8]) -> bool {
        self.0 == other
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alpn_protocol_encode() {
        let alpn = AlpnProtocol::encode_sequence(&[AlpnProtocol::HTTP1, AlpnProtocol::HTTP2]);
        assert_eq!(alpn, Bytes::from_static(b"\x08http/1.1\x02h2"));

        let alpn = AlpnProtocol::encode_sequence(&[AlpnProtocol::HTTP3]);
        assert_eq!(alpn, Bytes::from_static(b"\x02h3"));

        let alpn = AlpnProtocol::encode_sequence(&[AlpnProtocol::HTTP1, AlpnProtocol::HTTP3]);
        assert_eq!(alpn, Bytes::from_static(b"\x08http/1.1\x02h3"));

        let alpn = AlpnProtocol::encode_sequence(&[AlpnProtocol::HTTP2, AlpnProtocol::HTTP3]);
        assert_eq!(alpn, Bytes::from_static(b"\x02h2\x02h3"));

        let alpn = AlpnProtocol::encode_sequence(&[
            AlpnProtocol::HTTP1,
            AlpnProtocol::HTTP2,
            AlpnProtocol::HTTP3,
        ]);
        assert_eq!(alpn, Bytes::from_static(b"\x08http/1.1\x02h2\x02h3"));
    }

    #[test]
    fn alpn_protocol_encode_single() {
        let alpn = AlpnProtocol::HTTP1.encode();
        assert_eq!(alpn, b"\x08http/1.1".as_ref());

        let alpn = AlpnProtocol::HTTP2.encode();
        assert_eq!(alpn, b"\x02h2".as_ref());

        let alpn = AlpnProtocol::HTTP3.encode();
        assert_eq!(alpn, b"\x02h3".as_ref());
    }
}
