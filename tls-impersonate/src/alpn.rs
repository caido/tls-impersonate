#[derive(Debug, Clone, Copy, Default)]
pub enum AlpnProtocol {
    /// Advertise HTTP/1.1
    #[default]
    Http1,
    /// Advertise HTTP/2
    Http2,
}

impl AlpnProtocol {
    pub fn serialize(input: &[Self]) -> Vec<u8> {
        let len = input.iter().map(|p| p.len()).sum();
        let mut buf = Vec::with_capacity(len);
        for protocol in input {
            buf.extend_from_slice(protocol.as_bytes());
        }
        buf
    }

    fn len(&self) -> usize {
        match self {
            AlpnProtocol::Http1 => 8,
            AlpnProtocol::Http2 => 2,
        }
    }

    fn as_bytes(&self) -> &[u8] {
        match self {
            AlpnProtocol::Http1 => b"\x08http/1.1",
            AlpnProtocol::Http2 => b"\x02h2",
        }
    }
}
