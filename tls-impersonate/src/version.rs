/// A TLS protocol version.
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsVersion {
    TLS1_0,
    TLS1_1,
    TLS1_2,
    TLS1_3,
}
