use itertools::Itertools;

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherSuite {
    TLS_AES_128_GCM_SHA256,
    TLS_AES_256_GCM_SHA384,
    TLS_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
    TLS_RSA_WITH_AES_128_CBC_SHA,
    TLS_RSA_WITH_AES_128_CBC_SHA256,
    TLS_RSA_WITH_AES_128_GCM_SHA256,
    TLS_RSA_WITH_AES_256_CBC_SHA,
    TLS_RSA_WITH_AES_256_CBC_SHA256,
    TLS_RSA_WITH_AES_256_GCM_SHA384,
    TLS_RSA_WITH_3DES_EDE_CBC_SHA,
}

impl CipherSuite {
    pub fn serialize(input: &[Self]) -> String {
        Itertools::intersperse(input.iter().map(|s| s.as_str()), ":").collect()
    }

    fn as_str(&self) -> &str {
        match self {
            CipherSuite::TLS_AES_128_GCM_SHA256 => "TLS_AES_128_GCM_SHA256",
            CipherSuite::TLS_AES_256_GCM_SHA384 => "TLS_AES_256_GCM_SHA384",
            CipherSuite::TLS_CHACHA20_POLY1305_SHA256 => "TLS_CHACHA20_POLY1305_SHA256",
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA => {
                "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"
            }
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 => {
                "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"
            }
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 => {
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
            }
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA => {
                "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"
            }
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 => {
                "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
            }
            CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 => {
                "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
            }
            CipherSuite::TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA => {
                "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA"
            }
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA => "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 => {
                "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
            }
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 => {
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
            }
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA => "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 => {
                "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"
            }
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 => {
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
            }
            CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => {
                "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
            }
            CipherSuite::TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA => {
                "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"
            }
            CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA => "TLS_RSA_WITH_AES_128_CBC_SHA",
            CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA256 => "TLS_RSA_WITH_AES_128_CBC_SHA256",
            CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256 => "TLS_RSA_WITH_AES_128_GCM_SHA256",
            CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA => "TLS_RSA_WITH_AES_256_CBC_SHA",
            CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA256 => "TLS_RSA_WITH_AES_256_CBC_SHA256",
            CipherSuite::TLS_RSA_WITH_AES_256_GCM_SHA384 => "TLS_RSA_WITH_AES_256_GCM_SHA384",
            CipherSuite::TLS_RSA_WITH_3DES_EDE_CBC_SHA => "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        }
    }
}
