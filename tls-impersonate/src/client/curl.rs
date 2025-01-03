use crate::{CipherSuite, SignatureAlgorithm, TlsSettings, TlsVersion};

pub mod curl_7_61_1 {
    use crate::CertsStore;

    use super::*;

    const CIPHERS: &[CipherSuite] = &[
        CipherSuite::TLS_AES_128_GCM_SHA256,
        CipherSuite::TLS_AES_256_GCM_SHA384,
        CipherSuite::TLS_CHACHA20_POLY1305_SHA256,
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    ];

    const SIGNATURE_ALGORITHMS: &[SignatureAlgorithm] = &[
        SignatureAlgorithm::RSA_PSS_RSAE_SHA256,
        SignatureAlgorithm::ECDSA_SECP256R1_SHA256,
        SignatureAlgorithm::ED25519,
        SignatureAlgorithm::RSA_PSS_RSAE_SHA384,
        SignatureAlgorithm::RSA_PSS_RSAE_SHA512,
        SignatureAlgorithm::RSA_PKCS1_SHA256,
        SignatureAlgorithm::RSA_PKCS1_SHA384,
        SignatureAlgorithm::RSA_PKCS1_SHA512,
        SignatureAlgorithm::ECDSA_SECP384R1_SHA384,
        SignatureAlgorithm::RSA_PKCS1_SHA1,
        SignatureAlgorithm::ECDSA_SHA1,
    ];

    pub fn settings(with_certs: bool) -> TlsSettings {
        TlsSettings::builder()
            .certs_store(if with_certs {
                Some(CertsStore::load())
            } else {
                None
            })
            .min_tls_version(TlsVersion::TLS1_0)
            .max_tls_version(TlsVersion::TLS1_3)
            .session_ticket(false)
            .alpn_protos(&[])
            .ciphers(CIPHERS)
            .signature_algorithms(SIGNATURE_ALGORITHMS)
            .enable_ocsp_stapling(true)
            .enable_signed_cert_timestamps(true)
            .encrypt_then_mac(false)
            .padding(false)
            .build()
    }
}
