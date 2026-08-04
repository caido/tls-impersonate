use crate::compress::CompressionKind;
use crate::options::TlsOptions;
use boring::ssl::SslVersion;

pub const CURVES_1: &str = join!(":", "X25519", "P-256", "P-384");

pub const CURVES_2: &str = join!(":", "X25519Kyber768Draft00", "X25519", "P-256", "P-384");

pub const CURVES_3: &str = join!(":", "X25519MLKEM768", "X25519", "P-256", "P-384");

pub const CIPHER_LIST: &str = join!(
    ":",
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    "TLS_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_RSA_WITH_AES_128_CBC_SHA",
    "TLS_RSA_WITH_AES_256_CBC_SHA"
);

pub const SIGALGS_LIST: &str = join!(
    ":",
    "ecdsa_secp256r1_sha256",
    "rsa_pss_rsae_sha256",
    "rsa_pkcs1_sha256",
    "ecdsa_secp384r1_sha384",
    "rsa_pss_rsae_sha384",
    "rsa_pkcs1_sha384",
    "rsa_pss_rsae_sha512",
    "rsa_pkcs1_sha512"
);

const CERTIFICATE_COMPRESSOR: &[&CompressionKind] = &[&CompressionKind::Brotli];

impl TlsOptions {
    pub fn chrome() -> Self {
        TlsOptions {
            certificate_compressors: Some(CERTIFICATE_COMPRESSOR),
            cipher_list: Some(CIPHER_LIST),
            curves_list: Some(CURVES_1),
            enable_ech_grease: true,
            enable_ocsp_stapling: true,
            enable_signed_cert_timestamps: true,
            grease_enabled: Some(true),
            max_tls_version: Some(SslVersion::TLS1_3),
            min_tls_version: Some(SslVersion::TLS1_2),
            permute_extensions: Some(false),
            pre_shared_key: false,
            sigalgs_list: Some(SIGALGS_LIST),
            ..Default::default()
        }
    }

    pub fn chrome_124() -> Self {
        TlsOptions {
            curves_list: Some(CURVES_2),
            ..Self::chrome()
        }
    }

    pub fn chrome_132() -> Self {
        TlsOptions {
            curves_list: Some(CURVES_3),
            ..Self::chrome()
        }
    }
}
