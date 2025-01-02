use itertools::Itertools;

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    ECDSA_SHA1,
    ECDSA_SECP256R1_SHA256,
    ECDSA_SECP384R1_SHA384,
    ECDSA_SECP521R1_SHA512,
    RSA_PSS_RSAE_SHA256,
    RSA_PSS_RSAE_SHA384,
    RSA_PSS_RSAE_SHA512,
    RSA_PKCS1_SHA1,
    RSA_PKCS1_SHA256,
    RSA_PKCS1_SHA384,
    RSA_PKCS1_SHA512,
    ED25519,
}

impl SignatureAlgorithm {
    pub fn serialize(input: &[Self]) -> String {
        Itertools::intersperse(input.iter().map(|s| s.as_str()), ":").collect()
    }

    fn as_str(&self) -> &str {
        match self {
            SignatureAlgorithm::ECDSA_SHA1 => "ecdsa_sha1",
            SignatureAlgorithm::ECDSA_SECP256R1_SHA256 => "ecdsa_secp256r1_sha256",
            SignatureAlgorithm::ECDSA_SECP384R1_SHA384 => "ecdsa_secp384r1_sha384",
            SignatureAlgorithm::ECDSA_SECP521R1_SHA512 => "ecdsa_secp521r1_sha512",
            SignatureAlgorithm::RSA_PSS_RSAE_SHA256 => "rsa_pss_rsae_sha256",
            SignatureAlgorithm::RSA_PSS_RSAE_SHA384 => "rsa_pss_rsae_sha384",
            SignatureAlgorithm::RSA_PSS_RSAE_SHA512 => "rsa_pss_rsae_sha512",
            SignatureAlgorithm::RSA_PKCS1_SHA1 => "rsa_pkcs1_sha1",
            SignatureAlgorithm::RSA_PKCS1_SHA256 => "rsa_pkcs1_sha256",
            SignatureAlgorithm::RSA_PKCS1_SHA384 => "rsa_pkcs1_sha384",
            SignatureAlgorithm::RSA_PKCS1_SHA512 => "rsa_pkcs1_sha512",
            SignatureAlgorithm::ED25519 => "ed25519",
        }
    }
}
