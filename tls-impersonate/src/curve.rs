#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SslCurve {
    X25519,
    X25519_KYBER_768_DRAFT_00,
    X25519_MLKEM_768,
    SECP256R1,
    SECP384R1,
    SECP521R1,
    FFDHE2048,
    FFDHE3072,
}
