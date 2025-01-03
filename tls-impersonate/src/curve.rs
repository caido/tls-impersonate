use itertools::Itertools;

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SslCurve {
    X25519,
    X25519_KYBER768_DRAFT00,
    X25519_MLKEM768,
    SECP256R1,
    SECP384R1,
    SECP521R1,
    FFDHE2048,
    FFDHE3072,
}

impl SslCurve {
    pub fn serialize(input: &[SslCurve]) -> String {
        Itertools::intersperse(input.iter().map(|s| s.as_str()), ":").collect()
    }

    fn as_str(&self) -> &str {
        match self {
            SslCurve::X25519 => "X25519",
            SslCurve::X25519_KYBER768_DRAFT00 => "X25519Kyber768Draft00",
            SslCurve::X25519_MLKEM768 => "X25519MLKEM768",
            SslCurve::SECP256R1 => "secp256r1",
            SslCurve::SECP384R1 => "secp384r1",
            SslCurve::SECP521R1 => "secp521r1",
            SslCurve::FFDHE2048 => "ffdhe2048",
            SslCurve::FFDHE3072 => "ffdhe3072",
        }
    }
}
