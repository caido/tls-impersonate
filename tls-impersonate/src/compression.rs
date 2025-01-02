/// Certificate compression algorithm.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum CertCompressionAlgorithm {
    Brotli,
    Zlib,
    Zstd,
}
