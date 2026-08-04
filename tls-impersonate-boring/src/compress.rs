use std::io::Write;

use boring::{
    error::ErrorStack,
    ssl::{CertificateCompressionAlgorithm, CertificateCompressor, SslConnectorBuilder},
};

pub fn register_compressors(
    builder: &mut SslConnectorBuilder,
    compression: Option<&'static [&'static CompressionKind]>,
) -> Result<(), ErrorStack> {
    let Some(algos) = compression else {
        return Ok(());
    };
    for alg in algos {
        match alg {
            CompressionKind::Brotli => {
                builder.add_certificate_compression_algorithm(BrotliCompressor::default())
            }
            CompressionKind::Zlib => builder.add_certificate_compression_algorithm(ZlibCompressor),
            CompressionKind::Zstd => builder.add_certificate_compression_algorithm(ZstdCompressor),
        }?
    }
    Ok(())
}

#[derive(Debug)]
pub enum CompressionKind {
    Brotli,
    Zlib,
    Zstd,
}

struct BrotliCompressor {
    q: u32,
    lgwin: u32,
}

impl Default for BrotliCompressor {
    fn default() -> Self {
        Self { q: 11, lgwin: 32 }
    }
}

impl CertificateCompressor for BrotliCompressor {
    const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm::BROTLI;
    const CAN_COMPRESS: bool = true;
    const CAN_DECOMPRESS: bool = true;

    fn compress<W>(&self, input: &[u8], output: &mut W) -> std::io::Result<()>
    where
        W: std::io::Write,
    {
        let mut writer = brotli::CompressorWriter::new(output, 1024, self.q, self.lgwin);
        writer.write_all(input)?;
        Ok(())
    }

    fn decompress<W>(&self, input: &[u8], output: &mut W) -> std::io::Result<()>
    where
        W: std::io::Write,
    {
        brotli::BrotliDecompress(&mut std::io::Cursor::new(input), output)?;
        Ok(())
    }
}

#[derive(Clone, Copy, Default)]
struct ZlibCompressor;

impl CertificateCompressor for ZlibCompressor {
    const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm::ZLIB;
    const CAN_COMPRESS: bool = true;
    const CAN_DECOMPRESS: bool = true;

    fn compress<W>(&self, input: &[u8], output: &mut W) -> std::io::Result<()>
    where
        W: std::io::Write,
    {
        let mut z = flate2::write::ZlibEncoder::new(output, flate2::Compression::default());
        z.write_all(input)?;
        z.finish()?;
        Ok(())
    }

    fn decompress<W>(&self, input: &[u8], output: &mut W) -> std::io::Result<()>
    where
        W: std::io::Write,
    {
        let mut decoder = flate2::read::ZlibDecoder::new(std::io::Cursor::new(input));
        std::io::copy(&mut decoder, output)?;
        Ok(())
    }
}

const ZSTD_ALGO: CertificateCompressionAlgorithm =
    unsafe { std::mem::transmute::<u16, CertificateCompressionAlgorithm>(3) };

struct ZstdCompressor;

impl CertificateCompressor for ZstdCompressor {
    const ALGORITHM: CertificateCompressionAlgorithm = ZSTD_ALGO;

    const CAN_COMPRESS: bool = true;

    const CAN_DECOMPRESS: bool = true;

    fn compress<W>(&self, input: &[u8], output: &mut W) -> std::io::Result<()>
    where
        W: Write,
    {
        let mut encoder = zstd::stream::Encoder::new(output, 3)?;
        encoder.write_all(input)?;
        encoder.finish()?;
        Ok(())
    }

    fn decompress<W>(&self, input: &[u8], output: &mut W) -> std::io::Result<()>
    where
        W: Write,
    {
        let mut decoder = zstd::stream::Decoder::new(input)?;
        std::io::copy(&mut decoder, output)?;
        Ok(())
    }
}
