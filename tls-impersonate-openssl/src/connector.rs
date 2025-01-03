use openssl::{
    error::ErrorStack,
    ssl::{ConnectConfiguration, SslConnector, SslMethod, SslOptions, SslVerifyMode, SslVersion},
};
use tls_impersonate::TlsVersion;

use crate::{OpensslSettings, SslContextBuilderExt};

type Result<T> = std::result::Result<T, ErrorStack>;

pub struct OpensslConnector {
    tls_sni: bool,
    inner: SslConnector,
}

impl OpensslConnector {
    pub fn new(settings: &OpensslSettings) -> Result<Self> {
        let mut builder = SslConnector::builder(SslMethod::tls_client()).unwrap();

        // Set the verification mode
        if settings.certs_verification {
            builder.set_verify(SslVerifyMode::PEER);
        } else {
            builder.set_verify(SslVerifyMode::NONE);
        }

        // Set the ALPN protocols
        builder.set_alpn_protos(&settings.alpn_protos)?;

        // Set no session ticket if it is set.
        if let Some(false) = settings.session_ticket {
            builder.set_options(SslOptions::NO_TICKET);
        }

        // Set the minimum and maximum TLS version
        if let Some(version) = settings.min_tls_version.as_ref() {
            builder.set_min_proto_version(Some(ssl_version(version)))?;
        }

        if let Some(version) = settings.max_tls_version.as_ref() {
            builder.set_max_proto_version(Some(ssl_version(version)))?;
        }

        // Set the supported signature algorithms
        if let Some(sigalgs) = settings.signature_algorithms.as_ref() {
            builder.set_sigalgs_list(sigalgs)?;
        }

        // Set the cipher list if it is set.
        if let Some(ciphers) = settings.ciphers.as_ref() {
            builder.set_cipher_list(ciphers)?;
        }

        // Enable signed cert timestamps if it is set.
        if settings.enable_signed_cert_timestamps {
            builder.enable_signed_cert_timestamps()?;
        }

        // Set the encrypt then mac option
        if let Some(false) = settings.encrypt_then_mac {
            builder.set_options(SSL_OP_NO_ENCRYPT_THEN_MAC);
        }

        // Set the padding option
        if let Some(false) = settings.padding {
            builder.clear_options(SSL_OP_TLSEXT_PADDING);
        }

        Ok(Self {
            tls_sni: settings.tls_sni,
            inner: builder.build(),
        })
    }

    pub fn configure(&self) -> Result<ConnectConfiguration> {
        let mut config = self.inner.configure()?;

        config.set_use_server_name_indication(self.tls_sni);

        Ok(config)
    }
}

const SSL_OP_NO_ENCRYPT_THEN_MAC: SslOptions = SslOptions::from_bits_retain(0x00080000);
const SSL_OP_TLSEXT_PADDING: SslOptions = SslOptions::from_bits_retain(0x00000010);

fn ssl_version(version: &TlsVersion) -> SslVersion {
    match version {
        TlsVersion::TLS1_0 => SslVersion::TLS1,
        TlsVersion::TLS1_1 => SslVersion::TLS1_1,
        TlsVersion::TLS1_2 => SslVersion::TLS1_2,
        TlsVersion::TLS1_3 => SslVersion::TLS1_3,
    }
}
