use boring::ssl::{ConnectConfiguration, SslConnector, SslMethod, SslOptions};

use crate::alpn::AlpnProtocol;
use crate::compress::register_compressors;
use boring::{error::ErrorStack, ssl::SslVersion};

use crate::{alpn::AlpsProtocol, compress::CompressionKind};

mod chrome;
mod firefox;
mod opera;
mod safari;

#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct TlsOptions {
    pub alpn_protocols: Option<&'static [AlpnProtocol]>,
    pub alps_protocols: Option<&'static [AlpsProtocol]>,
    pub alps_use_new_codepoint: bool,
    pub certificate_compressors: Option<&'static [&'static CompressionKind]>,
    pub cipher_list: Option<&'static str>,
    pub curves_list: Option<&'static str>,
    pub delegated_credentials: Option<&'static str>,
    pub enable_ech_grease: bool,
    pub enable_ocsp_stapling: bool,
    pub enable_signed_cert_timestamps: bool,
    pub grease_enabled: Option<bool>,
    pub max_tls_version: Option<SslVersion>,
    pub min_tls_version: Option<SslVersion>,
    pub permute_extensions: Option<bool>,
    pub pre_shared_key: bool,
    pub psk_dhe_ke: bool,
    pub psk_skip_session_ticket: bool,
    pub record_size_limit: Option<u16>,
    pub renegotiation: bool,
    pub session_ticket: bool,
    pub sigalgs_list: Option<&'static str>,
    pub tls_sni: bool,
    pub verify_hostname: bool,
}

impl Default for TlsOptions {
    fn default() -> Self {
        TlsOptions {
            alpn_protocols: Some(&[AlpnProtocol::HTTP1]),
            alps_protocols: None,
            alps_use_new_codepoint: false,
            certificate_compressors: None,
            cipher_list: None,
            curves_list: None,
            delegated_credentials: None,
            enable_ech_grease: false,
            enable_ocsp_stapling: false,
            enable_signed_cert_timestamps: false,
            grease_enabled: None,
            max_tls_version: None,
            min_tls_version: None,
            permute_extensions: None,
            pre_shared_key: false,
            psk_dhe_ke: true,
            psk_skip_session_ticket: false,
            record_size_limit: None,
            renegotiation: true,
            session_ticket: true,
            sigalgs_list: None,
            tls_sni: true,
            verify_hostname: true,
        }
    }
}

impl TryFrom<&TlsOptions> for ConnectConfiguration {
    type Error = ErrorStack;

    fn try_from(opts: &TlsOptions) -> Result<Self, Self::Error> {
        let mut builder = SslConnector::builder(SslMethod::tls())?;

        // Set maximum TLS version
        builder.set_max_proto_version(opts.max_tls_version)?;

        // Set minimum TLS version
        builder.set_min_proto_version(opts.min_tls_version)?;

        // Set TLS compression
        register_compressors(&mut builder, opts.certificate_compressors)?;

        // Set ciphers
        set_option_ref_try!(opts, cipher_list, builder, set_cipher_list);

        // Set OCSP stapling
        set_bool!(opts, enable_ocsp_stapling, builder, enable_ocsp_stapling);

        // Set Signed Certificate Timestamps (SCT)
        set_bool!(
            opts,
            enable_signed_cert_timestamps,
            builder,
            enable_signed_cert_timestamps
        );

        // Set TLS Session ticket options
        set_bool!(
            opts,
            !session_ticket,
            builder,
            set_options,
            SslOptions::NO_TICKET
        );

        // Set TLS No Renegotiation options
        set_bool!(
            opts,
            !renegotiation,
            builder,
            set_options,
            SslOptions::NO_RENEGOTIATION
        );

        // Set TLS grease options
        set_option!(opts, grease_enabled, builder, set_grease_enabled);

        // Set TLS permute extensions options
        set_option!(opts, permute_extensions, builder, set_permute_extensions);

        // Set TLS curves list
        set_option_ref_try!(opts, curves_list, builder, set_curves_list);

        // Set TLS signature algorithms list
        set_option_ref_try!(opts, sigalgs_list, builder, set_sigalgs_list);

        //              ==================

        // configure client handshake
        let mut cfg: ConnectConfiguration = builder.build().configure()?;

        // Use server name indication
        cfg.set_use_server_name_indication(opts.tls_sni);

        // Verify hostname
        cfg.set_verify_hostname(opts.verify_hostname);

        // Set ECH grease
        cfg.set_enable_ech_grease(opts.enable_ech_grease);

        // Set ALPN protocols
        if let Some(alpn_values) = opts.alpn_protocols {
            let encoded = AlpnProtocol::encode_sequence(alpn_values);
            cfg.set_alpn_protos(&encoded)?;
        }

        Ok(cfg)
    }
}
