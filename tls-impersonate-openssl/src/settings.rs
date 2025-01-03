use std::borrow::Cow;

use tls_impersonate::{
    AlpnProtocol, CipherSuite, SignatureAlgorithm, SslCurve, TlsSettings, TlsVersion,
};
use typed_builder::TypedBuilder;

#[derive(TypedBuilder, Default, Clone, Debug)]
pub struct OpensslSettings {
    /// Root certificates store.
    // #[builder(default)]
    // pub root_certs_store: RootCertsStore,

    /// Verify certificates.
    #[builder(default = true)]
    pub certs_verification: bool,

    /// Enable TLS SNI
    ///
    /// SNI is the Server Name Indication extension, which allows the client to specify
    /// the hostname of the server it is connecting to. This is used to allow multiple
    /// domains to be served on the same IP address.
    #[builder(default = true)]
    pub tls_sni: bool,

    /// The HTTP version preference (setting alpn).
    ///
    /// ALPN (Application-Layer Protocol Negotiation) is a TLS extension that allows the client
    /// and server to negotiate which application layer protocol they will use during the TLS handshake,
    /// before the connection is fully established.
    #[builder(
        default = Cow::Owned(AlpnProtocol::serialize(&[AlpnProtocol::Http2, AlpnProtocol::Http1])),
        setter(transform = |input: &[AlpnProtocol]| Cow::Owned(AlpnProtocol::serialize(input)))
    )]
    pub alpn_protos: Cow<'static, [u8]>,

    /// No session ticket
    ///
    /// Session ticket is a way to resume a TLS session without having to perform a full handshake.
    /// This is enabled by default.
    #[builder(default, setter(into))]
    pub session_ticket: Option<bool>,

    /// The minimum TLS version to use.
    #[builder(default, setter(into))]
    pub min_tls_version: Option<TlsVersion>,

    /// The maximum TLS version to use.
    #[builder(default, setter(into))]
    pub max_tls_version: Option<TlsVersion>,

    /// Enable OCSP stapling.
    ///
    /// Online Certificate Status Protocol (OCSP) stapling allows the server to include ("staple") its OCSP response
    /// during the TLS handshake, eliminating the need for clients to separately contact the OCSP responder to verify
    /// the server's certificate status, improving performance and privacy.
    #[builder(default = false)]
    pub enable_ocsp_stapling: bool,

    /// The curves to use.
    ///
    /// Specifies which elliptic curves the client supports for key exchange during TLS handshake.
    #[builder(default, setter(into))]
    pub curves: Option<Cow<'static, [SslCurve]>>,

    /// The signature algorithms to use.
    ///
    /// These algorithms are used for digital signatures in various parts of the TLS protocol,
    /// particularly for certificate verification and authentication.
    #[builder(default, setter(transform = |input: &[SignatureAlgorithm]| Some(Cow::Owned(SignatureAlgorithm::serialize(input)))))]
    pub signature_algorithms: Option<Cow<'static, str>>,

    /// The ciphers to use.
    ///
    /// A list of cipher suites that can be used for the TLS connection, specified in OpenSSL format.
    /// These determine the algorithms used for key exchange, authentication, encryption and message integrity.
    #[builder(default, setter(transform = |input: &[CipherSuite]| Some(Cow::Owned(CipherSuite::serialize(input)))))]
    pub ciphers: Option<Cow<'static, str>>,

    /// Enable signed cert timestamps (SCT).
    ///
    /// SCTs provide proof that certificates are publicly logged in Certificate Transparency logs,
    /// helping detect misissued certificates and improving TLS security.
    #[builder(default = false)]
    pub enable_signed_cert_timestamps: bool,

    /// The key shares length limit.
    #[builder(default, setter(into))]
    pub key_shares_length_limit: Option<u8>,

    /// Encrypt then MAC
    ///
    /// A TLS extension that changes the order of operations to apply MAC after encryption, rather than before.
    /// This provides better security against padding oracle attacks in CBC mode ciphersuites by ensuring the MAC
    /// covers the entire encrypted content.
    #[builder(default, setter(into))]
    pub encrypt_then_mac: Option<bool>,

    /// Enable padding.
    ///
    /// Padding is a technique used to ensure the length of a message is a multiple of the block size of the cipher.
    /// This is used to prevent certain attacks, such as padding oracle attacks.
    #[builder(default, setter(transform = |input: bool| Some(input)))]
    pub padding: Option<bool>,
}

impl From<TlsSettings> for OpensslSettings {
    fn from(settings: TlsSettings) -> Self {
        Self {
            certs_verification: settings.certs_verification,
            tls_sni: settings.tls_sni,
            alpn_protos: settings.alpn_protos,
            session_ticket: settings.session_ticket,
            min_tls_version: settings.min_tls_version,
            max_tls_version: settings.max_tls_version,
            enable_ocsp_stapling: settings.enable_ocsp_stapling,
            curves: settings.curves,
            signature_algorithms: settings.signature_algorithms,
            ciphers: settings.ciphers,
            enable_signed_cert_timestamps: settings.enable_signed_cert_timestamps,
            key_shares_length_limit: settings.key_shares_length_limit,
            encrypt_then_mac: settings.encrypt_then_mac,
            padding: settings.padding,
        }
    }
}
