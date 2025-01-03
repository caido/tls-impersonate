use std::borrow::Cow;

use rustls_pki_types::CertificateDer;

#[derive(Debug, Clone)]
pub struct CertsStore(Cow<'static, [CertificateDer<'static>]>);

impl CertsStore {
    pub fn load() -> Self {
        #[cfg(feature = "webpki-certs")]
        {
            Self(Cow::Borrowed(webpki_root_certs::TLS_SERVER_ROOT_CERTS))
        }
        #[cfg(all(feature = "native-certs", not(feature = "webpki-certs")))]
        {
            Self(Cow::Owned(rustls_native_certs::load_native_certs().certs))
        }
        #[cfg(all(not(feature = "native-certs"), not(feature = "webpki-certs")))]
        {
            Self::empty()
        }
    }

    pub fn empty() -> Self {
        Self(Cow::Borrowed(&[]))
    }

    pub fn add_cert(&mut self, cert: CertificateDer<'static>) {
        match &mut self.0 {
            Cow::Borrowed(certs) => {
                let mut new_certs = certs.to_vec();
                new_certs.push(cert);
                self.0 = Cow::Owned(new_certs);
            }
            Cow::Owned(certs) => certs.push(cert),
        }
    }

    pub fn certs(&self) -> &[CertificateDer<'static>] {
        &self.0
    }
}
