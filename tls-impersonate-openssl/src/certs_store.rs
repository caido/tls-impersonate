use std::fmt;

use foreign_types::ForeignType;
use openssl::error::ErrorStack;
use openssl::x509::{
    store::{X509Store, X509StoreBuilder},
    X509,
};
use tls_impersonate::CertsStore;

use crate::sys as ffi;
use crate::utils::cvt;

/// Openssl native certs store.
pub struct OpensslCertsStore(X509Store);

impl OpensslCertsStore {
    pub fn new(store: CertsStore) -> Result<Self, ErrorStack> {
        let mut cert_store = X509StoreBuilder::new()?;

        for cert in store.certs() {
            let cert = X509::from_der(cert)?;
            cert_store.add_cert(cert)?;
        }

        Ok(Self(cert_store.build()))
    }

    pub fn try_clone(&self) -> Result<Self, ErrorStack> {
        unsafe {
            let ptr = self.0.as_ptr();
            cvt(ffi::X509_STORE_up_ref(ptr)).map(|_| ())?;
            Ok(Self(X509Store::from_ptr(ptr)))
        }
    }

    pub fn as_ptr(&self) -> *mut ffi::X509_STORE {
        self.0.as_ptr()
    }
}

impl fmt::Debug for OpensslCertsStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpensslCertStore").finish()
    }
}
