use openssl::{error::ErrorStack, ssl::SslContextBuilder};

use crate::utils::{cvt, cvt_long};
use crate::{sys as ffi, OpensslCertsStore};
pub trait SslContextBuilderExt {
    fn enable_signed_cert_timestamps(&mut self) -> Result<(), ErrorStack>;

    fn enable_ocsp_stapling(&mut self) -> Result<(), ErrorStack>;

    fn configure_certs_store(&mut self, store: &OpensslCertsStore) -> Result<(), ErrorStack>;
}

impl SslContextBuilderExt for SslContextBuilder {
    fn enable_signed_cert_timestamps(&mut self) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::SSL_CTX_enable_ct(
                self.as_ptr(),
                ffi::SSL_CT_VALIDATION_PERMISSIVE,
            ))
            .map(|_| ())
        }
    }

    fn enable_ocsp_stapling(&mut self) -> Result<(), ErrorStack> {
        unsafe {
            cvt_long(ffi::SSL_CTX_set_tlsext_status_type(
                self.as_ptr(),
                ffi::TLSEXT_STATUSTYPE_ocsp,
            ))
            .map(|_| ())
        }
    }

    fn configure_certs_store(&mut self, store: &OpensslCertsStore) -> Result<(), ErrorStack> {
        unsafe {
            cvt_long(ffi::SSL_CTX_set1_verify_cert_store(
                self.as_ptr(),
                store.as_ptr(),
            ))
            .map(|_| ())
        }
    }
}
