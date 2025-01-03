use std::ffi::{c_int, c_long};

use openssl::{error::ErrorStack, ssl::SslContextBuilder};
use openssl_sys::TLSEXT_STATUSTYPE_ocsp;

use crate::sys as ffi;

#[inline]
fn cvt(r: c_int) -> Result<c_int, ErrorStack> {
    if r <= 0 {
        Err(ErrorStack::get())
    } else {
        Ok(r)
    }
}

#[inline]
fn cvt_long(r: c_long) -> Result<c_long, ErrorStack> {
    if r <= 0 {
        Err(ErrorStack::get())
    } else {
        Ok(r)
    }
}

pub trait SslContextBuilderExt {
    fn enable_signed_cert_timestamps(&self) -> Result<(), ErrorStack>;

    fn enable_ocsp_stapling(&self) -> Result<(), ErrorStack>;
}

impl SslContextBuilderExt for SslContextBuilder {
    fn enable_signed_cert_timestamps(&self) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::SSL_CTX_enable_ct(
                self.as_ptr(),
                ffi::SSL_CT_VALIDATION_STRICT,
            ))
            .map(|_| ())
        }
    }

    fn enable_ocsp_stapling(&self) -> Result<(), ErrorStack> {
        unsafe {
            cvt_long(ffi::SSL_CTX_set_tlsext_status_type(
                self.as_ptr(),
                TLSEXT_STATUSTYPE_ocsp,
            ))
            .map(|_| ())
        }
    }
}
