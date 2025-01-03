use std::ffi::c_int;

use openssl::{error::ErrorStack, ssl::SslContextBuilder};

use crate::sys as ffi;

#[inline]
fn cvt(r: c_int) -> Result<c_int, ErrorStack> {
    if r <= 0 {
        Err(ErrorStack::get())
    } else {
        Ok(r)
    }
}

pub trait SslContextBuilderExt {
    fn enable_signed_cert_timestamps(&self) -> Result<(), ErrorStack>;
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
}
