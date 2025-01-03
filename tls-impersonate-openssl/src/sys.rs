use std::ffi::c_int;

pub use openssl_sys::*;

extern "C" {
    pub fn SSL_CTX_enable_ct(ctx: *mut SSL_CTX, validation_mode: c_int) -> c_int;
}

pub const SSL_CT_VALIDATION_STRICT: c_int = 1;
