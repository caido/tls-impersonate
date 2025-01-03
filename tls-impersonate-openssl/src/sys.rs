use std::ffi::{c_int, c_long};

use openssl_sys::SSL_CTX;

extern "C" {
    pub fn SSL_CTX_enable_ct(ctx: *mut SSL_CTX, validation_mode: c_int) -> c_int;

    pub fn SSL_CTX_set_tlsext_status_type(ctx: *mut SSL_CTX, status_type: c_int) -> c_long;
}

pub const SSL_CT_VALIDATION_STRICT: c_int = 1;
