#![allow(non_snake_case)]

use std::{
    ffi::{c_int, c_long, c_void},
    ptr,
};

pub use openssl_sys::*;

extern "C" {
    pub fn SSL_CTX_enable_ct(ctx: *mut SSL_CTX, validation_mode: c_int) -> c_int;

    pub fn X509_STORE_up_ref(xs: *mut X509_STORE) -> c_int;
}

pub unsafe fn SSL_CTX_set1_verify_cert_store(ctx: *mut SSL_CTX, st: *mut X509_STORE) -> c_long {
    SSL_CTX_ctrl(ctx, SSL_CTRL_SET_VERIFY_CERT_STORE, 1, st as *mut c_void)
}

pub unsafe fn SSL_CTX_set_tlsext_status_type(ctx: *mut SSL_CTX, r#type: c_int) -> c_long {
    SSL_CTX_ctrl(
        ctx,
        SSL_CTRL_SET_TLSEXT_STATUS_REQ_TYPE,
        r#type as c_long,
        ptr::null_mut(),
    )
}

pub const SSL_CT_VALIDATION_PERMISSIVE: c_int = 0;
