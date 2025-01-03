use std::ffi::{c_int, c_long};

use openssl::error::ErrorStack;

#[inline]
pub fn cvt(r: c_int) -> Result<c_int, ErrorStack> {
    if r <= 0 {
        Err(ErrorStack::get())
    } else {
        Ok(r)
    }
}

#[inline]
pub fn cvt_long(r: c_long) -> Result<c_long, ErrorStack> {
    if r <= 0 {
        Err(ErrorStack::get())
    } else {
        Ok(r)
    }
}
