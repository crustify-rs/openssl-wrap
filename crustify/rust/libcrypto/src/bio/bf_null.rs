//! Wrappers assigned from `crypto/bio/bf_null.c`.

use libcrypto_sys as ffi;

use super::internal_bio::BioMethodRef;

/// Wraps: BIO_f_null
#[allow(non_snake_case)]
pub fn BIO_f_null() -> BioMethodRef<'static> {
    // SAFETY: OpenSSL returns a non-null process-lifetime static method table.
    let raw = unsafe { ffi::BIO_f_null() };
    // SAFETY: the returned method table is immutable and has process lifetime.
    unsafe { BioMethodRef::from_ptr(raw.cast_mut()) }.expect("BIO_f_null returned null")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn method_table_is_static() {
        assert!(!BIO_f_null().as_ptr().is_null());
    }
}
