//! Wrappers assigned from `crypto/bio/bf_nbio.c`.

use libcrypto_sys as ffi;

use super::internal_bio::BioMethodRef;

/// Wraps: BIO_f_nbio_test
#[allow(non_snake_case)]
pub fn BIO_f_nbio_test() -> BioMethodRef<'static> {
    // SAFETY: OpenSSL returns a non-null process-lifetime static method table.
    let raw = unsafe { ffi::BIO_f_nbio_test() };
    // SAFETY: the returned method table is immutable and has process lifetime.
    unsafe { BioMethodRef::from_ptr(raw.cast_mut()) }.expect("BIO_f_nbio_test returned null")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn method_table_is_static() {
        assert!(!BIO_f_nbio_test().as_ptr().is_null());
    }
}
