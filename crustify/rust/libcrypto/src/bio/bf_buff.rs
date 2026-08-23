//! Wrappers assigned from `crypto/bio/bf_buff.c`.

use libcrypto_sys as ffi;

use super::internal_bio::BioMethodRef;

/// Wraps: BIO_f_buffer
#[allow(non_snake_case)]
pub fn BIO_f_buffer() -> BioMethodRef<'static> {
    // SAFETY: OpenSSL returns a non-null process-lifetime static method table.
    let raw = unsafe { ffi::BIO_f_buffer() };
    // SAFETY: the returned method table is immutable and has process lifetime.
    unsafe { BioMethodRef::from_ptr(raw.cast_mut()) }.expect("BIO_f_buffer returned null")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bio::bio_lib::{BIO_method_name, BIO_new};

    #[test]
    fn the_selector_names_this_file_s_filter_method() {
        // A non-null table is not enough: the selector has to hand back this
        // filter's table and not a neighbouring one.
        assert!(!BIO_f_buffer().as_ptr().is_null());
        let bio = BIO_new(BIO_f_buffer()).expect("filter BIO");
        assert_eq!(BIO_method_name(bio.as_ref()), c"buffer");
    }
}
