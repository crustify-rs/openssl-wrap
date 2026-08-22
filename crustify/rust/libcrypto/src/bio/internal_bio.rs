//! Wrappers assigned from `include/internal/bio.h`.

use ffibox::define_ctype;
use libcrypto_sys as ffi;

define_ctype!(
    /// Wraps: bio_method_st
    BioMethod,
    BioMethodRef,
    BioMethodMut,
    ffi::bio_method_st
);

/// Converts a process-lifetime OpenSSL method table into its borrowed handle.
pub(crate) fn static_bio_method(
    method: *const ffi::bio_method_st,
) -> Option<BioMethodRef<'static>> {
    // SAFETY: callers pass only pointers returned by the `BIO_s_*` family,
    // whose static method tables live for the process lifetime.
    unsafe { BioMethodRef::from_ptr(method.cast_mut()) }
}

// Methods produced by `BIO_meth_new` exclusively own their allocation and
// duplicated name. OpenSSL's static method tables are represented only by
// borrowed handles and therefore never reach this implementation.
ffibox::impl_dropped!(BioMethod, ffi::bio_method_st, ffi::BIO_meth_free);

#[cfg(test)]
mod tests {
    use ffibox::CBox;

    use super::*;

    #[test]
    fn owned_method_produces_shared_and_exclusive_handles() {
        // SAFETY: the name is a live NUL-terminated string for the duration of
        // the call; OpenSSL either returns a fresh method or null.
        let raw = unsafe { ffi::BIO_meth_new(37, c"rust method".as_ptr()) };
        // SAFETY: `BIO_meth_new` returns a fresh, fully initialized allocation
        // whose ownership is transferred to the matching `BIO_meth_free` owner.
        let mut method =
            unsafe { CBox::<BioMethod>::from_raw(raw) }.expect("BIO_meth_new allocation");

        let shared = method.as_ref();
        assert_eq!(shared.as_ptr(), raw.cast_const());

        let mut exclusive = method.as_mut();
        assert_eq!(exclusive.as_mut_ptr(), raw);
        assert_eq!(exclusive.as_ref().as_ptr(), raw.cast_const());
    }
}
