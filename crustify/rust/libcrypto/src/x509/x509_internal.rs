//! Wrappers assigned from `include/crypto/x509.h`.

use ffibox::{define_ctype, impl_cloned, impl_dropped};
use libcrypto_sys as ffi;

define_ctype!(
    /// Wraps: X509_name_st
    ///
    /// Pointer-compatible target for OpenSSL's distinguished-name object.
    /// Although the complete C layout lives in the private `crypto/x509.h`,
    /// the public API exposes `X509_NAME` only as an opaque handle. Its entry
    /// stack and cached encodings therefore remain behind OpenSSL's call
    /// surface rather than becoming Rust field accessors.
    ///
    /// An owning [`ffibox::CBox<X509Name>`] contains one complete name and
    /// releases its owned entries and encodings. Cloning performs the public
    /// ASN.1 deep duplication and creates an independent allocation.
    X509Name,
    X509NameRef,
    X509NameMut,
    ffi::X509_name_st
);

// `X509_NAME_free` is the public full destructor. It pop-frees the owned name
// entries, frees both encoding caches and then releases the name allocation.
impl_dropped!(X509Name, ffi::X509_name_st, ffi::X509_NAME_free);

// X509_NAME has no reference count. Its public duplication routine encodes
// and decodes the value into a fresh object, so each clone owes a full free.
impl_cloned!(X509Name, ffi::X509_name_st, dup = ffi::X509_NAME_dup);

#[cfg(test)]
mod tests {
    use ffibox::CBox;

    use super::*;

    #[test]
    fn opaque_name_owner_borrows_and_deep_clones() {
        // SAFETY: OpenSSL returns null or a fresh, fully initialized empty
        // name with one `X509_NAME_free` ownership obligation.
        let raw = unsafe { ffi::X509_NAME_new() };
        // SAFETY: ownership of the fresh result transfers once to the owner
        // whose registered destructor is `X509_NAME_free`.
        let mut name = unsafe { CBox::<X509Name>::from_raw(raw) }.expect("X509_NAME_new");

        assert_eq!(name.as_ref().as_ptr(), raw.cast_const());
        assert_eq!(name.as_mut().as_mut_ptr(), raw);

        let duplicate = name.try_clone().expect("X509_NAME_dup");
        assert_ne!(duplicate.as_ptr(), raw);
    }

    #[test]
    fn opaque_name_handles_and_owner_are_pointer_sized() {
        assert_eq!(
            core::mem::size_of::<X509NameRef<'static>>(),
            core::mem::size_of::<*const ffi::X509_name_st>()
        );
        assert_eq!(
            core::mem::size_of::<X509NameMut<'static>>(),
            core::mem::size_of::<*mut ffi::X509_name_st>()
        );
        assert_eq!(
            core::mem::size_of::<CBox<X509Name>>(),
            core::mem::size_of::<*mut ffi::X509_name_st>()
        );
    }
}
