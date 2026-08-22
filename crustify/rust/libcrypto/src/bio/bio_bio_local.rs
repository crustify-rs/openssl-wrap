//! Wrappers assigned from `crypto/bio/bio_local.h`.

use core::ptr::NonNull;

use ffibox::{CCloned, CDropped};
use libcrypto_sys as ffi;

ffibox::define_ctype!(
    /// Wraps: bio_st
    /// A layout-compatible OpenSSL BIO object.
    Bio,
    BioRef,
    BioMut,
    ffi::bio_st
);

// SAFETY: `BIO_free` consumes exactly one reference to a fully constructed
// BIO. `Bio` is transparent over the corresponding bindgen C type.
unsafe impl CDropped for Bio {
    unsafe fn c_drop(obj: NonNull<Self>) {
        // SAFETY: the trait contract transfers one live owned BIO reference;
        // the transparent wrapper preserves the pointer representation.
        unsafe { ffi::BIO_free(obj.as_ptr().cast()) };
    }
}

// SAFETY: a successful `BIO_up_ref` leaves the original BIO live and creates
// one additional reference settled by `CDropped`. Failure is propagated.
unsafe impl CCloned for Bio {
    unsafe fn c_clone(obj: NonNull<Self>) -> Option<NonNull<Self>> {
        // SAFETY: the trait contract supplies a live BIO and the transparent
        // wrapper preserves the pointer representation expected by OpenSSL.
        (unsafe { ffi::BIO_up_ref(obj.as_ptr().cast()) } != 0).then_some(obj)
    }
}

#[cfg(test)]
mod tests {
    use core::ptr;

    use ffibox::CBox;

    use super::*;

    fn new_null_bio() -> CBox<Bio> {
        let method = crate::bio::bss_null::BIO_s_null().expect("null method");
        // SAFETY: the safe selector returned a process-lifetime descriptor;
        // `BIO_new` returns a fresh, fully constructed BIO or null.
        let raw = unsafe { ffi::BIO_new(method.as_ptr()) };
        // SAFETY: ownership of the returned BIO reference transfers to the
        // matching `BIO_free` owner.
        unsafe { CBox::from_raw(raw) }.expect("BIO_new")
    }

    #[test]
    fn owner_produces_lifetime_bound_handles() {
        let mut bio = new_null_bio();
        let raw = bio.as_ptr();

        let shared = bio.as_ref();
        assert!(ptr::eq(shared.as_ptr(), raw.cast_const()));

        let mut exclusive = bio.as_mut();
        assert!(ptr::eq(exclusive.as_ref().as_ptr(), raw.cast_const()));
        assert_eq!(exclusive.as_mut_ptr(), raw);
    }

    #[test]
    fn clone_owns_an_independent_reference_count() {
        let bio = new_null_bio();
        let clone = bio.try_clone().expect("BIO_up_ref");

        assert_eq!(bio.as_ptr(), clone.as_ptr());
        drop(bio);

        let second_clone = clone.try_clone().expect("BIO remains live");
        assert_eq!(clone.as_ptr(), second_clone.as_ptr());
    }
}
