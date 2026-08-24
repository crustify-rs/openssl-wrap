//! Wrappers assigned from `crypto/bio/bio_local.h`.

use core::ptr::NonNull;

use ffibox::CDropped;
use libcrypto_sys as ffi;

ffibox::define_ctype!(
    /// Wraps: bio_st
    ///
    /// An OpenSSL BIO, reached only through owning pointers and borrowed
    /// handles.
    ///
    /// `bio_st` is defined in `crypto/bio/bio_local.h`, which the bindgen
    /// input cannot include: that header rejects any translation unit that
    /// already saw `openssl/bio.h` or `internal/cryptlib.h`, and the public
    /// headers this crate binds do both. `ffi::bio_st` is therefore the
    /// incomplete type the public API publishes, which makes `Bio` an opaque
    /// pointee rather than a layout mirror. It must not be embedded by value
    /// in a `#[repr(C)]` struct, and [`Bio::zeroed`] yields no usable BIO;
    /// only the pointer identity carried by `CBox<Bio>`, [`BioRef`] and
    /// [`BioMut`] is meaningful.
    ///
    /// That matches the wrapped surface. The public API keeps the body
    /// private, so the fields recorded for this type -- `libctx`, `method`,
    /// `ptr`, `init`, `shutdown`, `flags`, `next_bio`, `prev_bio`, `cb_arg`
    /// and the counters -- are reached through the accessor symbols wrapped in
    /// [`bio_lib`](super::bio_lib) (`BIO_get_data`, `BIO_get_init`,
    /// `BIO_get_shutdown`, `BIO_next`, their setters and the `BIO_ctrl`
    /// family) rather than by field projection.
    Bio,
    BioRef,
    BioMut,
    ffi::bio_st
);

// SAFETY: `BIO_free` is `BIO_free_int` applied to a single node. It consumes
// exactly one reference from `references`, and only when that count reaches
// zero does it run the method destructor, free the ex_data and release the
// allocation. It never follows `next_bio`, so one owner per node is the
// correct unit and a link left in `next_bio` is untouched; releasing a whole
// chain is the separate `BIO_free_all` strategy in
// [`bio_lib`](super::bio_lib). `Bio` is `#[repr(transparent)]` over
// `ffi::bio_st`, so C receives the pointer value it handed out.
unsafe impl CDropped for Bio {
    unsafe fn c_drop(obj: NonNull<Self>) {
        // SAFETY: the trait contract transfers one live owned BIO reference;
        // the transparent wrapper preserves the pointer representation.
        unsafe { ffi::BIO_free(obj.as_ptr().cast()) };
    }
}

// `Bio` is reference counted, so it deliberately has **no** `CCloned` impl.
// Registering `BIO_up_ref` there would give `CBox<Bio>` a `Clone` that takes
// only `&self` and yields a second owner of the *same* BIO, whose
// `CBox::as_mut` would then assert an exclusivity the count cannot provide.
// An extra count is acquired through [`BIO_up_ref`](super::bio_lib::BIO_up_ref),
// which hands back a [`crate::refcount::SharedRef`] with no exclusive handle.

#[cfg(test)]
mod tests {
    use core::ptr;

    use ffibox::CBox;

    use super::*;
    use crate::bio::bio_lib::{BIO_get_init, BIO_next};

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
    fn an_extra_count_shares_the_same_object() {
        let bio = new_null_bio();
        let share = crate::bio::bio_lib::BIO_up_ref(&bio.as_ref()).expect("BIO_up_ref");

        assert_eq!(share.as_ptr(), bio.as_ptr());
        // The share grants `as_ref` only, so it cannot become a second
        // exclusive handle to the object `bio` also owns.
        assert_eq!(BIO_get_init(share.as_ref()), 1);
    }

    #[test]
    fn dropping_one_share_leaves_the_original_owner_intact() {
        let bio = new_null_bio();
        {
            let share = crate::bio::bio_lib::BIO_up_ref(&bio.as_ref()).expect("BIO_up_ref");
            assert_eq!(share.as_ptr(), bio.as_ptr());
        }
        // The share released its own count and nothing else: the null method
        // has no `create`, so `BIO_new_ex` set `init` to 1 and it is still 1.
        assert_eq!(BIO_get_init(bio.as_ref()), 1);
    }

    #[test]
    fn an_owner_governs_exactly_one_chain_node() {
        let bio = new_null_bio();

        // `BIO_free` releases this node alone, so a `CBox<Bio>` claims no
        // successor. A freshly constructed BIO has none.
        assert!(BIO_next(&bio.as_ref()).is_none());
    }
}
