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

/// Adopts a process-lifetime OpenSSL method table as a borrowed handle.
///
/// The `BIO_s_*` and `BIO_f_*` selectors return a pointer to a `static const
/// BIO_METHOD` — or null where the method is compiled out, as `BIO_s_log` is
/// without syslog. That storage is what justifies the `'static` borrow, so the
/// obligation is on the caller and cannot be checked here.
///
/// # Safety
///
/// `method` must be null, or address a `bio_method_st` that stays live and
/// unmodified for the remainder of the process.
///
/// A `BIO_meth_new` allocation does not qualify: `BIO_meth_free` releases it
/// and the `BIO_meth_set_*` family mutates it, so borrow that table from its
/// [`CBox<BioMethod>`](ffibox::CBox) owner instead.
pub(crate) unsafe fn static_bio_method(
    method: *const ffi::bio_method_st,
) -> Option<BioMethodRef<'static>> {
    // SAFETY: the caller guarantees `method` is null or a table that outlives
    // the process, which outlives the `'static` borrow produced here. A shared
    // handle exposes no write path, so the `*const` to `*mut` cast is never
    // written through.
    unsafe { BioMethodRef::from_ptr(method.cast_mut()) }
}

// `BIO_meth_new` allocates the method table and owns the name it duplicates;
// `BIO_meth_free` releases both, so a sole-owner `CBox` is the whole contract.
// There is no `BIO_meth_dup` and no reference count, hence no `CCloned`.
// OpenSSL's static tables are reached only through `static_bio_method`, which
// hands out borrowed handles, so they never reach this implementation.
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

    #[test]
    fn static_tables_borrow_without_taking_ownership() {
        // SAFETY: `BIO_s_mem` has no caller-side obligations and returns the
        // address of a process-lifetime static method table.
        let raw = unsafe { ffi::BIO_s_mem() };
        // SAFETY: that table is `static const`, so it satisfies the
        // process-lifetime contract of `static_bio_method`.
        let method = unsafe { static_bio_method(raw) }.expect("BIO_s_mem table");
        assert_eq!(method.as_ptr(), raw);

        // The handle is `Copy` and reborrowing it never consumes the table.
        let again = method;
        assert_eq!(again.as_ptr(), method.as_ptr());

        // SAFETY: the same selector still returns the same static table.
        let repeat = unsafe { static_bio_method(ffi::BIO_s_mem()) }.expect("BIO_s_mem table");
        assert_eq!(repeat.as_ptr(), raw);
    }

    #[test]
    fn absent_static_table_is_none() {
        // SAFETY: a null pointer is explicitly admitted by the contract and
        // models a selector for a method compiled out of this build.
        assert!(unsafe { static_bio_method(core::ptr::null()) }.is_none());
    }

    #[test]
    fn owned_and_static_tables_are_distinct_objects() {
        // SAFETY: as in `owned_method_produces_shared_and_exclusive_handles`.
        let raw = unsafe { ffi::BIO_meth_new(38, c"rust method".as_ptr()) };
        // SAFETY: ownership of the fresh allocation moves into the owner.
        let owned = unsafe { CBox::<BioMethod>::from_raw(raw) }.expect("BIO_meth_new allocation");
        // SAFETY: `BIO_s_mem`'s table is `static const`.
        let borrowed = unsafe { static_bio_method(ffi::BIO_s_mem()) }.expect("BIO_s_mem table");

        assert_ne!(owned.as_ref().as_ptr(), borrowed.as_ptr());
        // Dropping the owner runs `BIO_meth_free` on the allocation only; the
        // static table is untouched and still readable afterwards.
        drop(owned);
        // SAFETY: the selector still has no caller-side obligations and hands
        // back the same static table it returned above.
        let after = unsafe { ffi::BIO_s_mem() };
        assert_eq!(borrowed.as_ptr(), after);
    }
}
