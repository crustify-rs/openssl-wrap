//! Wrappers assigned from `crypto/evp/names.c`.

#![allow(non_snake_case)]

use core::ffi::{CStr, c_void};
use std::any::Any;
use std::boxed::Box;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};

use libcrypto_sys as ffi;

use crate::evp::evp::{EvpCipherRef, EvpMdRef, EvpMdRef as DigestRef};

fn do_all<F>(sorted: bool, callback: &mut F)
where
    F: for<'a> FnMut(Option<DigestRef<'a>>, &'a CStr, Option<&'a CStr>),
{
    unsafe extern "C" fn trampoline<F>(
        digest: *const ffi::evp_md_st,
        from: *const core::ffi::c_char,
        to: *const core::ffi::c_char,
        state: *mut c_void,
    ) where
        F: for<'a> FnMut(Option<EvpMdRef<'a>>, &'a CStr, Option<&'a CStr>),
    {
        if from.is_null() {
            return;
        }
        // SAFETY: OpenSSL supplies a live digest for a method entry or null for
        // an alias, and retains it throughout this synchronous invocation.
        let digest = unsafe { EvpMdRef::from_ptr(digest.cast_mut()) };
        // SAFETY: `from` is non-null and both strings are published as
        // NUL-terminated for the duration of the callback.
        let from = unsafe { CStr::from_ptr(from) };
        let to = (!to.is_null()).then(|| {
            // SAFETY: established by the callback contract above.
            unsafe { CStr::from_ptr(to) }
        });
        // SAFETY: `do_all` passes the unique live closure and OpenSSL neither
        // retains nor concurrently invokes this callback state.
        let callback = unsafe { &mut *state.cast::<F>() };
        callback(digest, from, to);
    }

    let state = core::ptr::from_mut(callback).cast();
    // SAFETY: the trampoline and unique closure state remain live throughout
    // the synchronous enumeration.
    unsafe {
        if sorted {
            ffi::EVP_MD_do_all_sorted(Some(trampoline::<F>), state);
        } else {
            ffi::EVP_MD_do_all(Some(trampoline::<F>), state);
        }
    }
}

/// Wraps: EVP_MD_do_all
#[allow(non_snake_case)]
pub fn EVP_MD_do_all<F>(callback: &mut F)
where
    F: for<'a> FnMut(Option<EvpMdRef<'a>>, &'a CStr, Option<&'a CStr>),
{
    do_all(false, callback);
}

/// Wraps: EVP_MD_do_all_sorted
#[allow(non_snake_case)]
pub fn EVP_MD_do_all_sorted<F>(callback: &mut F)
where
    F: for<'a> FnMut(Option<EvpMdRef<'a>>, &'a CStr, Option<&'a CStr>),
{
    do_all(true, callback);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synchronous_enumerators_hide_callback_state() {
        let mut count = 0usize;
        EVP_MD_do_all(&mut |_, from, _| {
            assert!(!from.to_bytes().is_empty());
            count += 1;
        });
        assert!(count > 0);

        let mut sorted_count = 0usize;
        EVP_MD_do_all_sorted(&mut |_, _, _| sorted_count += 1);
        assert_eq!(sorted_count, count);
    }
}

/// Trampoline state for the cipher enumerators.
///
/// `EVP_CIPHER_do_all[_sorted]` walk the legacy name table while holding its
/// lock, so a panic escaping the closure must not unwind through OpenSSL. It
/// is captured here, the remaining entries are skipped, and the panic resumes
/// once C has returned — the same discipline the other cipher enumerators in
/// this crate use.
struct CipherNames<'a, F> {
    callback: &'a mut F,
    panic: Option<Box<dyn Any + Send>>,
}

fn do_all_cipher<F>(sorted: bool, callback: &mut F)
where
    F: for<'a> FnMut(Option<EvpCipherRef<'a>>, &'a CStr, Option<&'a CStr>),
{
    unsafe extern "C" fn trampoline<F>(
        cipher: *const ffi::evp_cipher_st,
        from: *const core::ffi::c_char,
        to: *const core::ffi::c_char,
        state: *mut c_void,
    ) where
        F: for<'a> FnMut(Option<EvpCipherRef<'a>>, &'a CStr, Option<&'a CStr>),
    {
        // SAFETY: the outer wrapper supplies this exact uniquely borrowed
        // state, and C neither retains nor concurrently invokes it.
        let state = unsafe { &mut *state.cast::<CipherNames<'_, F>>() };
        if state.panic.is_some() || from.is_null() {
            return;
        }
        // SAFETY: OpenSSL supplies a live cipher for a method entry or null for
        // an alias, and retains it for this synchronous invocation.
        let cipher = unsafe { EvpCipherRef::from_ptr(cipher.cast_mut()) };
        // SAFETY: `from` is non-null and both names are NUL-terminated for the
        // duration of this callback.
        let from = unsafe { CStr::from_ptr(from) };
        let to = (!to.is_null()).then(|| {
            // SAFETY: established by the callback contract above.
            unsafe { CStr::from_ptr(to) }
        });
        if let Err(panic) = catch_unwind(AssertUnwindSafe(|| (state.callback)(cipher, from, to))) {
            state.panic = Some(panic);
        }
    }

    let mut state = CipherNames {
        callback,
        panic: None,
    };
    let state_ptr = core::ptr::from_mut(&mut state).cast();
    // SAFETY: callback code and state remain live for synchronous enumeration.
    unsafe {
        if sorted {
            ffi::EVP_CIPHER_do_all_sorted(Some(trampoline::<F>), state_ptr);
        } else {
            ffi::EVP_CIPHER_do_all(Some(trampoline::<F>), state_ptr);
        }
    }
    if let Some(panic) = state.panic {
        resume_unwind(panic);
    }
}

/// Wraps: EVP_CIPHER_do_all
pub fn EVP_CIPHER_do_all<F>(callback: &mut F)
where
    F: for<'a> FnMut(Option<EvpCipherRef<'a>>, &'a CStr, Option<&'a CStr>),
{
    do_all_cipher(false, callback);
}

/// Wraps: EVP_CIPHER_do_all_sorted
pub fn EVP_CIPHER_do_all_sorted<F>(callback: &mut F)
where
    F: for<'a> FnMut(Option<EvpCipherRef<'a>>, &'a CStr, Option<&'a CStr>),
{
    do_all_cipher(true, callback);
}

#[cfg(test)]
mod cipher_tests {
    use super::*;

    #[test]
    fn cipher_enumerators_hide_callback_state() {
        let mut count = 0usize;
        EVP_CIPHER_do_all(&mut |_, from, _| {
            assert!(!from.to_bytes().is_empty());
            count += 1;
        });
        assert!(count > 0);

        let mut sorted_count = 0usize;
        EVP_CIPHER_do_all_sorted(&mut |_, _, _| sorted_count += 1);
        assert_eq!(sorted_count, count);
    }

    #[test]
    fn cipher_enumerator_panics_resume_only_after_c_returns() {
        let mut seen = 0usize;
        let panic = catch_unwind(AssertUnwindSafe(|| {
            EVP_CIPHER_do_all(&mut |_, _, _| {
                seen += 1;
                panic!("callback panic");
            });
        }));
        assert!(panic.is_err());
        // The traversal ran to completion with the remaining entries skipped,
        // so exactly one visit reached the panicking closure.
        assert_eq!(seen, 1);
    }
}
