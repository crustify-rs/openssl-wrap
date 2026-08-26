//! Wrappers assigned from `crypto/rand/rand_lib.c`.

#![allow(non_snake_case)]

use core::ffi::CStr;
use core::ptr;

use ffibox::CBox;
use libcrypto_sys as ffi;

use crate::bio::context::{OsslLibCtxMut, OsslLibCtxRef};
use crate::evp::evp_local::{EvpRandCtx, EvpRandCtxRef};
use crate::provider::provider_core::OsslProviderRef;

fn context_ptr(context: Option<OsslLibCtxRef<'_>>) -> *mut ffi::ossl_lib_ctx_st {
    context.map_or(ptr::null_mut(), |context| context.as_ptr().cast_mut())
}

fn c_string_ptr(value: Option<&CStr>) -> *const core::ffi::c_char {
    value.map_or(ptr::null(), CStr::as_ptr)
}

/// Wraps: RAND_add
/// Mixes `buffer` into the default random generator with the given entropy estimate.
///
/// `randomness` estimates how many bytes of entropy `buffer` carries and should
/// lie between zero and its length. The C function reports nothing: `true` only
/// states that the request was submitted, and `false` that `buffer` is longer
/// than a C `int` can express, so nothing was mixed in.
#[must_use]
pub fn RAND_add(buffer: &[u8], randomness: f64) -> bool {
    let Ok(length) = i32::try_from(buffer.len()) else {
        return false;
    };
    // SAFETY: `buffer` supplies exactly `length` readable bytes and OpenSSL
    // consumes them synchronously without retaining the pointer.
    unsafe { ffi::RAND_add(buffer.as_ptr().cast(), length, randomness) }
    true
}

/// Wraps: RAND_bytes
/// Fills `output` from the public random generator.
///
/// Returns `1` on success, `0` on failure and `-1` when the current random
/// method does not implement generation. `output` keeps its previous contents
/// unless the call reports success. A slice longer than a C `int` can express
/// is rejected as out of range with `-1`, without generating anything.
pub fn RAND_bytes(output: &mut [u8]) -> i32 {
    let Ok(length) = i32::try_from(output.len()) else {
        return -1;
    };
    // SAFETY: `output` supplies exactly `length` writable bytes for the
    // synchronous generation call and is exclusively borrowed.
    unsafe { ffi::RAND_bytes(output.as_mut_ptr(), length) }
}

/// Wraps: RAND_keep_random_devices_open
/// Controls whether the default provider's seed sources retain their device
/// file descriptors, which lets them keep working inside a `chroot(2)` jail.
///
/// # Safety
///
/// No other thread may acquire entropy from the default seed source during
/// this call. The device-backed seeder keeps its retention flag and its open
/// descriptors in unsynchronized process-global storage
/// (`providers/implementations/rands/seeding/rand_unix.c`), which the entropy
/// path reads without a lock, so a concurrent call races it. Passing `false`
/// additionally closes those descriptors, and the freed descriptor numbers may
/// be reused by an unrelated `open` before a concurrent seeder finishes
/// reading from them. Call this during initialization, as OpenSSL documents.
pub unsafe fn RAND_keep_random_devices_open(keep_open: bool) {
    // SAFETY: the caller excludes concurrent entropy acquisition, which is the
    // only reader of the global retention flag and of the device descriptors
    // this call may close. The argument itself carries no memory obligation.
    unsafe { ffi::RAND_keep_random_devices_open(i32::from(keep_open)) }
}

/// Wraps: RAND_poll
/// Reseeds the default generator from the configured entropy sources.
///
/// Returns whether seed data was generated; the C function reports this as a
/// strict `0` or `1`.
#[must_use]
pub fn RAND_poll() -> bool {
    // SAFETY: this function has no pointer or caller-side memory obligations.
    unsafe { ffi::RAND_poll() == 1 }
}

/// Wraps: RAND_priv_bytes
/// Fills `output` from the private random generator.
///
/// Reports success and rejects an out-of-range length exactly as
/// [`RAND_bytes`] does.
pub fn RAND_priv_bytes(output: &mut [u8]) -> i32 {
    let Ok(length) = i32::try_from(output.len()) else {
        return -1;
    };
    // SAFETY: `output` supplies exactly `length` writable bytes for the
    // synchronous generation call and is exclusively borrowed.
    unsafe { ffi::RAND_priv_bytes(output.as_mut_ptr(), length) }
}

/// Wraps: RAND_seed
/// Mixes `buffer` into the default random generator as seed material.
///
/// Equivalent to [`RAND_add`] with the entropy estimate set to the slice
/// length, and reports submission the same way.
#[must_use]
pub fn RAND_seed(buffer: &[u8]) -> bool {
    let Ok(length) = i32::try_from(buffer.len()) else {
        return false;
    };
    // SAFETY: `buffer` supplies exactly `length` readable bytes and OpenSSL
    // consumes them synchronously without retaining the pointer.
    unsafe { ffi::RAND_seed(buffer.as_ptr().cast(), length) }
    true
}

/// Wraps: RAND_status
/// Reports whether the random generator holds enough seed material.
#[must_use]
pub fn RAND_status() -> bool {
    // SAFETY: this function has no pointer or caller-side memory obligations.
    //
    // A legacy `RAND_METHOD` returns its `status` callback's value verbatim,
    // so the result is only documented as a truth value, not as a strict `1`.
    // C tests it that way itself, as in `RAND_load_file`.
    unsafe { ffi::RAND_status() != 0 }
}

/// Wraps: RAND_bytes_ex
/// Fills `output` from the public generator belonging to `context`.
pub fn RAND_bytes_ex(context: Option<OsslLibCtxRef<'_>>, output: &mut [u8], strength: u32) -> i32 {
    // SAFETY: the optional handle addresses a live library context, while
    // `output` supplies exactly its reported writable extent and is borrowed
    // exclusively for this synchronous call.
    unsafe {
        ffi::RAND_bytes_ex(
            context_ptr(context),
            output.as_mut_ptr(),
            output.len(),
            strength,
        )
    }
}

/// Wraps: RAND_get0_primary
/// Borrows the primary generator owned by `context` (or the default context).
#[must_use]
pub fn RAND_get0_primary<'a>(context: Option<OsslLibCtxRef<'a>>) -> Option<EvpRandCtxRef<'a>> {
    // SAFETY: OpenSSL returns null or a shared, non-owning pointer into the
    // selected context's RAND state. The returned handle cannot outlive the
    // explicit context borrow; the null-context state is library-managed.
    unsafe { EvpRandCtxRef::from_ptr(ffi::RAND_get0_primary(context_ptr(context))) }
}

/// Wraps: RAND_get0_private
/// Borrows the current thread's private generator for `context`.
#[must_use]
pub fn RAND_get0_private<'a>(context: Option<OsslLibCtxRef<'a>>) -> Option<EvpRandCtxRef<'a>> {
    // SAFETY: OpenSSL retains this thread-local context and returns no new
    // ownership count. Its lifetime is bounded by the explicit library
    // context, or managed by the default context and current thread.
    unsafe { EvpRandCtxRef::from_ptr(ffi::RAND_get0_private(context_ptr(context))) }
}

/// Wraps: RAND_get0_public
/// Borrows the current thread's public generator for `context`.
#[must_use]
pub fn RAND_get0_public<'a>(context: Option<OsslLibCtxRef<'a>>) -> Option<EvpRandCtxRef<'a>> {
    // SAFETY: as for `RAND_get0_private`, for the public thread-local slot.
    unsafe { EvpRandCtxRef::from_ptr(ffi::RAND_get0_public(context_ptr(context))) }
}

/// Wraps: RAND_priv_bytes_ex
/// Fills `output` from the private generator belonging to `context`.
pub fn RAND_priv_bytes_ex(
    context: Option<OsslLibCtxRef<'_>>,
    output: &mut [u8],
    strength: u32,
) -> i32 {
    // SAFETY: the optional handle addresses a live library context, while
    // `output` supplies exactly its reported writable extent and is borrowed
    // exclusively for this synchronous call.
    unsafe {
        ffi::RAND_priv_bytes_ex(
            context_ptr(context),
            output.as_mut_ptr(),
            output.len(),
            strength,
        )
    }
}

/// Wraps: RAND_set0_private
/// Replaces the current thread's private generator, returning it on failure.
pub fn RAND_set0_private(
    context: &mut OsslLibCtxMut<'_>,
    generator: Option<CBox<EvpRandCtx>>,
) -> Result<(), Option<CBox<EvpRandCtx>>> {
    set0_generator(context.as_mut_ptr(), generator, ffi::RAND_set0_private)
}

/// Wraps: RAND_set0_private
/// Replaces the default context's current-thread private generator.
///
/// # Safety
///
/// No borrowed handle to the private generator being replaced may remain live.
/// A successful call frees that generator's current-thread ownership count.
pub unsafe fn RAND_set0_private_default(
    generator: Option<CBox<EvpRandCtx>>,
) -> Result<(), Option<CBox<EvpRandCtx>>> {
    set0_generator(ptr::null_mut(), generator, ffi::RAND_set0_private)
}

/// Wraps: RAND_set0_public
/// Replaces the current thread's public generator, returning it on failure.
pub fn RAND_set0_public(
    context: &mut OsslLibCtxMut<'_>,
    generator: Option<CBox<EvpRandCtx>>,
) -> Result<(), Option<CBox<EvpRandCtx>>> {
    set0_generator(context.as_mut_ptr(), generator, ffi::RAND_set0_public)
}

/// Wraps: RAND_set0_public
/// Replaces the default context's current-thread public generator.
///
/// # Safety
///
/// No borrowed handle to the public generator being replaced may remain live.
/// A successful call frees that generator's current-thread ownership count.
pub unsafe fn RAND_set0_public_default(
    generator: Option<CBox<EvpRandCtx>>,
) -> Result<(), Option<CBox<EvpRandCtx>>> {
    set0_generator(ptr::null_mut(), generator, ffi::RAND_set0_public)
}

fn set0_generator(
    context: *mut ffi::ossl_lib_ctx_st,
    generator: Option<CBox<EvpRandCtx>>,
    setter: unsafe extern "C" fn(*mut ffi::ossl_lib_ctx_st, *mut ffi::evp_rand_ctx_st) -> i32,
) -> Result<(), Option<CBox<EvpRandCtx>>> {
    let raw = generator.map_or(ptr::null_mut(), CBox::into_raw);
    // SAFETY: `raw` is null or transfers one fully initialized ownership
    // obligation. OpenSSL takes it only when the setter reports success.
    if unsafe { setter(context, raw) } > 0 {
        Ok(())
    } else {
        // SAFETY: failure leaves the exact ownership obligation represented by
        // `raw` with the caller; null reconstructs the original `None`.
        Err(unsafe { CBox::from_raw(raw) })
    }
}

/// Wraps: RAND_set1_random_provider
/// Selects a provider for random generation, or disables the override.
///
/// # Safety
///
/// No other thread may generate randomness from, configure, load, or unload a
/// provider in the selected library context during this call. OpenSSL stores a
/// borrowed provider pointer and documents this operation as not thread-safe;
/// its provider lifecycle hooks clear the pointer when that provider unloads.
#[must_use]
pub unsafe fn RAND_set1_random_provider(
    context: Option<OsslLibCtxRef<'_>>,
    provider: Option<OsslProviderRef<'_>>,
) -> bool {
    let provider = provider.map_or(ptr::null_mut(), |provider| provider.as_ptr().cast_mut());
    // SAFETY: the caller excludes the documented concurrent operations, and
    // both optional handles address live objects for this call. OpenSSL's
    // unload hook manages the stored non-owning provider pointer afterwards.
    unsafe { ffi::RAND_set1_random_provider(context_ptr(context), provider) == 1 }
}

/// Wraps: RAND_set_DRBG_type
/// Configures the generator fetched for a library context.
#[must_use]
pub fn RAND_set_DRBG_type(
    context: &mut OsslLibCtxMut<'_>,
    generator: Option<&CStr>,
    properties: Option<&CStr>,
    cipher: Option<&CStr>,
    digest: Option<&CStr>,
) -> bool {
    set_drbg_type(context.as_mut_ptr(), generator, properties, cipher, digest)
}

/// Wraps: RAND_set_DRBG_type
/// Configures the generator fetched for the default library context.
///
/// # Safety
///
/// No other thread may initialize, generate from, or configure the default
/// context's RAND state during this call.
#[must_use]
pub unsafe fn RAND_set_DRBG_type_default(
    generator: Option<&CStr>,
    properties: Option<&CStr>,
    cipher: Option<&CStr>,
    digest: Option<&CStr>,
) -> bool {
    set_drbg_type(ptr::null_mut(), generator, properties, cipher, digest)
}

fn set_drbg_type(
    context: *mut ffi::ossl_lib_ctx_st,
    generator: Option<&CStr>,
    properties: Option<&CStr>,
    cipher: Option<&CStr>,
    digest: Option<&CStr>,
) -> bool {
    // SAFETY: `context` is null or comes from an exclusive live handle. Each
    // C string is live and NUL-terminated for the call; OpenSSL duplicates
    // every non-null value it retains.
    unsafe {
        ffi::RAND_set_DRBG_type(
            context,
            c_string_ptr(generator),
            c_string_ptr(properties),
            c_string_ptr(cipher),
            c_string_ptr(digest),
        ) == 1
    }
}

/// Wraps: RAND_set_seed_source_type
/// Configures the seed source fetched for a library context.
#[must_use]
pub fn RAND_set_seed_source_type(
    context: &mut OsslLibCtxMut<'_>,
    seed_source: Option<&CStr>,
    properties: Option<&CStr>,
) -> bool {
    set_seed_source_type(context.as_mut_ptr(), seed_source, properties)
}

/// Wraps: RAND_set_seed_source_type
/// Configures the seed source fetched for the default library context.
///
/// # Safety
///
/// No other thread may initialize, generate from, or configure the default
/// context's RAND state during this call.
#[must_use]
pub unsafe fn RAND_set_seed_source_type_default(
    seed_source: Option<&CStr>,
    properties: Option<&CStr>,
) -> bool {
    set_seed_source_type(ptr::null_mut(), seed_source, properties)
}

fn set_seed_source_type(
    context: *mut ffi::ossl_lib_ctx_st,
    seed_source: Option<&CStr>,
    properties: Option<&CStr>,
) -> bool {
    // SAFETY: `context` is null or comes from an exclusive live handle.
    // OpenSSL synchronously duplicates both optional C strings before return.
    unsafe {
        ffi::RAND_set_seed_source_type(context, c_string_ptr(seed_source), c_string_ptr(properties))
            == 1
    }
}

#[cfg(test)]
mod tests {
    use ffibox::CBox;

    use super::*;
    use crate::bio::context::OsslLibCtx;

    #[test]
    fn seed_poll_and_generate_use_bounded_slices() {
        assert!(RAND_seed(b"crustify seed material"));
        assert!(RAND_add(b"additional input", 0.0));
        assert!(RAND_poll());
        assert!(RAND_status());

        let mut public = [0; 32];
        let mut private = [0; 32];
        assert_eq!(RAND_bytes(&mut public), 1);
        assert_eq!(RAND_priv_bytes(&mut private), 1);
    }

    #[test]
    fn explicit_context_generation_returns_borrowed_generators() {
        // SAFETY: a non-null constructor result transfers one fresh, fully
        // initialized context to its registered owner.
        let mut context = unsafe { CBox::<OsslLibCtx>::from_raw(ffi::OSSL_LIB_CTX_new()) }
            .expect("isolated library context");
        let mut public = [0_u8; 16];
        let mut private = [0_u8; 16];

        assert_eq!(RAND_bytes_ex(Some(context.as_ref()), &mut public, 128), 1);
        assert_eq!(
            RAND_priv_bytes_ex(Some(context.as_ref()), &mut private, 128),
            1
        );
        assert!(RAND_get0_primary(Some(context.as_ref())).is_some());
        assert!(RAND_get0_public(Some(context.as_ref())).is_some());
        assert!(RAND_get0_private(Some(context.as_ref())).is_some());

        // Clearing transfers no owner but still exercises the nullable set0
        // contract. The next generation call recreates the thread-local slot.
        assert!(RAND_set0_public(&mut context.as_mut(), None).is_ok());
        assert_eq!(RAND_bytes_ex(Some(context.as_ref()), &mut public, 128), 1);
    }

    #[test]
    fn configuration_copies_optional_c_strings_before_generation() {
        // SAFETY: a non-null constructor result transfers one fresh, fully
        // initialized context to its registered owner.
        let mut context = unsafe { CBox::<OsslLibCtx>::from_raw(ffi::OSSL_LIB_CTX_new()) }
            .expect("isolated library context");

        assert!(RAND_set_DRBG_type(
            &mut context.as_mut(),
            Some(c"CTR-DRBG"),
            None,
            Some(c"AES-256-CTR"),
            None,
        ));
        assert!(RAND_set_seed_source_type(
            &mut context.as_mut(),
            Some(c"SEED-SRC"),
            None
        ));

        let mut output = [0_u8; 16];
        assert_eq!(RAND_bytes_ex(Some(context.as_ref()), &mut output, 128), 1);
    }
}
