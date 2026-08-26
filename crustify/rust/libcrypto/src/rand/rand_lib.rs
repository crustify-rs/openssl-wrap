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
///
/// `strength` is the security strength required of the result, in bits; the
/// call fails when the selected generator cannot supply it. Returns `1` on
/// success and `0` on failure, and `output` keeps its previous contents unless
/// the call reports success. A build that retains the deprecated
/// `RAND_METHOD` path can additionally return `-1` when an installed legacy
/// table rejects the length or implements no `bytes` callback; this build
/// compiles that path out.
///
/// A provider registered through [`RAND_set1_random_provider`] answers instead
/// of the context's DRBG, and receives `strength` unchanged.
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
/// Borrows the primary generator of `context`, creating it on first use.
///
/// The primary DRBG is not generated from directly: it only reseeds the public
/// and private generators. One instance is shared by every thread using the
/// context, which is why OpenSSL enables locking on it. The context owns it, so
/// no reference is transferred, and `None` reports that creating or seeding it
/// failed. Creating it also settles the context's seed source, which is what
/// closes the [`RAND_set_DRBG_type`] and [`RAND_set_seed_source_type`] windows.
///
/// With `Some(context)` the returned handle cannot outlive that borrow. With
/// `None` it names the default context's primary DRBG and this signature
/// constrains its lifetime not at all; that generator is released only when the
/// library is cleaned up, which no safe wrapper performs.
#[must_use]
pub fn RAND_get0_primary<'a>(context: Option<OsslLibCtxRef<'a>>) -> Option<EvpRandCtxRef<'a>> {
    // SAFETY: OpenSSL returns null or a shared, non-owning pointer into the
    // selected context's RAND state. The returned handle cannot outlive the
    // explicit context borrow; the null-context state is library-managed.
    unsafe { EvpRandCtxRef::from_ptr(ffi::RAND_get0_primary(context_ptr(context))) }
}

/// Wraps: RAND_get0_private
/// Borrows the calling thread's private generator for `context`, creating it
/// and the context's primary DRBG on first use.
///
/// The generator belongs to the pair of `context` and the calling thread; it is
/// released when that thread exits or when [`RAND_set0_private`] replaces it.
/// Neither release can invalidate the returned handle: the handle is neither
/// `Send` nor `Sync`, so it never reaches the thread whose exit would free the
/// generator, and replacing the generator needs an exclusive context handle
/// that this shared borrow already excludes. `None` reports that creation
/// failed.
///
/// With `None` the returned lifetime is unconstrained, and the default
/// context's slot is replaced only through the unsafe
/// [`RAND_set0_private_default`], whose contract covers an outstanding handle.
#[must_use]
pub fn RAND_get0_private<'a>(context: Option<OsslLibCtxRef<'a>>) -> Option<EvpRandCtxRef<'a>> {
    // SAFETY: OpenSSL retains this thread-local context and returns no new
    // ownership count. Its lifetime is bounded by the explicit library
    // context, or managed by the default context and current thread.
    unsafe { EvpRandCtxRef::from_ptr(ffi::RAND_get0_private(context_ptr(context))) }
}

/// Wraps: RAND_get0_public
/// Borrows the calling thread's public generator for `context`, creating it
/// and the context's primary DRBG on first use.
///
/// Scoped, released and bounded exactly as [`RAND_get0_private`] is, for the
/// public thread-local slot and [`RAND_set0_public`].
#[must_use]
pub fn RAND_get0_public<'a>(context: Option<OsslLibCtxRef<'a>>) -> Option<EvpRandCtxRef<'a>> {
    // SAFETY: as for `RAND_get0_private`, for the public thread-local slot.
    unsafe { EvpRandCtxRef::from_ptr(ffi::RAND_get0_public(context_ptr(context))) }
}

/// Wraps: RAND_priv_bytes_ex
/// Fills `output` from the private generator belonging to `context`.
///
/// Interprets `strength`, reports success and honours a registered random
/// provider exactly as [`RAND_bytes_ex`] does.
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
/// Installs `generator` as the calling thread's private generator for
/// `context`, returning it unchanged when the call fails.
///
/// On success the thread's previously installed private generator is freed and
/// `None` leaves the slot empty, so the next private generation call rebuilds
/// one. The exclusive context handle is what rules out an outstanding
/// [`RAND_get0_private`] borrow of the generator being freed.
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
/// Installs `generator` as the calling thread's public generator for
/// `context`, returning it unchanged when the call fails.
///
/// Frees the replaced generator and bounds outstanding borrows exactly as
/// [`RAND_set0_private`] does, for the public thread-local slot.
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
/// Routes `context`'s public and private generation through `provider`, or
/// clears that override with `None`. Reports whether the request was applied.
///
/// Despite the `set1` spelling only the provider's *name* is copied; the
/// provider itself is stored as a bare address that OpenSSL never up-refs. A
/// registered provider answers [`RAND_bytes_ex`] and [`RAND_priv_bytes_ex`]
/// through its `OSSL_FUNC_PROVIDER_RANDOM_BYTES` dispatch entry. No provider
/// shipped with OpenSSL supplies one, and `ossl_provider_random_bytes`
/// (`crypto/provider_core.c`) reports failure when it is absent, so registering
/// a stock provider makes both calls fail until the override is cleared.
///
/// # Safety
///
/// The registration must not outlive `provider`'s allocation, and OpenSSL
/// guarantees that only for a provider loaded against the very library context
/// this call selects. Such a provider is kept alive by that context's provider
/// store until the context itself is freed, after which nothing reads the
/// stored address. A provider loaded against a *different* context is not:
/// `crypto/provider_core.c` deregisters through
/// `ossl_rand_check_random_provider_on_unload(prov->libctx, prov)`, keyed on the
/// provider's own context, so it never clears this context's registration, and
/// its owning context can be freed first — leaving the safe generation calls
/// above reading a released provider.
///
/// No other thread may generate randomness from, configure, load or unload a
/// provider in the selected context during the call: OpenSSL replaces the
/// stored name and address without holding a lock, and documents the operation
/// as not thread-safe. The other setters in this module obtain that exclusion
/// from the borrow checker by taking an exclusive
/// [`OsslLibCtxMut`](crate::bio::context::OsslLibCtxMut); this one cannot,
/// because an owned provider handle holds the same context's shared borrow for
/// as long as it lives.
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
/// Names the generator, property query, cipher and digest that `context`
/// fetches when it builds its DRBGs.
///
/// Each supplied string is duplicated into context-owned storage and each
/// `None` clears the stored value. Returns `false` once the context's primary
/// DRBG has been instantiated — any generation, seeding or
/// [`RAND_get0_primary`] call does that — and also when a duplication fails, in
/// which case the arguments accepted before the failure have already replaced
/// their stored values.
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
/// Names the generator, property query, cipher and digest fetched for the
/// default library context.
///
/// Copies its arguments and reports failure exactly as [`RAND_set_DRBG_type`]
/// does.
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
/// Names the seed source and property query that `context` fetches when it
/// builds its entropy source.
///
/// Copies its arguments as [`RAND_set_DRBG_type`] does. Returns `false` once
/// the context's seed source has been instantiated, which happens while the
/// primary DRBG is created, and also on a duplication failure that leaves an
/// already accepted argument stored.
#[must_use]
pub fn RAND_set_seed_source_type(
    context: &mut OsslLibCtxMut<'_>,
    seed_source: Option<&CStr>,
    properties: Option<&CStr>,
) -> bool {
    set_seed_source_type(context.as_mut_ptr(), seed_source, properties)
}

/// Wraps: RAND_set_seed_source_type
/// Names the seed source and property query fetched for the default library
/// context.
///
/// Copies its arguments and reports failure exactly as
/// [`RAND_set_seed_source_type`] does.
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
    use crate::provider::provider_core::SharedOsslProvider;

    /// An isolated context keeps these tests from configuring, or disabling
    /// fallback loading in, the process-global context other tests share.
    fn new_context() -> CBox<OsslLibCtx> {
        // SAFETY: a non-null constructor result transfers one fresh, fully
        // initialized context to its registered owner.
        unsafe { CBox::<OsslLibCtx>::from_raw(ffi::OSSL_LIB_CTX_new()) }
            .expect("isolated library context")
    }

    /// Loads the default provider, tying the owner to the context's borrow.
    fn load_default(context: OsslLibCtxRef<'_>) -> SharedOsslProvider<'_> {
        // SAFETY: the handle addresses a live library context and the literal
        // is a live NUL-terminated name. The call returns null or one active
        // public provider handle.
        let raw =
            unsafe { ffi::OSSL_PROVIDER_load(context.as_ptr().cast_mut(), c"default".as_ptr()) };
        // SAFETY: a non-null result transfers exactly one activation and one
        // reference, settled by the owner's single `OSSL_PROVIDER_unload`.
        unsafe { SharedOsslProvider::from_raw(raw) }.expect("load the default provider")
    }

    /// Builds one uninstantiated HASH-DRBG that the caller solely owns.
    fn new_generator(context: OsslLibCtxRef<'_>) -> CBox<EvpRandCtx> {
        // SAFETY: the handle addresses a live library context and the literal
        // is a live NUL-terminated algorithm name; a null property query
        // selects the default one.
        let algorithm = unsafe {
            ffi::EVP_RAND_fetch(
                context.as_ptr().cast_mut(),
                c"HASH-DRBG".as_ptr(),
                ptr::null(),
            )
        };
        assert!(!algorithm.is_null(), "fetch HASH-DRBG");

        // SAFETY: `algorithm` is a live fetched implementation, which the
        // constructor up-refs for itself; a null parent selects no reseeding
        // source, which this generator never needs.
        let raw = unsafe { ffi::EVP_RAND_CTX_new(algorithm, ptr::null_mut()) };
        // SAFETY: the constructor took its own reference, so this settles the
        // fetch obligation created just above and leaves `raw` valid.
        unsafe { ffi::EVP_RAND_free(algorithm) };
        // SAFETY: a non-null result transfers exactly one fresh, fully
        // constructed generator to its registered owner.
        unsafe { CBox::<EvpRandCtx>::from_raw(raw) }.expect("build a DRBG context")
    }

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
        let mut context = new_context();
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
        let mut context = new_context();

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

    #[test]
    fn configuration_is_refused_once_the_context_has_instantiated_its_drbgs() {
        let mut context = new_context();

        assert!(RAND_set_DRBG_type(
            &mut context.as_mut(),
            Some(c"HASH-DRBG"),
            None,
            None,
            Some(c"SHA2-512"),
        ));

        // Building the primary DRBG also settles the seed source, which closes
        // both configuration windows for this context.
        assert!(RAND_get0_primary(Some(context.as_ref())).is_some());

        assert!(!RAND_set_DRBG_type(
            &mut context.as_mut(),
            Some(c"CTR-DRBG"),
            None,
            Some(c"AES-256-CTR"),
            None,
        ));
        assert!(!RAND_set_seed_source_type(
            &mut context.as_mut(),
            Some(c"SEED-SRC"),
            None
        ));
    }

    #[test]
    fn a_registered_random_provider_answers_generation_until_it_is_cleared() {
        let context = new_context();
        let provider = load_default(context.as_ref());
        let mut output = [0_u8; 16];

        // The provider owner already holds the context's shared borrow, which
        // is why this setter takes a shared context handle and states its
        // exclusion requirement in prose instead.
        //
        // SAFETY: the provider was loaded against this very context, so its
        // store keeps it alive for as long as the registration can be read.
        // Nothing else in this test uses the context concurrently.
        assert!(unsafe {
            RAND_set1_random_provider(Some(context.as_ref()), Some(provider.as_ref()))
        });

        // The default provider implements no `OSSL_FUNC_PROVIDER_RANDOM_BYTES`,
        // so generation now reports failure rather than reaching the DRBGs.
        assert_eq!(RAND_bytes_ex(Some(context.as_ref()), &mut output, 128), 0);
        assert_eq!(
            RAND_priv_bytes_ex(Some(context.as_ref()), &mut output, 128),
            0
        );

        // SAFETY: as above; clearing the override stores no borrowed pointer.
        assert!(unsafe { RAND_set1_random_provider(Some(context.as_ref()), None) });
        assert_eq!(RAND_bytes_ex(Some(context.as_ref()), &mut output, 128), 1);

        // The owner unloads before the context it borrows is freed.
        drop(provider);
    }

    #[test]
    fn set0_public_and_private_take_over_a_caller_built_generator() {
        let mut context = new_context();
        let public = new_generator(context.as_ref());
        let private = new_generator(context.as_ref());
        let installed_public = public.as_ref().as_ptr();
        let installed_private = private.as_ref().as_ptr();
        let mut output = [0_u8; 16];

        assert!(RAND_set0_public(&mut context.as_mut(), Some(public)).is_ok());
        assert!(RAND_set0_private(&mut context.as_mut(), Some(private)).is_ok());
        assert_eq!(
            RAND_get0_public(Some(context.as_ref()))
                .expect("installed public generator")
                .as_ptr(),
            installed_public
        );
        assert_eq!(
            RAND_get0_private(Some(context.as_ref()))
                .expect("installed private generator")
                .as_ptr(),
            installed_private
        );

        // The transferred generators were never instantiated, so generation
        // fails — evidence that they, and not the DRBGs OpenSSL would have
        // built, are what this thread now generates through.
        assert_eq!(RAND_bytes_ex(Some(context.as_ref()), &mut output, 0), 0);
        assert_eq!(
            RAND_priv_bytes_ex(Some(context.as_ref()), &mut output, 0),
            0
        );

        // Clearing frees both transferred generators; the next call rebuilds
        // the thread-local slots. Running this under the C build's sanitizers
        // is what proves the transfer released each obligation exactly once.
        assert!(RAND_set0_public(&mut context.as_mut(), None).is_ok());
        assert!(RAND_set0_private(&mut context.as_mut(), None).is_ok());
        assert_eq!(RAND_bytes_ex(Some(context.as_ref()), &mut output, 0), 1);
        assert_eq!(
            RAND_priv_bytes_ex(Some(context.as_ref()), &mut output, 0),
            1
        );
    }
}
