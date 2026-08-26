//! Wrappers assigned from `include/crypto/evp.h`.

use ffibox::{define_ctype, impl_dropped};
use libcrypto_sys as ffi;

use crate::evp::p_lib::BorrowedEvpPkey;

define_ctype!(
    /// Wraps: evp_pkey_st
    ///
    /// OpenSSL publishes `EVP_PKEY` as an opaque, reference-counted key
    /// container. Its allocation and fields remain C-owned; this layout
    /// wrapper only supplies the pointer-compatible target used by owning and
    /// lifetime-bound borrowed handles.
    ///
    /// An owning [`CBox<EvpPkey>`](ffibox::CBox) carries one reference count
    /// and is deliberately not `Clone`: a second count names the same key, so
    /// every wrapper that raises one hands back a shared-only
    /// [`SharedEvpPkey`] rather than an owner with an exclusive handle. Use
    /// [`EvpPkeyRef::try_dup`] when an independent deep copy is required.
    ///
    /// The record itself stores no `OSSL_LIB_CTX`, but a provider-backed key
    /// holds an acquired `EVP_KEYMGMT` reference, and that method reaches the
    /// library context it was fetched from. Nothing in the chain keeps the
    /// context alive — a provider reference does not — so every owner of a key
    /// carries that dependency in its type: `BorrowedEvpPkey<'a>` for a key
    /// built from a context borrow — generation, import and duplication all
    /// return one — and [`SharedEvpPkey<'a>`] for an extra reference reached
    /// through a container that already carries one. A bare `CBox<EvpPkey>` is
    /// reserved for the constructors that select no context at all
    /// (`EVP_PKEY_new`, the legacy NID-keyed `EVP_PKEY_new_raw_*`,
    /// `EVP_PKEY_new_mac_key` and `EVP_PKEY_new_CMAC_key`, which passes its
    /// cipher's *name* on and builds through a null library context), so they
    /// borrow nothing an owner could outlive.
    EvpPkey,
    EvpPkeyRef,
    EvpPkeyMut,
    ffi::evp_pkey_st
);

// `EVP_PKEY_free` is the public down-reference operation. It accepts null;
// for a live owner it decrements the atomic reference count and, on the final
// count, releases the provider or legacy key material, attributes, operation
// cache, ex-data, lock, and allocation.
impl_dropped!(EvpPkey, ffi::evp_pkey_st, ffi::EVP_PKEY_free);

// `EVP_PKEY` is reference counted, so it deliberately has **no** `CCloned`
// impl. Registering `EVP_PKEY_up_ref` there would give `CBox<EvpPkey>` a
// `Clone` taking only `&self`, and the resulting second owner's
// `CBox::as_mut` would assert an exclusivity the count cannot provide. Every
// wrapper that raises the count — `X509_get_pubkey`, `X509_PUBKEY_get` —
// returns [`SharedEvpPkey`] instead. [`EvpPkeyRef::try_dup`] remains the route
// to an independent, mutable copy.

/// One owned reference to a key that other owners may also hold.
///
/// The lifetime carries the library-context dependency the key inherits from
/// the `EVP_KEYMGMT` it retains, exactly as [`SharedEvpSkey`] does. A key
/// selected from the process-wide default context may use `'static`; a share
/// raised from a container built in an explicit context keeps that container's
/// borrow, which is what bounds the context.
///
/// Raising a reference count is therefore not a way to escape the container:
///
/// ```compile_fail
/// use libcrypto::x509::x_pubkey::{X509_PUBKEY_get, X509_PUBKEY_new_ex};
///
/// let shared = {
///     let container = X509_PUBKEY_new_ex(None, None).expect("container");
///     // The share borrows `container`, which the block then drops.
///     X509_PUBKEY_get(container.as_ref())
/// };
/// drop(shared);
/// ```
pub type SharedEvpPkey<'a> = crate::refcount::SharedRef<'a, EvpPkey>;

impl<'a> EvpPkeyRef<'a> {
    /// Create an independently owned deep copy of this key container.
    ///
    /// This differs from cloning an owning handle: `try_dup` copies the key
    /// material, attributes, and auxiliary data into a fresh `EVP_PKEY`, while
    /// an owner clone only increments this object's reference count.
    ///
    /// The copy is a sole allocation and may therefore be exclusively
    /// borrowed, but it is not context-independent: `EVP_PKEY_dup` gives a
    /// provider-backed duplicate its source's `EVP_KEYMGMT`, so the result
    /// keeps this handle's borrow.
    #[must_use]
    pub fn try_dup(self) -> Option<BorrowedEvpPkey<'a>> {
        // SAFETY: the handle carries a live shared borrow. Although the C
        // declaration predates const-correctness, `EVP_PKEY_dup` only reads
        // its source — the provided path exports through
        // `evp_keymgmt_util_export`, which takes a `const EVP_PKEY *`, and
        // every legacy `ameth->copy` duplicates the source key object — and
        // returns null or a fresh fully initialized allocation.
        let duplicate = unsafe { ffi::EVP_PKEY_dup(self.as_ptr().cast_mut()) };
        // SAFETY: a non-null duplicate transfers one independent
        // `EVP_PKEY_free` obligation, and the duplicate's provider-side
        // dependencies are the ones this handle's borrow already covers.
        unsafe { BorrowedEvpPkey::from_raw(duplicate) }
    }
}

#[cfg(test)]
mod tests {
    use ffibox::CBox;

    use super::*;

    #[test]
    fn owner_borrows_and_duplicates_deeply() {
        // SAFETY: OpenSSL returns null or a fresh fully initialized,
        // reference-count-one `EVP_PKEY` allocation.
        let raw = unsafe { ffi::EVP_PKEY_new() };
        // SAFETY: ownership of the fresh result transfers once to the owner,
        // whose registered down-reference is `EVP_PKEY_free`.
        let mut key = unsafe { CBox::<EvpPkey>::from_raw(raw) }.expect("EVP_PKEY_new");

        assert_eq!(key.as_ref().as_ptr(), raw.cast_const());
        assert_eq!(key.as_mut().as_mut_ptr(), raw);

        let mut duplicate = key.as_ref().try_dup().expect("EVP_PKEY_dup");
        assert_ne!(duplicate.as_ref().as_ptr(), raw.cast_const());
        // The copy really is a sole allocation, so it grants the exclusive
        // handle a share of the original never could.
        assert_eq!(
            duplicate.as_mut().as_mut_ptr().cast_const(),
            duplicate.as_ref().as_ptr()
        );
    }

    /// The key above is an `EVP_PKEY_NONE` container: it holds no `keymgmt`,
    /// so it exercises none of the provider-side dependency this type's
    /// ownership claims are about. A provider-backed key does. `EVP_PKEY_dup`
    /// gives the copy the source's acquired `EVP_KEYMGMT` and exports its key
    /// data through it, which is why the duplicate keeps the source handle's
    /// borrow instead of becoming a context-independent `CBox<EvpPkey>`.
    #[test]
    fn duplicating_a_provider_backed_key_carries_the_source_borrow() {
        use crate::evp::evp_lib::{EVP_PKEY_Q_keygen, QuickKeygen};
        use crate::evp::p_lib::{EVP_PKEY_eq, EVP_PKEY_is_a};

        let key = EVP_PKEY_Q_keygen(None, None, QuickKeygen::Ed25519).expect("Ed25519 keygen");
        let duplicate = key.as_ref().try_dup().expect("EVP_PKEY_dup");

        assert_ne!(duplicate.as_ref().as_ptr(), key.as_ref().as_ptr());
        assert!(EVP_PKEY_is_a(duplicate.as_ref(), c"ED25519"));
        assert_eq!(EVP_PKEY_eq(key.as_ref(), duplicate.as_ref()), 1);

        // Each owner releases its own reference and its own provider key data,
        // and the duplicate cannot outlive the borrow it inherited.
    }
}

define_ctype!(
    /// Wraps: evp_cipher_st
    ///
    /// OpenSSL publishes `EVP_CIPHER` as an opaque cipher implementation.
    /// Provider-backed records retain their provider and are reference
    /// counted, while legacy records are static. Both kinds use the public
    /// `EVP_CIPHER_up_ref` / `EVP_CIPHER_free` pair: for cached or static
    /// records those operations are deliberately no-ops.
    ///
    /// An owning reference is exposed as [`SharedEvpCipher`], not as a public
    /// `CBox<EvpCipher>`, because fetches and reference-count increments may
    /// name the same record and therefore cannot grant exclusive access.
    EvpCipher,
    EvpCipherRef,
    EvpCipherMut,
    ffi::evp_cipher_st
);

// `EVP_CIPHER_free` is the public down-reference operation. Depending on the
// cipher's origin and cache policy it either decrements the dynamic record or
// is a no-op, exactly matching `EVP_CIPHER_up_ref`.
impl_dropped!(EvpCipher, ffi::evp_cipher_st, ffi::EVP_CIPHER_free);

// Do not register `EVP_CIPHER_up_ref` as `CCloned`: that would make
// `CBox<EvpCipher>` cloneable even though every clone could call `as_mut` on
// the same record. `SharedEvpCipher` intentionally grants shared access only.

/// One owned reference to a cipher implementation.
///
/// The lifetime carries the library-context dependency of a fetched cipher.
/// A cipher selected from the default context may use `'static`; a fetch from
/// an explicit context must use that context's borrow.
pub type SharedEvpCipher<'a> = crate::refcount::SharedRef<'a, EvpCipher>;

impl<'a> EvpCipherRef<'a> {
    /// Raise this cipher's public reference and return a shared-only owner.
    #[must_use]
    pub fn try_share(&self) -> Option<SharedEvpCipher<'a>> {
        // SAFETY: the handle carries a live shared borrow. OpenSSL may update
        // the dynamic record's atomic reference count but does not otherwise
        // mutate it, and reports whether it created the matching public
        // release obligation.
        if unsafe { ffi::EVP_CIPHER_up_ref(self.as_ptr().cast_mut()) } != 1 {
            return None;
        }

        // SAFETY: successful `EVP_CIPHER_up_ref` creates one matching
        // `EVP_CIPHER_free` obligation. The share retains the handle's
        // library-context lifetime and exposes no exclusive access.
        unsafe { SharedEvpCipher::from_raw(self.as_ptr().cast_mut()) }
    }
}

#[cfg(test)]
mod cipher_tests {
    use core::ptr;

    use ffibox::CBox;

    use super::*;

    #[test]
    fn fetched_cipher_and_raised_reference_are_shared_only() {
        // SAFETY: null selects the process-wide default library context, the
        // algorithm name is a live NUL-terminated string, and a null property
        // query requests the default selection. A non-null result transfers
        // one public EVP_CIPHER reference.
        let raw =
            unsafe { ffi::EVP_CIPHER_fetch(ptr::null_mut(), c"AES-128-CBC".as_ptr(), ptr::null()) };
        // SAFETY: the default library context is process-wide, and the fresh
        // fetch result transfers one `EVP_CIPHER_free` obligation.
        let cipher: SharedEvpCipher<'static> =
            unsafe { SharedEvpCipher::from_raw(raw) }.expect("EVP_CIPHER_fetch");

        let shared = cipher.as_ref().try_share().expect("EVP_CIPHER_up_ref");
        assert_eq!(shared.as_ptr(), cipher.as_ptr());
        assert_eq!(shared.as_ref().as_ptr(), raw.cast_const());
    }

    /// A cached fetch hands back a record the library context owns, not a
    /// counted reference of its own — the reason [`SharedEvpCipher`] carries
    /// the fetching context's borrow instead of being `'static` by default.
    #[test]
    fn a_cached_fetch_shares_one_library_context_owned_record() {
        // SAFETY: the constructor returns null or a fresh, fully initialized
        // context carrying one ownership obligation, transferred once here.
        let libctx =
            unsafe { CBox::<crate::bio::context::OsslLibCtx>::from_raw(ffi::OSSL_LIB_CTX_new()) }
                .expect("OSSL_LIB_CTX_new");

        let fetch = || {
            // SAFETY: `libctx` is live for the whole closure body, the
            // algorithm name is NUL-terminated, and a null property query
            // selects the default properties.
            unsafe { ffi::EVP_CIPHER_fetch(libctx.as_ptr(), c"AES-128-CBC".as_ptr(), ptr::null()) }
        };

        let first = fetch();
        let second = fetch();
        assert!(!first.is_null());
        // Two fetches name one record: caching returns the stored method
        // without taking a reference for the caller.
        assert_eq!(first, second);

        // SAFETY: the record is live and owned by `libctx`; on the cached path
        // `EVP_CIPHER_up_ref` reports success without touching a count, which
        // is why `try_share` may not treat its result as sole ownership.
        let borrowed = unsafe { EvpCipherRef::from_ptr(first) }.expect("fetched cipher");
        let share = borrowed.try_share().expect("EVP_CIPHER_up_ref");
        assert_eq!(share.as_ptr(), first);
        // The share's own release runs here and changes nothing.
        drop(share);

        // Balancing both fetches still leaves the record usable, because every
        // release is a no-op for a cached method.
        for _ in 0..2 {
            // SAFETY: releasing a cached record is the documented no-op path;
            // the store keeps the only real reference.
            unsafe { ffi::EVP_CIPHER_free(first) };
        }
        // SAFETY: the record is still live, as the previous releases show.
        let name = unsafe { ffi::EVP_CIPHER_get0_name(first) };
        assert!(!name.is_null());

        // `libctx` frees the record here, which is the dependency
        // `SharedEvpCipher<'a>` exists to express.
        drop(libctx);
    }
}

define_ctype!(
    /// Wraps: evp_pkey_ctx_st
    ///
    /// OpenSSL publishes `EVP_PKEY_CTX` as an opaque, uniquely owned operation
    /// context. Its fields, provider operation state, and allocation remain
    /// C-owned; this wrapper supplies pointer-compatible owning and borrowed
    /// handles without exposing the private layout.
    ///
    /// A context retains references to any keys and fetched operation methods
    /// it stores, but only borrows its `OSSL_LIB_CTX`: `EVP_PKEY_CTX_free`
    /// never releases it. A context made with a non-default library context
    /// must therefore not outlive that context, which is why the public
    /// constructors that take one return
    /// [`crate::evp::pmeth_lib::BorrowedEvpPkeyCtx`] rather than a bare
    /// `CBox<EvpPkeyCtx>`. A plain `CBox<EvpPkeyCtx>` is only produced for the
    /// process-wide default context, which outlives every owner.
    EvpPkeyCtx,
    EvpPkeyCtxRef,
    EvpPkeyCtxMut,
    ffi::evp_pkey_ctx_st
);

// `EVP_PKEY_CTX_free` accepts null and completely tears down a uniquely owned
// context, including provider operation state, cached parameters, retained
// key and method references, legacy state, and the allocation itself.
impl_dropped!(EvpPkeyCtx, ffi::evp_pkey_ctx_st, ffi::EVP_PKEY_CTX_free);

// `EVP_PKEY_CTX_dup` allocates a distinct context, raises or duplicates every
// retained dependency, and duplicates active provider state, so its result
// does carry one independent `EVP_PKEY_CTX_free` obligation and may be mutably
// borrowed on its own. It is still **not** registered as `CCloned`, for two
// reasons.
//
// Failure is ordinary, not exceptional: the routine returns null for any
// generation operation ("Not supported - This would need a gen_dupctx()"), so
// `EVP_PKEY_keygen_init` followed by an infallible `Clone` would abort the
// process from correct safe code. And the duplicate copies the source's
// non-owning `libctx` pointer, so it inherits that borrow — a `Clone` handing
// back an unbounded `CBox<EvpPkeyCtx>` would drop it.
//
// Duplication is exposed instead as the fallible, borrow-preserving
// `EvpPkeyCtxRef::try_dup` / `BorrowedEvpPkeyCtx::try_dup`, implemented in
// `crate::evp::pmeth_lib` beside the other `EVP_PKEY_CTX` lifecycle wrappers.

#[cfg(test)]
mod pkey_ctx_tests {
    #[test]
    fn owner_borrows_and_duplicates_independently() {
        let mut context = crate::evp::pmeth_lib::EVP_PKEY_CTX_new_from_name(None, c"RSA", None)
            .expect("EVP_PKEY_CTX_new_from_name");
        let raw = context.as_ref().as_ptr();

        assert_eq!(context.as_ref().as_ptr(), raw);
        assert_eq!(context.as_mut().as_mut_ptr(), raw.cast_mut());

        let duplicate = context.try_dup().expect("EVP_PKEY_CTX_dup");
        assert_ne!(duplicate.as_ref().as_ptr(), raw);
    }

    /// A generation operation is the documented "cannot duplicate" case. It
    /// must surface as `None`, never as an aborting infallible `Clone`.
    #[test]
    fn duplicating_a_generation_context_reports_failure() {
        let mut context = crate::evp::pmeth_lib::EVP_PKEY_CTX_new_from_name(None, c"RSA", None)
            .expect("EVP_PKEY_CTX_new_from_name");

        assert!(context.try_dup().is_some());
        assert_eq!(
            crate::evp::pmeth_gn::EVP_PKEY_keygen_init(&mut context.as_mut()),
            1
        );
        assert!(context.try_dup().is_none());
    }
}

define_ctype!(
    /// Wraps: evp_skey_st
    ///
    /// OpenSSL publishes `EVP_SKEY` as an opaque, reference-counted provider
    /// secret-key container. The C implementation retains its key-management
    /// method and uses that method to release the provider-specific key data;
    /// its allocation and fields therefore remain C-owned.
    ///
    /// Public owners use [`SharedEvpSkey`] rather than exposing a
    /// `CBox<EvpSkey>`: raising the reference count creates another owner of
    /// the same record, so neither owner may grant exclusive access.
    EvpSkey,
    EvpSkeyRef,
    EvpSkeyMut,
    ffi::evp_skey_st
);

// `EVP_SKEY_free` consumes one public reference. The final down-reference
// releases the provider key data, key-management method, lock, reference-count
// state, and allocation.
impl_dropped!(EvpSkey, ffi::evp_skey_st, ffi::EVP_SKEY_free);

// Do not register `EVP_SKEY_up_ref` as `CCloned`: a cloneable `CBox` would let
// two owners of the same record each request an exclusive borrowed handle.

/// One owned, shared-only reference to a provider secret key.
///
/// The lifetime carries the library-context dependency of the retained
/// key-management method. Keys from the process-wide default context may use
/// `'static`; keys created in an explicit context retain that context's borrow.
pub type SharedEvpSkey<'a> = crate::refcount::SharedRef<'a, EvpSkey>;

impl<'a> EvpSkeyRef<'a> {
    /// Raise this key's public reference count and return a shared-only owner.
    #[must_use]
    pub fn try_share(&self) -> Option<SharedEvpSkey<'a>> {
        // SAFETY: the handle carries a live shared borrow. The C operation only
        // mutates the atomic reference count and reports whether it created a
        // matching public release obligation.
        if unsafe { ffi::EVP_SKEY_up_ref(self.as_ptr().cast_mut()) } != 1 {
            return None;
        }

        // SAFETY: successful `EVP_SKEY_up_ref` creates exactly one matching
        // `EVP_SKEY_free` obligation. The owner retains this handle's context
        // lifetime and exposes shared access only.
        unsafe { SharedEvpSkey::from_raw(self.as_ptr().cast_mut()) }
    }
}

#[cfg(test)]
mod skey_tests {
    use core::ptr;

    use super::*;

    #[test]
    fn imported_key_and_raised_reference_are_shared_only() {
        let mut bytes = [0x53_u8; 16];
        // SAFETY: null selects the process-wide default library context, both
        // string pointers are live and NUL-terminated, and `bytes` is a live
        // buffer of the supplied length. A non-null result transfers one
        // public `EVP_SKEY` reference.
        let raw = unsafe {
            ffi::EVP_SKEY_import_raw_key(
                ptr::null_mut(),
                c"GENERIC".as_ptr(),
                bytes.as_mut_ptr(),
                bytes.len(),
                ptr::null(),
            )
        };
        // SAFETY: the default library context is process-wide, and the fresh
        // import result transfers one `EVP_SKEY_free` obligation.
        let key: SharedEvpSkey<'static> =
            unsafe { SharedEvpSkey::from_raw(raw) }.expect("EVP_SKEY_import_raw_key");

        let shared = key.as_ref().try_share().expect("EVP_SKEY_up_ref");
        assert_eq!(shared.as_ptr(), key.as_ptr());
        assert_eq!(shared.as_ref().as_ptr(), raw.cast_const());
    }
}

#[cfg(feature = "deprecated-3-0")]
/// Wraps: EVP_PKEY_decrypt_old
/// Runs the legacy private-key decrypt operation after verifying output capacity.
#[must_use]
#[allow(non_snake_case)]
pub fn EVP_PKEY_decrypt_old(
    output: &mut [u8],
    encrypted: &[u8],
    private_key: EvpPkeyRef<'_>,
) -> Option<i32> {
    let input_len = i32::try_from(encrypted.len()).ok()?;
    // SAFETY: the shared key is live and the size query retains no pointers.
    let required = unsafe { ffi::EVP_PKEY_get_size(private_key.as_ptr()) };
    if required <= 0 || output.len() < usize::try_from(required).ok()? {
        return None;
    }
    // SAFETY: `output` has at least the key's documented maximum result size,
    // and `encrypted` supplies exactly `input_len` readable bytes.
    Some(unsafe {
        ffi::EVP_PKEY_decrypt_old(
            output.as_mut_ptr(),
            encrypted.as_ptr(),
            input_len,
            private_key.as_ptr().cast_mut(),
        )
    })
}

#[cfg(feature = "deprecated-3-0")]
/// Wraps: EVP_PKEY_encrypt_old
/// Runs the legacy public-key encrypt operation after verifying output capacity.
#[must_use]
#[allow(non_snake_case)]
pub fn EVP_PKEY_encrypt_old(
    output: &mut [u8],
    plaintext: &[u8],
    public_key: EvpPkeyRef<'_>,
) -> Option<i32> {
    let input_len = i32::try_from(plaintext.len()).ok()?;
    // SAFETY: the shared key is live and the size query retains no pointers.
    let required = unsafe { ffi::EVP_PKEY_get_size(public_key.as_ptr()) };
    if required <= 0 || output.len() < usize::try_from(required).ok()? {
        return None;
    }
    // SAFETY: `output` has at least the key's documented maximum result size,
    // and `plaintext` supplies exactly `input_len` readable bytes.
    Some(unsafe {
        ffi::EVP_PKEY_encrypt_old(
            output.as_mut_ptr(),
            plaintext.as_ptr(),
            input_len,
            public_key.as_ptr().cast_mut(),
        )
    })
}

define_ctype!(
    /// Wraps: evp_md_st
    ///
    /// OpenSSL publishes `EVP_MD` as an opaque digest implementation.
    /// Provider-backed records retain their provider and are reference
    /// counted, while legacy records are static. Both kinds use the public
    /// `EVP_MD_up_ref` / `EVP_MD_free` pair; for cached or static records
    /// those operations are deliberately no-ops.
    ///
    /// An owning reference is exposed as [`SharedEvpMd`], not as a public
    /// `CBox<EvpMd>`, because fetches and reference-count increments may name
    /// the same record and therefore cannot grant exclusive access.
    EvpMd,
    EvpMdRef,
    EvpMdMut,
    ffi::evp_md_st
);

// `EVP_MD_free` is the public down-reference operation. Depending on the
// digest's origin and cache policy it either decrements the dynamic record or
// is a no-op, exactly matching `EVP_MD_up_ref`.
impl_dropped!(EvpMd, ffi::evp_md_st, ffi::EVP_MD_free);

// Do not register `EVP_MD_up_ref` as `CCloned`: that would make `CBox<EvpMd>`
// cloneable even though every clone could call `as_mut` on the same record.
// `SharedEvpMd` intentionally grants shared access only.

/// One owned reference to a digest implementation.
///
/// The lifetime carries the library-context dependency of a fetched digest.
/// A digest selected from the default context may use `'static`; a fetch from
/// an explicit context must use that context's borrow.
pub type SharedEvpMd<'a> = crate::refcount::SharedRef<'a, EvpMd>;

impl<'a> EvpMdRef<'a> {
    /// Raise this digest's public reference and return a shared-only owner.
    #[must_use]
    pub fn try_share(&self) -> Option<SharedEvpMd<'a>> {
        // SAFETY: the handle carries a live shared borrow. OpenSSL may update
        // the dynamic record's atomic reference count but does not otherwise
        // mutate it, and reports whether it created the matching public
        // release obligation.
        if unsafe { ffi::EVP_MD_up_ref(self.as_ptr().cast_mut()) } != 1 {
            return None;
        }

        // SAFETY: successful `EVP_MD_up_ref` creates one matching
        // `EVP_MD_free` obligation. The share retains the handle's library-
        // context lifetime and exposes no exclusive access.
        unsafe { SharedEvpMd::from_raw(self.as_ptr().cast_mut()) }
    }
}

#[cfg(test)]
mod md_tests {
    use core::ptr;

    use ffibox::CBox;

    use super::*;

    #[test]
    fn fetched_digest_and_raised_reference_are_shared_only() {
        // SAFETY: null selects the process-wide default library context, the
        // algorithm name is a live NUL-terminated string, and a null property
        // query requests the default selection. A non-null result transfers
        // one public EVP_MD reference.
        let raw = unsafe { ffi::EVP_MD_fetch(ptr::null_mut(), c"SHA2-256".as_ptr(), ptr::null()) };
        // SAFETY: the default library context is process-wide, and the fresh
        // fetch result transfers one `EVP_MD_free` obligation.
        let digest: SharedEvpMd<'static> =
            unsafe { SharedEvpMd::from_raw(raw) }.expect("EVP_MD_fetch");

        let shared = digest.as_ref().try_share().expect("EVP_MD_up_ref");
        assert_eq!(shared.as_ptr(), digest.as_ptr());
        assert_eq!(shared.as_ref().as_ptr(), raw.cast_const());
    }

    /// A cached fetch hands back a record the library context's method store
    /// owns, not a counted reference of its own — the reason [`SharedEvpMd`]
    /// carries the fetching context's borrow instead of being `'static`.
    #[test]
    fn a_cached_fetch_shares_one_library_context_owned_record() {
        // SAFETY: the constructor returns null or a fresh, fully initialized
        // context carrying one ownership obligation, transferred once here.
        let libctx =
            unsafe { CBox::<crate::bio::context::OsslLibCtx>::from_raw(ffi::OSSL_LIB_CTX_new()) }
                .expect("OSSL_LIB_CTX_new");

        let fetch = || {
            // SAFETY: `libctx` is live for the whole closure body, the
            // algorithm name is NUL-terminated, and a null property query
            // selects the default implementation.
            unsafe { ffi::EVP_MD_fetch(libctx.as_ptr(), c"SHA2-256".as_ptr(), ptr::null()) }
        };

        let first = fetch();
        assert!(!first.is_null());
        // Two fetches name one record: caching stores the constructed
        // method and hands it back without a reference for the caller.
        assert_eq!(first, fetch());

        // SAFETY: the record is live and owned by `libctx`'s method store; on
        // the cached path the public up-reference reports success without
        // touching a count, which is why `try_share` may not treat its result
        // as sole ownership.
        let borrowed = unsafe { EvpMdRef::from_ptr(first) }.expect("fetched method");
        let share = borrowed.try_share().expect("public up-reference");
        assert_eq!(share.as_ptr(), first);
        // The share's own release runs here and changes nothing.
        drop(share);

        // Balancing both fetches still leaves the record usable, because every
        // public release is a no-op for a cached method.
        for _ in 0..2 {
            // SAFETY: releasing a cached record is the documented no-op path;
            // the store keeps the only real reference.
            unsafe { ffi::EVP_MD_free(first) };
        }
        // SAFETY: the record is still live, as the previous releases show.
        assert!(!unsafe { ffi::EVP_MD_get0_name(first) }.is_null());

        // `libctx` frees the record here, which is the dependency
        // `SharedEvpMd<'a>` exists to express.
        drop(libctx);
    }
}

/// Wraps: EVP_PKEY_gen_cb
///
/// Callable handle for OpenSSL's key-generation progress callback.
#[derive(Clone, Copy)]
pub struct EvpPkeyGenCallback(ffi::EVP_PKEY_gen_cb);

impl EvpPkeyGenCallback {
    /// Adopts a raw callback, returning `None` for a null function pointer.
    ///
    /// # Safety
    ///
    /// A non-null callback must accept every live generation context supplied
    /// by OpenSSL, obey its thread-safety rules, return a valid C `int`, and
    /// never unwind across the C ABI.
    #[must_use]
    pub unsafe fn from_raw(raw: ffi::EVP_PKEY_gen_cb) -> Option<Self> {
        raw.map(|callback| Self(Some(callback)))
    }

    pub(crate) fn as_raw(self) -> ffi::EVP_PKEY_gen_cb {
        self.0
    }

    /// Invokes the callback with an exclusively borrowed operation context.
    pub fn call(self, ctx: &mut EvpPkeyCtxMut<'_>) -> i32 {
        let callback = self.0.expect("EvpPkeyGenCallback is non-null");
        // SAFETY: construction established the callback contract and the
        // exclusive handle supplies a live context for this invocation.
        unsafe { callback(ctx.as_mut_ptr()) }
    }
}

#[cfg(test)]
mod pkey_gen_callback_tests {
    use ffibox::CBox;

    use super::*;

    unsafe extern "C" fn accepts_context(ctx: *mut ffi::evp_pkey_ctx_st) -> i32 {
        i32::from(!ctx.is_null())
    }

    #[test]
    fn callback_handle_invokes_with_a_typed_context() {
        // SAFETY: null selects the process-wide library context, the algorithm
        // name is static, and null selects the default properties.
        let raw = unsafe {
            ffi::EVP_PKEY_CTX_new_from_name(
                core::ptr::null_mut(),
                c"RSA".as_ptr(),
                core::ptr::null(),
            )
        };
        // SAFETY: a non-null result transfers one context-free obligation.
        let mut ctx = unsafe { CBox::<EvpPkeyCtx>::from_raw(raw) }.expect("RSA context");
        // SAFETY: the test callback accepts every non-null live context and
        // cannot unwind or retain its argument.
        let callback = unsafe { EvpPkeyGenCallback::from_raw(Some(accepts_context)) }
            .expect("non-null callback");
        assert_eq!(callback.call(&mut ctx.as_mut()), 1);
    }
}

define_ctype!(
    /// Wraps: evp_kdf_st
    ///
    /// OpenSSL publishes `EVP_KDF` as an opaque provider method. Provider-
    /// backed records retain their provider and own their algorithm name;
    /// their description and dispatch functions borrow from that provider.
    ///
    /// Fetches and reference increments can name the same cached record. Safe
    /// owners therefore use [`SharedEvpKdf`] and expose shared borrows only.
    EvpKdf,
    EvpKdfRef,
    EvpKdfMut,
    ffi::evp_kdf_st
);

// `EVP_KDF_free` consumes one public reference. A no-store record is down-
// referenced and releases its provider, name, and allocation on the final
// count; cached records deliberately pair this with a no-op up-reference.
impl_dropped!(EvpKdf, ffi::evp_kdf_st, ffi::EVP_KDF_free);

// Do not register `EVP_KDF_up_ref` as `CCloned`: cloning a `CBox` would let
// two owners of one method each obtain an exclusive borrowed handle.

/// One owned, shared-only reference to an `EVP_KDF` method.
///
/// The lifetime carries the library-context dependency of a fetched method.
/// A method fetched from the process-wide default context may use `'static`.
pub type SharedEvpKdf<'a> = crate::refcount::SharedRef<'a, EvpKdf>;

impl<'a> EvpKdfRef<'a> {
    /// Raise this method's public reference and return a shared-only owner.
    #[must_use]
    pub fn try_share(&self) -> Option<SharedEvpKdf<'a>> {
        // SAFETY: the handle carries a live shared borrow. OpenSSL only
        // changes the reference count (or performs the paired cached no-op).
        if unsafe { ffi::EVP_KDF_up_ref(self.as_ptr().cast_mut()) } != 1 {
            return None;
        }

        // SAFETY: successful up-reference creates one matching public free
        // obligation, and the owner retains this handle's context lifetime.
        unsafe { SharedEvpKdf::from_raw(self.as_ptr().cast_mut()) }
    }
}

#[cfg(test)]
mod kdf_tests {
    use core::ptr;

    use ffibox::CBox;

    use super::*;

    #[test]
    fn fetched_kdf_and_raised_reference_are_shared_only() {
        // SAFETY: null selects the process-wide default library context, the
        // algorithm name is live and NUL-terminated, and null selects default
        // properties. A non-null result transfers one public reference.
        let raw = unsafe { ffi::EVP_KDF_fetch(ptr::null_mut(), c"HKDF".as_ptr(), ptr::null()) };
        // SAFETY: the default context is process-wide and the fetch result
        // transfers one matching `EVP_KDF_free` obligation.
        let kdf: SharedEvpKdf<'static> =
            unsafe { SharedEvpKdf::from_raw(raw) }.expect("EVP_KDF_fetch");

        let shared = kdf.as_ref().try_share().expect("EVP_KDF_up_ref");
        assert_eq!(shared.as_ptr(), kdf.as_ptr());
        assert_eq!(shared.as_ref().as_ptr(), raw.cast_const());
    }

    /// A cached fetch hands back a record the library context's method store
    /// owns, not a counted reference of its own — the reason [`SharedEvpKdf`]
    /// carries the fetching context's borrow instead of being `'static`.
    #[test]
    fn a_cached_fetch_shares_one_library_context_owned_record() {
        // SAFETY: the constructor returns null or a fresh, fully initialized
        // context carrying one ownership obligation, transferred once here.
        let libctx =
            unsafe { CBox::<crate::bio::context::OsslLibCtx>::from_raw(ffi::OSSL_LIB_CTX_new()) }
                .expect("OSSL_LIB_CTX_new");

        let fetch = || {
            // SAFETY: `libctx` is live for the whole closure body, the
            // algorithm name is NUL-terminated, and a null property query
            // selects the default implementation.
            unsafe { ffi::EVP_KDF_fetch(libctx.as_ptr(), c"HKDF".as_ptr(), ptr::null()) }
        };

        let first = fetch();
        assert!(!first.is_null());
        // Two fetches name one record: caching stores the constructed
        // method and hands it back without a reference for the caller.
        assert_eq!(first, fetch());

        // SAFETY: the record is live and owned by `libctx`'s method store; on
        // the cached path the public up-reference reports success without
        // touching a count, which is why `try_share` may not treat its result
        // as sole ownership.
        let borrowed = unsafe { EvpKdfRef::from_ptr(first) }.expect("fetched method");
        let share = borrowed.try_share().expect("public up-reference");
        assert_eq!(share.as_ptr(), first);
        // The share's own release runs here and changes nothing.
        drop(share);

        // Balancing both fetches still leaves the record usable, because every
        // public release is a no-op for a cached method.
        for _ in 0..2 {
            // SAFETY: releasing a cached record is the documented no-op path;
            // the store keeps the only real reference.
            unsafe { ffi::EVP_KDF_free(first) };
        }
        // SAFETY: the record is still live, as the previous releases show.
        assert!(!unsafe { ffi::EVP_KDF_get0_name(first) }.is_null());

        // `libctx` frees the record here, which is the dependency
        // `SharedEvpKdf<'a>` exists to express.
        drop(libctx);
    }
}

define_ctype!(
    /// Wraps: evp_mac_st
    ///
    /// Pointer-compatible target for OpenSSL's opaque provider MAC method.
    /// The record retains its provider, owns a copy of its algorithm name,
    /// and borrows its dispatch functions and description from that provider.
    /// Its private layout remains behind OpenSSL's public call surface.
    ///
    /// Public fetch and up-reference operations can name one cached record,
    /// so safe owning APIs use [`SharedEvpMac`] and grant shared access only.
    /// A fetched method also borrows the `OSSL_LIB_CTX` whose method store owns
    /// a cached record; that dependency is carried by the owner's lifetime.
    EvpMac,
    EvpMacRef,
    EvpMacMut,
    ffi::evp_mac_st
);

// `EVP_MAC_free` is the public release operation. For an uncached `no_store`
// method it decrements the reference count and releases the copied name,
// provider, and allocation on the final count; for a cached method it is the
// deliberate no-op paired with `EVP_MAC_up_ref`.
impl_dropped!(EvpMac, ffi::evp_mac_st, ffi::EVP_MAC_free);

// Do not register `EVP_MAC_up_ref` as `CCloned`: cloning a `CBox` would let
// two owners of one method each obtain an exclusive borrowed handle.

/// One owned, shared-only reference to a provider MAC method.
///
/// The lifetime carries the library-context dependency of a fetched method.
/// A method selected from the process-wide default context may use `'static`.
pub type SharedEvpMac<'a> = crate::refcount::SharedRef<'a, EvpMac>;

impl<'a> EvpMacRef<'a> {
    /// Raise this method's public reference and return a shared-only owner.
    #[must_use]
    pub fn try_share(&self) -> Option<SharedEvpMac<'a>> {
        // SAFETY: the handle carries a live shared borrow. OpenSSL may update
        // a no-store method's atomic reference count but otherwise leaves the
        // method unchanged, and reports whether it created the paired public
        // release obligation.
        if unsafe { ffi::EVP_MAC_up_ref(self.as_ptr().cast_mut()) } != 1 {
            return None;
        }

        // SAFETY: successful `EVP_MAC_up_ref` creates one matching
        // `EVP_MAC_free` obligation (or the paired cached no-op). The owner
        // retains this handle's library-context lifetime and grants no
        // exclusive access.
        unsafe { SharedEvpMac::from_raw(self.as_ptr().cast_mut()) }
    }
}

#[cfg(test)]
mod mac_tests {
    use core::{mem::size_of, ptr};

    use ffibox::{CBox, CCell, CDropped};

    use super::*;

    fn assert_owned_cell<T: CCell + CDropped>() {}

    #[test]
    fn fetched_mac_and_raised_reference_are_shared_only() {
        assert_owned_cell::<EvpMac>();

        // SAFETY: null selects the process-wide default library context, the
        // algorithm name is a live NUL-terminated string, and a null property
        // query selects the default implementation. A non-null result carries
        // one public EVP_MAC release obligation.
        let raw = unsafe { ffi::EVP_MAC_fetch(ptr::null_mut(), c"HMAC".as_ptr(), ptr::null()) };
        // SAFETY: the default context is process-wide, and the fetched result
        // transfers its public release obligation once.
        let method: SharedEvpMac<'static> =
            unsafe { SharedEvpMac::from_raw(raw) }.expect("EVP_MAC_fetch");

        let shared = method.as_ref().try_share().expect("EVP_MAC_up_ref");
        assert_eq!(shared.as_ptr(), method.as_ptr());
        assert_eq!(shared.as_ref().as_ptr(), raw.cast_const());
    }

    #[test]
    fn opaque_mac_handles_are_pointer_sized() {
        assert_eq!(
            size_of::<EvpMacRef<'static>>(),
            size_of::<*const ffi::evp_mac_st>()
        );
        assert_eq!(
            size_of::<EvpMacMut<'static>>(),
            size_of::<*mut ffi::evp_mac_st>()
        );
        assert_eq!(
            size_of::<SharedEvpMac<'static>>(),
            size_of::<*mut ffi::evp_mac_st>()
        );
    }

    /// A cached fetch hands back a record the library context's method store
    /// owns, not a counted reference of its own — the reason [`SharedEvpMac`]
    /// carries the fetching context's borrow instead of being `'static`.
    #[test]
    fn a_cached_fetch_shares_one_library_context_owned_record() {
        // SAFETY: the constructor returns null or a fresh, fully initialized
        // context carrying one ownership obligation, transferred once here.
        let libctx =
            unsafe { CBox::<crate::bio::context::OsslLibCtx>::from_raw(ffi::OSSL_LIB_CTX_new()) }
                .expect("OSSL_LIB_CTX_new");

        let fetch = || {
            // SAFETY: `libctx` is live for the whole closure body, the
            // algorithm name is NUL-terminated, and a null property query
            // selects the default implementation.
            unsafe { ffi::EVP_MAC_fetch(libctx.as_ptr(), c"HMAC".as_ptr(), ptr::null()) }
        };

        let first = fetch();
        assert!(!first.is_null());
        // Two fetches name one record: caching stores the constructed
        // method and hands it back without a reference for the caller.
        assert_eq!(first, fetch());

        // SAFETY: the record is live and owned by `libctx`'s method store; on
        // the cached path the public up-reference reports success without
        // touching a count, which is why `try_share` may not treat its result
        // as sole ownership.
        let borrowed = unsafe { EvpMacRef::from_ptr(first) }.expect("fetched method");
        let share = borrowed.try_share().expect("public up-reference");
        assert_eq!(share.as_ptr(), first);
        // The share's own release runs here and changes nothing.
        drop(share);

        // Balancing both fetches still leaves the record usable, because every
        // public release is a no-op for a cached method.
        for _ in 0..2 {
            // SAFETY: releasing a cached record is the documented no-op path;
            // the store keeps the only real reference.
            unsafe { ffi::EVP_MAC_free(first) };
        }
        // SAFETY: the record is still live, as the previous releases show.
        assert!(!unsafe { ffi::EVP_MAC_get0_name(first) }.is_null());

        // `libctx` frees the record here, which is the dependency
        // `SharedEvpMac<'a>` exists to express.
        drop(libctx);
    }
}
