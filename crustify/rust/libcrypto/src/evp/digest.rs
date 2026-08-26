//! Wrappers assigned from `crypto/evp/digest.c`.

#![allow(non_snake_case)]

use core::ffi::{CStr, c_void};
use core::marker::PhantomData;
use core::ptr::{self, NonNull};

use ffibox::{CBox, CSlice};
use libcrypto_sys as ffi;

use crate::bio::context::OsslLibCtxRef;
use crate::core::openssl_core::{
    OsslParam, OsslParamArray, OsslParamListMut, OsslParamListRef, OsslParamRef,
    terminated_param_len,
};
use crate::evp::evp::{EvpMdRef, SharedEvpMd};
use crate::evp::evp_local::{EvpMdCtx, EvpMdCtxMut, EvpMdCtxRef};

fn optional_cstr(value: Option<&CStr>) -> *const core::ffi::c_char {
    value.map_or(ptr::null(), CStr::as_ptr)
}

/// Checks a finalization buffer against the byte count OpenSSL will write.
///
/// `EVP_DigestFinal_ex` takes no capacity: it finalizes into `md` with
/// `EVP_MD_CTX_get_size(ctx)`, the macro spelling of `EVP_MD_CTX_get_size_ex`
/// queried here. Checking the same number is therefore what bounds the write,
/// and it is checked under the caller's exclusive borrow so nothing can change
/// the context in between.
fn output_fits(ctx: EvpMdCtxRef<'_>, output: &[u8]) -> bool {
    // SAFETY: the shared handle is live and the size query retains nothing.
    let required = unsafe { ffi::EVP_MD_CTX_get_size_ex(ctx.as_ptr()) };
    required >= 0 && usize::try_from(required).is_ok_and(|len| output.len() >= len)
}

/// A trusted serialization produced by [`EVP_MD_CTX_serialize`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SerializedDigestState {
    bytes: Vec<u8>,
}

impl SerializedDigestState {
    /// Views the provider serialization for storage or transport.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// A borrowed, key-terminated parameter table advertised by a digest context.
pub struct DigestParamTable<'a> {
    next: NonNull<ffi::ossl_param_st>,
    borrow: PhantomData<EvpMdCtxRef<'a>>,
}

impl<'a> Iterator for DigestParamTable<'a> {
    type Item = OsslParamRef<'a, 'a>;

    fn next(&mut self) -> Option<Self::Item> {
        // SAFETY: OpenSSL publishes a contiguous key-terminated table and the
        // context borrow keeps it live.
        let item = unsafe { OsslParamRef::from_ptr(self.next.as_ptr()) }
            .expect("non-null digest parameter table entry");
        item.key()?;
        // SAFETY: a non-null key means the initialized terminator follows at a
        // later position, so advancing by one stays within the table.
        self.next = unsafe { NonNull::new_unchecked(self.next.as_ptr().add(1)) };
        Some(item)
    }
}

/// Wraps: EVP_MD_get_params
/// Retrieves digest implementation parameters into a terminated descriptor array.
pub fn EVP_MD_get_params(digest: Option<EvpMdRef<'_>>, params: &mut OsslParamArray<'_>) -> bool {
    let digest = digest.map_or(ptr::null(), |digest| digest.as_ptr());
    // SAFETY: null is accepted for the digest. The parameter array owns an
    // initialized terminator and exclusively borrows every writable data run.
    unsafe { ffi::EVP_MD_get_params(digest, params.as_mut_ptr()) == 1 }
}

/// Wraps: EVP_MD_gettable_ctx_params
/// Returns the provider-owned descriptor run for retrievable context parameters.
#[must_use]
pub fn EVP_MD_gettable_ctx_params<'md>(
    md: Option<EvpMdRef<'md>>,
) -> Option<CSlice<'md, OsslParam<'md>>> {
    let md = md.map_or(ptr::null(), |md| md.as_ptr());
    // SAFETY: null is accepted; a non-null shared digest remains live for `'md`.
    let params = unsafe { ffi::EVP_MD_gettable_ctx_params(md) };
    // SAFETY: a non-null provider result is a constant, initialized,
    // null-key-terminated descriptor array retained by the digest/provider.
    let len = unsafe { terminated_param_len(params) }?;
    let params = NonNull::new(params.cast_mut().cast::<OsslParam<'md>>())?;
    // SAFETY: the scan established `len` initialized entries before the
    // terminator and the digest borrow retains their provider for `'md`.
    Some(unsafe { CSlice::from_raw_parts(params, len) })
}

/// Wraps: EVP_MD_gettable_params
/// Returns the provider-owned descriptor run for retrievable digest parameters.
#[must_use]
pub fn EVP_MD_gettable_params<'md>(
    digest: Option<EvpMdRef<'md>>,
) -> Option<CSlice<'md, OsslParam<'md>>> {
    let digest = digest.map_or(ptr::null(), |digest| digest.as_ptr());
    // SAFETY: null is accepted; a non-null shared digest remains live for `'md`.
    let params = unsafe { ffi::EVP_MD_gettable_params(digest) };
    // SAFETY: a non-null provider result is a constant, initialized,
    // null-key-terminated descriptor array retained by the digest/provider.
    let len = unsafe { terminated_param_len(params) }?;
    let params = NonNull::new(params.cast_mut().cast::<OsslParam<'md>>())?;
    // SAFETY: the scan established `len` initialized entries before the
    // terminator and the digest borrow retains their provider for `'md`.
    Some(unsafe { CSlice::from_raw_parts(params, len) })
}

/// Wraps: EVP_MD_settable_ctx_params
/// Returns the provider-owned descriptor run for settable context parameters.
#[must_use]
pub fn EVP_MD_settable_ctx_params<'md>(
    md: Option<EvpMdRef<'md>>,
) -> Option<CSlice<'md, OsslParam<'md>>> {
    let md = md.map_or(ptr::null(), |md| md.as_ptr());
    // SAFETY: null is accepted; a non-null shared digest remains live for `'md`.
    let params = unsafe { ffi::EVP_MD_settable_ctx_params(md) };
    // SAFETY: a non-null provider result is a constant, initialized,
    // null-key-terminated descriptor array retained by the digest/provider.
    let len = unsafe { terminated_param_len(params) }?;
    let params = NonNull::new(params.cast_mut().cast::<OsslParam<'md>>())?;
    // SAFETY: the scan established `len` initialized entries before the
    // terminator and the digest borrow retains their provider for `'md`.
    Some(unsafe { CSlice::from_raw_parts(params, len) })
}

/// Wraps: EVP_Digest
/// Computes a fixed-size digest after checking output capacity.
///
/// C never learns `output`'s length: the private context `EVP_Digest` builds
/// finalizes with `EVP_MD_CTX_get_size(ctx)` bytes, so this wrapper is the only
/// bound on the write. `EVP_MD_get_size` is that same number for every
/// non-extendable digest, and for an extendable one it is `0` while the context
/// size is negative, which makes `EVP_DigestFinal_ex` fail before writing —
/// see `every_provided_digest_bounds_its_one_shot_output`.
#[allow(non_snake_case)]
pub fn EVP_Digest(data: &[u8], output: &mut [u8], digest: EvpMdRef<'_>) -> Result<usize, i32> {
    // SAFETY: the digest handle is live and the query retains nothing.
    let required = unsafe { ffi::EVP_MD_get_size(digest.as_ptr()) };
    if required < 0 || !usize::try_from(required).is_ok_and(|len| output.len() >= len) {
        return Err(0);
    }
    let mut written = 0_u32;
    // SAFETY: the slices supply exact readable and writable extents, the
    // digest is live, and null is the only supported ENGINE argument.
    let status = unsafe {
        ffi::EVP_Digest(
            data.as_ptr().cast(),
            data.len(),
            output.as_mut_ptr(),
            &mut written,
            digest.as_ptr(),
            ptr::null_mut(),
        )
    };
    (status == 1).then_some(written as usize).ok_or(status)
}

/// Wraps: EVP_DigestFinal
/// Finalizes and resets a digest context.
#[allow(non_snake_case)]
pub fn EVP_DigestFinal(ctx: &mut EvpMdCtxMut<'_>, output: &mut [u8]) -> Result<usize, i32> {
    if !output_fits(ctx.as_ref(), output) {
        return Err(0);
    }
    let mut written = 0_u32;
    // SAFETY: capacity was checked and the exclusive handle permits finalizing
    // and resetting the context.
    let status =
        unsafe { ffi::EVP_DigestFinal(ctx.as_mut_ptr(), output.as_mut_ptr(), &mut written) };
    (status == 1).then_some(written as usize).ok_or(status)
}

/// Wraps: EVP_DigestFinalXOF
/// Finalizes an extendable-output function into exactly `output.len()` bytes.
///
/// The length is both the requested output size and the buffer capacity:
/// `EVP_DigestFinalXOF` publishes it as `OSSL_DIGEST_PARAM_XOFLEN` before
/// finalizing, and also passes it as the provider's output-size argument, which
/// a fixed-size digest rejects when it is short of its own digest length.
#[allow(non_snake_case)]
pub fn EVP_DigestFinalXOF(ctx: &mut EvpMdCtxMut<'_>, output: &mut [u8]) -> i32 {
    // SAFETY: the exclusive context is live and the slice supplies the exact
    // writable extent, which is the length OpenSSL both requests and bounds
    // the finalization by.
    unsafe { ffi::EVP_DigestFinalXOF(ctx.as_mut_ptr(), output.as_mut_ptr(), output.len()) }
}

/// Wraps: EVP_DigestFinal_ex
/// Finalizes without resetting the context.
#[allow(non_snake_case)]
pub fn EVP_DigestFinal_ex(ctx: &mut EvpMdCtxMut<'_>, output: &mut [u8]) -> Result<usize, i32> {
    if !output_fits(ctx.as_ref(), output) {
        return Err(0);
    }
    let mut written = 0_u32;
    // SAFETY: capacity was checked and the exclusive handle permits finalizing
    // the provider state.
    let status =
        unsafe { ffi::EVP_DigestFinal_ex(ctx.as_mut_ptr(), output.as_mut_ptr(), &mut written) };
    (status == 1).then_some(written as usize).ok_or(status)
}

/// Wraps: EVP_DigestInit
#[allow(non_snake_case)]
pub fn EVP_DigestInit(ctx: &mut EvpMdCtxMut<'_>, digest: Option<EvpMdRef<'_>>) -> i32 {
    let digest = digest.map_or(ptr::null(), |digest| digest.as_ptr());
    // SAFETY: both handles are live; OpenSSL retains any provider digest it
    // stores in the context.
    unsafe { ffi::EVP_DigestInit(ctx.as_mut_ptr(), digest) }
}

/// Wraps: EVP_DigestInit_ex
#[allow(non_snake_case)]
pub fn EVP_DigestInit_ex(ctx: &mut EvpMdCtxMut<'_>, digest: Option<EvpMdRef<'_>>) -> i32 {
    let digest = digest.map_or(ptr::null(), |digest| digest.as_ptr());
    // SAFETY: as `EVP_DigestInit`; null is the only supported ENGINE value.
    unsafe { ffi::EVP_DigestInit_ex(ctx.as_mut_ptr(), digest, ptr::null_mut()) }
}

/// Wraps: EVP_DigestInit_ex2
#[allow(non_snake_case)]
pub fn EVP_DigestInit_ex2(
    ctx: &mut EvpMdCtxMut<'_>,
    digest: Option<EvpMdRef<'_>>,
    params: Option<&OsslParamListRef<'_, '_>>,
) -> i32 {
    let digest = digest.map_or(ptr::null(), |digest| digest.as_ptr());
    let params = params.map_or(ptr::null(), OsslParamListRef::as_ptr);
    // SAFETY: the typed handles and validated terminated parameter list remain
    // live for the synchronous call.
    unsafe { ffi::EVP_DigestInit_ex2(ctx.as_mut_ptr(), digest, params) }
}

/// Wraps: EVP_DigestSqueeze
/// Squeezes `output.len()` further bytes out of an extendable-output function.
#[allow(non_snake_case)]
pub fn EVP_DigestSqueeze(ctx: &mut EvpMdCtxMut<'_>, output: &mut [u8]) -> i32 {
    // SAFETY: the exclusive context and writable slice are live for the call,
    // and the squeeze writes exactly the requested count.
    unsafe { ffi::EVP_DigestSqueeze(ctx.as_mut_ptr(), output.as_mut_ptr(), output.len()) }
}

/// Wraps: EVP_DigestUpdate
#[allow(non_snake_case)]
pub fn EVP_DigestUpdate(ctx: &mut EvpMdCtxMut<'_>, data: &[u8]) -> i32 {
    // SAFETY: `data` supplies exactly the readable byte count; OpenSSL accepts
    // an empty run before inspecting its pointer.
    unsafe { ffi::EVP_DigestUpdate(ctx.as_mut_ptr(), data.as_ptr().cast(), data.len()) }
}

/// Wraps: EVP_MD_CTX_copy
#[allow(non_snake_case)]
pub fn EVP_MD_CTX_copy(output: &mut EvpMdCtxMut<'_>, input: EvpMdCtxRef<'_>) -> i32 {
    // SAFETY: the exclusive/shared handles prevent aliasing and keep both
    // contexts live for the deep copy.
    unsafe { ffi::EVP_MD_CTX_copy(output.as_mut_ptr(), input.as_ptr()) }
}

/// Wraps: EVP_MD_CTX_copy_ex
#[allow(non_snake_case)]
pub fn EVP_MD_CTX_copy_ex(output: &mut EvpMdCtxMut<'_>, input: EvpMdCtxRef<'_>) -> i32 {
    // SAFETY: as `EVP_MD_CTX_copy`.
    unsafe { ffi::EVP_MD_CTX_copy_ex(output.as_mut_ptr(), input.as_ptr()) }
}

/// Wraps: EVP_MD_CTX_ctrl
///
/// # Safety
/// `payload` must satisfy the selected command's type, alignment, extent,
/// initialization, mutability, and lifetime contract.
#[allow(non_snake_case)]
pub unsafe fn EVP_MD_CTX_ctrl(
    ctx: &mut EvpMdCtxMut<'_>,
    command: i32,
    integer: i32,
    payload: Option<NonNull<c_void>>,
) -> i32 {
    let payload = payload.map_or(ptr::null_mut(), NonNull::as_ptr);
    // SAFETY: the caller establishes the untyped command payload contract.
    unsafe { ffi::EVP_MD_CTX_ctrl(ctx.as_mut_ptr(), command, integer, payload) }
}

/// Wraps: EVP_MD_CTX_deserialize
#[allow(non_snake_case)]
pub fn EVP_MD_CTX_deserialize(ctx: &mut EvpMdCtxMut<'_>, state: &SerializedDigestState) -> i32 {
    // SAFETY: the opaque state is only constructed by OpenSSL serialization,
    // and the exclusive handle permits replacing context state.
    unsafe {
        ffi::EVP_MD_CTX_deserialize(ctx.as_mut_ptr(), state.bytes.as_ptr(), state.bytes.len())
    }
}

/// Wraps: EVP_MD_CTX_dup
#[allow(non_snake_case)]
pub fn EVP_MD_CTX_dup(input: EvpMdCtxRef<'_>) -> Option<CBox<EvpMdCtx>> {
    // SAFETY: OpenSSL returns null or an independent initialized copy.
    let raw = unsafe { ffi::EVP_MD_CTX_dup(input.as_ptr()) };
    // SAFETY: a non-null result transfers one free obligation.
    unsafe { CBox::from_raw(raw) }
}

/// Wraps: EVP_MD_CTX_free
#[allow(non_snake_case)]
pub fn EVP_MD_CTX_free(ctx: Option<CBox<EvpMdCtx>>) {
    drop(ctx);
}

/// Wraps: EVP_MD_CTX_get_params
#[allow(non_snake_case)]
pub fn EVP_MD_CTX_get_params(
    ctx: &mut EvpMdCtxMut<'_>,
    params: &mut OsslParamListMut<'_, '_>,
) -> i32 {
    // SAFETY: the writable terminated list and exclusive context are live.
    unsafe { ffi::EVP_MD_CTX_get_params(ctx.as_mut_ptr(), params.as_mut_ptr()) }
}

/// Wraps: EVP_MD_CTX_gettable_params
#[allow(non_snake_case)]
pub fn EVP_MD_CTX_gettable_params<'a>(ctx: EvpMdCtxRef<'a>) -> Option<DigestParamTable<'a>> {
    // SAFETY: the implementation only queries metadata; the returned table is
    // bounded by the live context borrow.
    let raw = unsafe { ffi::EVP_MD_CTX_gettable_params(ctx.as_ptr().cast_mut()) };
    NonNull::new(raw.cast_mut()).map(|next| DigestParamTable {
        next,
        borrow: PhantomData,
    })
}

/// Wraps: EVP_MD_CTX_new
#[allow(non_snake_case)]
pub fn EVP_MD_CTX_new() -> Option<CBox<EvpMdCtx>> {
    // SAFETY: OpenSSL returns null or a fresh initialized context.
    let raw = unsafe { ffi::EVP_MD_CTX_new() };
    // SAFETY: a non-null result transfers its sole free obligation.
    unsafe { CBox::from_raw(raw) }
}

/// Wraps: EVP_MD_CTX_reset
#[allow(non_snake_case)]
pub fn EVP_MD_CTX_reset(ctx: &mut EvpMdCtxMut<'_>) -> i32 {
    // SAFETY: the exclusive handle permits disposing retained fields while
    // keeping the allocation reusable.
    unsafe { ffi::EVP_MD_CTX_reset(ctx.as_mut_ptr()) }
}

/// Wraps: EVP_MD_CTX_serialize
#[allow(non_snake_case)]
pub fn EVP_MD_CTX_serialize(ctx: &mut EvpMdCtxMut<'_>) -> Result<SerializedDigestState, i32> {
    let mut len = 0usize;
    // SAFETY: null output queries the size and `len` is writable.
    let status = unsafe { ffi::EVP_MD_CTX_serialize(ctx.as_mut_ptr(), ptr::null_mut(), &mut len) };
    if status != 1 {
        return Err(status);
    }
    let mut bytes = vec![0_u8; len];
    // SAFETY: `bytes` supplies the capacity in `len`; exclusive access keeps
    // the state stable between query and serialization.
    let status =
        unsafe { ffi::EVP_MD_CTX_serialize(ctx.as_mut_ptr(), bytes.as_mut_ptr(), &mut len) };
    if status != 1 || len > bytes.len() {
        return Err(status);
    }
    bytes.truncate(len);
    Ok(SerializedDigestState { bytes })
}

/// Wraps: EVP_MD_CTX_set_params
#[allow(non_snake_case)]
pub fn EVP_MD_CTX_set_params(ctx: &mut EvpMdCtxMut<'_>, params: &OsslParamListRef<'_, '_>) -> i32 {
    // SAFETY: the validated read-only list and exclusive context remain live.
    unsafe { ffi::EVP_MD_CTX_set_params(ctx.as_mut_ptr(), params.as_ptr()) }
}

/// Wraps: EVP_MD_CTX_settable_params
#[allow(non_snake_case)]
pub fn EVP_MD_CTX_settable_params<'a>(ctx: EvpMdCtxRef<'a>) -> Option<DigestParamTable<'a>> {
    // SAFETY: the implementation only queries metadata and the returned table
    // is bounded by the context borrow.
    let raw = unsafe { ffi::EVP_MD_CTX_settable_params(ctx.as_ptr().cast_mut()) };
    NonNull::new(raw.cast_mut()).map(|next| DigestParamTable {
        next,
        borrow: PhantomData,
    })
}

/// Wraps: EVP_MD_do_all_provided
#[allow(non_snake_case)]
pub fn EVP_MD_do_all_provided<F>(libctx: Option<OsslLibCtxRef<'_>>, callback: &mut F)
where
    F: for<'a> FnMut(EvpMdRef<'a>),
{
    unsafe extern "C" fn trampoline<F>(md: *mut ffi::evp_md_st, arg: *mut c_void)
    where
        F: for<'a> FnMut(EvpMdRef<'a>),
    {
        // SAFETY: OpenSSL supplies a live digest for this invocation.
        let Some(md) = (unsafe { EvpMdRef::from_ptr(md) }) else {
            return;
        };
        // SAFETY: the outer wrapper passes the unique live closure and C does
        // not retain or concurrently invoke it.
        let callback = unsafe { &mut *arg.cast::<F>() };
        callback(md);
    }

    let libctx = libctx.map_or(ptr::null_mut(), |ctx| ctx.as_ptr().cast_mut());
    // SAFETY: the context and trampoline/state pair remain live throughout the
    // synchronous enumeration.
    unsafe {
        ffi::EVP_MD_do_all_provided(
            libctx,
            Some(trampoline::<F>),
            core::ptr::from_mut(callback).cast(),
        )
    }
}

/// Wraps: EVP_MD_fetch
#[allow(non_snake_case)]
pub fn EVP_MD_fetch<'a>(
    libctx: Option<OsslLibCtxRef<'a>>,
    algorithm: &CStr,
    properties: Option<&CStr>,
) -> Option<SharedEvpMd<'a>> {
    let libctx = libctx.map_or(ptr::null_mut(), |ctx| ctx.as_ptr().cast_mut());
    // SAFETY: the context and strings are live for the fetch.
    let raw = unsafe { ffi::EVP_MD_fetch(libctx, algorithm.as_ptr(), optional_cstr(properties)) };
    // SAFETY: a non-null result transfers one reference and `'a` retains an
    // explicit library context.
    unsafe { SharedEvpMd::from_raw(raw) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_shot_and_cloned_context_agree() {
        let digest = EVP_MD_fetch(None, c"SHA2-256", None).expect("fetch");
        let mut one_shot = [0_u8; 64];
        assert_eq!(EVP_Digest(b"abc", &mut one_shot, digest.as_ref()), Ok(32));

        let mut ctx = EVP_MD_CTX_new().expect("context");
        assert_eq!(
            EVP_DigestInit_ex(&mut ctx.as_mut(), Some(digest.as_ref())),
            1
        );
        assert_eq!(EVP_DigestUpdate(&mut ctx.as_mut(), b"abc"), 1);
        let mut copy = EVP_MD_CTX_dup(ctx.as_ref()).expect("duplicate");
        let mut output = [0_u8; 64];
        assert_eq!(EVP_DigestFinal_ex(&mut copy.as_mut(), &mut output), Ok(32));
        assert_eq!(&one_shot[..32], &output[..32]);
    }
}

#[cfg(test)]
mod digest_descriptor_tests {
    use super::*;
    use crate::evp::evp::SharedEvpMd;

    fn fetch(name: &core::ffi::CStr) -> SharedEvpMd<'static> {
        // SAFETY: null selects the process-wide default context and properties;
        // the name is NUL-terminated and a non-null result transfers one ref.
        let raw = unsafe { ffi::EVP_MD_fetch(ptr::null_mut(), name.as_ptr(), ptr::null()) };
        // SAFETY: the default context is process-wide and the fresh result
        // transfers one `EVP_MD_free` obligation.
        unsafe { SharedEvpMd::from_raw(raw) }.expect("fetched digest")
    }

    #[test]
    fn get_params_accepts_safe_owned_descriptor_storage() {
        use core::mem::{MaybeUninit, size_of};

        let digest = fetch(c"SHA2-256");
        let mut empty = OsslParamArray::new([]);
        assert!(EVP_MD_get_params(Some(digest.as_ref()), &mut empty));
        assert!(!EVP_MD_get_params(None, &mut empty));

        // `OSSL_PARAM_UNSIGNED_INTEGER`, per `include/openssl/core.h`.
        const UNSIGNED_INTEGER: u32 = 2;

        // The array took over the descriptor's exclusive borrow of `storage`,
        // so the provider writes through it and the result reads back off the
        // array rather than off a buffer safe code still holds.
        let mut storage = [MaybeUninit::new(0_u8); size_of::<usize>()];
        let mut params = OsslParamArray::new([OsslParam::for_slice(
            c"blocksize",
            UNSIGNED_INTEGER,
            &mut storage,
        )
        .expect("byte descriptor")]);
        assert!(EVP_MD_get_params(Some(digest.as_ref()), &mut params));

        let values = params.as_list().values();
        let block_size = values.get(0).expect("the blocksize descriptor");
        assert_eq!(block_size.return_size(), size_of::<usize>());
        let written = block_size.data().expect("the filled run");
        let mut bytes = [0_u8; size_of::<usize>()];
        for (index, byte) in bytes.iter_mut().enumerate() {
            // SAFETY: `return_size` reports that the provider initialized the
            // whole run, so every byte of it now holds a value.
            *byte = unsafe { written.elem(index).expect("in range").assume_init() };
        }
        assert_eq!(usize::from_ne_bytes(bytes), 64);
    }

    #[test]
    fn descriptor_tables_are_lifetime_bound_to_the_digest() {
        let digest = fetch(c"SHAKE-128");
        let md = digest.as_ref();

        let gettable = EVP_MD_gettable_params(Some(md)).expect("digest parameters");
        assert!(!gettable.is_empty());
        for index in 0..gettable.len() {
            assert!(gettable.get(index).and_then(|param| param.key()).is_some());
        }

        let _ = EVP_MD_gettable_ctx_params(Some(md));
        let _ = EVP_MD_settable_ctx_params(Some(md));
        assert!(EVP_MD_gettable_params(None).is_none());
        assert!(EVP_MD_gettable_ctx_params(None).is_none());
        assert!(EVP_MD_settable_ctx_params(None).is_none());
    }

    /// Pins the precondition [`EVP_Digest`]'s capacity check rests on.
    ///
    /// `EVP_Digest` finalizes into a context this wrapper cannot reach, using
    /// `EVP_MD_CTX_get_size(ctx)` bytes, while the check ahead of the call can
    /// only ask the digest itself. The two must not disagree in the unsafe
    /// direction: for every provided digest the context size is either equal to
    /// the digest size or negative, and a negative one makes
    /// `EVP_DigestFinal_ex` bail before it writes.
    #[test]
    fn every_provided_digest_bounds_its_one_shot_output() {
        use crate::evp::evp_lib::{EVP_MD_CTX_get_size_ex, EVP_MD_get_size, EVP_MD_get0_name};

        let mut visited = 0_usize;
        EVP_MD_do_all_provided(None, &mut |md| {
            visited += 1;
            let name = EVP_MD_get0_name(md).expect("digest name").to_owned();
            let algorithm_size = EVP_MD_get_size(Some(md));

            let mut ctx = EVP_MD_CTX_new().expect("context");
            let mut ctx_mut = ctx.as_mut();
            assert_eq!(
                EVP_DigestInit_ex(&mut ctx_mut, Some(md)),
                1,
                "{name:?} could not be initialized"
            );
            let context_size = EVP_MD_CTX_get_size_ex(ctx.as_ref());

            assert!(
                context_size < 0 || context_size == algorithm_size,
                "{name:?} finalizes {context_size} bytes but advertises {algorithm_size}"
            );
        });
        assert!(visited > 0);
    }
}

#[cfg(test)]
mod digest_lifecycle_tests {
    use super::*;
    use crate::evp::evp_lib::{
        EVP_MD_CTX_clear_flags, EVP_MD_CTX_get_size_ex, EVP_MD_CTX_get0_md, EVP_MD_CTX_set_flags,
        EVP_MD_CTX_test_flags,
    };

    fn started(algorithm: &CStr, message: &[u8]) -> (SharedEvpMd<'static>, CBox<EvpMdCtx>) {
        let digest = EVP_MD_fetch(None, algorithm, None).expect("fetch");
        let mut ctx = EVP_MD_CTX_new().expect("context");
        assert_eq!(
            EVP_DigestInit_ex(&mut ctx.as_mut(), Some(digest.as_ref())),
            1
        );
        assert_eq!(EVP_DigestUpdate(&mut ctx.as_mut(), message), 1);
        (digest, ctx)
    }

    /// `EVP_DigestFinal` is `EVP_DigestFinal_ex` plus a reset, so only the
    /// first leaves the context able to name its digest afterwards.
    #[test]
    fn plain_finalization_resets_the_context_and_the_ex_form_does_not() {
        let (_digest, mut ctx) = started(c"SHA2-256", b"abc");
        let mut output = [0_u8; 32];
        assert_eq!(EVP_DigestFinal_ex(&mut ctx.as_mut(), &mut output), Ok(32));
        assert!(EVP_MD_CTX_get0_md(ctx.as_ref()).is_some());

        let (_digest, mut ctx) = started(c"SHA2-256", b"abc");
        let mut reset_output = [0_u8; 32];
        assert_eq!(
            EVP_DigestFinal(&mut ctx.as_mut(), &mut reset_output),
            Ok(32)
        );
        assert_eq!(output, reset_output);
        assert!(EVP_MD_CTX_get0_md(ctx.as_ref()).is_none());
    }

    /// C never sees the caller's buffer length, so a short buffer has to be
    /// refused here — before the finalization that would overrun it.
    #[test]
    fn a_short_buffer_is_refused_before_the_call() {
        let (_digest, mut ctx) = started(c"SHA2-256", b"abc");
        let mut output = [0_u8; 31];
        assert_eq!(EVP_DigestFinal_ex(&mut ctx.as_mut(), &mut output), Err(0));
        assert_eq!(output, [0_u8; 31]);
        // Refusing left the context untouched, so it still finalizes normally.
        let mut full = [0_u8; 32];
        assert_eq!(EVP_DigestFinal_ex(&mut ctx.as_mut(), &mut full), Ok(32));
    }

    /// The extendable-output paths take their length from the slice, and
    /// squeezing the same stream in pieces reproduces one long finalization.
    #[test]
    fn extendable_output_length_comes_from_the_slice() {
        let (_digest, mut ctx) = started(c"SHAKE-128", b"abc");
        let mut whole = [0_u8; 32];
        assert_eq!(EVP_DigestFinalXOF(&mut ctx.as_mut(), &mut whole), 1);

        let (_digest, mut ctx) = started(c"SHAKE-128", b"abc");
        let mut pieces = [0_u8; 32];
        let (head, tail) = pieces.split_at_mut(16);
        assert_eq!(EVP_DigestSqueeze(&mut ctx.as_mut(), head), 1);
        assert_eq!(EVP_DigestSqueeze(&mut ctx.as_mut(), tail), 1);
        assert_eq!(whole, pieces);
    }

    /// A serialization only this module can mint travels through a second
    /// context and resumes the same digest stream.
    #[test]
    fn provider_state_round_trips_through_an_opaque_serialization() {
        let (digest, mut ctx) = started(c"SHA3-256", b"abc");
        let state = EVP_MD_CTX_serialize(&mut ctx.as_mut()).expect("serialize");
        assert!(!state.as_bytes().is_empty());

        let mut resumed = EVP_MD_CTX_new().expect("context");
        assert_eq!(
            EVP_DigestInit_ex(&mut resumed.as_mut(), Some(digest.as_ref())),
            1
        );
        assert_eq!(EVP_MD_CTX_deserialize(&mut resumed.as_mut(), &state), 1);
        assert_eq!(EVP_DigestUpdate(&mut resumed.as_mut(), b"def"), 1);
        assert_eq!(EVP_DigestUpdate(&mut ctx.as_mut(), b"def"), 1);

        let mut original = [0_u8; 32];
        let mut copy = [0_u8; 32];
        assert_eq!(EVP_DigestFinal_ex(&mut ctx.as_mut(), &mut original), Ok(32));
        assert_eq!(EVP_DigestFinal_ex(&mut resumed.as_mut(), &mut copy), Ok(32));
        assert_eq!(original, copy);
    }

    /// Both copy forms produce an independent context that continues the
    /// source's stream; only `EVP_MD_CTX_copy` resets the destination first.
    #[test]
    fn copies_continue_the_source_stream_independently() {
        let (_digest, mut source) = started(c"SHA2-256", b"ab");
        let mut destination = EVP_MD_CTX_new().expect("context");
        assert_eq!(
            EVP_MD_CTX_copy(&mut destination.as_mut(), source.as_ref()),
            1
        );
        assert_eq!(EVP_DigestUpdate(&mut destination.as_mut(), b"c"), 1);
        assert_eq!(EVP_DigestUpdate(&mut source.as_mut(), b"c"), 1);

        let mut from_copy = [0_u8; 32];
        let mut from_source = [0_u8; 32];
        assert_eq!(
            EVP_DigestFinal_ex(&mut destination.as_mut(), &mut from_copy),
            Ok(32)
        );
        assert_eq!(
            EVP_DigestFinal_ex(&mut source.as_mut(), &mut from_source),
            Ok(32)
        );
        assert_eq!(from_copy, from_source);

        let (_digest, source) = started(c"SHA2-256", b"ab");
        let mut reused = EVP_MD_CTX_new().expect("context");
        assert_eq!(EVP_MD_CTX_copy_ex(&mut reused.as_mut(), source.as_ref()), 1);
        assert!(EVP_MD_CTX_get0_md(reused.as_ref()).is_some());
    }

    /// Flag reads and writes go through the shared and exclusive handles
    /// respectively, and clearing is the exact inverse of setting.
    #[test]
    fn flags_round_trip_through_the_matching_handle() {
        const PROBE: i32 = 0x0001;

        let mut ctx = EVP_MD_CTX_new().expect("context");
        assert_eq!(EVP_MD_CTX_test_flags(ctx.as_ref(), PROBE), 0);
        EVP_MD_CTX_set_flags(&mut ctx.as_mut(), PROBE);
        assert_eq!(EVP_MD_CTX_test_flags(ctx.as_ref(), PROBE), PROBE);
        EVP_MD_CTX_clear_flags(&mut ctx.as_mut(), PROBE);
        assert_eq!(EVP_MD_CTX_test_flags(ctx.as_ref(), PROBE), 0);
    }

    /// The context parameter tables are advertised per context and stay bound
    /// to its borrow; an extendable-output context publishes a length key.
    #[test]
    fn context_parameter_tables_are_bound_to_the_context() {
        let (_digest, mut ctx) = started(c"SHAKE-128", b"abc");

        let mut terminator = [OsslParam::end()];
        let mut empty =
            OsslParamListMut::from_values(&mut terminator).expect("terminated empty list");
        assert_eq!(EVP_MD_CTX_get_params(&mut ctx.as_mut(), &mut empty), 1);
        assert_eq!(EVP_MD_CTX_set_params(&mut ctx.as_mut(), &empty.as_ref()), 1);

        let gettable: Vec<_> = EVP_MD_CTX_gettable_params(ctx.as_ref())
            .expect("gettable table")
            .filter_map(|param| param.key().map(CStr::to_owned))
            .collect();
        assert!(gettable.iter().any(|key| key.as_c_str() == c"xoflen"));

        let settable: Vec<_> = EVP_MD_CTX_settable_params(ctx.as_ref())
            .expect("settable table")
            .filter_map(|param| param.key().map(CStr::to_owned))
            .collect();
        assert!(settable.iter().any(|key| key.as_c_str() == c"xoflen"));

        // Both tables end at the terminator rather than running on.
        assert!(gettable.len() < 32 && settable.len() < 32);

        assert!(EVP_MD_CTX_get_size_ex(ctx.as_ref()) < 0);
    }
}
