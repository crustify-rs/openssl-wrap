//! Wrappers assigned from `include/openssl/asn1t.h`.

use core::ffi::{CStr, c_long, c_ulong};
use core::ptr::{NonNull, addr_of};

use ffibox::{CCell, CPtr, CType};
use libcrypto_sys as ffi;

/// Wraps: ASN1_TEMPLATE_st
///
/// Layout-compatible view of OpenSSL's immutable ASN.1 field descriptor.
/// Templates are emitted as `static const` data by the public macros, so this
/// type has borrowed handles but no owning lifecycle.
#[repr(transparent)]
pub struct Asn1Template(CType<ffi::ASN1_TEMPLATE_st>);

/// Shared borrowed handle to an OpenSSL ASN.1 template descriptor.
#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct Asn1TemplateRef<'a>(CPtr<'a, Asn1Template>);

/// Exclusive borrowed handle to an OpenSSL ASN.1 template descriptor.
#[repr(transparent)]
pub struct Asn1TemplateMut<'a>(Asn1TemplateRef<'a>);

// SAFETY: `Asn1Template` is transparent over `CType<ASN1_TEMPLATE_st>` and
// both handles are transparent over `CPtr<Asn1Template>`. The shared handle
// exposes only field reads and neither handle forms a reference to the layout.
unsafe impl CCell for Asn1Template {
    type C = ffi::ASN1_TEMPLATE_st;
    type Ref<'a> = Asn1TemplateRef<'a>;
    type Mut<'a> = Asn1TemplateMut<'a>;

    unsafe fn ref_from_raw<'a>(ptr: NonNull<Self>) -> Self::Ref<'a> {
        // SAFETY: the caller guarantees that the template is live for `'a`.
        Asn1TemplateRef(unsafe { CPtr::new(ptr) })
    }

    unsafe fn mut_from_raw<'a>(ptr: NonNull<Self>) -> Self::Mut<'a> {
        // SAFETY: the caller additionally guarantees exclusive access for `'a`.
        Asn1TemplateMut(Asn1TemplateRef(unsafe { CPtr::new(ptr) }))
    }
}

/// A process-lifetime OpenSSL function that resolves a template's item.
///
/// The returned function remains unsafe to call because the template flags
/// determine whether its raw result denotes an `ASN1_ITEM` or an `ASN1_ADB`.
#[derive(Clone, Copy)]
pub struct Asn1ItemProvider(unsafe extern "C" fn() -> *const ffi::ASN1_ITEM);

impl Asn1ItemProvider {
    /// Returns the underlying OpenSSL item resolver.
    #[must_use]
    pub fn as_raw(self) -> unsafe extern "C" fn() -> *const ffi::ASN1_ITEM {
        self.0
    }
}

impl<'a> Asn1TemplateRef<'a> {
    /// Borrows a raw template pointer, returning `None` for null.
    ///
    /// # Safety
    ///
    /// A non-null pointer must address a live `ASN1_TEMPLATE` for `'a`. Its
    /// `field_name` must remain a valid NUL-terminated string and its `item`
    /// slot must contain the process-lifetime resolver established by the
    /// OpenSSL template macros.
    pub unsafe fn from_ptr(ptr: *mut ffi::ASN1_TEMPLATE_st) -> Option<Self> {
        NonNull::new(ptr.cast::<Asn1Template>()).map(|ptr| {
            // SAFETY: the caller supplies the required liveness and invariants.
            Self(unsafe { CPtr::new(ptr) })
        })
    }

    /// Read-only pointer for the raw FFI seam.
    #[must_use]
    pub fn as_ptr(&self) -> *const ffi::ASN1_TEMPLATE_st {
        self.0.as_non_null().as_ptr().cast()
    }

    /// Wraps: ASN1_TEMPLATE_st.offset
    #[must_use]
    pub fn offset(&self) -> c_ulong {
        // SAFETY: `self` carries a live shared borrow; raw-place projection
        // reads the scalar without forming a reference to the C object.
        unsafe { addr_of!((*self.as_ptr()).offset).read() }
    }

    /// Wraps: ASN1_TEMPLATE_st.flags
    #[must_use]
    pub fn flags(&self) -> c_ulong {
        // SAFETY: `self` carries a live shared borrow; raw-place projection
        // reads the scalar without forming a reference to the C object.
        unsafe { addr_of!((*self.as_ptr()).flags).read() }
    }

    /// Wraps: ASN1_TEMPLATE_st.item
    #[must_use]
    pub fn item(&self) -> Asn1ItemProvider {
        // SAFETY: `self` carries a live shared borrow; raw-place projection
        // reads the function pointer without referencing the C object.
        let provider = unsafe { addr_of!((*self.as_ptr()).item).read() };
        Asn1ItemProvider(provider.expect("valid ASN1_TEMPLATE item resolver"))
    }

    /// Wraps: ASN1_TEMPLATE_st.tag
    #[must_use]
    pub fn tag(&self) -> c_long {
        // SAFETY: `self` carries a live shared borrow; raw-place projection
        // reads the scalar without forming a reference to the C object.
        unsafe { addr_of!((*self.as_ptr()).tag).read() }
    }

    /// Wraps: ASN1_TEMPLATE_st.field_name
    #[must_use]
    pub fn field_name(&self) -> &'a CStr {
        // SAFETY: `from_ptr` requires this slot to remain a valid NUL-terminated
        // string for `'a`; reading the pointer does not reference the template.
        let ptr = unsafe { addr_of!((*self.as_ptr()).field_name).read() };
        // SAFETY: the constructor contract supplies validity and lifetime.
        unsafe { CStr::from_ptr(ptr) }
    }
}

impl Asn1TemplateMut<'_> {
    /// Borrows a raw template pointer exclusively, returning `None` for null.
    ///
    /// # Safety
    ///
    /// As [`Asn1TemplateRef::from_ptr`], and no other handle to this template
    /// may be used while the result lives.
    pub unsafe fn from_ptr(ptr: *mut ffi::ASN1_TEMPLATE_st) -> Option<Self> {
        NonNull::new(ptr.cast::<Asn1Template>()).map(|ptr| {
            // SAFETY: the caller supplies liveness, invariants and exclusivity.
            Self(Asn1TemplateRef(unsafe { CPtr::new(ptr) }))
        })
    }

    /// Writable pointer for FFI calls that initialize a descriptor.
    #[must_use]
    pub fn as_mut_ptr(&mut self) -> *mut ffi::ASN1_TEMPLATE_st {
        self.0.0.as_non_null().as_ptr().cast()
    }

    /// Reborrows this exclusive handle without write access.
    #[must_use]
    pub fn as_ref(&self) -> Asn1TemplateRef<'_> {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn item_provider() -> *const ffi::ASN1_ITEM {
        // This callback is compared but not invoked by the wrapper test.
        core::ptr::dangling()
    }

    fn raw_template() -> ffi::ASN1_TEMPLATE_st {
        ffi::ASN1_TEMPLATE_st {
            flags: 0x12,
            tag: -7,
            offset: 24,
            field_name: c"member".as_ptr(),
            item: Some(item_provider),
        }
    }

    #[test]
    fn wrapper_and_handles_preserve_layout() {
        assert_eq!(
            core::mem::size_of::<Asn1Template>(),
            core::mem::size_of::<ffi::ASN1_TEMPLATE_st>()
        );
        assert_eq!(
            core::mem::align_of::<Asn1Template>(),
            core::mem::align_of::<ffi::ASN1_TEMPLATE_st>()
        );
        assert_eq!(
            core::mem::size_of::<Asn1TemplateRef<'static>>(),
            core::mem::size_of::<*mut ffi::ASN1_TEMPLATE_st>()
        );
    }

    #[test]
    fn shared_handle_reads_published_fields() {
        let mut raw = raw_template();
        // SAFETY: every pointer field satisfies the documented constructor
        // invariants and `raw` remains live for the handle's scope.
        let template = unsafe { Asn1TemplateRef::from_ptr(core::ptr::addr_of_mut!(raw)) }
            .expect("non-null template");

        assert_eq!(template.flags(), 0x12);
        assert_eq!(template.tag(), -7);
        assert_eq!(template.offset(), 24);
        assert_eq!(template.field_name(), c"member");
        assert_eq!(
            template.item().as_raw() as *const (),
            item_provider as *const ()
        );
    }

    #[test]
    fn exclusive_handle_reborrows_shared() {
        let mut raw = raw_template();
        // SAFETY: `raw` is valid and exclusively borrowed for this scope.
        let mut template = unsafe { Asn1TemplateMut::from_ptr(core::ptr::addr_of_mut!(raw)) }
            .expect("non-null template");
        assert_eq!(template.as_ref().field_name(), c"member");
        assert_eq!(template.as_mut_ptr(), core::ptr::addr_of_mut!(raw));
    }
}
