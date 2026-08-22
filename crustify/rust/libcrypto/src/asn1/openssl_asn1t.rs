//! Wrappers assigned from `include/openssl/asn1t.h`.

use core::ffi::{CStr, c_char, c_long, c_ulong, c_void};
use core::marker::PhantomData;
use core::ptr::{NonNull, addr_of};

use ffibox::{CCell, CPtr, CSlice, CType};
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
    /// Resolves an ordinary ASN.1 item descriptor.
    ///
    /// Returns `None` if a nonconforming resolver returns null.
    ///
    /// # Safety
    ///
    /// The template flags must identify this provider as an `ASN1_ITEM`
    /// resolver rather than an `ASN1_ADB` resolver.
    pub unsafe fn resolve_item(self) -> Option<Asn1ItemRef<'static>> {
        // SAFETY: the caller distinguishes the erased resolver kind. OpenSSL's
        // item macros return immutable process-lifetime descriptor storage.
        unsafe { Asn1ItemRef::from_ptr((self.0)()) }
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

/// Wraps: ASN1_ITEM_st
///
/// Layout-compatible storage for OpenSSL's immutable ASN.1 type descriptor.
/// Public definition macros create these descriptors and all of their pointees
/// as process-lifetime `static const` data, so the type has no owning lifecycle.
#[repr(transparent)]
pub struct Asn1Item(CType<ffi::ASN1_ITEM_st>);

/// Shared borrowed handle to an OpenSSL ASN.1 item descriptor.
#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct Asn1ItemRef<'a>(CPtr<'a, Asn1Item>);

/// Exclusive borrowed handle for code initializing an ASN.1 item descriptor.
#[repr(transparent)]
pub struct Asn1ItemMut<'a>(Asn1ItemRef<'a>);

// SAFETY: `Asn1Item` is transparent over `CType<ASN1_ITEM_st>` and both
// handles are transparent over `CPtr<Asn1Item>`. The shared handle performs
// only raw-place reads and neither handle forms a reference to the C layout.
unsafe impl CCell for Asn1Item {
    type C = ffi::ASN1_ITEM_st;
    type Ref<'a> = Asn1ItemRef<'a>;
    type Mut<'a> = Asn1ItemMut<'a>;

    unsafe fn ref_from_raw<'a>(ptr: NonNull<Self>) -> Self::Ref<'a> {
        // SAFETY: the caller guarantees that the descriptor is live for `'a`.
        Asn1ItemRef(unsafe { CPtr::new(ptr) })
    }

    unsafe fn mut_from_raw<'a>(ptr: NonNull<Self>) -> Self::Mut<'a> {
        // SAFETY: the caller additionally guarantees exclusive access for `'a`.
        Asn1ItemMut(Asn1ItemRef(unsafe { CPtr::new(ptr) }))
    }
}

/// Opaque borrowed view of an item's type-specific static function table.
#[derive(Clone, Copy)]
pub struct Asn1ItemFuncsRef<'a> {
    ptr: NonNull<c_void>,
    lifetime: PhantomData<&'a c_void>,
}

impl PartialEq for Asn1ItemFuncsRef<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.ptr == other.ptr
    }
}

impl Eq for Asn1ItemFuncsRef<'_> {}

/// The cardinality encoded by an ASN.1 item's template pointer and count.
#[derive(Clone, Copy)]
pub enum Asn1ItemTemplates<'a> {
    /// This item has no template.
    None,
    /// The primitive wrapper form points at one standalone template.
    Single(Asn1TemplateRef<'a>),
    /// A SEQUENCE or CHOICE points at `tcount` contiguous templates.
    Multiple(CSlice<'a, Asn1Template>),
}

impl<'a> Asn1ItemRef<'a> {
    /// Borrows an immutable item descriptor, returning `None` for null.
    ///
    /// # Safety
    ///
    /// A non-null pointer must address a live `ASN1_ITEM` for `'a`. `sname`
    /// must be a valid NUL-terminated string for that lifetime. `funcs`, when
    /// present, must address its type-selected function table, and `templates`
    /// must be null, one template when `tcount == 0`, or an initialized array
    /// of the nonnegative `tcount` length. Every pointee must outlive `'a`.
    pub unsafe fn from_ptr(ptr: *const ffi::ASN1_ITEM_st) -> Option<Self> {
        NonNull::new(ptr.cast_mut().cast::<Asn1Item>()).map(|ptr| {
            // SAFETY: the caller supplies the required liveness and invariants.
            Self(unsafe { CPtr::new(ptr) })
        })
    }

    /// Read-only pointer for the raw FFI seam.
    #[must_use]
    pub fn as_ptr(&self) -> *const ffi::ASN1_ITEM_st {
        self.0.as_non_null().as_ptr().cast()
    }

    /// Wraps: ASN1_ITEM_st.size
    #[must_use]
    pub fn size(&self) -> c_long {
        // SAFETY: the handle carries a live borrow and raw-place projection
        // reads the scalar without forming a reference to the descriptor.
        unsafe { addr_of!((*self.as_ptr()).size).read() }
    }

    /// Wraps: ASN1_ITEM_st.sname
    #[must_use]
    pub fn structure_name(&self) -> &'a CStr {
        // SAFETY: the constructor requires a live NUL-terminated string for
        // `'a`; reading the pointer does not reference the item descriptor.
        let ptr = unsafe { addr_of!((*self.as_ptr()).sname).read() };
        // SAFETY: the constructor contract supplies validity and lifetime.
        unsafe { CStr::from_ptr(ptr) }
    }

    /// Wraps: ASN1_ITEM_st.itype
    #[must_use]
    pub fn item_type(&self) -> c_char {
        // SAFETY: as `size`, for the `itype` scalar.
        unsafe { addr_of!((*self.as_ptr()).itype).read() }
    }

    /// Wraps: ASN1_ITEM_st.funcs
    #[must_use]
    pub fn functions(&self) -> Option<Asn1ItemFuncsRef<'a>> {
        // SAFETY: the handle carries a live borrow; the pointer is copied by
        // raw-place read and remains opaque because its concrete type varies.
        let ptr = unsafe { addr_of!((*self.as_ptr()).funcs).read() };
        NonNull::new(ptr.cast_mut()).map(|ptr| Asn1ItemFuncsRef {
            ptr,
            lifetime: PhantomData,
        })
    }

    /// Wraps: ASN1_ITEM_st.utype
    #[must_use]
    pub fn underlying_type(&self) -> c_long {
        // SAFETY: as `size`, for the `utype` scalar.
        unsafe { addr_of!((*self.as_ptr()).utype).read() }
    }

    /// Wraps: ASN1_ITEM_st.tcount
    #[must_use]
    pub fn template_count(&self) -> c_long {
        // SAFETY: as `size`, for the `tcount` scalar.
        unsafe { addr_of!((*self.as_ptr()).tcount).read() }
    }

    /// Wraps: ASN1_ITEM_st.templates
    #[must_use]
    pub fn templates(&self) -> Asn1ItemTemplates<'a> {
        // SAFETY: the handle carries a live borrow; both fields are copied by
        // raw-place reads without forming a reference to the descriptor.
        let ptr = unsafe { addr_of!((*self.as_ptr()).templates).read() };
        let count = self.template_count();
        let Some(ptr) = NonNull::new(ptr.cast_mut().cast::<Asn1Template>()) else {
            return Asn1ItemTemplates::None;
        };
        if count == 0 {
            // SAFETY: the constructor requires a standalone initialized
            // template when a non-null pointer accompanies a zero count.
            return Asn1ItemTemplates::Single(unsafe { Asn1TemplateRef(CPtr::new(ptr)) });
        }
        let count = usize::try_from(count)
            .expect("ASN1_ITEM constructor requires a nonnegative template count");
        // SAFETY: the constructor requires `count` initialized contiguous
        // templates, all living for the handle's lifetime.
        Asn1ItemTemplates::Multiple(unsafe { CSlice::from_raw_parts(ptr, count) })
    }
}

impl Asn1ItemMut<'_> {
    /// Exclusively borrows an item descriptor, returning `None` for null.
    ///
    /// # Safety
    ///
    /// As [`Asn1ItemRef::from_ptr`], and no other handle to this descriptor
    /// may be used while the result lives.
    pub unsafe fn from_ptr(ptr: *mut ffi::ASN1_ITEM_st) -> Option<Self> {
        NonNull::new(ptr.cast::<Asn1Item>()).map(|ptr| {
            // SAFETY: the caller supplies liveness, invariants and exclusivity.
            Self(Asn1ItemRef(unsafe { CPtr::new(ptr) }))
        })
    }

    /// Writable pointer for FFI code initializing a descriptor.
    #[must_use]
    pub fn as_mut_ptr(&mut self) -> *mut ffi::ASN1_ITEM_st {
        self.0.0.as_non_null().as_ptr().cast()
    }

    /// Reborrows this exclusive handle without write access.
    #[must_use]
    pub fn as_ref(&self) -> Asn1ItemRef<'_> {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn item_provider() -> *const ffi::ASN1_ITEM {
        core::ptr::null()
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
        // SAFETY: the test callback has the ordinary item-resolver signature,
        // rather than the alternate ASN1_ADB interpretation.
        assert!(unsafe { template.item().resolve_item() }.is_none());
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

    fn raw_item(
        templates: *const ffi::ASN1_TEMPLATE_st,
        template_count: c_long,
        funcs: *const c_void,
    ) -> ffi::ASN1_ITEM_st {
        ffi::ASN1_ITEM_st {
            itype: 1,
            utype: 16,
            templates,
            tcount: template_count,
            funcs,
            size: 48,
            sname: c"EXAMPLE".as_ptr(),
        }
    }

    #[test]
    fn item_wrapper_and_handles_preserve_layout() {
        assert_eq!(
            core::mem::size_of::<Asn1Item>(),
            core::mem::size_of::<ffi::ASN1_ITEM_st>()
        );
        assert_eq!(
            core::mem::align_of::<Asn1Item>(),
            core::mem::align_of::<ffi::ASN1_ITEM_st>()
        );
        assert_eq!(
            core::mem::size_of::<Asn1ItemRef<'static>>(),
            core::mem::size_of::<*const ffi::ASN1_ITEM_st>()
        );
    }

    #[test]
    fn item_handle_reads_scalars_string_and_opaque_functions() {
        let funcs = 0_u8;
        let mut raw = raw_item(core::ptr::null(), 0, core::ptr::addr_of!(funcs).cast());
        // SAFETY: all pointer fields satisfy the constructor contract and the
        // local pointees remain live for the handle's scope.
        let item =
            unsafe { Asn1ItemRef::from_ptr(core::ptr::addr_of!(raw)) }.expect("non-null item");

        assert_eq!(item.item_type(), 1);
        assert_eq!(item.underlying_type(), 16);
        assert_eq!(item.template_count(), 0);
        assert_eq!(item.size(), 48);
        assert_eq!(item.structure_name(), c"EXAMPLE");
        let functions = item.functions().expect("function table");
        assert!(Some(functions) == item.functions());
        assert!(matches!(item.templates(), Asn1ItemTemplates::None));

        // SAFETY: `raw` is valid and exclusively borrowed for this scope.
        let mut item_mut =
            unsafe { Asn1ItemMut::from_ptr(core::ptr::addr_of_mut!(raw)) }.expect("non-null item");
        assert_eq!(item_mut.as_ref().size(), 48);
        assert_eq!(item_mut.as_mut_ptr(), core::ptr::addr_of_mut!(raw));
    }

    #[test]
    fn item_template_cardinality_preserves_borrowed_handles() {
        let mut templates = [raw_template(), raw_template()];
        templates[1].offset = 99;

        let multiple_raw = raw_item(templates.as_ptr(), 2, core::ptr::null());
        // SAFETY: `templates` supplies two initialized contiguous descriptors
        // and both it and the item remain live for the handle's scope.
        let multiple = unsafe { Asn1ItemRef::from_ptr(core::ptr::addr_of!(multiple_raw)) }
            .expect("non-null item");
        let Asn1ItemTemplates::Multiple(run) = multiple.templates() else {
            panic!("expected an array of templates");
        };
        assert_eq!(run.len(), 2);
        assert_eq!(run.get(1).expect("second template").offset(), 99);

        let single_raw = raw_item(templates.as_ptr(), 0, core::ptr::null());
        // SAFETY: a non-null pointer with zero count denotes the standalone
        // initialized primitive-wrapper template at `templates[0]`.
        let single = unsafe { Asn1ItemRef::from_ptr(core::ptr::addr_of!(single_raw)) }
            .expect("non-null item");
        let Asn1ItemTemplates::Single(template) = single.templates() else {
            panic!("expected one standalone template");
        };
        assert_eq!(template.offset(), 24);
    }
}
