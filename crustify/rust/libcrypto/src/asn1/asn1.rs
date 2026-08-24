//! Wrappers assigned from `include/crypto/asn1.h`.

use core::ptr::NonNull;

use ffibox::{CBox, CBoxWith, CCloner, CDropper, define_ctype, impl_cloned, impl_dropped};
use libcrypto_sys as ffi;

use crate::stack::stack::{Stack, StackMut, StackRef};

define_ctype!(
    /// Wraps: asn1_object_st
    ///
    /// The public OpenSSL API keeps `ASN1_OBJECT` opaque. Owned handles use
    /// `ffibox::CBox<Asn1Object>` and borrowed access remains lifetime-bound
    /// through `Asn1ObjectRef` and `Asn1ObjectMut`.
    Asn1Object,
    Asn1ObjectRef,
    Asn1ObjectMut,
    ffi::asn1_object_st
);

impl_dropped!(Asn1Object, ffi::asn1_object_st, ffi::ASN1_OBJECT_free);

/// The two ownership outcomes of `OBJ_dup`.
///
/// Dynamic objects produce an independently owned copy. For a non-dynamic
/// object OpenSSL returns the source pointer, so that result remains borrowed
/// for the source handle's lifetime.
pub enum Asn1ObjectDuplicate<'a> {
    /// A fresh object released by `ASN1_OBJECT_free`.
    Owned(CBox<Asn1Object>),
    /// The original non-dynamic object, still borrowed from the source.
    Borrowed(Asn1ObjectRef<'a>),
}

impl Asn1ObjectDuplicate<'_> {
    /// Borrow either duplicate outcome.
    #[must_use]
    pub fn as_ref(&self) -> Asn1ObjectRef<'_> {
        match self {
            Self::Owned(object) => object.as_ref(),
            Self::Borrowed(object) => *object,
        }
    }
}

impl<'a> Asn1ObjectRef<'a> {
    /// Duplicate this object, preserving OpenSSL's owned-versus-borrowed result.
    #[must_use]
    pub fn try_dup(&self) -> Option<Asn1ObjectDuplicate<'a>> {
        // SAFETY: this handle carries a live shared borrow. `OBJ_dup` leaves
        // its source unchanged and returns null, a fresh allocation, or the
        // same pointer when the source is non-dynamic.
        let duplicate = unsafe { ffi::OBJ_dup(self.as_ptr()) };
        if duplicate.cast_const() == self.as_ptr() {
            // SAFETY: pointer equality is the non-dynamic branch of `OBJ_dup`;
            // the returned borrow remains bounded by this handle's `'a`.
            let object = unsafe { Asn1ObjectRef::from_ptr(duplicate) }?;
            Some(Asn1ObjectDuplicate::Borrowed(object))
        } else {
            // SAFETY: a distinct non-null `OBJ_dup` result is a fresh object
            // carrying one `ASN1_OBJECT_free` obligation.
            let object = unsafe { CBox::from_raw(duplicate) }?;
            Some(Asn1ObjectDuplicate::Owned(object))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owned_object_duplicates_and_borrows() {
        // SAFETY: the input is a live NUL-terminated numeric OID; OpenSSL
        // returns either null or a fully initialized owned object.
        let raw = unsafe { ffi::OBJ_txt2obj(c"1.3.6.1.4.1.55555.999999".as_ptr(), 1) };
        // SAFETY: `OBJ_txt2obj` transfers its fresh result to the caller and
        // `Asn1Object` registers the matching `ASN1_OBJECT_free` destructor.
        let mut object =
            unsafe { CBox::<Asn1Object>::from_raw(raw) }.expect("numeric object identifier");

        assert_eq!(object.as_ref().as_ptr(), raw.cast_const());
        assert_eq!(object.as_mut().as_mut_ptr(), raw);

        let duplicate = object.as_ref().try_dup().expect("OBJ_dup");
        let Asn1ObjectDuplicate::Owned(duplicate) = duplicate else {
            panic!("unregistered numeric OID unexpectedly resolved to a static object");
        };
        assert_ne!(duplicate.as_ptr(), raw);
        assert_eq!(duplicate.as_ref().as_ptr(), duplicate.as_ptr().cast_const());
    }

    #[test]
    fn duplicate_keeps_builtin_objects_borrowed() {
        // SAFETY: the input is a live NUL-terminated numeric OID. OpenSSL
        // returns the registered built-in object for this well-known value.
        let raw = unsafe { ffi::OBJ_txt2obj(c"1.2.840.113549.1.1.1".as_ptr(), 1) };
        // SAFETY: the returned pointer remains live until the matching free
        // below (which is a no-op for this built-in object).
        let object = unsafe { Asn1ObjectRef::from_ptr(raw) }.expect("RSA object identifier");
        let duplicate = object.try_dup().expect("OBJ_dup of built-in object");
        let is_borrowed = matches!(duplicate, Asn1ObjectDuplicate::Borrowed(_));
        drop(duplicate);
        // SAFETY: this releases the one result returned by `OBJ_txt2obj`; for
        // the expected built-in object OpenSSL intentionally does nothing.
        unsafe { ffi::ASN1_OBJECT_free(raw) };

        assert!(is_borrowed);
    }
}

define_ctype!(
    /// Wraps: asn1_string_st
    ///
    /// Every public ASN.1 string typedef — `ASN1_STRING`, `ASN1_INTEGER`,
    /// `ASN1_OCTET_STRING`, `ASN1_TIME` and the rest of the eighteen — is this
    /// one C struct, told apart at runtime by its `type` field, so one wrapper
    /// covers all of them.
    ///
    /// The public headers only forward-declare `struct asn1_string_st`; the
    /// body lives in the internal `crypto/asn1.h`. The generated binding is
    /// therefore an incomplete type and this wrapper deliberately carries no
    /// field accessors. `length`, `type`, `data` and `flags` are reached
    /// through the published call surface in [`crate::asn1::asn1_lib`] —
    /// `ASN1_STRING_get_length`, `ASN1_STRING_type`, `ASN1_STRING_get0_data`,
    /// `ASN1_STRING_set0` and friends — which is also what keeps the handles
    /// one pointer wide over OpenSSL's own allocation.
    ///
    /// Adoption is the part Rust cannot check for the caller. Both destructors
    /// registered below consult `flags` to decide whether they release the
    /// header, the byte buffer, or neither, so a raw pointer may be adopted as
    /// an owner only when it is a heap header the caller owns outright — what
    /// `ASN1_STRING_new`, `ASN1_STRING_type_new`, `ASN1_STRING_dup` and
    /// `ASN1_STRING_set_by_NID` return. A string that OpenSSL embedded in a
    /// parent (`ASN1_STRING_FLAG_EMBED`, which the ASN.1 template code sets for
    /// every `ASN1_EMBED` field) or one merely borrowed from a parent, as every
    /// `X509_get0_*`-style accessor returns, stays a borrowed
    /// [`Asn1StringRef`] or [`Asn1StringMut`]: adopting it would free a buffer
    /// the parent still points at.
    Asn1String,
    Asn1StringRef,
    Asn1StringMut,
    ffi::asn1_string_st
);

// `ASN1_STRING_free` is the destructor for a heap-allocated ASN.1 string, and
// both halves of it are conditional on `flags`: the byte buffer is released
// unless it belongs to someone else (`ASN1_STRING_FLAG_DATA_NOT_OWNED`, set by
// `ASN1_STRING_new_not_owned`, or `ASN1_STRING_FLAG_NDEF`, set by the
// streaming PKCS#7 and CMS code), and the header is released unless it is
// embedded in a parent (`ASN1_STRING_FLAG_EMBED`). For the strings the public
// API hands out as owned, none of those flags is set and this frees both.
impl_dropped!(Asn1String, ffi::asn1_string_st, ffi::ASN1_STRING_free);

// `ASN1_STRING_dup` allocates a fresh header with `ASN1_STRING_new` and
// deep-copies the bytes into it, so the duplicate is independent of its source
// and owes exactly one free of its own. No refcount exists on this type, which
// is why the binding is a `dup =` and not an `up_ref =`.
//
// The copy also inherits the source's flags, all but `ASN1_STRING_FLAG_EMBED`.
// When the source's buffer is external — `ASN1_STRING_FLAG_DATA_NOT_OWNED` or
// `ASN1_STRING_FLAG_NDEF` — the duplicate ends up owning a freshly allocated
// buffer while flagged as not owning it, and its destructor then leaves that
// buffer behind. Cloning such a string leaks the copied bytes. The `CCloned`
// contract still holds, since the duplicate owes and receives exactly one
// `c_drop`; the leak is inside OpenSSL's copy routine, and callers cloning a
// string built by `ASN1_STRING_new_not_owned` should know about it.
impl_cloned!(Asn1String, ffi::asn1_string_st, dup = ffi::ASN1_STRING_dup);

/// Selects `ASN1_STRING_clear_free` for an owned ASN.1 string.
///
/// A type gets one `CDropped`, which is spent on `ASN1_STRING_free`, so this
/// second, equally valid destructor is registered as a policy object instead
/// and selected by the [`ClearAsn1String`] owner. The two differ only in that
/// this one cleanses the released bytes first; every object either accepts is
/// accepted by the other, which is what makes [`Asn1String::into_clearing`] and
/// [`Asn1String::into_plain`] safe.
#[derive(Clone, Copy, Debug, Default)]
pub struct Asn1StringClearFree;

// SAFETY: `ASN1_STRING_clear_free` is the public clearing destructor for a
// fully initialized, uniquely owned ASN.1 string allocation.
unsafe impl CDropper<Asn1String> for Asn1StringClearFree {
    unsafe fn c_drop(&self, object: NonNull<Asn1String>) {
        // SAFETY: the `CDropper` contract supplies unique ownership and the
        // layout wrapper is pointer-compatible with `ffi::asn1_string_st`.
        unsafe { ffi::ASN1_STRING_clear_free(object.as_ptr().cast()) }
    }
}

// SAFETY: `ASN1_STRING_dup` returns a fresh independent allocation without
// modifying its source, and that allocation may be clearing-freed.
unsafe impl CCloner<Asn1String> for Asn1StringClearFree {
    unsafe fn c_clone(&self, object: NonNull<Asn1String>) -> Option<NonNull<Asn1String>> {
        // SAFETY: the `CCloner` contract supplies a live source and OpenSSL
        // returns either null or a fully initialized independent duplicate.
        let duplicate = unsafe { ffi::ASN1_STRING_dup(object.as_ptr().cast()) };
        NonNull::new(duplicate.cast())
    }
}

/// An owning ASN.1 string that clears its contents before releasing storage.
pub type ClearAsn1String = CBoxWith<Asn1String, Asn1StringClearFree>;

impl Asn1String {
    /// Hand an owned string to the clearing destructor.
    ///
    /// The object is untouched — only which destructor will run changes — so
    /// this is the way to reach [`ClearAsn1String`] for a string that arrived
    /// under the ordinary owner, such as the result of `ASN1_STRING_new` or of
    /// a duplication.
    pub fn into_clearing(owner: CBox<Self>) -> ClearAsn1String {
        let raw = owner.into_raw();
        // SAFETY: `into_raw` surrenders the sole ownership of a live, fully
        // initialized heap string, and `ASN1_STRING_clear_free` releases
        // exactly what `ASN1_STRING_free` would, cleansing the bytes first.
        let clearing = unsafe { CBoxWith::from_raw(raw, Asn1StringClearFree) };
        clearing.expect("CBox::into_raw yields the non-null pointer it owned")
    }

    /// Hand a clearing owner back to the ordinary destructor.
    pub fn into_plain(owner: ClearAsn1String) -> CBox<Self> {
        // SAFETY: both owners describe the same fully formed heap string and
        // nothing about it changes here; `ASN1_STRING_free` requires exactly
        // what `ASN1_STRING_clear_free` already required of this object.
        unsafe { owner.into_box() }
    }
}

#[cfg(test)]
mod string_tests {
    use super::*;
    use crate::asn1::asn1_lib::{ASN1_STRING_get0_data, ASN1_STRING_new, ASN1_STRING_set1_data};

    #[test]
    fn owned_string_clones_and_borrows() {
        // SAFETY: OpenSSL returns either null or a fully initialized string.
        let raw = unsafe { ffi::ASN1_STRING_new() };
        // SAFETY: ownership of the fresh allocation transfers exactly once to
        // the owner whose registered destructor is `ASN1_STRING_free`.
        let mut string = unsafe { CBox::<Asn1String>::from_raw(raw) }.expect("ASN1_STRING_new");

        assert_eq!(string.as_ref().as_ptr(), raw.cast_const());
        assert_eq!(string.as_mut().as_mut_ptr(), raw);

        let duplicate = string.try_clone().expect("ASN1_STRING_dup");
        assert_ne!(duplicate.as_ptr(), raw);
    }

    #[test]
    fn clearing_owner_preserves_its_drop_policy_when_cloned() {
        // SAFETY: OpenSSL returns either null or a fully initialized string.
        let raw = unsafe { ffi::ASN1_STRING_new() };
        // SAFETY: the fresh allocation is uniquely transferred to the
        // clearing policy, whose destructor accepts every ASN.1 string.
        let string: ClearAsn1String =
            unsafe { CBoxWith::from_raw(raw, Asn1StringClearFree) }.expect("ASN1_STRING_new");

        let duplicate = string.try_clone().expect("ASN1_STRING_dup");
        assert_ne!(duplicate.as_ptr(), raw);
    }

    #[test]
    fn a_duplicate_stops_tracking_its_source() {
        let mut source = ASN1_STRING_new().expect("ASN1_STRING_new");
        assert!(ASN1_STRING_set1_data(&mut source.as_mut(), b"first"));

        let duplicate = source.try_clone().expect("ASN1_STRING_dup");
        assert_ne!(duplicate.as_ptr(), source.as_ptr());
        assert!(ASN1_STRING_set1_data(&mut source.as_mut(), b"second"));

        let copied = ASN1_STRING_get0_data(duplicate.as_ref()).expect("duplicated data");
        assert_eq!(copied.elems().collect::<Vec<_>>(), b"first");
    }

    #[test]
    fn the_two_owner_forms_convert_in_both_directions() {
        let mut string = ASN1_STRING_new().expect("ASN1_STRING_new");
        assert!(ASN1_STRING_set1_data(&mut string.as_mut(), b"secret"));
        let raw = string.as_ptr();

        let clearing = Asn1String::into_clearing(string);
        assert_eq!(clearing.as_ptr(), raw);

        // The round trip must not duplicate or release anything: the final
        // owner releases this one allocation once, with `ASN1_STRING_free`.
        let plain = Asn1String::into_plain(clearing);
        assert_eq!(plain.as_ptr(), raw);
        assert_eq!(
            ASN1_STRING_get0_data(plain.as_ref())
                .expect("retained data")
                .elems()
                .collect::<Vec<_>>(),
            b"secret"
        );
    }

    #[test]
    fn owners_and_handles_stay_pointer_sized() {
        assert_eq!(
            size_of::<CBox<Asn1String>>(),
            size_of::<*mut ffi::asn1_string_st>()
        );
        assert_eq!(
            size_of::<ClearAsn1String>(),
            size_of::<*mut ffi::asn1_string_st>()
        );
        assert_eq!(
            size_of::<Asn1StringRef<'static>>(),
            size_of::<*mut ffi::asn1_string_st>()
        );
        assert_eq!(
            size_of::<Asn1StringMut<'static>>(),
            size_of::<*mut ffi::asn1_string_st>()
        );
    }
}

/// Wraps: stack_st_ASN1_INTEGER
///
/// Typed view of OpenSSL's `STACK_OF(ASN1_INTEGER)`. `ASN1_INTEGER` is a
/// typedef of the common ASN.1 string layout, while the generated stack tag
/// erases to `OPENSSL_STACK`; this alias retains the element type without
/// changing the generic container's representation.
///
/// A plain stack owns its pointer array, not the integers. Element ownership
/// can instead be selected explicitly with [`Stack::into_pop_free`].
pub type Asn1IntegerStack = Stack<Asn1String>;

/// Shared borrowed handle to a `STACK_OF(ASN1_INTEGER)`.
pub type Asn1IntegerStackRef<'a> = StackRef<'a, Asn1String>;

/// Exclusive borrowed handle to a `STACK_OF(ASN1_INTEGER)`.
pub type Asn1IntegerStackMut<'a> = StackMut<'a, Asn1String>;

/// Wraps: stack_st_ASN1_OBJECT
///
/// Typed view of OpenSSL's `STACK_OF(ASN1_OBJECT)`. The generated C tag is a
/// forward declaration whose operations erase it to `OPENSSL_STACK`, so this
/// alias uses the generic container while preserving [`Asn1Object`] as its
/// element type.
///
/// A plain stack owns its pointer array, not the objects. Element ownership
/// can instead be selected explicitly with [`Stack::into_pop_free`].
pub type Asn1ObjectStack = Stack<Asn1Object>;

/// Shared borrowed handle to a `STACK_OF(ASN1_OBJECT)`.
pub type Asn1ObjectStackRef<'a> = StackRef<'a, Asn1Object>;

/// Exclusive borrowed handle to a `STACK_OF(ASN1_OBJECT)`.
pub type Asn1ObjectStackMut<'a> = StackMut<'a, Asn1Object>;

#[cfg(test)]
mod stack_tests {
    use core::mem::size_of;

    use ffibox::{CBox, CCell, CCloned, CDropped};

    use super::*;
    use crate::stack::stack::{OPENSSL_sk_new_null, OPENSSL_sk_num};

    fn assert_owned_cloneable_cell<T: CCell + CCloned + CDropped>() {}

    #[test]
    fn asn1_stacks_keep_the_typed_erased_surface() {
        assert_owned_cloneable_cell::<Asn1IntegerStack>();
        assert_owned_cloneable_cell::<Asn1ObjectStack>();

        assert_eq!(
            size_of::<CBox<Asn1IntegerStack>>(),
            size_of::<*mut ffi::OPENSSL_STACK>()
        );
        assert_eq!(
            size_of::<Asn1IntegerStackRef<'static>>(),
            size_of::<*mut ffi::OPENSSL_STACK>()
        );
        assert_eq!(
            size_of::<Asn1IntegerStackMut<'static>>(),
            size_of::<*mut ffi::OPENSSL_STACK>()
        );
        assert_eq!(
            size_of::<CBox<Asn1ObjectStack>>(),
            size_of::<*mut ffi::OPENSSL_STACK>()
        );
        assert_eq!(
            size_of::<Asn1ObjectStackRef<'static>>(),
            size_of::<*mut ffi::OPENSSL_STACK>()
        );
        assert_eq!(
            size_of::<Asn1ObjectStackMut<'static>>(),
            size_of::<*mut ffi::OPENSSL_STACK>()
        );
    }

    #[test]
    fn owners_produce_integer_and_object_stack_handles() {
        let mut integers: CBox<Asn1IntegerStack> =
            OPENSSL_sk_new_null().expect("ASN1_INTEGER stack");
        let integer_raw = integers.as_ptr();
        let integer_shared: Asn1IntegerStackRef<'_> = integers.as_ref();
        assert_eq!(integer_shared.as_ptr(), integer_raw.cast_const());
        let mut integer_exclusive: Asn1IntegerStackMut<'_> = integers.as_mut();
        assert_eq!(integer_exclusive.as_mut_ptr(), integer_raw);
        assert_eq!(OPENSSL_sk_num(Some(integer_exclusive.as_ref())), Some(0));

        let mut objects: CBox<Asn1ObjectStack> = OPENSSL_sk_new_null().expect("ASN1_OBJECT stack");
        let object_raw = objects.as_ptr();
        let object_shared: Asn1ObjectStackRef<'_> = objects.as_ref();
        assert_eq!(object_shared.as_ptr(), object_raw.cast_const());
        let mut object_exclusive: Asn1ObjectStackMut<'_> = objects.as_mut();
        assert_eq!(object_exclusive.as_mut_ptr(), object_raw);
        assert_eq!(OPENSSL_sk_num(Some(object_exclusive.as_ref())), Some(0));
    }
}

define_ctype!(
    /// Wraps: asn1_pctx_st
    ///
    /// OpenSSL publishes `ASN1_PCTX` as an opaque print-options handle. Its
    /// five flag words remain behind the public getter/setter functions, while
    /// owned values use [`CBox<Asn1Pctx>`] and `ASN1_PCTX_free`.
    Asn1Pctx,
    Asn1PctxRef,
    Asn1PctxMut,
    ffi::asn1_pctx_st
);

impl_dropped!(Asn1Pctx, ffi::asn1_pctx_st, ffi::ASN1_PCTX_free);

impl Asn1Pctx {
    /// Allocates a zero-initialized ASN.1 print context.
    #[must_use]
    pub fn new() -> Option<CBox<Self>> {
        // SAFETY: a non-null `ASN1_PCTX_new` result is a fresh, fully
        // initialized allocation released by the registered destructor.
        unsafe { CBox::from_raw(ffi::ASN1_PCTX_new()) }
    }
}

impl Asn1PctxRef<'_> {
    /// Field: asn1_pctx_st.flags
    #[must_use]
    pub fn flags(&self) -> core::ffi::c_ulong {
        // SAFETY: this handle carries a live shared borrow and the public
        // getter only copies the initialized flag word.
        unsafe { ffi::ASN1_PCTX_get_flags(self.as_ptr()) }
    }

    /// Field: asn1_pctx_st.nm_flags
    #[must_use]
    pub fn nm_flags(&self) -> core::ffi::c_ulong {
        // SAFETY: this handle carries a live shared borrow and the public
        // getter only copies the initialized flag word.
        unsafe { ffi::ASN1_PCTX_get_nm_flags(self.as_ptr()) }
    }

    /// Field: asn1_pctx_st.cert_flags
    #[must_use]
    pub fn cert_flags(&self) -> core::ffi::c_ulong {
        // SAFETY: this handle carries a live shared borrow and the public
        // getter only copies the initialized flag word.
        unsafe { ffi::ASN1_PCTX_get_cert_flags(self.as_ptr()) }
    }

    /// Field: asn1_pctx_st.oid_flags
    #[must_use]
    pub fn oid_flags(&self) -> core::ffi::c_ulong {
        // SAFETY: this handle carries a live shared borrow and the public
        // getter only copies the initialized flag word.
        unsafe { ffi::ASN1_PCTX_get_oid_flags(self.as_ptr()) }
    }

    /// Field: asn1_pctx_st.str_flags
    #[must_use]
    pub fn str_flags(&self) -> core::ffi::c_ulong {
        // SAFETY: this handle carries a live shared borrow and the public
        // getter only copies the initialized flag word.
        unsafe { ffi::ASN1_PCTX_get_str_flags(self.as_ptr()) }
    }
}

impl Asn1PctxMut<'_> {
    /// Field: asn1_pctx_st.flags
    ///
    /// Sets the general print flags.
    pub fn set_flags(&mut self, flags: core::ffi::c_ulong) {
        // SAFETY: this handle carries exclusive access and the public setter
        // writes only this context's scalar flag word.
        unsafe { ffi::ASN1_PCTX_set_flags(self.as_mut_ptr(), flags) }
    }

    /// Field: asn1_pctx_st.nm_flags
    ///
    /// Sets the distinguished-name print flags.
    pub fn set_nm_flags(&mut self, flags: core::ffi::c_ulong) {
        // SAFETY: this handle carries exclusive access and the public setter
        // writes only this context's scalar flag word.
        unsafe { ffi::ASN1_PCTX_set_nm_flags(self.as_mut_ptr(), flags) }
    }

    /// Field: asn1_pctx_st.cert_flags
    ///
    /// Sets the certificate print flags.
    pub fn set_cert_flags(&mut self, flags: core::ffi::c_ulong) {
        // SAFETY: this handle carries exclusive access and the public setter
        // writes only this context's scalar flag word.
        unsafe { ffi::ASN1_PCTX_set_cert_flags(self.as_mut_ptr(), flags) }
    }

    /// Field: asn1_pctx_st.oid_flags
    ///
    /// Sets the object-identifier print flags.
    pub fn set_oid_flags(&mut self, flags: core::ffi::c_ulong) {
        // SAFETY: this handle carries exclusive access and the public setter
        // writes only this context's scalar flag word.
        unsafe { ffi::ASN1_PCTX_set_oid_flags(self.as_mut_ptr(), flags) }
    }

    /// Field: asn1_pctx_st.str_flags
    ///
    /// Sets the ASN.1 string print flags.
    pub fn set_str_flags(&mut self, flags: core::ffi::c_ulong) {
        // SAFETY: this handle carries exclusive access and the public setter
        // writes only this context's scalar flag word.
        unsafe { ffi::ASN1_PCTX_set_str_flags(self.as_mut_ptr(), flags) }
    }
}

#[cfg(test)]
mod pctx_tests {
    use core::mem::size_of;

    use ffibox::{CCell, CDropped};

    use super::*;

    fn assert_owned_cell<T: CCell + CDropped>() {}

    #[test]
    fn owned_context_borrows_and_round_trips_all_flags() {
        assert_owned_cell::<Asn1Pctx>();

        let mut context = Asn1Pctx::new().expect("ASN1_PCTX_new");
        assert_eq!(context.as_ref().flags(), 0);
        assert_eq!(context.as_ref().nm_flags(), 0);
        assert_eq!(context.as_ref().cert_flags(), 0);
        assert_eq!(context.as_ref().oid_flags(), 0);
        assert_eq!(context.as_ref().str_flags(), 0);

        let mut context = context.as_mut();
        context.set_flags(0x11);
        context.set_nm_flags(0x22);
        context.set_cert_flags(0x33);
        context.set_oid_flags(0x44);
        context.set_str_flags(0x55);

        let context = context.as_ref();
        assert_eq!(context.flags(), 0x11);
        assert_eq!(context.nm_flags(), 0x22);
        assert_eq!(context.cert_flags(), 0x33);
        assert_eq!(context.oid_flags(), 0x44);
        assert_eq!(context.str_flags(), 0x55);
    }

    #[test]
    fn opaque_context_handles_and_owner_are_pointer_sized() {
        assert_eq!(
            size_of::<Asn1PctxRef<'static>>(),
            size_of::<*const ffi::asn1_pctx_st>()
        );
        assert_eq!(
            size_of::<Asn1PctxMut<'static>>(),
            size_of::<*mut ffi::asn1_pctx_st>()
        );
        assert_eq!(
            size_of::<CBox<Asn1Pctx>>(),
            size_of::<*mut ffi::asn1_pctx_st>()
        );
    }
}
