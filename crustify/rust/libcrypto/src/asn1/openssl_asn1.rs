//! Wrappers assigned from `include/openssl/asn1.h`.

use core::ffi::{c_int, c_void};
use core::ptr;

use ffibox::{CBox, define_ctype, impl_dropped};

use libcrypto_sys as ffi;

use crate::asn1::asn1::{Asn1Object, Asn1ObjectRef, Asn1StringMut, Asn1StringRef};
use crate::stack::stack::{Stack, StackMut, StackRef};

define_ctype!(
    /// Wraps: asn1_string_table_st
    ///
    /// Layout-compatible storage for one ASN.1 string-constraint record. A
    /// record has no destructor of its own: OpenSSL keeps them in two places
    /// and `flags` says which, through [`Asn1StringTableRef::is_heap_allocated`].
    ///
    /// * Records carrying `STABLE_FLAGS_MALLOC` were heap-allocated on behalf
    ///   of `ASN1_STRING_TABLE_add`, are owned by the process-global dynamic
    ///   table, and are released together when `ASN1_STRING_TABLE_cleanup`
    ///   frees that table through its `st_free` callback.
    /// * Records without it are elements of the `static const` standard table
    ///   compiled into the library. `ASN1_STRING_TABLE_get` casts that
    ///   constness away, so a record reached from a lookup may live in
    ///   read-only storage.
    ///
    /// Building an [`Asn1StringTableMut`] over a record therefore requires the
    /// caller to have established that the record is heap-allocated; writing
    /// through a standard-table record is undefined behaviour. The safe
    /// lookup in `a_strnid` avoids the question by copying the scalars out.
    Asn1StringTable,
    Asn1StringTableRef,
    Asn1StringTableMut,
    ffi::asn1_string_table_st
);

define_ctype!(
    /// Wraps: ASN1_VALUE_st
    ///
    /// OpenSSL deliberately leaves this tag undefined and uses its pointers as
    /// type-erased ASN.1 value handles. The borrowed handles therefore carry only
    /// pointer provenance and a Rust lifetime; they never expose a layout.
    Asn1Value,
    Asn1ValueRef,
    Asn1ValueMut,
    ffi::ASN1_VALUE_st
);

impl Asn1StringTableRef<'_> {
    /// Wraps: asn1_string_table_st.flags
    #[must_use]
    pub fn flags(&self) -> core::ffi::c_ulong {
        // SAFETY: this raw projection reads an initialized scalar field from
        // the live object represented by the shared handle.
        unsafe { ptr::addr_of!((*self.as_ptr()).flags).read() }
    }

    /// Whether this record was allocated by `ASN1_STRING_TABLE_add`.
    ///
    /// `true` means the record lives in the writable, process-global dynamic
    /// table; `false` means it is an element of the `static const` standard
    /// table and must never be written through, even though
    /// `ASN1_STRING_TABLE_get` hands it back as a non-const pointer.
    #[must_use]
    pub fn is_heap_allocated(&self) -> bool {
        self.flags() & core::ffi::c_ulong::from(ffi::STABLE_FLAGS_MALLOC) != 0
    }

    /// Whether the record's `mask` is used without the process default mask.
    ///
    /// `ASN1_STRING_set_by_NID` intersects `mask` with the default mask unless
    /// this `STABLE_NO_MASK` bit is set.
    #[must_use]
    pub fn ignores_default_mask(&self) -> bool {
        self.flags() & core::ffi::c_ulong::from(ffi::STABLE_NO_MASK) != 0
    }

    /// Wraps: asn1_string_table_st.nid
    #[must_use]
    pub fn nid(&self) -> core::ffi::c_int {
        // SAFETY: this raw projection reads an initialized scalar field from
        // the live object represented by the shared handle.
        unsafe { ptr::addr_of!((*self.as_ptr()).nid).read() }
    }

    /// Wraps: asn1_string_table_st.mask
    #[must_use]
    pub fn mask(&self) -> core::ffi::c_ulong {
        // SAFETY: this raw projection reads an initialized scalar field from
        // the live object represented by the shared handle.
        unsafe { ptr::addr_of!((*self.as_ptr()).mask).read() }
    }

    /// Wraps: asn1_string_table_st.minsize
    #[must_use]
    pub fn min_size(&self) -> core::ffi::c_long {
        // SAFETY: this raw projection reads an initialized scalar field from
        // the live object represented by the shared handle.
        unsafe { ptr::addr_of!((*self.as_ptr()).minsize).read() }
    }

    /// Wraps: asn1_string_table_st.maxsize
    #[must_use]
    pub fn max_size(&self) -> core::ffi::c_long {
        // SAFETY: this raw projection reads an initialized scalar field from
        // the live object represented by the shared handle.
        unsafe { ptr::addr_of!((*self.as_ptr()).maxsize).read() }
    }
}

/// Setters for a record whose storage the caller has proven writable.
///
/// Only a record carrying `STABLE_FLAGS_MALLOC` qualifies; see
/// [`Asn1StringTable`] and [`Asn1StringTableRef::is_heap_allocated`].
impl Asn1StringTableMut<'_> {
    /// Set the table flags.
    pub fn set_flags(&mut self, flags: core::ffi::c_ulong) {
        // SAFETY: this raw projection writes the scalar field through the
        // exclusive handle without forming a reference to the C object.
        unsafe { ptr::addr_of_mut!((*self.as_mut_ptr()).flags).write(flags) }
    }

    /// Set the numeric object identifier.
    pub fn set_nid(&mut self, nid: core::ffi::c_int) {
        // SAFETY: this raw projection writes the scalar field through the
        // exclusive handle without forming a reference to the C object.
        unsafe { ptr::addr_of_mut!((*self.as_mut_ptr()).nid).write(nid) }
    }

    /// Set the permitted ASN.1 string type mask.
    pub fn set_mask(&mut self, mask: core::ffi::c_ulong) {
        // SAFETY: this raw projection writes the scalar field through the
        // exclusive handle without forming a reference to the C object.
        unsafe { ptr::addr_of_mut!((*self.as_mut_ptr()).mask).write(mask) }
    }

    /// Set the minimum string size.
    pub fn set_min_size(&mut self, min_size: core::ffi::c_long) {
        // SAFETY: this raw projection writes the scalar field through the
        // exclusive handle without forming a reference to the C object.
        unsafe { ptr::addr_of_mut!((*self.as_mut_ptr()).minsize).write(min_size) }
    }

    /// Set the maximum string size.
    pub fn set_max_size(&mut self, max_size: core::ffi::c_long) {
        // SAFETY: this raw projection writes the scalar field through the
        // exclusive handle without forming a reference to the C object.
        unsafe { ptr::addr_of_mut!((*self.as_mut_ptr()).maxsize).write(max_size) }
    }
}

#[cfg(test)]
mod tests {
    use core::ptr;

    use super::*;

    #[test]
    fn scalar_fields_round_trip_through_handles() {
        let mut value = Asn1StringTable::zeroed();
        let raw = ptr::addr_of_mut!(value).cast::<ffi::asn1_string_table_st>();
        // SAFETY: `raw` points to a live layout-compatible value and remains
        // exclusively borrowed for the lifetime of the returned handle.
        let mut view =
            unsafe { Asn1StringTableMut::from_ptr(raw) }.expect("stack ASN.1 string table");

        view.set_nid(7);
        view.set_min_size(8);
        view.set_max_size(64);
        view.set_mask(0x1234);
        view.set_flags(0x2);

        let shared = view.as_ref();
        assert_eq!(shared.nid(), 7);
        assert_eq!(shared.min_size(), 8);
        assert_eq!(shared.max_size(), 64);
        assert_eq!(shared.mask(), 0x1234);
        assert_eq!(shared.flags(), 0x2);
    }

    #[test]
    fn flag_predicates_report_the_records_storage_class_and_mask_rule() {
        let mut value = Asn1StringTable::zeroed();
        let raw = ptr::addr_of_mut!(value).cast::<ffi::asn1_string_table_st>();
        // SAFETY: `raw` points to a live layout-compatible value and remains
        // exclusively borrowed for the lifetime of the returned handle.
        let mut view =
            unsafe { Asn1StringTableMut::from_ptr(raw) }.expect("stack ASN.1 string table");

        assert!(!view.as_ref().is_heap_allocated());
        assert!(!view.as_ref().ignores_default_mask());

        view.set_flags(core::ffi::c_ulong::from(
            ffi::STABLE_FLAGS_MALLOC | ffi::STABLE_NO_MASK,
        ));
        assert!(view.as_ref().is_heap_allocated());
        assert!(view.as_ref().ignores_default_mask());

        view.set_flags(core::ffi::c_ulong::from(ffi::STABLE_NO_MASK));
        assert!(!view.as_ref().is_heap_allocated());
        assert!(view.as_ref().ignores_default_mask());
    }

    #[test]
    fn a_standard_table_entry_is_not_heap_allocated() {
        // The standard entries live in a `static const` array, so a lookup that
        // reports no `STABLE_FLAGS_MALLOC` bit is one no caller may write to.
        let nid = crate::objects::obj_dat::OBJ_sn2nid(c"CN");
        let entry = crate::asn1::a_strnid::ASN1_STRING_TABLE_get(nid)
            .expect("commonName standard table entry");
        assert_eq!(
            entry.flags & core::ffi::c_ulong::from(ffi::STABLE_FLAGS_MALLOC),
            0
        );
    }

    #[test]
    fn erased_value_borrows_are_pointer_sized() {
        assert_eq!(
            core::mem::size_of::<Asn1ValueRef<'static>>(),
            core::mem::size_of::<*mut ffi::ASN1_VALUE_st>()
        );
        assert_eq!(
            core::mem::size_of::<Asn1ValueMut<'static>>(),
            core::mem::size_of::<*mut ffi::ASN1_VALUE_st>()
        );

        let mut storage = 0_u8;
        let raw = ptr::addr_of_mut!(storage).cast::<ffi::ASN1_VALUE_st>();
        // SAFETY: the opaque ASN1_VALUE pointer denotes the live byte of
        // type-erased storage for the duration of this handle.
        let shared = unsafe { Asn1ValueRef::from_ptr(raw) }.expect("non-null value");
        assert_eq!(shared.as_ptr(), raw.cast_const());
        let _ = shared;

        // SAFETY: the same live erased storage is now borrowed exclusively.
        let mut exclusive = unsafe { Asn1ValueMut::from_ptr(raw) }.expect("non-null value");
        assert_eq!(exclusive.as_mut_ptr(), raw);
        assert_eq!(exclusive.as_ref().as_ptr(), raw.cast_const());
    }
}

/// Wraps: stack_st_ASN1_STRING_TABLE
///
/// Typed view of OpenSSL's `STACK_OF(ASN1_STRING_TABLE)`. `DEFINE_STACK_OF`
/// only forward-declares the tag and casts every operation to
/// `OPENSSL_STACK *`, so the instance is the generic container with
/// [`Asn1StringTable`] retained as its element type.
///
/// The container owns its pointer array and not the records in it. That is
/// the ownership `a_strnid.c` relies on: the process-global `stable` holds
/// both heap records created by `ASN1_STRING_TABLE_add` and, after a lookup,
/// nothing else — it is released with `sk_ASN1_STRING_TABLE_pop_free` and its
/// `st_free` callback, which [`Stack::into_pop_free`] models, never with the
/// plain destructor bound here.
pub type Asn1StringTableStack = Stack<Asn1StringTable>;

/// Shared borrowed handle to a `STACK_OF(ASN1_STRING_TABLE)`.
pub type Asn1StringTableStackRef<'a> = StackRef<'a, Asn1StringTable>;

/// Exclusive borrowed handle to a `STACK_OF(ASN1_STRING_TABLE)`.
pub type Asn1StringTableStackMut<'a> = StackMut<'a, Asn1StringTable>;

#[cfg(test)]
mod stack_tests {
    use core::mem::size_of;
    use core::ptr;

    use ffibox::{CBox, CCell, CCloned, CDropped};

    use super::*;
    use crate::stack::stack::{
        OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_pop, OPENSSL_sk_push, OPENSSL_sk_value,
        StackElement,
    };

    fn assert_owned_cloneable_cell<T: CCell + CCloned + CDropped>() {}

    #[test]
    fn string_table_stack_keeps_its_typed_erased_surface() {
        assert_owned_cloneable_cell::<Asn1StringTableStack>();
        // The owner and both handles are one pointer wide: the generated tag
        // adds nothing to `OPENSSL_STACK`'s representation.
        assert_eq!(
            size_of::<CBox<Asn1StringTableStack>>(),
            size_of::<*mut ffi::OPENSSL_STACK>()
        );
        assert_eq!(
            size_of::<Asn1StringTableStackRef<'static>>(),
            size_of::<*mut ffi::OPENSSL_STACK>()
        );
        assert_eq!(
            size_of::<Asn1StringTableStackMut<'static>>(),
            size_of::<*mut ffi::OPENSSL_STACK>()
        );

        // `OPENSSL_sk_dup(NULL)` creates a complete empty stack.
        // SAFETY: ownership of the returned allocation transfers to `CBox`,
        // whose generic stack destructor calls the matching `OPENSSL_sk_free`.
        let mut stack =
            unsafe { CBox::<Asn1StringTableStack>::from_raw(ffi::OPENSSL_sk_dup(ptr::null())) }
                .expect("allocate ASN1_STRING_TABLE stack");
        let raw = stack.as_ptr();

        let shared: Asn1StringTableStackRef<'_> = stack.as_ref();
        assert_eq!(shared.as_ptr(), raw.cast_const());
        let mut exclusive: Asn1StringTableStackMut<'_> = stack.as_mut();
        assert_eq!(exclusive.as_mut_ptr(), raw);
        assert_eq!(exclusive.as_ref().as_ptr(), raw.cast_const());

        let duplicate = stack.try_clone().expect("duplicate typed stack");
        assert_ne!(duplicate.as_ptr(), raw);
    }

    #[test]
    fn string_table_stack_hands_back_typed_record_handles() {
        let mut record = Asn1StringTable::zeroed();
        {
            // SAFETY: `record` is caller-owned writable storage, live for this
            // handle, and no other handle to it is in use.
            let mut writable =
                unsafe { Asn1StringTableMut::from_ptr(ptr::from_mut(&mut record).cast()) }
                    .expect("address of local storage is non-null");
            writable.set_nid(1234);
            writable.set_mask(0x5A);
        }
        // SAFETY: the address has the container's element type and `record`
        // outlives every stack below.
        let element = unsafe { StackElement::from_raw(ptr::from_mut(&mut record)) }
            .expect("address of local storage is non-null");

        let mut stack =
            OPENSSL_sk_new_null::<Asn1StringTable>().expect("allocate ASN1_STRING_TABLE stack");
        {
            let mut exclusive = stack.as_mut();
            // SAFETY: `record` outlives the stack and no comparator is set, so
            // nothing dereferences the element during storage.
            unsafe {
                assert_eq!(
                    OPENSSL_sk_push(Some(&mut exclusive), Some(element)),
                    Some(1)
                );
            }
        }
        assert_eq!(OPENSSL_sk_num(Some(stack.as_ref())), Some(1));

        let stored = OPENSSL_sk_value(Some(stack.as_ref()), 0).expect("stored record");
        assert_eq!(stored.as_non_null(), element.as_non_null());
        // SAFETY: the slot holds the still-live `record`, which no handle is
        // mutating for the duration of this shared borrow.
        let stored_ref =
            unsafe { Asn1StringTableRef::from_ptr(stored.as_non_null().as_ptr().cast()) }
                .expect("non-null stored record");
        assert_eq!(stored_ref.nid(), 1234);
        assert_eq!(stored_ref.mask(), 0x5A);
        assert!(!stored_ref.is_heap_allocated());

        assert_eq!(
            OPENSSL_sk_pop(Some(&mut stack.as_mut())).map(StackElement::as_non_null),
            Some(element.as_non_null())
        );

        // `OPENSSL_sk_free` releases the pointer array only; the record is
        // still the caller's, which is why `ASN1_STRING_TABLE_cleanup` needs
        // the pop-free form to reclaim the heap entries as well.
        drop(stack);
        // SAFETY: `record` is still live, caller-owned storage and no other
        // handle to it exists at this point.
        let survivor = unsafe { Asn1StringTableRef::from_ptr(ptr::from_mut(&mut record).cast()) }
            .expect("address of local storage is non-null");
        assert_eq!(survivor.nid(), 1234);
    }
}

define_ctype!(
    /// Wraps: asn1_type_st
    ///
    /// Layout-compatible storage for OpenSSL's discriminated ASN.1 value.
    /// Owned values are held in `CBox<Asn1Type>`; borrowed access goes through
    /// the tagged `value` view and never forms a Rust reference to C storage.
    Asn1Type,
    Asn1TypeRef,
    Asn1TypeMut,
    ffi::asn1_type_st
);

impl_dropped!(Asn1Type, ffi::asn1_type_st, ffi::ASN1_TYPE_free);

/// Wraps: asn1_type_st.type
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Asn1TypeKind {
    Boolean,
    Integer,
    BitString,
    OctetString,
    Null,
    Object,
    Enumerated,
    Utf8String,
    Sequence,
    Set,
    PrintableString,
    T61String,
    Ia5String,
    UtcTime,
    GeneralizedTime,
    VisibleString,
    GeneralString,
    UniversalString,
    BmpString,
    Other,
    /// A tag without a dedicated member in the public `ASN1_TYPE` union.
    Unknown(c_int),
}

impl Asn1TypeKind {
    /// Converts an OpenSSL ASN.1 tag into a lossless Rust discriminator.
    #[must_use]
    pub fn from_raw(raw: c_int) -> Self {
        match raw {
            value if value == ffi::V_ASN1_BOOLEAN as c_int => Self::Boolean,
            value if value == ffi::V_ASN1_INTEGER as c_int => Self::Integer,
            value if value == ffi::V_ASN1_BIT_STRING as c_int => Self::BitString,
            value if value == ffi::V_ASN1_OCTET_STRING as c_int => Self::OctetString,
            value if value == ffi::V_ASN1_NULL as c_int => Self::Null,
            value if value == ffi::V_ASN1_OBJECT as c_int => Self::Object,
            value if value == ffi::V_ASN1_ENUMERATED as c_int => Self::Enumerated,
            value if value == ffi::V_ASN1_UTF8STRING as c_int => Self::Utf8String,
            value if value == ffi::V_ASN1_SEQUENCE as c_int => Self::Sequence,
            value if value == ffi::V_ASN1_SET as c_int => Self::Set,
            value if value == ffi::V_ASN1_PRINTABLESTRING as c_int => Self::PrintableString,
            value if value == ffi::V_ASN1_T61STRING as c_int => Self::T61String,
            value if value == ffi::V_ASN1_IA5STRING as c_int => Self::Ia5String,
            value if value == ffi::V_ASN1_UTCTIME as c_int => Self::UtcTime,
            value if value == ffi::V_ASN1_GENERALIZEDTIME as c_int => Self::GeneralizedTime,
            value if value == ffi::V_ASN1_VISIBLESTRING as c_int => Self::VisibleString,
            value if value == ffi::V_ASN1_GENERALSTRING as c_int => Self::GeneralString,
            value if value == ffi::V_ASN1_UNIVERSALSTRING as c_int => Self::UniversalString,
            value if value == ffi::V_ASN1_BMPSTRING as c_int => Self::BmpString,
            ffi::V_ASN1_OTHER => Self::Other,
            value => Self::Unknown(value),
        }
    }

    /// Returns the tag expected by OpenSSL.
    #[must_use]
    pub const fn as_raw(self) -> c_int {
        match self {
            Self::Boolean => ffi::V_ASN1_BOOLEAN as c_int,
            Self::Integer => ffi::V_ASN1_INTEGER as c_int,
            Self::BitString => ffi::V_ASN1_BIT_STRING as c_int,
            Self::OctetString => ffi::V_ASN1_OCTET_STRING as c_int,
            Self::Null => ffi::V_ASN1_NULL as c_int,
            Self::Object => ffi::V_ASN1_OBJECT as c_int,
            Self::Enumerated => ffi::V_ASN1_ENUMERATED as c_int,
            Self::Utf8String => ffi::V_ASN1_UTF8STRING as c_int,
            Self::Sequence => ffi::V_ASN1_SEQUENCE as c_int,
            Self::Set => ffi::V_ASN1_SET as c_int,
            Self::PrintableString => ffi::V_ASN1_PRINTABLESTRING as c_int,
            Self::T61String => ffi::V_ASN1_T61STRING as c_int,
            Self::Ia5String => ffi::V_ASN1_IA5STRING as c_int,
            Self::UtcTime => ffi::V_ASN1_UTCTIME as c_int,
            Self::GeneralizedTime => ffi::V_ASN1_GENERALIZEDTIME as c_int,
            Self::VisibleString => ffi::V_ASN1_VISIBLESTRING as c_int,
            Self::GeneralString => ffi::V_ASN1_GENERALSTRING as c_int,
            Self::UniversalString => ffi::V_ASN1_UNIVERSALSTRING as c_int,
            Self::BmpString => ffi::V_ASN1_BMPSTRING as c_int,
            Self::Other => ffi::V_ASN1_OTHER,
            Self::Unknown(value) => value,
        }
    }

    const fn is_string(self) -> bool {
        !matches!(
            self,
            Self::Boolean | Self::Null | Self::Object | Self::Other | Self::Unknown(_)
        )
    }
}

/// Wraps: asn1_type_st.value.asn1_string
///
/// A type-tagged borrow of the common `asn1_string_st` representation. The
/// concrete tag travels with the borrow so `try_set_string` cannot copy it
/// using an incompatible ASN.1 discriminator.
#[derive(Clone, Copy)]
pub struct Asn1TypeStringRef<'a> {
    value: Asn1StringRef<'a>,
    kind: Asn1TypeKind,
}

impl<'a> Asn1TypeStringRef<'a> {
    /// Returns the concrete ASN.1 string kind.
    #[must_use]
    pub const fn kind(self) -> Asn1TypeKind {
        self.kind
    }

    /// Returns the typed borrow of the common ASN.1 string representation.
    #[must_use]
    pub const fn as_string(self) -> Asn1StringRef<'a> {
        self.value
    }
}

/// Wraps: asn1_type_st.value
#[derive(Clone, Copy)]
pub enum Asn1TypeValue<'a> {
    /// Wraps: asn1_type_st.value.boolean
    Boolean(c_int),
    Null,
    /// Wraps: asn1_type_st.value.object
    Object(Option<Asn1ObjectRef<'a>>),
    /// Wraps: asn1_type_st.value.integer
    Integer(Option<Asn1TypeStringRef<'a>>),
    /// Wraps: asn1_type_st.value.enumerated
    Enumerated(Option<Asn1TypeStringRef<'a>>),
    /// Wraps: asn1_type_st.value.bit_string
    BitString(Option<Asn1TypeStringRef<'a>>),
    /// Wraps: asn1_type_st.value.octet_string
    OctetString(Option<Asn1TypeStringRef<'a>>),
    /// Wraps: asn1_type_st.value.printablestring
    PrintableString(Option<Asn1TypeStringRef<'a>>),
    /// Wraps: asn1_type_st.value.t61string
    T61String(Option<Asn1TypeStringRef<'a>>),
    /// Wraps: asn1_type_st.value.ia5string
    Ia5String(Option<Asn1TypeStringRef<'a>>),
    /// Wraps: asn1_type_st.value.generalstring
    GeneralString(Option<Asn1TypeStringRef<'a>>),
    /// Wraps: asn1_type_st.value.bmpstring
    BmpString(Option<Asn1TypeStringRef<'a>>),
    /// Wraps: asn1_type_st.value.universalstring
    UniversalString(Option<Asn1TypeStringRef<'a>>),
    /// Wraps: asn1_type_st.value.utctime
    UtcTime(Option<Asn1TypeStringRef<'a>>),
    /// Wraps: asn1_type_st.value.generalizedtime
    GeneralizedTime(Option<Asn1TypeStringRef<'a>>),
    /// Wraps: asn1_type_st.value.visiblestring
    VisibleString(Option<Asn1TypeStringRef<'a>>),
    /// Wraps: asn1_type_st.value.utf8string
    Utf8String(Option<Asn1TypeStringRef<'a>>),
    /// Wraps: asn1_type_st.value.set
    Set(Option<Asn1TypeStringRef<'a>>),
    /// Wraps: asn1_type_st.value.sequence
    Sequence(Option<Asn1TypeStringRef<'a>>),
    /// Wraps: asn1_type_st.value.asn1_value
    Other(Option<Asn1ValueRef<'a>>),
    /// Wraps: asn1_type_st.value.ptr
    Unknown {
        type_tag: c_int,
        value: Option<Asn1ValueRef<'a>>,
    },
}

impl Asn1Type {
    /// Allocates OpenSSL's default empty ASN.1 type.
    #[must_use]
    pub fn new() -> Option<CBox<Self>> {
        // SAFETY: a non-null `ASN1_TYPE_new` result is a fully initialized
        // allocation whose matching destructor is registered above.
        unsafe { CBox::from_raw(ffi::ASN1_TYPE_new()) }
    }
}

impl<'a> Asn1TypeRef<'a> {
    /// Returns the lossless ASN.1 discriminator.
    #[must_use]
    pub fn kind(&self) -> Asn1TypeKind {
        // SAFETY: the live shared handle permits copying the initialized tag
        // through a raw-place projection.
        let raw = unsafe { ptr::addr_of!((*self.as_ptr()).type_).read() };
        Asn1TypeKind::from_raw(raw)
    }

    fn string_value(&self, kind: Asn1TypeKind) -> Option<Asn1TypeStringRef<'a>> {
        if !kind.is_string() {
            return None;
        }
        // SAFETY: `kind` was read from this live `ASN1_TYPE` and selects one
        // of the `asn1_string_st`-compatible arms. Reading the common union
        // pointer does not dereference it or form a reference to C storage.
        let raw = unsafe { ptr::addr_of!((*self.as_ptr()).value.asn1_string).read() };
        // SAFETY: a non-null active string arm denotes a live ASN.1 string for
        // this handle's lifetime; the typed handle preserves that lifetime.
        let value = unsafe { Asn1StringRef::from_ptr(raw) }?;
        Some(Asn1TypeStringRef { value, kind })
    }

    /// Returns a tagged, nullable-aware view of the active union arm.
    #[must_use]
    pub fn value(&self) -> Asn1TypeValue<'a> {
        let kind = self.kind();
        match kind {
            Asn1TypeKind::Boolean => {
                // SAFETY: the discriminator selects the initialized boolean
                // scalar and the raw projection merely copies it.
                let value = unsafe { ptr::addr_of!((*self.as_ptr()).value.boolean).read() };
                Asn1TypeValue::Boolean(value)
            }
            Asn1TypeKind::Null => Asn1TypeValue::Null,
            Asn1TypeKind::Object => {
                // SAFETY: the discriminator selects the object pointer arm;
                // copying the pointer does not access the object itself.
                let raw = unsafe { ptr::addr_of!((*self.as_ptr()).value.object).read() };
                // SAFETY: a non-null active object arm is a live ASN1_OBJECT
                // borrowed for the lifetime carried by this type handle.
                let object = unsafe { Asn1ObjectRef::from_ptr(raw) };
                Asn1TypeValue::Object(object)
            }
            Asn1TypeKind::Integer => Asn1TypeValue::Integer(self.string_value(kind)),
            Asn1TypeKind::Enumerated => Asn1TypeValue::Enumerated(self.string_value(kind)),
            Asn1TypeKind::BitString => Asn1TypeValue::BitString(self.string_value(kind)),
            Asn1TypeKind::OctetString => Asn1TypeValue::OctetString(self.string_value(kind)),
            Asn1TypeKind::PrintableString => {
                Asn1TypeValue::PrintableString(self.string_value(kind))
            }
            Asn1TypeKind::T61String => Asn1TypeValue::T61String(self.string_value(kind)),
            Asn1TypeKind::Ia5String => Asn1TypeValue::Ia5String(self.string_value(kind)),
            Asn1TypeKind::GeneralString => Asn1TypeValue::GeneralString(self.string_value(kind)),
            Asn1TypeKind::BmpString => Asn1TypeValue::BmpString(self.string_value(kind)),
            Asn1TypeKind::UniversalString => {
                Asn1TypeValue::UniversalString(self.string_value(kind))
            }
            Asn1TypeKind::UtcTime => Asn1TypeValue::UtcTime(self.string_value(kind)),
            Asn1TypeKind::GeneralizedTime => {
                Asn1TypeValue::GeneralizedTime(self.string_value(kind))
            }
            Asn1TypeKind::VisibleString => Asn1TypeValue::VisibleString(self.string_value(kind)),
            Asn1TypeKind::Utf8String => Asn1TypeValue::Utf8String(self.string_value(kind)),
            Asn1TypeKind::Set => Asn1TypeValue::Set(self.string_value(kind)),
            Asn1TypeKind::Sequence => Asn1TypeValue::Sequence(self.string_value(kind)),
            Asn1TypeKind::Other => {
                // SAFETY: the discriminator selects the erased ASN.1 value
                // pointer; copying it does not access its pointee.
                let raw = unsafe { ptr::addr_of!((*self.as_ptr()).value.asn1_value).read() };
                // SAFETY: a non-null active value is live for this handle's
                // lifetime and remains type-erased.
                let value = unsafe { Asn1ValueRef::from_ptr(raw) };
                Asn1TypeValue::Other(value)
            }
            Asn1TypeKind::Unknown(type_tag) => {
                // SAFETY: every union arm shares the pointer-sized storage;
                // copying `ptr` neither dereferences nor interprets the pointee.
                let raw = unsafe { ptr::addr_of!((*self.as_ptr()).value.ptr).read() };
                // SAFETY: a non-null pointer in a live unknown arm is exposed
                // only as an erased borrow tied to this handle.
                let value = unsafe { Asn1ValueRef::from_ptr(raw.cast()) };
                Asn1TypeValue::Unknown { type_tag, value }
            }
        }
    }
}

impl Asn1TypeMut<'_> {
    /// Replaces the current value with ASN.1 NULL, releasing any owned payload.
    pub fn set_null(&mut self) {
        // SAFETY: the exclusive handle is a live `ASN1_TYPE`; OpenSSL releases
        // its old active payload and NULL carries no pointer payload.
        unsafe {
            ffi::ASN1_TYPE_set(
                self.as_mut_ptr(),
                ffi::V_ASN1_NULL as c_int,
                ptr::null_mut(),
            )
        }
    }

    /// Replaces the current value with a canonical ASN.1 BOOLEAN.
    pub fn set_boolean(&mut self, value: bool) {
        let marker = if value {
            ptr::NonNull::<c_void>::dangling().as_ptr()
        } else {
            ptr::null_mut()
        };
        // SAFETY: OpenSSL only tests the marker for null in the BOOLEAN branch;
        // it releases any old active payload before storing the scalar.
        unsafe { ffi::ASN1_TYPE_set(self.as_mut_ptr(), ffi::V_ASN1_BOOLEAN as c_int, marker) }
    }

    /// Transfers an owned ASN.1 object into this value.
    pub fn set_object_owned(&mut self, object: CBox<Asn1Object>) {
        let object = object.into_raw().cast::<c_void>();
        // SAFETY: ownership of `object` has been surrendered. OpenSSL releases
        // the old payload and records the matching OBJECT discriminator.
        unsafe { ffi::ASN1_TYPE_set(self.as_mut_ptr(), ffi::V_ASN1_OBJECT as c_int, object) }
    }

    /// Deep-copies a borrowed ASN.1 object into this value.
    pub fn try_set_object(&mut self, object: Asn1ObjectRef<'_>) -> bool {
        // SAFETY: both handles are live. `ASN1_TYPE_set1` duplicates the object
        // before replacing this value and reports allocation failure as zero.
        unsafe {
            ffi::ASN1_TYPE_set1(
                self.as_mut_ptr(),
                ffi::V_ASN1_OBJECT as c_int,
                object.as_ptr().cast::<c_void>(),
            ) != 0
        }
    }

    /// Deep-copies a tagged ASN.1 string value into this value.
    pub fn try_set_string(&mut self, value: Asn1TypeStringRef<'_>) -> bool {
        // SAFETY: `value` can only be created from a live string-compatible
        // union arm and carries its exact discriminator. OpenSSL duplicates it
        // before replacing the current payload.
        unsafe {
            ffi::ASN1_TYPE_set1(
                self.as_mut_ptr(),
                value.kind.as_raw(),
                value.value.as_ptr().cast::<c_void>(),
            ) != 0
        }
    }
}

#[cfg(test)]
mod asn1_type_tests {
    use core::mem::{align_of, size_of};

    use super::*;

    #[test]
    fn layout_and_owned_lifecycle_match_openssl() {
        assert_eq!(size_of::<Asn1Type>(), size_of::<ffi::asn1_type_st>());
        assert_eq!(align_of::<Asn1Type>(), align_of::<ffi::asn1_type_st>());
        assert_eq!(
            size_of::<CBox<Asn1Type>>(),
            size_of::<*mut ffi::asn1_type_st>()
        );

        let mut value = Asn1Type::new().expect("ASN1_TYPE_new");
        value.as_mut().set_boolean(true);
        assert!(matches!(
            value.as_ref().value(),
            Asn1TypeValue::Boolean(0xff)
        ));
        value.as_mut().set_null();
        assert!(matches!(value.as_ref().value(), Asn1TypeValue::Null));
    }

    #[test]
    fn object_ownership_transfers_and_borrowed_objects_duplicate() {
        // SAFETY: the literal is NUL terminated and OpenSSL returns a fresh
        // fully initialized object or null.
        let raw = unsafe { ffi::OBJ_txt2obj(c"1.3.6.1.4.1.55555.424242".as_ptr(), 1) };
        // SAFETY: a distinct numeric OID result transfers one free obligation.
        let object = unsafe { CBox::<Asn1Object>::from_raw(raw) }.expect("ASN1 object");

        let mut first = Asn1Type::new().expect("first ASN1_TYPE");
        first.as_mut().set_object_owned(object);
        let Asn1TypeValue::Object(Some(borrowed)) = first.as_ref().value() else {
            panic!("object arm");
        };
        assert_eq!(borrowed.as_ptr(), raw.cast_const());

        let mut second = Asn1Type::new().expect("second ASN1_TYPE");
        assert!(second.as_mut().try_set_object(borrowed));
        let Asn1TypeValue::Object(Some(duplicate)) = second.as_ref().value() else {
            panic!("duplicated object arm");
        };
        assert_ne!(duplicate.as_ptr(), raw.cast_const());
    }

    #[test]
    fn string_and_erased_union_arms_stay_lifetime_bound() {
        // SAFETY: OpenSSL returns either null or a fresh initialized string.
        let string =
            unsafe { CBox::<crate::asn1::asn1::Asn1String>::from_raw(ffi::ASN1_STRING_new()) }
                .expect("ASN1_STRING_new");
        let mut raw = ffi::asn1_type_st {
            type_: ffi::V_ASN1_BMPSTRING as c_int,
            value: ffi::asn1_type_st__bindgen_ty_1 {
                bmpstring: string.as_ptr(),
            },
        };
        // SAFETY: `raw` is initialized and its non-null opaque payload remains
        // live for the returned handle's use in this scope.
        let value = unsafe { Asn1TypeRef::from_ptr(&raw mut raw) }.expect("ASN1_TYPE view");
        let Asn1TypeValue::BmpString(Some(string_value)) = value.value() else {
            panic!("BMP string arm");
        };
        assert_eq!(string_value.kind(), Asn1TypeKind::BmpString);
        assert_eq!(
            string_value.as_string().as_ptr(),
            string.as_ptr().cast_const()
        );

        raw.type_ = ffi::V_ASN1_OTHER;
        raw.value = ffi::asn1_type_st__bindgen_ty_1 {
            asn1_value: string.as_ptr().cast(),
        };
        // SAFETY: the prior handle is no longer used; `raw` and its erased
        // payload remain initialized and live for this new shared borrow.
        let value = unsafe { Asn1TypeRef::from_ptr(&raw mut raw) }.expect("erased ASN1_TYPE view");
        assert!(matches!(value.value(), Asn1TypeValue::Other(Some(_))));
    }
}

/// Wraps: ASN1_OBJECT_new
///
/// OpenSSL 4.0 deprecated this compatibility constructor and its retained C
/// implementation always returns null. Use `ASN1_OBJECT_create` for a value.
#[must_use]
#[allow(non_snake_case)]
pub fn ASN1_OBJECT_new() -> Option<ffibox::CBox<crate::asn1::asn1::Asn1Object>> {
    None
}

/// Wraps: ASN1_STRING_length
/// Compatibility getter for OpenSSL's signed legacy length API.
#[must_use]
#[allow(non_snake_case)]
pub fn ASN1_STRING_length(string: Asn1StringRef<'_>) -> c_int {
    // SAFETY: the shared handle is live; the compatibility shim only copies
    // the initialized signed length field.
    unsafe { ffi::crustify_ASN1_STRING_length(string.as_ptr()) }
}

/// Wraps: ASN1_STRING_length_set
/// Shrinks the logical string length without changing its allocation.
///
/// Unlike the deprecated C entry point, this safe surface rejects growth:
/// OpenSSL does not track the allocation capacity needed to prove such a write
/// leaves later reads and destruction in bounds.
#[must_use]
#[allow(non_snake_case)]
pub fn ASN1_STRING_length_set(string: &mut Asn1StringMut<'_>, new_length: usize) -> bool {
    let current = crate::asn1::asn1_lib::ASN1_STRING_get_length(string.as_ref());
    let Ok(new_length) = c_int::try_from(new_length) else {
        return false;
    };
    if usize::try_from(new_length).expect("nonnegative length") > current {
        return false;
    }
    // SAFETY: the exclusive handle permits the scalar update, and the safe
    // precondition restricts the new logical extent to initialized old bytes.
    unsafe { ffi::crustify_ASN1_STRING_length_set(string.as_mut_ptr(), new_length) }
    true
}

/// Wraps: ASN1_STRING_set
/// Deep-copies bytes and retains the legacy extra NUL byte after the data.
#[must_use]
#[allow(non_snake_case)]
pub fn ASN1_STRING_set(string: &mut Asn1StringMut<'_>, data: &[u8]) -> bool {
    if c_int::try_from(data.len()).is_err() {
        return false;
    }
    // SAFETY: the exclusive string is live and `data` supplies its reported
    // initialized bytes. The shim copies them into an OpenSSL allocation.
    unsafe { ffi::crustify_ASN1_STRING_set(string.as_mut_ptr(), data.as_ptr(), data.len()) == 1 }
}

#[cfg(test)]
mod legacy_string_tests {
    use super::*;

    #[test]
    fn legacy_setter_copies_and_safe_length_setter_only_shrinks() {
        let mut string = crate::asn1::asn1_lib::ASN1_STRING_new().expect("ASN1_STRING_new");
        assert!(ASN1_STRING_set(&mut string.as_mut(), b"legacy"));
        assert_eq!(ASN1_STRING_length(string.as_ref()), 6);
        assert!(!ASN1_STRING_length_set(&mut string.as_mut(), 7));
        assert!(ASN1_STRING_length_set(&mut string.as_mut(), 3));
        assert_eq!(ASN1_STRING_length(string.as_ref()), 3);
    }
}
