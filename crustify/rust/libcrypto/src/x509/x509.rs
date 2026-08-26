//! Wrappers assigned from `include/openssl/x509.h`.

use core::ptr;

use ffibox::{CBox, define_ctype, impl_cloned, impl_dropped};
use libcrypto_sys as ffi;

use crate::asn1::asn1::{Asn1Object, Asn1ObjectRef};
use crate::asn1::openssl_asn1::{Asn1Type, Asn1TypeMut, Asn1TypeRef};
use crate::stack::stack::{Stack, StackMut, StackRef};
use crate::x509::x509_internal::X509NameEntry;
pub use crate::x509::x509_local::X509Extension;

/// Wraps: stack_st_X509_EXTENSION
///
/// Typed view of OpenSSL's `STACK_OF(X509_EXTENSION)`. The generated C tag is
/// only a forward declaration and every operation erases it to
/// `OPENSSL_STACK *`, so this is the generic container with its extension
/// element type retained.
pub type X509ExtensionStack = Stack<X509Extension>;

/// Shared borrowed handle to a `STACK_OF(X509_EXTENSION)`.
pub type X509ExtensionStackRef<'a> = StackRef<'a, X509Extension>;

/// Exclusive borrowed handle to a `STACK_OF(X509_EXTENSION)`.
pub type X509ExtensionStackMut<'a> = StackMut<'a, X509Extension>;

#[cfg(test)]
mod tests {
    use core::mem::size_of;
    use core::ptr;

    use ffibox::{CBox, CCell, CCloned, CDropped};
    use libcrypto_sys as ffi;

    use super::*;
    use crate::stack::stack::{
        OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_push, OPENSSL_sk_value, StackElement,
    };

    fn assert_owned_cloneable_cell<T: CCell + CCloned + CDropped>() {}

    #[test]
    fn extension_stack_keeps_its_typed_erased_surface() {
        assert_owned_cloneable_cell::<X509ExtensionStack>();
        assert_eq!(
            size_of::<CBox<X509ExtensionStack>>(),
            size_of::<*mut ffi::OPENSSL_STACK>()
        );
        assert_eq!(
            size_of::<X509ExtensionStackRef<'static>>(),
            size_of::<*mut ffi::OPENSSL_STACK>()
        );
        assert_eq!(
            size_of::<X509ExtensionStackMut<'static>>(),
            size_of::<*mut ffi::OPENSSL_STACK>()
        );

        let mut stack = OPENSSL_sk_new_null::<X509Extension>().expect("extension stack");
        let raw = stack.as_ptr();
        let shared: X509ExtensionStackRef<'_> = stack.as_ref();
        assert_eq!(shared.as_ptr(), raw.cast_const());
        let mut exclusive: X509ExtensionStackMut<'_> = stack.as_mut();
        assert_eq!(exclusive.as_mut_ptr(), raw);
    }

    #[test]
    fn extension_stack_preserves_borrowed_element_addresses() {
        let extension_storage = Box::new(0x5a_u8);
        // SAFETY: the stable box address outlives the stack, which only moves
        // the opaque address between slots and never dereferences the marker.
        let element = unsafe {
            StackElement::from_raw(
                ptr::from_ref(&*extension_storage)
                    .cast_mut()
                    .cast::<X509Extension>(),
            )
        }
        .expect("non-null extension address");

        let mut stack = OPENSSL_sk_new_null::<X509Extension>().expect("extension stack");
        // SAFETY: `extension_storage` remains live through the final stack use,
        // and this stack has no comparator that could inspect the marker.
        assert_eq!(
            // SAFETY: the stable storage is valid for the retained borrow.
            unsafe { OPENSSL_sk_push(Some(&mut stack.as_mut()), Some(element)) },
            Some(1)
        );
        assert_eq!(OPENSSL_sk_num(Some(stack.as_ref())), Some(1));
        assert_eq!(
            OPENSSL_sk_value(Some(stack.as_ref()), 0).map(StackElement::as_non_null),
            Some(element.as_non_null())
        );

        // Plain stack destruction releases only the pointer array.
        drop(stack);
        assert_eq!(*extension_storage, 0x5a);
    }
}

define_ctype!(
    /// Wraps: X509_algor_st
    ///
    /// Layout-compatible storage for an ASN.1 `AlgorithmIdentifier`. Both
    /// pointer fields belong to the value: full destruction releases the
    /// algorithm object and optional parameter before releasing this record.
    /// Borrowed access is carried by [`X509AlgorRef`] and [`X509AlgorMut`]
    /// without forming a Rust reference over memory OpenSSL may mutate.
    ///
    /// # Embedded by value
    ///
    /// This record is also embedded by value, in the public
    /// `NETSCAPE_SPKI::sig_algor` and in the internal `x509_st`,
    /// `x509_cinf_st`, `X509_req_st`, `X509_crl_st` and `X509_crl_info_st`
    /// bodies. The layout newtype covers that placement and the two handles
    /// reach such a projected place. No `ffibox::CValued` is registered: the
    /// embedded teardown lives inside the parent's `ASN1_EMBED` template
    /// (`ossl_asn1_primitive_free` on each field, no header release) and
    /// OpenSSL publishes no standalone disposer for it, while the hand-built
    /// stack instance in `crypto/evp/evp_lib.c` deliberately *borrows* its
    /// `parameter` — so a dispose-on-drop by-value owner would be wrong for
    /// the one by-value shape Rust could construct today.
    ///
    /// # Duplication is fallible
    ///
    /// `X509_ALGOR_dup` re-encodes and re-decodes its source, so it fails for
    /// every identifier the SEQUENCE template cannot encode: `algorithm`
    /// detached, or holding an OID with no content octets. A freshly allocated
    /// identifier is already in that state — see [`X509Algor::new`] — so
    /// `Clone`, which aborts the process when the C routine fails, is not the
    /// right entry point here. Use [`ffibox::CBox::try_clone`] or
    /// [`crate::asn1::x_algor::X509_ALGOR_dup`], both of which surface the
    /// failure as `None`.
    X509Algor,
    X509AlgorRef,
    X509AlgorMut,
    ffi::X509_algor_st
);

// `X509_ALGOR_free` is the public full destructor generated from the ASN.1
// sequence template. It releases `algorithm`, the optional `parameter`, and
// finally the record allocation.
impl_dropped!(X509Algor, ffi::X509_algor_st, ffi::X509_ALGOR_free);

// This type has no reference count. `X509_ALGOR_dup` encodes and decodes the
// source into a fresh independent allocation, so every clone owes one full
// `X509_ALGOR_free`. That round trip is fallible for states this safe surface
// can reach, which is why the type documentation steers callers to the
// `Option`-returning duplication entry points rather than to `Clone`.
impl_cloned!(X509Algor, ffi::X509_algor_st, dup = ffi::X509_ALGOR_dup);

impl X509Algor {
    /// Allocates a fully initialized algorithm identifier.
    ///
    /// The SEQUENCE template does not leave the record blank: it installs the
    /// built-in `NID_undef` object in `algorithm` — so
    /// [`algorithm`](X509AlgorRef::algorithm) already reports `Some` — and
    /// leaves the optional `parameter` null. That object carries no content
    /// octets, so the fresh identifier is allocated but not yet encodable.
    #[must_use]
    pub fn new() -> Option<CBox<Self>> {
        // SAFETY: a non-null result is a fresh, fully initialized allocation
        // carrying one `X509_ALGOR_free` ownership obligation.
        unsafe { CBox::from_raw(ffi::X509_ALGOR_new()) }
    }
}

impl<'a> X509AlgorRef<'a> {
    /// Wraps: X509_algor_st.algorithm
    ///
    /// Borrows the installed algorithm OID. Null is representable: the public
    /// layout, `X509_ALGOR_set0` and the stack instances OpenSSL builds by hand
    /// in `crypto/evp/evp_lib.c` all leave this slot empty. The template marks
    /// the field mandatory, so encoding an identifier in that state fails
    /// rather than omitting it, and so does `X509_ALGOR_dup`.
    #[must_use]
    pub fn algorithm(&self) -> Option<Asn1ObjectRef<'a>> {
        // SAFETY: raw-place projection copies the pointer from the live shared
        // handle without forming a reference to C storage. A non-null object is
        // owned by the identifier and therefore lives for this handle's `'a`.
        unsafe {
            let algorithm = ptr::addr_of!((*self.as_ptr()).algorithm).read();
            Asn1ObjectRef::from_ptr(algorithm)
        }
    }

    /// Wraps: X509_algor_st.parameter
    ///
    /// Borrows the optional tagged ASN.1 parameter.
    #[must_use]
    pub fn parameter(&self) -> Option<Asn1TypeRef<'a>> {
        // SAFETY: raw-place projection copies the pointer from the live shared
        // handle. A non-null parameter is owned by the identifier and remains
        // live for this handle's `'a`.
        unsafe {
            let parameter = ptr::addr_of!((*self.as_ptr()).parameter).read();
            Asn1TypeRef::from_ptr(parameter)
        }
    }
}

impl X509AlgorMut<'_> {
    /// Exclusively reborrows the optional tagged ASN.1 parameter.
    #[must_use]
    pub fn parameter_mut(&mut self) -> Option<Asn1TypeMut<'_>> {
        // SAFETY: the exclusive identifier handle supplies exclusive access to
        // its owned parameter for the duration of this reborrow.
        unsafe {
            let parameter = ptr::addr_of!((*self.as_mut_ptr()).parameter).read();
            Asn1TypeMut::from_ptr(parameter)
        }
    }

    /// Replaces the owned algorithm object and releases the previous value.
    pub fn set_algorithm(&mut self, algorithm: Option<CBox<Asn1Object>>) {
        let algorithm = algorithm.map_or(ptr::null_mut(), CBox::into_raw);
        // SAFETY: the exclusive handle permits replacing this owned pointer.
        // The old non-null value carries exactly the release the field owed,
        // which transfers into the temporary owner below.
        let previous =
            unsafe { ptr::addr_of_mut!((*self.as_mut_ptr()).algorithm).replace(algorithm) };
        // SAFETY: the prior field value, when non-null, was owned by this
        // identifier and is no longer reachable through it. `ASN1_OBJECT_free`
        // is flag-guarded, so adopting a built-in object here — the state
        // `X509_ALGOR_new` leaves behind — releases nothing.
        drop(unsafe { CBox::<Asn1Object>::from_raw(previous) });
    }

    /// Takes the owned algorithm object, leaving the nullable slot empty.
    ///
    /// The detached object may be a built-in registry entry — that is what
    /// `X509_ALGOR_new` installs — whose `ASN1_OBJECT_free` is a documented
    /// no-op, so the returned owner is safe either way. The identifier is left
    /// unencodable until a new object is installed.
    #[must_use]
    pub fn take_algorithm(&mut self) -> Option<CBox<Asn1Object>> {
        // SAFETY: the exclusive handle permits clearing the field, transferring
        // whatever release the field owed to the returned owner.
        let algorithm =
            unsafe { ptr::addr_of_mut!((*self.as_mut_ptr()).algorithm).replace(ptr::null_mut()) };
        // SAFETY: a non-null old field was owned by this identifier and remains
        // fully initialized after being detached.
        unsafe { CBox::from_raw(algorithm) }
    }

    /// Replaces the optional owned parameter and releases the previous value.
    pub fn set_parameter(&mut self, parameter: Option<CBox<Asn1Type>>) {
        let parameter = parameter.map_or(ptr::null_mut(), CBox::into_raw);
        // SAFETY: the exclusive handle permits replacing this owned pointer.
        // The old value transfers into the temporary owner before it is freed.
        let previous =
            unsafe { ptr::addr_of_mut!((*self.as_mut_ptr()).parameter).replace(parameter) };
        // SAFETY: a non-null old parameter was uniquely owned by the field and
        // is no longer reachable through the identifier.
        drop(unsafe { CBox::<Asn1Type>::from_raw(previous) });
    }

    /// Takes the optional parameter, leaving the field null.
    #[must_use]
    pub fn take_parameter(&mut self) -> Option<CBox<Asn1Type>> {
        // SAFETY: the exclusive handle permits clearing the field and moving
        // its ownership obligation into the returned handle.
        let parameter =
            unsafe { ptr::addr_of_mut!((*self.as_mut_ptr()).parameter).replace(ptr::null_mut()) };
        // SAFETY: a non-null detached parameter remains a fully initialized
        // `ASN1_TYPE` with one `ASN1_TYPE_free` obligation.
        unsafe { CBox::from_raw(parameter) }
    }
}

#[cfg(test)]
mod x509_algor_tests {
    use core::mem::{align_of, size_of};

    use ffibox::{CCell, CCloned, CDropped};

    use super::*;
    use crate::asn1::a_object::ASN1_OBJECT_create;
    use crate::asn1::x_algor::{X509_ALGOR_dup, i2d_X509_ALGOR};

    fn assert_owned_cloneable_cell<T: CCell + CCloned + CDropped>() {}

    #[test]
    fn layout_handles_and_lifecycle_match_openssl() {
        assert_owned_cloneable_cell::<X509Algor>();
        assert_eq!(size_of::<X509Algor>(), size_of::<ffi::X509_algor_st>());
        assert_eq!(align_of::<X509Algor>(), align_of::<ffi::X509_algor_st>());
        assert_eq!(
            size_of::<CBox<X509Algor>>(),
            size_of::<*mut ffi::X509_algor_st>()
        );
        assert_eq!(
            size_of::<X509AlgorRef<'static>>(),
            size_of::<*const ffi::X509_algor_st>()
        );
        assert_eq!(
            size_of::<X509AlgorMut<'static>>(),
            size_of::<*mut ffi::X509_algor_st>()
        );

        let mut algorithm = X509Algor::new().expect("X509_ALGOR_new");
        assert_eq!(algorithm.as_ref().as_ptr(), algorithm.as_ptr().cast_const());
        assert_eq!(algorithm.as_mut().as_mut_ptr(), algorithm.as_ptr());
    }

    #[test]
    fn a_fresh_identifier_carries_the_builtin_undefined_object() {
        let algorithm = X509Algor::new().expect("X509_ALGOR_new");

        // The SEQUENCE template installs `OBJ_nid2obj(NID_undef)`, so the
        // mandatory slot is occupied even though nothing was set yet.
        assert!(algorithm.as_ref().algorithm().is_some());
        assert!(algorithm.as_ref().parameter().is_none());

        // That built-in object has no content octets, so the identifier cannot
        // be encoded and the encode/decode duplication therefore fails.
        assert!(i2d_X509_ALGOR(algorithm.as_ref()).is_none());
        assert!(algorithm.try_clone().is_none());
        assert!(X509_ALGOR_dup(Some(algorithm.as_ref())).is_none());
    }

    #[test]
    fn detaching_the_builtin_object_is_harmless_and_stays_fallible() {
        let mut algorithm = X509Algor::new().expect("X509_ALGOR_new");

        // `ASN1_OBJECT_free` is flag-guarded, so adopting the registry entry
        // into an owner and dropping it releases nothing.
        let builtin = algorithm
            .as_mut()
            .take_algorithm()
            .expect("built-in undefined object");
        drop(builtin);
        assert!(algorithm.as_ref().algorithm().is_none());

        // A detached mandatory field keeps the identifier unencodable.
        assert!(i2d_X509_ALGOR(algorithm.as_ref()).is_none());
        assert!(algorithm.try_clone().is_none());

        // Installing a real OID makes both operations succeed.
        let oid = [0x2a_u8, 0x03, 0x04];
        let object = ASN1_OBJECT_create(0, &oid, None, None).expect("OID object");
        algorithm.as_mut().set_algorithm(Some(object));
        assert!(i2d_X509_ALGOR(algorithm.as_ref()).is_some());
        assert!(algorithm.try_clone().is_some());
    }

    #[test]
    fn owned_fields_can_be_replaced_borrowed_and_taken() {
        let mut algorithm = X509Algor::new().expect("X509_ALGOR_new");
        let oid = [0x2a_u8, 0x03, 0x04];
        let object = ASN1_OBJECT_create(0, &oid, None, None).expect("OID object");
        let object_ptr = object.as_ptr();
        algorithm.as_mut().set_algorithm(Some(object));
        assert_eq!(
            algorithm.as_ref().algorithm().map(|value| value.as_ptr()),
            Some(object_ptr.cast_const())
        );

        let mut parameter = Asn1Type::new().expect("ASN1_TYPE_new");
        parameter.as_mut().set_boolean(true);
        let parameter_ptr = parameter.as_ptr();
        algorithm.as_mut().set_parameter(Some(parameter));
        assert_eq!(
            algorithm.as_ref().parameter().map(|value| value.as_ptr()),
            Some(parameter_ptr.cast_const())
        );
        algorithm
            .as_mut()
            .parameter_mut()
            .expect("installed parameter")
            .set_null();

        let duplicate = algorithm.try_clone().expect("X509_ALGOR_dup");
        assert_ne!(duplicate.as_ptr(), algorithm.as_ptr());
        assert_ne!(
            duplicate.as_ref().algorithm().map(|value| value.as_ptr()),
            Some(object_ptr.cast_const())
        );
        assert_ne!(
            duplicate.as_ref().parameter().map(|value| value.as_ptr()),
            Some(parameter_ptr.cast_const())
        );

        let detached_parameter = algorithm
            .as_mut()
            .take_parameter()
            .expect("owned parameter");
        assert_eq!(detached_parameter.as_ptr(), parameter_ptr);
        assert!(algorithm.as_ref().parameter().is_none());

        let detached_object = algorithm
            .as_mut()
            .take_algorithm()
            .expect("owned algorithm object");
        assert_eq!(detached_object.as_ptr(), object_ptr);
        assert!(algorithm.as_ref().algorithm().is_none());
    }
}

/// Wraps: stack_st_X509_NAME_ENTRY
///
/// Typed view of OpenSSL's `STACK_OF(X509_NAME_ENTRY)`. The generated C tag is
/// a forward declaration whose inline API erases every operation to the common
/// `OPENSSL_STACK` implementation, so the generic container retains the entry
/// element type without changing its representation.
pub type X509NameEntryStack = Stack<X509NameEntry>;

/// Shared borrowed handle to a `STACK_OF(X509_NAME_ENTRY)`.
pub type X509NameEntryStackRef<'a> = StackRef<'a, X509NameEntry>;

/// Exclusive borrowed handle to a `STACK_OF(X509_NAME_ENTRY)`.
pub type X509NameEntryStackMut<'a> = StackMut<'a, X509NameEntry>;

#[cfg(test)]
mod x509_name_entry_stack_tests {
    use core::mem::size_of;

    use ffibox::{CBox, CCell, CCloned, CDropped};

    use super::*;
    use crate::stack::stack::{OPENSSL_sk_new_null, OPENSSL_sk_num};

    fn assert_owned_cloneable_cell<T: CCell + CCloned + CDropped>() {}

    #[test]
    fn generated_stack_uses_the_typed_erased_container() {
        assert_owned_cloneable_cell::<X509NameEntryStack>();
        assert_eq!(
            size_of::<CBox<X509NameEntryStack>>(),
            size_of::<*mut ffi::OPENSSL_STACK>()
        );
        assert_eq!(
            size_of::<X509NameEntryStackRef<'static>>(),
            size_of::<*mut ffi::OPENSSL_STACK>()
        );
        assert_eq!(
            size_of::<X509NameEntryStackMut<'static>>(),
            size_of::<*mut ffi::OPENSSL_STACK>()
        );

        let mut stack = OPENSSL_sk_new_null::<X509NameEntry>().expect("name-entry stack");
        let raw = stack.as_ptr();
        assert_eq!(stack.as_ref().as_ptr(), raw.cast_const());
        assert_eq!(stack.as_mut().as_mut_ptr(), raw);
        assert_eq!(OPENSSL_sk_num(Some(stack.as_ref())), Some(0));
    }
}
