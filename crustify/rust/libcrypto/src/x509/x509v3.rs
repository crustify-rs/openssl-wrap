//! Wrappers assigned from `include/openssl/x509v3.h`.

use core::ffi::c_void;
use core::ptr::{self, NonNull};

use ffibox::{CBox, CBoxWith, CDropper, define_ctype, impl_dropped};
use libcrypto_sys as ffi;

use crate::asn1::asn1::{Asn1Object, Asn1ObjectRef};
use crate::stack::stack::{Stack, StackMut, StackRef};
use crate::x509::x509_vfy::{PolicyQualInfoStack, PolicyQualInfoStackMut, PolicyQualInfoStackRef};

/// Opaque element marker for the `GENERAL_SUBTREE` records stored in this
/// stack.
///
/// `GENERAL_SUBTREE` has its own authored item and is outside this worklist.
/// Until that layout wrapper is available, this unconstructible marker keeps
/// the generated stack typed without exposing or dereferencing the record.
/// Replace it with the element wrapper when `GENERAL_SUBTREE_st` is filled.
#[repr(C)]
pub struct GeneralSubtree {
    _opaque: [u8; 0],
}

/// Wraps: stack_st_GENERAL_SUBTREE
///
/// Typed view of OpenSSL's `STACK_OF(GENERAL_SUBTREE)`. The generated C tag is
/// only a forward declaration and every operation erases it to the common
/// `OPENSSL_STACK *`, so this is the generic container with its subtree
/// element type retained.
///
/// The plain owner releases only the stack and its pointer array. Element
/// ownership must be selected explicitly through the generic stack's
/// pop-free policy.
pub type GeneralSubtreeStack = Stack<GeneralSubtree>;

/// Shared borrowed handle to a `STACK_OF(GENERAL_SUBTREE)`.
pub type GeneralSubtreeStackRef<'a> = StackRef<'a, GeneralSubtree>;

/// Exclusive borrowed handle to a `STACK_OF(GENERAL_SUBTREE)`.
pub type GeneralSubtreeStackMut<'a> = StackMut<'a, GeneralSubtree>;

/// Opaque element marker for the `ACCESS_DESCRIPTION` records stored in this
/// stack.
///
/// The element record has its own public definition and lifecycle, but that
/// higher-layer type is not part of this worklist. Until its wrapper is
/// available, this unconstructible marker retains the generated stack's
/// element type without exposing or dereferencing an element layout.
#[repr(C)]
pub struct AccessDescription {
    _opaque: [u8; 0],
}

/// Wraps: stack_st_ACCESS_DESCRIPTION
///
/// Typed view of OpenSSL's `STACK_OF(ACCESS_DESCRIPTION)`. The generated C tag
/// is a forward declaration and every stack operation erases it to the common
/// `OPENSSL_STACK *` representation, so this is the generic container with its
/// element type retained.
///
/// A plain [`ffibox::CBox<AccessDescriptionStack>`] owns only the stack and its
/// pointer array. [`AuthorityInfoAccess`] additionally owns every stored
/// access description and uses the ASN.1 full destructor.
pub type AccessDescriptionStack = Stack<AccessDescription>;

/// Shared borrowed handle to a `STACK_OF(ACCESS_DESCRIPTION)`.
pub type AccessDescriptionStackRef<'a> = StackRef<'a, AccessDescription>;

/// Exclusive borrowed handle to a `STACK_OF(ACCESS_DESCRIPTION)`.
pub type AccessDescriptionStackMut<'a> = StackMut<'a, AccessDescription>;

/// Selects the ASN.1 full destructor for an authority-information-access
/// sequence, including every `ACCESS_DESCRIPTION` element.
#[derive(Clone, Copy, Debug, Default)]
pub struct AuthorityInfoAccessFree;

// SAFETY: `AUTHORITY_INFO_ACCESS_free` accepts a fully initialized generated
// stack, releases every owned access-description element, and finally releases
// the common stack allocation.
unsafe impl CDropper<AccessDescriptionStack> for AuthorityInfoAccessFree {
    unsafe fn c_drop(&self, object: NonNull<AccessDescriptionStack>) {
        // SAFETY: the `CDropper` contract supplies sole ownership of a complete
        // authority-info-access value. Its generated stack tag and
        // `OPENSSL_STACK` have the same pointer representation.
        unsafe { ffi::AUTHORITY_INFO_ACCESS_free(object.as_ptr().cast()) }
    }
}

/// Owning authority-information-access sequence whose elements are released
/// together with its generated stack.
pub type AuthorityInfoAccess = CBoxWith<AccessDescriptionStack, AuthorityInfoAccessFree>;

impl AccessDescriptionStack {
    /// Allocates a complete empty authority-information-access sequence.
    #[must_use]
    pub fn new_authority_info_access() -> Option<AuthorityInfoAccess> {
        // SAFETY: a non-null ASN.1 constructor result is a fresh, fully
        // initialized generated stack carrying one
        // `AUTHORITY_INFO_ACCESS_free` obligation.
        unsafe {
            CBoxWith::from_raw(
                ffi::AUTHORITY_INFO_ACCESS_new().cast(),
                AuthorityInfoAccessFree,
            )
        }
    }
}

define_ctype!(
    /// Wraps: POLICYINFO_st
    ///
    /// Layout-compatible storage for an ASN.1 certificate-policy record. The
    /// record owns its policy object and optional qualifier sequence; borrowed
    /// access is carried by [`PolicyInfoRef`] and [`PolicyInfoMut`] without
    /// forming Rust references over memory OpenSSL may mutate.
    PolicyInfo,
    PolicyInfoRef,
    PolicyInfoMut,
    ffi::POLICYINFO_st
);

// `POLICYINFO_free` is the ASN.1 sequence's full destructor: it releases the
// policy object, every qualifier and its stack, then the record allocation.
impl_dropped!(PolicyInfo, ffi::POLICYINFO_st, ffi::POLICYINFO_free);

/// Wraps: stack_st_POLICYINFO
///
/// Typed view of OpenSSL's `STACK_OF(POLICYINFO)`, also published as
/// `CERTIFICATEPOLICIES`. The generated C tag is only a forward declaration
/// and every operation erases it to `OPENSSL_STACK *`, so this is the generic
/// container with its policy-info element type retained.
///
/// A plain stack owns its pointer array, not the policy-info records. Element
/// ownership can instead be selected explicitly with [`Stack::into_pop_free`].
pub type PolicyInfoStack = Stack<PolicyInfo>;

/// Shared borrowed handle to a `STACK_OF(POLICYINFO)`.
pub type PolicyInfoStackRef<'a> = StackRef<'a, PolicyInfo>;

/// Exclusive borrowed handle to a `STACK_OF(POLICYINFO)`.
pub type PolicyInfoStackMut<'a> = StackMut<'a, PolicyInfo>;

/// Rust spelling of OpenSSL's `CERTIFICATEPOLICIES` typedef.
pub type CertificatePolicies = PolicyInfoStack;

/// Selects full destruction for an owned qualifier sequence, including each
/// `POLICYQUALINFO` element.
#[derive(Clone, Copy, Debug, Default)]
pub struct PolicyQualifiersFree;

unsafe extern "C" fn policy_qualifier_free(value: *mut c_void) {
    // SAFETY: this callback is installed only on a stack whose elements are
    // complete, uniquely owned `POLICYQUALINFO` allocations.
    unsafe { ffi::POLICYQUALINFO_free(value.cast()) }
}

// SAFETY: this policy is attached only to a qualifier stack that owns all of
// its elements. `OPENSSL_sk_pop_free` visits each element exactly once with the
// matching ASN.1 destructor, then releases the pointer array and stack header.
unsafe impl CDropper<PolicyQualInfoStack> for PolicyQualifiersFree {
    unsafe fn c_drop(&self, object: NonNull<PolicyQualInfoStack>) {
        // SAFETY: the `CDropper` contract supplies unique ownership of the
        // complete stack and every stored qualifier.
        unsafe { ffi::OPENSSL_sk_pop_free(object.as_ptr().cast(), Some(policy_qualifier_free)) }
    }
}

/// Owning form of `POLICYINFO_st.qualifiers`, releasing the stack and every
/// qualifier together.
pub type PolicyQualifiers = CBoxWith<PolicyQualInfoStack, PolicyQualifiersFree>;

impl PolicyInfo {
    /// Allocates a complete empty policy-info record.
    #[must_use]
    pub fn new() -> Option<CBox<Self>> {
        // SAFETY: a non-null result is a fresh, fully initialized ASN.1
        // sequence carrying one `POLICYINFO_free` obligation.
        unsafe { CBox::from_raw(ffi::POLICYINFO_new()) }
    }
}

impl<'a> PolicyInfoRef<'a> {
    /// Wraps: POLICYINFO_st.policyid
    ///
    /// Borrows the installed policy object. The public layout permits the slot
    /// to be cleared after an ownership transfer.
    #[must_use]
    pub fn policy_id(&self) -> Option<Asn1ObjectRef<'a>> {
        // SAFETY: raw-place projection copies the pointer from the live shared
        // handle without forming a reference to C storage. A non-null object is
        // owned by this record and therefore lives for the handle's `'a`.
        unsafe {
            let policy_id = ptr::addr_of!((*self.as_ptr()).policyid).read();
            Asn1ObjectRef::from_ptr(policy_id)
        }
    }

    /// Wraps: POLICYINFO_st.qualifiers
    ///
    /// Borrows the optional qualifier sequence, including its element-address
    /// array. The record keeps the sequence and its elements alive.
    #[must_use]
    pub fn qualifiers(&self) -> Option<PolicyQualInfoStackRef<'a>> {
        // SAFETY: raw-place projection reads only the stored pointer. The
        // generated stack tag erases to `OPENSSL_STACK`, and the non-null stack
        // remains owned by this record for the handle's `'a`.
        unsafe {
            let qualifiers = ptr::addr_of!((*self.as_ptr()).qualifiers).read();
            PolicyQualInfoStackRef::from_ptr(qualifiers.cast())
        }
    }
}

impl PolicyInfoMut<'_> {
    /// Exclusively reborrows the optional qualifier sequence.
    #[must_use]
    pub fn qualifiers_mut(&mut self) -> Option<PolicyQualInfoStackMut<'_>> {
        // SAFETY: the exclusive policy-info handle supplies exclusive access to
        // its owned qualifier stack for the duration of this reborrow.
        unsafe {
            let qualifiers = ptr::addr_of!((*self.as_mut_ptr()).qualifiers).read();
            PolicyQualInfoStackMut::from_ptr(qualifiers.cast())
        }
    }

    /// Replaces the owned policy object and releases the previous value.
    pub fn set_policy_id(&mut self, policy_id: Option<CBox<Asn1Object>>) {
        let policy_id = policy_id.map_or(ptr::null_mut(), CBox::into_raw);
        // SAFETY: the exclusive handle permits replacing this owned pointer;
        // the old value's release obligation transfers to the owner below.
        let previous =
            unsafe { ptr::addr_of_mut!((*self.as_mut_ptr()).policyid).replace(policy_id) };
        // SAFETY: the detached non-null value was uniquely owned by this record
        // and remains a complete ASN.1 object.
        drop(unsafe { CBox::<Asn1Object>::from_raw(previous) });
    }

    /// Takes the owned policy object, leaving the nullable slot empty.
    #[must_use]
    pub fn take_policy_id(&mut self) -> Option<CBox<Asn1Object>> {
        // SAFETY: the exclusive handle permits clearing the field and moving
        // its unique release obligation into the returned owner.
        let policy_id =
            unsafe { ptr::addr_of_mut!((*self.as_mut_ptr()).policyid).replace(ptr::null_mut()) };
        // SAFETY: a detached non-null object remains fully initialized and
        // carries exactly one `ASN1_OBJECT_free` obligation.
        unsafe { CBox::from_raw(policy_id) }
    }

    /// Replaces the owned qualifier sequence and releases the previous stack
    /// and all of its elements.
    pub fn set_qualifiers(&mut self, qualifiers: Option<PolicyQualifiers>) {
        let qualifiers: *mut ffi::stack_st_POLICYQUALINFO =
            qualifiers.map_or(ptr::null_mut(), |qualifiers| {
                let (raw, _dropper) = qualifiers.into_raw();
                raw.cast()
            });
        // SAFETY: the exclusive handle permits replacing the owned sequence;
        // ownership of the old pointer transfers to the temporary owner.
        let previous =
            unsafe { ptr::addr_of_mut!((*self.as_mut_ptr()).qualifiers).replace(qualifiers) };
        // SAFETY: the detached non-null stack and each element were uniquely
        // owned by this field and match `PolicyQualifiersFree`.
        drop(unsafe { PolicyQualifiers::from_raw(previous.cast(), PolicyQualifiersFree) });
    }

    /// Takes the owned qualifier sequence, leaving the nullable slot empty.
    #[must_use]
    pub fn take_qualifiers(&mut self) -> Option<PolicyQualifiers> {
        // SAFETY: the exclusive handle permits clearing the field and moving
        // ownership of its stack and elements to the returned policy owner.
        let qualifiers =
            unsafe { ptr::addr_of_mut!((*self.as_mut_ptr()).qualifiers).replace(ptr::null_mut()) };
        // SAFETY: a detached non-null field is a complete stack whose elements
        // remain uniquely owned and require the full pop-free policy.
        unsafe { PolicyQualifiers::from_raw(qualifiers.cast(), PolicyQualifiersFree) }
    }
}

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
    fn assert_owned_cell<T: CCell + CDropped>() {}

    #[test]
    fn generated_subtree_stack_uses_the_typed_erased_container() {
        assert_owned_cloneable_cell::<GeneralSubtreeStack>();
        assert_eq!(
            size_of::<CBox<GeneralSubtreeStack>>(),
            size_of::<*mut ffi::OPENSSL_STACK>()
        );
        assert_eq!(
            size_of::<GeneralSubtreeStackRef<'static>>(),
            size_of::<*mut ffi::OPENSSL_STACK>()
        );
        assert_eq!(
            size_of::<GeneralSubtreeStackMut<'static>>(),
            size_of::<*mut ffi::OPENSSL_STACK>()
        );

        let mut stack = OPENSSL_sk_new_null::<GeneralSubtree>().expect("subtree stack");
        let raw = stack.as_ptr();
        assert_eq!(stack.as_ref().as_ptr(), raw.cast_const());
        assert_eq!(stack.as_mut().as_mut_ptr(), raw);
    }

    #[test]
    fn subtree_stack_preserves_borrowed_element_addresses() {
        let subtree_storage = Box::new(0x5a_u8);
        // SAFETY: the stable box address outlives both stacks. With no
        // comparator installed, the container only moves this opaque address
        // between slots and never dereferences it.
        let element = unsafe {
            StackElement::from_raw(
                ptr::from_ref(&*subtree_storage)
                    .cast_mut()
                    .cast::<GeneralSubtree>(),
            )
        }
        .expect("non-null subtree address");

        let mut stack = OPENSSL_sk_new_null::<GeneralSubtree>().expect("subtree stack");
        assert_eq!(
            // SAFETY: the stable stand-in allocation remains live through
            // every stack use and no callback can inspect the marker.
            unsafe { OPENSSL_sk_push(Some(&mut stack.as_mut()), Some(element)) },
            Some(1)
        );
        assert_eq!(OPENSSL_sk_num(Some(stack.as_ref())), Some(1));
        assert_eq!(
            OPENSSL_sk_value(Some(stack.as_ref()), 0).map(StackElement::as_non_null),
            Some(element.as_non_null())
        );

        // Cloning duplicates the pointer array and deliberately shares the
        // borrowed element address.
        let duplicate = stack.try_clone().expect("duplicate subtree stack");
        assert_eq!(
            OPENSSL_sk_value(Some(duplicate.as_ref()), 0).map(StackElement::as_non_null),
            Some(element.as_non_null())
        );
        drop(duplicate);
        drop(stack);
        assert_eq!(*subtree_storage, 0x5a);
    }

    #[test]
    fn generated_access_stack_keeps_its_typed_erased_surface() {
        assert_owned_cloneable_cell::<AccessDescriptionStack>();
        assert_eq!(
            size_of::<CBox<AccessDescriptionStack>>(),
            size_of::<*mut ffi::OPENSSL_STACK>()
        );
        assert_eq!(
            size_of::<AccessDescriptionStackRef<'static>>(),
            size_of::<*mut ffi::OPENSSL_STACK>()
        );
        assert_eq!(
            size_of::<AccessDescriptionStackMut<'static>>(),
            size_of::<*mut ffi::OPENSSL_STACK>()
        );

        let mut stack = OPENSSL_sk_new_null::<AccessDescription>().expect("access stack");
        let raw = stack.as_ptr();
        assert_eq!(stack.as_ref().as_ptr(), raw.cast_const());
        assert_eq!(stack.as_mut().as_mut_ptr(), raw);
        assert_eq!(OPENSSL_sk_num(Some(stack.as_ref())), Some(0));
    }

    #[test]
    fn authority_owner_preserves_the_full_drop_policy() {
        let mut access =
            AccessDescriptionStack::new_authority_info_access().expect("AUTHORITY_INFO_ACCESS_new");
        let raw = access.as_ptr();
        assert_eq!(access.as_ref().as_ptr(), raw.cast_const());
        assert_eq!(access.as_mut().as_mut_ptr(), raw);
        assert_eq!(OPENSSL_sk_num(Some(access.as_ref())), Some(0));
        assert_eq!(
            size_of::<AuthorityInfoAccess>(),
            size_of::<*mut ffi::OPENSSL_STACK>()
        );
    }

    #[test]
    fn policy_info_stack_produces_typed_borrows() {
        assert_owned_cloneable_cell::<PolicyInfoStack>();
        assert_eq!(
            size_of::<CBox<PolicyInfoStack>>(),
            size_of::<*mut ffi::OPENSSL_STACK>()
        );
        assert_eq!(
            size_of::<PolicyInfoStackRef<'static>>(),
            size_of::<*mut ffi::OPENSSL_STACK>()
        );
        assert_eq!(
            size_of::<PolicyInfoStackMut<'static>>(),
            size_of::<*mut ffi::OPENSSL_STACK>()
        );

        let mut stack: CBox<CertificatePolicies> = OPENSSL_sk_new_null().expect("POLICYINFO stack");
        let raw = stack.as_ptr();
        let shared: PolicyInfoStackRef<'_> = stack.as_ref();
        assert_eq!(shared.as_ptr(), raw.cast_const());
        let exclusive: PolicyInfoStackMut<'_> = stack.as_mut();
        assert_eq!(OPENSSL_sk_num(Some(exclusive.as_ref())), Some(0));
    }

    #[test]
    fn policy_info_owns_and_transfers_its_optional_fields() {
        use crate::asn1::a_object::ASN1_OBJECT_create;
        use crate::x509::x509_vfy::PolicyQualInfo;

        assert_owned_cell::<PolicyInfo>();
        assert_eq!(size_of::<PolicyInfo>(), size_of::<ffi::POLICYINFO_st>());
        assert_eq!(
            size_of::<CBox<PolicyInfo>>(),
            size_of::<*mut ffi::POLICYINFO_st>()
        );
        assert_eq!(
            size_of::<PolicyInfoRef<'static>>(),
            size_of::<*mut ffi::POLICYINFO_st>()
        );
        assert_eq!(
            size_of::<PolicyInfoMut<'static>>(),
            size_of::<*mut ffi::POLICYINFO_st>()
        );

        let mut policy = PolicyInfo::new().expect("POLICYINFO_new");
        assert!(policy.as_ref().policy_id().is_some());
        assert!(policy.as_ref().qualifiers().is_none());

        let object =
            ASN1_OBJECT_create(10_003, &[0x2a, 0x03, 0x05], None, None).expect("policy object");
        let object_raw = object.as_ptr();
        policy.as_mut().set_policy_id(Some(object));
        assert_eq!(
            policy.as_ref().policy_id().map(|object| object.as_ptr()),
            Some(object_raw.cast_const())
        );
        let detached_object = policy.as_mut().take_policy_id().expect("policy object");
        assert_eq!(detached_object.as_ptr(), object_raw);
        assert!(policy.as_ref().policy_id().is_none());
        drop(detached_object);

        let qualifiers = OPENSSL_sk_new_null::<PolicyQualInfo>().expect("qualifier stack");
        // SAFETY: the fresh stack is empty, hence vacuously owns every stored
        // element and is valid for the full pop-free policy.
        let qualifiers =
            unsafe { PolicyQualifiers::from_raw(qualifiers.into_raw(), PolicyQualifiersFree) }
                .expect("non-null qualifier stack");
        let qualifiers_raw = qualifiers.as_ptr();
        policy.as_mut().set_qualifiers(Some(qualifiers));
        assert_eq!(
            policy.as_ref().qualifiers().map(|stack| stack.as_ptr()),
            Some(qualifiers_raw.cast_const())
        );
        {
            let mut policy_mut = policy.as_mut();
            let qualifiers_mut = policy_mut.qualifiers_mut().expect("qualifier stack");
            assert_eq!(OPENSSL_sk_num(Some(qualifiers_mut.as_ref())), Some(0));
        }
        let detached_qualifiers = policy
            .as_mut()
            .take_qualifiers()
            .expect("detached qualifier stack");
        assert_eq!(detached_qualifiers.as_ptr(), qualifiers_raw);
        assert!(policy.as_ref().qualifiers().is_none());
        drop(detached_qualifiers);
    }
}
