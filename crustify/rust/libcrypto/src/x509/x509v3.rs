//! Wrappers assigned from `include/openssl/x509v3.h`.

use core::ffi::c_void;
use core::ptr::{self, NonNull};

use ffibox::{CBox, CBoxWith, CDropper, define_ctype, impl_cloned, impl_dropped};
use libcrypto_sys as ffi;

use crate::asn1::asn1::{Asn1Object, Asn1ObjectRef, Asn1String, Asn1StringMut, Asn1StringRef};
use crate::asn1::openssl_asn1::{Asn1Type, Asn1TypeMut, Asn1TypeRef};
use crate::stack::stack::{Stack, StackMut, StackRef};
pub use crate::x509::v3_info::{AuthorityInfoAccess, AuthorityInfoAccessFree};
use crate::x509::x509::{X509NameEntryStack, X509NameEntryStackMut, X509NameEntryStackRef};
use crate::x509::x509_internal::{
    GeneralNameStack, GeneralNameStackMut, GeneralNameStackRef, X509Name, X509NameMut, X509NameRef,
};
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

impl AccessDescriptionStack {
    /// Allocates a complete empty authority-information-access sequence.
    #[must_use]
    pub fn new_authority_info_access() -> Option<AuthorityInfoAccess> {
        crate::x509::v3_info::AUTHORITY_INFO_ACCESS_new()
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
        crate::x509::v3_cpols::POLICYINFO_new()
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

/// Error reported by an X.509 identity check.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum X509CheckError {
    /// The checked identity had an invalid representation.
    InvalidInput,
    /// OpenSSL could not complete the comparison.
    Internal,
}

fn checked_identity_result(result: i32) -> Result<bool, X509CheckError> {
    match result {
        1 => Ok(true),
        0 => Ok(false),
        -2 => Err(X509CheckError::InvalidInput),
        _ => Err(X509CheckError::Internal),
    }
}

/// Wraps: X509_check_email
/// Checks an RFC 822 or SMTPUTF8 mailbox against a certificate.
#[allow(non_snake_case)]
pub fn X509_check_email(
    certificate: crate::x509::x509_internal::X509Ref<'_>,
    email: &[u8],
    flags: u32,
) -> Result<bool, X509CheckError> {
    if email.is_empty() {
        return Err(X509CheckError::InvalidInput);
    }
    // SAFETY: the certificate and exact byte extent remain live for the call;
    // non-empty input prevents C's zero-length `strlen` convention.
    checked_identity_result(unsafe {
        libcrypto_sys::X509_check_email(
            certificate.as_ptr(),
            email.as_ptr().cast(),
            email.len(),
            flags,
        )
    })
}

/// Wraps: X509_check_host
/// Checks a DNS identity and returns the matched certificate name.
#[allow(non_snake_case)]
pub fn X509_check_host(
    certificate: crate::x509::x509_internal::X509Ref<'_>,
    host: &[u8],
    flags: u32,
) -> Result<Option<crate::mem::CryptoString>, X509CheckError> {
    if host.is_empty() {
        return Err(X509CheckError::InvalidInput);
    }
    let mut peer_name = core::ptr::null_mut();
    // SAFETY: the certificate, input extent and output slot remain live for
    // the call. OpenSSL allocates a non-null peer name only for a match.
    let result = unsafe {
        libcrypto_sys::X509_check_host(
            certificate.as_ptr(),
            host.as_ptr().cast(),
            host.len(),
            flags,
            &mut peer_name,
        )
    };
    // SAFETY: a non-null output is a fresh NUL-terminated allocation from the
    // OpenSSL allocator, independent of the certificate.
    let peer_name = unsafe { crate::mem::CryptoString::from_raw(peer_name.cast()) };
    match checked_identity_result(result)? {
        true => peer_name.ok_or(X509CheckError::Internal).map(Some),
        false => Ok(None),
    }
}

/// Wraps: X509_check_ip
/// Checks a four-byte IPv4 or sixteen-byte IPv6 address.
#[allow(non_snake_case)]
pub fn X509_check_ip(
    certificate: crate::x509::x509_internal::X509Ref<'_>,
    address: &[u8],
    flags: u32,
) -> Result<bool, X509CheckError> {
    if !matches!(address.len(), 4 | 16) {
        return Err(X509CheckError::InvalidInput);
    }
    // SAFETY: the certificate and exact address extent remain live for the
    // synchronous comparison.
    checked_identity_result(unsafe {
        libcrypto_sys::X509_check_ip(certificate.as_ptr(), address.as_ptr(), address.len(), flags)
    })
}

/// Wraps: X509_check_ip_asc
/// Parses and checks a NUL-terminated textual IP address.
#[allow(non_snake_case)]
pub fn X509_check_ip_asc(
    certificate: crate::x509::x509_internal::X509Ref<'_>,
    address: &core::ffi::CStr,
    flags: u32,
) -> Result<bool, X509CheckError> {
    // SAFETY: the certificate and NUL-terminated address remain live for the
    // synchronous parse and comparison.
    checked_identity_result(unsafe {
        libcrypto_sys::X509_check_ip_asc(certificate.as_ptr(), address.as_ptr(), flags)
    })
}

#[cfg(test)]
mod identity_check_tests {
    use super::*;
    use crate::x509::x_x509::X509_new;

    #[test]
    fn empty_certificate_does_not_match_valid_identities() {
        let certificate = X509_new().expect("certificate");
        assert_eq!(
            X509_check_email(certificate.as_ref(), b"a@example.test", 0),
            Ok(false)
        );
        assert!(matches!(
            X509_check_host(certificate.as_ref(), b"example.test", 0),
            Ok(None)
        ));
        assert_eq!(
            X509_check_ip(certificate.as_ref(), &[127, 0, 0, 1], 0),
            Ok(false)
        );
        assert_eq!(
            X509_check_ip_asc(certificate.as_ref(), c"127.0.0.1", 0),
            Ok(false)
        );
    }

    #[test]
    fn safe_surface_rejects_invalid_extents() {
        let certificate = X509_new().expect("certificate");
        assert!(matches!(
            X509_check_host(certificate.as_ref(), b"", 0),
            Err(X509CheckError::InvalidInput)
        ));
        assert_eq!(
            X509_check_email(certificate.as_ref(), b"", 0),
            Err(X509CheckError::InvalidInput)
        );
        assert_eq!(
            X509_check_ip(certificate.as_ref(), &[127, 0, 0], 0),
            Err(X509CheckError::InvalidInput)
        );
    }
}

define_ctype!(
    /// Wraps: DIST_POINT_NAME_st
    ///
    /// Layout-compatible storage for the ASN.1 distribution-point-name
    /// choice. `type` selects which owned stack pointer is active in `name`,
    /// while `dpname` is a separately owned, optional full-name cache.
    DistPointName,
    DistPointNameRef,
    DistPointNameMut,
    ffi::DIST_POINT_NAME_st
);

// `DIST_POINT_NAME_free` releases the active choice arm, the optional cached
// full name, and finally the record allocation.
impl_dropped!(
    DistPointName,
    ffi::DIST_POINT_NAME_st,
    ffi::DIST_POINT_NAME_free
);

// The value has no reference count. ASN.1 duplication creates an independent
// record and recursively duplicates the active stack and cached name.
impl_cloned!(
    DistPointName,
    ffi::DIST_POINT_NAME_st,
    dup = ffi::DIST_POINT_NAME_dup
);

/// Wraps: DIST_POINT_NAME_st.type
///
/// Lossless spelling of the ASN.1 choice discriminator. OpenSSL initializes a
/// fresh choice to `-1`, uses zero for `fullName`, and one for
/// `nameRelativeToCRLIssuer`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DistPointNameKind {
    Unset,
    FullName,
    RelativeName,
    Unknown(i32),
}

impl DistPointNameKind {
    #[must_use]
    pub const fn from_raw(value: i32) -> Self {
        match value {
            -1 => Self::Unset,
            0 => Self::FullName,
            1 => Self::RelativeName,
            value => Self::Unknown(value),
        }
    }

    #[must_use]
    pub const fn as_raw(self) -> i32 {
        match self {
            Self::Unset => -1,
            Self::FullName => 0,
            Self::RelativeName => 1,
            Self::Unknown(value) => value,
        }
    }
}

/// Selects the ASN.1 full destructor for a `GENERAL_NAMES` sequence.
#[derive(Clone, Copy, Debug, Default)]
pub struct GeneralNamesFree;

// SAFETY: `GENERAL_NAMES_free` pop-frees every owned `GENERAL_NAME`, releases
// the pointer array, and releases the stack allocation exactly once.
unsafe impl CDropper<GeneralNameStack> for GeneralNamesFree {
    unsafe fn c_drop(&self, object: NonNull<GeneralNameStack>) {
        // SAFETY: the policy is attached only to a complete owned
        // `GENERAL_NAMES` sequence, whose generated stack tag erases to the
        // common stack representation used by `GeneralNameStack`.
        unsafe { ffi::GENERAL_NAMES_free(object.as_ptr().cast()) }
    }
}

/// An owned `GENERAL_NAMES` sequence, including all stored names.
pub type GeneralNames = CBoxWith<GeneralNameStack, GeneralNamesFree>;

unsafe extern "C" fn free_x509_name_entry(value: *mut c_void) {
    // SAFETY: this adapter is installed only on stacks whose non-null elements
    // are uniquely owned `X509_NAME_ENTRY` allocations.
    unsafe { ffi::X509_NAME_ENTRY_free(value.cast()) }
}

/// Selects pop-free destruction for the relative-name entry stack.
#[derive(Clone, Copy, Debug, Default)]
pub struct RelativeNameEntriesFree;

// SAFETY: the strategy is constructed only for a stack that uniquely owns all
// of its X509 name entries. The callback frees each entry and the generic
// pop-free routine then frees the stack allocation.
unsafe impl CDropper<X509NameEntryStack> for RelativeNameEntriesFree {
    unsafe fn c_drop(&self, object: NonNull<X509NameEntryStack>) {
        // SAFETY: `object` is the complete owned stack selected by this
        // policy, and every element satisfies `free_x509_name_entry`.
        unsafe { ffi::OPENSSL_sk_pop_free(object.as_ptr().cast(), Some(free_x509_name_entry)) }
    }
}

/// An owned relative-name stack, including all stored name entries.
pub type RelativeNameEntries = CBoxWith<X509NameEntryStack, RelativeNameEntriesFree>;

/// Wraps: DIST_POINT_NAME_st.name
///
/// Borrowed view of the discriminator-selected union arm. Pointer arms remain
/// optional so malformed or construction-phase C values never become invalid
/// Rust handles.
#[derive(Clone, Copy)]
pub enum DistPointNameChoice<'a> {
    Unset,
    FullName(Option<GeneralNameStackRef<'a>>),
    RelativeName(Option<X509NameEntryStackRef<'a>>),
    Unknown(i32),
}

impl DistPointName {
    /// Allocates OpenSSL's empty, unset distribution-point-name choice.
    #[must_use]
    pub fn new() -> Option<CBox<Self>> {
        crate::x509::v3_crld::DIST_POINT_NAME_new()
    }
}

impl<'a> DistPointNameRef<'a> {
    /// Returns the lossless ASN.1 choice discriminator.
    #[must_use]
    pub fn kind(&self) -> DistPointNameKind {
        // SAFETY: raw-place projection copies the initialized integer from the
        // live shared handle without forming a reference to C storage.
        DistPointNameKind::from_raw(unsafe { ptr::addr_of!((*self.as_ptr()).type_).read() })
    }

    /// Returns the active choice arm together with its nullable pointer state.
    #[must_use]
    pub fn name(&self) -> DistPointNameChoice<'a> {
        match self.kind() {
            DistPointNameKind::Unset => DistPointNameChoice::Unset,
            DistPointNameKind::FullName => DistPointNameChoice::FullName(self.full_name()),
            DistPointNameKind::RelativeName => {
                DistPointNameChoice::RelativeName(self.relative_name())
            }
            DistPointNameKind::Unknown(value) => DistPointNameChoice::Unknown(value),
        }
    }

    /// Wraps: DIST_POINT_NAME_st.name.fullname
    ///
    /// Borrows the owned full-name sequence only when its discriminator is
    /// active.
    #[must_use]
    pub fn full_name(&self) -> Option<GeneralNameStackRef<'a>> {
        if self.kind() != DistPointNameKind::FullName {
            return None;
        }
        // SAFETY: discriminator zero selects the initialized `fullname`
        // pointer. A non-null sequence is owned by this choice and therefore
        // remains live for the handle's `'a`.
        let raw = unsafe { ptr::addr_of!((*self.as_ptr()).name.fullname).read() };
        // SAFETY: generated `GENERAL_NAMES` erases to `OPENSSL_STACK` and the
        // enclosing shared borrow supplies the returned lifetime.
        unsafe { GeneralNameStackRef::from_ptr(raw.cast()) }
    }

    /// Wraps: DIST_POINT_NAME_st.name.relativename
    ///
    /// Borrows the owned relative-name entry stack only when its discriminator
    /// is active.
    #[must_use]
    pub fn relative_name(&self) -> Option<X509NameEntryStackRef<'a>> {
        if self.kind() != DistPointNameKind::RelativeName {
            return None;
        }
        // SAFETY: discriminator one selects this initialized union pointer.
        // A non-null stack remains owned by the enclosing choice for `'a`.
        let raw = unsafe { ptr::addr_of!((*self.as_ptr()).name.relativename).read() };
        // SAFETY: the generated stack tag has the common stack representation
        // and the enclosing handle carries its lifetime.
        unsafe { X509NameEntryStackRef::from_ptr(raw.cast()) }
    }

    /// Wraps: DIST_POINT_NAME_st.dpname
    ///
    /// Borrows the optional cached full distribution-point name.
    #[must_use]
    pub fn dp_name(&self) -> Option<X509NameRef<'a>> {
        // SAFETY: raw-place projection copies the pointer without forming a
        // reference. A non-null name is owned by this record and lives for `'a`.
        let raw = unsafe { ptr::addr_of!((*self.as_ptr()).dpname).read() };
        // SAFETY: the preceding ownership invariant supplies the lifetime.
        unsafe { X509NameRef::from_ptr(raw) }
    }
}

impl DistPointNameMut<'_> {
    /// Exclusively reborrows the active full-name sequence.
    #[must_use]
    pub fn full_name_mut(&mut self) -> Option<GeneralNameStackMut<'_>> {
        if self.as_ref().kind() != DistPointNameKind::FullName {
            return None;
        }
        // SAFETY: the exclusive choice handle permits an exclusive reborrow of
        // its active owned sequence.
        let raw = unsafe { ptr::addr_of!((*self.as_mut_ptr()).name.fullname).read() };
        // SAFETY: the generated tag erases to the common stack and the result
        // is bounded by this exclusive reborrow.
        unsafe { GeneralNameStackMut::from_ptr(raw.cast()) }
    }

    /// Exclusively reborrows the active relative-name entry stack.
    #[must_use]
    pub fn relative_name_mut(&mut self) -> Option<X509NameEntryStackMut<'_>> {
        if self.as_ref().kind() != DistPointNameKind::RelativeName {
            return None;
        }
        // SAFETY: the exclusive choice handle permits an exclusive reborrow of
        // its active owned stack.
        let raw = unsafe { ptr::addr_of!((*self.as_mut_ptr()).name.relativename).read() };
        // SAFETY: the generated tag erases to the common stack and the result
        // is bounded by this exclusive reborrow.
        unsafe { X509NameEntryStackMut::from_ptr(raw.cast()) }
    }

    /// Exclusively reborrows the optional cached name.
    #[must_use]
    pub fn dp_name_mut(&mut self) -> Option<X509NameMut<'_>> {
        // SAFETY: the exclusive record handle permits an exclusive reborrow of
        // its separately owned cached name.
        let raw = unsafe { ptr::addr_of!((*self.as_mut_ptr()).dpname).read() };
        // SAFETY: the result is bounded by the exclusive reborrow above.
        unsafe { X509NameMut::from_ptr(raw) }
    }

    /// Replaces the cached full name and releases the previous value.
    pub fn set_dp_name(&mut self, value: Option<CBox<X509Name>>) {
        let value = value.map_or(ptr::null_mut(), CBox::into_raw);
        // SAFETY: the exclusive handle permits replacing this owned pointer.
        let previous = unsafe { ptr::addr_of_mut!((*self.as_mut_ptr()).dpname).replace(value) };
        // SAFETY: the detached non-null value carried the field's unique
        // `X509_NAME_free` obligation.
        drop(unsafe { CBox::<X509Name>::from_raw(previous) });
    }

    /// Takes the cached full name, leaving the nullable cache empty.
    #[must_use]
    pub fn take_dp_name(&mut self) -> Option<CBox<X509Name>> {
        // SAFETY: the exclusive handle transfers the old owned pointer out and
        // leaves a valid null cache.
        let raw =
            unsafe { ptr::addr_of_mut!((*self.as_mut_ptr()).dpname).replace(ptr::null_mut()) };
        // SAFETY: a non-null detached value is a complete uniquely owned name.
        unsafe { CBox::from_raw(raw) }
    }

    /// Replaces the active arm with an owned full-name sequence.
    ///
    /// On an unknown C discriminator the value is returned unchanged because
    /// Rust cannot determine which destructor the existing union pointer needs.
    pub fn try_set_full_name(
        &mut self,
        value: Option<GeneralNames>,
    ) -> Result<(), Option<GeneralNames>> {
        if matches!(self.as_ref().kind(), DistPointNameKind::Unknown(_)) {
            return Err(value);
        }
        self.clear_known_name();
        let raw = value.map_or(ptr::null_mut(), |value| value.into_raw().0.cast());
        // SAFETY: the old known arm has been cleared. Write the pointer before
        // publishing its matching discriminator under the exclusive handle.
        unsafe {
            ptr::addr_of_mut!((*self.as_mut_ptr()).name.fullname).write(raw);
            ptr::addr_of_mut!((*self.as_mut_ptr()).type_).write(0);
        }
        Ok(())
    }

    /// Takes the active full-name sequence and leaves the choice unset.
    #[must_use]
    pub fn take_full_name(&mut self) -> Option<GeneralNames> {
        if self.as_ref().kind() != DistPointNameKind::FullName {
            return None;
        }
        // SAFETY: discriminator zero selects the initialized pointer. Clearing
        // it and then unsetting the tag transfers the unique sequence debt.
        let raw = unsafe {
            let raw =
                ptr::addr_of_mut!((*self.as_mut_ptr()).name.fullname).replace(ptr::null_mut());
            ptr::addr_of_mut!((*self.as_mut_ptr()).type_).write(-1);
            raw
        };
        // SAFETY: a non-null active arm was a complete owned GENERAL_NAMES.
        unsafe { CBoxWith::from_raw(raw.cast(), GeneralNamesFree) }
    }

    /// Replaces the active arm with an owned relative-name stack.
    ///
    /// On an unknown C discriminator the value is returned unchanged because
    /// the existing union pointer cannot be safely classified.
    pub fn try_set_relative_name(
        &mut self,
        value: Option<RelativeNameEntries>,
    ) -> Result<(), Option<RelativeNameEntries>> {
        if matches!(self.as_ref().kind(), DistPointNameKind::Unknown(_)) {
            return Err(value);
        }
        self.clear_known_name();
        let raw = value.map_or(ptr::null_mut(), |value| value.into_raw().0.cast());
        // SAFETY: the old known arm has been cleared. The pointer and matching
        // discriminator are installed together under the exclusive handle.
        unsafe {
            ptr::addr_of_mut!((*self.as_mut_ptr()).name.relativename).write(raw);
            ptr::addr_of_mut!((*self.as_mut_ptr()).type_).write(1);
        }
        Ok(())
    }

    /// Takes the active relative-name stack and leaves the choice unset.
    #[must_use]
    pub fn take_relative_name(&mut self) -> Option<RelativeNameEntries> {
        if self.as_ref().kind() != DistPointNameKind::RelativeName {
            return None;
        }
        // SAFETY: discriminator one selects this initialized pointer. Clearing
        // it before unsetting the tag transfers the unique stack debt.
        let raw = unsafe {
            let raw =
                ptr::addr_of_mut!((*self.as_mut_ptr()).name.relativename).replace(ptr::null_mut());
            ptr::addr_of_mut!((*self.as_mut_ptr()).type_).write(-1);
            raw
        };
        // SAFETY: a non-null active arm owns its stack and every entry.
        unsafe { CBoxWith::from_raw(raw.cast(), RelativeNameEntriesFree) }
    }

    fn clear_known_name(&mut self) {
        match self.as_ref().kind() {
            DistPointNameKind::FullName => drop(self.take_full_name()),
            DistPointNameKind::RelativeName => drop(self.take_relative_name()),
            DistPointNameKind::Unset => {}
            DistPointNameKind::Unknown(_) => {
                unreachable!("callers reject an unknown discriminator")
            }
        }
    }
}

define_ctype!(
    /// Wraps: NAME_CONSTRAINTS_st
    ///
    /// Layout-compatible name-constraints sequence. Both optional fields own
    /// their generated stack, pointer array, and every `GENERAL_SUBTREE`
    /// element stored in it.
    NameConstraints,
    NameConstraintsRef,
    NameConstraintsMut,
    ffi::NAME_CONSTRAINTS_st
);

// The generated ASN.1 destructor pop-frees both optional subtree sequences and
// finally releases the containing allocation.
impl_dropped!(
    NameConstraints,
    ffi::NAME_CONSTRAINTS_st,
    ffi::NAME_CONSTRAINTS_free
);

unsafe extern "C" fn free_general_subtree(value: *mut c_void) {
    // SAFETY: this adapter is installed only for uniquely owned
    // `GENERAL_SUBTREE` allocations in a name-constraints sequence.
    unsafe { ffi::GENERAL_SUBTREE_free(value.cast()) }
}

/// Selects pop-free destruction for an owned general-subtree stack.
#[derive(Clone, Copy, Debug, Default)]
pub struct GeneralSubtreesFree;

// SAFETY: this strategy is attached only to stacks that uniquely own all
// their `GENERAL_SUBTREE` elements. The callback and pop-free operation consume
// every element and the stack allocation exactly once.
unsafe impl CDropper<GeneralSubtreeStack> for GeneralSubtreesFree {
    unsafe fn c_drop(&self, object: NonNull<GeneralSubtreeStack>) {
        // SAFETY: `object` and all elements satisfy the strategy invariant.
        unsafe { ffi::OPENSSL_sk_pop_free(object.as_ptr().cast(), Some(free_general_subtree)) }
    }
}

/// An owned stack of general subtrees, including all stored subtrees.
pub type GeneralSubtrees = CBoxWith<GeneralSubtreeStack, GeneralSubtreesFree>;

impl NameConstraints {
    /// Allocates an empty name-constraints sequence.
    #[must_use]
    pub fn new() -> Option<CBox<Self>> {
        crate::x509::v3_ncons::NAME_CONSTRAINTS_new()
    }
}

impl<'a> NameConstraintsRef<'a> {
    /// Wraps: NAME_CONSTRAINTS_st.excludedSubtrees
    ///
    /// Borrows the optional excluded-subtree sequence.
    #[must_use]
    pub fn excluded_subtrees(&self) -> Option<GeneralSubtreeStackRef<'a>> {
        // SAFETY: raw-place projection copies the owned nullable pointer. A
        // non-null stack remains live for the enclosing handle's `'a`.
        let raw = unsafe { ptr::addr_of!((*self.as_ptr()).excludedSubtrees).read() };
        // SAFETY: the generated stack tag erases to the common representation
        // and the enclosing handle supplies the lifetime.
        unsafe { GeneralSubtreeStackRef::from_ptr(raw.cast()) }
    }

    /// Wraps: NAME_CONSTRAINTS_st.permittedSubtrees
    ///
    /// Borrows the optional permitted-subtree sequence.
    #[must_use]
    pub fn permitted_subtrees(&self) -> Option<GeneralSubtreeStackRef<'a>> {
        // SAFETY: raw-place projection copies the owned nullable pointer. A
        // non-null stack remains live for the enclosing handle's `'a`.
        let raw = unsafe { ptr::addr_of!((*self.as_ptr()).permittedSubtrees).read() };
        // SAFETY: the generated stack tag erases to the common representation
        // and the enclosing handle supplies the lifetime.
        unsafe { GeneralSubtreeStackRef::from_ptr(raw.cast()) }
    }
}

impl NameConstraintsMut<'_> {
    /// Exclusively reborrows the optional excluded-subtree sequence.
    #[must_use]
    pub fn excluded_subtrees_mut(&mut self) -> Option<GeneralSubtreeStackMut<'_>> {
        // SAFETY: the exclusive record handle permits an exclusive reborrow of
        // this owned stack.
        let raw = unsafe { ptr::addr_of!((*self.as_mut_ptr()).excludedSubtrees).read() };
        // SAFETY: the generated tag erases to the common stack and the result
        // is bounded by this exclusive reborrow.
        unsafe { GeneralSubtreeStackMut::from_ptr(raw.cast()) }
    }

    /// Exclusively reborrows the optional permitted-subtree sequence.
    #[must_use]
    pub fn permitted_subtrees_mut(&mut self) -> Option<GeneralSubtreeStackMut<'_>> {
        // SAFETY: the exclusive record handle permits an exclusive reborrow of
        // this owned stack.
        let raw = unsafe { ptr::addr_of!((*self.as_mut_ptr()).permittedSubtrees).read() };
        // SAFETY: the generated tag erases to the common stack and the result
        // is bounded by this exclusive reborrow.
        unsafe { GeneralSubtreeStackMut::from_ptr(raw.cast()) }
    }

    /// Replaces the excluded-subtree sequence and releases the previous one.
    pub fn set_excluded_subtrees(&mut self, value: Option<GeneralSubtrees>) {
        let raw = value.map_or(ptr::null_mut(), |value| value.into_raw().0.cast());
        // SAFETY: the exclusive handle permits replacing the owned pointer.
        let previous =
            unsafe { ptr::addr_of_mut!((*self.as_mut_ptr()).excludedSubtrees).replace(raw) };
        // SAFETY: a non-null detached stack owned every element and carries the
        // matching pop-free obligation.
        drop(unsafe { CBoxWith::from_raw(previous.cast(), GeneralSubtreesFree) });
    }

    /// Takes the excluded-subtree sequence, leaving its optional field empty.
    #[must_use]
    pub fn take_excluded_subtrees(&mut self) -> Option<GeneralSubtrees> {
        // SAFETY: the exclusive handle transfers the old owned stack out and
        // leaves the nullable field empty.
        let raw = unsafe {
            ptr::addr_of_mut!((*self.as_mut_ptr()).excludedSubtrees).replace(ptr::null_mut())
        };
        // SAFETY: a non-null detached value owns the stack and all elements.
        unsafe { CBoxWith::from_raw(raw.cast(), GeneralSubtreesFree) }
    }

    /// Replaces the permitted-subtree sequence and releases the previous one.
    pub fn set_permitted_subtrees(&mut self, value: Option<GeneralSubtrees>) {
        let raw = value.map_or(ptr::null_mut(), |value| value.into_raw().0.cast());
        // SAFETY: the exclusive handle permits replacing the owned pointer.
        let previous =
            unsafe { ptr::addr_of_mut!((*self.as_mut_ptr()).permittedSubtrees).replace(raw) };
        // SAFETY: a non-null detached stack owned every element and carries the
        // matching pop-free obligation.
        drop(unsafe { CBoxWith::from_raw(previous.cast(), GeneralSubtreesFree) });
    }

    /// Takes the permitted-subtree sequence, leaving its optional field empty.
    #[must_use]
    pub fn take_permitted_subtrees(&mut self) -> Option<GeneralSubtrees> {
        // SAFETY: the exclusive handle transfers the old owned stack out and
        // leaves the nullable field empty.
        let raw = unsafe {
            ptr::addr_of_mut!((*self.as_mut_ptr()).permittedSubtrees).replace(ptr::null_mut())
        };
        // SAFETY: a non-null detached value owns the stack and all elements.
        unsafe { CBoxWith::from_raw(raw.cast(), GeneralSubtreesFree) }
    }
}

define_ctype!(
    /// Wraps: otherName_st
    ///
    /// Layout-compatible storage for an X.509 `OTHERNAME` record. The ASN.1
    /// sequence owns its object identifier and tagged value; borrowed access
    /// stays on pointer-carrying handles rather than references over C memory.
    OtherName,
    OtherNameRef,
    OtherNameMut,
    ffi::otherName_st
);

impl_dropped!(OtherName, ffi::otherName_st, ffi::OTHERNAME_free);

impl OtherName {
    /// Allocates a complete default `OTHERNAME` sequence.
    #[must_use]
    pub fn new() -> Option<CBox<Self>> {
        // SAFETY: a non-null result is a fresh, fully initialized ASN.1
        // sequence carrying one `OTHERNAME_free` obligation.
        unsafe { CBox::from_raw(ffi::OTHERNAME_new()) }
    }
}

impl<'a> OtherNameRef<'a> {
    /// Wraps: otherName_st.type_id
    ///
    /// Borrows the installed object identifier. The public layout and set0
    /// construction paths permit this owned slot to be null.
    #[must_use]
    pub fn type_id(&self) -> Option<Asn1ObjectRef<'a>> {
        // SAFETY: raw-place projection copies the pointer from the live shared
        // handle. A non-null object remains owned by this record for `'a`.
        unsafe {
            let type_id = ptr::addr_of!((*self.as_ptr()).type_id).read();
            Asn1ObjectRef::from_ptr(type_id)
        }
    }

    /// Wraps: otherName_st.value
    ///
    /// Borrows the installed tagged ASN.1 value. The public layout and set0
    /// construction paths permit this owned slot to be null.
    #[must_use]
    pub fn value(&self) -> Option<Asn1TypeRef<'a>> {
        // SAFETY: raw-place projection copies the pointer from the live shared
        // handle. A non-null value remains owned by this record for `'a`.
        unsafe {
            let value = ptr::addr_of!((*self.as_ptr()).value).read();
            Asn1TypeRef::from_ptr(value)
        }
    }
}

impl OtherNameMut<'_> {
    /// Exclusively reborrows the installed tagged ASN.1 value.
    #[must_use]
    pub fn value_mut(&mut self) -> Option<Asn1TypeMut<'_>> {
        // SAFETY: this exclusive record handle permits an exclusive reborrow
        // of its uniquely owned value for the duration of `&mut self`.
        unsafe {
            let value = ptr::addr_of!((*self.as_mut_ptr()).value).read();
            Asn1TypeMut::from_ptr(value)
        }
    }

    /// Replaces the owned object identifier and releases the previous value.
    pub fn set_type_id(&mut self, type_id: Option<CBox<Asn1Object>>) {
        let type_id = type_id.map_or(ptr::null_mut(), CBox::into_raw);
        // SAFETY: the exclusive handle permits replacing this owned pointer;
        // the old release obligation transfers to the temporary owner below.
        let previous = unsafe { ptr::addr_of_mut!((*self.as_mut_ptr()).type_id).replace(type_id) };
        // SAFETY: a detached non-null object remains valid for its registered
        // destructor, which intentionally ignores built-in static objects.
        drop(unsafe { CBox::<Asn1Object>::from_raw(previous) });
    }

    /// Takes the owned object identifier, leaving the nullable slot empty.
    #[must_use]
    pub fn take_type_id(&mut self) -> Option<CBox<Asn1Object>> {
        // SAFETY: the exclusive handle permits clearing the slot and moving
        // its one `ASN1_OBJECT_free` obligation into the returned owner.
        let type_id =
            unsafe { ptr::addr_of_mut!((*self.as_mut_ptr()).type_id).replace(ptr::null_mut()) };
        // SAFETY: a detached non-null object remains a complete ASN.1 object.
        unsafe { CBox::from_raw(type_id) }
    }

    /// Replaces the owned tagged value and releases the previous value.
    pub fn set_value(&mut self, value: Option<CBox<Asn1Type>>) {
        let value = value.map_or(ptr::null_mut(), CBox::into_raw);
        // SAFETY: the exclusive handle permits replacing this owned pointer;
        // the prior release obligation transfers to the temporary owner.
        let previous = unsafe { ptr::addr_of_mut!((*self.as_mut_ptr()).value).replace(value) };
        // SAFETY: a detached non-null value remains a complete `ASN1_TYPE`.
        drop(unsafe { CBox::<Asn1Type>::from_raw(previous) });
    }

    /// Takes the owned tagged value, leaving the nullable slot empty.
    #[must_use]
    pub fn take_value(&mut self) -> Option<CBox<Asn1Type>> {
        // SAFETY: the exclusive handle permits clearing the slot and moving
        // its one `ASN1_TYPE_free` obligation into the returned owner.
        let value =
            unsafe { ptr::addr_of_mut!((*self.as_mut_ptr()).value).replace(ptr::null_mut()) };
        // SAFETY: a detached non-null value remains a complete `ASN1_TYPE`.
        unsafe { CBox::from_raw(value) }
    }
}

#[cfg(test)]
mod wrapped_x509v3_tests {
    use core::mem::{align_of, size_of};

    use ffibox::{CCell, CCloned, CDropped};

    use super::*;
    use crate::asn1::openssl_asn1::{Asn1TypeKind, Asn1TypeValue};
    use crate::stack::stack::{OPENSSL_sk_new_null, OPENSSL_sk_num};
    use crate::x509::x509_internal::{GeneralName, X509NameEntry};

    fn assert_cloneable_owner<T: CCell + CCloned + CDropped>() {}
    fn assert_drop_owner<T: CCell + CDropped>() {}

    fn empty_general_names() -> GeneralNames {
        let stack = OPENSSL_sk_new_null::<GeneralName>().expect("GENERAL_NAMES stack");
        let raw = stack.into_raw();
        // SAFETY: this fresh stack is empty, so the full GENERAL_NAMES policy
        // has no element ownership to establish and owns the stack allocation.
        unsafe { CBoxWith::from_raw(raw, GeneralNamesFree) }
            .expect("an owning stack has a non-null pointer")
    }

    fn empty_relative_names() -> RelativeNameEntries {
        let stack = OPENSSL_sk_new_null::<X509NameEntry>().expect("relative-name stack");
        let raw = stack.into_raw();
        // SAFETY: this fresh stack is empty, so pop-free has no element
        // ownership to establish and owns the stack allocation.
        unsafe { CBoxWith::from_raw(raw, RelativeNameEntriesFree) }
            .expect("an owning stack has a non-null pointer")
    }

    fn empty_general_subtrees() -> GeneralSubtrees {
        let stack = OPENSSL_sk_new_null::<GeneralSubtree>().expect("GENERAL_SUBTREE stack");
        let raw = stack.into_raw();
        // SAFETY: this fresh stack is empty, so pop-free has no element
        // ownership to establish and owns the stack allocation.
        unsafe { CBoxWith::from_raw(raw, GeneralSubtreesFree) }
            .expect("an owning stack has a non-null pointer")
    }

    #[test]
    fn distribution_point_name_preserves_layout_and_lifecycle() {
        assert_cloneable_owner::<DistPointName>();
        assert_eq!(
            size_of::<DistPointName>(),
            size_of::<ffi::DIST_POINT_NAME_st>()
        );
        assert_eq!(
            align_of::<DistPointName>(),
            align_of::<ffi::DIST_POINT_NAME_st>()
        );
        assert_eq!(
            size_of::<CBox<DistPointName>>(),
            size_of::<*mut ffi::DIST_POINT_NAME_st>()
        );

        let mut name = DistPointName::new().expect("DIST_POINT_NAME_new");
        assert_eq!(name.as_ref().kind(), DistPointNameKind::Unset);
        assert!(matches!(name.as_ref().name(), DistPointNameChoice::Unset));
        assert!(name.as_ref().dp_name().is_none());

        assert!(
            name.as_mut()
                .try_set_full_name(Some(empty_general_names()))
                .is_ok()
        );
        assert_eq!(name.as_ref().kind(), DistPointNameKind::FullName);
        assert_eq!(OPENSSL_sk_num(name.as_ref().full_name()), Some(0));
        assert!(name.as_mut().full_name_mut().is_some());

        let duplicate = name.try_clone().expect("DIST_POINT_NAME_dup");
        assert_ne!(duplicate.as_ptr(), name.as_ptr());
        assert_eq!(duplicate.as_ref().kind(), DistPointNameKind::FullName);
        assert_ne!(
            duplicate.as_ref().full_name().map(|stack| stack.as_ptr()),
            name.as_ref().full_name().map(|stack| stack.as_ptr())
        );

        drop(name.as_mut().take_full_name().expect("owned full name"));
        assert_eq!(name.as_ref().kind(), DistPointNameKind::Unset);
        assert!(
            name.as_mut()
                .try_set_relative_name(Some(empty_relative_names()))
                .is_ok()
        );
        assert_eq!(name.as_ref().kind(), DistPointNameKind::RelativeName);
        assert!(name.as_mut().relative_name_mut().is_some());
        drop(
            name.as_mut()
                .take_relative_name()
                .expect("owned relative name"),
        );
    }

    #[test]
    fn distribution_point_cached_name_transfers_ownership() {
        let mut point = DistPointName::new().expect("DIST_POINT_NAME_new");
        // SAFETY: OpenSSL returns null or a fresh complete name with one
        // `X509_NAME_free` obligation.
        let raw = unsafe { ffi::X509_NAME_new() };
        // SAFETY: ownership of the fresh result transfers once to this owner.
        let cached = unsafe { CBox::<X509Name>::from_raw(raw) }.expect("X509_NAME_new");

        point.as_mut().set_dp_name(Some(cached));
        assert_eq!(
            point.as_ref().dp_name().map(|name| name.as_ptr()),
            Some(raw.cast_const())
        );
        assert!(point.as_mut().dp_name_mut().is_some());
        let cached = point.as_mut().take_dp_name().expect("cached full name");
        assert_eq!(cached.as_ptr(), raw);
        assert!(point.as_ref().dp_name().is_none());
    }

    #[test]
    fn name_constraints_owns_and_reborrows_both_optional_stacks() {
        assert_drop_owner::<NameConstraints>();
        assert_eq!(
            size_of::<NameConstraints>(),
            size_of::<ffi::NAME_CONSTRAINTS_st>()
        );
        assert_eq!(
            align_of::<NameConstraints>(),
            align_of::<ffi::NAME_CONSTRAINTS_st>()
        );

        let mut constraints = NameConstraints::new().expect("NAME_CONSTRAINTS_new");
        assert!(constraints.as_ref().permitted_subtrees().is_none());
        assert!(constraints.as_ref().excluded_subtrees().is_none());

        constraints
            .as_mut()
            .set_permitted_subtrees(Some(empty_general_subtrees()));
        constraints
            .as_mut()
            .set_excluded_subtrees(Some(empty_general_subtrees()));
        assert_eq!(
            OPENSSL_sk_num(constraints.as_ref().permitted_subtrees()),
            Some(0)
        );
        assert_eq!(
            OPENSSL_sk_num(constraints.as_ref().excluded_subtrees()),
            Some(0)
        );
        assert!(constraints.as_mut().permitted_subtrees_mut().is_some());
        assert!(constraints.as_mut().excluded_subtrees_mut().is_some());

        let permitted = constraints
            .as_mut()
            .take_permitted_subtrees()
            .expect("owned permitted stack");
        assert!(constraints.as_ref().permitted_subtrees().is_none());
        constraints.as_mut().set_permitted_subtrees(Some(permitted));
        drop(
            constraints
                .as_mut()
                .take_excluded_subtrees()
                .expect("owned excluded stack"),
        );
        assert!(constraints.as_ref().excluded_subtrees().is_none());
    }

    #[test]
    fn other_name_owns_and_reborrows_both_fields() {
        assert_drop_owner::<OtherName>();
        assert_eq!(size_of::<OtherName>(), size_of::<ffi::otherName_st>());
        assert_eq!(align_of::<OtherName>(), align_of::<ffi::otherName_st>());
        assert_eq!(
            size_of::<CBox<OtherName>>(),
            size_of::<*mut ffi::otherName_st>()
        );

        let mut other_name = OtherName::new().expect("OTHERNAME_new");
        assert!(other_name.as_ref().type_id().is_some());
        assert!(matches!(
            other_name.as_ref().value().map(|value| value.value()),
            Some(Asn1TypeValue::Undefined)
        ));

        // SAFETY: the literal is NUL terminated and OpenSSL returns null or a
        // fresh, fully initialized dynamic object identifier.
        let raw_type_id = unsafe { ffi::OBJ_txt2obj(c"1.3.6.1.4.1.55555.31337".as_ptr(), 1) };
        // SAFETY: the fresh non-null result transfers one free obligation.
        let type_id = unsafe { CBox::<Asn1Object>::from_raw(raw_type_id) }.expect("ASN1 object");
        other_name.as_mut().set_type_id(Some(type_id));
        assert_eq!(
            other_name.as_ref().type_id().map(|value| value.as_ptr()),
            Some(raw_type_id.cast_const())
        );
        let type_id = other_name
            .as_mut()
            .take_type_id()
            .expect("installed object identifier");
        assert!(other_name.as_ref().type_id().is_none());
        other_name.as_mut().set_type_id(Some(type_id));

        let mut value = Asn1Type::new().expect("ASN1_TYPE_new");
        value.as_mut().set_boolean(true);
        let raw_value = value.as_ptr();
        other_name.as_mut().set_value(Some(value));
        assert_eq!(
            other_name.as_ref().value().map(|value| value.as_ptr()),
            Some(raw_value.cast_const())
        );
        assert_eq!(
            other_name.as_ref().value().map(|value| value.kind()),
            Some(Asn1TypeKind::Boolean)
        );
        other_name
            .as_mut()
            .value_mut()
            .expect("installed value")
            .set_null();
        assert_eq!(
            other_name.as_ref().value().map(|value| value.kind()),
            Some(Asn1TypeKind::Null)
        );
        let value = other_name
            .as_mut()
            .take_value()
            .expect("installed tagged value");
        assert!(other_name.as_ref().value().is_none());
        other_name.as_mut().set_value(Some(value));
    }
}

define_ctype!(
    /// Wraps: DIST_POINT_st
    ///
    /// Layout-compatible storage for an ASN.1 CRL distribution point. Its
    /// three optional pointer fields are uniquely owned by the record;
    /// borrowed access is carried by [`DistPointRef`] and [`DistPointMut`].
    DistPoint,
    DistPointRef,
    DistPointMut,
    ffi::DIST_POINT_st
);

// The generated ASN.1 destructor recursively releases every optional child
// and the record allocation itself.
impl_dropped!(DistPoint, ffi::DIST_POINT_st, ffi::DIST_POINT_free);

impl DistPoint {
    /// Allocates an empty distribution point.
    #[must_use]
    pub fn new() -> Option<CBox<Self>> {
        // SAFETY: a non-null result is a fresh, fully initialized generated
        // ASN.1 record carrying one `DIST_POINT_free` obligation.
        unsafe { CBox::from_raw(ffi::DIST_POINT_new()) }
    }
}

impl<'a> DistPointRef<'a> {
    /// Wraps: DIST_POINT_st.dp_reasons
    ///
    /// Returns OpenSSL's derived reason-mask cache.
    #[must_use]
    pub fn dp_reasons(&self) -> i32 {
        // SAFETY: raw-place projection copies the initialized scalar without
        // forming a reference over storage OpenSSL may mutate.
        unsafe { ptr::addr_of!((*self.as_ptr()).dp_reasons).read() }
    }

    /// Wraps: DIST_POINT_st.reasons
    ///
    /// Borrows the optional owned reason bit string.
    #[must_use]
    pub fn reasons(&self) -> Option<Asn1StringRef<'a>> {
        // SAFETY: raw-place projection copies the nullable owned pointer. A
        // non-null child remains alive for the enclosing handle's `'a`.
        let raw = unsafe { ptr::addr_of!((*self.as_ptr()).reasons).read() };
        // SAFETY: the enclosing record owns the child for the returned borrow.
        unsafe { Asn1StringRef::from_ptr(raw) }
    }

    /// Wraps: DIST_POINT_st.distpoint
    ///
    /// Borrows the optional owned distribution-point name.
    #[must_use]
    pub fn dist_point_name(&self) -> Option<DistPointNameRef<'a>> {
        // SAFETY: raw-place projection copies the nullable owned pointer. A
        // non-null child remains alive for the enclosing handle's `'a`.
        let raw = unsafe { ptr::addr_of!((*self.as_ptr()).distpoint).read() };
        // SAFETY: the enclosing record owns the child for the returned borrow.
        unsafe { DistPointNameRef::from_ptr(raw) }
    }

    /// Wraps: DIST_POINT_st.CRLissuer
    ///
    /// Borrows the optional issuer-name sequence and all its elements.
    #[must_use]
    pub fn crl_issuer(&self) -> Option<GeneralNameStackRef<'a>> {
        // SAFETY: raw-place projection copies the nullable owned pointer. A
        // non-null generated stack remains alive for the record borrow.
        let raw = unsafe { ptr::addr_of!((*self.as_ptr()).CRLissuer).read() };
        // SAFETY: the generated stack tag erases to the common representation,
        // and the enclosing record supplies the returned lifetime.
        unsafe { GeneralNameStackRef::from_ptr(raw.cast()) }
    }
}

impl DistPointMut<'_> {
    /// Updates OpenSSL's derived reason-mask cache.
    pub fn set_dp_reasons(&mut self, value: i32) {
        // SAFETY: raw-place projection writes the scalar through the exclusive
        // record handle without forming a Rust reference to C storage.
        unsafe { ptr::addr_of_mut!((*self.as_mut_ptr()).dp_reasons).write(value) }
    }

    /// Exclusively reborrows the optional reason bit string.
    #[must_use]
    pub fn reasons_mut(&mut self) -> Option<Asn1StringMut<'_>> {
        // SAFETY: the exclusive record handle permits an exclusive reborrow of
        // its owned child for the duration of this call's result.
        let raw = unsafe { ptr::addr_of!((*self.as_mut_ptr()).reasons).read() };
        // SAFETY: the result is bounded by the exclusive reborrow above.
        unsafe { Asn1StringMut::from_ptr(raw) }
    }

    /// Replaces the owned reason string and releases the previous value.
    pub fn set_reasons(&mut self, value: Option<CBox<Asn1String>>) {
        let value = value.map_or(ptr::null_mut(), CBox::into_raw);
        // SAFETY: the exclusive handle permits replacing this owned field.
        let previous = unsafe { ptr::addr_of_mut!((*self.as_mut_ptr()).reasons).replace(value) };
        // SAFETY: a detached non-null child remains a complete ASN.1 string
        // carrying exactly one `ASN1_STRING_free` obligation.
        drop(unsafe { CBox::<Asn1String>::from_raw(previous) });
    }

    /// Takes the owned reason string, leaving the optional field empty.
    #[must_use]
    pub fn take_reasons(&mut self) -> Option<CBox<Asn1String>> {
        // SAFETY: the exclusive handle permits clearing the field and moving
        // its unique ownership into the returned owner.
        let raw =
            unsafe { ptr::addr_of_mut!((*self.as_mut_ptr()).reasons).replace(ptr::null_mut()) };
        // SAFETY: a detached non-null value is still complete and uniquely
        // owns its registered free obligation.
        unsafe { CBox::from_raw(raw) }
    }

    /// Exclusively reborrows the optional distribution-point name.
    #[must_use]
    pub fn dist_point_name_mut(&mut self) -> Option<DistPointNameMut<'_>> {
        // SAFETY: the exclusive record handle permits an exclusive child
        // reborrow bounded by the returned handle's lifetime.
        let raw = unsafe { ptr::addr_of!((*self.as_mut_ptr()).distpoint).read() };
        // SAFETY: the result is bounded by the exclusive reborrow above.
        unsafe { DistPointNameMut::from_ptr(raw) }
    }

    /// Replaces the owned distribution-point name and frees the old value.
    pub fn set_dist_point_name(&mut self, value: Option<CBox<DistPointName>>) {
        let value = value.map_or(ptr::null_mut(), CBox::into_raw);
        // SAFETY: the exclusive handle permits replacing this owned field.
        let previous = unsafe { ptr::addr_of_mut!((*self.as_mut_ptr()).distpoint).replace(value) };
        // SAFETY: a detached non-null child remains complete and uniquely
        // carries one `DIST_POINT_NAME_free` obligation.
        drop(unsafe { CBox::<DistPointName>::from_raw(previous) });
    }

    /// Takes the owned distribution-point name, leaving the field empty.
    #[must_use]
    pub fn take_dist_point_name(&mut self) -> Option<CBox<DistPointName>> {
        // SAFETY: the exclusive handle permits clearing the field and moving
        // its unique ownership into the returned owner.
        let raw =
            unsafe { ptr::addr_of_mut!((*self.as_mut_ptr()).distpoint).replace(ptr::null_mut()) };
        // SAFETY: a detached non-null value remains a complete owned choice.
        unsafe { CBox::from_raw(raw) }
    }

    /// Exclusively reborrows the optional issuer-name sequence.
    #[must_use]
    pub fn crl_issuer_mut(&mut self) -> Option<GeneralNameStackMut<'_>> {
        // SAFETY: the exclusive record handle permits an exclusive reborrow of
        // the owned generated sequence.
        let raw = unsafe { ptr::addr_of!((*self.as_mut_ptr()).CRLissuer).read() };
        // SAFETY: the generated tag erases to the common stack representation,
        // and the result is bounded by the exclusive record reborrow.
        unsafe { GeneralNameStackMut::from_ptr(raw.cast()) }
    }

    /// Replaces the owned issuer sequence and releases all old elements.
    pub fn set_crl_issuer(&mut self, value: Option<GeneralNames>) {
        let value: *mut ffi::stack_st_GENERAL_NAME = value.map_or(ptr::null_mut(), |value| {
            let (raw, _dropper) = value.into_raw();
            raw.cast()
        });
        // SAFETY: the exclusive handle permits replacing this owned sequence.
        let previous = unsafe { ptr::addr_of_mut!((*self.as_mut_ptr()).CRLissuer).replace(value) };
        // SAFETY: the detached non-null sequence and each of its elements were
        // uniquely owned and match `GeneralNamesFree`.
        drop(unsafe { GeneralNames::from_raw(previous.cast(), GeneralNamesFree) });
    }

    /// Takes the issuer-name sequence, leaving the optional field empty.
    #[must_use]
    pub fn take_crl_issuer(&mut self) -> Option<GeneralNames> {
        // SAFETY: the exclusive handle permits clearing the field and moving
        // ownership of the sequence and all elements to the returned owner.
        let raw =
            unsafe { ptr::addr_of_mut!((*self.as_mut_ptr()).CRLissuer).replace(ptr::null_mut()) };
        // SAFETY: the detached non-null sequence remains complete and uniquely
        // owned under the matching generated full-destructor policy.
        unsafe { GeneralNames::from_raw(raw.cast(), GeneralNamesFree) }
    }
}

define_ctype!(
    /// Wraps: EDIPartyName_st
    ///
    /// Layout-compatible storage for an EDI party name. Both directory-string
    /// pointers are owned; `nameAssigner` is optional, while a manually
    /// modified or malformed `partyName` may be null even though valid ASN.1
    /// encodings require it.
    EdiPartyName,
    EdiPartyNameRef,
    EdiPartyNameMut,
    ffi::EDIPartyName_st
);

// The generated ASN.1 destructor releases both directory strings and the
// containing allocation.
impl_dropped!(EdiPartyName, ffi::EDIPartyName_st, ffi::EDIPARTYNAME_free);

impl EdiPartyName {
    /// Allocates an empty EDI party-name record.
    #[must_use]
    pub fn new() -> Option<CBox<Self>> {
        // SAFETY: a non-null result is a fresh initialized generated record
        // carrying exactly one `EDIPARTYNAME_free` obligation.
        unsafe { CBox::from_raw(ffi::EDIPARTYNAME_new()) }
    }
}

impl<'a> EdiPartyNameRef<'a> {
    /// Wraps: EDIPartyName_st.partyName
    ///
    /// Borrows the owned party name. The option preserves construction and
    /// malformed or manually modified states even though ASN.1 encoding
    /// requires this field.
    #[must_use]
    pub fn party_name(&self) -> Option<Asn1StringRef<'a>> {
        // SAFETY: raw-place projection copies the nullable owned pointer. A
        // non-null string remains alive for the enclosing handle's `'a`.
        let raw = unsafe { ptr::addr_of!((*self.as_ptr()).partyName).read() };
        // SAFETY: the enclosing record owns the child for the returned borrow.
        unsafe { Asn1StringRef::from_ptr(raw) }
    }

    /// Wraps: EDIPartyName_st.nameAssigner
    ///
    /// Borrows the optional owned name assigner.
    #[must_use]
    pub fn name_assigner(&self) -> Option<Asn1StringRef<'a>> {
        // SAFETY: raw-place projection copies the nullable owned pointer. A
        // non-null string remains alive for the enclosing handle's `'a`.
        let raw = unsafe { ptr::addr_of!((*self.as_ptr()).nameAssigner).read() };
        // SAFETY: the enclosing record owns the child for the returned borrow.
        unsafe { Asn1StringRef::from_ptr(raw) }
    }
}

impl EdiPartyNameMut<'_> {
    /// Exclusively reborrows the owned party name.
    #[must_use]
    pub fn party_name_mut(&mut self) -> Option<Asn1StringMut<'_>> {
        // SAFETY: the exclusive record handle permits an exclusive child
        // reborrow bounded by the returned handle's lifetime.
        let raw = unsafe { ptr::addr_of!((*self.as_mut_ptr()).partyName).read() };
        // SAFETY: the result is bounded by the exclusive reborrow above.
        unsafe { Asn1StringMut::from_ptr(raw) }
    }

    /// Replaces the owned party name and frees the previous string.
    pub fn set_party_name(&mut self, value: Option<CBox<Asn1String>>) {
        let value = value.map_or(ptr::null_mut(), CBox::into_raw);
        // SAFETY: the exclusive handle permits replacing this owned field.
        let previous = unsafe { ptr::addr_of_mut!((*self.as_mut_ptr()).partyName).replace(value) };
        // SAFETY: a detached non-null child remains a complete uniquely owned
        // ASN.1 string with one matching free obligation.
        drop(unsafe { CBox::<Asn1String>::from_raw(previous) });
    }

    /// Takes the party name, leaving the field empty.
    #[must_use]
    pub fn take_party_name(&mut self) -> Option<CBox<Asn1String>> {
        // SAFETY: the exclusive handle permits clearing the field and moving
        // its unique ownership into the returned owner.
        let raw =
            unsafe { ptr::addr_of_mut!((*self.as_mut_ptr()).partyName).replace(ptr::null_mut()) };
        // SAFETY: a detached non-null value remains a complete owned string.
        unsafe { CBox::from_raw(raw) }
    }

    /// Exclusively reborrows the optional name assigner.
    #[must_use]
    pub fn name_assigner_mut(&mut self) -> Option<Asn1StringMut<'_>> {
        // SAFETY: the exclusive record handle permits an exclusive child
        // reborrow bounded by the returned handle's lifetime.
        let raw = unsafe { ptr::addr_of!((*self.as_mut_ptr()).nameAssigner).read() };
        // SAFETY: the result is bounded by the exclusive reborrow above.
        unsafe { Asn1StringMut::from_ptr(raw) }
    }

    /// Replaces the owned name assigner and frees the previous string.
    pub fn set_name_assigner(&mut self, value: Option<CBox<Asn1String>>) {
        let value = value.map_or(ptr::null_mut(), CBox::into_raw);
        // SAFETY: the exclusive handle permits replacing this owned field.
        let previous =
            unsafe { ptr::addr_of_mut!((*self.as_mut_ptr()).nameAssigner).replace(value) };
        // SAFETY: a detached non-null child remains a complete uniquely owned
        // ASN.1 string with one matching free obligation.
        drop(unsafe { CBox::<Asn1String>::from_raw(previous) });
    }

    /// Takes the optional name assigner, leaving the field empty.
    #[must_use]
    pub fn take_name_assigner(&mut self) -> Option<CBox<Asn1String>> {
        // SAFETY: the exclusive handle permits clearing the field and moving
        // its unique ownership into the returned owner.
        let raw = unsafe {
            ptr::addr_of_mut!((*self.as_mut_ptr()).nameAssigner).replace(ptr::null_mut())
        };
        // SAFETY: a detached non-null value remains a complete owned string.
        unsafe { CBox::from_raw(raw) }
    }
}

#[cfg(test)]
mod distribution_point_and_edi_tests {
    use core::mem::{align_of, size_of};

    use ffibox::{CCell, CDropped};

    use super::*;
    use crate::asn1::asn1_lib::ASN1_STRING_new;
    use crate::stack::stack::OPENSSL_sk_num;

    fn assert_owned_cell<T: CCell + CDropped>() {}

    #[test]
    fn distribution_point_owns_and_reborrows_all_optional_children() {
        assert_owned_cell::<DistPoint>();
        assert_eq!(size_of::<DistPoint>(), size_of::<ffi::DIST_POINT_st>());
        assert_eq!(align_of::<DistPoint>(), align_of::<ffi::DIST_POINT_st>());

        let mut point = DistPoint::new().expect("DIST_POINT_new");
        assert!(point.as_ref().reasons().is_none());
        assert!(point.as_ref().dist_point_name().is_none());
        assert!(point.as_ref().crl_issuer().is_none());

        point.as_mut().set_dp_reasons(0x807f);
        assert_eq!(point.as_ref().dp_reasons(), 0x807f);

        point.as_mut().set_reasons(ASN1_STRING_new());
        assert!(point.as_ref().reasons().is_some());
        assert!(point.as_mut().reasons_mut().is_some());
        let reasons = point.as_mut().take_reasons().expect("owned reasons");
        assert!(point.as_ref().reasons().is_none());
        point.as_mut().set_reasons(Some(reasons));

        point.as_mut().set_dist_point_name(DistPointName::new());
        assert!(point.as_ref().dist_point_name().is_some());
        assert!(point.as_mut().dist_point_name_mut().is_some());
        drop(
            point
                .as_mut()
                .take_dist_point_name()
                .expect("owned distribution point name"),
        );

        // A generated empty sequence is a complete full-destructor owner.
        // SAFETY: OpenSSL returns null or a fresh complete GENERAL_NAMES stack.
        let issuers =
            unsafe { GeneralNames::from_raw(ffi::GENERAL_NAMES_new().cast(), GeneralNamesFree) };
        point.as_mut().set_crl_issuer(issuers);
        assert_eq!(OPENSSL_sk_num(point.as_ref().crl_issuer()), Some(0));
        assert!(point.as_mut().crl_issuer_mut().is_some());
        drop(point.as_mut().take_crl_issuer().expect("owned issuers"));
    }

    #[test]
    fn edi_party_name_owns_both_directory_strings() {
        assert_owned_cell::<EdiPartyName>();
        assert_eq!(size_of::<EdiPartyName>(), size_of::<ffi::EDIPartyName_st>());
        assert_eq!(
            align_of::<EdiPartyName>(),
            align_of::<ffi::EDIPartyName_st>()
        );

        let mut edi = EdiPartyName::new().expect("EDIPARTYNAME_new");
        // The generated constructor materializes the required directory
        // string, while leaving the optional assigner absent.
        assert!(edi.as_ref().party_name().is_some());
        assert!(edi.as_ref().name_assigner().is_none());

        edi.as_mut().set_party_name(ASN1_STRING_new());
        edi.as_mut().set_name_assigner(ASN1_STRING_new());
        assert!(edi.as_ref().party_name().is_some());
        assert!(edi.as_ref().name_assigner().is_some());
        assert!(edi.as_mut().party_name_mut().is_some());
        assert!(edi.as_mut().name_assigner_mut().is_some());

        let party = edi.as_mut().take_party_name().expect("owned party name");
        let assigner = edi.as_mut().take_name_assigner().expect("owned assigner");
        assert!(edi.as_ref().party_name().is_none());
        assert!(edi.as_ref().name_assigner().is_none());
        edi.as_mut().set_party_name(Some(party));
        edi.as_mut().set_name_assigner(Some(assigner));
    }
}
define_ctype!(
    /// Wraps: AUTHORITY_KEYID_st
    ///
    /// Layout-compatible storage for an authority-key-identifier sequence.
    /// Each optional pointer is independently owned by the record; borrowed
    /// access stays lifetime-bound through [`AuthorityKeyIdRef`] and
    /// [`AuthorityKeyIdMut`] without forming Rust references over C storage.
    AuthorityKeyId,
    AuthorityKeyIdRef,
    AuthorityKeyIdMut,
    ffi::AUTHORITY_KEYID_st
);

// The generated ASN.1 destructor releases all three optional fields, including
// every GENERAL_NAME in `issuer`, and then releases the record allocation.
impl_dropped!(
    AuthorityKeyId,
    ffi::AUTHORITY_KEYID_st,
    ffi::AUTHORITY_KEYID_free
);

impl AuthorityKeyId {
    /// Allocates an empty authority-key-identifier sequence.
    #[must_use]
    pub fn new() -> Option<CBox<Self>> {
        // SAFETY: a non-null result is a fresh complete ASN.1 sequence carrying
        // exactly one `AUTHORITY_KEYID_free` obligation.
        unsafe { CBox::from_raw(ffi::AUTHORITY_KEYID_new()) }
    }
}

impl<'a> AuthorityKeyIdRef<'a> {
    /// Wraps: AUTHORITY_KEYID_st.issuer
    ///
    /// Borrows the optional issuer-name sequence. The enclosing record keeps
    /// the stack, its pointer array, and every general name alive.
    #[must_use]
    pub fn issuer(&self) -> Option<GeneralNameStackRef<'a>> {
        // SAFETY: raw-place projection copies the nullable owned pointer
        // without forming a reference. The enclosing handle supplies `'a`.
        let issuer = unsafe { ptr::addr_of!((*self.as_ptr()).issuer).read() };
        // SAFETY: the generated stack tag erases to the common stack layout,
        // and a non-null value remains owned by this record for `'a`.
        unsafe { GeneralNameStackRef::from_ptr(issuer.cast()) }
    }

    /// Wraps: AUTHORITY_KEYID_st.serial
    ///
    /// Borrows the optional ASN.1 serial number.
    #[must_use]
    pub fn serial(&self) -> Option<Asn1StringRef<'a>> {
        // SAFETY: raw-place projection copies the nullable owned pointer. A
        // non-null ASN1_INTEGER is the common ASN.1 string layout and remains
        // alive for the enclosing handle's `'a`.
        let serial = unsafe { ptr::addr_of!((*self.as_ptr()).serial).read() };
        // SAFETY: the ownership and lifetime are established above.
        unsafe { Asn1StringRef::from_ptr(serial) }
    }

    /// Wraps: AUTHORITY_KEYID_st.keyid
    ///
    /// Borrows the optional ASN.1 octet string containing the key identifier.
    #[must_use]
    pub fn key_id(&self) -> Option<Asn1StringRef<'a>> {
        // SAFETY: raw-place projection copies the nullable owned pointer. A
        // non-null ASN1_OCTET_STRING uses the common ASN.1 string layout and
        // remains alive for the enclosing handle's `'a`.
        let key_id = unsafe { ptr::addr_of!((*self.as_ptr()).keyid).read() };
        // SAFETY: the ownership and lifetime are established above.
        unsafe { Asn1StringRef::from_ptr(key_id) }
    }
}

impl AuthorityKeyIdMut<'_> {
    /// Exclusively reborrows the optional issuer-name sequence.
    #[must_use]
    pub fn issuer_mut(&mut self) -> Option<GeneralNameStackMut<'_>> {
        // SAFETY: the exclusive record handle permits an exclusive reborrow of
        // its owned sequence for the duration of this call's borrow.
        let issuer = unsafe { ptr::addr_of!((*self.as_mut_ptr()).issuer).read() };
        // SAFETY: the generated tag erases to the common stack layout and the
        // result is bounded by the exclusive reborrow above.
        unsafe { GeneralNameStackMut::from_ptr(issuer.cast()) }
    }

    /// Exclusively reborrows the optional serial number.
    #[must_use]
    pub fn serial_mut(&mut self) -> Option<Asn1StringMut<'_>> {
        // SAFETY: the exclusive record handle permits an exclusive reborrow of
        // its owned ASN1_INTEGER for the duration of this borrow.
        let serial = unsafe { ptr::addr_of!((*self.as_mut_ptr()).serial).read() };
        // SAFETY: ASN1_INTEGER has the wrapped ASN.1 string layout.
        unsafe { Asn1StringMut::from_ptr(serial) }
    }

    /// Exclusively reborrows the optional key identifier.
    #[must_use]
    pub fn key_id_mut(&mut self) -> Option<Asn1StringMut<'_>> {
        // SAFETY: the exclusive record handle permits an exclusive reborrow of
        // its owned ASN1_OCTET_STRING for the duration of this borrow.
        let key_id = unsafe { ptr::addr_of!((*self.as_mut_ptr()).keyid).read() };
        // SAFETY: ASN1_OCTET_STRING has the wrapped ASN.1 string layout.
        unsafe { Asn1StringMut::from_ptr(key_id) }
    }

    /// Replaces the owned issuer sequence and releases the previous sequence
    /// together with every name it contains.
    pub fn set_issuer(&mut self, issuer: Option<GeneralNames>) {
        let issuer = issuer.map_or(ptr::null_mut(), |issuer| issuer.into_raw().0.cast());
        // SAFETY: the exclusive handle permits replacing this owned pointer;
        // ownership of the detached sequence transfers to the temporary owner.
        let previous = unsafe { ptr::addr_of_mut!((*self.as_mut_ptr()).issuer).replace(issuer) };
        // SAFETY: a detached non-null sequence and each of its elements carried
        // exactly the full `GENERAL_NAMES_free` obligation.
        drop(unsafe { GeneralNames::from_raw(previous.cast(), GeneralNamesFree) });
    }

    /// Takes the owned issuer sequence, leaving the optional slot empty.
    #[must_use]
    pub fn take_issuer(&mut self) -> Option<GeneralNames> {
        // SAFETY: the exclusive handle permits clearing the field and moving
        // its unique sequence ownership into the returned owner.
        let issuer =
            unsafe { ptr::addr_of_mut!((*self.as_mut_ptr()).issuer).replace(ptr::null_mut()) };
        // SAFETY: a detached non-null value owns the complete sequence and all
        // of its elements under the full GENERAL_NAMES policy.
        unsafe { GeneralNames::from_raw(issuer.cast(), GeneralNamesFree) }
    }

    /// Replaces the owned serial number and releases the previous value.
    pub fn set_serial(&mut self, serial: Option<CBox<Asn1String>>) {
        let serial = serial.map_or(ptr::null_mut(), CBox::into_raw);
        // SAFETY: the exclusive handle permits replacing this owned pointer.
        let previous = unsafe { ptr::addr_of_mut!((*self.as_mut_ptr()).serial).replace(serial) };
        // SAFETY: a detached non-null ASN1_INTEGER is a complete independently
        // allocated ASN.1 string carrying one ordinary free obligation.
        drop(unsafe { CBox::<Asn1String>::from_raw(previous) });
    }

    /// Takes the owned serial number, leaving the optional slot empty.
    #[must_use]
    pub fn take_serial(&mut self) -> Option<CBox<Asn1String>> {
        // SAFETY: the exclusive handle transfers the owned pointer out while
        // leaving a valid null optional field.
        let serial =
            unsafe { ptr::addr_of_mut!((*self.as_mut_ptr()).serial).replace(ptr::null_mut()) };
        // SAFETY: a detached non-null ASN1_INTEGER is a complete ASN.1 string.
        unsafe { CBox::from_raw(serial) }
    }

    /// Replaces the owned key identifier and releases the previous value.
    pub fn set_key_id(&mut self, key_id: Option<CBox<Asn1String>>) {
        let key_id = key_id.map_or(ptr::null_mut(), CBox::into_raw);
        // SAFETY: the exclusive handle permits replacing this owned pointer.
        let previous = unsafe { ptr::addr_of_mut!((*self.as_mut_ptr()).keyid).replace(key_id) };
        // SAFETY: a detached non-null ASN1_OCTET_STRING is a complete
        // independently allocated ASN.1 string.
        drop(unsafe { CBox::<Asn1String>::from_raw(previous) });
    }

    /// Takes the owned key identifier, leaving the optional slot empty.
    #[must_use]
    pub fn take_key_id(&mut self) -> Option<CBox<Asn1String>> {
        // SAFETY: the exclusive handle transfers the owned pointer out while
        // leaving a valid null optional field.
        let key_id =
            unsafe { ptr::addr_of_mut!((*self.as_mut_ptr()).keyid).replace(ptr::null_mut()) };
        // SAFETY: a detached non-null ASN1_OCTET_STRING is a complete string.
        unsafe { CBox::from_raw(key_id) }
    }
}

define_ctype!(
    /// Wraps: BASIC_CONSTRAINTS_st
    ///
    /// Layout-compatible storage for an X.509 basic-constraints sequence. Its
    /// path-length integer is optional and owned by the record.
    BasicConstraints,
    BasicConstraintsRef,
    BasicConstraintsMut,
    ffi::BASIC_CONSTRAINTS_st
);

// The generated ASN.1 destructor releases the optional path-length integer and
// then the basic-constraints allocation.
impl_dropped!(
    BasicConstraints,
    ffi::BASIC_CONSTRAINTS_st,
    ffi::BASIC_CONSTRAINTS_free
);

impl BasicConstraints {
    /// Allocates an empty basic-constraints sequence.
    #[must_use]
    pub fn new() -> Option<CBox<Self>> {
        // SAFETY: a non-null result is a fresh complete ASN.1 sequence carrying
        // exactly one `BASIC_CONSTRAINTS_free` obligation.
        unsafe { CBox::from_raw(ffi::BASIC_CONSTRAINTS_new()) }
    }
}

impl<'a> BasicConstraintsRef<'a> {
    /// Wraps: BASIC_CONSTRAINTS_st.ca
    ///
    /// Reports whether the certificate-authority flag is set. OpenSSL treats
    /// every nonzero representation of this ASN.1 boolean as true.
    #[must_use]
    pub fn is_ca(&self) -> bool {
        // SAFETY: raw-place projection copies the initialized integer without
        // forming a reference over memory OpenSSL may mutate.
        unsafe { ptr::addr_of!((*self.as_ptr()).ca).read() != 0 }
    }

    /// Wraps: BASIC_CONSTRAINTS_st.pathlen
    ///
    /// Borrows the optional ASN.1 path-length integer.
    #[must_use]
    pub fn path_len(&self) -> Option<Asn1StringRef<'a>> {
        // SAFETY: raw-place projection copies the nullable owned pointer. A
        // non-null ASN1_INTEGER remains alive for this handle's borrow.
        let path_len = unsafe { ptr::addr_of!((*self.as_ptr()).pathlen).read() };
        // SAFETY: ASN1_INTEGER has the common wrapped ASN.1 string layout.
        unsafe { Asn1StringRef::from_ptr(path_len) }
    }
}

impl BasicConstraintsMut<'_> {
    /// Sets the certificate-authority flag to OpenSSL's canonical false or
    /// true integer representation.
    pub fn set_ca(&mut self, value: bool) {
        // SAFETY: raw-place projection writes the initialized scalar through
        // the exclusive record handle without forming a reference.
        unsafe { ptr::addr_of_mut!((*self.as_mut_ptr()).ca).write(i32::from(value)) }
    }

    /// Exclusively reborrows the optional path-length integer.
    #[must_use]
    pub fn path_len_mut(&mut self) -> Option<Asn1StringMut<'_>> {
        // SAFETY: the exclusive record handle permits an exclusive reborrow of
        // its owned ASN1_INTEGER for the duration of this borrow.
        let path_len = unsafe { ptr::addr_of!((*self.as_mut_ptr()).pathlen).read() };
        // SAFETY: ASN1_INTEGER has the common wrapped ASN.1 string layout.
        unsafe { Asn1StringMut::from_ptr(path_len) }
    }

    /// Replaces the owned path-length integer and releases the previous value.
    pub fn set_path_len(&mut self, path_len: Option<CBox<Asn1String>>) {
        let path_len = path_len.map_or(ptr::null_mut(), CBox::into_raw);
        // SAFETY: the exclusive handle permits replacing this owned pointer.
        let previous = unsafe { ptr::addr_of_mut!((*self.as_mut_ptr()).pathlen).replace(path_len) };
        // SAFETY: a detached non-null ASN1_INTEGER is a complete independently
        // allocated ASN.1 string carrying one free obligation.
        drop(unsafe { CBox::<Asn1String>::from_raw(previous) });
    }

    /// Takes the owned path-length integer, leaving the optional slot empty.
    #[must_use]
    pub fn take_path_len(&mut self) -> Option<CBox<Asn1String>> {
        // SAFETY: the exclusive handle transfers the owned pointer out and
        // leaves a valid null optional field.
        let path_len =
            unsafe { ptr::addr_of_mut!((*self.as_mut_ptr()).pathlen).replace(ptr::null_mut()) };
        // SAFETY: a detached non-null ASN1_INTEGER is a complete ASN.1 string.
        unsafe { CBox::from_raw(path_len) }
    }
}

#[cfg(test)]
mod authority_and_basic_constraints_tests {
    use core::mem::{align_of, size_of};

    use ffibox::{CCell, CDropped};

    use super::*;
    use crate::asn1::asn1_lib::ASN1_STRING_type_new;
    use crate::stack::stack::{OPENSSL_sk_new_null, OPENSSL_sk_num};
    use crate::x509::x509_internal::GeneralName;

    fn assert_drop_owner<T: CCell + CDropped>() {}

    fn empty_general_names() -> GeneralNames {
        let stack = OPENSSL_sk_new_null::<GeneralName>().expect("GENERAL_NAMES stack");
        let raw = stack.into_raw();
        // SAFETY: this fresh stack is empty, so the full GENERAL_NAMES policy
        // has no element ownership to establish and owns the stack allocation.
        unsafe { CBoxWith::from_raw(raw, GeneralNamesFree) }
            .expect("an owning stack has a non-null pointer")
    }

    #[test]
    fn authority_key_id_owns_and_reborrows_all_optional_fields() {
        assert_drop_owner::<AuthorityKeyId>();
        assert_eq!(
            size_of::<AuthorityKeyId>(),
            size_of::<ffi::AUTHORITY_KEYID_st>()
        );
        assert_eq!(
            align_of::<AuthorityKeyId>(),
            align_of::<ffi::AUTHORITY_KEYID_st>()
        );

        let mut authority = AuthorityKeyId::new().expect("AUTHORITY_KEYID_new");
        assert!(authority.as_ref().issuer().is_none());
        assert!(authority.as_ref().serial().is_none());
        assert!(authority.as_ref().key_id().is_none());

        authority.as_mut().set_issuer(Some(empty_general_names()));
        authority
            .as_mut()
            .set_serial(ASN1_STRING_type_new(ffi::V_ASN1_INTEGER as i32));
        authority
            .as_mut()
            .set_key_id(ASN1_STRING_type_new(ffi::V_ASN1_OCTET_STRING as i32));

        assert_eq!(OPENSSL_sk_num(authority.as_ref().issuer()), Some(0));
        assert!(authority.as_mut().issuer_mut().is_some());
        assert!(authority.as_mut().serial_mut().is_some());
        assert!(authority.as_mut().key_id_mut().is_some());

        let issuer = authority.as_mut().take_issuer().expect("owned issuer");
        let serial = authority.as_mut().take_serial().expect("owned serial");
        let key_id = authority.as_mut().take_key_id().expect("owned key id");
        assert!(authority.as_ref().issuer().is_none());
        assert!(authority.as_ref().serial().is_none());
        assert!(authority.as_ref().key_id().is_none());
        authority.as_mut().set_issuer(Some(issuer));
        authority.as_mut().set_serial(Some(serial));
        authority.as_mut().set_key_id(Some(key_id));
    }

    #[test]
    fn basic_constraints_preserves_scalar_and_owned_path_length() {
        assert_drop_owner::<BasicConstraints>();
        assert_eq!(
            size_of::<BasicConstraints>(),
            size_of::<ffi::BASIC_CONSTRAINTS_st>()
        );
        assert_eq!(
            align_of::<BasicConstraints>(),
            align_of::<ffi::BASIC_CONSTRAINTS_st>()
        );

        let mut constraints = BasicConstraints::new().expect("BASIC_CONSTRAINTS_new");
        assert!(!constraints.as_ref().is_ca());
        assert!(constraints.as_ref().path_len().is_none());
        constraints.as_mut().set_ca(true);
        assert!(constraints.as_ref().is_ca());

        let path_len = ASN1_STRING_type_new(ffi::V_ASN1_INTEGER as i32).expect("ASN1_INTEGER");
        let path_len_raw = path_len.as_ptr();
        constraints.as_mut().set_path_len(Some(path_len));
        assert_eq!(
            constraints.as_ref().path_len().map(|value| value.as_ptr()),
            Some(path_len_raw.cast_const())
        );
        assert!(constraints.as_mut().path_len_mut().is_some());
        let path_len = constraints
            .as_mut()
            .take_path_len()
            .expect("owned path length");
        assert_eq!(path_len.as_ptr(), path_len_raw);
        assert!(constraints.as_ref().path_len().is_none());
        constraints.as_mut().set_path_len(Some(path_len));
    }
}
