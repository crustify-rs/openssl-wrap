//! Wrappers assigned from `crypto/x509/v3_genn.c`.

use core::cmp::Ordering;
use core::ptr::{self, NonNull};

use ffibox::{CBox, CBoxWith, CDropper};
use libcrypto_sys as ffi;

use crate::asn1::asn1::{Asn1ObjectRef, Asn1StringRef};
use crate::asn1::openssl_asn1::{Asn1TypeRef, Asn1TypeValue};
use crate::x509::x509_internal::{GeneralNameStack, X509NameRef};
use crate::x509::x509v3::{
    EdiPartyNameRef, GeneralName, GeneralNameRef, GeneralNameType, GeneralNameValueRef,
    OtherNameRef,
};

/// Full ASN.1 teardown policy for a general-names sequence.
#[derive(Clone, Copy, Debug, Default)]
pub struct GeneralNamesFree;

// SAFETY: the generated destructor releases every owned GENERAL_NAME and the
// generated stack exactly once.
unsafe impl CDropper<GeneralNameStack> for GeneralNamesFree {
    unsafe fn c_drop(&self, object: NonNull<GeneralNameStack>) {
        // SAFETY: the dropper contract supplies the sole complete stack owner.
        unsafe { ffi::GENERAL_NAMES_free(object.as_ptr().cast()) }
    }
}

/// A general-names sequence that owns all its elements.
pub type GeneralNames = CBoxWith<GeneralNameStack, GeneralNamesFree>;

/// Wraps: GENERAL_NAMES_free
#[allow(non_snake_case)]
pub fn GENERAL_NAMES_free(value: GeneralNames) {
    drop(value);
}

/// Wraps: GENERAL_NAMES_new
#[must_use]
#[allow(non_snake_case)]
pub fn GENERAL_NAMES_new() -> Option<GeneralNames> {
    // SAFETY: a non-null result is a fresh complete generated stack with one
    // matching full-destructor obligation.
    unsafe { CBoxWith::from_raw(ffi::GENERAL_NAMES_new().cast(), GeneralNamesFree) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stack::stack::OPENSSL_sk_num;

    #[test]
    fn constructor_returns_an_empty_owned_sequence() {
        let value = GENERAL_NAMES_new().expect("GENERAL_NAMES_new");
        assert_eq!(OPENSSL_sk_num(Some(value.as_ref())), Some(0));
        GENERAL_NAMES_free(value);
    }
}

/// Wraps: GENERAL_NAME_cmp
/// Compares two optional, complete general-name choices.
///
/// Several of the C comparator's arms dereference a choice member without a
/// null check, so an incomplete choice is screened out here and reported as
/// [`Ordering::Less`] — the same answer C gives for every mismatch it does
/// detect. "Complete" reaches one level deeper than non-null for the
/// `GEN_OTHERNAME` arm: see [`is_comparable_value`].
#[must_use]
#[allow(non_snake_case)]
pub fn GENERAL_NAME_cmp(a: Option<GeneralNameRef<'_>>, b: Option<GeneralNameRef<'_>>) -> Ordering {
    if a.is_some_and(|value| !is_comparable(value)) || b.is_some_and(|value| !is_comparable(value))
    {
        return Ordering::Less;
    }
    let a = a.map_or(ptr::null_mut(), |value| value.as_ptr().cast_mut());
    let b = b.map_or(ptr::null_mut(), |value| value.as_ptr().cast_mut());
    // SAFETY: each pointer is null or a live shared complete choice. The
    // legacy non-const signature exists because the `GEN_DIRNAME` arm reaches
    // `X509_NAME_cmp`, which may refresh a name's cached canonical encoding;
    // no arm releases or reallocates a choice member.
    unsafe { ffi::GENERAL_NAME_cmp(a, b) }.cmp(&0)
}

fn is_comparable(value: GeneralNameRef<'_>) -> bool {
    match value.value() {
        GeneralNameValueRef::Empty | GeneralNameValueRef::Unknown(_) => false,
        GeneralNameValueRef::OtherName(Some(value)) => {
            value.type_id().is_some() && value.value().is_some_and(is_comparable_value)
        }
        GeneralNameValueRef::EdiPartyName(Some(value)) => value.party_name().is_some(),
        GeneralNameValueRef::OtherName(None)
        | GeneralNameValueRef::Email(None)
        | GeneralNameValueRef::Dns(None)
        | GeneralNameValueRef::X400Address(None)
        | GeneralNameValueRef::DirectoryName(None)
        | GeneralNameValueRef::EdiPartyName(None)
        | GeneralNameValueRef::Uri(None)
        | GeneralNameValueRef::IpAddress(None)
        | GeneralNameValueRef::RegisteredId(None) => false,
        GeneralNameValueRef::Email(Some(_))
        | GeneralNameValueRef::Dns(Some(_))
        | GeneralNameValueRef::X400Address(Some(_))
        | GeneralNameValueRef::DirectoryName(Some(_))
        | GeneralNameValueRef::Uri(Some(_))
        | GeneralNameValueRef::IpAddress(Some(_))
        | GeneralNameValueRef::RegisteredId(Some(_)) => true,
    }
}

/// Reports whether `ASN1_TYPE_cmp` can read this tagged value.
///
/// The `GEN_OTHERNAME` arm of `GENERAL_NAME_cmp` reaches `ASN1_TYPE_cmp`,
/// which dispatches on the tag. Only three of its arms avoid dereferencing the
/// union: `V_ASN1_BOOLEAN` reads a scalar, `V_ASN1_NULL` reads nothing, and
/// `V_ASN1_OBJECT` hands both pointers to `OBJ_cmp`. Every other tag falls
/// into the `default:` arm, which casts the union to `ASN1_STRING *` and
/// dereferences it without a null check — so a non-null `value` is not on its
/// own enough, and the tag decides.
///
/// Two tags are rejected outright rather than by their payload. `V_ASN1_UNDEF`
/// is what a freshly allocated `ASN1_TYPE` carries beside a null union, which
/// is exactly the state `OTHERNAME_new` leaves behind. `V_ASN1_ANY`'s payload
/// is a nested `ASN1_TYPE` header, which that same `default:` arm would read
/// as an `ASN1_STRING`.
fn is_comparable_value(value: Asn1TypeRef<'_>) -> bool {
    match value.value() {
        Asn1TypeValue::Boolean(_) | Asn1TypeValue::Null => true,
        Asn1TypeValue::Object(object) => object.is_some(),
        Asn1TypeValue::Undefined | Asn1TypeValue::Any(_) => false,
        Asn1TypeValue::Integer(value)
        | Asn1TypeValue::Enumerated(value)
        | Asn1TypeValue::BitString(value)
        | Asn1TypeValue::OctetString(value)
        | Asn1TypeValue::PrintableString(value)
        | Asn1TypeValue::T61String(value)
        | Asn1TypeValue::Ia5String(value)
        | Asn1TypeValue::GeneralString(value)
        | Asn1TypeValue::BmpString(value)
        | Asn1TypeValue::UniversalString(value)
        | Asn1TypeValue::UtcTime(value)
        | Asn1TypeValue::GeneralizedTime(value)
        | Asn1TypeValue::VisibleString(value)
        | Asn1TypeValue::Utf8String(value)
        | Asn1TypeValue::Set(value)
        | Asn1TypeValue::Sequence(value)
        | Asn1TypeValue::Other(value)
        | Asn1TypeValue::Unknown { value, .. } => value.is_some(),
    }
}

/// Wraps: GENERAL_NAME_dup
/// Deep-copies a complete general-name choice into an independent owner.
#[must_use]
#[allow(non_snake_case)]
pub fn GENERAL_NAME_dup(value: GeneralNameRef<'_>) -> Option<CBox<GeneralName>> {
    // SAFETY: the shared source remains live for the synchronous deep copy. A
    // non-null result is fresh and carries one `GENERAL_NAME_free` obligation.
    unsafe { CBox::from_raw(ffi::GENERAL_NAME_dup(value.as_ptr())) }
}

/// Wraps: GENERAL_NAME_free
/// Consumes an optional complete general-name owner.
#[allow(non_snake_case)]
pub fn GENERAL_NAME_free(value: Option<CBox<GeneralName>>) {
    drop(value);
}

/// Wraps: GENERAL_NAME_get0_otherName
/// Borrows the nullable object identifier and value of an active OTHERNAME.
#[must_use]
#[allow(non_snake_case)]
pub fn GENERAL_NAME_get0_otherName<'a>(
    value: GeneralNameRef<'a>,
) -> Option<(Option<Asn1ObjectRef<'a>>, Option<Asn1TypeRef<'a>>)> {
    if !matches!(value.value(), GeneralNameValueRef::OtherName(Some(_))) {
        return None;
    }
    let mut object = ptr::null_mut();
    let mut tagged_value = ptr::null_mut();
    // SAFETY: the checked discriminator selects a non-null OTHERNAME. Both
    // locals are valid pointer output slots, and returned children remain
    // retained by `value` for `'a`.
    let success =
        unsafe { ffi::GENERAL_NAME_get0_otherName(value.as_ptr(), &mut object, &mut tagged_value) };
    if success == 0 {
        return None;
    }
    // SAFETY: success writes null or live children borrowed from `value`; the
    // handle constructors bind both optional borrows to its `'a`.
    Some(unsafe {
        (
            Asn1ObjectRef::from_ptr(object),
            Asn1TypeRef::from_ptr(tagged_value),
        )
    })
}

/// Wraps: GENERAL_NAME_get0_value
/// Returns a tagged shared borrow of the active choice member.
#[must_use]
#[allow(non_snake_case)]
pub fn GENERAL_NAME_get0_value<'a>(value: GeneralNameRef<'a>) -> GeneralNameValueRef<'a> {
    let mut kind = -1;
    // SAFETY: `value` is a live shared choice and `kind` is a valid scalar
    // output slot. The returned pointer remains retained by `value` for `'a`.
    let raw = unsafe { ffi::GENERAL_NAME_get0_value(value.as_ptr(), &mut kind) };
    // SAFETY: the discriminator returned with `raw` selects the stated
    // pointer type; each optional handle is bounded by `value`'s `'a`.
    unsafe {
        match GeneralNameType::try_from(kind) {
            Ok(GeneralNameType::OtherName) => {
                GeneralNameValueRef::OtherName(OtherNameRef::from_ptr(raw.cast()))
            }
            Ok(GeneralNameType::Email) => {
                GeneralNameValueRef::Email(Asn1StringRef::from_ptr(raw.cast()))
            }
            Ok(GeneralNameType::Dns) => {
                GeneralNameValueRef::Dns(Asn1StringRef::from_ptr(raw.cast()))
            }
            Ok(GeneralNameType::X400Address) => {
                GeneralNameValueRef::X400Address(Asn1StringRef::from_ptr(raw.cast()))
            }
            Ok(GeneralNameType::DirectoryName) => {
                GeneralNameValueRef::DirectoryName(X509NameRef::from_ptr(raw.cast()))
            }
            Ok(GeneralNameType::EdiPartyName) => {
                GeneralNameValueRef::EdiPartyName(EdiPartyNameRef::from_ptr(raw.cast()))
            }
            Ok(GeneralNameType::Uri) => {
                GeneralNameValueRef::Uri(Asn1StringRef::from_ptr(raw.cast()))
            }
            Ok(GeneralNameType::IpAddress) => {
                GeneralNameValueRef::IpAddress(Asn1StringRef::from_ptr(raw.cast()))
            }
            Ok(GeneralNameType::RegisteredId) => {
                GeneralNameValueRef::RegisteredId(Asn1ObjectRef::from_ptr(raw.cast()))
            }
            Err(-1) => GeneralNameValueRef::Empty,
            Err(kind) => GeneralNameValueRef::Unknown(kind),
        }
    }
}

/// Wraps: GENERAL_NAME_new
/// Allocates an empty, fully initialized general-name choice.
#[must_use]
#[allow(non_snake_case)]
pub fn GENERAL_NAME_new() -> Option<CBox<GeneralName>> {
    // SAFETY: a non-null result is a fresh complete choice carrying one
    // matching `GENERAL_NAME_free` obligation.
    unsafe { CBox::from_raw(ffi::GENERAL_NAME_new()) }
}

#[cfg(test)]
mod general_name_tests {
    use super::*;
    use crate::asn1::asn1_lib::{ASN1_STRING_set1_data, ASN1_STRING_type_new};
    use crate::x509::x509v3::{GeneralNameValue, GeneralNameValueMut, OtherName};

    #[test]
    fn constructor_duplicate_comparison_and_free_preserve_ownership() {
        let fresh = GENERAL_NAME_new().expect("GENERAL_NAME_new");
        assert!(matches!(
            GENERAL_NAME_get0_value(fresh.as_ref()),
            GeneralNameValueRef::Empty
        ));
        assert_eq!(
            GENERAL_NAME_cmp(Some(fresh.as_ref()), Some(fresh.as_ref())),
            Ordering::Less
        );
        GENERAL_NAME_free(Some(fresh));
        GENERAL_NAME_free(None);

        let mut string =
            ASN1_STRING_type_new(ffi::V_ASN1_IA5STRING as i32).expect("IA5 string allocation");
        assert!(ASN1_STRING_set1_data(&mut string.as_mut(), b"name@example"));
        let name = match GeneralName::from_value(GeneralNameValue::Email(Some(string))) {
            Ok(name) => name,
            Err(_) => panic!("GENERAL_NAME_new failed"),
        };
        let duplicate = GENERAL_NAME_dup(name.as_ref()).expect("GENERAL_NAME_dup");
        assert_ne!(name.as_ptr(), duplicate.as_ptr());
        assert!(matches!(
            GENERAL_NAME_get0_value(name.as_ref()),
            GeneralNameValueRef::Email(Some(_))
        ));
        assert!(matches!(
            GENERAL_NAME_get0_value(duplicate.as_ref()),
            GeneralNameValueRef::Email(Some(_))
        ));
        assert_eq!(name.as_ref().kind(), duplicate.as_ref().kind());
        assert_eq!(
            GENERAL_NAME_cmp(Some(name.as_ref()), Some(name.as_ref())),
            Ordering::Equal
        );
        assert_eq!(
            GENERAL_NAME_cmp(Some(name.as_ref()), Some(duplicate.as_ref())),
            Ordering::Equal
        );
        assert_eq!(GENERAL_NAME_cmp(None, Some(name.as_ref())), Ordering::Less);
        GENERAL_NAME_free(Some(name));
        GENERAL_NAME_free(Some(duplicate));
    }

    #[test]
    fn an_other_name_holding_an_unset_value_is_not_compared() {
        // `OTHERNAME_new` leaves `type_id` and `value` both non-null, but the
        // value is a fresh `ASN1_TYPE` whose tag is `V_ASN1_UNDEF` and whose
        // union is null. `ASN1_TYPE_cmp` would route that tag to its
        // `default:` arm and hand the null to `ASN1_STRING_cmp`, which
        // dereferences it. The guard has to reject it before the call.
        let build = || {
            let other = OtherName::new().expect("OTHERNAME_new");
            assert!(other.as_ref().type_id().is_some());
            assert!(other.as_ref().value().is_some());
            match GeneralName::from_value(GeneralNameValue::OtherName(Some(other))) {
                Ok(name) => name,
                Err(_) => panic!("GENERAL_NAME_new failed"),
            }
        };
        let first = build();
        let second = build();
        assert_eq!(
            GENERAL_NAME_cmp(Some(first.as_ref()), Some(second.as_ref())),
            Ordering::Less
        );
        // The same choice against itself takes the same path: the C function
        // has no pointer-identity shortcut.
        assert_eq!(
            GENERAL_NAME_cmp(Some(first.as_ref()), Some(first.as_ref())),
            Ordering::Less
        );

        // Giving the value a tag the comparator can read makes the pair
        // comparable again, so the guard is not simply refusing every
        // `OTHERNAME`.
        let mut third = build();
        let mut fourth = build();
        for name in [&mut third, &mut fourth] {
            let mut choice = name.as_mut();
            let GeneralNameValueMut::OtherName(Some(mut other)) = choice.value_mut() else {
                panic!("OTHERNAME arm");
            };
            other.value_mut().expect("tagged value").set_null();
        }
        assert_eq!(
            GENERAL_NAME_cmp(Some(third.as_ref()), Some(fourth.as_ref())),
            Ordering::Equal
        );
    }

    #[test]
    fn other_name_outputs_are_borrowed_from_the_parent() {
        let other_name = OtherName::new().expect("OTHERNAME_new");
        let expected_object = other_name.as_ref().type_id().map(|value| value.as_ptr());
        let expected_value = other_name.as_ref().value().map(|value| value.as_ptr());
        let name = match GeneralName::from_value(GeneralNameValue::OtherName(Some(other_name))) {
            Ok(name) => name,
            Err(_) => panic!("GENERAL_NAME_new failed"),
        };

        let (object, value) = GENERAL_NAME_get0_otherName(name.as_ref()).expect("OTHERNAME arm");
        assert_eq!(object.map(|value| value.as_ptr()), expected_object);
        assert_eq!(value.map(|value| value.as_ptr()), expected_value);
        assert!(matches!(
            GENERAL_NAME_get0_value(name.as_ref()),
            GeneralNameValueRef::OtherName(Some(_))
        ));
        GENERAL_NAME_free(Some(name));
    }
}
