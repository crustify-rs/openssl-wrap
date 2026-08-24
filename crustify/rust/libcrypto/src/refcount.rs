//! Owners for OpenSSL's reference-counted objects.
//!
//! A `*_up_ref` does not produce an independent object: the count rises and
//! every owner still names the same allocation. That makes such an owner a
//! *share*, and a share must not grant exclusive access — see [`SharedRef`].

use core::ffi::c_void;
use core::marker::PhantomData;

use ffibox::{CBox, CCell, CDropped, CType};

/// One owned reference to a reference-counted C object, granting shared access
/// only.
///
/// [`ffibox::CBox`] is the owner of a *sole* allocation: its
/// [`as_mut`](ffibox::CBox::as_mut) hands out the exclusive handle, which
/// asserts that nothing else can reach the object. A reference count cannot
/// support that assertion. Several owners of one refcounted object are live at
/// once by construction — that is what the count is for — and an extra count
/// is typically raised from a *shared* borrow, so an owner that offered
/// `as_mut` would let safe code mutate storage that a live borrow taken
/// through the first handle still points into. This owner therefore exposes
/// [`as_ref`](Self::as_ref) and nothing else.
///
/// The borrow parameter carries whatever the object itself borrows — a method
/// table, a library context, a Rust buffer — exactly as the corresponding
/// `Borrowed*` owner does, so an extra count cannot outlive the BIO's method
/// table or the certificate's `OSSL_LIB_CTX`.
///
/// For an owner that *can* be mutated, take an independent copy instead: the
/// deep-duplication wrappers (`X509_dup`, `X509Ref::try_dup`,
/// `EvpPkeyRef::try_dup`) return a normal [`ffibox::CBox`], because the copy
/// really is a sole allocation.
///
/// # Why there is no `as_mut`
///
/// A share is reachable from a *shared* borrow, so if it offered an exclusive
/// handle a caller could hold a byte view through one handle and free the
/// storage under it through the other:
///
/// ```compile_fail
/// use libcrypto::x509::x509_set::X509_up_ref;
/// use libcrypto::x509::x_x509::X509_new;
///
/// let certificate = X509_new().expect("certificate");
/// let mut shared = X509_up_ref(certificate.as_ref()).expect("up-ref");
/// // A share exposes `as_ref` and nothing else, so this does not compile.
/// let _exclusive = shared.as_mut();
/// ```
///
/// The same reasoning removes `Clone` from the owner: `CBox::try_clone` takes
/// `&self`, so a `CCloned` impl backed by an `up_ref` would be that same door.
///
/// ```compile_fail
/// use libcrypto::x509::x_x509::X509_new;
///
/// let certificate = X509_new().expect("certificate");
/// // `X509` registers no `CCloned`, so `CBox<X509>` has no `try_clone`.
/// let _second = certificate.try_clone().expect("second owner");
/// ```
///
/// Reading through a share, alongside a live borrow taken from the original
/// owner, is exactly what stays allowed:
///
/// ```
/// use libcrypto::asn1::asn1_lib::{ASN1_STRING_get0_data, ASN1_STRING_set1_data};
/// use libcrypto::x509::x509_cmp::{X509_get0_serialNumber, X509_get_serialNumber};
/// use libcrypto::x509::x509_set::X509_up_ref;
/// use libcrypto::x509::x_x509::X509_new;
///
/// let mut certificate = X509_new().expect("certificate");
/// {
///     let mut exclusive = certificate.as_mut();
///     let mut serial = X509_get_serialNumber(&mut exclusive);
///     assert!(ASN1_STRING_set1_data(&mut serial, &[1, 2, 3, 4]));
/// }
///
/// let serial = X509_get0_serialNumber(certificate.as_ref());
/// let bytes = ASN1_STRING_get0_data(serial).expect("serial bytes");
/// let shared = X509_up_ref(certificate.as_ref()).expect("up-ref");
/// assert_eq!(shared.as_ref().as_ptr(), certificate.as_ptr().cast_const());
/// drop(shared);
/// assert_eq!(bytes.elems().collect::<Vec<u8>>(), vec![1, 2, 3, 4]);
/// ```
#[must_use = "dropping the owner releases its reference"]
pub struct SharedRef<'a, T: CCell + CDropped> {
    inner: CBox<T>,
    borrow: PhantomData<&'a CType<c_void>>,
}

impl<T: CCell + CDropped> SharedRef<'_, T> {
    /// Adopt one raised reference count.
    ///
    /// # Safety
    ///
    /// The caller must transfer exactly one reference to the live object,
    /// obtained from a successful `*_up_ref` or from a getter documented to
    /// return a new count, and the object must not outlive the borrow `'a`
    /// names.
    pub(crate) unsafe fn from_raw(raw: *mut T::C) -> Option<Self> {
        // SAFETY: the caller transfers one reference, which this owner settles
        // through `T::c_drop` — the type's registered down-reference.
        unsafe { CBox::from_raw(raw) }.map(|inner| Self {
            inner,
            borrow: PhantomData,
        })
    }

    /// Borrow the object without write access.
    #[must_use]
    pub fn as_ref(&self) -> T::Ref<'_> {
        self.inner.as_ref()
    }

    /// Raw pointer for an explicit lower-level FFI seam. Ownership is retained.
    #[must_use]
    pub fn as_ptr(&self) -> *mut T::C {
        self.inner.as_ptr()
    }
}
