//! Wrappers assigned from `include/openssl/objects.h`.

use core::ffi::{CStr, c_char};
use core::ptr::{NonNull, addr_of, addr_of_mut};

use ffibox::define_ctype;
use libcrypto_sys as ffi;

use super::o_names::ObjNameValue;

/// `OBJ_NAME_ALIAS`, the bit `OBJ_NAME_add` copies out of its class argument
/// into [`obj_name_st::alias`](ObjNameRef::alias).
const ALIAS_FLAG: i32 = ffi::OBJ_NAME_ALIAS as i32;

define_ctype!(
    /// Wraps: obj_name_st
    ///
    /// One entry of OpenSSL's process-global object-name registry: the
    /// `LHASH_OF(OBJ_NAME)` in `crypto/objects/o_names.c`, keyed on the
    /// `(type, name)` pair.
    ///
    /// `obj_name_st` is defined in the public `include/openssl/objects.h`, so
    /// the binding carries its complete layout and this wrapper is a true
    /// layout mirror: it embeds by value in a `#[repr(C)]` struct and its
    /// fields are reached by projection through [`ObjNameRef`] and
    /// [`ObjNameMut`].
    ///
    /// # Lifecycle
    ///
    /// Entries are not independently owned, so this type binds no `CDropped`
    /// and has no `CBox` form. `OBJ_NAME_add` allocates the record with
    /// `OPENSSL_malloc` and hands it to the hash table; `OBJ_NAME_add` (on
    /// replacement), `OBJ_NAME_remove` and `OBJ_NAME_cleanup` release it with
    /// `OPENSSL_free` after invoking the class's registered `free_func` on the
    /// `name`/`data` pair. No public routine accepts or returns a record, so
    /// every handle is borrowed: from the
    /// [`OBJ_NAME_do_all`](super::o_names::OBJ_NAME_do_all) traversal, or over
    /// a caller's own storage — the pattern `OBJ_NAME_get` and
    /// `OBJ_NAME_remove` use for their lookup keys.
    ///
    /// # Invariants
    ///
    /// `alias` discriminates `data`, and the safety of
    /// [`ObjNameRef::data`] depends on it: a non-zero `alias` means `data` is
    /// the NUL-terminated name of another entry, and a zero `alias` means it
    /// is the class's registered payload, an erased pointer that is not a
    /// string. Both spellings are produced by `OBJ_NAME_add` and consumed by
    /// `OBJ_NAME_get` and `EVP_CIPHER_do_all`/`EVP_MD_do_all`. The setter that
    /// writes `data` writes `alias` with it for exactly this reason.
    ///
    /// `type` and `name` are the hash key. Rewriting either on a record that
    /// is installed in the registry leaves it mis-bucketed and unreachable,
    /// which is why both setters are documented against installed entries.
    ObjName,
    ObjNameRef,
    ObjNameMut,
    ffi::obj_name_st
);

/// The two meanings of an entry's `data` slot, discriminated by `alias`.
///
/// C spells both as `const char *`. They are not interchangeable: only the
/// alias arm is a string.
pub enum ObjNameData<'a> {
    /// `alias` is non-zero: `data` is the borrowed NUL-terminated name of
    /// another entry of the same class, which `OBJ_NAME_get` follows as its
    /// next lookup key.
    Alias(&'a CStr),
    /// `alias` is zero: `data` is the payload registered for this name, an
    /// erased pointer whose concrete type is fixed by the entry's class —
    /// `const EVP_CIPHER *` for `OBJ_NAME_TYPE_CIPHER_METH`, `const EVP_MD *`
    /// for `OBJ_NAME_TYPE_MD_METH`, and whatever the registrar chose for a
    /// class from `OBJ_NAME_new_index`.
    Value(ObjNameValue<'a>),
}

impl<'a> ObjNameRef<'a> {
    /// Wraps: obj_name_st.type
    ///
    /// The entry's class: one of the `OBJ_NAME_TYPE_*` constants, or an index
    /// handed out by `OBJ_NAME_new_index`. Together with `name` it is the hash
    /// key, and it fixes how a non-alias [`ObjNameData::Value`] may be cast.
    #[must_use]
    pub fn r#type(&self) -> i32 {
        // SAFETY: `self` carries a live shared borrow and raw-place projection
        // reads the initialized integer without forming a reference to C memory.
        unsafe { addr_of!((*self.as_ptr()).type_).read() }
    }

    /// Wraps: obj_name_st.data
    ///
    /// Reads the payload slot under the discriminator in `alias`, so the
    /// string interpretation is applied only where C applies it. `None` is an
    /// empty slot: `OBJ_NAME_get` reports a NULL `data` as "not registered".
    #[must_use]
    pub fn data(&self) -> Option<ObjNameData<'a>> {
        // SAFETY: `self` carries a live shared borrow and raw-place projection
        // reads the initialized pointer without forming a reference to C memory.
        let data = unsafe { addr_of!((*self.as_ptr()).data).read() };
        let data = NonNull::new(data.cast_mut())?;
        if self.is_alias() {
            // SAFETY: an alias entry's `data` is the borrowed NUL-terminated
            // name of another entry — `OBJ_NAME_get` feeds it straight back in
            // as a lookup key — and its storage outlives this handle's `'a`.
            Some(ObjNameData::Alias(unsafe { CStr::from_ptr(data.as_ptr()) }))
        } else {
            Some(ObjNameData::Value(ObjNameValue::from_ptr(data.cast())))
        }
    }

    /// Wraps: obj_name_st.name
    ///
    /// The registered name, borrowed from the registrar: `OBJ_NAME_add` stores
    /// the caller's pointer without copying it.
    ///
    /// `None` is a malformed entry rather than a normal state. Every reader
    /// dereferences this field unconditionally — `obj_name_cmp` compares it
    /// with `OPENSSL_strcasecmp` and `apps/enc.c` indexes it — but no writer
    /// checks it: `EVP_add_cipher` and `EVP_add_digest` pass an unchecked
    /// `OBJ_nid2sn`/`OBJ_nid2ln` result, which is NULL for a nid outside the
    /// object table. The `Option` keeps that reachable state out of a
    /// reference.
    #[must_use]
    pub fn name(&self) -> Option<&'a CStr> {
        // SAFETY: `self` carries a live shared borrow and raw-place projection
        // reads the initialized pointer without forming a reference to C memory.
        let name = unsafe { addr_of!((*self.as_ptr()).name).read() };
        if name.is_null() {
            None
        } else {
            // SAFETY: a non-null `name` field is a borrowed NUL-terminated
            // string whose lifetime is bounded by this handle's `'a`.
            Some(unsafe { CStr::from_ptr(name) })
        }
    }

    /// Wraps: obj_name_st.alias
    ///
    /// The raw discriminator: `OBJ_NAME_ALIAS` for an alias entry and zero
    /// otherwise. Use [`is_alias`](Self::is_alias) to test it the way C does.
    #[must_use]
    pub fn alias(&self) -> i32 {
        // SAFETY: `self` carries a live shared borrow and raw-place projection
        // reads the initialized integer without forming a reference to C memory.
        unsafe { addr_of!((*self.as_ptr()).alias).read() }
    }

    /// Whether this entry aliases another name of the same class.
    ///
    /// Matches the C predicate: `do_all_cipher_fn` and `do_all_md_fn` branch on
    /// `nm->alias` being non-zero, not on it equalling `OBJ_NAME_ALIAS`.
    #[must_use]
    pub fn is_alias(&self) -> bool {
        self.alias() != 0
    }
}

impl ObjNameMut<'_> {
    /// Set the entry's class.
    ///
    /// `type` is half of the registry's hash key, and it fixes how the payload
    /// returned by [`ObjNameRef::data`] may be cast. Rewriting it on an entry
    /// that is installed in the registry leaves that entry mis-bucketed, and
    /// lets a lookup of the new class hand C a payload of the old one.
    pub fn set_type(&mut self, value: i32) {
        // SAFETY: the exclusive handle permits writing this initialized scalar
        // field, and raw-place projection forms no reference to C memory.
        unsafe { addr_of_mut!((*self.as_mut_ptr()).type_).write(value) }
    }

    /// Store the payload slot together with its `alias` discriminator.
    ///
    /// The pair is written as one operation because [`ObjNameRef::data`] reads
    /// `data` under `alias`: a separate `set_alias` would let safe code label
    /// an erased payload as a string and have the getter build a `CStr` over
    /// it. `None` clears the slot to the "not registered" state.
    ///
    /// # Safety
    ///
    /// The referent of `value`, when present, must remain live and unmodified
    /// for every later C or Rust access through this `OBJ_NAME`, until the
    /// field is replaced. For [`ObjNameData::Value`], it must additionally be
    /// of the type the entry's class prescribes, since C casts it on that
    /// basis alone.
    pub unsafe fn set_data(&mut self, value: Option<ObjNameData<'_>>) {
        let (alias, data): (i32, *const c_char) = match value {
            None => (0, core::ptr::null()),
            Some(ObjNameData::Alias(name)) => (ALIAS_FLAG, name.as_ptr()),
            Some(ObjNameData::Value(payload)) => {
                (0, payload.as_non_null().as_ptr().cast_const().cast())
            }
        };
        // SAFETY: the exclusive handle permits replacing these two initialized
        // fields; the caller supplies the stored payload's otherwise
        // unexpressible lifetime, and writing both keeps the discriminator in
        // step with the slot it describes.
        unsafe {
            addr_of_mut!((*self.as_mut_ptr()).alias).write(alias);
            addr_of_mut!((*self.as_mut_ptr()).data).write(data);
        }
    }

    /// Store a caller-managed object name.
    ///
    /// # Safety
    ///
    /// `value`, when present, must remain live and unmodified for every later
    /// C or Rust access through this `OBJ_NAME`, until the field is replaced.
    /// `name` is half of the registry's hash key, so the entry must not be
    /// installed in the registry when it is rewritten.
    pub unsafe fn set_name(&mut self, value: Option<&CStr>) {
        let value = value.map_or(core::ptr::null(), CStr::as_ptr);
        // SAFETY: the exclusive handle permits replacing this borrowed pointer;
        // the caller supplies the stored string's otherwise-unexpressible lifetime.
        unsafe { addr_of_mut!((*self.as_mut_ptr()).name).write(value) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(alias: i32, data: *const c_char) -> ffi::obj_name_st {
        ffi::obj_name_st {
            // `OBJ_NAME_TYPE_CIPHER_METH`; the class only decides how a
            // payload may be cast, never how `data` is read here.
            type_: 0x03,
            alias,
            name: c"aes-128-cbc".as_ptr(),
            data,
        }
    }

    #[test]
    fn fields_round_trip_through_borrowed_handles() {
        let name = c"sha256";
        let target = c"sha-256";
        let mut raw = ffi::obj_name_st {
            type_: 1,
            alias: 0,
            name: name.as_ptr(),
            data: core::ptr::null(),
        };

        // SAFETY: `raw` is initialized, live, and exclusively borrowed here.
        let mut wrapped = unsafe { ObjNameMut::from_ptr(&raw mut raw) }.unwrap();
        assert_eq!(wrapped.as_ref().r#type(), 1);
        assert_eq!(wrapped.as_ref().name(), Some(name));
        assert!(wrapped.as_ref().data().is_none());
        assert!(!wrapped.as_ref().is_alias());

        wrapped.set_type(7);
        // SAFETY: `target` outlives `raw` and is immutable for all later access.
        unsafe { wrapped.set_data(Some(ObjNameData::Alias(target))) };

        let shared = wrapped.as_ref();
        assert_eq!(shared.r#type(), 7);
        assert_eq!(shared.alias(), ALIAS_FLAG);
        assert!(shared.is_alias());
        assert!(matches!(shared.data(), Some(ObjNameData::Alias(t)) if t == target));
    }

    #[test]
    fn alias_entries_read_their_target_name() {
        let target = c"sha-256";
        let mut raw = record(ALIAS_FLAG, target.as_ptr());

        // SAFETY: `raw` is initialized and live for the borrow.
        let shared = unsafe { ObjNameRef::from_ptr(&raw mut raw) }.unwrap();
        let Some(ObjNameData::Alias(name)) = shared.data() else {
            panic!("an alias entry's data is its target name");
        };
        assert_eq!(name, target);
    }

    #[test]
    fn method_entries_keep_their_payload_erased() {
        // A registered payload is a method object, not a string:
        // `EVP_add_cipher` stores `(const char *)cipher`. Nothing here contains
        // a NUL byte, so any attempt to read it as a C string would run off the
        // end of this array.
        let payload = [0xffu8; 32];
        let mut raw = record(0, payload.as_ptr().cast());

        // SAFETY: `raw` is initialized and live for the borrow.
        let shared = unsafe { ObjNameRef::from_ptr(&raw mut raw) }.unwrap();
        assert!(!shared.is_alias());
        let Some(ObjNameData::Value(value)) = shared.data() else {
            panic!("a non-alias entry's data is an erased payload");
        };
        // SAFETY: the payload was stored as this byte array and outlives the
        // handle it was read through.
        let recovered = unsafe { value.cast::<u8>() };
        assert_eq!(recovered.as_ptr().cast_const(), payload.as_ptr());
    }

    #[test]
    fn clearing_the_payload_clears_its_discriminator() {
        let target = c"sha-256";
        let mut raw = record(ALIAS_FLAG, target.as_ptr());

        // SAFETY: `raw` is initialized, live, and exclusively borrowed here.
        let mut wrapped = unsafe { ObjNameMut::from_ptr(&raw mut raw) }.unwrap();
        // SAFETY: clearing the slot stores no pointer at all.
        unsafe { wrapped.set_data(None) };

        let shared = wrapped.as_ref();
        assert_eq!(shared.alias(), 0);
        assert!(!shared.is_alias());
        assert!(shared.data().is_none());
    }

    #[test]
    fn a_missing_name_stays_out_of_a_reference() {
        // `EVP_add_cipher` passes an unchecked `OBJ_nid2sn` result, so a NULL
        // name is reachable for a nid outside the object table.
        let mut raw = record(0, core::ptr::null());
        raw.name = core::ptr::null();

        // SAFETY: `raw` is initialized and live for the borrow.
        let shared = unsafe { ObjNameRef::from_ptr(&raw mut raw) }.unwrap();
        assert!(shared.name().is_none());
    }
}
