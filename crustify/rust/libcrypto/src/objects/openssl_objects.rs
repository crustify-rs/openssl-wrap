//! Wrappers assigned from `include/openssl/objects.h`.

use core::ffi::CStr;
use core::ptr::{addr_of, addr_of_mut};

use ffibox::define_ctype;
use libcrypto_sys as ffi;

define_ctype!(
    /// Wraps: obj_name_st
    ObjName,
    ObjNameRef,
    ObjNameMut,
    ffi::obj_name_st
);

impl<'a> ObjNameRef<'a> {
    /// Wraps: obj_name_st.type
    #[must_use]
    pub fn r#type(&self) -> i32 {
        // SAFETY: `self` carries a live shared borrow and raw-place projection
        // reads the initialized integer without forming a reference to C memory.
        unsafe { addr_of!((*self.as_ptr()).type_).read() }
    }

    /// Wraps: obj_name_st.data
    #[must_use]
    pub fn data(&self) -> Option<&'a CStr> {
        // SAFETY: `self` carries a live shared borrow and raw-place projection
        // reads the initialized pointer without forming a reference to C memory.
        let data = unsafe { addr_of!((*self.as_ptr()).data).read() };
        if data.is_null() {
            None
        } else {
            // SAFETY: a non-null `data` field is a borrowed NUL-terminated
            // string whose lifetime is bounded by this handle's `'a`.
            Some(unsafe { CStr::from_ptr(data) })
        }
    }

    /// Wraps: obj_name_st.name
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
    #[must_use]
    pub fn alias(&self) -> i32 {
        // SAFETY: `self` carries a live shared borrow and raw-place projection
        // reads the initialized integer without forming a reference to C memory.
        unsafe { addr_of!((*self.as_ptr()).alias).read() }
    }
}

impl ObjNameMut<'_> {
    /// Set the numeric object-name class.
    pub fn set_type(&mut self, value: i32) {
        // SAFETY: the exclusive handle permits writing this initialized scalar
        // field, and raw-place projection forms no reference to C memory.
        unsafe { addr_of_mut!((*self.as_mut_ptr()).type_).write(value) }
    }

    /// Store a caller-managed data string.
    ///
    /// # Safety
    ///
    /// `value`, when present, must remain live and unmodified for every later
    /// C or Rust access through this `OBJ_NAME`, until the field is replaced.
    pub unsafe fn set_data(&mut self, value: Option<&CStr>) {
        let value = value.map_or(core::ptr::null(), CStr::as_ptr);
        // SAFETY: the exclusive handle permits replacing this borrowed pointer;
        // the caller supplies the stored string's otherwise-unexpressible lifetime.
        unsafe { addr_of_mut!((*self.as_mut_ptr()).data).write(value) }
    }

    /// Store a caller-managed object name.
    ///
    /// # Safety
    ///
    /// `value`, when present, must remain live and unmodified for every later
    /// C or Rust access through this `OBJ_NAME`, until the field is replaced.
    pub unsafe fn set_name(&mut self, value: Option<&CStr>) {
        let value = value.map_or(core::ptr::null(), CStr::as_ptr);
        // SAFETY: the exclusive handle permits replacing this borrowed pointer;
        // the caller supplies the stored string's otherwise-unexpressible lifetime.
        unsafe { addr_of_mut!((*self.as_mut_ptr()).name).write(value) }
    }

    /// Set whether this record represents an alias.
    pub fn set_alias(&mut self, value: i32) {
        // SAFETY: the exclusive handle permits writing this initialized scalar
        // field, and raw-place projection forms no reference to C memory.
        unsafe { addr_of_mut!((*self.as_mut_ptr()).alias).write(value) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fields_round_trip_through_borrowed_handles() {
        let name = c"sha256";
        let data = c"provider-value";
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
        assert_eq!(wrapped.as_ref().data(), None);

        wrapped.set_type(7);
        wrapped.set_alias(0x8000);
        // SAFETY: `data` outlives `raw` and is immutable for all later access.
        unsafe { wrapped.set_data(Some(data)) };

        let shared = wrapped.as_ref();
        assert_eq!(shared.r#type(), 7);
        assert_eq!(shared.alias(), 0x8000);
        assert_eq!(shared.data(), Some(data));
    }
}
