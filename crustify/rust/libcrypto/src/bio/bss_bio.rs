//! Wrappers assigned from `crypto/bio/bss_bio.c`.

use core::ptr;

use ffibox::CBox;
use libcrypto_sys as ffi;

use super::bio_bio_local::{Bio, BioMut};

/// Wraps: BIO_ctrl_get_read_request
#[allow(non_snake_case)]
pub fn BIO_ctrl_get_read_request(bio: &mut BioMut<'_>) -> usize {
    // SAFETY: the exclusive handle supplies one live BIO for the synchronous control.
    unsafe { ffi::BIO_ctrl_get_read_request(bio.as_mut_ptr()) }
}

/// Wraps: BIO_ctrl_get_write_guarantee
#[allow(non_snake_case)]
pub fn BIO_ctrl_get_write_guarantee(bio: &mut BioMut<'_>) -> usize {
    // SAFETY: the exclusive handle supplies one live BIO for the synchronous control.
    unsafe { ffi::BIO_ctrl_get_write_guarantee(bio.as_mut_ptr()) }
}

/// Wraps: BIO_ctrl_reset_read_request
#[allow(non_snake_case)]
pub fn BIO_ctrl_reset_read_request(bio: &mut BioMut<'_>) -> bool {
    // SAFETY: the exclusive handle supplies one live BIO for the synchronous control.
    unsafe { ffi::BIO_ctrl_reset_read_request(bio.as_mut_ptr()) != 0 }
}

/// Wraps: BIO_new_bio_pair
/// Creates two owned endpoints of an in-memory BIO pair.
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_new_bio_pair(
    first_buffer_size: usize,
    second_buffer_size: usize,
) -> Option<(CBox<Bio>, CBox<Bio>)> {
    let mut first = ptr::null_mut();
    let mut second = ptr::null_mut();
    // SAFETY: both output slots are live; OpenSSL writes either two fresh BIO
    // references on success or nulls on failure.
    let ok = unsafe {
        ffi::BIO_new_bio_pair(
            &mut first,
            first_buffer_size,
            &mut second,
            second_buffer_size,
        )
    };
    if ok != 1 {
        return None;
    }
    // SAFETY: success transfers one independently owned reference in each slot.
    let first = unsafe { CBox::from_raw(first) }?;
    // SAFETY: as above for the second output; `first` cleans up on anomaly.
    let second = unsafe { CBox::from_raw(second) }?;
    Some((first, second))
}

#[cfg(test)]
mod tests {
    use ffibox::CBox;

    use super::super::bio_bio_local::Bio;
    use super::*;

    fn new_pair_bio() -> CBox<Bio> {
        // SAFETY: both called constructors have no caller-owned pointer inputs.
        let raw = unsafe { ffi::BIO_new(ffi::BIO_s_null()) };
        // SAFETY: a non-null result transfers one owned BIO reference.
        unsafe { CBox::from_raw(raw) }.expect("BIO_new")
    }

    #[test]
    fn pair_controls_use_exclusive_handle() {
        let mut bio = new_pair_bio();
        let mut view = bio.as_mut();
        let _ = BIO_ctrl_get_read_request(&mut view);
        let _ = BIO_ctrl_get_write_guarantee(&mut view);
        let _ = BIO_ctrl_reset_read_request(&mut view);
    }
    #[test]
    fn pair_returns_two_independent_owners() {
        let (first, second) = BIO_new_bio_pair(0, 0).expect("BIO pair");
        assert_ne!(first.as_ptr(), second.as_ptr());
    }
}
