//! Wrappers assigned from `crypto/bio/bss_bio.c`.

use libcrypto_sys as ffi;

use super::bio_bio_local::BioMut;

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
}
