//! Wrappers assigned from `crypto/bio/bss_dgram_pair.c`.

use core::ptr;

use ffibox::CBox;
use libcrypto_sys as ffi;

use super::bio_bio_local::Bio;

/// Wraps: BIO_new_bio_dgram_pair
/// Creates two owned endpoints of an in-memory datagram BIO pair.
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_new_bio_dgram_pair(
    first_buffer_size: usize,
    second_buffer_size: usize,
) -> Option<(CBox<Bio>, CBox<Bio>)> {
    let mut first = ptr::null_mut();
    let mut second = ptr::null_mut();
    // SAFETY: both output slots are live; success transfers two fresh BIOs.
    let ok = unsafe {
        ffi::BIO_new_bio_dgram_pair(
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
