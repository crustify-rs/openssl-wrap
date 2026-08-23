//! Wrappers assigned from `crypto/bio/bss_bio.c`.

use core::ptr::{self, NonNull};

use ffibox::{CBox, CSlice, CSliceMut};
use libcrypto_sys as ffi;

use super::bio_bio_local::{Bio, BioMut};
use super::internal_bio::{BioMethodRef, static_bio_method};

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

/// # Safety
///
/// The readable region belongs to the peer endpoint, not to `bio`: see
/// [`BIO_nread0`]. The caller keeps that peer alive for `'a`.
unsafe fn shared_region<'a>(
    bio: &'a mut BioMut<'_>,
    amount: Option<i32>,
) -> Result<CSlice<'a, u8>, i32> {
    let mut ptr = core::ptr::null_mut();
    // SAFETY: `bio` is exclusive and `ptr` is a live output slot. The selected
    // pair-BIO routine returns the region length and pointer together.
    let result = unsafe {
        match amount {
            None => ffi::BIO_nread0(bio.as_mut_ptr(), &mut ptr),
            Some(n) => ffi::BIO_nread(bio.as_mut_ptr(), &mut ptr, n),
        }
    };
    if result < 0 {
        return Err(result);
    }
    // A zero-length result leaves the output slot untouched, so the pointer is
    // only meaningful when `result > 0`.
    let ptr = NonNull::new(ptr.cast::<u8>()).unwrap_or_else(NonNull::dangling);
    // SAFETY: OpenSSL returned `result` initialized bytes inside the peer's
    // write buffer, which the caller keeps alive for `'a`; `CSlice` forms no
    // reference over C-owned storage, so a concurrent C write is not aliasing.
    Ok(unsafe { CSlice::from_raw_parts(ptr, result as usize) })
}

/// Unlike [`shared_region`], the writable region is `bio`'s own buffer, which
/// the exclusive borrow already keeps alive, so this helper needs no extra
/// caller obligation.
fn exclusive_region<'a>(
    bio: &'a mut BioMut<'_>,
    amount: Option<i32>,
) -> Result<CSliceMut<'a, u8>, i32> {
    let mut ptr = core::ptr::null_mut();
    // SAFETY: `bio` is exclusive and `ptr` is a live output slot. The selected
    // pair-BIO routine returns the writable region length and pointer together.
    let result = if let Some(amount) = amount {
        // SAFETY: `bio` is exclusive and `ptr` is a live output slot.
        unsafe { ffi::BIO_nwrite(bio.as_mut_ptr(), &mut ptr, amount) }
    } else {
        // SAFETY: `bio` is exclusive and `ptr` is a live output slot.
        unsafe { ffi::BIO_nwrite0(bio.as_mut_ptr(), &mut ptr) }
    };
    if result < 0 {
        return Err(result);
    }
    // A zero-length result leaves the output slot untouched, so the pointer is
    // only meaningful when `result > 0`.
    let ptr = NonNull::new(ptr.cast::<u8>()).unwrap_or_else(NonNull::dangling);
    // SAFETY: OpenSSL returned `result` writable bytes inside `bio`'s own ring
    // buffer, which the exclusive borrow keeps alive for `'a`; the move-only
    // handle forms no Rust slice reference.
    Ok(unsafe { CSliceMut::from_raw_parts(ptr, result as usize) })
}

/// Wraps: BIO_nread
///
/// Reports at most `amount` readable bytes and advances the read index past
/// them. Negative amounts are clamped to zero, since C reinterprets the count
/// as a `size_t`.
///
/// # Safety
///
/// As [`BIO_nread0`]: the returned region is storage owned by the peer
/// endpoint, so the peer must outlive it.
#[allow(non_snake_case)]
pub unsafe fn BIO_nread<'a>(bio: &'a mut BioMut<'_>, amount: i32) -> Result<CSlice<'a, u8>, i32> {
    // SAFETY: forwarded verbatim to this function's own caller obligation.
    unsafe { shared_region(bio, Some(amount.max(0))) }
}

/// Wraps: BIO_nread0
///
/// Reports the readable region without consuming it.
///
/// # Safety
///
/// `bss_bio.c` reads through `bio->ptr->peer`: the region handed back is a
/// window into the *peer* endpoint's ring buffer, and `bio_free` on that peer
/// releases the buffer while leaving `bio` itself perfectly valid. The
/// exclusive borrow of `bio` therefore cannot keep the region alive, and no
/// safe signature can name the peer, which is not an argument. The caller must
/// keep the peer endpoint alive for as long as the returned handle is used.
///
/// The region is also invalidated in place by any later operation on either
/// endpoint, which reuses the same ring buffer. That is a correctness rule
/// rather than a soundness one: [`CSlice`] holds a raw pointer and forms no
/// Rust reference, so a concurrent C write is not aliasing UB.
#[allow(non_snake_case)]
pub unsafe fn BIO_nread0<'a>(bio: &'a mut BioMut<'_>) -> Result<CSlice<'a, u8>, i32> {
    // SAFETY: forwarded verbatim to this function's own caller obligation.
    unsafe { shared_region(bio, None) }
}

/// Wraps: BIO_nwrite
///
/// Reserves at most `amount` writable bytes and advances the write index past
/// them. Negative amounts are clamped to zero, since C reinterprets the count
/// as a `size_t`.
///
/// The region is `bio`'s own ring buffer, so unlike [`BIO_nread`] the
/// exclusive borrow already keeps it alive and this is a safe operation.
#[allow(non_snake_case)]
pub fn BIO_nwrite<'a>(bio: &'a mut BioMut<'_>, amount: i32) -> Result<CSliceMut<'a, u8>, i32> {
    exclusive_region(bio, Some(amount.max(0)))
}

/// Wraps: BIO_nwrite0
///
/// Reports the writable region without reserving it. As [`BIO_nwrite`], the
/// region is `bio`'s own buffer and the borrow is enough to keep it alive.
#[allow(non_snake_case)]
pub fn BIO_nwrite0<'a>(bio: &'a mut BioMut<'_>) -> Result<CSliceMut<'a, u8>, i32> {
    exclusive_region(bio, None)
}

/// Wraps: BIO_s_bio
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_s_bio() -> Option<BioMethodRef<'static>> {
    // SAFETY: the selector has no caller-side memory obligations and returns
    // null or the address of a `static const` table, which is the
    // process-lifetime borrow `static_bio_method` requires.
    unsafe { static_bio_method(ffi::BIO_s_bio()) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bio::bio_lib::{BIO_read, BIO_write};

    /// Both halves of a pair with a small, explicitly sized ring buffer, so the
    /// write guarantee is a number the test can predict.
    const BUFFER: usize = 128;

    #[test]
    fn pair_controls_track_the_ring_buffer_and_the_peer_read_request() {
        let (mut first, mut second) = BIO_new_bio_pair(BUFFER, BUFFER).expect("BIO pair");

        assert_eq!(BIO_ctrl_get_write_guarantee(&mut first.as_mut()), BUFFER);
        assert_eq!(BIO_ctrl_get_read_request(&mut first.as_mut()), 0);

        // A read on the empty pipe fails and records the size the reader
        // wanted on the half that would have to supply it.
        let mut buffer = [0_u8; 32];
        assert!(BIO_read(&mut second.as_mut(), &mut buffer) < 0);
        assert_eq!(BIO_ctrl_get_read_request(&mut first.as_mut()), buffer.len());

        // Resetting clears the recorded request without moving any data.
        assert!(BIO_ctrl_reset_read_request(&mut first.as_mut()));
        assert_eq!(BIO_ctrl_get_read_request(&mut first.as_mut()), 0);
        assert_eq!(BIO_ctrl_get_write_guarantee(&mut first.as_mut()), BUFFER);

        // Buffered bytes come out of the writer's guarantee and go back into it
        // once the peer has taken them.
        assert_eq!(BIO_write(&mut first.as_mut(), b"hello"), 5);
        assert_eq!(
            BIO_ctrl_get_write_guarantee(&mut first.as_mut()),
            BUFFER - 5
        );
        assert_eq!(BIO_read(&mut second.as_mut(), &mut buffer), 5);
        assert_eq!(&buffer[..5], b"hello");
        assert_eq!(BIO_ctrl_get_write_guarantee(&mut first.as_mut()), BUFFER);
    }

    #[test]
    fn pair_returns_two_independent_owners() {
        let (first, second) = BIO_new_bio_pair(0, 0).expect("BIO pair");
        assert_ne!(first.as_ptr(), second.as_ptr());
    }

    #[test]
    fn the_non_copying_interface_moves_bytes_between_the_endpoints() {
        let (mut writer, mut reader) = BIO_new_bio_pair(32, 32).expect("BIO pair");

        {
            let mut view = writer.as_mut();
            // The reservation is inside `writer`'s own ring buffer.
            assert_eq!(BIO_nwrite0(&mut view).expect("write region").len(), 32);
            let mut region = BIO_nwrite(&mut view, 5).expect("write region");
            assert_eq!(region.len(), 5);
            assert!(region.copy_from_slice(b"hello"));
        }

        let mut view = reader.as_mut();
        // SAFETY: `writer` owns the storage behind both regions below and
        // outlives them; nothing writes to the pair in between.
        let peeked = unsafe { BIO_nread0(&mut view) }.expect("peek region");
        assert_eq!(peeked.len(), 5);
        drop(peeked);

        // SAFETY: as above.
        let region = unsafe { BIO_nread(&mut view, 5) }.expect("read region");
        let mut seen = [0_u8; 5];
        assert!(region.copy_to_slice(&mut seen));
        assert_eq!(&seen, b"hello");
    }

    #[test]
    fn a_reservation_is_limited_by_the_configured_buffer() {
        let (mut writer, _reader) = BIO_new_bio_pair(8, 8).expect("BIO pair");
        let mut view = writer.as_mut();
        // `bio_nwrite0` never wraps the ring, so the request is clamped to the
        // contiguous space rather than satisfied in full.
        assert_eq!(BIO_nwrite(&mut view, 64).expect("write region").len(), 8);
        // A negative request is clamped to zero instead of becoming a huge
        // `size_t`, and the buffer is full anyway.
        assert!(BIO_nwrite(&mut view, -1).is_err());
    }
}
