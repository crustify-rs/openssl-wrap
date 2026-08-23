//! Wrappers assigned from `crypto/bio/bio_cb.c`.

use libcrypto_sys as ffi;

use super::bio_bio_local::BioMut;

/// Wraps: BIO_debug_callback_ex
///
/// `processed` is an input: OpenSSL copies the count out of the slot and never
/// writes it back, so a shared borrow states the whole contract.
///
/// # Safety
/// `argp`, `len`, `argi`, and `operation` must describe the operation-specific
/// callback payload expected by OpenSSL; `BIO_CB_RECVMMSG` and `BIO_CB_SENDMMSG`
/// in particular read `argp` as a live `BIO_MMSG_CB_ARGS`. The BIO's callback
/// argument must be null or point to a live BIO suitable for debug output,
/// because this routine writes its line through it.
#[allow(non_snake_case)]
#[allow(clippy::too_many_arguments)]
pub unsafe fn BIO_debug_callback_ex(
    bio: &mut BioMut<'_>,
    operation: i32,
    argp: *const core::ffi::c_char,
    len: usize,
    argi: i32,
    argl: core::ffi::c_long,
    result: i32,
    processed: Option<&usize>,
) -> core::ffi::c_long {
    let processed = processed.map_or(core::ptr::null_mut(), |processed| {
        core::ptr::from_ref(processed).cast_mut()
    });
    // SAFETY: the caller establishes the operation-dependent payload contract;
    // the exclusive BIO handle and the read-only processed slot are live.
    unsafe {
        ffi::BIO_debug_callback_ex(
            bio.as_mut_ptr(),
            operation,
            argp,
            len,
            argi,
            argl,
            result,
            processed,
        )
    }
}

#[cfg(test)]
mod tests {
    use core::ptr::{self, NonNull};

    use super::*;
    use crate::bio::bio_lib::{BIO_new, BIO_read_ex, BIO_set_callback_arg};
    use crate::bio::bss_mem::BIO_s_mem;
    use crate::bio::bss_null::BIO_s_null;

    /// `<openssl/bio.h>`: the completion half of a read notification.
    const BIO_CB_READ: i32 = 0x02;
    const BIO_CB_RETURN: i32 = 0x80;

    #[test]
    fn debug_line_goes_to_the_callback_bio_and_reports_the_processed_count() {
        let mut sink = BIO_new(BIO_s_mem().expect("memory method")).expect("memory BIO");
        let sink_pointer = {
            let mut handle = sink.as_mut();
            NonNull::new(handle.as_mut_ptr()).expect("live memory BIO")
        };

        let mut subject = BIO_new(BIO_s_null().expect("null method")).expect("null BIO");
        // SAFETY: `sink` outlives every use of `subject` below, so the stored
        // cookie stays a live BIO for as long as the debug callback can run.
        unsafe { BIO_set_callback_arg(&mut subject.as_mut(), Some(sink_pointer)) };

        let processed = 7_usize;
        // SAFETY: the completion half of a read notification carries no `argp`
        // payload, and the callback argument installed above is a live BIO.
        let returned = unsafe {
            BIO_debug_callback_ex(
                &mut subject.as_mut(),
                BIO_CB_READ | BIO_CB_RETURN,
                ptr::null(),
                0,
                0,
                0,
                3,
                Some(&processed),
            )
        };
        assert_eq!(returned, 3, "the callback echoes its result unchanged");

        let mut line = [0_u8; 128];
        let written = BIO_read_ex(&mut sink.as_mut(), &mut line).expect("debug output");
        let line = core::str::from_utf8(&line[..written]).expect("ASCII debug line");
        assert!(line.contains("read return 3 processed: 7"), "{line}");
    }

    #[test]
    fn an_absent_processed_slot_reports_a_zero_count() {
        let mut sink = BIO_new(BIO_s_mem().expect("memory method")).expect("memory BIO");
        let sink_pointer = {
            let mut handle = sink.as_mut();
            NonNull::new(handle.as_mut_ptr()).expect("live memory BIO")
        };

        let mut subject = BIO_new(BIO_s_null().expect("null method")).expect("null BIO");
        // SAFETY: as above, `sink` outlives `subject`'s use.
        unsafe { BIO_set_callback_arg(&mut subject.as_mut(), Some(sink_pointer)) };

        // SAFETY: as above; a null processed slot is the documented "unknown
        // count" encoding and is never dereferenced.
        unsafe {
            BIO_debug_callback_ex(
                &mut subject.as_mut(),
                BIO_CB_READ | BIO_CB_RETURN,
                ptr::null(),
                0,
                0,
                0,
                1,
                None,
            )
        };

        let mut line = [0_u8; 128];
        let written = BIO_read_ex(&mut sink.as_mut(), &mut line).expect("debug output");
        let line = core::str::from_utf8(&line[..written]).expect("ASCII debug line");
        assert!(line.contains("read return 1 processed: 0"), "{line}");
    }
}
