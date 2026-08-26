//! Wrappers assigned from `crypto/rand/rand_lib.c`.

#![allow(non_snake_case)]

use libcrypto_sys as ffi;

/// Wraps: RAND_add
/// Mixes `buffer` into the default random generator with the given entropy estimate.
#[must_use]
pub fn RAND_add(buffer: &[u8], randomness: f64) -> bool {
    let Ok(length) = i32::try_from(buffer.len()) else {
        return false;
    };
    // SAFETY: `buffer` supplies exactly `length` readable bytes and OpenSSL
    // consumes them synchronously without retaining the pointer.
    unsafe { ffi::RAND_add(buffer.as_ptr().cast(), length, randomness) }
    true
}

/// Wraps: RAND_bytes
/// Fills `output` from the public random generator.
pub fn RAND_bytes(output: &mut [u8]) -> i32 {
    let Ok(length) = i32::try_from(output.len()) else {
        return -1;
    };
    // SAFETY: `output` supplies exactly `length` writable bytes for the
    // synchronous generation call and is exclusively borrowed.
    unsafe { ffi::RAND_bytes(output.as_mut_ptr(), length) }
}

/// Wraps: RAND_keep_random_devices_open
pub fn RAND_keep_random_devices_open(keep_open: bool) {
    // SAFETY: this function has no pointer or caller-side memory obligations.
    unsafe { ffi::RAND_keep_random_devices_open(i32::from(keep_open)) }
}

/// Wraps: RAND_poll
#[must_use]
pub fn RAND_poll() -> bool {
    // SAFETY: this function has no pointer or caller-side memory obligations.
    unsafe { ffi::RAND_poll() == 1 }
}

/// Wraps: RAND_priv_bytes
/// Fills `output` from the private random generator.
pub fn RAND_priv_bytes(output: &mut [u8]) -> i32 {
    let Ok(length) = i32::try_from(output.len()) else {
        return -1;
    };
    // SAFETY: `output` supplies exactly `length` writable bytes for the
    // synchronous generation call and is exclusively borrowed.
    unsafe { ffi::RAND_priv_bytes(output.as_mut_ptr(), length) }
}

/// Wraps: RAND_seed
/// Mixes `buffer` into the default random generator as seed material.
#[must_use]
pub fn RAND_seed(buffer: &[u8]) -> bool {
    let Ok(length) = i32::try_from(buffer.len()) else {
        return false;
    };
    // SAFETY: `buffer` supplies exactly `length` readable bytes and OpenSSL
    // consumes them synchronously without retaining the pointer.
    unsafe { ffi::RAND_seed(buffer.as_ptr().cast(), length) }
    true
}

/// Wraps: RAND_status
#[must_use]
pub fn RAND_status() -> bool {
    // SAFETY: this function has no pointer or caller-side memory obligations.
    unsafe { ffi::RAND_status() == 1 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_poll_and_generate_use_bounded_slices() {
        assert!(RAND_seed(b"crustify seed material"));
        assert!(RAND_add(b"additional input", 0.0));
        assert!(RAND_poll());
        assert!(RAND_status());

        let mut public = [0; 32];
        let mut private = [0; 32];
        assert_eq!(RAND_bytes(&mut public), 1);
        assert_eq!(RAND_priv_bytes(&mut private), 1);
    }
}
