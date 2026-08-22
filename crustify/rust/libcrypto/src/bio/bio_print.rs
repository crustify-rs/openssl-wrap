//! Wrappers assigned from `crypto/bio/bio_print.c`.

use core::ffi::CStr;
use core::ptr::NonNull;

use libcrypto_sys as ffi;

use super::bio_bio_local::BioMut;

/// Wraps: BIO_printf
/// Safely prints one C string as data rather than interpreting it as a format.
#[allow(non_snake_case)]
pub fn BIO_printf(bio: &mut BioMut<'_>, text: &CStr) -> i32 {
    // SAFETY: `bio` is exclusive, the format is fixed, and `text` supplies the
    // sole matching string argument.
    unsafe { ffi::BIO_printf(bio.as_mut_ptr(), c"%s".as_ptr(), text.as_ptr()) }
}

/// Wraps: BIO_snprintf
/// Safely formats one C string as data into `output`.
#[allow(non_snake_case)]
pub fn BIO_snprintf(output: &mut [u8], text: &CStr) -> i32 {
    // SAFETY: `output` supplies its declared writable length, the format is
    // fixed, and `text` supplies the sole matching string argument.
    unsafe {
        ffi::BIO_snprintf(
            output.as_mut_ptr().cast(),
            output.len(),
            c"%s".as_ptr(),
            text.as_ptr(),
        )
    }
}

/// Wraps: BIO_vprintf
///
/// # Safety
/// `arguments` must point to a live platform `va_list` whose promoted argument
/// types exactly match `format`. The list must be valid for the duration of the
/// call and may be advanced according to the platform ABI.
#[allow(non_snake_case)]
pub unsafe fn BIO_vprintf(
    bio: &mut BioMut<'_>,
    format: &CStr,
    arguments: NonNull<ffi::__va_list_tag>,
) -> i32 {
    // SAFETY: `bio` and `format` are live; the caller upholds the untypeable
    // platform `va_list` contract.
    unsafe { ffi::BIO_vprintf(bio.as_mut_ptr(), format.as_ptr(), arguments.as_ptr()) }
}

/// Wraps: BIO_vsnprintf
///
/// # Safety
/// `arguments` must point to a live platform `va_list` whose promoted argument
/// types exactly match `format`. The list must be valid for the duration of the
/// call and may be advanced according to the platform ABI.
#[allow(non_snake_case)]
pub unsafe fn BIO_vsnprintf(
    output: &mut [u8],
    format: &CStr,
    arguments: NonNull<ffi::__va_list_tag>,
) -> i32 {
    // SAFETY: `output` and `format` are live; the caller upholds the untypeable
    // platform `va_list` contract.
    unsafe {
        ffi::BIO_vsnprintf(
            output.as_mut_ptr().cast(),
            output.len(),
            format.as_ptr(),
            arguments.as_ptr(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snprintf_treats_percent_characters_as_data() {
        let mut output = [0_u8; 16];
        assert_eq!(BIO_snprintf(&mut output, c"100% ready"), 10);
        assert_eq!(&output[..11], b"100% ready\0");
    }
}
