//! Wrappers assigned from `include/internal/conf.h`.

use ffibox::{define_ctype, impl_dropped};
use libcrypto_sys as ffi;

define_ctype!(
    /// Wraps: ossl_init_settings_st
    OsslInitSettings,
    OsslInitSettingsRef,
    OsslInitSettingsMut,
    ffi::ossl_init_settings_st
);

impl_dropped!(
    OsslInitSettings,
    ffi::ossl_init_settings_st,
    ffi::OPENSSL_INIT_free
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opaque_handles_remain_pointer_sized() {
        assert_eq!(
            core::mem::size_of::<OsslInitSettingsRef<'static>>(),
            core::mem::size_of::<*mut ffi::ossl_init_settings_st>()
        );
        assert_eq!(
            core::mem::size_of::<OsslInitSettingsMut<'static>>(),
            core::mem::size_of::<*mut ffi::ossl_init_settings_st>()
        );
    }
}
