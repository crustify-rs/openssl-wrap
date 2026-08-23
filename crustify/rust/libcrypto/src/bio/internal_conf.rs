//! Wrappers assigned from `include/internal/conf.h`.

use ffibox::{define_ctype, impl_dropped};
use libcrypto_sys as ffi;

define_ctype!(
    /// Wraps: ossl_init_settings_st
    ///
    /// The configuration settings handed to `OPENSSL_init_crypto`, reached
    /// only through owning pointers and borrowed handles.
    ///
    /// `ossl_init_settings_st` is defined in `include/internal/conf.h`, which
    /// the bindgen input does not include: the public headers publish the
    /// typedef alone (`include/openssl/types.h`), and the type is additionally
    /// listed as an opaque bindgen type. `ffi::ossl_init_settings_st` is
    /// therefore the incomplete type the public API publishes, which makes
    /// `OsslInitSettings` a zero-sized, align-1 opaque pointee rather than a
    /// layout mirror. It must not be embedded by value in a `#[repr(C)]`
    /// struct, and [`OsslInitSettings::zeroed`] yields no usable settings
    /// object; only the pointer identity carried by `CBox<OsslInitSettings>`,
    /// [`OsslInitSettingsRef`] and [`OsslInitSettingsMut`] is meaningful.
    ///
    /// That matches the wrapped surface rather than leaving a gap. The three
    /// recorded fields — `filename`, `appname` and `flags` — are written
    /// through the public `OPENSSL_INIT_set_config_filename`,
    /// `OPENSSL_INIT_set_config_appname` and
    /// `OPENSSL_INIT_set_config_file_flags`, which own the `strdup`/`free`
    /// discipline described below; no public routine reads them back, and
    /// their only reader anywhere is `ossl_config_int` in
    /// `crypto/conf/conf_sap.c`, still on the C side. A Rust field setter
    /// could not honour that discipline, so field projection would have to
    /// wait for the layout, which in turn waits for a port of that reader.
    OsslInitSettings,
    OsslInitSettingsRef,
    OsslInitSettingsMut,
    ffi::ossl_init_settings_st
);

// SAFETY: `OPENSSL_INIT_free` is the sole releaser of a settings object and
// the exact counterpart of `OPENSSL_INIT_new`: it frees the two optional
// strings and then the struct, all with the C runtime's `free`, which is what
// `OPENSSL_INIT_new` and the two config setters deliberately allocate with —
// `crypto/conf/conf_lib.c` uses plain `malloc`/`strdup`/`free` there so a
// later `CRYPTO_set_mem_functions` cannot disjoin allocation from release.
// Nothing else may free the object, and no `OPENSSL_free`-family routine may
// be substituted. The type carries no reference count and has no duplicator,
// so one `CBox` is the whole ownership and no `CCloned` exists to pair with
// this. `OsslInitSettings` is `#[repr(transparent)]` over the bindgen type, so
// C receives the pointer value it handed out.
impl_dropped!(
    OsslInitSettings,
    ffi::ossl_init_settings_st,
    ffi::OPENSSL_INIT_free
);

#[cfg(test)]
mod tests {
    use ffibox::CBox;

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

    #[test]
    fn the_owner_is_the_counterpart_of_the_c_constructor() {
        // SAFETY: `OPENSSL_INIT_new` returns a fully constructed settings
        // object, solely owned by its caller, whose only releaser is the
        // `OPENSSL_INIT_free` bound above. Ownership transfers to the `CBox`.
        let mut settings = unsafe { CBox::<OsslInitSettings>::from_raw(ffi::OPENSSL_INIT_new()) }
            .expect("allocate OPENSSL_INIT_SETTINGS");

        // The owner is exactly the pointer C handed out: both handles address
        // it, and the object stays opaque behind them.
        let raw = settings.as_ptr();
        assert_eq!(settings.as_ref().as_ptr(), raw.cast_const());
        assert_eq!(settings.as_mut().as_mut_ptr(), raw);

        // Dropping here runs `OPENSSL_INIT_free` on a freshly built object:
        // both string fields are still NULL, and the allocation goes back to
        // the same C runtime `free` that `malloc` came from.
        drop(settings);
    }

    #[test]
    fn an_owner_is_one_pointer_wide() {
        assert_eq!(
            core::mem::size_of::<CBox<OsslInitSettings>>(),
            core::mem::size_of::<*mut ffi::ossl_init_settings_st>()
        );
    }
}
