//! Wrappers assigned from `include/openssl/bio.h`.

use libcrypto_sys as ffi;

/// Wraps: BIO_hostserv_priorities
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct BioHostservPriorities(ffi::BIO_hostserv_priorities);

impl BioHostservPriorities {
    /// Treat an unqualified input as a host name.
    pub const HOST: Self = Self(ffi::BIO_hostserv_priorities_BIO_PARSE_PRIO_HOST);

    /// Treat an unqualified input as a service name.
    pub const SERVICE: Self = Self(ffi::BIO_hostserv_priorities_BIO_PARSE_PRIO_SERV);

    /// Validates and wraps a raw OpenSSL priority value.
    pub const fn from_raw(raw: ffi::BIO_hostserv_priorities) -> Option<Self> {
        match raw {
            ffi::BIO_hostserv_priorities_BIO_PARSE_PRIO_HOST
            | ffi::BIO_hostserv_priorities_BIO_PARSE_PRIO_SERV => Some(Self(raw)),
            _ => None,
        }
    }

    /// Returns the raw value expected by OpenSSL.
    pub const fn as_raw(self) -> ffi::BIO_hostserv_priorities {
        self.0
    }
}

/// Wraps: BIO_lookup_type
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct BioLookupType(ffi::BIO_lookup_type);

impl BioLookupType {
    /// Request addresses suitable for connecting a client.
    pub const CLIENT: Self = Self(ffi::BIO_lookup_type_BIO_LOOKUP_CLIENT);

    /// Request addresses suitable for accepting server connections.
    pub const SERVER: Self = Self(ffi::BIO_lookup_type_BIO_LOOKUP_SERVER);

    /// Validates and wraps a raw OpenSSL lookup type.
    pub const fn from_raw(raw: ffi::BIO_lookup_type) -> Option<Self> {
        match raw {
            ffi::BIO_lookup_type_BIO_LOOKUP_CLIENT | ffi::BIO_lookup_type_BIO_LOOKUP_SERVER => {
                Some(Self(raw))
            }
            _ => None,
        }
    }

    /// Returns the raw value expected by OpenSSL.
    pub const fn as_raw(self) -> ffi::BIO_lookup_type {
        self.0
    }
}

/// Wraps: BIO_sock_info_type
///
/// A checked, layout-compatible value for the socket-information selector.
/// Keeping the bindgen integer private prevents safe Rust from inventing a C
/// enum value that OpenSSL's switch does not handle.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BioSockInfoType(ffi::BIO_sock_info_type);

impl BioSockInfoType {
    /// Request the socket's local address.
    pub const ADDRESS: Self = Self(ffi::BIO_sock_info_type_BIO_SOCK_INFO_ADDRESS);

    /// Convert a raw C enum value after validating its discriminant.
    #[must_use]
    pub const fn from_raw(raw: ffi::BIO_sock_info_type) -> Option<Self> {
        if raw == ffi::BIO_sock_info_type_BIO_SOCK_INFO_ADDRESS {
            Some(Self::ADDRESS)
        } else {
            None
        }
    }

    /// Return the ABI value used by OpenSSL.
    #[must_use]
    pub const fn as_raw(self) -> ffi::BIO_sock_info_type {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostserv_priorities_validate_raw_values() {
        assert_eq!(
            BioHostservPriorities::from_raw(ffi::BIO_hostserv_priorities_BIO_PARSE_PRIO_HOST,),
            Some(BioHostservPriorities::HOST)
        );
        assert_eq!(
            BioHostservPriorities::from_raw(ffi::BIO_hostserv_priorities_BIO_PARSE_PRIO_SERV,),
            Some(BioHostservPriorities::SERVICE)
        );
        assert_eq!(BioHostservPriorities::from_raw(u32::MAX), None);
    }

    #[test]
    fn lookup_types_validate_raw_values() {
        assert_eq!(
            BioLookupType::from_raw(ffi::BIO_lookup_type_BIO_LOOKUP_CLIENT),
            Some(BioLookupType::CLIENT)
        );
        assert_eq!(
            BioLookupType::from_raw(ffi::BIO_lookup_type_BIO_LOOKUP_SERVER),
            Some(BioLookupType::SERVER)
        );
        assert_eq!(BioLookupType::from_raw(u32::MAX), None);
    }

    #[test]
    fn socket_info_selector_is_checked_and_layout_compatible() {
        assert_eq!(
            core::mem::size_of::<BioSockInfoType>(),
            core::mem::size_of::<ffi::BIO_sock_info_type>()
        );
        assert_eq!(
            core::mem::align_of::<BioSockInfoType>(),
            core::mem::align_of::<ffi::BIO_sock_info_type>()
        );
        assert_eq!(
            BioSockInfoType::from_raw(BioSockInfoType::ADDRESS.as_raw()),
            Some(BioSockInfoType::ADDRESS)
        );
        assert_eq!(BioSockInfoType::from_raw(1), None);
    }

    #[test]
    fn wrappers_preserve_the_raw_enum_layout() {
        assert_eq!(
            core::mem::size_of::<BioHostservPriorities>(),
            core::mem::size_of::<ffi::BIO_hostserv_priorities>()
        );
        assert_eq!(
            core::mem::align_of::<BioLookupType>(),
            core::mem::align_of::<ffi::BIO_lookup_type>()
        );
    }
}
