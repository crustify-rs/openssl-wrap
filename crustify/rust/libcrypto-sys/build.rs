use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

// crustify:allowlist-agent:start
const AGENT_CLANG_ARGS: &[&str] = &[];
const AGENT_LINK_ARGS: &[&str] = &[
    "rustc-link-lib=static=crypto",
    "rustc-link-lib=ubsan",
    "rustc-link-lib=dl",
    "rustc-link-lib=pthread",
];
const AGENT_ALLOWED_TYPES: &[&str] = &[
    "ASN1_ITEM",
    "ASN1_OBJECT",
    "ASN1_TEMPLATE",
    "ASN1_VALUE",
    "BIGNUM",
    "BIO_hostserv_priorities",
    "BIO_lookup_type",
    "BIO_sock_info_type",
    "BIO_sock_info_u",
    "OBJ_NAME",
    "OPENSSL_INIT_SETTINGS",
    "OPENSSL_LHASH",
    "OPENSSL_STACK",
    "asn1_string_table_st",
    "bio_addr_st",
    "bio_msg_st",
    "bio_method_st",
    "bio_poll_descriptor_st",
    "bio_st",
    "ossl_lib_ctx_st",
    "OPENSSL_sk_compfunc",
    "OPENSSL_sk_copyfunc",
    "OPENSSL_sk_freefunc",
    "BIO_callback_fn",
    "BIO_callback_fn_ex",
    "addrinfo",
];
const AGENT_OPAQUE_TYPES: &[&str] = &["lhash_st", "ossl_init_settings_st", "stack_st"];
const AGENT_ALLOWED_FUNCTIONS: &[&str] = &[
    "ASN1_OBJECT_free",
    "BIO_free",
    "BIO_meth_free",
    "BIO_meth_new",
    "BIO_new",
    "BIO_s_null",
    "BIO_up_ref",
    "BN_clear_free",
    "BN_dup",
    "BN_free",
    "BN_new",
    "CRYPTO_clear_free",
    "CRYPTO_free",
    "CRYPTO_memdup",
    "CRYPTO_secure_clear_free",
    "CRYPTO_secure_free",
    "CRYPTO_secure_zalloc",
    "CRYPTO_strdup",
    "OPENSSL_INIT_free",
    "OPENSSL_LH_free",
    "OPENSSL_sk_dup",
    "OPENSSL_sk_free",
    "OSSL_LIB_CTX_free",
    "OSSL_LIB_CTX_new",
    "ASN1_STRING_TABLE_add",
    "ASN1_STRING_get_default_mask",
    "ASN1_STRING_set_default_mask",
    "ASN1_STRING_set_default_mask_asc",
    "BIO_accept",
    "BIO_closesocket",
    "BIO_dgram_non_fatal_error",
    "BIO_dump_cb",
    "BIO_dump_indent_cb",
    "BIO_err_is_non_fatal",
    "BIO_fd_non_fatal_error",
    "BIO_fd_should_retry",
    "BIO_get_accept_socket",
    "BIO_get_host_ip",
    "BIO_get_new_index",
    "BIO_get_port",
    "BIO_set_tcp_ndelay",
    "BIO_sock_error",
    "BIO_sock_init",
    "BIO_sock_non_fatal_error",
    "BIO_sock_should_retry",
    "BIO_socket",
    "BIO_socket_ioctl",
    "BIO_socket_nbio",
    "BIO_socket_wait",
    "OBJ_NAME_get",
    "OBJ_NAME_init",
    "OBJ_dup",
    "OBJ_bsearch_",
    "OBJ_bsearch_ex_",
    "OBJ_create",
    "OBJ_find_sigid_algs",
    "OBJ_ln2nid",
    "OBJ_new_nid",
    "OBJ_txt2obj",
    "OBJ_nid2ln",
    "OBJ_nid2sn",
    "OBJ_sn2nid",
    "BIO_ADDRINFO_address",
    "BIO_ADDRINFO_family",
    "BIO_ADDRINFO_free",
    "BIO_ADDRINFO_next",
    "BIO_ADDRINFO_protocol",
    "BIO_ADDRINFO_socktype",
    "BIO_ADDR_clear",
    "BIO_ADDR_copy",
    "BIO_ADDR_dup",
    "BIO_ADDR_family",
    "BIO_ADDR_free",
    "BIO_ADDR_hostname_string",
    "BIO_ADDR_new",
    "BIO_ADDR_path_string",
    "BIO_ADDR_rawaddress",
    "BIO_ADDR_rawmake",
    "BIO_ADDR_rawport",
    "BIO_ADDR_service_string",
    "BIO_accept_ex",
    "BIO_bind",
    "BIO_clear_flags",
    "BIO_connect",
    "BIO_copy_next_retry",
    "BIO_ctrl",
    "BIO_ctrl_get_read_request",
    "BIO_ctrl_get_write_guarantee",
    "BIO_ctrl_pending",
    "BIO_ctrl_reset_read_request",
    "BIO_ctrl_wpending",
    "BIO_debug_callback",
    "BIO_debug_callback_ex",
    "BIO_do_connect_retry",
    "BIO_dump",
    "BIO_dump_fp",
    "BIO_dump_indent",
    "BIO_dump_indent_fp",
    "BIO_eof",
    "BIO_f_buffer",
    "BIO_f_linebuffer",
    "BIO_f_nbio_test",
    "BIO_f_null",
    "BIO_f_prefix",
    "BIO_f_readbuffer",
    "BIO_find_type",
    "BIO_free_all",
    "BIO_get_callback",
    "BIO_get_callback_arg",
    "BIO_get_data",
    "BIO_next",
];
const AGENT_ALLOWED_VARS: &[&str] = &[
    "BIO_POLL_DESCRIPTOR_CUSTOM_START",
    "BIO_POLL_DESCRIPTOR_TYPE_NONE",
    "BIO_POLL_DESCRIPTOR_TYPE_SOCK_FD",
    "BIO_POLL_DESCRIPTOR_TYPE_SSL",
    "BIO_SOCK_INFO_ADDRESS",
];
const AGENT_BLOCKLIST: &[&str] = &[];
// crustify:allowlist-agent:end

fn main() {
    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let repo_root = manifest_dir.ancestors().nth(3).unwrap();
    let output = PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("bindings.rs");

    let mut command = Command::new("bindgen");
    command
        .arg(manifest_dir.join("bindgen.h"))
        .arg("--output")
        .arg(&output)
        .arg("--allowlist-type")
        .arg("^$")
        .arg("--allowlist-function")
        .arg("^$")
        .arg("--allowlist-var")
        .arg("^$");
    for name in AGENT_ALLOWED_TYPES {
        command.args(["--allowlist-type", name]);
    }
    for name in AGENT_OPAQUE_TYPES {
        command.args(["--opaque-type", name]);
    }
    for name in AGENT_ALLOWED_FUNCTIONS {
        command.args(["--allowlist-function", name]);
    }
    for name in AGENT_ALLOWED_VARS {
        command.args(["--allowlist-var", name]);
    }
    for name in AGENT_BLOCKLIST {
        command.args(["--blocklist-item", name]);
    }
    command
        .arg("--")
        .arg(format!("-I{}", repo_root.join("include").display()));
    for argument in AGENT_CLANG_ARGS {
        command.arg(resolve_include(repo_root, argument));
    }

    let status = command.status().expect("failed to invoke bindgen-cli");
    assert!(status.success(), "bindgen-cli failed");

    for argument in AGENT_LINK_ARGS {
        println!("cargo:{argument}");
    }
    if !AGENT_LINK_ARGS.is_empty() {
        println!("cargo:rustc-link-search=native={}", repo_root.display());
    }
    println!("cargo:rerun-if-changed=bindgen.h");
}

fn resolve_include(repo_root: &Path, argument: &str) -> String {
    argument.strip_prefix("-I").map_or_else(
        || argument.to_owned(),
        |path| format!("-I{}", repo_root.join(path).display()),
    )
}
