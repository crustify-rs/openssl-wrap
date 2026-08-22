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
    "ASN1_TEMPLATE",
    "ASN1_VALUE",
    "BIO_hostserv_priorities",
    "BIO_lookup_type",
    "BIO_sock_info_type",
    "OPENSSL_LHASH",
    "asn1_string_table_st",
    "bio_addr_st",
    "bio_method_st",
    "bio_st",
];
const AGENT_OPAQUE_TYPES: &[&str] = &["lhash_st"];
const AGENT_ALLOWED_FUNCTIONS: &[&str] = &[
    "BIO_free",
    "BIO_meth_free",
    "BIO_meth_new",
    "BIO_new",
    "BIO_s_null",
    "BIO_up_ref",
    "CRYPTO_clear_free",
    "CRYPTO_free",
    "CRYPTO_memdup",
    "CRYPTO_secure_clear_free",
    "CRYPTO_secure_free",
    "CRYPTO_secure_zalloc",
    "CRYPTO_strdup",
    "OPENSSL_LH_free",
];
const AGENT_ALLOWED_VARS: &[&str] = &["BIO_SOCK_INFO_ADDRESS"];
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
