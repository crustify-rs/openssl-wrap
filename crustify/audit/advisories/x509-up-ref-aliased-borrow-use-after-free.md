# `X509_up_ref` turns a shared borrow into an exclusive one: heap use-after-free from safe code

- **Crate:** `libcrypto` 0.1.0 (`crustify/rust/libcrypto`), repository revision
  `10edf02776`.
- **Instruments:** AddressSanitizer (clang 19.1.7 `libcrypto.a` + rustc
  `-Zsanitizer=address`, nightly `1.100.0-nightly (c656540d6)`), and the
  unsanitized build for the plain corrupted read.
- **Verdict:** confirmed. `heap-use-after-free` in a reproduction that is
  `#![forbid(unsafe_code)]`, depends on the audited crate by path, and calls
  only its public API.
- **Lead note:** [`../notes/refcounted-share-grants-exclusive-access.md`](../notes/refcounted-share-grants-exclusive-access.md).

## The path from safe code

Every step is a safe `pub fn` of the audited crate. There is no `unsafe` in the
caller.

```rust
let certificate = d2i_X509(&mut input)?;                    // CBox<X509>

// (1) a shared borrow of the certificate, and a byte view into the C heap
//     buffer of its embedded serial number. Both carry `'a = &certificate`.
let serial = X509_get0_serialNumber(certificate.as_ref());  // Asn1StringRef<'a>
let bytes  = ASN1_STRING_get0_data(serial)?;                // CSlice<'a, u8>

// (2) a *second owner* of the same certificate, produced from a *shared*
//     handle. `X509Ref<'a>` is `Copy`, so this is another shared borrow of
//     `certificate` and coexists happily with (1).
let mut alias = X509_up_ref(certificate.as_ref())?;         // BorrowedX509<'a>

// (3) ... which hands out an *exclusive* handle to the very same X509, and
//     therefore to the very same embedded serial number.
let mut certificate_mut = alias.as_mut();                   // X509Mut<'_>
let mut serial_mut = X509_get_serialNumber(&mut certificate_mut); // Asn1StringMut

// (4) `ASN1_STRING_set0(str, NULL, 0)` runs `OPENSSL_free(str->data)`.
clear_data(&mut serial_mut);

// (5) `bytes` is still live for `'a` as far as the type system is concerned.
let after: Vec<u8> = bytes.elems().collect();               // <-- use-after-free
```

The borrow checker accepts this because both (1) and (2) are *shared* borrows
of `certificate`, and (3) is an exclusive borrow of `alias`, a different local.
Nothing in the type system connects `alias` to the object `bytes` points into.

## Why the crate permits it

`X509` is registered as reference-counted:

`crustify/rust/libcrypto/src/x509/x509_internal.rs:98`
```rust
impl_cloned!(X509, ffi::x509_st, up_ref = ffi::X509_up_ref);
```

and the wrapper hands the extra count back as an owner:

`crustify/rust/libcrypto/src/x509/x509_set.rs:89-103`
```rust
/// Wraps: X509_up_ref
/// Acquires a new owned reference to the same certificate.
#[must_use]
#[allow(non_snake_case)]
pub fn X509_up_ref<'a>(certificate: X509Ref<'a>) -> Option<BorrowedX509<'a>> {
```

`BorrowedX509::as_mut` (`x509/x_x509.rs:38-42`) is `pub fn as_mut(&mut self) ->
X509Mut<'_>`, i.e. it asserts exclusive access to the certificate. The
assertion is false whenever more than one owner exists, which `X509_up_ref` is
*for*.

This is not a slip in the wrapper; it follows `ffibox`'s documented design.
From `/opt/ffibox/README.md`:

> where RFL splits `ARef`/`AlwaysRefCounted` from `KBox` and adds `UniqueArc`
> for the pre-publication phase, crustify collapses all three into `CBox<T>` —
> every handle reaches the object through a raw pointer, so a refcounted share
> and a sole owner are the same handle, and the up_ref is just another
> `CCloned::c_clone`.

Rust-for-Linux splits `ARef` from `KBox` precisely so a refcount share cannot
produce `&mut`. Collapsing them removes that separation, and `CBox::as_mut`
reintroduces the exclusive claim.

## Route B: the same crash without naming `X509_up_ref`

Because `impl_cloned!(… up_ref = …)` gives `CBox<X509>` a `CCloned` impl,
`CBox::try_clone(&self)` — which takes a *shared* borrow — is a second door to
the same second owner:

```rust
let mut alias = certificate.try_clone().expect("X509_up_ref");   // CBox<X509>
let mut certificate_mut = alias.as_mut();
let mut serial_mut = X509_get_serialNumber(&mut certificate_mut);
assert!(ASN1_STRING_set1_data(&mut serial_mut, &[0x41; 4096]));  // OPENSSL_realloc
let after: Vec<u8> = bytes.elems().collect();                    // <-- use-after-free
```

`Clone` (which aborts instead of returning `None`) is the same door again. This
route frees by `realloc` rather than `free`, so both C release paths are
covered.

## Reproductions

`crustify/audit/tmp/x509-uaf-uref/` — one cargo crate, two binaries, both
`#![forbid(unsafe_code)]`, both depending on the audited crate by path:

- `src/main.rs` — route A (`X509_up_ref` + `clear_data`)
- `src/bin/clone_route.rs` — route B (`CBox::try_clone` + `ASN1_STRING_set1_data`)

The certificate is `crustify/audit/tmp/x509-probe/corpus/cert.der`; any
DER certificate works, and so does `X509_new()` after any operation that gives
the serial number a heap buffer.

### Unsanitized (the tree's own `libcrypto.a`)

```
$ cargo build && ./target/debug/x509-uaf-upref
len            = 20
before         = [36, 4f, 5a, ea, 90, 31, f1, 2e, 2d, 8e, 1f, f4, b3, 12, ba, c3, a2, 3f, b9, ff]
after          = [32, 17, 97, b0, 46, 58, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00]
```

The "after" bytes are glibc's freed-chunk metadata, read through a `CSlice`
whose lifetime says it is live.

### AddressSanitizer

```sh
cp .cargo/config.toml.asan .cargo/config.toml
CARGO_TARGET_DIR=target-asan rustup run nightly cargo build --target x86_64-unknown-linux-gnu
ASAN_OPTIONS=detect_leaks=0 ./target-asan/x86_64-unknown-linux-gnu/debug/x509-uaf-upref
```

(`.cargo/config.toml.asan` points `-L native=/tmp/osrc-clang` at the clang+ASan
`libcrypto.a`; see [`../notes/sanitizer-setup-for-this-tree.md`](../notes/sanitizer-setup-for-this-tree.md).
Addresses symbolized with `crustify/audit/tmp/symbolize.py`, since this image
has no `llvm-symbolizer`.)

```
==888810==ERROR: AddressSanitizer: heap-use-after-free on address 0x7613275e0940 at pc 0x5f6a4598d387 bp 0x7fff40c4a960 sp 0x7fff40c4a958
READ of size 1 at 0x7613275e0940 thread T0
    #0 core::ptr::read::<u8> | <ffibox::borrowed_refs::CSlice<u8>>::elems::{closure#0} (/opt/ffibox/src/borrowed_refs.rs:212)
    ...
    #11 x509_uaf_upref::main (/work/openssl/crustify/audit/tmp/x509-uaf-uref/src/main.rs:41)

0x7613275e0940 is located 0 bytes inside of 20-byte region [0x7613275e0940,0x7613275e0954)
freed by thread T0 here:
    #0 ___interceptor_free
    #1 ASN1_STRING_set0 (/tmp/osrc-clang/crypto/asn1/asn1_lib.c:377)
    #2 libcrypto::asn1::asn1_lib::clear_data (/work/openssl/crustify/rust/libcrypto/src/asn1/asn1_lib.rs:173)
    #3 <fn() as core::ops::function::FnOnce<()>>::call_once
    #4 std::rt::lang_start::<()>
    #5 main

previously allocated by thread T0 here:
    #0 ___interceptor_malloc
    #1 CRYPTO_realloc (/tmp/osrc-clang/crypto/mem.c:230)
    #2 ossl_asn1_string_set_internal (/tmp/osrc-clang/crypto/asn1/asn1_lib.c:343)
    #3 ossl_c2i_ASN1_INTEGER (/tmp/osrc-clang/crypto/asn1/a_int.c:319)
    ...
    #10 ASN1_item_d2i (/tmp/osrc-clang/crypto/asn1/tasn_dec.c:143)
    #11 libcrypto::x509::x_x509::d2i_X509 (/work/openssl/crustify/rust/libcrypto/src/x509/x_x509.rs:107)
    #12 x509_uaf_upref::main (/work/openssl/crustify/audit/tmp/x509-uaf-uref/src/main.rs:19)

SUMMARY: AddressSanitizer: heap-use-after-free
```

Every frame that matters is in the audited crate: the allocation comes from its
`d2i_X509`, the free from its `clear_data`, the read from a `CSlice` its
`ASN1_STRING_get0_data` handed out.

Route B, same command against `clone_route`:

```
freed by thread T0 here:
    #0 __interceptor_realloc
    #1 CRYPTO_realloc (/tmp/osrc-clang/crypto/mem.c:303)
    #2 ossl_asn1_string_set_internal (/tmp/osrc-clang/crypto/asn1/asn1_lib.c:343)
    #3 libcrypto::asn1::asn1_lib::ASN1_STRING_set1_data (/work/openssl/crustify/rust/libcrypto/src/asn1/asn1_lib.rs:183)
```

## Arguing against myself

- **"The reproduction adds something the crate does not have."** It adds
  nothing. Every call is a safe `pub fn` of `libcrypto`, spelled exactly as the
  crate spells it, and the file carries `#![forbid(unsafe_code)]` so the
  compiler enforces the claim. The freed buffer is allocated by C inside the
  crate's own `d2i_X509` and freed by C inside the crate's own `clear_data`.
- **"`X509_get_serialNumber` and `X509_get0_serialNumber` are different
  objects."** They are the same object; both C functions return
  `&a->cert_info.serialNumber`.
- **"The `'a` on `BorrowedX509` bounds it correctly."** It does — for
  *liveness*. `certificate` cannot be dropped while `alias` lives. Liveness was
  never the problem: the problem is that `'a` is a **shared** borrow and
  `as_mut` is an **exclusive** claim, and nothing reconciles the two.
- **"This is C's fault for reallocating."** No. `ASN1_STRING_set0` and
  `ASN1_STRING_set` are doing exactly what they document. The wrapper is what
  says the byte view is still valid.
- **"The crate documents this somewhere."** I looked. `X509_up_ref`'s doc says
  "Acquires a new owned reference to the same certificate" — it names the
  aliasing and does not draw the conclusion. `BIO_up_ref`'s much longer doc
  (`bio/bio_lib.rs:695-716`) reasons carefully about *which borrows the extra
  count must not outlive* and never mentions exclusivity. `ffibox`'s README
  states the collapse as a deliberate simplification. Nothing anywhere
  acknowledges that `as_mut` on a shared count is unsound.
- **"Was it already known?"** `crustify/audit/notes/handle-discipline-cleared.md`
  §1 and §4, from the previous run, explicitly cleared aliasing and lifetime
  decoupling. This is the case both sections miss, and the note now records
  why. Nothing in `SECURITY.md`, the existing advisories, or a `// SAFETY:`
  comment covers it.

## Scope

The same shape exists for the crate's other two reference-counted types. I could
not turn either into a crash; the reasoning is in the lead note.

- **`Bio`** — `bio/bio_bio_local.rs:63` registers the `up_ref` as `CCloned`,
  `bio/bio_lib.rs:717` `BIO_up_ref` returns `BorrowedBio<'a>` with an `as_mut`.
  There is a large safe mutating surface, but I could not pair it with a safe
  borrow into BIO-owned heap: the only such borrows are `BIO_nread*`/
  `BIO_nwrite*` on a BIO pair, and the operation that frees that buffer needs
  `BIO_ctrl`, which is correctly `unsafe fn`.
- **`EvpPkey`** — `evp/evp.rs:40`. `X509_get0_pubkey` (shared handle) and
  `X509_get_pubkey` (owning handle) already return handles to the same cached
  key with no `up_ref` call in the caller. `EvpPkeyMut` has no safe mutating
  operation today, so there is nothing to demonstrate.

## Not checked

- Whether a second owner can be raced across threads: no wrapper type is
  `Send`, so this is single-threaded only.
- `X509_PUBKEY`, `X509_NAME`, `X509_EXTENSION` and the `x509v3` records — none
  is reference counted; their `*_dup` clones are independent allocations, which
  I confirmed by pointer inequality in the sweep.
- Whether other `CSlice`-yielding getters (`X509_NAME_get0_der`,
  `X509_PUBKEY_get0_param().encoded_key`, `X509_get0_signature().value`) can be
  invalidated *without* the alias. I looked for a shared-access C path that
  reallocates those caches and did not find one; `X509_NAME_get0_der` calls
  `i2d_X509_NAME` first, which clears `modified`, so the later `X509_NAME_cmp`
  re-encode does not fire.

## Suggested fix

**The real fix belongs in `ffibox`**: reintroduce the `ARef`/`KBox` split that
the README says was collapsed — a shared owner type for reference-counted C
objects that exposes `as_ref()` and `Drop` but no `as_mut()`, with
`impl_cloned!(…, up_ref = …)` producing that instead of `Clone for CBox`.
`ffibox` is outside this repository, so the patch below is the local
equivalent inside `libcrypto`, applying the same rule to the three types this
crate registers as refcounted:

1. Drop the `CCloned` registration for `X509`, `EvpPkey` and `Bio`, removing
   `CBox::try_clone`/`Clone` for them.
2. Add a shared-only owner and return it from every wrapper that acquires a
   count: `X509_up_ref`, `BIO_up_ref`, `X509_get_pubkey`, `X509_PUBKEY_get`.

**This is a breaking change.** `CBox<X509>`, `CBox<Bio>` and `CBox<EvpPkey>`
stop being `Clone`; `X509_up_ref`, `BIO_up_ref`, `X509_get_pubkey` and
`X509_PUBKEY_get` change their return types. There is no non-breaking version:
the unsoundness *is* the ability to reach `as_mut` from an extra count.

## Remediation

- **Branch:** `crustify/audit-fix-refcount-alias-and-general-name-cmp`, cut
  from `10edf02776`. Committed, not merged, not pushed.
- **Commit:** `bd209c96b8` "Make a reference-count share grant shared access
  only".

### What the patch does

New module `crustify/rust/libcrypto/src/refcount.rs`:

```rust
#[must_use = "dropping the owner releases its reference"]
pub struct SharedRef<'a, T: CCell + CDropped> {
    inner: CBox<T>,
    borrow: PhantomData<&'a CType<c_void>>,
}
```

It owns one count, settles it through the type's registered down-reference,
and exposes `as_ref` and `as_ptr` — no `as_mut`. It keeps the borrow parameter
the `Borrowed*` owners carry, so a share still cannot outlive a BIO's method
table or a certificate's `OSSL_LIB_CTX`.

Applied to all three reference-counted types:

| was | now |
|---|---|
| `impl_cloned!(X509, up_ref = X509_up_ref)` | removed — `CBox<X509>` is not `Clone` |
| `impl_cloned!(EvpPkey, up_ref = EVP_PKEY_up_ref)` | removed |
| hand-written `unsafe impl CCloned for Bio` | removed |
| `X509_up_ref -> Option<BorrowedX509<'a>>` | `-> Option<SharedX509<'a>>` |
| `BIO_up_ref -> Option<BorrowedBio<'a>>` | `-> Option<SharedBio<'a>>` |
| `X509_get_pubkey -> Option<CBox<EvpPkey>>` | `-> Option<SharedEvpPkey>` |
| `X509_PUBKEY_get -> Option<CBox<EvpPkey>>` | `-> Option<SharedEvpPkey>` |

`X509Ref::try_dup`, `X509_dup` and `EvpPkeyRef::try_dup` are untouched: a deep
copy really is a sole allocation, so it stays a `CBox` and stays mutable.

### Regression tests

A runtime test cannot assert the *absence* of a method, so the guards are two
`compile_fail` doctests on `SharedRef`, plus a passing one for the shape that
must stay legal:

```
running 1 test
test libcrypto/src/refcount.rs - refcount::SharedRef (line 65) ... ok

running 2 tests
test libcrypto/src/refcount.rs - refcount::SharedRef (line 41) - compile fail ... ok
test libcrypto/src/refcount.rs - refcount::SharedRef (line 54) - compile fail ... ok
```

Line 41 is `SharedRef::as_mut`; line 54 is `CBox<X509>::try_clone`. Either door
reopening turns the corresponding doctest red. Line 65 is the positive case: a
byte view of the serial number taken through the original owner, read before
and after a share is taken and dropped.

The `X509`, `X509_up_ref` and `BIO_up_ref` unit tests were rewritten to
exercise the share instead of a clone.

### Commands and results

```sh
cd /work/openssl/crustify/rust
cargo clippy --workspace --all-targets     # 0 warnings, 0 errors
cargo test -p libcrypto                    # 329 lib + 1 doctest + 2 compile-fail, all ok
cargo fmt --check                          # only the two pre-existing diffs (see below)
```

`cargo fmt --check` reports the module-ordering diffs in
`libcrypto/src/lib.rs` and `libcrypto/src/stack/mod.rs` that are already
present on `10edf02776`; I verified that by stashing the patch and rerunning.
The files this patch touches were formatted with `rustfmt --edition 2024` so
that no *new* diff is introduced — deliberately not `cargo fmt`, which would
reformat untouched files.

Under AddressSanitizer, `--lib` only:

```sh
RUSTFLAGS="-L native=/tmp/osrc-clang -Zsanitizer=address" \
CARGO_TARGET_DIR=/tmp/asan-target-audit ASAN_OPTIONS=detect_leaks=1 \
rustup run nightly cargo test --target x86_64-unknown-linux-gnu -p libcrypto --lib
# test result: ok. 329 passed; 0 failed
```

`--lib` is required: `rustdoc` does not forward `-Zsanitizer=address` to the
binary it builds for a doctest, so an ordinary doctest fails to link against
the ASan `libcrypto.a`. Recorded in
[`../notes/sanitizer-setup-for-this-tree.md`](../notes/sanitizer-setup-for-this-tree.md).

### The reproduction against the patch

Both routes now fail to compile, which is the whole point — the UB is no longer
expressible without `unsafe`:

```
$ cd crustify/audit/tmp/x509-uaf-uref && cargo build
error[E0599]: no method named `as_mut` found for struct `SharedRef<'a, T>` in the current scope
  --> src/main.rs:34:37
   |
34 |     let mut certificate_mut = alias.as_mut();
   |                                     ^^^^^^ method not found in `SharedRef<'_, X509>`

error[E0599]: the method `try_clone` exists for struct `ffibox::owned_refs::CBox<X509>`,
              but its trait bounds were not satisfied
  --> src/bin/clone_route.rs:24:33
   |
24 |     let mut alias = certificate.try_clone().expect("X509_up_ref");
   |                                 ^^^^^^^^^ method cannot be called on `CBox<X509>`
   = note: the following trait bounds were not satisfied:
           `X509: ffibox::traits::CCloned`
```

The ten-section adversarial sweep in `crustify/audit/tmp/x509-probe/` also
still reports `0 failing section(s)` against the patched crate, under both the
tree's UBSan build and ASan.

### What the patch costs

One capability disappears with the `CCloned` impls: `CBox<Bio>::try_clone`
used to hand back a count *detached* from the original owner's lifetime, and
`BIO_up_ref`'s `'a` bound does not. The crate's own test for that
(`up_ref_of_an_owner_still_yields_a_detached_owner_through_clone`) is removed
rather than adapted. If a caller needs it, the sound shape is a second contract
for the same symbol — `BIO_up_ref` taking `&CBox<Bio>` and returning
`SharedBio<'static>`, justified by a `CBox<Bio>` having no borrowed dependency
by construction. I did not add it: nothing in the crate needs it today, and the
crate's convention is one wrapper per C contract actually in use.
