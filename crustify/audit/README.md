# Audit record — `crustify/rust/libcrypto`

Hunting undefined behaviour reachable from safe Rust.

## `advisories/` — confirmed, each with a `#![forbid(unsafe_code)]` reproduction

| advisory | what fires | instrument |
|---|---|---|
| [`asn1-string-table-data-race.md`](advisories/asn1-string-table-data-race.md) | use-after-free, double-free, glibc heap-metadata corruption | ASan **and** glibc, 0/10 runs survive either |
| [`x509-up-ref-aliased-borrow-use-after-free.md`](advisories/x509-up-ref-aliased-borrow-use-after-free.md) | heap use-after-free: an `up_ref` share hands out an exclusive handle | ASan |
| [`asn1-string-print-ex-object-type-confusion.md`](advisories/asn1-string-print-ex-object-type-confusion.md) | 8-byte heap-buffer-overflow read (`ASN1_STRING` read as `ASN1_OBJECT`) | ASan |
| [`bio-gets-buffer-filter-null-deref.md`](advisories/bio-gets-buffer-filter-null-deref.md) | null-pointer read at `NULL+0x28` | UBSan (tree build) **and** ASan |
| [`bio-dup-chain-double-close.md`](advisories/bio-dup-chain-double-close.md) | one descriptor closed twice; std aborts | Rust std I/O-safety check |
| [`obj-sigid-comparator-signed-overflow.md`](advisories/obj-sigid-comparator-signed-overflow.md) | signed integer overflow in a C comparator | UBSan (tree build) |
| [`general-name-cmp-unset-asn1-type-null-deref.md`](advisories/general-name-cmp-unset-asn1-type-null-deref.md) | null-pointer read in `ASN1_STRING_cmp` via `GENERAL_NAME_cmp` | UBSan (tree build) **and** ASan |

The first five safe wrapper routes are remediated by `589b6078ec`; the two
added by the second run are remediated on branch
`crustify/audit-fix-refcount-alias-and-general-name-cmp` (`d5e86577a2`,
`bd209c96b8`), committed and not merged. Each advisory ends with the focused
regression and instrument rerun that verifies its guard.

All seven are reachable from this crate's safe API with no `unsafe` in the
caller; each advisory says which side it thinks should be fixed. They are
listed most-severe first.

Six of the seven root-cause in OpenSSL C, with the Rust wrapper as the thing
that makes them reachable. **`x509-up-ref-aliased-borrow-use-after-free.md` is
the exception and is the one to read if you only read one:** the defect is in
the Rust ownership model itself, and its root cause is a documented `ffibox`
design decision — collapsing Rust-for-Linux's `ARef`/`KBox` split into a
single `CBox`, so a reference-count *share* can hand out the *exclusive*
handle. Its lead note, `refcounted-share-grants-exclusive-access.md`, records
the two other refcounted types where the same shape exists but no crash could
be produced. Second-most-severe is `asn1-string-table-data-race.md`, which
needs no exotic argument, only `std::thread::spawn`.

## `notes/` — every lead chased, including the ones that went nowhere

Cleared, so nobody re-derives them:
[`handle-discipline-cleared.md`](notes/handle-discipline-cleared.md) (the six
classic wrapper shapes, plus `zeroed()` reachability),
[`safe-api-reachability.md`](notes/safe-api-reachability.md) (roughly a third of
the safe surface is uncallable without `unsafe`, and which third).

Real but not UB:
[`asn1-string-not-owned-flag-leak.md`](notes/asn1-string-not-owned-flag-leak.md),
[`asn1-string-zero-length-realloc-leaks.md`](notes/asn1-string-zero-length-realloc-leaks.md)
— two leaks in the same C function family, both LSan-confirmed.

New in the second run:
[`refcounted-share-grants-exclusive-access.md`](notes/refcounted-share-grants-exclusive-access.md)
(the lead behind the use-after-free advisory, plus the `Bio` and `EvpPkey`
instances of the same shape that could not be crashed),
[`x509-surface-adversarial-sweep.md`](notes/x509-surface-adversarial-sweep.md)
(the ten-section sweep over the `x509/` and `stack/` subtrees, everything it
cleared, and the two API gaps that shrink the reachable surface).

Live leads for the next run:
[`mmsg-callback-getters-unreachable.md`](notes/mmsg-callback-getters-unreachable.md)
(a type-confusion hole that is one safe constructor away from firing),
[`global-registry-thread-safety.md`](notes/global-registry-thread-safety.md)
(one registry confirmed, three cleared with a control, cross-registry
interleavings untested),
[`no-safe-bio-chain.md`](notes/no-safe-bio-chain.md) (a conclusion I had to
correct mid-run; the correction became route B of the double-close advisory).

Infrastructure:
[`sanitizer-setup-for-this-tree.md`](notes/sanitizer-setup-for-this-tree.md) —
read this before wiring up AddressSanitizer here; the obvious approach produces
~25% false crashes.

## `tmp/` — reproductions and the exploratory probes

See [`tmp/README.md`](tmp/README.md).
