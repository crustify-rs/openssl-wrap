# Audit record — `crustify/rust/libcrypto`

Hunting undefined behaviour reachable from safe Rust.

## `advisories/` — confirmed, each with a `#![forbid(unsafe_code)]` reproduction

| advisory | what fires | instrument |
|---|---|---|
| [`asn1-string-table-data-race.md`](advisories/asn1-string-table-data-race.md) | use-after-free, double-free, glibc heap-metadata corruption | ASan **and** glibc, 0/10 runs survive either |
| [`asn1-string-print-ex-object-type-confusion.md`](advisories/asn1-string-print-ex-object-type-confusion.md) | 8-byte heap-buffer-overflow read (`ASN1_STRING` read as `ASN1_OBJECT`) | ASan |
| [`bio-gets-buffer-filter-null-deref.md`](advisories/bio-gets-buffer-filter-null-deref.md) | null-pointer read at `NULL+0x28` | UBSan (tree build) **and** ASan |
| [`bio-dup-chain-double-close.md`](advisories/bio-dup-chain-double-close.md) | one descriptor closed twice; std aborts | Rust std I/O-safety check |
| [`obj-sigid-comparator-signed-overflow.md`](advisories/obj-sigid-comparator-signed-overflow.md) | signed integer overflow in a C comparator | UBSan (tree build) |

All five root-cause in OpenSSL C and are reachable from this crate's safe API
with no `unsafe` in the caller; each advisory says which side it thinks should
be fixed, and four of the five also carry a non-breaking wrapper-side guard.
They are listed most-severe first.

The first one is the one to read if you only read one: it needs no exotic
argument, only `std::thread::spawn`, and the crate already has the mutex that
fixes it sitting in its own `#[cfg(test)]` block.

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
