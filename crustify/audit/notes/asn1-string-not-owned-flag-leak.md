# Lead: `ASN1_STRING_copy` propagates `DATA_NOT_OWNED` onto an owned buffer

**Status: real defect, but a memory *leak*, not UB. No advisory.**

## The mechanism

`ASN1_STRING_new_not_owned` (safe, `asn1/asn1_lib.rs:126`) builds an
`ASN1_STRING` whose `data` points into a Rust `&[u8]` and whose flags carry
`ASN1_STRING_FLAG_DATA_NOT_OWNED`. `BorrowedAsn1String<'a>` tracks the borrow
correctly, and every C mutator I checked handles the flag properly
(`ossl_asn1_string_set_internal` and `ASN1_STRING_set0` both clear it before
touching `data`; `ossl_asn1_string_free_internal` nulls `data` first).

The bug is in `ASN1_STRING_copy` (`crypto/asn1/asn1_lib.c`):

```c
    dst->type = str->type;
    if (!ossl_asn1_string_set_internal(dst, str->data, str->length, 0))
        return 0;
    /* Copy flags but preserve embed value */
    dst->flags &= ASN1_STRING_FLAG_EMBED;
    dst->flags |= str->flags & ~ASN1_STRING_FLAG_EMBED;
```

`set_internal` has just given `dst` a freshly `OPENSSL_malloc`ed buffer that
`dst` owns. The flag copy then labels that owned buffer `DATA_NOT_OWNED`, so
`ossl_asn1_string_free_internal` nulls `data` and never frees it.

## Reachable from safe Rust

`ASN1_STRING_dup(borrowed.as_ref())` or
`ASN1_STRING_copy(&mut owned.as_mut(), borrowed.as_ref())` — both safe.

## Evidence

`crustify/audit/tmp/probe`, sub-experiment `1`, run against a clang+ASan build of
libcrypto (`/tmp/osrc-clang`, `./Configure linux-x86_64-clang no-deprecated
enable-asan`):

```
Direct leak of 31 byte(s) in 1 object(s) allocated from:
    #0 __interceptor_malloc
    #1 CRYPTO_malloc crypto/mem.c:230
    #2 ossl_asn1_string_set_internal crypto/asn1/asn1_lib.c:343
    #3 ASN1_STRING_copy crypto/asn1/asn1_lib.c:268
    #4 ASN1_STRING_dup crypto/asn1/asn1_lib.c:286
    #5 libcrypto::asn1::asn1_lib::ASN1_STRING_dup src/asn1/asn1_lib.rs:72
SUMMARY: AddressSanitizer: 62 byte(s) leaked in 2 allocation(s).
```

## Why it is not an advisory

A leak is not undefined behaviour, and I could not turn it into one. I chased
the dangerous inversion — a string whose flag is *cleared* while `data` still
points at Rust memory, which would make C `OPENSSL_free` a Rust pointer — and it
does not exist: every path that clears the flag (`ASN1_STRING_set0`,
`ossl_asn1_string_set_internal`, `ossl_asn1_string_free_internal`) replaces or
nulls `data` in the same step.

## Who should hear about it

This is an OpenSSL C defect (`ASN1_STRING_copy` should mask `DATA_NOT_OWNED` out
of the copied flags, as it already does for `ASN1_STRING_FLAG_EMBED`). The Rust
wrapper is what makes it *reachable*, since `ASN1_STRING_new_not_owned` is the
only safe producer of a not-owned string in this surface, but the wrapper is not
doing anything wrong.

## What would change my mind

Finding a path where the `NDEF` flag is involved: `ossl_asn1_string_set_internal`
does **not** consult `ASN1_STRING_FLAG_NDEF` before `OPENSSL_realloc`ing
`str->data`, so an NDEF-flagged string reaching it would be an invalid realloc.
I could not reach an NDEF string from this surface (it is set only by
`crypto/asn1/bio_ndef.c`, which is not wrapped). Worth re-checking if the
wrapped surface ever grows to include the NDEF streaming BIO.
