# Lead: a zero-length `ASN1_STRING` leaks its buffer on the next set

**Status: real, but a memory *leak*, not UB. No advisory. Second instance of
the same C defect family as
[`asn1-string-not-owned-flag-leak.md`](asn1-string-not-owned-flag-leak.md).**

## The mechanism

`ossl_asn1_string_set_internal` decides whether to reuse the existing buffer by
looking at the *logical* length, and treats "length 0" as "no buffer":

```c
    if ((size_t)str->length != alloc_len) {
        uint8_t *c;
        c = OPENSSL_realloc(str->length == 0 ? NULL : str->data, alloc_len);
```

When `str->length == 0` but `str->data != NULL`, the live pointer is simply
dropped on the floor.

Two safe routes into that state:

1. `ASN1_STRING_set(s, &[])` — the crustify shim `crustify_ASN1_STRING_set`
   does `OPENSSL_malloc(length + 1)` unconditionally, so an empty input still
   allocates one byte, then `ASN1_STRING_set0(s, copy, 0)` records
   `length == 0` beside a non-null `data`.
2. `ASN1_STRING_length_set(s, 0)` — shrinking the logical length to zero while
   the buffer stays. The wrapper's own doc comment already calls this out
   ("Shrinking to zero ... a later `ASN1_STRING_set1_data` on this string
   allocates afresh and leaks what was there. Nothing is freed twice or read
   after release").

## Evidence

Found by the ASan+LSan sweep, from route 1 (which the doc does *not* mention):

```
Direct leak of 1 byte(s) in 1 object(s) allocated from:
    #1 CRYPTO_malloc /tmp/osrc-clang/crypto/mem.c:230
    #2 crustify_ASN1_STRING_set
    #3 libcrypto::asn1::openssl_asn1::ASN1_STRING_set  src/asn1/openssl_asn1.rs:986
    #4 sweep::asn1_strings  src/bin/sweep.rs:95
SUMMARY: AddressSanitizer: 1 byte(s) leaked in 1 allocation(s).
```

Triggered by `ASN1_STRING_set(s, &[])` followed by
`ASN1_STRING_set1_data(s, b"z")`.

## Why it is not an advisory

Leaking is safe. I specifically looked for the dangerous inversion — a
`str->length` that is *larger* than the allocation, which would turn the next
`memcpy` into a heap overflow — and it does not exist:

- `ASN1_STRING_length_set` refuses growth (`openssl_asn1.rs:960`), so the
  logical length can only ever be <= capacity.
- `ASN1_STRING_set0` sets length and capacity together from one `CVec`.
- `set_internal` writes exactly `alloc_len` bytes and only skips the realloc
  when `str->length == alloc_len`, and the capacity invariant
  (`capacity in {length, length+1}`) makes that write fit.

I walked every `(previous op, next op, length)` combination in the sweep —
types `-10..=40` x lengths `{0,1,2,3,4,5,7,8,15,16,257}` x every shrink target
— under both UBSan and ASan. No out-of-bounds access.

## Who should hear about it

`ossl_asn1_string_set_internal` should test `str->data == NULL` rather than
`str->length == 0`. That is an OpenSSL C fix. The wrapper could also stop
allocating for an empty input in `crustify_ASN1_STRING_set`, which would remove
route 1.
