# `ASN1_STRING_type_new` + `ASN1_STRING_print_ex` read past a heap allocation

**Crate:** `libcrypto` 0.1.0 (`/work/openssl/crustify/rust/libcrypto`), branch
`crustify/libcrypto-gpt-5.6-sol`, code tip `eab7392e15`.
**Affected safe functions:** `asn1::asn1_lib::ASN1_STRING_type_new` combined
with `asn1::a_strex::ASN1_STRING_print_ex`.
**Class:** heap-buffer-overflow (8-byte out-of-bounds read) caused by
`ASN1_STRING` / `ASN1_OBJECT` type confusion.
**Root cause:** OpenSSL C, reachable identically from plain C — see
*Whose bug is this*. It is reachable from this crate's safe API, so the crate
is unsound as it stands.
**Lead note:** [`notes/asn1-string-type-tag-is-unvalidated.md`](../notes/asn1-string-type-tag-is-unvalidated.md)

## The path from safe code

Three safe calls, no `unsafe` in the caller:

```rust
const V_ASN1_OBJECT: i32 = 6;
const DUMP_ALL_DER: u64 = 0x0080 | 0x0200;  // ASN1_STRFLGS_DUMP_ALL|_DUMP_DER

let s = ASN1_STRING_type_new(V_ASN1_OBJECT).unwrap();          // safe
let mut sink = BIO_new(BIO_s_null().unwrap()).unwrap();        // safe
ASN1_STRING_print_ex(&mut sink.as_mut(), s.as_ref(), DUMP_ALL_DER as _);  // safe
```

`ASN1_STRING_type_new(string_type: c_int)` (`asn1/asn1_lib.rs:206`) forwards the
tag to C unvalidated, so safe code can allocate a 24-byte `asn1_string_st`
whose `type` field claims `V_ASN1_OBJECT`. `ASN1_STRING_print_ex` takes `flags`
as a bare `c_ulong` (`asn1/a_strex.rs:18`) and likewise forwards it.

With `ASN1_STRFLGS_DUMP_DER` set, `do_dump` re-labels the string as an
`ASN1_TYPE` and asks the DER encoder to encode it under its own tag
(`crypto/asn1/a_strex.c`):

```c
    t.type = str->type;
    t.value.ptr = (char *)str;
    der_len = i2d_ASN1_TYPE(&t, NULL);          /* a_strex.c:291 */
```

and the encoder believes the tag (`crypto/asn1/tasn_enc.c`):

```c
    switch (utype) {
    case V_ASN1_OBJECT:
        otmp = (ASN1_OBJECT *)*pval;
        cont = otmp->data;                      /* tasn_enc.c:554 */
        len = otmp->length;
```

`ASN1_OBJECT::data` sits at offset 24; `sizeof(asn1_string_st)` is 24
(`int length; int type; unsigned char *data; long flags;`). The load is
therefore entirely outside the allocation.

The crate elsewhere knows this distinction is load-bearing —
`Asn1TypeKind::holds_string` (`asn1/openssl_asn1.rs`) deliberately excludes
`Object` from the tags whose payload is an `asn1_string_st`, with a doc comment
explaining that `V_ASN1_OBJECT` holds an `ASN1_OBJECT` instead. The `Asn1Type`
wrapper enforces it; `ASN1_STRING_type_new` does not, and nothing connects the
two.

## The reproduction

`crustify/audit/tmp/strex-object-confusion/`, `#![forbid(unsafe_code)]`.
Build/run instructions for the ASan configuration are in its `README.md`.

```
$ ASAN_OPTIONS=detect_leaks=0 ./target-asan/x86_64-unknown-linux-gnu/debug/strex-object-confusion
=================================================================
==3621002==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x6e6b741e00b8 at pc 0x5bae4386c7d3 ...
READ of size 8 at 0x6e6b741e00b8 thread T0
    #0 asn1_ex_i2c            crypto/asn1/tasn_enc.c:554
    #1 asn1_i2d_ex_primitive  crypto/asn1/tasn_enc.c:469
    #2 ASN1_item_ex_i2d       crypto/asn1/tasn_enc.c:98
    #3 asn1_item_flags_i2d    crypto/asn1/tasn_enc.c:73
    #4 do_print_ex            crypto/asn1/a_strex.c:291
    #5 libcrypto::asn1::a_strex::ASN1_STRING_print_ex   src/asn1/a_strex.rs:25
    #6 strex_object_confusion::main                     src/main.rs:25

0x6e6b741e00b8 is located 0 bytes after 24-byte region [0x6e6b741e00a0,0x6e6b741e00b8)
allocated by thread T0 here:
    #1 CRYPTO_zalloc          crypto/mem.c:230
    #2 ASN1_STRING_type_new   crypto/asn1/asn1_lib.c:413
    #3 libcrypto::asn1::asn1_lib::ASN1_STRING_type_new  src/asn1/asn1_lib.rs:209

SUMMARY: AddressSanitizer: heap-buffer-overflow
```

Deterministic: **20/20**.

Instrument: AddressSanitizer. `libcrypto.a` from
`CC=clang ./Configure linux-x86_64-clang no-deprecated enable-asan` out of tree
in `/tmp/osrc-clang`; Rust side built with nightly `-Zsanitizer=address`
(`clang 19.1.7`, `rustc nightly`). The stack frames above were resolved with
`addr2line` against the binary.

**The tree's own UBSan build does not catch this.** Against
`/work/openssl/libcrypto.a` (`enable-ubsan`) the same program prints
`ASN1_STRING_print_ex -> -1` and exits 0, because UBSan does not instrument
heap bounds. That is worth knowing: this class of bug is invisible to the
project's configured sanitizer and needs an ASan build to see.

## Scope: exactly four cells

`crustify/audit/tmp/probe/src/bin/strex.rs` (also `#![forbid(unsafe_code)]`)
runs `ASN1_STRING_print_ex` over string types `-10..=40` x eight flag words
x {empty, filled}, one call per process — 816 cells. Four fail, all of them
`type == 6` (`V_ASN1_OBJECT`) with `ASN1_STRFLGS_DUMP_DER` set:

```
  FAIL type=6    flags=DUMP_ALL|DUMP_DER      fill=0
  FAIL type=6    flags=DUMP_ALL|DUMP_DER      fill=1
  FAIL type=6    flags=DUMP_UNKNOWN|DUMP_DER  fill=0
  FAIL type=6    flags=DUMP_UNKNOWN|DUMP_DER  fill=1
```

No other tag reaches an out-of-bounds access, because every other arm of
`asn1_ex_i2c`'s switch either treats the payload as the `ASN1_STRING` it really
is (the `default:` arm, plus `BIT_STRING`), reads nothing (`NULL`), bails
(`UNDEF`), or reads within the caller's stack `ASN1_TYPE` (`BOOLEAN`).

## How bad is it

An 8-byte out-of-bounds **read** whose value is then discarded, in this
configuration. Immediately after the load, C checks
`if (cont == NULL || len == 0) return -1;` — and `len` comes from
`otmp->length` at offset 20, which overlays the top half of `asn1_string_st`'s
`long flags`. Every flag OpenSSL defines is below `2^32` and I found no safe
path that sets a higher bit, so `len` reads as 0 and the encoder bails before
using `cont`.

That bound is a property of the current layout, not a guarantee:

- Were `len` ever nonzero, C would go on to hex-dump `len` bytes from the wild
  `cont` pointer into the caller's BIO — a heap-memory disclosure primitive.
  The only thing preventing it is that the four bytes at offset 20 happen to be
  zero.
- Even as a discarded read, it faults if the 24-byte allocation ends a page,
  which a hardened allocator (or ASan itself, as here) makes likely.

I am not claiming a disclosure primitive; I am reporting the out-of-bounds read
I demonstrated, and noting that the field that keeps it harmless is not
something the code checks on purpose.

## Whose bug is this

OpenSSL's, and reachable from plain C with no Rust involved:

```c
ASN1_STRING *s = ASN1_STRING_type_new(V_ASN1_OBJECT);
BIO *b = BIO_new(BIO_s_null());
ASN1_STRING_print_ex(b, s, ASN1_STRFLGS_DUMP_ALL | ASN1_STRFLGS_DUMP_DER);
```
```
$ clang -fsanitize=address -fno-sanitize-link-runtime -I include -o /tmp/cstrex /tmp/cstrex.c \
      libcrypto.a $RUSTC_ASAN_RT -ldl -lpthread -lrt -lm -lstdc++ && /tmp/cstrex
==3621509==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x799364fe0058
READ of size 8 at 0x799364fe0058 thread T0
```

C's defence would be that an `ASN1_STRING` tagged `V_ASN1_OBJECT` is a
malformed object and the caller made it. But `ASN1_STRING_type_new` is public
API that accepts any `int` without complaint, so C hands out the malformed
object itself.

For this crate the conclusion is the same either way: two safe `pub fn`s, no
`unsafe`, no documented precondition on either the tag or the flag word, and a
heap-buffer-overflow at the end of it.

## The counter-argument I could not make stick

1. *A caller would never tag a string `V_ASN1_OBJECT`.* `ASN1_STRING_type_new`
   exists precisely to choose a tag, its parameter is `c_int`, and `6` is a
   perfectly ordinary universal tag. Nothing in the crate's docs marks it as
   forbidden — while `openssl_asn1.rs` documents at length that
   `V_ASN1_OBJECT` payloads are *not* strings, which is an argument that the
   crate should have caught this, not that a caller should have.
2. *`DUMP_DER` is an exotic flag.* It is one of the documented
   `ASN1_STRFLGS_*` bits and part of `XN_FLAG_RFC2253`-style presets that real
   code passes wholesale.
3. *The read is discarded, so it is not really UB.* It is a load from outside a
   live allocation. ASan reports it; on a page boundary it segfaults.
4. *`ASN1_STRING_print_ex` should be `unsafe`, so this is by design.* It is
   not marked `unsafe` and carries no `# Safety` section.

## Suggested fixes

**In the wrapper (non-breaking, and the smaller change).** Reject the
inconsistent pair at whichever end suits the maintainers:

- `ASN1_STRING_type_new`: refuse the tags whose payload is not an
  `asn1_string_st`. The predicate already exists in this crate —
  `Asn1TypeKind::from_raw(string_type).holds_string()` — so this is
  `if !Asn1TypeKind::from_raw(string_type).holds_string() { return None; }`,
  reusing the module that already reasons about exactly this distinction. It
  also closes the same hole for any future consumer of a mis-tagged string,
  not just the printer.
- or `ASN1_STRING_print_ex`: return `-1` when
  `ASN1_STRFLGS_DUMP_DER` is set and `ASN1_STRING_type(string)` is not
  `holds_string()`. Narrower, but only fixes the one call site.

I would do the first. Returning `None` from `ASN1_STRING_type_new` for a
non-string tag loses nothing a caller could legitimately want, since the
resulting object is unusable as either a string or an object.

**Upstream C.** `asn1_ex_i2c`'s `V_ASN1_OBJECT` arm trusts a tag that
`do_dump` copied out of an `ASN1_STRING`. The cheap fix is in `do_dump`: refuse
to build the temporary `ASN1_TYPE` when `str->type` names a tag whose payload is
not an `ASN1_STRING` (`V_ASN1_OBJECT`, `V_ASN1_BOOLEAN`, `V_ASN1_NULL`,
`V_ASN1_ANY`), and fall back to the content-octet dump. Having
`ASN1_STRING_type_new` reject those tags outright would be the deeper fix and
may be too incompatible for OpenSSL to take.

## What I did not check

- `ASN1_STRING_print_ex_fp`, the `FILE *` variant. It routes through the same
  `do_print_ex`, so I expect it to be affected identically, but I could not
  test it: `IoFileMut` has no safe constructor in this workspace, so the fp
  wrapper is not reachable from safe Rust at all.
- Whether a mis-tagged string can be smuggled into any *other* C consumer that
  switches on `type`. `ASN1_STRING_cmp`, `ASN1_STRING_dup`,
  `ASN1_STRING_to_UTF8`, `ASN1_STRING_print` and the whole `set`/`set1_data`
  family are clean for tag 6 (they were exercised across all tags in
  `probe/src/bin/sweep.rs` under ASan), but the wrapped surface is not the whole
  library.
- Whether `otmp->length` can be made nonzero by any route, which is what
  separates this from a disclosure primitive. I convinced myself it cannot
  through the wrapped API; I did not prove it for libcrypto as a whole.
- Non-x86-64 layouts. The offsets that make `data` land outside the allocation
  are LP64-specific; on ILP32 the struct sizes differ and the overlap may not.

## Cleared while looking at this

- Every other string tag in `-10..=40` under eight flag words, empty and
  filled: clean.
- `ASN1_STRING_print` (`asn1/a_print.rs`) — no flag word, never reaches
  `do_dump`. Clean for tag 6.
- `ASN1_STRING_to_UTF8` on a tag-6 string: returns an error rather than
  mis-reading. Clean.

## Remediation

Fixed on `crustify/orchestrator/ub-remediation` by `589b6078ec`. Both safe
constructors that accept a caller-selected tag now require
`Asn1TypeKind::holds_string()` before entering C, so neither an owned nor a
borrowed header can claim an `ASN1_OBJECT`, Boolean, NULL, ANY, or UNDEF payload.
Focused constructor tests cover every rejected representation class.

The remediation-aware ASan reproduction ran against the original instrumented
libcrypto build and exited 0 with
`blocked: ASN1_STRING_type_new rejected V_ASN1_OBJECT`; no sanitizer diagnostic
was emitted. The complete Rust workspace tests, formatting, warnings-denied
clippy, and the seeded deterministic unsafe scan also passed.
