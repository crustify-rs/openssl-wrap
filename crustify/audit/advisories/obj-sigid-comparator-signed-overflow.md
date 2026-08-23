# `OBJ_find_sigid_*` / `OBJ_add_sigid` let safe code overflow a C comparator

**Crate:** `libcrypto` 0.1.0 (`/work/openssl/crustify/rust/libcrypto`), branch
`crustify/libcrypto-gpt-5.6-sol`, code tip `eab7392e15`.
**Affected safe functions:** `objects::obj_xref::OBJ_find_sigid_algs`,
`objects::obj_xref::OBJ_find_sigid_by_algs`, `objects::obj_xref::OBJ_add_sigid`.
**Root cause:** OpenSSL C — the subtraction comparators `sig_cmp` and
`sigx_cmp` in `crypto/objects/obj_xref.c`. Reachable from this crate's safe API
with an ordinary `i32` argument.
**Severity:** signed-overflow UB, not memory corruption. See *What the damage
actually is*.
**Lead note:** [`notes/nid-argument-ranges.md`](../notes/nid-argument-ranges.md)

## The path from safe code

One safe call, no `unsafe` in the caller:

```rust
OBJ_find_sigid_algs(i32::MIN);
```

The wrapper (`objects/obj_xref.rs:9`) takes a bare `i32` and forwards it
unchanged. C then binary-searches the static signature table with:

```c
/* crypto/objects/obj_xref.c */
static int sig_cmp(const nid_triple *a, const nid_triple *b)
{
    return a->sign_id - b->sign_id;                 /* line 21 */
}

static int sigx_cmp(const nid_triple *const *a, const nid_triple *const *b)
{
    int ret;
    ret = (*a)->hash_id - (*b)->hash_id;            /* line 38 */
    ...
    return (*a)->pkey_id - (*b)->pkey_id;
}
```

`INT_MIN - 942` is not representable, which is undefined behaviour in C.

## The reproduction

`crustify/audit/tmp/sigid-overflow/`, `#![forbid(unsafe_code)]`:

```
$ cd /work/openssl/crustify/audit/tmp/sigid-overflow
$ cargo build && UBSAN_OPTIONS=print_stacktrace=1 ./target/debug/sigid-overflow
crypto/objects/obj_xref.c:21:23: runtime error: signed integer overflow: -2147483648 - 942 cannot be represented in type 'int'
    #0 0x61edd3f7e3d6 in sig_cmp crypto/objects/obj_xref.c:21
    #1 0x61edd3f7e3d6 in sig_cmp_BSEARCH_CMP_FN crypto/objects/obj_xref.c:25
    #2 0x61edd3f7dd19 in ossl_bsearch crypto/bsearch.c:33
    #3 0x61edd3f7b7b1 in OBJ_bsearch_ex_ crypto/objects/obj_dat.c:609
    #4 0x61edd3f7e74b in OBJ_bsearch_sig crypto/objects/obj_xref.c:25
    #5 0x61edd3f7e74b in ossl_obj_find_sigid_algs crypto/objects/obj_xref.c:77
    #6 0x61edd3f7e74b in OBJ_find_sigid_algs crypto/objects/obj_xref.c:105
$ echo $?
1
```

Deterministic: **20/20**.

Instrument: UndefinedBehaviorSanitizer, in the tree's own canonical C build
(`crustify/build.json`: `./Configure no-deprecated enable-ubsan
--strict-warnings`). OpenSSL's `enable-ubsan` implies `-fno-sanitize-recover`,
so the process aborts on the diagnostic. `rustc 1.98.0`.

AddressSanitizer has nothing to say about this one — integer overflow is not a
memory error — so unlike the `buffer_gets` finding there is only one instrument
here.

## Scope

`crustify/audit/tmp/probe/src/bin/sigid.rs` runs each of the three safe entry
points over `{INT_MIN, INT_MIN+1, -1, 0, 1, 8, 65, INT_MAX}`, one call per
process. All three trigger:

| entry point | comparator | trips when |
|---|---|---|
| `OBJ_find_sigid_algs(nid)` | `sig_cmp`, line 21 | `nid < INT_MIN + 942` |
| `OBJ_find_sigid_by_algs(digest, pkey)` | `sigx_cmp`, line 38 | `digest < INT_MIN + 674` |
| `OBJ_add_sigid(sig, digest, pkey)` | `sig_cmp`, line 21 | `sig < INT_MIN + 942` |

(942 and 674 are the largest `sign_id` / `hash_id` the static table happens to
contain, so the exact thresholds are table-dependent; the class is not.)

No other NID value in the sample trips anything, and `OBJ_nid2obj`,
`OBJ_nid2sn`, `OBJ_nid2ln` are clean across the same range — they compare with
`<`/`>` rather than by subtraction.

## What the damage actually is

Be clear-eyed about this one. It is real UB, and it is reachable with no
`unsafe`, but it is not a memory-safety hole:

- On every compiler in practical use the subtraction wraps, so the comparator
  returns a wrong sign. `ossl_bsearch` (`crypto/bsearch.c`) computes its index
  as `(l + h) / 2` with `l`/`h` derived from the element count, never from the
  comparator's return value, so a wrong sign yields a wrong or absent match —
  never an out-of-bounds access. I checked `ossl_bsearch` specifically for this.
- The concrete impact in a UBSan-hardened build — which is how this tree is
  configured, and how a number of distribution and CI builds are configured —
  is an `abort()`. If the NID reaches the call from attacker-influenced input,
  that is a remote denial of service.
- In a normal build, the impact is a silently wrong lookup result.

I would rank this below the other two advisories in this directory. It is here
because it is demonstrable UB from a safe `pub fn`, not because I think it will
corrupt anything.

## The counter-argument I could not make stick

1. *No real caller passes `i32::MIN` as a NID.* Maybe not deliberately — but
   the wrapper's parameter is `i32` with no documented range, and NIDs do flow
   from `OBJ_txt2nid`/`OBJ_sn2nid` (which return `0` for unknown) and from
   application configuration. A safe function that is UB for part of its
   declared input domain is unsound regardless of how the value arrives.
2. *Signed overflow is benign in practice, so it does not count.* It counts
   under the standard, UBSan reports it, and this tree's own canonical build
   turns it into an abort. "Benign in practice" is exactly the reasoning
   `-fno-sanitize-recover` exists to reject.
3. *The wrapper could not know.* It could: the C comparator is in the audited
   tree, three lines long.

## Suggested fixes

**Upstream C (preferred).** Replace the subtractions with comparisons, which is
what the rest of `crypto/objects` already does:

```c
static int sig_cmp(const nid_triple *a, const nid_triple *b)
{
    return (a->sign_id > b->sign_id) - (a->sign_id < b->sign_id);
}
```
and likewise for both subtractions in `sigx_cmp`.

**In the wrapper.** Non-breaking: reject non-positive NIDs before the call.
`NID_undef` is `0` and every registered NID is positive, so
`if (nid <= 0) { return None; }` in `OBJ_find_sigid_algs` /
`OBJ_find_sigid_by_algs`, and the same for each argument of `OBJ_add_sigid`,
changes no signature and loses no functionality. This is the same shape of
guard `ASN1_STRING_TABLE_add` already applies ("A non-positive NID ... is
refused"), so it is consistent with the crate's existing style.

A `NonZeroI32`-or-newtype NID type would be the thorough fix, but it is a
breaking change across the whole `objects` module and I would not start there.

## What I did not check

- Whether the same subtraction pattern exists in comparators outside
  `crypto/objects/obj_xref.c`. `obj_dat.c`'s own comparators use `<`/`>` and I
  swept `OBJ_nid2*` / `OBJ_txt2*` / `OBJ_obj2*` clean, but I did not audit
  every comparator in the tree.
- Whether `OBJ_add_sigid` leaves the process-global cross-reference stack in a
  usable state after aborting mid-`bsearch`; the process is dead at that point,
  so it did not seem worth chasing.
- The `sigx_cmp` `pkey_id` subtraction (line 47) in isolation — the `hash_id`
  one at line 38 fires first and aborts, masking it. It is the same defect.

## Cleared while looking at this

- `OBJ_bsearch_` / `OBJ_bsearch_ex_` (`objects/obj_dat.rs:37,66`): the wrapper
  validates the returned pointer back into the caller's slice — in range,
  correctly aligned, correct stride — before handing out a `&'a T`. That is
  more defensive than C, and it holds even if a comparator misbehaves. Not a
  bug.
- `ossl_bsearch` index arithmetic: bounded by the element count, independent of
  the comparator's return value. A wrong comparator gives a wrong answer, not
  an out-of-bounds read.
