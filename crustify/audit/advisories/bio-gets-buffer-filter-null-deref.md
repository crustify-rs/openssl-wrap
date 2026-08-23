# `BIO_gets` on an unchained `BIO_f_buffer` BIO dereferences NULL

**Crate:** `libcrypto` 0.1.0 (`/work/openssl/crustify/rust/libcrypto`), branch
`crustify/libcrypto-gpt-5.6-sol`, code tip `eab7392e15`.
**Affected safe functions:** `bio::bio_lib::BIO_gets` applied to a BIO built by
`bio::bio_lib::BIO_new(bio::bf_buff::BIO_f_buffer())`.
**Root cause:** OpenSSL C — `buffer_gets` in `crypto/bio/bf_buff.c` is missing
the `b->next_bio == NULL` guard that its sibling methods have. See
*Whose bug is this* below; it is reachable from this crate's safe API, so the
crate is unsound as it stands.
**Lead note:** [`notes/filter-bio-unchained-matrix.md`](../notes/filter-bio-unchained-matrix.md)

## The path from safe code

Two safe calls, no `unsafe` in the caller:

```rust
let mut bio = BIO_new(BIO_f_buffer()).unwrap();   // safe
let mut line = [0u8; 32];
BIO_gets(bio.as_mut(), &mut line);                // safe -> reads *(NULL + 0x28)
```

`BIO_f_buffer()` returns a *filter* method. `BIO_new` on a filter leaves
`bio->next_bio == NULL` — that is the normal, intended state of a freshly
constructed filter, before anything is chained behind it, and the crate has no
way to reach any other state anyway (`BIO_push` is correctly `unsafe`).

`BIO_gets` dispatches to `buffer_gets`, which — unlike `buffer_read` and
`buffer_write` — does not check `next_bio`:

```c
/* crypto/bio/bf_buff.c */
static int buffer_read(BIO *b, char *out, int outl)
{
    ...
    if ((ctx == NULL) || (b->next_bio == NULL))     /* guard present */
        return 0;

static int buffer_write(BIO *b, const char *in, int inl)
{
    ...
    if ((ctx == NULL) || (b->next_bio == NULL))     /* guard present */
        return 0;

static int buffer_gets(BIO *b, char *buf, int size)
{
    BIO_F_BUFFER_CTX *ctx;
    ...
    ctx = (BIO_F_BUFFER_CTX *)b->ptr;               /* no next_bio guard */
    size--;
    BIO_clear_retry_flags(b);
    for (;;) {
        if (ctx->ibuf_len > 0) { ... } else {
            i = BIO_read(b->next_bio, ctx->ibuf, ctx->ibuf_size);   /* NULL: returns -1 */
            if (i <= 0) {
                BIO_copy_next_retry(b);                             /* <-- here */
```

and `BIO_copy_next_retry` (`crypto/bio/bio_lib.c:938`) dereferences it
unconditionally:

```c
void BIO_copy_next_retry(BIO *b)
{
    BIO_set_flags(b, BIO_get_retry_flags(b->next_bio));   /* BIO_test_flags(NULL, ..) */
    b->retry_reason = b->next_bio->retry_reason;
}

int BIO_test_flags(const BIO *b, int flags)
{
    return (b->flags & flags);                            /* bio_lib.c:211 */
}
```

## The reproduction

`crustify/audit/tmp/buffer-gets-null/` — a cargo crate depending on the audited
`libcrypto` by path; `src/main.rs` starts with `#![forbid(unsafe_code)]`, so the
compiler proves the caller writes no `unsafe`.

### Instrument 1 — UndefinedBehaviorSanitizer (the tree's own C build)

`libcrypto.a` as configured by `crustify/build.json`:
`./Configure no-deprecated enable-ubsan --strict-warnings`. OpenSSL's
`enable-ubsan` implies `-fno-sanitize-recover`, so this aborts the process.

```
$ cd /work/openssl/crustify/audit/tmp/buffer-gets-null
$ cargo build && UBSAN_OPTIONS=print_stacktrace=1 ./target/debug/buffer-gets-null
crypto/bio/bio_lib.c:211:14: runtime error: member access within null pointer of type 'const struct BIO'
    #0 0x6167a891c3ce in BIO_test_flags crypto/bio/bio_lib.c:211
    #1 0x6167a891efbe in BIO_copy_next_retry crypto/bio/bio_lib.c:939
    #2 0x6167a891803d in buffer_gets crypto/bio/bf_buff.c:458
    #3 0x6167a891d52a in BIO_gets crypto/bio/bio_lib.c:596
    #4 0x6167a891479c in libcrypto::bio::bio_lib::BIO_gets src/bio/bio_lib.rs:316
    #5 0x6167a89144da in buffer_gets_null::main src/main.rs:16
$ echo $?
1
```

Deterministic: **20/20** runs fail.

### Instrument 2 — AddressSanitizer (clang-built libcrypto + `-Zsanitizer=address`)

`/tmp/osrc-clang` from `CC=clang ./Configure linux-x86_64-clang no-deprecated
enable-asan`; the Rust side built with nightly `-Zsanitizer=address`. This
confirms the load actually happens rather than being a UBSan-only pedantry:

```
AddressSanitizer:DEADLYSIGNAL
==3618331==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000028
                  (pc 0x556b86327515 bp .. sp .. T0)
==3618331==The signal is caused by a READ memory access.
==3618331==HINT: address points to the zero page.
```

`0x28` is `offsetof(struct bio_st, flags)`. Reproduction steps for this
configuration are in the repro directory's `README.md`.

Toolchains: `rustc 1.98.0` (instrument 1), `rustc nightly` + `clang 19.1.7`
(instrument 2).

## Scope: exactly one cell

I ran every safe BIO I/O entry point the crate exposes against every filter and
source method it exposes, one pair per process, so an abort pins one cell
(`crustify/audit/tmp/probe/src/bin/filters.rs`, also `#![forbid(unsafe_code)]`).
80 pairs: `{buffer, linebuffer, prefix, nbio_test, null_filter, readbuffer,
s_null, s_mem}` x `{gets, get_line, read, read_ex, write, write_ex, puts,
printf, eof, ctrl_pending}`.

**One fails: `buffer` x `gets`.** Every other pair returns cleanly. In
particular `linebuffer`, `prefix`, `nbio_test`, `null_filter` and `readbuffer`
are all fine unchained, and `BIO_get_line` — which is a different C entry point,
not a wrapper over `BIO_gets` — is fine on the buffer filter too. That
narrowness is itself evidence: this is a missing guard in one function, not a
systemic property of unchained filters.

## Whose bug is this

Primarily OpenSSL's. The equivalent plain-C program fails identically against
the same library, with no Rust involved:

```c
#include <openssl/bio.h>
int main(void) {
    BIO *b = BIO_new(BIO_f_buffer());
    char buf[32];
    BIO_gets(b, buf, (int)sizeof buf);
    return 0;
}
```
```
$ cc -I include -o /tmp/cbug /tmp/cbug.c libcrypto.a -lubsan -ldl -lpthread && /tmp/cbug
crypto/bio/bio_lib.c:211:14: runtime error: member access within null pointer of type 'const struct BIO'
```

That does **not** get the Rust crate off the hook. A safe `pub fn` may not
permit undefined behaviour, whoever's code the UB is executed in; and here the
crate hands the caller both halves — `BIO_new` over `BIO_f_buffer` produces the
state, `BIO_gets` consumes it — with no `unsafe` and no documented precondition
anywhere in `bio_lib.rs:307-320` or `bf_buff.rs`. Until the C is fixed, this
crate's `BIO_gets` is an unsound safe function.

I am reporting both: fix upstream, and decide separately whether the wrapper
should carry a guard so it is sound against unpatched libcrypto.

## The counter-argument I could not make stick

1. *`BIO_gets` on an unchained filter is meaningless, so callers will not do
   it.* Soundness is not about what callers intend. And it is not exotic:
   constructing a filter and reading from it before pushing a source is a
   plausible ordering mistake, and the crate cannot even express the chained
   case safely — `BIO_push` is `unsafe`, so an *unchained* filter is the only
   thing safe Rust can build.
2. *`BIO_gets` is `-2`-guarded for methods without a `bgets` slot, so the
   dispatch is checked.* It is, and `BIO_f_buffer` has a `bgets` slot, so the
   check passes and we go straight into the unguarded function.
3. *`BIO_new` on a filter yields `init == 0`, so `BIO_gets` bails early.* No:
   `buffer_new` sets `bi->init = 1`, which I confirmed by observing the call
   actually reach `buffer_gets`.
4. *UBSan is being pedantic about a member access that never loads.* Refuted by
   instrument 2: ASan reports an actual `READ` at `0x28`.

## Suggested fixes

**Upstream C (preferred, fixes every language binding).** Give `buffer_gets`
the guard its siblings already have:

```c
     ctx = (BIO_F_BUFFER_CTX *)b->ptr;
+    if ((ctx == NULL) || (b->next_bio == NULL))
+        return 0;
     size--;                     /* reserve space for a '\0' */
```

Hardening `BIO_copy_next_retry` against a NULL `next_bio` is worth doing as
well, since it is a public function that any BIO method may call, but the
missing guard in `buffer_gets` is the actual defect.

**In the wrapper (if the crate must be sound against unpatched libcrypto).**
Non-breaking: have `BIO_gets` return `-1` when the BIO's method is a filter with
no successor. Both facts are already reachable through this crate's own safe
API — `BIO_method_type(bio.as_ref()) & BIO_TYPE_FILTER` and
`BIO_next(&bio.as_ref()).is_none()` — so the check costs one branch and changes
no signature. Applying it to all of `BIO_gets`/`BIO_get_line`/`BIO_read`/
`BIO_write` uniformly would be the conservative version, and matches what the C
filters already do internally for read and write.

## What I did not check

- Whether an unchained `BIO_f_buffer` reaches `BIO_copy_next_retry` through any
  path other than `buffer_gets` — `buffer_ctrl` also calls into `next_bio` in
  places, but every `BIO_ctrl` route in this crate is `unsafe`, so I could not
  get there from safe code.
- Filter BIOs from `libssl` (out of the audited target set).
- Whether the same missing guard exists in OpenSSL releases other than this
  tree; I only tested `2924476b5591e691e904c4baf57894c526c4b8de`.
- Non-x86-64 targets.

## Cleared while looking at this

- `BIO_get_line` on the same BIO: it is a separate C function
  (`crypto/bio/bio_lib.c`), does not route through `buffer_gets`, and returns 0
  cleanly. Not affected.
- `BIO_gets`/`BIO_get_line` with a zero-length buffer: both wrappers pass the
  slice length straight through and C rejects `size <= 0` with `-1` before
  touching the pointer. The empty-slice dangling pointer is never dereferenced.
  Not a bug — and the crate has a regression test for it.
- The other five filter methods the crate exposes, unchained, across ten
  operations each. All clean.

## Remediation

Fixed on `crustify/orchestrator/ub-remediation` by `589b6078ec`. The safe
`BIO_gets` wrapper now identifies an unchained `BIO_TYPE_BUFFER` before calling
C and returns `-1`; other BIO methods and chained buffers retain their existing
behavior. A focused regression constructs the exact safe failing state.

The original UBSan workload exited 0 and printed `BIO_gets returned -1` with no
diagnostic. The complete Rust workspace tests, formatting, warnings-denied
clippy, and the seeded deterministic unsafe scan also passed.
