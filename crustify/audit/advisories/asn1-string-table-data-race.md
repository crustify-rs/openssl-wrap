# `ASN1_STRING_TABLE_add` is a safe fn that corrupts the heap when called from two threads

**Crate:** `libcrypto` 0.1.0 (`/work/openssl/crustify/rust/libcrypto`), branch
`crustify/libcrypto-gpt-5.6-sol`, code tip `eab7392e15`.
**Affected safe functions:** `asn1::a_strnid::ASN1_STRING_TABLE_add` and
`asn1::a_strnid::ASN1_STRING_TABLE_get`, called concurrently (either one alone
is enough).
**Class:** data race on a process-global `STACK_OF(ASN1_STRING_TABLE)`,
observed as use-after-free, double-free and heap-metadata corruption.
**Root cause:** OpenSSL C takes no lock. The crate knows — it serialises its own
tests over exactly this — but exposes both functions as safe anyway. See
*Already known*.
**Lead note:** [`notes/global-registry-thread-safety.md`](../notes/global-registry-thread-safety.md)

## The path from safe code

`ASN1_STRING_TABLE_add(nid: i32, min_size, max_size, mask, flags) -> bool`
takes **only scalars**. It holds no handle, so nothing about it is `!Send` or
`!Sync`, and nothing in its signature, its documentation or the type system
suggests it may not be called from two threads. The same is true of
`ASN1_STRING_TABLE_get(nid: i32) -> Option<Asn1StringTableValues>`.

Underneath (`crypto/asn1/a_strnid.c`), both mutate one process-global stack
with no synchronisation at all:

```c
ASN1_STRING_TABLE *ASN1_STRING_TABLE_get(int nid)
{
    ...
    if (stable != NULL) {
        /* Ideally, this would be done under lock */          /* <- OpenSSL's own comment */
        sk_ASN1_STRING_TABLE_sort(stable);                    /* in-place qsort  */
        idx = sk_ASN1_STRING_TABLE_find(stable, &fnd);        /* bsearch         */
```

```c
static ASN1_STRING_TABLE *stable_get(int nid)
{
    ...
    tmp = ASN1_STRING_TABLE_get(nid);                         /* sorts + searches */
    if (tmp != NULL && tmp->flags & STABLE_FLAGS_MALLOC) return tmp;
    if ((rv = OPENSSL_zalloc(sizeof(*rv))) == NULL) return NULL;
    if (!sk_ASN1_STRING_TABLE_push(stable, rv)) {             /* reallocs the array */
```

`grep -n 'lock\|CRYPTO_THREAD' crypto/asn1/a_strnid.c` returns exactly one hit:
the comment quoted above. A `push` that reallocates the pointer array while
another thread is sorting or bsearching that same array is a data race on both
the array pointer and its contents.

## The reproduction

`crustify/audit/tmp/string-table-race/`, `#![forbid(unsafe_code)]`. The racing
section contains a single libcrypto call:

```rust
std::thread::spawn(move || {
    barrier.wait();
    loop {
        let i = cursor.fetch_add(1, Ordering::Relaxed);
        if i >= nids.len() { break; }
        let _ = ASN1_STRING_TABLE_add(nids[i], 0, 8, MASK as _, 0);   // safe
    }
})
```

The NIDs are registered single-threaded up front with `OBJ_create`, so only the
string table — not the object registry — is under contention, and every NID's
first `_add` takes the `push` path.

### Instrument 1 — AddressSanitizer

`/tmp/osrc-clang` (`CC=clang ./Configure linux-x86_64-clang no-deprecated
enable-asan`) plus nightly `-Zsanitizer=address`. **0 of 10 runs survive**:
9 double-free, 1 heap-use-after-free.

```
==3626731==ERROR: AddressSanitizer: heap-use-after-free on address 0x754a5fee90d0
READ of size 8 at 0x754a5fee90d0 thread T1
    #0 sk_table_cmp                        crypto/asn1/a_strnid.c:114
    #1 ossl_bsearch                        crypto/bsearch.c:31
    #2 internal_find                       crypto/stack/stack.c:409
    #3 ASN1_STRING_TABLE_get               crypto/asn1/a_strnid.c:145
    #4 ASN1_STRING_TABLE_add               crypto/asn1/a_strnid.c:167
    #5 libcrypto::asn1::a_strnid::ASN1_STRING_TABLE_add   src/a_strnid.rs:21
    #6 string_table_race::main::{closure#2}::{closure#0}  src/main.rs:71

0x754a5fee90d0 is located 16 bytes inside of 32-byte region [0x754a5fee90c0,0x754a5fee90e0)
freed by thread T9 here:
    #1 CRYPTO_realloc                      crypto/mem.c:303
    #2 sk_reserve                          crypto/stack/stack.c:212
    #3 OPENSSL_sk_insert                   crypto/stack/stack.c:296
    #4 ASN1_STRING_TABLE_add               crypto/asn1/a_strnid.c:172
    #5 libcrypto::asn1::a_strnid::ASN1_STRING_TABLE_add   src/a_strnid.rs:21

previously allocated by thread T3 here:
    #1 CRYPTO_zalloc                       crypto/mem.c:230
    #2 sk_reserve                          crypto/stack/stack.c:194
    #3 OPENSSL_sk_insert                   crypto/stack/stack.c:296
    #4 ASN1_STRING_TABLE_add               crypto/asn1/a_strnid.c:172
    #5 libcrypto::asn1::a_strnid::ASN1_STRING_TABLE_add   src/a_strnid.rs:21

SUMMARY: AddressSanitizer: heap-use-after-free
```

Both the reading thread and the freeing thread bottom out in the audited
crate's own safe wrapper at `src/asn1/a_strnid.rs:21`.

### Instrument 2 — the tree's own C build, no sanitizer beyond UBSan

Against `/work/openssl/libcrypto.a` (`enable-ubsan`), **10 of 10 runs die**:

```
  run 1  exit=139  Segmentation fault
  run 2  exit=1    crypto/asn1/a_strnid.c:114:28: runtime error: member access within null pointer of type 'const struct ASN1_STRING_TABLE'
  run 3  exit=134  realloc(): invalid next size
  run 4  exit=1    crypto/asn1/a_strnid.c:114:16: runtime error: member access within null pointer ...
  run 5  exit=139  Segmentation fault
  run 6  exit=134  Fatal glibc error: malloc assertion failure in sysmalloc: (old_top == initial_top (av) && old_size == 0) || ...
  run 7  exit=139  Fatal glibc error: malloc assertion failure in sysmalloc: ...
  run 8  exit=139  Fatal glibc error: malloc assertion failure in __libc_realloc: !newp || chunk_is_mmapped ...
  run 9  exit=139  Segmentation fault
  run 10 exit=139  Segmentation fault
```

`realloc(): invalid next size` and the `sysmalloc`/`__libc_realloc` assertions
are **glibc's own heap-consistency checks**. This is not an abstract race that
only a sanitizer minds: the allocator's metadata is being corrupted.

Toolchains: `rustc 1.98.0` (instrument 2), `rustc nightly` + `clang 19.1.7`
(instrument 1). I did not use ThreadSanitizer — OpenSSL has no `enable-tsan` in
this tree and building with `-fsanitize=thread` by hand fails on a missing
`sanitizer/tsan_interface.h`. ASan and glibc were enough.

## Already known — but only half-acted-on

The crate's test module says so outright (`asn1/a_strnid.rs:48`):

```rust
/// OpenSSL sorts and mutates the process-global ASN.1 string table without
/// holding a lock, so every test that reaches it runs one at a time.
#[cfg(test)]
static STRING_TABLE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
```

and `ASN1_STRING_TABLE_cleanup` is correctly `unsafe fn` with

> `# Safety` — No C code may concurrently access the process-global ASN.1
> string table.

So the hazard was identified, a mutex was written for the tests, and the
`cleanup` entry point was gated. `add` and `get` — the two functions that
*create* the hazard — were left safe with no note. That is the gap, and it is
the kind that survives review precisely because the surrounding code looks like
it has been thought about.

I found nothing in `SECURITY.md`, the notes directory or `wrappers-results.md`
treating it as an open defect.

## The counter-argument I could not make stick

1. *The handles are `!Send`, so the crate is single-threaded by construction.*
   True for everything that carries a handle — and irrelevant here. These two
   functions take `i32` and `c_long`; there is no handle to be `!Send`.
   `thread::spawn` accepts the closure without complaint.
2. *A caller should know libcrypto globals need external locking.* Then say so
   in the signature. `ASN1_STRING_TABLE_cleanup` in the very same file does
   exactly that. Safe/`unsafe` is how Rust states this, and the crate uses it
   correctly one function away.
3. *You have to hammer it to see it.* 10/10 at 16 threads over 3000 NIDs, and
   1/10 even in my first crude version at 16 threads over 64 NIDs. It is not a
   one-in-a-million interleaving.
4. *This is only about a table nobody populates.* `ASN1_STRING_TABLE_add` is
   the documented way to constrain a custom attribute type, and OpenSSL's own
   config loader calls into the same table. A server that registers custom OIDs
   during a concurrent startup is the ordinary case, not a contrived one.

## Suggested fix

**In the wrapper, non-breaking.** Serialise both entry points behind a
crate-level mutex — the same one the test module already has, promoted out of
`#[cfg(test)]`:

```rust
static STRING_TABLE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub fn ASN1_STRING_TABLE_add(..) -> bool {
    let _guard = STRING_TABLE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // SAFETY: ... and the lock excludes every other safe wrapper that mutates
    // the process-global table.
    unsafe { ffi::ASN1_STRING_TABLE_add(..) == 1 }
}
```

applied to `ASN1_STRING_TABLE_add`, `ASN1_STRING_TABLE_get` and
`ASN1_STRING_set_by_NID` / `ASN1_STRING_set_by_NID_into` (both reach
`ASN1_STRING_TABLE_get` through `ASN1_mbstring_ncopy`). This is exactly the
pattern the crate already uses for `BIO_gethostbyname`'s static `hostent`
(`HOST_LOOKUP_LOCK` in `openssl_bio.rs`), so it is consistent with the crate's
own precedent.

It is honest about its limit and the limit should be documented: the mutex
excludes other *Rust* callers, not C code in the same process reaching the
table by another route. `ASN1_STRING_TABLE_cleanup`'s `# Safety` note already
draws that distinction and should be cross-referenced.

**Upstream C.** Give `stable` a `CRYPTO_RWLOCK`, as `crypto/objects/obj_xref.c`
does for `sig_app`/`sigx_app` with `sig_lock`. The in-place sort inside a
notionally-read-only getter is the awkward part; the usual fix is to keep the
stack sorted on insert instead. That is a larger change and the wrapper should
not wait for it.

## What I did not check

- **The other process-global registries.** `OBJ_create`, `OBJ_add_object`,
  `OBJ_new_nid`, `OBJ_add_sigid` and `OBJ_NAME_new_index` are all safe and all
  scalar/borrow-only, so they are all callable concurrently. `obj_xref.c` does
  take `sig_lock`, and `OBJ_NAME_do_all` was correctly marked `unsafe` for the
  unlocked-traversal reason — but I only *tested* the ASN.1 string table. See
  [`notes/global-registry-thread-safety.md`](../notes/global-registry-thread-safety.md)
  for what is and is not covered; this is the largest thing I am leaving open.
- Whether the race can be steered into a controlled write rather than a
  crash. I observed use-after-free, double-free and allocator-metadata
  corruption; I did not try to exploit any of them.
- Any target other than x86-64 Linux/glibc.

## Cleared while looking at this

- `ASN1_STRING_TABLE_add`'s own argument validation: it refuses `nid <= 0` and
  an inverted `minsize > maxsize` range, and the wrapper's tests cover both.
  Single-threaded, the whole `a_strnid` surface is clean — I swept it over
  adversarial masks, flags and size ranges under both ASan and UBSan
  (`tmp/probe/src/bin/sweep.rs`, section `table`) with no diagnostic.
- `sk_table_cmp` / `table_cmp` use the same `a->nid - b->nid` subtraction as the
  [obj_xref comparators](obj-sigid-comparator-signed-overflow.md), but both C
  entry points reject `nid <= 0` before the search, so the overflow is not
  reachable here.
