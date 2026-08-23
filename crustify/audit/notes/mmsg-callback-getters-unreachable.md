# Lead: `BIO_meth_get_*` + `Callback::call` is a type-confusion hole that safe
# code currently cannot reach

**Status: NOT reachable from safe code today. No advisory. Read this before
adding any safe `CSliceMut<BioMsg>` constructor or enabling `deprecated-3-5`.**

## The shape

`bio/bio_meth.rs` gives each BIO method-slot callback a handle type whose
`from_raw` is `unsafe` (good) but whose `call` is **safe**:

```rust
impl BioMethodReadCallback {
    pub fn call(self, mut bio: BioMut<'_>, buffer: &mut [u8]) -> i32 { ... }
}
```

`call` takes an arbitrary `BioMut`. Nothing ties the callback to a BIO created
from *its own* method. The `from_raw` safety contract says the callback "must
obey OpenSSL's argument, buffer, return-value, unwinding, and thread-safety
requirements whenever C invokes it" — a statement about the callback's
behaviour, not about which BIO it may be applied to. The getters' SAFETY
comment ("any callback installed in a valid BIO_METHOD obeys that method slot's
static C contract") silently assumes the missing half.

Meanwhile `bio/openssl_bio.rs` has **safe** getters that mint those handles:
`BIO_meth_get_read`, `_read_ex`, `_write`, `_write_ex`, `_gets`, `_puts`,
`_ctrl`, `_create`, `_destroy`, `_callback_ctrl` (all `#[cfg(feature =
"deprecated-3-5")]`), and `BIO_meth_get_recvmmsg` / `BIO_meth_get_sendmmsg`
(**ungated**).

The attack is then obvious:

```rust
let read = BIO_meth_get_read(BIO_s_datagram().unwrap()).unwrap();  // dgram_read
let mut mem = BIO_new(BIO_s_mem().unwrap()).unwrap();              // b->ptr is a 16-byte BIO_BUF_MEM
read.call(mem.as_mut(), &mut buf);   // dgram_read casts b->ptr to bio_dgram_data*
```

`dgram_read` reads `data->next_timeout` at an offset past 256 bytes into a
16-byte allocation. Type confusion, heap-buffer-overflow, no `unsafe` anywhere.

## Why it does not fire today

Two independent blocks, and both have to stay in place:

1. **The typed getters are `deprecated-3-5`-gated, and that feature cannot be
   built against this tree's C configuration.** `crustify/build.json` configures
   `./Configure no-deprecated`, so `BIO_meth_get_read` and friends are not
   declared in `include/openssl/bio.h` and bindgen fails:
   `cargo build --features deprecated-3-5` dies in `libcrypto-sys`'s build
   script. `libcrypto-sys/build.rs` hard-codes the header search path to the
   repo root, so there is no way to point it at a deprecated-enabled build
   without editing the audited tree.
2. **The two ungated getters need a `CSliceMut<'_, BioMsg<'_>>`, which has no
   safe constructor.** `BioMethodMmsgCallback::call`, `BIO_recvmmsg` and
   `BIO_sendmmsg` all take one. In `ffibox` the only routes are
   `CSliceMut::from_raw_parts` (`unsafe`) and `CVec::as_handles_mut` — and
   `CVec::from_raw_parts` is `unsafe` too, with no safe producer of a
   `CVec<BioMsg, _>` anywhere in `libcrypto`. `BioMsg::empty`/`for_slice`
   produce a `CVal<BioMsg>`, which does not convert. I grepped every `-> ...
   CSliceMut` in the workspace to confirm: `bss_bio.rs` (u8 only) and
   `openssl_bio.rs`'s `BioMsg` accessors (u8 only). The crate's own test builds
   the slice with an explicit `unsafe` block.

So the entire multi-message surface — `BIO_recvmmsg`, `BIO_sendmmsg`,
`BioMethodMmsgCallback::call` — is currently dead from safe code. That is an
API-completeness gap, not a soundness bug, but it is the only thing standing
between this crate and the type confusion above.

## What to do about it

The right fix does not depend on which block is removed first: give the
callback handles a `call` that cannot be applied to a foreign BIO. Options,
roughly in order of how much they change:

- Make `call` `unsafe fn`, with the contract "`bio`'s method must be the
  `BIO_METHOD` this callback was read from". Smallest change, honest.
- Tag the handle with the method it came from (`BioMethodReadCallback<'m>` plus
  a runtime `BIO_method_type` check in `call`), so the safe version stays safe.
- Drop the safe getters and keep only the setters. The getters exist to
  round-trip a method table; nothing in the wrapped C surface needs to *invoke*
  a callback fetched from a foreign method.

## What would change my mind

Nothing about the analysis — I did not demonstrate it, so it stays a note. If
either block above is lifted, this becomes an advisory-grade finding in a few
lines of test code, and the reduction is already written down here.
