# Lead: an `up_ref` share and a sole owner are the same handle, so a shared
# borrow can be turned into an exclusive one

**Status: CONFIRMED ->
[`advisories/x509-up-ref-aliased-borrow-use-after-free.md`](../advisories/x509-up-ref-aliased-borrow-use-after-free.md).
This note records how the lead was found, the three C types it applies to, and
which of them I could and could not turn into a crash.**

## Where it came from

[`handle-discipline-cleared.md`](handle-discipline-cleared.md) §1 cleared
aliasing on the grounds that *no Rust reference to a wrapped C object is ever
formed*, so no handle carries a `noalias` claim. That is true, and it is not
the whole story: the crate also hands out `CSlice<'a, u8>` views over **C heap
buffers**, and those are ordinary reads. Their soundness does not depend on
Rust's aliasing model at all — it depends on nothing freeing the buffer while
`'a` is alive. §4 checked that every `'a` is tied to the borrow it came from,
which it is. What neither section checked is whether the *borrow itself* still
implies exclusivity once a second owner of the same object exists.

For a reference-counted C type it does not. `ffibox`'s README says so as a
design decision:

> where RFL splits `ARef`/`AlwaysRefCounted` from `KBox` and adds `UniqueArc`
> for the pre-publication phase, crustify collapses all three into `CBox<T>` —
> every handle reaches the object through a raw pointer, so a refcounted share
> and a sole owner are the same handle, and the up_ref is just another
> `CCloned::c_clone`.

`CBox<T>::as_mut(&mut self) -> T::Mut<'_>` is the exclusive handle. Collapsing
`ARef` into `CBox` means every refcount share can produce one.

## The three refcounted types in this crate

| type | registration | `up_ref` wrapper | safe mutator on the `Mut` handle? |
|---|---|---|---|
| `X509` | `x509/x509_internal.rs:98` `impl_cloned!(X509, up_ref = X509_up_ref)` | `x509/x509_set.rs:93` `X509_up_ref` -> `BorrowedX509<'a>` | **yes** — `X509_get_serialNumber(&mut X509Mut) -> Asn1StringMut` |
| `Bio` | `bio/bio_bio_local.rs:63` (`up_ref`, hand-written `CCloned`) | `bio/bio_lib.rs:717` `BIO_up_ref` -> `BorrowedBio<'a>` | yes — the whole `BIO_write`/`BIO_push`/... surface |
| `EvpPkey` | `evp/evp.rs:40` `impl_cloned!(EvpPkey, up_ref = EVP_PKEY_up_ref)` | `X509_get_pubkey`, `X509_PUBKEY_get` -> `CBox<EvpPkey>` | **no** — `EvpPkeyMut` has no safe mutating operation today |

`X509` is the one I crashed, because it is the one where a safe mutator and a
safe `CSlice`-yielding getter meet on the same embedded child.

## What I could not demonstrate

- **`Bio`.** The shape is identical and there are many safe mutators, but I
  could not find a safe pair *(borrow that yields a C-heap view, mutation that
  frees it)*. The only `CSlice`/`CSliceMut` producers over BIO-internal memory
  are `BIO_nread*`/`BIO_nwrite*` on a BIO pair, and the operation that frees
  the pair's buffer is `BIO_C_SET_WRITE_BUF_SIZE`, reachable only through
  `BIO_ctrl`, which is correctly an `unsafe fn`. `BIO_free` through one owner
  does not free while the other count is held. So: same defect, no crash from
  me. I would look again if `BIO_set_write_buf_size` or `BIO_reset` ever gets a
  safe wrapper.
- **`EvpPkey`.** `X509_get0_pubkey(cert)` (shared `EvpPkeyRef<'a>`) and
  `X509_get_pubkey(cert)` (an owning `CBox<EvpPkey>` on the *same* cached key)
  already coexist without any `up_ref` call in the caller, so the aliasing is
  there. There is simply nothing safe to mutate through the `Mut` handle yet.

## What would change my mind about the two undemonstrated ones

A safe wrapper for any C function that reallocates or frees storage a live
`CSlice`/child handle points into: `BIO_ctrl`'s buffer-sizing commands,
`EVP_PKEY_set1_*`, `EVP_PKEY_assign`. Each of those turns its row of the table
above into the same advisory.
