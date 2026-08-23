# Lead: `BIO_dup_chain` copies `num` and `shutdown` into a second owner

**Status: CONFIRMED -> [`advisories/bio-dup-chain-double-close.md`](../advisories/bio-dup-chain-double-close.md)**

## How I got here

Reading `bio/bio_lib.rs` for lifetime smells, the doc comment on `BIO_dup_chain`
volunteers its own hazard (`bio_lib.rs:989`): the duplicate keeps the source's
`num` and `shutdown`, so "for a descriptor-backed method with `shutdown` set,
source and duplicate each close the same descriptor when released". The comment
concludes the hazard "belongs to C" and "this wrapper cannot remove" it.

That conclusion is what I went after. It only holds if the Rust layer never
claimed descriptor ownership — but `BIO_new_fd` takes `OwnedFd` by value and
`BIO_new_socket` takes `BioSocket` by value, and both pass `BIO_CLOSE`. So this
crate *is* the layer that made the claim, and `BIO_dup_chain` is a safe `pub fn`
that hands out a second owner.

## What made it work

- A single BIO is a one-node chain, so no `unsafe` `BIO_push` is needed to reach
  `BIO_dup_chain` — `BIO_new_fd` alone gives a valid source.
- `fd_ctrl` answers `BIO_CTRL_DUP` with 1 (`crypto/bio/bss_fd.c`), so
  `BIO_dup_state` succeeds and the dup is not rejected. Same for `bss_sock.c`,
  `bss_dgram.c`, `bss_mem.c`, `bss_file.c`, `bss_null.c`.
- The borrow checker does not help: `BioChain<'a>` constrains drop *order*, not
  the number of owners.

## Evidence

`crustify/audit/tmp/dup-chain-fd/`, `#![forbid(unsafe_code)]`, 20/20 deterministic
abort with std's `IO Safety violation: owned file descriptor already closed`.

## What would change my mind

If `BIO_dup_chain` were made `unsafe fn`, or if it rejected descriptor-backed
sources, the safe path disappears. Nothing else does: making `BioChain` non-`Drop`
or re-parenting the lifetime does not remove the second `close()`.
