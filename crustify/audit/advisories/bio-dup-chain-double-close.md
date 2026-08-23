# `BIO_dup_chain` lets safe code close one file descriptor twice

**Crate:** `libcrypto` 0.1.0 (`/work/openssl/crustify/rust/libcrypto`), branch
`crustify/libcrypto-gpt-5.6-sol`, code tip `eab7392e15`.
**Affected safe functions:** `bio::bio_lib::BIO_dup_chain`, in combination with
any descriptor-owning constructor — `bio::bss_fd::BIO_new_fd`,
`bio::bss_sock::BIO_new_socket`, `bio::bss_dgram::BIO_new_dgram` — **or** with a
chain libcrypto builds by itself from `bio::bss_acpt::BIO_new_accept` plus
`BIO_read` (route B below), where the crate never handles the descriptor at
all.
**Class:** I/O-safety violation (double `close(2)` of a descriptor owned by a
live `OwnedFd`). Not memory UB — see *What this is and is not* below.
**Lead note:** [`notes/bio-dup-chain-resource-sharing.md`](../notes/bio-dup-chain-resource-sharing.md)

## Route A — a descriptor Rust handed over

Three safe calls, no `unsafe` in the caller:

```rust
let donor: OwnedFd = File::create(path)?.into();
let mut bio  = BIO_new_fd(donor).unwrap();              // safe: fd ownership -> BIO (BIO_CLOSE)
let dup      = BIO_dup_chain(Some(&mut bio.as_mut())).unwrap();  // safe
drop(dup);                                              // close(fd)  #1
drop(bio);                                              // close(fd)  #2
```

`BIO_new_fd` takes an `OwnedFd` **by value**: the crate opts into Rust's I/O
safety model and moves the close obligation into the returned `CBox<Bio>`
(`bss_fd.rs:32`, passing `BIO_CLOSE`). `BIO_dup_chain` then hands back a
*second* owner of the same descriptor, because C copies the descriptor number
and the close flag verbatim — `crypto/bio/bio_lib.c`:

```c
        new_bio->init     = bio->init;
        new_bio->shutdown = bio->shutdown;
        new_bio->flags    = bio->flags;

        /* This will let SSL_s_sock() work with stdin/stdout */
        new_bio->num      = bio->num;
```

and `fd_free` (`crypto/bio/bss_fd.c`) closes unconditionally on that copy:

```c
static int fd_free(BIO *a)
{
    if (a == NULL) return 0;
    if (a->shutdown) {
        if (a->init) { UP_close(a->num); }
        ...
```

`BIO_dup_chain` succeeds here because `fd_ctrl` answers `BIO_CTRL_DUP` with 1.
The same holds for `bss_sock.c:202`, `bss_dgram.c:613`, `bss_mem.c:335`,
`bss_file.c:370` and `bss_null.c:60`; of those, `BIO_s_fd`, `BIO_s_socket` and
`BIO_s_datagram` are the descriptor-owning ones and are all reachable through
safe constructors that consume an `OwnedFd`/`BioSocket`.

Neither owner is marked `unsafe`, neither is `unsafe fn`, and the borrow
checker is satisfied: `BioChain<'a>` is bounded by the source's borrow, which
constrains *ordering* but not *ownership*.

## Route B — a chain libcrypto builds by itself, on a live socket

Route A can be argued away as "you gave the BIO your `OwnedFd`, of course it is
touchy". Route B removes that step entirely. `crypto/bio/bss_acpt.c`'s
`acpt_state` `BIO_push`es the accepted socket BIO behind the accept BIO, and it
runs from `acpt_read` — so **`BIO_read` on an accept BIO is a safe function that
builds a two-node chain**, with the tail owning an `accept(2)` descriptor the
Rust side has never seen:

```rust
let mut accept_bio = BIO_new_accept(c"127.0.0.1:PORT").unwrap();   // safe
BIO_read(&mut accept_bio.as_mut(), &mut buf);                       // safe: binds, listens, accepts, pushes
// now: accept BIO (0x50d) -> socket BIO (0x505), tail shutdown = 1

let dup = BIO_dup_chain(Some(&mut accept_bio.as_mut())).unwrap();   // safe: dup tail shutdown = 1, same fd
drop(dup);                       // BIO_free_all -> close(accepted fd)   #1
let victim = File::create(..);   // ordinary Rust File takes the freed number
BIO_free_all(accept_bio);        // safe -> close(accepted fd)           #2
```

Observed (`crustify/audit/tmp/accept-chain-double-close/`, `#![forbid(unsafe_code)]`,
which also drives the connecting peer from a `std::net::TcpStream` in a thread):

```
accept BIO type = 0x50d
BIO_read = 20
next after  = true
  tail type = 0x505 (socket = 0x505, accept = 0x50d)
  tail shutdown = 1
accepted connection descriptor = 4
BIO_dup_chain -> true
  dup head type = 0x50d
  dup tail type = 0x505, shutdown = 1
dropped the duplicate (first close of the accepted descriptor)
victim File descriptor = 4
BIO_free_all on the original (second close)
victim descriptor still open? false
dropping the victim File (std I/O-safety check runs now)...
fatal runtime error: IO Safety violation: owned file descriptor already closed, aborting
```

Deterministic: **10/10** runs abort with status 134. The descriptor number is
read back through `BIO_get_rpoll_descriptor`, which is also safe.

Two things this route settles that route A does not:

- The chain is **not** something the caller assembled. `BIO_push` is correctly
  `unsafe` in this crate, and until this I had concluded safe code could not
  build a chain at all; `acpt_state` builds one on the caller's behalf.
- The descriptor is created inside C by `accept(2)`. There is no `OwnedFd`
  handoff to blame, so "the crate should not have accepted an `OwnedFd`" is not
  an available answer.

## The reproduction

Route A: `crustify/audit/tmp/dup-chain-fd/` — a cargo crate depending on the audited
`libcrypto` by path, whose `main.rs` begins with `#![forbid(unsafe_code)]`, so
the compiler proves the caller writes no `unsafe`.

```
$ cd /work/openssl/crustify/audit/tmp/dup-chain-fd && cargo build && ./target/debug/dup-chain-fd
donor descriptor            = 3
after dropping the duplicate, descriptor 3 is closed
victim File descriptor      = 3
victim descriptor still open? false
write to the victim File: Bad file descriptor (os error 9)
dropping the victim File (std I/O-safety check runs now)...
fatal runtime error: IO Safety violation: owned file descriptor already closed, aborting
Aborted (core dumped)      # exit 134
```

Deterministic: **20/20** runs abort with status 134. Route B lives in
`crustify/audit/tmp/accept-chain-double-close/` and aborts **10/10**.

In both cases the instrument is the Rust standard library's own I/O-safety runtime check in
`OwnedFd::drop`. It fires because step 5 of the program closed a descriptor
that a live, ordinary `std::fs::File` owned. Before that check runs, the
program also observes the damage directly: the `File`'s `write_all` fails with
`EBADF`, and `/proc/self/fd/3` has vanished while the `File` is still alive.

Toolchain: `rustc 1.98.0`, `libcrypto.a` from the tree's canonical C build
(`./Configure no-deprecated enable-ubsan --strict-warnings`). No sanitizer is
needed — this is not a memory error.

## What this is and is not

It **is** a soundness bug in the Rust sense: `std::os::fd` documents that
closing a descriptor owned by an `OwnedFd` is exactly the hazard
`FromRawFd::from_raw_fd` is `unsafe` for, and std treats the resulting state as
a fatal runtime violation. A safe function that produces it lets safe code
break another safe abstraction's invariant. In a library that is not artificially
arranged, the consequence is silent: a write intended for one file or socket
lands on whatever unrelated descriptor the kernel handed out in between.

It is **not** memory-model UB. Miri cannot execute this (it stops at the
`extern "C"` boundary) and ASan/UBSan have nothing to say about `close(2)`.
I am reporting exactly what I ran: a std-level I/O-safety abort, not a
sanitizer memory report.

## Already known?

Partly. `BIO_dup_chain`'s own doc comment (`bio_lib.rs:989-992`) says:

> The copied `num` and `shutdown` are a resource-sharing hazard that belongs to
> C and that this wrapper cannot remove: for a descriptor-backed method with
> `shutdown` set, source and duplicate each close the same descriptor when
> released.

So the *mechanism* is documented. What the note gets wrong is the conclusion.
Attributing the hazard to C and declaring it unremovable is only tenable if the
Rust surface never claimed descriptor ownership — but `BIO_new_fd` takes an
`OwnedFd` and `BIO_new_socket` takes a `BioSocket`, so this crate is precisely
the layer that made the ownership claim. A documented hazard reachable from a
safe `pub fn` is still an unsound safe `pub fn`; the comment is a description,
not a safety contract a caller can be held to. I found nothing in
`SECURITY.md`, the notes directory or the campaign results treating it as an
open defect.

## The counter-argument I could not make stick

I tried three ways to argue this is not a bug:

1. *The borrow checker prevents it.* It does not. `BioChain<'a>` borrows the
   source for `'a`, which forces the duplicate to be dropped or the source to
   stay borrowed — but both owners still run their destructor, in either order.
   Dropping them in the other order gives the same double close.
2. *`BIO_dup_chain` can only be reached with a chain, and chains need the
   `unsafe` `BIO_push`.* False twice over: a single BIO is already a one-node
   chain, and — route B — `BIO_read` on an accept BIO makes libcrypto build a
   genuine two-node chain for you.
3. *Rust I/O safety is a convention, not soundness.* std disagrees loudly
   enough to `abort()`. And `BIO_new_fd`'s signature (`OwnedFd` by value) is the
   crate electing into that model.

One thing genuinely weakens the report: without a live `OwnedFd` occupying the
recycled descriptor, the double close is merely an `EBADF` that C swallows. The
violation requires the descriptor to be reused, which my reproduction arranges
deliberately. That is a statement about how *often* it bites, not about whether
the safe API permits it.

## Suggested fix

Preferred, non-breaking: make `BIO_dup_chain` refuse a source whose method
owns a descriptor. The information is available before the call —
`BIO_method_type(bio)` distinguishes `BIO_TYPE_FD` / `BIO_TYPE_SOCKET` /
`BIO_TYPE_DGRAM`, and `BIO_get_shutdown(bio)` reports the close flag. Returning
`None` for that combination keeps the signature and costs nothing on every
other method.

It **must walk the whole chain, not just the head** — route B is exactly the
case where the head (an accept BIO, `0x50d`) is harmless and the tail (a socket
BIO, `0x505`, `shutdown = 1`) is the problem. `BIO_next` makes the walk easy and
is already safe.

Alternative, breaking: mark `BIO_dup_chain` `unsafe fn`, with a contract that
no node in the chain owns a descriptor with `shutdown` set. This is the honest
encoding if the maintainers want the operation to stay total, but it demotes a
currently-safe function.

A third option — clearing `shutdown` on every duplicated node — is *not*
suggested: it changes C's documented semantics for callers who dup a chain of
BIOs that legitimately hold their own resources, and it would silently leak for
methods where the duplicate really does own something.

## What I did not check

- `libssl`'s BIO methods (out of the audited target set).
- Whether `BIO_dup_chain` over a multi-node chain hits additional copies of the
  same hazard through `cb_arg` or `ex_data`; the doc comment raises both, and I
  could not reach either from safe code because `BIO_set_callback_arg` and
  `BIO_set_ex_data` are correctly `unsafe`. Note that route B does put a real
  multi-node chain in safe hands, so this is now worth someone's time.
- Route B on `BIO_new_connect` + `BIO_do_connect_retry`: `conn_state` does not
  `BIO_push`, so I do not expect a chain there, but I did not test it against a
  live peer.
- Windows/other targets: `UP_close` and descriptor recycling behave differently
  there, so the abort may not reproduce, but the double close still happens.

## Cleared while looking at this

- `BIO_new_file` + `BIO_dup_chain`: the `FILE *` lives in `b->ptr`, which
  `BIO_dup_chain` does **not** copy, and `file_free` only `fclose`s a non-null
  `ptr`. No double `fclose`. Not a bug.
- The `ex_data` duplication path: `CRYPTO_dup_ex_data` copies raw slot pointers
  when no `dup_func` is registered, which would double-free on teardown — but
  registering an ex_data class is not wrapped and `BIO_set_ex_data` is `unsafe`,
  so safe code cannot populate a slot. Not reachable.
