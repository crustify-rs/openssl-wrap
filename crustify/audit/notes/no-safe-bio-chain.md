# CORRECTED: safe code *can* build a multi-node BIO chain

**Status: I first concluded the opposite. The correction is the finding — see
route B in [`advisories/bio-dup-chain-double-close.md`](../advisories/bio-dup-chain-double-close.md).**

## The wrong conclusion, and why it was tempting

`BIO_push`, `BIO_pop` and `BIO_set_next` are all `unsafe fn`, correctly. Every
safe constructor (`BIO_new`, `BIO_new_ex`, `BIO_new_mem_buf`, `BIO_new_file`,
`BIO_new_fd`, `BIO_new_socket`, `BIO_new_dgram`, `BIO_new_bio_pair`,
`BIO_new_bio_dgram_pair`, `BIO_new_accept`, `BIO_new_connect`, the six `BIO_f_*`
filters) hands back a single node with `next_bio == NULL`. `BIO_dup_chain`
duplicates a chain but cannot create the first link. So it looks airtight, and
I recorded it as cleared.

It is not, because **C links nodes on the caller's behalf**.

## What actually happens

`crypto/bio/bss_acpt.c`'s `acpt_state` ends its state machine with
`BIO_push(b, bio)`, attaching the accepted socket BIO behind the accept BIO —
and `acpt_state` is driven from `acpt_read`/`acpt_write`, not only from
`BIO_do_accept`:

```c
static int acpt_read(BIO *b, char *out, int outl)
{
    ...
    while (b->next_bio == NULL) {
        ret = acpt_state(b, data);
        if (ret <= 0) return ret;
    }
    ret = BIO_read(b->next_bio, out, outl);
```

`BIO_new_accept` and `BIO_read` are both safe. Demonstrated in
`crustify/audit/tmp/accept-chain-double-close/` against a live loopback
connection:

```
accept BIO type = 0x50d
next before = false
BIO_read = 20
next after  = true
  tail type = 0x505 (socket), shutdown = 1
```

## What that unlocks, and what it does not

Now live:

- **`BIO_dup_chain` over a real two-node chain**, whose tail owns an
  `accept(2)` descriptor with `shutdown` set. That is route B of the
  double-close advisory, and it is the stronger of the two routes because the
  Rust side never touches the descriptor.
- **`BIO_free` vs `BIO_free_all` on a chain.** `CBox<Bio>`'s destructor is
  `BIO_free`, which releases only the head, so simply dropping an accept BIO
  leaks the socket node and its descriptor. A leak, not UB — but worth knowing
  that the two safe teardown routes for the same value differ in whether the
  tail is released.

Checked and still sound:

- **`BIO_find_type<'a>(bio: &'a mut BioMut<'_>, ty) -> Option<BioMut<'a>>`.**
  With a real chain it does now return a handle to a *different* object than the
  one borrowed — I confirmed it hands back the socket node
  (`0x...e30`) while the head is `0x...090`. That is still sound: the returned
  `BioMut<'a>` keeps the head's handle mutably borrowed for `'a`, and every
  other route to the tail (`BIO_next`, a second `BIO_find_type`) needs a
  conflicting borrow of the same head. I could not construct two simultaneous
  handles to the tail.
- **`BIO_next`, `BIO_get_retry_BIO`** — shared handles only, `Copy`, no writes.

## What would change my mind / what is still open

I did not audit the other state machines for the same pattern. `conn_state`
(`bss_conn.c`) does not appear to `BIO_push`, and I did not test it against a
live peer. Any C method whose read/write path can call `BIO_push` puts a chain
in safe hands the same way; that is the general lesson, and it is worth a grep
for `BIO_push` across `crypto/bio/` whenever the wrapped surface grows.
