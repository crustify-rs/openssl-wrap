# Lead: what a filter BIO does when nothing is chained behind it

**Status: CONFIRMED (one cell) -> [`advisories/bio-gets-buffer-filter-null-deref.md`](../advisories/bio-gets-buffer-filter-null-deref.md)**

## Why this was worth checking

`BIO_push` is correctly `unsafe` in this crate, so a caller cannot chain a
filter behind anything. (C *can* link nodes on the caller's behalf — see
[`no-safe-bio-chain.md`](no-safe-bio-chain.md) — but only in `bss_acpt.c`, and
only a socket BIO behind an accept BIO, never a filter.) So **an unchained
filter is the only filter safe Rust can obtain**, which puts every C filter
method's `next_bio == NULL` path squarely on the safe surface, and makes every
one of them worth testing.

## What I ran

`crustify/audit/tmp/probe/src/bin/filters.rs` — 8 methods x 10 safe operations,
one pair per child process so an abort names one cell:

- methods: `BIO_f_buffer`, `BIO_f_linebuffer`, `BIO_f_prefix`,
  `BIO_f_nbio_test`, `BIO_f_null`, `BIO_f_readbuffer`, plus `BIO_s_null` and
  `BIO_s_mem` as controls
- operations: `BIO_gets`, `BIO_get_line`, `BIO_read`, `BIO_read_ex`,
  `BIO_write`, `BIO_write_ex`, `BIO_puts`, `BIO_printf`, `BIO_eof`,
  `BIO_ctrl_pending`

## Result

One cell fails: **`BIO_f_buffer` x `BIO_gets`**, a null-pointer read
(`buffer_gets` lacks the `next_bio == NULL` guard that `buffer_read` and
`buffer_write` have). 79 cells clean.

Full matrix output is in the advisory. The narrowness is the useful part: this
is one missing guard, not a systemic property of unchained filters, so a
maintainer does not need to audit the whole filter family.

## What would change my mind about the clean 79

Every `BIO_ctrl` route in this crate is `unsafe`, so I could only reach the
filters through the read/write/gets/puts entry points. `buffer_ctrl`,
`prefix_ctrl` and friends also reach through `next_bio`, and several forward
commands to it unconditionally. If a safe `BIO_ctrl`-family wrapper is ever
added, this matrix must be re-run with the control commands included.
