# Lead: NID arguments are unconstrained `i32` all over `objects`

**Status: CONFIRMED (obj_xref) -> [`advisories/obj-sigid-comparator-signed-overflow.md`](../advisories/obj-sigid-comparator-signed-overflow.md)**

## The idea

Every safe `objects` wrapper takes NIDs as bare `i32` and forwards them. C's
object code is full of hand-written comparators, and the classic defect in a
C comparator is `return a - b;`. So: feed extreme NIDs to every safe entry
point and see what UBSan says.

## What I ran

`crustify/audit/tmp/probe/src/bin/sigid.rs` — the three `obj_xref` entry points
over `{INT_MIN, INT_MIN+1, -1, 0, 1, 8, 65, INT_MAX}`, one call per process.
Also the wider `objects` block of `crustify/audit/tmp/probe/src/bin/sweep.rs`,
which covers `OBJ_nid2sn`, `OBJ_nid2ln`, `OBJ_nid2obj`, `OBJ_txt2obj`,
`OBJ_obj2txt`, `OBJ_create`, `OBJ_add_object`, `OBJ_NAME_*` and
`OBJ_create_objects` over the same range plus adversarial strings.

## Result

`OBJ_find_sigid_algs`, `OBJ_find_sigid_by_algs` and `OBJ_add_sigid` all overflow
`sig_cmp` / `sigx_cmp` in `crypto/objects/obj_xref.c` for NIDs near `INT_MIN`.
Everything else in `objects` is clean across the same range, because
`obj_dat.c`'s comparators use `<`/`>` rather than subtraction.

## Cleared here, worth not re-deriving

- `OBJ_bsearch_` / `OBJ_bsearch_ex_` (`objects/obj_dat.rs`) look alarming — a
  safe function handing a Rust slice to a C binary search with a caller-supplied
  erased comparator — but the wrapper validates the returned pointer back into
  the caller's slice (in range, aligned, correct stride) via `bsearch_result`
  before forming a `&'a T`. Even a malicious comparator cannot make it hand out
  a reference outside `base`. This is more defensive than the C it wraps.
- `ossl_bsearch` (`crypto/bsearch.c`) derives its index from the element count
  only; the comparator's return value never feeds an offset. A wrong comparator
  gives a wrong answer, not an out-of-bounds access. That is what bounds the
  severity of the confirmed finding.
- `OBJ_add_object` refuses a non-dynamic source so the process-global registry
  never retains a borrow (`obj_dat.rs:206`). Correct, and the reasoning in the
  doc comment matches `OBJ_dup`'s actual behaviour.
