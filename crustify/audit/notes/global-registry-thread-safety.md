# Lead: the process-global registries are reachable from safe code on any thread

**Status: one CONFIRMED ->
[`advisories/asn1-string-table-data-race.md`](../advisories/asn1-string-table-data-race.md).
The other three registries tested clean, with a control experiment.**

## Why this class exists at all

Almost every handle in this crate is `!Send` (they are `CPtr`-carrying newtypes
with no `Send`/`Sync` impls — see
[`handle-discipline-cleared.md`](handle-discipline-cleared.md) §6), so the
thread-safety question looks closed. It is not, because a family of safe
wrappers takes **no handle at all** — only `i32`, `c_long`, `&CStr` — and
mutates process-global C state:

| wrapper | global | C lock |
|---|---|---|
| `ASN1_STRING_TABLE_add`, `ASN1_STRING_TABLE_get`, `ASN1_STRING_set_by_NID{,_into}` | `stable` in `crypto/asn1/a_strnid.c` | **none** |
| `OBJ_create`, `OBJ_add_object`, `OBJ_new_nid`, `OBJ_nid2*`, `OBJ_txt2*`, `OBJ_sn2nid`, `OBJ_ln2nid`, `OBJ_create_objects` | `added` in `crypto/objects/obj_dat.c` | `ossl_obj_lock` (RW) |
| `OBJ_add_sigid`, `OBJ_find_sigid_algs`, `OBJ_find_sigid_by_algs` | `sig_app`/`sigx_app` in `crypto/objects/obj_xref.c` | `sig_lock` (RW) |
| `OBJ_NAME_init`, `OBJ_NAME_get`, `OBJ_NAME_new_index` | `names_lh` in `crypto/objects/o_names.c` | `obj_lock` (RW) |

`grep -n 'lock\|CRYPTO_THREAD' crypto/asn1/a_strnid.c` returns exactly one hit,
and it is the comment `/* Ideally, this would be done under lock */`. The other
three files each create and take a `CRYPTO_RWLOCK`.

## Confirmed

`ASN1_STRING_TABLE_add` from 16 threads: use-after-free and double-free under
ASan (0/10 runs survive), segfaults and glibc heap-corruption assertions
against the tree's own build (0/10 survive). Details and reproduction in the
advisory; the reproduction is `crustify/audit/tmp/string-table-race/`.

## Cleared, with a control

`crustify/audit/tmp/probe/src/bin/objrace.rs` hammers the other three
registries the same way — 16 threads x 2000 iterations, interleaving
`OBJ_create`, `OBJ_sn2nid`/`OBJ_nid2sn`/`OBJ_nid2ln`/`OBJ_nid2obj`,
`OBJ_txt2obj` + `OBJ_add_object`, `OBJ_new_nid`, `OBJ_add_sigid` +
`OBJ_find_sigid_algs` + `OBJ_find_sigid_by_algs`, and `OBJ_NAME_init` +
`OBJ_NAME_get` + `OBJ_NAME_new_index`.

**8/8 clean** against the tree's UBSan build, **4/4 clean** under ASan.

That control matters: it rules out "any global registry blows up if you push on
it hard enough" and pins the finding on the one file whose C takes no lock.

## Still open

- **`OBJ_NAME_do_all` / `OBJ_NAME_do_all_sorted`.** Already `unsafe fn` in this
  crate, with a `# Safety` note that OpenSSL traverses without taking
  `obj_lock`. Correctly gated, so not a soundness bug — but if it is ever made
  safe, it belongs in this class.
- **Mixed-registry interleavings.** I raced each registry against itself.
  `OBJ_create` internally reaches `OBJ_add_object`, and `ASN1_STRING_TABLE_get`
  triggers `OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG)`, which can itself
  populate the string table. A cross-registry racer might find something the
  per-registry ones cannot. Not attempted.
- **`OSSL_LIB_CTX` / provider state.** Out of the wrapped surface here.

## What would change my mind about the clean three

Nothing I can see in the C — the locks are unconditional, on both the read and
write paths. But my control only exercised the entry points this crate wraps.
If the wrapped `objects` surface grows (`OBJ_NAME_add`, `OBJ_NAME_remove`,
`OBJ_cleanup`), re-run `objrace.rs` with the new calls added; the harness is
built to have arms bolted on.
