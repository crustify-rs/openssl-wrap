# crustify — `openssl / crypto`

## Campaign

- **target repo** — `openssl` @ `2924476b5591e691e904c4baf57894c526c4b8de`
- **target** — first public `libcrypto` subset: ASN.1 string/object, generic `STACK_OF`, and BIO; `libssl` excluded; X.509 and EVP deferred
- **campaign objective** — `wrap`
- **`impl_files`** — `crypto/`, `include/crypto/`, `include/internal/`
- **`api_headers`** — `include/openssl/`
- **agent backend** — `codex`
- **model** — `openai/gpt-5.6-sol`
- **`--billing`** — `api`
- **`--max-types`** — `2`
- **`--max-syms`** — `50`
- **`--max-loc`** — `1000`
- **`--min-fields`** — `10`
- **`--parallel-max`** — `8`
- **branch** — `crustify/libcrypto-gpt-5.6-sol`, code tip `32ada326d7`
- **deps** — crustify-cli `ae596e5` (`fix/review-unplaced-context`), ffibox `c2178c4` (`main`)

## Review pass

`--objective review`, LLM-as-a-Judge over the landed waves. Run it under a
DIFFERENT model from the one being judged — a review by the author is
self-review, and any disagreement is what makes the pass informative.

- **agent backend** — `claude`
- **model** — `anthropic/claude-opus-5`
- **`--billing`** — `subscription`
- **`--max-types`** — `10`
- **`--max-syms`** — `50`
- **`--max-loc`** — `1000`
- **`--min-fields`** — `10`
- **`--parallel-max`** — `8`
- **branch** — `crustify/session/review-2026-08-23_00-42-36_ea63`, tip `00a3a7870e`
- **agents** — `29`: `4` lifetime + `25` target-set review agents, over `2` sessions

`rv`-prefixed columns below carry the review pass; the unprefixed ones remain
the campaign's.

## Legend

- `DAG layer` — the unit's own wrap DAG layer
- `kind` — `struct` / `union` / `enum` for a type; `callback`; `function` for
  every symbol, whatever linkage the C declaration carries
- `fields` — all declared fields
- `target fields` / `target ptr` — fields a target-section function touches / of
  those, pointers
- `wrapped fields` — fields given an accessor, counted as DISTINCT `type.field`
  paths; `—` = wrapped with no field accessor (opaque)
- `newtypes` — distinct Rust types carrying a `/// Wraps: <tag>` anchor; `1` is
  a plain 1:1 wrap, `>1` where one C type needs several representations (an
  owned handle beside a borrowed view, a by-value beside a by-pointer form)
- `target fns` — every target-section function needing the symbol, tree-wide
- `deps` — import types/callbacks the symbol needs
- `wrappers` — distinct safe fns emitted over the one C routine; `>1` where the
  signature forked (a slice-taking beside a `CStr`-taking form, a fallible
  beside an infallible one)
- `batch` — the agent that emitted it. Symbols pool, so their cost is per
  batch, not per symbol — see the batches table
- `$` / `wall` / `loc` — that agent's own cost, its elapsed time, and the `.rs`
  insertions of its landing commit. `wall` is `ended_at − started_at` from the
  agent's own `usage.json`, so it INCLUDES the per-worktree C rebuild
- `$/unit` / `$/loc` / `$/field` — that row's `$` over its units, its `loc`, or
  its declared fields
- `$/symbol` / `$/type` — a batch holds one kind or the other, so one of the
  two reads `—`; on a Σ row each divides that kind's own cost by its own count
- `↖ batched` — shares the row above's agent; one usage record covers both
- `rv $` / `rv wall` / `rv loc` — the REVIEW agent's own cost, elapsed time, and
  net `.rs` line delta (`+ins/-del`) of its landing commit
- `verdict` — what the judge concluded: `held` = analysis and code confirmed as
  emitted, `fixed` = a defect in the emitted Rust corrected, `record` = an
  ownership finding resubmitted through the oracle. Several may apply
- In a batches row, `wall` is the layer's LONGEST agent — what the layer would
  cost with every batch spawned at once — and the parenthetical is the
  serial-sum multiple. A Σ row sums the columns it can and carries the same
  longest-agent reading for `wall`

## Overview

Each row groups a reviewee with the campaigns that actually reviewed it.
Totals price the recorded token classes at provider API rates; the compact
model tag sits beside each total. The lifetime review total contains metered
campaigns `02` and `04`; superseded campaign `03` is unmetered. The orchestrator
row is live at the report checkpoint and is not part of `crustify-log-cost`'s
agent total. For mixed campaigns, each unit rate uses only its matching cost
bucket. The 8 callback units are excluded from both counts and folded into the
type bucket's cost. Rate cells in the Σ row are medians of the displayed
campaign-level rates. Its unit counts are distinct implementation units, so
review, audit, and orchestration coverage is not counted again.

| campaign | objective | nr types | nr symbols | session wall | campaign total | campaign $/type | campaign $/sym | review total | review $/type | review $/sym |
|---|---|---:|---:|---|---:|---:|---:|---:|---:|---:|
| `00–01-lifetimes` | raw lifetime | `0` | `10` | `39m26s` | `$13.63` (gpt56sol) | — | `$1.36` | `$29.61` (gpt55, opus5) | — | `$2.96` |
| `10–11-foundation` | wrap + corrective wrap | `34` | `277` | `2h50m51s` | `$244.34` (gpt56sol) | `$4.48` | `$0.33` | `$217.23` (opus5) | `$3.84` | `$0.31` |
| `ub-20260823-025523` | UB audit | `34` | `277` | `56m04s` | `$43.48` (opus5) | — | — | — | — | — |
| orchestrator | orchestration | `34` | `277` | live | `$77.52` (gpt56sol) | — | — | — | — | — |
| **Σ recorded agents** | | **`34`** | **`287`** | | **`$301.45`** | **`$4.48`** | **`$0.85`** | **`$246.84`** | **`$3.84`** | **`$1.64`** |

## Raw lifetime discovery

Goal: turn the untyped lifecycle primitives into Rust lifetime contracts before
any wrapper needs one. Oracle `schedule --lifetime-for void` then
`schedule --lifetime-for string`, one
agent each, objective `raw` (set by the tier, not `--objective`). `strategies`
counts the deleter/cloner ZSTs emitted; the four trait columns count the
`unsafe impl`s that bind them.

| tier | symbols submitted | strategies | CDropped | CCloned | CLenDropped | CLenCloned | $ | wall |
|---|---|---|---|---|---|---|---|---|
| void | `7` | `6` | `3` | `0` | `6` | `1` | `$7.94` | `24m20s` |
| string | `3` | `0` | `2` | `3` | `0` | `0` | `$5.69` | `15m05s` |
| **Σ** | **`10`** | **`6`** | **`5`** | **`3`** | **`6`** | **`1`** | **`$13.64`** | **`39m26s`** |

## Target set

What the campaign wrapped and in what order: types and callbacks first,
bottom-up by DAG layer, then the symbols over them.

### Types and callbacks

| DAG layer | unit | kind | fields | target fields | target ptr | wrapped fields | newtypes | $ | wall | loc | rv $ | rv wall | rv loc | verdict |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `0` | `ASN1_TEMPLATE_st` | struct | `5` | `5` | `2` | `5` | `1` | ↖ batch table | ↖ batch table | ↖ batch table | ↖ review table | ↖ review table | ↖ review table | held · fixed (batch) |
| `0` | `ASN1_VALUE_st` | struct | `—` | `—` | `—` | `—` | `1` | ↖ batch table | ↖ batch table | ↖ batch table | ↖ review table | ↖ review table | ↖ review table | held · fixed (batch) |
| `0` | `BIO_hostserv_priorities` | enum | `—` | `—` | `—` | `—` | `1` | ↖ batch table | ↖ batch table | ↖ batch table | ↖ review table | ↖ review table | ↖ review table | held · fixed (batch) |
| `0` | `BIO_lookup_type` | enum | `—` | `—` | `—` | `—` | `1` | ↖ batch table | ↖ batch table | ↖ batch table | ↖ review table | ↖ review table | ↖ review table | held · fixed (batch) |
| `0` | `BIO_sock_info_type` | enum | `—` | `—` | `—` | `—` | `1` | ↖ batch table | ↖ batch table | ↖ batch table | ↖ review table | ↖ review table | ↖ review table | held · fixed (batch) |
| `0` | `DEFINE_LHASH_OF_EX` | macro | `—` | `—` | `—` | `—` | `1` | ↖ batch table | ↖ batch table | ↖ batch table | ↖ review table | ↖ review table | ↖ review table | held · fixed (batch) |
| `0` | `_IO_FILE` | struct | `29` | `—` | `—` | `—` | `1` | ↖ batch table | ↖ batch table | ↖ batch table | ↖ review table | ↖ review table | ↖ review table | held · fixed (batch) |
| `0` | `addrinfo` | struct | `8` | `7` | `2` | `—` | `1` | ↖ batch table | ↖ batch table | ↖ batch table | ↖ review table | ↖ review table | ↖ review table | held · fixed (batch) |
| `0` | `asn1_string_table_st` | struct | `5` | `5` | `0` | `5` | `1` | ↖ batch table | ↖ batch table | ↖ batch table | ↖ review table | ↖ review table | ↖ review table | held · fixed (batch) |
| `0` | `bio_addr_st` | struct | `4` | `4` | `0` | `—` | `1` | ↖ batch table | ↖ batch table | ↖ batch table | ↖ review table | ↖ review table | ↖ review table | held · fixed (batch) |
| `0` | `bio_method_st` | struct | `14` | `14` | `13` | `—` | `1` | ↖ batch table | ↖ batch table | ↖ batch table | ↖ review table | ↖ review table | ↖ review table | held · fixed (batch) |
| `0` | `bio_st` | struct | `16` | `16` | `7` | `—` | `1` | ↖ batch table | ↖ batch table | ↖ batch table | ↖ review table | ↖ review table | ↖ review table | held · fixed (batch) |
| `0` | `hostent` | struct | `5` | `3` | `1` | `—` | `1` | ↖ batch table | ↖ batch table | ↖ batch table | ↖ review table | ↖ review table | ↖ review table | held · fixed (batch) |
| `0` | `in6_addr` | struct | `4` | `1` | `0` | `—` | `1` | ↖ batch table | ↖ batch table | ↖ batch table | ↖ review table | ↖ review table | ↖ review table | held · fixed (batch) |
| `0` | `in_addr` | struct | `1` | `1` | `0` | `—` | `1` | ↖ batch table | ↖ batch table | ↖ batch table | ↖ review table | ↖ review table | ↖ review table | held · fixed (batch) |
| `0` | `lhash_st` | struct | `15` | `15` | `7` | `—` | `1` | ↖ batch table | ↖ batch table | ↖ batch table | ↖ review table | ↖ review table | ↖ review table | held · fixed (batch) |
| `0` | `obj_name_st` | struct | `4` | `4` | `2` | `4` | `1` | ↖ batch table | ↖ batch table | ↖ batch table | ↖ review table | ↖ review table | ↖ review table | held · fixed (batch) |
| `0` | `ossl_init_settings_st` | struct | `3` | `3` | `2` | `—` | `1` | ↖ batch table | ↖ batch table | ↖ batch table | ↖ review table | ↖ review table | ↖ review table | held · fixed (batch) |
| `0` | `ossl_lib_ctx_st` | struct | `24` | `24` | `21` | `—` | `1` | ↖ batch table | ↖ batch table | ↖ batch table | ↖ review table | ↖ review table | ↖ review table | held · fixed (batch) |
| `0` | `stack_st` | struct | `8` | `8` | `5` | `—` | `1` | ↖ batch table | ↖ batch table | ↖ batch table | ↖ review table | ↖ review table | ↖ review table | held · fixed (batch) |
| `0` | `OPENSSL_sk_compfunc` | callback | `—` | `—` | `—` | `—` | `2` | ↖ batch table | ↖ batch table | ↖ batch table | ↖ review table | ↖ review table | ↖ review table | held · fixed (batch) |
| `0` | `OPENSSL_sk_copyfunc` | callback | `—` | `—` | `—` | `—` | `1` | ↖ batch table | ↖ batch table | ↖ batch table | ↖ review table | ↖ review table | ↖ review table | held · fixed (batch) |
| `0` | `OPENSSL_sk_freefunc` | callback | `—` | `—` | `—` | `—` | `1` | ↖ batch table | ↖ batch table | ↖ batch table | ↖ review table | ↖ review table | ↖ review table | held · fixed (batch) |
| `1` | `ASN1_ITEM_st` | struct | `7` | `7` | `3` | `7` | `1` | ↖ batch table | ↖ batch table | ↖ batch table | ↖ review table | ↖ review table | ↖ review table | held · fixed (batch) |
| `1` | `BIO_sock_info_u` | struct | `1` | `1` | `1` | `1` | `1` | ↖ batch table | ↖ batch table | ↖ batch table | ↖ review table | ↖ review table | ↖ review table | held · fixed (batch) |
| `1` | `asn1_object_st` | struct | `6` | `6` | `3` | `—` | `1` | ↖ batch table | ↖ batch table | ↖ batch table | ↖ review table | ↖ review table | ↖ review table | held · fixed (batch) |
| `1` | `bignum_st` | struct | `5` | `5` | `1` | `—` | `1` | ↖ batch table | ↖ batch table | ↖ batch table | ↖ review table | ↖ review table | ↖ review table | held · fixed (batch) |
| `1` | `bio_msg_st` | struct | `5` | `5` | `3` | `5` | `1` | ↖ batch table | ↖ batch table | ↖ batch table | ↖ review table | ↖ review table | ↖ review table | held · fixed (batch) |
| `1` | `bio_poll_descriptor_st` | struct | `6` | `2` | `0` | `6` | `1` | ↖ batch table | ↖ batch table | ↖ batch table | ↖ review table | ↖ review table | ↖ review table | held · fixed (batch) |
| `1` | `lhash_st_OBJ_NAME` | struct | `1` | `—` | `—` | `—` | `1` | ↖ batch table | ↖ batch table | ↖ batch table | ↖ review table | ↖ review table | ↖ review table | held · fixed (batch) |
| `1` | `stack_st_ASN1_STRING_TABLE` | struct | `—` | `—` | `—` | `—` | `1` | ↖ batch table | ↖ batch table | ↖ batch table | ↖ review table | ↖ review table | ↖ review table | held · fixed (batch) |
| `1` | `stack_st_NAME_FUNCS` | struct | `—` | `—` | `—` | `—` | `1` | ↖ batch table | ↖ batch table | ↖ batch table | ↖ review table | ↖ review table | ↖ review table | held · fixed (batch) |
| `1` | `stack_st_nid_triple` | struct | `—` | `—` | `—` | `—` | `1` | ↖ batch table | ↖ batch table | ↖ batch table | ↖ review table | ↖ review table | ↖ review table | held · fixed (batch) |
| `1` | `stack_st_void` | struct | `—` | `—` | `—` | `—` | `1` | ↖ batch table | ↖ batch table | ↖ batch table | ↖ review table | ↖ review table | ↖ review table | held · fixed (batch) |
| `1` | `BIO_callback_fn_ex` | callback | `—` | `—` | `—` | `—` | `1` | ↖ batch table | ↖ batch table | ↖ batch table | ↖ review table | ↖ review table | ↖ review table | held · fixed (batch) |
| `1` | `BIO_info_cb` | callback | `—` | `—` | `—` | `—` | `1` | ↖ batch table | ↖ batch table | ↖ batch table | ↖ review table | ↖ review table | ↖ review table | held · fixed (batch) |
| `1` | `OPENSSL_sk_copyfunc_thunk` | callback | `—` | `—` | `—` | `—` | `1` | ↖ batch table | ↖ batch table | ↖ batch table | ↖ review table | ↖ review table | ↖ review table | held · fixed (batch) |
| `1` | `OPENSSL_sk_freefunc_thunk` | callback | `—` | `—` | `—` | `—` | `1` | ↖ batch table | ↖ batch table | ↖ batch table | ↖ review table | ↖ review table | ↖ review table | held · fixed (batch) |
| `1` | `asn1_ps_func` | callback | `—` | `—` | `—` | `—` | `2` | ↖ batch table | ↖ batch table | ↖ batch table | ↖ review table | ↖ review table | ↖ review table | held · fixed (batch) |
| `2` | `asn1_type_st` | struct | `23` | `2` | `0` | `23` | `1` | ↖ batch table | ↖ batch table | ↖ batch table | ↖ review table | ↖ review table | ↖ review table | held · fixed (batch) |
| `2` | `crypto_ex_data_st` | struct | `2` | `2` | `2` | `2` | `1` | ↖ batch table | ↖ batch table | ↖ batch table | ↖ review table | ↖ review table | ↖ review table | held · fixed (batch) |
| `3` | `asn1_string_st` | struct | `4` | `4` | `1` | `—` | `1` | ↖ batch table | ↖ batch table | ↖ batch table | ↖ review table | ↖ review table | ↖ review table | held · fixed (batch) |
| **Σ `42`** | | | **`205`** | **`144`** | **`76`** | **`58`** | **`44`** | **`$126.91`** | | **`4,189`** | **`$130.58`** | | **`+3,602/-464`** | **`42`/`42` reviewed** |

### Batches — type review

| session | batch | units | rv loc | rv $ | rv wall | $/type |
|---|---|---|---|---|---|---|
| `2026-08-23_00-42-36_ea63` | `review-type_ASN1_TEMPLATE_st` | `6` types | `+115/-27` | `$9.94` | `20m22s` | `$1.66` |
| `2026-08-23_00-42-36_ea63` | `review-type__IO_FILE` | `1` type | `+52/-4` | `$4.67` | `13m38s` | `$4.67` |
| `2026-08-23_00-42-36_ea63` | `review-type_addrinfo` | `2` types | `+370/-0` | `$7.13` | `20m05s` | `$3.57` |
| `2026-08-23_00-42-36_ea63` | `review-type_bio_addr_st` | `1` type | `+167/-7` | `$6.61` | `18m45s` | `$6.61` |
| `2026-08-23_00-42-36_ea63` | `review-type_bio_method_st` | `1` type | `+118/-36` | `$8.22` | `16m30s` | `$8.22` |
| `2026-08-23_00-42-36_ea63` | `review-type_bio_st` | `1` type | `+61/-6` | `$4.83` | `9m56s` | `$4.83` |
| `2026-08-23_00-42-36_ea63` | `review-type_hostent` | `3` types | `+293/-35` | `$7.35` | `19m39s` | `$2.45` |
| `2026-08-23_00-42-36_ea63` | `review-type_lhash_st` | `1` type | `+122/-3` | `$6.19` | `14m03s` | `$6.19` |
| `2026-08-23_00-42-36_ea63` | `review-type_obj_name_st` | `2` types | `+306/-37` | `$8.21` | `18m21s` | `$4.10` |
| `2026-08-23_00-42-36_ea63` | `review-type_ossl_lib_ctx_st` | `1` type | `+134/-10` | `$7.54` | `18m16s` | `$7.54` |
| `2026-08-23_00-42-36_ea63` | `review-type_stack_st` | `1` type | `+121/-0` | `$5.40` | `15m17s` | `$5.40` |
| `2026-08-23_00-42-36_ea63` | `review-type_ASN1_ITEM_st` | `3` types | `+269/-28` | `$11.75` | `21m27s` | `$3.92` |
| `2026-08-23_00-42-36_ea63` | `review-type_bignum_st` | `2` types | `+329/-140` | `$8.81` | `19m10s` | `$4.40` |
| `2026-08-23_00-42-36_ea63` | `review-type_bio_poll_descriptor_st` | `6` types | `+540/-74` | `$13.62` | `20m54s` | `$2.27` |
| `2026-08-23_00-42-36_ea63` | `review-type_asn1_type_st` | `1` type | `+158/-30` | `$5.22` | `12m17s` | `$5.22` |
| `2026-08-23_00-42-36_ea63` | `review-type_crypto_ex_data_st` | `1` type | `+311/-20` | `$7.88` | `20m00s` | `$7.88` |
| `2026-08-23_00-42-36_ea63` | `review-type_asn1_string_st` | `1` type | `+136/-7` | `$7.21` | `18m58s` | `$7.21` |
| **Σ** | **`17` agents** | **`42` types** | **`+3,602/-464`** | **`$130.58`** | **`21m27s`** (longest; `4h57m46s` serial, `13.9`x) | **`$3.11`** |

### Batches — types

| DAG layer | units | loc | $ | wall (longest) | wall (actual) | serial Σ | $/unit | $/loc |
|---|---|---|---|---|---|---|---|---|
| `0` | `20` | `1,962` | `$72.74` | `20m07s` | **`46m05s`** | `2h48m25s` (`3.7`x) | `$3.64` | `$0.037` |
| `1` | `11` | `1,489` | `$35.91` | `15m13s` | **`45m24s`** | `1h15m54s` (`1.7`x) | `$3.26` | `$0.024` |
| `2` | `2` | `633` | `$12.94` | `16m48s` | **`33m54s`** | `32m33s` (`1.0`x) | `$6.47` | `$0.020` |
| `3` | `1` | `105` | `$5.32` | `13m27s` | **`13m28s`** | `13m27s` (`1.0`x) | `$5.32` | `$0.051` |
| **Σ** | **`34`** | **`4,189`** | **`$126.91`** | — | **`2h18m51s`** | **`4h50m19s`** (`2.1`x) | **`$3.73`** | **`$0.030`** |

### Symbols

| DAG layer | symbol | kind | target fns | deps | wrappers | batch | rv batch | verdict |
|---|---|---|---|---|---|---|---|---|
| `0` | `ASN1_STRING_TABLE_add` | function | `1` | — | `1` | `wrap-symbol_ASN1_STRING_TABLE_add` | `review-symbol_ASN1_STRING_TABLE_add` | held · fixed (batch) |
| `0` | `ASN1_STRING_get_default_mask` | function | `0` | — | `1` | `wrap-symbol_ASN1_STRING_TABLE_add` | `review-symbol_ASN1_STRING_TABLE_add` | held · fixed (batch) |
| `0` | `ASN1_STRING_set_default_mask` | function | `1` | — | `1` | `wrap-symbol_ASN1_STRING_TABLE_add` | `review-symbol_ASN1_STRING_TABLE_add` | held · fixed (batch) |
| `0` | `ASN1_STRING_set_default_mask_asc` | function | `0` | — | `1` | `wrap-symbol_ASN1_STRING_TABLE_add` | `review-symbol_ASN1_STRING_TABLE_add` | held · fixed (batch) |
| `0` | `BIO_accept` | function | `0` | — | `1` | `wrap-symbol_ASN1_STRING_TABLE_add` | `review-symbol_ASN1_STRING_TABLE_add` | held · fixed (batch) |
| `0` | `BIO_closesocket` | function | `6` | — | `1` | `wrap-symbol_ASN1_STRING_TABLE_add` | `review-symbol_ASN1_STRING_TABLE_add` | held · fixed (batch) |
| `0` | `BIO_dgram_non_fatal_error` | function | `1` | — | `1` | `wrap-symbol_ASN1_STRING_TABLE_add` | `review-symbol_ASN1_STRING_TABLE_add` | held · fixed (batch) |
| `0` | `BIO_dump_cb` | function | `2` | — | `1` | `wrap-symbol_ASN1_STRING_TABLE_add` | `review-symbol_ASN1_STRING_TABLE_add` | held · fixed (batch) |
| `0` | `BIO_dump_indent_cb` | function | `3` | — | `1` | `wrap-symbol_ASN1_STRING_TABLE_add` | `review-symbol_ASN1_STRING_TABLE_add` | held · fixed (batch) |
| `0` | `BIO_err_is_non_fatal` | function | `0` | — | `1` | `wrap-symbol_ASN1_STRING_TABLE_add` | `review-symbol_ASN1_STRING_TABLE_add` | held · fixed (batch) |
| `0` | `BIO_fd_non_fatal_error` | function | `1` | — | `1` | `wrap-symbol_ASN1_STRING_TABLE_add` | `review-symbol_ASN1_STRING_TABLE_add` | held · fixed (batch) |
| `0` | `BIO_fd_should_retry` | function | `2` | — | `1` | `wrap-symbol_ASN1_STRING_TABLE_add` | `review-symbol_ASN1_STRING_TABLE_add` | held · fixed (batch) |
| `0` | `BIO_get_accept_socket` | function | `0` | — | `1` | `wrap-symbol_ASN1_STRING_TABLE_add` | `review-symbol_ASN1_STRING_TABLE_add` | held · fixed (batch) |
| `0` | `BIO_get_host_ip` | function | `0` | — | `1` | `wrap-symbol_ASN1_STRING_TABLE_add` | `review-symbol_ASN1_STRING_TABLE_add` | held · fixed (batch) |
| `0` | `BIO_get_new_index` | function | `0` | — | `1` | `wrap-symbol_ASN1_STRING_TABLE_add` | `review-symbol_ASN1_STRING_TABLE_add` | held · fixed (batch) |
| `0` | `BIO_get_port` | function | `0` | — | `1` | `wrap-symbol_ASN1_STRING_TABLE_add` | `review-symbol_ASN1_STRING_TABLE_add` | held · fixed (batch) |
| `0` | `BIO_set_tcp_ndelay` | function | `0` | — | `1` | `wrap-symbol_ASN1_STRING_TABLE_add` | `review-symbol_ASN1_STRING_TABLE_add` | held · fixed (batch) |
| `0` | `BIO_sock_error` | function | `1` | — | `1` | `wrap-symbol_ASN1_STRING_TABLE_add` | `review-symbol_ASN1_STRING_TABLE_add` | held · fixed (batch) |
| `0` | `BIO_sock_init` | function | `3` | — | `1` | `wrap-symbol_ASN1_STRING_TABLE_add` | `review-symbol_ASN1_STRING_TABLE_add` | held · fixed (batch) |
| `0` | `BIO_sock_non_fatal_error` | function | `2` | — | `1` | `wrap-symbol_ASN1_STRING_TABLE_add` | `review-symbol_ASN1_STRING_TABLE_add` | held · fixed (batch) |
| `0` | `BIO_sock_should_retry` | function | `9` | — | `1` | `wrap-symbol_ASN1_STRING_TABLE_add` | `review-symbol_ASN1_STRING_TABLE_add` | held · fixed (batch) |
| `0` | `BIO_socket` | function | `2` | — | `1` | `wrap-symbol_ASN1_STRING_TABLE_add` | `review-symbol_ASN1_STRING_TABLE_add` | held · fixed (batch) |
| `0` | `BIO_socket_ioctl` | function | `1` | — | `1` | `wrap-symbol_ASN1_STRING_TABLE_add` | `review-symbol_ASN1_STRING_TABLE_add` | held · fixed (batch) |
| `0` | `BIO_socket_nbio` | function | `4` | — | `1` | `wrap-symbol_ASN1_STRING_TABLE_add` | `review-symbol_ASN1_STRING_TABLE_add` | held · fixed (batch) |
| `0` | `BIO_socket_wait` | function | `2` | — | `1` | `wrap-symbol_ASN1_STRING_TABLE_add` | `review-symbol_ASN1_STRING_TABLE_add` | held · fixed (batch) |
| `0` | `OBJ_NAME_get` | function | `8` | — | `1` | `wrap-symbol_ASN1_STRING_TABLE_add` | `review-symbol_ASN1_STRING_TABLE_add` | held · fixed (batch) |
| `0` | `OBJ_NAME_init` | function | `4` | — | `1` | `wrap-symbol_ASN1_STRING_TABLE_add` | `review-symbol_ASN1_STRING_TABLE_add` | held · fixed (batch) |
| `0` | `OBJ_bsearch_` | function | `11` | — | `1` | `wrap-symbol_ASN1_STRING_TABLE_add` | `review-symbol_ASN1_STRING_TABLE_add` | held · fixed (batch) |
| `0` | `OBJ_bsearch_ex_` | function | `1` | — | `1` | `wrap-symbol_ASN1_STRING_TABLE_add` | `review-symbol_ASN1_STRING_TABLE_add` | held · fixed (batch) |
| `0` | `OBJ_create` | function | `3` | — | `1` | `wrap-symbol_ASN1_STRING_TABLE_add` | `review-symbol_ASN1_STRING_TABLE_add` | held · fixed (batch) |
| `0` | `OBJ_find_sigid_algs` | function | `7` | — | `1` | `wrap-symbol_ASN1_STRING_TABLE_add` | `review-symbol_ASN1_STRING_TABLE_add` | held · fixed (batch) |
| `0` | `OBJ_ln2nid` | function | `5` | — | `1` | `wrap-symbol_ASN1_STRING_TABLE_add` | `review-symbol_ASN1_STRING_TABLE_add` | held · fixed (batch) |
| `0` | `OBJ_new_nid` | function | `1` | — | `1` | `wrap-symbol_ASN1_STRING_TABLE_add` | `review-symbol_ASN1_STRING_TABLE_add` | held · fixed (batch) |
| `0` | `OBJ_nid2ln` | function | `18` | — | `1` | `wrap-symbol_ASN1_STRING_TABLE_add` | `review-symbol_ASN1_STRING_TABLE_add` | held · fixed (batch) |
| `0` | `OBJ_nid2sn` | function | `54` | — | `1` | `wrap-symbol_ASN1_STRING_TABLE_add` | `review-symbol_ASN1_STRING_TABLE_add` | held · fixed (batch) |
| `0` | `OBJ_sn2nid` | function | `8` | — | `1` | `wrap-symbol_ASN1_STRING_TABLE_add` | `review-symbol_ASN1_STRING_TABLE_add` | held · fixed (batch) |
| `1` | `BIO_ADDRINFO_address` | function | `3` | `addrinfo`, `bio_addr_st` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | `review-symbol_BIO_ADDRINFO_address` | held · fixed (batch) |
| `1` | `BIO_ADDRINFO_family` | function | `4` | `addrinfo` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | `review-symbol_BIO_ADDRINFO_address` | held · fixed (batch) |
| `1` | `BIO_ADDRINFO_free` | function | `6` | `addrinfo` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | `review-symbol_BIO_ADDRINFO_address` | held · fixed (batch) |
| `1` | `BIO_ADDRINFO_next` | function | `2` | `addrinfo` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | `review-symbol_BIO_ADDRINFO_address` | held · fixed (batch) |
| `1` | `BIO_ADDRINFO_protocol` | function | `2` | `addrinfo` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | `review-symbol_BIO_ADDRINFO_address` | held · fixed (batch) |
| `1` | `BIO_ADDRINFO_socktype` | function | `2` | `addrinfo` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | `review-symbol_BIO_ADDRINFO_address` | held · fixed (batch) |
| `1` | `BIO_ADDR_clear` | function | `5` | `bio_addr_st` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | `review-symbol_BIO_ADDRINFO_address` | held · fixed (batch) |
| `1` | `BIO_ADDR_copy` | function | `1` | `bio_addr_st` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | `review-symbol_BIO_ADDRINFO_address` | held · fixed (batch) |
| `1` | `BIO_ADDR_dup` | function | `0` | `bio_addr_st` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | `review-symbol_BIO_ADDRINFO_address` | held · fixed (batch) |
| `1` | `BIO_ADDR_family` | function | `3` | `bio_addr_st` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | `review-symbol_BIO_ADDRINFO_address` | held · fixed (batch) |
| `1` | `BIO_ADDR_free` | function | `3` | `bio_addr_st` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | `review-symbol_BIO_ADDRINFO_address` | held · fixed (batch) |
| `1` | `BIO_ADDR_hostname_string` | function | `2` | `bio_addr_st` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | `review-symbol_BIO_ADDRINFO_address` | held · fixed (batch) |
| `1` | `BIO_ADDR_new` | function | `2` | `bio_addr_st` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | `review-symbol_BIO_ADDRINFO_address` | held · fixed (batch) |
| `1` | `BIO_ADDR_path_string` | function | `0` | `bio_addr_st` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | `review-symbol_BIO_ADDRINFO_address` | held · fixed (batch) |
| `1` | `BIO_ADDR_rawaddress` | function | `2` | `bio_addr_st` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | `review-symbol_BIO_ADDRINFO_address` | held · fixed (batch) |
| `1` | `BIO_ADDR_rawmake` | function | `1` | `bio_addr_st`, `in6_addr`, `in_addr` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | `review-symbol_BIO_ADDRINFO_address` | held · fixed (batch) |
| `1` | `BIO_ADDR_rawport` | function | `1` | `bio_addr_st` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | `review-symbol_BIO_ADDRINFO_address` | held · fixed (batch) |
| `1` | `BIO_ADDR_service_string` | function | `2` | `bio_addr_st` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | `review-symbol_BIO_ADDRINFO_address` | held · fixed (batch) |
| `1` | `BIO_accept_ex` | function | `1` | `bio_addr_st` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | `review-symbol_BIO_ADDRINFO_address` | held · fixed (batch) |
| `1` | `BIO_bind` | function | `1` | `bio_addr_st` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | `review-symbol_BIO_ADDRINFO_address` | held · fixed (batch) |
| `1` | `BIO_clear_flags` | function | `59` | `bio_st` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | `review-symbol_BIO_ADDRINFO_address` | held · fixed (batch) |
| `1` | `BIO_connect` | function | `1` | `bio_addr_st` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | `review-symbol_BIO_ADDRINFO_address` | held · fixed (batch) |
| `1` | `BIO_copy_next_retry` | function | `36` | `bio_st` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | `review-symbol_BIO_ADDRINFO_address` | held · fixed (batch) |
| `1` | `BIO_ctrl` | function | `139` | `bio_st` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | `review-symbol_BIO_ADDRINFO_address` | held · fixed (batch) |
| `1` | `BIO_ctrl_get_read_request` | function | `0` | `bio_st` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | `review-symbol_BIO_ADDRINFO_address` | held · fixed (batch) |
| `1` | `BIO_ctrl_get_write_guarantee` | function | `0` | `bio_st` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | `review-symbol_BIO_ADDRINFO_address` | held · fixed (batch) |
| `1` | `BIO_ctrl_pending` | function | `0` | `bio_st` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | `review-symbol_BIO_ADDRINFO_address` | held · fixed (batch) |
| `1` | `BIO_ctrl_reset_read_request` | function | `0` | `bio_st` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | `review-symbol_BIO_ADDRINFO_address` | held · fixed (batch) |
| `1` | `BIO_ctrl_wpending` | function | `0` | `bio_st` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | `review-symbol_BIO_ADDRINFO_address` | held · fixed (batch) |
| `1` | `BIO_debug_callback` | function | `0` | `bio_st` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | `review-symbol_BIO_ADDRINFO_address` | held · fixed (batch) |
| `1` | `BIO_debug_callback_ex` | function | `0` | `bio_st` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | `review-symbol_BIO_ADDRINFO_address` | held · fixed (batch) |
| `1` | `BIO_do_connect_retry` | function | `1` | `bio_st` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | `review-symbol_BIO_ADDRINFO_address` | held · fixed (batch) |
| `1` | `BIO_dump` | function | `3` | `bio_st` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | `review-symbol_BIO_ADDRINFO_address` | held · fixed (batch) |
| `1` | `BIO_dump_fp` | function | `0` | `_IO_FILE` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | `review-symbol_BIO_ADDRINFO_address` | held · fixed (batch) |
| `1` | `BIO_dump_indent` | function | `4` | `bio_st` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | `review-symbol_BIO_ADDRINFO_address` | held · fixed (batch) |
| `1` | `BIO_dump_indent_fp` | function | `0` | `_IO_FILE` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | `review-symbol_BIO_ADDRINFO_address` | held · fixed (batch) |
| `1` | `BIO_eof` | function | `7` | `bio_st` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | `review-symbol_BIO_ADDRINFO_address` | held · fixed (batch) |
| `1` | `BIO_f_buffer` | function | `3` | `bio_method_st` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | `review-symbol_BIO_ADDRINFO_address` | held · fixed (batch) |
| `1` | `BIO_f_linebuffer` | function | `0` | `bio_method_st` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | `review-symbol_BIO_ADDRINFO_address` | held · fixed (batch) |
| `1` | `BIO_f_nbio_test` | function | `0` | `bio_method_st` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | `review-symbol_BIO_ADDRINFO_address` | held · fixed (batch) |
| `1` | `BIO_f_null` | function | `0` | `bio_method_st` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | `review-symbol_BIO_ADDRINFO_address` | held · fixed (batch) |
| `1` | `BIO_f_prefix` | function | `2` | `bio_method_st` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | `review-symbol_BIO_ADDRINFO_address` | held · fixed (batch) |
| `1` | `BIO_f_readbuffer` | function | `2` | `bio_method_st` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | `review-symbol_BIO_ADDRINFO_address` | held · fixed (batch) |
| `1` | `BIO_find_type` | function | `6` | `bio_st` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | `review-symbol_BIO_ADDRINFO_address` | held · fixed (batch) |
| `1` | `BIO_free` | function | `130` | `bio_st` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | `review-symbol_BIO_ADDRINFO_address` | held · fixed (batch) |
| `1` | `BIO_free_all` | function | `17` | `bio_st` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | `review-symbol_BIO_ADDRINFO_address` | held · fixed (batch) |
| `1` | `BIO_get_callback` | function | `0` | `bio_st` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | `review-symbol_BIO_ADDRINFO_address` | held · fixed (batch) |
| `1` | `BIO_get_callback_arg` | function | `1` | `bio_st` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | `review-symbol_BIO_ADDRINFO_address` | held · fixed (batch) |
| `1` | `BIO_get_data` | function | `26` | `bio_st` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | `review-symbol_BIO_ADDRINFO_address` | held · fixed (batch) |
| `1` | `BIO_get_ex_data` | function | `0` | `bio_st` | `1` | `wrap-symbol_BIO_get_ex_data` | `review-symbol_BIO_get_ex_data` | held · fixed (batch) |
| `1` | `BIO_get_init` | function | `3` | `bio_st` | `1` | `wrap-symbol_BIO_get_ex_data` | `review-symbol_BIO_get_ex_data` | held · fixed (batch) |
| `1` | `BIO_get_line` | function | `2` | `bio_st` | `1` | `wrap-symbol_BIO_get_ex_data` | `review-symbol_BIO_get_ex_data` | held · fixed (batch) |
| `1` | `BIO_get_retry_BIO` | function | `0` | `bio_st` | `1` | `wrap-symbol_BIO_get_ex_data` | `review-symbol_BIO_get_ex_data` | held · fixed (batch) |
| `1` | `BIO_get_retry_reason` | function | `0` | `bio_st` | `1` | `wrap-symbol_BIO_get_ex_data` | `review-symbol_BIO_get_ex_data` | held · fixed (batch) |
| `1` | `BIO_get_shutdown` | function | `0` | `bio_st` | `1` | `wrap-symbol_BIO_get_ex_data` | `review-symbol_BIO_get_ex_data` | held · fixed (batch) |
| `1` | `BIO_gethostbyname` | function | `0` | `hostent` | `1` | `wrap-symbol_BIO_get_ex_data` | `review-symbol_BIO_get_ex_data` | held · fixed (batch) |
| `1` | `BIO_gets` | function | `17` | `bio_st` | `1` | `wrap-symbol_BIO_get_ex_data` | `review-symbol_BIO_get_ex_data` | held · fixed (batch) |
| `1` | `BIO_hex_string` | function | `3` | `bio_st` | `1` | `wrap-symbol_BIO_get_ex_data` | `review-symbol_BIO_get_ex_data` | held · fixed (batch) |
| `1` | `BIO_indent` | function | `11` | `bio_st` | `1` | `wrap-symbol_BIO_get_ex_data` | `review-symbol_BIO_get_ex_data` | held · fixed (batch) |
| `1` | `BIO_int_ctrl` | function | `6` | `bio_st` | `1` | `wrap-symbol_BIO_get_ex_data` | `review-symbol_BIO_get_ex_data` | held · fixed (batch) |
| `1` | `BIO_listen` | function | `1` | `bio_addr_st` | `1` | `wrap-symbol_BIO_get_ex_data` | `review-symbol_BIO_get_ex_data` | held · fixed (batch) |
| `1` | `BIO_lookup` | function | `2` | `BIO_lookup_type`, `addrinfo` | `1` | `wrap-symbol_BIO_get_ex_data` | `review-symbol_BIO_get_ex_data` | held · fixed (batch) |
| `1` | `BIO_lookup_ex` | function | `1` | `addrinfo` | `1` | `wrap-symbol_BIO_get_ex_data` | `review-symbol_BIO_get_ex_data` | held · fixed (batch) |
| `1` | `BIO_meth_free` | function | `0` | `bio_method_st` | `1` | `wrap-symbol_BIO_get_ex_data` | `review-symbol_BIO_get_ex_data` | held · fixed (batch) |
| `1` | `BIO_meth_get_callback_ctrl` | function | `0` | `bio_method_st`, `bio_st` | `1` | `wrap-symbol_BIO_get_ex_data` | `review-symbol_BIO_get_ex_data` | held · fixed (batch) |
| `1` | `BIO_meth_get_create` | function | `0` | `bio_method_st`, `bio_st` | `1` | `wrap-symbol_BIO_get_ex_data` | `review-symbol_BIO_get_ex_data` | held · fixed (batch) |
| `1` | `BIO_meth_get_ctrl` | function | `0` | `bio_method_st`, `bio_st` | `1` | `wrap-symbol_BIO_get_ex_data` | `review-symbol_BIO_get_ex_data` | held · fixed (batch) |
| `1` | `BIO_meth_get_destroy` | function | `0` | `bio_method_st`, `bio_st` | `1` | `wrap-symbol_BIO_get_ex_data` | `review-symbol_BIO_get_ex_data` | held · fixed (batch) |
| `1` | `BIO_meth_get_gets` | function | `0` | `bio_method_st`, `bio_st` | `1` | `wrap-symbol_BIO_get_ex_data` | `review-symbol_BIO_get_ex_data` | held · fixed (batch) |
| `1` | `BIO_meth_get_puts` | function | `0` | `bio_method_st`, `bio_st` | `1` | `wrap-symbol_BIO_get_ex_data` | `review-symbol_BIO_get_ex_data` | held · fixed (batch) |
| `1` | `BIO_meth_get_read` | function | `0` | `bio_method_st`, `bio_st` | `1` | `wrap-symbol_BIO_get_ex_data` | `review-symbol_BIO_get_ex_data` | held · fixed (batch) |
| `1` | `BIO_meth_get_read_ex` | function | `0` | `bio_method_st`, `bio_st` | `1` | `wrap-symbol_BIO_get_ex_data` | `review-symbol_BIO_get_ex_data` | held · fixed (batch) |
| `1` | `BIO_meth_get_write` | function | `0` | `bio_method_st`, `bio_st` | `1` | `wrap-symbol_BIO_get_ex_data` | `review-symbol_BIO_get_ex_data` | held · fixed (batch) |
| `1` | `BIO_meth_get_write_ex` | function | `0` | `bio_method_st`, `bio_st` | `1` | `wrap-symbol_BIO_get_ex_data` | `review-symbol_BIO_get_ex_data` | held · fixed (batch) |
| `1` | `BIO_meth_new` | function | `0` | `bio_method_st` | `1` | `wrap-symbol_BIO_get_ex_data` | `review-symbol_BIO_get_ex_data` | held · fixed (batch) |
| `1` | `BIO_meth_set_callback_ctrl` | function | `0` | `bio_method_st`, `bio_st` | `1` | `wrap-symbol_BIO_get_ex_data` | `review-symbol_BIO_get_ex_data` | held · fixed (batch) |
| `1` | `BIO_meth_set_create` | function | `0` | `bio_method_st`, `bio_st` | `1` | `wrap-symbol_BIO_get_ex_data` | `review-symbol_BIO_get_ex_data` | held · fixed (batch) |
| `1` | `BIO_meth_set_ctrl` | function | `0` | `bio_method_st`, `bio_st` | `1` | `wrap-symbol_BIO_get_ex_data` | `review-symbol_BIO_get_ex_data` | held · fixed (batch) |
| `1` | `BIO_meth_set_destroy` | function | `0` | `bio_method_st`, `bio_st` | `1` | `wrap-symbol_BIO_get_ex_data` | `review-symbol_BIO_get_ex_data` | held · fixed (batch) |
| `1` | `BIO_meth_set_gets` | function | `0` | `bio_method_st`, `bio_st` | `1` | `wrap-symbol_BIO_get_ex_data` | `review-symbol_BIO_get_ex_data` | held · fixed (batch) |
| `1` | `BIO_meth_set_puts` | function | `0` | `bio_method_st`, `bio_st` | `1` | `wrap-symbol_BIO_get_ex_data` | `review-symbol_BIO_get_ex_data` | held · fixed (batch) |
| `1` | `BIO_meth_set_read` | function | `0` | `bio_method_st`, `bio_st` | `1` | `wrap-symbol_BIO_get_ex_data` | `review-symbol_BIO_get_ex_data` | held · fixed (batch) |
| `1` | `BIO_meth_set_read_ex` | function | `0` | `bio_method_st`, `bio_st` | `1` | `wrap-symbol_BIO_get_ex_data` | `review-symbol_BIO_get_ex_data` | held · fixed (batch) |
| `1` | `BIO_meth_set_write` | function | `0` | `bio_method_st`, `bio_st` | `1` | `wrap-symbol_BIO_get_ex_data` | `review-symbol_BIO_get_ex_data` | held · fixed (batch) |
| `1` | `BIO_meth_set_write_ex` | function | `0` | `bio_method_st`, `bio_st` | `1` | `wrap-symbol_BIO_get_ex_data` | `review-symbol_BIO_get_ex_data` | held · fixed (batch) |
| `1` | `BIO_method_name` | function | `0` | `bio_st` | `1` | `wrap-symbol_BIO_get_ex_data` | `review-symbol_BIO_get_ex_data` | held · fixed (batch) |
| `1` | `BIO_method_type` | function | `4` | `bio_st` | `1` | `wrap-symbol_BIO_get_ex_data` | `review-symbol_BIO_get_ex_data` | held · fixed (batch) |
| `1` | `BIO_new` | function | `89` | `bio_method_st`, `bio_st`, `ossl_lib_ctx_st` | `1` | `wrap-symbol_BIO_get_ex_data` | `review-symbol_BIO_get_ex_data` | held · fixed (batch) |
| `1` | `BIO_new_accept` | function | `0` | `bio_st` | `1` | `wrap-symbol_BIO_get_ex_data` | `review-symbol_BIO_get_ex_data` | held · fixed (batch) |
| `1` | `BIO_new_bio_dgram_pair` | function | `0` | `bio_st` | `1` | `wrap-symbol_BIO_get_ex_data` | `review-symbol_BIO_get_ex_data` | held · fixed (batch) |
| `1` | `BIO_new_bio_pair` | function | `0` | `bio_st` | `1` | `wrap-symbol_BIO_get_ex_data` | `review-symbol_BIO_get_ex_data` | held · fixed (batch) |
| `1` | `BIO_new_connect` | function | `1` | `bio_st` | `1` | `wrap-symbol_BIO_get_ex_data` | `review-symbol_BIO_get_ex_data` | held · fixed (batch) |
| `1` | `BIO_new_dgram` | function | `1` | `bio_st` | `1` | `wrap-symbol_BIO_get_ex_data` | `review-symbol_BIO_get_ex_data` | held · fixed (batch) |
| `1` | `BIO_new_ex` | function | `2` | `bio_method_st`, `bio_st`, `ossl_lib_ctx_st` | `1` | `wrap-symbol_BIO_get_ex_data` | `review-symbol_BIO_get_ex_data` | held · fixed (batch) |
| `1` | `BIO_new_fd` | function | `0` | `bio_st` | `1` | `wrap-symbol_BIO_get_ex_data` | `review-symbol_BIO_get_ex_data` | held · fixed (batch) |
| `1` | `BIO_new_file` | function | `12` | `_IO_FILE`, `bio_st` | `1` | `wrap-symbol_BIO_get_ex_data` | `review-symbol_BIO_get_ex_data` | held · fixed (batch) |
| `1` | `BIO_new_fp` | function | `14` | `_IO_FILE`, `bio_st` | `1` | `wrap-symbol_BIO_get_ex_data` | `review-symbol_BIO_get_ex_data` | held · fixed (batch) |
| `1` | `BIO_new_from_core_bio` | function | `0` | `bio_st`, `ossl_core_bio_st`, `ossl_lib_ctx_st` | `1` | `wrap-symbol_BIO_get_ex_data` | `review-symbol_BIO_get_ex_data` | held · fixed (batch) |
| `1` | `BIO_new_mem_buf` | function | `7` | `bio_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | `review-symbol_BIO_new_mem_buf` | held · fixed (batch) |
| `1` | `BIO_new_socket` | function | `1` | `bio_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | `review-symbol_BIO_new_mem_buf` | held · fixed (batch) |
| `1` | `BIO_next` | function | `26` | `bio_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | `review-symbol_BIO_new_mem_buf` | held · fixed (batch) |
| `1` | `BIO_nread` | function | `0` | `bio_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | `review-symbol_BIO_new_mem_buf` | held · fixed (batch) |
| `1` | `BIO_nread0` | function | `0` | `bio_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | `review-symbol_BIO_new_mem_buf` | held · fixed (batch) |
| `1` | `BIO_number_read` | function | `0` | `bio_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | `review-symbol_BIO_new_mem_buf` | held · fixed (batch) |
| `1` | `BIO_number_written` | function | `0` | `bio_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | `review-symbol_BIO_new_mem_buf` | held · fixed (batch) |
| `1` | `BIO_nwrite` | function | `0` | `bio_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | `review-symbol_BIO_new_mem_buf` | held · fixed (batch) |
| `1` | `BIO_nwrite0` | function | `0` | `bio_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | `review-symbol_BIO_new_mem_buf` | held · fixed (batch) |
| `1` | `BIO_parse_hostserv` | function | `3` | `BIO_hostserv_priorities` | `1` | `wrap-symbol_BIO_new_mem_buf` | `review-symbol_BIO_new_mem_buf` | held · fixed (batch) |
| `1` | `BIO_pop` | function | `13` | `bio_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | `review-symbol_BIO_new_mem_buf` | held · fixed (batch) |
| `1` | `BIO_printf` | function | `161` | `__va_list_tag`, `bio_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | `review-symbol_BIO_new_mem_buf` | held · fixed (batch) |
| `1` | `BIO_ptr_ctrl` | function | `0` | `bio_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | `review-symbol_BIO_new_mem_buf` | held · fixed (batch) |
| `1` | `BIO_push` | function | `17` | `bio_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | `review-symbol_BIO_new_mem_buf` | held · fixed (batch) |
| `1` | `BIO_puts` | function | `82` | `bio_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | `review-symbol_BIO_new_mem_buf` | held · fixed (batch) |
| `1` | `BIO_read` | function | `30` | `bio_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | `review-symbol_BIO_new_mem_buf` | held · fixed (batch) |
| `1` | `BIO_read_ex` | function | `2` | `bio_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | `review-symbol_BIO_new_mem_buf` | held · fixed (batch) |
| `1` | `BIO_s_accept` | function | `1` | `bio_method_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | `review-symbol_BIO_new_mem_buf` | held · fixed (batch) |
| `1` | `BIO_s_bio` | function | `1` | `bio_method_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | `review-symbol_BIO_new_mem_buf` | held · fixed (batch) |
| `1` | `BIO_s_connect` | function | `1` | `bio_method_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | `review-symbol_BIO_new_mem_buf` | held · fixed (batch) |
| `1` | `BIO_s_core` | function | `1` | `bio_method_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | `review-symbol_BIO_new_mem_buf` | held · fixed (batch) |
| `1` | `BIO_s_datagram` | function | `1` | `bio_method_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | `review-symbol_BIO_new_mem_buf` | held · fixed (batch) |
| `1` | `BIO_s_dgram_mem` | function | `0` | `bio_method_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | `review-symbol_BIO_new_mem_buf` | held · fixed (batch) |
| `1` | `BIO_s_dgram_pair` | function | `1` | `bio_method_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | `review-symbol_BIO_new_mem_buf` | held · fixed (batch) |
| `1` | `BIO_s_fd` | function | `1` | `bio_method_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | `review-symbol_BIO_new_mem_buf` | held · fixed (batch) |
| `1` | `BIO_s_file` | function | `48` | `bio_method_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | `review-symbol_BIO_new_mem_buf` | held · fixed (batch) |
| `1` | `BIO_s_log` | function | `0` | `bio_method_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | `review-symbol_BIO_new_mem_buf` | held · fixed (batch) |
| `1` | `BIO_s_mem` | function | `20` | `bio_method_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | `review-symbol_BIO_new_mem_buf` | held · fixed (batch) |
| `1` | `BIO_s_null` | function | `3` | `bio_method_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | `review-symbol_BIO_new_mem_buf` | held · fixed (batch) |
| `1` | `BIO_s_secmem` | function | `1` | `bio_method_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | `review-symbol_BIO_new_mem_buf` | held · fixed (batch) |
| `1` | `BIO_s_socket` | function | `1` | `bio_method_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | `review-symbol_BIO_new_mem_buf` | held · fixed (batch) |
| `1` | `BIO_set_callback` | function | `0` | `bio_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | `review-symbol_BIO_new_mem_buf` | held · fixed (batch) |
| `1` | `BIO_set_callback_arg` | function | `1` | `bio_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | `review-symbol_BIO_new_mem_buf` | held · fixed (batch) |
| `1` | `BIO_set_data` | function | `11` | `bio_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | `review-symbol_BIO_new_mem_buf` | held · fixed (batch) |
| `1` | `BIO_set_ex_data` | function | `0` | `bio_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | `review-symbol_BIO_new_mem_buf` | held · fixed (batch) |
| `1` | `BIO_set_flags` | function | `23` | `bio_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | `review-symbol_BIO_new_mem_buf` | held · fixed (batch) |
| `1` | `BIO_set_init` | function | `14` | `bio_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | `review-symbol_BIO_new_mem_buf` | held · fixed (batch) |
| `1` | `BIO_set_next` | function | `0` | `bio_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | `review-symbol_BIO_new_mem_buf` | held · fixed (batch) |
| `1` | `BIO_set_retry_reason` | function | `0` | `bio_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | `review-symbol_BIO_new_mem_buf` | held · fixed (batch) |
| `1` | `BIO_set_send_flags` | function | `0` | `bio_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | `review-symbol_BIO_new_mem_buf` | held · fixed (batch) |
| `1` | `BIO_set_shutdown` | function | `0` | `bio_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | `review-symbol_BIO_new_mem_buf` | held · fixed (batch) |
| `1` | `BIO_snprintf` | function | `34` | `__va_list_tag` | `1` | `wrap-symbol_BIO_new_mem_buf` | `review-symbol_BIO_new_mem_buf` | held · fixed (batch) |
| `1` | `BIO_test_flags` | function | `12` | `bio_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | `review-symbol_BIO_new_mem_buf` | held · fixed (batch) |
| `1` | `BIO_up_ref` | function | `3` | `bio_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | `review-symbol_BIO_new_mem_buf` | held · fixed (batch) |
| `1` | `BIO_vfree` | function | `1` | `bio_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | `review-symbol_BIO_new_mem_buf` | held · fixed (batch) |
| `1` | `BIO_vprintf` | function | `2` | `__va_list_tag`, `bio_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | `review-symbol_BIO_new_mem_buf` | held · fixed (batch) |
| `1` | `BIO_vsnprintf` | function | `3` | `__va_list_tag` | `1` | `wrap-symbol_BIO_new_mem_buf` | `review-symbol_BIO_new_mem_buf` | held · fixed (batch) |
| `1` | `BIO_wait` | function | `2` | `bio_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | `review-symbol_BIO_new_mem_buf` | held · fixed (batch) |
| `1` | `BIO_write` | function | `67` | `bio_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | `review-symbol_BIO_new_mem_buf` | held · fixed (batch) |
| `1` | `BIO_write_ex` | function | `3` | `bio_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | `review-symbol_BIO_new_mem_buf` | held · fixed (batch) |
| `1` | `OBJ_NAME_do_all` | function | `4` | `obj_name_st` | `1` | `wrap-symbol_OBJ_NAME_do_all` | `review-symbol_OBJ_NAME_do_all` | held · fixed (batch) |
| `1` | `OBJ_NAME_do_all_sorted` | function | `2` | `obj_name_st` | `1` | `wrap-symbol_OBJ_NAME_do_all` | `review-symbol_OBJ_NAME_do_all` | held · fixed (batch) |
| `1` | `OBJ_create_objects` | function | `0` | `bio_st` | `1` | `wrap-symbol_OBJ_NAME_do_all` | `review-symbol_OBJ_NAME_do_all` | held · fixed (batch) |
| `1` | `OPENSSL_sk_deep_copy` | function | `54` | `stack_st`, `OPENSSL_sk_copyfunc`, `OPENSSL_sk_freefunc` | `1` | `wrap-symbol_OBJ_NAME_do_all` | `review-symbol_OBJ_NAME_do_all` | held · fixed (batch) |
| `1` | `OPENSSL_sk_delete` | function | `56` | `stack_st` | `1` | `wrap-symbol_OBJ_NAME_do_all` | `review-symbol_OBJ_NAME_do_all` | held · fixed (batch) |
| `1` | `OPENSSL_sk_delete_ptr` | function | `52` | `stack_st` | `1` | `wrap-symbol_OBJ_NAME_do_all` | `review-symbol_OBJ_NAME_do_all` | held · fixed (batch) |
| `1` | `OPENSSL_sk_dup` | function | `53` | `stack_st` | `1` | `wrap-symbol_OBJ_NAME_do_all` | `review-symbol_OBJ_NAME_do_all` | held · fixed (batch) |
| `1` | `OPENSSL_sk_find` | function | `63` | `stack_st` | `1` | `wrap-symbol_OBJ_NAME_do_all` | `review-symbol_OBJ_NAME_do_all` | held · fixed (batch) |
| `1` | `OPENSSL_sk_find_all` | function | `50` | `stack_st` | `1` | `wrap-symbol_OBJ_NAME_do_all` | `review-symbol_OBJ_NAME_do_all` | held · fixed (batch) |
| `1` | `OPENSSL_sk_find_ex` | function | `49` | `stack_st` | `1` | `wrap-symbol_OBJ_NAME_do_all` | `review-symbol_OBJ_NAME_do_all` | held · fixed (batch) |
| `1` | `OPENSSL_sk_free` | function | `116` | `stack_st` | `1` | `wrap-symbol_OBJ_NAME_do_all` | `review-symbol_OBJ_NAME_do_all` | held · fixed (batch) |
| `1` | `OPENSSL_sk_insert` | function | `54` | `stack_st` | `1` | `wrap-symbol_OBJ_NAME_do_all` | `review-symbol_OBJ_NAME_do_all` | held · fixed (batch) |
| `1` | `OPENSSL_sk_is_sorted` | function | `50` | `stack_st` | `1` | `wrap-symbol_OBJ_NAME_do_all` | `review-symbol_OBJ_NAME_do_all` | held · fixed (batch) |
| `1` | `OPENSSL_sk_new` | function | `64` | `stack_st`, `OPENSSL_sk_compfunc` | `1` | `wrap-symbol_OBJ_NAME_do_all` | `review-symbol_OBJ_NAME_do_all` | held · fixed (batch) |
| `1` | `OPENSSL_sk_new_null` | function | `133` | `stack_st` | `1` | `wrap-symbol_OBJ_NAME_do_all` | `review-symbol_OBJ_NAME_do_all` | held · fixed (batch) |
| `1` | `OPENSSL_sk_new_reserve` | function | `68` | `stack_st`, `OPENSSL_sk_compfunc` | `1` | `wrap-symbol_OBJ_NAME_do_all` | `review-symbol_OBJ_NAME_do_all` | held · fixed (batch) |
| `1` | `OPENSSL_sk_num` | function | `399` | `stack_st` | `1` | `wrap-symbol_OBJ_NAME_do_all` | `review-symbol_OBJ_NAME_do_all` | held · fixed (batch) |
| `1` | `OPENSSL_sk_pop` | function | `62` | `stack_st` | `1` | `wrap-symbol_OBJ_NAME_do_all` | `review-symbol_OBJ_NAME_do_all` | held · fixed (batch) |
| `1` | `OPENSSL_sk_pop_free` | function | `155` | `stack_st`, `OPENSSL_sk_freefunc` | `1` | `wrap-symbol_OBJ_NAME_do_all` | `review-symbol_OBJ_NAME_do_all` | held · fixed (batch) |
| `1` | `OPENSSL_sk_push` | function | `169` | `stack_st` | `1` | `wrap-symbol_OBJ_NAME_do_all` | `review-symbol_OBJ_NAME_do_all` | held · fixed (batch) |
| `1` | `OPENSSL_sk_reserve` | function | `51` | `stack_st` | `1` | `wrap-symbol_OBJ_NAME_do_all` | `review-symbol_OBJ_NAME_do_all` | held · fixed (batch) |
| `1` | `OPENSSL_sk_set` | function | `59` | `stack_st` | `1` | `wrap-symbol_OBJ_NAME_do_all` | `review-symbol_OBJ_NAME_do_all` | held · fixed (batch) |
| `1` | `OPENSSL_sk_set_cmp_func` | function | `54` | `stack_st`, `OPENSSL_sk_compfunc` | `1` | `wrap-symbol_OBJ_NAME_do_all` | `review-symbol_OBJ_NAME_do_all` | held · fixed (batch) |
| `1` | `OPENSSL_sk_set_cmp_thunks` | function | `367` | `stack_st` | `1` | `wrap-symbol_OBJ_NAME_do_all` | `review-symbol_OBJ_NAME_do_all` | held · fixed (batch) |
| `1` | `OPENSSL_sk_shift` | function | `54` | `stack_st` | `1` | `wrap-symbol_OBJ_NAME_do_all` | `review-symbol_OBJ_NAME_do_all` | held · fixed (batch) |
| `1` | `OPENSSL_sk_sort` | function | `62` | `stack_st` | `1` | `wrap-symbol_OBJ_NAME_do_all` | `review-symbol_OBJ_NAME_do_all` | held · fixed (batch) |
| `1` | `OPENSSL_sk_unshift` | function | `49` | `stack_st` | `1` | `wrap-symbol_OBJ_NAME_do_all` | `review-symbol_OBJ_NAME_do_all` | held · fixed (batch) |
| `1` | `OPENSSL_sk_value` | function | `369` | `stack_st` | `1` | `wrap-symbol_OBJ_NAME_do_all` | `review-symbol_OBJ_NAME_do_all` | held · fixed (batch) |
| `1` | `OPENSSL_sk_zero` | function | `49` | `stack_st` | `1` | `wrap-symbol_OBJ_NAME_do_all` | `review-symbol_OBJ_NAME_do_all` | held · fixed (batch) |
| `2` | `ASN1_OBJECT_create` | function | `0` | `asn1_object_st` | `1` | `wrap-symbol_ASN1_OBJECT_create` | `review-symbol_ASN1_OBJECT_create` | held · fixed (batch) |
| `2` | `ASN1_OBJECT_free` | function | `48` | `asn1_object_st` | `1` | `wrap-symbol_ASN1_OBJECT_create` | `review-symbol_ASN1_OBJECT_create` | held · fixed (batch) |
| `2` | `ASN1_OBJECT_it` | function | `0` | `ASN1_ITEM_st`, `ASN1_TEMPLATE_st` | `1` | `wrap-symbol_ASN1_OBJECT_create` | `review-symbol_ASN1_OBJECT_create` | held · fixed (batch) |
| `2` | `ASN1_OBJECT_new` | function | `0` | `asn1_object_st` | `1` | `wrap-symbol_ASN1_OBJECT_create` | `review-symbol_ASN1_OBJECT_create` | held · fixed (batch) |
| `2` | `ASN1_STRING_TABLE_cleanup` | function | `1` | `stack_st_ASN1_STRING_TABLE` | `1` | `wrap-symbol_ASN1_OBJECT_create` | `review-symbol_ASN1_OBJECT_create` | held · fixed (batch) |
| `2` | `ASN1_STRING_TABLE_get` | function | `2` | `asn1_string_table_st`, `ossl_init_settings_st`, `stack_st`, `stack_st_ASN1_STRING_TABLE` | `1` | `wrap-symbol_ASN1_OBJECT_create` | `review-symbol_ASN1_OBJECT_create` | held · fixed (batch) |
| `2` | `BIO_asn1_get_prefix` | function | `0` | `bio_st`, `asn1_ps_func` | `1` | `wrap-symbol_ASN1_OBJECT_create` | `review-symbol_ASN1_OBJECT_create` | held · fixed (batch) |
| `2` | `BIO_asn1_get_suffix` | function | `0` | `bio_st`, `asn1_ps_func` | `1` | `wrap-symbol_ASN1_OBJECT_create` | `review-symbol_ASN1_OBJECT_create` | held · fixed (batch) |
| `2` | `BIO_asn1_set_prefix` | function | `1` | `bio_st`, `asn1_ps_func` | `1` | `wrap-symbol_ASN1_OBJECT_create` | `review-symbol_ASN1_OBJECT_create` | held · fixed (batch) |
| `2` | `BIO_asn1_set_suffix` | function | `1` | `bio_st`, `asn1_ps_func` | `1` | `wrap-symbol_ASN1_OBJECT_create` | `review-symbol_ASN1_OBJECT_create` | held · fixed (batch) |
| `2` | `BIO_callback_ctrl` | function | `11` | `bio_st`, `BIO_info_cb` | `1` | `wrap-symbol_ASN1_OBJECT_create` | `review-symbol_ASN1_OBJECT_create` | held · fixed (batch) |
| `2` | `BIO_get_callback_ex` | function | `2` | `bio_st`, `BIO_callback_fn_ex` | `1` | `wrap-symbol_ASN1_OBJECT_create` | `review-symbol_ASN1_OBJECT_create` | held · fixed (batch) |
| `2` | `BIO_get_rpoll_descriptor` | function | `0` | `bio_poll_descriptor_st`, `bio_st` | `1` | `wrap-symbol_ASN1_OBJECT_create` | `review-symbol_ASN1_OBJECT_create` | held · fixed (batch) |
| `2` | `BIO_get_wpoll_descriptor` | function | `0` | `bio_poll_descriptor_st`, `bio_st` | `1` | `wrap-symbol_ASN1_OBJECT_create` | `review-symbol_ASN1_OBJECT_create` | held · fixed (batch) |
| `2` | `BIO_meth_get_recvmmsg` | function | `0` | `bio_method_st`, `bio_msg_st`, `bio_st` | `1` | `wrap-symbol_BIO_meth_get_recvmmsg` | `review-symbol_ASN1_OBJECT_create` | held · fixed (batch) |
| `2` | `BIO_meth_get_sendmmsg` | function | `0` | `bio_method_st`, `bio_msg_st`, `bio_st` | `1` | `wrap-symbol_BIO_meth_get_recvmmsg` | `review-symbol_ASN1_OBJECT_create` | held · fixed (batch) |
| `2` | `BIO_meth_set_recvmmsg` | function | `0` | `bio_method_st`, `bio_msg_st`, `bio_st` | `1` | `wrap-symbol_ASN1_OBJECT_create` | `review-symbol_ASN1_OBJECT_create` | held · fixed (batch) |
| `2` | `BIO_meth_set_sendmmsg` | function | `0` | `bio_method_st`, `bio_msg_st`, `bio_st` | `1` | `wrap-symbol_ASN1_OBJECT_create` | `review-symbol_ASN1_OBJECT_create` | held · fixed (batch) |
| `2` | `BIO_recvmmsg` | function | `1` | `bio_msg_st`, `bio_st` | `1` | `wrap-symbol_ASN1_OBJECT_create` | `review-symbol_ASN1_OBJECT_create` | held · fixed (batch) |
| `2` | `BIO_sendmmsg` | function | `1` | `bio_msg_st`, `bio_st` | `1` | `wrap-symbol_ASN1_OBJECT_create` | `review-symbol_ASN1_OBJECT_create` | held · fixed (batch) |
| `2` | `BIO_set_callback_ex` | function | `1` | `bio_st`, `BIO_callback_fn_ex` | `1` | `wrap-symbol_ASN1_OBJECT_create` | `review-symbol_ASN1_OBJECT_create` | held · fixed (batch) |
| `2` | `BIO_sock_info` | function | `1` | `BIO_sock_info_type`, `BIO_sock_info_u` | `1` | `wrap-symbol_ASN1_OBJECT_create` | `review-symbol_ASN1_OBJECT_create` | held · fixed (batch) |
| `2` | `OBJ_NAME_add` | function | `4` | `stack_st_NAME_FUNCS` | `1` | `wrap-symbol_ASN1_OBJECT_create` | `review-symbol_ASN1_OBJECT_create` | held · fixed (batch) |
| `2` | `OBJ_NAME_cleanup` | function | `1` | `lhash_st_OBJ_NAME`, `stack_st_NAME_FUNCS` | `1` | `wrap-symbol_ASN1_OBJECT_create` | `review-symbol_ASN1_OBJECT_create` | held · fixed (batch) |
| `2` | `OBJ_NAME_new_index` | function | `0` | `stack_st_NAME_FUNCS` | `1` | `wrap-symbol_ASN1_OBJECT_create` | `review-symbol_ASN1_OBJECT_create` | held · fixed (batch) |
| `2` | `OBJ_NAME_remove` | function | `1` | `stack_st_NAME_FUNCS` | `1` | `wrap-symbol_ASN1_OBJECT_create` | `review-symbol_ASN1_OBJECT_create` | held · fixed (batch) |
| `2` | `OBJ_add_object` | function | `0` | `asn1_object_st` | `1` | `wrap-symbol_ASN1_OBJECT_create` | `review-symbol_ASN1_OBJECT_create` | held · fixed (batch) |
| `2` | `OBJ_add_sigid` | function | `1` | `stack_st_nid_triple` | `1` | `wrap-symbol_ASN1_OBJECT_create` | `review-symbol_ASN1_OBJECT_create` | held · fixed (batch) |
| `2` | `OBJ_cmp` | function | `26` | `asn1_object_st` | `1` | `wrap-symbol_ASN1_OBJECT_create` | `review-symbol_ASN1_OBJECT_create` | held · fixed (batch) |
| `2` | `OBJ_dup` | function | `19` | `asn1_object_st` | `1` | `wrap-symbol_ASN1_OBJECT_create` | `review-symbol_ASN1_OBJECT_create` | held · fixed (batch) |
| `2` | `OBJ_find_sigid_by_algs` | function | `4` | `stack_st_nid_triple` | `1` | `wrap-symbol_ASN1_OBJECT_create` | `review-symbol_ASN1_OBJECT_create` | held · fixed (batch) |
| `2` | `OBJ_get0_data` | function | `1` | `asn1_object_st` | `1` | `wrap-symbol_ASN1_OBJECT_create` | `review-symbol_ASN1_OBJECT_create` | held · fixed (batch) |
| `2` | `OBJ_length` | function | `4` | `asn1_object_st` | `1` | `wrap-symbol_ASN1_OBJECT_create` | `review-symbol_ASN1_OBJECT_create` | held · fixed (batch) |
| `2` | `OBJ_nid2obj` | function | `119` | `asn1_object_st` | `1` | `wrap-symbol_ASN1_OBJECT_create` | `review-symbol_ASN1_OBJECT_create` | held · fixed (batch) |
| `2` | `OBJ_obj2nid` | function | `180` | `asn1_object_st` | `1` | `wrap-symbol_ASN1_OBJECT_create` | `review-symbol_ASN1_OBJECT_create` | held · fixed (batch) |
| `2` | `OBJ_obj2txt` | function | `41` | `asn1_object_st`, `bignum_st` | `1` | `wrap-symbol_ASN1_OBJECT_create` | `review-symbol_ASN1_OBJECT_create` | held · fixed (batch) |
| `2` | `OBJ_sigid_free` | function | `1` | `stack_st_nid_triple` | `1` | `wrap-symbol_ASN1_OBJECT_create` | `review-symbol_ASN1_OBJECT_create` | held · fixed (batch) |
| `2` | `OBJ_txt2nid` | function | `6` | `asn1_object_st` | `1` | `wrap-symbol_ASN1_OBJECT_create` | `review-symbol_ASN1_OBJECT_create` | held · fixed (batch) |
| `2` | `OBJ_txt2obj` | function | `19` | `asn1_object_st` | `1` | `wrap-symbol_ASN1_OBJECT_create` | `review-symbol_ASN1_OBJECT_create` | held · fixed (batch) |
| `2` | `OPENSSL_sk_set_copy_thunks` | function | `367` | `stack_st`, `OPENSSL_sk_copyfunc_thunk` | `1` | `wrap-symbol_ASN1_OBJECT_create` | `review-symbol_ASN1_OBJECT_create` | held · fixed (batch) |
| `2` | `OPENSSL_sk_set_thunks` | function | `416` | `stack_st`, `OPENSSL_sk_freefunc_thunk` | `1` | `wrap-symbol_ASN1_OBJECT_create` | `review-symbol_ASN1_OBJECT_create` | held · fixed (batch) |
| `3` | `BIO_dup_chain` | function | `1` | `bio_st`, `crypto_ex_data_st` | `1` | `wrap-symbol_BIO_dup_chain` | `review-symbol_BIO_dup_chain` | held · fixed (batch) |
| `4` | `ASN1_STRING_clear_free` | function | `4` | `asn1_string_st` | `1` | `wrap-symbol_ASN1_STRING_clear_free` | `review-symbol_ASN1_STRING_clear_free` | held · fixed (batch) |
| `4` | `ASN1_STRING_cmp` | function | `7` | `asn1_string_st` | `1` | `wrap-symbol_ASN1_STRING_clear_free` | `review-symbol_ASN1_STRING_clear_free` | held · fixed (batch) |
| `4` | `ASN1_STRING_copy` | function | `11` | `asn1_string_st` | `1` | `wrap-symbol_ASN1_STRING_clear_free` | `review-symbol_ASN1_STRING_clear_free` | held · fixed (batch) |
| `4` | `ASN1_STRING_dup` | function | `14` | `asn1_string_st` | `1` | `wrap-symbol_ASN1_STRING_clear_free` | `review-symbol_ASN1_STRING_clear_free` | held · fixed (batch) |
| `4` | `ASN1_STRING_free` | function | `43` | `asn1_string_st` | `1` | `wrap-symbol_ASN1_STRING_clear_free` | `review-symbol_ASN1_STRING_clear_free` | held · fixed (batch) |
| `4` | `ASN1_STRING_get0_data` | function | `38` | `asn1_string_st` | `1` | `wrap-symbol_ASN1_STRING_clear_free` | `review-symbol_ASN1_STRING_clear_free` | held · fixed (batch) |
| `4` | `ASN1_STRING_get_length` | function | `40` | `asn1_string_st` | `1` | `wrap-symbol_ASN1_STRING_clear_free` | `review-symbol_ASN1_STRING_clear_free` | held · fixed (batch) |
| `4` | `ASN1_STRING_length` | function | `0` | `asn1_string_st` | `1` | `wrap-symbol_ASN1_STRING_clear_free` | `review-symbol_ASN1_STRING_clear_free` | held · fixed (batch) |
| `4` | `ASN1_STRING_length_set` | function | `0` | `asn1_string_st` | `1` | `wrap-symbol_ASN1_STRING_clear_free` | `review-symbol_ASN1_STRING_clear_free` | held · fixed (batch) |
| `4` | `ASN1_STRING_new` | function | `17` | `asn1_string_st` | `1` | `wrap-symbol_ASN1_STRING_clear_free` | `review-symbol_ASN1_STRING_clear_free` | held · fixed (batch) |
| `4` | `ASN1_STRING_new_not_owned` | function | `0` | `asn1_string_st` | `1` | `wrap-symbol_ASN1_STRING_clear_free` | `review-symbol_ASN1_STRING_clear_free` | held · fixed (batch) |
| `4` | `ASN1_STRING_print` | function | `10` | `asn1_string_st`, `bio_st` | `1` | `wrap-symbol_ASN1_STRING_clear_free` | `review-symbol_ASN1_STRING_clear_free` | held · fixed (batch) |
| `4` | `ASN1_STRING_print_ex` | function | `2` | `asn1_string_st`, `bio_st` | `1` | `wrap-symbol_ASN1_STRING_clear_free` | `review-symbol_ASN1_STRING_clear_free` | held · fixed (batch) |
| `4` | `ASN1_STRING_print_ex_fp` | function | `0` | `_IO_FILE`, `asn1_string_st` | `1` | `wrap-symbol_ASN1_STRING_clear_free` | `review-symbol_ASN1_STRING_clear_free` | held · fixed (batch) |
| `4` | `ASN1_STRING_set` | function | `0` | `asn1_string_st` | `1` | `wrap-symbol_ASN1_STRING_clear_free` | `review-symbol_ASN1_STRING_clear_free` | held · fixed (batch) |
| `4` | `ASN1_STRING_set0` | function | `27` | `asn1_string_st` | `1` | `wrap-symbol_ASN1_STRING_clear_free` | `review-symbol_ASN1_STRING_clear_free` | held · fixed (batch) |
| `4` | `ASN1_STRING_set1_data` | function | `24` | `asn1_string_st` | `1` | `wrap-symbol_ASN1_STRING_clear_free` | `review-symbol_ASN1_STRING_clear_free` | held · fixed (batch) |
| `4` | `ASN1_STRING_set1_string` | function | `13` | `asn1_string_st` | `1` | `wrap-symbol_ASN1_STRING_clear_free` | `review-symbol_ASN1_STRING_clear_free` | held · fixed (batch) |
| `4` | `ASN1_STRING_set_by_NID` | function | `2` | `asn1_string_st` | `1` | `wrap-symbol_ASN1_STRING_clear_free` | `review-symbol_ASN1_STRING_clear_free` | held · fixed (batch) |
| `4` | `ASN1_STRING_to_UTF8` | function | `4` | `asn1_string_st` | `1` | `wrap-symbol_ASN1_STRING_clear_free` | `review-symbol_ASN1_STRING_clear_free` | held · fixed (batch) |
| `4` | `ASN1_STRING_type` | function | `0` | `asn1_string_st` | `1` | `wrap-symbol_ASN1_STRING_clear_free` | `review-symbol_ASN1_STRING_clear_free` | held · fixed (batch) |
| `4` | `ASN1_STRING_type_new` | function | `22` | `asn1_string_st` | `1` | `wrap-symbol_ASN1_STRING_clear_free` | `review-symbol_ASN1_STRING_clear_free` | held · fixed (batch) |
| **Σ `277`** | | | **`5,734`** | | **`277`** | **`9` batches** | **`8` batches** | **`277`/`277` reviewed** |

### Batches — symbol review

| session | batch | units | rv loc | rv $ | rv wall | $/symbol |
|---|---|---|---|---|---|---|
| `2026-08-23_00-42-36_ea63` | `review-symbol_ASN1_STRING_TABLE_add` | `39` symbols | `+417/-33` | `$9.44` | `17m34s` | `$0.24` |
| `2026-08-23_00-42-36_ea63` | `review-symbol_BIO_ADDRINFO_address` | `50` symbols | `+655/-28` | `$20.31` | `33m38s` | `$0.41` |
| `2026-08-23_00-42-36_ea63` | `review-symbol_BIO_get_ex_data` | `50` symbols | `+148/-26` | `$11.22` | `20m48s` | `$0.22` |
| `2026-08-23_00-42-36_ea63` | `review-symbol_BIO_new_mem_buf` | `50` symbols | `+150/-18` | `$8.91` | `19m28s` | `$0.18` |
| `2026-08-23_00-42-36_ea63` | `review-symbol_OBJ_NAME_do_all` | `32` symbols | `+589/-41` | `$14.38` | `28m31s` | `$0.45` |
| `2026-08-23_00-42-36_ea63` | `review-symbol_ASN1_OBJECT_create` | `41` symbols | `+155/-18` | `$10.16` | `18m10s` | `$0.25` |
| `2026-08-23_00-42-36_ea63` | `review-symbol_BIO_dup_chain` | `1` symbol | `+79/-6` | `$3.86` | `10m10s` | `$3.86` |
| `2026-08-23_00-42-36_ea63` | `review-symbol_ASN1_STRING_clear_free` | `22` symbols | `+233/-7` | `$8.36` | `16m25s` | `$0.38` |
| **Σ** | **`8` agents** | **`277` symbols** | **`+2,426/-177`** | **`$86.65`** | **`33m38s`** (longest; `2h44m47s` serial, `4.9`x) | **`$0.31`** |

### Batches — symbols

| DAG layer | units | loc | $ | wall | $/unit | $/loc |
|---|---|---|---|---|---|---|
| `0` | `39` | `841` | `$9.73` | `24m09s` (`1.0`x) | `$0.25` | `$0.012` |
| `1` | `182` | `3,900` | `$54.96` | `34m23s` (`3.1`x) | `$0.30` | `$0.014` |
| `2` | `43` (`41` unique) | `979` | `$15.86` | `33m52s` (`1.2`x) | `$0.37` | `$0.016` |
| `3` | `1` | `108` | `$3.50` | `6m15s` (`1.0`x) | `$3.50` | `$0.032` |
| `4` | `22` | `590` | `$7.77` | `26m17s` (`1.0`x) | `$0.35` | `$0.013` |
| **Σ** | **`287` submissions (`285` unique)** | **`6,418`** | **`$91.82`** | **`2h39m45s`** (`1.3`x, session wall) | **`$0.32`** | **`$0.014`** |
## Safety audit

`crustify-audit <crate> unsafe`, unseeded — tree-wide, not
per seed. Two snapshots: the tree the review pass judged, and the tree it
produced.

| | before review (`894f727207`) | after review (`32ada326d7`) |
|---|---|---|
| unsafe loc | `1,108` | `1,126` |
| % of loc | `27.87`% | `26.29`% |
| blocks | `624` | `641` |
| % in `impl T` | `42.31`% | `42.59`% |
| `unsafe fn` | `232` | `240` |
| ...of which not sanctioned | `82` | `90` |
| raw-ptr smell | `19` | `19` |
| void-ptr smell | `4` | `4` |
| FFI calls | `299` | `299` |
| `&`/`&mut` on a wrapper | `0` | `0` |
| field proj outside an accessor | `0` | `0` |

### All metrics

| metric | before | after | Δ | reading |
|---|---|---|---|---|
| `code_lines` | `3,975` | `4,283` | `+308` | union of HIR definition spans (denominator); `cfg`-disabled items excluded |
| `total_stmts` | `572` | `632` | `+60` | statements |
| `unsafe_blocks` | `624` | `641` | `+17` | count of `unsafe { }` blocks, macro-expanded included |
| `unsafe_block_stmts` | `29` | `37` | `+8` | statements inside them |
| `unsafe_block_lines` | `1,108` | `1,126` | `+18` | their lines, every outermost block |
| `unsafe_block_code_lines` | `1,108` | `1,126` | `+18` | **`27.87`% → `26.29`%** |
| `unsafe_blocks_wrapper_impl` | `264` | `273` | `+9` | inside `impl <wrapper T>` |
| `unsafe_blocks_ffi_export` | `3` | `4` | `+1` | inside the C-ABI gateway |
| `unsafe_fns` | `232` | `240` | `+8` | `unsafe fn` declarations, post-expansion |
| `unsafe_fns_seam` | `150` | `150` | `0` | ...the sanctioned subset |
| **`unsafe fn` smell** | **`82`** | **`90`** | **`+8`** | the remainder — read each and accept or fix it |
| `unsafe_fns_pub` | `227` | `232` | `+5` | ...of `unsafe_fns`, exported from the crate |
| `unsafe_impls` / `unsafe_traits` | `64` / `0` | `66` / `0` | `+2` / `0` | lifecycle contracts asserted once per type |
| `ffi_calls` | `299` | `299` | `0` | calls to a foreign item — the unsafe-FFI-call surface |
| `wrapper_newtypes` | `25` | `25` | `0` | LAYOUT newtypes — `repr(transparent)` over a `repr(C)` type by value, detected structurally |
| `wrapper_newtypes_declared` | `25` | `25` | `0` | the `CCell`-declared count, for comparison |
| `wrapper_declared_nonconformant` | `0` | `0` | `0` | declared but failing the structural test — **target 0** |
| `wrapper_newtypes_undeclared` | `0` | `0` | `0` | structural but undeclared — a hand-written layout newtype |
| `raw_ptr_args` | `92` | `91` | `-1` | raw-ptr positions in arguments |
| `raw_ptr_rets` | `96` | `94` | `-2` | raw-ptr positions in returns |
| **total positions** | **`188`** | **`185`** | `-3` | args + rets; disjoint, so this is the surface |
| `raw_ptr_seam` | `169` | `166` | `-3` | sanctioned: seam fn / `mod ffi_export` / `extern "C"` / ptr-to-own-`Self` |
| **smell (total − seam)** | **`19`** | **`19`** | `0` | the non-seam remainder |
| `raw_ptr_wrapped` | `4` | `4` | `0` | **of the smell**: pointee is a C type that HAS a wrapper — the actionable defect |
| `raw_ptr_in_wrapper` | `0` | `0` | `0` | **of the smell**: inside a wrapper impl — the least excusable placement |
| `raw_ptr_derefs` | `96` | `105` | `+9` | `*p` on a raw pointer (volume) |
| `ref_to_type_wrapper` | `0` | `0` | `0` | `&`/`&mut` on a layout newtype — **target 0** |
| `field_proj_wrapped` | `94` | `103` | `+9` | projection VOLUME — shares one HIR shape with `addr_of!`, not a violation |
| `field_proj_outside_impl` | `0` | `0` | `0` | projections outside any accessor — **target 0** |
| `field_ref_wrapped` | `0` | `0` | `0` | `&(*p).field` — forbidden by the translator playbook — **target 0** |
| `void_ptr_sanctioned` | `65` | `62` | `-3` | `*c_void` in a seam / `ffi_export` / `extern "C"` signature |
| `void_ptr_smell` | `4` | `4` | `0` | `*c_void` elsewhere; `void_ptr_sites` names each one |

### What the review moved

The review added `308` audited code lines and reduced unsafe density by `1.58`
percentage points. It removed three raw-pointer positions, all from sanctioned
seams, so raw-pointer smell held at `19`. Every hard structural target held at
zero: nonconformant and undeclared wrappers, raw pointers inside wrapper impls,
references to layout wrappers, field references, and field projections outside
accessors. The four void-pointer smells remain the explicitly localized erased
payload seams in `bio_lib.rs`, `obj_dat.rs`, and `stack.rs`.

## Notes

### Campaign result

The first approved subset is complete: 319 reviewed DAG units comprising 34
types, eight callbacks, and 277 public symbols. X.509 and EVP are intentionally
deferred rather than silently included. The canonical target-set review landed
25 of 25 Opus agents with no failures in `2h03m21s`.

### Lifetime review

The combined Opus review covered all ten void/string lifetime symbols in four
dependency batches. It corrected NUL and zero-length preconditions, allocator
metadata and pairing, cleansing behavior, secure-heap fallback, and the
corresponding tests and oracle records. Its four agents cost `$18.82`
API-equivalent and ran for `47m01s` session wall.

### Alignment and discriminants

The judge reproduced and fixed unaligned `in_addr`/`in6_addr` access. It also
corrected the `obj_name_st.data` alias-versus-opaque discriminant,
`ASN1_TEMPLATE` item-versus-ADB handling, ASN.1 item/function-table tags, and
the `ASN1_TYPE` UNDEF, ANY, unknown, and string-backed arms.

### Ownership and callback boundaries

`BIO_up_ref` now preserves borrowed method/buffer dependencies, `BIO_dup_chain`
tracks its source dependencies and correct chain destructor, and the non-copying
BIO regions carry the peer-owned lifetime and are unsafe where C can invalidate
them. Stack mutation/search/thunk operations no longer manufacture element
liveness. BIO dump panics resume after crossing the C callback, and
`CRYPTO_EX_DATA`, `OBJ_NAME`, and `OBJ_add_object` now model their registry,
disposer, alias-string, and dynamic-object ownership rules.

### C behavior retained by a wrap campaign

The review reproduced two OpenSSL C leaks rather than changing C: duplicating
an `ASN1_STRING` with `ASN1_STRING_FLAG_NDEF`/non-owned data can inherit a
non-owning flag on allocated storage, and `ASN1_STRING_length_set(x, 0)` can
orphan the buffer. The Rust documentation and safer alternatives record both.
The compatibility shim also rejects lengths at and above `INT_MAX`.

### Mixed callback batches

The scheduler pooled eight callbacks into symbol batches. Their rows point to `↖ batch table`; cost, wall, and loc are counted once in **Batches — symbols**.

### Scheduler admission repair

Twelve superseded agents covering 54 duplicate layer-0 units cost `$25.61`; this is excluded from landed tables but included in gross spend.

### Foundation audit correction

The corrective batch removed the two direct `BIO_METHOD` field projections.
The final 319-name seeded scan and unseeded scan agree on the whole-tree totals:
`field_proj_outside_impl = 0`, `field_ref_wrapped = 0`,
`ref_to_type_wrapper = 0`, and `wrapper_declared_nonconformant = 0`.

### Deprecated BIO configuration gap

`BIO_accept`, `BIO_get_accept_socket`, `BIO_get_host_ip`, and `BIO_get_port`
cannot be link-tested in the configured `no-deprecated` C build. Enabling the
corresponding Rust feature against that archive still fails by construction;
the default reviewed surface compiles and links.

### Regression gates

The promoted review passes `cargo fmt --check`, `cargo check --workspace`,
strict Clippy across all targets, and 247 UBSan-backed Rust tests (22 `libc`,
225 `libcrypto`). The pre-review foundation also passed all 4,463 native
OpenSSL tests. No C source changed during review.

### Accounting

`crustify-log-cost` prices every request from its recorded provider/model token
classes. The landed implementation is `$218.73`; raw lifetimes are `$13.64`;
the Opus lifetime and target reviews are `$18.82` and `$217.23`. Across all 79
recorded agents—including the superseded scheduling work and earlier review—the
tool reports `$504.81` API-equivalent and `18h48m` serial agent wall:
`review-symbol $116.26`, `review-type $130.58`, `wrap-symbol $92.06`,
`wrap-type $152.28`, and raw/other `$13.64`. The Opus runs used subscription
billing, so their `$236.05` is a comparison price, not incremental API billing;
recorded API-billed work remains `$268.76`.

### Post-campaign UB pass

Explicitly approved and pending immediately after this report snapshot.
