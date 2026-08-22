# crustify — `openssl / crypto`

## Campaign

- **target repo** — `openssl` @ `2924476b5591e691e904c4baf57894c526c4b8de`
- **target** — public `libcrypto` API subset: ASN.1 string/object, generic `STACK_OF`, BIO, narrow X.509 certificate/name/extension handling, and EVP; `libssl` excluded
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
- **branch** — `crustify/libcrypto-gpt-5.6-sol`, code tip `26c11a6472`
- **deps** — crustify-cli `a97146e` (`refactor/readonly-crates-command`), ffibox `c2178c4` (`main`)

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
- **branch** — final target-set review pending, tip `—`
- **agents** — `4` metered lifetime-review agents, over `1` session; final review pending

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
| `0` | `ASN1_TEMPLATE_st` | struct | `5` | `5` | `2` | `5` | `1` | ↖ batch table | ↖ batch table | ↖ batch table | — | — | — | pending |
| `0` | `ASN1_VALUE_st` | struct | `—` | `—` | `—` | `—` | `1` | ↖ batch table | ↖ batch table | ↖ batch table | — | — | — | pending |
| `0` | `BIO_hostserv_priorities` | enum | `—` | `—` | `—` | `—` | `1` | ↖ batch table | ↖ batch table | ↖ batch table | — | — | — | pending |
| `0` | `BIO_lookup_type` | enum | `—` | `—` | `—` | `—` | `1` | ↖ batch table | ↖ batch table | ↖ batch table | — | — | — | pending |
| `0` | `BIO_sock_info_type` | enum | `—` | `—` | `—` | `—` | `1` | ↖ batch table | ↖ batch table | ↖ batch table | — | — | — | pending |
| `0` | `DEFINE_LHASH_OF_EX` | macro | `—` | `—` | `—` | `—` | `1` | ↖ batch table | ↖ batch table | ↖ batch table | — | — | — | pending |
| `0` | `_IO_FILE` | struct | `29` | `—` | `—` | `—` | `1` | ↖ batch table | ↖ batch table | ↖ batch table | — | — | — | pending |
| `0` | `addrinfo` | struct | `8` | `7` | `2` | `—` | `1` | ↖ batch table | ↖ batch table | ↖ batch table | — | — | — | pending |
| `0` | `asn1_string_table_st` | struct | `5` | `5` | `0` | `5` | `1` | ↖ batch table | ↖ batch table | ↖ batch table | — | — | — | pending |
| `0` | `bio_addr_st` | struct | `4` | `4` | `0` | `—` | `1` | ↖ batch table | ↖ batch table | ↖ batch table | — | — | — | pending |
| `0` | `bio_method_st` | struct | `14` | `14` | `13` | `—` | `1` | ↖ batch table | ↖ batch table | ↖ batch table | — | — | — | pending |
| `0` | `bio_st` | struct | `16` | `16` | `7` | `—` | `1` | ↖ batch table | ↖ batch table | ↖ batch table | — | — | — | pending |
| `0` | `hostent` | struct | `5` | `3` | `1` | `—` | `1` | ↖ batch table | ↖ batch table | ↖ batch table | — | — | — | pending |
| `0` | `in6_addr` | struct | `4` | `1` | `0` | `—` | `1` | ↖ batch table | ↖ batch table | ↖ batch table | — | — | — | pending |
| `0` | `in_addr` | struct | `1` | `1` | `0` | `—` | `1` | ↖ batch table | ↖ batch table | ↖ batch table | — | — | — | pending |
| `0` | `lhash_st` | struct | `15` | `15` | `7` | `—` | `1` | ↖ batch table | ↖ batch table | ↖ batch table | — | — | — | pending |
| `0` | `obj_name_st` | struct | `4` | `4` | `2` | `4` | `1` | ↖ batch table | ↖ batch table | ↖ batch table | — | — | — | pending |
| `0` | `ossl_init_settings_st` | struct | `3` | `3` | `2` | `—` | `1` | ↖ batch table | ↖ batch table | ↖ batch table | — | — | — | pending |
| `0` | `ossl_lib_ctx_st` | struct | `24` | `24` | `21` | `—` | `1` | ↖ batch table | ↖ batch table | ↖ batch table | — | — | — | pending |
| `0` | `stack_st` | struct | `8` | `8` | `5` | `—` | `1` | ↖ batch table | ↖ batch table | ↖ batch table | — | — | — | pending |
| `0` | `OPENSSL_sk_compfunc` | callback | `—` | `—` | `—` | `—` | `2` | ↖ batch table | ↖ batch table | ↖ batch table | — | — | — | pending |
| `0` | `OPENSSL_sk_copyfunc` | callback | `—` | `—` | `—` | `—` | `1` | ↖ batch table | ↖ batch table | ↖ batch table | — | — | — | pending |
| `0` | `OPENSSL_sk_freefunc` | callback | `—` | `—` | `—` | `—` | `1` | ↖ batch table | ↖ batch table | ↖ batch table | — | — | — | pending |
| `1` | `ASN1_ITEM_st` | struct | `7` | `7` | `3` | `7` | `1` | ↖ batch table | ↖ batch table | ↖ batch table | — | — | — | pending |
| `1` | `BIO_sock_info_u` | struct | `1` | `1` | `1` | `1` | `1` | ↖ batch table | ↖ batch table | ↖ batch table | — | — | — | pending |
| `1` | `asn1_object_st` | struct | `6` | `6` | `3` | `—` | `1` | ↖ batch table | ↖ batch table | ↖ batch table | — | — | — | pending |
| `1` | `bignum_st` | struct | `5` | `5` | `1` | `—` | `1` | ↖ batch table | ↖ batch table | ↖ batch table | — | — | — | pending |
| `1` | `bio_msg_st` | struct | `5` | `5` | `3` | `5` | `1` | ↖ batch table | ↖ batch table | ↖ batch table | — | — | — | pending |
| `1` | `bio_poll_descriptor_st` | struct | `6` | `2` | `0` | `6` | `1` | ↖ batch table | ↖ batch table | ↖ batch table | — | — | — | pending |
| `1` | `lhash_st_OBJ_NAME` | struct | `1` | `—` | `—` | `—` | `1` | ↖ batch table | ↖ batch table | ↖ batch table | — | — | — | pending |
| `1` | `stack_st_ASN1_STRING_TABLE` | struct | `—` | `—` | `—` | `—` | `1` | ↖ batch table | ↖ batch table | ↖ batch table | — | — | — | pending |
| `1` | `stack_st_NAME_FUNCS` | struct | `—` | `—` | `—` | `—` | `1` | ↖ batch table | ↖ batch table | ↖ batch table | — | — | — | pending |
| `1` | `stack_st_nid_triple` | struct | `—` | `—` | `—` | `—` | `1` | ↖ batch table | ↖ batch table | ↖ batch table | — | — | — | pending |
| `1` | `stack_st_void` | struct | `—` | `—` | `—` | `—` | `1` | ↖ batch table | ↖ batch table | ↖ batch table | — | — | — | pending |
| `1` | `BIO_callback_fn_ex` | callback | `—` | `—` | `—` | `—` | `1` | ↖ batch table | ↖ batch table | ↖ batch table | — | — | — | pending |
| `1` | `BIO_info_cb` | callback | `—` | `—` | `—` | `—` | `1` | ↖ batch table | ↖ batch table | ↖ batch table | — | — | — | pending |
| `1` | `OPENSSL_sk_copyfunc_thunk` | callback | `—` | `—` | `—` | `—` | `1` | ↖ batch table | ↖ batch table | ↖ batch table | — | — | — | pending |
| `1` | `OPENSSL_sk_freefunc_thunk` | callback | `—` | `—` | `—` | `—` | `1` | ↖ batch table | ↖ batch table | ↖ batch table | — | — | — | pending |
| `1` | `asn1_ps_func` | callback | `—` | `—` | `—` | `—` | `2` | ↖ batch table | ↖ batch table | ↖ batch table | — | — | — | pending |
| `2` | `asn1_type_st` | struct | `23` | `2` | `0` | `23` | `1` | ↖ batch table | ↖ batch table | ↖ batch table | — | — | — | pending |
| `2` | `crypto_ex_data_st` | struct | `2` | `2` | `2` | `2` | `1` | ↖ batch table | ↖ batch table | ↖ batch table | — | — | — | pending |
| `3` | `asn1_string_st` | struct | `4` | `4` | `1` | `—` | `1` | ↖ batch table | ↖ batch table | ↖ batch table | — | — | — | pending |
| **Σ `42`** | | | **`205`** | **`144`** | **`76`** | **`58`** | **`44`** | **`$126.91`** | | **`4,189`** | **—** | | **—** | **`0`/`42` reviewed** |

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
| `0` | `ASN1_STRING_TABLE_add` | function | `1` | — | `1` | `wrap-symbol_ASN1_STRING_TABLE_add` | — | pending |
| `0` | `ASN1_STRING_get_default_mask` | function | `0` | — | `1` | `wrap-symbol_ASN1_STRING_TABLE_add` | — | pending |
| `0` | `ASN1_STRING_set_default_mask` | function | `1` | — | `1` | `wrap-symbol_ASN1_STRING_TABLE_add` | — | pending |
| `0` | `ASN1_STRING_set_default_mask_asc` | function | `0` | — | `1` | `wrap-symbol_ASN1_STRING_TABLE_add` | — | pending |
| `0` | `BIO_accept` | function | `0` | — | `1` | `wrap-symbol_ASN1_STRING_TABLE_add` | — | pending |
| `0` | `BIO_closesocket` | function | `6` | — | `1` | `wrap-symbol_ASN1_STRING_TABLE_add` | — | pending |
| `0` | `BIO_dgram_non_fatal_error` | function | `1` | — | `1` | `wrap-symbol_ASN1_STRING_TABLE_add` | — | pending |
| `0` | `BIO_dump_cb` | function | `2` | — | `1` | `wrap-symbol_ASN1_STRING_TABLE_add` | — | pending |
| `0` | `BIO_dump_indent_cb` | function | `3` | — | `1` | `wrap-symbol_ASN1_STRING_TABLE_add` | — | pending |
| `0` | `BIO_err_is_non_fatal` | function | `0` | — | `1` | `wrap-symbol_ASN1_STRING_TABLE_add` | — | pending |
| `0` | `BIO_fd_non_fatal_error` | function | `1` | — | `1` | `wrap-symbol_ASN1_STRING_TABLE_add` | — | pending |
| `0` | `BIO_fd_should_retry` | function | `2` | — | `1` | `wrap-symbol_ASN1_STRING_TABLE_add` | — | pending |
| `0` | `BIO_get_accept_socket` | function | `0` | — | `1` | `wrap-symbol_ASN1_STRING_TABLE_add` | — | pending |
| `0` | `BIO_get_host_ip` | function | `0` | — | `1` | `wrap-symbol_ASN1_STRING_TABLE_add` | — | pending |
| `0` | `BIO_get_new_index` | function | `0` | — | `1` | `wrap-symbol_ASN1_STRING_TABLE_add` | — | pending |
| `0` | `BIO_get_port` | function | `0` | — | `1` | `wrap-symbol_ASN1_STRING_TABLE_add` | — | pending |
| `0` | `BIO_set_tcp_ndelay` | function | `0` | — | `1` | `wrap-symbol_ASN1_STRING_TABLE_add` | — | pending |
| `0` | `BIO_sock_error` | function | `1` | — | `1` | `wrap-symbol_ASN1_STRING_TABLE_add` | — | pending |
| `0` | `BIO_sock_init` | function | `3` | — | `1` | `wrap-symbol_ASN1_STRING_TABLE_add` | — | pending |
| `0` | `BIO_sock_non_fatal_error` | function | `2` | — | `1` | `wrap-symbol_ASN1_STRING_TABLE_add` | — | pending |
| `0` | `BIO_sock_should_retry` | function | `9` | — | `1` | `wrap-symbol_ASN1_STRING_TABLE_add` | — | pending |
| `0` | `BIO_socket` | function | `2` | — | `1` | `wrap-symbol_ASN1_STRING_TABLE_add` | — | pending |
| `0` | `BIO_socket_ioctl` | function | `1` | — | `1` | `wrap-symbol_ASN1_STRING_TABLE_add` | — | pending |
| `0` | `BIO_socket_nbio` | function | `4` | — | `1` | `wrap-symbol_ASN1_STRING_TABLE_add` | — | pending |
| `0` | `BIO_socket_wait` | function | `2` | — | `1` | `wrap-symbol_ASN1_STRING_TABLE_add` | — | pending |
| `0` | `OBJ_NAME_get` | function | `8` | — | `1` | `wrap-symbol_ASN1_STRING_TABLE_add` | — | pending |
| `0` | `OBJ_NAME_init` | function | `4` | — | `1` | `wrap-symbol_ASN1_STRING_TABLE_add` | — | pending |
| `0` | `OBJ_bsearch_` | function | `11` | — | `1` | `wrap-symbol_ASN1_STRING_TABLE_add` | — | pending |
| `0` | `OBJ_bsearch_ex_` | function | `1` | — | `1` | `wrap-symbol_ASN1_STRING_TABLE_add` | — | pending |
| `0` | `OBJ_create` | function | `3` | — | `1` | `wrap-symbol_ASN1_STRING_TABLE_add` | — | pending |
| `0` | `OBJ_find_sigid_algs` | function | `7` | — | `1` | `wrap-symbol_ASN1_STRING_TABLE_add` | — | pending |
| `0` | `OBJ_ln2nid` | function | `5` | — | `1` | `wrap-symbol_ASN1_STRING_TABLE_add` | — | pending |
| `0` | `OBJ_new_nid` | function | `1` | — | `1` | `wrap-symbol_ASN1_STRING_TABLE_add` | — | pending |
| `0` | `OBJ_nid2ln` | function | `18` | — | `1` | `wrap-symbol_ASN1_STRING_TABLE_add` | — | pending |
| `0` | `OBJ_nid2sn` | function | `54` | — | `1` | `wrap-symbol_ASN1_STRING_TABLE_add` | — | pending |
| `0` | `OBJ_sn2nid` | function | `8` | — | `1` | `wrap-symbol_ASN1_STRING_TABLE_add` | — | pending |
| `1` | `BIO_ADDRINFO_address` | function | `3` | `addrinfo`, `bio_addr_st` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | — | pending |
| `1` | `BIO_ADDRINFO_family` | function | `4` | `addrinfo` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | — | pending |
| `1` | `BIO_ADDRINFO_free` | function | `6` | `addrinfo` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | — | pending |
| `1` | `BIO_ADDRINFO_next` | function | `2` | `addrinfo` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | — | pending |
| `1` | `BIO_ADDRINFO_protocol` | function | `2` | `addrinfo` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | — | pending |
| `1` | `BIO_ADDRINFO_socktype` | function | `2` | `addrinfo` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | — | pending |
| `1` | `BIO_ADDR_clear` | function | `5` | `bio_addr_st` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | — | pending |
| `1` | `BIO_ADDR_copy` | function | `1` | `bio_addr_st` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | — | pending |
| `1` | `BIO_ADDR_dup` | function | `0` | `bio_addr_st` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | — | pending |
| `1` | `BIO_ADDR_family` | function | `3` | `bio_addr_st` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | — | pending |
| `1` | `BIO_ADDR_free` | function | `3` | `bio_addr_st` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | — | pending |
| `1` | `BIO_ADDR_hostname_string` | function | `2` | `bio_addr_st` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | — | pending |
| `1` | `BIO_ADDR_new` | function | `2` | `bio_addr_st` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | — | pending |
| `1` | `BIO_ADDR_path_string` | function | `0` | `bio_addr_st` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | — | pending |
| `1` | `BIO_ADDR_rawaddress` | function | `2` | `bio_addr_st` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | — | pending |
| `1` | `BIO_ADDR_rawmake` | function | `1` | `bio_addr_st`, `in6_addr`, `in_addr` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | — | pending |
| `1` | `BIO_ADDR_rawport` | function | `1` | `bio_addr_st` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | — | pending |
| `1` | `BIO_ADDR_service_string` | function | `2` | `bio_addr_st` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | — | pending |
| `1` | `BIO_accept_ex` | function | `1` | `bio_addr_st` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | — | pending |
| `1` | `BIO_bind` | function | `1` | `bio_addr_st` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | — | pending |
| `1` | `BIO_clear_flags` | function | `59` | `bio_st` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | — | pending |
| `1` | `BIO_connect` | function | `1` | `bio_addr_st` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | — | pending |
| `1` | `BIO_copy_next_retry` | function | `36` | `bio_st` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | — | pending |
| `1` | `BIO_ctrl` | function | `139` | `bio_st` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | — | pending |
| `1` | `BIO_ctrl_get_read_request` | function | `0` | `bio_st` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | — | pending |
| `1` | `BIO_ctrl_get_write_guarantee` | function | `0` | `bio_st` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | — | pending |
| `1` | `BIO_ctrl_pending` | function | `0` | `bio_st` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | — | pending |
| `1` | `BIO_ctrl_reset_read_request` | function | `0` | `bio_st` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | — | pending |
| `1` | `BIO_ctrl_wpending` | function | `0` | `bio_st` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | — | pending |
| `1` | `BIO_debug_callback` | function | `0` | `bio_st` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | — | pending |
| `1` | `BIO_debug_callback_ex` | function | `0` | `bio_st` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | — | pending |
| `1` | `BIO_do_connect_retry` | function | `1` | `bio_st` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | — | pending |
| `1` | `BIO_dump` | function | `3` | `bio_st` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | — | pending |
| `1` | `BIO_dump_fp` | function | `0` | `_IO_FILE` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | — | pending |
| `1` | `BIO_dump_indent` | function | `4` | `bio_st` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | — | pending |
| `1` | `BIO_dump_indent_fp` | function | `0` | `_IO_FILE` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | — | pending |
| `1` | `BIO_eof` | function | `7` | `bio_st` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | — | pending |
| `1` | `BIO_f_buffer` | function | `3` | `bio_method_st` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | — | pending |
| `1` | `BIO_f_linebuffer` | function | `0` | `bio_method_st` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | — | pending |
| `1` | `BIO_f_nbio_test` | function | `0` | `bio_method_st` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | — | pending |
| `1` | `BIO_f_null` | function | `0` | `bio_method_st` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | — | pending |
| `1` | `BIO_f_prefix` | function | `2` | `bio_method_st` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | — | pending |
| `1` | `BIO_f_readbuffer` | function | `2` | `bio_method_st` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | — | pending |
| `1` | `BIO_find_type` | function | `6` | `bio_st` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | — | pending |
| `1` | `BIO_free` | function | `130` | `bio_st` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | — | pending |
| `1` | `BIO_free_all` | function | `17` | `bio_st` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | — | pending |
| `1` | `BIO_get_callback` | function | `0` | `bio_st` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | — | pending |
| `1` | `BIO_get_callback_arg` | function | `1` | `bio_st` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | — | pending |
| `1` | `BIO_get_data` | function | `26` | `bio_st` | `1` | `wrap-symbol_BIO_ADDRINFO_address` | — | pending |
| `1` | `BIO_get_ex_data` | function | `0` | `bio_st` | `1` | `wrap-symbol_BIO_get_ex_data` | — | pending |
| `1` | `BIO_get_init` | function | `3` | `bio_st` | `1` | `wrap-symbol_BIO_get_ex_data` | — | pending |
| `1` | `BIO_get_line` | function | `2` | `bio_st` | `1` | `wrap-symbol_BIO_get_ex_data` | — | pending |
| `1` | `BIO_get_retry_BIO` | function | `0` | `bio_st` | `1` | `wrap-symbol_BIO_get_ex_data` | — | pending |
| `1` | `BIO_get_retry_reason` | function | `0` | `bio_st` | `1` | `wrap-symbol_BIO_get_ex_data` | — | pending |
| `1` | `BIO_get_shutdown` | function | `0` | `bio_st` | `1` | `wrap-symbol_BIO_get_ex_data` | — | pending |
| `1` | `BIO_gethostbyname` | function | `0` | `hostent` | `1` | `wrap-symbol_BIO_get_ex_data` | — | pending |
| `1` | `BIO_gets` | function | `17` | `bio_st` | `1` | `wrap-symbol_BIO_get_ex_data` | — | pending |
| `1` | `BIO_hex_string` | function | `3` | `bio_st` | `1` | `wrap-symbol_BIO_get_ex_data` | — | pending |
| `1` | `BIO_indent` | function | `11` | `bio_st` | `1` | `wrap-symbol_BIO_get_ex_data` | — | pending |
| `1` | `BIO_int_ctrl` | function | `6` | `bio_st` | `1` | `wrap-symbol_BIO_get_ex_data` | — | pending |
| `1` | `BIO_listen` | function | `1` | `bio_addr_st` | `1` | `wrap-symbol_BIO_get_ex_data` | — | pending |
| `1` | `BIO_lookup` | function | `2` | `BIO_lookup_type`, `addrinfo` | `1` | `wrap-symbol_BIO_get_ex_data` | — | pending |
| `1` | `BIO_lookup_ex` | function | `1` | `addrinfo` | `1` | `wrap-symbol_BIO_get_ex_data` | — | pending |
| `1` | `BIO_meth_free` | function | `0` | `bio_method_st` | `1` | `wrap-symbol_BIO_get_ex_data` | — | pending |
| `1` | `BIO_meth_get_callback_ctrl` | function | `0` | `bio_method_st`, `bio_st` | `1` | `wrap-symbol_BIO_get_ex_data` | — | pending |
| `1` | `BIO_meth_get_create` | function | `0` | `bio_method_st`, `bio_st` | `1` | `wrap-symbol_BIO_get_ex_data` | — | pending |
| `1` | `BIO_meth_get_ctrl` | function | `0` | `bio_method_st`, `bio_st` | `1` | `wrap-symbol_BIO_get_ex_data` | — | pending |
| `1` | `BIO_meth_get_destroy` | function | `0` | `bio_method_st`, `bio_st` | `1` | `wrap-symbol_BIO_get_ex_data` | — | pending |
| `1` | `BIO_meth_get_gets` | function | `0` | `bio_method_st`, `bio_st` | `1` | `wrap-symbol_BIO_get_ex_data` | — | pending |
| `1` | `BIO_meth_get_puts` | function | `0` | `bio_method_st`, `bio_st` | `1` | `wrap-symbol_BIO_get_ex_data` | — | pending |
| `1` | `BIO_meth_get_read` | function | `0` | `bio_method_st`, `bio_st` | `1` | `wrap-symbol_BIO_get_ex_data` | — | pending |
| `1` | `BIO_meth_get_read_ex` | function | `0` | `bio_method_st`, `bio_st` | `1` | `wrap-symbol_BIO_get_ex_data` | — | pending |
| `1` | `BIO_meth_get_write` | function | `0` | `bio_method_st`, `bio_st` | `1` | `wrap-symbol_BIO_get_ex_data` | — | pending |
| `1` | `BIO_meth_get_write_ex` | function | `0` | `bio_method_st`, `bio_st` | `1` | `wrap-symbol_BIO_get_ex_data` | — | pending |
| `1` | `BIO_meth_new` | function | `0` | `bio_method_st` | `1` | `wrap-symbol_BIO_get_ex_data` | — | pending |
| `1` | `BIO_meth_set_callback_ctrl` | function | `0` | `bio_method_st`, `bio_st` | `1` | `wrap-symbol_BIO_get_ex_data` | — | pending |
| `1` | `BIO_meth_set_create` | function | `0` | `bio_method_st`, `bio_st` | `1` | `wrap-symbol_BIO_get_ex_data` | — | pending |
| `1` | `BIO_meth_set_ctrl` | function | `0` | `bio_method_st`, `bio_st` | `1` | `wrap-symbol_BIO_get_ex_data` | — | pending |
| `1` | `BIO_meth_set_destroy` | function | `0` | `bio_method_st`, `bio_st` | `1` | `wrap-symbol_BIO_get_ex_data` | — | pending |
| `1` | `BIO_meth_set_gets` | function | `0` | `bio_method_st`, `bio_st` | `1` | `wrap-symbol_BIO_get_ex_data` | — | pending |
| `1` | `BIO_meth_set_puts` | function | `0` | `bio_method_st`, `bio_st` | `1` | `wrap-symbol_BIO_get_ex_data` | — | pending |
| `1` | `BIO_meth_set_read` | function | `0` | `bio_method_st`, `bio_st` | `1` | `wrap-symbol_BIO_get_ex_data` | — | pending |
| `1` | `BIO_meth_set_read_ex` | function | `0` | `bio_method_st`, `bio_st` | `1` | `wrap-symbol_BIO_get_ex_data` | — | pending |
| `1` | `BIO_meth_set_write` | function | `0` | `bio_method_st`, `bio_st` | `1` | `wrap-symbol_BIO_get_ex_data` | — | pending |
| `1` | `BIO_meth_set_write_ex` | function | `0` | `bio_method_st`, `bio_st` | `1` | `wrap-symbol_BIO_get_ex_data` | — | pending |
| `1` | `BIO_method_name` | function | `0` | `bio_st` | `1` | `wrap-symbol_BIO_get_ex_data` | — | pending |
| `1` | `BIO_method_type` | function | `4` | `bio_st` | `1` | `wrap-symbol_BIO_get_ex_data` | — | pending |
| `1` | `BIO_new` | function | `89` | `bio_method_st`, `bio_st`, `ossl_lib_ctx_st` | `1` | `wrap-symbol_BIO_get_ex_data` | — | pending |
| `1` | `BIO_new_accept` | function | `0` | `bio_st` | `1` | `wrap-symbol_BIO_get_ex_data` | — | pending |
| `1` | `BIO_new_bio_dgram_pair` | function | `0` | `bio_st` | `1` | `wrap-symbol_BIO_get_ex_data` | — | pending |
| `1` | `BIO_new_bio_pair` | function | `0` | `bio_st` | `1` | `wrap-symbol_BIO_get_ex_data` | — | pending |
| `1` | `BIO_new_connect` | function | `1` | `bio_st` | `1` | `wrap-symbol_BIO_get_ex_data` | — | pending |
| `1` | `BIO_new_dgram` | function | `1` | `bio_st` | `1` | `wrap-symbol_BIO_get_ex_data` | — | pending |
| `1` | `BIO_new_ex` | function | `2` | `bio_method_st`, `bio_st`, `ossl_lib_ctx_st` | `1` | `wrap-symbol_BIO_get_ex_data` | — | pending |
| `1` | `BIO_new_fd` | function | `0` | `bio_st` | `1` | `wrap-symbol_BIO_get_ex_data` | — | pending |
| `1` | `BIO_new_file` | function | `12` | `_IO_FILE`, `bio_st` | `1` | `wrap-symbol_BIO_get_ex_data` | — | pending |
| `1` | `BIO_new_fp` | function | `14` | `_IO_FILE`, `bio_st` | `1` | `wrap-symbol_BIO_get_ex_data` | — | pending |
| `1` | `BIO_new_from_core_bio` | function | `0` | `bio_st`, `ossl_core_bio_st`, `ossl_lib_ctx_st` | `1` | `wrap-symbol_BIO_get_ex_data` | — | pending |
| `1` | `BIO_new_mem_buf` | function | `7` | `bio_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | — | pending |
| `1` | `BIO_new_socket` | function | `1` | `bio_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | — | pending |
| `1` | `BIO_next` | function | `26` | `bio_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | — | pending |
| `1` | `BIO_nread` | function | `0` | `bio_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | — | pending |
| `1` | `BIO_nread0` | function | `0` | `bio_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | — | pending |
| `1` | `BIO_number_read` | function | `0` | `bio_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | — | pending |
| `1` | `BIO_number_written` | function | `0` | `bio_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | — | pending |
| `1` | `BIO_nwrite` | function | `0` | `bio_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | — | pending |
| `1` | `BIO_nwrite0` | function | `0` | `bio_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | — | pending |
| `1` | `BIO_parse_hostserv` | function | `3` | `BIO_hostserv_priorities` | `1` | `wrap-symbol_BIO_new_mem_buf` | — | pending |
| `1` | `BIO_pop` | function | `13` | `bio_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | — | pending |
| `1` | `BIO_printf` | function | `161` | `__va_list_tag`, `bio_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | — | pending |
| `1` | `BIO_ptr_ctrl` | function | `0` | `bio_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | — | pending |
| `1` | `BIO_push` | function | `17` | `bio_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | — | pending |
| `1` | `BIO_puts` | function | `82` | `bio_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | — | pending |
| `1` | `BIO_read` | function | `30` | `bio_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | — | pending |
| `1` | `BIO_read_ex` | function | `2` | `bio_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | — | pending |
| `1` | `BIO_s_accept` | function | `1` | `bio_method_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | — | pending |
| `1` | `BIO_s_bio` | function | `1` | `bio_method_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | — | pending |
| `1` | `BIO_s_connect` | function | `1` | `bio_method_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | — | pending |
| `1` | `BIO_s_core` | function | `1` | `bio_method_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | — | pending |
| `1` | `BIO_s_datagram` | function | `1` | `bio_method_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | — | pending |
| `1` | `BIO_s_dgram_mem` | function | `0` | `bio_method_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | — | pending |
| `1` | `BIO_s_dgram_pair` | function | `1` | `bio_method_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | — | pending |
| `1` | `BIO_s_fd` | function | `1` | `bio_method_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | — | pending |
| `1` | `BIO_s_file` | function | `48` | `bio_method_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | — | pending |
| `1` | `BIO_s_log` | function | `0` | `bio_method_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | — | pending |
| `1` | `BIO_s_mem` | function | `20` | `bio_method_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | — | pending |
| `1` | `BIO_s_null` | function | `3` | `bio_method_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | — | pending |
| `1` | `BIO_s_secmem` | function | `1` | `bio_method_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | — | pending |
| `1` | `BIO_s_socket` | function | `1` | `bio_method_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | — | pending |
| `1` | `BIO_set_callback` | function | `0` | `bio_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | — | pending |
| `1` | `BIO_set_callback_arg` | function | `1` | `bio_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | — | pending |
| `1` | `BIO_set_data` | function | `11` | `bio_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | — | pending |
| `1` | `BIO_set_ex_data` | function | `0` | `bio_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | — | pending |
| `1` | `BIO_set_flags` | function | `23` | `bio_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | — | pending |
| `1` | `BIO_set_init` | function | `14` | `bio_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | — | pending |
| `1` | `BIO_set_next` | function | `0` | `bio_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | — | pending |
| `1` | `BIO_set_retry_reason` | function | `0` | `bio_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | — | pending |
| `1` | `BIO_set_send_flags` | function | `0` | `bio_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | — | pending |
| `1` | `BIO_set_shutdown` | function | `0` | `bio_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | — | pending |
| `1` | `BIO_snprintf` | function | `34` | `__va_list_tag` | `1` | `wrap-symbol_BIO_new_mem_buf` | — | pending |
| `1` | `BIO_test_flags` | function | `12` | `bio_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | — | pending |
| `1` | `BIO_up_ref` | function | `3` | `bio_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | — | pending |
| `1` | `BIO_vfree` | function | `1` | `bio_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | — | pending |
| `1` | `BIO_vprintf` | function | `2` | `__va_list_tag`, `bio_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | — | pending |
| `1` | `BIO_vsnprintf` | function | `3` | `__va_list_tag` | `1` | `wrap-symbol_BIO_new_mem_buf` | — | pending |
| `1` | `BIO_wait` | function | `2` | `bio_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | — | pending |
| `1` | `BIO_write` | function | `67` | `bio_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | — | pending |
| `1` | `BIO_write_ex` | function | `3` | `bio_st` | `1` | `wrap-symbol_BIO_new_mem_buf` | — | pending |
| `1` | `OBJ_NAME_do_all` | function | `4` | `obj_name_st` | `1` | `wrap-symbol_OBJ_NAME_do_all` | — | pending |
| `1` | `OBJ_NAME_do_all_sorted` | function | `2` | `obj_name_st` | `1` | `wrap-symbol_OBJ_NAME_do_all` | — | pending |
| `1` | `OBJ_create_objects` | function | `0` | `bio_st` | `1` | `wrap-symbol_OBJ_NAME_do_all` | — | pending |
| `1` | `OPENSSL_sk_deep_copy` | function | `54` | `stack_st`, `OPENSSL_sk_copyfunc`, `OPENSSL_sk_freefunc` | `1` | `wrap-symbol_OBJ_NAME_do_all` | — | pending |
| `1` | `OPENSSL_sk_delete` | function | `56` | `stack_st` | `1` | `wrap-symbol_OBJ_NAME_do_all` | — | pending |
| `1` | `OPENSSL_sk_delete_ptr` | function | `52` | `stack_st` | `1` | `wrap-symbol_OBJ_NAME_do_all` | — | pending |
| `1` | `OPENSSL_sk_dup` | function | `53` | `stack_st` | `1` | `wrap-symbol_OBJ_NAME_do_all` | — | pending |
| `1` | `OPENSSL_sk_find` | function | `63` | `stack_st` | `1` | `wrap-symbol_OBJ_NAME_do_all` | — | pending |
| `1` | `OPENSSL_sk_find_all` | function | `50` | `stack_st` | `1` | `wrap-symbol_OBJ_NAME_do_all` | — | pending |
| `1` | `OPENSSL_sk_find_ex` | function | `49` | `stack_st` | `1` | `wrap-symbol_OBJ_NAME_do_all` | — | pending |
| `1` | `OPENSSL_sk_free` | function | `116` | `stack_st` | `1` | `wrap-symbol_OBJ_NAME_do_all` | — | pending |
| `1` | `OPENSSL_sk_insert` | function | `54` | `stack_st` | `1` | `wrap-symbol_OBJ_NAME_do_all` | — | pending |
| `1` | `OPENSSL_sk_is_sorted` | function | `50` | `stack_st` | `1` | `wrap-symbol_OBJ_NAME_do_all` | — | pending |
| `1` | `OPENSSL_sk_new` | function | `64` | `stack_st`, `OPENSSL_sk_compfunc` | `1` | `wrap-symbol_OBJ_NAME_do_all` | — | pending |
| `1` | `OPENSSL_sk_new_null` | function | `133` | `stack_st` | `1` | `wrap-symbol_OBJ_NAME_do_all` | — | pending |
| `1` | `OPENSSL_sk_new_reserve` | function | `68` | `stack_st`, `OPENSSL_sk_compfunc` | `1` | `wrap-symbol_OBJ_NAME_do_all` | — | pending |
| `1` | `OPENSSL_sk_num` | function | `399` | `stack_st` | `1` | `wrap-symbol_OBJ_NAME_do_all` | — | pending |
| `1` | `OPENSSL_sk_pop` | function | `62` | `stack_st` | `1` | `wrap-symbol_OBJ_NAME_do_all` | — | pending |
| `1` | `OPENSSL_sk_pop_free` | function | `155` | `stack_st`, `OPENSSL_sk_freefunc` | `1` | `wrap-symbol_OBJ_NAME_do_all` | — | pending |
| `1` | `OPENSSL_sk_push` | function | `169` | `stack_st` | `1` | `wrap-symbol_OBJ_NAME_do_all` | — | pending |
| `1` | `OPENSSL_sk_reserve` | function | `51` | `stack_st` | `1` | `wrap-symbol_OBJ_NAME_do_all` | — | pending |
| `1` | `OPENSSL_sk_set` | function | `59` | `stack_st` | `1` | `wrap-symbol_OBJ_NAME_do_all` | — | pending |
| `1` | `OPENSSL_sk_set_cmp_func` | function | `54` | `stack_st`, `OPENSSL_sk_compfunc` | `1` | `wrap-symbol_OBJ_NAME_do_all` | — | pending |
| `1` | `OPENSSL_sk_set_cmp_thunks` | function | `367` | `stack_st` | `1` | `wrap-symbol_OBJ_NAME_do_all` | — | pending |
| `1` | `OPENSSL_sk_shift` | function | `54` | `stack_st` | `1` | `wrap-symbol_OBJ_NAME_do_all` | — | pending |
| `1` | `OPENSSL_sk_sort` | function | `62` | `stack_st` | `1` | `wrap-symbol_OBJ_NAME_do_all` | — | pending |
| `1` | `OPENSSL_sk_unshift` | function | `49` | `stack_st` | `1` | `wrap-symbol_OBJ_NAME_do_all` | — | pending |
| `1` | `OPENSSL_sk_value` | function | `369` | `stack_st` | `1` | `wrap-symbol_OBJ_NAME_do_all` | — | pending |
| `1` | `OPENSSL_sk_zero` | function | `49` | `stack_st` | `1` | `wrap-symbol_OBJ_NAME_do_all` | — | pending |
| `2` | `ASN1_OBJECT_create` | function | `0` | `asn1_object_st` | `1` | `wrap-symbol_ASN1_OBJECT_create` | — | pending |
| `2` | `ASN1_OBJECT_free` | function | `48` | `asn1_object_st` | `1` | `wrap-symbol_ASN1_OBJECT_create` | — | pending |
| `2` | `ASN1_OBJECT_it` | function | `0` | `ASN1_ITEM_st`, `ASN1_TEMPLATE_st` | `1` | `wrap-symbol_ASN1_OBJECT_create` | — | pending |
| `2` | `ASN1_OBJECT_new` | function | `0` | `asn1_object_st` | `1` | `wrap-symbol_ASN1_OBJECT_create` | — | pending |
| `2` | `ASN1_STRING_TABLE_cleanup` | function | `1` | `stack_st_ASN1_STRING_TABLE` | `1` | `wrap-symbol_ASN1_OBJECT_create` | — | pending |
| `2` | `ASN1_STRING_TABLE_get` | function | `2` | `asn1_string_table_st`, `ossl_init_settings_st`, `stack_st`, `stack_st_ASN1_STRING_TABLE` | `1` | `wrap-symbol_ASN1_OBJECT_create` | — | pending |
| `2` | `BIO_asn1_get_prefix` | function | `0` | `bio_st`, `asn1_ps_func` | `1` | `wrap-symbol_ASN1_OBJECT_create` | — | pending |
| `2` | `BIO_asn1_get_suffix` | function | `0` | `bio_st`, `asn1_ps_func` | `1` | `wrap-symbol_ASN1_OBJECT_create` | — | pending |
| `2` | `BIO_asn1_set_prefix` | function | `1` | `bio_st`, `asn1_ps_func` | `1` | `wrap-symbol_ASN1_OBJECT_create` | — | pending |
| `2` | `BIO_asn1_set_suffix` | function | `1` | `bio_st`, `asn1_ps_func` | `1` | `wrap-symbol_ASN1_OBJECT_create` | — | pending |
| `2` | `BIO_callback_ctrl` | function | `11` | `bio_st`, `BIO_info_cb` | `1` | `wrap-symbol_ASN1_OBJECT_create` | — | pending |
| `2` | `BIO_get_callback_ex` | function | `2` | `bio_st`, `BIO_callback_fn_ex` | `1` | `wrap-symbol_ASN1_OBJECT_create` | — | pending |
| `2` | `BIO_get_rpoll_descriptor` | function | `0` | `bio_poll_descriptor_st`, `bio_st` | `1` | `wrap-symbol_ASN1_OBJECT_create` | — | pending |
| `2` | `BIO_get_wpoll_descriptor` | function | `0` | `bio_poll_descriptor_st`, `bio_st` | `1` | `wrap-symbol_ASN1_OBJECT_create` | — | pending |
| `2` | `BIO_meth_get_recvmmsg` | function | `0` | `bio_method_st`, `bio_msg_st`, `bio_st` | `1` | `wrap-symbol_BIO_meth_get_recvmmsg` | — | pending |
| `2` | `BIO_meth_get_sendmmsg` | function | `0` | `bio_method_st`, `bio_msg_st`, `bio_st` | `1` | `wrap-symbol_BIO_meth_get_recvmmsg` | — | pending |
| `2` | `BIO_meth_set_recvmmsg` | function | `0` | `bio_method_st`, `bio_msg_st`, `bio_st` | `1` | `wrap-symbol_ASN1_OBJECT_create` | — | pending |
| `2` | `BIO_meth_set_sendmmsg` | function | `0` | `bio_method_st`, `bio_msg_st`, `bio_st` | `1` | `wrap-symbol_ASN1_OBJECT_create` | — | pending |
| `2` | `BIO_recvmmsg` | function | `1` | `bio_msg_st`, `bio_st` | `1` | `wrap-symbol_ASN1_OBJECT_create` | — | pending |
| `2` | `BIO_sendmmsg` | function | `1` | `bio_msg_st`, `bio_st` | `1` | `wrap-symbol_ASN1_OBJECT_create` | — | pending |
| `2` | `BIO_set_callback_ex` | function | `1` | `bio_st`, `BIO_callback_fn_ex` | `1` | `wrap-symbol_ASN1_OBJECT_create` | — | pending |
| `2` | `BIO_sock_info` | function | `1` | `BIO_sock_info_type`, `BIO_sock_info_u` | `1` | `wrap-symbol_ASN1_OBJECT_create` | — | pending |
| `2` | `OBJ_NAME_add` | function | `4` | `stack_st_NAME_FUNCS` | `1` | `wrap-symbol_ASN1_OBJECT_create` | — | pending |
| `2` | `OBJ_NAME_cleanup` | function | `1` | `lhash_st_OBJ_NAME`, `stack_st_NAME_FUNCS` | `1` | `wrap-symbol_ASN1_OBJECT_create` | — | pending |
| `2` | `OBJ_NAME_new_index` | function | `0` | `stack_st_NAME_FUNCS` | `1` | `wrap-symbol_ASN1_OBJECT_create` | — | pending |
| `2` | `OBJ_NAME_remove` | function | `1` | `stack_st_NAME_FUNCS` | `1` | `wrap-symbol_ASN1_OBJECT_create` | — | pending |
| `2` | `OBJ_add_object` | function | `0` | `asn1_object_st` | `1` | `wrap-symbol_ASN1_OBJECT_create` | — | pending |
| `2` | `OBJ_add_sigid` | function | `1` | `stack_st_nid_triple` | `1` | `wrap-symbol_ASN1_OBJECT_create` | — | pending |
| `2` | `OBJ_cmp` | function | `26` | `asn1_object_st` | `1` | `wrap-symbol_ASN1_OBJECT_create` | — | pending |
| `2` | `OBJ_dup` | function | `19` | `asn1_object_st` | `1` | `wrap-symbol_ASN1_OBJECT_create` | — | pending |
| `2` | `OBJ_find_sigid_by_algs` | function | `4` | `stack_st_nid_triple` | `1` | `wrap-symbol_ASN1_OBJECT_create` | — | pending |
| `2` | `OBJ_get0_data` | function | `1` | `asn1_object_st` | `1` | `wrap-symbol_ASN1_OBJECT_create` | — | pending |
| `2` | `OBJ_length` | function | `4` | `asn1_object_st` | `1` | `wrap-symbol_ASN1_OBJECT_create` | — | pending |
| `2` | `OBJ_nid2obj` | function | `119` | `asn1_object_st` | `1` | `wrap-symbol_ASN1_OBJECT_create` | — | pending |
| `2` | `OBJ_obj2nid` | function | `180` | `asn1_object_st` | `1` | `wrap-symbol_ASN1_OBJECT_create` | — | pending |
| `2` | `OBJ_obj2txt` | function | `41` | `asn1_object_st`, `bignum_st` | `1` | `wrap-symbol_ASN1_OBJECT_create` | — | pending |
| `2` | `OBJ_sigid_free` | function | `1` | `stack_st_nid_triple` | `1` | `wrap-symbol_ASN1_OBJECT_create` | — | pending |
| `2` | `OBJ_txt2nid` | function | `6` | `asn1_object_st` | `1` | `wrap-symbol_ASN1_OBJECT_create` | — | pending |
| `2` | `OBJ_txt2obj` | function | `19` | `asn1_object_st` | `1` | `wrap-symbol_ASN1_OBJECT_create` | — | pending |
| `2` | `OPENSSL_sk_set_copy_thunks` | function | `367` | `stack_st`, `OPENSSL_sk_copyfunc_thunk` | `1` | `wrap-symbol_ASN1_OBJECT_create` | — | pending |
| `2` | `OPENSSL_sk_set_thunks` | function | `416` | `stack_st`, `OPENSSL_sk_freefunc_thunk` | `1` | `wrap-symbol_ASN1_OBJECT_create` | — | pending |
| `3` | `BIO_dup_chain` | function | `1` | `bio_st`, `crypto_ex_data_st` | `1` | `wrap-symbol_BIO_dup_chain` | — | pending |
| `4` | `ASN1_STRING_clear_free` | function | `4` | `asn1_string_st` | `1` | `wrap-symbol_ASN1_STRING_clear_free` | — | pending |
| `4` | `ASN1_STRING_cmp` | function | `7` | `asn1_string_st` | `1` | `wrap-symbol_ASN1_STRING_clear_free` | — | pending |
| `4` | `ASN1_STRING_copy` | function | `11` | `asn1_string_st` | `1` | `wrap-symbol_ASN1_STRING_clear_free` | — | pending |
| `4` | `ASN1_STRING_dup` | function | `14` | `asn1_string_st` | `1` | `wrap-symbol_ASN1_STRING_clear_free` | — | pending |
| `4` | `ASN1_STRING_free` | function | `43` | `asn1_string_st` | `1` | `wrap-symbol_ASN1_STRING_clear_free` | — | pending |
| `4` | `ASN1_STRING_get0_data` | function | `38` | `asn1_string_st` | `1` | `wrap-symbol_ASN1_STRING_clear_free` | — | pending |
| `4` | `ASN1_STRING_get_length` | function | `40` | `asn1_string_st` | `1` | `wrap-symbol_ASN1_STRING_clear_free` | — | pending |
| `4` | `ASN1_STRING_length` | function | `0` | `asn1_string_st` | `1` | `wrap-symbol_ASN1_STRING_clear_free` | — | pending |
| `4` | `ASN1_STRING_length_set` | function | `0` | `asn1_string_st` | `1` | `wrap-symbol_ASN1_STRING_clear_free` | — | pending |
| `4` | `ASN1_STRING_new` | function | `17` | `asn1_string_st` | `1` | `wrap-symbol_ASN1_STRING_clear_free` | — | pending |
| `4` | `ASN1_STRING_new_not_owned` | function | `0` | `asn1_string_st` | `1` | `wrap-symbol_ASN1_STRING_clear_free` | — | pending |
| `4` | `ASN1_STRING_print` | function | `10` | `asn1_string_st`, `bio_st` | `1` | `wrap-symbol_ASN1_STRING_clear_free` | — | pending |
| `4` | `ASN1_STRING_print_ex` | function | `2` | `asn1_string_st`, `bio_st` | `1` | `wrap-symbol_ASN1_STRING_clear_free` | — | pending |
| `4` | `ASN1_STRING_print_ex_fp` | function | `0` | `_IO_FILE`, `asn1_string_st` | `1` | `wrap-symbol_ASN1_STRING_clear_free` | — | pending |
| `4` | `ASN1_STRING_set` | function | `0` | `asn1_string_st` | `1` | `wrap-symbol_ASN1_STRING_clear_free` | — | pending |
| `4` | `ASN1_STRING_set0` | function | `27` | `asn1_string_st` | `1` | `wrap-symbol_ASN1_STRING_clear_free` | — | pending |
| `4` | `ASN1_STRING_set1_data` | function | `24` | `asn1_string_st` | `1` | `wrap-symbol_ASN1_STRING_clear_free` | — | pending |
| `4` | `ASN1_STRING_set1_string` | function | `13` | `asn1_string_st` | `1` | `wrap-symbol_ASN1_STRING_clear_free` | — | pending |
| `4` | `ASN1_STRING_set_by_NID` | function | `2` | `asn1_string_st` | `1` | `wrap-symbol_ASN1_STRING_clear_free` | — | pending |
| `4` | `ASN1_STRING_to_UTF8` | function | `4` | `asn1_string_st` | `1` | `wrap-symbol_ASN1_STRING_clear_free` | — | pending |
| `4` | `ASN1_STRING_type` | function | `0` | `asn1_string_st` | `1` | `wrap-symbol_ASN1_STRING_clear_free` | — | pending |
| `4` | `ASN1_STRING_type_new` | function | `22` | `asn1_string_st` | `1` | `wrap-symbol_ASN1_STRING_clear_free` | — | pending |
| **Σ `277`** | | | **`5,734`** | | **`277`** | **`9` batches** | **pending** | **`0`/`277` reviewed** |
### Batches — symbols

| DAG layer | units | loc | $ | wall | $/unit | $/loc |
|---|---|---|---|---|---|---|
| `0` | `39` | `841` | `$9.73` | `24m09s` (`1.0`x) | `$0.25` | `$0.012` |
| `1` | `182` | `3,900` | `$54.96` | `34m23s` (`3.1`x) | `$0.30` | `$0.014` |
| `2` | `43` (`41` unique) | `979` | `$15.86` | `33m52s` (`1.2`x) | `$0.37` | `$0.016` |
| `3` | `1` | `108` | `$3.50` | `6m15s` (`1.0`x) | `$3.50` | `$0.032` |
| `4` | `22` | `590` | `$7.77` | `26m17s` (`1.0`x) | `$0.35` | `$0.013` |
| **Σ** | **`287` submissions (`285` unique)** | **`6,418`** | **`$91.82`** | **`2h39m45s`** (`1.3`x, session wall) | **`$0.32`** | **`$0.014`** |
### Batches — review

One agent per judged batch, same split as the wave it judges. `rv loc` is the
net `.rs` delta of the landing commit; a review that confirms without changing
code reads `+0/-0`.

| session | batch | units | rv loc | rv $ | rv wall | $/symbol | $/type |
|---|---|---|---|---|---|---|---|
| `2026-08-22_18-28-47_440f` | `review-symbol_free` | `1` symbols | `+0/-0` | `$3.36` | `5m21s` | `$3.36` | — |
| `2026-08-22_18-28-47_440f` | `review-symbol_CRYPTO_free` | `2` symbols | `+0/-0` | `$2.98` | `9m52s` | `$1.49` | — |
| `2026-08-22_18-28-47_440f` | `review-symbol_CRYPTO_clear_free` | `2` symbols | `+0/-0` | `$1.26` | `3m23s` | `$0.63` | — |
| `2026-08-22_18-28-47_440f` | `review-symbol_CRYPTO_secure_free` | `2` symbols | `+0/-0` | `$3.19` | `6m39s` | `$1.59` | — |
| **Σ** | **`4` agents** | **`0` types · `7` symbols** | **`+0/-0`** | **`$10.79`** | **`9m52s`** (longest; `25m15s` serial, `2.6`x) | **`$1.54`** | **—** |
## Safety audit

`crustify-audit <crate> unsafe`, unseeded — tree-wide, not
per seed. Two snapshots: the tree the review pass judged, and the tree it
produced.

| | before review (`pending`) | after review (`pending`) |
|---|---|---|
| unsafe loc | `—` | `—` |
| % of loc | `—`% | `—`% |
| blocks | `—` | `—` |
| % in `impl T` | `—`% | `—`% |
| `unsafe fn` | `—` | `—` |
| ...of which not sanctioned | `—` | `—` |
| raw-ptr smell | `—` | `—` |
| void-ptr smell | `—` | `—` |
| FFI calls | `—` | `—` |
| `&`/`&mut` on a wrapper | `—` | `—` |
| field proj outside an accessor | `—` | `—` |

### All metrics

| metric | before | after | Δ | reading |
|---|---|---|---|---|
| `code_lines` | `—` | `—` | `—` | union of HIR definition spans (denominator); `cfg`-disabled items excluded |
| `total_stmts` | `—` | `—` | `—` | statements |
| `unsafe_blocks` | `—` | `—` | `—` | count of `unsafe { }` blocks, macro-expanded included |
| `unsafe_block_stmts` | `—` | `—` | `—` | statements inside them |
| `unsafe_block_lines` | `—` | `—` | `—` | their lines, every outermost block |
| `unsafe_block_code_lines` | `—` | `—` | `—` | **`—`% → `—`%** |
| `unsafe_blocks_wrapper_impl` | `—` | `—` | `—` | inside `impl <wrapper T>` |
| `unsafe_blocks_ffi_export` | `—` | `—` | `—` | inside the C-ABI gateway |
| `unsafe_fns` | `—` | `—` | `—` | `unsafe fn` declarations, post-expansion |
| `unsafe_fns_seam` | `—` | `—` | `—` | ...the sanctioned subset |
| **`unsafe fn` smell** | **`—`** | **`—`** | **`—`** | the remainder — read each and accept or fix it |
| `unsafe_fns_pub` | `—` | `—` | `—` | ...of `unsafe_fns`, exported from the crate |
| `unsafe_impls` / `unsafe_traits` | `—` / `—` | `—` / `—` | `—` | lifecycle contracts asserted once per type |
| `ffi_calls` | `—` | `—` | `—` | calls to a foreign item — the unsafe-FFI-call surface |
| `wrapper_newtypes` | `—` | `—` | `—` | LAYOUT newtypes — `repr(transparent)` over a `repr(C)` type by value, detected structurally |
| `wrapper_newtypes_declared` | `—` | `—` | `—` | the `CCell`-declared count, for comparison |
| `wrapper_declared_nonconformant` | `—` | `—` | `—` | declared but failing the structural test — **target 0** |
| `wrapper_newtypes_undeclared` | `—` | `—` | `—` | structural but undeclared — a hand-written layout newtype |
| `raw_ptr_args` | `—` | `—` | `—` | raw-ptr positions in arguments |
| `raw_ptr_rets` | `—` | `—` | `—` | raw-ptr positions in returns |
| **total positions** | **`—`** | **`—`** | `—` | args + rets; disjoint, so this is the surface |
| `raw_ptr_seam` | `—` | `—` | `—` | sanctioned: seam fn / `mod ffi_export` / `extern "C"` / ptr-to-own-`Self` |
| **smell (total − seam)** | **`—`** | **`—`** | `—` | the non-seam remainder |
| `raw_ptr_wrapped` | `—` | `—` | `—` | **of the smell**: pointee is a C type that HAS a wrapper — the actionable defect |
| `raw_ptr_in_wrapper` | `—` | `—` | `—` | **of the smell**: inside a wrapper impl — the least excusable placement |
| `raw_ptr_derefs` | `—` | `—` | `—` | `*p` on a raw pointer (volume) |
| `ref_to_type_wrapper` | `—` | `—` | `—` | `&`/`&mut` on a layout newtype — **target 0** |
| `field_proj_wrapped` | `—` | `—` | `—` | projection VOLUME — shares one HIR shape with `addr_of!`, not a violation |
| `field_proj_outside_impl` | `—` | `—` | `—` | projections outside any accessor — **target 0** |
| `field_ref_wrapped` | `—` | `—` | `—` | `&(*p).field` — forbidden by the translator playbook — **target 0** |
| `void_ptr_sanctioned` | `—` | `—` | `—` | `*c_void` in a seam / `ffi_export` / `extern "C"` signature |
| `void_ptr_smell` | `—` | `—` | `—` | `*c_void` elsewhere; `void_ptr_sites` names each one |

### What the review moved

Pending the final target-set review and its before/after unseeded scans.

## Notes

### Campaign progress

Raw lifetimes and the ASN.1 string/object, generic `STACK_OF`, and BIO foundation are complete. Narrow X.509, EVP, final review, unseeded safety snapshots, and the approved post-campaign UB pass remain pending.

### Lifetime reviews

The void and string corrective reviews held the canonical Rust unchanged. Four metered `gpt-5.5` void-review batches cost `$10.79`; the standalone string review has no separate usage record.

### Mixed callback batches

The scheduler pooled eight callbacks into symbol batches. Their rows point to `↖ batch table`; cost, wall, and loc are counted once in **Batches — symbols**.

### Scheduler admission repair

Twelve superseded agents covering 54 duplicate layer-0 units cost `$25.61`; this is excluded from landed tables but included in gross spend.

### Foundation audit correction

The corrective batch removed the two direct `BIO_METHOD` field projections. The repeated seeded scan reported `field_proj_outside_impl = 0`, `field_ref_wrapped = 0`, and `wrapper_declared_nonconformant = 0`. Unseeded before/after scans remain pending as required by the template.

### Regression gates

The foundation passed formatting, `cargo check`, strict Clippy, 113 Rust tests, and all 4,463 native OpenSSL tests.

### Accounting

`crustify-log-cost` prices request-level usage records. Landed target-set cost is `$218.73`; raw lifetimes add `$13.64`, metered review adds `$10.79`, and superseded work adds `$25.61`, for `$268.76` gross recorded spend.
