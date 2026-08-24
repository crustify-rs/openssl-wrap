# Campaign status — `openssl / crypto`

Snapshot taken 2026-08-24 by the orchestrator, after promoting the second UB
run's repairs. Supersedes nothing; `crustify/wrappers-results.md` remains the
campaign's accounting record.

## Position

| | |
|---|---|
| repository | `openssl` @ base revision `2924476b55` |
| oracle target | `crypto` |
| objective | `wrap` (libcrypto public API; libssl excluded) |
| canonical branch | `crustify/libcrypto-gpt-5.6-sol`, tip `3bb143b635` |
| translator | `codex` / `gpt-5.6-sol`, `--billing api` |
| reviewer | `claude` / `opus-5`, `--billing subscription` |
| running work | none — every session has terminated |

## Landed and promoted

All of the following sit on the canonical branch and passed their gates.

| campaign | objective | units | batches | failures | wall |
|---|---|---:|---:|---:|---|
| `00-lifetime-void` | raw lifetime | 10 syms | — | 0 | 39m26s (with `01`) |
| `01-lifetime-string` | raw lifetime | — | — | 0 | — |
| `02`/`04-review-lifetimes` | review | — | — | 0 | — |
| `10-foundation` | wrap | 34 types, 277 syms | — | 0 | 2h50m51s (with `11`) |
| `11-foundation-audit` | corrective wrap | — | — | 0 | — |
| `20-review-foundation` | review (opus5) | — | — | 0 | — |
| `30-ub-remediation` | UB repair | — | — | — | merged |
| `40-x509-pubkey-type` | wrap | 1 type | 1 | 0 | 12m28s |
| `41-x509-core` | wrap | 5 types, 45 syms | 6 | 0 | 1h29m17s |
| `42-x509-names` | wrap | 2 types, 21 syms | 3 | 0 | 30m37s |
| `43-x509-extensions` | wrap | 24 types, 57 syms | 21 | 0 | 1h55m32s |
| `50-review-x509` | review (opus5) | 32 types, 123 syms | 2 | 0 | 35m31s |
| `51-review-x509-clippy` | review (opus5) | 1 sym | 1 | 0 | 8m02s |

X.509 wrap tranche totals **32 types and 123 symbols** over 31 batches; the
`50`/`51` reviews covered that same set.

## Second UB pass — promoted this session

`crustify-audit ub` run `ub-20260824-004145` confirmed two findings reachable
from safe code, both with `#![forbid(unsafe_code)]` reproductions:

- `general-name-cmp-unset-asn1-type-null-deref` — `GENERAL_NAME_cmp`'s
  `OTHERNAME` guard missed an unset `ASN1_TYPE` (UBSan + ASan).
- `x509-up-ref-aliased-borrow-use-after-free` — `X509_up_ref` promoted a shared
  borrow into an exclusive one (ASan heap-use-after-free).

The agent's repairs landed as `d5e86577a2`, `bd209c96b8` and evidence commit
`3bb143b635`, introducing `libcrypto::refcount::SharedRef` and applying it to
the `X509`, `BIO` and `EVP_PKEY` share grants. Verified before promotion:
`cargo build` clean, **354 tests pass, 0 failed**, `cargo clippy --all-targets`
clean under the workspace's `undocumented_unsafe_blocks = "deny"`. The diff is
confined to the two confirmed findings and their evidence.

Fast-forwarded onto the canonical branch; the source branch
`crustify/audit-fix-refcount-alias-and-general-name-cmp` is now redundant.

## Tree-wide deterministic scan

Re-run unseeded after the repairs, so it postdates them and is the campaign
record (`crustify/audit/unsafe.json`, gitignored and reproducible):

| counter | value |
|---|---|
| `unsafe_blocks` / `code_lines` | 1230 / 7180 |
| `unsafe_fns` (of which seam) | 395 (264) |
| `wrapper_newtypes` | 46 |
| `wrapper_declared_nonconformant` | **0** |
| `wrapper_newtypes_undeclared` | **0** |
| `raw_ptr_in_wrapper` | **0** |
| `ref_to_type_wrapper` | **0** |
| `field_ref_wrapped` / `field_proj_outside_impl` | **0 / 0** |
| `raw_ptr_derefs_outside_impl` | 2 |
| `void_ptr_smell` | 6 |

Every conformance counter is zero. The two remaining leads are
`bio/bio_dump.rs:31` and `objects/o_names.rs:140`; the `void_ptr_smell` sites
are in `bio_lib.rs`, `obj_dat.rs`, `stack.rs` and `v3_lib.rs`.

## Open work

1. **Accounting gap.** `wrappers-results.md` stops at campaigns `00–11` plus the
   first UB pass. The X.509 tranche (`40–43`), its reviews (`50`/`51`) and the
   second UB run are landed but unrecorded. Measured figures ready to fill:
   wrap `$150.39` over 31 agents, review `$23.77` over 3 agents.
2. **Next subset undecided.** The agreed sequence after X.509 is the
   CryptoProvider-oriented tier: EVP core and key management, signature
   algorithms and key loading, key exchange, then TLS 1.3 AEAD/hashes/HMAC/HKDF,
   with TLS 1.2 later. No campaign has been scheduled for it.
3. **Untracked campaign specs.** `campaigns/00-…` through `30-…` hold their
   `campaign.json` outside git; only `40–51` are tracked.

## Cost to date

`crustify-log-cost` over 113 agent runs: **$623.24**, 26h37m of agent wall.

| kind | runs | $ total | $/run |
|---|---:|---:|---:|
| `wrap-type` | 55 | 219.74 | 4.00 |
| `wrap-symbol` | 20 | 122.21 | 6.11 |
| `review-type` | 18 | 141.86 | 7.88 |
| `review-symbol` | 18 | 128.74 | 7.15 |
| other | 2 | 10.70 | 5.35 |

Excludes the two `crustify-audit ub` runs and orchestrator sessions.
