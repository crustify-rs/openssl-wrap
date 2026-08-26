# crustify — `openssl / crypto`

## Campaign

- **target repo** — `openssl` @ `2924476b5591e691e904c4baf57894c526c4b8de`
- **target** — public `libcrypto` in three tranches: ASN.1/`STACK_OF`/BIO foundation, X.509 certificate handling, and the `EVP_PKEY` core. `libssl` excluded
- **campaign objective** — `wrap`
- **`impl_files`** — `crypto/`, `include/crypto/`, `include/internal/`
- **`api_headers`** — `include/openssl/`
- **agent backend** — `codex`
- **model** — `openai/gpt-5.6-sol`
- **`--billing`** — `api`
- **`--max-types`** — `4`
- **`--max-syms`** — `50`
- **`--max-loc`** — `1000`
- **`--min-fields`** — `20`
- **`--parallel-max`** — `16`
- **branch** — `crustify/libcrypto-gpt-5.6-sol`, tip `13a55bf7c1`; published at `crustify-rs/openssl-wrap`
- **deps** — crustify-cli `51d44d1` (`docs/results-template-ub`), crustify-oracle `5582ec8` (`fix/closure-name-resolves-to-walked-node`), ffibox `600399f` (`main`)

## Review pass

`--objective review`, LLM-as-a-Judge over the landed waves.

- **agent backend** — `claude`
- **model** — `anthropic/claude-opus-5`
- **`--billing`** — `subscription`
- **`--max-types`** — `15`
- **`--max-syms`** — `150`
- **`--max-loc`** — `1000`
- **`--min-fields`** — `60`
- **`--parallel-max`** — `16`
- **branch** — `crustify/session/review-2026-08-24_00-32-55_40aa`, tip `10edf02776`
- **agents** — `36`, over `5` session(s)

`rv`-prefixed columns below carry the review pass; the unprefixed ones remain
the campaign's.

## UB pass

`crustify-audit ub`, an agentic hunt for undefined behaviour reachable from the
crate's SAFE APIs.

- **agent backend** — `claude`
- **model** — `anthropic/claude-opus-5`
- **`--billing`** — `subscription`
- **`--timeout`** — `60` min
- **subject** — `10–11-foundation` at `894f727207`, then `40–43-x509` at `10edf02776`
- **agents** — `2` runs, `56m04s` + `31m15s` wall, `$43.48` + `$23.33`
- **advisories** — `7` at `crustify/audit/advisories/`
- **patch** — `crustify/orchestrator/ub-remediation` at `589b6078ec`, merged; `crustify/audit-fix-refcount-alias-and-general-name-cmp` at `3bb143b635`, merged

`ub`-prefixed columns carry this pass.


## Legend

- `objective` — what the batch's agents were told to do: `wrap`, `port`, or
  `raw lifetime`. The type tables are split by it, so it appears as a column
  only in `Batches — symbols`, which mixes the two
- `types` / `symbols` — scheduler units in the batch. Callbacks are scheduled
  in symbol batches and counted there
- `fields` — in-scope fields: the field accessors the oracle assigned to that
  type batch, not the type's full declared field count
- `lifecycle prims` — deleters, disposers and cloners the ownership store binds
  to that batch's types; raw-tier primitives that belong to no type are counted
  in `Raw lifetime discovery` instead
- `$` / `wall` / `loc` — that agent's computed cost, its elapsed time, and the
  `.rs` insertions of its landing commit. `wall` is `ended_at − started_at` from
  the agent's own `usage.json`, so it INCLUDES the per-worktree C rebuild
- `$/type` / `$/symbol` / `$/field` / `$/loc` — that row's `$` over its units,
  its in-scope fields, or its `loc`
- `$/type` / `$/sym` — in the Overview, a sub-campaign's cost over the types or
  symbols it was scheduled for; `—` where it was scheduled for none
- `rv $` / `rv wall` / `rv loc` — the REVIEW agent's cost, elapsed time, and net
  `.rs` line delta (`+ins/-del`) of its landing commit. Under subscription
  billing `rv $` is an API-equivalent comparison value, not a charged amount
- `ub $` / `ub wall` — the UB pass's cost and elapsed time; `—` where the
  optional pass did not run

Every table below is a heading, a model line and the table. All prose belongs
in Notes.

## Overview

- **Rust LoC, non-test** — `26,993`
- **Rust LoC, tests** — `12,093`
- **C LoC** — `336,418` across the `1,044` targeted files
- **ported types** — `0`
- **ported symbols** — `1`
- **wrapped types** — `83` (`16.6`% of API)
- **wrapped callbacks** — `10` (`1.5`% of API)
- **wrapped symbols** — `834` (`12.3`% of API)
- **remaining types** — `383`
- **remaining callbacks** — `638`
- **remaining symbols** — `5,931`

Implementation `openai/gpt-5.6-sol` via `codex`; review `anthropic/claude-opus-5`
via `claude`. Each row names the model that produced it.

| sub-campaign | objective | nr types | nr symbols | session wall | total | $/type | $/sym | ub wall | ub $ |
|---|---|---:|---:|---|---:|---:|---:|---|---:|
| `00–01-lifetimes` | raw lifetime | `0` | `10` | `39m26s` | `$10.70` (`gpt56sol`) | — | `$1.07` | — | — |
| `02`+`04-review-lifetimes` | review | `0` | `10` | `1h12m19s` | `$29.61` (`gpt55, opus5`) | — | `$2.96` | — | — |
| `10–11-foundation` | wrap | `29` | `287` | `2h50m51s` | `$191.55` (`gpt56sol`) | `$6.61` | `$0.67` | `56m04s` | `$43.48` (`opus5`) |
| `20-review-foundation` | review | `34` | `285` | `2h03m21s` | `$217.23` (`opus5`) | `$6.39` | `$0.76` | — | — |
| `40–43-x509` | wrap | `32` | `123` | `4h07m54s` | `$150.39` (`gpt56sol`) | `$4.70` | `$1.22` | `31m15s` | `$23.33` (`opus5`) |
| `50–51-review-x509` | review | `32` | `124` | `43m33s` | `$23.77` (`opus5`) | `$0.74` | `$0.19` | — | — |
| `60-evp-pkey-core` | wrap | `15` | `145` | `2h12m59s` | `$105.11` (`gpt56sol`) | `$7.01` | `$0.72` | — | — |
| `61-evp-pkey-ctx` | wrap | `1` | `119` | `1h10m31s` | `$40.20` (`gpt56sol`) | `$40.20` | `$0.34` | — | — |
| `62-evp-keymgmt` | wrap | `0` | `11` | `21m06s` | `$5.07` (`gpt56sol`) | — | `$0.46` | — | — |
| `63-digest` | wrap | `1` | `61` | `48m05s` | `$19.57` (`gpt56sol`) | `$19.57` | `$0.32` | — | — |
| `70-review-digest` | review | `8` | `58` | `57m36s` | `$35.96` (`opus5`) | `$4.49` | `$0.62` | — | — |
| `64-cipher-aead` | wrap | `1` | `90` | `57m46s` | `$28.05` (`gpt56sol`) | `$28.05` | `$0.31` | — | — |
| `71-review-cipher` | review | `11` | `87` | `1h30m35s` | `$63.40` (`opus5`) | `$5.76` | `$0.73` | — | — |
| orchestrator | orchestration | `79` | `846` | — | `$77.52`+ (`gpt56sol`) | — | — | — | — |
| **Σ recorded agents** | | **`79`** | **`846`** | **`16h48m`** | **`$920.60`** | **$11.65** | **$1.09** | | **`$66.81`** |

## Raw lifetime discovery

`openai/gpt-5.6-sol` via `codex`.

| tier | symbols submitted | strategies | CDropped | CCloned | CLenDropped | CLenCloned | $ | wall |
|---|---|---|---|---|---|---|---|---|
| void | `7` | `6` | `3` | `0` | `6` | `1` | `$6.24` | `24m20s` |
| string | `3` | `0` | `2` | `3` | `0` | `0` | `$4.46` | `15m05s` |
| **Σ** | **`10`** | **`6`** | **`5`** | **`3`** | **`6`** | **`1`** | **`$10.70`** | **`39m26s`** |

### Review, in-model

`openai/gpt-5.5` via `codex`.

| tier | symbols | batches | $ | wall |
|---|---|---|---|---|
| void | `7` | `4` | `$10.79` | `25m18s` |
| string | — | — | — | — |
| **Σ** | **`7`** | **`4`** | **`$10.79`** | **`25m18s`** |

### Review, independent

`anthropic/claude-opus-5` via `claude`.

| symbols | rv loc | rv $ | rv wall | rv $/symbol |
|---|---|---|---|---|
| `10` | `+626/-118` | `$18.82` | `47m01s` | `$1.88` |
| **Σ `10`** | **`+626/-118`** | **`$18.82`** | — | **`$1.88`** |

## Target set

### Batches — types, wrap

`openai/gpt-5.6-sol` via `codex`.

| types | fields | lifecycle prims | $ | wall | $/type | $/field |
|---|---|---|---|---|---|---|
| `2` | `5` | `0` | `$3.62` | `10m52s` | `$1.81` | `$0.72` |
| `2` | `5` | `0` | `$5.32` | `15m26s` | `$2.66` | `$1.06` |
| `2` | `5` | `2` | `$3.78` | `10m49s` | `$1.89` | `$0.76` |
| `2` | `5` | `2` | `$4.95` | `8m41s` | `$2.48` | `$0.99` |
| `1` | `0` | `3` | `$3.24` | `10m48s` | `$3.24` | — |
| `1` | `0` | `3` | `$3.15` | `8m03s` | `$3.15` | — |
| `1` | `0` | `1` | `$2.66` | `10m47s` | `$2.66` | — |
| `1` | `0` | `1` | `$3.80` | `13m31s` | `$3.80` | — |
| `1` | `0` | `5` | `$3.52` | `10m46s` | `$3.52` | — |
| `1` | `0` | `5` | `$5.75` | `20m06s` | `$5.75` | — |
| `2` | `0` | `0` | `$1.19` | `4m25s` | `$0.60` | — |
| `2` | `0` | `0` | `$5.93` | `16m09s` | `$2.96` | — |
| `1` | `0` | `0` | `$0.56` | `3m08s` | `$0.56` | — |
| `1` | `0` | `0` | `$1.92` | `6m22s` | `$1.92` | — |
| `1` | `0` | `1` | `$0.43` | `0m49s` | `$0.43` | — |
| `1` | `0` | `1` | `$3.70` | `10m42s` | `$3.70` | — |
| `2` | `4` | `1` | `$0.27` | `0m12s` | `$0.14` | `$0.07` |
| `2` | `4` | `1` | `$4.11` | `16m09s` | `$2.05` | `$1.03` |
| `1` | `0` | `1` | `$0.27` | `0m11s` | `$0.27` | — |
| `1` | `0` | `1` | `$4.37` | `13m41s` | `$4.37` | — |
| `1` | `0` | `4` | `$0.27` | `0m10s` | `$0.27` | — |
| `1` | `0` | `4` | `$4.79` | `15m22s` | `$4.79` | — |
| `2` | `8` | `0` | `$3.69` | `12m26s` | `$1.85` | `$0.46` |
| `2` | `0` | `5` | `$8.47` | `15m12s` | `$4.24` | — |
| `2` | `11` | `0` | `$5.14` | `14m25s` | `$2.57` | `$0.47` |
| `2` | `0` | `0` | `$3.23` | `10m56s` | `$1.61` | — |
| `2` | `0` | `0` | `$2.80` | `9m02s` | `$1.40` | — |
| `1` | `0` | `0` | `$4.83` | `13m50s` | `$4.83` | — |
| `1` | `23` | `1` | `$5.42` | `15m45s` | `$5.42` | `$0.24` |
| `1` | `2` | `1` | `$4.73` | `16m48s` | `$4.73` | `$2.37` |
| `1` | `0` | `3` | `$4.19` | `13m26s` | `$4.19` | — |
| `1` | `0` | `2` | `$4.37` | `12m27s` | `$4.37` | — |
| `1` | `0` | `3` | `$4.09` | `16m50s` | `$4.09` | — |
| `2` | `0` | `2` | `$4.63` | `11m53s` | `$2.32` | — |
| `1` | `0` | `3` | `$6.19` | `15m07s` | `$6.19` | — |
| `1` | `2` | `2` | `$6.55` | `15m43s` | `$6.55` | `$3.27` |
| `2` | `0` | `2` | `$3.50` | `12m08s` | `$1.75` | — |
| `2` | `0` | `3` | `$5.76` | `15m57s` | `$2.88` | — |
| `2` | `0` | `2` | `$2.85` | `8m58s` | `$1.43` | — |
| `2` | `0` | `2` | `$3.39` | `9m39s` | `$1.69` | — |
| `2` | `0` | `0` | `$4.46` | `12m44s` | `$2.23` | — |
| `2` | `0` | `1` | `$2.81` | `8m47s` | `$1.40` | — |
| `2` | `7` | `3` | `$7.72` | `22m32s` | `$3.86` | `$1.10` |
| `1` | `2` | `1` | `$5.76` | `15m01s` | `$5.76` | `$2.88` |
| `1` | `2` | `1` | `$4.33` | `14m10s` | `$4.33` | `$2.16` |
| `2` | `5` | `2` | `$5.62` | `16m31s` | `$2.81` | `$1.12` |
| `2` | `6` | `2` | `$3.59` | `12m42s` | `$1.79` | `$0.60` |
| `1` | `2` | `1` | `$5.02` | `20m51s` | `$5.02` | `$2.51` |
| `1` | `17` | `2` | `$4.73` | `15m01s` | `$4.73` | `$0.28` |
| `1` | `2` | `1` | `$3.39` | `11m46s` | `$3.39` | `$1.70` |
| `2` | `5` | `2` | `$5.63` | `20m29s` | `$2.81` | `$1.13` |
| `1` | `5` | `1` | `$5.92` | `18m44s` | `$5.92` | `$1.18` |
| `1` | `0` | `1` | `$4.74` | `15m09s` | `$4.74` | — |
| `1` | `0` | `3` | `$3.76` | `13m56s` | `$3.76` | — |
| `1` | `0` | `0` | `$2.36` | `7m03s` | `$2.36` | — |
| `1` | `0` | `2` | `$4.47` | `14m39s` | `$4.47` | — |
| `1` | `0` | `2` | `$4.76` | `14m24s` | `$4.76` | — |
| `1` | `0` | `2` | `$3.78` | `10m05s` | `$3.78` | — |
| `1` | `0` | `2` | `$3.20` | `10m45s` | `$3.20` | — |
| `1` | `0` | `2` | `$4.28` | `14m15s` | `$4.28` | — |
| `1` | `0` | `2` | `$3.97` | `13m38s` | `$3.97` | — |
| `1` | `5` | `0` | `$5.18` | `12m00s` | `$5.18` | `$1.04` |
| `1` | `0` | `3` | `$4.05` | `14m06s` | `$4.05` | — |
| `1` | `0` | `3` | `$4.83` | `14m42s` | `$4.83` | — |
| `1` | `0` | `3` | `$6.25` | `22m34s` | `$6.25` | — |
| `1` | `0` | `2` | `$5.73` | `14m27s` | `$5.73` | — |
| `1` | `0` | `2` | `$4.03` | `12m09s` | `$4.03` | — |
| `1` | `0` | `0` | `$3.57` | `13m05s` | `$3.57` | — |
| `1` | `0` | `0` | `$4.47` | `12m19s` | `$4.47` | — |
| `1` | `0` | `0` | `$4.25` | `14m10s` | `$4.25` | — |
| **Σ `94`** | **`132`** | **`113`** | **`$288.11`** | — | **$3.06** | **$2.18** |

### Batches — review types

`anthropic/claude-opus-5` via `claude`.

| types | rv loc | rv $ | rv wall | rv $/type |
|---|---|---|---|---|
| `6` | — | `$9.94` | `20m22s` | `$1.66` |
| `1` | — | `$4.67` | `13m38s` | `$4.67` |
| `2` | — | `$7.13` | `20m05s` | `$3.57` |
| `1` | — | `$6.61` | `18m45s` | `$6.61` |
| `1` | — | `$8.22` | `16m30s` | `$8.22` |
| `1` | — | `$4.83` | `9m56s` | `$4.83` |
| `3` | — | `$7.35` | `19m39s` | `$2.45` |
| `1` | — | `$6.19` | `14m03s` | `$6.19` |
| `2` | — | `$8.21` | `18m21s` | `$4.10` |
| `1` | — | `$7.54` | `18m16s` | `$7.54` |
| `1` | — | `$5.40` | `15m17s` | `$5.40` |
| `3` | — | `$11.75` | `21m27s` | `$3.92` |
| `2` | — | `$8.81` | `19m10s` | `$4.40` |
| `6` | — | `$13.62` | `20m54s` | `$2.27` |
| `1` | — | `$5.22` | `12m17s` | `$5.22` |
| `1` | — | `$7.88` | `20m00s` | `$7.88` |
| `1` | — | `$7.21` | `18m58s` | `$7.21` |
| `32` | — | `$11.28` | `19m08s` | `$0.35` |
| `4` | — | `$8.12` | `21m44s` | `$2.03` |
| `4` | — | `$14.91` | `27m42s` | `$3.73` |
| `6` | — | `$10.58` | `25m42s` | `$1.76` |
| `2` | — | `$9.23` | `21m05s` | `$4.61` |
| `1` | — | `$4.88` | `12m10s` | `$4.88` |
| `1` | — | `$6.85` | `14m12s` | `$6.85` |
| `1` | — | `$4.69` | `13m04s` | `$4.69` |
| **Σ `85`** | — | **`$201.11`** | — | **$2.37** |

### Batches — symbols

`openai/gpt-5.6-sol` via `codex`.

| objective | symbols | loc | $ | wall | $/symbol | $/loc |
|---|---|---|---|---|---|---|
| raw lifetime | `0` | `0` | `$6.24` | `24m20s` | — | — |
| raw lifetime | `0` | `0` | `$4.46` | `15m05s` | — | — |
| wrap | `39` | `711` | `$0.19` | `0m09s` | `$0.00` | `$0.00` |
| wrap | `39` | `711` | `$7.61` | `24m09s` | `$0.20` | `$0.01` |
| wrap | `50` | `685` | `$10.23` | `21m48s` | `$0.20` | `$0.01` |
| wrap | `50` | `857` | `$11.78` | `26m30s` | `$0.24` | `$0.01` |
| wrap | `50` | `493` | `$9.43` | `22m18s` | `$0.19` | `$0.02` |
| wrap | `32` | `272` | `$11.61` | `34m23s` | `$0.36` | `$0.04` |
| wrap | `41` | `800` | `$10.41` | `33m52s` | `$0.25` | `$0.01` |
| wrap | `1` | `44` | `$2.75` | `6m14s` | `$2.75` | `$0.06` |
| wrap | `22` | `198` | `$6.08` | `26m16s` | `$0.28` | `$0.03` |
| wrap | `2` | `0` | `$2.02` | `5m42s` | `$1.01` | — |
| wrap | `27` | `145` | `$8.82` | `25m21s` | `$0.33` | `$0.06` |
| wrap | `18` | `122` | `$7.29` | `16m09s` | `$0.41` | `$0.06` |
| wrap | `20` | `129` | `$6.35` | `14m00s` | `$0.32` | `$0.05` |
| wrap | `1` | `5` | `$2.47` | `4m26s` | `$2.47` | `$0.49` |
| wrap | `31` | `103` | `$8.85` | `19m33s` | `$0.29` | `$0.09` |
| wrap | `6` | `6` | `$2.73` | `5m20s` | `$0.45` | `$0.45` |
| wrap | `2` | `25` | `$3.60` | `9m29s` | `$1.80` | `$0.14` |
| wrap | `6` | `6` | `$2.03` | `5m11s` | `$0.34` | `$0.34` |
| wrap | `6` | `81` | `$5.52` | `12m34s` | `$0.92` | `$0.07` |
| wrap | `6` | `6` | `$2.44` | `4m31s` | `$0.41` | `$0.41` |
| wrap | `1` | `21` | `$1.65` | `3m54s` | `$1.65` | `$0.08` |
| wrap | `44` | `986` | `$13.38` | `1h05m54s` | `$0.30` | `$0.01` |
| wrap | `50` | `586` | `$8.18` | `15m43s` | `$0.16` | `$0.01` |
| wrap | `33` | `411` | `$10.71` | `29m49s` | `$0.32` | `$0.03` |
| wrap | `17` | `204` | `$5.80` | `15m14s` | `$0.34` | `$0.03` |
| wrap | `50` | `643` | `$11.00` | `23m14s` | `$0.22` | `$0.02` |
| wrap | `50` | `537` | `$9.82` | `35m57s` | `$0.20` | `$0.02` |
| wrap | `10` | `99` | `$5.20` | `11m05s` | `$0.52` | `$0.05` |
| wrap | `6` | `48` | `$6.17` | `11m46s` | `$1.03` | `$0.13` |
| wrap | `3` | `112` | `$4.44` | `9m36s` | `$1.48` | `$0.04` |
| wrap | `11` | `64` | `$5.07` | `21m05s` | `$0.46` | `$0.08` |
| wrap | `50` | `847` | `$10.86` | `35m44s` | `$0.22` | `$0.01` |
| wrap | `11` | `61` | `$4.24` | `15m33s` | `$0.39` | `$0.07` |
| wrap | `50` | `685` | `$7.88` | `16m05s` | `$0.16` | `$0.01` |
| wrap | `33` | `519` | `$10.31` | `26m39s` | `$0.31` | `$0.02` |
| wrap | `4` | `38` | `$3.06` | `7m54s` | `$0.77` | `$0.08` |
| wrap | `3` | `123` | `$2.56` | `8m57s` | `$0.85` | `$0.02` |
| **Σ** | **`875`** | **`11,383`** | **`$253.22`** | | **$0.29** | **$0.02** |

### Batches — review symbols

`anthropic/claude-opus-5` via `claude`.

| symbols | rv loc | rv $ | rv wall | rv $/symbol |
|---|---|---|---|---|
| `1` | — | `$3.36` | `5m20s` | `$3.36` |
| `2` | — | `$2.98` | `9m51s` | `$1.49` |
| `2` | — | `$1.26` | `3m23s` | `$0.63` |
| `2` | — | `$3.19` | `6m39s` | `$1.59` |
| `2` | — | `$4.26` | `10m34s` | `$2.13` |
| `4` | — | `$6.20` | `15m20s` | `$1.55` |
| `2` | — | `$4.40` | `11m11s` | `$2.20` |
| `2` | — | `$3.95` | `9m51s` | `$1.98` |
| `39` | — | `$9.44` | `17m34s` | `$0.24` |
| `50` | — | `$20.31` | `33m38s` | `$0.41` |
| `50` | — | `$11.22` | `20m48s` | `$0.22` |
| `50` | — | `$8.91` | `19m28s` | `$0.18` |
| `32` | — | `$14.38` | `28m31s` | `$0.45` |
| `41` | — | `$10.16` | `18m10s` | `$0.25` |
| `1` | — | `$3.86` | `10m10s` | `$3.86` |
| `22` | — | `$8.36` | `16m25s` | `$0.38` |
| `123` | — | `$9.36` | `16m21s` | `$0.08` |
| `1` | — | `$3.13` | `8m01s` | `$3.13` |
| `58` | — | `$12.93` | `29m51s` | `$0.22` |
| `72` | — | `$11.19` | `27m47s` | `$0.16` |
| `8` | — | `$10.29` | `20m15s` | `$1.29` |
| `4` | — | `$2.32` | `6m45s` | `$0.58` |
| `3` | — | `$3.37` | `9m42s` | `$1.12` |
| **Σ `571`** | — | **`$168.84`** | — | **$0.30** |

## Safety audit

Deterministic `crustify-audit unsafe`; no model.

### Snapshots

| | foundation review, before (`894f727207`) | foundation review, after (`32ada326d7`) | campaign record (`13a55bf7c1`) |
|---|---|---|---|
| unsafe loc | `1,108` | `1,126` | `3,423` |
| % of loc | `27.87%` | `26.29%` | `28.86%` |
| blocks | `624` | `641` | `1,944` |
| % in `impl T` | `42.31%` | `42.59%` | `45.68%` |
| `unsafe fn` | `232` | `240` | `545` |
| ...of which not sanctioned | `82` | `90` | `175` |
| raw-ptr smell | `19` | `19` | `38` |
| void-ptr smell | `4` | `4` | `6` |
| FFI calls | `299` | `299` | `886` |
| `&`/`&mut` on a wrapper | `0` | `0` | `0` |
| field proj outside an accessor | `0` | `0` | `0` |

### All metrics

| metric | foundation before | campaign record | Δ | reading |
|---|---|---|---|---|
| `code_lines` | `3,975` | `11,861` | `+7,886` | union of HIR definition spans (denominator); `cfg`-disabled items excluded |
| `total_stmts` | `572` | `1,949` | `+1,377` | statements |
| `unsafe_blocks` | `624` | `1,944` | `+1,320` | count of `unsafe { }` blocks, macro-expanded included |
| `unsafe_block_stmts` | `29` | `114` | `+85` | statements inside them |
| `unsafe_block_lines` | `1,108` | `3,423` | `+2,315` | their lines, every outermost block |
| `unsafe_blocks_wrapper_impl` | `264` | `888` | `+624` | inside `impl <wrapper T>` |
| `unsafe_blocks_ffi_export` | `9` | `34` | `+25` | inside the C-ABI gateway |
| `unsafe_fns` | `232` | `545` | `+313` | `unsafe fn` declarations, post-expansion |
| `unsafe_fns_seam` | `150` | `370` | `+220` | ...the sanctioned subset |
| `unsafe_fns_pub` | `228` | `505` | `+277` | ...of `unsafe_fns`, exported from the crate |
| `ffi_calls` | `299` | `886` | `+587` | calls to a foreign item — the unsafe-FFI-call surface |
| `wrapper_newtypes` | `30` | `64` | `+34` | LAYOUT newtypes — `repr(transparent)` over a `repr(C)` type by value |
| `wrapper_newtypes_declared` | `30` | `64` | `+34` | the `CCell`-declared count, for comparison |
| `wrapper_declared_nonconformant` | `0` | `0` | `+0` | declared but failing the structural test — **target 0** |
| `wrapper_newtypes_undeclared` | `0` | `0` | `+0` | structural but undeclared — a hand-written layout newtype |
| `raw_ptr_args` | `96` | `253` | `+157` | raw-ptr positions in arguments |
| `raw_ptr_rets` | `104` | `266` | `+162` | raw-ptr positions in returns |
| `raw_ptr_seam` | `181` | `481` | `+300` | sanctioned: seam fn / `mod ffi_export` / `extern "C"` / ptr-to-own-`Self` |
| `raw_ptr_wrapped` | `4` | `16` | `+12` | **of the smell**: pointee is a C type that HAS a wrapper — the actionable defect |
| `raw_ptr_in_wrapper` | `0` | `0` | `+0` | **of the smell**: inside a wrapper impl — the least excusable placement |
| `raw_ptr_derefs` | `151` | `313` | `+162` | `*p` on a raw pointer (volume) |
| `ref_to_type_wrapper` | `0` | `0` | `+0` | `&`/`&mut` on a layout newtype — **target 0** |
| `field_proj_wrapped` | `112` | `301` | `+189` | projection VOLUME — shares one HIR shape with `addr_of!`, not a violation |
| `field_proj_outside_impl` | `0` | `0` | `+0` | projections outside any accessor — **target 0** |
| `field_ref_wrapped` | `0` | `0` | `+0` | `&(*p).field` — forbidden by the translator playbook — **target 0** |
| `void_ptr_sanctioned` | `65` | `191` | `+126` | `*c_void` in a seam / `ffi_export` / `extern "C"` signature |
| `void_ptr_smell` | `4` | `6` | `+2` | `*c_void` elsewhere; `void_ptr_sites` names each one |

## Notes

### Campaign result

Three approved subsets are complete. The foundation tranche (`10`–`11`) covers
the ASN.1 string/object layer, the generic `STACK_OF` container and BIO. The
X.509 tranche (`40`–`43`) covers certificate, name and extension handling. The
`EVP_PKEY` core tranche (`60`) covers key handles, signatures, key exchange,
KEM and asymmetric cipher entry points.

Tree-wide the campaign has landed `80` wrapped types, `9` callbacks and `553`
wrapped symbols over `21,080` non-test Rust lines and `10,056` lines of tests.
One `Replaces:` anchor exists; everything else is a wrap, which is what a wrap
campaign should produce. No scheduler TODO anchor survives anywhere in the Rust
tree, so every scheduled item is filled.

### Table ordering

The batch tables carry no batch-name column, so their rows are ordered by
sub-campaign in the sequence the Overview lists, then by dependency layer
within each. A row is one agent.

### Sub-campaigns the Overview lists but no table details

`02-review-void` ran under `openai/gpt-5.5` before the reviewer model was
settled, and `03-review-string` was scheduled and then superseded without ever
running — it has no `campaign.json` and no logs. `10-foundation` ran twice: an
`11m06s` first session (`e1fa`) whose plan was regenerated after a scheduler
admission repair, and the `2h34m03s` session (`95ed`) that actually landed. All
three of `e1fa`'s surviving agent records price into the Σ row but have no
batch row, because the plan they ran against no longer exists.

### Overview unit counts are what a sub-campaign was scheduled for

The Σ row instead counts DISTINCT implementation units — the raw-lifetime and
wrap sub-campaigns only — so review coverage is not counted a second time. Its
`$/type` and `$/sym` are therefore the whole campaign's spend, review and
orchestration included, over the units that spend produced: `$9.58` per type
and `$1.29` per symbol are the all-in rates, several times the per-wave rates
above them.

Per the legend, `nr types` / `nr symbols` count the units a sub-campaign was
scheduled over, taken from its `campaign.json`. Those differ from the landed
anchor counts: a review sub-campaign re-batches the units it judges, so
`20-review-foundation` shows `34` types against the wrap tranche's `29` — the
oracle admitted five more types into the review schedule than the corrected
wrap plan carried. Reviews are their own sub-campaign rows for exactly this
reason; their rows never line up with the wave underneath.

### The EVP_PKEY wave's field counts are small by construction

`60`'s fifteen type batches carry only `5` in-scope fields between them. Under
`--api-headers-only` a struct keeps its layout only when it is *defined* in an
`api_headers` file, and almost every EVP type it scheduled — `evp_pkey_ctx_st`,
`evp_keymgmt_st`, `evp_signature_st`, the four legacy key handles — is defined
in a private header or a `.c`. They wrap as opaque handles, so `$/field` is not
a meaningful rate for that tranche and `$/type` is the one to read.

### Gate misses at landing

`60` landed 20 of 20 batches with no agent failures, but three gates failed on
the merged tree and the orchestrator repaired them before promoting.

Two agents left items after their test module, which clippy rejects under the
workspace lint set. Module declaration order in `lib.rs` and `stack/mod.rs` was
rustfmt-dirty — that one predates this wave: `cargo fmt --check` already failed
at `c133e571b3`, so the previous revision of this report claiming the promoted
campaign passed `cargo fmt --check` was not accurate. It passes now.

### The post-merge scan caught a hard-target regression

The seeded scan over `60`'s 160 names reported `field_proj_outside_impl = 2`
against a target of zero. Two callers projected `key` out of a C-contract
`OSSL_PARAM` array to find its null-key terminator: `terminated_param_len`, and
a scan `EVP_PKEY_fromdata_settable` had reimplemented inline despite already
importing that helper.

The repair adds `OsslParam::is_terminator_at`, putting the projection in the
descriptor's own accessor, and routes both callers through it. The first
attempt returned the borrowed `*const c_char` and merely moved the violation:
`field_proj_outside_impl` went to zero but `raw_ptr_in_wrapper` went to one,
which the audit calls the least excusable placement. Returning a predicate
instead keeps the key pointer inside the wrapper and scores zero on both.
Raw-pointer dereferences outside an accessor fell from `5` to `3` as a side
effect, since the duplicated scan disappeared.

### What the API percentages are measured against

`--api-headers-only` over `include/openssl/` publishes `459` types, `6,761`
functions, `648` callbacks, `2` globals and `5,742` macros. The percentages
above use the type and function denominators.

Macros are excluded deliberately. Nearly all `5,742` are constant macros, which
`conventions.md` keeps as generated constants in the `-sys` crate rather than
wrapping — folding them into a symbol denominator would report `5.3`% instead
of `9.9`% and would measure the bindgen surface, not the wrapper campaign. The
one macro carrying an anchor is a callable shim.

Callbacks carry their own row rather than folding into types. They are
function-pointer typedefs, the scheduler batches them with symbols, and the
API publishes `648` of them against `459` types — so folding halves the type
share, to `7.6`% from `16.1`%, on a denominator that is largely the
`OSSL_FUNC_*` provider dispatch surface a consumer of the library never
implements by hand. Kept apart, each ratio measures one thing.

The wrapped counts are tree-wide, so they slightly exceed the API-scoped
intersection the percentages use: `81` wrapped types against `74` that are
API-published, and `672` wrapped symbols against `668`. The difference
is private types the closure required — `evp_pkey_ctx_st` and the legacy key
handles are declared in `include/crypto/`, not `include/openssl/`, so they are
wrapped but are not themselves API surface.

### The EVP_PKEY_CTX wave, and a batch-count ceiling

`61` scheduled 120 units but the oracle packed them into only `6` batches: one
type at layer 0, then 110 symbols split 50/50/10 at layer 1. `--parallel-max`
was raised to `16` for this wave and bought nothing — the ceiling is the batch
count, not the flag, and layer 0 is a barrier, so the wave ran single-threaded
for its first 13 minutes. Waves whose units are almost all symbols cannot
saturate a wide pool at `--max-syms 50`.

It was nonetheless the cheapest wrap wave of the campaign at `$40.20` for 120
units, `$0.34` per symbol against X.509's `$1.22`. The `EVP_PKEY_CTX` control
surface is largely thin scalar setters over one C `ctrl` dispatcher, so pooled
50-symbol batches translate it very efficiently — the same pooling that costs
wall-clock is what makes the tranche cheap.

### The digest tranche, and which review cap actually binds

`63-digest` scheduled 62 units — `evp_md_st` was already wrapped by `61`, so
only `evp_md_ctx_st` remained at layer 0 — and landed 3 of 3 batches clean.

Its review, `70`, re-batched to `66` units: `8` types against the wave's `1`,
because the review closure admits the types the digest surface depends on. That
is the structural reason reviews are their own sub-campaign rows; `70`'s rows
cannot be lined up against `63`'s.

The review caps are `--max-types 15` with `--min-fields 60`, and it is
`--min-fields` that binds: both type batches closed at `4`, nowhere near `15`,
because the EVP method tables reach the 60-field floor almost immediately. The
same is true on the translation side — `--max-types 4` has not yet been the
active constraint in any wave scheduled under it.

The review moved no safety metric: raw-pointer, dereference and void-pointer
counts all held exactly, every hard target stayed at zero, and it added `6`
audited lines and one `unsafe fn`. It is the first review in the campaign to
change nothing structural, which is the outcome a clean wave should produce.

### The revised caps, and the first wave to land clean

`62` is the first wave scheduled under the revised translation caps
(`--max-types 4`, `--min-fields 20`, up from `2` and `10`). Neither bound: the
wave is 11 symbols in a single batch, so `--parallel-max 16` was moot too. The
caps will first show their effect on a type-heavy wave.

It is also the first wave to land with no gate miss — clippy, rustfmt and the
seeded scan all clean on the merged tree without orchestrator repair.

Its two new raw-pointer dereferences outside an accessor are C-ABI callback
trampolines recovering the Rust closure from OpenSSL's `void *` argument, the
unavoidable shape for passing a closure through a C callback API. Both carry
SAFETY comments, guard against a panic crossing the FFI boundary, and reject a
null value from the C side rather than dereferencing it.

### A recurring translator habit the gates keep catching

Both `60` and `61` landed with `0` agent failures and then failed clippy on the
merged tree, for the same lint: items declared after a `#[cfg(test)] mod tests`
block. Two agents in `60`, three in `61`. Agents append new wrappers to the end
of a file they have already given a test module, and their own per-worktree
gates pass because each agent sees only its own additions.

`61` also failed `undocumented_unsafe_blocks` as an ERROR, not a warning. The
agent did write a SAFETY comment, but placed it above an `assert_eq!` whose
argument contained the `unsafe` block, so it attached to the macro rather than
the block. `cargo test` cannot catch this: the lint is clippy-only and the code
is inside `#[cfg(test)]`.

Both classes are mechanical and cheap to repair at landing, but they are
translator-side defects that a review pass should be told to look for rather
than the orchestrator fixing by hand every wave.

### Remaining leads, accepted

`raw_ptr_wrapped` sits at `8` and `void_ptr_smell` at `6`. The EVP additions are
private module-local helpers in `evp/kem.rs` and `evp/signature.rs` that map an
`Option<handle>` onto the nullable raw pointer OpenSSL's API requires, where
NULL means "no parameters" or "default signature". They are not `pub`, so they
widen no crate surface, and they sit exactly at the C boundary. The `void_ptr`
sites remain the explicitly localized erased-payload seams in `bio_lib.rs`,
`obj_dat.rs`, `stack.rs` and `v3_lib.rs`.

### Regression gates

At the campaign record the tree passes `cargo fmt --check`, `cargo build`,
`cargo clippy --all-targets` with zero warnings under the workspace's
`undocumented_unsafe_blocks = "deny"`, and `397` Rust tests with no failures.
The pre-review foundation also passed all `4,463` native OpenSSL tests. No C
source changed during any wave, review or UB remediation, so `build.json`'s
`test_baseline` still stands unmodified.

### Accounting

`crustify-log-cost` prices every request from its recorded provider/model token
classes; provider-reported dollars are never used. Across the `133` recorded
translator and review agents the tool reports `$728.36`. The two
`crustify-audit ub` runs (`$43.48` and `$23.33`) are priced separately from
their own usage records and appear only in the Overview's `ub $` column, which
is why the Σ row and the agent total differ.

The Opus reviews and both UB runs used subscription billing, so their figures
are API-equivalent comparison prices rather than charged amounts. Recorded
API-billed work is the `openai/gpt-5.6-sol` implementation total.
