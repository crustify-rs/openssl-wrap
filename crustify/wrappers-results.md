# crustify — `openssl / crypto`

## Campaign

- **target repo** — `openssl` @ `2924476b5591e691e904c4baf57894c526c4b8de`
- **target** — public `libcrypto` API subset; `libssl` excluded
- **campaign objective** — `wrap`
- **agent backend** — `codex`
- **model** — `openai/gpt-5.6-sol`
- **billing** — `api`
- **branch** — `crustify/libcrypto-gpt-5.6-sol`, tip `26c11a6472`
- **deps** — crustify-cli `a97146e`, ffibox `c2178c4`

## Raw lifetime discovery

`strategies` counts newly emitted lifecycle ZSTs. The trait columns count the
`unsafe impl`s added in that tier. The string tier reused five strategies from
the void tier, so it added trait contracts and string aliases without emitting
another strategy ZST.

| tier | symbols submitted | strategies | CDropped | CCloned | CLenDropped | CLenCloned | $ | wall |
|---|---|---|---|---|---|---|---|---|
| void | `7` | `6` | `3` | `0` | `6` | `1` | `$7.94` | `24m20s` |
| string | `3` | `0` | `2` | `3` | `0` | `0` | `$5.69` | `15m05s` |
| **Σ** | **`10`** | **`6`** | **`5`** | **`3`** | **`6`** | **`1`** | **`$13.64`** | **`39m26s`** |

## Foundation wave

The foundation closes the public ASN.1 string/object, generic `STACK_OF`, and
BIO dependency base. It contains `319` unique units: `34` type-route units and
`285` symbol-route units (`277` functions and `8` callbacks), split into `31`
base batches over DAG layers 0–4. The audit corrective batch revisited two of
those symbols; it does not increase the unique-unit count.

### Effective layer accounting

`actual wall` is the dependency-ordered session time. `agent Σ wall` sums
concurrent agents and therefore measures consumed agent time rather than
elapsed campaign time. Layer 0 includes the three retained pre-fix batches;
layer 2 includes the audit corrective batch.

| DAG layer | unique units | effective agents | $ | agent Σ wall | actual wall |
|---|---|---|---|---|---|
| `0` | `59` | `15` | `$82.47` | `3h12m34s` | `46m05s` |
| `1` | `193` | `10` | `$90.87` | `3h00m54s` | `45m24s` |
| `2` | `43` | `4` | `$28.80` | `1h12m08s` | `39m36s` |
| `3` | `2` | `2` | `$8.81` | `19m42s` | `13m28s` |
| `4` | `22` | `1` | `$7.77` | `26m17s` | `26m18s` |
| **Σ** | **`319`** | **`32`** | **`$218.73`** | **`8h11m34s`** | **`2h50m51s`** |

### Gross run accounting

The first foundation schedule admitted private field anchors for public opaque
types. Five units in three completed batches were retained; the other 54
layer-0 units were rerun after the scheduler fix. The superseded work is kept
in gross spend even though it did not land.

| component | worklist units | agents | $ | agent Σ wall | session wall |
|---|---|---|---|---|---|
| retained pre-fix batches | `5` | `3` | `$11.87` | `24m06s` | `11m06s` |
| corrected foundation schedule | `314` | `28` | `$204.27` | `7h41m46s` | `2h34m03s` |
| audit corrective | `2` reworked | `1` | `$2.59` | `5m42s` | `5m42s` |
| **landed/effective** | **`319` unique** | **`32`** | **`$218.73`** | **`8h11m34s`** | **`2h50m51s`** |
| superseded pre-fix work | `54` duplicate | `12` | `$25.61` | `1h03m12s` | included above |
| **gross billed** | **`375` submissions** | **`44`** | **`$244.34`** | **`9h14m47s`** | **`2h50m51s`** |

### Token accounting

Token counts are summed from the request records; cache reads and writes are
shown separately because they are priced differently.

| scope | requests | input | output | cache read | cache write | token events |
|---|---|---|---|---|---|---|
| landed/effective | `2,489` | `5,368,631` | `859,631` | `265,270,865` | `5,353,754` | `276,852,881` |
| superseded | `329` | `988,333` | `119,188` | `21,840,889` | `987,346` | `23,935,756` |
| **gross billed** | **`2,818`** | **`6,356,964`** | **`978,819`** | **`287,111,754`** | **`6,341,100`** | **`300,788,637`** |

The promoted foundation changed Rust sources by `+10,531/-5` lines from the
foundation scaffold through `26c11a6472`.

## Notes

### Lifetime reviews

The void wave landed at `72a0a734fc`; its corrective review held without a
Rust change at `f623e151f5`. The string wave landed at `450d09a229`; its review
also held without a Rust change at `6a625beff8`.

### Accounting

Costs come from `crustify-log-cost` over the per-agent usage records, priced
request by request rather than from provider-reported dollar totals. Raw
lifetime discovery uses two records; foundation gross accounting uses all 44
records, including the superseded scheduler-bug attempt. Totals are computed
from unrounded request costs, so they can differ by one cent from the sum of
displayed row values.
