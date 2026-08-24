# `GENERAL_NAME_cmp`'s `OTHERNAME` guard misses the unset `ASN1_TYPE`: null dereference from safe code

- **Crate:** `libcrypto` 0.1.0 (`crustify/rust/libcrypto`), repository revision
  `10edf02776`.
- **Instruments:** UndefinedBehaviorSanitizer (the tree's own
  `./Configure no-deprecated enable-ubsan --strict-warnings` build, which
  implies `-fno-sanitize-recover`, so the process dies) **and** AddressSanitizer
  (clang 19.1.7 build in `/tmp/osrc-clang`), which reports the same access as
  `SEGV on unknown address 0x000000000000`.
- **Verdict:** confirmed. Both instruments fire in a reproduction that is
  `#![forbid(unsafe_code)]`, depends on the audited crate by path, and calls
  only its public API.
- **Lead note:** [`../notes/x509-surface-adversarial-sweep.md`](../notes/x509-surface-adversarial-sweep.md)
  (section `general-names`, variant pair 10 x 10).

## The path from safe code

```rust
fn other_name() -> CBox<GeneralName> {
    let other = OtherName::new().expect("OTHERNAME_new");
    GeneralName::from_value(GeneralNameValue::OtherName(Some(other))).unwrap()
}

let a = other_name();
let b = other_name();
GENERAL_NAME_cmp(Some(a.as_ref()), Some(b.as_ref()));   // <-- null dereference
```

Three safe `pub fn`s: `OtherName::new`, `GeneralName::from_value`,
`GENERAL_NAME_cmp`. Comparing one such choice with *itself*
(`GENERAL_NAME_cmp(Some(a.as_ref()), Some(a.as_ref()))`) crashes too — the C
function has no pointer-identity shortcut.

## Why the guard does not catch it

`v3_genn.rs:65-103` deliberately screens the arguments before entering C,
because several `GENERAL_NAME_cmp` arms dereference union members without a
null check:

```rust
pub fn GENERAL_NAME_cmp(a: Option<GeneralNameRef<'_>>, b: Option<GeneralNameRef<'_>>) -> Ordering {
    if a.is_some_and(|value| !is_comparable(value)) || b.is_some_and(|value| !is_comparable(value))
    {
        return Ordering::Less;
    }
    ...
    unsafe { ffi::GENERAL_NAME_cmp(a, b) }.cmp(&0)
}

fn is_comparable(value: GeneralNameRef<'_>) -> bool {
    match value.value() {
        ...
        GeneralNameValueRef::OtherName(Some(value)) => {
            value.type_id().is_some() && value.value().is_some()
        }
        ...
    }
}
```

The `OTHERNAME` arm checks that `type_id` and `value` are non-null. Both are,
in a freshly allocated `OTHERNAME`: its ASN.1 template gives `type_id` the
`NID_undef` object and `value` a fresh `ASN1_TYPE`. But that `ASN1_TYPE` is
*unset* — `type == -1`, `value.ptr == NULL` — and C dispatches on that tag:

`crypto/x509/v3_genn.c`
```c
    case GEN_OTHERNAME:
        result = OTHERNAME_cmp(a->d.otherName, b->d.otherName);
```
```c
static int OTHERNAME_cmp(OTHERNAME *a, OTHERNAME *b)
{
    ...
    if ((result = OBJ_cmp(a->type_id, b->type_id)) != 0)
        return result;
    result = ASN1_TYPE_cmp(a->value, b->value);
```
`crypto/asn1/a_type.c`
```c
int ASN1_TYPE_cmp(const ASN1_TYPE *a, const ASN1_TYPE *b)
{
    if (!a || !b || a->type != b->type)
        return -1;
    switch (a->type) {
    case V_ASN1_OBJECT:  ...
    case V_ASN1_BOOLEAN: ...
    case V_ASN1_NULL:    result = 0; break;
    ...
    case V_ASN1_OTHER:
    default:
        result = ASN1_STRING_cmp((ASN1_STRING *)a->value.ptr,
            (ASN1_STRING *)b->value.ptr);
        break;
    }
```
`type == -1` matches no case, so it falls to `default:` and hands two NULLs to
`ASN1_STRING_cmp`, whose first statement is `a->length - b->length`
(`crypto/asn1/asn1_lib.c:495`).

The guard's own predicate is therefore one level too shallow: "the value
pointer is non-null" does not imply "`ASN1_TYPE_cmp` can read it". The three
tags that are safe are `V_ASN1_BOOLEAN` (reads a scalar), `V_ASN1_NULL` (reads
nothing) and `V_ASN1_OBJECT` (reads a pointer that the crate's safe setters
always fill). Everything else, `-1` included, reaches `ASN1_STRING_cmp`.

## Reproduction

`crustify/audit/tmp/general-name-cmp-null/` — a cargo crate with
`#![forbid(unsafe_code)]` in `src/main.rs`, depending on the audited crate by
path. The whole program is quoted above.

### UBSan (the tree's own build — nothing extra to set up)

```sh
$ cargo build
$ UBSAN_OPTIONS=print_stacktrace=1 ./target/debug/general-name-cmp-null
comparing two GEN_OTHERNAME choices
crypto/asn1/asn1_lib.c:495:11: runtime error: member access within null pointer of type 'const struct ASN1_STRING'
    #0 0x6286b5ca5e9d in ASN1_STRING_cmp crypto/asn1/asn1_lib.c:495
    #1 0x6286b5c9b524 in libcrypto::x509::v3_genn::GENERAL_NAME_cmp src/x509/v3_genn.rs:76
    #2 0x6286b5c99a7c in general_name_cmp_null::main src/main.rs:31
    ...
$ echo $?
1
```

### AddressSanitizer (clang build, `/tmp/osrc-clang`)

```sh
$ cp .cargo/config.toml.asan .cargo/config.toml
$ CARGO_TARGET_DIR=target-asan rustup run nightly cargo build --target x86_64-unknown-linux-gnu
$ ASAN_OPTIONS=detect_leaks=0 ./target-asan/x86_64-unknown-linux-gnu/debug/general-name-cmp-null
comparing two GEN_OTHERNAME choices
AddressSanitizer:DEADLYSIGNAL
=================================================================
==890397==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000 (pc 0x5ee0abba050d ...)
==890397==The signal is caused by a READ memory access.
==890397==HINT: address points to the zero page.
    #0 ASN1_STRING_cmp (/tmp/osrc-clang/crypto/asn1/asn1_lib.c:495)
    #1 libcrypto::x509::v3_genn::GENERAL_NAME_cmp (/work/openssl/crustify/rust/libcrypto/src/x509/v3_genn.rs:76)
    #2 general_name_cmp_null::main (.../general-name-cmp-null/src/main.rs:31)
```

(Symbolized with `crustify/audit/tmp/symbolize.py`; see
[`../notes/sanitizer-setup-for-this-tree.md`](../notes/sanitizer-setup-for-this-tree.md).)

## Arguing against myself

- **"`OTHERNAME_new()` does not really leave `value` unset."** The
  reproduction asserts `other.as_ref().type_id().is_some()` and
  `other.as_ref().value().is_some()` before building the choice — those are the
  exact two predicates the crate's guard uses, and both hold. The tag is what
  is wrong, and the guard never looks at it.
- **"Safe code cannot really produce this."** `OtherName::new()` is
  `pub fn new() -> Option<CBox<Self>>` (`x509v3.rs:1388`), and
  `GeneralName::from_value` is `pub fn` (`x509v3.rs:3151`). The crate's own
  test `other_name_outputs_are_borrowed_from_the_parent`
  (`v3_genn.rs:259-277`) builds exactly this object; it just never compares it.
- **"It is only reachable with a hand-built value, not from a decoded
  certificate."** True as far as I tested — a `GEN_OTHERNAME` decoded from DER
  always has a set `ASN1_TYPE`, because the ASN.1 `ANY` parser fills the tag.
  That narrows the input source, not the soundness claim: the bar is a safe
  caller reaching UB, and `OtherName::new()` is a safe caller's ordinary
  starting point for building a name.
- **"It is really an OpenSSL bug."** `ASN1_TYPE_cmp`'s `default:` arm should
  null-check, and I think upstream should fix it (see below). But this wrapper
  *added a guard for precisely this class* and the guard is incomplete, so the
  Rust side is where the reachable-from-safe-code defect is.
- **"It duplicates an existing advisory."** It does not.
  `bio-gets-buffer-filter-null-deref.md` is a null read at `NULL+0x28` in
  `bf_buff.c` reached through `BIO_gets` on an unchained filter — different
  function, different mechanism, different module. The only thing they share is
  the instrument.
- **"It is a known CVE."** CVE-2015-0286 is also in `ASN1_TYPE_cmp` but is the
  `V_ASN1_BOOLEAN` type confusion, fixed by the `case V_ASN1_BOOLEAN:` arm that
  is present here. CVE-2020-1971 is the `GENERAL_NAME_cmp` EDIPARTYNAME null
  deref, fixed by the `edipartyname_cmp` helper that is present here. This is a
  third, distinct hole in the same two functions, and neither existing fix
  covers it.

## Not checked

- Whether `ASN1_TYPE_cmp` is reachable with an unset `ASN1_TYPE` through any
  other wrapped entry point. `ASN1_TYPE_cmp` itself is not wrapped, and
  `GENERAL_NAME_cmp` is the only safe caller I found (`grep -rn ASN1_TYPE_cmp`
  over the crate returns two doc comments and no call).
- Whether an `ASN1_TYPE` with tag `V_ASN1_OBJECT` and a null `value.object` is
  reachable — it would hit the same class through `OBJ_cmp`. The crate's two
  safe object setters both take a non-null owner, so I believe it is not, but I
  did not exhaustively check the decode paths.

## Suggested fix

Deepen the guard so the `OTHERNAME` arm also classifies the tagged value, using
the crate's existing `Asn1TypeRef::value()` view rather than a raw tag
comparison. Only `V_ASN1_BOOLEAN`, `V_ASN1_NULL` and a non-null `V_ASN1_OBJECT`
are safe; everything else must be treated as incomparable and take the existing
`Ordering::Less` path, which is what the wrapper already returns for the other
malformed shapes.

**Not a breaking change** — the signature does not move, and the only
behavioural difference is that a shape which previously crashed now reports
`Ordering::Less`, consistent with how the wrapper already handles `Empty`,
`Unknown` and null arms.

Separately, and independently of this crate, `ASN1_TYPE_cmp`'s `default:` arm
in `crypto/asn1/a_type.c` should null-check both `value.ptr`s (or
`ASN1_STRING_cmp` should tolerate null, as several sibling comparators do).
That is an OpenSSL C fix and is not attempted here — the C tree is shared with
the project's own 4463-assertion baseline and a comparator semantics change
belongs upstream.

## Remediation

- **Branch:** `crustify/audit-fix-refcount-alias-and-general-name-cmp`, cut
  from `10edf02776`. Committed, not merged, not pushed.
- **Commit:** `d5e86577a2` "Reject an unset ASN1_TYPE before GENERAL_NAME_cmp
  dereferences it".

### What the patch does

`crustify/rust/libcrypto/src/x509/v3_genn.rs` only. The `GEN_OTHERNAME` arm of
the existing screen now reaches one level deeper:

```rust
GeneralNameValueRef::OtherName(Some(value)) => {
    value.type_id().is_some() && value.value().is_some_and(is_comparable_value)
}
```

and the new predicate classifies the tagged value through the crate's own
`Asn1TypeRef::value()` view rather than a raw tag comparison:

```rust
fn is_comparable_value(value: Asn1TypeRef<'_>) -> bool {
    match value.value() {
        Asn1TypeValue::Boolean(_) | Asn1TypeValue::Null => true,
        Asn1TypeValue::Object(object) => object.is_some(),
        Asn1TypeValue::Undefined | Asn1TypeValue::Any(_) => false,
        Asn1TypeValue::Integer(value)
        | ... all remaining string arms ...
        | Asn1TypeValue::Unknown { value, .. } => value.is_some(),
    }
}
```

`V_ASN1_BOOLEAN` reads a scalar and `V_ASN1_NULL` reads nothing, so both are
comparable unconditionally. `V_ASN1_OBJECT` is comparable when its object is
present, because `OBJ_cmp` dereferences it. Every remaining tag reaches
`ASN1_STRING_cmp`, so it needs a non-null payload. `V_ASN1_UNDEF` — the bug —
and `V_ASN1_ANY` are rejected outright: the first has no payload at all, the
second's payload is a nested `ASN1_TYPE` header that the `default:` arm would
read as an `ASN1_STRING`. (`V_ASN1_ANY` is unreachable from this crate's safe
surface today, so that arm is defence in depth.)

No signature change; an incomparable pair takes the `Ordering::Less` path the
wrapper already returns for empty, unknown and null-armed choices.

### Regression test

`v3_genn::general_name_tests::an_other_name_holding_an_unset_value_is_not_compared`
builds the exact object the crash needed, asserts both predicates that
previously passed still pass, and checks that the comparison is refused — for
two such choices and for one against itself. It then sets the value's tag to
`V_ASN1_NULL` and checks the pair compares `Equal`, so the guard is not simply
refusing every `OTHERNAME`.

### Commands and results

```sh
cd /work/openssl/crustify/rust
cargo test -p libcrypto        # test result: ok. 330 passed; 0 failed
cargo clippy --workspace --all-targets   # 0 warnings, 0 errors
cargo fmt --check              # only the two pre-existing diffs, verified by stashing
```

(330 at this commit; the count returns to 329 in the following commit, which
removes a test whose premise the second fix deletes.)

### The reproduction against the patch

```
$ cd crustify/audit/tmp/general-name-cmp-null && cargo build
$ UBSAN_OPTIONS=print_stacktrace=1 ./target/debug/general-name-cmp-null
comparing two GEN_OTHERNAME choices
survived: Less
$ echo $?
0
```

and under AddressSanitizer:

```
$ ASAN_OPTIONS=detect_leaks=0 ./target-asan/x86_64-unknown-linux-gnu/debug/general-name-cmp-null
comparing two GEN_OTHERNAME choices
survived: Less
$ echo $?
0
```

The `general-names` section of `crustify/audit/tmp/x509-probe/` — the 15 x 15
`GeneralNameValue` matrix that found this — now runs its previously fatal pair
without a skip and reports `0 failing section(s)` under both instruments.

### Left undone

`ASN1_TYPE_cmp`'s missing null check in `crypto/asn1/a_type.c` is untouched.
It is a real OpenSSL defect and any other C caller that reaches it with an
unset `ASN1_TYPE` still crashes, but changing a comparator's semantics in the
shared C tree would need to go through the project's own 4463-assertion
baseline and belongs upstream, not in an audit patch.
