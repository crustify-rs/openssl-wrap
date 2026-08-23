# Lead: `ASN1_STRING_type_new` accepts any tag, including non-string tags

**Status: CONFIRMED -> [`advisories/asn1-string-print-ex-object-type-confusion.md`](../advisories/asn1-string-print-ex-object-type-confusion.md)**

## How I got here

`asn1/openssl_asn1.rs` contains a careful, explicitly-reasoned predicate:

```rust
    /// Whether a non-null payload under this tag is an `asn1_string_st`.
    pub const fn holds_string(self) -> bool {
        !matches!(self, Self::Undefined | Self::Boolean | Self::Null
                      | Self::Object | Self::Any)
    }
```

with a doc comment explaining that `V_ASN1_OBJECT` holds an `ASN1_OBJECT` and
`V_ASN1_ANY` a nested `ASN1_TYPE`, and that "the safe surface must not mistake
such a payload for an `ASN1_STRING`". `Asn1TypeRef::value` honours it.

Two modules over, `ASN1_STRING_type_new(string_type: c_int)` (`asn1/asn1_lib.rs`)
hands the tag straight to C with no check at all. So the crate has both a
statement of the invariant and an unguarded factory for objects that violate it.
That gap is what I went looking for a consumer of.

## Finding the consumer

I swept `ASN1_STRING_print_ex` over tags `-10..=40` x eight flag words x
{empty, filled} under ASan — 816 cells, one per process
(`crustify/audit/tmp/probe/src/bin/strex.rs`). Four fail, all tag 6 with
`ASN1_STRFLGS_DUMP_DER`: `do_dump` re-wraps the string as an `ASN1_TYPE` under
its own tag and the DER encoder reads `((ASN1_OBJECT *)str)->data` at offset 24
of a 24-byte allocation.

## Consumers I checked and cleared for a mis-tagged string

Exercised across all tags in `crustify/audit/tmp/probe/src/bin/sweep.rs` under
both ASan and the tree's UBSan build, all clean:
`ASN1_STRING_set`, `ASN1_STRING_set1_data`, `ASN1_STRING_set1_string`,
`ASN1_STRING_length_set`, `ASN1_STRING_get0_data`, `ASN1_STRING_get_length`,
`ASN1_STRING_type`, `ASN1_STRING_cmp`, `ASN1_STRING_copy`, `ASN1_STRING_dup`,
`ASN1_STRING_to_UTF8`, `ASN1_STRING_print`, `clear_data`, `ASN1_STRING_free`,
`ASN1_STRING_clear_free`.

`V_ASN1_ANY` — the other tag `holds_string` excludes with a pointer payload —
does not reach an out-of-bounds access through `do_dump`, because
`asn1_ex_i2c`'s switch has no arm for it and the `default:` arm treats the
payload as the `ASN1_STRING` it really is.

## What would change my mind

If `ASN1_STRING_type_new` grew a `holds_string` check, this whole class closes
at the source. Until then, any *new* wrapper that switches on a string's `type`
field re-opens it, and the sweep above should be re-run.
