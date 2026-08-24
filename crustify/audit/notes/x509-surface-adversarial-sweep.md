# Reference: the adversarial sweep over the x509 / stack surface, and what it cleared

The `x509/` (26 modules, ~9 600 lines) and `stack/` (4 modules, ~1 700 lines)
subtrees are new since the previous audit run — `crustify/audit/README.md` as
it stood covered only `asn1/`, `bio/` and `objects/`. This note records the
sweep I ran over them, the two things it found, and the much longer list it
cleared, so the next run can spend its budget elsewhere.

Harness: `crustify/audit/tmp/x509-probe/`. `#![forbid(unsafe_code)]`, ten
sections, each run as a child process so one crash does not hide the rest.
Instruments: the tree's own UBSan build (free, see
[`sanitizer-setup-for-this-tree.md`](sanitizer-setup-for-this-tree.md)) and the
clang/ASan build in `/tmp/osrc-clang`.

Input corpus: `tmp/x509-probe/corpus/cert.der`, a certificate generated with
`corpus/ext.cnf` carrying all six extension syntaxes the crate decodes
(`subjectAltName` with nine `GENERAL_NAME` arms including `otherName`,
`dirName`, `RID` and both IP families; `basicConstraints`;
`extendedKeyUsage`; `authorityInfoAccess`; `crlDistributionPoints` with a full
name, reasons and a CRL issuer; `certificatePolicies` with a CPS URI and a
user notice with notice numbers), plus `nameConstraints`, both key
identifiers and `tlsfeature`.

## Found

1. **`GENERAL_NAME_cmp` on two `GEN_OTHERNAME` choices with an unset
   `ASN1_TYPE`** — null dereference in `ASN1_STRING_cmp`. Section
   `general-names`, variant pair (10, 10). Confirmed:
   [`advisories/general-name-cmp-unset-asn1-type-null-deref.md`](../advisories/general-name-cmp-unset-asn1-type-null-deref.md).

2. Not from this sweep but from reading the same surface: the reference-count
   aliasing hole,
   [`advisories/x509-up-ref-aliased-borrow-use-after-free.md`](../advisories/x509-up-ref-aliased-borrow-use-after-free.md),
   led by [`refcounted-share-grants-exclusive-access.md`](refcounted-share-grants-exclusive-access.md).

## Cleared

With the one pair above skipped, **all ten sections run clean under both
instruments** (UBSan: `0 failing section(s)`; ASan with `detect_leaks=0`:
`0 failing section(s)`).

| section | what it exercises |
|---|---|
| `decoded-getters` | every safe getter on a decoded certificate, all 6 `X509V3ExtensionKind`s through both `X509_get_ext_d2i` and `X509V3_get_d2i`, extension enumeration by index/NID/OID/criticality, `i2d_X509`, `i2d_re_X509_tbs`, all four comparators |
| `mutated-der` | 4 000 certificates with 1–4 random byte mutations, each pushed through the whole getter set; then 4 000 single-byte mutations fed to `d2i_X509_NAME`, `d2i_X509_NAME_ENTRY`, `d2i_X509_EXTENSION`, `d2i_X509_PUBKEY` and truncated `d2i_X509` |
| `name-text` | `X509_NAME_get_text_by_NID`/`_by_OBJ` at buffer sizes 0,1,2,3,5,8,64,128 and with `None`; entry enumeration past the end; `X509_NAME_get0_der` and `i2d_X509_NAME` on an empty name; `i2d_X509_NAME_ENTRY` on an unfilled entry |
| `stack-ops` | every safe `OPENSSL_sk_*` operation on the six decoded, genuinely non-empty stacks: `value` past the end, `dup`, `reserve(1024)`, `sort`, `delete(0)`, `delete(usize::MAX)`, `pop`, `shift`, `zero`, then `sort` again |
| `records` | set/take/borrow cycles on `ACCESS_DESCRIPTION`, `GENERAL_SUBTREE`, `NAME_CONSTRAINTS`, `AUTHORITY_KEYID`, `BASIC_CONSTRAINTS`, `NOTICEREF`, `USERNOTICE`, `EDIPARTYNAME`, `OTHERNAME`, `POLICYINFO` |
| `general-names` | 15 x 15 `GeneralNameValue` variants through `from_value` + `GENERAL_NAME_cmp` + `GENERAL_NAME_dup` + `get0_value` + `get0_otherName`, then a take/set churn over all 15 on one choice |
| `policy-qualifiers` | `PolicyQualInfo` set/take/kind cycles across `CpsUri`, `UserNotice`, `Other{qualifier_id}` and `Empty`, including the reserved-selector rejection |
| `dist-point` | `DIST_POINT_NAME` arm juggling (`try_set_full_name`/`try_set_relative_name`/`take_*`), the `dpname` cache left populated while the active arm changes, `try_clone`; `DIST_POINT` reasons at `0/1/-1/i32::MAX/i32::MIN` |
| `pubkey` | `X509_PUBKEY_get0_param` byte view, `i2d`/`d2i` round trip, `X509_PUBKEY_eq`, `X509_PUBKEY_dup`, `X509_PUBKEY_get` |
| `checks` | `X509_check_host`/`_email` over 9 adversarial identities (embedded NUL, trailing NUL, non-UTF-8, 4 KiB) x 9 flag words including `u32::MAX`; `X509_check_ip` for both lengths; `X509_check_ip_asc` including the empty string |

Two things that make the cleared list smaller than it looks, and are worth
knowing before designing the next sweep:

- **`StackElement<T>` is opaque and has no safe consumer.** `OPENSSL_sk_value`
  hands back a token that cannot be turned into a `Ref` without `unsafe`, so
  the *contents* of a decoded `GENERAL_NAMES` / `CERTIFICATEPOLICIES` /
  `CRL_DIST_POINTS` are unreachable from safe code. `stack-ops` can only push
  on the container. The previous run's
  [`safe-api-reachability.md`](safe-api-reachability.md) said "stacks are
  always empty"; that is no longer true — the decoders build full ones — but
  the elements are still out of reach.
- **`x509v3::GeneralNames` has no safe constructor.** `x509v3.rs:938` and
  `v3_genn.rs:19` each define a `GeneralNamesFree` ZST with identical bodies
  (`GENERAL_NAMES_free`), so `v3_genn::GENERAL_NAMES_new()` returns a
  `CBoxWith<_, v3_genn::GeneralNamesFree>` while `AuthorityKeyIdMut::set_issuer`,
  `DistPointMut::set_crl_issuer` and `DistPointNameMut::try_set_full_name` all
  want `CBoxWith<_, x509v3::GeneralNamesFree>`. There is no safe conversion and
  no other producer, so those three setters can only ever be called with
  `None`, and `X509V3_get_d2i`'s decoded `GeneralNames` (the `v3_genn` flavour)
  cannot be installed into a record. Same story for `RelativeNameEntries`.
  This is an API-completeness defect, not a soundness one — but it is the
  reason `dist-point` and `records` could not test a populated arm.

## What would change my mind

Either gap closing. A safe `StackElement -> T::Ref` conversion reopens the
whole element surface; a safe `x509v3::GeneralNames` producer reopens
`DIST_POINT_NAME`'s arm/`dpname`-cache interaction, which the module's own
doc comment already flags as a hazard the caller owns ("Nothing recomputes
that cache when the active arm changes, exactly as in C").
