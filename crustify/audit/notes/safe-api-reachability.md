# Reference: which parts of the safe API are actually reachable from safe code

Roughly a third of the safe `pub fn` surface cannot be called at all without
`unsafe`, because some argument type has no safe constructor. Knowing which is
which halves the search space, so it is worth writing down. This is what I
worked out while looking for a callable path to the
[mmsg callback hole](mmsg-callback-getters-unreachable.md).

## Argument types with no safe producer in this workspace

| type | needed by | why unreachable |
|---|---|---|
| `CSliceMut<'_, BioMsg<'_>>` | `BIO_recvmmsg`, `BIO_sendmmsg`, `BioMethodMmsgCallback::call` | only `CSliceMut::from_raw_parts` (unsafe) or `CVec::as_handles_mut`, and `CVec::from_raw_parts` is unsafe |
| `StackElement<T>` | `OPENSSL_sk_push`/`insert`/`set`/`find*` (all already `unsafe`) | safe code cannot get an element *into* a stack, so `sk_value`/`pop`/`shift` on a safely-built stack always return `None` |
| `OpenSslSkCompFunc`, `OpenSslSkStackCompFunc`, `OpenSslSkCopyFunc`, `OpenSslSkFreeFunc`, and the three thunk types | `OBJ_bsearch_`, `OPENSSL_sk_new`, `OPENSSL_sk_deep_copy`, `OPENSSL_sk_set_cmp_func`, `OPENSSL_sk_set_*_thunks` | `from_raw` only |
| `IoFileMut<'_>` | `BIO_new_fp`, `BIO_dump_fp`, `BIO_dump_indent_fp`, `ASN1_STRING_print_ex_fp` | the `libc` crate models a stream as borrowed-only; `IoFileRef/Mut::from_ptr` are unsafe and there is no safe `fopen` |
| `OsslLibCtxRef<'_>` | `BIO_new_ex`'s context argument, `BIO_new_from_core_bio` | no safe constructor at all, deliberately (see `bio/context.rs`) |
| `CryptoExDataRef/Mut` | `ctx`, `sk`, `sk_mut`, `take_sk`, `set_sk`, `set_ctx` | `CryptoExData` implements `CDropped`-nothing, so no `CVal`; handles need `from_ptr` |
| `LHashRef/Mut<'_, T>` | every `LHash` accessor | same |
| `ObjNameRef/Mut<'_>` | `OBJ_NAME` field accessors | only produced by the `OBJ_NAME_do_all` traversal, which is `unsafe fn` |
| `AddrInfoRef<'_>`, `BioAddrInfo` | the `BIO_ADDRINFO_*` family | `BIO_lookup_ex` is not wrapped |
| `Asn1TypeStringRef<'_>` | `Asn1TypeMut::try_set_string` | only produced by `Asn1TypeRef::value` on a type that *already* holds a string arm, and no safe setter creates one — `set_null`/`set_boolean`/`set_object_owned`/`try_set_object` cover only the non-string tags. Circular, so dead. |
| `CVec<u8, CryptoClearFree>` | `ASN1_STRING_set0` | `ASN1_STRING_to_UTF8` yields `CVec<u8, CryptoFree>` — a different strategy — and `CVec::from_raw_parts` is unsafe |
| `BioInfoCallback` | `BIO_callback_ctrl(.., Some(..))`, `BioMethodCallbackCtrl::call` | `from_raw` only; no safe getter |
| `Asn1PsSetupFunc`, `Asn1PsCleanupFunc` | `BIO_asn1_set_prefix`/`set_suffix` | `from_raw` only. (`BIO_asn1_get_prefix`/`get_suffix` *are* safe getters, but their `call` methods are `unsafe fn`, so the round-trip is not a hole.) |

## Consequences worth remembering

- **The whole multi-message BIO surface is dead code from safe Rust.** That is
  the only thing preventing the `BIO_meth_get_sendmmsg` type confusion.
- **Stacks are always empty.** `OPENSSL_sk_*` cannot be made to hold an element
  without `unsafe`, so the comparator/copy/free callback machinery — the most
  dangerous-looking part of `stack/` — is unreachable. `OPENSSL_sk_sort` on an
  empty stack never calls a comparator.
- **`ASN1_TYPE` can never hold a string arm from safe code**, which is why
  `try_set_string` is dead and why the `V_ASN1_ANY` nesting hazard the module
  documents is not reachable.
- **Anything taking a `FILE *` is dead**, which is why the `_fp` variants of the
  printing functions could not be tested (noted as unchecked in the
  corresponding advisory).

## The other direction: reachable *without any handle at all*

Worth naming separately, because it is what produced the most severe finding of
the run. A handful of safe wrappers take only scalars or `&CStr` and touch
process-global C state — `ASN1_STRING_TABLE_add`/`_get`, the `OBJ_*` registry
functions, `OBJ_NAME_*`. Since they carry no handle, none of the `!Send`
reasoning that protects the rest of the API applies to them, and safe code can
call them from any number of threads. See
[`global-registry-thread-safety.md`](global-registry-thread-safety.md).

## What would change my mind

Any of these becoming constructible — a safe `CVec` factory, a wrapped
`BIO_lookup_ex`, a safe `fopen` in the `libc` crate, a safe `Asn1TypeMut`
string setter — reopens a chunk of surface that has never been exercised. The
mmsg row in particular is one constructor away from a demonstrable
heap-buffer-overflow, with the reduction already written down.
