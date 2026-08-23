# Cleared: the shapes this kind of wrapper usually gets wrong

A roundup of the classic C-wrapper soundness shapes, each checked against this
crate and each **cleared**, with the reason. A future run should not re-derive
these; the "what would change my mind" line on each says when to look again.

## 1. Aliasing (`&mut T` and `&T` to one object)

Structurally excluded, not merely avoided. `ffibox`'s central rule is that no
Rust reference to a wrapped C object is ever formed: `CType<T>` is only ever
reached through `CPtr`-carrying handles that hold the pointer *by value*, and
every field access goes through `addr_of!`/`addr_of_mut!` raw-place
projections. `&FooRef` covers the handle (one pointer of Rust stack), never the
C object, so it carries no `noalias`/`readonly` claim about C memory.

Grep confirms the crate holds the line: **zero** `transmute`, **zero**
`transmute_copy`, **zero** `impl Deref`/`DerefMut` in the whole workspace.
Nothing to launder a `&mut` through.

*What would change my mind:* a wrapper that returns `&T`/`&mut T` to C storage
rather than a handle. The two that come close both hand out `&CStr` over
`static const` C strings (`Asn1ItemRef::structure_name`,
`Asn1TemplateRef::field_name`) and one hands out `&[u8]` over a Rust-owned
`CVec` (`Asn1Utf8::as_bytes`) — all fine.

## 2. Lending iterators

Not applicable: the workspace has **zero** `impl Iterator` and **zero**
`type Item`. Sequence access is `CSlice::get`/`iter` (shared, `Copy`, so `'a` is
sound) and `CSliceMut::get_mut`/`iter_mut`, which are deliberately bound by
`&mut self` rather than `'a` — `ffibox/src/borrowed_refs.rs` documents exactly
why. No `collect()` can produce two `Mut` handles to one element.

## 3. Unvalidated integer -> enum conversion

Every C-integer-to-Rust-enum conversion I found is total, with an explicit
catch-all arm rather than a transmute:
`Asn1ItemKind::from_raw` -> `Unknown(c_char)`,
`Asn1TypeKind::from_raw` -> `Unknown(c_int)`,
`BioPollDescriptorType::from_raw` -> `Option`,
`BioSockInfoType::from_raw` -> `Option`,
`BioPollCustomType::new` -> `Option` (rejects OpenSSL's reserved range).
None of them is `unsafe`, none of them can produce an invalid discriminant.

Union arms are read under their discriminant and the pointer arms are never
dereferenced by the safe view — `BioPollCustomValue` deliberately exposes the
shared pointer/integer bits as a `usize` and says so.

*Note the exception that did bite:* `ASN1_STRING`'s `type` field is not an enum
conversion at all, and `ASN1_STRING_type_new` takes it unvalidated. That is
[a confirmed advisory](../advisories/asn1-string-print-ex-object-type-confusion.md),
and it is the counterexample to how well this category is otherwise handled.

## 4. Lifetimes decoupled from the borrow they came from

The dangerous pattern is a getter returning `T::Ref<'a>`/`T::Mut<'a>` where
`'a` is the *handle's* parameter rather than `&self`. The crate uses it in
several places and each time it is on the **shared** side, where it is sound
because the handle is `Copy` and grants no writes: `CSlice::get`,
`BioMsgRef::data`, `CryptoExDataRef::sk`, `Asn1ItemRef::templates`,
`Asn1TypeRef::value`, `BioPollDescriptorRef::value`.

Every exclusive counterpart is bound to `&mut self` instead: `data_mut`,
`peer_mut`, `local_mut`, `sk_mut`, `CSliceMut::get_mut`, `as_ref` on every
`Mut` handle. The three that return `'buf`-lifetime `Mut` handles
(`BioMsgMut::set_data`/`set_peer`/`set_local`) are *takes* — they null the
field in the same operation, so the descriptor stops aliasing what it hands
back.

## 5. `Deref`/`DerefMut` exposing an inner value to `mem::swap`/`replace`

Not applicable — no `Deref` impls at all. `ffibox` documents the deliberate
choice: `Deref::Target` cannot name a lifetime taken from `&self`, so the
handles use explicit `as_ref()`/`as_mut()` instead.

## 6. `Send`/`Sync` over thread-affine C state

There are **no** `unsafe impl Send` and **no** `unsafe impl Sync` for any
wrapper type. All 40 `unsafe impl`s in the workspace are `ffibox` lifecycle
traits (`CCell`, `CDropped`, `CCloned`, `CDropper`, `CCloner`, `CValued`,
`CLenDropped`, `CLenCloned`). The one `unsafe impl Sync` in the tree is on a
test-local `StaticItem` fixture inside `#[cfg(test)]`.

Consequence worth recording: the handles are therefore `!Send`/`!Sync` by
default, which is why the process-global registries (`OBJ_*`, the ASN.1 string
table) cannot be raced from safe Rust across threads through this API — the
crate's own tests serialise them with a `Mutex` where a test needs to.

## 7. `zeroed()` values reaching C

`define_ctype!` emits a **safe** `Foo::zeroed()`. That looked like a way to
hand C a bogus object — most sharply for `OsslLibCtx`, whose bindgen type is
zero-sized (opaque), so `zeroed()` is a ZST whose address points at nothing.

Cleared: a *value* is not a *handle*. Reaching C requires either
`Foo::from_ptr` (`unsafe`) or `CVal`, and `CVal<T>` is bounded on
`T: CValued` — which only `BioMsg`, `BioSockInfo` and `BioPollDescriptor`
implement, all of them caller-allocated by design and all with sound safe
constructors. `OsslLibCtx`, `CryptoExData`, `ObjName`, `Asn1Item`,
`Asn1Template` and `IoFile` implement `CDropped`/nothing, so `CVal` does not
typecheck and their `zeroed()` values are inert.

*What would change my mind:* a `CValued` impl added to a type whose all-zero
state is not something C accepts, or a safe constructor that adopts a `zeroed()`
value into a handle.

## 8. Two `Mut` handles from `BIO_find_type`

Cleared, but not for the reason I first thought. Safe code **can** end up
holding a multi-node chain — `BIO_read` on an accept BIO makes `acpt_state`
`BIO_push` the accepted socket behind it — so `BIO_find_type` really does hand
back an exclusive handle to an object other than the one borrowed. I confirmed
that empirically.

It is still sound: the returned `BioMut<'a>` holds the *head's* handle mutably
borrowed for `'a`, and every other route to the tail (`BIO_next`, a second
`BIO_find_type`, `as_ref`) needs a conflicting borrow of that same head. I could
not construct two simultaneous handles to one node. Details, and the
descriptor-ownership bug that the same chain *does* expose, are in
[`no-safe-bio-chain.md`](no-safe-bio-chain.md).
