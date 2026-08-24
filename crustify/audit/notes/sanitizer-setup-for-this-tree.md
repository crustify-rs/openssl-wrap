# Reference: how to get a working instrument on this tree

This cost a meaningful slice of one run's budget. It should cost the next run
nothing.

## What already exists

`/work/openssl/libcrypto.a` is prebuilt from
`./Configure no-deprecated enable-ubsan --strict-warnings` (see
`crustify/build.json`), and `libcrypto-sys/build.rs` links it plus `-lubsan`.
So **UBSan is free** — just `cargo build` a crate that depends on `libcrypto`
and run it. OpenSSL's `enable-ubsan` implies `-fno-sanitize-recover`, so the
process dies on the first diagnostic; `UBSAN_OPTIONS=print_stacktrace=1` gives
symbolized C frames *and* demangled Rust frames.

Two of the four advisories in this directory were found this way.

## What UBSan cannot see

Heap bounds. The `ASN1_STRING`/`ASN1_OBJECT` type-confusion advisory is an
8-byte out-of-bounds **read**; against the tree's own build the program prints
`-1` and exits 0. If you only run UBSan you will not find that class at all.

## Adding AddressSanitizer

**Do not** try to LD_PRELOAD gcc's `libasan.so` over a gcc-instrumented
`libcrypto.a`. I tried; it "works" but segfaults inside the ASan runtime on
roughly 25% of runs at random, independent of what the program does (I measured
6-9 failures out of 30 on every probe including trivial ones, and 30/30 with
ASLR disabled). Every one of those is a false positive and it will waste your
time.

The setup that is stable — 0/10 spurious failures, and it instruments the Rust
side as well:

```sh
# 1. clang-built ASan libcrypto, out of tree so the audited repo is untouched
git clone --depth 1 --no-local /work/openssl /tmp/osrc-clang
cd /tmp/osrc-clang
CC=clang perl ./Configure linux-x86_64-clang no-deprecated enable-asan
make -j64 build_libs          # ~3 minutes on this box

# 2. point the probe crate at it and use rustc's own sanitizer
cat > .cargo/config.toml <<'CFG'
[target.x86_64-unknown-linux-gnu]
rustflags = ["-L","native=/tmp/osrc-clang","-Zsanitizer=address"]
CFG
CARGO_TARGET_DIR=target-asan rustup run nightly cargo build --target x86_64-unknown-linux-gnu
./target-asan/x86_64-unknown-linux-gnu/debug/<bin>
```

`-L native=/tmp/osrc-clang` lands *before* the `-L /work/openssl` that
`build.rs` emits, so the ASan `libcrypto.a` wins. Both sides are LLVM, so
rustc's runtime and clang-19's instrumentation agree.

Two gotchas:

- **Pass `--target x86_64-unknown-linux-gnu`.** Without it, `RUSTFLAGS` /
  `[target.*].rustflags` also apply to host build scripts and `libc-sys`'s
  build script fails. With it, they apply to target artifacts only.
- **`.cargo/config.toml` breaks plain `cargo build`** (stable rustc rejects
  `-Zsanitizer`). Keep it as `.cargo/config.toml.asan` and copy it in when you
  want ASan; that is how the reproduction directories here are arranged.

## Symbolizing ASan output

There is no `llvm-symbolizer` on this image, so ASan prints bare addresses.
`/usr/bin/addr2line` resolves them fine against the binary:

```sh
addr2line -f -C -e ./target-asan/x86_64-unknown-linux-gnu/debug/<bin> 0x4cbcb2
```

`crustify/audit/tmp/` has a short python filter that rewrites a whole ASan
report; the symbolized traces quoted in the advisories were produced with it.

## Running the crate's own test suite under ASan

Works, and all 225 tests pass (no leaks reported):

```sh
cd /work/openssl/crustify/rust
RUSTFLAGS="-L native=/tmp/osrc-clang -Zsanitizer=address" \
CARGO_TARGET_DIR=/tmp/asan-target ASAN_OPTIONS=detect_leaks=1 \
rustup run nightly cargo test --target x86_64-unknown-linux-gnu -p libcrypto
```

Useful as a regression gate, but it found nothing: the tests are written to use
the API correctly, and soundness bugs live in the *incorrect* uses that the type
system still permits. The adversarial sweeps in `tmp/probe/src/bin/` are where
the findings came from.

## Miri

Not usable here, as expected: it stops at every `extern "C"` call and this crate
is nothing but `extern "C"` calls. I did not attempt it.

## Doctests do not survive the ASan setup (added by a later run)

`cargo test -p libcrypto` now has doctests, and the ASan recipe above breaks
them:

```
rust-lld: error: undefined symbol: __asan_memset
  >>> referenced by a_bitstr.c:152 ... in liblibcrypto_sys-....rlib
```

`rustdoc` does not forward `-Zsanitizer=address` to the binary it builds for a
doctest, so that binary has no ASan runtime while the `libcrypto.a` it links
does. `compile_fail` doctests still "pass" (they only have to fail to compile);
an ordinary one fails to link.

Use `--lib` when running the suite under ASan:

```sh
RUSTFLAGS="-L native=/tmp/osrc-clang -Zsanitizer=address" \
CARGO_TARGET_DIR=/tmp/asan-target ASAN_OPTIONS=detect_leaks=1 \
rustup run nightly cargo test --target x86_64-unknown-linux-gnu -p libcrypto --lib
```

and run the doctests separately against the tree's own UBSan build with plain
`cargo test`.
