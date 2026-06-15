# librsi ABI snapshot & header verification

The **hand-written `include/rsi/*.h` headers are the shipping API** — they carry the
prose docs. cbindgen is used here not to *generate* that API but to **verify** it:
to prove, mechanically, that those headers never drift from the Rust
`#[no_mangle] extern "C"` surface they describe. This mirrors libpeios's setup.

## Files

- **`rsi-abi.h`** — the ABI *snapshot*: a doc-stripped C header generated from the
  Rust source by cbindgen, the machine-checked source of truth for the ABI. Checked
  in so regenerating + diffing reveals any Rust-side ABI change. **Not** part of the
  installed API — include `<rsi.h>` (or the individual `<rsi/*.h>`), not this.
- **`../cbindgen.toml`** — the generator config.
- **`../tools/verify-abi.sh`** — the verification gate (5 checks).

## Regenerating

cbindgen 0.29.2 (via nix; not on the default PATH):

```sh
cd librsi
nix-shell -p rust-cbindgen --run 'cbindgen --config cbindgen.toml --lang c -o abi/rsi-abi.h .'
```

## Verifying

The script needs `cbindgen` on PATH; run it under nix:

```sh
cd librsi
nix-shell -p rust-cbindgen --run ./tools/verify-abi.sh
```

It (1) regenerates + diffs the snapshot (Rust-drift gate), (2) compiles the snapshot
standalone C/C++, (3) compares every function signature via `gcc -aux-info`, (4)
compares every struct's `sizeof`+`_Alignof`, (5) compares data symbols. Steps 3–5
ignore ABI-irrelevant spellings (param/field names, `struct`/`enum` tags,
`ptrdiff_t`≡`ssize_t`, `uintptr_t`≡`size_t`, enum≡int). See libpeios's `abi/README.md`
for the rationale and the residual same-size-reorder caveat.

## Workflow when the ABI changes

1. Change the Rust `extern "C"` surface.
2. Regenerate `rsi-abi.h` and commit it (the diff shows exactly what moved).
3. Update the matching hand-written `<rsi/*.h>` declaration(s).
4. Run `./tools/verify-abi.sh` — green means header and Rust agree again.
