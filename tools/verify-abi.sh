#!/usr/bin/env bash
#
# verify-abi.sh — prove the hand-written <rsi/*.h> headers match the Rust C ABI.
#
# The hand-written headers are the shipping API (they carry the prose docs); this
# script uses cbindgen as a drift gate. It:
#
#   1. regenerates the ABI snapshot from the Rust source and checks it is identical
#      to the committed abi/rsi-abi.h;
#   2. compiles the snapshot standalone in C and C++;
#   3. compares every public *function signature* between the hand-written headers
#      and the snapshot, using `gcc -aux-info`;
#   4. compares every public *struct* on size and alignment;
#   5. compares the *data symbols* (if any).
#
# Steps 3-5 ignore only ABI-irrelevant spellings: parameter/field names, struct/enum
# tags, `ptrdiff_t`≡`ssize_t` / `uintptr_t`≡`size_t`, and `enum`≡`int`.
#
# cbindgen must be on PATH; in this environment that means running the script under
# nix:  nix-shell -p rust-cbindgen --run ./tools/verify-abi.sh
# Exit status is non-zero on any mismatch.

set -euo pipefail
cd "$(dirname "$0")/.."  # librsi crate root

SNAPSHOT=abi/rsi-abi.h
INC=(-I include -I ../pkm/uapi)
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

run_cbindgen() {  # $1 = output path
  command -v cbindgen >/dev/null 2>&1 \
    || fail "cbindgen not on PATH — run this under nix, e.g. \`nix-shell -p rust-cbindgen --run ./tools/verify-abi.sh\`"
  cbindgen --config cbindgen.toml --lang c -o "$1" . 2>/dev/null
}

norm_fns() {
  grep -hE 'rsi_[a-z_]+ *\(' "$1" \
    | sed -E 's#^/\*[^*]*\*/ ##; s/^extern //;
              s/\bstruct //g; s/\benum [A-Za-z_][A-Za-z0-9_]*/int/g;
              s/\bptrdiff_t\b/ssize_t/g; s/\buintptr_t\b/size_t/g;
              s/ +/ /g; s/ ;$/;/; s/ $//' \
    | sort -u
}

fail() { echo "FAIL: $*" >&2; exit 1; }

# --- 1. snapshot is up to date with the Rust source ------------------------------
run_cbindgen "$TMP/gen.h"
diff -u "$SNAPSHOT" "$TMP/gen.h" \
  || fail "$SNAPSHOT is stale — the Rust ABI changed. Regenerate it (see abi/README.md)."
echo "ok 1/5: snapshot is up to date with the Rust source"

# --- 2. snapshot compiles standalone ---------------------------------------------
gcc "${INC[@]}" -fsyntax-only -xc   "$SNAPSHOT" || fail "snapshot does not compile as C"
g++ "${INC[@]}" -fsyntax-only -xc++ "$SNAPSHOT" || fail "snapshot does not compile as C++"
echo "ok 2/5: snapshot compiles standalone (C and C++)"

# Hand-written TU = the umbrella header (also checks the umbrella is complete).
printf '#include <rsi.h>\n'                   > "$TMP/hand.c"
printf '#include "%s/%s"\n' "$PWD" "$SNAPSHOT" > "$TMP/snap.c"

# --- 3. function signatures ------------------------------------------------------
gcc "${INC[@]}" -aux-info "$TMP/hand.aux" -c -o /dev/null "$TMP/hand.c"
gcc "${INC[@]}" -aux-info "$TMP/snap.aux" -c -o /dev/null "$TMP/snap.c"
norm_fns "$TMP/hand.aux" > "$TMP/hand.fns"
norm_fns "$TMP/snap.aux" > "$TMP/snap.fns"
diff "$TMP/hand.fns" "$TMP/snap.fns" \
  || fail "function signature mismatch ('<' hand-written, '>' Rust snapshot)"
echo "ok 3/5: $(wc -l < "$TMP/hand.fns") function signature(s) match the Rust ABI"

# --- 4. struct size + alignment --------------------------------------------------
mapfile -t STRUCTS < <(grep -oE '^struct rsi_[a-z_]+ \{' "$SNAPSHOT" \
                       | sed -E 's/^struct //; s/ \{//' | sort -u)
{
  printf '#include <stdio.h>\n#include <stddef.h>\n'
  printf 'HEADERS\nint main(void){\n'
  for s in "${STRUCTS[@]}"; do
    printf '  printf("%s %%zu %%zu\\n", sizeof(struct %s), _Alignof(struct %s));\n' "$s" "$s" "$s"
  done
  printf '  return 0;\n}\n'
} > "$TMP/size.tmpl"
sed 's#^HEADERS$#\#include <rsi.h>#'             "$TMP/size.tmpl" > "$TMP/size_hand.c"
sed "s#^HEADERS\$#\#include \"$PWD/$SNAPSHOT\"#"  "$TMP/size.tmpl" > "$TMP/size_snap.c"
gcc "${INC[@]}" -o "$TMP/size_hand" "$TMP/size_hand.c"
gcc "${INC[@]}" -o "$TMP/size_snap" "$TMP/size_snap.c"
"$TMP/size_hand" | sort > "$TMP/size_hand.txt"
"$TMP/size_snap" | sort > "$TMP/size_snap.txt"
diff "$TMP/size_hand.txt" "$TMP/size_snap.txt" \
  || fail "struct size/alignment mismatch ('<' hand-written, '>' Rust snapshot)"
echo "ok 4/5: ${#STRUCTS[@]} struct layout(s) match (size + alignment)"

# --- 5. data symbols (grep may legitimately match nothing) -----------------------
{ grep -hoE 'extern [^;]*rsi_[a-z_]+ *;' include/rsi/*.h 2>/dev/null || true; } \
  | sed -E 's/ +/ /g' | sort -u > "$TMP/hand.data"
{ grep -hoE 'extern [^;]*rsi_[a-z_]+ *;' "$SNAPSHOT" || true; } \
  | sed -E 's/ +/ /g' | sort -u > "$TMP/snap.data"
diff "$TMP/hand.data" "$TMP/snap.data" \
  || fail "data-symbol mismatch ('<' hand-written, '>' Rust snapshot)"
echo "ok 5/5: $(wc -l < "$TMP/hand.data") data symbol(s) match"

echo
echo "ABI VERIFIED: the hand-written <rsi/*.h> headers are ABI-identical to the Rust source."
