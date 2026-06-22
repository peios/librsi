#!/usr/bin/env bash
#
# verify-abi.sh — prove the hand-written <rsi/*.h> headers match the Rust C ABI.
#
# The hand-written headers are the shipping API (they carry the prose docs); this
# script uses cbindgen as a drift gate. It:
#
#   1. regenerates the ABI snapshot from the Rust source and checks it is identical
#      to the committed abi/rsi-abi.h;
#   2. compiles the snapshot and hand-written headers standalone in C and C++;
#   3. compares every public *function signature* between the hand-written headers
#      and the snapshot, using `gcc -aux-info`;
#   4. compares every public *struct* on name set, field-name set, size, alignment,
#      field offsets, and field sizes;
#   5. compares the *data symbols* (if any);
#   6. builds the release shared object and checks it has no unresolved dynamic
#      symbols and exports exactly the header-declared `rsi_*` ABI symbols.
#
# Steps 3-5 ignore only ABI-irrelevant spellings: parameter names, struct/enum tags,
# `ptrdiff_t`≡`ssize_t` / `uintptr_t`≡`size_t`, and `enum`≡`int`.
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
  local err="$TMP/cbindgen.err"
  if ! cbindgen --config cbindgen.toml --lang c -o "$1" . 2>"$err"; then
    cat "$err" >&2
    fail "cbindgen failed while generating the ABI snapshot"
  fi
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

extract_structs() {
  grep -hoE '^struct rsi_[a-z_]+ \{' "$@" \
    | sed -E 's/^struct //; s/ \{//' \
    | sort -u
}

extract_fields() {
  awk '
    /^struct rsi_[a-z_]+ \{/ { s = $2; next }
    s && /^};/ { s = ""; next }
    s && /^[[:space:]]+[A-Za-z_]/ {
      line = $0
      sub(/;.*/, "", line)
      gsub(/\[[^]]+\]/, "", line)
      gsub(/\*/, " ", line)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
      n = split(line, parts, /[[:space:]]+/)
      if (n > 0) print s "." parts[n]
    }
  ' "$@" | sort -u
}

# --- 1. snapshot is up to date with the Rust source ------------------------------
run_cbindgen "$TMP/gen.h"
diff -u "$SNAPSHOT" "$TMP/gen.h" \
  || fail "$SNAPSHOT is stale — the Rust ABI changed. Regenerate it (see abi/README.md)."
echo "ok 1/6: snapshot is up to date with the Rust source"

printf '#include <rsi.h>\n'                    > "$TMP/hand.c"
printf '#include "%s/%s"\n' "$PWD" "$SNAPSHOT" > "$TMP/snap.c"

# --- 2. snapshot compiles standalone ---------------------------------------------
gcc "${INC[@]}" -fsyntax-only -xc   "$SNAPSHOT" || fail "snapshot does not compile as C"
g++ "${INC[@]}" -fsyntax-only -xc++ "$SNAPSHOT" || fail "snapshot does not compile as C++"
gcc "${INC[@]}" -fsyntax-only -xc   "$TMP/hand.c" || fail "hand-written headers do not compile as C"
g++ "${INC[@]}" -fsyntax-only -xc++ "$TMP/hand.c" || fail "hand-written headers do not compile as C++"
echo "ok 2/6: snapshot and hand-written headers compile standalone (C and C++)"

# --- 3. function signatures ------------------------------------------------------
gcc "${INC[@]}" -aux-info "$TMP/hand.aux" -c -o /dev/null "$TMP/hand.c"
gcc "${INC[@]}" -aux-info "$TMP/snap.aux" -c -o /dev/null "$TMP/snap.c"
norm_fns "$TMP/hand.aux" > "$TMP/hand.fns"
norm_fns "$TMP/snap.aux" > "$TMP/snap.fns"
diff "$TMP/hand.fns" "$TMP/snap.fns" \
  || fail "function signature mismatch ('<' hand-written, '>' Rust snapshot)"
echo "ok 3/6: $(wc -l < "$TMP/hand.fns") function signature(s) match the Rust ABI"

# --- 4. struct size, alignment, and field layout ----------------------------------
extract_structs include/rsi/*.h > "$TMP/hand.structs"
extract_structs "$SNAPSHOT" > "$TMP/snap.structs"
diff "$TMP/hand.structs" "$TMP/snap.structs" \
  || fail "struct declaration mismatch ('<' hand-written, '>' Rust snapshot)"
mapfile -t STRUCTS < "$TMP/snap.structs"
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

extract_fields include/rsi/*.h > "$TMP/hand.fields"
extract_fields "$SNAPSHOT" > "$TMP/snap.fields"
diff "$TMP/hand.fields" "$TMP/snap.fields" \
  || fail "struct field-name mismatch ('<' hand-written, '>' Rust snapshot)"
sed 's/\./ /' "$TMP/snap.fields" > "$TMP/fields.txt"
{
  printf '#include <stdio.h>\n#include <stddef.h>\n'
  printf 'HEADERS\nint main(void){\n'
  while read -r s f; do
    printf '  printf("%s.%s %%zu %%zu\\n", offsetof(struct %s, %s), sizeof(((struct %s *)0)->%s));\n' "$s" "$f" "$s" "$f" "$s" "$f"
  done < "$TMP/fields.txt"
  printf '  return 0;\n}\n'
} > "$TMP/fields.tmpl"
sed 's#^HEADERS$#\#include <rsi.h>#'                "$TMP/fields.tmpl" > "$TMP/fields_hand.c"
sed "s#^HEADERS\$#\#include \"$PWD/$SNAPSHOT\"#"     "$TMP/fields.tmpl" > "$TMP/fields_snap.c"
gcc "${INC[@]}" -o "$TMP/fields_hand" "$TMP/fields_hand.c"
gcc "${INC[@]}" -o "$TMP/fields_snap" "$TMP/fields_snap.c"
"$TMP/fields_hand" | sort > "$TMP/fields_hand.txt"
"$TMP/fields_snap" | sort > "$TMP/fields_snap.txt"
diff "$TMP/fields_hand.txt" "$TMP/fields_snap.txt" \
  || fail "struct field offset/size mismatch ('<' hand-written, '>' Rust snapshot)"
echo "ok 4/6: ${#STRUCTS[@]} struct layout(s) match (names + size + alignment + field offsets/sizes)"

# --- 5. data symbols (grep may legitimately match nothing) -----------------------
{ grep -hoE 'extern [^;]*rsi_[a-z_]+ *;' include/rsi/*.h 2>/dev/null || true; } \
  | sed -E 's/ +/ /g' | sort -u > "$TMP/hand.data"
{ grep -hoE 'extern [^;]*rsi_[a-z_]+ *;' "$SNAPSHOT" || true; } \
  | sed -E 's/ +/ /g' | sort -u > "$TMP/snap.data"
diff "$TMP/hand.data" "$TMP/snap.data" \
  || fail "data-symbol mismatch ('<' hand-written, '>' Rust snapshot)"
echo "ok 5/6: $(wc -l < "$TMP/hand.data") data symbol(s) match"

# --- 6. shared object is dynamically loadable -------------------------------------
cargo build --release >/dev/null
ldd -r target/release/librsi.so > "$TMP/ldd-r.txt" 2>&1 \
  || { cat "$TMP/ldd-r.txt" >&2; fail "release shared object failed ldd -r"; }
if grep -q 'undefined symbol:' "$TMP/ldd-r.txt"; then
  cat "$TMP/ldd-r.txt" >&2
  fail "release shared object has unresolved dynamic symbol(s)"
fi
nm -D --defined-only target/release/librsi.so | awk '{ print $3 }' | sort -u > "$TMP/exports.txt"
sed -E 's/.*[^A-Za-z0-9_](rsi_[a-z_]+)[[:space:]]*\(.*/\1/' "$TMP/hand.fns" \
  | sort -u > "$TMP/expected.exports"
diff "$TMP/expected.exports" "$TMP/exports.txt" \
  || fail "dynamic export set mismatch ('<' headers, '>' release shared object)"
echo "ok 6/6: release shared object has no unresolved symbols and exports exactly the rsi_* ABI"

echo
echo "ABI VERIFIED: the hand-written <rsi/*.h> headers are ABI-identical to the Rust source."
