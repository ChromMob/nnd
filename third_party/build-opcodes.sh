#!/usr/bin/env bash
# Build multi-arch static libopcodes (+ libiberty, libbfd) from a pinned binutils
# release into third_party/opcodes-out/. Idempotent: exits immediately when the
# stamp matches version+targets+script hash.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
CACHE="$ROOT/cache"
BUILDROOT="$CACHE/build"
SRC="$BUILDROOT/binutils-2.47"
OUT="$ROOT/opcodes-out"

VERSION="2.47"
# sha256 of binutils-2.47.tar.xz from ftp.gnu.org (pinned after trusted download)
SHA256="154ab23b60070e8f27013c22977f1129425d67d1e8acd6e13010e617811e4cff"
URL="https://ftp.gnu.org/gnu/binutils/binutils-${VERSION}.tar.xz"
TARGETS="all"

SCRIPT_HASH="$(sha256sum "$0" | awk '{print $1}')"
STAMP_EXPECTED="${VERSION}|${TARGETS}|${SCRIPT_HASH}"

if [[ -f "$OUT/stamp" && "$(cat "$OUT/stamp")" == "$STAMP_EXPECTED" ]]; then
  exit 0
fi

mkdir -p "$CACHE" "$BUILDROOT"

TARBALL="$CACHE/binutils-${VERSION}.tar.xz"
if [[ ! -f "$TARBALL" ]]; then
  echo "downloading $URL"
  curl -L --retry 3 --fail -o "$TARBALL.part" "$URL"
  mv "$TARBALL.part" "$TARBALL"
fi
echo "$SHA256  $TARBALL" | sha256sum -c -

if [[ ! -f "$SRC/configure" ]]; then
  echo "extracting $TARBALL"
  rm -rf "$SRC"
  tar -xf "$TARBALL" -C "$BUILDROOT"
fi

CONF_ARGS=(
  --disable-nls
  --disable-gdb
  --disable-ld
  --disable-gold
  --disable-gas
  --disable-sim
  --disable-gprof
  --disable-gprofng
  --disable-werror
  --enable-targets="$TARGETS"
  --prefix="$OUT/prefix"
)
CONF_HASH="$(printf '%s\n' "${CONF_ARGS[@]}" | sha256sum | awk '{print $1}')"

cd "$SRC"
if [[ ! -f .nnd-conf-hash || "$(cat .nnd-conf-hash)" != "$CONF_HASH" ]]; then
  echo "configuring binutils ${VERSION} (targets=${TARGETS})"
  ./configure "${CONF_ARGS[@]}"
  printf '%s\n' "$CONF_HASH" > .nnd-conf-hash
fi

NPROC="$(nproc 2>/dev/null || echo 2)"
echo "building opcodes (jobs=$NPROC)"
make -j"$NPROC" all-libiberty all-bfd all-opcodes

# Locate built static archives (libtool may place them under .libs/).
find_lib() {
  local name="$1" hit
  hit="$(find "$SRC" -name "$name" -type f \( -path '*/.libs/*' -o -path '*/libiberty/*' -o -path '*/opcodes/*' -o -path '*/bfd/*' -o -path '*/zlib/*' -o -path '*/libsframe/*' \) | head -n1 || true)"
  if [[ -z "$hit" ]]; then
    hit="$(find "$SRC" -name "$name" -type f | head -n1 || true)"
  fi
  if [[ -z "$hit" ]]; then
    echo "error: $name not found under $SRC" >&2
    exit 1
  fi
  printf '%s\n' "$hit"
}

LIB_OPCODES="$(find_lib libopcodes.a)"
LIB_IBERTY="$(find_lib libiberty.a)"
LIB_BFD="$(find_lib libbfd.a)"

rm -rf "$OUT"
mkdir -p "$OUT/include"
cp "$LIB_OPCODES" "$LIB_IBERTY" "$LIB_BFD" "$OUT/"

# Optional companions the linker may demand.
for extra in libsframe.a libz.a; do
  hit="$(find "$SRC" -name "$extra" -type f | head -n1 || true)"
  [[ -n "$hit" ]] && cp "$hit" "$OUT/"
done

# Headers for the shim: dis-asm.h pulls in bfd.h; bfd.h pulls in a few include/ bits.
# bfd.h is the configure-generated bfd-in3.h (bfd only copies it during its build).
cp "$SRC/include/dis-asm.h" "$OUT/include/"
if [[ -f "$SRC/bfd/bfd.h" ]]; then
  cp "$SRC/bfd/bfd.h" "$OUT/include/"
else
  cp "$SRC/bfd/bfd-in3.h" "$OUT/include/bfd.h"
fi
cp "$SRC/include/ansidecl.h" "$SRC/include/symcat.h" "$SRC/include/diagnostics.h" "$OUT/include/" 2>/dev/null || true
# opcodes/disassemble.h declares print_insn_* per arch.
cp "$SRC/opcodes/disassemble.h" "$OUT/include/" 2>/dev/null || true

printf '%s\n' "$STAMP_EXPECTED" > "$OUT/stamp"
echo "installed libopcodes into $OUT"
