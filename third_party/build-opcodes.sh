#!/usr/bin/env bash
# Build multi-arch libopcodes (x86-64, aarch64, riscv64, ...) from pinned binutils
# into third_party/opcodes-out/. Idempotent via stamp file.
set -euo pipefail
cd "$(dirname "$0")"

VERSION=2.47
SHA256=154ab23b60070e8f27013c22977f1129425d67d1e8acd6e13010e617811e4cff
TARBALL="cache/binutils-${VERSION}.tar.xz"
SRC="cache/build/binutils-${VERSION}"
BUILD="cache/build/opcodes-build"
OUT="$PWD/opcodes-out"
STAMP="$OUT/.stamp"
SCRIPT_HASH=$(sha256sum "$0" | cut -c1-16)
KEY="${VERSION}-${SCRIPT_HASH}"

if [ -f "$STAMP" ] && grep -qxF "$KEY" "$STAMP" && [ -f "$OUT/lib/libopcodes.a" ]; then
  exit 0
fi

mkdir -p cache "$OUT/lib" "$OUT/include"
ROOT="$PWD"

if [ ! -f "$TARBALL" ]; then
  curl -L --fail -o "$TARBALL" "https://ftp.gnu.org/gnu/binutils/binutils-${VERSION}.tar.xz"
fi
echo "${SHA256}  ${TARBALL}" | sha256sum -c -

if [ ! -f "$SRC/configure" ]; then
  mkdir -p cache/build
  tar -xf "$TARBALL" -C cache/build
fi

if [ ! -f "$BUILD/config.status" ]; then
  mkdir -p "$BUILD"
  (
    cd "$BUILD"
    "$ROOT/$SRC/configure" \
      --disable-nls \
      --disable-gdb \
      --disable-ld \
      --disable-gold \
      --disable-gas \
      --disable-sim \
      --disable-gprof \
      --disable-gprofng \
      --disable-werror \
      --disable-shared \
      --enable-targets=all \
      --prefix="$OUT"
  )
fi

make -C "$BUILD" -j"$(nproc)" all-libiberty all-opcodes all-bfd

# libtool puts final archives under .libs/
cp "$BUILD/opcodes/.libs/libopcodes.a" "$OUT/lib/" 2>/dev/null || cp "$BUILD/opcodes/libopcodes.a" "$OUT/lib/"
cp "$BUILD/bfd/.libs/libbfd.a" "$OUT/lib/" 2>/dev/null || cp "$BUILD/bfd/libbfd.a" "$OUT/lib/"
cp "$BUILD/libiberty/libiberty.a" "$OUT/lib/"
cp "$BUILD/libsframe/.libs/libsframe.a" "$OUT/lib/" 2>/dev/null || true
cp "$BUILD/zlib/libz.a" "$OUT/lib/" 2>/dev/null || true

# Headers needed by the C shim (dis-asm.h includes bfd.h).
cp "$SRC/include/dis-asm.h" "$OUT/include/"
cp "$BUILD/bfd/bfd.h" "$OUT/include/" 2>/dev/null || cp "$SRC/bfd/bfd.h" "$OUT/include/"
cp "$SRC/include/ansidecl.h" "$OUT/include/" 2>/dev/null || true
cp "$SRC/include/bfdlink.h" "$OUT/include/" 2>/dev/null || true
cp "$SRC/include/symcat.h" "$OUT/include/" 2>/dev/null || true
cp "$SRC/include/diagnostics.h" "$OUT/include/" 2>/dev/null || true
for h in bucomm.h plugin-api.h; do
  cp "$SRC/include/$h" "$OUT/include/" 2>/dev/null || true
  cp "$SRC/bfd/$h" "$OUT/include/" 2>/dev/null || true
done

printf '%s\n' "$KEY" > "$STAMP"
echo "opcodes ready: $OUT/lib/libopcodes.a"
