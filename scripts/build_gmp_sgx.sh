#!/usr/bin/env bash
set -euo pipefail

version=6.2.1
sha256=fd4829912cddd12f84181c3451cc752be224643e87fac497b69edddadc49b4f2
url="https://ftp.gnu.org/gnu/gmp/gmp-${version}.tar.xz"
prefix="${1:-${SGX_SDK:-/opt/intel/sgxsdk}/gmp-sgx}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

if [[ -n "${GMP_SOURCE_ARCHIVE:-}" ]]; then
  cp "$GMP_SOURCE_ARCHIVE" "$work/gmp.tar.xz"
else
  wget -4 -q "$url" -O "$work/gmp.tar.xz"
fi
echo "$sha256  $work/gmp.tar.xz" | sha256sum -c -
tar -xf "$work/gmp.tar.xz" -C "$work"
cd "$work/gmp-${version}"

# A fixed x86_64 target selects GMP's baseline assembly implementation without
# the fat-binary runtime CPUID dispatcher. The resulting archive is linked
# against SGX trusted libc, never loaded from the untrusted host at runtime.
CC="${CC:-gcc-11}" ./configure \
  --prefix="$prefix" \
  --host=x86_64-linux-gnu \
  --disable-shared \
  --enable-static \
  --disable-cxx \
  --with-pic \
  CFLAGS="-O3 -fPIC -fvisibility=hidden"
make -j"${BUILD_JOBS:-2}"
make install
mv "$prefix/lib/libgmp.a" "$prefix/lib/libgmp_sgx.a"
rm -f "$prefix/lib/libgmp.la"
echo "installed $prefix/lib/libgmp_sgx.a"
