#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
BUILD_DIR=${1:-"$ROOT/build/scalable"}
OUT=${TEE_CBC_OUT:-"$ROOT/build/tee_cbc"}
CBC_BIN=${CBC_BIN:-"$(command -v cbc || true)"}

command -v gramine-manifest >/dev/null || { echo "gramine-manifest is required" >&2; exit 2; }
test -x "$CBC_BIN" || { echo "cbc executable not found (set CBC_BIN)" >&2; exit 2; }
cmake --build "$BUILD_DIR" --target soci_cbc_plaintext_benchmark -j"${JOBS:-2}"
mkdir -p "$OUT/root"
cp "$BUILD_DIR/soci_cbc_plaintext_benchmark" "$OUT/root/"

template="$ROOT/tee_cbc/tee_cbc.manifest.template"
render() {
  local mode=$1 data_dir=$2 key_name=$3 input_mount
  local app_dir="$OUT/$mode"
  mkdir -p "$app_dir"
  cp "$BUILD_DIR/soci_cbc_plaintext_benchmark" "$app_dir/soci_cbc_plaintext_benchmark"
  if [[ "$mode" == sgx ]]; then
    input_mount="{ type = \"encrypted\", path = \"/input\", uri = \"file:$data_dir\", key_name = \"$key_name\" },"
  else
    input_mount="{ type = \"chroot\", path = \"/input\", uri = \"file:$data_dir\" },"
  fi
  local dst="$app_dir/soci_cbc_plaintext_benchmark.manifest"
  sed -e "s|@TEE_ROOT@|$app_dir|g" \
      -e "s|@CBC_BIN@|$CBC_BIN|g" \
      -e "s|@DATA_DIR@|$data_dir|g" \
      -e "s|@KEY_NAME@|$key_name|g" \
      -e "s|@INPUT_MOUNT@|$input_mount|g" "$template" > "$dst"
  gramine-manifest "$dst" "$dst.rendered"
  mv "$dst.rendered" "$dst"
  if [[ "$mode" == sgx ]]; then
    command -v gramine-sgx-sign >/dev/null || { echo "gramine-sgx-sign is required" >&2; exit 2; }
    : "${SGX_SIGNING_KEY:?set SGX_SIGNING_KEY for SGX signing}"
    gramine-sgx-sign --key "$SGX_SIGNING_KEY" --manifest "$dst" \
      --output "${dst}.sgx"
  fi
}

DATA_DIR=${TEE_CBC_DATA_DIR:-"$OUT/data"}
mkdir -p "$DATA_DIR"
render direct "$DATA_DIR" default
if [[ "${TEE_CBC_BUILD_SGX:-1}" == 1 ]]; then
  render sgx "$DATA_DIR" _sgx_mrenclave
fi
echo "Built manifests under $OUT"
