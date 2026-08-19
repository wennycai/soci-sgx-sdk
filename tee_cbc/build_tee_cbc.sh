#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
BUILD_DIR=${1:-"$ROOT/build/scalable"}
OUT=${TEE_CBC_OUT:-"$ROOT/build/tee_cbc"}
CBC_BIN=${CBC_BIN:-"$(command -v cbc || true)"}
BENCH="$BUILD_DIR/soci_cbc_plaintext_benchmark"

command -v gramine-manifest >/dev/null || { echo "gramine-manifest is required" >&2; exit 2; }
test -x "$CBC_BIN" || { echo "cbc executable not found (set CBC_BIN)" >&2; exit 2; }
cmake --build "$BUILD_DIR" --target soci_cbc_plaintext_benchmark -j"${JOBS:-2}"

# Enumerate the concrete runtime dependencies of CBC, the benchmark binary
# and /bin/sh (std::system spawns it) so the SGX manifest can trust files
# individually.  A missing entry fails closed at gramine-sgx-sign or launch.
trusted_files() {
  {
    printf '%s\n' "$CBC_BIN" /bin/sh
    ldd "$CBC_BIN"
    ldd "$BENCH"
    ldd /bin/sh
  } | grep -oE '/[^ ()]+' | sort -u | while read -r f; do
      [[ -f $f ]] && printf '"file:%s", ' "$f"
    done
}

render() {
  local mode=$1 data_dir=$2 key_name=$3
  local app_dir="$OUT/$mode"
  mkdir -p "$app_dir"
  cp "$BENCH" "$app_dir/soci_cbc_plaintext_benchmark"
  local input_mount sgx_trusted_files
  sgx_trusted_files=$(trusted_files)
  if [[ "$mode" == sgx ]]; then
    input_mount="{ type = \"encrypted\", path = \"/input\", uri = \"file:$data_dir\", key_name = \"$key_name\" },"
  else
    input_mount="{ type = \"chroot\", path = \"/input\", uri = \"file:$data_dir\" },"
  fi
  local dst="$app_dir/soci_cbc_plaintext_benchmark.manifest"
  sed -e "s|@TEE_ROOT@|$app_dir|g" \
      -e "s|@DATA_DIR@|$data_dir|g" \
      -e "s|@WORK_DIR@|$WORK_DIR|g" \
      -e "s|@KEY_NAME@|$key_name|g" \
      -e "s|@INPUT_MOUNT@|$input_mount|g" \
      -e "s|@SGX_TRUSTED_FILES@|$sgx_trusted_files|g" \
      "$ROOT/tee_cbc/tee_cbc.manifest.$mode.template" > "$dst"
  gramine-manifest "$dst" "$dst.rendered"
  mv "$dst.rendered" "$dst"
}

DATA_DIR=${TEE_CBC_DATA_DIR:-"$OUT/data"}
WORK_DIR=${TEE_CBC_WORK_DIR:-"$OUT/work"}
mkdir -p "$DATA_DIR" "$WORK_DIR"
# The direct manifest is a functional simulation; the SGX manifest is the
# strict, fail-closed confidentiality path.  Both are always rendered so
# template regressions surface even without SGX hardware.
render direct "$DATA_DIR" default
render sgx "$DATA_DIR" _sgx_mrenclave
if [[ "${TEE_CBC_BUILD_SGX:-1}" == 1 ]]; then
  command -v gramine-sgx-sign >/dev/null || { echo "gramine-sgx-sign is required" >&2; exit 2; }
  : "${SGX_SIGNING_KEY:?set SGX_SIGNING_KEY for SGX signing}"
  # Offline measurement/signing: verifies that every trusted file in the
  # strict manifest resolves; launching the enclave still needs SGX HW.
  gramine-sgx-sign --key "$SGX_SIGNING_KEY" \
    --manifest "$OUT/sgx/soci_cbc_plaintext_benchmark.manifest" \
    --output "$OUT/sgx/soci_cbc_plaintext_benchmark.manifest.sgx"
fi
echo "Built manifests under $OUT"
