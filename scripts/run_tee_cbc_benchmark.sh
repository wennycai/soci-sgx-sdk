#!/usr/bin/env bash
# TEE+CBC performance acceptance, Gramine-direct / SIM-functional stage.
#
# Gramine-direct is a FUNCTIONAL SIMULATION: it is not Intel SGX SDK SIM and
# not a real SGX enclave.  Results from this script must never be reported as
# "SGX performance" or "real TEE overhead".  The hardware entry point
# (tee_cbc/run_tee_cbc.sh sgx) is intentionally never invoked here; it is
# reserved for a later run on real SGX hardware, reusing this same dataset,
# metric set and result schema.
#
# This script is deliberately NOT wired into the OFF/SIM CI.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
OUT=${TEE_CBC_OUT:-/tmp/tee-cbc-benchmark-build}
DATA=${TEE_CBC_DATA_DIR:-/tmp/tee-cbc-benchmark-data}
WORK=${TEE_CBC_WORK_DIR:-/tmp/tee-cbc-benchmark-work}
BUILD_DIR=${TEE_CBC_BUILD_DIR:-"$ROOT/build/scalable"}
WORKBOOK=${TEE_CBC_WORKBOOK:-"$ROOT/examples/optimization-demo/sample-costs-410.xlsx"}
RESULTS=${TEE_CBC_RESULTS:-"$ROOT/results/tee-cbc-benchmark-gramine-direct.json"}

command -v gramine-direct >/dev/null || {
  echo "gramine-direct not found; run via docker/compose.tee-cbc.yaml" >&2; exit 2; }

mkdir -p "$DATA" "$WORK" "$(dirname "$RESULTS")"

# Render the direct + strict SGX manifests and stage the native control.  SGX
# signing is skipped: this stage needs no signing key, and the regression
# (scripts/test_tee_cbc_direct.sh) already covers offline signing.
TEE_CBC_BUILD_SGX=0 TEE_CBC_OUT="$OUT" \
  TEE_CBC_DATA_DIR="$DATA" TEE_CBC_WORK_DIR="$WORK" \
  "$ROOT/tee_cbc/build_tee_cbc.sh" "$BUILD_DIR"

# One costs.tsv serves the whole matrix: the benchmark reads the first ROWS
# lines, so every row count in the matrix is an exact prefix.  410 is the full
# real workbook and the matrix tops out at 200, so the file carries no
# synthetic rows at all.
python3 "$ROOT/tee_cbc/prepare_tee_cbc_data.py" "$WORKBOOK" "$DATA" \
  --rows "${TEE_CBC_DATA_ROWS:-410}" \
  --provenance "$(dirname "$RESULTS")/tee-cbc-dataset-provenance.json"

TEE_CBC_OUT="$OUT" python3 "$ROOT/tee_cbc/benchmark_tee_cbc.py" \
  --runner "$ROOT/tee_cbc/run_tee_cbc.sh" --output "$RESULTS" "$@"
