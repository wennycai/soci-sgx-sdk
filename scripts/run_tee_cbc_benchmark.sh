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
RESULTS=${TEE_CBC_RESULTS:-"$ROOT/results/tee-cbc-benchmark-gramine-direct.json"}
# The frozen dataset and its provenance are committed inputs, not outputs.  The
# overrides exist so a larger frozen dataset can serve a wider matrix later;
# they are NOT a way to regenerate data per run (see tee_cbc/README.md).
DATASET=${TEE_CBC_DATASET:-"$ROOT/tee_cbc/data/costs.tsv"}
PROVENANCE=${TEE_CBC_DATASET_PROVENANCE:-"$ROOT/tee_cbc/data/costs.provenance.json"}

command -v gramine-direct >/dev/null || {
  echo "gramine-direct not found; run via docker/compose.tee-cbc.yaml" >&2; exit 2; }

mkdir -p "$DATA" "$WORK" "$(dirname "$RESULTS")"

# Render the direct + strict SGX manifests and stage the native control.  SGX
# signing is skipped: this stage needs no signing key, and the regression
# (scripts/test_tee_cbc_direct.sh) already covers offline signing.
TEE_CBC_BUILD_SGX=0 TEE_CBC_OUT="$OUT" \
  TEE_CBC_DATA_DIR="$DATA" TEE_CBC_WORK_DIR="$WORK" \
  "$ROOT/tee_cbc/build_tee_cbc.sh" "$BUILD_DIR"

# Stage the FROZEN dataset into the Gramine /input mount.  Deliberately a copy
# of a committed file, never a regeneration: the acceptance matrix has to run
# on the same bytes every published result was measured on.  The harness hashes
# what lands here against the committed provenance and refuses to measure on a
# mismatch, so this copy cannot quietly go wrong.
[[ -f "$DATASET" ]] || {
  echo "frozen dataset $DATASET is missing; prepare it once with" >&2
  echo "  tee_cbc/prepare_tee_cbc_data.py WORKBOOK tee_cbc/data \\" >&2
  echo "    --provenance tee_cbc/data/costs.provenance.json" >&2
  exit 2; }
[[ -f "$PROVENANCE" ]] || { echo "missing provenance $PROVENANCE" >&2; exit 2; }
install -m 0644 "$DATASET" "$DATA/costs.tsv"

# --residue-dir covers both sides' CBC scratch space: WORK backs the Gramine
# encrypted /work mount, and native gets the sibling directory build_tee_cbc.sh
# stages for it.  Anything found there after a run was left by a killed
# process and blocks acceptance.
TEE_CBC_OUT="$OUT" python3 "$ROOT/tee_cbc/benchmark_tee_cbc.py" \
  --runner "$ROOT/tee_cbc/run_tee_cbc.sh" \
  --dataset-file "$DATA/costs.tsv" --dataset-provenance "$PROVENANCE" \
  --residue-dir "$WORK" --residue-dir "${TEE_CBC_NATIVE_WORK_DIR:-$OUT/native-work}" \
  --output "$RESULTS" "$@"
