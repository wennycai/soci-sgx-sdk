#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
OUT=${TEE_CBC_OUT:-"$ROOT/build/tee_cbc"}
MODE=${1:?usage: run_tee_cbc.sh direct|sgx ROWS THRESHOLD TIMEOUT [DATA_DIR]}
ROWS=${2:?missing rows}; THRESHOLD=${3:?missing threshold}; TIMEOUT=${4:-60}
DATA_DIR=${5:-${TEE_CBC_DATA_DIR:-"$OUT/data"}}
MANIFEST="$OUT/$MODE/soci_cbc_plaintext_benchmark.manifest"
[[ -f "$MANIFEST" ]] || { echo "run build_tee_cbc.sh first" >&2; exit 2; }
export SOCI_CBC_TMPDIR=/opt/tee_cbc

# The host sees only public dimensions/threshold and the final JSON.  Costs
# are read from /input inside Gramine; CBC's LP/solution files are in tmpfs.
if [[ "$MODE" == sgx ]]; then
  exec gramine-sgx "$OUT/$MODE/soci_cbc_plaintext_benchmark" \
    /input/costs.tsv "$ROWS" "$THRESHOLD" "$TIMEOUT"
fi
exec gramine-direct "$OUT/$MODE/soci_cbc_plaintext_benchmark" \
  /input/costs.tsv "$ROWS" "$THRESHOLD" "$TIMEOUT"
