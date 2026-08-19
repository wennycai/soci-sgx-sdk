#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
DATA=${TEE_CBC_TEST_DATA:-/tmp/tee-cbc-direct-data}
OUT=${TEE_CBC_OUT:-/tmp/tee-cbc-direct-build}
mkdir -p "$DATA"
cat > "$DATA/costs.tsv" <<'EOF'
10	12	10.1
11	13	11.1
12	14	12.1
10	12	10.1
11	13	11.1
12	14	12.1
EOF
TEE_CBC_BUILD_SGX=0 TEE_CBC_DATA_DIR="$DATA" TEE_CBC_OUT="$OUT" \
  "$ROOT/tee_cbc/build_tee_cbc.sh" "$ROOT/build/scalable"
result=$(TEE_CBC_DATA_DIR="$DATA" TEE_CBC_OUT="$OUT" \
  "$ROOT/tee_cbc/run_tee_cbc.sh" direct 6 0.5 60)
python3 -c 'import json,sys; d=json.loads(sys.argv[1]); assert d["optimality_status"] == "optimal_verified" and d["total_cost"] > 0 and len(d["solution"]) == 6; print(d)' "$result"
