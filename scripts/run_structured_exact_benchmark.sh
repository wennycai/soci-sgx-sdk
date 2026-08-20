#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
BUILD_DIR=${STRUCTURED_EXACT_BUILD_DIR:-"$ROOT/build/structured-exact"}
TIMEOUT=${STRUCTURED_EXACT_TIMEOUT:-60}
NODE_LIMIT=${STRUCTURED_EXACT_NODE_LIMIT:-0}
STRATEGY=${STRUCTURED_EXACT_STRATEGY:-B2}
cmake -S "$ROOT" -B "$BUILD_DIR" -DSOCI_SGX_MODE=OFF -DSOCI_BUILD_PYTHON=OFF -DSOCI_BUILD_JAVA=OFF
cmake --build "$BUILD_DIR" --target soci_structured_exact_benchmark soci_structured_exact_test soci_cbc_plaintext_benchmark -j"${CMAKE_BUILD_PARALLEL_LEVEL:-2}"
"$BUILD_DIR/soci_structured_exact_test"
python3 "$ROOT/scripts/benchmark_structured_exact.py" \
  --structured "$BUILD_DIR/soci_structured_exact_benchmark" \
  --cbc "$BUILD_DIR/soci_cbc_plaintext_benchmark" --timeout "$TIMEOUT" \
  --node-limit "$NODE_LIMIT" --strategy "$STRATEGY"
