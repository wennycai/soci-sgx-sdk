#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
bits="${1:-3072}"
samples="${2:-50}"
cmake --preset off-benchmark
cmake --build --preset off-benchmark
mkdir -p results
./build/off-benchmark/soci_benchmark "$bits" "$samples" \
  > "results/benchmark-off-${bits}.json"
echo "wrote results/benchmark-off-${bits}.json"
