#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
decrypt_samples="${1:-100}"
keygen_samples="${2:-30}"
decrypt_warmup="${3:-10}"
keygen_warmup="${4:-5}"
: "${SGX_SDK:=/opt/intel/sgxsdk}"
test -x "$SGX_SDK/bin/x64/sgx_edger8r" || {
  echo "Intel SGX SDK 2.26 missing; use docker compose -f docker/compose.sim.yaml" >&2
  exit 1
}
./scripts/build_sim.sh
mkdir -p results
LD_LIBRARY_PATH="$SGX_SDK/lib64${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
  ./build/sim-release/soci_sgx_crypto_benchmark \
  ./build/sim-release/soci_provisioning_enclave.signed.so \
  "$decrypt_samples" "$keygen_samples" "$decrypt_warmup" "$keygen_warmup" \
  > results/benchmark-sim-3072.json
echo "wrote results/benchmark-sim-3072.json"
