#!/usr/bin/env bash
set -euo pipefail
repo="$(cd "$(dirname "$0")/../.." && pwd)"
mode="${1:-sim}"
port="${2:-8080}"
if [[ "$mode" == off ]]; then
  exec "$repo/examples/optimization-demo/run_off_demo.sh" "$port"
fi
if [[ "$mode" != sim ]]; then
  echo "usage: $0 [sim|off] [port]" >&2
  exit 2
fi
: "${SGX_SDK:=/opt/intel/sgxsdk}"
export SGX_SDK
"$repo/scripts/build_sim.sh"
build="$repo/build/sim-release"
state="$repo/runtime/sim/demo"
classes="$build/demo-java"
csp_port="${SOCI_DEMO_CSP_PORT:-19091}"
mkdir -p "$state" "$classes"
export LD_LIBRARY_PATH="$SGX_SDK/lib64:$build${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
SOCI_SGX_MODE=SIM "$build/soci_threshold_runtime" provision \
  "$build/soci_provisioning_enclave.signed.so" "$state" 3072
SOCI_SGX_MODE=SIM "$build/soci_threshold_runtime" csp \
  "$build/soci_csp_enclave.signed.so" "$state" "$csp_port" &
csp_pid=$!
trap 'kill "$csp_pid" 2>/dev/null || true; wait "$csp_pid" 2>/dev/null || true' EXIT INT TERM
javac -d "$classes" $(find "$repo/bindings/java/src/main/java" \
  "$repo/examples/optimization-demo/java" -name '*.java' -print)
java -Djava.library.path="$build" -cp "$classes" com.soci.demo.SociDemoServer \
  "$repo/examples/optimization-demo" "$port" SIM "$state" \
  "$build/soci_cp_enclave.signed.so" "$state" 127.0.0.1 "$csp_port"
