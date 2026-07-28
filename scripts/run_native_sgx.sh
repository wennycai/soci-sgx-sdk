#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  ./scripts/run_native_sgx.sh [auto|sim|hw] [--benchmark]

Examples:
  ./scripts/run_native_sgx.sh
  ./scripts/run_native_sgx.sh hw
  ./scripts/run_native_sgx.sh hw --benchmark

Environment:
  SGX_SDK      Intel SGX SDK directory (default: /opt/intel/sgxsdk)
  BUILD_JOBS   Parallel build jobs
EOF
}

mode=auto
run_benchmark=0
for arg in "$@"; do
  case "$arg" in
    auto|sim|hw) mode="$arg" ;;
    --benchmark) run_benchmark=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $arg" >&2; usage >&2; exit 2 ;;
  esac
done

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
sgx_sdk="${SGX_SDK:-/opt/intel/sgxsdk}"
export SGX_SDK="$sgx_sdk"

required_commands=(cmake make gcc-11 g++-11 m4 openssl sha256sum tar)
missing=()
for command_name in "${required_commands[@]}"; do
  command -v "$command_name" >/dev/null 2>&1 || missing+=("$command_name")
done
if ((${#missing[@]})); then
  echo "Missing build commands: ${missing[*]}" >&2
  echo "On Ubuntu 22.04 install: build-essential gcc-11 g++-11 cmake m4 libgmp-dev libssl-dev" >&2
  exit 1
fi

if [[ ! -x "$sgx_sdk/bin/x64/sgx_edger8r" || ! -x "$sgx_sdk/bin/x64/sgx_sign" ]]; then
  echo "Intel SGX SDK 2.26 not found under: $sgx_sdk" >&2
  echo "Install the SDK first, or set SGX_SDK to its installation directory." >&2
  exit 1
fi

if [[ "$mode" == auto ]]; then
  if [[ -e /dev/sgx_enclave && -e /dev/sgx_provision ]] &&
     grep -qw sgx /proc/cpuinfo; then
    mode=hw
  else
    mode=sim
  fi
fi

if [[ "$mode" == hw ]]; then
  "$project_dir/scripts/check_sgx_host.sh"
  preset=hw-release
  result_name=benchmark-hw-3072.json
else
  preset=sim-release
  result_name=benchmark-sim-3072.json
fi

gmp_root="$project_dir/.deps/gmp-sgx"
gmp_archive="$project_dir/third_party/gmp-6.2.1.tar.xz"
if [[ ! -f "$gmp_root/lib/libgmp_sgx.a" || ! -f "$gmp_root/include/gmp.h" ]]; then
  echo "[1/4] Building trusted GMP into $gmp_root"
  GMP_SOURCE_ARCHIVE="$gmp_archive" \
    "$project_dir/scripts/build_gmp_sgx.sh" "$gmp_root"
else
  echo "[1/4] Reusing trusted GMP from $gmp_root"
fi

echo "[2/4] Configuring and building SGX $mode mode"
cd "$project_dir"
CMAKE_PRESET_NAME="$preset" cmake --preset "$preset" -DGMP_SGX_ROOT="$gmp_root"
cmake --build --preset "$preset" --parallel "${BUILD_JOBS:-$(nproc)}"

echo "[3/4] Running SGX $mode correctness tests"
export LD_LIBRARY_PATH="$sgx_sdk/lib64${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
ctest --preset "$preset"

if ((run_benchmark)); then
  echo "[4/4] Running benchmark (KeyGen warm-up 20/sample 30; decrypt warm-up 10/sample 100)"
  mkdir -p results
  "./build/$preset/soci_sgx_crypto_benchmark" \
    "./build/$preset/soci_provisioning_enclave.signed.so" \
    100 30 10 20 > "results/$result_name"
  echo "Benchmark result: $project_dir/results/$result_name"
else
  echo "[4/4] Benchmark skipped (add --benchmark to run it)"
fi

echo "SUCCESS: native SGX $mode build and tests completed"
