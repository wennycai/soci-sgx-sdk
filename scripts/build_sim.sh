#!/usr/bin/env bash
set -euo pipefail
: "${SGX_SDK:=/opt/intel/sgxsdk}"
test -x "$SGX_SDK/bin/x64/sgx_edger8r" || { echo "Intel SGX SDK 2.26 missing" >&2; exit 1; }
cd "$(dirname "$0")/.."
CMAKE_PRESET_NAME=sim-release cmake --preset sim-release
cmake --build --preset sim-release
