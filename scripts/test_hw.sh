#!/usr/bin/env bash
set -euo pipefail
"$(dirname "$0")/check_sgx_host.sh"
cd "$(dirname "$0")/.."
ctest --preset hw-release
