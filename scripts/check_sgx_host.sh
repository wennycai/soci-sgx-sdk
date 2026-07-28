#!/usr/bin/env bash
set -euo pipefail
grep -qw sgx /proc/cpuinfo || { echo "CPU does not advertise SGX" >&2; exit 1; }
test -e /dev/sgx_enclave || { echo "/dev/sgx_enclave missing" >&2; exit 1; }
test -e /dev/sgx_provision || { echo "/dev/sgx_provision missing" >&2; exit 1; }
echo "SGX hardware devices present"
