#!/usr/bin/env bash
set -euo pipefail

# Never load the development uRTS shipped in SGX_SDK for HW execution.
unset LD_LIBRARY_PATH

check_environment() {
  grep -qw sgx /proc/cpuinfo || {
    echo "CPU does not advertise SGX inside the container" >&2
    return 1
  }
  test -c /dev/sgx_enclave || {
    echo "/dev/sgx_enclave is not mapped into the container" >&2
    return 1
  }
}

run_tests() {
  /opt/soci/bin/soci_sgx_lifecycle_test \
    /opt/soci/enclaves/soci_cp_enclave.signed.so HW
  /opt/soci/bin/soci_sgx_lifecycle_test \
    /opt/soci/enclaves/soci_csp_enclave.signed.so HW
  /opt/soci/bin/soci_sgx_threshold_test \
    /opt/soci/enclaves/soci_provisioning_enclave.signed.so \
    /opt/soci/enclaves/soci_cp_enclave.signed.so \
    /opt/soci/enclaves/soci_csp_enclave.signed.so HW
  echo "SOCI SGX HW lifecycle and CP/CSP threshold decrypt tests passed"
}

case "${1:-test}" in
  check)
    check_environment
    echo "SOCI SGX container environment is ready"
    ;;
  test)
    check_environment
    run_tests
    ;;
  benchmark)
    check_environment
    /opt/soci/bin/soci_sgx_crypto_benchmark \
      /opt/soci/enclaves/soci_provisioning_enclave.signed.so \
      "${DECRYPT_SAMPLES:-100}" "${KEYGEN_SAMPLES:-30}" \
      "${DECRYPT_WARMUP:-10}" "${KEYGEN_WARMUP:-20}" \
      | tee /opt/soci/results/benchmark-hw-3072.json
    ;;
  provision)
    check_environment
    mkdir -p /var/lib/soci
    /opt/soci/bin/soci_threshold_runtime provision \
      /opt/soci/enclaves/soci_provisioning_enclave.signed.so \
      /var/lib/soci "${MODULUS_BITS:-3072}" \
      | tee /opt/soci/results/keygen-hw-3072.json
    ;;
  csp)
    check_environment
    exec /opt/soci/bin/soci_threshold_runtime csp \
      /opt/soci/enclaves/soci_csp_enclave.signed.so \
      /var/lib/soci "${CSP_PORT:-19090}"
    ;;
  cp-benchmark)
    check_environment
    /opt/soci/bin/soci_threshold_runtime benchmark \
      /opt/soci/enclaves/soci_cp_enclave.signed.so /var/lib/soci \
      "${CSP_HOST:-127.0.0.1}" "${CSP_PORT:-19090}" \
      "${PROTOCOL_WARMUP:-20}" "${PROTOCOL_SAMPLES:-100}" \
      | tee /opt/soci/results/cp-csp-benchmark-hw-3072.json
    ;;
  shell) exec bash ;;
  *) exec "$@" ;;
esac
