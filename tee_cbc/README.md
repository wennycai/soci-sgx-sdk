# Independent Gramine + CBC TEE PoC

This directory is an independent plaintext MILP comparison route. It runs the
existing COIN-OR CBC executable under Gramine; it does not reimplement CBC and
does not modify the HE/CP-CSP, Paillier, PredicateEngine, PEGA, or existing SGX
paths.

The application is the existing `soci_cbc_plaintext_benchmark`. It retains the
cheapest-fast-path → CBC Exact flow and the CBC one-hot, ratio, and objective
recomputation checks. LP, solution, and log files are created under Gramine
`tmpfs`; the input is mounted as an encrypted Gramine filesystem at `/input`.

## Build

Install Gramine using its official instructions, install CBC, and set an SGX
signing key for the SGX manifest:

```bash
export SGX_SIGNING_KEY=/path/to/gramine-sgx-signing-key.pem
tee_cbc/build_tee_cbc.sh build/scalable
```

This produces manifests beside mode-specific
`soci_cbc_plaintext_benchmark` launchers under `build/tee_cbc/direct/` and
`build/tee_cbc/sgx/`. The direct manifest is useful for functional tests;
the SGX manifest is the confidentiality path.

Prepare an encrypted `costs.tsv` under `TEE_CBC_DATA_DIR`. Use
`gramine-sgx-pf-crypt` with a deployment-provisioned wrap key; do not use
`fs.insecure__keys` in production. The `_sgx_mrenclave` key name in the SGX
manifest is intended to be provisioned through Gramine’s attestation/secret
provisioning flow.

## Run

```bash
TEE_CBC_DATA_DIR=/sealed/input \
  tee_cbc/run_tee_cbc.sh direct 410 0.5 60

TEE_CBC_DATA_DIR=/sealed/input \
  tee_cbc/run_tee_cbc.sh sgx 410 0.5 60
```

Only the final benchmark JSON is printed. The host supplies public rows,
threshold, and timeout; costs and CBC intermediate state are read and processed
inside Gramine. This PoC does not implement remote attestation or a production
secret-provisioning service.

## Docker

`tee_cbc/Dockerfile` builds the plaintext benchmark and CBC dependencies. A
Gramine package/image and SGX device/DCAP passthrough must be supplied by the
deployment environment; the repository does not silently fall back to OFF or
to the existing SIM path.
