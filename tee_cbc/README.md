# Independent Gramine + CBC TEE PoC

This directory is an independent plaintext MILP comparison route. It runs the
existing COIN-OR CBC executable under Gramine; it does not reimplement CBC and
does not modify the HE/CP-CSP, Paillier, PredicateEngine, PEGA, or existing SGX
paths. It is fully decoupled from the core SDK build and the OFF/SIM CI: it
uses its own Dockerfile, compose file and test script.

The application is the existing `soci_cbc_plaintext_benchmark`
(`EXCLUDE_FROM_ALL`; built only via `--target`). It retains the
cheapest-fast-path → CBC Exact flow and the CBC one-hot, ratio, and objective
recomputation checks.

## Security boundary

- **Host-visible input** is limited to the public parameters: rows, threshold,
  timeout. Costs are read only inside Gramine from `/input` (an encrypted
  Gramine filesystem mount in the SGX manifest; a plain chroot mount in the
  direct simulation).
- **Host-visible output** is limited to the final authorized JSON: solution,
  total_cost, ratio, optimality_status and performance counters. CBC
  incumbents, bounds, cuts, LP content and raw costs are never printed.
- **CBC intermediates never touch the host filesystem as plaintext.** The LP
  model, solution and solver log are written under `SOCI_CBC_TMPDIR=/work`,
  an in-Gramine **encrypted** filesystem mount: the host only ever sees
  ciphertext (keyed with the measurement-derived `_sgx_mrenclave` key in the
  SGX manifest), and the benchmark removes the files on every exit path
  (success, timeout, solver failure, validation error). A plain Gramine
  `tmpfs` cannot be used for this: Gramine tmpfs is per-process, so the CBC
  child process could not read the parent's LP file. `/opt/tee_cbc` holds
  only the static benchmark binary and is not a CBC work directory.
- **The SGX manifest is fail-closed.** `sgx.file_check_policy = "strict"`,
  no `allowed_files`, and `sgx.trusted_files` lists the concrete CBC binary,
  benchmark binary, `/bin/sh` and their `ldd`-enumerated libraries
  individually — no whole-directory trust. A missing dependency aborts
  `gramine-sgx-sign` or enclave launch instead of being silently accepted.
- **Gramine-direct is a functional simulation only.** It provides no SGX
  confidentiality and must never be cited as an SGX security or performance
  result. Real `gramine-sgx` hardware validation (including remote
  attestation and production key provisioning) is still TODO.

## Build

Install Gramine using its official instructions, install CBC, and set an SGX
signing key for the SGX manifest:

```bash
export SGX_SIGNING_KEY=/path/to/gramine-sgx-signing-key.pem  # RSA-3072
tee_cbc/build_tee_cbc.sh build/scalable
```

This renders mode-specific manifests under `build/tee_cbc/direct/` (strict
mount namespace, functional simulation) and `build/tee_cbc/sgx/` (strict,
fail-closed), and signs the SGX manifest offline. Offline signing verifies
that every trusted file resolves; launching the enclave still requires SGX
hardware. Set `TEE_CBC_BUILD_SGX=0` to skip signing.

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

`tee_cbc/Dockerfile` is a standalone image (Gramine + CBC + the benchmark,
built with `SOCI_SGX_MODE=OFF`). It is fully decoupled from the core SDK
build and the SIM CI image, and does not depend on any pre-existing local
image. The Gramine-direct regression runs via its own compose file, outside
the default OFF/SIM CI:

```bash
docker compose -f docker/compose.tee-cbc.yaml up --build \
  --abort-on-container-exit --exit-code-from tee_cbc_direct
docker compose -f docker/compose.tee-cbc.yaml down --volumes
```

The regression covers: CBC Exact and cheapest-fast-path runs under
Gramine-direct, solver-failure cleanup, a fail-closed probe (an undeclared
host file must be unreadable), offline signing of the strict SGX manifest
with a throwaway key, and host-side residue checks (no `.lp`/`.sol`/`.log`
anywhere after the runs). SGX device/DCAP passthrough must be supplied by the
deployment environment; the repository does not silently fall back to OFF or
to the existing SIM path.
