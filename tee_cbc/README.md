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
- **Encryption keys are distinct per mount.**
  - `/input` uses `key_name = "input_key"`: the cost data is prepared
    **outside** the enclave by the data owner with `gramine-sgx-pf-crypt`.
    Production provisioning of `input_key` (a 16-byte wrap key installed via
    remote attestation + Gramine secret provisioning) is **TODO**; until such
    a provisioning service exists, the mount cannot be decrypted. Do not use
    `fs.insecure__keys` in production.
  - `/work` uses `key_name = "_sgx_mrenclave"`, one of Gramine's
    measurement-derived SGX PAL special keys. These files are enclave-local
    CBC intermediates created and consumed inside the enclave, so binding
    them to the enclave measurement is exactly right.
  The direct (simulation) manifest mirrors this split structurally but uses
  an insecure fixed key, acceptable only because direct mode makes no
  confidentiality claims.
- **CBC intermediates never touch the host filesystem as plaintext.** The LP
  model, solution and solver log are written under `SOCI_CBC_TMPDIR=/work`,
  an in-Gramine **encrypted** filesystem mount: the host only ever sees
  ciphertext, and the benchmark removes the files on every exit path
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

Prepare an encrypted `costs.tsv` under `TEE_CBC_DATA_DIR` for the SGX mode.
The data owner encrypts it with `gramine-sgx-pf-crypt` under the wrap key
that the enclave knows as `input_key`; provisioning that key through remote
attestation + Gramine secret provisioning is the remaining TODO for
production.

## Run

```bash
TEE_CBC_DATA_DIR=/sealed/input \
  tee_cbc/run_tee_cbc.sh native 410 0.5 60

# Under Gramine the last argument MUST be 0: CBC's own time limit is unusable
# there and produces bogus infeasibility, so run_tee_cbc.sh rejects anything
# else. Bound these runs externally instead. See "Why CBC's internal time
# limit is disabled" below.
TEE_CBC_DATA_DIR=/sealed/input \
  tee_cbc/run_tee_cbc.sh direct 410 0.5 0

TEE_CBC_DATA_DIR=/sealed/input \
  tee_cbc/run_tee_cbc.sh sgx 410 0.5 0
```

Only the final benchmark JSON is printed. The host supplies public rows,
threshold, and timeout; costs and CBC intermediate state are read and processed
inside Gramine. This PoC does not implement remote attestation or a production
secret-provisioning service.

`native` runs the same benchmark binary directly on plain Linux, outside
Gramine. It is the performance control for the comparison below; it makes no
confidentiality claim and its CBC intermediates go to a separate work directory
so they never mix with the encrypted `/work` backing store.

## Performance acceptance

**Scope and labelling — read this before quoting any number.**

- This is a **Gramine-direct simulated performance acceptance**. Every result
  produced here is labelled `Gramine-direct / SIM-functional`.
- It is **not an SGX HW benchmark**, not "SGX performance", not "real TEE
  overhead", and not equivalent to Intel SGX SDK SIM. Gramine-direct executes
  the binary through the Gramine LibOS with no enclave, no EPC, no memory
  encryption and no attestation, so it captures LibOS syscall-emulation cost
  only.
- The comparison metric is therefore named `gramine_direct_vs_native_overhead`,
  never `tee_overhead`.
- **Real hardware data will be added later** through
  `tee_cbc/run_tee_cbc.sh sgx` on an SGX server. That entry point is kept
  wired up but is deliberately never invoked by the acceptance script at this
  stage. The dataset, metrics and JSON result format are identical between the
  two stages so the HW numbers can be dropped into the same tables.

The acceptance compares two modes over a fixed matrix — rows
`10 / 200` × threshold `0.5 / 0.7 / 0.8`, `binding` dataset, 10 repetitions
per point:

| mode | what it is |
| --- | --- |
| `native` | `soci_cbc_plaintext_benchmark` on plain Linux |
| `direct` | the same binary under `gramine-direct` (`Gramine-direct / SIM-functional`) |

Each point is validated as well as timed: `objective`, `solution`, `ratio` and
`optimality_status` must agree between the two modes. Both
`optimal_verified` and `cheapest_global_optimum` count as success;
`timeout`, `solver_error` and `infeasible` are counted separately and are
never mixed into the performance samples, and a failing group never aborts the
run.

Metrics, per group: `external_wall_time` (measured out-of-process by the
harness with a monotonic clock), `internal_total_time`
(`total_runtime_seconds`), `cbc_solver_time` (`cbc_runtime_seconds`) — each
reported as median and P95.

### Reading the overhead numbers

`gramine_direct_vs_native_overhead` reports both an absolute delta and a
percentage; **the absolute delta is the only figure to quote, and on the
current matrix the percentage is never meaningful at all.**

Gramine's cost on this workload is an essentially constant per-process startup
charge of roughly 0.65 s. Every group in the 10/200-row matrix has a native
baseline of 8–35 ms, so the percentage is that constant divided by another
constant: it lands in the 1000–9000 % range and describes nothing about the
loader. All such groups are marked `percent_meaningful: false` (the threshold
is `PERCENT_FLOOR_SECONDS`, 0.5 s).

**Be explicit about what this therefore does and does not establish.** It
establishes that Native and Gramine-direct agree on every answer, and it
measures Gramine's startup cost at roughly 0.65 s. It does **not** measure how
the Gramine loader scales with solver work, because no point in the current
matrix is solver-dominated. The one row count that was solver-dominated,
rows=400 at T=0.8, was removed: it is a hard-knapsack outlier needing ~7.7M
branch-and-bound nodes and ~23 s (independently reproduced at 33 s with PuLP's
own bundled CBC, so it is a property of the instance, not of this harness or
of Gramine). Difficulty on this model is wildly non-monotonic in row count —
300 rows solves in 0.024 s, 400 rows in 23 s, 410 rows in 0.029 s — so a
solver-dominated point cannot be recovered just by picking a larger size.

### Why CBC's internal time limit is disabled

`--timeout` (CBC's own `seconds` limit) **defaults to 0, which switches it
off**; `--wall-timeout` (default 600 s), measured out-of-process by the
harness with a monotonic clock, is the authoritative bound in both modes.

This is not a convenience default. CBC derives its internal limit from
`CoinCpuTime()`, and Gramine does not report CPU-time clocks relative to the
process — `CLOCK_PROCESS_CPUTIME_ID` comes back at epoch scale (≈1.79e9 s) and
`times()` returns a negative value. Any finite internal limit therefore reads
as already exhausted the moment CBC starts, so CBC bails out during CGL
preprocessing and writes its fractional root relaxation as `Integer
infeasible` instead of the true optimum. Passing a non-zero `--timeout` in
`direct` mode yields wrong answers, not slow ones.

Measured on the 6-row regression instance: `seconds 60` gives `Integer
infeasible` in 10/10 Gramine runs, while dropping the clause gives the correct
optimum in 10/10. `run_tee_cbc.sh` therefore **rejects** a non-zero `TIMEOUT`
in `direct` and `sgx` mode rather than silently overriding it — the failure it
guards against is a wrong answer, not a slow one. (`seconds 0` is not a way to
express "no limit": CBC reads it as a zero-second budget and fails the same
way, so the clause has to be omitted entirely.) The `sgx` guard is applied by
inference from the shared Gramine clock emulation and still has to be
confirmed on real hardware.

The same broken clocks are why the benchmark invokes CBC with `-log 0`:
`CoinMessageHandler` formats those epoch-scale timings into a fixed-size
buffer and glibc `_FORTIFY_SOURCE` aborts the process (`*** buffer overflow
detected ***`, SIGABRT) at roughly 100 rows and above. `-log 1` does not avoid
it; only `-log 0` does. It is applied in **both** modes so native and
Gramine-direct run an identical solver configuration — at the cost of CBC's
node and iteration counters, which are no longer recoverable from the log, so
`cbc_nodes` and `lp_iterations` report 0. (`steady_clock` remains usable under
Gramine: it is epoch-shifted too, but the benchmark only ever takes
differences, so `cbc_runtime_seconds` and `total_runtime_seconds` stay valid.)

```bash
# full acceptance (builds, prepares the dataset, runs both modes)
scripts/run_tee_cbc_benchmark.sh

# or in Docker, behind the `benchmark` profile
docker compose -f docker/compose.tee-cbc.yaml --profile benchmark up --build \
  --abort-on-container-exit --exit-code-from tee_cbc_benchmark
```

The dataset is materialised by `tee_cbc/prepare_tee_cbc_data.py` from
`examples/optimization-demo/sample-costs-410.xlsx`, which has 410 real rows.
The matrix tops out at 200 rows, so **the acceptance data is 100% real: no
rows are synthesised** and the provenance record reports
`"extension": "none", "synthetic_rows": 0`. Row counts are prefix-stable
(rows=200 is the first 200 lines of the file) and the file carries a sha256
digest so a later SGX HW run can prove it used the same input.

The script can still extend past 410 via `--rows` — it resamples whole real
rows with a fixed seed (915017) plus ±10% jitter and records the result as a
synthetic extension — but the acceptance no longer uses that path.

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
Gramine-direct, solver-failure cleanup, offline signing of the strict SGX
manifest with a throwaway key, and host-side residue checks (no
`.lp`/`.sol`/`.log` anywhere after the runs). Runtime fail-closed validation
still requires SGX hardware. SGX device/DCAP passthrough must be supplied by
the deployment environment; the repository does not silently fall back to OFF
or to the existing SIM path.
