#!/usr/bin/env python3
"""Native vs Gramine-direct CBC acceptance benchmark.

STAGE LABEL: "Gramine-direct / SIM-functional".

Gramine-direct is a FUNCTIONAL SIMULATION.  It is neither Intel SGX SDK SIM
nor a real SGX enclave, so nothing produced here may be reported as "SGX
performance", "real TEE overhead" or "SGX HW performance".  The cross-mode
delta is therefore named `gramine_direct_vs_native_overhead`, never
`tee_overhead`.  The real hardware entry point (`run_tee_cbc.sh sgx`) is
deliberately not exercised by this harness; once an SGX server is available it
reuses the same dataset, the same metrics and the same result schema.

Both modes execute the *same* `soci_cbc_plaintext_benchmark` binary on the
*same* `costs.tsv` (`run_tee_cbc.sh` resolves both from what
`build_tee_cbc.sh` baked into the manifest), so the only difference between
the two columns is the Gramine loader.

Three timings are reported per run:

- `external_wall_time`: measured by this process with a monotonic clock around
  the child process, i.e. the full end-to-end cost including Gramine startup.
- `internal_total_time`: the child's own `total_runtime_seconds`.
- `cbc_solver_time`:     the child's own `cbc_runtime_seconds`.

Failure handling: `timeout`, `solver_error` and `infeasible` are each counted
separately and are never mixed into the performance samples, and a failing
group never aborts the matrix.

Time limits: `--timeout` is CBC's own internal limit and defaults to 0, which
disables it.  That is deliberate - CBC derives it from `CoinCpuTime()`, which
Gramine does not report relative to the process, so any finite internal limit
reads as already exhausted at startup and CBC bails out of preprocessing with
a bogus infeasibility.  `--wall-timeout` is the out-of-process monotonic bound
and is authoritative in both modes.
"""

import argparse
import json
import math
import statistics
import subprocess
import sys
import time

STAGE_LABEL = "Gramine-direct / SIM-functional"
# Both count as a normal successful solve: "cheapest_global_optimum" means the
# per-row cheapest selection was already feasible and provably optimal, so CBC
# was correctly never invoked.
SUCCESS_STATUSES = ("optimal_verified", "cheapest_global_optimum")
# "infeasible" is a proven property of the instance, so it is kept apart from
# "solver_error": the latter must stay a pure environment-fault counter.  None
# of the three ever contributes a performance sample.
FAILURE_STATUSES = ("timeout", "solver_error", "infeasible")
# 400 and 800 were dropped from the matrix: 400/T=0.8 is a hard-knapsack
# outlier (7.7M branch-and-bound nodes, ~23s) that says nothing about the
# loader, and 800 was the only row count needing synthetic data.
DEFAULT_ROWS = (10, 200)
DEFAULT_THRESHOLDS = ("0.5", "0.7", "0.8")
# "native" is the plain-Linux control; "direct" is the Gramine-direct
# simulation.  "sgx" is intentionally absent - see the module docstring.
MODES = ("native", "direct")
# Relative tolerance for the cross-mode objective/ratio agreement check.  The
# two modes run the identical binary over the identical bytes, so an exact
# match is expected; the tolerance only absorbs JSON round-tripping.
TOLERANCE = 1e-9
# Below this native baseline the run is dominated by process startup rather
# than by solving, so the *percentage* overhead is a ratio of two constants and
# says nothing about the loader's cost at scale.  Such groups still report an
# absolute delta; the percentage is flagged as not meaningful.
PERCENT_FLOOR_SECONDS = 0.5
# Gramine writes these to stderr on every run.  They are not diagnostics and
# they are long enough to crowd the real message out of a truncated detail
# string, so they are dropped before a failure is reported.
GRAMINE_NOISE = ("Emulating a raw system/supervisor call",
                 "consider patching your application")


def failure_detail(completed):
    """Best available explanation for a non-zero exit.

    The benchmark reports validation failures ("CBC solution violates ...")
    on stdout, not stderr, so stdout is consulted first; Gramine's unavoidable
    stderr banner is filtered out either way.
    """
    for stream in (completed.stdout, completed.stderr):
        lines = [line.strip() for line in (stream or "").splitlines()
                 if line.strip() and not any(n in line for n in GRAMINE_NOISE)]
        if lines:
            return " | ".join(lines)[:200]
    return f"exit {completed.returncode}"


def nearest_rank(values, percentile=0.95):
    """P95 by nearest rank, matching scripts/benchmark_constraint_binding.py."""
    ordered = sorted(values)
    return ordered[math.ceil(len(ordered) * percentile) - 1]


def statistics_for(values):
    if not values:
        return {"median": None, "p95": None}
    return {"median": statistics.median(values), "p95": nearest_rank(values)}


def run_once(runner, mode, rows, threshold, timeout, wall_timeout):
    """Run one benchmark process and classify its outcome.

    Never raises: a crashed or unparseable child is reported as
    `harness_error` so that one bad group cannot abort the whole matrix.
    """
    command = [runner, mode, str(rows), threshold, str(timeout)]
    start = time.monotonic()
    try:
        # This monotonic wall clock is the authoritative time limit, and with
        # the default `--timeout 0` it is the *only* one: CBC's internal limit
        # is driven by CoinCpuTime(), which Gramine does not report relative to
        # the process, so any finite internal limit reads as already exhausted
        # at startup (see README).  Bounding the run from out here keeps native
        # and Gramine-direct on an identical solver configuration.
        completed = subprocess.run(command, capture_output=True, text=True,
                                   timeout=wall_timeout)
    except subprocess.TimeoutExpired:
        # The run genuinely exceeded its time budget: a timeout sample, not a
        # harness fault.  Counted separately, never a performance sample.
        return {"outcome": "timeout", "status": "timeout",
                "external_wall_time": time.monotonic() - start,
                "detail": f"external wall-clock limit {wall_timeout}s exceeded"}
    except OSError as error:
        return {"outcome": "harness_error",
                "external_wall_time": time.monotonic() - start,
                "detail": f"{type(error).__name__}: {error}"[:200]}
    wall = time.monotonic() - start
    if completed.returncode != 0:
        # The benchmark exits non-zero only when its own one-hot / ratio /
        # objective validation rejects the CBC solution.  That is a
        # correctness fault, not a performance sample and not a solver error.
        return {"outcome": "harness_error", "external_wall_time": wall,
                "detail": failure_detail(completed)}
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return {"outcome": "harness_error", "external_wall_time": wall,
                "detail": failure_detail(completed)}
    status = payload.get("optimality_status")
    if status in SUCCESS_STATUSES:
        outcome = "success"
    elif status in FAILURE_STATUSES:
        outcome = status
    else:
        outcome = "harness_error"
    return {"outcome": outcome, "status": status, "external_wall_time": wall,
            "internal_total_time": payload.get("total_runtime_seconds"),
            "cbc_solver_time": payload.get("cbc_runtime_seconds"),
            "objective": payload.get("total_cost"),
            "ratio": payload.get("ratio"),
            "solution": payload.get("solution"),
            "cbc_nodes": payload.get("cbc_nodes"),
            "lp_iterations": payload.get("lp_iterations")}


def summarise(dataset, rows, threshold, mode, samples):
    successful = [sample for sample in samples if sample["outcome"] == "success"]
    # With no successful run there is still a status worth reporting and worth
    # comparing across modes: two modes that agree the instance is infeasible
    # do agree, they just yield no performance samples.
    reference = next((s for s in samples if s["outcome"] == "success"),
                     next((s for s in samples if s.get("status")), {}))
    # Nondeterminism inside one mode would silently corrupt the medians, so
    # flag it here instead of only comparing across modes.
    stable = all(sample.get("objective") == reference.get("objective") and
                 sample.get("solution") == reference.get("solution")
                 for sample in successful)
    return {
        "stage": STAGE_LABEL if mode == "direct" else "Native",
        "dataset": dataset, "rows": rows, "threshold": float(threshold),
        "mode": mode, "repetitions": len(samples),
        "successful_runs": len(successful),
        "timeout_runs": sum(s["outcome"] == "timeout" for s in samples),
        "solver_error_runs": sum(s["outcome"] == "solver_error" for s in samples),
        "infeasible_runs": sum(s["outcome"] == "infeasible" for s in samples),
        "harness_error_runs": sum(s["outcome"] == "harness_error" for s in samples),
        "external_wall_time": statistics_for([s["external_wall_time"] for s in successful]),
        "internal_total_time": statistics_for([s["internal_total_time"] for s in successful]),
        "cbc_solver_time": statistics_for([s["cbc_solver_time"] for s in successful]),
        "objective": reference.get("objective"),
        "ratio": reference.get("ratio"),
        "optimality_status": reference.get("status"),
        "solution": reference.get("solution"),
        "cbc_nodes": reference.get("cbc_nodes"),
        "lp_iterations": reference.get("lp_iterations"),
        "self_consistent": stable,
        "failure_details": [s["detail"] for s in samples if "detail" in s][:3],
    }


def close(left, right):
    if left is None or right is None:
        return left is None and right is None
    return abs(left - right) <= TOLERANCE * max(1.0, abs(left), abs(right))


def compare(native, direct):
    """Cross-mode agreement on objective / solution / ratio / optimality_status."""
    checks = {
        "objective_match": close(native["objective"], direct["objective"]),
        "ratio_match": close(native["ratio"], direct["ratio"]),
        "solution_match": native["solution"] == direct["solution"],
        "optimality_status_match":
            native["optimality_status"] == direct["optimality_status"],
    }
    # "comparable" means there are performance samples on both sides.  Two
    # modes can still *agree* without being comparable - both infeasible, both
    # timed out - and that agreement is a passing acceptance result, so it is
    # tracked separately instead of being folded into a failure.
    comparable = native["successful_runs"] > 0 and direct["successful_runs"] > 0
    agreed_without_samples = (
        not comparable and native["optimality_status"] is not None
        and native["optimality_status"] == direct["optimality_status"])
    return {"rows": native["rows"], "threshold": native["threshold"],
            "comparable": comparable,
            "agreed_without_samples": agreed_without_samples,
            "consistent": ((comparable and all(checks.values()))
                           or agreed_without_samples), **checks}


def overhead(native, direct):
    """Gramine-direct minus Native, absolute seconds and percent.

    Deliberately NOT called `tee_overhead`: Gramine-direct is a functional
    simulation, so this is a loader delta, not an SGX enclave cost.

    The absolute delta is the primary figure.  Gramine's cost here is an
    essentially constant per-process startup charge, so on a group whose native
    baseline is itself only milliseconds the percentage is that constant
    divided by another constant - it inflates without bound as the baseline
    shrinks and describes nothing about the loader.  Those groups are marked
    `percent_meaningful: false` and their percentage must not be quoted.
    """
    result = {}
    for metric in ("external_wall_time", "internal_total_time", "cbc_solver_time"):
        entry = {}
        for point in ("median", "p95"):
            base, other = native[metric][point], direct[metric][point]
            if base is None or other is None:
                entry[f"{point}_absolute_seconds"] = None
                entry[f"{point}_percent"] = None
                continue
            entry[f"{point}_absolute_seconds"] = other - base
            entry[f"{point}_percent"] = ((other - base) / base * 100.0
                                         if base > 0 else None)
        base = native[metric]["median"]
        entry["percent_meaningful"] = (base is not None
                                       and base >= PERCENT_FLOOR_SECONDS)
        entry["percent_floor_seconds"] = PERCENT_FLOOR_SECONDS
        result[metric] = entry
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runner", default="tee_cbc/run_tee_cbc.sh")
    parser.add_argument("--repetitions", type=int, default=10)
    parser.add_argument("--timeout", type=int, default=0,
                        help="CBC's own internal time limit in seconds; 0 (the "
                             "default) disables it and leaves --wall-timeout "
                             "authoritative, which is required for "
                             "Gramine-direct - see README")
    parser.add_argument("--wall-timeout", type=int, default=600,
                        help="out-of-process wall-clock limit per run in "
                             "seconds (default: 600)")
    parser.add_argument("--rows", default=",".join(str(r) for r in DEFAULT_ROWS))
    parser.add_argument("--thresholds", default=",".join(DEFAULT_THRESHOLDS))
    parser.add_argument("--dataset", default="binding")
    parser.add_argument("--output", help="write the full result JSON here")
    args = parser.parse_args()

    rows_matrix = [int(value) for value in args.rows.split(",") if value]
    thresholds = [value for value in args.thresholds.split(",") if value]
    groups, comparisons = [], []
    for rows in rows_matrix:
        for threshold in thresholds:
            by_mode = {}
            for mode in MODES:
                samples = [run_once(args.runner, mode, rows, threshold,
                                    args.timeout, args.wall_timeout)
                           for _ in range(args.repetitions)]
                group = summarise(args.dataset, rows, threshold, mode, samples)
                by_mode[mode] = group
                groups.append(group)
                # Stream progress: a long matrix must show results as it goes.
                print(json.dumps(group, separators=(",", ":")), flush=True)
            comparison = compare(by_mode["native"], by_mode["direct"])
            comparison["gramine_direct_vs_native_overhead"] = overhead(
                by_mode["native"], by_mode["direct"])
            comparisons.append(comparison)
            print(json.dumps(comparison, separators=(",", ":")), flush=True)

    inconsistent = [c for c in comparisons if not c["consistent"]]
    report = {
        "stage": STAGE_LABEL,
        "note": ("Gramine-direct is a functional simulation. These numbers are "
                 "NOT SGX HW performance and NOT Intel SGX SDK SIM. Real "
                 "hardware acceptance runs later via run_tee_cbc.sh sgx."),
        "dataset": args.dataset, "repetitions": args.repetitions,
        "cbc_internal_timeout_seconds": args.timeout,
        "wall_timeout_seconds": args.wall_timeout, "rows": rows_matrix,
        "thresholds": [float(value) for value in thresholds],
        "modes": list(MODES), "groups": groups, "comparisons": comparisons,
        "consistent": not inconsistent,
        "inconsistent_groups": [{"rows": c["rows"], "threshold": c["threshold"]}
                                for c in inconsistent],
    }
    if args.output:
        with open(args.output, "w") as handle:
            json.dump(report, handle, indent=2)
            handle.write("\n")
    print(json.dumps({"stage": report["stage"],
                      "consistent": report["consistent"],
                      "inconsistent_groups": report["inconsistent_groups"],
                      "output": args.output}, separators=(",", ":")))
    # A consistency failure between Native and Gramine-direct is an acceptance
    # failure even when every individual run "succeeded".
    return 1 if inconsistent else 0


if __name__ == "__main__":
    sys.exit(main())
