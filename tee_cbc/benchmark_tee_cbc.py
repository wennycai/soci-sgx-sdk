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

DATASET: frozen, never regenerated here.  `prepare_tee_cbc_data.py` is a
one-time preparation step whose output is committed together with its
provenance; this harness only ever *verifies*.  Given `--dataset-provenance`
it hashes the `costs.tsv` it is about to feed to both modes and refuses to
start unless the digest matches, because a dataset regenerated per run would
let a result drift away from the results it is being compared against without
anything in the report showing it.  The provenance's row count is also an
upper bound on the matrix: asking for more rows than the frozen file holds is
refused rather than silently truncated, which is what keeps larger row counts
available later - prepare a larger frozen dataset and point at it.

Three timings are reported per run:

- `external_wall_time`: measured by this process with a monotonic clock around
  the child process, i.e. the full end-to-end cost including Gramine startup.
- `internal_total_time`: the child's own `total_runtime_seconds`.
- `cbc_solver_time`:     the child's own `cbc_runtime_seconds`.

CONSISTENT vs ACCEPTED - two different questions, deliberately separate:

- `consistent` asks only whether Native and Gramine-direct *agree*.  Two modes
  that both time out do agree, and a group in which only some repetitions
  survived agrees on those survivors.  It is a diagnostic, not a verdict.
- `accepted` is the acceptance verdict and drives the exit code.  On top of
  agreement it requires every repetition of both modes to have succeeded -
  zero timeout / solver_error / infeasible / harness_error - with results
  stable inside each mode, no CBC intermediates left behind, and real samples
  on both sides.  An unverified dataset also blocks it.

Reading `consistent` as a pass is precisely the false green this split exists
to prevent.

Failure handling: `timeout`, `solver_error` and `infeasible` are each counted
separately and are never mixed into the performance samples, and a failing
group never aborts the matrix.

Time limits: `--timeout` is CBC's own internal limit and defaults to 0, which
disables it.  That is deliberate - CBC derives it from `CoinCpuTime()`, which
Gramine does not report relative to the process, so any finite internal limit
reads as already exhausted at startup and CBC bails out of preprocessing with
a bogus infeasibility.  `--wall-timeout` is the out-of-process monotonic bound
and is authoritative in both modes; on expiry the child's whole process group
is signalled, not just the direct child.

Exit codes: 0 accepted, 1 not accepted, 3 refused before measuring (dataset
mismatch, matrix wider than the dataset).
"""

import argparse
import hashlib
import json
import math
import os
import pathlib
import signal
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
# Grace period between SIGTERM and SIGKILL when a run overruns --wall-timeout.
TERM_GRACE_SECONDS = 5.0
# CBC's intermediates.  The benchmark unlinks these on every exit path, so
# anything still present after a run belonged to a process that was killed
# mid-solve.  They are swept after *every* run, not only after a timeout:
# residue behind a clean exit means the RAII cleanup has a hole, and either way
# a stale file would be read as the next run's output.
RESIDUE_PATTERNS = ("*.lp", "*.sol", "*.log")


def failure_detail(stdout, stderr, returncode):
    """Best available explanation for a non-zero exit.

    The benchmark reports validation failures ("CBC solution violates ...")
    on stdout, not stderr, so stdout is consulted first; Gramine's unavoidable
    stderr banner is filtered out either way.
    """
    for stream in (stdout, stderr):
        lines = [line.strip() for line in (stream or "").splitlines()
                 if line.strip() and not any(n in line for n in GRAMINE_NOISE)]
        if lines:
            return " | ".join(lines)[:200]
    return f"exit {returncode}"


def sweep_residue(directories):
    """Remove CBC intermediates left behind by a killed run and report them.

    Never silently swallowed: `residue_runs` blocks acceptance.  Leaving the
    files would also be a confidentiality regression in the native control,
    whose .lp/.sol/.log are plaintext, and would break the host-side
    "no plaintext residue" assertion the security regression relies on.
    """
    removed = []
    for directory in directories:
        base = pathlib.Path(directory)
        if not base.is_dir():
            continue
        for pattern in RESIDUE_PATTERNS:
            for path in sorted(base.glob(pattern)):
                try:
                    path.unlink()
                    removed.append(str(path))
                except OSError as error:
                    removed.append(f"{path} (unlink failed: {error})")
    return removed


def kill_process_group(process):
    """SIGTERM then SIGKILL the child's entire process group.

    `run_once` starts the child with `start_new_session=True`, so it leads its
    own process group and one `killpg` reaches gramine-direct and the CBC
    process it spawned.  Signalling only the direct child would leave CBC
    running: it would keep burning the CPU the next repetition is about to be
    measured on, and keep the encrypted /work mount busy.  Returns True if the
    group had to be escalated to SIGKILL.
    """
    escalated = False
    for signum in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(process.pid, signum)
        except OSError:
            # Already gone, or not ours to signal.  Still fall through to
            # communicate(): the child has to be drained and reaped either way,
            # or it stays a zombie holding its pipes open.
            pass
        escalated = signum is signal.SIGKILL
        try:
            # communicate() rather than wait(): the pipes may still hold
            # output, and wait() on a full pipe deadlocks.
            process.communicate(timeout=TERM_GRACE_SECONDS)
            return escalated
        except subprocess.TimeoutExpired:
            continue
    process.kill()
    process.communicate()
    return True


def nearest_rank(values, percentile=0.95):
    """P95 by nearest rank, matching scripts/benchmark_constraint_binding.py."""
    ordered = sorted(values)
    return ordered[math.ceil(len(ordered) * percentile) - 1]


def statistics_for(values):
    if not values:
        return {"median": None, "p95": None}
    return {"median": statistics.median(values), "p95": nearest_rank(values)}


def run_once(runner, mode, rows, threshold, timeout, wall_timeout,
             residue_dirs=()):
    """Run one benchmark process and classify its outcome.

    Never raises: a crashed or unparseable child is reported as
    `harness_error` so that one bad group cannot abort the whole matrix.
    """
    command = [runner, mode, str(rows), threshold, str(timeout)]
    start = time.monotonic()
    try:
        # start_new_session puts the child in its own session and process
        # group.  subprocess.run(timeout=...) would kill only this direct child
        # - run_tee_cbc.sh - and orphan gramine-direct and CBC underneath it;
        # the timeout path below signals the whole group instead.
        process = subprocess.Popen(command, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True,
                                   start_new_session=True)
    except OSError as error:
        return {"outcome": "harness_error",
                "external_wall_time": time.monotonic() - start,
                "detail": f"{type(error).__name__}: {error}"[:200]}
    try:
        # This monotonic wall clock is the authoritative time limit, and with
        # the default `--timeout 0` it is the *only* one: CBC's internal limit
        # is driven by CoinCpuTime(), which Gramine does not report relative to
        # the process, so any finite internal limit reads as already exhausted
        # at startup (see README).  Bounding the run from out here keeps native
        # and Gramine-direct on an identical solver configuration.
        stdout, stderr = process.communicate(timeout=wall_timeout)
    except subprocess.TimeoutExpired:
        # The run genuinely exceeded its time budget: a timeout sample, not a
        # harness fault.  Counted separately, never a performance sample.
        escalated = kill_process_group(process)
        return {"outcome": "timeout", "status": "timeout",
                "external_wall_time": time.monotonic() - start,
                "killed_process_group": True,
                "escalated_to_sigkill": escalated,
                "residue_removed": sweep_residue(residue_dirs),
                "detail": f"external wall-clock limit {wall_timeout}s exceeded"}
    wall = time.monotonic() - start
    # A killed run cannot have cleaned up after itself, and a clean run that
    # still leaves files behind is a defect worth failing on, so this runs on
    # every path.
    residue = sweep_residue(residue_dirs)
    if process.returncode != 0:
        # The benchmark exits non-zero only when its own one-hot / ratio /
        # objective validation rejects the CBC solution.  That is a
        # correctness fault, not a performance sample and not a solver error.
        return {"outcome": "harness_error", "external_wall_time": wall,
                "residue_removed": residue,
                "detail": failure_detail(stdout, stderr, process.returncode)}
    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError:
        return {"outcome": "harness_error", "external_wall_time": wall,
                "residue_removed": residue,
                "detail": failure_detail(stdout, stderr, process.returncode)}
    status = payload.get("optimality_status")
    if status in SUCCESS_STATUSES:
        outcome = "success"
    elif status in FAILURE_STATUSES:
        outcome = status
    else:
        outcome = "harness_error"
    return {"outcome": outcome, "status": status, "external_wall_time": wall,
            "residue_removed": residue,
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
    counters = {
        "timeout_runs": sum(s["outcome"] == "timeout" for s in samples),
        "solver_error_runs": sum(s["outcome"] == "solver_error" for s in samples),
        "infeasible_runs": sum(s["outcome"] == "infeasible" for s in samples),
        "harness_error_runs": sum(s["outcome"] == "harness_error" for s in samples),
        "residue_runs": sum(bool(s.get("residue_removed")) for s in samples),
    }
    # Acceptance is all-or-nothing per mode.  A group in which only some
    # repetitions survived can still look consistent across modes - the
    # survivors do agree - so completeness has to be tracked separately from
    # agreement or a partly failed matrix reads as green.
    complete = (bool(samples) and len(successful) == len(samples)
                and not any(counters.values()) and stable)
    return {
        "stage": STAGE_LABEL if mode == "direct" else "Native",
        "dataset": dataset, "rows": rows, "threshold": float(threshold),
        "mode": mode, "repetitions": len(samples),
        "successful_runs": len(successful), **counters, "complete": complete,
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
        "residue_details": [path for s in samples
                            for path in s.get("residue_removed") or ()][:6],
    }


def close(left, right):
    if left is None or right is None:
        return left is None and right is None
    return abs(left - right) <= TOLERANCE * max(1.0, abs(left), abs(right))


def compare(native, direct):
    """Cross-mode agreement (`consistent`) and the acceptance verdict (`accepted`).

    These are answers to different questions and must not be collapsed:

    - `consistent` is agreement only.  Two modes that both time out agree, and
      a group where 3 of 10 repetitions survived agrees on those 3.
    - `accepted` additionally demands that both modes ran to completion, so
      neither of those cases can pass.  It is what the exit code follows.
    """
    checks = {
        "objective_match": close(native["objective"], direct["objective"]),
        "ratio_match": close(native["ratio"], direct["ratio"]),
        "solution_match": native["solution"] == direct["solution"],
        "optimality_status_match":
            native["optimality_status"] == direct["optimality_status"],
    }
    # "comparable" means there are performance samples on both sides.  Two
    # modes can still *agree* without being comparable - both infeasible, both
    # timed out - which is reported, but is never an acceptance pass: there is
    # nothing to compare and no evidence the run did what it claims.
    comparable = native["successful_runs"] > 0 and direct["successful_runs"] > 0
    agreed_without_samples = (
        not comparable and native["optimality_status"] is not None
        and native["optimality_status"] == direct["optimality_status"])
    consistent = (comparable and all(checks.values())) or agreed_without_samples
    accepted = comparable and native["complete"] and direct["complete"] \
        and all(checks.values())
    reasons = []
    for mode, group in (("native", native), ("direct", direct)):
        if not group["complete"]:
            reasons.append(
                f"{mode}: {group['successful_runs']}/{group['repetitions']} ok, "
                f"timeout={group['timeout_runs']} "
                f"solver_error={group['solver_error_runs']} "
                f"infeasible={group['infeasible_runs']} "
                f"harness_error={group['harness_error_runs']} "
                f"residue={group['residue_runs']} "
                f"self_consistent={group['self_consistent']}")
    if not comparable:
        reasons.append("no successful samples on both sides")
    reasons.extend(name for name, passed in checks.items() if not passed)
    return {"rows": native["rows"], "threshold": native["threshold"],
            "comparable": comparable,
            "agreed_without_samples": agreed_without_samples,
            "consistent": consistent, "accepted": accepted,
            "rejection_reasons": [] if accepted else reasons, **checks}


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


def refuse(message):
    """Abort before measuring anything.

    Distinct from an acceptance failure (exit 1): nothing was measured, so
    there is no result to report - the inputs were wrong.
    """
    print(json.dumps({"stage": STAGE_LABEL, "refused": message}), file=sys.stderr)
    raise SystemExit(3)


def verify_dataset(path, provenance_path, rows_matrix):
    """Check the frozen costs.tsv against its committed provenance.

    The dataset is prepared once and then frozen, so the only thing left to do
    at run time is prove that the file both modes are about to read is still
    the one the provenance - and every previously published result - describes.
    Fails closed: a mismatch aborts before a single measurement is taken,
    because a report produced from unknown data is worse than no report.
    """
    try:
        with open(provenance_path) as handle:
            provenance = json.load(handle)
        digest = hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()
    except (OSError, json.JSONDecodeError) as error:
        refuse(f"cannot verify dataset: {type(error).__name__}: {error}")
    expected = provenance.get("costs_sha256")
    if digest != expected:
        refuse(f"dataset sha256 mismatch for {path}: expected {expected}, "
               f"found {digest}. The dataset is frozen; regenerate it only via "
               f"prepare_tee_cbc_data.py --force and re-commit the provenance.")
    # The binary reads the first ROWS lines, so a matrix wider than the frozen
    # file would silently measure fewer rows than it reports.  Refused instead:
    # larger row counts stay available, they just need their own frozen dataset.
    available = provenance.get("rows")
    if rows_matrix and isinstance(available, int) and max(rows_matrix) > available:
        refuse(f"matrix asks for {max(rows_matrix)} rows but the frozen dataset "
               f"holds {available}; prepare a larger dataset and point "
               f"--dataset-file/--dataset-provenance at it")
    return {"verified": True, "path": path, "provenance": provenance_path,
            "sha256": digest, "rows": available,
            "workbook_sha256": provenance.get("workbook_sha256")}


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
    parser.add_argument("--dataset-file",
                        help="the frozen costs.tsv both modes will read")
    parser.add_argument("--dataset-provenance",
                        help="committed provenance JSON carrying the expected "
                             "costs_sha256; without it the run cannot be "
                             "accepted, only explored")
    parser.add_argument("--residue-dir", action="append", default=[],
                        dest="residue_dirs", metavar="DIR",
                        help="directory to sweep for leftover CBC .lp/.sol/"
                             ".log after every run; repeatable")
    parser.add_argument("--output", help="write the full result JSON here")
    args = parser.parse_args()

    rows_matrix = [int(value) for value in args.rows.split(",") if value]
    thresholds = [value for value in args.thresholds.split(",") if value]
    if args.dataset_file and args.dataset_provenance:
        dataset_info = verify_dataset(args.dataset_file,
                                      args.dataset_provenance, rows_matrix)
    else:
        # Exploratory runs are still allowed, they just cannot claim
        # acceptance: an unverified dataset makes every number unattributable.
        dataset_info = {"verified": False, "path": args.dataset_file,
                        "provenance": args.dataset_provenance, "sha256": None,
                        "reason": "--dataset-file/--dataset-provenance not given"}

    groups, comparisons = [], []
    for rows in rows_matrix:
        for threshold in thresholds:
            by_mode = {}
            for mode in MODES:
                samples = [run_once(args.runner, mode, rows, threshold,
                                    args.timeout, args.wall_timeout,
                                    args.residue_dirs)
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
    rejected = [c for c in comparisons if not c["accepted"]]
    # An unverified dataset blocks acceptance on its own: the measurements may
    # be internally perfect and still describe a file nobody can identify.
    accepted = (bool(comparisons) and not rejected
                and bool(dataset_info.get("verified")))
    rejected_groups = [{"rows": c["rows"], "threshold": c["threshold"],
                        "reasons": c["rejection_reasons"]} for c in rejected]
    if not rejected_groups and not accepted:
        rejected_groups = [{"reasons": [
            "no comparisons were run" if not comparisons
            else "dataset not verified: " + str(dataset_info.get("reason"))]}]
    report = {
        "stage": STAGE_LABEL,
        "note": ("Gramine-direct is a functional simulation. These numbers are "
                 "NOT SGX HW performance and NOT Intel SGX SDK SIM. Real "
                 "hardware acceptance runs later via run_tee_cbc.sh sgx."),
        "acceptance_rule": ("accepted requires every repetition of both modes "
                            "to succeed with zero timeout/solver_error/"
                            "infeasible/harness_error and no CBC residue, plus "
                            "cross-mode agreement and a verified dataset. "
                            "consistent reports agreement ALONE and is not a "
                            "pass."),
        "dataset": args.dataset, "dataset_verification": dataset_info,
        "repetitions": args.repetitions,
        "cbc_internal_timeout_seconds": args.timeout,
        "wall_timeout_seconds": args.wall_timeout, "rows": rows_matrix,
        "thresholds": [float(value) for value in thresholds],
        "modes": list(MODES), "groups": groups, "comparisons": comparisons,
        "consistent": not inconsistent,
        "inconsistent_groups": [{"rows": c["rows"], "threshold": c["threshold"]}
                                for c in inconsistent],
        "accepted": accepted, "rejected_groups": rejected_groups,
    }
    if args.output:
        with open(args.output, "w") as handle:
            json.dump(report, handle, indent=2)
            handle.write("\n")
    print(json.dumps({"stage": report["stage"], "accepted": accepted,
                      "consistent": report["consistent"],
                      "dataset_verified": dataset_info.get("verified"),
                      "rejected_groups": rejected_groups,
                      "output": args.output}, separators=(",", ":")))
    # The verdict is `accepted`, never `consistent`: agreement between two
    # modes that both failed is agreement, not acceptance.
    return 0 if accepted else 1


if __name__ == "__main__":
    sys.exit(main())
