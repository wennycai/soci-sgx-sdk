#!/usr/bin/env python3
"""Repeat native-vs-Gramine CBC runs without exposing input costs to the caller."""
import argparse
import json
import statistics
import subprocess
import time


def p95(values):
    values = sorted(values)
    return values[max(0, min(len(values) - 1, int((len(values) - 1) * .95 + .999999)))]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("data_root", help="directory containing easy/binding/<rows>/costs.tsv")
    ap.add_argument("--runner", default="tee_cbc/run_tee_cbc.sh")
    ap.add_argument("--repetitions", type=int, default=10)
    ap.add_argument("--timeout", type=int, default=60)
    args = ap.parse_args()
    for dataset in ("binding",):
        for rows in (410, 1000, 2000, 5000):
            for threshold in ("0.5", "0.7", "0.8"):
                for mode in ("direct", "sgx"):
                    samples = []
                    for _ in range(args.repetitions):
                        start = time.monotonic()
                        command = [args.runner, mode, str(rows), threshold,
                                   str(args.timeout),
                                   f"{args.data_root}/{dataset}/{rows}"]
                        result = subprocess.run(command, check=True,
                                                capture_output=True, text=True)
                        total = time.monotonic() - start
                        payload = json.loads(result.stdout)
                        solver = payload.get("cbc_runtime_seconds", 0.0)
                        samples.append((total, solver, total - solver, payload))
                    print(json.dumps({
                        "dataset": dataset, "rows": rows,
                        "threshold": float(threshold), "mode": mode,
                        "repetitions": len(samples),
                        "total_runtime_median": statistics.median(x[0] for x in samples),
                        "total_runtime_p95": p95([x[0] for x in samples]),
                        "solver_runtime_median": statistics.median(x[1] for x in samples),
                        "solver_runtime_p95": p95([x[1] for x in samples]),
                        "tee_overhead_median": statistics.median(x[2] for x in samples),
                        "tee_overhead_p95": p95([x[2] for x in samples]),
                        "objective": samples[0][3].get("total_cost"),
                        "status": samples[0][3].get("optimality_status"),
                    }, separators=(",", ":")))


if __name__ == "__main__":
    main()
