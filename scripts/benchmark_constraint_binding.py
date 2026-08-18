#!/usr/bin/env python3
"""Benchmark GA on data where the ratio constraint forces expensive choices."""

import json
import statistics
import subprocess
import sys
import tempfile


def make_rows(count):
    # method3 is always cheapest.  method1/2 have deliberately varied
    # localization deltas, so the cheapest feasible subset is non-trivial.
    rows = []
    for i in range(count):
        m3 = 1.0 + (i % 7) * 0.35
        m1 = 7.0 + ((i * 17) % 23) * 0.83 + (i % 5) * 0.11
        m2 = m1 + 0.4 + (i % 3) * 0.07
        rows.append((m1, m2, m3))
    return rows


def run(executable, path, rows, population, generations, seed):
    output = subprocess.check_output(
        [executable, path, str(rows), str(population), str(generations), str(seed)],
        text=True)
    return json.loads(output)


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: benchmark_constraint_binding.py EXECUTABLE")
    executable = sys.argv[1]
    with tempfile.NamedTemporaryFile(mode="w", suffix=".tsv") as data:
        for row in make_rows(410):
            data.write("\t".join(f"{value:.6f}" for value in row) + "\n")
        data.flush()
        small = []
        for rows in (10, 20, 30):
            for seed in range(30):
                small.append(run(executable, data.name, rows, 512, 3000, seed + 1))
        exact = [item for item in small if item["rows"] == 30]
        gaps = [item["optimality_gap"] for item in small]
        representative = run(executable, data.name, 30, 512, 3000, 1)
        large = []
        for rows in (100, 200, 410):
            for seed in range(20):
                large.append(run(executable, data.name, rows, 256, 1000, seed + 1))
        summary = {
            "small": {
                "runs": len(small),
                "mean_gap": statistics.mean(gaps),
                "p95_gap": sorted(gaps)[int(len(gaps) * 0.95) - 1],
                "by_rows": {},
                "representative_convergence": representative,
            },
            "large": {
                "runs": len(large),
                "by_rows": {},
            },
        }
        for rows in (10, 20, 30):
            values = [item["optimality_gap"] for item in small
                      if item["rows"] == rows]
            summary["small"]["by_rows"][str(rows)] = {
                "mean_gap": statistics.mean(values),
                "p95_gap": sorted(values)[int(len(values) * 0.95) - 1],
                "best_generations": [item["generation"] for item in small
                                     if item["rows"] == rows],
            }
        for rows in (100, 200, 410):
            values = [item for item in large if item["rows"] == rows]
            totals = [item["total_cost"] for item in values]
            summary["large"]["by_rows"][str(rows)] = {
                "min_runtime_seconds": min(item["runtime_seconds"] for item in values),
                "max_runtime_seconds": max(item["runtime_seconds"] for item in values),
                "min_total": min(totals),
                "max_total": max(totals),
                "total_spread": max(totals) - min(totals),
                "mean_feasible_rate": statistics.mean(
                    item["feasible_rate"] for item in values),
                "best_generations": [item["generation"] for item in values],
            }
        print(json.dumps(summary, separators=(",", ":")))


if __name__ == "__main__":
    main()
