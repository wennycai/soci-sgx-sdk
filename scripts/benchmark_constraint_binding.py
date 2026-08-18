#!/usr/bin/env python3
"""Run GA/Exact on constraint-binding variants of the real 410-row workbook."""

import json
import math
import statistics
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
import zipfile
from concurrent.futures import ThreadPoolExecutor


def read_xlsx(path):
    ns = {"x": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
    with zipfile.ZipFile(path) as archive:
        root = ET.fromstring(archive.read("xl/worksheets/sheet1.xml"))
    rows = []
    for row in root.findall(".//x:row", ns)[1:]:
        cells = ["", "", "", ""]
        for cell in row.findall("x:c", ns):
            column = ord(cell.attrib["r"][0]) - ord("A")
            inline = cell.find("x:is/x:t", ns)
            numeric = cell.find("x:v", ns)
            cells[column] = inline.text if inline is not None else (
                numeric.text if numeric is not None else "")
        rows.append(cells[1:])
    return rows


def binding_rows(source, threshold):
    """Preserve missingness and raw distribution; adjust only selected m3 cells."""
    rows = [[float(value) if value else None for value in row] for row in source]
    for index, row in enumerate(rows):
        if row[2] is not None:
            alternatives = [value for value in row[:2] if value is not None]
            # Only 2/3 of method3 cells are altered. Keeping the factor near
            # one preserves the real cost span while making m3 the cheap side
            # of the localization trade-off.
            if alternatives and index % 3 != 0:
                row[2] = min(row[2], min(alternatives) * 0.95)
        else:
            # Missing method3 remains missing. Bound only the fallback costs
            # on these rows; this is a warm-up cap, not multiplicative scaling.
            # Long tails remain intact on rows that retain method3.
            for method in (0, 1):
                if row[method] is not None:
                    row[method] = min(row[method], 45.0)
    return rows


def write_tsv(handle, rows):
    handle.seek(0)
    handle.truncate()
    for row in rows:
        handle.write("\t".join("" if value is None else f"{value:.6f}"
                               for value in row) + "\n")
    handle.flush()


def run(executable, path, rows, population, generations, seed, threshold,
        no_exact=False):
    command = [executable, path, str(rows), str(population), str(generations),
               str(seed), f"{threshold:.1f}"]
    if no_exact:
        command.append("--no-exact")
    output = subprocess.check_output(command, text=True)
    return json.loads(output)


def nearest_rank(values, percentile=0.95):
    ordered = sorted(values)
    return ordered[math.ceil(len(ordered) * percentile) - 1]


def parallel_runs(calls):
    with ThreadPoolExecutor(max_workers=8) as pool:
        return list(pool.map(lambda call: run(*call), calls))


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: benchmark_constraint_binding.py EXECUTABLE XLSX")
    executable, workbook = sys.argv[1:]
    source = read_xlsx(workbook)
    with tempfile.NamedTemporaryFile(mode="w+", suffix=".tsv") as data:
        summary = {}
        for threshold in (0.3, 0.5, 0.7, 0.8):
            write_tsv(data, binding_rows(source, threshold))
            exact = {}
            for rows in (10, 20, 30):
                exact[rows] = run(executable, data.name, rows, 2, 1, 0,
                                  threshold)["exact_total_cost"]
            small = []
            small_calls = [(executable, data.name, rows, 512, 3000, seed,
                            threshold, True)
                           for rows in (10, 20, 30) for seed in range(30)]
            for item in parallel_runs(small_calls):
                rows = item["rows"]
                item["exact_total_cost"] = exact[rows]
                item["optimality_gap"] = ((item["total_cost"] - exact[rows]) /
                                           exact[rows])
                small.append(item)
            large_calls = [(executable, data.name, rows, 256, 1000, seed,
                            threshold, True)
                           for rows in (100, 200) for seed in range(30)]
            large_calls += [(executable, data.name, 410, 256, generations,
                             seed, threshold, True)
                            for generations in (1000, 3000)
                            for seed in range(30)]
            large = []
            for item in parallel_runs(large_calls):
                if item["rows"] == 410:
                    generations = item["generations"]
                    item["benchmark_generations"] = generations
                large.append(item)
            threshold_summary = {"small": {}, "large": {}}
            for rows in (10, 20, 30):
                values = [item for item in small if item["rows"] == rows]
                gaps = [item["optimality_gap"] for item in values]
                threshold_summary["small"][str(rows)] = {
                    "mean_gap": statistics.mean(gaps),
                    "p95_gap": nearest_rank(gaps),
                    "best_generation_min": min(item["generation"] for item in values),
                    "best_generation_max": max(item["generation"] for item in values),
                }
            for rows in (100, 200):
                values = [item for item in large if item["rows"] == rows]
                totals = [item["total_cost"] for item in values]
                threshold_summary["large"][str(rows)] = {
                    "runtime_min_seconds": min(item["runtime_seconds"]
                                                for item in values),
                    "runtime_max_seconds": max(item["runtime_seconds"]
                                                for item in values),
                    "total_spread": max(totals) - min(totals),
                    "mean_pre_repair_feasible_rate": statistics.mean(
                        item["pre_repair_feasible_rate"] for item in values),
                    "mean_repair_success_rate": statistics.mean(
                        item["repair_success_rate"] for item in values),
                    "mean_final_feasible_rate": statistics.mean(
                        item["feasible_rate"] for item in values),
                    "best_generation_min": min(item["generation"] for item in values),
                    "best_generation_max": max(item["generation"] for item in values),
                }
            values = [item for item in large if item["rows"] == 410]
            threshold_summary["large"]["410"] = {}
            for generations in (1000, 3000):
                group = [item for item in values
                         if item["benchmark_generations"] == generations]
                totals = [item["total_cost"] for item in group]
                threshold_summary["large"]["410"][str(generations)] = {
                    "runtime_min_seconds": min(item["runtime_seconds"]
                                                for item in group),
                    "runtime_max_seconds": max(item["runtime_seconds"]
                                                for item in group),
                    "mean_total": statistics.mean(totals),
                    "total_spread": max(totals) - min(totals),
                    "mean_pre_repair_feasible_rate": statistics.mean(
                        item["pre_repair_feasible_rate"] for item in group),
                    "mean_repair_success_rate": statistics.mean(
                        item["repair_success_rate"] for item in group),
                    "mean_final_feasible_rate": statistics.mean(
                        item["feasible_rate"] for item in group),
                    "best_generation_min": min(item["generation"] for item in group),
                    "best_generation_max": max(item["generation"] for item in group),
                }
            totals_1000 = [item["total_cost"] for item in values
                           if item["benchmark_generations"] == 1000]
            totals_3000 = [item["total_cost"] for item in values
                           if item["benchmark_generations"] == 3000]
            threshold_summary["large"]["410"]["improvement_rate_mean"] = statistics.mean(
                (a - b) / a for a, b in zip(totals_1000, totals_3000))
            summary[f"{threshold:.1f}"] = threshold_summary
        print(json.dumps(summary, separators=(",", ":")))


if __name__ == "__main__":
    main()
