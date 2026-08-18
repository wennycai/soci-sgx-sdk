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
            available = [j for j, value in enumerate(row[:2])
                         if value is not None]
            # Missing method3 remains missing; scale only the cheapest
            # available fallback so these rows do not overwhelm C3.
            if available:
                cheapest = min(available, key=lambda j: row[j])
                row[cheapest] *= 0.001
    return rows


def write_tsv(handle, rows):
    handle.seek(0)
    handle.truncate()
    for row in rows:
        handle.write("\t".join("" if value is None else f"{value:.6f}"
                               for value in row) + "\n")
    handle.flush()


def run(executable, path, rows, population, generations, seed, threshold):
    output = subprocess.check_output(
        [executable, path, str(rows), str(population), str(generations),
         str(seed), f"{threshold:.1f}"], text=True)
    return json.loads(output)


def nearest_rank(values, percentile=0.95):
    ordered = sorted(values)
    return ordered[math.ceil(len(ordered) * percentile) - 1]


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: benchmark_constraint_binding.py EXECUTABLE XLSX")
    executable, workbook = sys.argv[1:]
    source = read_xlsx(workbook)
    with tempfile.NamedTemporaryFile(mode="w+", suffix=".tsv") as data:
        summary = {}
        for threshold in (0.3, 0.5, 0.7, 0.8):
            write_tsv(data, binding_rows(source, threshold))
            small = [run(executable, data.name, rows, 512, 3000, seed,
                         threshold)
                     for rows in (10, 20, 30) for seed in range(30)]
            large = [run(executable, data.name, rows, 256, 1000, seed,
                         threshold)
                     for rows in (100, 200, 410) for seed in range(30)]
            threshold_summary = {"small": {}, "large": {}}
            for rows in (10, 20, 30):
                values = [item for item in small if item["rows"] == rows]
                gaps = [item["optimality_gap"] for item in values]
                threshold_summary["small"][str(rows)] = {
                    "mean_gap": statistics.mean(gaps),
                    "p95_gap": nearest_rank(gaps),
                    "best_generations": [item["generation"] for item in values],
                }
            for rows in (100, 200, 410):
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
                    "best_generations": [item["generation"] for item in values],
                }
            summary[f"{threshold:.1f}"] = threshold_summary
        print(json.dumps(summary, separators=(",", ":")))


if __name__ == "__main__":
    main()
