#!/usr/bin/env python3
"""Fail-closed comparison of the isolated Structured Exact prototype and CBC.

This intentionally reads the frozen TSV directly and performs its own exact
fixed-point validation; neither solver's self-reported feasibility is trusted.
"""
import argparse
import hashlib
import json
import subprocess
import sys
import time
from decimal import Decimal, InvalidOperation
from pathlib import Path

SCALE = 1_000_000
FROZEN_SHA256 = "0931c4ac98e2897a4fba3248ddeae7a56e3259e074e7c036a62fae5f6ebc99e7"

def fixed(cell):
    if not cell:
        return None
    try:
        value = Decimal(cell)
    except InvalidOperation as exc:
        raise ValueError(f"invalid TSV decimal {cell!r}") from exc
    scaled = value * SCALE
    if scaled != scaled.to_integral_value() or value < 0:
        raise ValueError(f"non-six-decimal or negative TSV cost {cell!r}")
    return int(scaled)

def load_costs(path, count):
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines()[:count]:
        cells = line.split("\t")
        if len(cells) > 3:
            raise ValueError("too many TSV columns")
        rows.append([fixed(cells[i]) if i < len(cells) else None for i in range(3)])
    if len(rows) != count:
        raise ValueError(f"expected {count} rows, got {len(rows)}")
    return rows

def verify_provenance(data, provenance):
    raw = data.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    record = json.loads(provenance.read_text(encoding="utf-8"))
    if (digest != FROZEN_SHA256 or record.get("costs_sha256") != FROZEN_SHA256 or
            record.get("path") != "tee_cbc/data/costs.tsv" or record.get("rows") != 410 or
            record.get("real_rows") != 410):
        raise RuntimeError("frozen 410-row provenance verification failed")

def validate(rows, threshold, solution):
    if not isinstance(solution, list) or len(solution) != len(rows):
        raise ValueError("solution length")
    c12 = c3 = 0
    for row, method in zip(rows, solution):
        if not isinstance(method, int) or method not in (1, 2, 3) or row[method - 1] is None:
            raise ValueError("one-hot/availability violation")
        if method == 3:
            c3 += row[2]
        else:
            c12 += row[method - 1]
    g = (SCALE - threshold) * c12 - threshold * c3
    if c3 <= 0:
        raise ValueError("rhs_positive violation")
    if g < 0:
        raise ValueError("ratio violation")
    return c12 + c3, c12 / (c12 + c3), g

def invoke(command, timeout):
    started = time.monotonic()
    try:
        completed = subprocess.run(command, text=True, capture_output=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return None, time.monotonic() - started, "external_timeout"
    if completed.returncode not in (0, 2, 3):
        raise RuntimeError(f"command failed ({completed.returncode}): {completed.stderr.strip()}")
    try:
        return json.loads(completed.stdout), time.monotonic() - started, None
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"non-JSON solver output: {completed.stdout!r}") from exc

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--structured", required=True)
    parser.add_argument("--cbc", required=True)
    parser.add_argument("--data", default="tee_cbc/data/costs.tsv")
    parser.add_argument("--provenance", default="tee_cbc/data/costs.provenance.json")
    parser.add_argument("--timeout", type=float, default=60.0)
    parser.add_argument("--node-limit", type=int, default=0,
                        help="diagnostic Structured node cap; 0 requires a full Exact proof")
    parser.add_argument("--strategy", choices=("B1", "B2"), default="B2",
                        help="Structured exact bound configuration (default B2)")
    args = parser.parse_args()
    data, provenance = Path(args.data), Path(args.provenance)
    verify_provenance(data, provenance)
    rows = load_costs(data, 410)
    report = {"dataset_sha256": FROZEN_SHA256, "rows": 410, "thresholds": []}
    failed = False
    for text_threshold in ("0.5", "0.7", "0.8"):
        threshold = fixed(text_threshold)
        structured_command = [args.structured, str(data), "410", text_threshold,
                              str(args.node_limit), args.strategy]
        structured, structured_wall, structured_error = invoke(
            structured_command, args.timeout)
        cbc, cbc_wall, cbc_error = invoke(
            [args.cbc, str(data), "410", text_threshold, "0"], args.timeout)
        entry = {"threshold": text_threshold, "structured_wall_runtime": structured_wall,
                 "cbc_wall_runtime": cbc_wall, "structured_status": structured_error or structured.get("optimality_status"),
                 "cbc_status": cbc_error or cbc.get("optimality_status")}
        if structured_error or cbc_error:
            failed = True; entry["objective_match"] = False; report["thresholds"].append(entry); continue
        try:
            structured_objective, structured_ratio, _ = validate(rows, threshold, structured.get("solution"))
            cbc_objective, cbc_ratio, _ = validate(rows, threshold, cbc.get("solution"))
            if structured.get("final_objective_scaled") != structured_objective:
                raise ValueError("structured reported objective mismatch")
            reported_cbc = float(cbc.get("total_cost"))
            expected_cbc = cbc_objective / SCALE
            if abs(reported_cbc - expected_cbc) > 1e-6 * max(1.0, abs(reported_cbc)):
                raise ValueError("CBC reported objective tolerance mismatch")
            entry.update({key: structured[key] for key in (
                "total_rows", "cheapest_fast_path_hit", "fixed_no_m3_rows", "fixed_dominated_rows",
                "decision_rows", "baseline_G", "required_gain_D", "nodes_visited", "max_depth",
                "cover_completion_count", "feasibility_prune_count", "cost_prune_count",
                "incumbent_update_count", "rhs_positive_prune_count", "preprocessing_runtime",
                "search_runtime", "total_runtime", "final_objective", "final_ratio", "optimality_status",
                "lagrangian_grid_size", "lagrangian_bound_evaluation_count",
                "lagrangian_prune_count", "strategy")})
            structured_proven = structured.get("optimality_status") in (
                "optimal_verified", "cheapest_global_optimum")
            cbc_proven = cbc.get("optimality_status") in (
                "optimal_verified", "cheapest_global_optimum")
            integer_objectives_equal = structured_objective == cbc_objective
            entry.update({"structured_objective_scaled": structured_objective, "structured_ratio_validated": structured_ratio,
                          "cbc_objective": expected_cbc, "cbc_objective_scaled": cbc_objective,
                          "cbc_runtime": cbc.get("total_runtime_seconds", cbc_wall), "cbc_ratio": cbc_ratio,
                          "structured_feasible": True, "cbc_feasible": True,
                          "structured_optimality_proven": structured_proven,
                          "cbc_optimality_proven": cbc_proven,
                          "incumbent_objective_match": integer_objectives_equal,
                          "objective_match": structured_proven and cbc_proven and integer_objectives_equal})
            if not entry["objective_match"]:
                failed = True
        except (KeyError, TypeError, ValueError) as exc:
            failed = True; entry["validation_error"] = str(exc); entry["objective_match"] = False
        report["thresholds"].append(entry)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 1 if failed else 0

if __name__ == "__main__":
    sys.exit(main())
