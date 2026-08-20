#!/usr/bin/env python3
"""Prepare the frozen binding dataset for the TEE+CBC benchmark. ONE-TIME.

This script is *not* part of a benchmark run.  It materialises `costs.tsv`
once; the file and its provenance are then committed and frozen, and
`benchmark_tee_cbc.py` only ever verifies the recorded sha256 before
measuring.  Regenerating per run would decouple each result from the results
it is compared against without anything in the report showing it, so an
existing dataset is never overwritten without an explicit `--force`.

Re-preparing is legitimate for exactly one reason: the acceptance matrix needs
row counts the current file cannot serve.  Then prepare a larger dataset,
commit it with its provenance, and point the harness at it - the frozen file
bounds the matrix, not the other way round.

`soci_cbc_plaintext_benchmark` reads the first ROWS lines of the TSV, so a
single `costs.tsv` serves every row count up to its length and the smaller
counts are exact prefixes of the larger ones.  That also keeps the Gramine
`/input` mount single-file: the mount path is baked into the manifest at
render time, so per-row-count directories could not be swapped at runtime.

Provenance of the rows:

- Rows 1..410 are the real workbook
  (`examples/optimization-demo/sample-costs-410.xlsx`).
- Rows 411..N are synthetic.  The real workbook has only 410 rows, so the
  extension resamples whole real rows with a fixed seed - resampling whole
  rows preserves the per-row missingness pattern, which the ratio constraint
  depends on - and applies a bounded +-JITTER multiplicative perturbation to
  every present cell.  Resampling whole rows rather than tiling avoids the
  duplicate-row symmetry that would otherwise distort CBC's branch and bound.

The constraint-binding transform is applied *after* the extension so that it
sees the full matrix; it is purely per-row and indexed by position, so rows
1..410 come out identical to the 410-row transform in
`scripts/benchmark_constraint_binding.py`, i.e. the prefix property holds.
"""

import argparse
import hashlib
import json
import os
import random
import sys
import xml.etree.ElementTree as ET
import zipfile

NAMESPACE = {"x": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
REAL_ROW_LIMIT = 410
DEFAULT_SEED = 915017
JITTER = 0.10


def read_xlsx(path):
    """Read the cost workbook exactly like scripts/benchmark_constraint_binding.py."""
    with zipfile.ZipFile(path) as archive:
        root = ET.fromstring(archive.read("xl/worksheets/sheet1.xml"))
    rows = []
    for row in root.findall(".//x:row", NAMESPACE)[1:]:
        cells = ["", "", "", ""]
        for cell in row.findall("x:c", NAMESPACE):
            column = ord(cell.attrib["r"][0]) - ord("A")
            inline = cell.find("x:is/x:t", NAMESPACE)
            numeric = cell.find("x:v", NAMESPACE)
            cells[column] = inline.text if inline is not None else (
                numeric.text if numeric is not None else "")
        rows.append([float(value) if value else None for value in cells[1:]])
    return rows


def extend(rows, target, seed):
    """Append seeded resampled + jittered rows until the matrix reaches `target`."""
    if len(rows) >= target:
        return list(rows[:target]), 0
    rng = random.Random(seed)
    extended = list(rows)
    while len(extended) < target:
        source = rows[rng.randrange(len(rows))]
        extended.append([None if value is None
                         else value * rng.uniform(1.0 - JITTER, 1.0 + JITTER)
                         for value in source])
    return extended, target - len(rows)


def binding_rows(rows):
    """Preserve missingness and raw distribution; adjust only selected m3 cells.

    Byte-for-byte the transform used by scripts/benchmark_constraint_binding.py:
    it makes method 3 the cheap side of the localization trade-off so that the
    per-row cheapest selection violates the ratio threshold and CBC actually
    has to solve, instead of the cheapest fast path short-circuiting the run.
    """
    rows = [list(row) for row in rows]
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


def render(rows):
    return "".join("\t".join("" if value is None else f"{value:.6f}"
                             for value in row) + "\n" for row in rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("workbook", help="examples/optimization-demo/sample-costs-410.xlsx")
    parser.add_argument("data_dir", help="Gramine /input mount directory")
    parser.add_argument("--rows", type=int, default=410,
                        help="total rows to materialise (default: 410, the "
                             "full real workbook - the acceptance matrix tops "
                             "out at 200 rows, so nothing is synthesised)")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--provenance",
                        help="write the dataset provenance JSON here; keep it "
                             "OUTSIDE the Gramine /input mount, which is "
                             "encrypted in SGX mode")
    parser.add_argument("--force", action="store_true",
                        help="overwrite an existing costs.tsv. Re-freezing the "
                             "dataset invalidates comparability with every "
                             "result already published against it, so the "
                             "provenance must be re-committed alongside.")
    args = parser.parse_args()

    target = os.path.join(args.data_dir, "costs.tsv")
    if os.path.exists(target) and not args.force:
        print(f"{target} already exists and the dataset is frozen; pass "
              f"--force to re-prepare it (and re-commit the provenance).",
              file=sys.stderr)
        return 3

    source = read_xlsx(args.workbook)
    extended, synthetic = extend(source, args.rows, args.seed)
    payload = render(binding_rows(extended))
    os.makedirs(args.data_dir, exist_ok=True)
    with open(target, "w") as handle:
        handle.write(payload)

    with open(args.workbook, "rb") as handle:
        workbook_digest = hashlib.sha256(handle.read()).hexdigest()
    provenance = {
        "dataset": "binding",
        "path": target,
        "rows": args.rows,
        "real_rows": len(extended) - synthetic,
        "synthetic_rows": synthetic,
        "extension": "seeded_resample_jitter" if synthetic else "none",
        "seed": args.seed,
        "jitter": JITTER,
        "row_counts_are_prefixes": True,
        "workbook": args.workbook,
        "workbook_sha256": workbook_digest,
        "costs_sha256": hashlib.sha256(payload.encode()).hexdigest(),
    }
    if args.provenance:
        with open(args.provenance, "w") as handle:
            json.dump(provenance, handle, indent=2, sort_keys=True)
            handle.write("\n")
    print(json.dumps(provenance, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
