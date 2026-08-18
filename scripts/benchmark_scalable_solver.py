#!/usr/bin/env python3
"""Extract an XLSX and run the plaintext scalable-solver benchmark matrix."""

import json
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
import zipfile


def xlsx_rows(path):
    ns = {"x": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
    with zipfile.ZipFile(path) as archive:
        root = ET.fromstring(archive.read("xl/worksheets/sheet1.xml"))
    output = []
    for row in root.findall(".//x:row", ns)[1:]:
        values = ["", "", "", ""]
        for cell in row.findall("x:c", ns):
            column = ord(cell.attrib["r"][0]) - ord("A")
            inline = cell.find("x:is/x:t", ns)
            numeric = cell.find("x:v", ns)
            values[column] = inline.text if inline is not None else (
                numeric.text if numeric is not None else "")
        output.append(values)
    return output


def main():
    if len(sys.argv) < 3:
        raise SystemExit("usage: benchmark_scalable_solver.py EXECUTABLE XLSX")
    executable, workbook = sys.argv[1:3]
    rows = xlsx_rows(workbook)
    with tempfile.NamedTemporaryFile(mode="w", suffix=".tsv") as data:
        for row in rows:
            data.write("\t".join(row[1:4]) + "\n")
        data.flush()
        results = []
        for count, population, generations in (
                (10, 256, 1000), (20, 256, 1000), (30, 256, 1000),
                (len(rows), 256, 1000), (len(rows), 512, 1000),
                (len(rows), 256, 3000), (len(rows), 512, 3000),
                (len(rows), 256, 10000), (len(rows), 512, 10000)):
            completed = subprocess.run(
                [executable, data.name, str(count), str(population),
                 str(generations), "915017"], check=True,
                capture_output=True, text=True)
            result = json.loads(completed.stdout)
            results.append(result)
            print(json.dumps(result, separators=(",", ":")), flush=True)
    print(json.dumps({"results": results}, separators=(",", ":")))


if __name__ == "__main__":
    main()
