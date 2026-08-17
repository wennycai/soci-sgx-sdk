#!/usr/bin/env python3
"""Run the existing XLSX sample through the demo HTTP API."""

import json
import sys
import urllib.request
import xml.etree.ElementTree as ET
import zipfile


def rows(path):
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


def post(url, body):
    request = urllib.request.Request(url, body.encode(), method="POST")
    request.add_header("Content-Type", "text/plain;charset=utf-8")
    with urllib.request.urlopen(request, timeout=900) as response:
        return json.load(response)


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: benchmark_demo_sample.py BASE_URL XLSX")
    base, xlsx = sys.argv[1:]
    sample = rows(xlsx)
    body = "0.5\tcurrent_suffix\t3\n" + "\n".join(
        "\t".join(row) for row in sample)
    optimized = post(base + "/api/optimize", body)
    revealed = post(base + "/api/workflow/decrypt", optimized["resultId"])
    solution = revealed["solution"]
    selected = [float(sample[i][solution[i]]) for i in range(len(sample))]
    c12 = round(sum(value for value, method in zip(selected, solution)
                    if method < 3), 2)
    c3 = round(sum(value for value, method in zip(selected, solution)
                   if method == 3), 2)
    expected = [2,2,1,3,2,2,3,3,3,1]
    if solution != expected or abs(revealed["totalCost"]-31890.31)>1e-6 or \
            abs(c12-31388.99)>1e-6 or abs(c3-501.32)>1e-6 or \
            abs(revealed["ratio"]-0.9842798643224228)>1e-12:
        raise RuntimeError("SIM result does not match the plaintext reference")
    revealed.update({"c12":c12,"c3":c3,"plaintext_reference_match":True})
    print(json.dumps({"optimized": optimized, "revealed": revealed},
                     separators=(",", ":"), sort_keys=True))


if __name__ == "__main__":
    main()
