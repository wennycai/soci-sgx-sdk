#!/usr/bin/env python3
"""Generate the local plaintext sample workbook without third-party packages."""
from pathlib import Path
from xml.sax.saxutils import escape
from zipfile import ZIP_DEFLATED, ZipFile

ROWS = [
    ["material_id", "method_1", "method_2", "method_3"],
    ["M01", 1779.51, 862.31, None], ["M02", 2094.58, 1653.47, None],
    ["M03", 34.55, None, None], ["M04", 442.14, None, 294.00],
    ["M05", 141.84, 38.23, None], ["M06", 29778.22, 28796.37, None],
    ["M07", 197.73, None, 158.00], ["M08", 67.96, None, 27.00],
    ["M09", 66.24, None, 22.32], ["M10", 4.06, None, 7.11],
]

def column(index):
    value, index = "", index + 1
    while index:
        index, remainder = divmod(index - 1, 26)
        value = chr(65 + remainder) + value
    return value

def worksheet():
    rows = []
    for row_index, row in enumerate(ROWS, 1):
        cells = []
        for column_index, value in enumerate(row):
            if value is None:
                continue
            ref = f"{column(column_index)}{row_index}"
            if isinstance(value, str):
                cells.append(f'<c r="{ref}" t="inlineStr"><is><t>{escape(value)}</t></is></c>')
            else:
                cells.append(f'<c r="{ref}"><v>{value}</v></c>')
        rows.append(f'<row r="{row_index}">{"".join(cells)}</row>')
    return ('<?xml version="1.0" encoding="UTF-8"?>'
            '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
            f'<sheetData>{"".join(rows)}</sheetData></worksheet>')

def main():
    target = Path(__file__).with_name("sample-costs.xlsx")
    with ZipFile(target, "w", ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>')
        archive.writestr("_rels/.rels", '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>')
        archive.writestr("xl/workbook.xml", '<?xml version="1.0"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Costs" sheetId="1" r:id="rId1"/></sheets></workbook>')
        archive.writestr("xl/_rels/workbook.xml.rels", '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>')
        archive.writestr("xl/worksheets/sheet1.xml", worksheet())
    print(target)

if __name__ == "__main__":
    main()
