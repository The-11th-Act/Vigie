"""A minimal XLSX writer: one sheet, a header row, then typed cells.

An XLSX file is a zip of XML parts: the standard library writes the few the
extracts need (text and numbers, row by row, into a seekable file) rather than
a dependency. Text always goes in as an inline string, never as a formula:
unlike a CSV cell, no spreadsheet evaluates it, so it needs no neutralising
quote.
"""

import math
import re
import zipfile
from collections.abc import Iterable, Sequence
from decimal import Decimal
from typing import IO, Any
from xml.sax.saxutils import escape

# What one cell holds at most in Excel.
MAX_CELL_CHARS = 32_767
MAX_SHEET_NAME = 31
# Characters XML 1.0 forbids: a scanner's plugin output may carry them.
_ILLEGAL_XML = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f￾￿]")
# Characters a sheet name may not contain.
_SHEET_NAME_FORBIDDEN = re.compile(r"[\[\]:*?/\\]")

MEDIA_TYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"

_CONTENT_TYPES = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
    '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
    '<Default Extension="rels" '
    'ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
    '<Default Extension="xml" ContentType="application/xml"/>'
    '<Override PartName="/xl/workbook.xml" ContentType="application/'
    'vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
    '<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/'
    'vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
    '<Override PartName="/xl/styles.xml" ContentType="application/'
    'vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'
    "</Types>"
)

_ROOT_RELS = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
    '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/'
    '2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
    "</Relationships>"
)

_WORKBOOK_RELS = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
    '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/'
    '2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>'
    '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/'
    '2006/relationships/styles" Target="styles.xml"/>'
    "</Relationships>"
)

# Style 0 is the default; style 1, bold, is the header's.
_STYLES = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
    '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
    '<fonts count="2"><font><sz val="11"/><name val="Calibri"/></font>'
    '<font><b/><sz val="11"/><name val="Calibri"/></font></fonts>'
    '<fills count="2"><fill><patternFill patternType="none"/></fill>'
    '<fill><patternFill patternType="gray125"/></fill></fills>'
    '<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border>'
    "</borders>"
    '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/>'
    "</cellStyleXfs>"
    '<cellXfs count="2"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>'
    '<xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/>'
    "</cellXfs>"
    '<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/>'
    "</cellStyles>"
    "</styleSheet>"
)

_SHEET_START = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
    '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
    # The header row stays in view while scrolling.
    '<sheetViews><sheetView workbookViewId="0">'
    '<pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/>'
    "</sheetView></sheetViews>"
    "<sheetData>"
)
_SHEET_END = "</sheetData></worksheet>"


def column_letters(index: int) -> str:
    """0 -> A, 25 -> Z, 26 -> AA."""
    letters = ""
    index += 1
    while index:
        index, remainder = divmod(index - 1, 26)
        letters = chr(ord("A") + remainder) + letters
    return letters


def sheet_name(name: str) -> str:
    cleaned = _SHEET_NAME_FORBIDDEN.sub(" ", name).strip().strip("'")
    return cleaned[:MAX_SHEET_NAME] or "Sheet1"


def _cell(ref: str, value: Any, style: str) -> str:
    """One cell as XML; "" for an empty one. Booleans read yes / no, as in CSV."""
    if value is None:
        return ""
    if isinstance(value, bool):
        value = "yes" if value else "no"
    if isinstance(value, int | float | Decimal) and not isinstance(value, bool):
        if isinstance(value, float | Decimal) and not math.isfinite(value):
            return ""
        return f'<c r="{ref}"{style}><v>{value}</v></c>'
    text = _ILLEGAL_XML.sub("", str(value))[:MAX_CELL_CHARS]
    if not text:
        return ""
    return (
        f'<c r="{ref}" t="inlineStr"{style}>'
        f'<is><t xml:space="preserve">{escape(text)}</t></is></c>'
    )


def _row(number: int, values: Sequence[Any], style: str = "") -> str:
    cells = "".join(
        _cell(f"{column_letters(index)}{number}", value, style)
        for index, value in enumerate(values)
    )
    return f'<row r="{number}">{cells}</row>'


def write_xlsx(
    fileobj: IO[bytes],
    header: Sequence[str],
    rows: Iterable[Sequence[Any]],
    name: str = "Sheet1",
) -> None:
    """Write a one-sheet workbook to ``fileobj``, a seekable binary file.

    The rows are consumed one by one into the sheet's zip entry: memory stays
    flat whatever their number.
    """
    workbook = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        f'<sheets><sheet name="{escape(sheet_name(name), {chr(34): "&quot;"})}" '
        'sheetId="1" r:id="rId1"/></sheets></workbook>'
    )
    with zipfile.ZipFile(fileobj, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", _CONTENT_TYPES)
        archive.writestr("_rels/.rels", _ROOT_RELS)
        archive.writestr("xl/workbook.xml", workbook)
        archive.writestr("xl/_rels/workbook.xml.rels", _WORKBOOK_RELS)
        archive.writestr("xl/styles.xml", _STYLES)
        with archive.open("xl/worksheets/sheet1.xml", "w") as sheet:
            sheet.write(_SHEET_START.encode())
            sheet.write(_row(1, header, ' s="1"').encode())
            for number, values in enumerate(rows, start=2):
                sheet.write(_row(number, values).encode())
            sheet.write(_SHEET_END.encode())
