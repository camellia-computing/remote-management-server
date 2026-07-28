import csv
from io import BytesIO

from django.http import HttpResponse
from openpyxl import Workbook

XLSX_CONTENT_TYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"


def spreadsheet_safe_value(value):
    if value is None:
        return ""
    if not isinstance(value, str) or not value:
        return value
    trimmed = value.lstrip(" \t\r\n")
    if value[0] in "\t\r\n" or (trimmed and trimmed[0] in "=+-@"):
        return "'" + value
    return value


class _SafeCsvWriter:
    def __init__(self, output, **kwargs):
        self._writer = csv.writer(output, **kwargs)

    def writerow(self, row):
        return self._writer.writerow([spreadsheet_safe_value(value) for value in row])

    def writerows(self, rows):
        return self._writer.writerows([spreadsheet_safe_value(value) for value in row] for row in rows)


def safe_csv_writer(output, **kwargs):
    return _SafeCsvWriter(output, **kwargs)


def xlsx_response(filename, sheet_name, headers, rows):
    workbook = Workbook()
    sheet = workbook.active
    safe_sheet_name = "".join("_" if character in r"[]:*?/\\" else character for character in str(sheet_name))
    sheet.title = safe_sheet_name[:31] or "Sheet1"
    sheet.append([spreadsheet_safe_value(value) for value in headers])
    for row in rows:
        sheet.append([spreadsheet_safe_value(value) for value in row])

    output = BytesIO()
    workbook.save(output)
    output.seek(0)
    response = HttpResponse(output.getvalue(), content_type=XLSX_CONTENT_TYPE)
    response["Content-Disposition"] = f"attachment; filename={filename}"
    return response
