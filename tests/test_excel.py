from openpyxl import load_workbook

from ecc.assess import assess
from ecc.excel import SHEETS, write_workbook


def workbook(tmp_path, dataset, after, before=None):
    path = tmp_path / "out.xlsx"
    old = assess(dataset, before) if before is not None else None
    write_workbook(path, dataset, assess(dataset, after), old)
    return load_workbook(path)


def values(sheet, row):
    return [cell.value for cell in sheet[row]]


def test_the_workbook_has_five_sheets(tmp_path, dataset, after):
    assert workbook(tmp_path, dataset, after).sheetnames == list(SHEETS)


def test_the_summary_compares_two_snapshots(tmp_path, dataset, baseline, after):
    sheet = workbook(tmp_path, dataset, after, baseline)["Summary"]
    assert values(sheet, 1) == ["Area", "baseline %", "after %", "Change"]
    assert values(sheet, 2) == ["Overall", 50.0, 75.0, 25.0]
    assert values(sheet, 4) == ["2 Cybersecurity Defense", 50.0, 83.3, 33.3]
    assert values(sheet, 5) == [
        "4 Third-Party and Cloud Computing Cybersecurity",
        "n/a",
        "n/a",
        "n/a",
    ]


def test_the_summary_for_one_snapshot(tmp_path, dataset, after):
    sheet = workbook(tmp_path, dataset, after)["Summary"]
    assert values(sheet, 1) == ["Area", "after %"]
    assert values(sheet, 2) == ["Overall", 75.0]


def test_the_controls_sheet_colours_the_status(tmp_path, dataset, after):
    sheet = workbook(tmp_path, dataset, after)["Controls"]
    rows = list(sheet.iter_rows(min_row=2, values_only=True))
    assert [row[0] for row in rows] == ["1-3-1", "2-2-1", "2-2-3", "2-12-3", "4-2-1"]
    assert rows[2][4] == "Implemented"
    assert sheet["E4"].fill.start_color.rgb.endswith("C6EFCE")


def test_technical_evidence_lists_every_check(tmp_path, dataset, after):
    sheet = workbook(tmp_path, dataset, after)["Technical evidence"]
    rows = list(sheet.iter_rows(min_row=2, values_only=True))
    assert [row[0] for row in rows] == [26000, 26001, 26139, 26140]
    assert rows[0][3:] == ("passed", "2-2-3")


def test_closed_risks_leave_the_roadmap(tmp_path, dataset, after):
    book = workbook(tmp_path, dataset, after)
    register = book["Risk register"].iter_rows(min_row=2, values_only=True)
    assert {row[0]: row[10] for row in register} == {
        "R-01": "Closed",
        "R-02": "Open",
        "R-03": "Open",
    }
    plan = [row[:2] for row in book["Roadmap"].iter_rows(min_row=2, values_only=True)]
    assert plan == [("60 days", "R-02"), ("Later", "R-03")]
