import dataclasses
import os

import pytest

from ecc.assess import assess
from ecc.html import PdfError, find_browser, render_html, write_pdf
from ecc.models import RiskRegister

BROWSER = find_browser(os.environ)


def test_the_report_shows_the_score_and_every_control(dataset, baseline):
    html = render_html(dataset, assess(dataset, baseline))
    assert "50.0%" in html
    for control in dataset.catalog:
        assert f"<td>{control.id}</td>" in html
    assert "WS-01" in html
    assert "What changed" not in html


def test_the_report_compares_two_snapshots(dataset, baseline, after):
    html = render_html(dataset, assess(dataset, after), assess(dataset, baseline))
    assert "What changed" in html
    assert "75.0%" in html
    assert "(was 50.0%)" in html


def test_text_from_data_files_is_escaped(dataset, baseline):
    risk = dataset.risks.risks[0].model_copy(update={"statement": "<b>bold</b>"})
    changed = dataclasses.replace(
        dataset, risks=RiskRegister(risks=(risk, *dataset.risks.risks[1:]))
    )
    html = render_html(changed, assess(changed, baseline))
    assert "&lt;b&gt;bold&lt;/b&gt;" in html
    assert "<b>bold</b>" not in html


def test_the_heatmap_counts_open_risks(dataset, baseline):
    html = render_html(dataset, assess(dataset, baseline))
    assert html.count('<td class="high">1</td>') == 2  # R-01 (3x4) and R-02 (4x4)
    assert '<td class="low">1</td>' in html  # R-03 (2x2)


def test_the_chrome_variable_wins():
    assert find_browser({"CHROME": "/opt/chrome"}) == "/opt/chrome"


def test_no_browser_means_none(monkeypatch):
    monkeypatch.setattr("ecc.html.shutil.which", lambda name: None)
    monkeypatch.setattr("ecc.html.WINDOWS_BROWSERS", ())
    assert find_browser({}) is None


def test_a_missing_browser_is_a_clear_error(tmp_path):
    page = tmp_path / "index.html"
    page.write_text("<p>x</p>", encoding="utf-8")
    with pytest.raises(PdfError):
        write_pdf(page, tmp_path / "out.pdf", str(tmp_path / "no-browser.exe"))


@pytest.mark.skipif(
    BROWSER is None or os.environ.get("CI") == "true", reason="needs a local Chrome or Edge"
)
def test_the_pdf_is_printed(tmp_path, dataset, baseline):
    page = tmp_path / "index.html"
    page.write_text(render_html(dataset, assess(dataset, baseline)), encoding="utf-8")
    pdf = tmp_path / "report.pdf"
    write_pdf(page, pdf, BROWSER)
    assert pdf.read_bytes().startswith(b"%PDF")
