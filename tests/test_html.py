import dataclasses
import os
import re

import pytest

from ecc.assess import assess
from ecc.html import PdfError, find_browser, render_html, write_pdf
from ecc.models import RiskRegister, SamaExclusion

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


def stub_browser(tmp_path, exit_code: int) -> str:
    """A fake browser that writes nothing and exits with exit_code."""
    if os.name == "nt":
        path = tmp_path / "browser.bat"
        path.write_text(f"@exit /b {exit_code}\n", encoding="utf-8")
    else:
        path = tmp_path / "browser.sh"
        path.write_text(f"#!/bin/sh\nexit {exit_code}\n", encoding="utf-8")
        path.chmod(0o755)
    return str(path)


def test_an_old_pdf_never_counts_as_success(tmp_path):
    page = tmp_path / "index.html"
    page.write_text("<p>x</p>", encoding="utf-8")
    pdf = tmp_path / "out.pdf"
    pdf.write_bytes(b"%PDF old report")
    with pytest.raises(PdfError, match="without writing"):
        write_pdf(page, pdf, stub_browser(tmp_path, 0))
    assert not pdf.exists()


def test_a_failing_browser_reports_its_exit_code(tmp_path):
    page = tmp_path / "index.html"
    page.write_text("<p>x</p>", encoding="utf-8")
    with pytest.raises(PdfError, match="exited with code 3"):
        write_pdf(page, tmp_path / "out.pdf", stub_browser(tmp_path, 3))


def test_the_heatmap_puts_likelihood_across_and_impact_down(dataset, baseline):
    risk = dataset.risks.risks[2].model_copy(update={"likelihood": 4, "impact": 1})
    changed = dataclasses.replace(
        dataset, risks=RiskRegister(risks=(*dataset.risks.risks[:2], risk))
    )
    html = render_html(changed, assess(changed, baseline))
    row = html.split("<tr><th>1</th>")[1].split("</tr>")[0]
    assert re.findall(r"<td[^>]*>([^<]*)</td>", row) == ["", "", "", "1", ""]


def test_unrated_controls_are_counted_and_filterable(dataset, baseline):
    evidence = dataset.evidence.model_copy(update={"entries": dataset.evidence.entries[1:]})
    changed = dataclasses.replace(dataset, evidence=evidence)
    html = render_html(changed, assess(changed, baseline))
    assert "<b>1</b>No rating</div>" in html
    assert "<option>No rating</option>" in html
    assert '<tr data-status="No rating"><td>1-3-1</td>' in html


def test_the_method_matches_the_scoring(dataset, baseline):
    html = render_html(dataset, assess(dataset, baseline))
    assert "rated applicable controls" in html
    assert "weakest of its checks rating and its facts" in html


def test_the_report_shows_the_company_summary_and_limitations(dataset, baseline):
    report = dataset.report.model_copy(update={"key_findings": ("<i>Passwords</i> need work.",)})
    changed = dataclasses.replace(dataset, report=report)
    html = render_html(changed, assess(changed, baseline))
    assert '<p class="company">Example Co (fictional)</p>' in html
    assert "<p>Example Co is a made-up company used by the tests.</p>" in html
    assert "<li>&lt;i&gt;Passwords&lt;/i&gt; need work.</li>" in html
    assert "<li>All data here is made up.</li>" in html


def test_the_scope_and_method_describe_the_whole_company(dataset, baseline):
    html = render_html(dataset, assess(dataset, baseline))
    assert "The assessment covers Example Co (fictional) as a whole." in html
    assert "The assessment covers one Windows 11 workstation" not in html
    assert "documented and approved is Implemented" in html


def test_the_report_shows_the_sama_view(dataset, after):
    html = render_html(dataset, assess(dataset, after))
    assert "SAMA Cyber Security Framework view (indicative)" in html
    assert "<b>1 of 4 applicable subdomains reach Level 3</b>" in html
    assert "<td>3 Structured and formalized</td>" in html
    assert "Level 2 at 50% or more with at least one Implemented" in html
    assert "Example Co runs no payment systems." in html
    assert "<td>Not applicable</td>" in html
    assert "so no level is derived.</span></td><td>4-2-1</td><td>n/a</td><td>n/a</td>" in html


def test_sama_text_is_escaped(dataset, baseline):
    mapping = dataset.sama_mapping.model_copy(
        update={"not_applicable": (SamaExclusion(subdomain="3.3.12", reason="<i>No</i> cards."),)}
    )
    changed = dataclasses.replace(dataset, sama_mapping=mapping)
    html = render_html(changed, assess(changed, baseline))
    assert "&lt;i&gt;No&lt;/i&gt; cards." in html
    assert "<i>No</i>" not in html


def test_the_report_shows_remediation_results(dataset, baseline, after):
    html = render_html(dataset, assess(dataset, after), assess(dataset, baseline))
    assert "<h2>Remediation on WS-01</h2>" in html
    assert "were applied with remediation/apply.ps1" in html
    assert "<b>2 of 2 targeted checks pass</b> (was 0)." in html
    assert "snapshots. Each row counts" in html
    assert "No CIS check outside the fixes changed" in html
    assert "<td>2-12-3</td><td class=\"nowrap\">0 &rarr; 1 of 1</td>" in html
    assert "Audit sign-ins</b> (optional)" in html
    assert "<h3>CIS checks passing, by control</h3>" in html
    assert "<td>2-2-3 Identity and Access Management</td><td>1 of 2</td><td>2 of 2</td>" in html


def test_a_single_snapshot_report_lists_the_fixes(dataset, baseline):
    html = render_html(dataset, assess(dataset, baseline))
    assert "2 reversible fixes are listed in remediation/fixes.json" in html
    assert "<b>0 of 2 targeted checks pass</b>." in html
    assert "CIS checks passing, by control" not in html


def test_the_title_and_scope_name_the_company_safely(dataset, baseline):
    report = dataset.report.model_copy(update={"company": "<b>Co</b>"})
    changed = dataclasses.replace(dataset, report=report)
    html = render_html(changed, assess(changed, baseline))
    assert "<title>&lt;b&gt;Co&lt;/b&gt; &middot; NCA ECC Gap Assessment</title>" in html
    assert "The assessment covers &lt;b&gt;Co&lt;/b&gt; as a whole." in html
    assert "taken 12 October 2026" in html


def test_an_optional_fix_left_out_is_marked_and_not_counted(dataset, baseline, after):
    report = dataset.report.model_copy(update={"optional_fixes_applied": ()})
    changed = dataclasses.replace(dataset, report=report)
    html = render_html(changed, assess(changed, after), assess(changed, baseline))
    assert "except the optional F02, which was left out" in html
    assert "<b>1 of 1 targeted checks pass</b> (was 0)." in html
    assert '<td>2-12-3</td><td class="nowrap">Not applied</td>' in html


def test_a_single_snapshot_report_also_marks_a_fix_left_out(dataset, baseline):
    report = dataset.report.model_copy(update={"optional_fixes_applied": ()})
    changed = dataclasses.replace(dataset, report=report)
    html = render_html(changed, assess(changed, baseline))
    assert "the optional F02 is left out" in html
    assert "<b>0 of 1 targeted checks pass</b>." in html
    assert '<td>2-12-3</td><td class="nowrap">Not applied</td>' in html


def test_checks_changed_outside_the_fixes_are_listed(dataset, baseline, after):
    results = tuple(
        check.model_copy(update={"result": "failed"}) if check.id == 26001 else check
        for check in after.checks
    )
    later = after.model_copy(update={"checks": results})
    html = render_html(dataset, assess(dataset, later), assess(dataset, baseline))
    assert "No applied fix targets these checks" in html
    assert "<td>26001</td><td>1.1.2</td>" in html
    assert "<td>passed</td><td>failed</td>" in html
