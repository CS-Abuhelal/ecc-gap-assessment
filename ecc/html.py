"""Render the report page and print it to PDF with headless Chrome or Edge."""

from __future__ import annotations

import shutil
import subprocess
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from jinja2 import Environment, PackageLoader, select_autoescape

from ecc.assess import Assessment, compare, compliance, domain_scores
from ecc.load import Dataset
from ecc.models import Status
from ecc.risk import BUCKET_ORDER, rating, risk_rows, roadmap

BROWSER_NAMES = ("chrome", "google-chrome", "google-chrome-stable", "chromium", "msedge")
WINDOWS_BROWSERS = (
    "C:/Program Files/Google/Chrome/Application/chrome.exe",
    "C:/Program Files (x86)/Google/Chrome/Application/chrome.exe",
    "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe",
    "C:/Program Files/Microsoft/Edge/Application/msedge.exe",
)
STATUS_CLASS = {
    Status.IMPLEMENTED: "ok",
    Status.PARTIAL: "part",
    Status.NOT_IMPLEMENTED: "gap",
    Status.NOT_APPLICABLE: "na",
}
RATING_CLASS = {"Low": "low", "Medium": "medium", "High": "high", "Critical": "critical"}


class PdfError(Exception):
    """The PDF could not be printed."""


def environment() -> Environment:
    return Environment(
        loader=PackageLoader("ecc", "templates"),
        autoescape=select_autoescape(["html", "j2"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )


def report_context(
    dataset: Dataset, after: Assessment, before: Assessment | None = None
) -> dict[str, Any]:
    titles = {control.domain: control.domain_title for control in dataset.catalog}
    after_domains = domain_scores(after)
    before_domains = domain_scores(before) if before is not None else {}
    rows = risk_rows(dataset.risks, after)
    open_rows = [row for row in rows if not row.closed]
    heatmap = [
        [
            sum(1 for row in open_rows if (row.risk.likelihood, row.risk.impact) == (lk, im))
            for lk in range(1, 6)
        ]
        for im in range(5, 0, -1)
    ]
    domains = [
        {"id": d, "title": titles[d], "after": after_domains[d], "before": before_domains.get(d)}
        for d in after_domains
    ]
    return {
        "snapshot": after.snapshot,
        "before_snapshot": before.snapshot if before is not None else None,
        "overall": compliance(after.results),
        "overall_before": compliance(before.results) if before is not None else None,
        "domains": domains,
        "statuses": list(Status),
        "counts": {s: sum(1 for r in after.results if r.status is s) for s in Status},
        "results": after.results,
        "changes": compare(before, after) if before is not None else (),
        "risks": rows,
        "open_risks": open_rows,
        "heatmap": heatmap,
        "roadmap": roadmap(rows),
        "bucket_order": BUCKET_ORDER,
        "rules": dataset.mapping.rules,
        "not_applicable": [r for r in after.results if r.status is Status.NOT_APPLICABLE],
        "check_count": len(dataset.policy.checks),
        "policy_name": dataset.policy.policy.name,
        "status_class": STATUS_CLASS,
        "rating_class": RATING_CLASS,
        "rating": rating,
    }


def render_html(dataset: Dataset, after: Assessment, before: Assessment | None = None) -> str:
    template = environment().get_template("report.html.j2")
    return template.render(**report_context(dataset, after, before))


def find_browser(env: Mapping[str, str]) -> str | None:
    if env.get("CHROME"):
        return env["CHROME"]
    for name in BROWSER_NAMES:
        found = shutil.which(name)
        if found:
            return found
    for path in WINDOWS_BROWSERS:
        if Path(path).is_file():
            return path
    return None


def write_pdf(html_path: Path, pdf_path: Path, browser: str) -> None:
    command = [
        browser,
        "--headless=new",
        "--disable-gpu",
        "--no-pdf-header-footer",
        f"--print-to-pdf={pdf_path.resolve()}",
        html_path.resolve().as_uri(),
    ]
    try:
        subprocess.run(command, check=True, capture_output=True, timeout=120)
    except (OSError, subprocess.SubprocessError) as error:
        raise PdfError(f"Printing the PDF with {Path(browser).name} failed: {error}") from error
    if not pdf_path.is_file() or pdf_path.stat().st_size == 0:
        raise PdfError("The browser finished without writing the PDF.")
