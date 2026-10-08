"""Command line: collect a snapshot, check the data, build the outputs."""

from __future__ import annotations

import argparse
import os
import re
import sys
from collections import Counter
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path

from ecc.assess import assess, compliance
from ecc.collect import CollectError, Indexer, IndexerSettings, collect, snapshot_path
from ecc.excel import write_workbook
from ecc.html import PdfError, find_browser, render_html, write_pdf
from ecc.load import DataError, load_dataset, load_model, load_snapshots
from ecc.models import LABEL_PATTERN, CisPolicy, Snapshot
from ecc.privacy import PrivacyError, forbidden_terms, write_snapshot
from ecc.validate import validate

WORKBOOK = "ecc-gap-assessment.xlsx"
PAGE = "index.html"
PDF = "ecc-gap-assessment.pdf"


def label(value: str) -> str:
    if not re.fullmatch(LABEL_PATTERN, value):
        raise argparse.ArgumentTypeError("use lowercase letters, digits and dashes, e.g. baseline")
    return value


def parser() -> argparse.ArgumentParser:
    top = argparse.ArgumentParser(prog="python -m ecc", description=__doc__)
    commands = top.add_subparsers(dest="command", required=True)
    collect_cmd = commands.add_parser("collect", help="read Wazuh and write a snapshot")
    collect_cmd.add_argument("--label", type=label, required=True)
    collect_cmd.add_argument("--agent", help="Wazuh agent name, if more than one has results")
    check_cmd = commands.add_parser("check", help="validate the data files and snapshots")
    build_cmd = commands.add_parser("build", help="write the workbook, web page and PDF")
    build_cmd.add_argument("--after", type=label, help="snapshot to report (default: newest)")
    build_cmd.add_argument("--before", type=label, help="snapshot to compare against")
    build_cmd.add_argument("--no-pdf", action="store_true", help="skip printing the PDF")
    for command in (collect_cmd, check_cmd, build_cmd):
        command.add_argument("--root", default=".", help="repository root (default: .)")
    return top


def main(
    argv: Sequence[str] | None = None,
    env: Mapping[str, str] | None = None,
    now: datetime | None = None,
) -> int:
    args = parser().parse_args(argv)
    env = os.environ if env is None else env
    root = Path(args.root)
    try:
        if args.command == "collect":
            return run_collect(root, args, env, now or datetime.now(UTC))
        if args.command == "check":
            return run_check(root)
        return run_build(root, args, env)
    except (DataError, CollectError, PrivacyError, PdfError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    except FileExistsError as error:
        name = Path(str(error.filename)).name
        print(f"Error: {name} already exists. Choose another --label.", file=sys.stderr)
        return 1


def run_collect(
    root: Path, args: argparse.Namespace, env: Mapping[str, str], now: datetime
) -> int:
    policy = load_model(CisPolicy, root / "data" / "cis_checks.yaml")
    settings = IndexerSettings.from_env(env)
    with settings.client() as client:
        indexer = Indexer(client, settings.server_name)
        collected = collect(indexer, policy, args.label, now, args.agent)
    path = snapshot_path(root / "snapshots", collected.snapshot)
    write_snapshot(collected.snapshot, path, forbidden_terms(env, extra=[collected.agent]))
    counts = Counter(check.result for check in collected.snapshot.checks)
    print(
        f"Wrote snapshots/{path.name}: {counts['passed']} passed, {counts['failed']} failed, "
        f"{counts['not applicable']} not applicable, {counts['not scanned']} not scanned."
    )
    print("Review the file before committing it.")
    return 0


def report(problems: Sequence[str]) -> None:
    print(f"{len(problems)} problem(s):", file=sys.stderr)
    for problem in problems:
        print(f"- {problem}", file=sys.stderr)


def run_check(root: Path) -> int:
    dataset = load_dataset(root)
    snapshots = load_snapshots(root / "snapshots")
    problems = validate(dataset, snapshots)
    if problems:
        report(problems)
        return 1
    print(
        f"OK: {len(dataset.catalog)} controls, {len(dataset.policy.checks)} checks, "
        f"{len(snapshots)} snapshot(s)."
    )
    return 0


def pick(snapshots: Sequence[Snapshot], wanted: str) -> Snapshot:
    for snapshot in snapshots:
        if snapshot.label == wanted:
            return snapshot
    raise DataError(f"No snapshot with label '{wanted}' in snapshots/.")


def run_build(root: Path, args: argparse.Namespace, env: Mapping[str, str]) -> int:
    dataset = load_dataset(root)
    snapshots = load_snapshots(root / "snapshots")
    if not snapshots:
        raise DataError("No snapshots yet. Run 'python -m ecc collect --label baseline' first.")
    problems = validate(dataset, snapshots)
    if problems:
        report(problems)
        return 1
    after = assess(dataset, pick(snapshots, args.after) if args.after else snapshots[-1])
    before = assess(dataset, pick(snapshots, args.before)) if args.before else None
    out = root / "build"
    out.mkdir(exist_ok=True)
    write_workbook(out / WORKBOOK, dataset, after, before)
    (out / PAGE).write_text(render_html(dataset, after, before), encoding="utf-8")
    built = [WORKBOOK, PAGE]
    if not args.no_pdf:
        browser = find_browser(env)
        if browser is None:
            raise PdfError(
                "Chrome or Edge was not found. Set CHROME to the browser's path, or use --no-pdf."
            )
        write_pdf(out / PAGE, out / PDF, browser)
        built.append(PDF)
    names = ", ".join(f"build/{name}" for name in built)
    score = compliance(after.results)
    print(f"Built {names}: {score}% compliant ({after.snapshot.label}).")
    return 0
