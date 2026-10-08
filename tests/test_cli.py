import shutil

import pytest

from ecc import cli
from ecc.collect import Collected
from ecc.models import Snapshot
from tests.fixtures import BASELINE, RISKS, rewrite

ENV = {"WAZUH_INDEXER_URL": "https://indexer.test", "USERNAME": "jdoe"}


def run(*args: str, env: dict[str, str] | None = None) -> int:
    return cli.main(list(args), env=ENV if env is None else env)


def fake_collect(indexer, policy, label, now, agent=None) -> Collected:
    return Collected(Snapshot.model_validate({**BASELINE, "label": label}), "lab-agent")


def test_check_passes_on_valid_data(root, capsys):
    assert run("check", "--root", str(root)) == 0
    assert "OK: 5 controls, 4 checks, 2 snapshot(s)." in capsys.readouterr().out


def test_check_lists_problems(root, capsys):
    rewrite(root, "risks.yaml", {"risks": RISKS["risks"][1:]})
    assert run("check", "--root", str(root)) == 1
    err = capsys.readouterr().err
    assert "1 problem(s):" in err
    assert "gaps with no risk" in err


def test_build_writes_the_workbook_and_page(root, capsys):
    assert run("build", "--root", str(root), "--before", "baseline", "--no-pdf") == 0
    assert (root / "build" / "ecc-gap-assessment.xlsx").is_file()
    assert "What changed" in (root / "build" / "index.html").read_text(encoding="utf-8")
    assert "75.0% compliant (after)" in capsys.readouterr().out


def test_build_reports_a_chosen_snapshot(root, capsys):
    assert run("build", "--root", str(root), "--after", "baseline", "--no-pdf") == 0
    assert "50.0% compliant (baseline)" in capsys.readouterr().out


def test_build_with_an_unknown_label_fails(root, capsys):
    assert run("build", "--root", str(root), "--after", "nope", "--no-pdf") == 1
    assert "No snapshot with label 'nope'" in capsys.readouterr().err


def test_build_without_a_browser_fails_cleanly(root, capsys, monkeypatch):
    monkeypatch.setattr(cli, "find_browser", lambda env: None)
    assert run("build", "--root", str(root)) == 1
    assert "Chrome or Edge was not found" in capsys.readouterr().err


def test_collect_writes_a_snapshot_for_review(root, capsys, monkeypatch):
    monkeypatch.setattr(cli, "collect", fake_collect)
    assert run("collect", "--root", str(root), "--label", "test") == 0
    assert (root / "snapshots" / "2026-10-test.json").is_file()
    out = capsys.readouterr().out
    assert "1 passed, 2 failed, 1 not applicable, 0 not scanned" in out
    assert "Review the file before committing it." in out


def test_collect_refuses_a_forbidden_term(root, capsys, monkeypatch):
    monkeypatch.setattr(cli, "collect", fake_collect)
    env = {**ENV, "ECC_FORBIDDEN_TERMS": "WS-01"}
    assert run("collect", "--root", str(root), "--label", "test", env=env) == 1
    assert not (root / "snapshots" / "2026-10-test.json").exists()
    assert "forbidden term" in capsys.readouterr().err


def test_collect_never_overwrites(root, capsys, monkeypatch):
    monkeypatch.setattr(cli, "collect", fake_collect)
    assert run("collect", "--root", str(root), "--label", "baseline") == 1
    assert "2026-10-baseline.json already exists" in capsys.readouterr().err


def test_collect_needs_the_indexer_url(root, capsys):
    assert run("collect", "--root", str(root), "--label", "test", env={}) == 1
    assert "WAZUH_INDEXER_URL" in capsys.readouterr().err


def test_labels_must_be_simple(root):
    with pytest.raises(SystemExit):
        run("collect", "--root", str(root), "--label", "Bad Label")


def test_collect_refuses_the_real_agent_name(root, capsys, monkeypatch):
    monkeypatch.setattr(cli, "collect", fake_collect)
    assert run("collect", "--root", str(root), "--label", "lab-agent") == 1
    assert not list((root / "snapshots").glob("*lab-agent*"))
    assert "forbidden term" in capsys.readouterr().err


def test_collect_refuses_the_windows_user_name(root, capsys, monkeypatch):
    monkeypatch.setattr(cli, "collect", fake_collect)
    assert run("collect", "--root", str(root), "--label", "jdoe") == 1
    assert not list((root / "snapshots").glob("*jdoe*"))


def test_build_with_invalid_data_writes_nothing(root, capsys):
    rewrite(root, "risks.yaml", {"risks": RISKS["risks"][1:]})
    assert run("build", "--root", str(root), "--no-pdf") == 1
    assert not (root / "build").exists()
    assert "gaps with no risk" in capsys.readouterr().err


def test_build_without_a_browser_writes_nothing(root, capsys, monkeypatch):
    monkeypatch.setattr(cli, "find_browser", lambda env: None)
    assert run("build", "--root", str(root)) == 1
    assert not (root / "build").exists()


def test_a_locked_output_file_is_a_clear_error(root, capsys):
    (root / "build" / "ecc-gap-assessment.xlsx").mkdir(parents=True)
    assert run("build", "--root", str(root), "--no-pdf") == 1
    err = capsys.readouterr().err
    assert "Error: cannot write ecc-gap-assessment.xlsx" in err
    assert "Traceback" not in err


def test_a_snapshots_folder_that_is_a_file_is_a_clear_error(root, capsys, monkeypatch):
    monkeypatch.setattr(cli, "collect", fake_collect)
    shutil.rmtree(root / "snapshots")
    (root / "snapshots").write_text("not a folder", encoding="utf-8")
    assert run("collect", "--root", str(root), "--label", "test") == 1
    err = capsys.readouterr().err
    assert "Error: cannot write snapshots" in err
    assert "already exists. Choose another --label" not in err
