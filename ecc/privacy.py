"""Keep personal names out of snapshots before they reach the disk."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from pathlib import Path

from ecc.models import Snapshot

MIN_TERM_LENGTH = 3


class PrivacyError(Exception):
    """A snapshot still contains a forbidden term, so it was not written."""


def forbidden_terms(env: Mapping[str, str], extra: Iterable[str] = ()) -> list[str]:
    """Names that must never appear in a snapshot: Windows user, computer, and any extras."""
    raw = [
        env.get("USERNAME", ""),
        env.get("COMPUTERNAME", ""),
        *env.get("ECC_FORBIDDEN_TERMS", "").split(","),
        *extra,
    ]
    terms = {term.strip() for term in raw if len(term.strip()) >= MIN_TERM_LENGTH}
    return sorted(terms, key=str.lower)


def find_leaks(text: str, terms: Iterable[str]) -> list[str]:
    lowered = text.lower()
    return [term for term in terms if term.lower() in lowered]


def snapshot_json(snapshot: Snapshot) -> str:
    return snapshot.model_dump_json(by_alias=True, indent=2) + "\n"


def write_snapshot(snapshot: Snapshot, path: Path, terms: Iterable[str]) -> None:
    """Write the snapshot, refusing leaks and never overwriting an existing file."""
    text = snapshot_json(snapshot)
    leaks = find_leaks(text, terms)
    if leaks:
        raise PrivacyError(
            f"Snapshot not written: it contains {len(leaks)} forbidden term(s). Nothing was saved. "
            "Check --label and ECC_FORBIDDEN_TERMS."
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as file:
        file.write(text)
