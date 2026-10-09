"""Read the YAML data files and JSON snapshots into models."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TypeVar

import yaml
from pydantic import BaseModel, ValidationError

from ecc.models import (
    Applicability,
    CatalogFile,
    CisPolicy,
    Control,
    Evidence,
    Mapping,
    ReportText,
    RiskRegister,
    SamaFramework,
    SamaMapping,
    Snapshot,
)

ModelT = TypeVar("ModelT", bound=BaseModel)


class DataError(Exception):
    """A data file is missing, unreadable or does not match its model."""


@dataclass(frozen=True)
class Dataset:
    root: Path
    catalog: tuple[Control, ...]
    policy: CisPolicy
    mapping: Mapping
    evidence: Evidence
    applicability: Applicability
    risks: RiskRegister
    report: ReportText
    sama: SamaFramework
    sama_mapping: SamaMapping


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as error:
        raise DataError(f"{path.name}: cannot read the file ({error.strerror}).") from error
    except UnicodeDecodeError as error:
        raise DataError(f"{path.name}: not UTF-8 text ({error.reason}).") from error


def load_model(model: type[ModelT], path: Path) -> ModelT:
    try:
        data: Any = yaml.safe_load(read_text(path))
    except yaml.YAMLError as error:
        raise DataError(f"{path.name}: not valid YAML ({error}).") from error
    try:
        return model.model_validate(data)
    except ValidationError as error:
        raise DataError(f"{path.name}: {error}") from error


def load_catalog(path: Path) -> tuple[Control, ...]:
    catalog = load_model(CatalogFile, path)
    return tuple(
        Control(
            id=entry.id,
            domain=domain.id,
            domain_title=domain.title,
            subdomain=subdomain.id,
            subdomain_title=subdomain.title,
            text=entry.text,
            subcontrols=entry.subcontrols,
        )
        for domain in catalog.domains
        for subdomain in domain.subdomains
        for entry in subdomain.controls
    )


def load_dataset(root: Path) -> Dataset:
    """Read all nine data files; if any are broken, report every one of them together."""
    data = root / "data"
    readers: dict[str, Callable[[], Any]] = {
        "catalog": lambda: load_catalog(data / "catalog.yaml"),
        "policy": lambda: load_model(CisPolicy, data / "cis_checks.yaml"),
        "mapping": lambda: load_model(Mapping, data / "mapping.yaml"),
        "evidence": lambda: load_model(Evidence, data / "evidence.yaml"),
        "applicability": lambda: load_model(Applicability, data / "applicability.yaml"),
        "risks": lambda: load_model(RiskRegister, data / "risks.yaml"),
        "report": lambda: load_model(ReportText, data / "report.yaml"),
        "sama": lambda: load_model(SamaFramework, data / "sama_csf.yaml"),
        "sama_mapping": lambda: load_model(SamaMapping, data / "sama_mapping.yaml"),
    }
    loaded: dict[str, Any] = {}
    errors: list[str] = []
    for name, read in readers.items():
        try:
            loaded[name] = read()
        except DataError as error:
            errors.append(str(error))
    if errors:
        raise DataError("\n".join(errors))
    return Dataset(root=root, **loaded)


def load_snapshot(path: Path) -> Snapshot:
    try:
        return Snapshot.model_validate_json(read_text(path))
    except ValidationError as error:
        raise DataError(f"{path.name}: {error}") from error


def load_snapshots(directory: Path) -> list[Snapshot]:
    if not directory.is_dir():
        return []
    snapshots: list[Snapshot] = []
    errors: list[str] = []
    for path in sorted(directory.glob("*.json")):
        try:
            snapshots.append(load_snapshot(path))
        except DataError as error:
            errors.append(str(error))
    if errors:
        raise DataError("\n".join(errors))
    return sorted(snapshots, key=lambda snapshot: snapshot.taken_at)
