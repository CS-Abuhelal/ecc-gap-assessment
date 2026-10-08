"""Read the YAML data files and JSON snapshots into models."""

from __future__ import annotations

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
    RiskRegister,
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


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as error:
        raise DataError(f"{path.name}: cannot read the file ({error.strerror}).") from error


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
    data = root / "data"
    return Dataset(
        root=root,
        catalog=load_catalog(data / "catalog.yaml"),
        policy=load_model(CisPolicy, data / "cis_checks.yaml"),
        mapping=load_model(Mapping, data / "mapping.yaml"),
        evidence=load_model(Evidence, data / "evidence.yaml"),
        applicability=load_model(Applicability, data / "applicability.yaml"),
        risks=load_model(RiskRegister, data / "risks.yaml"),
    )


def load_snapshot(path: Path) -> Snapshot:
    try:
        return Snapshot.model_validate_json(read_text(path))
    except ValidationError as error:
        raise DataError(f"{path.name}: {error}") from error


def load_snapshots(directory: Path) -> list[Snapshot]:
    if not directory.is_dir():
        return []
    snapshots = [load_snapshot(path) for path in sorted(directory.glob("*.json"))]
    return sorted(snapshots, key=lambda snapshot: snapshot.taken_at)
