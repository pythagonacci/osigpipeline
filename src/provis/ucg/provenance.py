"""Shared provenance model with richer metadata and Arrow serialization helpers."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Mapping, MutableMapping, Optional, Union

from .discovery import FileMeta, Language
from .parser_registry import CstEvent, DriverInfo

ConfidenceValue = Union[str, float, int]


def _default_confidence() -> Dict[str, ConfidenceValue]:
    return {"structure": "high"}


def _normalize_enricher_versions(
    base: Optional[Mapping[str, str]],
    info: Optional[DriverInfo],
) -> Dict[str, str]:
    versions: Dict[str, str] = {}
    if info is not None and info.version:
        key = info.grammar_name or info.language.value
        versions[key] = str(info.version)
    if base:
        for k, v in base.items():
            if not k:
                continue
            versions[k] = str(v)
    return versions


def _normalize_confidence(conf: Optional[Mapping[str, ConfidenceValue]]) -> Dict[str, ConfidenceValue]:
    normalized: Dict[str, ConfidenceValue] = {}
    if conf:
        for k, v in conf.items():
            if not k or v is None:
                continue
            if isinstance(v, (int, float)):
                normalized[k] = float(v)
            else:
                normalized[k] = str(v)
    if not normalized:
        normalized.update(_default_confidence())
    return normalized


def _confidence_to_arrow(conf: Mapping[str, ConfidenceValue]) -> Dict[str, Dict[str, Optional[float]]]:
    arrow_map: Dict[str, Dict[str, Optional[float]]] = {}
    for key, value in conf.items():
        if isinstance(value, (int, float)):
            arrow_map[key] = {"string_value": None, "double_value": float(value)}
        else:
            arrow_map[key] = {"string_value": str(value), "double_value": None}
    return arrow_map


@dataclass(frozen=True)
class ProvenanceV2:
    path: str
    blob_sha: str
    lang: Language
    grammar_sha: str
    run_id: str
    config_hash: str
    byte_start: int
    byte_end: int
    line_start: int
    line_end: int
    enricher_versions: Mapping[str, str] = field(default_factory=dict)
    confidence: Mapping[str, ConfidenceValue] = field(default_factory=_default_confidence)

    def __post_init__(self) -> None:
        object.__setattr__(self, "enricher_versions", dict(self.enricher_versions))
        object.__setattr__(self, "confidence", _normalize_confidence(self.confidence))

    def base_columns(self, prefix: str = "prov_") -> Dict[str, object]:
        return {
            f"{prefix}path": self.path,
            f"{prefix}blob_sha": self.blob_sha,
            f"{prefix}lang": getattr(self.lang, "value", str(self.lang)),
            f"{prefix}grammar_sha": self.grammar_sha,
            f"{prefix}run_id": self.run_id,
            f"{prefix}config_hash": self.config_hash,
            f"{prefix}byte_start": int(self.byte_start),
            f"{prefix}byte_end": int(self.byte_end),
            f"{prefix}line_start": int(self.line_start),
            f"{prefix}line_end": int(self.line_end),
        }

    def v2_columns(self, prefix: str = "prov_") -> Dict[str, object]:
        return {
            f"{prefix}enricher_versions": dict(self.enricher_versions),
            f"{prefix}confidence": _confidence_to_arrow(self.confidence),
        }


def build_provenance(
    fm: FileMeta,
    info: Optional[DriverInfo],
    *,
    byte_start: int,
    byte_end: int,
    line_start: int,
    line_end: int,
    enricher_versions: Optional[Mapping[str, str]] = None,
    confidence: Optional[Mapping[str, ConfidenceValue]] = None,
) -> ProvenanceV2:
    return ProvenanceV2(
        path=fm.path,
        blob_sha=fm.blob_sha,
        lang=fm.lang,
        grammar_sha=info.grammar_sha if info else "",
        run_id=fm.run_id,
        config_hash=fm.config_hash,
        byte_start=byte_start,
        byte_end=byte_end,
        line_start=line_start,
        line_end=line_end,
        enricher_versions=_normalize_enricher_versions(enricher_versions, info),
        confidence=_normalize_confidence(confidence),
    )


def build_provenance_from_event(
    fm: FileMeta,
    info: Optional[DriverInfo],
    ev: CstEvent,
    *,
    enricher_versions: Optional[Mapping[str, str]] = None,
    confidence: Optional[Mapping[str, ConfidenceValue]] = None,
) -> ProvenanceV2:
    return build_provenance(
        fm,
        info,
        byte_start=ev.byte_start,
        byte_end=ev.byte_end,
        line_start=ev.line_start,
        line_end=ev.line_end,
        enricher_versions=enricher_versions,
        confidence=confidence,
    )


# Backwards compatibility alias for existing imports.
Provenance = ProvenanceV2
