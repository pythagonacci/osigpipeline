# src/provis/ucg/api.py
from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Tuple

from .discovery import (
    FileMeta,
    Language,
    Anomaly,
    AnomalyKind,
    AnomalySink,
    Severity,
)
from .normalize import normalize_parse_stream
from .cfg import build_cfg
from .dfg import build_dfg
from .ucg_store import UcgStore
# If you added these drivers; otherwise, swap in your actual parser integrations.
from .python_driver import PythonDriver  # type: ignore
from .ts_driver import TsDriver          # type: ignore

# CST event types (imported for type hints only; not strictly required here)
from .parser_registry import ParseStream  # type: ignore


@dataclass(frozen=True)
class Step1Config:
    """
    Execution knobs for Step 1 orchestration.
    """
    zstd_level: int = 7
    roll_rows: int = 2_000_000
    max_store_bytes: Optional[int] = None
    # Guards
    max_file_bytes: int = 100 * 1024 * 1024  # 100MB per file hard cap
    # Whether to compute CFG/DFG (allow disabling during bring-up)
    enable_cfg: bool = True
    enable_dfg: bool = True


@dataclass(frozen=True)
class Step1Summary:
    files_total: int
    files_parsed: int
    nodes_rows: int
    edges_rows: int
    cfg_blocks_rows: int
    cfg_edges_rows: int
    dfg_nodes_rows: int
    dfg_edges_rows: int
    anomalies: int
    wall_ms: int


def _select_driver(lang: Language):
    """
    Map Language -> parser driver instance.
    Extend here for more languages.
    """
    if lang == Language.PY:
        return PythonDriver()
    if lang in (Language.JS, Language.TS, Language.JSX, Language.TSX):
        return TsDriver(lang)  # TsDriver should accept the specific JS/TS flavor
    # No driver → return None
    return None


def _parse_file(file: FileMeta):
    """
    Produce a ParseStream for a file using the right driver, or an error.
    """
    driver = _select_driver(file.lang)
    if driver is None:
        return None, f"no-driver:{file.lang}"
    try:
        ps = driver.parse(file)
        return ps, None
    except Exception as e:  # pragma: no cover (driver-specific)
        return None, f"parse-exception:{type(e).__name__}:{e}"


def build_ucg_for_files(
    files: Iterable[FileMeta],
    out_dir: Path,
    *,
    cfg: Optional[Step1Config] = None,
    run_metadata: Optional[Dict] = None,
) -> Step1Summary:
    """
    High-level Step 1 runner:
      - parses files → normalize → CFG (opt) → DFG (opt) → writes Parquet via UcgStore
      - captures anomalies and publishes a single atomic output directory

    Returns a Step1Summary with useful counters.
    """
    cfg = cfg or Step1Config()
    start = time.time()

    store = UcgStore(
        out_dir,
        zstd_level=cfg.zstd_level,
        roll_rows=cfg.roll_rows,
        max_bytes=cfg.max_store_bytes,
    )
    sink = AnomalySink()

    files_total = 0
    files_parsed = 0

    # Process files deterministically by (path, blob_sha)
    files_sorted = sorted(list(files), key=lambda f: (f.path, f.blob_sha or ""))

    for fm in files_sorted:
        files_total += 1

        # Guards
        if not fm.is_text:
            sink.emit(
                Anomaly(
                    path=fm.path,
                    blob_sha=fm.blob_sha,
                    kind=AnomalyKind.SKIPPED,
                    severity=Severity.INFO,
                    detail="binary-or-nontext",
                )
            )
            continue
        if fm.size_bytes is not None and fm.size_bytes > cfg.max_file_bytes:
            sink.emit(
                Anomaly(
                    path=fm.path,
                    blob_sha=fm.blob_sha,
                    kind=AnomalyKind.MEMORY_LIMIT,
                    severity=Severity.ERROR,
                    detail=f"file-too-large:{fm.size_bytes}",
                )
            )
            continue

        # Parse
        ps, perr = _parse_file(fm)
        if ps is None:
            sink.emit(
                Anomaly(
                    path=fm.path,
                    blob_sha=fm.blob_sha,
                    kind=AnomalyKind.PARSE_FAILED,
                    severity=Severity.ERROR,
                    detail=perr or "parse-failed",
                )
            )
            continue

        files_parsed += 1

        # Normalize → Nodes/Edges
        try:
            for item in normalize_parse_stream(ps, sink):
                # item is ("node", NodeRow) or ("edge", EdgeRow)
                store.append([item])
        except Exception as e:
            sink.emit(
                Anomaly(
                    path=fm.path,
                    blob_sha=fm.blob_sha,
                    kind=AnomalyKind.UNKNOWN,
                    severity=Severity.ERROR,
                    detail=f"normalize-exception:{type(e).__name__}:{e}",
                )
            )

        # CFG (optional)
        if cfg.enable_cfg:
            try:
                for item in build_cfg(ps, sink):
                    # item is ("cfg_block", BlockRow) or ("cfg_edge", CfgEdgeRow)
                    store.append_cfg([item])
            except Exception as e:
                sink.emit(
                    Anomaly(
                        path=fm.path,
                        blob_sha=fm.blob_sha,
                        kind=AnomalyKind.UNKNOWN,
                        severity=Severity.ERROR,
                        detail=f"cfg-exception:{type(e).__name__}:{e}",
                    )
                )

        # DFG (optional)
        if cfg.enable_dfg:
            try:
                for item in build_dfg(ps, sink):
                    # item is ("dfg_node", DfgNodeRow) or ("dfg_edge", DfgEdgeRow)
                    store.append_dfg([item])
            except Exception as e:
                sink.emit(
                    Anomaly(
                        path=fm.path,
                        blob_sha=fm.blob_sha,
                        kind=AnomalyKind.UNKNOWN,
                        severity=Severity.ERROR,
                        detail=f"dfg-exception:{type(e).__name__}:{e}",
                    )
                )

        # Periodically flush (keeps memory bounded on huge repos)
        if (files_parsed % 50) == 0:
            store.flush()
            # push anomalies collected so far
            store.append_anomalies(sink.drain())

    # Final flush + anomalies
    store.flush()
    store.append_anomalies(sink.drain())

    # Publish
    store.finalize(
        receipt={
            "run_meta": run_metadata or {},
            "step": "step1_ucg",
        }
    )

    wall_ms = int((time.time() - start) * 1000)
    # We can read back counts from receipt, but we tracked major ones via store; for simplicity, return zeros for per-table
    # (DuckDB catalog has exact numbers; if needed, parse store receipt JSON after finalize.)
    return Step1Summary(
        files_total=files_total,
        files_parsed=files_parsed,
        nodes_rows=0,
        edges_rows=0,
        cfg_blocks_rows=0,
        cfg_edges_rows=0,
        dfg_nodes_rows=0,
        dfg_edges_rows=0,
        anomalies=0,
        wall_ms=wall_ms,
    )
