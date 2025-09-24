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
from .normalize import normalize_parse_stream, NodeRow, NodeKind
from .provenance import ProvenanceV2
from .cfg import build_cfg
from .dfg import build_dfg
from .effects import build_effects
from .ucg_store import UcgStore
from .python_driver import PythonLibCstDriver as PythonDriver
from .ts_driver import TSTreeSitterDriver as TsDriver
from .parser_registry import CstEvent, DriverInfo


@dataclass(frozen=True)
class Step1Config:
    """Execution knobs for Step 1 orchestration."""
    zstd_level: int = 7
    roll_rows: int = 2_000_000
    max_store_bytes: Optional[int] = None
    max_file_bytes: int = 100 * 1024 * 1024
    enable_cfg: bool = True
    enable_dfg: bool = True
    enable_symbols: bool = True
    enable_effects: bool = True
    flush_every_n_files: int = 50
    node_edge_batch: int = 4096
    cfg_batch: int = 4096
    dfg_batch: int = 4096
    sym_batch: int = 4096
    eff_batch: int = 4096


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
    symbols_rows: int
    aliases_rows: int
    effects_rows: int
    anomalies: int
    wall_ms: int


def _coerce_provenance(row: object) -> ProvenanceV2:
    prov_attr = getattr(row, "prov", None)
    if isinstance(prov_attr, ProvenanceV2):
        return prov_attr
    blob_sha = getattr(prov_attr, "blob_sha", getattr(row, "blob_sha", ""))
    lang = getattr(row, "lang")
    grammar_sha = getattr(prov_attr, "grammar_sha", "")
    run_id = getattr(prov_attr, "run_id", "")
    config_hash = getattr(prov_attr, "config_hash", "")
    byte_start = int(getattr(prov_attr, "byte_start", 0))
    byte_end = int(getattr(prov_attr, "byte_end", 0))
    line_start = int(getattr(prov_attr, "line_start", 1))
    line_end = int(getattr(prov_attr, "line_end", 1))
    enricher_versions = getattr(prov_attr, "enricher_versions", None) or {}
    confidence = getattr(prov_attr, "confidence", None)
    path = getattr(row, "path", "")
    return ProvenanceV2(
        path=path,
        blob_sha=blob_sha,
        lang=lang,
        grammar_sha=grammar_sha,
        run_id=run_id,
        config_hash=config_hash,
        byte_start=byte_start,
        byte_end=byte_end,
        line_start=line_start,
        line_end=line_end,
        enricher_versions=enricher_versions,
        confidence=confidence,
    )


def _select_driver(lang: Language):
    if lang == Language.PY:
        return PythonDriver()
    if lang in (Language.JS, Language.TS, Language.JSX, Language.TSX):
        return TsDriver(lang)
    return None


def _parse_file(file: FileMeta):
    driver = _select_driver(file.lang)
    if driver is None:
        return None, f"no-driver:{file.lang}"
    try:
        ps = driver.parse(file)
        return ps, None
    except Exception as e:
        return None, f"parse-exception:{type(e).__name__}:{e}"


def build_ucg_for_files(
    files: Iterable[FileMeta],
    out_dir: Path,
    *,
    cfg: Optional[Step1Config] = None,
    run_metadata: Optional[Dict] = None,
) -> Step1Summary:
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

    try:
        from .symbols import build_symbols
    except ImportError:
        build_symbols = None

    files_sorted = sorted(list(files), key=lambda f: (f.path, f.blob_sha or ""))

    node_edge_buf: List[Tuple[str, object]] = []
    cfg_buf: List[Tuple[str, object]] = []
    dfg_buf: List[Tuple[str, object]] = []
    sym_buf: List[Tuple[str, object]] = []
    eff_buf: List[Tuple[str, object]] = []

    def flush_buffers(force: bool = False) -> None:
        if force or len(node_edge_buf) >= cfg.node_edge_batch:
            if node_edge_buf:
                store.append(node_edge_buf)
                node_edge_buf.clear()
        if force or len(cfg_buf) >= cfg.cfg_batch:
            if cfg_buf:
                store.append_cfg(cfg_buf)
                cfg_buf.clear()
        if force or len(dfg_buf) >= cfg.dfg_batch:
            if dfg_buf:
                store.append_dfg(dfg_buf)
                dfg_buf.clear()
        if force or len(sym_buf) >= cfg.sym_batch:
            if sym_buf:
                store.append_symbols(sym_buf)
                sym_buf.clear()
        if force or len(eff_buf) >= cfg.eff_batch:
            if eff_buf and hasattr(store, "append_effects"):
                store.append_effects(eff_buf)
                eff_buf.clear()

    for i, fm in enumerate(files_sorted, start=1):
        files_total += 1

        if not fm.is_text:
            sink.emit(Anomaly(path=fm.path, blob_sha=fm.blob_sha, kind=AnomalyKind.BINARY_FILE, severity=Severity.INFO, detail="binary-or-nontext"))
            continue
        if fm.size_bytes is not None and fm.size_bytes > cfg.max_file_bytes:
            sink.emit(Anomaly(path=fm.path, blob_sha=fm.blob_sha, kind=AnomalyKind.MEMORY_LIMIT, severity=Severity.ERROR, detail=f"file-too-large:{fm.size_bytes}"))
            continue

        ps, perr = _parse_file(fm)
        if ps is None or not ps.ok:
            sink.emit(Anomaly(path=fm.path, blob_sha=fm.blob_sha, kind=AnomalyKind.PARSE_FAILED, severity=Severity.ERROR, detail=f"{perr or ps.error} path={fm.path} lang={fm.lang}"))
            continue

        files_parsed += 1

        driver_info: Optional[DriverInfo] = getattr(ps, "driver", None)
        try:
            event_list: List[CstEvent] = list(ps.events) if ps.events is not None else []
        except Exception as e:
            sink.emit(Anomaly(path=fm.path, blob_sha=fm.blob_sha, kind=AnomalyKind.UNKNOWN, severity=Severity.ERROR, detail=f"event-materialization-exception:{type(e).__name__}:{e}"))
            continue
        
        if not event_list:
            continue

        try:
            for item in normalize_parse_stream(fm, driver_info, event_list, sink):
                if item[0] in ("node", "edge"):
                    node_edge_buf.append(item)
            if len(node_edge_buf) >= cfg.node_edge_batch:
                flush_buffers()
        except Exception as e:
            sink.emit(Anomaly(path=fm.path, blob_sha=fm.blob_sha, kind=AnomalyKind.UNKNOWN, severity=Severity.ERROR, detail=f"normalize-exception:{type(e).__name__}:{e}"))

        if cfg.enable_cfg:
            try:
                for item in build_cfg(fm, driver_info, event_list, sink):
                    cfg_buf.append(item)
                if len(cfg_buf) >= cfg.cfg_batch:
                    flush_buffers()
            except Exception as e:
                sink.emit(Anomaly(path=fm.path, blob_sha=fm.blob_sha, kind=AnomalyKind.UNKNOWN, severity=Severity.ERROR, detail=f"cfg-exception:{type(e).__name__}:{e}"))

        alias_hints = []
        if cfg.enable_dfg:
            try:
                for item_kind, item_data in build_dfg(fm, driver_info, event_list, sink):
                    if item_kind == "alias_hint":
                        alias_hints.append(item_data)
                    else:
                        dfg_buf.append((item_kind, item_data))
                if len(dfg_buf) >= cfg.dfg_batch:
                    flush_buffers()
            except Exception as e:
                sink.emit(Anomaly(path=fm.path, blob_sha=fm.blob_sha, kind=AnomalyKind.UNKNOWN, severity=Severity.ERROR, detail=f"dfg-exception:{type(e).__name__}:{e}"))

        if cfg.enable_symbols and build_symbols is not None:
            try:
                for item in build_symbols(fm, driver_info, event_list, sink, alias_hints=alias_hints):
                    sym_buf.append(item)
                if len(sym_buf) >= cfg.sym_batch:
                    flush_buffers()
            except Exception as e:
                sink.emit(Anomaly(path=fm.path, blob_sha=fm.blob_sha, kind=AnomalyKind.UNKNOWN, severity=Severity.ERROR, detail=f"symbols-exception:{type(e).__name__}:{e}"))

        if cfg.enable_effects:
            try:
                for item in build_effects(fm, driver_info, event_list, sink):
                    eff_buf.append(item)
                if len(eff_buf) >= cfg.eff_batch:
                    flush_buffers()
            except Exception as e:
                sink.emit(Anomaly(path=fm.path, blob_sha=fm.blob_sha, kind=AnomalyKind.UNKNOWN, severity=Severity.ERROR, detail=f"effects-exception:{type(e).__name__}:{e}"))

        if (i % max(1, cfg.flush_every_n_files)) == 0:
            flush_buffers(force=True)
            store.flush()
            if sink._buffer:
                store.append_anomalies(sink.drain())

    flush_buffers(force=True)
    store.flush()
    if sink._buffer:
        store.append_anomalies(sink.drain())

    store.finalize(receipt={"run_meta": run_metadata or {}, "step": "step1_ucg"})

    wall_ms = int((time.time() - start) * 1000)

    summary = Step1Summary(
        files_total=files_total,
        files_parsed=files_parsed,
        nodes_rows=getattr(store, "_node_rows_total", 0),
        edges_rows=getattr(store, "_edge_rows_total", 0),
        cfg_blocks_rows=getattr(store, "_cfg_block_rows_total", 0),
        cfg_edges_rows=getattr(store, "_cfg_edge_rows_total", 0),
        dfg_nodes_rows=getattr(store, "_dfg_node_rows_total", 0),
        dfg_edges_rows=getattr(store, "_dfg_edge_rows_total", 0),
        symbols_rows=getattr(store, "_symbol_rows_total", 0),
        aliases_rows=getattr(store, "_alias_rows_total", 0),
        effects_rows=getattr(store, "_effect_rows_total", 0),
        anomalies=sink.counters().get("total", 0),
        wall_ms=wall_ms,
    )
    return summary