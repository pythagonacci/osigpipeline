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
from .cfg import build_cfg  # optional
from .dfg import build_dfg  # optional
from .effects import build_effects  # optional
from .ucg_store import UcgStore
# If you added these drivers; otherwise, swap in your actual parser integrations.
from .python_driver import PythonLibCstDriver as PythonDriver  # type: ignore
from .ts_driver import TSTreeSitterDriver as TsDriver          # type: ignore

# CST event types (imported for type hints only; not strictly required here)
# from .parser_registry import ParseStream  # type: ignore


@dataclass(frozen=True)
class Step1Config:
    """Execution knobs for Step 1 orchestration."""
    zstd_level: int = 7
    roll_rows: int = 2_000_000
    max_store_bytes: Optional[int] = None
    # Guards
    max_file_bytes: int = 100 * 1024 * 1024  # 100MB per file hard cap
    # Whether to compute CFG/DFG (allow disabling during bring-up)
    enable_cfg: bool = True
    enable_dfg: bool = True
    enable_symbols: bool = True
    enable_effects: bool = True
    # Flush cadence (keeps memory bounded)
    flush_every_n_files: int = 50
    # Batch sizes for appends
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


def _select_driver(lang: Language):
    """Map Language -> parser driver instance. Extend here for more languages."""
    if lang == Language.PY:
        return PythonDriver()
    if lang in (Language.JS, Language.TS, Language.JSX, Language.TSX):
        return TsDriver(lang)  # TsDriver should accept the specific JS/TS flavor
    # No driver → return None
    return None


def _parse_file(file: FileMeta):
    """Produce a parse stream for a file using the right driver, or an error."""
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
      - parses files → normalize → CFG (opt) → DFG (opt) → symbols/aliases (opt) → effects (opt)
      - streams into Parquet via UcgStore
      - records anomalies and publishes a single atomic output directory
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

    # Optional imports (symbols builder may not exist yet in your repo)
    try:
        from .symbols import build_symbols  # type: ignore
    except Exception:
        build_symbols = None  # type: ignore

    # Process files deterministically by (path, blob_sha)
    files_sorted = sorted(list(files), key=lambda f: (f.path, f.blob_sha or ""))

    # Small append buffers to reduce writer churn
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
                store.append_effects(eff_buf)  # type: ignore[attr-defined]
                eff_buf.clear()

    for i, fm in enumerate(files_sorted, start=1):
        files_total += 1

        # Guards
        if not fm.is_text:
            sink.emit(Anomaly(
                path=fm.path, blob_sha=fm.blob_sha, kind=AnomalyKind.BINARY_FILE,
                severity=Severity.INFO, detail="binary-or-nontext",
            ))
            continue
        if fm.size_bytes is not None and fm.size_bytes > cfg.max_file_bytes:
            sink.emit(Anomaly(
                path=fm.path, blob_sha=fm.blob_sha, kind=AnomalyKind.MEMORY_LIMIT,
                severity=Severity.ERROR, detail=f"file-too-large:{fm.size_bytes}",
            ))
            continue

        # Parse
        ps, perr = _parse_file(fm)
        if ps is None:
            sink.emit(Anomaly(
                path=fm.path, blob_sha=fm.blob_sha, kind=AnomalyKind.PARSE_FAILED,
                severity=Severity.ERROR, detail=f"{perr} path={fm.path} lang={fm.lang}",
            ))
            continue

        files_parsed += 1

        # Ensure parse events are reusable across phases
        try:
            if ps.events is not None and not isinstance(ps.events, list):
                ps = type(ps)(file=ps.file, info=ps.driver, error=ps.error, events=list(ps.events), ok=ps.ok)  # type: ignore
        except Exception:
            # Fallback: best-effort materialization
            try:
                evs = list(ps.events) if ps.events is not None else None
                ps.events = evs  # type: ignore[attr-defined]
            except Exception:
                pass

        # Normalize → Nodes/Edges
        try:
            for item in normalize_parse_stream(ps, sink):
                node_edge_buf.append(item)
                if len(node_edge_buf) >= cfg.node_edge_batch:
                    flush_buffers()
        except Exception as e:
            sink.emit(Anomaly(
                path=fm.path, blob_sha=fm.blob_sha, kind=AnomalyKind.UNKNOWN,
                severity=Severity.ERROR, detail=f"normalize-exception:{type(e).__name__}:{e}",
            ))

        # CFG (optional) — re-parse for fresh events
        if cfg.enable_cfg and 'build_cfg' in globals():
            try:
                ps_cfg, perr_cfg = _parse_file(fm)
                if ps_cfg is not None:
                    for item in build_cfg(ps_cfg, sink):
                        cfg_buf.append(item)
                        if len(cfg_buf) >= cfg.cfg_batch:
                            flush_buffers()
                else:
                    sink.emit(Anomaly(
                        path=fm.path, blob_sha=fm.blob_sha, kind=AnomalyKind.PARSE_FAILED,
                        severity=Severity.ERROR, detail=f"{perr_cfg} (cfg) path={fm.path} lang={fm.lang}",
                    ))
            except Exception as e:
                sink.emit(Anomaly(
                    path=fm.path, blob_sha=fm.blob_sha, kind=AnomalyKind.UNKNOWN,
                    severity=Severity.ERROR, detail=f"cfg-exception:{type(e).__name__}:{e}",
                ))

        # DFG (optional) — re-parse for fresh events
        if cfg.enable_dfg and 'build_dfg' in globals():
            try:
                ps_dfg, perr_dfg = _parse_file(fm)
                if ps_dfg is not None:
                    for item in build_dfg(ps_dfg, sink):
                        dfg_buf.append(item)
                        if len(dfg_buf) >= cfg.dfg_batch:
                            flush_buffers()
                else:
                    sink.emit(Anomaly(
                        path=fm.path, blob_sha=fm.blob_sha, kind=AnomalyKind.PARSE_FAILED,
                        severity=Severity.ERROR, detail=f"{perr_dfg} (dfg) path={fm.path} lang={fm.lang}",
                    ))
            except Exception as e:
                sink.emit(Anomaly(
                    path=fm.path, blob_sha=fm.blob_sha, kind=AnomalyKind.UNKNOWN,
                    severity=Severity.ERROR, detail=f"dfg-exception:{type(e).__name__}:{e}",
                ))

        # Symbols/Aliases (optional) — re-parse for fresh events
        if cfg.enable_symbols and build_symbols is not None:
            try:
                ps_sym, perr_sym = _parse_file(fm)
                if ps_sym is not None:
                    for item in build_symbols(ps_sym, sink):  # yields ('symbol', SymbolRow) | ('alias', AliasRow)
                        sym_buf.append(item)
                        if len(sym_buf) >= cfg.sym_batch:
                            flush_buffers()
                else:
                    sink.emit(Anomaly(
                        path=fm.path, blob_sha=fm.blob_sha, kind=AnomalyKind.PARSE_FAILED,
                        severity=Severity.ERROR, detail=f"{perr_sym} (symbols) path={fm.path} lang={fm.lang}",
                    ))
            except Exception as e:
                sink.emit(Anomaly(
                    path=fm.path, blob_sha=fm.blob_sha, kind=AnomalyKind.UNKNOWN,
                    severity=Severity.ERROR, detail=f"symbols-exception:{type(e).__name__}:{e}",
                ))

        # Effects (neutral carriers) — re-parse for fresh events
        if cfg.enable_effects and 'build_effects' in globals():
            try:
                ps_eff, perr_eff = _parse_file(fm)
                if ps_eff is not None:
                    for item in build_effects(ps_eff, sink):
                        eff_buf.append(item)
                        if len(eff_buf) >= cfg.eff_batch:
                            flush_buffers()
                else:
                    sink.emit(Anomaly(
                        path=fm.path, blob_sha=fm.blob_sha, kind=AnomalyKind.PARSE_FAILED,
                        severity=Severity.ERROR, detail=f"{perr_eff} (effects) path={fm.path} lang={fm.lang}",
                    ))
            except Exception as e:
                sink.emit(Anomaly(
                    path=fm.path, blob_sha=fm.blob_sha, kind=AnomalyKind.UNKNOWN,
                    severity=Severity.ERROR, detail=f"effects-exception:{type(e).__name__}:{e}",
                ))

        # Periodic flush (keeps memory bounded on huge repos)
        if (i % max(1, cfg.flush_every_n_files)) == 0:
            flush_buffers(force=True)
            store.flush()
            # push anomalies collected so far
            try:
                store.append_anomalies(list(sink.items()))
            except Exception:
                pass

    # Final flush + anomalies
    flush_buffers(force=True)
    store.flush()
    try:
        store.append_anomalies(list(sink.items()))
    except Exception:
        pass

    # Publish
    store.finalize(
        receipt={
            "run_meta": run_metadata or {},
            "step": "step1_ucg",
        }
    )

    wall_ms = int((time.time() - start) * 1000)

    # Return real counters from the store (populated during flushes)
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
        anomalies=len(getattr(sink, "_buffer", []) or []) + sum(v for v in getattr(sink, "_counts", {}).values()) if hasattr(sink, "_counts") else 0,
        wall_ms=wall_ms,
    )
    return summary