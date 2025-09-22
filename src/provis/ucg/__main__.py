# src/provis/ucg/main.py
from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, Optional

from .discovery import discover_files, DiscoveryConfig, AnomalySink
from .api import build_ucg_for_files, Step1Config, Step1Summary


def run_step1_on_path(
    root: Path,
    *,
    out_dir: Path,
    discovery: Optional[DiscoveryConfig] = None,
    step1: Optional[Step1Config] = None,
    run_meta: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Web-safe entry your HTTP handler can call.

    - Runs discovery → step1 → finalize artifacts atomically in out_dir.
    - Returns a JSON-serializable dict with summary + receipt path.
    """
    root = Path(root)
    out_dir = Path(out_dir)
    sink = AnomalySink()
    files = list(discover_files(root, discovery or DiscoveryConfig(), sink=sink))

    # Step-1
    summary: Step1Summary = build_ucg_for_files(
        files,
        out_dir,
        cfg=step1 or Step1Config(),
        run_metadata=run_meta or {},
    )

    # Try to read receipt (if present)
    receipt_path = out_dir / "run_receipt.json"
    receipt: Dict[str, Any] = {}
    if receipt_path.exists():
        try:
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        except Exception:
            receipt = {}

    return {
        "summary": _summary_to_dict(summary),
        "out_dir": str(out_dir),
        "receipt_path": str(receipt_path),
        "receipt": receipt,
        "discovery_counters": sink.counters(),
    }


def load_receipt(out_dir: Path) -> Dict[str, Any]:
    """
    Helper for your UI to re-read the receipt at any time.
    """
    out_dir = Path(out_dir)
    receipt_path = out_dir / "run_receipt.json"
    if not receipt_path.exists():
        return {}
    try:
        return json.loads(receipt_path.read_text(encoding="utf-8"))
    except Exception:
        return {}


# ----------------------------- helpers ----------------------------------------

def _summary_to_dict(s: Step1Summary) -> Dict[str, Any]:
    # dataclass → dict (explicit to avoid surprises if dataclass changes)
    return {
        "files_total": s.files_total,
        "files_parsed": s.files_parsed,
        "nodes_rows": s.nodes_rows,
        "edges_rows": s.edges_rows,
        "cfg_blocks_rows": s.cfg_blocks_rows,
        "cfg_edges_rows": s.cfg_edges_rows,
        "dfg_nodes_rows": s.dfg_nodes_rows,
        "dfg_edges_rows": s.dfg_edges_rows,
        "symbols_rows": getattr(s, "symbols_rows", 0),
        "aliases_rows": getattr(s, "aliases_rows", 0),
        "effects_rows": getattr(s, "effects_rows", 0),
        "anomalies": s.anomalies,
        "wall_ms": s.wall_ms,
    }
