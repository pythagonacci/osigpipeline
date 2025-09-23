# src/provis/ucg/ucg_store.py
from __future__ import annotations

import hashlib
import json
import shutil
import time
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

# Parquet / Arrow
try:
    import pyarrow as pa
    import pyarrow.parquet as pq
except Exception as e:  # pragma: no cover
    _PA_IMPORT_ERROR = e
else:
    _PA_IMPORT_ERROR = None

# UCG rows
from .cfg import BlockRow, CfgEdgeRow
from .dfg import DfgNodeRow, DfgEdgeRow
from .normalize import NodeRow, EdgeRow, NodeKind, EdgeKind
from .symbols import SymbolRow, AliasRow
from .effects import EffectRow, EffectKind
# Anomalies
from .discovery import Anomaly
from ..core.config import feature_enabled


SCHEMA_VERSION = "1.0"
SCHEMA_VERSION_V2 = "2.0"

if _PA_IMPORT_ERROR is None:
    _PROV_ENRICHER_TYPE = pa.map_(pa.string(), pa.string())
    _CONFIDENCE_VALUE_STRUCT = pa.struct(
        [
            pa.field("string_value", pa.string()),
            pa.field("double_value", pa.float64()),
        ]
    )
    _PROV_CONFIDENCE_TYPE = pa.map_(pa.string(), _CONFIDENCE_VALUE_STRUCT)
else:  # pragma: no cover - only exercised when pyarrow unavailable
    _PROV_ENRICHER_TYPE = None
    _CONFIDENCE_VALUE_STRUCT = None
    _PROV_CONFIDENCE_TYPE = None


class UcgStore:
    """
    Streaming Parquet store for UCG rows (nodes/edges/anomalies) with:
      - adaptive buffers (row-count & memory pressure)
      - ZSTD compression
      - verified flushes (read-back row counts)
      - atomic publish (staging -> out_dir)
      - schema versioning with Arrow metadata & explicit column
      - query hints (catalog.json, DuckDB schema.sql)
    """

    def __init__(
        self,
        out_dir: Path,
        *,
        zstd_level: int = 7,
        roll_rows: int = 2_000_000,
        max_bytes: Optional[int] = None,
        staging_suffix: str = ".staging",
        file_prefix: str = "ucg",
        max_buffer_memory_mb: int = 128,
    ) -> None:
        if _PA_IMPORT_ERROR is not None:
            raise RuntimeError(f"pyarrow is required: {_PA_IMPORT_ERROR}")

        self.out_dir = Path(out_dir)
        self.zstd_level = int(zstd_level)
        self.roll_rows = int(max(1000, roll_rows))
        self.max_bytes = max_bytes
        self.staging_suffix = staging_suffix
        self.file_prefix = file_prefix
        self.max_buffer_memory_mb = max_buffer_memory_mb
        self._enable_prov_v2 = feature_enabled("feature.step1.provenance_v2")

        # Staging
        self._staging = Path(str(self.out_dir) + self.staging_suffix)
        if self._staging.exists():
            shutil.rmtree(self._staging, ignore_errors=True)
        (self._staging / "nodes").mkdir(parents=True, exist_ok=True)
        (self._staging / "edges").mkdir(parents=True, exist_ok=True)
        (self._staging / "anomalies").mkdir(parents=True, exist_ok=True)
        (self._staging / "cfg_blocks").mkdir(parents=True, exist_ok=True)
        (self._staging / "cfg_edges").mkdir(parents=True, exist_ok=True)
        (self._staging / "dfg_nodes").mkdir(parents=True, exist_ok=True)
        (self._staging / "dfg_edges").mkdir(parents=True, exist_ok=True)
        (self._staging / "symbols").mkdir(parents=True, exist_ok=True)
        (self._staging / "aliases").mkdir(parents=True, exist_ok=True)
        (self._staging / "effects").mkdir(parents=True, exist_ok=True)
        if self._enable_prov_v2:
            (self._staging / "nodes_v2").mkdir(parents=True, exist_ok=True)
            (self._staging / "edges_v2").mkdir(parents=True, exist_ok=True)
            (self._staging / "cfg_blocks_v2").mkdir(parents=True, exist_ok=True)
            (self._staging / "cfg_edges_v2").mkdir(parents=True, exist_ok=True)
            (self._staging / "dfg_nodes_v2").mkdir(parents=True, exist_ok=True)
            (self._staging / "dfg_edges_v2").mkdir(parents=True, exist_ok=True)
            (self._staging / "symbols_v2").mkdir(parents=True, exist_ok=True)
            (self._staging / "aliases_v2").mkdir(parents=True, exist_ok=True)
            (self._staging / "effects_v2").mkdir(parents=True, exist_ok=True)
            (self._staging / "scopes_v2").mkdir(parents=True, exist_ok=True)
            (self._staging / "symbols_scopes_v2").mkdir(parents=True, exist_ok=True)

        # Schemas
        self._node_schema = _node_schema()
        self._edge_schema = _edge_schema()
        self._anomaly_schema = _anomaly_schema()
        self._cfg_block_schema = _cfg_block_schema()
        self._cfg_edge_schema = _cfg_edge_schema()
        self._dfg_node_schema = _dfg_node_schema()
        self._dfg_edge_schema = _dfg_edge_schema()
        self._symbol_schema = _symbol_schema()
        self._alias_schema = _alias_schema()
        self._effect_schema = _effect_schema()
        self._node_schema_v2 = _node_schema_v2() if self._enable_prov_v2 else None
        self._edge_schema_v2 = _edge_schema_v2() if self._enable_prov_v2 else None
        self._cfg_block_schema_v2 = _cfg_block_schema_v2() if self._enable_prov_v2 else None
        self._cfg_edge_schema_v2 = _cfg_edge_schema_v2() if self._enable_prov_v2 else None
        self._dfg_node_schema_v2 = _dfg_node_schema_v2() if self._enable_prov_v2 else None
        self._dfg_edge_schema_v2 = _dfg_edge_schema_v2() if self._enable_prov_v2 else None
        self._symbol_schema_v2 = _symbol_schema_v2() if self._enable_prov_v2 else None
        self._alias_schema_v2 = _alias_schema_v2() if self._enable_prov_v2 else None
        self._effect_schema_v2 = _effect_schema_v2() if self._enable_prov_v2 else None

        # Buffers
        self._node_buf = _AdaptiveRowBuffer(self._node_schema, self.roll_rows, self.max_buffer_memory_mb)
        self._edge_buf = _AdaptiveRowBuffer(self._edge_schema, self.roll_rows, self.max_buffer_memory_mb)
        self._anomaly_buf = _AdaptiveRowBuffer(self._anomaly_schema, self.roll_rows, self.max_buffer_memory_mb)
        self._cfg_block_buf = _AdaptiveRowBuffer(self._cfg_block_schema, self.roll_rows, self.max_buffer_memory_mb)
        self._cfg_edge_buf = _AdaptiveRowBuffer(self._cfg_edge_schema, self.roll_rows, self.max_buffer_memory_mb)
        self._dfg_node_buf = _AdaptiveRowBuffer(self._dfg_node_schema, self.roll_rows, self.max_buffer_memory_mb)
        self._dfg_edge_buf = _AdaptiveRowBuffer(self._dfg_edge_schema, self.roll_rows, self.max_buffer_memory_mb)
        self._symbol_buf = _AdaptiveRowBuffer(self._symbol_schema, self.roll_rows, self.max_buffer_memory_mb)
        self._alias_buf = _AdaptiveRowBuffer(self._alias_schema, self.roll_rows, self.max_buffer_memory_mb)
        self._effect_buf = _AdaptiveRowBuffer(self._effect_schema, self.roll_rows, self.max_buffer_memory_mb)
        self._node_buf_v2 = (
            _AdaptiveRowBuffer(self._node_schema_v2, self.roll_rows, self.max_buffer_memory_mb)
            if self._node_schema_v2 is not None
            else None
        )
        self._edge_buf_v2 = (
            _AdaptiveRowBuffer(self._edge_schema_v2, self.roll_rows, self.max_buffer_memory_mb)
            if self._edge_schema_v2 is not None
            else None
        )
        self._cfg_block_buf_v2 = (
            _AdaptiveRowBuffer(self._cfg_block_schema_v2, self.roll_rows, self.max_buffer_memory_mb)
            if self._cfg_block_schema_v2 is not None
            else None
        )
        self._cfg_edge_buf_v2 = (
            _AdaptiveRowBuffer(self._cfg_edge_schema_v2, self.roll_rows, self.max_buffer_memory_mb)
            if self._cfg_edge_schema_v2 is not None
            else None
        )
        self._dfg_node_buf_v2 = (
            _AdaptiveRowBuffer(self._dfg_node_schema_v2, self.roll_rows, self.max_buffer_memory_mb)
            if self._dfg_node_schema_v2 is not None
            else None
        )
        self._dfg_edge_buf_v2 = (
            _AdaptiveRowBuffer(self._dfg_edge_schema_v2, self.roll_rows, self.max_buffer_memory_mb)
            if self._dfg_edge_schema_v2 is not None
            else None
        )
        self._symbol_buf_v2 = (
            _AdaptiveRowBuffer(self._symbol_schema_v2, self.roll_rows, self.max_buffer_memory_mb)
            if self._symbol_schema_v2 is not None
            else None
        )
        self._alias_buf_v2 = (
            _AdaptiveRowBuffer(self._alias_schema_v2, self.roll_rows, self.max_buffer_memory_mb)
            if self._alias_schema_v2 is not None
            else None
        )
        self._effect_buf_v2 = (
            _AdaptiveRowBuffer(self._effect_schema_v2, self.roll_rows, self.max_buffer_memory_mb)
            if self._effect_schema_v2 is not None
            else None
        )
        self._scopes_buf_v2 = (
            _AdaptiveRowBuffer(_scope_schema_v2(), self.roll_rows, self.max_buffer_memory_mb)
            if self._enable_prov_v2
            else None
        )
        self._sym_scopes_buf_v2 = (
            _AdaptiveRowBuffer(_symbols_scopes_schema_v2(), self.roll_rows, self.max_buffer_memory_mb)
            if self._enable_prov_v2
            else None
        )

        # Counters/indices
        self._node_file_idx = 0
        self._edge_file_idx = 0
        self._anomaly_file_idx = 0
        self._cfg_block_file_idx = 0
        self._cfg_edge_file_idx = 0
        self._dfg_node_file_idx = 0
        self._dfg_edge_file_idx = 0
        self._symbol_file_idx = 0
        self._alias_file_idx = 0
        self._effect_file_idx = 0
        self._node_rows_total = 0
        self._edge_rows_total = 0
        self._anomaly_rows_total = 0
        self._cfg_block_rows_total = 0
        self._cfg_edge_rows_total = 0
        self._dfg_node_rows_total = 0
        self._dfg_edge_rows_total = 0
        self._symbol_rows_total = 0
        self._alias_rows_total = 0
        self._effect_rows_total = 0
        self._node_file_idx_v2 = 0
        self._edge_file_idx_v2 = 0
        self._cfg_block_file_idx_v2 = 0
        self._cfg_edge_file_idx_v2 = 0
        self._dfg_node_file_idx_v2 = 0
        self._dfg_edge_file_idx_v2 = 0
        self._symbol_file_idx_v2 = 0
        self._alias_file_idx_v2 = 0
        self._effect_file_idx_v2 = 0
        self._scopes_file_idx_v2 = 0
        self._sym_scopes_file_idx_v2 = 0
        self._node_rows_total_v2 = 0
        self._edge_rows_total_v2 = 0
        self._cfg_block_rows_total_v2 = 0
        self._cfg_edge_rows_total_v2 = 0
        self._dfg_node_rows_total_v2 = 0
        self._dfg_edge_rows_total_v2 = 0
        self._symbol_rows_total_v2 = 0
        self._alias_rows_total_v2 = 0
        self._effect_rows_total_v2 = 0
        self._scopes_rows_total_v2 = 0
        self._sym_scopes_rows_total_v2 = 0
        self._bytes_written = 0

        # Compression
        self._pq_write_kwargs = dict(
            compression="zstd",
            compression_level=self.zstd_level,
            use_dictionary=True,
            write_statistics=True,
        )

        # Simple transaction log for audit/recovery
        self._transaction_log: List[str] = []

    # ----------------------------- append APIs --------------------------------

    def append(self, rows: Iterable[Tuple[str, object]]) -> None:
        """
        Append a stream of ("node", NodeRow) or ("edge", EdgeRow) tuples.
        """
        for kind, row in rows:
            if kind == "node":
                # Duck-type to tolerate equivalent rows from different module contexts
                if not isinstance(row, NodeRow):
                    try:
                        mapped = {
                            "id": getattr(row, "id"),
                            "kind": getattr(row, "kind"),
                            "name": getattr(row, "name", None),
                            "path": getattr(row, "path"),
                            "lang": getattr(row, "lang"),
                            "attrs_json": getattr(row, "attrs_json", "{}"),
                            "prov": getattr(row, "prov"),
                        }
                        row = NodeRow(**mapped)  # type: ignore[arg-type]
                    except Exception:
                        raise TypeError("node row must be NodeRow-like with required attributes")
                self._node_buf.add(_node_to_arrow_row(row))
                if self._node_buf.should_roll():
                    self._flush_nodes()
                if self._enable_prov_v2 and self._node_buf_v2 is not None:
                    self._node_buf_v2.add(_node_to_arrow_row_v2(row))
                    if self._node_buf_v2.should_roll():
                        self._flush_nodes_v2()
            elif kind == "edge":
                # Duck-type to tolerate equivalent rows from different module contexts
                if not isinstance(row, EdgeRow):
                    try:
                        mapped = {
                            "id": getattr(row, "id"),
                            "kind": getattr(row, "kind"),
                            "src_id": getattr(row, "src_id"),
                            "dst_id": getattr(row, "dst_id"),
                            "path": getattr(row, "path"),
                            "lang": getattr(row, "lang"),
                            "attrs_json": getattr(row, "attrs_json", "{}"),
                            "prov": getattr(row, "prov"),
                        }
                        row = EdgeRow(**mapped)  # type: ignore[arg-type]
                    except Exception:
                        raise TypeError("edge row must be EdgeRow-like with required attributes")
                self._edge_buf.add(_edge_to_arrow_row(row))
                if self._edge_buf.should_roll():
                    self._flush_edges()
                if self._enable_prov_v2 and self._edge_buf_v2 is not None:
                    self._edge_buf_v2.add(_edge_to_arrow_row_v2(row))
                    if self._edge_buf_v2.should_roll():
                        self._flush_edges_v2()
            else:
                raise ValueError(f"unknown row kind: {kind!r}")

    def append_anomalies(self, anomalies: Iterable[Anomaly]) -> None:
        """Store anomalies alongside UCG data."""
        for a in anomalies:
            self._anomaly_buf.add(_anomaly_to_arrow_row(a))
            if self._anomaly_buf.should_roll():
                self._flush_anomalies()

    def append_cfg(self, rows: Iterable[Tuple[str, object]]) -> None:
        """
        Accept ('cfg_block', BlockRow) and ('cfg_edge', CfgEdgeRow) tuples.
        """
        for kind, row in rows:
            if kind == "cfg_block":
                if not isinstance(row, BlockRow):
                    raise TypeError("cfg_block row must be BlockRow")
                self._cfg_block_buf.add(_cfg_block_to_arrow_row(row))
                if self._cfg_block_buf.should_roll():
                    self._flush_cfg_blocks()
                if self._enable_prov_v2 and self._cfg_block_buf_v2 is not None:
                    self._cfg_block_buf_v2.add(_cfg_block_to_arrow_row_v2(row))
                    if self._cfg_block_buf_v2.should_roll():
                        self._flush_cfg_blocks_v2()
            elif kind == "cfg_edge":
                if not isinstance(row, CfgEdgeRow):
                    raise TypeError("cfg_edge row must be CfgEdgeRow")
                self._cfg_edge_buf.add(_cfg_edge_to_arrow_row(row))
                if self._cfg_edge_buf.should_roll():
                    self._flush_cfg_edges()
                if self._enable_prov_v2 and self._cfg_edge_buf_v2 is not None:
                    self._cfg_edge_buf_v2.add(_cfg_edge_to_arrow_row_v2(row))
                    if self._cfg_edge_buf_v2.should_roll():
                        self._flush_cfg_edges_v2()
            else:
                raise ValueError(f"unknown cfg row kind: {kind!r}")

    def append_dfg(self, rows: Iterable[Tuple[str, object]]) -> None:
        """
        Accept ('dfg_node', DfgNodeRow) and ('dfg_edge', DfgEdgeRow) tuples.
        """
        for kind, row in rows:
            if kind == "dfg_node":
                if not isinstance(row, DfgNodeRow):
                    raise TypeError("dfg_node row must be DfgNodeRow")
                self._dfg_node_buf.add(_dfg_node_to_arrow_row(row))
                if self._dfg_node_buf.should_roll():
                    self._flush_dfg_nodes()
                if self._enable_prov_v2 and self._dfg_node_buf_v2 is not None:
                    self._dfg_node_buf_v2.add(_dfg_node_to_arrow_row_v2(row))
                    if self._dfg_node_buf_v2.should_roll():
                        self._flush_dfg_nodes_v2()
            elif kind == "dfg_edge":
                if not isinstance(row, DfgEdgeRow):
                    raise TypeError("dfg_edge row must be DfgEdgeRow")
                self._dfg_edge_buf.add(_dfg_edge_to_arrow_row(row))
                if self._dfg_edge_buf.should_roll():
                    self._flush_dfg_edges()
                if self._enable_prov_v2 and self._dfg_edge_buf_v2 is not None:
                    self._dfg_edge_buf_v2.add(_dfg_edge_to_arrow_row_v2(row))
                    if self._dfg_edge_buf_v2.should_roll():
                        self._flush_dfg_edges_v2()
            else:
                raise ValueError(f"unknown dfg row kind: {kind!r}")

    def append_symbols(self, rows: Iterable[Tuple[str, object]]) -> None:
        """
        Accept ('symbol', SymbolRow) and ('alias', AliasRow) tuples.
        """
        for kind, row in rows:
            if kind == "scope_v2":
                if not self._enable_prov_v2 or self._scopes_buf_v2 is None:
                    continue
                # row is expected to be a dict already matching _scope_schema_v2
                self._scopes_buf_v2.add(row)
                if self._scopes_buf_v2.should_roll():
                    self._flush_scopes_v2()
                continue
            if kind == "symbol_scope_v2":
                if not self._enable_prov_v2 or self._sym_scopes_buf_v2 is None:
                    continue
                self._sym_scopes_buf_v2.add(row)
                if self._sym_scopes_buf_v2.should_roll():
                    self._flush_symbols_scopes_v2()
                continue
            if kind == "symbol":
                if not isinstance(row, SymbolRow):
                    raise TypeError("symbol row must be SymbolRow")
                self._symbol_buf.add(_symbol_to_arrow_row(row))
                if self._symbol_buf.should_roll():
                    self._flush_symbols()
                if self._enable_prov_v2 and self._symbol_buf_v2 is not None:
                    self._symbol_buf_v2.add(_symbol_to_arrow_row_v2(row))
                    if self._symbol_buf_v2.should_roll():
                        self._flush_symbols_v2()
            elif kind == "alias":
                if not isinstance(row, AliasRow):
                    raise TypeError("alias row must be AliasRow")
                self._alias_buf.add(_alias_to_arrow_row(row))
                if self._alias_buf.should_roll():
                    self._flush_aliases()
                if self._enable_prov_v2 and self._alias_buf_v2 is not None:
                    self._alias_buf_v2.add(_alias_to_arrow_row_v2(row))
                    if self._alias_buf_v2.should_roll():
                        self._flush_aliases_v2()
            else:
                raise ValueError(f"unknown symbol-kind: {kind!r}")

    def append_effects(self, rows: Iterable[Tuple[str, object]]) -> None:
        for kind, row in rows:
            if kind != "effect":
                raise ValueError(f"unknown effect row kind: {kind!r}")
            if not isinstance(row, EffectRow):
                raise TypeError("effect row must be EffectRow")
            self._effect_buf.add(_effect_to_arrow_row(row))
            if self._effect_buf.should_roll():
                self._flush_effects()
            if self._enable_prov_v2 and self._effect_buf_v2 is not None:
                self._effect_buf_v2.add(_effect_to_arrow_row_v2(row))
                if self._effect_buf_v2.should_roll():
                    self._flush_effects_v2()

    # ----------------------------- flush/finalize ------------------------------

    def flush(self) -> None:
        self._flush_nodes()
        if self._enable_prov_v2:
            self._flush_nodes_v2()
        self._flush_edges()
        if self._enable_prov_v2:
            self._flush_edges_v2()
        self._flush_anomalies()
        self._flush_cfg_blocks()
        if self._enable_prov_v2:
            self._flush_cfg_blocks_v2()
        self._flush_cfg_edges()
        if self._enable_prov_v2:
            self._flush_cfg_edges_v2()
        self._flush_dfg_nodes()
        if self._enable_prov_v2:
            self._flush_dfg_nodes_v2()
        self._flush_dfg_edges()
        if self._enable_prov_v2:
            self._flush_dfg_edges_v2()
        self._flush_symbols()
        if self._enable_prov_v2:
            self._flush_symbols_v2()
        self._flush_aliases()
        if self._enable_prov_v2:
            self._flush_aliases_v2()
        self._flush_effects()
        if self._enable_prov_v2:
            self._flush_effects_v2()
            self._flush_scopes_v2()
            self._flush_symbols_scopes_v2()

    def finalize(self, *, receipt: Dict) -> None:
        """
        Flush buffers, write run_receipt.json + query hints, compute integrity hashes,
        then atomically publish the staging contents into out_dir.
        """
        self.flush()

        meta = {
            "schema_version": SCHEMA_VERSION,
            "nodes_rows": self._node_rows_total,
            "edges_rows": self._edge_rows_total,
            "anomaly_rows": self._anomaly_rows_total,
            "cfg_block_rows": self._cfg_block_rows_total,
            "cfg_edge_rows": self._cfg_edge_rows_total,
            "dfg_node_rows": self._dfg_node_rows_total,
            "dfg_edge_rows": self._dfg_edge_rows_total,
            "symbol_rows": self._symbol_rows_total,
            "alias_rows": self._alias_rows_total,
            "effect_rows": self._effect_rows_total,
            "bytes_written": self._bytes_written,
            "compression": {"algorithm": "zstd", "level": self.zstd_level},
            "files": {
                "nodes": self._node_file_idx,
                "edges": self._edge_file_idx,
                "anomalies": self._anomaly_file_idx,
                "cfg_blocks": self._cfg_block_file_idx,
                "cfg_edges": self._cfg_edge_file_idx,
                "dfg_nodes": self._dfg_node_file_idx,
                "dfg_edges": self._dfg_edge_file_idx,
                "symbols": self._symbol_file_idx,
                "aliases": self._alias_file_idx,
                "effects": self._effect_file_idx,
            },
            "created_at_epoch": int(time.time()),
            "created_at_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "transaction_log": self._transaction_log,
        }
        if self._enable_prov_v2:
            meta["v2"] = {
                "nodes_rows": self._node_rows_total_v2,
                "edges_rows": self._edge_rows_total_v2,
                "scopes_rows": self._scopes_rows_total_v2,
                "symbols_scopes_rows": self._sym_scopes_rows_total_v2,
                "cfg_block_rows": self._cfg_block_rows_total_v2,
                "cfg_edge_rows": self._cfg_edge_rows_total_v2,
                "dfg_node_rows": self._dfg_node_rows_total_v2,
                "dfg_edge_rows": self._dfg_edge_rows_total_v2,
                "symbol_rows": self._symbol_rows_total_v2,
                "alias_rows": self._alias_rows_total_v2,
                "effect_rows": self._effect_rows_total_v2,
                "files": {
                    "nodes": self._node_file_idx_v2,
                    "edges": self._edge_file_idx_v2,
                    "scopes": self._scopes_file_idx_v2,
                    "symbols_scopes": self._sym_scopes_file_idx_v2,
                    "cfg_blocks": self._cfg_block_file_idx_v2,
                    "cfg_edges": self._cfg_edge_file_idx_v2,
                    "dfg_nodes": self._dfg_node_file_idx_v2,
                    "dfg_edges": self._dfg_edge_file_idx_v2,
                    "symbols": self._symbol_file_idx_v2,
                    "aliases": self._alias_file_idx_v2,
                    "effects": self._effect_file_idx_v2,
                },
                "schema_version": SCHEMA_VERSION_V2,
            }
        meta.update(receipt or {})

        # Integrity hashes
        meta["integrity"] = self._compute_integrity_hashes()

        # Write receipt
        (self._staging / "run_receipt.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")

        # Query hints
        self._write_query_hints()

        # Atomic publish
        self._atomic_publish()

    # ----------------------------- internals: flush ----------------------------

    def _flush_nodes(self) -> None:
        if not self._node_buf and self._node_file_idx > 0:
            return
        path = self._staging / "nodes" / f"{self.file_prefix}_nodes_{self._node_file_idx:05}.parquet"
        rows_written = self._verified_write(self._node_buf, path)
        self._node_rows_total += rows_written
        self._node_file_idx += 1
        self._transaction_log.append(f"wrote_nodes:{path.name}")
        self._node_buf.clear()

    def _flush_nodes_v2(self) -> None:
        if not self._enable_prov_v2 or self._node_buf_v2 is None:
            return
        if not self._node_buf_v2 and self._node_file_idx_v2 > 0:
            return
        path = self._staging / "nodes_v2" / f"{self.file_prefix}_nodes_v2_{self._node_file_idx_v2:05}.parquet"
        rows_written = self._verified_write(self._node_buf_v2, path, schema_version=SCHEMA_VERSION_V2)
        self._node_rows_total_v2 += rows_written
        self._node_file_idx_v2 += 1
        self._transaction_log.append(f"wrote_nodes_v2:{path.name}")
        self._node_buf_v2.clear()

    def _flush_edges(self) -> None:
        if not self._edge_buf and self._edge_file_idx > 0:
            return
        path = self._staging / "edges" / f"{self.file_prefix}_edges_{self._edge_file_idx:05}.parquet"
        rows_written = self._verified_write(self._edge_buf, path)
        self._edge_rows_total += rows_written
        self._edge_file_idx += 1
        self._transaction_log.append(f"wrote_edges:{path.name}")
        self._edge_buf.clear()

    def _flush_edges_v2(self) -> None:
        if not self._enable_prov_v2 or self._edge_buf_v2 is None:
            return
        if not self._edge_buf_v2 and self._edge_file_idx_v2 > 0:
            return
        path = self._staging / "edges_v2" / f"{self.file_prefix}_edges_v2_{self._edge_file_idx_v2:05}.parquet"
        rows_written = self._verified_write(self._edge_buf_v2, path, schema_version=SCHEMA_VERSION_V2)
        self._edge_rows_total_v2 += rows_written
        self._edge_file_idx_v2 += 1
        self._transaction_log.append(f"wrote_edges_v2:{path.name}")
        self._edge_buf_v2.clear()

    def _flush_anomalies(self) -> None:
        if not self._anomaly_buf:
            return
        path = self._staging / "anomalies" / f"{self.file_prefix}_anomalies_{self._anomaly_file_idx:05}.parquet"
        rows_written = self._verified_write(self._anomaly_buf, path)
        self._anomaly_rows_total += rows_written
        self._anomaly_file_idx += 1
        self._transaction_log.append(f"wrote_anomalies:{path.name}")
        self._anomaly_buf.clear()

    def _flush_cfg_blocks(self) -> None:
        if not self._cfg_block_buf:
            return
        path = self._staging / "cfg_blocks" / f"{self.file_prefix}_cfg_blocks_{self._cfg_block_file_idx:05}.parquet"
        rows_written = self._verified_write(self._cfg_block_buf, path)
        self._cfg_block_rows_total += rows_written
        self._cfg_block_file_idx += 1
        self._transaction_log.append(f"wrote_cfg_blocks:{path.name}")
        self._cfg_block_buf.clear()

    def _flush_cfg_blocks_v2(self) -> None:
        if not self._enable_prov_v2 or self._cfg_block_buf_v2 is None:
            return
        if not self._cfg_block_buf_v2 and self._cfg_block_file_idx_v2 > 0:
            return
        path = self._staging / "cfg_blocks_v2" / f"{self.file_prefix}_cfg_blocks_v2_{self._cfg_block_file_idx_v2:05}.parquet"
        rows_written = self._verified_write(self._cfg_block_buf_v2, path, schema_version=SCHEMA_VERSION_V2)
        self._cfg_block_rows_total_v2 += rows_written
        self._cfg_block_file_idx_v2 += 1
        self._transaction_log.append(f"wrote_cfg_blocks_v2:{path.name}")
        self._cfg_block_buf_v2.clear()

    def _flush_cfg_edges(self) -> None:
        if not self._cfg_edge_buf:
            return
        path = self._staging / "cfg_edges" / f"{self.file_prefix}_cfg_edges_{self._cfg_edge_file_idx:05}.parquet"
        rows_written = self._verified_write(self._cfg_edge_buf, path)
        self._cfg_edge_rows_total += rows_written
        self._cfg_edge_file_idx += 1
        self._transaction_log.append(f"wrote_cfg_edges:{path.name}")
        self._cfg_edge_buf.clear()

    def _flush_cfg_edges_v2(self) -> None:
        if not self._enable_prov_v2 or self._cfg_edge_buf_v2 is None:
            return
        if not self._cfg_edge_buf_v2 and self._cfg_edge_file_idx_v2 > 0:
            return
        path = self._staging / "cfg_edges_v2" / f"{self.file_prefix}_cfg_edges_v2_{self._cfg_edge_file_idx_v2:05}.parquet"
        rows_written = self._verified_write(self._cfg_edge_buf_v2, path, schema_version=SCHEMA_VERSION_V2)
        self._cfg_edge_rows_total_v2 += rows_written
        self._cfg_edge_file_idx_v2 += 1
        self._transaction_log.append(f"wrote_cfg_edges_v2:{path.name}")
        self._cfg_edge_buf_v2.clear()

    def _flush_dfg_nodes(self) -> None:
        if not self._dfg_node_buf:
            return
        path = self._staging / "dfg_nodes" / f"{self.file_prefix}_dfg_nodes_{self._dfg_node_file_idx:05}.parquet"
        rows_written = self._verified_write(self._dfg_node_buf, path)
        self._dfg_node_rows_total += rows_written
        self._dfg_node_file_idx += 1
        self._transaction_log.append(f"wrote_dfg_nodes:{path.name}")
        self._dfg_node_buf.clear()

    def _flush_dfg_nodes_v2(self) -> None:
        if not self._enable_prov_v2 or self._dfg_node_buf_v2 is None:
            return
        if not self._dfg_node_buf_v2 and self._dfg_node_file_idx_v2 > 0:
            return
        path = self._staging / "dfg_nodes_v2" / f"{self.file_prefix}_dfg_nodes_v2_{self._dfg_node_file_idx_v2:05}.parquet"
        rows_written = self._verified_write(self._dfg_node_buf_v2, path, schema_version=SCHEMA_VERSION_V2)
        self._dfg_node_rows_total_v2 += rows_written
        self._dfg_node_file_idx_v2 += 1
        self._transaction_log.append(f"wrote_dfg_nodes_v2:{path.name}")
        self._dfg_node_buf_v2.clear()

    def _flush_dfg_edges(self) -> None:
        if not self._dfg_edge_buf:
            return
        path = self._staging / "dfg_edges" / f"{self.file_prefix}_dfg_edges_{self._dfg_edge_file_idx:05}.parquet"
        rows_written = self._verified_write(self._dfg_edge_buf, path)
        self._dfg_edge_rows_total += rows_written
        self._dfg_edge_file_idx += 1
        self._transaction_log.append(f"wrote_dfg_edges:{path.name}")
        self._dfg_edge_buf.clear()

    def _flush_dfg_edges_v2(self) -> None:
        if not self._enable_prov_v2 or self._dfg_edge_buf_v2 is None:
            return
        if not self._dfg_edge_buf_v2 and self._dfg_edge_file_idx_v2 > 0:
            return
        path = self._staging / "dfg_edges_v2" / f"{self.file_prefix}_dfg_edges_v2_{self._dfg_edge_file_idx_v2:05}.parquet"
        rows_written = self._verified_write(self._dfg_edge_buf_v2, path, schema_version=SCHEMA_VERSION_V2)
        self._dfg_edge_rows_total_v2 += rows_written
        self._dfg_edge_file_idx_v2 += 1
        self._transaction_log.append(f"wrote_dfg_edges_v2:{path.name}")
        self._dfg_edge_buf_v2.clear()

    def _flush_symbols(self) -> None:
        if not self._symbol_buf:
            return
        path = self._staging / "symbols" / f"{self.file_prefix}_symbols_{self._symbol_file_idx:05}.parquet"
        rows_written = self._verified_write(self._symbol_buf, path)
        self._symbol_rows_total += rows_written
        self._symbol_file_idx += 1
        self._transaction_log.append(f"wrote_symbols:{path.name}")
        self._symbol_buf.clear()

    def _flush_symbols_v2(self) -> None:
        if not self._enable_prov_v2 or self._symbol_buf_v2 is None:
            return
        if not self._symbol_buf_v2 and self._symbol_file_idx_v2 > 0:
            return
        path = self._staging / "symbols_v2" / f"{self.file_prefix}_symbols_v2_{self._symbol_file_idx_v2:05}.parquet"
        rows_written = self._verified_write(self._symbol_buf_v2, path, schema_version=SCHEMA_VERSION_V2)
        self._symbol_rows_total_v2 += rows_written
        self._symbol_file_idx_v2 += 1
        self._transaction_log.append(f"wrote_symbols_v2:{path.name}")
        self._symbol_buf_v2.clear()

    def _flush_aliases(self) -> None:
        if not self._alias_buf:
            return
        path = self._staging / "aliases" / f"{self.file_prefix}_aliases_{self._alias_file_idx:05}.parquet"
        rows_written = self._verified_write(self._alias_buf, path)
        self._alias_rows_total += rows_written
        self._alias_file_idx += 1
        self._transaction_log.append(f"wrote_aliases:{path.name}")
        self._alias_buf.clear()

    def _flush_aliases_v2(self) -> None:
        if not self._enable_prov_v2 or self._alias_buf_v2 is None:
            return
        if not self._alias_buf_v2 and self._alias_file_idx_v2 > 0:
            return
        path = self._staging / "aliases_v2" / f"{self.file_prefix}_aliases_v2_{self._alias_file_idx_v2:05}.parquet"
        rows_written = self._verified_write(self._alias_buf_v2, path, schema_version=SCHEMA_VERSION_V2)
        self._alias_rows_total_v2 += rows_written
        self._alias_file_idx_v2 += 1
        self._transaction_log.append(f"wrote_aliases_v2:{path.name}")
        self._alias_buf_v2.clear()

    def _flush_effects(self) -> None:
        if not self._effect_buf:
            return
        path = self._staging / "effects" / f"{self.file_prefix}_effects_{self._effect_file_idx:05}.parquet"
        rows_written = self._verified_write(self._effect_buf, path)
        self._effect_rows_total += rows_written
        self._effect_file_idx += 1
        self._transaction_log.append(f"wrote_effects:{path.name}")
        self._effect_buf.clear()

    def _flush_effects_v2(self) -> None:
        if not self._enable_prov_v2 or self._effect_buf_v2 is None:
            return
        if not self._effect_buf_v2 and self._effect_file_idx_v2 > 0:
            return
        path = self._staging / "effects_v2" / f"{self.file_prefix}_effects_v2_{self._effect_file_idx_v2:05}.parquet"
        rows_written = self._verified_write(self._effect_buf_v2, path, schema_version=SCHEMA_VERSION_V2)
        self._effect_rows_total_v2 += rows_written
        self._effect_file_idx_v2 += 1
        self._transaction_log.append(f"wrote_effects_v2:{path.name}")
        self._effect_buf_v2.clear()

    def _flush_scopes_v2(self) -> None:
        if not self._enable_prov_v2 or self._scopes_buf_v2 is None:
            return
        if not self._scopes_buf_v2 and self._scopes_file_idx_v2 > 0:
            return
        path = self._staging / "scopes_v2" / f"{self.file_prefix}_scopes_v2_{self._scopes_file_idx_v2:05}.parquet"
        rows_written = self._verified_write(self._scopes_buf_v2, path, schema_version=SCHEMA_VERSION_V2)
        self._scopes_rows_total_v2 += rows_written
        self._scopes_file_idx_v2 += 1
        self._transaction_log.append(f"wrote_scopes_v2:{path.name}")
        self._scopes_buf_v2.clear()

    def _flush_symbols_scopes_v2(self) -> None:
        if not self._enable_prov_v2 or self._sym_scopes_buf_v2 is None:
            return
        if not self._sym_scopes_buf_v2 and self._sym_scopes_file_idx_v2 > 0:
            return
        path = self._staging / "symbols_scopes_v2" / f"{self.file_prefix}_symbols_scopes_v2_{self._sym_scopes_file_idx_v2:05}.parquet"
        rows_written = self._verified_write(self._sym_scopes_buf_v2, path, schema_version=SCHEMA_VERSION_V2)
        self._sym_scopes_rows_total_v2 += rows_written
        self._sym_scopes_file_idx_v2 += 1
        self._transaction_log.append(f"wrote_symbols_scopes_v2:{path.name}")
        self._sym_scopes_buf_v2.clear()

    # ----------------------------- internals: write helpers --------------------

    def _verified_write(
        self,
        buf: "_AdaptiveRowBuffer",
        path: Path,
        *,
        schema_version: str = SCHEMA_VERSION,
    ) -> int:
        """Write Parquet and verify on disk; clean up on failure. Returns row count."""
        try:
            tbl = buf.to_table()
            # append schema_version column if missing
            if "schema_version" not in tbl.schema.names:
                tbl = tbl.append_column(
                    "schema_version",
                    pa.array([schema_version] * tbl.num_rows, type=pa.string()),
                )
            # add schema metadata
            meta = dict(tbl.schema.metadata or {})
            meta[b"version"] = schema_version.encode("utf-8")
            tbl = tbl.replace_schema_metadata(meta)

            pq.write_table(tbl, path, **self._pq_write_kwargs)

            if not path.exists() or path.stat().st_size == 0:
                raise RuntimeError(f"Failed to write {path}")

            written = pq.read_table(path)
            if written.num_rows != tbl.num_rows:
                raise RuntimeError(f"Row count mismatch: expected {tbl.num_rows}, got {written.num_rows}")

            # Update bytes written and enforce max_bytes limit
            file_size = path.stat().st_size
            self._bytes_written += file_size
            
            if self.max_bytes is not None and self._bytes_written > self.max_bytes:
                # Rollback the last file to stay consistent
                try:
                    self._bytes_written -= file_size
                    path.unlink(missing_ok=True)
                except Exception:
                    pass
                raise RuntimeError(
                    f"UcgStore exceeded max_bytes={self.max_bytes} (written={self._bytes_written}) at {path.name}"
                )

            return tbl.num_rows

        except Exception as e:
            # Try to remove partial file
            try:
                if path.exists():
                    path.unlink()
            except Exception:
                pass
            raise RuntimeError(f"Parquet write verification failed for {path}: {e}") from e


    # ----------------------------- finalize helpers ---------------------------

    def _compute_integrity_hashes(self) -> Dict[str, str]:
        hashes: Dict[str, str] = {}
        for file_path in self._staging.rglob("*.parquet"):
            with open(file_path, "rb") as f:
                file_hash = hashlib.blake2b(f.read(), digest_size=16).hexdigest()
                hashes[file_path.relative_to(self._staging).as_posix()] = file_hash
        return hashes

    def _write_query_hints(self) -> None:
        catalog_tables = {
            "nodes": {
                "path": "nodes/*.parquet",
                "schema": str(self._node_schema),
                "partitions": ["lang", "kind"],
                "row_count": self._node_rows_total,
            },
            "edges": {
                "path": "edges/*.parquet",
                "schema": str(self._edge_schema),
                "partitions": ["lang", "kind"],
                "row_count": self._edge_rows_total,
            },
            "anomalies": {
                "path": "anomalies/*.parquet",
                "schema": str(self._anomaly_schema),
                "partitions": [],
                "row_count": self._anomaly_rows_total,
            },
            "cfg_blocks": {
                "path": "cfg_blocks/*.parquet",
                "schema": str(self._cfg_block_schema),
                "partitions": ["lang", "kind"],
                "row_count": self._cfg_block_rows_total,
            },
            "cfg_edges": {
                "path": "cfg_edges/*.parquet",
                "schema": str(self._cfg_edge_schema),
                "partitions": ["lang", "kind"],
                "row_count": self._cfg_edge_rows_total,
            },
            "dfg_nodes": {
                "path": "dfg_nodes/*.parquet",
                "schema": str(self._dfg_node_schema),
                "partitions": ["lang", "kind"],
                "row_count": self._dfg_node_rows_total,
            },
            "dfg_edges": {
                "path": "dfg_edges/*.parquet",
                "schema": str(self._dfg_edge_schema),
                "partitions": ["lang", "kind"],
                "row_count": self._dfg_edge_rows_total,
            },
            "symbols": {
                "path": "symbols/*.parquet",
                "schema": str(self._symbol_schema),
                "partitions": ["lang", "kind"],
                "row_count": self._symbol_rows_total,
            },
            "aliases": {
                "path": "aliases/*.parquet",
                "schema": str(self._alias_schema),
                "partitions": ["alias_kind"],
                "row_count": self._alias_rows_total,
            },
            "effects": {
                "path": "effects/*.parquet",
                "schema": str(self._effect_schema),
                "partitions": ["lang", "kind"],
                "row_count": self._effect_rows_total,
            },
        }
        if self._enable_prov_v2:
            catalog_tables.update(
                {
                    "nodes_v2": {
                        "path": "nodes_v2/*.parquet",
                        "schema": str(self._node_schema_v2),
                        "partitions": ["lang", "kind"],
                        "row_count": self._node_rows_total_v2,
                    },
                    "edges_v2": {
                        "path": "edges_v2/*.parquet",
                        "schema": str(self._edge_schema_v2),
                        "partitions": ["lang", "kind"],
                        "row_count": self._edge_rows_total_v2,
                    },
                    "cfg_blocks_v2": {
                        "path": "cfg_blocks_v2/*.parquet",
                        "schema": str(self._cfg_block_schema_v2),
                        "partitions": ["lang", "kind"],
                        "row_count": self._cfg_block_rows_total_v2,
                    },
                    "cfg_edges_v2": {
                        "path": "cfg_edges_v2/*.parquet",
                        "schema": str(self._cfg_edge_schema_v2),
                        "partitions": ["lang", "kind"],
                        "row_count": self._cfg_edge_rows_total_v2,
                    },
                    "dfg_nodes_v2": {
                        "path": "dfg_nodes_v2/*.parquet",
                        "schema": str(self._dfg_node_schema_v2),
                        "partitions": ["lang", "kind"],
                        "row_count": self._dfg_node_rows_total_v2,
                    },
                    "dfg_edges_v2": {
                        "path": "dfg_edges_v2/*.parquet",
                        "schema": str(self._dfg_edge_schema_v2),
                        "partitions": ["lang", "kind"],
                        "row_count": self._dfg_edge_rows_total_v2,
                    },
                    "symbols_v2": {
                        "path": "symbols_v2/*.parquet",
                        "schema": str(self._symbol_schema_v2),
                        "partitions": ["lang", "kind"],
                        "row_count": self._symbol_rows_total_v2,
                    },
                    "aliases_v2": {
                        "path": "aliases_v2/*.parquet",
                        "schema": str(self._alias_schema_v2),
                        "partitions": ["alias_kind"],
                        "row_count": self._alias_rows_total_v2,
                    },
                    "effects_v2": {
                        "path": "effects_v2/*.parquet",
                        "schema": str(self._effect_schema_v2),
                        "partitions": ["lang", "kind"],
                        "row_count": self._effect_rows_total_v2,
                    },
                    "scopes_v2": {
                        "path": "scopes_v2/*.parquet",
                        "schema": str(_scope_schema_v2()),
                        "partitions": ["lang", "kind"],
                        "row_count": self._scopes_rows_total_v2,
                    },
                    "symbols_scopes_v2": {
                        "path": "symbols_scopes_v2/*.parquet",
                        "schema": str(_symbols_scopes_schema_v2()),
                        "partitions": ["lang"],
                        "row_count": self._sym_scopes_rows_total_v2,
                    },
                }
            )
        catalog = {"tables": catalog_tables}
        (self._staging / "catalog.json").write_text(json.dumps(catalog, indent=2), encoding="utf-8")

        duckdb_sql = [
            "-- Auto-generated UCG schema for DuckDB",
            "CREATE TABLE nodes AS SELECT * FROM read_parquet('nodes/*.parquet');",
            "CREATE TABLE edges AS SELECT * FROM read_parquet('edges/*.parquet');",
            "CREATE TABLE anomalies AS SELECT * FROM read_parquet('anomalies/*.parquet');",
            "CREATE TABLE cfg_blocks AS SELECT * FROM read_parquet('cfg_blocks/*.parquet');",
            "CREATE TABLE cfg_edges AS SELECT * FROM read_parquet('cfg_edges/*.parquet');",
            "CREATE TABLE dfg_nodes AS SELECT * FROM read_parquet('dfg_nodes/*.parquet');",
            "CREATE TABLE dfg_edges AS SELECT * FROM read_parquet('dfg_edges/*.parquet');",
            "CREATE TABLE symbols AS SELECT * FROM read_parquet('symbols/*.parquet');",
            "CREATE TABLE aliases AS SELECT * FROM read_parquet('aliases/*.parquet');",
            "CREATE TABLE effects AS SELECT * FROM read_parquet('effects/*.parquet');",
        ]
        if self._enable_prov_v2:
            duckdb_sql.extend(
                [
                    "CREATE TABLE nodes_v2 AS SELECT * FROM read_parquet('nodes_v2/*.parquet');",
                    "CREATE TABLE edges_v2 AS SELECT * FROM read_parquet('edges_v2/*.parquet');",
                    "CREATE TABLE cfg_blocks_v2 AS SELECT * FROM read_parquet('cfg_blocks_v2/*.parquet');",
                    "CREATE TABLE cfg_edges_v2 AS SELECT * FROM read_parquet('cfg_edges_v2/*.parquet');",
                    "CREATE TABLE dfg_nodes_v2 AS SELECT * FROM read_parquet('dfg_nodes_v2/*.parquet');",
                    "CREATE TABLE dfg_edges_v2 AS SELECT * FROM read_parquet('dfg_edges_v2/*.parquet');",
                    "CREATE TABLE symbols_v2 AS SELECT * FROM read_parquet('symbols_v2/*.parquet');",
                    "CREATE TABLE aliases_v2 AS SELECT * FROM read_parquet('aliases_v2/*.parquet');",
                    "CREATE TABLE effects_v2 AS SELECT * FROM read_parquet('effects_v2/*.parquet');",
                    "CREATE TABLE scopes_v2 AS SELECT * FROM read_parquet('scopes_v2/*.parquet');",
                    "CREATE TABLE symbols_scopes_v2 AS SELECT * FROM read_parquet('symbols_scopes_v2/*.parquet');",
                ]
            )
        duckdb_sql += [
            "",
            "-- Suggested indexes",
            "CREATE INDEX idx_nodes_kind ON nodes(kind);",
            "CREATE INDEX idx_nodes_path ON nodes(path);",
            "CREATE INDEX idx_edges_src ON edges(src_id);",
            "CREATE INDEX idx_edges_dst ON edges(dst_id);",
            "CREATE INDEX idx_cfg_blocks_func ON cfg_blocks(func_id);",
            "CREATE INDEX idx_cfg_edges_src ON cfg_edges(src_block_id);",
            "CREATE INDEX idx_cfg_edges_dst ON cfg_edges(dst_block_id);",
            "CREATE INDEX idx_dfg_nodes_func ON dfg_nodes(func_id);",
            "CREATE INDEX idx_dfg_nodes_name ON dfg_nodes(name);",
            "CREATE INDEX idx_dfg_edges_src ON dfg_edges(src_id);",
            "CREATE INDEX idx_dfg_edges_dst ON dfg_edges(dst_id);",
            "CREATE INDEX idx_symbols_scope ON symbols(scope_id);",
            "CREATE INDEX idx_symbols_name ON symbols(name);",
            "CREATE INDEX idx_aliases_kind ON aliases(alias_kind);",
            "CREATE INDEX idx_aliases_alias ON aliases(alias_id);",
            "CREATE INDEX idx_aliases_tgt ON aliases(target_symbol_id);",
            "CREATE INDEX idx_effects_kind ON effects(kind);",
            "CREATE INDEX idx_effects_carr ON effects(carrier);",
            "CREATE INDEX idx_effects_path ON effects(path);",
        ]
        if self._enable_prov_v2:
            duckdb_sql.extend(
                [
                    "CREATE INDEX idx_nodes_v2_kind ON nodes_v2(kind);",
                    "CREATE INDEX idx_nodes_v2_path ON nodes_v2(path);",
                    "CREATE INDEX idx_edges_v2_src ON edges_v2(src_id);",
                    "CREATE INDEX idx_edges_v2_dst ON edges_v2(dst_id);",
                    "CREATE INDEX idx_cfg_blocks_v2_func ON cfg_blocks_v2(func_id);",
                    "CREATE INDEX idx_cfg_edges_v2_src ON cfg_edges_v2(src_block_id);",
                    "CREATE INDEX idx_cfg_edges_v2_dst ON cfg_edges_v2(dst_block_id);",
                    "CREATE INDEX idx_dfg_nodes_v2_func ON dfg_nodes_v2(func_id);",
                    "CREATE INDEX idx_dfg_nodes_v2_name ON dfg_nodes_v2(name);",
                    "CREATE INDEX idx_dfg_edges_v2_src ON dfg_edges_v2(src_id);",
                    "CREATE INDEX idx_dfg_edges_v2_dst ON dfg_edges_v2(dst_id);",
                    "CREATE INDEX idx_symbols_v2_scope ON symbols_v2(scope_id);",
                    "CREATE INDEX idx_symbols_v2_name ON symbols_v2(name);",
                    "CREATE INDEX idx_aliases_v2_kind ON aliases_v2(alias_kind);",
                    "CREATE INDEX idx_aliases_v2_alias ON aliases_v2(alias_id);",
                    "CREATE INDEX idx_aliases_v2_tgt ON aliases_v2(target_symbol_id);",
                    "CREATE INDEX idx_effects_v2_kind ON effects_v2(kind);",
                    "CREATE INDEX idx_effects_v2_carr ON effects_v2(carrier);",
                    "CREATE INDEX idx_effects_v2_path ON effects_v2(path);",
                    "CREATE INDEX idx_scopes_v2_kind ON scopes_v2(kind);",
                    "CREATE INDEX idx_scopes_v2_path ON scopes_v2(path);",
                    "CREATE INDEX idx_symbols_scopes_v2_scope ON symbols_scopes_v2(scope_id);",
                    "CREATE INDEX idx_symbols_scopes_v2_symbol ON symbols_scopes_v2(symbol_id);",
                ]
            )
        (self._staging / "schema.sql").write_text("\n".join(duckdb_sql), encoding="utf-8")

    def _atomic_publish(self) -> None:
        # Replace existing out_dir atomically
        if self.out_dir.exists():
            backup = Path(str(self.out_dir) + ".bak")
            if backup.exists():
                shutil.rmtree(backup, ignore_errors=True)
            self.out_dir.replace(backup)
        self.out_dir.parent.mkdir(parents=True, exist_ok=True)
        self._staging.replace(self.out_dir)


# ============================== schemas & mapping ==============================

def _node_schema() -> pa.schema:
    schema = pa.schema(
        [
            pa.field("id", pa.string()),
            pa.field("kind", pa.string()),
            pa.field("name", pa.string()),
            pa.field("path", pa.string()),
            pa.field("lang", pa.string()),
            pa.field("attrs_json", pa.string()),
            pa.field("prov_path", pa.string()),
            pa.field("prov_blob_sha", pa.string()),
            pa.field("prov_lang", pa.string()),
            pa.field("prov_grammar_sha", pa.string()),
            pa.field("prov_run_id", pa.string()),
            pa.field("prov_config_hash", pa.string()),
            pa.field("prov_byte_start", pa.int64()),
            pa.field("prov_byte_end", pa.int64()),
            pa.field("prov_line_start", pa.int32()),
            pa.field("prov_line_end", pa.int32()),
            pa.field("schema_version", pa.string()),
        ]
    )
    return schema.with_metadata({"version": SCHEMA_VERSION})


def _node_schema_v2() -> pa.schema:
    schema = pa.schema(
        [
            pa.field("id", pa.string()),
            pa.field("kind", pa.string()),
            pa.field("name", pa.string()),
            pa.field("path", pa.string()),
            pa.field("lang", pa.string()),
            pa.field("attrs_json", pa.string()),
            pa.field("prov_path", pa.string()),
            pa.field("prov_blob_sha", pa.string()),
            pa.field("prov_lang", pa.string()),
            pa.field("prov_grammar_sha", pa.string()),
            pa.field("prov_run_id", pa.string()),
            pa.field("prov_config_hash", pa.string()),
            pa.field("prov_byte_start", pa.int64()),
            pa.field("prov_byte_end", pa.int64()),
            pa.field("prov_line_start", pa.int32()),
            pa.field("prov_line_end", pa.int32()),
            pa.field("prov_enricher_versions", _PROV_ENRICHER_TYPE),
            pa.field("prov_confidence", _PROV_CONFIDENCE_TYPE),
            pa.field("schema_version", pa.string()),
        ]
    )
    return schema.with_metadata({"version": SCHEMA_VERSION_V2})


def _edge_schema() -> pa.schema:
    schema = pa.schema(
        [
            pa.field("id", pa.string()),
            pa.field("kind", pa.string()),
            pa.field("src_id", pa.string()),
            pa.field("dst_id", pa.string()),
            pa.field("path", pa.string()),
            pa.field("lang", pa.string()),
            pa.field("attrs_json", pa.string()),
            pa.field("prov_path", pa.string()),
            pa.field("prov_blob_sha", pa.string()),
            pa.field("prov_lang", pa.string()),
            pa.field("prov_grammar_sha", pa.string()),
            pa.field("prov_run_id", pa.string()),
            pa.field("prov_config_hash", pa.string()),
            pa.field("prov_byte_start", pa.int64()),
            pa.field("prov_byte_end", pa.int64()),
            pa.field("prov_line_start", pa.int32()),
            pa.field("prov_line_end", pa.int32()),
            pa.field("schema_version", pa.string()),
        ]
    )
    return schema.with_metadata({"version": SCHEMA_VERSION})


def _edge_schema_v2() -> pa.schema:
    schema = pa.schema(
        [
            pa.field("id", pa.string()),
            pa.field("kind", pa.string()),
            pa.field("src_id", pa.string()),
            pa.field("dst_id", pa.string()),
            pa.field("path", pa.string()),
            pa.field("lang", pa.string()),
            pa.field("attrs_json", pa.string()),
            pa.field("prov_path", pa.string()),
            pa.field("prov_blob_sha", pa.string()),
            pa.field("prov_lang", pa.string()),
            pa.field("prov_grammar_sha", pa.string()),
            pa.field("prov_run_id", pa.string()),
            pa.field("prov_config_hash", pa.string()),
            pa.field("prov_byte_start", pa.int64()),
            pa.field("prov_byte_end", pa.int64()),
            pa.field("prov_line_start", pa.int32()),
            pa.field("prov_line_end", pa.int32()),
            pa.field("prov_enricher_versions", _PROV_ENRICHER_TYPE),
            pa.field("prov_confidence", _PROV_CONFIDENCE_TYPE),
            pa.field("schema_version", pa.string()),
        ]
    )
    return schema.with_metadata({"version": SCHEMA_VERSION_V2})


def _anomaly_schema() -> pa.schema:
    schema = pa.schema(
        [
            pa.field("path", pa.string()),
            pa.field("blob_sha", pa.string()),
            pa.field("kind", pa.string()),
            pa.field("severity", pa.string()),
            pa.field("detail", pa.string()),
            pa.field("span_start", pa.int64()),
            pa.field("span_end", pa.int64()),
            pa.field("ts_ms", pa.int64()),
            pa.field("schema_version", pa.string()),
        ]
    )
    return schema.with_metadata({"version": SCHEMA_VERSION})


def _cfg_block_schema() -> pa.schema:
    schema = pa.schema([
        pa.field("id", pa.string()),
        pa.field("func_id", pa.string()),
        pa.field("kind", pa.string()),
        pa.field("index", pa.int32()),
        pa.field("path", pa.string()),
        pa.field("lang", pa.string()),
        pa.field("attrs_json", pa.string()),
        pa.field("prov_path", pa.string()),
        pa.field("prov_blob_sha", pa.string()),
        pa.field("prov_lang", pa.string()),
        pa.field("prov_grammar_sha", pa.string()),
        pa.field("prov_run_id", pa.string()),
        pa.field("prov_config_hash", pa.string()),
        pa.field("prov_byte_start", pa.int64()),
        pa.field("prov_byte_end", pa.int64()),
        pa.field("prov_line_start", pa.int32()),
        pa.field("prov_line_end", pa.int32()),
        pa.field("schema_version", pa.string()),
    ])
    return schema.with_metadata({"version": SCHEMA_VERSION})


def _cfg_block_schema_v2() -> pa.schema:
    schema = pa.schema([
        pa.field("id", pa.string()),
        pa.field("func_id", pa.string()),
        pa.field("kind", pa.string()),
        pa.field("index", pa.int32()),
        pa.field("path", pa.string()),
        pa.field("lang", pa.string()),
        pa.field("attrs_json", pa.string()),
        pa.field("prov_path", pa.string()),
        pa.field("prov_blob_sha", pa.string()),
        pa.field("prov_lang", pa.string()),
        pa.field("prov_grammar_sha", pa.string()),
        pa.field("prov_run_id", pa.string()),
        pa.field("prov_config_hash", pa.string()),
        pa.field("prov_byte_start", pa.int64()),
        pa.field("prov_byte_end", pa.int64()),
        pa.field("prov_line_start", pa.int32()),
        pa.field("prov_line_end", pa.int32()),
        pa.field("prov_enricher_versions", _PROV_ENRICHER_TYPE),
        pa.field("prov_confidence", _PROV_CONFIDENCE_TYPE),
        pa.field("schema_version", pa.string()),
    ])
    return schema.with_metadata({"version": SCHEMA_VERSION_V2})


def _cfg_edge_schema() -> pa.schema:
    schema = pa.schema([
        pa.field("id", pa.string()),
        pa.field("func_id", pa.string()),
        pa.field("kind", pa.string()),
        pa.field("src_block_id", pa.string()),
        pa.field("dst_block_id", pa.string()),
        pa.field("path", pa.string()),
        pa.field("lang", pa.string()),
        pa.field("attrs_json", pa.string()),
        pa.field("prov_path", pa.string()),
        pa.field("prov_blob_sha", pa.string()),
        pa.field("prov_lang", pa.string()),
        pa.field("prov_grammar_sha", pa.string()),
        pa.field("prov_run_id", pa.string()),
        pa.field("prov_config_hash", pa.string()),
        pa.field("prov_byte_start", pa.int64()),
        pa.field("prov_byte_end", pa.int64()),
        pa.field("prov_line_start", pa.int32()),
        pa.field("prov_line_end", pa.int32()),
        pa.field("schema_version", pa.string()),
    ])
    return schema.with_metadata({"version": SCHEMA_VERSION})


def _cfg_edge_schema_v2() -> pa.schema:
    schema = pa.schema([
        pa.field("id", pa.string()),
        pa.field("func_id", pa.string()),
        pa.field("kind", pa.string()),
        pa.field("src_block_id", pa.string()),
        pa.field("dst_block_id", pa.string()),
        pa.field("path", pa.string()),
        pa.field("lang", pa.string()),
        pa.field("attrs_json", pa.string()),
        pa.field("prov_path", pa.string()),
        pa.field("prov_blob_sha", pa.string()),
        pa.field("prov_lang", pa.string()),
        pa.field("prov_grammar_sha", pa.string()),
        pa.field("prov_run_id", pa.string()),
        pa.field("prov_config_hash", pa.string()),
        pa.field("prov_byte_start", pa.int64()),
        pa.field("prov_byte_end", pa.int64()),
        pa.field("prov_line_start", pa.int32()),
        pa.field("prov_line_end", pa.int32()),
        pa.field("prov_enricher_versions", _PROV_ENRICHER_TYPE),
        pa.field("prov_confidence", _PROV_CONFIDENCE_TYPE),
        pa.field("schema_version", pa.string()),
    ])
    return schema.with_metadata({"version": SCHEMA_VERSION_V2})


def _dfg_node_schema() -> pa.schema:
    schema = pa.schema([
        pa.field("id", pa.string()),
        pa.field("func_id", pa.string()),
        pa.field("kind", pa.string()),           # param | var_def | var_use | literal
        pa.field("name", pa.string()),           # None for literal
        pa.field("version", pa.int32()),         # None for literal
        pa.field("path", pa.string()),
        pa.field("lang", pa.string()),
        pa.field("attrs_json", pa.string()),
        pa.field("prov_path", pa.string()),
        pa.field("prov_blob_sha", pa.string()),
        pa.field("prov_lang", pa.string()),
        pa.field("prov_grammar_sha", pa.string()),
        pa.field("prov_run_id", pa.string()),
        pa.field("prov_config_hash", pa.string()),
        pa.field("prov_byte_start", pa.int64()),
        pa.field("prov_byte_end", pa.int64()),
        pa.field("prov_line_start", pa.int32()),
        pa.field("prov_line_end", pa.int32()),
        pa.field("schema_version", pa.string()),
    ])
    return schema.with_metadata({"version": SCHEMA_VERSION})


def _dfg_node_schema_v2() -> pa.schema:
    schema = pa.schema([
        pa.field("id", pa.string()),
        pa.field("func_id", pa.string()),
        pa.field("kind", pa.string()),
        pa.field("name", pa.string()),
        pa.field("version", pa.int32()),
        pa.field("path", pa.string()),
        pa.field("lang", pa.string()),
        pa.field("attrs_json", pa.string()),
        pa.field("prov_path", pa.string()),
        pa.field("prov_blob_sha", pa.string()),
        pa.field("prov_lang", pa.string()),
        pa.field("prov_grammar_sha", pa.string()),
        pa.field("prov_run_id", pa.string()),
        pa.field("prov_config_hash", pa.string()),
        pa.field("prov_byte_start", pa.int64()),
        pa.field("prov_byte_end", pa.int64()),
        pa.field("prov_line_start", pa.int32()),
        pa.field("prov_line_end", pa.int32()),
        pa.field("prov_enricher_versions", _PROV_ENRICHER_TYPE),
        pa.field("prov_confidence", _PROV_CONFIDENCE_TYPE),
        pa.field("schema_version", pa.string()),
    ])
    return schema.with_metadata({"version": SCHEMA_VERSION_V2})


def _dfg_edge_schema() -> pa.schema:
    schema = pa.schema([
        pa.field("id", pa.string()),
        pa.field("func_id", pa.string()),
        pa.field("kind", pa.string()),           # def_use | const_part | arg_to_param
        pa.field("src_id", pa.string()),
        pa.field("dst_id", pa.string()),
        pa.field("path", pa.string()),
        pa.field("lang", pa.string()),
        pa.field("attrs_json", pa.string()),
        pa.field("prov_path", pa.string()),
        pa.field("prov_blob_sha", pa.string()),
        pa.field("prov_lang", pa.string()),
        pa.field("prov_grammar_sha", pa.string()),
        pa.field("prov_run_id", pa.string()),
        pa.field("prov_config_hash", pa.string()),
        pa.field("prov_byte_start", pa.int64()),
        pa.field("prov_byte_end", pa.int64()),
        pa.field("prov_line_start", pa.int32()),
        pa.field("prov_line_end", pa.int32()),
        pa.field("schema_version", pa.string()),
    ])
    return schema.with_metadata({"version": SCHEMA_VERSION})


def _dfg_edge_schema_v2() -> pa.schema:
    schema = pa.schema([
        pa.field("id", pa.string()),
        pa.field("func_id", pa.string()),
        pa.field("kind", pa.string()),
        pa.field("src_id", pa.string()),
        pa.field("dst_id", pa.string()),
        pa.field("path", pa.string()),
        pa.field("lang", pa.string()),
        pa.field("attrs_json", pa.string()),
        pa.field("prov_path", pa.string()),
        pa.field("prov_blob_sha", pa.string()),
        pa.field("prov_lang", pa.string()),
        pa.field("prov_grammar_sha", pa.string()),
        pa.field("prov_run_id", pa.string()),
        pa.field("prov_config_hash", pa.string()),
        pa.field("prov_byte_start", pa.int64()),
        pa.field("prov_byte_end", pa.int64()),
        pa.field("prov_line_start", pa.int32()),
        pa.field("prov_line_end", pa.int32()),
        pa.field("prov_enricher_versions", _PROV_ENRICHER_TYPE),
        pa.field("prov_confidence", _PROV_CONFIDENCE_TYPE),
        pa.field("schema_version", pa.string()),
    ])
    return schema.with_metadata({"version": SCHEMA_VERSION_V2})


def _symbol_schema() -> pa.schema:
    schema = pa.schema([
        pa.field("id", pa.string()),
        pa.field("scope_id", pa.string()),
        pa.field("name", pa.string()),
        pa.field("kind", pa.string()),
        pa.field("visibility", pa.string()),
        pa.field("is_dynamic", pa.bool_()),
        pa.field("path", pa.string()),
        pa.field("lang", pa.string()),
        pa.field("attrs_json", pa.string()),
        pa.field("prov_path", pa.string()),
        pa.field("prov_blob_sha", pa.string()),
        pa.field("prov_lang", pa.string()),
        pa.field("prov_grammar_sha", pa.string()),
        pa.field("prov_run_id", pa.string()),
        pa.field("prov_config_hash", pa.string()),
        pa.field("prov_byte_start", pa.int64()),
        pa.field("prov_byte_end", pa.int64()),
        pa.field("prov_line_start", pa.int32()),
        pa.field("prov_line_end", pa.int32()),
        pa.field("schema_version", pa.string()),
    ])
    return schema.with_metadata({"version": SCHEMA_VERSION})


def _symbol_schema_v2() -> pa.schema:
    schema = pa.schema([
        pa.field("id", pa.string()),
        pa.field("scope_id", pa.string()),
        pa.field("name", pa.string()),
        pa.field("kind", pa.string()),
        pa.field("visibility", pa.string()),
        pa.field("is_dynamic", pa.bool_()),
        pa.field("path", pa.string()),
        pa.field("lang", pa.string()),
        pa.field("attrs_json", pa.string()),
        pa.field("prov_path", pa.string()),
        pa.field("prov_blob_sha", pa.string()),
        pa.field("prov_lang", pa.string()),
        pa.field("prov_grammar_sha", pa.string()),
        pa.field("prov_run_id", pa.string()),
        pa.field("prov_config_hash", pa.string()),
        pa.field("prov_byte_start", pa.int64()),
        pa.field("prov_byte_end", pa.int64()),
        pa.field("prov_line_start", pa.int32()),
        pa.field("prov_line_end", pa.int32()),
        pa.field("prov_enricher_versions", _PROV_ENRICHER_TYPE),
        pa.field("prov_confidence", _PROV_CONFIDENCE_TYPE),
        pa.field("schema_version", pa.string()),
    ])
    return schema.with_metadata({"version": SCHEMA_VERSION_V2})


def _alias_schema() -> pa.schema:
    schema = pa.schema([
        pa.field("id", pa.string()),
        pa.field("alias_kind", pa.string()),
        pa.field("alias_id", pa.string()),
        pa.field("target_symbol_id", pa.string()),
        pa.field("alias_name", pa.string()),
        pa.field("path", pa.string()),
        pa.field("lang", pa.string()),
        pa.field("attrs_json", pa.string()),
        pa.field("prov_path", pa.string()),
        pa.field("prov_blob_sha", pa.string()),
        pa.field("prov_lang", pa.string()),
        pa.field("prov_grammar_sha", pa.string()),
        pa.field("prov_run_id", pa.string()),
        pa.field("prov_config_hash", pa.string()),
        pa.field("prov_byte_start", pa.int64()),
        pa.field("prov_byte_end", pa.int64()),
        pa.field("prov_line_start", pa.int32()),
        pa.field("prov_line_end", pa.int32()),
        pa.field("schema_version", pa.string()),
    ])
    return schema.with_metadata({"version": SCHEMA_VERSION})


def _alias_schema_v2() -> pa.schema:
    schema = pa.schema([
        pa.field("id", pa.string()),
        pa.field("alias_kind", pa.string()),
        pa.field("alias_id", pa.string()),
        pa.field("target_symbol_id", pa.string()),
        pa.field("alias_root_id", pa.string()),
        pa.field("alias_name", pa.string()),
        pa.field("path", pa.string()),
        pa.field("lang", pa.string()),
        pa.field("attrs_json", pa.string()),
        pa.field("prov_path", pa.string()),
        pa.field("prov_blob_sha", pa.string()),
        pa.field("prov_lang", pa.string()),
        pa.field("prov_grammar_sha", pa.string()),
        pa.field("prov_run_id", pa.string()),
        pa.field("prov_config_hash", pa.string()),
        pa.field("prov_byte_start", pa.int64()),
        pa.field("prov_byte_end", pa.int64()),
        pa.field("prov_line_start", pa.int32()),
        pa.field("prov_line_end", pa.int32()),
        pa.field("prov_enricher_versions", _PROV_ENRICHER_TYPE),
        pa.field("prov_confidence", _PROV_CONFIDENCE_TYPE),
        pa.field("schema_version", pa.string()),
    ])
    return schema.with_metadata({"version": SCHEMA_VERSION_V2})


def _effect_schema() -> pa.schema:
    schema = pa.schema([
        pa.field("id", pa.string()),
        pa.field("kind", pa.string()),
        pa.field("carrier", pa.string()),
        pa.field("args_json", pa.string()),
        pa.field("path", pa.string()),
        pa.field("lang", pa.string()),
        pa.field("attrs_json", pa.string()),
        pa.field("prov_path", pa.string()),
        pa.field("prov_blob_sha", pa.string()),
        pa.field("prov_lang", pa.string()),
        pa.field("prov_grammar_sha", pa.string()),
        pa.field("prov_run_id", pa.string()),
        pa.field("prov_config_hash", pa.string()),
        pa.field("prov_byte_start", pa.int64()),
        pa.field("prov_byte_end", pa.int64()),
        pa.field("prov_line_start", pa.int32()),
        pa.field("prov_line_end", pa.int32()),
        pa.field("schema_version", pa.string()),
    ])
    return schema.with_metadata({"version": SCHEMA_VERSION})


def _effect_schema_v2() -> pa.schema:
    schema = pa.schema([
        pa.field("id", pa.string()),
        pa.field("kind", pa.string()),
        pa.field("carrier", pa.string()),
        pa.field("args_json", pa.string()),
        pa.field("path", pa.string()),
        pa.field("lang", pa.string()),
        pa.field("attrs_json", pa.string()),
        pa.field("prov_path", pa.string()),
        pa.field("prov_blob_sha", pa.string()),
        pa.field("prov_lang", pa.string()),
        pa.field("prov_grammar_sha", pa.string()),
        pa.field("prov_run_id", pa.string()),
        pa.field("prov_config_hash", pa.string()),
        pa.field("prov_byte_start", pa.int64()),
        pa.field("prov_byte_end", pa.int64()),
        pa.field("prov_line_start", pa.int32()),
        pa.field("prov_line_end", pa.int32()),
        pa.field("prov_enricher_versions", _PROV_ENRICHER_TYPE),
        pa.field("prov_confidence", _PROV_CONFIDENCE_TYPE),
        pa.field("schema_version", pa.string()),
    ])
    return schema.with_metadata({"version": SCHEMA_VERSION_V2})


def _scope_schema_v2() -> pa.schema:
    schema = pa.schema([
        pa.field("id", pa.string()),
        pa.field("parent_scope_id", pa.string()),
        pa.field("kind", pa.string()),
        pa.field("path", pa.string()),
        pa.field("lang", pa.string()),
        pa.field("attrs_json", pa.string()),
        pa.field("prov_path", pa.string()),
        pa.field("prov_blob_sha", pa.string()),
        pa.field("prov_lang", pa.string()),
        pa.field("prov_grammar_sha", pa.string()),
        pa.field("prov_run_id", pa.string()),
        pa.field("prov_config_hash", pa.string()),
        pa.field("prov_byte_start", pa.int64()),
        pa.field("prov_byte_end", pa.int64()),
        pa.field("prov_line_start", pa.int32()),
        pa.field("prov_line_end", pa.int32()),
        pa.field("prov_enricher_versions", _PROV_ENRICHER_TYPE),
        pa.field("prov_confidence", _PROV_CONFIDENCE_TYPE),
        pa.field("schema_version", pa.string()),
    ])
    return schema.with_metadata({"version": SCHEMA_VERSION_V2})


def _symbols_scopes_schema_v2() -> pa.schema:
    schema = pa.schema([
        pa.field("scope_id", pa.string()),
        pa.field("symbol_id", pa.string()),
        pa.field("binding_name", pa.string()),
        pa.field("visibility", pa.string()),
        pa.field("is_exported", pa.bool_()),
        pa.field("dynamic_flags_json", pa.string()),
        pa.field("path", pa.string()),
        pa.field("lang", pa.string()),
        pa.field("prov_path", pa.string()),
        pa.field("prov_blob_sha", pa.string()),
        pa.field("prov_lang", pa.string()),
        pa.field("prov_grammar_sha", pa.string()),
        pa.field("prov_run_id", pa.string()),
        pa.field("prov_config_hash", pa.string()),
        pa.field("prov_byte_start", pa.int64()),
        pa.field("prov_byte_end", pa.int64()),
        pa.field("prov_line_start", pa.int32()),
        pa.field("prov_line_end", pa.int32()),
        pa.field("prov_enricher_versions", _PROV_ENRICHER_TYPE),
        pa.field("prov_confidence", _PROV_CONFIDENCE_TYPE),
        pa.field("schema_version", pa.string()),
    ])
    return schema.with_metadata({"version": SCHEMA_VERSION_V2})


def _node_base_row(n: NodeRow) -> Dict:
    data = dict(
        id=n.id,
        kind=n.kind.value if isinstance(n.kind, NodeKind) else str(n.kind),
        name=n.name,
        path=n.path,
        lang=getattr(n.lang, "value", str(n.lang)),
        attrs_json=n.attrs_json,
    )
    data.update(n.prov.base_columns())
    return data


def _node_to_arrow_row(n: NodeRow) -> Dict:
    data = _node_base_row(n)
    data["schema_version"] = SCHEMA_VERSION
    return data


def _node_to_arrow_row_v2(n: NodeRow) -> Dict:
    data = _node_base_row(n)
    data.update(n.prov.v2_columns())
    data["schema_version"] = SCHEMA_VERSION_V2
    return data


def _edge_base_row(e: EdgeRow) -> Dict:
    data = dict(
        id=e.id,
        kind=e.kind.value if isinstance(e.kind, EdgeKind) else str(e.kind),
        src_id=e.src_id,
        dst_id=e.dst_id,
        path=e.path,
        lang=getattr(e.lang, "value", str(e.lang)),
        attrs_json=e.attrs_json,
    )
    data.update(e.prov.base_columns())
    return data


def _edge_to_arrow_row(e: EdgeRow) -> Dict:
    data = _edge_base_row(e)
    data["schema_version"] = SCHEMA_VERSION
    return data


def _edge_to_arrow_row_v2(e: EdgeRow) -> Dict:
    data = _edge_base_row(e)
    data.update(e.prov.v2_columns())
    data["schema_version"] = SCHEMA_VERSION_V2
    return data


def _anomaly_to_arrow_row(a: Anomaly) -> Dict:
    span_start, span_end = (None, None)
    if getattr(a, "span", None) and isinstance(a.span, (tuple, list)) and len(a.span) == 2:
        span_start, span_end = a.span
    ts_ms = getattr(a, "ts_ms", None)
    if ts_ms is None:
        ts_ms = int(time.time() * 1000)
    return dict(
        path=a.path,
        blob_sha=a.blob_sha,
        kind=str(getattr(a, "kind", "UNKNOWN")),
        severity=str(getattr(a, "severity", "INFO")),
        detail=a.detail or "",
        span_start=int(span_start or 0),
        span_end=int(span_end or 0),
        ts_ms=int(ts_ms),
        schema_version=SCHEMA_VERSION,
    )


def _cfg_block_base_row(b: BlockRow) -> Dict:
    data = dict(
        id=b.id,
        func_id=b.func_id,
        kind=b.kind.value if hasattr(b.kind, "value") else str(b.kind),
        index=int(b.index),
        path=b.path,
        lang=getattr(b.lang, "value", str(b.lang)),
        attrs_json=b.attrs_json,
    )
    data.update(b.prov.base_columns())
    return data


def _cfg_block_to_arrow_row(b: BlockRow) -> Dict:
    data = _cfg_block_base_row(b)
    data["schema_version"] = SCHEMA_VERSION
    return data


def _cfg_block_to_arrow_row_v2(b: BlockRow) -> Dict:
    data = _cfg_block_base_row(b)
    data.update(b.prov.v2_columns())
    data["schema_version"] = SCHEMA_VERSION_V2
    return data


def _cfg_edge_base_row(e: CfgEdgeRow) -> Dict:
    data = dict(
        id=e.id,
        func_id=e.func_id,
        kind=e.kind.value if hasattr(e.kind, "value") else str(e.kind),
        src_block_id=e.src_block_id,
        dst_block_id=e.dst_block_id,
        path=e.path,
        lang=getattr(e.lang, "value", str(e.lang)),
        attrs_json=e.attrs_json,
    )
    data.update(e.prov.base_columns())
    return data


def _cfg_edge_to_arrow_row(e: CfgEdgeRow) -> Dict:
    data = _cfg_edge_base_row(e)
    data["schema_version"] = SCHEMA_VERSION
    return data


def _cfg_edge_to_arrow_row_v2(e: CfgEdgeRow) -> Dict:
    data = _cfg_edge_base_row(e)
    data.update(e.prov.v2_columns())
    data["schema_version"] = SCHEMA_VERSION_V2
    return data


def _dfg_node_base_row(n: DfgNodeRow) -> Dict:
    data = dict(
        id=n.id,
        func_id=n.func_id,
        kind=n.kind.value if hasattr(n.kind, "value") else str(n.kind),
        name=n.name,
        version=None if n.version is None else int(n.version),
        path=n.path,
        lang=getattr(n.lang, "value", str(n.lang)),
        attrs_json=n.attrs_json,
    )
    data.update(n.prov.base_columns())
    return data


def _dfg_node_to_arrow_row(n: DfgNodeRow) -> Dict:
    data = _dfg_node_base_row(n)
    data["schema_version"] = SCHEMA_VERSION
    return data


def _dfg_node_to_arrow_row_v2(n: DfgNodeRow) -> Dict:
    data = _dfg_node_base_row(n)
    data.update(n.prov.v2_columns())
    data["schema_version"] = SCHEMA_VERSION_V2
    return data


def _dfg_edge_base_row(e: DfgEdgeRow) -> Dict:
    data = dict(
        id=e.id,
        func_id=e.func_id,
        kind=e.kind.value if hasattr(e.kind, "value") else str(e.kind),
        src_id=e.src_id,
        dst_id=e.dst_id,
        path=e.path,
        lang=getattr(e.lang, "value", str(e.lang)),
        attrs_json=e.attrs_json,
    )
    data.update(e.prov.base_columns())
    return data


def _dfg_edge_to_arrow_row(e: DfgEdgeRow) -> Dict:
    data = _dfg_edge_base_row(e)
    data["schema_version"] = SCHEMA_VERSION
    return data


def _dfg_edge_to_arrow_row_v2(e: DfgEdgeRow) -> Dict:
    data = _dfg_edge_base_row(e)
    data.update(e.prov.v2_columns())
    data["schema_version"] = SCHEMA_VERSION_V2
    return data


def _symbol_base_row(s: SymbolRow) -> Dict:
    data = dict(
        id=s.id,
        scope_id=s.scope_id,
        name=s.name,
        kind=s.kind.value if hasattr(s.kind, "value") else str(s.kind),
        visibility=s.visibility,
        is_dynamic=bool(s.is_dynamic),
        path=s.path,
        lang=getattr(s.lang, "value", str(s.lang)),
        attrs_json=s.attrs_json,
    )
    data.update(s.prov.base_columns())
    return data


def _symbol_to_arrow_row(s: SymbolRow) -> Dict:
    data = _symbol_base_row(s)
    data["schema_version"] = SCHEMA_VERSION
    return data


def _symbol_to_arrow_row_v2(s: SymbolRow) -> Dict:
    data = _symbol_base_row(s)
    data.update(s.prov.v2_columns())
    data["schema_version"] = SCHEMA_VERSION_V2
    return data


def _alias_base_row(a: AliasRow) -> Dict:
    data = dict(
        id=a.id,
        alias_kind=a.alias_kind.value if hasattr(a.alias_kind, "value") else str(a.alias_kind),
        alias_id=a.alias_id,
        target_symbol_id=a.target_symbol_id,
        alias_name=a.alias_name,
        path=a.path,
        lang=getattr(a.lang, "value", str(a.lang)),
        attrs_json=a.attrs_json,
    )
    data.update(a.prov.base_columns())
    return data


def _alias_to_arrow_row(a: AliasRow) -> Dict:
    data = _alias_base_row(a)
    data["schema_version"] = SCHEMA_VERSION
    return data


def _alias_to_arrow_row_v2(a: AliasRow) -> Dict:
    data = _alias_base_row(a)
    # v2-only expansion
    try:
        data["alias_root_id"] = getattr(a, "alias_root_id", "")
    except Exception:
        data["alias_root_id"] = ""
    data.update(a.prov.v2_columns())
    data["schema_version"] = SCHEMA_VERSION_V2
    return data


def _effect_base_row(r: EffectRow) -> Dict:
    data = dict(
        id=r.id,
        kind=r.kind.value if hasattr(r.kind, "value") else str(r.kind),
        carrier=r.carrier,
        args_json=r.args_json,
        path=r.path,
        lang=getattr(r.lang, "value", str(r.lang)),
        attrs_json=r.attrs_json,
    )
    data.update(r.prov.base_columns())
    return data


def _effect_to_arrow_row(r: EffectRow) -> Dict:
    data = _effect_base_row(r)
    data["schema_version"] = SCHEMA_VERSION
    return data


def _effect_to_arrow_row_v2(r: EffectRow) -> Dict:
    data = _effect_base_row(r)
    data.update(r.prov.v2_columns())
    data["schema_version"] = SCHEMA_VERSION_V2
    return data


# ============================== buffers =======================================

class _AdaptiveRowBuffer:
    """
    Row buffer → Arrow Table with adaptive rollover based on row count or
    estimated memory usage (string-heavy columns can balloon).
    """

    __slots__ = ("_schema", "_roll_rows", "_cols", "_count", "_max_bytes", "_last_check")

    def __init__(self, schema: pa.Schema, roll_rows: int, max_memory_mb: int) -> None:
        self._schema = schema
        self._roll_rows = int(roll_rows)
        self._cols: Dict[str, List] = {f.name: [] for f in schema}
        self._count = 0
        self._max_bytes = int(max_memory_mb) * 1024 * 1024
        self._last_check = 0

    def __bool__(self) -> bool:
        return self._count > 0

    def add(self, row: Dict) -> None:
        for f in self._schema:
            self._cols[f.name].append(row.get(f.name))
        self._count += 1

    def should_roll(self) -> bool:
        if self._count >= self._roll_rows:
            return True
        # periodic rough size check every ~1000 rows added
        if self._count - self._last_check >= 1000:
            self._last_check = self._count
            if self._estimate_memory_usage() > self._max_bytes:
                return True
        return False

    def _estimate_memory_usage(self) -> int:
        if self._count == 0:
            return 0
        sample = min(128, self._count)
        total_chars = 0
        for f in self._schema:
            col = self._cols[f.name][:sample]
            for v in col:
                if isinstance(v, str):
                    total_chars += len(v)
                else:
                    total_chars += 8  # rough for numeric
        avg = total_chars / max(1, sample)
        return int(avg * self._count)

    def to_table(self) -> pa.Table:
        arrays = [pa.array(self._cols[f.name], type=f.type) for f in self._schema]
        return pa.Table.from_arrays(arrays, schema=self._schema)

    def clear(self) -> None:
        for k in self._cols:
            self._cols[k].clear()
        self._count = 0
