# src/provis/ucg/iterators.py
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Generator, Iterable, Iterator, List, Optional, Tuple, Literal

# Depend on DuckDB for fast columnar scans & joins
try:
    import duckdb
except Exception as e:  # pragma: no cover
    _DUCKDB_IMPORT_ERROR = e
else:
    _DUCKDB_IMPORT_ERROR = None


# ---------------------------- typed result rows --------------------------------

@dataclass(frozen=True)
class NodeRecord:
    id: str
    kind: str
    name: Optional[str]
    path: str
    lang: str
    attrs: Dict
    byte_start: int
    byte_end: int
    line_start: int
    line_end: int
    blob_sha: str
    grammar_sha: str
    run_id: str
    config_hash: str


@dataclass(frozen=True)
class EdgeRecord:
    id: str
    kind: str
    src_id: str
    dst_id: str
    path: str
    lang: str
    attrs: Dict
    byte_start: int
    byte_end: int
    line_start: int
    line_end: int
    blob_sha: str
    grammar_sha: str
    run_id: str
    config_hash: str


@dataclass(frozen=True)
class CallRecord:
    edge: EdgeRecord
    callee: Optional[str]  # from attrs['callee'] if present


@dataclass(frozen=True)
class DecoratorRecord:
    node: NodeRecord
    target_id: Optional[str]  # requires user-side join if needed


@dataclass(frozen=True)
class EffectRecord:
    id: str
    kind: str             # 'call' | 'decorator' | 'string_literal' | 'sql_like' | 'route_like' | ...
    carrier: Optional[str]
    args: Dict
    path: str
    lang: str
    byte_start: int
    byte_end: int
    line_start: int
    line_end: int
    blob_sha: str
    grammar_sha: str
    run_id: str
    config_hash: str


# ---------------------------- helpers ------------------------------------------

def _require_duckdb():
    if _DUCKDB_IMPORT_ERROR is not None:
        raise RuntimeError(
            "duckdb is required for UCG iterators. "
            f"Import failed with: {_DUCKDB_IMPORT_ERROR}"
        )


def _as_json(maybe: Optional[str]) -> Dict:
    if not maybe:
        return {}
    try:
        return json.loads(maybe)
    except Exception:
        return {}


def _node_row_to_record(r) -> NodeRecord:
    return NodeRecord(
        id=r.id,
        kind=r.kind,
        name=r.name,
        path=r.path,
        lang=r.lang,
        attrs=_as_json(r.attrs_json),
        byte_start=int(r.prov_byte_start),
        byte_end=int(r.prov_byte_end),
        line_start=int(r.prov_line_start),
        line_end=int(r.prov_line_end),
        blob_sha=r.prov_blob_sha,
        grammar_sha=r.prov_grammar_sha,
        run_id=r.prov_run_id,
        config_hash=r.prov_config_hash,
    )


def _edge_row_to_record(r) -> EdgeRecord:
    return EdgeRecord(
        id=r.id,
        kind=r.kind,
        src_id=r.src_id,
        dst_id=r.dst_id,
        path=r.path,
        lang=r.lang,
        attrs=_as_json(r.attrs_json),
        byte_start=int(r.prov_byte_start),
        byte_end=int(r.prov_byte_end),
        line_start=int(r.prov_line_start),
        line_end=int(r.prov_line_end),
        blob_sha=r.prov_blob_sha,
        grammar_sha=r.prov_grammar_sha,
        run_id=r.prov_run_id,
        config_hash=r.prov_config_hash,
    )


def _effect_row_to_record(r) -> EffectRecord:
    return EffectRecord(
        id=r.id,
        kind=r.kind,
        carrier=getattr(r, "carrier", None),
        args=_as_json(getattr(r, "args_json", None)),
        path=r.path,
        lang=r.lang,
        byte_start=int(r.prov_byte_start),
        byte_end=int(r.prov_byte_end),
        line_start=int(r.prov_line_start),
        line_end=int(r.prov_line_end),
        blob_sha=r.prov_blob_sha,
        grammar_sha=r.prov_grammar_sha,
        run_id=r.prov_run_id,
        config_hash=r.prov_config_hash,
    )


# ---------------------------- public API ---------------------------------------

class UcgReader:
    """
    Read-side API over UCG Parquet artifacts.

    - Uses DuckDB to stream rows in stable order without loading entire tables.
    - Batch generators return typed records with provenance.
    - Path should be the published UCG dir (containing nodes/, edges/, anomalies/).
    """

    def __init__(self, ucg_dir: Path) -> None:
        _require_duckdb()
        self.ucg_dir = Path(ucg_dir)
        if not (self.ucg_dir / "nodes").exists() or not (self.ucg_dir / "edges").exists():
            raise FileNotFoundError(f"UCG directory is missing nodes/ or edges/: {ucg_dir}")
        # One connection per reader; read-only mode
        self.con = duckdb.connect(database=":memory:")
        # Register Parquet "tables"
        self.nodes_glob = str((self.ucg_dir / "nodes" / "*.parquet").as_posix())
        self.edges_glob = str((self.ucg_dir / "edges" / "*.parquet").as_posix())
        self.anoms_glob = str((self.ucg_dir / "anomalies" / "*.parquet").as_posix())
        self.effects_glob = str((self.ucg_dir / "effects" / "*.parquet").as_posix())

    # ---------------- core scans ----------------

    def iter_nodes_by_path(
        self,
        *,
        path: Optional[str] = None,
        kinds: Optional[Iterable[str]] = None,
        langs: Optional[Iterable[str]] = None,
        batch_size: int = 50_000,
    ) -> Iterator[NodeRecord]:
        """
        Stream nodes filtered by path/kind/lang in deterministic order (path, byte_start ASC).
        """
        where = []
        params = []
        if path:
            where.append("path = ?")
            params.append(path)
        if kinds:
            ks = list(kinds)
            where.append(f"kind IN ({','.join(['?']*len(ks))})")
            params.extend(ks)
        if langs:
            ls = list(langs)
            where.append(f"lang IN ({','.join(['?']*len(ls))})")
            params.extend(ls)

        where_sql = ("WHERE " + " AND ".join(where)) if where else ""
        sql = f"""
            SELECT id, kind, name, path, lang, attrs_json,
                   prov_blob_sha, prov_grammar_sha, prov_run_id, prov_config_hash,
                   prov_byte_start, prov_byte_end, prov_line_start, prov_line_end
            FROM read_parquet('{self.nodes_glob}')
            {where_sql}
            ORDER BY path ASC, prov_byte_start ASC
        """
        yield from self._stream_nodes(sql, params, batch_size)

    def iter_edges_by_src_or_dst(
        self,
        *,
        kinds: Optional[Iterable[str]] = None,
        src_id: Optional[str] = None,
        dst_id: Optional[str] = None,
        path: Optional[str] = None,
        batch_size: int = 50_000,
    ) -> Iterator[EdgeRecord]:
        """
        Stream edges filtered by kind/src/dst/path in deterministic order (path, byte_start ASC).
        """
        where = []
        params = []
        if kinds:
            ks = list(kinds)
            where.append(f"kind IN ({','.join(['?']*len(ks))})")
            params.extend(ks)
        if src_id:
            where.append("src_id = ?")
            params.append(src_id)
        if dst_id:
            where.append("dst_id = ?")
            params.append(dst_id)
        if path:
            where.append("path = ?")
            params.append(path)
        where_sql = ("WHERE " + " AND ".join(where)) if where else ""
        sql = f"""
            SELECT id, kind, src_id, dst_id, path, lang, attrs_json,
                   prov_blob_sha, prov_grammar_sha, prov_run_id, prov_config_hash,
                   prov_byte_start, prov_byte_end, prov_line_start, prov_line_end
            FROM read_parquet('{self.edges_glob}')
            {where_sql}
            ORDER BY path ASC, prov_byte_start ASC
        """
        yield from self._stream_edges(sql, params, batch_size)

    def iter_effects(
        self,
        *,
        kinds: Optional[Iterable[str]] = None,
        carriers_like: Optional[Iterable[str]] = None,
        path: Optional[str] = None,
        batch_size: int = 50_000,
    ) -> Iterator[EffectRecord]:
        # Graceful if effects dir missing
        if not (self.ucg_dir / "effects").exists():
            return iter(())  # no-op

        where = []
        params: List[object] = []
        if kinds:
            ks = list(kinds)
            where.append(f"kind IN ({','.join(['?']*len(ks))})")
            params.extend(ks)
        if path:
            where.append("path = ?")
            params.append(path)
        if carriers_like:
            # ORed prefix filters
            ors = []
            for p in carriers_like:
                ors.append("starts_with(carrier, ?)")
                params.append(p)
            if ors:
                where.append("(" + " OR ".join(ors) + ")")

        where_sql = ("WHERE " + " AND ".join(where)) if where else ""
        sql = f"""
            SELECT id, kind, carrier, args_json, path, lang,
                   prov_blob_sha, prov_grammar_sha, prov_run_id, prov_config_hash,
                   prov_byte_start, prov_byte_end, prov_line_start, prov_line_end
            FROM read_parquet('{self.effects_glob}')
            {where_sql}
            ORDER BY path ASC, prov_byte_start ASC
        """
        rel = self.con.execute(sql, params).fetch_record_batch(batch_size)
        while True:
            batch = rel.fetch_next_batch()
            if batch is None:
                break
            tbl = batch.to_table()
            for r in tbl.to_pylist():
                _row = type("Row", (), r)
                yield _effect_row_to_record(_row)

    # -------------- higher-level convenience scans ----------------

    def iter_calls(self, *, path: Optional[str] = None, batch_size: int = 50_000) -> Iterator[CallRecord]:
        """
        Yield CallRecord for edges where kind='calls'.
        """
        where = "WHERE kind = 'calls'"
        params: List[object] = []
        if path:
            where += " AND path = ?"
            params.append(path)

        sql = f"""
            SELECT id, kind, src_id, dst_id, path, lang, attrs_json,
                   prov_blob_sha, prov_grammar_sha, prov_run_id, prov_config_hash,
                   prov_byte_start, prov_byte_end, prov_line_start, prov_line_end
            FROM read_parquet('{self.edges_glob}')
            {where}
            ORDER BY path ASC, prov_byte_start ASC
        """
        for e in self._stream_edges(sql, params, batch_size):
            callee = None
            if "callee" in e.attrs and isinstance(e.attrs["callee"], str):
                callee = e.attrs["callee"]
            yield CallRecord(edge=e, callee=callee)

    def iter_decorators(
        self, *, path: Optional[str] = None, batch_size: int = 50_000
    ) -> Iterator[DecoratorRecord]:
        """
        Yield decorator/effect-carrier nodes (kind='decorator' from effects table).
        """
        for eff in self.iter_effects(kinds=["decorator"], path=path, batch_size=batch_size):
            # Smoothly wrap into DecoratorRecord for API compatibility
            dummy_node = NodeRecord(
                id=eff.id, kind="decorator", name=eff.carrier, path=eff.path, lang=eff.lang,
                attrs=eff.args, byte_start=eff.byte_start, byte_end=eff.byte_end,
                line_start=eff.line_start, line_end=eff.line_end, blob_sha=eff.blob_sha,
                grammar_sha=eff.grammar_sha, run_id=eff.run_id, config_hash=eff.config_hash,
            )
            yield DecoratorRecord(node=dummy_node, target_id=None)

    def iter_effect_calls(self, *, carriers_like: Optional[Iterable[str]] = None,
                          path: Optional[str] = None, batch_size: int = 50_000) -> Iterator[EffectRecord]:
        return self.iter_effects(kinds=["call", "decorator"], carriers_like=carriers_like, path=path, batch_size=batch_size)

    def iter_route_like_literals(self, *, path: Optional[str] = None, batch_size: int = 50_000) -> Iterator[EffectRecord]:
        return self.iter_effects(kinds=["route_like", "string_literal"], path=path, batch_size=batch_size)

    def iter_sql_like_literals(self, *, path: Optional[str] = None, batch_size: int = 50_000) -> Iterator[EffectRecord]:
        return self.iter_effects(kinds=["sql_like"], path=path, batch_size=batch_size)

    # -------------- helper: “calls with nearby string literals” (best-effort) --

    def iter_calls_with_string_args(
        self,
        *,
        path: Optional[str] = None,
        proximity_bytes: int = 256,
        batch_size: int = 50_000,
    ) -> Iterator[Tuple[CallRecord, List[NodeRecord]]]:
        """
        Heuristic: for each call edge, return any LITERAL nodes in the same file whose
        byte_start lies within [call.byte_start, call.byte_end + proximity_bytes].
        This is conservative and fast; Step 3 will do precise propagation.
        """
        # Calls
        calls = self.iter_calls(path=path, batch_size=batch_size)
        # Literals by file (one pass, windowed into memory per file path)
        lits_by_path: Dict[str, List[NodeRecord]] = {}
        for lit in self.iter_nodes_by_path(path=path, kinds=["literal"], batch_size=batch_size):
            lits_by_path.setdefault(lit.path, []).append(lit)

        # Ensure literals are ordered by byte_start
        for v in lits_by_path.values():
            v.sort(key=lambda n: n.byte_start)

        # Join per call
        for call in calls:
            start = call.edge.byte_start
            end = call.edge.byte_end + max(0, int(proximity_bytes))
            nearby: List[NodeRecord] = []
            lits = lits_by_path.get(call.edge.path, [])
            # binary walk (list is small-ish per file typically)
            # simple linear scan with early break (good enough; nodes are ordered)
            for lit in lits:
                if lit.byte_start > end:
                    break
                if lit.byte_start >= start and lit.byte_start <= end:
                    nearby.append(lit)
            yield (call, nearby)

    def iter_calls_with_nearby_literals_from_effects(
        self,
        *,
        path: Optional[str] = None,
        proximity_bytes: int = 200,
        batch_size: int = 50_000,
    ) -> Iterator[Tuple[EffectRecord, List[EffectRecord]]]:
        calls = list(self.iter_effect_calls(path=path, batch_size=batch_size))
        lits = list(self.iter_route_like_literals(path=path, batch_size=batch_size))
        # Partition by file
        lits_by_path: Dict[str, List[EffectRecord]] = {}
        for lt in lits:
            lits_by_path.setdefault(lt.path, []).append(lt)
        for file_lits in lits_by_path.values():
            file_lits.sort(key=lambda r: r.byte_start)

        for c in sorted(calls, key=lambda r: (r.path, r.byte_start)):
            band = (c.byte_start - proximity_bytes, c.byte_start + proximity_bytes)
            near = []
            for lt in lits_by_path.get(c.path, []):
                if lt.byte_start > band[1]:
                    break
                if band[0] <= lt.byte_start <= band[1]:
                    near.append(lt)
            yield (c, near)

    # ---------------- low-level streaming primitives ---------------------------

    def _stream_nodes(self, sql: str, params: List[object], batch_size: int) -> Iterator[NodeRecord]:
        rel = self.con.execute(sql, params).fetch_record_batch(batch_size)
        while True:
            batch = rel.fetch_next_batch()
            if batch is None:
                break
            tbl = batch.to_table()
            for r in tbl.to_pylist():
                # duckdb returns dict rows in PyList; map keys directly
                # Convert to a simple object with attribute access via dot (simulate row)
                _row = type("Row", (), r)
                yield _node_row_to_record(_row)

    def _stream_edges(self, sql: str, params: List[object], batch_size: int) -> Iterator[EdgeRecord]:
        rel = self.con.execute(sql, params).fetch_record_batch(batch_size)
        while True:
            batch = rel.fetch_next_batch()
            if batch is None:
                break
            tbl = batch.to_table()
            for r in tbl.to_pylist():
                _row = type("Row", (), r)
                yield _edge_row_to_record(_row)

    def close(self) -> None:
        try:
            self.con.close()
        except Exception:
            pass
