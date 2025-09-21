# src/provis/ucg/normalize.py
from __future__ import annotations

import hashlib
import json
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Iterable, Iterator, List, Optional, Tuple

from .discovery import Anomaly, AnomalyKind, AnomalySink, FileMeta, Language, Severity
from .parser_registry import (
    CstEvent,
    CstEventKind,
    DriverInfo,
    ParseStream,
)

# ==============================================================================
# UCG schema (row-oriented; persisted by ucg_store.py)
# ==============================================================================

class NodeKind(str, Enum):
    FILE = "file"
    MODULE = "module"
    CLASS = "class"
    FUNCTION = "function"
    BLOCK = "block"
    SYMBOL = "symbol"
    LITERAL = "literal"
    EFFECT_CARRIER = "effect_carrier"  # neutral placeholder (e.g., decorator)


class EdgeKind(str, Enum):
    DEFINES = "defines"         # parent scope defines child (module->fn/class, class->method)
    DECLARES = "declares"
    IMPORTS = "imports"
    EXPORTS = "exports"
    EXTENDS = "extends"
    IMPLEMENTS = "implements"
    CALLS = "calls"
    READS = "reads"
    WRITES = "writes"
    THROWS = "throws"
    ALIASES = "aliases"
    DECORATES = "decorates"


@dataclass(frozen=True)
class Provenance:
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


@dataclass(frozen=True)
class NodeRow:
    id: str
    kind: NodeKind
    name: Optional[str]
    path: str
    lang: Language
    attrs_json: str  # compact JSON with language-aware extras
    prov: Provenance


@dataclass(frozen=True)
class EdgeRow:
    id: str
    kind: EdgeKind
    src_id: str
    dst_id: str
    path: str
    lang: Language
    attrs_json: str
    prov: Provenance


# ==============================================================================
# Config
# ==============================================================================

@dataclass(frozen=True)
class NormalizerConfig:
    # Payload discipline
    max_literal_len: int = 4_096
    # Emissions
    emit_module_nodes: bool = True
    emit_effect_carriers: bool = True
    # Stable ID salt
    id_salt: str = "ucg-v1"
    # Resource guards
    max_scope_depth: int = 200
    max_pending_constructs: int = 5000


# ==============================================================================
# Helpers: stable hashing & json compaction
# ==============================================================================

def _stable_id(*parts: str) -> str:
    h = hashlib.blake2b(digest_size=20)
    for p in parts:
        h.update(b"\x1f")
        h.update(p.encode("utf-8", "ignore"))
    return h.hexdigest()


def _compact(obj: dict) -> str:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True)


# ==============================================================================
# Language adapters
# ==============================================================================

class _Adapter:
    """Language-aware hooks to spot constructs from node type strings."""

    def __init__(self, language: Language) -> None:
        self.language = language
        self._init_patterns()

    def _init_patterns(self) -> None:
        if self.language == Language.PY:
            self.module_types = {"Module"}
            self.class_types = {"ClassDef"}
            self.function_types = {"FunctionDef", "AsyncFunctionDef", "Lambda"}
            self.import_types = {"Import", "ImportFrom"}
            self.export_types = set()
            self.call_types = {"Call"}
            self.decorator_types = {"Decorator", "Decorators"}
            self.identifier_tokens = {"Name", "Attribute"}
            self.string_tokens = {"SimpleString"}
        else:  # JS/TS/JSX/TSX
            self.module_types = {"program"}
            self.class_types = {"class_declaration"}
            self.function_types = {"function_declaration", "function_expression", "method_definition", "arrow_function"}
            self.import_types = {"import_statement", "import_declaration"}
            self.export_types = {"export_statement", "export_clause", "export_assignment"}
            self.call_types = {"call_expression", "new_expression"}
            self.decorator_types = {"decorator"}
            self.identifier_tokens = {"identifier", "property_identifier", "shorthand_property_identifier", "private_property_identifier"}
            self.string_tokens = {"string", "string_fragment", "string_literal", "template_string"}

    def is_module(self, t: str) -> bool: return t in self.module_types
    def is_class(self, t: str) -> bool: return t in self.class_types
    def is_function(self, t: str) -> bool: return t in self.function_types
    def is_import(self, t: str) -> bool: return t in self.import_types
    def is_export(self, t: str) -> bool: return t in self.export_types
    def is_call(self, t: str) -> bool: return t in self.call_types
    def is_decorator(self, t: str) -> bool: return t in self.decorator_types
    def is_identifier_token(self, t: str) -> bool: return t in self.identifier_tokens
    def is_string_token(self, t: str) -> bool: return t in self.string_tokens


_ADAPTERS: Dict[Language, _Adapter] = {
    Language.PY: _Adapter(Language.PY),
    Language.JS: _Adapter(Language.JS),
    Language.TS: _Adapter(Language.TS),
    Language.JSX: _Adapter(Language.JSX),
    Language.TSX: _Adapter(Language.TSX),
}

# ==============================================================================
# Normalizer core
# ==============================================================================

@dataclass
class _Scope:
    node_id: str
    kind: NodeKind
    name: Optional[str]
    parent_id: Optional[str]
    byte_start: int


@dataclass
class _PendingConstruct:
    kind: NodeKind
    type_name: str
    byte_start: int
    line_start: int
    name: Optional[str] = None
    extra: Dict[str, str] = field(default_factory=dict)
    want_edge_from: Optional[str] = None  # For call edges


class Normalizer:
    """
    Streaming normalizer: consumes ParseStream.events and yields NodeRow/EdgeRow with provenance.
    Deterministic, memory-bounded, language-agnostic with adapters, robust to malformed events.
    """

    def __init__(self, cfg: Optional[NormalizerConfig] = None) -> None:
        self.cfg = cfg or NormalizerConfig()
        # Sliding window of recent TOKEN events for qualified-name heuristics (small & bounded)
        self._token_window = deque(maxlen=16)

    # ---- public ---------------------------------------------------------------

    def normalize(self, ps: ParseStream, sink: AnomalySink) -> Iterator[tuple[str, object]]:
        fm = ps.file
        lang = fm.lang
        info: Optional[DriverInfo] = ps.driver

        adapter = _ADAPTERS.get(lang, _Adapter(lang))

        # Always emit FILE node
        file_node = self._file_node(fm, info)
        yield ("node", file_node)
        file_id = file_node.id

        if not ps.ok or ps.events is None:
            sink.emit(
                Anomaly(
                    path=fm.path,
                    blob_sha=fm.blob_sha,
                    kind=AnomalyKind.PARSE_FAILED,
                    severity=Severity.ERROR,
                    detail=ps.error or "parse stream missing",
                )
            )
            return

        scope_stack: List[_Scope] = []
        pend_stack: List[_PendingConstruct] = []
        pending_scopes: Dict[int, _Scope] = {}  # key = byte_start → scope (activated at ENTER)

        module_emitted = False

        for ev in ps.events:
            # Validate event quickly
            if not self._validate_event(ev, fm, sink):
                continue

            # maintain small token window for qualified-name heuristics
            if ev.kind == CstEventKind.TOKEN:
                self._token_window.append(ev)

            nkind, will_emit = self._safe_classify(adapter, ev.type, ev, sink, fm)

            if ev.kind == CstEventKind.ENTER:
                # Resource limits
                if len(pend_stack) > self.cfg.max_pending_constructs or len(scope_stack) > self.cfg.max_scope_depth:
                    sink.emit(
                        Anomaly(
                            path=fm.path,
                            blob_sha=fm.blob_sha,
                            kind=AnomalyKind.MEMORY_LIMIT,
                            severity=Severity.ERROR,
                            detail=f"Resource limits exceeded (scopes={len(scope_stack)}, pending={len(pend_stack)})",
                        )
                    )
                    # Stop normalizing this file but keep FILE node present
                    return

                # Track all nodes for potential names/literals
                cur = _PendingConstruct(
                    kind=(nkind if nkind else NodeKind.BLOCK),
                    type_name=ev.type,
                    byte_start=ev.byte_start,
                    line_start=ev.line_start,
                )
                # Handle MODULE & scope-creating nodes
                if nkind == NodeKind.MODULE and self.cfg.emit_module_nodes and not module_emitted:
                    mod_id = self._start_based_node_id(fm, NodeKind.MODULE, ev.byte_start)
                    scope = _Scope(node_id=mod_id, kind=NodeKind.MODULE, name=self._module_name_from_path(fm.path),
                                   parent_id=file_id, byte_start=ev.byte_start)
                    scope_stack.append(scope)
                    pending_scopes[ev.byte_start] = scope
                    module_emitted = True

                if nkind in (NodeKind.CLASS, NodeKind.FUNCTION):
                    node_id = self._start_based_node_id(fm, nkind, ev.byte_start)
                    parent_id = scope_stack[-1].node_id if scope_stack else (file_id if module_emitted else file_id)
                    scope = _Scope(node_id=node_id, kind=nkind, name=None, parent_id=parent_id, byte_start=ev.byte_start)
                    scope_stack.append(scope)
                    pending_scopes[ev.byte_start] = scope

                # call placeholder (we’ll emit CALL edge at EXIT)
                if adapter.is_call(ev.type):
                    cur.want_edge_from = scope_stack[-1].node_id if scope_stack else file_id
                    cur.extra["call_like"] = "1"

                pend_stack.append(cur)

            elif ev.kind == CstEventKind.TOKEN:
                if not pend_stack:
                    continue
                cur = pend_stack[-1]
                if adapter.is_identifier_token(ev.type) and cur.name is None:
                    nm = self._safe_token_name(ev, fm)
                    if nm:
                        cur.name = nm
                        # If we are inside an active scope lacking a name, fill it
                        if scope_stack and scope_stack[-1].name is None and scope_stack[-1].byte_start == cur.byte_start and cur.kind in (NodeKind.CLASS, NodeKind.FUNCTION):
                            scope_stack[-1].name = nm
                elif adapter.is_string_token(ev.type):
                    lit_val = self._slice_literal_span_only(ev)
                    if lit_val is not None:
                        if cur.kind == NodeKind.LITERAL:
                            cur.extra["value"] = lit_val
                        elif "literal_hint" not in cur.extra and (ev.byte_end - ev.byte_start) <= 256:
                            cur.extra["literal_hint"] = "<span>"

            elif ev.kind == CstEventKind.EXIT:
                # Find corresponding pending construct (should match top)
                if not pend_stack:
                    continue
                cur = pend_stack.pop()

                # If this EXIT closes an active scope, finalize it now
                maybe_scope = pending_scopes.pop(cur.byte_start, None)
                if maybe_scope is not None:
                    # Emit the node for the scope with full provenance (end bytes)
                    nrow = self._node_row_with_start_id(
                        fm, info, maybe_scope.kind, maybe_scope.node_id, name=maybe_scope.name, ev=ev, extra={"type": cur.type_name}
                    )
                    yield ("node", nrow)
                    # Emit defines edge from parent to this node
                    parent_id = maybe_scope.parent_id or file_id
                    erow = self._edge_row(fm, info, EdgeKind.DEFINES, src_id=parent_id, dst_id=maybe_scope.node_id, ev=ev, extra={})
                    yield ("edge", erow)
                    # pop from scope stack (must match)
                    if scope_stack and scope_stack[-1].byte_start == maybe_scope.byte_start:
                        scope_stack.pop()

                # Effect carriers
                if cur.kind == NodeKind.EFFECT_CARRIER and self.cfg.emit_effect_carriers:
                    nrow = self._node_row_with_start_id(fm, info, NodeKind.EFFECT_CARRIER,
                                                        self._start_based_node_id(fm, NodeKind.EFFECT_CARRIER, cur.byte_start),
                                                        name=cur.name, ev=ev, extra={"type": cur.type_name, **cur.extra})
                    yield ("node", nrow)
                    if scope_stack:
                        erow = self._edge_row(fm, info, EdgeKind.DECORATES, src_id=nrow.id, dst_id=scope_stack[-1].node_id, ev=ev, extra={})
                        yield ("edge", erow)

                # Imports / exports as symbols
                if _is_import_like(adapter, cur.type_name):
                    sym = self._create_symbol_node(fm, info, cur.name or "<unknown>", ev, "import")
                    yield ("node", sym)
                    yield ("edge", self._edge_row(fm, info, EdgeKind.IMPORTS, src_id=file_id, dst_id=sym.id, ev=ev, extra={}))
                if _is_export_like(adapter, cur.type_name):
                    sym = self._create_symbol_node(fm, info, cur.name or "<unknown>", ev, "export")
                    yield ("node", sym)
                    yield ("edge", self._edge_row(fm, info, EdgeKind.EXPORTS, src_id=file_id, dst_id=sym.id, ev=ev, extra={}))

                # Calls
                if cur.extra.get("call_like") == "1":
                    # Try to extract a qualified name from the sliding window (best-effort)
                    qname = self._extract_qualified_name(list(self._token_window)[-8:], fm)
                    callee = qname or cur.name or "<unknown>"
                    sym = self._create_symbol_node(fm, info, callee, ev, "callee")
                    yield ("node", sym)
                    src_id = cur.want_edge_from or (scope_stack[-1].node_id if scope_stack else file_id)
                    yield ("edge", self._edge_row(
                        fm, info, EdgeKind.CALLS, src_id=src_id, dst_id=sym.id, ev=ev, extra={"callee": callee}
                    ))

        # Synthesize endings for any scopes that never got an EXIT (malformed/partial trees)
        if scope_stack:
            last_ev = CstEvent(kind=CstEventKind.EXIT, type="__eof__", byte_start=fm.size_bytes,
                               byte_end=fm.size_bytes, line_start=1, line_end=1)
            # Emit in LIFO order to respect nesting
            while scope_stack:
                scope = scope_stack.pop()
                for item in self._emit_synthetic_scope_end(scope, last_ev, fm, info):
                    yield item

    # ---- internals ------------------------------------------------------------

    def _is_identifier_like(self, ev: CstEvent, lang: Language) -> bool:
        adapter = _ADAPTERS.get(lang, _Adapter(lang))
        return adapter.is_identifier_token(ev.type)

    def _extract_qualified_name(self, events_window: List[CstEvent], fm: FileMeta) -> Optional[str]:
        """
        Best-effort extraction of qualified names (e.g., obj.method) from a small token window.
        Strategy: collect consecutive identifier-like tokens near the end, optionally skipping
        single '.' tokens if present as punctuation nodes in some parsers. We avoid heavy parsing.
        """
        if not events_window:
            return None

        parts: List[str] = []
        # walk from the end; collect a short tail of identifiers (and optional dots)
        i = len(events_window) - 1
        # Allow patterns like ident . ident . ident  OR just trailing ident
        collected: List[str] = []
        while i >= 0 and len(collected) < 5:  # cap components to stay bounded
            ev = events_window[i]
            # Accept identifier-like tokens
            nm = self._safe_token_name(ev, fm) if self._is_identifier_like(ev, fm.lang) else None
            if nm:
                collected.append(nm)
                i -= 1
                # Optionally skip a single '.' between identifiers (if present as its own token type)
                if i >= 0 and events_window[i].type in {".", "dot", "period"}:
                    i -= 1
                continue
            # If we have at least one identifier collected, stop at the first non-identifier
            if collected:
                break
            i -= 1

        if not collected:
            return None
        parts = list(reversed(collected))  # we collected backwards
        return ".".join(parts)

    def _safe_classify(self, adapter: _Adapter, node_type: str, ev: CstEvent, sink: AnomalySink, fm: FileMeta) -> Tuple[Optional[NodeKind], bool]:
        try:
            if adapter.is_module(node_type):
                return NodeKind.MODULE, True
            if adapter.is_class(node_type):
                return NodeKind.CLASS, True
            if adapter.is_function(node_type):
                return NodeKind.FUNCTION, True
            if adapter.is_decorator(node_type):
                return NodeKind.EFFECT_CARRIER, True
            if _is_import_like(adapter, node_type) or _is_export_like(adapter, node_type) or adapter.is_call(node_type):
                return NodeKind.BLOCK, True
            return None, False
        except Exception as e:
            sink.emit(Anomaly(
                path=fm.path,
                blob_sha=fm.blob_sha,
                kind=AnomalyKind.UNKNOWN,
                severity=Severity.WARN,
                detail=f"Classification error for '{node_type}': {e}",
                span=(ev.byte_start, ev.byte_end)
            ))
            return None, False

    def _validate_event(self, ev: CstEvent, fm: FileMeta, sink: AnomalySink) -> bool:
        if ev.byte_start < 0 or ev.byte_end < ev.byte_start:
            sink.emit(Anomaly(
                path=fm.path, blob_sha=fm.blob_sha, kind=AnomalyKind.UNKNOWN, severity=Severity.WARN,
                detail=f"Invalid byte range {ev.byte_start}:{ev.byte_end}"
            ))
            return False
        if ev.line_start < 1 or ev.line_end < ev.line_start:
            sink.emit(Anomaly(
                path=fm.path, blob_sha=fm.blob_sha, kind=AnomalyKind.UNKNOWN, severity=Severity.WARN,
                detail=f"Invalid line range {ev.line_start}:{ev.line_end}"
            ))
            return False
        return True

    # IDs: start-based for scope nodes so we can activate scope on ENTER and keep IDs stable
    def _start_based_node_id(self, fm: FileMeta, kind: NodeKind, byte_start: int) -> str:
        return _stable_id(self.cfg.id_salt, "node", kind.value, fm.path, fm.blob_sha, f"{byte_start}")

    def _node_row_with_start_id(self, fm: FileMeta, info: Optional[DriverInfo], kind: NodeKind, node_id: str,
                                *, name: Optional[str], ev: CstEvent, extra: Dict[str, str]) -> NodeRow:
        prov = Provenance(
            path=fm.path, blob_sha=fm.blob_sha, lang=fm.lang, grammar_sha=(info.grammar_sha if info else ""),
            run_id=fm.run_id, config_hash=fm.config_hash,
            byte_start=ev.byte_start, byte_end=ev.byte_end, line_start=ev.line_start, line_end=ev.line_end,
        )
        return NodeRow(
            id=node_id,
            kind=kind,
            name=name,
            path=fm.path,
            lang=fm.lang,
            attrs_json=_compact(extra),
            prov=prov,
        )

    def _edge_row(self, fm: FileMeta, info: Optional[DriverInfo], kind: EdgeKind, *, src_id: str, dst_id: str, ev: CstEvent, extra: Dict[str, str]) -> EdgeRow:
        prov = Provenance(
            path=fm.path, blob_sha=fm.blob_sha, lang=fm.lang, grammar_sha=(info.grammar_sha if info else ""),
            run_id=fm.run_id, config_hash=fm.config_hash,
            byte_start=ev.byte_start, byte_end=ev.byte_end, line_start=ev.line_start, line_end=ev.line_end,
        )
        eid = _stable_id(self.cfg.id_salt, "edge", kind.value, fm.path, fm.blob_sha, src_id, dst_id, f"{ev.byte_start}")
        return EdgeRow(
            id=eid,
            kind=kind,
            src_id=src_id,
            dst_id=dst_id,
            path=fm.path,
            lang=fm.lang,
            attrs_json=_compact(extra),
            prov=prov,
        )

    def _create_symbol_node(self, fm: FileMeta, info: Optional[DriverInfo], name: str, ev: CstEvent, symbol_kind: str) -> NodeRow:
        prov = Provenance(
            path=fm.path, blob_sha=fm.blob_sha, lang=fm.lang, grammar_sha=(info.grammar_sha if info else ""),
            run_id=fm.run_id, config_hash=fm.config_hash,
            byte_start=ev.byte_start, byte_end=ev.byte_end, line_start=ev.line_start, line_end=ev.line_end,
        )
        symbol_id = _stable_id(self.cfg.id_salt, "symbol", fm.path, fm.blob_sha, name, symbol_kind)
        return NodeRow(
            id=symbol_id,
            kind=NodeKind.SYMBOL,
            name=name,
            path=fm.path,
            lang=fm.lang,
            attrs_json=_compact({"kind": symbol_kind}),
            prov=prov,
        )

    def _file_node(self, fm: FileMeta, info: Optional[DriverInfo]) -> NodeRow:
        prov = Provenance(
            path=fm.path, blob_sha=fm.blob_sha, lang=fm.lang, grammar_sha=(info.grammar_sha if info else ""),
            run_id=fm.run_id, config_hash=fm.config_hash,
            byte_start=0, byte_end=fm.size_bytes, line_start=1, line_end=1,
        )
        nid = _stable_id(self.cfg.id_salt, "node", "file", fm.path, fm.blob_sha, "0")
        return NodeRow(
            id=nid,
            kind=NodeKind.FILE,
            name=fm.path.split("/")[-1],
            path=fm.path,
            lang=fm.lang,
            attrs_json=_compact({"role": "file"}),
            prov=prov,
        )

    def _module_name_from_path(self, path: str) -> str:
        base = path.split("/")[-1]
        if "." in base:
            return base[: base.rfind(".")]
        return base

    def _slice_literal_span_only(self, ev: CstEvent) -> Optional[str]:
        # We keep literals by span only (no payload here) to remain streaming + memory-safe.
        length = ev.byte_end - ev.byte_start
        if length <= 0:
            return None
        if length > self.cfg.max_literal_len:
            return f"<literal:{length}b>"
        return "<span>"

    def _safe_token_name(self, ev: CstEvent, fm: FileMeta) -> Optional[str]:
        """
        Memory-efficient token extraction. Reads only the token slice (<=1KB) directly from disk.
        Conservative identifier validation keeps us from mislabeling literals/punctuators.
        """
        try:
            if ev.byte_end <= ev.byte_start:
                return None
            token_size = ev.byte_end - ev.byte_start
            if token_size > 1024:  # large tokens are unlikely to be identifiers
                return None

            with open(fm.real_path, "rb") as f:
                f.seek(ev.byte_start)
                token_bytes = f.read(token_size)

            encoding = fm.encoding or "utf-8"
            token_text = token_bytes.decode(encoding, errors="replace").strip()
            if not token_text or len(token_text) > 256:
                return None

            # conservative: first char alpha/_; remaining allow alnum/_/$ (covers JS & Python)
            ch0 = token_text[0]
            if not (ch0.isalpha() or ch0 == "_"):
                return None
            for ch in token_text[1:]:
                if not (ch.isalnum() or ch in "._$"):
                    return None

            # Avoid strings that look like numbers
            if token_text.replace("_", "").isdigit():
                return None

            return token_text
        except Exception:
            return None

    def _emit_synthetic_scope_end(
        self, scope: _Scope, current_ev: CstEvent, fm: FileMeta, info: Optional[DriverInfo]
    ) -> Iterator[tuple[str, object]]:
        """
        Emit a node + DEFINES edge for a scope lacking a proper EXIT.
        Uses current event's start as a conservative end; falls back to file end at EOF.
        """
        end_byte = max(scope.byte_start, current_ev.byte_start)
        syn_ev = CstEvent(
            kind=CstEventKind.EXIT,
            type="__synthetic_end__",
            byte_start=scope.byte_start,
            byte_end=end_byte,
            line_start=current_ev.line_start,
            line_end=current_ev.line_start,
        )
        nrow = self._node_row_with_start_id(
            fm, info, scope.kind, scope.node_id, name=scope.name, ev=syn_ev,
            extra={"type": "__incomplete__", "synthetic": "true"}
        )
        yield ("node", nrow)
        parent = scope.parent_id
        if parent:
            erow = self._edge_row(
                fm, info, EdgeKind.DEFINES, src_id=parent, dst_id=scope.node_id, ev=syn_ev, extra={"synthetic": "true"}
            )
            yield ("edge", erow)


# ---- tiny adapter helpers -----------------------------------------------------

def _is_import_like(adapter: _Adapter, t: str) -> bool:
    return adapter.is_import(t)

def _is_export_like(adapter: _Adapter, t: str) -> bool:
    return adapter.is_export(t)


# ==============================================================================
# Convenience function
# ==============================================================================

def normalize_parse_stream(ps: ParseStream, sink: AnomalySink, cfg: Optional[NormalizerConfig] = None) -> Iterator[tuple[str, object]]:
    norm = Normalizer(cfg)
    yield from norm.normalize(ps, sink)
