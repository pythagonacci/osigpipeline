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
from .provenance import (
    ProvenanceV2,
    build_provenance,
    build_provenance_from_event,
)

# --- Identifier normalization constants ----------------------------------------

_ID_TOKENS_BY_LANG = {
    Language.PY: {"Name", "Identifier", "Attribute"},
    Language.JS: {"identifier", "property_identifier", "private_identifier"},
    Language.TS: {"identifier", "property_identifier", "private_identifier"},
    Language.JSX: {"identifier", "property_identifier", "private_identifier"},
    Language.TSX: {"identifier", "property_identifier", "private_identifier"},
}

_DECL_HEAD_STOP_TOKENS = {"(", ":", "{", "=>"}  # language-agnostic enough

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
    IMPORT = "import"  # Added missing enum values
    EXPORT = "export"


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
class NodeRow:
    id: str
    kind: NodeKind
    name: Optional[str]
    path: str
    lang: Language
    attrs_json: str  # compact JSON with language-aware extras
    prov: ProvenanceV2


@dataclass(frozen=True)
class EdgeRow:
    id: str
    kind: EdgeKind
    src_id: str
    dst_id: str
    path: str
    lang: Language
    attrs_json: str
    prov: ProvenanceV2


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
            self.class_types_lower = {t.lower() for t in self.class_types}
            self.function_types_lower = {t.lower() for t in self.function_types}
        else:  # JS/TS/JSX/TSX
            self.module_types = {"program"}
            self.class_types = {"class_declaration"}
            self.function_types = {
                "function_declaration",
                "function_expression",
                "method_definition",
                "arrow_function",
                "generator_function_declaration",
                "generator_function",
            }
            self.import_types = {"import_statement", "import_declaration"}
            self.export_types = {"export_statement", "export_clause", "export_assignment"}
            self.call_types = {"call_expression", "new_expression"}
            self.decorator_types = {"decorator"}
            self.identifier_tokens = {"identifier", "property_identifier", "shorthand_property_identifier", "private_property_identifier"}
            self.string_tokens = {"string", "string_fragment", "string_literal", "template_string"}
            self.class_types_lower = {t.lower() for t in self.class_types}
            self.function_types_lower = {t.lower() for t in self.function_types}

    def is_module(self, t: str) -> bool: return t in self.module_types
    def is_class(self, t: str) -> bool: return t in self.class_types
    def is_function(self, t: str) -> bool: return t in self.function_types
    def is_import(self, t: str) -> bool: return t in self.import_types
    def is_export(self, t: str) -> bool: return t in self.export_types
    def is_call(self, t: str) -> bool: return t in self.call_types
    def is_decorator(self, t: str) -> bool: return t in self.decorator_types
    def is_identifier_token(self, t: str) -> bool: return t in self.identifier_tokens
    def is_string_token(self, t: str) -> bool: return t in self.string_tokens

    def looks_like_function(self, node_type: str) -> bool:
        lowered = node_type.lower()
        if not lowered:
            return False
        if node_type in self.function_types or lowered in getattr(self, "function_types_lower", set()):
            return True
        if lowered in {"constructor"}:
            return True
        if "function" in lowered or "method" in lowered or "lambda" in lowered or "arrow" in lowered:
            if any(bad in lowered for bad in ("call", "argument", "type", "signature", "expr", "expression")):
                return False
            return True
        return False

    def looks_like_class(self, node_type: str) -> bool:
        lowered = node_type.lower()
        if not lowered:
            return False
        if node_type in self.class_types or lowered in getattr(self, "class_types_lower", set()):
            return True
        if "class" in lowered:
            if any(bad in lowered for bad in ("class_body", "class_heritage", "class_im")):
                return False
            return True
        return False


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
    params: List[str] = field(default_factory=list)


@dataclass
class _PendingConstruct:
    kind: NodeKind
    type_name: str
    byte_start: int
    line_start: int
    name: Optional[str] = None
    extra: Dict[str, object] = field(default_factory=dict)
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

        # Initialize stacks
        scope_stack: List[_Scope] = []
        pend_stack: List[_PendingConstruct] = []
        pending_scopes: Dict[int, _Scope] = {}
        pending_decorators: List[Tuple[str, CstEvent, Dict[str, object]]] = []
        
        # NEW: Track pending name tokens that arrive before their declaration's ENTER is processed
        pending_name_token: Optional[Tuple[CstEvent, str]] = None

        module_emitted = False

        for ev in ps.events:
            # Validate event quickly
            if not self._validate_event(ev, fm, sink):
                continue

            # Process TOKEN events
            if ev.kind == CstEventKind.TOKEN:
                self._token_window.append(ev)

                token_name: Optional[str] = None
                if adapter.is_identifier_token(ev.type):
                    token_name = self._safe_token_name(ev, fm)

                self._update_function_param_capture(
                    ev, adapter, fm, pend_stack, pending_scopes, token_name
                )

                # Check if this is an identifier token
                if adapter.is_identifier_token(ev.type):
                    if token_name:
                        # If we have a pending construct at this exact byte position,
                        # this is likely its name token
                        if pend_stack:
                            cur = pend_stack[-1]
                            # Check if this token immediately follows the construct's ENTER
                            # (within a small byte range to account for whitespace)
                            if (
                                cur.kind in (NodeKind.FUNCTION, NodeKind.CLASS)
                                and cur.name is None
                                and abs(ev.byte_start - cur.byte_start) <= 50
                            ):  # reasonable proximity
                                cur.name = token_name
                                # Also update the scope if it exists
                                if scope_stack and scope_stack[-1].byte_start == cur.byte_start:
                                    scope_stack[-1].name = token_name
                        else:
                            # Store as potentially pending name token for next ENTER
                            pending_name_token = (ev, token_name)

                # Process string tokens
                elif adapter.is_string_token(ev.type):
                    if pend_stack:
                        cur = pend_stack[-1]
                        lit_val = self._slice_literal_span_only(ev)
                        if lit_val is not None:
                            if cur.kind == NodeKind.LITERAL:
                                cur.extra["value"] = lit_val
                            elif "literal_hint" not in cur.extra and (ev.byte_end - ev.byte_start) <= 256:
                                cur.extra["literal_hint"] = "<span>"
                
                continue  # TOKEN events don't need further processing

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
                    return

                # Track all nodes for potential names/literals
                cur = _PendingConstruct(
                    kind=(nkind if nkind else NodeKind.BLOCK),
                    type_name=ev.type,
                    byte_start=ev.byte_start,
                    line_start=ev.line_start,
                )
                
                # NEW: Check if we have a pending name token that might belong to this declaration
                if (nkind in (NodeKind.FUNCTION, NodeKind.CLASS) and 
                    pending_name_token is not None):
                    token_ev, token_name = pending_name_token
                    # Check if the token is close to this ENTER (within reasonable byte range)
                    if abs(token_ev.byte_start - ev.byte_start) <= 50:
                        cur.name = token_name
                        pending_name_token = None  # Consume the pending token
                
                # Handle MODULE & scope-creating nodes
                if nkind == NodeKind.MODULE and self.cfg.emit_module_nodes and not module_emitted:
                    mod_id = self._start_based_node_id(fm, NodeKind.MODULE, ev.byte_start)
                    scope = _Scope(node_id=mod_id, kind=NodeKind.MODULE, name=self._module_name_from_path(fm.path),
                                   parent_id=file_id, byte_start=ev.byte_start)
                    scope_stack.append(scope)
                    pending_scopes[ev.byte_start] = scope
                    module_emitted = True

                if nkind in (NodeKind.CLASS, NodeKind.FUNCTION):
                    # Extra guard: only open scopes for true decl nodes (prevents keyword-leaf scopes)
                    is_real_decl = (
                        (nkind == NodeKind.FUNCTION and ev.type in adapter.function_types) or
                        (nkind == NodeKind.CLASS and ev.type in adapter.class_types)
                    )
                    if is_real_decl:
                        node_id = self._start_based_node_id(fm, nkind, ev.byte_start)
                        parent_id = scope_stack[-1].node_id if scope_stack else file_id
                        scope = _Scope(node_id=node_id, kind=nkind, name=cur.name, parent_id=parent_id, byte_start=ev.byte_start)
                        scope_stack.append(scope)
                        pending_scopes[ev.byte_start] = scope
                        if nkind == NodeKind.FUNCTION:
                            scope.params = []
                            lower_type = ev.type.lower()
                            is_lambda_like = "lambda" in lower_type
                            is_arrow_like = "arrow" in lower_type
                            cur.extra["param_names"] = []
                            cur.extra["param_capture_active"] = True
                            cur.extra["param_capture_paren"] = 0
                            cur.extra["param_capture_started"] = False
                            cur.extra["param_capture_lambda"] = bool(is_lambda_like or is_arrow_like)
                            cur.extra["param_expect_name"] = bool(cur.extra["param_capture_lambda"])
                        if pending_decorators:
                            still_pending: List[Tuple[str, CstEvent, Dict[str, object]]] = []
                            for deco_id, deco_ev, deco_extra in pending_decorators:
                                if deco_ev.byte_start <= ev.byte_start:
                                    erow = self._edge_row(
                                        fm,
                                        info,
                                        EdgeKind.DECORATES,
                                        src_id=deco_id,
                                        dst_id=node_id,
                                        ev=deco_ev,
                                        extra=dict(deco_extra),
                                    )
                                    yield ("edge", erow)
                                else:
                                    still_pending.append((deco_id, deco_ev, deco_extra))
                            pending_decorators[:] = still_pending
                    else:
                        # Demote misclassified construct to a non-scope BLOCK to avoid duplicates
                        cur.kind = NodeKind.BLOCK

                # call placeholder (we'll emit CALL edge at EXIT)
                if adapter.is_call(ev.type):
                    # Prefer nearest enclosing FUNCTION scope as caller; fallback to current top or file
                    caller_id = None
                    for s in reversed(scope_stack):
                        if s.kind == NodeKind.FUNCTION:
                            caller_id = s.node_id
                            break
                    cur.want_edge_from = caller_id
                    if caller_id is None:
                        fallback_id = scope_stack[-1].node_id if scope_stack else file_id
                        cur.extra["call_src_fallback"] = fallback_id
                    cur.extra["call_like"] = "1"

                pend_stack.append(cur)
                
                # Clear pending name token if it's too far from this ENTER
                if pending_name_token is not None:
                    token_ev, _ = pending_name_token
                    if abs(token_ev.byte_start - ev.byte_start) > 100:
                        pending_name_token = None

            elif ev.kind == CstEventKind.EXIT:
                if not pend_stack:
                    continue
                cur = pend_stack.pop()

                # Final attempt to set a name for functions/classes if still unknown
                if cur.kind in (NodeKind.FUNCTION, NodeKind.CLASS) and not cur.name:
                    tw = list(self._token_window)[-12:]
                    for t in reversed(tw):
                        if t.byte_start >= cur.byte_start and t.byte_start <= ev.byte_end:
                            if self._token_is_identifier(t, fm.lang):
                                name = self._safe_token_name(t, fm)
                                # Allow normal names, and double-underscore specials; avoid single-underscore privates
                                if name and (not name.startswith("_") or name.startswith("__")):
                                    cur.name = name
                                    break

                # If this EXIT should close a scope, do so robustly
                if cur.kind in (NodeKind.MODULE, NodeKind.CLASS, NodeKind.FUNCTION):
                    # Update the *active* scope name if it matches this construct start
                    if scope_stack and scope_stack[-1].byte_start == cur.byte_start:
                        if cur.name and not scope_stack[-1].name:
                            scope_stack[-1].name = cur.name
                        if (
                            scope_stack[-1].kind == NodeKind.FUNCTION
                            and "param_names" in cur.extra
                            and isinstance(cur.extra.get("param_names"), list)
                        ):
                            names = [
                                str(p)
                                for p in cur.extra.get("param_names", [])
                                if isinstance(p, str) and p
                            ]
                            scope_stack[-1].params = names
                        pending_scopes.pop(scope_stack[-1].byte_start, None)
                        # Normal fast-path finalization (top matches)
                        for item in self._finalize_scope_at_index(
                            len(scope_stack) - 1,
                            scope_stack=scope_stack,
                            fm=fm,
                            info=info,
                            ev=ev,
                            extra_type=cur.type_name,
                            file_id=file_id,
                        ):
                            yield item
                    else:
                        # Slow-path: search for a scope that started at this construct's byte_start
                        match_idx = -1
                        for i in range(len(scope_stack) - 1, -1, -1):
                            if scope_stack[i].byte_start == cur.byte_start:
                                match_idx = i
                                break

                        if match_idx != -1:
                            # Carry over the discovered name if we have one
                            if cur.name and not scope_stack[match_idx].name:
                                scope_stack[match_idx].name = cur.name
                            if (
                                scope_stack[match_idx].kind == NodeKind.FUNCTION
                                and "param_names" in cur.extra
                                and isinstance(cur.extra.get("param_names"), list)
                            ):
                                names = [
                                    str(p)
                                    for p in cur.extra.get("param_names", [])
                                    if isinstance(p, str) and p
                                ]
                                scope_stack[match_idx].params = names
                            pending_scopes.pop(scope_stack[match_idx].byte_start, None)
                            for item in self._finalize_scope_at_index(
                                match_idx,
                                scope_stack=scope_stack,
                                fm=fm,
                                info=info,
                                ev=ev,
                                extra_type=cur.type_name,
                                file_id=file_id,
                            ):
                                yield item
                        else:
                            # Extremely rare with a balanced driver: no matching scope by start.
                            # Close the top scope to avoid orphans and log an anomaly.
                            if scope_stack:
                                top = scope_stack[-1]
                                sink.emit(
                                    Anomaly(
                                        path=fm.path,
                                        blob_sha=fm.blob_sha,
                                        kind=AnomalyKind.UNKNOWN,
                                        severity=Severity.WARN,
                                        detail=(
                                            f"Out-of-order scope EXIT for {cur.type_name} at {cur.byte_start}; "
                                            f"closing top scope started at {top.byte_start}"
                                        ),
                                        span=(ev.byte_start, ev.byte_end),
                                    )
                                )
                                for item in self._finalize_scope_at_index(
                                    len(scope_stack) - 1,
                                    scope_stack=scope_stack,
                                    fm=fm,
                                    info=info,
                                    ev=ev,
                                    extra_type=cur.type_name,
                                    file_id=file_id,
                                ):
                                    yield item

                # Effect carriers
                if cur.kind == NodeKind.EFFECT_CARRIER and self.cfg.emit_effect_carriers:
                    deco_extra = {"type": cur.type_name, **cur.extra}
                    deco_id = self._start_based_node_id(fm, NodeKind.EFFECT_CARRIER, cur.byte_start)
                    nrow = self._node_row_with_start_id(
                        fm,
                        info,
                        NodeKind.EFFECT_CARRIER,
                        deco_id,
                        name=cur.name,
                        ev=ev,
                        extra=deco_extra,
                    )
                    yield ("node", nrow)
                    target_scope = None
                    for scope in reversed(scope_stack):
                        if scope.kind not in (NodeKind.FUNCTION, NodeKind.CLASS):
                            continue
                        if cur.byte_start <= scope.byte_start:
                            target_scope = scope
                            break
                    if target_scope is not None:
                        erow = self._edge_row(
                            fm,
                            info,
                            EdgeKind.DECORATES,
                            src_id=deco_id,
                            dst_id=target_scope.node_id,
                            ev=ev,
                            extra=dict(deco_extra),
                        )
                        yield ("edge", erow)
                    else:
                        pending_decorators.append((deco_id, ev, dict(deco_extra)))

                # Fallback emission: if this was recognized as a function/class by adapter,
                # but no scope was opened (cur.kind got demoted to BLOCK), still emit a node
                # and a defines edge under the nearest parent scope (module/class) or file.
                if cur.kind == NodeKind.BLOCK:
                    if adapter.is_function(cur.type_name) or adapter.looks_like_function(cur.type_name):
                        inferred_kind = NodeKind.FUNCTION
                    elif adapter.is_class(cur.type_name) or adapter.looks_like_class(cur.type_name):
                        inferred_kind = NodeKind.CLASS
                    else:
                        inferred_kind = None
                    if inferred_kind is not None:
                        node_id = self._start_based_node_id(fm, inferred_kind, cur.byte_start)
                        parent_id = scope_stack[-1].node_id if scope_stack else file_id
                        nrow = self._node_row_with_start_id(
                            fm, info, inferred_kind, node_id, name=cur.name, ev=ev, extra={"type": cur.type_name, "inferred": "true"}
                        )
                        yield ("node", nrow)
                        erow = self._edge_row(fm, info, EdgeKind.DEFINES, src_id=parent_id, dst_id=node_id, ev=ev, extra={"inferred": "true"})
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
                    qname = self._extract_qualified_name(list(self._token_window)[-8:], fm)
                    callee = qname or cur.name or "<unknown>"
                    sym = self._create_symbol_node(fm, info, callee, ev, "callee")
                    yield ("node", sym)
                    src_id = cur.want_edge_from
                    caller_extra: Dict[str, object] = {}
                    if src_id is None:
                        fallback_id = cur.extra.get("call_src_fallback")
                        if not isinstance(fallback_id, str):
                            fallback_id = scope_stack[-1].node_id if scope_stack else file_id
                        src_id = fallback_id
                        caller_extra["caller_fallback"] = "true"
                    # Attach a lightweight argument stub for Step-2 alignment (best-effort)
                    args_stub = self._build_args_stub(fm, ev)
                    edge_extra: Dict[str, object] = {"callee": callee, "args_model_stub": args_stub}
                    edge_extra.update(caller_extra)
                    yield ("edge", self._edge_row(
                        fm, info, EdgeKind.CALLS, src_id=src_id, dst_id=sym.id, ev=ev,
                        extra=edge_extra
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

    def _token_is_identifier(self, ev: CstEvent, lang: Language) -> bool:
        """Check if a token event represents an identifier in the given language."""
        # Some drivers set ev.type, some set ev.token_type; normalize
        t = getattr(ev, "type", None) or getattr(ev, "token_type", None)
        if not t:
            return False
        return t in _ID_TOKENS_BY_LANG.get(lang, set())

    def _token_text(self, ev: CstEvent) -> Optional[str]:
        """Extract text content from a token event."""
        # Prefer 'text' then 'value', finally 'lexeme'; drivers vary
        for attr in ("text", "value", "lexeme"):
            v = getattr(ev, attr, None)
            if isinstance(v, str) and v.strip():
                return v
        return None

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

    def _build_args_stub(self, fm: FileMeta, ev: CstEvent) -> List[Dict[str, object]]:
        """
        Best-effort, bounded argument model stub for call edges.
        We do not parse deeply here; we return an empty list (valid JSON array),
        which is sufficient for Step-2 presence checks. Implementors can enhance
        this to slice spans and classify literals/templates/identifiers.
        """
        return []

    def _update_function_param_capture(
        self,
        ev: CstEvent,
        adapter: _Adapter,
        fm: FileMeta,
        pend_stack: List[_PendingConstruct],
        pending_scopes: Dict[int, _Scope],
        token_text: Optional[str],
    ) -> None:
        if not pend_stack:
            return

        tok_type = ev.type or ""
        tok_lower = tok_type.lower()

        for pending in reversed(pend_stack):
            if pending.kind != NodeKind.FUNCTION:
                continue
            if not pending.extra.get("param_capture_active"):
                continue

            names_list = pending.extra.setdefault("param_names", [])
            paren_depth = int(pending.extra.get("param_capture_paren", 0) or 0)
            started = bool(pending.extra.get("param_capture_started", False))
            expect_name = bool(pending.extra.get("param_expect_name", False))
            is_lambda_like = bool(pending.extra.get("param_capture_lambda", False))

            if tok_type in {"(", "["} or tok_lower in {"l_paren", "left_paren", "left_parenthesis"}:
                paren_depth += 1
                pending.extra["param_capture_paren"] = paren_depth
                pending.extra["param_capture_started"] = True
                pending.extra["param_expect_name"] = True
                break

            if tok_type in {")",
                "]",
            } or tok_lower in {"r_paren", "right_paren", "right_parenthesis"}:
                if paren_depth > 0:
                    paren_depth -= 1
                pending.extra["param_capture_paren"] = paren_depth
                if paren_depth <= 0 and started:
                    pending.extra["param_capture_active"] = False
                    pending.extra["param_expect_name"] = False
                break

            if tok_type in {"{", "l_brace"} or tok_lower in {"l_brace", "left_brace", "brace"}:
                if paren_depth <= 0:
                    pending.extra["param_capture_active"] = False
                    pending.extra["param_expect_name"] = False
                break

            if tok_type in {"=>", "->"} or tok_lower in {"arrow", "fat_arrow"}:
                pending.extra["param_capture_active"] = False
                pending.extra["param_expect_name"] = False
                break

            if tok_type in {":", "colon"} or tok_lower == "colon":
                if paren_depth <= 0:
                    if started or is_lambda_like:
                        pending.extra["param_capture_active"] = False
                    pending.extra["param_expect_name"] = False
                else:
                    pending.extra["param_expect_name"] = False
                break

            if tok_type in {"=", "equals"} or tok_lower == "equals":
                pending.extra["param_expect_name"] = False
                break

            if tok_type in {",", "comma"} or tok_lower == "comma":
                if paren_depth > 0 or is_lambda_like:
                    pending.extra["param_expect_name"] = True
                break

            if tok_type in {"/", "slash"} or tok_lower == "slash":
                if paren_depth > 0:
                    pending.extra["param_expect_name"] = True
                break

            if tok_type in {"*", "star", "**"} or tok_lower in {"star", "asterisk", "double_star"}:
                pending.extra["param_expect_name"] = True
                break

            if adapter.is_identifier_token(tok_type):
                active_zone = False
                if paren_depth > 0:
                    active_zone = expect_name
                elif not started:
                    active_zone = expect_name
                if active_zone:
                    name = token_text if token_text else self._safe_token_name(ev, fm)
                    if name:
                        if not names_list or names_list[-1] != name:
                            names_list.append(name)
                            scope = pending_scopes.get(pending.byte_start)
                            if scope is not None:
                                if not scope.params or scope.params[-1] != name:
                                    scope.params.append(name)
                    pending.extra["param_expect_name"] = False
                    pending.extra["param_capture_started"] = True
                break

            # Token didn't match any capture control; continue to next outer function.
        return

    def _extract_params_from_source(self, fm: FileMeta, scope: _Scope) -> List[str]:
        try:
            with open(fm.real_path, "rb") as fh:
                fh.seek(max(0, scope.byte_start))
                header_bytes = fh.read(512)
        except Exception:
            return []

        try:
            text = header_bytes.decode(fm.encoding or "utf-8", errors="ignore")
        except Exception:
            text = header_bytes.decode("utf-8", errors="ignore")

        segment = ""
        stripped = text.lstrip()
        if "(" in text:
            start = text.find("(") + 1
            depth = 1
            for idx in range(start, len(text)):
                ch = text[idx]
                if ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
                    if depth == 0:
                        segment = text[start:idx]
                        break
        elif stripped.startswith("lambda"):
            after = stripped.split("lambda", 1)[1]
            for idx, ch in enumerate(after):
                if ch == ":":
                    segment = after[:idx]
                    break
        elif "=>" in text:
            arrow_idx = text.find("=>")
            before = text[:arrow_idx].strip()
            if before.startswith("(") and ")" in before:
                start = before.find("(") + 1
                end = before.rfind(")")
                segment = before[start:end]
            else:
                segment = before

        if not segment:
            return []

        names: List[str] = []
        for chunk in self._split_param_chunks(segment):
            name = self._param_name_from_chunk(chunk)
            if name:
                names.append(name)
        return names

    def _split_param_chunks(self, segment: str) -> List[str]:
        chunks: List[str] = []
        current: List[str] = []
        depth = 0
        for ch in segment:
            if ch in "([{":
                depth += 1
            elif ch in ")]}":
                if depth > 0:
                    depth -= 1
            if ch == "," and depth == 0:
                chunk = "".join(current).strip()
                if chunk:
                    chunks.append(chunk)
                current = []
                continue
            current.append(ch)
        tail = "".join(current).strip()
        if tail:
            chunks.append(tail)
        return chunks

    def _param_name_from_chunk(self, chunk: str) -> Optional[str]:
        text = chunk.strip()
        if not text or text == "/":
            return None
        if text[0] in "[{":
            return None
        # Strip default values or annotations
        for sep in ("=", ":"):
            if sep in text:
                text = text.split(sep, 1)[0].strip()
        if not text:
            return None
        while text and text[0] == "*":
            text = text[1:].lstrip()
        if not text:
            return None
        name_chars: List[str] = []
        for ch in text:
            if ch.isalnum() or ch in {"_", "$"}:
                name_chars.append(ch)
            else:
                break
        name = "".join(name_chars)
        return name or None

    def _safe_classify(self, adapter: _Adapter, node_type: str, ev: CstEvent, sink: AnomalySink, fm: FileMeta) -> Tuple[Optional[NodeKind], bool]:
        """Harden node-kind classification to handle all function/class variants."""
        try:
            # Module
            if adapter.is_module(node_type):
                return NodeKind.MODULE, True

            # Class (libCST / TS) - explicit variants (no bare 'class' keyword)
            if adapter.is_class(node_type) or node_type in {"ClassDef", "class_declaration"}:
                return NodeKind.CLASS, True

            # Function / Method / Arrow / Async across languages (no bare 'function' keyword)
            if adapter.is_function(node_type) or node_type in {
                "FunctionDef", "AsyncFunctionDef",              # Python
                "generator_function_declaration",               # if present
            }:
                return NodeKind.FUNCTION, True

            if adapter.looks_like_function(node_type):
                return NodeKind.FUNCTION, True

            if adapter.looks_like_class(node_type):
                return NodeKind.CLASS, True

            # Imports / Exports (unchanged)
            if _is_import_like(adapter, node_type):
                return NodeKind.IMPORT, False
            if _is_export_like(adapter, node_type):
                return NodeKind.EXPORT, False

            # Calls (unchanged)
            if adapter.is_call(node_type):
                return NodeKind.SYMBOL, False  # call-sites are symbols + CALL edges

            # Decorators
            if adapter.is_decorator(node_type):
                return NodeKind.EFFECT_CARRIER, True

            # Literals, identifiers, etc. fall through...
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

    def _node_row_with_start_id(
        self,
        fm: FileMeta,
        info: Optional[DriverInfo],
        kind: NodeKind,
        node_id: str,
        *,
        name: Optional[str],
        ev: CstEvent,
        extra: Dict[str, object],
    ) -> NodeRow:
        prov = build_provenance_from_event(
            fm,
            info,
            ev,
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

    def _edge_row(
        self,
        fm: FileMeta,
        info: Optional[DriverInfo],
        kind: EdgeKind,
        *,
        src_id: str,
        dst_id: str,
        ev: CstEvent,
        extra: Dict[str, object],
    ) -> EdgeRow:
        prov = build_provenance_from_event(
            fm,
            info,
            ev,
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
        prov = build_provenance_from_event(
            fm,
            info,
            ev,
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
        prov = build_provenance(
            fm,
            info,
            byte_start=0,
            byte_end=fm.size_bytes,
            line_start=1,
            line_end=1,
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

    def _finalize_scope_at_index(
        self,
        idx: int,
        *,
        scope_stack: List[_Scope],
        fm: FileMeta,
        info: Optional[DriverInfo],
        ev: CstEvent,
        extra_type: str,
        file_id: str,
    ) -> Iterator[tuple[str, object]]:
        """Emit node+edge for the scope at scope_stack[idx] and pop it."""
        scope = scope_stack[idx]

        # Emit the scope node (start-id preserved) with current EXIT span
        extra_payload: Dict[str, object] = {"type": extra_type}
        if scope.kind == NodeKind.FUNCTION:
            param_names = [name for name in scope.params if name]
            if not param_names:
                param_names = self._extract_params_from_source(fm, scope)
            scope.params = param_names
            param_map = {str(idx): name for idx, name in enumerate(param_names) if name}
            extra_payload["param_index_to_name"] = param_map
        nrow = self._node_row_with_start_id(
            fm,
            info,
            scope.kind,
            scope.node_id,
            name=scope.name,
            ev=ev,
            extra=extra_payload,
        )
        yield ("node", nrow)

        parent_id = scope.parent_id or file_id
        erow = self._edge_row(fm, info, EdgeKind.DEFINES, src_id=parent_id, dst_id=scope.node_id, ev=ev, extra={})
        yield ("edge", erow)

        # Pop exactly this scope (and only this one)
        scope_stack.pop(idx)

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