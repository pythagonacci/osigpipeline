# src/provis/ucg/dfg.py
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Iterator, List, Optional, Tuple

from .discovery import Anomaly, AnomalyKind, AnomalySink, FileMeta, Language, Severity
from .parser_registry import CstEvent, CstEventKind, DriverInfo, ParseStream


# ==============================================================================
# DFG schema (rows)
# ==============================================================================

class DfgNodeKind(str, Enum):
    PARAM = "param"
    VAR_DEF = "var_def"
    VAR_USE = "var_use"
    LITERAL = "literal"


class DfgEdgeKind(str, Enum):
    DEF_USE = "def_use"         # var_def -> var_use
    CONST_PART = "const_part"   # literal -> var_def/use (string builder parts)
    ARG_TO_PARAM = "arg_to_param"  # call arg literal/var -> callee param (intra-file seed only)


@dataclass(frozen=True)
class DfgProvenance:
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
class DfgNodeRow:
    id: str
    func_id: str
    kind: DfgNodeKind
    name: Optional[str]  # var/param name; None for literal
    version: Optional[int]  # SSA index for VAR_DEF/VAR_USE
    path: str
    lang: Language
    attrs_json: str
    prov: DfgProvenance


@dataclass(frozen=True)
class DfgEdgeRow:
    id: str
    func_id: str
    kind: DfgEdgeKind
    src_id: str
    dst_id: str
    path: str
    lang: Language
    attrs_json: str
    prov: DfgProvenance


# ==============================================================================
# Config
# ==============================================================================

@dataclass(frozen=True)
class DfgConfig:
    id_salt: str = "dfg-v1"
    max_defs_per_func: int = 100000   # guards for pathological files
    max_uses_per_func: int = 200000
    capture_numeric_literals: bool = True
    capture_string_literals: bool = True
    max_literal_span: int = 8192      # keep spans reasonable


# ==============================================================================
# Helpers
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
# Language adapters (assignment/ident/params)
# ==============================================================================

class _Adapter:
    """Spot assignment sites, identifier tokens, params, and string/number tokens."""

    def __init__(self, lang: Language) -> None:
        self.lang = lang
        self._init_sets()

    def _init_sets(self) -> None:
        if self.lang == Language.PY:
            # statement/expr nodes
            self.function_nodes = {"FunctionDef", "AsyncFunctionDef", "Lambda"}
            self.param_list_nodes = {"Parameters"}  # libcst Parameters node; we’ll also accept PARAM tokens
            self.assign_nodes = {"Assign", "AnnAssign", "AugAssign"}
            self.identifier_tokens = {"Name", "Attribute"}  # conservative
            self.string_tokens = {"SimpleString"}
            self.number_tokens = {"Integer", "Float"}
            self.call_nodes = {"Call"}
            self.arg_name_tokens = {"Name"}  # simple heuristic
            self.param_token_types = {"Name"}  # parameter names appear as Name tokens inside parameters list
            self.assignment_operators = {"=", "+=", "-=", "*=", "/=", "%=", "**=", "//=", "|=", "&=", "^=", ">>=", "<<="}
        else:
            # JS/TS
            self.function_nodes = {"function_declaration", "function_expression", "method_definition", "arrow_function"}
            self.param_list_nodes = {"formal_parameters"}
            self.assign_nodes = {"variable_declarator", "assignment_expression"}
            self.identifier_tokens = {"identifier", "property_identifier", "shorthand_property_identifier", "private_property_identifier"}
            self.string_tokens = {"string", "string_fragment", "string_literal", "template_string"}
            self.number_tokens = {"number"}
            self.call_nodes = {"call_expression", "new_expression"}
            self.arg_name_tokens = {"identifier", "property_identifier"}
            self.param_token_types = {"identifier"}
            self.assignment_operators = {"=", "+=", "-=", "*=", "/=", "%=", "**=", "|=", "&=", "^=", ">>=", "<<="}

    def is_function(self, t: str) -> bool: return t in self.function_nodes
    def is_param_list(self, t: str) -> bool: return t in self.param_list_nodes
    def is_assign(self, t: str) -> bool: return t in self.assign_nodes
    def is_identifier_token(self, t: str) -> bool: return t in self.identifier_tokens
    def is_string_token(self, t: str) -> bool: return t in self.string_tokens
    def is_number_token(self, t: str) -> bool: return t in self.number_tokens
    def is_call(self, t: str) -> bool: return t in self.call_nodes
    def is_param_token(self, t: str) -> bool: return t in self.param_token_types
    def is_assignment_operator(self, tok: str) -> bool: return tok in self.assignment_operators


# ==============================================================================
# Builder state
# ==============================================================================

@dataclass
class _FuncState:
    func_id: str
    defs_count: int = 0
    uses_count: int = 0
    # current SSA versions per variable name
    versions: Dict[str, int] = field(default_factory=dict)
    # whether we are scanning parameter list tokens
    in_params: bool = False
    # last opened assignment byte_start (to attach literal parts)
    assign_stack: List[int] = field(default_factory=list)
    # map literal node ids emitted in this assignment to connect const_part edges
    pending_literals: List[str] = field(default_factory=list)


# ==============================================================================
# DFG builder
# ==============================================================================

class DfgBuilder:
    """Streaming SSA-lite local DFG over one ParseStream."""

    def __init__(self, cfg: Optional[DfgConfig] = None) -> None:
        self.cfg = cfg or DfgConfig()

    def build(self, ps: ParseStream, sink: AnomalySink) -> Iterator[Tuple[str, object]]:
        fm = ps.file
        info: Optional[DriverInfo] = ps.driver
        adapter = _Adapter(fm.lang)

        if not ps.ok or ps.events is None:
            sink.emit(Anomaly(
                path=fm.path, blob_sha=fm.blob_sha, kind=AnomalyKind.PARSE_FAILED, severity=Severity.ERROR,
                detail=ps.error or "parse stream missing",
            ))
            return

        func_stack: List[_FuncState] = []

        def prov(ev: CstEvent) -> DfgProvenance:
            return DfgProvenance(
                path=fm.path, blob_sha=fm.blob_sha, lang=fm.lang,
                grammar_sha=(info.grammar_sha if info else ""),
                run_id=fm.run_id, config_hash=fm.config_hash,
                byte_start=ev.byte_start, byte_end=ev.byte_end,
                line_start=ev.line_start, line_end=ev.line_end,
            )

        def node_id(kind: DfgNodeKind, func_id: str, name: Optional[str], version: Optional[int], ev: CstEvent) -> str:
            # stable by function, name, version, and start byte
            vpart = "" if version is None else str(version)
            nmpart = "" if name is None else name
            return _stable_id(self.cfg.id_salt, "node", fm.path, fm.blob_sha, func_id, kind.value, nmpart, vpart, str(ev.byte_start))

        def edge_id(kind: DfgEdgeKind, func_id: str, src: str, dst: str, ev: CstEvent) -> str:
            return _stable_id(self.cfg.id_salt, "edge", fm.path, fm.blob_sha, func_id, kind.value, src, dst, str(ev.byte_start))

        def emit_param(name: str, func: _FuncState, ev: CstEvent) -> Iterator[Tuple[str, object]]:
            # params start at version 0
            func.versions.setdefault(name, 0)
            nid = node_id(DfgNodeKind.PARAM, func.func_id, name, 0, ev)
            row = DfgNodeRow(
                id=nid, func_id=func.func_id, kind=DfgNodeKind.PARAM, name=name, version=0,
                path=fm.path, lang=fm.lang, attrs_json=_compact({}), prov=prov(ev),
            )
            yield ("dfg_node", row)

        def emit_var_def(name: str, func: _FuncState, ev: CstEvent) -> Iterator[Tuple[str, object]]:
            v = func.versions.get(name, -1) + 1
            func.versions[name] = v
            func.defs_count += 1
            nid = node_id(DfgNodeKind.VAR_DEF, func.func_id, name, v, ev)
            row = DfgNodeRow(
                id=nid, func_id=func.func_id, kind=DfgNodeKind.VAR_DEF, name=name, version=v,
                path=fm.path, lang=fm.lang, attrs_json=_compact({}), prov=prov(ev),
            )
            yield ("dfg_node", row)

        def emit_var_use(name: str, func: _FuncState, ev: CstEvent) -> Iterator[Tuple[str, object]]:
            v = func.versions.get(name, 0)  # use current version; if unseen, assume 0
            func.uses_count += 1
            nid = node_id(DfgNodeKind.VAR_USE, func.func_id, name, v, ev)
            row = DfgNodeRow(
                id=nid, func_id=func.func_id, kind=DfgNodeKind.VAR_USE, name=name, version=v,
                path=fm.path, lang=fm.lang, attrs_json=_compact({}), prov=prov(ev),
            )
            yield ("dfg_node", row)
            # Edge from latest def (same version) to this use:
            def_id = node_id(DfgNodeKind.VAR_DEF, func.func_id, name, v, ev)  # same key parts except start byte differs
            # We can’t reconstruct exact def’s start byte here; use “version-only” id by dropping ev byte.
            # Workaround: create a *logical* id by hashing without the ev.byte_start for defs and reuse here.
            # For stability across this run, synthesize a def key:
            def logical_def_id(nm: str, ver: int) -> str:
                return _stable_id(self.cfg.id_salt, "node", fm.path, fm.blob_sha, func.func_id, "var_def", nm, str(ver))
            def logical_use_id(nm: str, ver: int, b: int) -> str:
                return _stable_id(self.cfg.id_salt, "node", fm.path, fm.blob_sha, func.func_id, "var_use", nm, str(ver), str(b))
            src = logical_def_id(name, v)
            dst = logical_use_id(name, v, ev.byte_start)
            # Emit DEF_USE with logical ids in attrs so downstream can resolve by join keys
            eid = edge_id(DfgEdgeKind.DEF_USE, func.func_id, src, dst, ev)
            erow = DfgEdgeRow(
                id=eid, func_id=func.func_id, kind=DfgEdgeKind.DEF_USE, src_id=src, dst_id=dst,
                path=fm.path, lang=fm.lang, attrs_json=_compact({"name": name, "version": v, "logical": True}), prov=prov(ev),
            )
            yield ("dfg_edge", erow)

        def emit_literal(kind: str, func: _FuncState, ev: CstEvent) -> str:
            # literal nodes have no name/version; keep spans only
            if ev.byte_end - ev.byte_start > self.cfg.max_literal_span:
                return ""
            nid = node_id(DfgNodeKind.LITERAL, func.func_id, None, None, ev)
            row = DfgNodeRow(
                id=nid, func_id=func.func_id, kind=DfgNodeKind.LITERAL, name=None, version=None,
                path=fm.path, lang=fm.lang, attrs_json=_compact({"token_kind": kind}), prov=prov(ev),
            )
            yield ("dfg_node", row)
            return nid  # type: ignore[return-value]

        def emit_const_part(lit_id: str, target_id: str, func: _FuncState, ev: CstEvent) -> Iterator[Tuple[str, object]]:
            eid = edge_id(DfgEdgeKind.CONST_PART, func.func_id, lit_id, target_id, ev)
            row = DfgEdgeRow(
                id=eid, func_id=func.func_id, kind=DfgEdgeKind.CONST_PART, src_id=lit_id, dst_id=target_id,
                path=fm.path, lang=fm.lang, attrs_json=_compact({}), prov=prov(ev),
            )
            yield ("dfg_edge", row)

        # walk events
        for ev in ps.events:
            if ev.kind == CstEventKind.ENTER and adapter.is_function(ev.type):
                # open function
                func_id = _stable_id(self.cfg.id_salt, "func", fm.path, fm.blob_sha, str(ev.byte_start))
                func_stack.append(_FuncState(func_id=func_id))
                continue

            if not func_stack:
                continue  # ignore top-level uses/assigns

            func = func_stack[-1]

            # Resource guards
            if func.defs_count > self.cfg.max_defs_per_func or func.uses_count > self.cfg.max_uses_per_func:
                sink.emit(Anomaly(
                    path=fm.path, blob_sha=fm.blob_sha, kind=AnomalyKind.MEMORY_LIMIT, severity=Severity.ERROR,
                    detail="DFG limits exceeded", span=(ev.byte_start, ev.byte_end),
                ))
                # drop rest of this function
                func_stack.pop()
                continue

            if ev.kind == CstEventKind.ENTER:
                # parameter list starts
                if adapter.is_param_list(ev.type):
                    func.in_params = True
                if adapter.is_assign(ev.type):
                    func.assign_stack.append(ev.byte_start)

            elif ev.kind == CstEventKind.TOKEN:
                # params
                if func.in_params and adapter.is_param_token(ev.type):
                    name = self._safe_token_name(ev, fm)
                    if name:
                        for out in emit_param(name, func, ev):
                            yield out
                    continue

                # assignment LHS variable defs (heuristic: identifier tokens that appear soon after an assignment ENTER)
                if adapter.is_identifier_token(ev.type):
                    name = self._safe_token_name(ev, fm)
                    if not name:
                        continue
                    if func.assign_stack:
                        # Treat first identifier after an assignment as a DEF; subsequent identifiers are uses.
                        # This is conservative (covers simple patterns: x = ..., let x = ..., x += ...)
                        for out in emit_var_def(name, func, ev):
                            yield out
                        # attach any pending literals as CONST_PARTs targeting this new def
                        # we can’t know literal ids here (streaming); so we emit edges later when we emit literals: store target id in pending list
                        # Instead: synthesize a stable target placeholder id for this def (logical id), and connect literal → logical-def
                        def logical_def_id(nm: str, ver: int) -> str:
                            return _stable_id(self.cfg.id_salt, "node", fm.path, fm.blob_sha, func.func_id, "var_def", nm, str(func.versions.get(nm, 0)))
                        target = logical_def_id(name, func.versions.get(name, 0))
                        # mark where to connect; actual connection occurs when literal appears (below) using same target id
                        func.pending_literals.append(target)
                        # only treat the first identifier after opening assignment as LHS; pop to avoid marking all as defs
                        func.assign_stack.pop()
                    else:
                        # plain use
                        for out in emit_var_use(name, func, ev):
                            yield out
                    continue

                # literals → emit literal nodes & const_part edges to most recent pending target (if any)
                if (self.cfg.capture_string_literals and adapter.is_string_token(ev.type)) or (
                    self.cfg.capture_numeric_literals and adapter.is_number_token(ev.type)
                ):
                    # emit literal node
                    lit_id_out = ""
                    for out in emit_literal(ev.type, func, ev):
                        if isinstance(out, tuple) and out[0] == "dfg_node":
                            lit_id_out = out[1].id  # type: ignore[attr-defined]
                        yield out
                    if func.pending_literals and lit_id_out:
                        # connect literal to last pending def placeholder
                        target = func.pending_literals[-1]
                        for out in emit_const_part(lit_id_out, target, func, ev):
                            yield out
                    continue

            elif ev.kind == CstEventKind.EXIT:
                if adapter.is_param_list(ev.type):
                    func.in_params = False
                if adapter.is_function(ev.type):
                    func_stack.pop()
                # close assignment expression scope if EXIT matches last assignment ENTER (best-effort)
                if adapter.is_assign(ev.type) and func.assign_stack:
                    func.assign_stack.pop()

        # synthesize close for any dangling functions
        while func_stack:
            func_stack.pop()

    # ---- utilities ------------------------------------------------------------

    def _safe_token_name(self, ev: CstEvent, fm: FileMeta) -> Optional[str]:
        """Memory-lean, conservative identifier extraction (<=1KB slice)."""
        try:
            if ev.byte_end <= ev.byte_start:
                return None
            size = ev.byte_end - ev.byte_start
            if size > 1024:
                return None
            with open(fm.real_path, "rb") as f:
                f.seek(ev.byte_start)
                token = f.read(size)
            text = token.decode(fm.encoding or "utf-8", errors="replace").strip()
            if not text or len(text) > 256:
                return None
            ch0 = text[0]
            if not (ch0.isalpha() or ch0 == "_"):
                return None
            for ch in text[1:]:
                if not (ch.isalnum() or ch in "._$"):
                    return None
            # avoid pure numbers
            if text.replace("_", "").isdigit():
                return None
            return text
        except Exception:
            return None


# ==============================================================================
# Public convenience
# ==============================================================================

def build_dfg(ps: ParseStream, sink: AnomalySink, cfg: Optional[DfgConfig] = None) -> Iterator[Tuple[str, object]]:
    builder = DfgBuilder(cfg)
    yield from builder.build(ps, sink)
