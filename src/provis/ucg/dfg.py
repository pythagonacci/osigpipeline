# src/provis/ucg/dfg.py
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Iterator, List, Optional, Tuple

from .discovery import Anomaly, AnomalyKind, AnomalySink, FileMeta, Language, Severity
from .parser_registry import CstEvent, CstEventKind, DriverInfo
from .provenance import ProvenanceV2, build_provenance_from_event

# ==============================================================================
# DFG schema (rows)
# ==============================================================================

class DfgNodeKind(str, Enum):
    PARAM = "param"
    VAR_DEF = "var_def"
    VAR_USE = "var_use"
    LITERAL = "literal"

class DfgEdgeKind(str, Enum):
    DEF_USE = "def_use"
    CONST_PART = "const_part"
    ARG_TO_PARAM = "arg_to_param"

@dataclass(frozen=True)
class DfgNodeRow:
    id: str
    func_id: str
    kind: DfgNodeKind
    name: Optional[str]
    version: Optional[int]
    path: str
    lang: Language
    attrs_json: str
    prov: ProvenanceV2

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
    prov: ProvenanceV2

# ==============================================================================
# Config & State Management Classes
# ==============================================================================

@dataclass(frozen=True)
class DfgConfig:
    id_salt: str = "dfg-v1"
    max_defs_per_func: int = 100000
    max_uses_per_func: int = 200000
    capture_numeric_literals: bool = True
    capture_string_literals: bool = True
    max_literal_span: int = 8192

def _stable_id(*parts: str) -> str:
    h = hashlib.blake2b(digest_size=20)
    for p in parts:
        h.update(b"\x1f")
        h.update(p.encode("utf-8", "ignore"))
    return h.hexdigest()

def _compact(obj: dict) -> str:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True)

@dataclass
class _VariableState:
    name: str
    version: int = -1 # Start at -1, first definition makes it 0
    defining_node_id: Optional[str] = None

class Scope:
    def __init__(self, scope_id: str, parent: Optional['Scope'] = None):
        self.scope_id = scope_id
        self.parent = parent
        self.variables: Dict[str, _VariableState] = {}

    def find_variable(self, name: str) -> Optional[_VariableState]:
        if name in self.variables:
            return self.variables[name]
        if self.parent:
            return self.parent.find_variable(name)
        return None

    def define_variable(self, name: str, defining_node_id: str) -> _VariableState:
        var = self.variables.get(name, _VariableState(name=name))
        var.version += 1
        var.defining_node_id = defining_node_id
        self.variables[name] = var
        return var

# ==============================================================================
# Language adapters
# ==============================================================================
class _Adapter:
    def __init__(self, lang: Language) -> None:
        self.lang = lang
        self._init_sets()

    def _init_sets(self) -> None:
        if self.lang == Language.PY:
            self.function_nodes = {"FunctionDef", "AsyncFunctionDef", "Lambda"}
            self.param_list_nodes = {"Parameters", "LambdaParameters"}
            self.assign_nodes = {"Assign", "AnnAssign", "AugAssign"}
            self.assign_target_nodes = {"AssignTarget", "Name", "Attribute"}
            self.identifier_tokens = {"Name", "Attribute"}
            self.param_token_types = {"Name"}
            self.assignment_operators = {"=", "+=", "-=", "*=", "/=", "%=", "**=", "//=", "|=", "&=", "^=", ">>=", "<<="}
        else: # JS/TS
            self.function_nodes = {"function_declaration", "function_expression", "method_definition", "arrow_function"}
            self.param_list_nodes = {"formal_parameters"}
            self.assign_nodes = {"variable_declarator", "assignment_expression"}
            self.assign_target_nodes = {"identifier", "property_identifier", "shorthand_property_identifier", "array_pattern", "object_pattern"}
            self.identifier_tokens = {"identifier", "property_identifier", "shorthand_property_identifier", "private_property_identifier"}
            self.param_token_types = {"identifier"}
            self.assignment_operators = {"=", "+=", "-=", "*=", "/=", "%=", "**=", "|=", "&=", "^=", ">>=", "<<="}

    def is_function(self, t: str) -> bool: return t in self.function_nodes
    def is_param_list(self, t: str) -> bool: return t in self.param_list_nodes
    def is_assign(self, t: str) -> bool: return t in self.assign_nodes
    def is_assign_target(self, t: str) -> bool: return t in self.assign_target_nodes
    def is_identifier_token(self, t: str) -> bool: return t in self.identifier_tokens
    def is_param_token(self, t: str) -> bool: return t in self.param_token_types
    def is_assignment_operator(self, text: str) -> bool: return text in self.assignment_operators

# ==============================================================================
# DFG builder
# ==============================================================================

class DfgBuilder:
    """Robust, single-pass DFG builder using a stack-based CST walker to understand syntactic context."""

    def __init__(self, fm: FileMeta, info: Optional[DriverInfo], events: List[CstEvent], sink: AnomalySink, cfg: DfgConfig):
        self.fm = fm
        self.info = info
        self.events = events
        self.sink = sink
        self.cfg = cfg
        self.adapter = _Adapter(fm.lang)
        self.scope_stack: List[Scope] = []
        self.node_stack: List[CstEvent] = []
        self.current_assignment: Optional[dict] = None

    def build(self) -> Iterator[Tuple[str, object]]:
        if not self.events:
            return

        root_scope_id = _stable_id(self.cfg.id_salt, "module", self.fm.path, self.fm.blob_sha or "")
        self.scope_stack.append(Scope(root_scope_id))

        for i, ev in enumerate(self.events):
            if ev.kind == CstEventKind.ENTER:
                self.node_stack.append(ev)
                yield from self._handle_enter_event(ev, i)
            elif ev.kind == CstEventKind.TOKEN:
                yield from self._handle_token_event(ev)
            elif ev.kind == CstEventKind.EXIT:
                if self.node_stack:
                    yield from self._handle_exit_event(self.node_stack[-1])
                    self.node_stack.pop()

    def _handle_enter_event(self, ev: CstEvent, event_index: int) -> Iterator[Tuple[str, object]]:
        if self.adapter.is_function(ev.type):
            parent_scope = self.scope_stack[-1]
            func_name = self._find_name_in_node_span(event_index) or "<anonymous>"
            func_scope_id = _stable_id(self.cfg.id_salt, "scope", self.fm.path, self.fm.blob_sha or "", parent_scope.scope_id, "function", func_name, str(ev.byte_start))
            func_scope = Scope(func_scope_id, parent_scope)
            self.scope_stack.append(func_scope)
            
            params = self._find_params_in_node_span(event_index)
            for param_name, param_event in params:
                param_node_id = self._node_id(DfgNodeKind.PARAM, func_scope.scope_id, param_name, 0, param_event)
                yield ("dfg_node", DfgNodeRow(
                    id=param_node_id, func_id=func_scope.scope_id, kind=DfgNodeKind.PARAM, name=param_name, version=0,
                    path=self.fm.path, lang=self.fm.lang, attrs_json=_compact({}),
                    prov=build_provenance_from_event(self.fm, self.info, param_event)
                ))
                func_scope.define_variable(param_name, param_node_id)
                
        elif self.adapter.is_assign(ev.type):
            self.current_assignment = {"operator_found": False, "lhs_vars": [], "rhs_vars": []}

    def _handle_token_event(self, ev: CstEvent) -> Iterator[Tuple[str, object]]:
        token_text = self._safe_token_text(ev)
        if self.current_assignment and not self.current_assignment["operator_found"]:
            if token_text and self.adapter.is_assignment_operator(token_text):
                self.current_assignment["operator_found"] = True
                return

        name = self._safe_token_name(ev)
        if not name or not self.adapter.is_identifier_token(ev.type):
            return

        if self.current_assignment:
            if not self.current_assignment["operator_found"] or self._is_inside_assign_target():
                self.current_assignment["lhs_vars"].append((name, ev))
            else:
                self.current_assignment["rhs_vars"].append((name, ev))
        else:
            current_scope = self.scope_stack[-1]
            var_state = current_scope.find_variable(name)
            if var_state and var_state.defining_node_id:
                use_node_id = self._node_id(DfgNodeKind.VAR_USE, current_scope.scope_id, name, var_state.version, ev)
                yield ("dfg_node", DfgNodeRow(
                    id=use_node_id, func_id=current_scope.scope_id, kind=DfgNodeKind.VAR_USE, name=name, version=var_state.version,
                    path=self.fm.path, lang=self.fm.lang, attrs_json=_compact({}), 
                    prov=build_provenance_from_event(self.fm, self.info, ev)
                ))
                yield ("dfg_edge", DfgEdgeRow(
                    id=self._edge_id(DfgEdgeKind.DEF_USE, current_scope.scope_id, var_state.defining_node_id, use_node_id, ev),
                    func_id=current_scope.scope_id, kind=DfgEdgeKind.DEF_USE, src_id=var_state.defining_node_id, dst_id=use_node_id,
                    path=self.fm.path, lang=self.fm.lang, attrs_json=_compact({"name": name, "version": var_state.version}),
                    prov=build_provenance_from_event(self.fm, self.info, ev)
                ))

    def _handle_exit_event(self, exited_node_event: CstEvent) -> Iterator[Tuple[str, object]]:
        if self.adapter.is_function(exited_node_event.type):
            if len(self.scope_stack) > 1:
                self.scope_stack.pop()
        elif self.adapter.is_assign(exited_node_event.type):
            if self.current_assignment:
                current_scope = self.scope_stack[-1]
                
                # Process RHS (uses) first
                for name, token_ev in self.current_assignment["rhs_vars"]:
                    var_state = current_scope.find_variable(name)
                    if var_state and var_state.defining_node_id:
                        use_node_id = self._node_id(DfgNodeKind.VAR_USE, current_scope.scope_id, name, var_state.version, token_ev)
                        yield ("dfg_node", DfgNodeRow(
                            id=use_node_id, func_id=current_scope.scope_id, kind=DfgNodeKind.VAR_USE, name=name, version=var_state.version,
                            path=self.fm.path, lang=self.fm.lang, attrs_json=_compact({}),
                            prov=build_provenance_from_event(self.fm, self.info, token_ev)
                        ))
                        yield ("dfg_edge", DfgEdgeRow(
                            id=self._edge_id(DfgEdgeKind.DEF_USE, current_scope.scope_id, var_state.defining_node_id, use_node_id, token_ev),
                            func_id=current_scope.scope_id, kind=DfgEdgeKind.DEF_USE, src_id=var_state.defining_node_id, dst_id=use_node_id,
                            path=self.fm.path, lang=self.fm.lang, attrs_json=_compact({}),
                            prov=build_provenance_from_event(self.fm, self.info, token_ev)
                        ))
                
                # Process LHS (defs) second
                for name, token_ev in self.current_assignment["lhs_vars"]:
                    new_def_node_id_placeholder = self._node_id(DfgNodeKind.VAR_DEF, current_scope.scope_id, name, -1, token_ev)
                    var_state = current_scope.define_variable(name, new_def_node_id_placeholder)
                    new_def_node_id = self._node_id(DfgNodeKind.VAR_DEF, current_scope.scope_id, name, var_state.version, token_ev)
                    var_state.defining_node_id = new_def_node_id
                    
                    yield ("dfg_node", DfgNodeRow(
                        id=new_def_node_id, func_id=current_scope.scope_id, kind=DfgNodeKind.VAR_DEF, name=name, version=var_state.version,
                        path=self.fm.path, lang=self.fm.lang, attrs_json=_compact({}),
                        prov=build_provenance_from_event(self.fm, self.info, token_ev)
                    ))
                
                # Check for simple alias
                if len(self.current_assignment["lhs_vars"]) == 1 and len(self.current_assignment["rhs_vars"]) == 1:
                    lhs_name, _ = self.current_assignment["lhs_vars"][0]
                    rhs_name, _ = self.current_assignment["rhs_vars"][0]
                    yield ("alias_hint", {"lhs_name": lhs_name, "rhs_name": rhs_name, "scope_id": current_scope.scope_id})

                self.current_assignment = None

    def _find_node_span_indices(self, parent_enter_index: int) -> Tuple[int, int]:
        start_index = parent_enter_index
        start_byte = self.events[start_index].byte_start
        end_byte = self.events[start_index].byte_end
        
        # Find the matching EXIT event
        depth = 0
        for i in range(start_index, len(self.events)):
            ev = self.events[i]
            if ev.byte_start < start_byte: continue
            
            if ev.kind == CstEventKind.ENTER and ev.byte_start >= start_byte:
                depth += 1
            elif ev.kind == CstEventKind.EXIT and ev.byte_start >= start_byte:
                depth -= 1
            
            if depth == 0 and ev.byte_start == start_byte:
                return start_index, i
        return start_index, len(self.events) - 1

    def _find_child_node_span(self, parent_enter_index: int, child_types: set[str]) -> Optional[Tuple[int, int]]:
        depth = 0
        for i in range(parent_enter_index + 1, len(self.events)):
            ev = self.events[i]
            if ev.kind == CstEventKind.ENTER:
                if depth == 0 and ev.type in child_types:
                    return self._find_node_span_indices(i)
                depth += 1
            elif ev.kind == CstEventKind.EXIT:
                depth -= 1
            
            if depth < 0:
                return None
        return None

    def _find_name_in_node_span(self, node_enter_index: int) -> Optional[str]:
        start, end = self._find_node_span_indices(node_enter_index)
        depth = 0
        for i in range(start + 1, end):
            ev = self.events[i]
            if ev.kind == CstEventKind.ENTER:
                depth += 1
            elif ev.kind == CstEventKind.EXIT:
                depth -= 1

            if depth == 0 and self.adapter.is_identifier_token(ev.type):
                name = self._safe_token_name(ev)
                if name: return name
        return None

    def _find_params_in_node_span(self, node_enter_index: int) -> List[Tuple[str, CstEvent]]:
        params = []
        param_list_span = self._find_child_node_span(node_enter_index, self.adapter.param_list_nodes)
        if not param_list_span:
            return []
            
        start, end = param_list_span
        depth = 0
        for i in range(start + 1, end):
            ev = self.events[i]
            if ev.kind == CstEventKind.ENTER:
                depth += 1
            elif ev.kind == CstEventKind.EXIT:
                depth -= 1
            
            if depth == 0 and self.adapter.is_param_token(ev.type):
                name = self._safe_token_name(ev)
                if name:
                    params.append((name, ev))
        return params

    def _is_inside_assign_target(self) -> bool:
        """Checks the node_stack to see if the current context is inside an assignment target."""
        for node_event in reversed(self.node_stack):
            if self.adapter.is_assign_target(node_event.type):
                return True
            if self.adapter.is_assign(node_event.type):
                return False
        return False

    def _node_id(self, kind: DfgNodeKind, func_id: str, name: Optional[str], version: Optional[int], ev: CstEvent) -> str:
        vpart = "" if version is None else str(version)
        nmpart = "" if name is None else name
        return _stable_id(self.cfg.id_salt, "node", self.fm.path, self.fm.blob_sha or "", func_id, kind.value, nmpart, vpart, str(ev.byte_start))

    def _edge_id(self, kind: DfgEdgeKind, func_id: str, src: str, dst: str, ev: CstEvent) -> str:
        return _stable_id(self.cfg.id_salt, "edge", self.fm.path, self.fm.blob_sha or "", func_id, kind.value, src, dst, str(ev.byte_start))
        
    def _safe_token_name(self, ev: CstEvent) -> Optional[str]:
        try:
            if ev.byte_end <= ev.byte_start or (ev.byte_end - ev.byte_start) > 1024: return None
            with open(self.fm.real_path, "rb") as f:
                f.seek(ev.byte_start)
                token = f.read(ev.byte_end - ev.byte_start)
            text = token.decode(self.fm.encoding or "utf-8", errors="replace").strip()
            if not text or len(text) > 256: return None
            if not (text[0].isalpha() or text[0] == "_"): return None
            for ch in text[1:]:
                if not (ch.isalnum() or ch in "._$"): return None
            if text.replace("_", "").isdigit(): return None
            return text
        except Exception: return None

    def _safe_token_text(self, ev: CstEvent) -> Optional[str]:
        try:
            if ev.byte_end <= ev.byte_start or (ev.byte_end - ev.byte_start) > 1024: return None
            with open(self.fm.real_path, "rb") as f:
                f.seek(ev.byte_start)
                token = f.read(ev.byte_end - ev.byte_start)
            return token.decode(self.fm.encoding or "utf-8", errors="replace").strip()
        except Exception: return None

# ==============================================================================
# Public convenience
# ==============================================================================

def build_dfg(fm: FileMeta, info: Optional[DriverInfo], events: List[CstEvent], sink: AnomalySink, cfg: Optional[DfgConfig] = None) -> Iterator[Tuple[str, object]]:
    builder = DfgBuilder(fm, info, events, sink, cfg or DfgConfig())
    yield from builder.build()