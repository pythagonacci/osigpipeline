# src/provis/ucg/symbols.py
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Iterator, List, Optional, Tuple

from .discovery import Anomaly, AnomalyKind, AnomalySink, FileMeta, Language, Severity
from .parser_registry import CstEvent, CstEventKind, DriverInfo, ParseStream


# ==============================================================================
# Row models (tables: symbols/, aliases/)
# ==============================================================================

class SymbolKind(str, Enum):
    MODULE = "module"
    CLASS = "class"
    FUNCTION = "function"
    METHOD = "method"
    VARIABLE = "variable"
    PARAM = "param"
    IMPORT = "import"      # a binding introduced by import/import-from or import decl
    EXPORT = "export"      # explicit re-export (JS) or __all__ additions (Py)


@dataclass(frozen=True)
class SymProvenance:
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
class SymbolRow:
    """
    One binding in a scope. (scope_id,name,kind) uniquely identifies a symbol
    within a run; id is deterministic content-addressed.
    """
    id: str
    scope_id: str
    name: str
    kind: SymbolKind
    visibility: str  # "public" | "private" | "internal"
    is_dynamic: bool
    path: str
    lang: Language
    attrs_json: str
    prov: SymProvenance


class AliasKind(str, Enum):
    IMPORT = "import"          # alias introduced by import ... as ...
    REEXPORT = "reexport"      # export {X as Y} or from ... export ...
    ASSIGN = "assign"          # name2 = name1 (simple in-scope alias)
    STAR_IMPORT = "star_import"
    DYNAMIC = "dynamic"        # anything we couldn’t resolve deterministically


@dataclass(frozen=True)
class AliasRow:
    """
    A → B relationship: alias_id names A (the alias binding), target_symbol_id is B.
    For unresolved/dynamic cases, target_symbol_id is empty and attrs carries detail.
    """
    id: str
    alias_kind: AliasKind
    alias_id: str           # SymbolRow.id of alias binding, if we created one; else empty
    target_symbol_id: str   # SymbolRow.id if resolved; else ""
    alias_name: str         # readable alias text (for unresolved)
    path: str
    lang: Language
    attrs_json: str
    prov: SymProvenance


# ==============================================================================
# Config & helpers
# ==============================================================================

@dataclass(frozen=True)
class SymbolsConfig:
    id_salt: str = "sym-v1"
    max_scope_depth: int = 256
    # Whether to create a module scope node for each file. When False, top scope is file-level implicit id.
    emit_module_scope: bool = True


def _stable_id(*parts: str) -> str:
    h = hashlib.blake2b(digest_size=20)
    for p in parts:
        h.update(b"\x1f")
        h.update(p.encode("utf-8", "ignore"))
    return h.hexdigest()


def _compact(obj: dict) -> str:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True)


# ------------------------------------------------------------------------------
# Path helpers
# ------------------------------------------------------------------------------

def _module_name_from_path(path: str) -> str:
    base = path.split("/")[-1]
    if "." in base:
        return base[: base.rfind(".")]
    return base


# ==============================================================================
# Language adapters: tell us where symbols/aliases appear
# ==============================================================================

class _Adapter:
    def __init__(self, lang: Language) -> None:
        self.lang = lang
        self._init_sets()

    def _init_sets(self) -> None:
        if self.lang == Language.PY:
            # libcst-ish node type names
            self.function_nodes = {"FunctionDef", "AsyncFunctionDef", "Lambda"}
            self.class_nodes = {"ClassDef"}
            self.param_token = {"Name"}    # params show as Name tokens inside Parameters
            self.assign_nodes = {"Assign", "AnnAssign", "AugAssign"}
            self.import_nodes = {"Import", "ImportFrom"}
            self.export_nodes = {"Expr"}   # we’ll detect __all__ = [...] inside
            self.identifier_tokens = {"Name"}
        else:
            # Tree-sitter JS/TS node names
            self.function_nodes = {"function_declaration", "function_expression", "method_definition", "arrow_function"}
            self.class_nodes = {"class_declaration"}
            self.param_token = {"identifier"}
            self.assign_nodes = {"variable_declarator", "assignment_expression"}
            self.import_nodes = {"import_declaration"}
            self.export_nodes = {"export_statement", "export_clause"}
            self.identifier_tokens = {"identifier", "shorthand_property_identifier", "property_identifier"}

    def is_function(self, t: str) -> bool: return t in self.function_nodes
    def is_class(self, t: str) -> bool: return t in self.class_nodes
    def is_param_token(self, t: str) -> bool: return t in self.param_token
    def is_assign(self, t: str) -> bool: return t in self.assign_nodes
    def is_import(self, t: str) -> bool: return t in self.import_nodes
    def is_export(self, t: str) -> bool: return t in self.export_nodes
    def is_identifier(self, t: str) -> bool: return t in self.identifier_tokens


# ==============================================================================
# Builder state
# ==============================================================================

@dataclass
class _Scope:
    id: str
    kind: SymbolKind
    name: str
    byte_start: int
    parent: Optional[str]


@dataclass
class _BuildState:
    adapter: _Adapter
    file: FileMeta
    driver: Optional[DriverInfo]
    cfg: SymbolsConfig
    scope_stack: List[_Scope] = field(default_factory=list)
    # Quick index: (scope_id, name) -> symbol_id for intra-file alias resolution
    sym_index: Dict[Tuple[str, str], str] = field(default_factory=dict)
    # Track whether we are scanning parameters for current function
    in_params: bool = False
    # Last assignment start → first identifier is a def; subsequent identifiers are uses (for aliasing)
    open_assign_bytes: List[int] = field(default_factory=list)
    # Counters / flags for observability
    symbols_emitted: int = 0
    aliases_emitted: int = 0
    had_precise: bool = False
    # Emission tracking for baseline WARNs
    symbols_emitted: int = 0
    aliases_emitted: int = 0
    had_precise: bool = False


# ==============================================================================
# Public API
# ==============================================================================

def build_symbols(ps: ParseStream, sink: AnomalySink, cfg: Optional[SymbolsConfig] = None) -> Iterator[Tuple[str, object]]:
    """
    Streaming symbol + alias extraction with conservative semantics.
    Emits:
      - ("symbol", SymbolRow)
      - ("alias", AliasRow)
    """
    cfg = cfg or SymbolsConfig()
    fm = ps.file
    info: Optional[DriverInfo] = ps.driver
    ad = _Adapter(fm.lang)
    st = _BuildState(adapter=ad, file=fm, driver=info, cfg=cfg)

    if not ps.ok or ps.events is None:
        sink.emit(Anomaly(
            path=fm.path, blob_sha=fm.blob_sha, kind=AnomalyKind.PARSE_FAILED, severity=Severity.ERROR,
            detail=ps.error or "parse stream missing",
        ))
        return

    # Initialize module/file scope (stable id)
    mod_scope_id = _stable_id(cfg.id_salt, "module", fm.path, fm.blob_sha or "")
    module_name = _module_name_from_path(fm.path)
    if cfg.emit_module_scope:
        mod_sym = _symbol_row(
            cfg, st, scope_id=mod_scope_id, name=module_name, kind=SymbolKind.MODULE,
            visibility="public", is_dynamic=False,
            ev=_synthetic_ev(),
            extra={"module": True},
        )
        st.scope_stack.append(_Scope(id=mod_scope_id, kind=SymbolKind.MODULE, name=mod_sym.name, byte_start=0, parent=None))
        yield ("symbol", mod_sym)
    else:
        st.scope_stack.append(_Scope(id=mod_scope_id, kind=SymbolKind.MODULE, name=module_name, byte_start=0, parent=None))

    for ev in ps.events:
        if ev.kind == CstEventKind.ENTER:
            # New function/class scopes
            if ad.is_class(ev.type):
                name = _extract_name_token(st, ev)
                scope_id = _scope_id(cfg, st, SymbolKind.CLASS, name or "<class>", ev.byte_start)
                srow = _yield_decl_and_push(st, cfg, sink, ev, name or "<class>", SymbolKind.CLASS, scope_id)
                if srow is not None:
                    st.symbols_emitted += 1
                    yield ("symbol", srow)
                continue

            if ad.is_function(ev.type):
                # functions and methods; if current scope is CLASS → METHOD else FUNCTION
                parent_kind = st.scope_stack[-1].kind if st.scope_stack else SymbolKind.MODULE
                sym_kind = SymbolKind.METHOD if parent_kind == SymbolKind.CLASS else SymbolKind.FUNCTION
                name = _extract_name_token(st, ev)
                scope_id = _scope_id(cfg, st, sym_kind, name or "<lambda>", ev.byte_start)
                srow = _yield_decl_and_push(st, cfg, sink, ev, name or "<lambda>", sym_kind, scope_id)
                if srow is not None:
                    st.symbols_emitted += 1
                    yield ("symbol", srow)
                st.in_params = True  # expect params tokens following for Py / identifiers in JS formal_parameters
                continue

            # Assignment begins (potential variable def or alias)
            if ad.is_assign(ev.type):
                st.open_assign_bytes.append(ev.byte_start)
                continue

        elif ev.kind == CstEventKind.TOKEN:
            # parameters become symbols with PARAM kind in current (function/method) scope
            if st.in_params and ad.is_param_token(ev.type):
                pname = _safe_token_text(st.file, ev)
                if pname:
                    srow = _symbol_row(cfg, st, st.scope_stack[-1].id, pname, SymbolKind.PARAM,
                                       visibility=_visibility_from_name(pname),
                                       is_dynamic=False, ev=ev, extra={})
                    st.sym_index[(st.scope_stack[-1].id, pname)] = srow.id
                    st.symbols_emitted += 1
                    yield ("symbol", srow)
                continue

            # Assignment LHS → variable definition symbol
            if st.open_assign_bytes and ad.is_identifier(ev.type):
                vname = _safe_token_text(st.file, ev)
                if vname:
                    # If name already exists in this scope, we still emit another VARIABLE symbol;
                    # alias edges (ASSIGN) tie names when pattern matches.
                    srow = _symbol_row(cfg, st, st.scope_stack[-1].id, vname, SymbolKind.VARIABLE,
                                       visibility=_visibility_from_name(vname),
                                       is_dynamic=False, ev=ev, extra={"from_assign": True})
                    st.sym_index[(st.scope_stack[-1].id, vname)] = srow.id
                    st.symbols_emitted += 1
                    yield ("symbol", srow)
                # Do not consume open_assign_bytes here; EXIT of the assignment will pop it.
                continue

        elif ev.kind == CstEventKind.EXIT:
            # Close assignment (evaluate alias heuristics)
            if st.open_assign_bytes and ad.is_assign(ev.type):
                # Simple heuristic: within one assignment, if exactly two identifier tokens appeared, treat name2=name1 as an alias
                # This is conservative and won’t fire on complex RHS.
                # (We don’t store the tokens; instead, rely on nearby token extraction — best-effort.)
                # We can’t reconstruct reliably here without a token window; mark DYNAMIC alias if uncertain.
                st.open_assign_bytes.pop()  # close the assignment block
                continue

            # End of parameter list for function/method (based on EXIT of function for simplicity)
            if ad.is_function(ev.type):
                st.in_params = False

                # Close function/method scope
                if st.scope_stack:
                    st.scope_stack.pop()
                continue

            if ad.is_class(ev.type):
                if st.scope_stack:
                    st.scope_stack.pop()
                continue

            # Imports / exports
            if ad.is_import(ev.type):
                # Create IMPORT symbols for imported bindings; resolve alias target conservatively
                # We cannot parse module path robustly here from tokens; emit IMPORT symbol + DYNAMIC alias
                names, is_type_only = _parse_import_like(st, ev)
                if not names:
                    names = [(_extract_name_token(st, ev) or "<import>")]
                for nm in names:
                    srow = _symbol_row(cfg, st, st.scope_stack[-1].id, nm, SymbolKind.IMPORT,
                                       visibility="public", is_dynamic=False, ev=ev, extra={"is_type_only": bool(is_type_only)})
                    st.sym_index[(st.scope_stack[-1].id, nm)] = srow.id
                    st.symbols_emitted += 1
                    yield ("symbol", srow)
                    # unresolved target → DYNAMIC alias
                    arow = _alias_row(cfg, st, AliasKind.DYNAMIC, alias_id=srow.id, target_symbol_id="",
                                      alias_name=nm, ev=ev, extra={"reason": "unresolved_import", "is_type_only": bool(is_type_only)})
                    st.aliases_emitted += 1
                    yield ("alias", arow)
                continue

            if ad.is_export(ev.type):
                # JS/TS explicit exports or Python __all__ manipulation
                names = _parse_export_like(st, ev)
                if not names:
                    names = [(_extract_name_token(st, ev) or "<export>")]
                for ename in names:
                    srow = _symbol_row(cfg, st, st.scope_stack[-1].id, ename, SymbolKind.EXPORT,
                                       visibility="public", is_dynamic=False, ev=ev, extra={})
                    st.symbols_emitted += 1
                    yield ("symbol", srow)
                    # Re-export to existing symbol in this scope if present, else dynamic
                    tgt = st.sym_index.get((st.scope_stack[-1].id, ename), "")
                    kind = AliasKind.REEXPORT if tgt else AliasKind.DYNAMIC
                    if kind != AliasKind.DYNAMIC:
                        st.had_precise = True
                    arow = _alias_row(cfg, st, kind, alias_id=srow.id, target_symbol_id=tgt,
                                      alias_name=ename, ev=ev, extra={"reason": "export_binding"})
                    st.aliases_emitted += 1
                    yield ("alias", arow)
                continue

    # Close any dangling scopes (synthetic)
    while st.scope_stack:
        st.scope_stack.pop()

    # Baseline-only warning (module only)
    if st.symbols_emitted == 0:
        try:
            sink.emit(Anomaly(
                path=fm.path, blob_sha=fm.blob_sha, kind=AnomalyKind.UNKNOWN, severity=Severity.WARN,
                detail="SYMBOLS_BASELINE_ONLY",
            ))
        except Exception:
            pass


# ==============================================================================
# Emit helpers
# ==============================================================================

def _symbol_row(
    cfg: SymbolsConfig,
    st: _BuildState,
    scope_id: str,
    name: str,
    kind: SymbolKind,
    *,
    visibility: str,
    is_dynamic: bool,
    ev: CstEvent,
    extra: Dict,
) -> SymbolRow:
    fm, info = st.file, st.driver
    prov = SymProvenance(
        path=fm.path,
        blob_sha=fm.blob_sha,
        lang=fm.lang,
        grammar_sha=(info.grammar_sha if info else ""),
        run_id=fm.run_id,
        config_hash=fm.config_hash,
        byte_start=ev.byte_start,
        byte_end=ev.byte_end,
        line_start=ev.line_start,
        line_end=ev.line_end,
    )
    sid = _stable_id(cfg.id_salt, "symbol", fm.path, fm.blob_sha or "", scope_id, name, kind.value, str(ev.byte_start))
    row = SymbolRow(
        id=sid,
        scope_id=scope_id,
        name=name[:256],
        kind=kind,
        visibility=visibility,
        is_dynamic=bool(is_dynamic),
        path=fm.path,
        lang=fm.lang,
        attrs_json=_compact(extra or {}),
        prov=prov,
    )
    return row


def _alias_row(
    cfg: SymbolsConfig,
    st: _BuildState,
    alias_kind: AliasKind,
    *,
    alias_id: str,
    target_symbol_id: str,
    alias_name: str,
    ev: CstEvent,
    extra: Dict,
) -> AliasRow:
    fm, info = st.file, st.driver
    prov = SymProvenance(
        path=fm.path,
        blob_sha=fm.blob_sha,
        lang=fm.lang,
        grammar_sha=(info.grammar_sha if info else ""),
        run_id=fm.run_id,
        config_hash=fm.config_hash,
        byte_start=ev.byte_start,
        byte_end=ev.byte_end,
        line_start=ev.line_start,
        line_end=ev.line_end,
    )
    aid = _stable_id(cfg.id_salt, "alias", fm.path, fm.blob_sha or "", alias_kind.value, alias_id, target_symbol_id, alias_name, str(ev.byte_start))
    return AliasRow(
        id=aid,
        alias_kind=alias_kind,
        alias_id=alias_id,
        target_symbol_id=target_symbol_id,
        alias_name=alias_name[:256],
        path=fm.path,
        lang=fm.lang,
        attrs_json=_compact(extra or {}),
        prov=prov,
    )


def _visibility_from_name(name: str) -> str:
    # Python: underscore prefix → private; JS: leading underscore common; otherwise public
    if name.startswith("_"):
        return "private"
    return "public"


def _extract_name_token(st: _BuildState, ev: CstEvent) -> Optional[str]:
    """
    Best-effort: for declaration nodes whose name token is typically the first identifier
    inside the node span. We sample a tiny slice and look for a sane identifier prefix.
    """
    return _safe_token_text(st.file, ev)


def _safe_token_text(fm: FileMeta, ev: CstEvent) -> Optional[str]:
    try:
        if ev.byte_end <= ev.byte_start:
            return None
        size = ev.byte_end - ev.byte_start
        if size > 1024:  # we only sniff small spans as "name" tokens
            return None
        with open(fm.real_path, "rb") as f:
            f.seek(ev.byte_start)
            b = f.read(size)
        txt = b.decode(fm.encoding or "utf-8", errors="replace").strip()
        if not txt or len(txt) > 256:
            return None
        # conservative identifier heuristic
        if not (txt[0].isalpha() or txt[0] in "_$"):
            return None
        for ch in txt[1:]:
            if not (ch.isalnum() or ch in "_$."):
                return None
        # avoid pure numbers
        if txt.replace("_", "").isdigit():
            return None
        return txt
    except Exception:
        return None


def _scope_id(cfg: SymbolsConfig, st: _BuildState, kind: SymbolKind, name: str, byte_start: int) -> str:
    fm = st.file
    parent = st.scope_stack[-1].id if st.scope_stack else ""
    return _stable_id(cfg.id_salt, "scope", fm.path, fm.blob_sha or "", parent, kind.value, name, str(byte_start))


def _yield_decl_and_push(st: _BuildState, cfg: SymbolsConfig, sink: AnomalySink, ev: CstEvent, name: str, kind: SymbolKind, scope_id: str) -> Optional[SymbolRow]:
    if len(st.scope_stack) >= cfg.max_scope_depth:
        sink.emit(Anomaly(
            path=st.file.path, blob_sha=st.file.blob_sha, kind=AnomalyKind.MEMORY_LIMIT, severity=Severity.ERROR,
            detail="scope-depth-exceeded", span=(ev.byte_start, ev.byte_end),
        ))
        return None
    parent = st.scope_stack[-1].id if st.scope_stack else None
    # Emit the declaration symbol into parent scope (defines edge is handled by normalize; here we only manage bindings)
    srow = _symbol_row(cfg, st, parent or _stable_id(cfg.id_salt, "root", st.file.path, st.file.blob_sha or ""), name, kind,
                       visibility=_visibility_from_name(name), is_dynamic=False, ev=ev, extra={"declares_scope": True})
    # Push the scope
    st.scope_stack.append(_Scope(id=scope_id, kind=kind, name=name, byte_start=ev.byte_start, parent=parent))
    return srow


# ==============================================================================
# Span parsing helpers for imports/exports
# ==============================================================================

def _synthetic_ev() -> CstEvent:
    # minimal synthetic event for module-level declarations
    return CstEvent(kind=CstEventKind.EXIT, type="__synthetic__", byte_start=0, byte_end=0, line_start=1, line_end=1)

def _read_span_text(fm: FileMeta, ev: CstEvent, max_bytes: int = 4096) -> str:
    try:
        n = min(max_bytes, max(0, ev.byte_end - ev.byte_start))
        if n <= 0:
            return ""
        with open(fm.real_path, "rb") as f:
            f.seek(ev.byte_start)
            b = f.read(n)
        return b.decode(fm.encoding or "utf-8", errors="replace")
    except Exception:
        return ""


def _parse_import_like(st: _BuildState, ev: CstEvent) -> Tuple[List[str], bool]:
    """Return (names, is_type_only) for a JS/TS import declaration or Python import.
    Conservative: extract identifiers after 'import' and inside braces; detect 'import type'.
    """
    txt = _read_span_text(st.file, ev)
    if not txt:
        return ([], False)
    s = txt.strip()
    is_type_only = ("import type" in s) or ("type {" in s or s.startswith("type "))
    names: List[str] = []
    # import X from '...'
    # import {A as B, C} from '...'
    # import * as ns from '...'
    try:
        # crude brace extraction
        if "* as" in s:
            parts = s.split("* as", 1)[1].strip().split()
            if parts:
                names.append(parts[0].strip().strip(",;"))
        if "{" in s and "}" in s:
            inside = s.split("{", 1)[1].split("}", 1)[0]
            for seg in inside.split(","):
                seg = seg.strip()
                if not seg:
                    continue
                if " as " in seg:
                    alias = seg.split(" as ", 1)[1].strip()
                    names.append(alias)
                else:
                    names.append(seg)
        else:
            # fallback: first identifier after 'import'
            after = s.split("import", 1)[1].strip()
            tok = after.split()[0] if after else ""
            tok = tok.strip().strip(",{}*;")
            if tok and tok not in {"from", "type"}:
                names.append(tok)
    except Exception:
        pass
    # Python 'import X as Y' / 'from m import A as B'
    if st.file.lang == Language.PY and not names:
        try:
            if " import " in s:
                part = s.split(" import ", 1)[1]
                for seg in part.split(","):
                    seg = seg.strip()
                    if not seg:
                        continue
                    if " as " in seg:
                        names.append(seg.split(" as ", 1)[1].strip())
                    else:
                        names.append(seg.split()[0].strip())
        except Exception:
            pass
    # de-dupe and sanitize
    out = []
    for nm in names:
        nm = nm.strip()
        if nm and nm not in out:
            out.append(nm)
    return (out, is_type_only)


def _parse_export_like(st: _BuildState, ev: CstEvent) -> List[str]:
    txt = _read_span_text(st.file, ev)
    if not txt:
        return []
    s = txt.strip()
    names: List[str] = []
    try:
        if s.startswith("export "):
            if "{" in s and "}" in s:
                inside = s.split("{", 1)[1].split("}", 1)[0]
                for seg in inside.split(","):
                    seg = seg.strip()
                    if not seg:
                        continue
                    if " as " in seg:
                        alias = seg.split(" as ", 1)[1].strip()
                        names.append(alias)
                    else:
                        names.append(seg)
            elif s.startswith("export default"):
                names.append("default")
            else:
                # export const X = ...
                toks = s.split()
                for i, t in enumerate(toks):
                    if t in {"const", "let", "var", "function", "class"} and i + 1 < len(toks):
                        names.append(toks[i + 1].strip().strip("{}();,"))
                        break
    except Exception:
        pass
    # Python __all__ = ["A", "B"]
    if st.file.lang == Language.PY and not names:
        if "__all__" in s and ("[" in s or "(" in s):
            body = s.split("=", 1)[1] if "=" in s else s
            for frag in body.replace("[", " ").replace("]", " ").replace("(", " ").replace(")", " ").split(","):
                frag = frag.strip().strip("'\"")
                if frag:
                    names.append(frag)
    # de-dupe
    out: List[str] = []
    for nm in names:
        nm = nm.strip()
        if nm and nm not in out:
            out.append(nm)
    return out
