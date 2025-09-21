# src/provis/ucg/cfg.py
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Iterator, List, Optional, Tuple

from .discovery import Anomaly, AnomalyKind, AnomalySink, FileMeta, Language, Severity
from .parser_registry import CstEvent, CstEventKind, DriverInfo, ParseStream


# ==============================================================================
# CFG schema (rows)
# ==============================================================================

class BlockKind(str, Enum):
    ENTRY = "entry"
    PREDICATE = "predicate"   # condition node (if/while/for condition)
    BODY = "body"
    HANDLER = "handler"       # except/catch/finally
    EXIT = "exit"


class CfgEdgeKind(str, Enum):
    NEXT = "next"
    TRUE = "true"
    FALSE = "false"
    EXCEPTION = "exception"
    RETURN = "return"


@dataclass(frozen=True)
class CfgProvenance:
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
class BlockRow:
    id: str
    func_id: str
    kind: BlockKind
    index: int                      # sequence within function (stable)
    path: str
    lang: Language
    attrs_json: str                 # {"node_type": "...", "label": "..."} etc.
    prov: CfgProvenance


@dataclass(frozen=True)
class CfgEdgeRow:
    id: str
    func_id: str
    kind: CfgEdgeKind
    src_block_id: str
    dst_block_id: str
    path: str
    lang: Language
    attrs_json: str
    prov: CfgProvenance


# ==============================================================================
# Config
# ==============================================================================

@dataclass(frozen=True)
class CfgConfig:
    id_salt: str = "cfg-v1"
    max_blocks_per_func: int = 20000  # guard against pathological code
    # Treat these node types as “predicate producers” (language adapters add to these sets)
    enable_try_edges: bool = True


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
# Language adapters (identify control constructs from node type strings)
# ==============================================================================

class _Adapter:
    def __init__(self, lang: Language) -> None:
        self.lang = lang
        self._init_sets()

    def _init_sets(self) -> None:
        if self.lang == Language.PY:
            # libcst types
            self.function_nodes = {"FunctionDef", "AsyncFunctionDef", "Lambda"}
            self.if_nodes = {"If"}
            self.while_nodes = {"While"}
            self.for_nodes = {"For"}
            self.try_nodes = {"Try"}
            self.return_nodes = {"Return"}
            self.raise_nodes = {"Raise"}
            self.break_nodes = {"Break"}
            self.continue_nodes = {"Continue"}
            self.switch_nodes = set()  # N/A
            self.catch_nodes = {"ExceptHandler"}  # appears as child types under Try in CST streams
            self.finally_nodes = {"Finally"}
        else:
            # Tree-sitter JS/TS
            self.function_nodes = {"function_declaration", "function_expression", "method_definition", "arrow_function"}
            self.if_nodes = {"if_statement", "conditional_expression"}  # ternary treated as predicate→body fallthrough
            self.while_nodes = {"while_statement", "do_statement"}
            self.for_nodes = {"for_statement", "for_in_statement", "for_of_statement"}
            self.try_nodes = {"try_statement"}
            self.return_nodes = {"return_statement"}
            self.raise_nodes = {"throw_statement"}
            self.break_nodes = {"break_statement"}
            self.continue_nodes = {"continue_statement"}
            self.switch_nodes = {"switch_statement"}
            self.catch_nodes = {"catch_clause"}
            self.finally_nodes = {"finally_clause"}

    # classification
    def is_function(self, t: str) -> bool: return t in self.function_nodes
    def is_if(self, t: str) -> bool: return t in self.if_nodes
    def is_while(self, t: str) -> bool: return t in self.while_nodes
    def is_for(self, t: str) -> bool: return t in self.for_nodes
    def is_try(self, t: str) -> bool: return t in self.try_nodes
    def is_return(self, t: str) -> bool: return t in self.return_nodes
    def is_throw(self, t: str) -> bool: return t in self.raise_nodes
    def is_break(self, t: str) -> bool: return t in self.break_nodes
    def is_continue(self, t: str) -> bool: return t in self.continue_nodes
    def is_switch(self, t: str) -> bool: return t in self.switch_nodes
    def is_catch(self, t: str) -> bool: return t in self.catch_nodes
    def is_finally(self, t: str) -> bool: return t in self.finally_nodes


# ==============================================================================
# Builder core
# ==============================================================================

@dataclass
class _FuncState:
    func_id: str
    entry_id: str
    exit_id: str
    current_block_id: str
    next_index: int
    block_count: int
    # stack of open control constructs: (kind, predicate_block_id, true_target_id?, false_target_id?)
    ctrl_stack: List[Tuple[str, str]] = field(default_factory=list)


class CfgBuilder:
    """
    Streaming CFG builder:
      - Opens a function when function node ENTER is seen, closes it on EXIT.
      - Produces basic blocks (ENTRY, PREDICATE, BODY, HANDLER, EXIT).
      - Produces edges: NEXT/TRUE/FALSE/EXCEPTION/RETURN.
      - Deterministic IDs: based on (file, blob_sha, func start byte, block index).
    """

    def __init__(self, cfg: Optional[CfgConfig] = None) -> None:
        self.cfg = cfg or CfgConfig()

    # -------- public API

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

        def prov(ev: CstEvent) -> CfgProvenance:
            return CfgProvenance(
                path=fm.path, blob_sha=fm.blob_sha, lang=fm.lang,
                grammar_sha=(info.grammar_sha if info else ""),
                run_id=fm.run_id, config_hash=fm.config_hash,
                byte_start=ev.byte_start, byte_end=ev.byte_end,
                line_start=ev.line_start, line_end=ev.line_end,
            )

        def new_block_id(func_id: str, idx: int) -> str:
            return _stable_id(self.cfg.id_salt, "block", fm.path, fm.blob_sha, func_id, str(idx))

        def block_row(func: _FuncState, kind: BlockKind, ev: CstEvent, attrs: Dict) -> BlockRow:
            bid = new_block_id(func.func_id, func.next_index)
            row = BlockRow(
                id=bid,
                func_id=func.func_id,
                kind=kind,
                index=func.next_index,
                path=fm.path,
                lang=fm.lang,
                attrs_json=_compact(attrs),
                prov=prov(ev),
            )
            func.next_index += 1
            func.block_count += 1
            return row

        def edge_row(func: _FuncState, kind: CfgEdgeKind, src: str, dst: str, ev: CstEvent, attrs: Dict) -> CfgEdgeRow:
            eid = _stable_id(self.cfg.id_salt, "edge", fm.path, fm.blob_sha, func.func_id, src, dst, kind.value, str(ev.byte_start))
            return CfgEdgeRow(
                id=eid,
                func_id=func.func_id,
                kind=kind,
                src_block_id=src,
                dst_block_id=dst,
                path=fm.path,
                lang=fm.lang,
                attrs_json=_compact(attrs),
                prov=prov(ev),
            )

        for ev in ps.events:
            # Open a function on ENTER
            if ev.kind == CstEventKind.ENTER and adapter.is_function(ev.type):
                # Function identity: start-based for stability
                func_id = _stable_id(self.cfg.id_salt, "func", fm.path, fm.blob_sha, str(ev.byte_start))
                # Create ENTRY and first BODY
                entry_tmp = _stable_id(self.cfg.id_salt, "entry", fm.path, fm.blob_sha, func_id)
                exit_tmp = _stable_id(self.cfg.id_salt, "exit", fm.path, fm.blob_sha, func_id)
                state = _FuncState(
                    func_id=func_id,
                    entry_id=entry_tmp, exit_id=exit_tmp,
                    current_block_id="", next_index=0, block_count=0,
                )
                # ENTRY block at function start (index 0)
                b_entry = block_row(state, BlockKind.ENTRY, ev, {"type": ev.type})
                yield ("cfg_block", b_entry)
                state.current_block_id = b_entry.id
                func_stack.append(state)
                continue

            # If not inside a function yet, ignore control constructs (global-level CFG not built here)
            if not func_stack:
                continue

            func = func_stack[-1]

            # Guard: too many blocks → abort function
            if func.block_count > self.cfg.max_blocks_per_func:
                sink.emit(Anomaly(
                    path=fm.path, blob_sha=fm.blob_sha, kind=AnomalyKind.MEMORY_LIMIT, severity=Severity.ERROR,
                    detail=f"CFG blocks exceeded limit ({self.cfg.max_blocks_per_func}) for function {func.func_id}",
                    span=(ev.byte_start, ev.byte_end),
                ))
                # synthesize exit and pop function
                b_exit = BlockRow(
                    id=_stable_id(self.cfg.id_salt, "block", fm.path, fm.blob_sha, func.func_id, "exit_overflow"),
                    func_id=func.func_id, kind=BlockKind.EXIT, index=func.next_index,
                    path=fm.path, lang=fm.lang, attrs_json=_compact({"synthetic": "true", "reason": "overflow"}),
                    prov=prov(ev),
                )
                yield ("cfg_block", b_exit)
                yield ("cfg_edge", edge_row(func, CfgEdgeKind.NEXT, func.current_block_id, b_exit.id, ev, {}))
                func_stack.pop()
                continue

            if ev.kind == CstEventKind.ENTER:
                # Branching / loop / try predicates
                if _is_predicate(adapter, ev.type):
                    b_pred = block_row(func, BlockKind.PREDICATE, ev, {"type": ev.type})
                    # connect current → predicate
                    if func.current_block_id != b_pred.id:
                        yield ("cfg_edge", edge_row(func, CfgEdgeKind.NEXT, func.current_block_id, b_pred.id, ev, {}))
                    func.current_block_id = b_pred.id
                    # push control marker (use node type as tag)
                    func.ctrl_stack.append((ev.type, b_pred.id))
                # Return/throw immediately ends current block and connects to EXIT
                elif adapter.is_return(ev.type):
                    b_body = block_row(func, BlockKind.BODY, ev, {"type": ev.type})
                    yield ("cfg_edge", edge_row(func, CfgEdgeKind.NEXT, func.current_block_id, b_body.id, ev, {}))
                    yield ("cfg_block", b_body)
                    # return edge to EXIT
                    b_exit = block_row(func, BlockKind.EXIT, ev, {"type": "exit"})
                    yield ("cfg_block", b_exit)
                    yield ("cfg_edge", edge_row(func, CfgEdgeKind.RETURN, b_body.id, b_exit.id, ev, {}))
                    func.current_block_id = b_exit.id
                elif adapter.is_throw(ev.type):
                    b_body = block_row(func, BlockKind.BODY, ev, {"type": ev.type})
                    yield ("cfg_edge", edge_row(func, CfgEdgeKind.NEXT, func.current_block_id, b_body.id, ev, {}))
                    yield ("cfg_block", b_body)
                    # exception edge to EXIT (we don’t model catch linkage interprocedurally here)
                    b_exit = block_row(func, BlockKind.EXIT, ev, {"type": "exit"})
                    yield ("cfg_block", b_exit)
                    yield ("cfg_edge", edge_row(func, CfgEdgeKind.EXCEPTION, b_body.id, b_exit.id, ev, {}))
                    func.current_block_id = b_exit.id
                else:
                    # Regular statement entry: keep building within current BODY; split on statements if needed.
                    pass

            elif ev.kind == CstEventKind.EXIT:
                # Close function
                if adapter.is_function(ev.type):
                    # ensure EXIT exists
                    b_exit = BlockRow(
                        id=_stable_id(self.cfg.id_salt, "block", fm.path, fm.blob_sha, func.func_id, "exit"),
                        func_id=func.func_id, kind=BlockKind.EXIT, index=func.next_index,
                        path=fm.path, lang=fm.lang, attrs_json=_compact({"type": "exit"}),
                        prov=prov(ev),
                    )
                    yield ("cfg_block", b_exit)
                    if func.current_block_id != b_exit.id:
                        yield ("cfg_edge", edge_row(func, CfgEdgeKind.NEXT, func.current_block_id, b_exit.id, ev, {}))
                    func_stack.pop()
                    continue

                # Resolve predicate exits
                if func.ctrl_stack:
                    top_type, pred_id = func.ctrl_stack[-1]
                    # if we see the end of the control structure, emit TRUE/FALSE edges to synthetic bodies
                    if _matches_close(adapter, top_type, ev.type):
                        func.ctrl_stack.pop()
                        # create two BODY blocks for true/false (or body/else) when applicable
                        if _has_dual_outcomes(adapter, top_type):
                            b_true = BlockRow(
                                id=_stable_id(self.cfg.id_salt, "block", fm.path, fm.blob_sha, func.func_id, f"true@{pred_id}@{ev.byte_end}"),
                                func_id=func.func_id, kind=BlockKind.BODY, index=func.next_index,
                                path=fm.path, lang=fm.lang, attrs_json=_compact({"arm": "true", "of": top_type}),
                                prov=prov(ev),
                            ); func.next_index += 1; func.block_count += 1
                            b_false = BlockRow(
                                id=_stable_id(self.cfg.id_salt, "block", fm.path, fm.blob_sha, func.func_id, f"false@{pred_id}@{ev.byte_end}"),
                                func_id=func.func_id, kind=BlockKind.BODY, index=func.next_index,
                                path=fm.path, lang=fm.lang, attrs_json=_compact({"arm": "false", "of": top_type}),
                                prov=prov(ev),
                            ); func.next_index += 1; func.block_count += 1
                            yield ("cfg_block", b_true); yield ("cfg_block", b_false)
                            yield ("cfg_edge", edge_row(func, CfgEdgeKind.TRUE, pred_id, b_true.id, ev, {}))
                            yield ("cfg_edge", edge_row(func, CfgEdgeKind.FALSE, pred_id, b_false.id, ev, {}))
                            # Continue from merge of arms → create a new BODY and connect both NEXT to it
                            b_merge = BlockRow(
                                id=_stable_id(self.cfg.id_salt, "block", fm.path, fm.blob_sha, func.func_id, f"merge@{ev.byte_end}"),
                                func_id=func.func_id, kind=BlockKind.BODY, index=func.next_index,
                                path=fm.path, lang=fm.lang, attrs_json=_compact({"merge": top_type}),
                                prov=prov(ev),
                            ); func.next_index += 1; func.block_count += 1
                            yield ("cfg_block", b_merge)
                            yield ("cfg_edge", edge_row(func, CfgEdgeKind.NEXT, b_true.id, b_merge.id, ev, {}))
                            yield ("cfg_edge", edge_row(func, CfgEdgeKind.NEXT, b_false.id, b_merge.id, ev, {}))
                            func.current_block_id = b_merge.id
                        else:
                            # Single successor predicate (e.g., while/do) → TRUE to body, FALSE to next
                            b_body = BlockRow(
                                id=_stable_id(self.cfg.id_salt, "block", fm.path, fm.blob_sha, func.func_id, f"loop_body@{pred_id}@{ev.byte_end}"),
                                func_id=func.func_id, kind=BlockKind.BODY, index=func.next_index,
                                path=fm.path, lang=fm.lang, attrs_json=_compact({"arm": "body", "of": top_type}),
                                prov=prov(ev),
                            ); func.next_index += 1; func.block_count += 1
                            b_after = BlockRow(
                                id=_stable_id(self.cfg.id_salt, "block", fm.path, fm.blob_sha, func.func_id, f"after_loop@{ev.byte_end}"),
                                func_id=func.func_id, kind=BlockKind.BODY, index=func.next_index,
                                path=fm.path, lang=fm.lang, attrs_json=_compact({"arm": "after", "of": top_type}),
                                prov=prov(ev),
                            ); func.next_index += 1; func.block_count += 1
                            yield ("cfg_block", b_body); yield ("cfg_block", b_after)
                            yield ("cfg_edge", edge_row(func, CfgEdgeKind.TRUE, pred_id, b_body.id, ev, {}))
                            yield ("cfg_edge", edge_row(func, CfgEdgeKind.FALSE, pred_id, b_after.id, ev, {}))
                            # back edge body → pred (loop)
                            yield ("cfg_edge", edge_row(func, CfgEdgeKind.NEXT, b_body.id, pred_id, ev, {}))
                            func.current_block_id = b_after.id

                # Try/catch/finally coarse modeling
                if self.cfg.enable_try_edges and (_is_try_related(adapter, ev.type)):
                    # create a handler block and exception edges from current
                    b_handler = BlockRow(
                        id=_stable_id(self.cfg.id_salt, "block", fm.path, fm.blob_sha, func.func_id, f"handler@{ev.byte_end}"),
                        func_id=func.func_id, kind=BlockKind.HANDLER, index=func.next_index,
                        path=fm.path, lang=fm.lang, attrs_json=_compact({"type": ev.type}),
                        prov=prov(ev),
                    ); func.next_index += 1; func.block_count += 1
                    yield ("cfg_block", b_handler)
                    yield ("cfg_edge", edge_row(func, CfgEdgeKind.EXCEPTION, func.current_block_id, b_handler.id, ev, {}))
                    # fallthrough after handler
                    b_after = BlockRow(
                        id=_stable_id(self.cfg.id_salt, "block", fm.path, fm.blob_sha, func.func_id, f"after_handler@{ev.byte_end}"),
                        func_id=func.func_id, kind=BlockKind.BODY, index=func.next_index,
                        path=fm.path, lang=fm.lang, attrs_json=_compact({"after": ev.type}),
                        prov=prov(ev),
                    ); func.next_index += 1; func.block_count += 1
                    yield ("cfg_block", b_after)
                    yield ("cfg_edge", edge_row(func, CfgEdgeKind.NEXT, b_handler.id, b_after.id, ev, {}))
                    func.current_block_id = b_after.id

        # If a function never closed (malformed), synthesize an EXIT
        while func_stack:
            func = func_stack.pop()
            syn_ev = CstEvent(kind=CstEventKind.EXIT, type="__synthetic__", byte_start=0, byte_end=0, line_start=1, line_end=1)
            b_exit = BlockRow(
                id=_stable_id(self.cfg.id_salt, "block", fm.path, fm.blob_sha, func.func_id, "exit_synth"),
                func_id=func.func_id, kind=BlockKind.EXIT, index=func.next_index,
                path=fm.path, lang=fm.lang, attrs_json=_compact({"synthetic": "true"}),
                prov=CfgProvenance(
                    path=fm.path, blob_sha=fm.blob_sha, lang=fm.lang,
                    grammar_sha=(info.grammar_sha if info else ""), run_id=fm.run_id,
                    config_hash=fm.config_hash, byte_start=0, byte_end=0, line_start=1, line_end=1,
                ),
            )
            yield ("cfg_block", b_exit)
            yield ("cfg_edge", CfgEdgeRow(
                id=_stable_id(self.cfg.id_salt, "edge", fm.path, fm.blob_sha, func.func_id, func.current_block_id, b_exit.id, "next", "synth"),
                func_id=func.func_id, kind=CfgEdgeKind.NEXT, src_block_id=func.current_block_id, dst_block_id=b_exit.id,
                path=fm.path, lang=fm.lang, attrs_json=_compact({"synthetic": "true"}),
                prov=b_exit.prov,
            ))


# ==============================================================================
# Helpers for adapter interplay
# ==============================================================================

def _is_predicate(adapter: _Adapter, t: str) -> bool:
    return adapter.is_if(t) or adapter.is_while(t) or adapter.is_for(t) or adapter.is_switch(t)

def _has_dual_outcomes(adapter: _Adapter, t: str) -> bool:
    # if/switch → true/false or case/default; while/for → body & after (single predicate result + loop backedge)
    return adapter.is_if(t) or adapter.is_switch(t)

def _matches_close(adapter: _Adapter, open_t: str, close_t: str) -> bool:
    # We don’t get explicit "end_if"; we use EXIT of the same node type
    return open_t == close_t

def _is_try_related(adapter: _Adapter, t: str) -> bool:
    return adapter.is_try(t) or adapter.is_catch(t) or adapter.is_finally(t)


# ==============================================================================
# Public convenience
# ==============================================================================

def build_cfg(ps: ParseStream, sink: AnomalySink, cfg: Optional[CfgConfig] = None) -> Iterator[Tuple[str, object]]:
    builder = CfgBuilder(cfg)
    yield from builder.build(ps, sink)
