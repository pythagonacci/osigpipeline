# src/provis/ucg/effects.py
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum
from typing import Dict, Iterable, Iterator, List, Optional, Tuple

from .discovery import FileMeta, Language, Anomaly, AnomalyKind, AnomalySink, Severity
from .parser_registry import CstEvent, CstEventKind, DriverInfo
from .provenance import ProvenanceV2, build_provenance_from_event


# ==============================================================================
# Row model
# ==============================================================================

class EffectKind(str, Enum):
    DECORATOR = "decorator"          # @router.post, @login_required
    CALL = "call"                    # f(...), obj.method(...)
    STRING_LITERAL = "string_literal"
    SQL_LIKE = "sql_like"            # SELECT/INSERT/etc. (rough heuristic)
    ROUTE_LIKE = "route_like"        # "/users/:id", "/api/v1/orders/{id}"
    ENV_LOOKUP = "env_lookup"        # os.getenv, process.env.X
    THROW_LIKE = "throw_like"        # raise/throw
    ANNOTATION = "annotation"        # type annotations / attributes
    UNKNOWN = "unknown_effect"


@dataclass(frozen=True)
class EffectRow:
    id: str
    kind: EffectKind
    carrier: str        # normalized handle, e.g. "router.post", "app.get", "Session.execute", "process.env"
    args_json: str      # compact JSON snapshot of visible literal args (strings/numbers) if any
    path: str
    lang: Language
    attrs_json: str     # extra hints {"callee_type":"member|identifier", ...}
    prov: ProvenanceV2


# ==============================================================================
# Config
# ==============================================================================

@dataclass(frozen=True)
class EffectsConfig:
    id_salt: str = "effects-v1"
    max_literal_len: int = 4096
    capture_string_literals: bool = True
    # Simple SQL / Route heuristics
    enable_sql_heuristic: bool = True
    enable_route_heuristic: bool = True


def _stable_id(*parts: str) -> str:
    h = hashlib.blake2b(digest_size=20)
    for p in parts:
        h.update(b"\x1f")
        h.update(p.encode("utf-8", "ignore"))
    return h.hexdigest()


def _compact(d: dict) -> str:
    return json.dumps(d, separators=(",", ":"), sort_keys=True)


# ==============================================================================
# Builders
# ==============================================================================

def build_effects(fm: FileMeta, info: Optional[DriverInfo], events: List[CstEvent], sink: AnomalySink, cfg: Optional[EffectsConfig] = None) -> Iterator[Tuple[str, EffectRow]]:
    """
    Streaming, conservative extraction of "effect carriers":
      - decorators, call-shapes, env lookups, string literals, sql/route hints, throw/raise
    Emits ("effect", EffectRow).
    """
    cfg = cfg or EffectsConfig()

    if not events:
        return

    lang = fm.lang
    # Tiny sliding window to recognize member calls and argument literals
    token_window: List[CstEvent] = []         # last ~16 tokens near a call/decorator
    MAX_WIN = 16

    # Call/Decorator assembly state
    # When we see a callee (identifier or member), we cache it; when we see a following "("
    # (or a decorator ENTER/EXIT), we emit a CALL/DECORATOR effect with captured string args in window.
    pending_callee: Optional[Tuple[str, CstEvent]] = None  # (carrier, at_event)
    expecting_call_paren: bool = False

    # simple per-file stats for WARNs
    stats = {"total": 0, "t0_or_t1": False}

    for ev in events:
        # Maintain a token window for heuristics
        if ev.kind == CstEventKind.TOKEN:
            token_window.append(ev)
            if len(token_window) > MAX_WIN:
                token_window.pop(0)

        # Language-specific cues
        if lang == Language.PY:
            for item in _py_effects_step(ev, fm, info, token_window, cfg, sink,
                                         state=(lambda: (pending_callee, expecting_call_paren),
                                                lambda a, b: (globals().__setitem__("_pc", a), globals().__setitem__("_ecp", b))),
                                         stats=stats):
                yield item
            # sync back quick state (avoid capturing by ref across yields)
            if "_pc" in globals(): pending_callee = globals().pop("_pc")
            if "_ecp" in globals(): expecting_call_paren = globals().pop("_ecp")
        else:
            for item in _js_effects_step(ev, fm, info, token_window, cfg, sink,
                                         state=(lambda: (pending_callee, expecting_call_paren),
                                                lambda a, b: (globals().__setitem__("_pc", a), globals().__setitem__("_ecp", b))),
                                         stats=stats):
                yield item
            if "_pc" in globals(): pending_callee = globals().pop("_pc")
            if "_ecp" in globals(): expecting_call_paren = globals().pop("_ecp")

        # Generic throw/raise detection (EXIT makes spans sane)
        if ev.kind == CstEventKind.EXIT and _is_throw_like(lang, ev.type):
            carrier = "raise" if lang == Language.PY else "throw"
            row = _mk_effect(cfg, fm, info, EffectKind.THROW_LIKE, carrier, {}, ev, {"node_type": ev.type, "tier": 0})
            stats["total"] += 1; stats["t0_or_t1"] = True
            yield ("effect", row)

        # Capture string literals (as standalone carriers) to help SCM/Step 3 normalize paths/SQL
        if cfg.capture_string_literals and ev.kind == CstEventKind.TOKEN and _looks_string_token(lang, ev.type):
            lit = _safe_literal(fm, ev, max_len=cfg.max_literal_len)
            if lit:
                attrs = {"token_type": ev.type, "tier": 2, "baseline": True}
                ek = EffectKind.STRING_LITERAL
                if cfg.enable_sql_heuristic and _looks_sql(lit):
                    ek = EffectKind.SQL_LIKE
                elif cfg.enable_route_heuristic and _looks_route(lit):
                    ek = EffectKind.ROUTE_LIKE
                row = _mk_effect(cfg, fm, info, ek, "__string__", {"value": lit}, ev, attrs)
                stats["total"] += 1
                yield ("effect", row)

    # Emit WARN if only Tier-2 produced
    try:
        if stats["total"] > 0 and not stats["t0_or_t1"]:
            sink.emit(Anomaly(path=fm.path, blob_sha=fm.blob_sha, kind=AnomalyKind.UNKNOWN, severity=Severity.WARN, detail="EFFECTS_TIER2_ONLY"))
    except Exception:
        pass


# ==============================================================================
# Python effects
# ==============================================================================

def _py_effects_step(
    ev: CstEvent,
    fm: FileMeta,
    info: Optional[DriverInfo],
    token_window: List[CstEvent],
    cfg: EffectsConfig,
    sink: AnomalySink,
    state: Tuple[callable, callable],  # (get_state, set_state)
    stats: Dict,
) -> Iterator[Tuple[str, EffectRow]]:
    get_state, set_state = state
    pending_callee, expecting_call_paren = get_state()

    # Decorators are often explicit nodes (e.g., "Decorator")
    if ev.kind == CstEventKind.EXIT and ev.type in {"Decorator", "decorator"}:
        carrier = _qualified_from_window(fm, token_window)
        if carrier:
            row = _mk_effect(cfg, fm, info, EffectKind.DECORATOR, carrier, _args_from_window(fm, token_window), ev, {"lang": "py", "tier": 0})
            stats["total"] += 1; stats["t0_or_t1"] = True
            yield ("effect", row)
        return

    # Function/Call: libcst/ast typically emits "Call" node with child "(" tokens; we do a simpler heuristic:
    if ev.kind == CstEventKind.TOKEN and ev.type in {"Name", "identifier"}:
        # cache identifier as potential callee; if we later see "(" we emit a CALL
        name = _safe_ident(fm, ev)
        if name:
            pending_callee = name, ev
            expecting_call_paren = True
        set_state(pending_callee, expecting_call_paren)
        return

    if expecting_call_paren and ev.kind == CstEventKind.TOKEN and ev.type in {"(", "l_paren"}:
        # Build carrier from token window (allow member like obj.method)
        carrier = _qualified_from_window(fm, token_window)
        if carrier:
            kind = EffectKind.CALL
            attrs = {"callee_type": "identifier"}
            # Special env lookups
            if carrier in {"os.getenv", "os.environ.get"}:
                kind = EffectKind.ENV_LOOKUP
                attrs["tier"] = 0
            row = _mk_effect(cfg, fm, info, kind, carrier, _args_from_window(fm, token_window), ev, attrs)
            stats["total"] += 1; stats["t0_or_t1"] = True
            yield ("effect", row)
        pending_callee, expecting_call_paren = None, False
        set_state(pending_callee, expecting_call_paren)
        return

    # Process env lookups via attribute access tokens (os . environ . get)
    if ev.kind == CstEventKind.TOKEN and ev.type == "Name":
        q = _qualified_from_window(fm, token_window)
        if q and q.startswith("os.environ"):
            row = _mk_effect(cfg, fm, info, EffectKind.ENV_LOOKUP, "os.environ", {}, ev, {"tier": 1})
            stats["total"] += 1; stats["t0_or_t1"] = True
            yield ("effect", row)


# ==============================================================================
# JS/TS/JSX/TSX effects
# ==============================================================================

def _js_effects_step(
    ev: CstEvent,
    fm: FileMeta,
    info: Optional[DriverInfo],
    token_window: List[CstEvent],
    cfg: EffectsConfig,
    sink: AnomalySink,
    state: Tuple[callable, callable],
    stats: Dict,
) -> Iterator[Tuple[str, EffectRow]]:
    get_state, set_state = state
    pending_callee, expecting_call_paren = get_state()

    # Decorators in TS/JS (experimental): often show up as "decorator" nodes around class/method
    if ev.kind == CstEventKind.EXIT and ev.type in {"decorator", "legacy_decorator"}:
        carrier = _qualified_from_window(fm, token_window)
        if carrier:
            # Angular decorators Tier-0
            attrs = {"lang": "js", "tier": 0}
            row = _mk_effect(cfg, fm, info, EffectKind.DECORATOR, carrier, _args_from_window(fm, token_window), ev, attrs)
            stats["total"] += 1; stats["t0_or_t1"] = True
            yield ("effect", row)
        return

    if ev.kind == CstEventKind.TOKEN and ev.type in {"identifier", "shorthand_property_identifier", "property_identifier"}:
        name = _safe_ident(fm, ev)
        if name:
            pending_callee = name, ev
            expecting_call_paren = True
        set_state(pending_callee, expecting_call_paren)
        return

    if expecting_call_paren and ev.kind == CstEventKind.TOKEN and ev.type in {"(", "l_paren"}:
        carrier = _qualified_from_window(fm, token_window)
        if carrier:
            kind = EffectKind.CALL
            attrs = {"callee_type": "identifier"}
            # env
            if carrier.startswith("process.env"):
                kind = EffectKind.ENV_LOOKUP
                carrier = "process.env"
                attrs["tier"] = 0
            # Router arrays / HttpClient recognizers (Tier-0/1)
            if carrier.endswith("RouterModule.forRoot") or carrier.endswith("RouterModule.forChild"):
                attrs["tier"] = 0
            if ".get" in carrier or ".post" in carrier or carrier.endswith("fetch") or "HttpClient." in carrier:
                # exact HTTP-like call
                attrs.setdefault("tier", 0)
            row = _mk_effect(cfg, fm, info, kind, carrier, _args_from_window(fm, token_window), ev, attrs)
            stats["total"] += 1; stats["t0_or_t1"] = True
            yield ("effect", row)
        pending_callee, expecting_call_paren = None, False
        set_state(pending_callee, expecting_call_paren)
        return


# ==============================================================================
# Heuristics & helpers
# ==============================================================================

def _looks_string_token(lang: Language, token_type: str) -> bool:
    if lang == Language.PY:
        return token_type in {"string", "fstring", "String", "STRING"}
    return token_type in {"string_fragment", "string", "template_string", "template_substitution"}


def _safe_literal(fm: FileMeta, ev: CstEvent, *, max_len: int) -> Optional[str]:
    try:
        if ev.byte_end <= ev.byte_start or ev.byte_end - ev.byte_start > max_len:
            return None
        with open(fm.real_path, "rb") as f:
            f.seek(ev.byte_start); b = f.read(ev.byte_end - ev.byte_start)
        s = b.decode(fm.encoding or "utf-8", errors="replace")
        # trim quotes conservatively
        s = s.strip()
        if not s:
            return None
        return s
    except Exception:
        return None


def _safe_ident(fm: FileMeta, ev: CstEvent) -> Optional[str]:
    try:
        if ev.byte_end <= ev.byte_start or (ev.byte_end - ev.byte_start) > 256:
            return None
        with open(fm.real_path, "rb") as f:
            f.seek(ev.byte_start); b = f.read(ev.byte_end - ev.byte_start)
        t = b.decode(fm.encoding or "utf-8", errors="replace").strip()
        if not t:
            return None
        if not (t[0].isalpha() or t[0] in "_$"):
            return None
        for ch in t[1:]:
            if not (ch.isalnum() or ch in "_$"):
                return None
        return t
    except Exception:
        return None


def _qualified_from_window(fm: FileMeta, win: List[CstEvent]) -> Optional[str]:
    """
    Build a simple qualified name from recent tokens: obj . prop . method
    """
    parts: List[str] = []
    for ev in reversed(win):
        if ev.kind != CstEventKind.TOKEN:
            continue
        tok = _safe_ident(fm, ev)
        if tok:
            parts.insert(0, tok)
        elif ev.type in {".", "::"}:
            continue
        else:
            break
        if len(parts) >= 4:  # cap
            break
    return ".".join(parts) if parts else None


def _args_from_window(fm: FileMeta, win: List[CstEvent]) -> Dict:
    """
    Best-effort: collect up to a few recent string literals as args.
    """
    vals: List[str] = []
    for ev in reversed(win):
        if ev.kind != CstEventKind.TOKEN:
            continue
        if _looks_string_token(fm.lang, ev.type):
            lit = _safe_literal(fm, ev, max_len=512)
            if lit:
                vals.insert(0, lit)
        if len(vals) >= 4:
            break
    return {"literals": vals} if vals else {}


def _looks_sql(s: str) -> bool:
    S = s.strip().lower()
    # quick cheap check
    return any(S.startswith(p) for p in ("select ", "insert ", "update ", "delete ", "with ")) or " join " in S


def _looks_route(s: str) -> bool:
    # crude but effective: initial slash + braces/params
    t = s.strip().strip("'\"")
    if not t.startswith("/"):
        return False
    return any(ch in t for ch in "{}:") or t.count("/") >= 2


def _is_throw_like(lang: Language, node_type: str) -> bool:
    if lang == Language.PY:
        return node_type in {"Raise", "raise_statement"}
    return node_type in {"throw_statement", "throw"}


def _mk_effect(
    cfg: EffectsConfig,
    fm: FileMeta,
    info: Optional[DriverInfo],
    kind: EffectKind,
    carrier: str,
    args: Dict,
    ev: CstEvent,
    attrs: Dict,
) -> EffectRow:
    prov = build_provenance_from_event(fm, info, ev)
    eid = _stable_id(cfg.id_salt, "effect", fm.path, fm.blob_sha or "", kind.value, carrier, str(ev.byte_start))
    return EffectRow(
        id=eid,
        kind=kind,
        carrier=carrier[:256],
        args_json=_compact(args or {}),
        path=fm.path,
        lang=fm.lang,
        attrs_json=_compact(attrs or {}),
        prov=prov,
    )
