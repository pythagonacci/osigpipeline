# src/provis/ucg/ts_driver.py
from __future__ import annotations

import hashlib
import importlib
import time
from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional, Tuple

from .discovery import FileMeta, Language
from .parser_registry import (
    CstEvent,
    CstEventKind,
    DriverInfo,
    ParserDriver,
    ParserError,
)

# -----------------------------------------------------------------------------
# Optional deps & grammar loaders
# -----------------------------------------------------------------------------

_TS_IMPORT_ERROR: Optional[Exception] = None
try:
    from tree_sitter import Parser as TSParser  # type: ignore
except Exception as e:  # pragma: no cover
    _TS_IMPORT_ERROR = e
    TSParser = None  # type: ignore


def _load_language(name: str):
    """
    Try to obtain a tree-sitter Language object flexibly:
    1) tree_sitter_languages.get_language(name)
    2) language modules (tree_sitter_javascript / tree_sitter_typescript)
    Returns (language_obj, grammar_name, version_string) or None.
    """
    # 1) Aggregator package
    try:
        tsl = importlib.import_module("tree_sitter_languages")
        get_language = getattr(tsl, "get_language")
        lang_obj = get_language(name)  # e.g., "javascript", "typescript", "tsx"
        version = getattr(tsl, "__version__", "unknown")
        return lang_obj, f"tree-sitter-{name}", version
    except Exception:
        pass

    # 2) Individual grammar wheels
    if name == "javascript":
        try:
            mod = importlib.import_module("tree_sitter_javascript")
            # language() returns a Language object in modern wheels
            lang_obj = getattr(mod, "language")()  # type: ignore[attr-defined]
            version = getattr(mod, "__version__", "unknown")
            return lang_obj, "tree-sitter-javascript", version
        except Exception:
            pass

    if name == "typescript":
        try:
            mod = importlib.import_module("tree_sitter_typescript")
            lang_obj = getattr(mod, "language_typescript")()  # type: ignore[attr-defined]
            version = getattr(mod, "__version__", "unknown")
            return lang_obj, "tree-sitter-typescript", version
        except Exception:
            pass

    if name == "tsx":
        try:
            mod = importlib.import_module("tree_sitter_typescript")
            lang_obj = getattr(mod, "language_tsx")()  # type: ignore[attr-defined]
            version = getattr(mod, "__version__", "unknown")
            return lang_obj, "tree-sitter-tsx", version
        except Exception:
            pass

    if name == "jsx":
        # Many builds don't ship a separate "jsx"—JS grammar usually handles JSX.
        js = _load_language("javascript")
        if js is not None:
            lang_obj, gname, version = js
            return lang_obj, gname + "+jsx", version

    return None


# -----------------------------------------------------------------------------
# Fast byte→line index (with tiny cache)
# -----------------------------------------------------------------------------

@dataclass
class _LineIndex:
    """Compact index of newline byte positions for fast byte→line lookups."""
    nl_positions: List[int]
    total_bytes: int
    _cache: Dict[int, int] = field(default_factory=dict)

    @classmethod
    def build(cls, raw: bytes) -> "_LineIndex":
        nl: List[int] = []
        off = 0
        find = raw.find
        while True:
            p = find(b"\n", off)
            if p == -1:
                break
            nl.append(p)
            off = p + 1
        return cls(nl_positions=nl, total_bytes=len(raw))

    def byte_to_line(self, b: int) -> int:
        """Map a byte offset to a 1-based line number."""
        cached = self._cache.get(b)
        if cached is not None:
            return cached

        if b <= 0:
            line = 1
        elif b >= self.total_bytes:
            line = len(self.nl_positions) + 1
        else:
            # binary search
            lo, hi = 0, len(self.nl_positions)
            while lo < hi:
                mid = (lo + hi) // 2
                if self.nl_positions[mid] < b:
                    lo = mid + 1
                else:
                    hi = mid
            line = lo + 1

        # Simple size-bounded cache to avoid unbounded growth
        if len(self._cache) >= 2048:
            self._cache.clear()
        self._cache[b] = line
        return line


# -----------------------------------------------------------------------------
# JS/TS driver (Tree-sitter)
# -----------------------------------------------------------------------------

class TSTreeSitterDriver(ParserDriver):
    """
    Tree-sitter driver for JavaScript/TypeScript (JS/TS/JSX/TSX).

    Guarantees:
      - Deterministic, streaming traversal with ENTER/TOKEN/EXIT events in source order.
      - Byte-accurate spans from tree-sitter; line numbers via _LineIndex.
      - Partial/error trees are surfaced: events emitted for ERROR/MISSING nodes,
        and a typed ParserError("SYNTAX_ERRORS") is raised post-traversal if any occurred.
      - Lazy initialization so import/setup errors are consistently surfaced via info()/parse.
    """

    # Extra guardrail beyond discovery's size checks
    MAX_FILE_SIZE_BYTES = 100 * 1024 * 1024  # 100 MiB

    def __init__(self, lang: Language) -> None:
        self._lang = lang
        self._init_error: Optional[ParserError] = None
        self._parser: Optional[TSParser] = None  # type: ignore[type-arg]
        self._info: Optional[DriverInfo] = None

        if _TS_IMPORT_ERROR is not None or TSParser is None:
            self._init_error = ParserError(
                code="LIB_DEP_MISSING",
                message="tree_sitter import failed",
                detail=repr(_TS_IMPORT_ERROR),
            )

    # ---- public API -----------------------------------------------------------

    def info(self) -> DriverInfo:
        if self._init_error:
            raise self._init_error
        if self._info is None:
            self._setup_parser()
        return self._info  # type: ignore[return-value]

    def parse(self, file: FileMeta):
        """Parse a file and return a ParseStream."""
        from .parser_registry import ParseStream, DriverInfo
        
        info = self.info()
        start = time.perf_counter()
        
        try:
            events = self.parse_to_events(file)
            elapsed = time.perf_counter() - start
            return ParseStream(file=file, driver=info, events=events, elapsed_s=elapsed, ok=True)
        except Exception as e:
            elapsed = time.perf_counter() - start
            return ParseStream(file=file, driver=info, events=None, elapsed_s=elapsed, ok=False, error=str(e))

    def parse_to_events(self, file: FileMeta) -> Iterator[CstEvent]:
        if self._init_error:
            raise self._init_error
        if self._parser is None or self._info is None:
            self._setup_parser()

        # File guards
        if file.size_bytes > self.MAX_FILE_SIZE_BYTES:
            raise ParserError(
                code="FILE_TOO_LARGE",
                message=f"File exceeds maximum size ({self.MAX_FILE_SIZE_BYTES} bytes)",
                detail=f"File size: {file.size_bytes} bytes",
            )
        if not file.is_text:
            raise ParserError(code="NOT_TEXT", message="File classified as binary by discovery")

        # Read raw bytes; Tree-sitter works directly on bytes.
        try:
            with open(file.real_path, "rb") as fh:
                raw = fh.read()
        except FileNotFoundError as e:
            raise ParserError(code="IO_ERROR", message="File not found", detail=str(e))
        except PermissionError as e:
            raise ParserError(code="PERMISSION_DENIED", message="Permission denied", detail=str(e))
        except OSError as e:
            raise ParserError(code="IO_ERROR", message="Read failed", detail=str(e))

        lidx = _LineIndex.build(raw)

        # Parse
        try:
            tree = self._parser.parse(raw)  # type: ignore[union-attr]
        except Exception as e:
            raise ParserError(code="PARSE_ERROR", message="Tree-sitter parse failed", detail=str(e))

        root = tree.root_node

        error_nodes: List[Tuple[int, int, str]] = []

        # Event emitter
        def emit(n, kind: CstEventKind) -> CstEvent:
            sb = int(getattr(n, "start_byte", 0))
            eb = int(getattr(n, "end_byte", sb))
            if eb < sb:
                eb = sb
            ls = lidx.byte_to_line(sb)
            le = lidx.byte_to_line(eb)
            ntype = getattr(n, "type", None) or "UNKNOWN"

            # Track syntax issues
            # Tree-sitter nodes have .type == "ERROR" for error nodes; "MISSING" for required-missing
            if ntype == "ERROR":
                error_nodes.append((sb, eb, "Parse error in source"))
            elif ntype == "MISSING":
                error_nodes.append((sb, eb, "Missing required syntax"))

            return CstEvent(
                kind=kind,
                type=ntype,
                byte_start=sb,
                byte_end=eb,
                line_start=ls,
                line_end=le if le >= ls else ls,
            )

        # Children accessor (robust) and stable sort
        def children_in_order(n) -> List:
            try:
                count = int(getattr(n, "child_count", 0))
            except Exception:
                count = 0
            if count == 0:
                return []
            out: List = []
            for i in range(count):
                try:
                    ch = n.child(i)
                    if ch is not None:
                        out.append(ch)
                except Exception:
                    continue
            # Stable sort by (start_byte, end_byte, id) to break ties deterministically
            out.sort(key=lambda x: (int(getattr(x, "start_byte", 0)),
                                    int(getattr(x, "end_byte", 0)),
                                    id(x)))
            return out

        # ---------------------------------------------------------------------
        # Balanced traversal via TreeCursor (guarantees ENTER/EXIT for all nodes)
        # ---------------------------------------------------------------------

        def is_leaf(n) -> bool:
            try:
                return int(getattr(n, "child_count", 0)) == 0
            except Exception:
                return True

        def maybe_preemit_decl_name(n):
            """
            For declarations, emit the identifier/property_identifier token early
            so the normalizer can capture names before we dive into params/body.
            (The identifier will still later emit its own ENTER/TOKEN/EXIT as a leaf.)
            """
            ntype = getattr(n, "type", None)
            if ntype in (
                "function_declaration",
                "function_expression",
                "method_definition",
                "class_declaration",
                "arrow_function",
            ):
                try:
                    cc = int(getattr(n, "child_count", 0))
                except Exception:
                    cc = 0
                for i in range(cc):
                    try:
                        ch = n.child(i)
                        if ch is None:
                            continue
                        ctype = getattr(ch, "type", None)
                        if ctype in ("identifier", "property_identifier"):
                            # Single token emission (no ENTER/EXIT wrapper) as before
                            yield emit(ch, CstEventKind.TOKEN)
                            break
                    except Exception:
                        continue

        cursor = root.walk()

        while True:
            node = cursor.node

            # ENTER the current node
            yield emit(node, CstEventKind.ENTER)

            # Optional: name token pre-emit for decls (kept for backward compat)
            for tok in maybe_preemit_decl_name(node):
                yield tok

            # If leaf, also emit a TOKEN now
            if is_leaf(node):
                yield emit(node, CstEventKind.TOKEN)

            # If we can go down, do so (post-order EXIT will be handled on unwind)
            if cursor.goto_first_child():
                continue

            # No children (or already finished children): EXIT this node, then
            # walk to next sibling; if none, keep bubbling up emitting EXITs
            yield emit(node, CstEventKind.EXIT)

            while True:
                if cursor.goto_next_sibling():
                    # Next sibling will ENTER on the next loop iteration
                    break
                if not cursor.goto_parent():
                    # We just finished the root. Surface syntax issues (if any),
                    # then end the generator.
                    if error_nodes:
                        details = "; ".join(
                            [f"bytes {s}-{e}: {msg}" for s, e, msg in error_nodes[:5]]
                        )
                        if len(error_nodes) > 5:
                            details += f" (and {len(error_nodes) - 5} more)"
                        first = error_nodes[0]
                        raise ParserError(
                            code="SYNTAX_ERRORS",
                            message=f"Found {len(error_nodes)} syntax errors in {file.path}",
                            detail=details,
                            byte_start=first[0],
                            byte_end=first[1],
                        )
                    return  # done

                # We climbed up because there was no next sibling at this level:
                # that means we just finished the parent's last child → EXIT parent.
                yield emit(cursor.node, CstEventKind.EXIT)

    # ---- internals ------------------------------------------------------------

    def _setup_parser(self) -> None:
        """Lazy initialization of parser and driver info."""
        # Grammar selection with smart fallbacks
        primary_name = self._select_grammar_name(self._lang)
        loaded = self._load_language_with_fallbacks(primary_name, self._lang)
        if loaded is None:
            raise ParserError(
                code="GRAMMAR_LOAD_FAILED",
                message=f"Could not load grammar: {primary_name}",
                detail="Tried aggregator (tree_sitter_languages) and individual wheels; none matched"
            )

        lang_obj, grammar_name, version = loaded
        # Some wheels expose grammars as PyCapsule; wrap into tree_sitter.Language if needed.
        try:
            import tree_sitter as _ts  # type: ignore
            def _is_language_like(obj) -> bool:
                return hasattr(obj, "copy") and hasattr(obj, "query") and hasattr(obj, "name")
            if not _is_language_like(lang_obj):
                try:
                    lang_obj = _ts.Language(lang_obj)  # type: ignore[arg-type]
                except Exception:
                    # keep original; assignment path below will fail clearly if incompatible
                    pass
        except Exception:
            # If tree_sitter import fails here, we'll surface during set_language below
            pass

        grammar_sha = hashlib.blake2b(
            f"{grammar_name}:{version}".encode("utf-8"), digest_size=20
        ).hexdigest()

        self._parser = TSParser()  # type: ignore[call-arg]
        try:
            # Support both modern and legacy APIs:
            #  - Modern: set_language(Language)
            #  - Legacy: parser.language = Language
            set_lang = getattr(self._parser, "set_language", None)
            if callable(set_lang):
                self._parser.set_language(lang_obj)  # type: ignore[attr-defined]
            elif hasattr(self._parser, "language"):
                try:
                    setattr(self._parser, "language", lang_obj)
                except Exception as e:
                    raise ParserError(
                        code="PARSER_INIT_FAILED",
                        message="Failed to set Tree-sitter language via language property",
                        detail=str(e),
                    )
            else:
                raise ParserError(
                    code="PARSER_INIT_FAILED",
                    message="Tree-sitter Parser missing set_language and language attribute",
                    detail=f"Parser attrs: {dir(self._parser)}",
                )
        except ParserError:
            self._parser = None
            raise
        except Exception as e:
            self._parser = None
            raise ParserError(
                code="PARSER_INIT_FAILED",
                message="Failed to configure Tree-sitter language",
                detail=str(e),
            )

        # Smoke test: parse an empty buffer to ensure language is accepted
        try:
            self._parser.parse(b"")
        except Exception as e:
            self._parser = None
            raise ParserError(
                code="PARSER_INIT_FAILED",
                message="Tree-sitter parser smoke test failed",
                detail=str(e),
            )

        self._info = DriverInfo(
            language=self._lang,
            grammar_name=grammar_name,
            grammar_sha=grammar_sha,
            version=version,
        )

    @staticmethod
    def _select_grammar_name(lang: Language) -> str:
        grammar_map = {
            Language.JS: "javascript",
            Language.TS: "typescript",
            Language.TSX: "tsx",
            Language.JSX: "javascript",  # JSX uses JS grammar; label adjusted in fallback
        }
        return grammar_map.get(lang, "javascript")

    @staticmethod
    def _load_language_with_fallbacks(primary_name: str, lang: Language):
        # Try primary grammar first
        res = _load_language(primary_name)
        if res is not None:
            return res

        # JSX fallback to JS grammar
        if lang == Language.JSX:
            res = _load_language("javascript")
            if res is not None:
                lang_obj, gname, version = res
                return lang_obj, gname + "+jsx", version

        # TSX fallback to TS grammar
        if lang == Language.TSX:
            res = _load_language("typescript")
            if res is not None:
                lang_obj, gname, version = res
                return lang_obj, gname + "+tsx", version

        return None