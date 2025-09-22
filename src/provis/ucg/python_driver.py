from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from typing import Iterator, List, Optional, Tuple

from .discovery import FileMeta, Language
from .parser_registry import (
    CstEvent,
    CstEventKind,
    DriverInfo,
    ParserDriver,
    ParserError,
)

# Third-party (lossless Python CST)
try:
    import libcst as cst
    from libcst.metadata import CodeRange, PositionProvider, MetadataWrapper
except Exception as e:  # pragma: no cover - exercised in integration
    _LIBCST_IMPORT_ERROR = e
else:
    _LIBCST_IMPORT_ERROR = None


# -----------------------------------------------------------------------------
# Byte offset indexer (O(1) lookups)
# -----------------------------------------------------------------------------

@dataclass
class _ByteOffsetIndexer:
    """
    Maps (1-based line, 0-based character column) → absolute byte offset in the original bytes.

    Precomputes:
      - per-line character→byte maps
      - line_start_bytes (cumulative starting byte offset for each line)
    So lookups are O(1):  start = line_start_bytes[line-1];  offset = start + per_line[col]
    """
    line_char_to_byte: List[List[int]]
    line_start_bytes: List[int]

    @classmethod
    def build(cls, raw_bytes: bytes, encoding: str) -> "_ByteOffsetIndexer":
        lines_bytes = raw_bytes.split(b"\n")  # '\r' (if CRLF) remains in the line payload
        per_line_maps: List[List[int]] = []
        line_start_bytes: List[int] = []

        cumulative = 0
        for idx, lb in enumerate(lines_bytes):
            line_start_bytes.append(cumulative)
            # decode this line to map char indices → byte lengths under the same encoding
            try:
                text = lb.decode(encoding, errors="strict")
            except Exception:
                text = lb.decode(encoding, errors="replace")

            per_char: List[int] = [0]
            if text:
                # Build cumulative byte lengths per character
                append = per_char.append
                total = 0
                for ch in text:
                    try:
                        b = ch.encode(encoding, errors="strict")
                    except Exception:
                        b = ch.encode(encoding, errors="replace")
                    total += len(b)
                    append(total)
            per_line_maps.append(per_char)

            # Advance cumulative: bytes in this line + one byte for '\n' separator (except last line if file ends without newline—OK to over-allocate; we rely on mapping bounds)
            cumulative += len(lb)
            if idx < len(lines_bytes) - 1:
                cumulative += 1  # the '\n'

        return cls(line_char_to_byte=per_line_maps, line_start_bytes=line_start_bytes)

    def to_byte_offset(self, line_1based: int, col_0based: int) -> int:
        # Clamp line to available range
        if line_1based < 1:
            line_1based = 1
        line_index = line_1based - 1
        if line_index >= len(self.line_char_to_byte):
            line_index = len(self.line_char_to_byte) - 1

        per_line = self.line_char_to_byte[line_index]
        if col_0based < 0:
            col_0based = 0
        if col_0based >= len(per_line):
            col_0based = len(per_line) - 1  # clamp to end of line

        return self.line_start_bytes[line_index] + per_line[col_0based]


# -----------------------------------------------------------------------------
# Python driver
# -----------------------------------------------------------------------------

class PythonLibCstDriver(ParserDriver):
    """
    Python parser using libcst for a lossless Concrete Syntax Tree with precise
    positions. Emits a stream of CstEvent(ENTER/EXIT/TOKEN) in source order.

    Improvements:
      - O(1) byte offset computation
      - Stable child ordering even when some children lack PositionProvider entries
      - Leaf detection based on already-materialized child list (no fragile heuristics)
      - Correct token position extraction for name tokens
    """

    def __init__(self) -> None:
        grammar_name = "libcst-python"
        version = self._libcst_version()
        grammar_sha = hashlib.blake2b(
            f"{grammar_name}:{version}".encode("utf-8"), digest_size=20
        ).hexdigest()
        self._info = DriverInfo(
            language=Language.PY, grammar_name=grammar_name, grammar_sha=grammar_sha, version=version
        )

    def info(self) -> DriverInfo:
        if _LIBCST_IMPORT_ERROR is not None:
            raise ParserError(
                code="LIB_DEP_MISSING",
                message="libcst import failed",
                detail=repr(_LIBCST_IMPORT_ERROR),
            )
        return self._info

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
        if _LIBCST_IMPORT_ERROR is not None:
            raise ParserError(
                code="LIB_DEP_MISSING",
                message="libcst import failed",
                detail=repr(_LIBCST_IMPORT_ERROR),
            )

        if not file.is_text:
            raise ParserError(code="NOT_TEXT", message="File classified as binary by discovery")

        enc = file.encoding or "utf-8"

        # Read original bytes (entire file) — needed for byte-accurate mapping.
        try:
            with open(file.real_path, "rb") as fh:
                raw = fh.read()
        except FileNotFoundError as e:
            raise ParserError(code="IO_ERROR", message="File not found", detail=str(e))
        except PermissionError as e:
            raise ParserError(code="PERMISSION_DENIED", message="Permission denied", detail=str(e))
        except OSError as e:
            raise ParserError(code="IO_ERROR", message="Read failed", detail=str(e))

        # Decode for libcst parsing
        try:
            text = raw.decode(enc, errors="strict")
        except Exception as e:
            raise ParserError(code="DECODE_FAILED", message=f"Could not decode with {enc}", detail=str(e))

        # Build O(1) byte indexer
        indexer = _ByteOffsetIndexer.build(raw, enc)

        # Parse & attach metadata once; cache the provider map
        try:
            parsed_module = cst.parse_module(text)
            wrapper = MetadataWrapper(parsed_module)
            positions = wrapper.resolve(PositionProvider)
            module = wrapper.module  # use metadata-annotated node
        except Exception as e:
            raise ParserError(code="PARSE_ERROR", message="libcst.parse_module failed", detail=str(e))

        # Iterative DFS with explicit stack
        stack: List[Tuple[cst.CSTNode, List[cst.CSTNode], int]] = []
        root_children = list(module.children)
        stack.append((module, root_children, 0))

        def _emit_for_node(n: cst.CSTNode, kind: CstEventKind) -> CstEvent:
            try:
                rng: CodeRange = positions[n]
                b_start = indexer.to_byte_offset(rng.start.line, rng.start.column)
                b_end = indexer.to_byte_offset(rng.end.line, rng.end.column)
                line_start = rng.start.line
                line_end = rng.end.line
            except Exception:
                # Fallback for nodes without position information
                b_start = 0
                b_end = len(text)
                line_start = 1
                line_end = len(text.splitlines())

            ntype = n.__class__.__name__
            return CstEvent(
                kind=kind,
                type=ntype,
                byte_start=b_start,
                byte_end=b_end if b_end >= b_start else b_start,
                line_start=line_start,
                line_end=line_end if line_end >= line_start else line_start,
            )

        def _extract_name_token(node: cst.CSTNode) -> Optional[CstEvent]:
            """
            Extract a TOKEN event for the name of a declaration node (FunctionDef, ClassDef, etc.)
            using the precise CodeRange from libcst's metadata.
            """
            name_node: Optional[cst.CSTNode]
            if isinstance(node, (cst.FunctionDef, cst.ClassDef)):
                name_node = node.name
            elif hasattr(node, "name") and isinstance(getattr(node, "name"), cst.CSTNode):
                name_node = node.name  # type: ignore[assignment]
            else:
                name_node = None

            if name_node is None:
                return None

            try:
                rng: CodeRange = positions[name_node]
            except Exception:
                return None

            byte_start = indexer.to_byte_offset(rng.start.line, rng.start.column)
            byte_end = indexer.to_byte_offset(rng.end.line, rng.end.column)
            if byte_end < byte_start:
                byte_end = byte_start

            return CstEvent(
                kind=CstEventKind.TOKEN,
                type=type(name_node).__name__,
                byte_start=byte_start,
                byte_end=byte_end,
                line_start=rng.start.line,
                line_end=rng.end.line,
            )

        while stack:
            node, children, state = stack.pop()
            if state == 0:
                # ENTER
                yield _emit_for_node(node, CstEventKind.ENTER)

                # Determine if leaf using the already-built child list
                # A node is a "leaf" iff it has NO CSTNode children.
                is_leaf = True
                for ch in children:
                    if isinstance(ch, cst.CSTNode):
                        is_leaf = False
                        break

                if is_leaf:
                    # For leaf nodes, emit a TOKEN event with the node's own position
                    yield _emit_for_node(node, CstEventKind.TOKEN)
                    # Schedule EXIT
                    stack.append((node, children, 2))
                    continue
                else:
                    # For non-leaf nodes that are declarations, emit a name token if available
                    if isinstance(node, (cst.FunctionDef, cst.ClassDef)):
                        name_token = _extract_name_token(node)
                        if name_token:
                            yield name_token

                # Order children robustly:
                # - Try to key by (start.line, start.col) from PositionProvider
                # - If missing, fall back to original index (stable) behind positioned nodes
                keyed: List[Tuple[Tuple[int, int, int], cst.CSTNode]] = []
                for idx, ch in enumerate(children):
                    if not isinstance(ch, cst.CSTNode):
                        # Non-node entries are ignored by libcst normally; be conservative.
                        key = (2_000_000_000, 2_000_000_000, idx)  # push to the end, stable
                        keyed.append((key, ch))  # type: ignore[arg-type]
                        continue
                    try:
                        cr: CodeRange = positions[ch]
                        key = (cr.start.line, cr.start.column, idx)
                    except Exception:
                        key = (1_000_000_000, 1_000_000_000, idx)  # after positioned, before non-nodes
                    keyed.append((key, ch))

                keyed.sort(key=lambda t: t[0])

                # Schedule EXIT after children
                stack.append((node, children, 2))

                # Push children in reverse so we visit in ascending order
                for _, ch in reversed(keyed):
                    if isinstance(ch, cst.CSTNode):
                        stack.append((ch, list(ch.children), 0))

            else:
                # EXIT
                yield _emit_for_node(node, CstEventKind.EXIT)

    @staticmethod
    def _libcst_version() -> str:
        try:
            import libcst
            return getattr(libcst, "__version__", "unknown")
        except Exception:
            return "unknown"
