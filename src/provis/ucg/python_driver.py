from __future__ import annotations

import hashlib
import time
from bisect import bisect_right
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

    def byte_to_line_col(self, byte_offset: int) -> Tuple[int, int]:
        """Map an absolute byte offset back to (1-based line, 0-based column)."""

        if not self.line_start_bytes:
            return 1, 0

        if byte_offset < 0:
            byte_offset = 0
        else:
            last_line_index = len(self.line_start_bytes) - 1
            last_line = self.line_char_to_byte[last_line_index]
            last_span = last_line[-1] if last_line else 0
            total_bytes = self.line_start_bytes[last_line_index] + last_span
            if byte_offset > total_bytes:
                byte_offset = total_bytes

        # Locate the line whose start byte is <= byte_offset
        line_index = bisect_right(self.line_start_bytes, byte_offset) - 1
        if line_index < 0:
            line_index = 0
        if line_index >= len(self.line_start_bytes):
            line_index = len(self.line_start_bytes) - 1

        line_start_byte = self.line_start_bytes[line_index]
        rel = byte_offset - line_start_byte
        if rel < 0:
            rel = 0

        per_line = self.line_char_to_byte[line_index]
        if not per_line:
            return line_index + 1, 0

        # per_line is a non-decreasing list of cumulative byte lengths. Find the
        # greatest column whose byte length does not exceed rel.
        col_index = bisect_right(per_line, rel) - 1
        if col_index < 0:
            col_index = 0
        if col_index >= len(per_line):
            col_index = len(per_line) - 1

        return line_index + 1, col_index


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
                rng = None

            if rng is not None:
                byte_start = indexer.to_byte_offset(rng.start.line, rng.start.column)
                byte_end = indexer.to_byte_offset(rng.end.line, rng.end.column)
                if byte_end < byte_start:
                    byte_end = byte_start
                line_start = rng.start.line
                line_end = rng.end.line
            else:
                # Fallback: derive the span directly from the source bytes. This handles
                # rare cases where metadata for the name node is missing but the parent
                # node still has a precise range.
                value = getattr(name_node, "value", None)
                if not isinstance(value, str) or not value:
                    return None

                parent_rng = positions.get(node)
                if parent_rng is not None:
                    parent_start = indexer.to_byte_offset(parent_rng.start.line, parent_rng.start.column)
                    parent_end = indexer.to_byte_offset(parent_rng.end.line, parent_rng.end.column)
                    if parent_end < parent_start:
                        parent_end = parent_start
                else:
                    parent_start = 0
                    parent_end = len(raw)

                if parent_end <= parent_start:
                    return None

                name_bytes = value.encode(enc, errors="ignore")
                if not name_bytes:
                    return None

                slice_start = max(0, parent_start)
                slice_end = min(len(raw), parent_end)
                haystack = raw[slice_start:slice_end]
                rel_index = haystack.find(name_bytes)
                if rel_index < 0:
                    return None

                byte_start = slice_start + rel_index
                byte_end = byte_start + len(name_bytes)
                line_start, _ = indexer.byte_to_line_col(byte_start)
                line_end, _ = indexer.byte_to_line_col(byte_end)
                if line_end < line_start:
                    line_end = line_start

            return CstEvent(
                kind=CstEventKind.TOKEN,
                type=type(name_node).__name__,
                byte_start=byte_start,
                byte_end=byte_end,
                line_start=line_start,
                line_end=line_end,
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
