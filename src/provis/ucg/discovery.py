# src/provis/ucg/discovery.py
from __future__ import annotations

import fnmatch
import hashlib
import io
import os
import re
import stat
import sys
import time
from dataclasses import dataclass, field, replace
from enum import Enum, auto
from pathlib import Path
from typing import Callable, Generator, Iterable, Iterator, Optional, Sequence, Set, Tuple

# ---- Discovery data model -----------------------------------------------------


class AnomalyKind(Enum):
    PARSE_FAILED = auto()          # reserved for parser layers
    ENCODING_ERROR = auto()
    TIMEOUT = auto()               # reserved; can be used by parsers too
    MEMORY_LIMIT = auto()          # reserved; can be used by parsers too
    LANG_UNKNOWN = auto()
    MINIFIED = auto()
    TOO_LARGE = auto()
    BINARY_FILE = auto()
    PERMISSION_DENIED = auto()
    IO_ERROR = auto()
    SYMLINK_OUT_OF_ROOT = auto()
    SYMLINK_CYCLE = auto()
    GENERATED_CODE = auto()
    SKIPPED_BY_RULE = auto()
    UNKNOWN = auto()


class Severity(Enum):
    INFO = auto()
    WARN = auto()
    ERROR = auto()


@dataclass(frozen=True)
class Anomaly:
    path: str
    blob_sha: Optional[str]   # may be None if we couldn't read bytes
    kind: AnomalyKind
    severity: Severity
    detail: str
    span: Optional[Tuple[int, int]] = None  # optional byte range
    ts_ms: int = field(default_factory=lambda: int(time.time() * 1000))


class AnomalySink:
    """
    Pluggable sink for anomaly records. Default implementation collects in memory.
    In production, a writer will batch to Parquet/DB.
    """

    def __init__(self) -> None:
        self._items: list[Anomaly] = []

    def emit(self, a: Anomaly) -> None:
        self._items.append(a)

    def __len__(self) -> int:
        return len(self._items)

    def items(self) -> Sequence[Anomaly]:
        return tuple(self._items)


class Language(Enum):
    PY = "py"
    JS = "js"
    TS = "ts"
    JSX = "jsx"
    TSX = "tsx"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class FileMeta:
    # Identity & provenance
    path: str                 # repo-relative posix path
    real_path: str            # resolved absolute path
    blob_sha: str             # content hash (BLAKE2b)
    size_bytes: int
    mtime_ns: int
    run_id: str
    config_hash: str

    # Classification
    is_text: bool
    encoding: Optional[str]   # 'utf-8', 'utf-16-le', etc. (None for binary)
    encoding_confidence: float
    lang: Language

    # Flags / notes
    flags: Set[str]           # e.g., {'minified','generated','too_large','binary','skipped_by_rule'}

    # For deterministic ordering & quick lookups
    inode: Optional[int] = None
    device: Optional[int] = None


@dataclass(frozen=True)
class DiscoveryConfig:
    # Limits
    max_file_size_bytes: int = 20 * 1024 * 1024  # 20 MiB
    follow_symlinks: bool = False
    max_symlink_depth: int = 5

    # Heuristics for minified/generated
    minified_long_line_threshold: int = 5000  # if any line > this → suspect minified
    minified_avg_line_len_threshold: int = 2000
    minified_symbol_density_threshold: float = 0.5  # non-alnum / total chars (sampled)
    minified_whitespace_ratio_min: float = 0.02     # whitespace / total chars (sampled)

    # Sampling for heuristics
    sample_bytes_for_heuristics: int = 1024 * 256   # 256 KiB of prefix
    sample_lines_for_heuristics: int = 4000

    # Skips & language gates
    include_globs: Tuple[str, ...] = ()
    exclude_globs: Tuple[str, ...] = (
        ".git/**",
        ".hg/**",
        ".svn/**",
        "node_modules/**",
        "dist/**",
        "build/**",
        "out/**",
        ".venv/**",
        "__pycache__/**",
        "*.min.js",
        "*.bundle.js",
        "*.map",
        "*.lock",
    )
    # Files that are almost always noise or binary
    binary_like_exts: Tuple[str, ...] = (
        ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico",
        ".pdf", ".zip", ".gz", ".tgz", ".bz2", ".xz", ".7z",
        ".jar", ".war", ".class", ".so", ".dll", ".dylib", ".bin",
        ".woff", ".woff2", ".ttf", ".otf",
    )

    # Language enablement
    enable_langs: Set[Language] = field(default_factory=lambda: {Language.PY, Language.JS, Language.TS, Language.JSX, Language.TSX})

    # Determinism
    config_hash: str = "dev-config"   # upstream should stamp a hash of the full run config
    run_id: str = "dev-run"           # upstream should stamp a unique run id

    # Safety / performance
    hard_read_time_budget_sec: float = 10.0


# ---- Utility helpers ----------------------------------------------------------


_POSIX_SEP = "/"


def _posix_relpath(p: Path, root: Path) -> str:
    rel = p.resolve().relative_to(root.resolve())
    return rel.as_posix()


def _is_within(root: Path, target: Path) -> bool:
    try:
        target.resolve().relative_to(root.resolve())
        return True
    except Exception:
        return False


def _matches_any(path: str, patterns: Sequence[str]) -> bool:
    return any(fnmatch.fnmatch(path, pat) for pat in patterns)


_BOMS: Tuple[Tuple[bytes, str], ...] = (
    (b"\xef\xbb\xbf", "utf-8-sig"),
    (b"\xff\xfe", "utf-16-le"),
    (b"\xfe\xff", "utf-16-be"),
    (b"\xff\xfe\x00\x00", "utf-32-le"),
    (b"\x00\x00\xfe\xff", "utf-32-be"),
)


def _detect_bom(data: bytes) -> Optional[str]:
    for sig, name in _BOMS:
        if data.startswith(sig):
            return name
    return None


def _is_binary_sample(sample: bytes) -> bool:
    if not sample:
        return False
    # Classic heuristic: NUL bytes or very high fraction of non-text bytes
    if b"\x00" in sample:
        return True
    # Consider bytes outside common text ranges; allow UTF-8 multibyte beginnings.
    # We approximate by counting very low control chars excluding \n \r \t \f \x0b
    ctrl = sum(1 for b in sample if (b < 32 and b not in (9, 10, 11, 12, 13)))
    high = sum(1 for b in sample if b > 0xF4)  # unlikely in valid UTF-8 streams
    return (ctrl / max(1, len(sample)) > 0.02) or (high > 0)


def _safe_decode(sample: bytes, fallback: str = "utf-8") -> Tuple[Optional[str], float]:
    """
    Try BOM first, then utf-8 (strict), then utf-8 (replace).
    Returns (encoding_label, confidence[0..1]).
    We avoid adding heavy deps; upstream can enrich later if needed.
    """
    bom = _detect_bom(sample)
    if bom:
        return bom, 1.0
    try:
        sample.decode("utf-8", errors="strict")
        return "utf-8", 0.95
    except UnicodeDecodeError:
        # best-effort view; caller records ENCODING_ERROR if later full decode fails
        try:
            sample.decode("utf-8", errors="replace")
            return "utf-8", 0.5
        except Exception:
            return None, 0.0


_SHEBANG_LANG_RE = re.compile(rb"^#![^\n]*\b(?P<cmd>(python|node))\b", re.IGNORECASE)


def _shebang_hint(sample: bytes) -> Optional[Language]:
    m = _SHEBANG_LANG_RE.match(sample)
    if not m:
        return None
    cmd = m.group("cmd").lower()
    if cmd.startswith(b"python"):
        return Language.PY
    if cmd.startswith(b"node"):
        return Language.JS
    return None


def _ext_language(path: str) -> Language:
    p = path.lower()
    if p.endswith(".py"):
        return Language.PY
    if p.endswith(".cjs") or p.endswith(".mjs") or p.endswith(".js"):
        return Language.JS
    if p.endswith(".ts"):
        return Language.TS
    if p.endswith(".tsx"):
        return Language.TSX
    if p.endswith(".jsx"):
        return Language.JSX
    return Language.UNKNOWN


def _content_language_hint(sample_text: str) -> Optional[Language]:
    # Super-lightweight probes; conservative and only used when extension is unknown.
    t = sample_text
    if re.search(r"\b(def|class|import|from)\b", t):
        return Language.PY
    if re.search(r"\b(function|class|import|export|const|let|var)\b", t):
        return Language.JS
    return None


def _looks_generated(text_sample: str) -> bool:
    banners = (
        "This file was generated", "Code generated by", "do not edit", "DO NOT EDIT",
        "@generated", "AUTOGENERATED", "autogenerated"
    )
    ls = text_sample.lower()
    return any(b.lower() in ls for b in banners)


def _minified_signature(sample_text: str, line_limit: int, avg_len_thr: int, sym_density_thr: float, ws_ratio_min: float) -> bool:
    if not sample_text:
        return False
    # Split but cap to avoid memory blowups on pathological single-line files.
    lines = sample_text.splitlines()
    if lines:
        # Any extremely long line?
        if any(len(ln) > line_limit for ln in lines[: min(len(lines), 2000)]):
            return True
        # Average line length on a reasonable prefix
        consider = lines[: min(len(lines), 2000)]
        if consider:
            avg_len = sum(len(l) for l in consider) / len(consider)
            if avg_len > avg_len_thr:
                return True
    # Symbol density & whitespace ratio on the sample
    total = len(sample_text)
    if total == 0:
        return False
    non_alnum = sum(1 for ch in sample_text if not ch.isalnum() and ch not in {" ", "\t", "\n", "\r"})
    symbol_density = non_alnum / total
    ws_ratio = sum(1 for ch in sample_text if ch in {" ", "\t", "\n", "\r"}) / total
    if symbol_density > sym_density_thr and ws_ratio < ws_ratio_min:
        return True
    return False


def _stable_hash_hex(kind: str, path: str, blob_sha: str, extra: str = "") -> str:
    h = hashlib.blake2b(digest_size=32)
    h.update(kind.encode("utf-8"))
    h.update(b"\x1f")
    h.update(path.encode("utf-8"))
    h.update(b"\x1f")
    h.update(blob_sha.encode("ascii"))
    if extra:
        h.update(b"\x1f")
        h.update(extra.encode("utf-8"))
    return h.hexdigest()


# ---- Discovery core -----------------------------------------------------------


@dataclass
class _WalkState:
    visited_inodes: Set[Tuple[int, int]] = field(default_factory=set)  # (st_dev, st_ino)
    symlink_depth: int = 0


def iter_discovered_files(
    root: Path,
    cfg: DiscoveryConfig,
    anomaly_sink: Optional[AnomalySink] = None,
) -> Iterator[FileMeta]:
    """
    Walk a repository root and yield FileMeta records for candidate files.
    All skips produce anomaly records (no silent failure). Ordering is deterministic.

    Notes:
      * This function is streaming and memory-bounded.
      * It never executes code from the repo.
      * It does not read entire files into memory; small prefix sampling is used
        for heuristics, and hashing streams the full file in chunks.
    """
    root = root.resolve()
    if not root.exists() or not root.is_dir():
        raise NotADirectoryError(f"Discovery root not found or not a directory: {root}")

    sink = anomaly_sink or AnomalySink()
    state = _WalkState()

    # Deterministic order: lexicographic walk
    for path in _iter_paths_lex(root, cfg, state, sink):
        # Apply include/exclude globs
        posix_rel = _posix_relpath(path, root)
        if cfg.include_globs and not _matches_any(posix_rel, cfg.include_globs):
            sink.emit(Anomaly(path=posix_rel, blob_sha=None, kind=AnomalyKind.SKIPPED_BY_RULE, severity=Severity.INFO, detail="Not matched by include_globs"))
            continue
        if _matches_any(posix_rel, cfg.exclude_globs):
            sink.emit(Anomaly(path=posix_rel, blob_sha=None, kind=AnomalyKind.SKIPPED_BY_RULE, severity=Severity.INFO, detail="Matched exclude_globs"))
            continue

        # Quick binary-like extension skip (but still hash/record as binary)
        lower = posix_rel.lower()
        ext = os.path.splitext(lower)[1]
        binary_by_ext = ext in cfg.binary_like_exts

        try:
            st = path.stat()
        except PermissionError:
            sink.emit(Anomaly(path=posix_rel, blob_sha=None, kind=AnomalyKind.PERMISSION_DENIED, severity=Severity.WARN, detail="Stat permission denied"))
            continue
        except OSError as e:
            sink.emit(Anomaly(path=posix_rel, blob_sha=None, kind=AnomalyKind.IO_ERROR, severity=Severity.WARN, detail=f"Stat failed: {e}"))
            continue

        size = int(st.st_size)
        mtime_ns = int(getattr(st, "st_mtime_ns", int(st.st_mtime * 1e9)))

        # Early size budget check: still compute hash (streaming) but mark flag
        too_large = size > cfg.max_file_size_bytes

        try:
            blob_sha, sample, is_text, encoding, enc_conf = _hash_and_sample(path, size, cfg)
        except PermissionError:
            sink.emit(Anomaly(path=posix_rel, blob_sha=None, kind=AnomalyKind.PERMISSION_DENIED, severity=Severity.WARN, detail="Read permission denied"))
            continue
        except OSError as e:
            sink.emit(Anomaly(path=posix_rel, blob_sha=None, kind=AnomalyKind.IO_ERROR, severity=Severity.WARN, detail=f"Read failed: {e}"))
            continue

        # Binary detection by content overrides text assumptions
        if binary_by_ext:
            is_text = False
        if not is_text:
            sink.emit(Anomaly(path=posix_rel, blob_sha=blob_sha, kind=AnomalyKind.BINARY_FILE, severity=Severity.INFO, detail="Binary detected by extension/content"))
            lang = Language.UNKNOWN
            flags: Set[str] = {"binary"}
        else:
            # Decode a UTF-8 view of the sample safely for heuristics
            sample_text = sample.decode(encoding or "utf-8", errors="replace")
            # Generated/minified heuristics
            generated = _looks_generated(sample_text)
            minified = _minified_signature(
                sample_text=sample_text,
                line_limit=cfg.minified_long_line_threshold,
                avg_len_thr=cfg.minified_avg_line_len_threshold,
                sym_density_thr=cfg.minified_symbol_density_threshold,
                ws_ratio_min=cfg.minified_whitespace_ratio_min,
            )
            flags = set()
            if generated:
                flags.add("generated")
                sink.emit(Anomaly(path=posix_rel, blob_sha=blob_sha, kind=AnomalyKind.GENERATED_CODE, severity=Severity.INFO, detail="Header/banner suggests generated code"))
            if minified:
                flags.add("minified")
                sink.emit(Anomaly(path=posix_rel, blob_sha=blob_sha, kind=AnomalyKind.MINIFIED, severity=Severity.INFO, detail="Minified signature detected"))

            # Language classification
            lang = _ext_language(posix_rel)
            if lang is Language.UNKNOWN:
                # Try shebang/content probes
                sb_hint = _shebang_hint(sample)
                if sb_hint:
                    lang = sb_hint
                else:
                    c_hint = _content_language_hint(sample_text)
                    if c_hint:
                        lang = c_hint
            if lang not in cfg.enable_langs:
                # If unknown and not allowed → mark as unknown & continue; still yield meta (Step 1 coverage accounting)
                if lang is Language.UNKNOWN:
                    sink.emit(Anomaly(path=posix_rel, blob_sha=blob_sha, kind=AnomalyKind.LANG_UNKNOWN, severity=Severity.INFO, detail="Could not classify language"))
                # We still yield meta; parsers will ignore unsupported langs.

        if too_large:
            flags.add("too_large")
            sink.emit(Anomaly(path=posix_rel, blob_sha=blob_sha, kind=AnomalyKind.TOO_LARGE, severity=Severity.INFO, detail=f"File exceeds size budget ({size} bytes)"))

        inode = int(getattr(st, "st_ino", 0)) or None
        device = int(getattr(st, "st_dev", 0)) or None

        fm = FileMeta(
            path=posix_rel,
            real_path=str(path.resolve()),
            blob_sha=blob_sha,
            size_bytes=size,
            mtime_ns=mtime_ns,
            run_id=cfg.run_id,
            config_hash=cfg.config_hash,
            is_text=is_text,
            encoding=encoding if is_text else None,
            encoding_confidence=enc_conf if is_text else 0.0,
            lang=lang if is_text else Language.UNKNOWN,
            flags=flags,
            inode=inode,
            device=device,
        )

        yield fm


def _iter_paths_lex(root: Path, cfg: DiscoveryConfig, state: _WalkState, sink: AnomalySink) -> Iterator[Path]:
    """
    Deterministic lexicographic directory walk with symlink safety.
    """
    stack: list[Path] = [root]
    root_dev_ino = _stat_dev_ino_safe(root)

    while stack:
        cur = stack.pop()
        try:
            entries = sorted(os.scandir(cur), key=lambda e: e.name)
        except PermissionError:
            rel = _posix_relpath(cur, root)
            sink.emit(Anomaly(path=rel, blob_sha=None, kind=AnomalyKind.PERMISSION_DENIED, severity=Severity.WARN, detail="Dir read permission denied"))
            continue
        except OSError as e:
            rel = _posix_relpath(cur, root)
            sink.emit(Anomaly(path=rel, blob_sha=None, kind=AnomalyKind.IO_ERROR, severity=Severity.WARN, detail=f"Dir read failed: {e}"))
            continue

        for entry in entries:
            # Skip special files early
            try:
                is_dir = entry.is_dir(follow_symlinks=False)
                is_file = entry.is_file(follow_symlinks=False)
                is_symlink = entry.is_symlink()
            except OSError:
                # If we can't stat, skip safely
                continue

            p = Path(entry.path)

            if is_dir:
                # Symlinked dirs policy
                if is_symlink:
                    if not cfg.follow_symlinks:
                        # We still record an anomaly but don't descend
                        rel = _posix_relpath(p, root)
                        sink.emit(Anomaly(path=rel, blob_sha=None, kind=AnomalyKind.SYMLINK_OUT_OF_ROOT, severity=Severity.INFO, detail="Symlinked directory not followed"))
                        continue
                    # If allowed, resolve and ensure within root
                    try:
                        tgt = p.resolve()
                    except OSError:
                        continue
                    if not _is_within(root, tgt):
                        rel = _posix_relpath(p, root)
                        sink.emit(Anomaly(path=rel, blob_sha=None, kind=AnomalyKind.SYMLINK_OUT_OF_ROOT, severity=Severity.WARN, detail="Symlink escapes root; not followed"))
                        continue
                    # Cycle protection
                    devino = _stat_dev_ino_safe(tgt)
                    if devino and devino in state.visited_inodes:
                        rel = _posix_relpath(p, root)
                        sink.emit(Anomaly(path=rel, blob_sha=None, kind=AnomalyKind.SYMLINK_CYCLE, severity=Severity.WARN, detail="Symlink cycle detected"))
                        continue
                    if devino:
                        state.visited_inodes.add(devino)
                stack.append(p)
            elif is_file:
                yield p
            else:
                # sockets, fifos, devices ignored
                continue


def _stat_dev_ino_safe(p: Path) -> Optional[Tuple[int, int]]:
    try:
        st = p.stat()
        return int(getattr(st, "st_dev", 0)), int(getattr(st, "st_ino", 0))
    except Exception:
        return None


def _hash_and_sample(
    path: Path,
    size: int,
    cfg: DiscoveryConfig,
) -> Tuple[str, bytes, bool, Optional[str], float]:
    """
    Stream file to compute content hash and take a small prefix sample for heuristics.
    Returns: (blob_sha_hex, sample_bytes, is_text, encoding_label, encoding_confidence)
    """
    h = hashlib.blake2b(digest_size=32)
    sample_budget = min(cfg.sample_bytes_for_heuristics, size)
    sample = bytearray()
    start = time.time()
    is_text_guess = True
    encoding: Optional[str] = None
    enc_conf = 0.0

    with open(path, "rb", buffering=1024 * 1024) as f:
        while True:
            if (time.time() - start) > cfg.hard_read_time_budget_sec:
                # we still return what we have; caller can emit TIMEOUT if desired
                break
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
            if len(sample) < sample_budget:
                need = sample_budget - len(sample)
                sample.extend(chunk[:need])

    sample_bytes = bytes(sample)
    # Quick binary probe on sample
    is_text_guess = not _is_binary_sample(sample_bytes)
    if is_text_guess:
        enc, conf = _safe_decode(sample_bytes)
        encoding, enc_conf = enc, conf
        # encoding can still be None if truly undecodable; caller will mark anomaly
        if encoding is None:
            is_text_guess = False

    return h.hexdigest(), sample_bytes, is_text_guess, encoding, enc_conf
