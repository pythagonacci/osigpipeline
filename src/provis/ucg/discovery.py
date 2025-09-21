# src/provis/ucg/discovery.py
from __future__ import annotations

import fnmatch
import hashlib
import os
import re
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Iterator, Optional, Sequence, Set, Tuple

# ==============================================================================
# Anomaly model
# ==============================================================================


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

    def items(self) -> Sequence[Anomaly]:
        return tuple(self._items)


# ==============================================================================
# Metrics (counters & histograms; Prometheus-compatible surface)
# ==============================================================================


@dataclass
class _HistogramBucket:
    le: float
    count: int = 0


class Metrics:
    """
    Lightweight, dependency-free metrics with a Prometheus-compatible feel.
    - counters: dict[str, int]
    - histograms: dict[str, (buckets, sum)]
    NOTE: If you later wire prometheus_client, you can mirror these updates.
    """

    def __init__(self) -> None:
        self.counters: dict[str, int] = {}
        self._hist_buckets: dict[str, list[_HistogramBucket]] = {}
        self._hist_sum: dict[str, float] = {}

        # default histograms
        self.define_histogram(
            "discovery_file_read_seconds",
            buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0],
        )
        self.define_histogram(
            "discovery_file_size_bytes",
            buckets=[1e3, 5e3, 1e4, 5e4, 1e5, 5e5, 1e6, 5e6, 1e7, 2e7, 5e7],
        )
        self.define_histogram(
            "discovery_sample_size_bytes",
            buckets=[256, 1024, 4096, 16384, 65536, 262144, 1048576],
        )

    # ---- counters
    def inc(self, name: str, by: int = 1) -> None:
        self.counters[name] = self.counters.get(name, 0) + by

    # ---- histograms
    def define_histogram(self, name: str, buckets: Sequence[float]) -> None:
        if name in self._hist_buckets:
            return
        ordered = sorted(set(float(b) for b in buckets))
        self._hist_buckets[name] = [ _HistogramBucket(le=b) for b in ordered ]
        self._hist_sum[name] = 0.0

    def observe(self, name: str, value: float) -> None:
        if name not in self._hist_buckets:
            # create a generic histogram if not predefined
            self.define_histogram(name, buckets=[0.01, 0.1, 1, 10])
        self._hist_sum[name] += value
        for b in self._hist_buckets[name]:
            if value <= b.le:
                b.count += 1

    def snapshot(self) -> dict:
        return {
            "counters": dict(self.counters),
            "histograms": {
                n: {
                    "buckets": [{"le": b.le, "count": b.count} for b in bs],
                    "sum": self._hist_sum.get(n, 0.0),
                }
                for n, bs in self._hist_buckets.items()
            },
        }


# ==============================================================================
# File & config models
# ==============================================================================


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

    # Heuristics for minified/generated
    minified_long_line_threshold: int = 5000
    minified_avg_line_len_threshold: int = 2000
    minified_symbol_density_threshold: float = 0.5
    minified_whitespace_ratio_min: float = 0.02

    # Sampling for heuristics
    sample_bytes_for_heuristics: int = 1024 * 256   # 256 KiB of prefix

    # Skips & language gates
    include_globs: Tuple[str, ...] = ()
    exclude_globs: Tuple[str, ...] = (
        ".git/**", ".hg/**", ".svn/**",
        "node_modules/**", "dist/**", "build/**", "out/**",
        ".venv/**", "__pycache__/**",
        "*.min.js", "*.bundle.js", "*.map", "*.lock",
    )
    binary_like_exts: Tuple[str, ...] = (
        ".png",".jpg",".jpeg",".gif",".webp",".ico",
        ".pdf",".zip",".gz",".tgz",".bz2",".xz",".7z",
        ".jar",".war",".class",".so",".dll",".dylib",".bin",
        ".woff",".woff2",".ttf",".otf",
    )

    # Language enablement
    enable_langs: Set[Language] = field(default_factory=lambda: {Language.PY, Language.JS, Language.TS, Language.JSX, Language.TSX})

    # Determinism
    config_hash: str = "dev-config"
    run_id: str = "dev-run"

    # Safety / performance
    hard_read_time_budget_sec: float = 10.0


# ==============================================================================
# Internal helpers
# ==============================================================================

_POSIX_SEP = "/"

_BOMS: Tuple[Tuple[bytes, str], ...] = (
    (b"\xef\xbb\xbf", "utf-8-sig"),
    (b"\xff\xfe", "utf-16-le"),
    (b"\xfe\xff", "utf-16-be"),
    (b"\xff\xfe\x00\x00", "utf-32-le"),
    (b"\x00\x00\xfe\xff", "utf-32-be"),
)

_SHEBANG_LANG_RE = re.compile(rb"^#![^\n]*\b(?P<cmd>(python|node))\b", re.IGNORECASE)

# --- language hint regexes (enhanced) ---
_JS_TOKENS = re.compile(r"\b(function|class|import|export|const|let|var|require\s*\(|module\.exports)\b")
_TS_TOKENS = re.compile(r"\b(interface|type\s+\w+\s*=|enum\s+\w+|as\s+const|satisfies\b|import\s+type\b)\b")
_JSX_MARKERS = re.compile(r"<[A-Za-z][A-Za-z0-9]*(\s[^>]*)?>.*?</[A-Za-z][A-Za-z0-9]*>|<[A-Za-z][A-Za-z0-9]*\s*\/>")
_REACT_HINTS = re.compile(r"\bfrom\s+['\"]react['\"]|import\s+React\b")
_PY_TOKENS = re.compile(r"\b(def|class|import|from|async\s+def|if\s+__name__\s*==\s*['\"]__main__['\"])\b")
_CJS_EXTS = (".cjs", ".mjs")
_TSX_EXT = ".tsx"
_JSX_EXT = ".jsx"


def _posix_relpath(p: Path, root: Path) -> str:
    rel = p.resolve().relative_to(root.resolve())
    return rel.as_posix()


def _matches_any(path: str, patterns: Sequence[str]) -> bool:
    return any(fnmatch.fnmatch(path, pat) for pat in patterns)


def _detect_bom(data: bytes) -> Optional[str]:
    for sig, name in _BOMS:
        if data.startswith(sig):
            return name
    return None


def _is_binary_sample(sample: bytes) -> bool:
    if not sample:
        return False
    if b"\x00" in sample:
        return True
    ctrl = sum(1 for b in sample if (b < 32 and b not in (9, 10, 11, 12, 13)))
    high = sum(1 for b in sample if b > 0xF4)
    return (ctrl / max(1, len(sample)) > 0.02) or (high > 0)


def _safe_decode(sample: bytes) -> Tuple[Optional[str], float]:
    bom = _detect_bom(sample)
    if bom:
        return bom, 1.0
    try:
        sample.decode("utf-8", errors="strict")
        return "utf-8", 0.95
    except UnicodeDecodeError:
        try:
            sample.decode("utf-8", errors="replace")
            return "utf-8", 0.5
        except Exception:
            return None, 0.0


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
    if p.endswith(".ts"):
        return Language.TS
    if p.endswith(".tsx"):
        return Language.TSX
    if p.endswith(".jsx"):
        return Language.JSX
    if p.endswith(".js") or p.endswith(_CJS_EXTS) or p.endswith(".mjs"):
        return Language.JS
    return Language.UNKNOWN


def _content_language_hint(sample_text: str, relpath: str) -> Optional[Language]:
    """
    Enhanced content probing:
      - JSX/TSX: JSX syntax + React/import hints
      - TS vs JS: presence of 'interface', 'enum', 'import type', ': Type' signals
      - JS (CJS/ESM): function/class/require/module.exports
      - Python: def/class/import/from/async def, __main__ guard
    Preference order: TSX > JSX > TS > JS > PY (only if extension unknown)
    """
    # Quick JSX/TSX check (angle-bracket tags with closing, or self-closing)
    jsx_like = bool(JSX_MARKERS := _JSX_MARKERS.search(sample_text))
    react_like = bool(_REACT_HINTS.search(sample_text))
    ts_tokens = bool(_TS_TOKENS.search(sample_text))
    js_tokens = bool(_JS_TOKENS.search(sample_text))
    py_tokens = bool(_PY_TOKENS.search(sample_text))

    # If file extension already suggests JSX/TSX, content only validates; but we call only on UNKNOWN ext.
    if jsx_like and (react_like or ts_tokens):
        return Language.TSX  # JSX + TS-ish/React → assume TSX
    if jsx_like:
        return Language.JSX
    if ts_tokens:
        return Language.TS
    if js_tokens:
        return Language.JS
    if py_tokens:
        return Language.PY
    return None


def _looks_generated(text_sample: str) -> bool:
    banners = (
        "This file was generated", "Code generated by", "do not edit", "DO NOT EDIT",
        "@generated", "AUTOGENERATED", "autogenerated"
    )
    ls = text_sample.lower()
    return any(b.lower() in ls for b in banners)


def _minified_signature(sample_text: str, *, line_limit: int, avg_len_thr: int, sym_density_thr: float, ws_ratio_min: float) -> bool:
    if not sample_text:
        return False
    # Heuristic: extremely long individual line or very high average on prefix
    lines = sample_text.splitlines()
    if lines:
        if any(len(ln) > line_limit for ln in lines[: min(len(lines), 2000)]):
            return True
        consider = lines[: min(len(lines), 2000)]
        if consider:
            avg_len = sum(len(l) for l in consider) / len(consider)
            if avg_len > avg_len_thr:
                return True
    total = len(sample_text)
    if total == 0:
        return False
    non_alnum = sum(1 for ch in sample_text if not ch.isalnum() and ch not in {" ", "\t", "\n", "\r"})
    symbol_density = non_alnum / total
    ws_ratio = sum(1 for ch in sample_text if ch in {" ", "\t", "\n", "\r"}) / total
    return symbol_density > sym_density_thr and ws_ratio < ws_ratio_min


def _hash_and_sample(path: Path, size: int, time_budget: float, sample_budget: int) -> Tuple[str, bytes, float]:
    """
    Stream the file to compute BLAKE2b hash and take a prefix sample.
    Returns: (blob_sha_hex, sample_bytes, read_seconds)
    """
    h = hashlib.blake2b(digest_size=32)
    sample_budget = min(sample_budget, size)
    sample = bytearray()
    start = time.perf_counter()

    with open(path, "rb", buffering=1024 * 1024) as f:
        while True:
            if (time.perf_counter() - start) > time_budget:
                break  # return what we have; caller can record TIMEOUT elsewhere if desired
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
            if len(sample) < sample_budget:
                need = sample_budget - len(sample)
                sample.extend(chunk[:need])

    elapsed = time.perf_counter() - start
    return h.hexdigest(), bytes(sample), elapsed


# ==============================================================================
# Discovery
# ==============================================================================


def iter_discovered_files(
    root: Path,
    cfg: DiscoveryConfig,
    anomaly_sink: Optional[AnomalySink] = None,
    metrics: Optional[Metrics] = None,
) -> Iterator[FileMeta]:
    """
    Walk a repository root and yield FileMeta records for candidate files.
    - Deterministic lexicographic order
    - Streaming, memory-bounded
    - Emits anomaly records for all skips / issues (no silent failures)
    - Records detailed counters and histograms
    """
    root = root.resolve()
    if not root.exists() or not root.is_dir():
        raise NotADirectoryError(f"Discovery root not found or not a directory: {root}")

    sink = anomaly_sink or AnomalySink()
    m = metrics or Metrics()

    # Walk deterministically
    for path in _iter_paths_lex(root, sink, m):
        posix_rel = _posix_relpath(path, root)

        # Include/exclude rules
        if cfg.include_globs and not _matches_any(posix_rel, cfg.include_globs):
            sink.emit(Anomaly(path=posix_rel, blob_sha=None, kind=AnomalyKind.SKIPPED_BY_RULE, severity=Severity.INFO, detail="Not matched by include_globs"))
            m.inc("discovery_skipped_include_miss_total")
            continue
        if _matches_any(posix_rel, cfg.exclude_globs):
            sink.emit(Anomaly(path=posix_rel, blob_sha=None, kind=AnomalyKind.SKIPPED_BY_RULE, severity=Severity.INFO, detail="Matched exclude_globs"))
            m.inc("discovery_skipped_exclude_match_total")
            continue

        # Stat
        try:
            st = path.stat()
        except PermissionError:
            sink.emit(Anomaly(path=posix_rel, blob_sha=None, kind=AnomalyKind.PERMISSION_DENIED, severity=Severity.WARN, detail="Stat permission denied"))
            m.inc("discovery_permission_denied_total")
            continue
        except OSError as e:
            sink.emit(Anomaly(path=posix_rel, blob_sha=None, kind=AnomalyKind.IO_ERROR, severity=Severity.WARN, detail=f"Stat failed: {e}"))
            m.inc("discovery_io_errors_total")
            continue

        size = int(st.st_size)
        m.observe("discovery_file_size_bytes", float(size))
        m.inc("discovery_files_seen_total")

        mtime_ns = int(getattr(st, "st_mtime_ns", int(st.st_mtime * 1e9)))
        inode = int(getattr(st, "st_ino", 0)) or None
        device = int(getattr(st, "st_dev", 0)) or None

        # Hash + sample
        blob_sha, sample, read_s = _hash_and_sample(
            path=path,
            size=size,
            time_budget=cfg.hard_read_time_budget_sec,
            sample_budget=cfg.sample_bytes_for_heuristics,
        )
        m.observe("discovery_file_read_seconds", read_s)
        m.observe("discovery_sample_size_bytes", float(len(sample)))

        # Early size budget
        too_large = size > cfg.max_file_size_bytes

        # Binary by extension?
        lower = posix_rel.lower()
        ext = os.path.splitext(lower)[1]
        binary_by_ext = ext in cfg.binary_like_exts

        # Binary by content?
        is_text_guess = not _is_binary_sample(sample)
        encoding_label: Optional[str] = None
        enc_conf = 0.0
        if is_text_guess:
            encoding_label, enc_conf = _safe_decode(sample)
            if encoding_label is None:
                is_text_guess = False
                sink.emit(Anomaly(path=posix_rel, blob_sha=blob_sha, kind=AnomalyKind.ENCODING_ERROR, severity=Severity.WARN, detail="Undecodable text sample"))
                m.inc("discovery_encoding_errors_total")

        if binary_by_ext:
            is_text_guess = False

        flags: Set[str] = set()
        lang = Language.UNKNOWN

        if not is_text_guess:
            # Binary path
            flags.add("binary")
            sink.emit(Anomaly(path=posix_rel, blob_sha=blob_sha, kind=AnomalyKind.BINARY_FILE, severity=Severity.INFO, detail="Binary detected by extension/content"))
            m.inc("discovery_files_binary_total")
        else:
            # Text path: heuristics
            m.inc("discovery_files_text_total")
            sample_text = sample.decode(encoding_label or "utf-8", errors="replace")

            # Generated/minified
            if _looks_generated(sample_text):
                flags.add("generated")
                sink.emit(Anomaly(path=posix_rel, blob_sha=blob_sha, kind=AnomalyKind.GENERATED_CODE, severity=Severity.INFO, detail="Header/banner suggests generated code"))
                m.inc("discovery_generated_code_total")

            if _minified_signature(
                sample_text,
                line_limit=cfg.minified_long_line_threshold,
                avg_len_thr=cfg.minified_avg_line_len_threshold,
                sym_density_thr=cfg.minified_symbol_density_threshold,
                ws_ratio_min=cfg.minified_whitespace_ratio_min,
            ):
                flags.add("minified")
                sink.emit(Anomaly(path=posix_rel, blob_sha=blob_sha, kind=AnomalyKind.MINIFIED, severity=Severity.INFO, detail="Minified signature detected"))
                m.inc("discovery_minified_files_total")

            # Language classification: extension → shebang → enhanced content probe
            lang = _ext_language(posix_rel)
            if lang is Language.UNKNOWN:
                sb = _shebang_hint(sample)
                if sb:
                    lang = sb
                else:
                    hint = _content_language_hint(sample_text, posix_rel)
                    if hint:
                        lang = hint

            if lang is Language.UNKNOWN:
                sink.emit(Anomaly(path=posix_rel, blob_sha=blob_sha, kind=AnomalyKind.LANG_UNKNOWN, severity=Severity.INFO, detail="Could not classify language"))
                m.inc("discovery_lang_unknown_total")
            elif lang not in cfg.enable_langs:
                # Keep meta; parser layers will ignore unsupported langs.
                m.inc(f"discovery_lang_{lang.value}_disabled_total")

        if too_large:
            flags.add("too_large")
            sink.emit(Anomaly(path=posix_rel, blob_sha=blob_sha, kind=AnomalyKind.TOO_LARGE, severity=Severity.INFO, detail=f"File exceeds size budget ({size} bytes)"))
            m.inc("discovery_files_too_large_total")

        fm = FileMeta(
            path=posix_rel,
            real_path=str(path.resolve()),
            blob_sha=blob_sha,
            size_bytes=size,
            mtime_ns=mtime_ns,
            run_id=cfg.run_id,
            config_hash=cfg.config_hash,
            is_text=is_text_guess,
            encoding=encoding_label if is_text_guess else None,
            encoding_confidence=enc_conf if is_text_guess else 0.0,
            lang=lang if is_text_guess else Language.UNKNOWN,
            flags=flags,
            inode=inode,
            device=device,
        )

        yield fm


def _iter_paths_lex(root: Path, sink: AnomalySink, m: Metrics) -> Iterator[Path]:
    """
    Deterministic lexicographic directory walk with symlink safety (we do not
    follow symlinked dirs in discovery; if you decide to, enforce within-root checks).
    """
    stack: list[Path] = [root]
    while stack:
        cur = stack.pop()
        try:
            entries = sorted(os.scandir(cur), key=lambda e: e.name)
        except PermissionError:
            rel = _posix_relpath(cur, root)
            sink.emit(Anomaly(path=rel, blob_sha=None, kind=AnomalyKind.PERMISSION_DENIED, severity=Severity.WARN, detail="Dir read permission denied"))
            m.inc("discovery_permission_denied_total")
            continue
        except OSError as e:
            rel = _posix_relpath(cur, root)
            sink.emit(Anomaly(path=rel, blob_sha=None, kind=AnomalyKind.IO_ERROR, severity=Severity.WARN, detail=f"Dir read failed: {e}"))
            m.inc("discovery_io_errors_total")
            continue

        for entry in entries:
            try:
                is_dir = entry.is_dir(follow_symlinks=False)
                is_file = entry.is_file(follow_symlinks=False)
                is_symlink = entry.is_symlink()
            except OSError:
                continue

            p = Path(entry.path)
            if is_dir:
                if is_symlink:
                    rel = _posix_relpath(p, root)
                    sink.emit(Anomaly(path=rel, blob_sha=None, kind=AnomalyKind.SYMLINK_OUT_OF_ROOT, severity=Severity.INFO, detail="Symlinked directory not followed"))
                    m.inc("discovery_symlink_dirs_not_followed_total")
                    continue
                stack.append(p)
            elif is_file:
                yield p
            else:
                # sockets, fifos, devices ignored
                continue


def _posix_relpath(p: Path, root: Path) -> str:
    rel = p.resolve().relative_to(root.resolve())
    return rel.as_posix()
