# src/provis/ucg/anomalies.py
from __future__ import annotations

import enum
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple


class Severity(str, enum.Enum):
    INFO = "INFO"
    WARN = "WARN"
    ERROR = "ERROR"


class AnomalyKind(str, enum.Enum):
    # Discovery / IO
    IO_ERROR = "IO_ERROR"
    SKIPPED = "SKIPPED"                # filtered/binary/non-text
    ENCODING = "ENCODING"              # decoding/encoding issues
    # Parsing
    PARSE_FAILED = "PARSE_FAILED"
    SYNTAX_ERRORS = "SYNTAX_ERRORS"
    TOOL_MISSING = "TOOL_MISSING"      # dependency not available
    # Limits & performance
    TIMEOUT = "TIMEOUT"
    MEMORY_LIMIT = "MEMORY_LIMIT"
    DEPTH_LIMIT = "DEPTH_LIMIT"
    SIZE_LIMIT = "SIZE_LIMIT"
    # Semantics / dynamic features
    DYNAMIC_IMPORT = "DYNAMIC_IMPORT"
    EVAL_USAGE = "EVAL_USAGE"
    UNKNOWN_FLOW = "UNKNOWN_FLOW"
    # Catch-all
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class Anomaly:
    """
    Immutable record. Persisted by UcgStore via its Arrow mapping.
    """
    path: str
    blob_sha: str
    kind: AnomalyKind
    severity: Severity
    detail: str = ""
    span: Optional[Tuple[int, int]] = None  # (byte_start, byte_end)
    ts_ms: int = field(default_factory=lambda: int(time.time() * 1000))

    def to_dict(self) -> Dict:
        s0, s1 = (None, None)
        if self.span and len(self.span) == 2:
            s0, s1 = int(self.span[0]), int(self.span[1])
        return {
            "path": self.path,
            "blob_sha": self.blob_sha,
            "kind": self.kind.value,
            "severity": self.severity.value,
            "detail": self.detail,
            "span_start": int(s0 or 0),
            "span_end": int(s1 or 0),
            "ts_ms": int(self.ts_ms),
        }


class AnomalySink:
    """
    Thread-safe anomaly collector + lightweight observability.

    - emit(): add an anomaly, update counters
    - drain(): atomically return & clear buffered anomalies
    - counters(): snapshot of counters (for receipts/metrics)
    - observe_duration(): record timing histograms (file parse times, etc.)
    """

    __slots__ = ("_lock", "_buffer", "_counts", "_timers")

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._buffer: List[Anomaly] = []
        # Counters: by kind/severity; flat totals; by path optional aggregation
        self._counts: Dict[str, int] = {
            "total": 0,
        }
        # Timers: name -> bucket -> count
        self._timers: Dict[str, Dict[str, int]] = {}

    # ----------------------------- public API ---------------------------------

    def emit(self, anomaly: Anomaly) -> None:
        with self._lock:
            self._buffer.append(anomaly)
            self._counts["total"] = self._counts.get("total", 0) + 1
            self._counts[f"kind:{anomaly.kind.value}"] = self._counts.get(f"kind:{anomaly.kind.value}", 0) + 1
            self._counts[f"sev:{anomaly.severity.value}"] = self._counts.get(f"sev:{anomaly.severity.value}", 0) + 1

    def extend(self, anomalies: Iterable[Anomaly]) -> None:
        for a in anomalies:
            self.emit(a)

    def drain(self) -> List[Anomaly]:
        with self._lock:
            out = self._buffer
            self._buffer = []
            return out

    def counters(self) -> Dict[str, int]:
        with self._lock:
            # shallow copy is enough (values are ints)
            return dict(self._counts)

    def observe_duration(self, name: str, key: str, seconds: float) -> None:
        """
        Record a single observation into log-scale buckets.
        Example: observe_duration("file_total_seconds", path, dt)
        """
        bucket = _duration_bucket(seconds)
        with self._lock:
            buckets = self._timers.setdefault(name, {})
            buckets[bucket] = buckets.get(bucket, 0) + 1
            # Optional per-key breakdown (kept sparse)
            total_key = f"{name}::count"
            buckets[total_key] = buckets.get(total_key, 0) + 1

    def timer_histograms(self) -> Dict[str, Dict[str, int]]:
        with self._lock:
            return {k: dict(v) for k, v in self._timers.items()}


# ----------------------------- helpers ----------------------------------------

def _duration_bucket(seconds: float) -> str:
    """
    Log-ish buckets from microseconds to minutes.
    """
    s = max(0.0, float(seconds))
    if s < 1e-6:
        return "<1µs"
    if s < 1e-3:
        return "<1ms"
    if s < 1e-2:
        return "<10ms"
    if s < 5e-2:
        return "<50ms"
    if s < 1e-1:
        return "<100ms"
    if s < 5e-1:
        return "<500ms"
    if s < 1.0:
        return "<1s"
    if s < 2.5:
        return "<2.5s"
    if s < 5.0:
        return "<5s"
    if s < 10.0:
        return "<10s"
    if s < 30.0:
        return "<30s"
    if s < 60.0:
        return "<60s"
    return ">=60s"
