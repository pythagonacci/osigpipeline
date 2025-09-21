# src/provis/ucg/parser_registry.py
from __future__ import annotations

import concurrent.futures as futures
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable, Iterator, Optional

from .discovery import (
    Anomaly,
    AnomalyKind,
    AnomalySink,
    FileMeta,
    Language,
    Metrics,
    Severity,
)

# ==============================================================================
# CST event model (streamed; spans only, no heavy text payloads)
# ==============================================================================


class CstEventKind(str, Enum):
    ENTER = "enter"
    EXIT = "exit"
    TOKEN = "token"


@dataclass(frozen=True)
class CstEvent:
    """
    A language-agnostic CST event produced by a parser driver.

    Invariants per event:
      - byte_start/end, line_start/end are >= 0
      - byte_end >= byte_start, line_end >= line_start
    """
    kind: CstEventKind
    type: str
    byte_start: int
    byte_end: int
    line_start: int
    line_end: int


# ==============================================================================
# Driver contract and typed error
# ==============================================================================


@dataclass(frozen=True)
class DriverInfo:
    language: Language
    grammar_name: str
    grammar_sha: str   # pin exact grammar build
    version: str       # driver version (semantic)


class ParserError(Exception):
    """
    Rich driver error propagated to the registry.
    """
    def __init__(
        self,
        code: str,
        message: str,
        *,
        byte_start: Optional[int] = None,
        byte_end: Optional[int] = None,
        line_start: Optional[int] = None,
        line_end: Optional[int] = None,
        detail: Optional[str] = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.byte_start = byte_start
        self.byte_end = byte_end
        self.line_start = line_start
        self.line_end = line_end
        self.detail = detail or ""


class ParserDriver:
    """
    Language-specific parser driver interface.

    Implementations MUST be thread-safe for concurrent parse calls and:
      - Return a non-empty DriverInfo with grammar_sha/version populated.
      - Implement parse_to_events(file) as a generator; on irrecoverable error,
        raise ParserError (or Exception) rather than yielding partial, misleading streams.
    """

    def info(self) -> DriverInfo:
        raise NotImplementedError

    def parse_to_events(self, file: FileMeta) -> Iterator[CstEvent]:
        raise NotImplementedError


# ==============================================================================
# Registry config and output stream
# ==============================================================================


@dataclass(frozen=True)
class ParseConfig:
    """
    Orchestration-level controls. Separate from DiscoveryConfig.
    """
    per_file_timeout_sec: float = 8.0
    max_workers: int = 4
    enable_langs: frozenset[Language] = frozenset(
        {Language.PY, Language.JS, Language.TS, Language.JSX, Language.TSX}
    )
    validate_events: bool = True  # run fast invariants on events


@dataclass
class ParseStream:
    """
    Output from the registry for a single input file.
    """
    file: FileMeta
    driver: Optional[DriverInfo]
    events: Optional[Iterator[CstEvent]]
    elapsed_s: float
    ok: bool
    error: Optional[str] = None


# ==============================================================================
# Registry
# ==============================================================================


class ParserRegistry:
    """
    Owns language → driver bindings and orchestrates concurrent parsing with
    deterministic output order, budgeting, metrics, and robust error/timeout handling.
    """

    def __init__(
        self,
        drivers: dict[Language, ParserDriver],
        cfg: Optional[ParseConfig] = None,
        anomaly_sink: Optional[AnomalySink] = None,
        metrics: Optional[Metrics] = None,
    ) -> None:
        self._drivers = dict(drivers)
        self._cfg = cfg or ParseConfig()
        self._sink = anomaly_sink or AnomalySink()
        self._metrics = metrics or Metrics()

        # Validate driver metadata up front (enhanced interface validation)
        for lang, drv in self._drivers.items():
            info = drv.info()
            if not info.grammar_name or not info.grammar_sha or not info.version:
                raise ValueError(f"Driver {lang} returned incomplete DriverInfo")
            if info.language != lang:
                raise ValueError(f"Driver {lang} reports mismatched language: {info.language}")

    # ---- public API -----------------------------------------------------------

    def parse_files(self, files: Iterable[FileMeta]) -> Iterator[ParseStream]:
        """
        Deterministic, order-preserving concurrent parsing using a sliding window.

        Guarantees:
          - Yields results in the exact order of the input iterable.
          - Every timeout/error result carries the real FileMeta (no placeholders).
        """
        max_workers = max(1, self._cfg.max_workers)

        with futures.ThreadPoolExecutor(
            max_workers=max_workers, thread_name_prefix="provis-parse"
        ) as pool:
            # Sliding window state
            pending: dict[int, futures.Future[ParseStream]] = {}
            fm_by_idx: dict[int, FileMeta] = {}
            driver_by_idx: dict[int, Optional[DriverInfo]] = {}

            # Enumerate inputs to lock-in deterministic indices
            it = enumerate(files)
            next_submit = 0
            next_yield = 0

            # Helper to submit a task and capture fm/driver context
            def _submit(i: int, fm: FileMeta) -> None:
                drv, info = self._resolve_driver(fm)
                driver_by_idx[i] = info  # may be None if unsupported/unknown
                fm_by_idx[i] = fm
                if drv is None:
                    # Synthesize a no-driver result synchronously via a completed future
                    pending[i] = pool.submit(self._no_driver_result, fm, info)
                else:
                    pending[i] = pool.submit(self._parse_one, drv, info, fm)

                self._metrics.inc("parser_registry_submitted_total")

            # Fill initial window
            while len(pending) < max_workers:
                try:
                    i, fm = next(it)
                except StopIteration:
                    break
                _submit(i, fm)
                next_submit = i + 1

            # Drain in strict input order with a sliding window
            while True:
                # If nothing pending and no more input → done
                if not pending and next_submit == next_yield:
                    break

                # Ensure the next index to yield is submitted (if more inputs exist)
                while (next_yield not in pending) and (len(pending) < max_workers):
                    try:
                        i, fm = next(it)
                    except StopIteration:
                        break
                    _submit(i, fm)
                    next_submit = i + 1

                # If still missing the required future (shouldn't happen), wait briefly and retry
                if next_yield not in pending:
                    time.sleep(0.002)
                    continue

                fut = pending[next_yield]
                fm = fm_by_idx[next_yield]
                info = driver_by_idx[next_yield]

                # Non-blocking poll loop with wall-time timeout
                start_wait = time.perf_counter()
                while not fut.done():
                    elapsed = time.perf_counter() - start_wait
                    if elapsed >= self._cfg.per_file_timeout_sec:
                        # Record timeout WITH real file info and driver context
                        self._sink.emit(
                            Anomaly(
                                path=fm.path,
                                blob_sha=fm.blob_sha,
                                kind=AnomalyKind.TIMEOUT,
                                severity=Severity.ERROR,
                                detail=f"Parser exceeded timeout ({self._cfg.per_file_timeout_sec}s)",
                            )
                        )
                        self._metrics.inc("parser_timeouts_total")
                        # We don’t block on thread cancellation (not reliable); we proceed.
                        ps = ParseStream(
                            file=fm,
                            driver=info,
                            events=None,
                            elapsed_s=self._cfg.per_file_timeout_sec,
                            ok=False,
                            error="timeout",
                        )
                        # Emit in-order
                        del pending[next_yield]
                        del fm_by_idx[next_yield]
                        del driver_by_idx[next_yield]
                        self._metrics.inc("parser_registry_completed_total")
                        yield ps
                        next_yield += 1
                        break
                    time.sleep(0.005)
                else:
                    # Future finished
                    try:
                        ps = fut.result()
                    finally:
                        del pending[next_yield]
                        del fm_by_idx[next_yield]
                        del driver_by_idx[next_yield]
                    self._metrics.inc("parser_registry_completed_total")
                    yield ps
                    next_yield += 1

                # Refill window after each yield
                while len(pending) < max_workers:
                    try:
                        i, fm = next(it)
                    except StopIteration:
                        break
                    _submit(i, fm)
                    next_submit = i + 1

    # ---- internals ------------------------------------------------------------

    def _resolve_driver(self, fm: FileMeta) -> tuple[Optional[ParserDriver], Optional[DriverInfo]]:
        """
        Return (driver, driver_info) or (None, None) if unsupported/unknown/disabled.
        """
        lang = fm.lang
        if (lang not in self._cfg.enable_langs) or (lang not in self._drivers):
            # Unknown or disabled: record anomaly now (explicit, deterministic)
            if lang is Language.UNKNOWN:
                self._sink.emit(
                    Anomaly(
                        path=fm.path,
                        blob_sha=fm.blob_sha,
                        kind=AnomalyKind.LANG_UNKNOWN,
                        severity=Severity.INFO,
                        detail="No parser driver for unknown language",
                    )
                )
                self._metrics.inc("parser_lang_unknown_total")
            else:
                self._sink.emit(
                    Anomaly(
                        path=fm.path,
                        blob_sha=fm.blob_sha,
                        kind=AnomalyKind.SKIPPED_BY_RULE,
                        severity=Severity.INFO,
                        detail=f"Language {lang.value} disabled or no driver available",
                    )
                )
                self._metrics.inc(f"parser_lang_{lang.value}_disabled_total")
            return None, None

        drv = self._drivers[lang]
        info = drv.info()
        return drv, info

    def _no_driver_result(self, fm: FileMeta, info: Optional[DriverInfo]) -> ParseStream:
        return ParseStream(file=fm, driver=info, events=None, elapsed_s=0.0, ok=False, error="no-driver")

    def _parse_one(self, drv: ParserDriver, info: DriverInfo, fm: FileMeta) -> ParseStream:
        """
        Parse a single file via its language driver and wrap events with fast invariants.
        """
        start = time.perf_counter()
        try:
            events = drv.parse_to_events(fm)
            if self._cfg.validate_events:
                events = self._validated_event_stream(events, fm, info)
            elapsed = time.perf_counter() - start
            self._metrics.inc(f"parser_files_ok_total_{info.language.value}")
            self._metrics.observe("parser_parse_seconds", elapsed)
            return ParseStream(file=fm, driver=info, events=events, elapsed_s=elapsed, ok=True)
        except ParserError as e:
            elapsed = time.perf_counter() - start
            self._metrics.inc(f"parser_files_failed_total_{info.language.value}")
            self._metrics.observe("parser_parse_seconds", elapsed)
            detail = f"{e.code}: {e.message}"
            if e.detail:
                detail += f" | {e.detail}"
            self._sink.emit(
                Anomaly(
                    path=fm.path,
                    blob_sha=fm.blob_sha,
                    kind=AnomalyKind.PARSE_FAILED,
                    severity=Severity.ERROR,
                    detail=detail,
                    span=((e.byte_start or 0), (e.byte_end or 0)) if (e.byte_start is not None and e.byte_end is not None) else None,
                )
            )
            return ParseStream(file=fm, driver=info, events=None, elapsed_s=elapsed, ok=False, error=detail)
        except Exception as e:
            elapsed = time.perf_counter() - start
            self._metrics.inc(f"parser_files_failed_total_{info.language.value}")
            self._metrics.observe("parser_parse_seconds", elapsed)
            self._sink.emit(
                Anomaly(
                    path=fm.path,
                    blob_sha=fm.blob_sha,
                    kind=AnomalyKind.PARSE_FAILED,
                    severity=Severity.ERROR,
                    detail=f"{type(e).__name__}: {e}",
                )
            )
            return ParseStream(file=fm, driver=info, events=None, elapsed_s=elapsed, ok=False, error=str(e))

    # ---- validation wrapper for events ---------------------------------------

    def _validated_event_stream(
        self,
        events: Iterator[CstEvent],
        fm: FileMeta,
        info: DriverInfo,
    ) -> Iterator[CstEvent]:
        """
        Fast, zero-alloc checks on event invariants.
        We avoid enforcing total monotonicity (drivers may emit EXIT events that move
        backward in text), but we guarantee sane ranges and non-negative indices.
        """
        for ev in events:
            if ev.byte_start < 0 or ev.byte_end < 0 or ev.line_start < 0 or ev.line_end < 0:
                raise ParserError(
                    code="INVALID_SPAN_NEGATIVE",
                    message="Negative span indices from driver",
                    detail=f"type={ev.type} byte=({ev.byte_start},{ev.byte_end}) line=({ev.line_start},{ev.line_end})",
                )
            if ev.byte_end < ev.byte_start or ev.line_end < ev.line_start:
                raise ParserError(
                    code="INVALID_SPAN_ORDER",
                    message="End before start in span from driver",
                    detail=f"type={ev.type} byte=({ev.byte_start},{ev.byte_end}) line=({ev.line_start},{ev.line_end})",
                )
            if not ev.type:
                raise ParserError(code="MISSING_NODE_TYPE", message="Empty node/token type")
            yield ev
