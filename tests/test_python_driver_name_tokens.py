from __future__ import annotations

import hashlib
from pathlib import Path

import sys

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from provis.ucg.discovery import FileMeta, Language
from provis.ucg.parser_registry import CstEventKind
from provis.ucg.python_driver import PythonLibCstDriver


def _file_meta_for(path: Path, repo_root: Path) -> tuple[FileMeta, bytes]:
    raw = path.read_bytes()
    fm = FileMeta(
        path=str(path.relative_to(repo_root)),
        real_path=str(path.resolve()),
        blob_sha=hashlib.blake2b(raw, digest_size=20).hexdigest(),
        size_bytes=len(raw),
        mtime_ns=0,
        run_id="test",
        config_hash="test-config",
        is_text=True,
        encoding="utf-8",
        encoding_confidence=1.0,
        lang=Language.PY,
        flags=set(),
    )
    return fm, raw


def test_python_driver_emits_name_tokens_for_declarations() -> None:
    repo_root = REPO_ROOT
    source_path = repo_root / "test_repo" / "hello.py"
    file_meta, raw = _file_meta_for(source_path, repo_root)

    driver = PythonLibCstDriver()
    events = list(driver.parse_to_events(file_meta))

    name_tokens = {
        raw[ev.byte_start:ev.byte_end].decode(file_meta.encoding or "utf-8", errors="replace")
        for ev in events
        if ev.kind == CstEventKind.TOKEN and ev.type == "Name"
    }

    expected = {"greet", "process_items", "__init__", "add", "multiply", "main", "Calculator"}
    missing = expected.difference(name_tokens)
    assert not missing, f"Missing name tokens for: {sorted(missing)}"
