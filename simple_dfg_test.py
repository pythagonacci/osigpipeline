#!/usr/bin/env python3
"""
Simple DFG test without full pipeline
"""

import sys
from pathlib import Path

# Add the project root to the Python path
sys.path.insert(0, str(Path(__file__).parent))

from src.provis.ucg.dfg import build_dfg
from src.provis.ucg.discovery import FileMeta, Language
from src.provis.ucg.python_driver import PythonLibCstDriver


def create_file_meta(file_path: Path) -> FileMeta:
    """Create FileMeta object for a test file."""
    return FileMeta(
        path=str(file_path),
        real_path=str(file_path),
        blob_sha=f"test_sha_{file_path.name}",
        size_bytes=file_path.stat().st_size,
        mtime_ns=file_path.stat().st_mtime_ns * 1_000_000_000,
        run_id="qa_test_run",
        config_hash="qa_test_config",
        is_text=True,
        encoding="utf-8",
        encoding_confidence=1.0,
        lang=Language.PY,
        flags=set()
    )


def test_dfg_builder():
    """Test the DFG builder directly."""
    
    # Test SSA versioning
    test_file = Path("test_repo/test_ssa.py")
    fm = create_file_meta(test_file)
    
    # Parse the file
    driver = PythonLibCstDriver()
    ps = driver.parse(fm)
    events = list(ps.events) if ps.events else []
    
    print(f"Parsed {len(events)} events from {test_file.name}")
    
    # Run DFG builder
    results = []
    alias_hints = []
    
    for item_kind, item_data in build_dfg(fm, ps.driver, events, None):
        results.append((item_kind, item_data))
        if item_kind == 'alias_hint':
            alias_hints.append(item_data)
    
    print(f"DFG Results: {len(results)} items")
    print(f"Alias Hints: {len(alias_hints)} items")
    
    # Print nodes
    for item_kind, item_data in results:
        if item_kind == 'dfg_node':
            print(f"  {item_data.kind}: {item_data.name} (version={item_data.version})")
        elif item_kind == 'dfg_edge':
            print(f"  {item_data.kind}: {item_data.src_id} -> {item_data.dst_id}")
    
    return results, alias_hints


if __name__ == "__main__":
    test_dfg_builder()
