#!/usr/bin/env python3
"""
Debug script to test parser drivers directly.
"""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from provis.ucg.discovery import FileMeta, Language
from provis.ucg.python_driver import PythonLibCstDriver
from provis.ucg.ts_driver import TSTreeSitterDriver


def test_python_driver():
    print("Testing Python driver...")
    
    # Create a test file metadata
    test_file = FileMeta(
        path="test.py",
        real_path="/Users/amnaahmad/osigfin/osigpipeline/test_repo/hello.py",
        blob_sha="test123",
        size_bytes=1197,
        mtime_ns=1234567890,
        run_id="test_run",
        config_hash="test_config",
        is_text=True,
        encoding="utf-8",
        encoding_confidence=0.95,
        lang=Language.PY,
        flags=0
    )
    
    driver = PythonLibCstDriver()
    
    try:
        ps = driver.parse(test_file)
        print(f"✅ Python driver created parse stream: {ps}")
        
        # Try to get some events
        events = list(ps.events)
        print(f"✅ Got {len(events)} events from Python file")
        
        if events:
            print("Sample events:")
            for i, ev in enumerate(events[:5]):
                print(f"  {i+1}. {ev.kind} {ev.type} at {ev.byte_start}-{ev.byte_end}")
        
    except Exception as e:
        print(f"❌ Python driver failed: {e}")
        import traceback
        traceback.print_exc()


def test_ts_driver():
    print("\nTesting TypeScript driver...")
    
    # Create a test file metadata
    test_file = FileMeta(
        path="test.js",
        real_path="/Users/amnaahmad/osigfin/osigpipeline/test_repo/app.js",
        blob_sha="test123",
        size_bytes=1015,
        mtime_ns=1234567890,
        run_id="test_run",
        config_hash="test_config",
        is_text=True,
        encoding="utf-8",
        encoding_confidence=0.95,
        lang=Language.JS,
        flags=0
    )
    
    driver = TSTreeSitterDriver(Language.JS)
    
    try:
        ps = driver.parse(test_file)
        print(f"✅ TypeScript driver created parse stream: {ps}")
        
        # Try to get some events
        events = list(ps.events)
        print(f"✅ Got {len(events)} events from JavaScript file")
        
        if events:
            print("Sample events:")
            for i, ev in enumerate(events[:5]):
                print(f"  {i+1}. {ev.kind} {ev.type} at {ev.byte_start}-{ev.byte_end}")
        
    except Exception as e:
        print(f"❌ TypeScript driver failed: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    test_python_driver()
    test_ts_driver()
