#!/usr/bin/env python3
"""
Debug script for the corrected DFG builder to understand why alias hints aren't being generated.
"""

import sys
from pathlib import Path

# Add the project root to the Python path
sys.path.insert(0, str(Path(__file__).parent))

from src.provis.ucg.discovery import FileMeta, Language
from src.provis.ucg.dfg import DfgBuilder, DfgConfig
from src.provis.ucg.parser_registry import CstEvent, CstEventKind
from src.provis.ucg.python_driver import PythonLibCstDriver


def debug_dfg():
    """Debug the DFG builder to understand assignment processing."""
    print("🔍 Debugging Corrected DFG Builder")
    print("=" * 40)
    
    # Create a simple test file
    test_code = """
def test_function():
    old_var = 42
    new_var = old_var
    return new_var
"""
    
    # Write test file
    test_file = Path("debug_test.py")
    test_file.write_text(test_code.strip())
    
    try:
        # Create FileMeta
        fm = FileMeta(
            path=str(test_file),
            real_path=str(test_file),
            blob_sha="debug_sha",
            size_bytes=test_file.stat().st_size,
            mtime_ns=test_file.stat().st_mtime_ns * 1_000_000_000,
            run_id="debug_run",
            config_hash="debug_config",
            is_text=True,
            encoding="utf-8",
            encoding_confidence=1.0,
            lang=Language.PY,
            flags=set()
        )
        
        # Parse the file
        driver = PythonLibCstDriver()
        ps = driver.parse(fm)
        
        if ps is None:
            print("❌ Failed to parse file")
            return
        
        # Get events
        events = list(ps.events) if ps.events else []
        print(f"📋 Total events: {len(events)}")
        
        # Analyze events
        print("\n🔍 Event Analysis:")
        assignment_events = []
        token_events = []
        
        for i, ev in enumerate(events):
            if ev.kind == CstEventKind.ENTER and "Assign" in ev.type:
                assignment_events.append((i, ev))
                print(f"  Event {i}: ENTER {ev.type} at bytes {ev.byte_start}-{ev.byte_end}")
            elif ev.kind == CstEventKind.TOKEN:
                token_events.append((i, ev))
                if ev.type in ["Name", "Integer"]:
                    print(f"  Event {i}: TOKEN {ev.type} '{ev}' at bytes {ev.byte_start}-{ev.byte_end}")
        
        print(f"\n📊 Found {len(assignment_events)} assignment events")
        print(f"📊 Found {len(token_events)} token events")
        
        # Test the DFG builder
        print("\n🧪 Testing DFG Builder:")
        
        class MockSink:
            def emit(self, anomaly):
                print(f"⚠️  Anomaly: {anomaly}")
        
        builder = DfgBuilder(fm, ps.driver, events, MockSink(), DfgConfig())
        
        results = []
        alias_hints = []
        
        for item_kind, item_data in builder.build():
            results.append((item_kind, item_data))
            if item_kind == "alias_hint":
                alias_hints.append(item_data)
        
        print(f"📊 DFG Results:")
        print(f"  Total results: {len(results)}")
        print(f"  Alias hints: {len(alias_hints)}")
        
        # Show results by type
        result_types = {}
        for item_kind, item_data in results:
            result_types[item_kind] = result_types.get(item_kind, 0) + 1
        
        for result_type, count in result_types.items():
            print(f"  {result_type}: {count}")
        
        # Show alias hints
        if alias_hints:
            print(f"\n🎯 Alias Hints:")
            for hint in alias_hints:
                print(f"  {hint}")
        else:
            print(f"\n❌ No alias hints generated")
            
            # Debug assignment processing
            print(f"\n🔍 Debugging Assignment Processing:")
            for i, (event_idx, ev) in enumerate(assignment_events):
                print(f"  Assignment {i+1} at event {event_idx}:")
                print(f"    Type: {ev.type}")
                print(f"    Bytes: {ev.byte_start}-{ev.byte_end}")
                
                # Find tokens within this assignment
                assignment_tokens = []
                for j, token_ev in enumerate(events[event_idx:event_idx+20]):  # Look ahead 20 events
                    if (token_ev.kind == CstEventKind.TOKEN and 
                        ev.byte_start <= token_ev.byte_start < ev.byte_end):
                        assignment_tokens.append((event_idx + j, token_ev))
                
                print(f"    Tokens within assignment: {len(assignment_tokens)}")
                for token_idx, token_ev in assignment_tokens:
                    token_text = builder._safe_token_text(token_ev, fm)
                    print(f"      Event {token_idx}: {token_ev.type} '{token_text}'")
                    
                    # Check if it's an assignment operator
                    if builder._is_assignment_operator_token(token_ev):
                        print(f"        ✅ This is an assignment operator!")
        
    finally:
        # Clean up
        if test_file.exists():
            test_file.unlink()


if __name__ == "__main__":
    debug_dfg()
