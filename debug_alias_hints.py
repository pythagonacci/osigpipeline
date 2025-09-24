#!/usr/bin/env python3
"""
Debug script to investigate alias hint generation and processing.
"""

import tempfile
from pathlib import Path
from src.provis.ucg.dfg import build_dfg, DfgConfig
from src.provis.ucg.discovery import FileMeta, Language, AnomalySink
from src.provis.ucg.symbols import build_symbols, SymbolsConfig
from src.provis.ucg.parser_registry import DriverInfo
import hashlib

def test_alias_hints():
    """Test alias hint generation and processing."""
    
    # Create a simple test file with a clear alias
    test_content = '''def test_function():
    old_var = 42
    new_var = old_var
    return new_var
'''
    
    # Create FileMeta
    blob_sha = hashlib.blake2b(test_content.encode()).hexdigest()
    test_file = Path("debug_test.py")
    test_file.write_text(test_content)
    
    fm = FileMeta(
        path=str(test_file),
        real_path=str(test_file.absolute()),
        blob_sha=blob_sha,
        size_bytes=len(test_content.encode()),
        mtime_ns=0,
        run_id="test-run",
        config_hash="test-config",
        is_text=True,
        encoding="utf-8",
        encoding_confidence=1.0,
        lang=Language.PY,
        flags=set()
    )
    
    # Parse the file to get events
    from src.provis.ucg.python_driver import PythonLibCstDriver
    driver = PythonLibCstDriver()
    ps = driver.parse(fm)
    
    if ps.events is None:
        print("❌ Failed to parse file")
        return
        
    events = list(ps.events)
    print(f"Parsed {len(events)} events")
    
    sink = AnomalySink()
    
    # Test DFG builder
    print("\n=== DFG BUILDER TEST ===")
    dfg_results = list(build_dfg(fm, ps.driver, events, sink, DfgConfig()))
    
    alias_hints = []
    dfg_items = []
    for item_kind, item_data in dfg_results:
        if item_kind == "alias_hint":
            alias_hints.append(item_data)
            print(f"✅ Alias hint found: {item_data}")
        else:
            dfg_items.append((item_kind, item_data))
    
    print(f"DFG items: {len(dfg_items)}")
    print(f"Alias hints: {len(alias_hints)}")
    
    # Test Symbols builder
    print("\n=== SYMBOLS BUILDER TEST ===")
    symbols_results = list(build_symbols(fm, ps.driver, events, sink, SymbolsConfig(), alias_hints=alias_hints))
    
    symbols = []
    aliases = []
    for item_kind, item_data in symbols_results:
        if item_kind == "symbol":
            symbols.append(item_data)
            print(f"Symbol: {item_data.name} in scope {item_data.scope_id}")
        elif item_kind == "alias":
            aliases.append(item_data)
            print(f"✅ Alias created: {item_data.alias_kind} - {item_data.alias_name}")
    
    print(f"Symbols: {len(symbols)}")
    print(f"Aliases: {len(aliases)}")
    
    # Debug: Check what symbols are available for the alias hint
    if alias_hints:
        hint = alias_hints[0]
        print(f"\nDebug: Looking for symbols with scope_id: {hint['scope_id']}")
        print(f"Looking for: lhs_name='{hint['lhs_name']}', rhs_name='{hint['rhs_name']}'")
        
        for symbol in symbols:
            if symbol.name in [hint['lhs_name'], hint['rhs_name']]:
                print(f"  Found symbol: {symbol.name} in scope {symbol.scope_id} (matches: {symbol.scope_id == hint['scope_id']})")
        
        # Debug: Show all function symbols to see what names are being used
        print(f"\nDebug: All function symbols:")
        for symbol in symbols:
            if symbol.kind.value == "function":
                print(f"  Function symbol: {symbol.name} in scope {symbol.scope_id}")
    
    # Cleanup
    test_file.unlink()
    
    return len(alias_hints) > 0 and len(aliases) > 0

if __name__ == "__main__":
    success = test_alias_hints()
    print(f"\n{'✅ SUCCESS' if success else '❌ FAILED'}")
