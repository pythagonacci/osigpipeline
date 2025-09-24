#!/usr/bin/env python3
"""
Test script to validate the corrected DFG builder with stack-based CST walker.
This tests the new prescriptive algorithm that properly interprets the syntactic tree structure.
"""

import sys
from pathlib import Path
from tempfile import TemporaryDirectory

# Add the project root to the Python path
sys.path.insert(0, str(Path(__file__).parent))

from src.provis.ucg.api import build_ucg_for_files, Step1Config
from src.provis.ucg.discovery import FileMeta, Language, DiscoveryConfig, iter_discovered_files
from src.provis.ucg.dfg import DfgBuilder, DfgConfig


def create_test_files():
    """Create test files with various code patterns."""
    test_files = {}
    
    # Test 1: Simple assignment with alias
    test_files["test_simple.py"] = """
def test_function():
    old_var = 42
    new_var = old_var
    return new_var
"""
    
    # Test 2: Multiple assignments
    test_files["test_multiple.py"] = """
def test_multiple():
    x = 1
    y = x + 1
    z = y * 2
    return z
"""
    
    # Test 3: Function with parameters
    test_files["test_params.py"] = """
def test_params(a, b):
    result = a + b
    return result
"""
    
    # Test 4: Complex assignment
    test_files["test_complex.py"] = """
def test_complex():
    data = {"key": "value"}
    processed = data["key"]
    return processed
"""
    
    return test_files


def run_test():
    """Run the corrected DFG builder test."""
    print("🧪 Testing Corrected DFG Builder with Stack-Based CST Walker")
    print("=" * 60)
    
    # Create test files
    test_files = create_test_files()
    
    with TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        
        # Write test files
        for filename, content in test_files.items():
            file_path = temp_path / filename
            file_path.write_text(content.strip())
        
        # Create FileMeta objects
        files = []
        for filename in test_files.keys():
            file_path = temp_path / filename
            fm = FileMeta(
                path=str(file_path),
                real_path=str(file_path),
                blob_sha="test_sha",
                size_bytes=file_path.stat().st_size,
                mtime_ns=file_path.stat().st_mtime_ns * 1_000_000_000,
                run_id="test_run",
                config_hash="test_config",
                is_text=True,
                encoding="utf-8",
                encoding_confidence=1.0,
                lang=Language.PY,
                flags=set()
            )
            files.append(fm)
        
        # Run the pipeline
        output_dir = temp_path / "output"
        output_dir.mkdir()
        
        config = Step1Config(
            enable_cfg=False,
            enable_dfg=True,
            enable_symbols=True,
            enable_effects=False
        )
        
        print(f"📁 Processing {len(files)} test files...")
        summary = build_ucg_for_files(files, output_dir, cfg=config)
        
        # Print results
        print(f"\n📊 Pipeline Results:")
        print(f"  Files processed: {summary.files_parsed}/{summary.files_total}")
        print(f"  DFG nodes: {summary.dfg_nodes_rows}")
        print(f"  DFG edges: {summary.dfg_edges_rows}")
        print(f"  Symbols: {summary.symbols_rows}")
        print(f"  Aliases: {summary.aliases_rows}")
        print(f"  Wall time: {summary.wall_ms}ms")
        
        # Validation criteria
        print(f"\n✅ Validation Results:")
        
        # AC_1: Basic functionality
        ac_1_basic = (summary.dfg_nodes_rows > 0 and summary.dfg_edges_rows > 0)
        print(f"  AC_1_basic_functionality: {'✅ PASS' if ac_1_basic else '❌ FAIL'}")
        
        # AC_2: Assignment detection
        ac_2_assignment = summary.dfg_nodes_rows >= 8  # Should have PARAM, VAR_DEF, VAR_USE nodes
        print(f"  AC_2_assignment_detection: {'✅ PASS' if ac_2_assignment else '❌ FAIL'}")
        
        # AC_3: Alias detection
        ac_3_alias = summary.aliases_rows > 0
        print(f"  AC_3_alias_detection: {'✅ PASS' if ac_3_alias else '❌ FAIL'}")
        
        # AC_4: Edge generation
        ac_4_edge = summary.dfg_edges_rows > 0
        print(f"  AC_4_edge_generation: {'✅ PASS' if ac_4_edge else '❌ FAIL'}")
        
        # Overall success
        all_passing = all([ac_1_basic, ac_2_assignment, ac_3_alias, ac_4_edge])
        success_rate = sum([ac_1_basic, ac_2_assignment, ac_3_alias, ac_4_edge]) / 4 * 100
        
        print(f"\n🎯 Overall Results:")
        print(f"  Success Rate: {success_rate:.0f}% ({sum([ac_1_basic, ac_2_assignment, ac_3_alias, ac_4_edge])}/4 criteria)")
        
        if all_passing:
            print(f"  Status: 🎉 ALL TESTS PASSING!")
        else:
            print(f"  Status: ⚠️  Some tests failing")
        
        return all_passing


if __name__ == "__main__":
    success = run_test()
    sys.exit(0 if success else 1)
