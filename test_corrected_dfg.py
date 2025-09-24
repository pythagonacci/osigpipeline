#!/usr/bin/env python3
"""
Test script to validate the corrected DFG and Symbol builder implementation.
"""

import tempfile
from pathlib import Path
from src.provis.ucg.api import build_ucg_for_files, Step1Config
from src.provis.ucg.discovery import FileMeta, Language
import hashlib

def create_test_files():
    """Create test files with various assignment patterns."""
    test_dir = Path("test_corrected_files")
    test_dir.mkdir(exist_ok=True)
    
    # Test file 1: Simple assignments and aliases
    test1_content = '''def test_function():
    x = 42
    y = x
    z = y + 1
    return z
'''
    
    # Test file 2: Multiple assignments
    test2_content = '''def complex_function():
    a, b = 1, 2
    c = a + b
    d = c * 2
    return d
'''
    
    # Test file 3: Function calls and complex expressions
    test3_content = '''def method_calls():
    result = get_data()
    processed = result.process()
    return processed.value
'''
    
    files = []
    for i, content in enumerate([test1_content, test2_content, test3_content], 1):
        file_path = test_dir / f"test_{i}.py"
        file_path.write_text(content)
        
        # Create FileMeta
        blob_sha = hashlib.blake2b(content.encode()).hexdigest()
        fm = FileMeta(
            path=str(file_path),
            real_path=str(file_path.absolute()),
            blob_sha=blob_sha,
            size_bytes=len(content.encode()),
            mtime_ns=0,
            run_id="test-run",
            config_hash="test-config",
            is_text=True,
            encoding="utf-8",
            encoding_confidence=1.0,
            lang=Language.PY,
            flags=set()
        )
        files.append(fm)
    
    return files

def validate_results(summary):
    """Validate the results against expected criteria."""
    print("=== VALIDATION RESULTS ===")
    
    # Basic checks
    print(f"Files processed: {summary.files_parsed}/{summary.files_total}")
    print(f"DFG nodes: {summary.dfg_nodes_rows}")
    print(f"DFG edges: {summary.dfg_edges_rows}")
    print(f"Symbols: {summary.symbols_rows}")
    print(f"Aliases: {summary.aliases_rows}")
    
    # Validation criteria
    criteria_passed = 0
    total_criteria = 0
    
    # AC 1: Basic functionality
    total_criteria += 1
    if summary.files_parsed > 0 and summary.dfg_nodes_rows > 0:
        print("✅ AC_1_basic_functionality: PASS")
        criteria_passed += 1
    else:
        print("❌ AC_1_basic_functionality: FAIL")
    
    # AC 2: Assignment detection
    total_criteria += 1
    if summary.dfg_nodes_rows >= 6:  # Should have multiple VAR_DEF and VAR_USE nodes
        print("✅ AC_2_assignment_detection: PASS")
        criteria_passed += 1
    else:
        print("❌ AC_2_assignment_detection: FAIL")
    
    # AC 3: Alias detection
    total_criteria += 1
    if summary.aliases_rows >= 1:  # Should detect at least one alias
        print("✅ AC_3_alias_detection: PASS")
        criteria_passed += 1
    else:
        print("❌ AC_3_alias_detection: FAIL")
    
    # AC 4: Edge generation
    total_criteria += 1
    if summary.dfg_edges_rows > 0:  # Should have DEF_USE edges
        print("✅ AC_4_edge_generation: PASS")
        criteria_passed += 1
    else:
        print("❌ AC_4_edge_generation: FAIL")
    
    success_rate = (criteria_passed / total_criteria) * 100
    print(f"\n=== SUMMARY ===")
    print(f"Criteria passed: {criteria_passed}/{total_criteria} ({success_rate:.1f}%)")
    
    if success_rate >= 75:
        print("🎉 CORRECTED IMPLEMENTATION SUCCESSFUL!")
        return True
    else:
        print("❌ CORRECTED IMPLEMENTATION NEEDS MORE WORK")
        return False

def main():
    """Run the validation test."""
    print("Testing corrected DFG and Symbol builder implementation...")
    
    # Create test files
    test_files = create_test_files()
    print(f"Created {len(test_files)} test files")
    
    # Run the pipeline
    output_dir = Path("test_corrected_output")
    config = Step1Config(
        enable_cfg=True,
        enable_dfg=True,
        enable_symbols=True,
        enable_effects=False
    )
    
    try:
        summary = build_ucg_for_files(test_files, output_dir, cfg=config)
        success = validate_results(summary)
        
        # Cleanup
        import shutil
        shutil.rmtree("test_corrected_files", ignore_errors=True)
        shutil.rmtree("test_corrected_output", ignore_errors=True)
        
        return success
        
    except Exception as e:
        print(f"❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)
