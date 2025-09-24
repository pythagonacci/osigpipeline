#!/usr/bin/env python3
"""
QA Validation Suite for DfgBuilder
Comprehensive testing of the stateful, CST-aware algorithm against various code patterns.
"""

import sys
import pandas as pd
from pathlib import Path
from tempfile import TemporaryDirectory
import os

# Add the project root to the Python path
sys.path.insert(0, str(Path(__file__).parent))

from src.provis.ucg.api import build_ucg_for_files, Step1Config
from src.provis.ucg.discovery import FileMeta, Language, iter_discovered_files


class QAValidator:
    """QA Validator for DfgBuilder testing."""
    
    def __init__(self):
        self.test_results = []
        self.output_dir = None
        
    def create_test_file(self, test_dir: Path, filename: str, code: str) -> Path:
        """Create a test file with the given code."""
        test_file = test_dir / filename
        test_file.write_text(code.strip())
        return test_file
    
    def create_file_meta(self, file_path: Path) -> FileMeta:
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
    
    def run_pipeline(self, test_files: list[Path], test_name: str) -> dict:
        """Run the Step 1 pipeline on test files."""
        print(f"\n🧪 Running {test_name}")
        print("=" * 50)
        
        # Create FileMeta objects
        files = [self.create_file_meta(f) for f in test_files]
        
        # Create output directory
        self.output_dir = Path(f"qa_output_{test_name}")
        self.output_dir.mkdir(exist_ok=True)
        
        # Run pipeline
        config = Step1Config(
            enable_cfg=False,
            enable_dfg=True,
            enable_symbols=True,
            enable_effects=False
        )
        
        summary = build_ucg_for_files(files, self.output_dir, cfg=config)
        
        print(f"📊 Pipeline Results:")
        print(f"  Files processed: {summary.files_parsed}/{summary.files_total}")
        print(f"  DFG nodes: {summary.dfg_nodes_rows}")
        print(f"  DFG edges: {summary.dfg_edges_rows}")
        print(f"  Symbols: {summary.symbols_rows}")
        print(f"  Aliases: {summary.aliases_rows}")
        
        return summary
    
    def load_parquet_data(self) -> dict:
        """Load all parquet files from the output directory."""
        data = {}
        
        # Load DFG nodes
        dfg_nodes_dir = self.output_dir / "dfg_nodes"
        if dfg_nodes_dir.exists():
            dfg_nodes_files = list(dfg_nodes_dir.glob("*.parquet"))
            if dfg_nodes_files:
                data['dfg_nodes'] = pd.read_parquet(dfg_nodes_files[0])
        
        # Load DFG edges
        dfg_edges_dir = self.output_dir / "dfg_edges"
        if dfg_edges_dir.exists():
            dfg_edges_files = list(dfg_edges_dir.glob("*.parquet"))
            if dfg_edges_files:
                data['dfg_edges'] = pd.read_parquet(dfg_edges_files[0])
        
        # Load symbols
        symbols_dir = self.output_dir / "symbols"
        if symbols_dir.exists():
            symbols_files = list(symbols_dir.glob("*.parquet"))
            if symbols_files:
                data['symbols'] = pd.read_parquet(symbols_files[0])
        
        # Load aliases
        aliases_dir = self.output_dir / "aliases"
        if aliases_dir.exists():
            aliases_files = list(aliases_dir.glob("*.parquet"))
            if aliases_files:
                data['aliases'] = pd.read_parquet(aliases_files[0])
        
        return data
    
    def log_result(self, test_name: str, assertion: str, result: str, details: str = ""):
        """Log a test result."""
        self.test_results.append({
            'test': test_name,
            'assertion': assertion,
            'result': result,
            'details': details
        })
        print(f"  {result} {assertion}")
        if details:
            print(f"    Details: {details}")
    
    def test_case_1_ssa_versioning(self):
        """Test Case 1: Simple Assignment & SSA Versioning"""
        with TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            # Create test file
            code = """
def ssa_test():
    x = 10      # Definition 1 (version 0)
    y = x       # Use 1 (version 0)
    x = 20      # Definition 2 (version 1)
    z = x       # Use 2 (version 1)
"""
            test_file = self.create_test_file(temp_path, "test_ssa.py", code)
            
            # Run pipeline
            self.run_pipeline([test_file], "ssa_versioning")
            
            # Load data
            data = self.load_parquet_data()
            
            if 'dfg_nodes' not in data or 'dfg_edges' not in data:
                self.log_result("SSA Versioning", "Data loading", "FAIL", "Missing DFG data")
                return
            
            dfg_nodes = data['dfg_nodes']
            dfg_edges = data['dfg_edges']
            
            # Filter for our test file
            test_nodes = dfg_nodes[dfg_nodes['path'].str.contains('test_ssa')]
            test_edges = dfg_edges[dfg_edges['path'].str.contains('test_ssa')]
            
            print(f"\n📋 DFG Nodes in test_ssa.py:")
            for _, row in test_nodes.iterrows():
                print(f"  {row['kind']}: {row['name']} (version={row.get('version', 'N/A')}) - {row['id']}")
            
            # Assertion 1: y VAR_DEF should connect to x VAR_DEF version 0
            y_def = test_nodes[(test_nodes['name'] == 'y') & (test_nodes['kind'] == 'var_def')]
            if len(y_def) > 0:
                y_use = test_nodes[(test_nodes['name'] == 'x') & (test_nodes['kind'] == 'var_use') & (test_nodes.get('version', 0) == 0)]
                if len(y_use) > 0:
                    def_use_edge = test_edges[
                        (test_edges['kind'] == 'def_use') &
                        (test_edges['dst_id'] == y_use.iloc[0]['id'])
                    ]
                    if len(def_use_edge) > 0:
                        src_id = def_use_edge.iloc[0]['src_id']
                        x_def_v0 = test_nodes[
                            (test_nodes['name'] == 'x') & 
                            (test_nodes['kind'] == 'var_def') & 
                            (test_nodes['version'] == 0)
                        ]
                        if len(x_def_v0) > 0 and src_id == x_def_v0.iloc[0]['id']:
                            self.log_result("SSA Versioning", "y connects to x version 0", "PASS")
                        else:
                            self.log_result("SSA Versioning", "y connects to x version 0", "FAIL", 
                                          f"Expected src_id {x_def_v0.iloc[0]['id'] if len(x_def_v0) > 0 else 'N/A'}, got {src_id}")
                    else:
                        self.log_result("SSA Versioning", "y connects to x version 0", "FAIL", "No DEF_USE edge found")
                else:
                    self.log_result("SSA Versioning", "y connects to x version 0", "FAIL", "No x VAR_USE version 0 found")
            else:
                self.log_result("SSA Versioning", "y connects to x version 0", "FAIL", "No y VAR_DEF found")
            
            # Assertion 2: z VAR_DEF should connect to x VAR_DEF version 1
            z_def = test_nodes[(test_nodes['name'] == 'z') & (test_nodes['kind'] == 'var_def')]
            if len(z_def) > 0:
                z_use = test_nodes[(test_nodes['name'] == 'x') & (test_nodes['kind'] == 'var_use') & (test_nodes.get('version', 0) == 1)]
                if len(z_use) > 0:
                    def_use_edge = test_edges[
                        (test_edges['kind'] == 'def_use') &
                        (test_edges['dst_id'] == z_use.iloc[0]['id'])
                    ]
                    if len(def_use_edge) > 0:
                        src_id = def_use_edge.iloc[0]['src_id']
                        x_def_v1 = test_nodes[
                            (test_nodes['name'] == 'x') & 
                            (test_nodes['kind'] == 'var_def') & 
                            (test_nodes['version'] == 1)
                        ]
                        if len(x_def_v1) > 0 and src_id == x_def_v1.iloc[0]['id']:
                            self.log_result("SSA Versioning", "z connects to x version 1", "PASS")
                        else:
                            self.log_result("SSA Versioning", "z connects to x version 1", "FAIL", 
                                          f"Expected src_id {x_def_v1.iloc[0]['id'] if len(x_def_v1) > 0 else 'N/A'}, got {src_id}")
                    else:
                        self.log_result("SSA Versioning", "z connects to x version 1", "FAIL", "No DEF_USE edge found")
                else:
                    self.log_result("SSA Versioning", "z connects to x version 1", "FAIL", "No x VAR_USE version 1 found")
            else:
                self.log_result("SSA Versioning", "z connects to x version 1", "FAIL", "No z VAR_DEF found")
    
    def test_case_2_function_params(self):
        """Test Case 2: Function Parameter Usage"""
        with TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            # Create test file
            code = """
def param_test(p1, p2):
    x = p1
    return p2
"""
            test_file = self.create_test_file(temp_path, "test_params.py", code)
            
            # Run pipeline
            self.run_pipeline([test_file], "function_params")
            
            # Load data
            data = self.load_parquet_data()
            
            if 'dfg_nodes' not in data or 'dfg_edges' not in data:
                self.log_result("Function Params", "Data loading", "FAIL", "Missing DFG data")
                return
            
            dfg_nodes = data['dfg_nodes']
            dfg_edges = data['dfg_edges']
            
            # Filter for our test file
            test_nodes = dfg_nodes[dfg_nodes['path'].str.contains('test_params')]
            test_edges = dfg_edges[dfg_edges['path'].str.contains('test_params')]
            
            print(f"\n📋 DFG Nodes in test_params.py:")
            for _, row in test_nodes.iterrows():
                print(f"  {row['kind']}: {row['name']} (version={row.get('version', 'N/A')}) - {row['id']}")
            
            # Assertion 1: x VAR_DEF should connect to p1 PARAM
            x_def = test_nodes[(test_nodes['name'] == 'x') & (test_nodes['kind'] == 'var_def')]
            if len(x_def) > 0:
                x_use = test_nodes[(test_nodes['name'] == 'p1') & (test_nodes['kind'] == 'var_use')]
                if len(x_use) > 0:
                    def_use_edge = test_edges[
                        (test_edges['kind'] == 'def_use') &
                        (test_edges['dst_id'] == x_use.iloc[0]['id'])
                    ]
                    if len(def_use_edge) > 0:
                        src_id = def_use_edge.iloc[0]['src_id']
                        p1_param = test_nodes[(test_nodes['name'] == 'p1') & (test_nodes['kind'] == 'param')]
                        if len(p1_param) > 0 and src_id == p1_param.iloc[0]['id']:
                            self.log_result("Function Params", "x connects to p1 param", "PASS")
                        else:
                            self.log_result("Function Params", "x connects to p1 param", "FAIL", 
                                          f"Expected p1 param src_id, got {src_id}")
                    else:
                        self.log_result("Function Params", "x connects to p1 param", "FAIL", "No DEF_USE edge found")
                else:
                    self.log_result("Function Params", "x connects to p1 param", "FAIL", "No p1 VAR_USE found")
            else:
                self.log_result("Function Params", "x connects to p1 param", "FAIL", "No x VAR_DEF found")
            
            # Assertion 2: return p2 should connect to p2 PARAM
            p2_use = test_nodes[(test_nodes['name'] == 'p2') & (test_nodes['kind'] == 'var_use')]
            if len(p2_use) > 0:
                def_use_edge = test_edges[
                    (test_edges['kind'] == 'def_use') &
                    (test_edges['dst_id'] == p2_use.iloc[0]['id'])
                ]
                if len(def_use_edge) > 0:
                    src_id = def_use_edge.iloc[0]['src_id']
                    p2_param = test_nodes[(test_nodes['name'] == 'p2') & (test_nodes['kind'] == 'param')]
                    if len(p2_param) > 0 and src_id == p2_param.iloc[0]['id']:
                        self.log_result("Function Params", "return p2 connects to p2 param", "PASS")
                    else:
                        self.log_result("Function Params", "return p2 connects to p2 param", "FAIL", 
                                      f"Expected p2 param src_id, got {src_id}")
                else:
                    self.log_result("Function Params", "return p2 connects to p2 param", "FAIL", "No DEF_USE edge found")
            else:
                self.log_result("Function Params", "return p2 connects to p2 param", "FAIL", "No p2 VAR_USE found")
    
    def test_case_3_scope_correctness(self):
        """Test Case 3: Scope Correctness"""
        with TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            # Create test file
            code = """
x = "global"  # Global scope var

def scope_test():
    x = "local"   # Local scope var
    y = x         # Use of local x

z = x             # Use of global x
"""
            test_file = self.create_test_file(temp_path, "test_scope.py", code)
            
            # Run pipeline
            self.run_pipeline([test_file], "scope_correctness")
            
            # Load data
            data = self.load_parquet_data()
            
            if 'dfg_nodes' not in data or 'dfg_edges' not in data:
                self.log_result("Scope Correctness", "Data loading", "FAIL", "Missing DFG data")
                return
            
            dfg_nodes = data['dfg_nodes']
            dfg_edges = data['dfg_edges']
            
            # Filter for our test file
            test_nodes = dfg_nodes[dfg_nodes['path'].str.contains('test_scope')]
            test_edges = dfg_edges[dfg_edges['path'].str.contains('test_scope')]
            
            print(f"\n📋 DFG Nodes in test_scope.py:")
            for _, row in test_nodes.iterrows():
                print(f"  {row['kind']}: {row['name']} (version={row.get('version', 'N/A')}) - {row['id']}")
            
            # Assertion 1: y = x (inside function) should connect to local x
            y_def = test_nodes[(test_nodes['name'] == 'y') & (test_nodes['kind'] == 'var_def')]
            if len(y_def) > 0:
                # Find the x VAR_USE that corresponds to y = x
                x_uses = test_nodes[(test_nodes['name'] == 'x') & (test_nodes['kind'] == 'var_use')]
                if len(x_uses) >= 2:  # Should have at least 2 uses (one local, one global)
                    # Find the one that's in the function scope
                    local_x_use = None
                    for _, x_use in x_uses.iterrows():
                        # Check if this use is in the function scope by looking at the byte range
                        # The local use should be around line 4 (y = x)
                        if 40 <= x_use['prov_byte_start'] <= 60:  # Approximate range for local use
                            local_x_use = x_use
                            break
                    
                    if local_x_use is not None:
                        def_use_edge = test_edges[
                            (test_edges['kind'] == 'def_use') &
                            (test_edges['dst_id'] == local_x_use['id'])
                        ]
                        if len(def_use_edge) > 0:
                            src_id = def_use_edge.iloc[0]['src_id']
                            # Find the local x VAR_DEF (should be around line 3)
                            local_x_defs = test_nodes[
                                (test_nodes['name'] == 'x') & 
                                (test_nodes['kind'] == 'var_def')
                            ]
                            # The local x def should be around line 3
                            local_x_def = None
                            for _, x_def in local_x_defs.iterrows():
                                if 20 <= x_def['prov_byte_start'] <= 40:  # Approximate range for local def
                                    local_x_def = x_def
                                    break
                            
                            if local_x_def is not None and src_id == local_x_def['id']:
                                self.log_result("Scope Correctness", "local y=x connects to local x", "PASS")
                            else:
                                self.log_result("Scope Correctness", "local y=x connects to local x", "FAIL", 
                                              f"Expected local x def, got {src_id}")
                        else:
                            self.log_result("Scope Correctness", "local y=x connects to local x", "FAIL", "No DEF_USE edge found")
                    else:
                        self.log_result("Scope Correctness", "local y=x connects to local x", "FAIL", "Could not identify local x use")
                else:
                    self.log_result("Scope Correctness", "local y=x connects to local x", "FAIL", "Insufficient x VAR_USE nodes")
            else:
                self.log_result("Scope Correctness", "local y=x connects to local x", "FAIL", "No y VAR_DEF found")
            
            # Assertion 2: z = x (global) should connect to global x
            z_def = test_nodes[(test_nodes['name'] == 'z') & (test_nodes['kind'] == 'var_def')]
            if len(z_def) > 0:
                # Find the global x VAR_USE
                x_uses = test_nodes[(test_nodes['name'] == 'x') & (test_nodes['kind'] == 'var_use')]
                global_x_use = None
                for _, x_use in x_uses.iterrows():
                    # The global use should be around line 6 (z = x)
                    if x_use['prov_byte_start'] >= 70:  # Approximate range for global use
                        global_x_use = x_use
                        break
                
                if global_x_use is not None:
                    def_use_edge = test_edges[
                        (test_edges['kind'] == 'def_use') &
                        (test_edges['dst_id'] == global_x_use['id'])
                    ]
                    if len(def_use_edge) > 0:
                        src_id = def_use_edge.iloc[0]['src_id']
                        # Find the global x VAR_DEF (should be around line 1)
                        global_x_defs = test_nodes[
                            (test_nodes['name'] == 'x') & 
                            (test_nodes['kind'] == 'var_def')
                        ]
                        global_x_def = None
                        for _, x_def in global_x_defs.iterrows():
                            if x_def['prov_byte_start'] <= 20:  # Approximate range for global def
                                global_x_def = x_def
                                break
                        
                        if global_x_def is not None and src_id == global_x_def['id']:
                            self.log_result("Scope Correctness", "global z=x connects to global x", "PASS")
                        else:
                            self.log_result("Scope Correctness", "global z=x connects to global x", "FAIL", 
                                          f"Expected global x def, got {src_id}")
                    else:
                        self.log_result("Scope Correctness", "global z=x connects to global x", "FAIL", "No DEF_USE edge found")
                else:
                    self.log_result("Scope Correctness", "global z=x connects to global x", "FAIL", "Could not identify global x use")
            else:
                self.log_result("Scope Correctness", "global z=x connects to global x", "FAIL", "No z VAR_DEF found")
    
    def test_case_4_alias_detection(self):
        """Test Case 4: Simple Alias Detection (alias_hint)"""
        with TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            # Create test file
            code = """
def alias_test():
    original = get_data()
    aliased = original  # This is a direct alias
    
    # This is NOT a direct alias
    processed = aliased.process()
"""
            test_file = self.create_test_file(temp_path, "test_alias.py", code)
            
            # Run pipeline
            summary = self.run_pipeline([test_file], "alias_detection")
            
            # Load data
            data = self.load_parquet_data()
            
            if 'aliases' not in data:
                self.log_result("Alias Detection", "Data loading", "FAIL", "Missing aliases data")
                return
            
            aliases = data['aliases']
            
            print(f"\n📋 Aliases in test_alias.py:")
            for _, row in aliases.iterrows():
                print(f"  {row['alias_kind']}: {row['alias_name']} -> {row['target_symbol_id']}")
            
            # Assertion 1: Exactly one alias_hint should be generated
            alias_count = len(aliases)
            if alias_count == 1:
                self.log_result("Alias Detection", "Exactly one alias generated", "PASS")
            else:
                self.log_result("Alias Detection", "Exactly one alias generated", "FAIL", 
                              f"Expected 1 alias, got {alias_count}")
            
            # Assertion 2: The alias should be for aliased -> original
            if alias_count > 0:
                alias = aliases.iloc[0]
                if alias['alias_name'] == 'aliased':
                    self.log_result("Alias Detection", "alias is aliased -> original", "PASS")
                else:
                    self.log_result("Alias Detection", "alias is aliased -> original", "FAIL", 
                                  f"Expected alias_name='aliased', got '{alias['alias_name']}'")
            else:
                self.log_result("Alias Detection", "alias is aliased -> original", "FAIL", "No aliases found")
            
            # Assertion 3: No alias should be generated for processed = aliased.process()
            # This is already covered by assertion 1 (exactly one alias), but let's be explicit
            processed_aliases = aliases[aliases['alias_name'] == 'processed']
            if len(processed_aliases) == 0:
                self.log_result("Alias Detection", "No alias for processed = aliased.process()", "PASS")
            else:
                self.log_result("Alias Detection", "No alias for processed = aliased.process()", "FAIL", 
                              f"Found {len(processed_aliases)} aliases for 'processed'")
    
    def test_case_5_attribute_assignment(self):
        """Test Case 5: Attribute Assignment (Stretch Goal)"""
        with TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            # Create test file
            code = """
class MyClass:
    def __init__(self):
        self.foo = 100

    def get_foo(self):
        return self.foo
"""
            test_file = self.create_test_file(temp_path, "test_attribute.py", code)
            
            # Run pipeline
            self.run_pipeline([test_file], "attribute_assignment")
            
            # Load data
            data = self.load_parquet_data()
            
            if 'dfg_nodes' not in data or 'dfg_edges' not in data:
                self.log_result("Attribute Assignment", "Data loading", "FAIL", "Missing DFG data")
                return
            
            dfg_nodes = data['dfg_nodes']
            dfg_edges = data['dfg_edges']
            
            # Filter for our test file
            test_nodes = dfg_nodes[dfg_nodes['path'].str.contains('test_attribute')]
            test_edges = dfg_edges[dfg_edges['path'].str.contains('test_attribute')]
            
            print(f"\n📋 DFG Nodes in test_attribute.py:")
            for _, row in test_nodes.iterrows():
                print(f"  {row['kind']}: {row['name']} (version={row.get('version', 'N/A')}) - {row['id']}")
            
            # Assertion 1: VAR_DEF for self.foo in __init__
            self_foo_defs = test_nodes[
                (test_nodes['name'] == 'self.foo') & 
                (test_nodes['kind'] == 'var_def')
            ]
            if len(self_foo_defs) > 0:
                self.log_result("Attribute Assignment", "VAR_DEF for self.foo in __init__", "PASS")
            else:
                self.log_result("Attribute Assignment", "VAR_DEF for self.foo in __init__", "FAIL", "No self.foo VAR_DEF found")
            
            # Assertion 2: DEF_USE edge from __init__ self.foo to get_foo self.foo
            self_foo_uses = test_nodes[
                (test_nodes['name'] == 'self.foo') & 
                (test_nodes['kind'] == 'var_use')
            ]
            if len(self_foo_uses) > 0 and len(self_foo_defs) > 0:
                # Find DEF_USE edge
                def_use_edges = test_edges[
                    (test_edges['kind'] == 'def_use') &
                    (test_edges['src_id'] == self_foo_defs.iloc[0]['id']) &
                    (test_edges['dst_id'] == self_foo_uses.iloc[0]['id'])
                ]
                if len(def_use_edges) > 0:
                    self.log_result("Attribute Assignment", "DEF_USE edge from __init__ to get_foo", "PASS")
                else:
                    self.log_result("Attribute Assignment", "DEF_USE edge from __init__ to get_foo", "FAIL", "No DEF_USE edge found")
            else:
                self.log_result("Attribute Assignment", "DEF_USE edge from __init__ to get_foo", "FAIL", 
                              f"Missing nodes: defs={len(self_foo_defs)}, uses={len(self_foo_uses)}")
    
    def run_all_tests(self):
        """Run all test cases."""
        print("🔍 QA Validation Suite for DfgBuilder")
        print("=" * 60)
        
        # Run all test cases
        self.test_case_1_ssa_versioning()
        self.test_case_2_function_params()
        self.test_case_3_scope_correctness()
        self.test_case_4_alias_detection()
        self.test_case_5_attribute_assignment()
        
        # Generate final report
        self.generate_final_report()
    
    def generate_final_report(self):
        """Generate the final QA report."""
        print(f"\n📋 FINAL QA REPORT")
        print("=" * 60)
        
        # Count results
        total_tests = len(self.test_results)
        passed_tests = len([r for r in self.test_results if r['result'] == 'PASS'])
        failed_tests = total_tests - passed_tests
        success_rate = (passed_tests / total_tests * 100) if total_tests > 0 else 0
        
        print(f"📊 Summary:")
        print(f"  Total Assertions: {total_tests}")
        print(f"  Passed: {passed_tests}")
        print(f"  Failed: {failed_tests}")
        print(f"  Success Rate: {success_rate:.1f}%")
        
        print(f"\n📋 Detailed Results:")
        current_test = None
        for result in self.test_results:
            if result['test'] != current_test:
                current_test = result['test']
                print(f"\n  🧪 {current_test}:")
            print(f"    {result['result']} {result['assertion']}")
            if result['details']:
                print(f"      Details: {result['details']}")
        
        # Status
        if success_rate == 100:
            print(f"\n🎉 STATUS: ALL TESTS PASSING!")
        elif success_rate >= 80:
            print(f"\n✅ STATUS: GOOD - Most tests passing")
        elif success_rate >= 60:
            print(f"\n⚠️  STATUS: NEEDS IMPROVEMENT - Some issues detected")
        else:
            print(f"\n❌ STATUS: FAILING - Major issues detected")
        
        return success_rate >= 80


def main():
    """Main QA validation runner."""
    validator = QAValidator()
    success = validator.run_all_tests()
    
    # Clean up output directories
    for output_dir in Path(".").glob("qa_output_*"):
        import shutil
        shutil.rmtree(output_dir, ignore_errors=True)
    
    return success


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
