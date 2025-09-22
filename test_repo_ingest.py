#!/usr/bin/env python3
"""
Test script to demonstrate repository ingestion with Step 1 UCG pipeline.

Usage:
    python test_repo_ingest.py <repo_path> [output_dir]
"""

import sys
import json
from pathlib import Path

# Add src to path so we can import provis modules
sys.path.insert(0, str(Path(__file__).parent / "src"))

from provis.ucg.discovery import iter_discovered_files, DiscoveryConfig, AnomalySink
from provis.ucg.api import build_ucg_for_files, Step1Config


def main():
    if len(sys.argv) < 2:
        print("Usage: python test_repo_ingest.py <repo_path> [output_dir]")
        print("Example: python test_repo_ingest.py /path/to/repo ./ucg_output")
        sys.exit(1)
    
    repo_path = Path(sys.argv[1])
    output_dir = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("./ucg_output")
    
    if not repo_path.exists():
        print(f"Error: Repository path does not exist: {repo_path}")
        sys.exit(1)
    
    print(f"🔍 Ingesting repository: {repo_path}")
    print(f"📁 Output directory: {output_dir}")
    print()
    
    # Step 1: Discovery
    print("Step 1: Discovering files...")
    discovery_config = DiscoveryConfig(
        include_globs=("*.py", "*.js", "*.ts", "*.tsx", "*.jsx"),
        exclude_globs=("*/node_modules/*", "*/__pycache__/*", "*/.git/*"),
    )
    sink = AnomalySink()
    
    files = list(iter_discovered_files(repo_path, discovery_config, anomaly_sink=sink))
    print(f"✅ Discovered {len(files)} files")
    
    if files:
        print("Sample files:")
        for i, f in enumerate(files[:5]):
            print(f"  {i+1}. {f.path} ({f.lang}, {f.size_bytes} bytes)")
        if len(files) > 5:
            print(f"  ... and {len(files) - 5} more files")
    
    # Step 2: UCG Processing
    print("\nStep 2: Building UCG...")
    step1_config = Step1Config(
        enable_cfg=True,
        enable_dfg=True,
        enable_symbols=True,
        enable_effects=True,
        flush_every_n_files=10,  # Flush more frequently for smaller repos
        node_edge_batch=1000,    # Smaller batches for testing
        cfg_batch=1000,
        dfg_batch=1000,
        sym_batch=1000,
        eff_batch=1000,
    )
    
    try:
        summary = build_ucg_for_files(
            files,
            output_dir,
            cfg=step1_config,
            run_metadata={
                "repo_path": str(repo_path),
                "test_run": True,
            }
        )
        
        print("✅ UCG processing completed!")
        print(f"\n📊 Results Summary:")
        print(f"  Files processed: {summary.files_parsed}/{summary.files_total}")
        print(f"  Nodes: {summary.nodes_rows:,}")
        print(f"  Edges: {summary.edges_rows:,}")
        print(f"  CFG blocks: {summary.cfg_blocks_rows:,}")
        print(f"  CFG edges: {summary.cfg_edges_rows:,}")
        print(f"  DFG nodes: {summary.dfg_nodes_rows:,}")
        print(f"  DFG edges: {summary.dfg_edges_rows:,}")
        print(f"  Symbols: {summary.symbols_rows:,}")
        print(f"  Aliases: {summary.aliases_rows:,}")
        print(f"  Effects: {summary.effects_rows:,}")
        print(f"  Anomalies: {summary.anomalies}")
        print(f"  Processing time: {summary.wall_ms:,}ms")
        
        # Check output structure
        print(f"\n📁 Output structure:")
        if output_dir.exists():
            for item in sorted(output_dir.iterdir()):
                if item.is_dir():
                    parquet_files = list(item.glob("*.parquet"))
                    print(f"  📂 {item.name}/ ({len(parquet_files)} files)")
                else:
                    print(f"  📄 {item.name}")
        
        # Show some anomalies if any
        if summary.anomalies > 0:
            print(f"\n⚠️  Anomalies detected: {summary.anomalies}")
            anomaly_files = list((output_dir / "anomalies").glob("*.parquet"))
            if anomaly_files:
                print("  Check anomaly files for details")
        
        print(f"\n🎉 Repository ingestion successful!")
        print(f"   Output directory: {output_dir}")
        print(f"   Ready for Step 2 analysis!")
        
    except Exception as e:
        print(f"❌ Error during UCG processing: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
