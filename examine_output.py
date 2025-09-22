#!/usr/bin/env python3
"""
Script to examine the UCG output data.
"""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

try:
    import pyarrow.parquet as pq
    import pandas as pd
except ImportError:
    print("Installing required packages...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pyarrow", "pandas"])
    import pyarrow.parquet as pq
    import pandas as pd

from provis.ucg.iterators import UcgReader


def examine_ucg_output(output_dir: str):
    """Examine the UCG output data."""
    output_path = Path(output_dir)
    
    print(f"🔍 Examining UCG output in: {output_path}")
    print("=" * 60)
    
    # Read the receipt
    receipt_path = output_path / "run_receipt.json"
    if receipt_path.exists():
        import json
        receipt = json.loads(receipt_path.read_text())
        print(f"📊 Summary:")
        print(f"  Nodes: {receipt['nodes_rows']:,}")
        print(f"  Edges: {receipt['edges_rows']:,}")
        print(f"  Anomalies: {receipt['anomaly_rows']}")
        print(f"  Total size: {receipt['bytes_written']:,} bytes")
        print()
    
    # Examine nodes
    nodes_dir = output_path / "nodes"
    if nodes_dir.exists():
        parquet_files = list(nodes_dir.glob("*.parquet"))
        if parquet_files:
            print(f"📁 Nodes ({len(parquet_files)} files):")
            for pf in parquet_files:
                df = pd.read_parquet(pf)
                print(f"  {pf.name}: {len(df)} rows")
                
                if len(df) > 0:
                    print(f"    Columns: {list(df.columns)}")
                    print(f"    Sample rows:")
                    for i, row in df.head(3).iterrows():
                        print(f"      {i+1}. {row['kind']} '{row['name']}' in {row['path']}")
                    if len(df) > 3:
                        print(f"      ... and {len(df) - 3} more")
            print()
    
    # Examine edges
    edges_dir = output_path / "edges"
    if edges_dir.exists():
        parquet_files = list(edges_dir.glob("*.parquet"))
        if parquet_files:
            print(f"🔗 Edges ({len(parquet_files)} files):")
            for pf in parquet_files:
                df = pd.read_parquet(pf)
                print(f"  {pf.name}: {len(df)} rows")
                
                if len(df) > 0:
                    print(f"    Sample edges:")
                    for i, row in df.head(3).iterrows():
                        print(f"      {i+1}. {row['kind']}: {row['src_id'][:8]}... -> {row['dst_id'][:8]}...")
                    if len(df) > 3:
                        print(f"      ... and {len(df) - 3} more")
            print()
    
    # Use the UcgReader API for structured queries
    print("🔍 Using UcgReader API:")
    try:
        reader = UcgReader(output_path)
        
        # Get all nodes by kind
        print("  Node types:")
        nodes_df = pd.read_parquet(output_path / "nodes" / "*.parquet")
        if len(nodes_df) > 0:
            kind_counts = nodes_df['kind'].value_counts()
            for kind, count in kind_counts.items():
                print(f"    {kind}: {count}")
        
        # Get all edge types
        print("  Edge types:")
        edges_df = pd.read_parquet(output_path / "edges" / "*.parquet")
        if len(edges_df) > 0:
            kind_counts = edges_df['kind'].value_counts()
            for kind, count in kind_counts.items():
                print(f"    {kind}: {count}")
        
        reader.close()
        
    except Exception as e:
        print(f"  Error using UcgReader: {e}")
    
    print("\n✅ Output examination complete!")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python examine_output.py <output_dir>")
        print("Example: python examine_output.py test_output")
        sys.exit(1)
    
    examine_ucg_output(sys.argv[1])
