import hashlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from provis.ucg.discovery import AnomalySink, FileMeta, Language
from provis.ucg.normalize import EdgeKind, NodeKind, Normalizer
from provis.ucg.python_driver import PythonLibCstDriver
from provis.ucg.ucg_store import UcgStore


def _file_meta_for(tmp_path, rel_name: str, content: str) -> FileMeta:
    path = tmp_path / rel_name
    path.write_text(content, encoding="utf-8")
    data = content.encode("utf-8")
    blob = hashlib.blake2b(data, digest_size=20).hexdigest()
    return FileMeta(
        path=rel_name,
        real_path=str(path),
        blob_sha=blob,
        size_bytes=len(data),
        mtime_ns=0,
        run_id="test-run",
        config_hash="test-config",
        is_text=True,
        encoding="utf-8",
        encoding_confidence=1.0,
        lang=Language.PY,
        flags=set(),
    )


def test_normalizer_emits_structural_and_decorator_links(tmp_path):
    source = """
@module_dec
def top(a, b):
    @inner_dec
    def inner(x):
        return helper_call(x)
    return inner(a)

@outer_dec
class Sample:
    @method_dec
    def method(self, value):
        helper(value)
"""
    fm = _file_meta_for(tmp_path, "sample.py", source)
    driver = PythonLibCstDriver()
    ps = driver.parse(fm)
    assert ps.ok, f"parse failed: {ps.error}"

    sink = AnomalySink()
    rows = list(Normalizer().normalize(ps, sink))
    assert not sink.items(), "expected no anomalies during normalization"

    nodes = [row for kind, row in rows if kind == "node"]
    edges = [row for kind, row in rows if kind == "edge"]
    assert nodes, "expected node emissions"
    assert edges, "expected edge emissions"

    node_by_id = {n.id: n for n in nodes}
    node_attrs = {n.id: json.loads(n.attrs_json) for n in nodes}

    # Ensure structural scope nodes exist
    functions = [n for n in nodes if n.kind == NodeKind.FUNCTION]
    classes = [n for n in nodes if n.kind == NodeKind.CLASS]
    assert functions, "no function nodes emitted"
    assert classes, "no class nodes emitted"

    defines_edges = [e for e in edges if e.kind == EdgeKind.DEFINES]
    assert any(
        node_by_id[e.src_id].kind == NodeKind.MODULE and node_by_id[e.dst_id].kind == NodeKind.FUNCTION
        for e in defines_edges
    )
    assert any(
        node_by_id[e.src_id].kind == NodeKind.CLASS and node_by_id[e.dst_id].kind == NodeKind.FUNCTION
        for e in defines_edges
    )

    # Decorators should materialize as effect carriers linked to their targets
    decorator_nodes = [
        n for n in nodes
        if n.kind == NodeKind.EFFECT_CARRIER and node_attrs.get(n.id, {}).get("type") == "Decorator"
    ]
    assert decorator_nodes, "expected decorator/effect-carrier nodes"
    decorates_edges = [e for e in edges if e.kind == EdgeKind.DECORATES]
    edge_src_ids = {e.src_id for e in decorates_edges}
    decorated_ids = {n.id for n in decorator_nodes}
    missing = decorated_ids - edge_src_ids
    assert not missing, f"decorators without edges: {[node_attrs[mid] for mid in missing]}"
    for edge in decorates_edges:
        assert node_by_id[edge.src_id].kind == NodeKind.EFFECT_CARRIER
        assert node_attrs.get(edge.src_id, {}).get("type") == "Decorator"
        assert node_by_id[edge.dst_id].kind in {NodeKind.FUNCTION, NodeKind.CLASS}

    # Calls must originate from functions and carry an args stub
    call_edges = [e for e in edges if e.kind == EdgeKind.CALLS]
    assert call_edges, "expected call edges"
    for edge in call_edges:
        caller_node = node_by_id[edge.src_id]
        assert caller_node.kind == NodeKind.FUNCTION
        attrs = json.loads(edge.attrs_json)
        assert "args_model_stub" in attrs

    # Function metadata carries parameter mappings
    function_attrs = {n.name: node_attrs[n.id] for n in functions if n.name}
    assert function_attrs["top"]["param_index_to_name"] == {"0": "a", "1": "b"}
    assert function_attrs["inner"]["param_index_to_name"] == {"0": "x"}
    assert function_attrs["method"]["param_index_to_name"] == {"0": "self", "1": "value"}


def test_ucg_store_persists_zero_row_partitions(tmp_path):
    pq = pytest.importorskip("pyarrow.parquet")
    out_dir = tmp_path / "ucg"
    store = UcgStore(out_dir)
    store.flush()
    store.finalize(receipt={})

    nodes_file = out_dir / "nodes" / "ucg_nodes_00000.parquet"
    edges_file = out_dir / "edges" / "ucg_edges_00000.parquet"

    assert nodes_file.exists()
    assert edges_file.exists()

    assert pq.read_table(nodes_file).num_rows == 0
    assert pq.read_table(edges_file).num_rows == 0
