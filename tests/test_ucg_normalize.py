import hashlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from provis.ucg.discovery import AnomalySink, FileMeta, Language
from provis.ucg.normalize import EdgeKind, NodeKind, Normalizer
from provis.ucg.parser_registry import CstEvent, CstEventKind, DriverInfo, ParseStream
from provis.ucg.python_driver import PythonLibCstDriver
from provis.ucg.ucg_store import UcgStore


def _file_meta_for(tmp_path, rel_name: str, content: str, *, lang: Language = Language.PY) -> FileMeta:
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
        lang=lang,
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


def test_normalizer_ts_scope_emission(tmp_path):
    source = """class Greeter {
  greet(name: string) {
    return helper(name);
  }
}
"""
    fm = _file_meta_for(tmp_path, "sample.ts", source, lang=Language.TS)

    def line_for(idx: int) -> int:
        if idx <= 0:
            return 1
        return source.count("\n", 0, idx) + 1

    def evt(kind: CstEventKind, node_type: str, start: int, end: int) -> CstEvent:
        end_line_idx = end - 1 if end > start else end
        return CstEvent(
            kind=kind,
            type=node_type,
            byte_start=start,
            byte_end=end,
            line_start=line_for(start),
            line_end=line_for(max(0, end_line_idx)),
        )

    prog_start, prog_end = 0, len(source)
    class_start = source.index("class")
    class_end = prog_end
    class_name_start = source.index("Greeter")
    class_name_end = class_name_start + len("Greeter")
    method_start = source.index("greet")
    method_end = source.index("return helper(name);") + len("return helper(name);")
    method_name_start = method_start
    method_name_end = method_name_start + len("greet")
    block_start = source.index("{", method_start)
    block_end = source.index("}", block_start) + 1
    return_start = source.index("return")
    return_end = return_start + len("return")
    call_start = source.index("helper")
    call_end = source.index(")", call_start) + 1
    helper_end = call_start + len("helper")
    arg_start = source.index("name", helper_end)
    arg_end = arg_start + len("name")

    events = [
        evt(CstEventKind.ENTER, "program", prog_start, prog_end),
        evt(CstEventKind.ENTER, "class_declaration", class_start, class_end),
        evt(CstEventKind.TOKEN, "identifier", class_name_start, class_name_end),
        evt(CstEventKind.ENTER, "class_body", class_start, class_end),
        evt(CstEventKind.ENTER, "method_definition", method_start, method_end),
        evt(CstEventKind.TOKEN, "property_identifier", method_name_start, method_name_end),
        evt(CstEventKind.ENTER, "statement_block", block_start, block_end),
        evt(CstEventKind.ENTER, "return_statement", return_start, return_end),
        evt(CstEventKind.ENTER, "call_expression", call_start, call_end),
        evt(CstEventKind.TOKEN, "identifier", call_start, helper_end),
        evt(CstEventKind.TOKEN, "identifier", arg_start, arg_end),
        evt(CstEventKind.EXIT, "call_expression", call_start, call_end),
        evt(CstEventKind.EXIT, "return_statement", return_start, return_end),
        evt(CstEventKind.EXIT, "statement_block", block_start, block_end),
        evt(CstEventKind.EXIT, "method_definition", method_start, method_end),
        evt(CstEventKind.EXIT, "class_body", class_start, class_end),
        evt(CstEventKind.EXIT, "class_declaration", class_start, class_end),
        evt(CstEventKind.EXIT, "program", prog_start, prog_end),
    ]

    ps = ParseStream(
        file=fm,
        driver=DriverInfo(language=Language.TS, grammar_name="ts", grammar_sha="stub", version="1.0"),
        events=iter(events),
        elapsed_s=0.0,
        ok=True,
    )

    sink = AnomalySink()
    rows = list(Normalizer().normalize(ps, sink))
    assert not sink.items()

    nodes = {row.id: row for kind, row in rows if kind == "node"}
    edges = [row for kind, row in rows if kind == "edge"]

    class_nodes = [n for n in nodes.values() if n.kind == NodeKind.CLASS]
    method_nodes = [n for n in nodes.values() if n.kind == NodeKind.FUNCTION]
    assert class_nodes, "expected class node emission"
    assert method_nodes, "expected method/function node emission"

    defines = [e for e in edges if e.kind == EdgeKind.DEFINES]
    assert any(nodes[e.src_id].kind == NodeKind.MODULE and nodes[e.dst_id].kind == NodeKind.CLASS for e in defines)
    assert any(nodes[e.src_id].kind == NodeKind.CLASS and nodes[e.dst_id].kind == NodeKind.FUNCTION for e in defines)

    call_edges = [e for e in edges if e.kind == EdgeKind.CALLS]
    assert call_edges, "expected call emission"
    for edge in call_edges:
        assert nodes[edge.src_id].kind == NodeKind.FUNCTION
        attrs = json.loads(edge.attrs_json)
        assert "args_model_stub" in attrs

    method_attrs = json.loads(method_nodes[0].attrs_json)
    assert method_attrs["param_index_to_name"] == {"0": "name"}


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
