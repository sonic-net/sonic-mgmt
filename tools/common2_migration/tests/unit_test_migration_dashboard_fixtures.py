import ast
import importlib.util
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPO_ROOT / "migration_dashboard.py"
SPEC = importlib.util.spec_from_file_location("migration_dashboard", SCRIPT_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def test_function_uses_symbol_detects_fixture_argument():
    source = """
import pytest

@pytest.fixture
def conn_graph_facts():
    return object()


def test_something(conn_graph_facts):
    assert conn_graph_facts is not None
"""
    tree = ast.parse(source)
    test_node = None
    for node in MODULE.ast.walk(tree):
        if isinstance(node, MODULE.ast.FunctionDef) and node.name == "test_something":
            test_node = node
            break

    assert test_node is not None
    assert MODULE.function_uses_symbol(test_node, "conn_graph_facts")


def test_module_has_common2_unit_tests_matches_dotted_form():
    assert MODULE.module_has_common2_unit_tests(
        "tests.common.helpers.bgp",
        {"tests.common2.helpers.bgp"},
    )
