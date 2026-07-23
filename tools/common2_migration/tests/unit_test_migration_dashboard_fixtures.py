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


def test_is_pytest_fixture_does_not_match_pytest_mark_decorators():
    source = """
import pytest

@pytest.mark.parametrize("x", [1, 2])
def sample_function(x):
    return x
"""
    tree = ast.parse(source)
    func_node = None
    for node in MODULE.ast.walk(tree):
        if isinstance(node, MODULE.ast.FunctionDef) and node.name == "sample_function":
            func_node = node
            break

    assert func_node is not None
    assert not MODULE.is_pytest_fixture(func_node)


def test_module_has_common2_unit_tests_matches_dotted_form():
    assert MODULE.module_has_common2_unit_tests(
        "tests.common.helpers.bgp",
        {"tests.common2.helpers.bgp"},
    )


def test_analyze_module_counts_fixtures_in_module_size(tmp_path):
    repo_root = tmp_path / "repo"
    module_dir = repo_root / "tests" / "common" / "helpers"
    module_dir.mkdir(parents=True)
    module_path = module_dir / "sample.py"
    module_path.write_text(
        """
import pytest

@pytest.fixture
def sample_fixture():
    return object()


def sample_function():
    return sample_fixture()


class SampleClass:
    pass
""",
        encoding="utf-8",
    )

    task = MODULE.analyze_module(
        str(module_path),
        str(repo_root),
        MODULE.ImpactGraph(),
        set(),
    )

    assert task is not None
    assert task.num_functions == 2
    assert task.num_classes == 1
    assert task.num_functions + task.num_classes == 3


def test_compute_module_score_avoids_double_counting_direct_dependencies():
    task = MODULE.ModuleTask(
        rel_path="tests/common/helpers/bgp.py",
        dotted="tests.common.helpers.bgp",
        domain="utilities/helpers",
        target_path="tests/common2/utilities/helpers/bgp.py",
        loc=40,
        num_functions=1,
        num_classes=0,
        typed_ratio=1.0,
        documented_ratio=1.0,
        has_common2_unit_tests=False,
        depends_on_direct=["tests.common.helpers.alpha"],
        depends_on_transitive=["tests.common.helpers.alpha", "tests.common.helpers.beta"],
    )

    assert MODULE.compute_module_score(task) == 8.8


def test_build_json_does_not_emit_migrated_sections():
    task = MODULE.ModuleTask(
        rel_path="tests/common/helpers/bgp.py",
        dotted="tests.common.helpers.bgp",
        domain="utilities/helpers",
        target_path="tests/common2/utilities/helpers/bgp.py",
        loc=40,
        num_functions=1,
        num_classes=0,
        typed_ratio=1.0,
        documented_ratio=1.0,
        has_common2_unit_tests=False,
        depends_on_direct=[],
        depends_on_transitive=[],
    )

    payload = MODULE.build_json([task], 5)

    assert "migrated_modules" not in payload["summary"]
    assert "migrated" not in payload
