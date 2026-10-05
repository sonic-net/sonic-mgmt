import ast
from pathlib import Path

import pytest


CONFTEST_PATH = (Path(__file__).resolve().parents[3] / "conftest.py")


def _load_generate_dut_feature_list(meta):
    """
    Extract features from generate_dut_feature_list from tests/conftest.py and run it in
    an isolated namespace with get_testbed_metadata stubbed to return
    meta data.

    tests/conftest.py imports the full integration-test dependency tree
    (paramiko, ansible device wrappers, etc.), so it cannot be imported
    directly in a lightweight unit test.
    """
    source = CONFTEST_PATH.read_text()
    tree = ast.parse(source)
    func_node = next(
        node for node in tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name == "generate_dut_feature_list"
    )
    module = ast.Module(body=[func_node], type_ignores=[])
    code = compile(module, filename=str(CONFTEST_PATH), mode="exec")

    namespace = {"get_testbed_metadata": lambda request: meta}
    exec(code, namespace)
    return namespace["generate_dut_feature_list"]


def _run(meta, duts_selected, asics_selected):
    generate_dut_feature_list = _load_generate_dut_feature_list(meta)
    return generate_dut_feature_list(None, duts_selected, asics_selected)


def test_disabled_features_filtered_with_asics():
    """Disabled features must be dropped when asics are selected (BMC case)."""
    meta = {
        "dut1": {
            "features": {
                "bgp": "disabled",
                "swss": "disabled",
                "lldp": "enabled",
                "pmon": "always_enabled",
            }
        }
    }
    result = _run(meta, ["dut1"], [["0"]])
    assert result == [("dut1", "0", "lldp"), ("dut1", "0", "pmon")]


def test_disabled_features_filtered_without_asics():
    """Disabled features must be dropped when no asics are selected."""
    meta = {
        "dut1": {
            "features": {
                "bgp": "disabled",
                "lldp": "enabled",
                "telemetry": "enabled",
            }
        }
    }
    result = _run(meta, ["dut1"], [])
    assert result == [("dut1", None, "lldp"), ("dut1", None, "telemetry")]


def test_skip_feature_list_excluded():
    """database, database-chassis and gbsyncd are always skipped."""
    meta = {
        "dut1": {
            "features": {
                "database": "enabled",
                "database-chassis": "enabled",
                "gbsyncd": "enabled",
                "lldp": "enabled",
            }
        }
    }
    assert _run(meta, ["dut1"], []) == [("dut1", None, "lldp")]
    assert _run(meta, ["dut1"], [["0"]]) == [("dut1", "0", "lldp")]


def test_enabled_variants_included():
    """Any status that does not contain 'disabled' is included."""
    meta = {
        "dut1": {
            "features": {
                "lldp": "enabled",
                "pmon": "always_enabled",
            }
        }
    }
    result = _run(meta, ["dut1"], [])
    assert result == [("dut1", None, "lldp"), ("dut1", None, "pmon")]


def test_meta_none_returns_empty():
    """When metadata is unavailable, an empty list is returned."""
    assert _run(None, ["dut1"], [["0"]]) == []
    assert _run(None, ["dut1"], []) == []


def test_dut_without_features_key():
    """A DUT lacking a 'features' key yields a single None-feature tuple."""
    meta = {"dut1": {}}
    assert _run(meta, ["dut1"], [["0"]]) == [("dut1", "0", None)]
    assert _run(meta, ["dut1"], []) == [("dut1", None, None)]


def test_multiple_asics_expand_features():
    """Each enabled feature is emitted once per selected asic."""
    meta = {
        "dut1": {
            "features": {
                "bgp": "disabled",
                "lldp": "enabled",
            }
        }
    }
    result = _run(meta, ["dut1"], [["0", "1"]])
    assert result == [("dut1", "0", "lldp"), ("dut1", "1", "lldp")]


def test_multiple_duts():
    """Features are filtered independently per DUT."""
    meta = {
        "dut1": {"features": {"bgp": "disabled", "lldp": "enabled"}},
        "dut2": {"features": {"swss": "enabled"}},
    }
    result = _run(meta, ["dut1", "dut2"], [])
    assert result == [("dut1", None, "lldp"), ("dut2", None, "swss")]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
