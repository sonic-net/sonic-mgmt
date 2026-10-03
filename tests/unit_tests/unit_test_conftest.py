import ast
from pathlib import Path
from types import SimpleNamespace


def _load_conftest_function(function_name):
    """
    Load a function from tests/conftest.py in isolation for unit testing.

    This helper extracts a specific function from conftest.py, parses it as an
    AST, and executes it in an isolated namespace. This allows testing
    conftest functions without loading the entire conftest module and its
    dependencies.

    Args:
        function_name (str): Name of the function to load from conftest.py

    Returns:
        dict: Namespace containing the loaded function and imports.

    Raises:
        AssertionError: If the function is not found in conftest.py
    """
    conftest_path = Path(__file__).resolve().parents[1] / "conftest.py"
    source = conftest_path.read_text(encoding="utf-8")
    module_ast = ast.parse(source)

    target_node = None
    for node in module_ast.body:
        if isinstance(node, ast.FunctionDef) and node.name == function_name:
            target_node = node
            break

    assert target_node is not None, (
        f"{function_name} not found in tests/conftest.py"
    )

    new_module = ast.Module(body=[target_node], type_ignores=[])
    ast.fix_missing_locations(new_module)

    # Include common dependencies that conftest functions might need
    namespace = {"re": __import__("re")}
    exec(compile(new_module, str(conftest_path), "exec"), namespace)
    return namespace


def _load_generate_skeleton_port_info():
    """Load generate_skeleton_port_info for backward compatibility."""
    return _load_conftest_function("generate_skeleton_port_info")


def _request_with_testbed(testbed_name):
    return SimpleNamespace(
        config=SimpleNamespace(getoption=lambda _: testbed_name)
    )


def test_generate_skeleton_port_info_returns_override_data():
    namespace = _load_generate_skeleton_port_info()
    namespace["parse_override"] = (
        lambda *_: (True, ["100-single_linecard_single_asic"])
    )
    namespace["get_snappi_testbed_metadata"] = lambda *_: {
        "unused": {
            "asic_to_interface": {"asic0": ["Ethernet0"]},
            "intf_status": {
                "Ethernet0": {
                    "name": "Ethernet0",
                    "speed": "100G",
                    "admin_state": "up",
                }
            },
        }
    }

    result = namespace["generate_skeleton_port_info"](
        _request_with_testbed("tbname")
    )

    assert result == ["100-single_linecard_single_asic"]


def test_generate_skeleton_port_info_builds_all_categories():
    namespace = _load_generate_skeleton_port_info()
    namespace["parse_override"] = lambda *_: (False, None)
    namespace["get_snappi_testbed_metadata"] = lambda *_: {
        "linecard-a": {
            "asic_to_interface": {
                "asic0": ["Ethernet0", "Ethernet4"],
                "asic1": ["Ethernet8"],
            },
            "intf_status": {
                "Ethernet0": {
                    "name": "Ethernet0",
                    "speed": "400G",
                    "admin_state": "up",
                },
                "Ethernet4": {
                    "name": "Ethernet4",
                    "speed": "400G",
                    "admin_state": "up",
                },
                "Ethernet8": {
                    "name": "Ethernet8",
                    "speed": "400G",
                    "admin_state": "up",
                },
            },
        },
        "linecard-b": {
            "asic_to_interface": {"asic0": ["Ethernet12"]},
            "intf_status": {
                "Ethernet12": {
                    "name": "Ethernet12",
                    "speed": "400G",
                    "admin_state": "up",
                },
            },
        },
    }

    request = _request_with_testbed("tbname")
    result = set(namespace["generate_skeleton_port_info"](request))

    assert "400.0-single_linecard_single_asic" in result
    assert "400.0-single_linecard_multiple_asic" in result
    assert (
        "400.0-multiple_linecard_multiple_asic" in result
    )


def test_generate_skeleton_port_info_handles_legacy_metadata_no_asic_map():
    namespace = _load_generate_skeleton_port_info()
    namespace["parse_override"] = lambda *_: (False, None)
    namespace["get_snappi_testbed_metadata"] = lambda *_: {
        "linecard-legacy": {
            "intf_status": {
                "Ethernet0": {
                    "name": "Ethernet0",
                    "speed": "100G",
                    "admin_state": "up",
                },
                "Ethernet4": {
                    "name": "Ethernet4",
                    "speed": "100G",
                    "admin_state": "up",
                },
                "Ethernet8": {
                    "name": "Ethernet8",
                    "speed": "100G",
                    "admin_state": "down",
                },
            },
        }
    }

    request = _request_with_testbed("tbname")
    result = set(namespace["generate_skeleton_port_info"](request))

    assert result == {"100.0-single_linecard_single_asic"}


def test_generate_skeleton_port_info_handles_missing_intf_status():
    namespace = _load_generate_skeleton_port_info()
    namespace["parse_override"] = lambda *_: (False, None)
    namespace["get_snappi_testbed_metadata"] = lambda *_: {
        "linecard-empty": {
            "asic_to_interface": {"asic0": ["Ethernet0"]},
        }
    }

    result = namespace["generate_skeleton_port_info"](
        _request_with_testbed("tbname")
    )

    assert result == []
