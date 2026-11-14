"""Exercise BMC golden configuration generation without DUT-only dependencies."""

import ast
import copy
import json
from pathlib import Path
from unittest.mock import Mock

import pytest


MODULE_PATH = Path(__file__).resolve().parents[3] / "ansible" / "library" / "generate_golden_config_db.py"
ENABLED_FEATURES = ["database", "gnmi", "lldp", "pmon", "redfish", "sysmgr", "telemetry", "acms"]


@pytest.fixture
def bmc_generator():
    """Load the production BMC methods without importing SONiC packages."""
    tree = ast.parse(MODULE_PATH.read_text(encoding="utf-8"))
    module_class = next(node for node in tree.body if isinstance(node, ast.ClassDef)
                        and node.name == "GenerateGoldenConfigDBModule")
    methods = [node for node in module_class.body if isinstance(node, ast.FunctionDef)
               and node.name in ("apply_bmc_feature_allowlist", "_apply_bmc_feature_allowlist_to_features")]
    module_class.body = methods
    namespace = {"copy": copy, "json": json}
    exec(compile(ast.Module(body=[module_class], type_ignores=[]), str(MODULE_PATH), "exec"), namespace)
    instance = namespace["GenerateGoldenConfigDBModule"]()
    instance.module = Mock()
    return instance


def generate(instance, golden, minigraph):
    """Apply the BMC policy to JSON inputs and return the resulting tables."""
    instance.get_config_from_minigraph = Mock(return_value=json.dumps(minigraph))
    result = json.loads(instance.apply_bmc_feature_allowlist(json.dumps(golden), ENABLED_FEATURES))
    instance.get_config_from_minigraph.assert_called_once_with()
    return result


@pytest.mark.parametrize("source", ["minigraph", "golden"])
@pytest.mark.parametrize("golden", [{}, {"DEVICE_METADATA": {"localhost": {"type": "NetworkBmc"}}}])
def test_relocates_console_before_applying_feature_policy(bmc_generator, source, golden):
    """A misplaced console table must not be treated as a service or block Redfish."""
    golden = copy.deepcopy(golden)
    minigraph = {"FEATURE": {
        "redfish": {"state": "disabled", "auto_restart": "enabled", "has_global_scope": "True"},
        "swss": {"state": "enabled", "auto_restart": "enabled"},
    }}
    console = {"console_mgmt": {"enabled": "yes"}}
    target = minigraph if source == "minigraph" else golden
    target.setdefault("FEATURE", {})["CONSOLE_SWITCH"] = copy.deepcopy(console)

    result = generate(bmc_generator, golden, minigraph)

    assert "CONSOLE_SWITCH" not in result["FEATURE"]
    assert result["CONSOLE_SWITCH"] == console
    assert result["FEATURE"]["redfish"] == {
        "state": "enabled", "auto_restart": "enabled", "has_global_scope": "True",
    }
    assert result["FEATURE"]["swss"] == {"state": "disabled", "auto_restart": "disabled"}
    assert result.get("DEVICE_METADATA") == golden.get("DEVICE_METADATA")
    bmc_generator.module.warn.assert_called_once()
    assert "FEATURE.CONSOLE_SWITCH" in bmc_generator.module.warn.call_args.args[0]


def test_console_precedence_and_preservation(bmc_generator):
    """Explicit golden console settings win over top-level minigraph and relocated settings."""
    minigraph = {
        "FEATURE": {"CONSOLE_SWITCH": {
            "console_mgmt": {"enabled": "no"},
            "nested_only": {"enabled": "yes"},
        }},
        "CONSOLE_SWITCH": {
            "console_mgmt": {"enabled": "yes"},
            "minigraph_only": {"enabled": "yes"},
        },
        "PORT": {"Ethernet0": {"admin_status": "up"}},
    }
    golden = {
        "CONSOLE_SWITCH": {"console_mgmt": {"enabled": "no"}, "golden_only": {"enabled": "yes"}},
        "DEVICE_METADATA": {"localhost": {"type": "NetworkBmc"}},
    }

    result = generate(bmc_generator, golden, minigraph)

    assert result["CONSOLE_SWITCH"] == {
        "console_mgmt": {"enabled": "no"},
        "nested_only": {"enabled": "yes"},
        "minigraph_only": {"enabled": "yes"},
        "golden_only": {"enabled": "yes"},
    }
    assert result["DEVICE_METADATA"] == golden["DEVICE_METADATA"]
    assert "PORT" not in result


def test_minigraph_top_level_console_wins_over_misplaced_golden(bmc_generator):
    """Correctly placed minigraph settings take precedence over a malformed golden entry."""
    result = generate(bmc_generator, {
        "FEATURE": {"CONSOLE_SWITCH": {"console_mgmt": {"enabled": "no"}}},
    }, {
        "CONSOLE_SWITCH": {"console_mgmt": {"enabled": "yes"}},
    })
    assert result["CONSOLE_SWITCH"] == {"console_mgmt": {"enabled": "yes"}}
    assert result["FEATURE"] == {}
    bmc_generator.module.warn.assert_called_once()


def test_golden_misplaced_console_overrides_minigraph_misplaced_console(bmc_generator):
    """The existing golden-over-minigraph FEATURE merge also applies to malformed entries."""
    result = generate(bmc_generator, {
        "FEATURE": {"CONSOLE_SWITCH": {"console_mgmt": {"enabled": "yes"}}},
    }, {
        "FEATURE": {"CONSOLE_SWITCH": {"console_mgmt": {"enabled": "no"}}},
    })
    assert result["CONSOLE_SWITCH"] == {"console_mgmt": {"enabled": "yes"}}
    assert result["FEATURE"] == {}


@pytest.mark.parametrize("golden", [{}, {"DEVICE_METADATA": {"localhost": {"type": "NetworkBmc"}}}])
def test_normal_inputs_preserve_tables_and_supported_features(bmc_generator, golden):
    """Only existing image/golden features are changed; a normal console service remains valid."""
    golden = copy.deepcopy(golden)
    golden["FEATURE"] = {"redfish": {"state": "disabled", "set_owner": "local"}}
    golden["CONSOLE_SWITCH"] = {"console_mgmt": {"enabled": "yes"}}
    golden["PORT"] = {"Ethernet0": {"admin_status": "down"}}
    original = copy.deepcopy(golden)
    minigraph = {"FEATURE": {
        "redfish": {"state": "disabled", "auto_restart": "enabled"},
        "console": {"state": "enabled", "auto_restart": "enabled", "custom": "keep"},
        "database": {"state": "disabled", "auto_restart": "enabled"},
    }}

    result = generate(bmc_generator, golden, minigraph)

    assert set(result["FEATURE"]) == {"redfish", "console", "database"}
    assert result["FEATURE"]["redfish"] == {"state": "enabled", "set_owner": "local"}
    assert result["FEATURE"]["database"] == {"state": "enabled", "auto_restart": "enabled"}
    assert result["FEATURE"]["console"] == {
        "state": "disabled", "auto_restart": "disabled", "custom": "keep",
    }
    assert {key: value for key, value in result.items() if key != "FEATURE"} == {
        key: value for key, value in golden.items() if key != "FEATURE"
    }
    assert golden == original
    bmc_generator.module.warn.assert_not_called()


@pytest.mark.parametrize("golden", [{}, {"DEVICE_METADATA": {"localhost": {"type": "NetworkBmc"}}}])
def test_absent_services_and_unrelated_minigraph_tables_are_not_added(bmc_generator, golden):
    """An empty or metadata-only golden config must not copy all minigraph tables."""
    result = generate(bmc_generator, golden, {
        "FEATURE": {"lldp": {"state": "disabled"}},
        "PORT": {"Ethernet0": {"admin_status": "up"}},
        "CONSOLE_SWITCH": {"console_mgmt": {"enabled": "yes"}},
    })
    assert result == dict(golden, FEATURE={"lldp": {"state": "enabled"}})
    bmc_generator.module.warn.assert_not_called()


def test_empty_misplaced_console_is_relocated(bmc_generator):
    """Even an empty misplaced table must be removed from FEATURE and reported."""
    result = generate(bmc_generator, {}, {"FEATURE": {"CONSOLE_SWITCH": {}}})
    assert result == {"FEATURE": {}, "CONSOLE_SWITCH": {}}
    bmc_generator.module.warn.assert_called_once()


@pytest.mark.parametrize("malformed_minigraph", [False, True])
def test_repeated_application_is_stable(bmc_generator, malformed_minigraph):
    """Repeated generation must preserve relocated console data and service policy."""
    minigraph = {"FEATURE": {"redfish": {"state": "disabled"}, "swss": {"state": "enabled"}}}
    golden = {"FEATURE": {"CONSOLE_SWITCH": {"console_mgmt": {"enabled": "yes"}}}}
    if malformed_minigraph:
        minigraph["FEATURE"]["CONSOLE_SWITCH"] = {"console_mgmt": {"enabled": "no"}}
    first = generate(bmc_generator, golden, minigraph)
    bmc_generator.module.reset_mock()
    second = generate(bmc_generator, first, minigraph)
    assert second == first
    if malformed_minigraph:
        bmc_generator.module.warn.assert_called_once()
    else:
        bmc_generator.module.warn.assert_not_called()
