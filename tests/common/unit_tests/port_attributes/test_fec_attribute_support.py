"""Tests for FEC inventory loading, schema validation, and attribute resolution."""

import json
from types import SimpleNamespace

import pytest

from tests.common.platform.fec_utils import (
    filter_interfaces_by_speed,
    get_capability,
    get_max_wait_for_ports,
    resolve_capability,
)
from tests.common.platform.interface_utils import get_fec_candidate_interfaces
from tests.common.port_attributes.builder import build_port_attributes_dict
from tests.common.port_attributes.fec_schema import (
    FecAttributeValidationError,
    validate_fec_shard,
)
from tests.common.port_attributes import pytest_plugin
from tests.common.port_attributes.exceptions import AttributeMergeError, DutInfoError


pytestmark = [
    pytest.mark.topology("any"),
]


def _write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def _fake_dut():
    return SimpleNamespace(
        hostname="dut-1",
        facts={"platform": "platform-1", "hwsku": "hwsku-1"},
    )


def _write_base_inventory(ansible_root, dut_body=None):
    inventory = ansible_root / "files/transceiver/inventory"
    _write_json(
        inventory / "normalization_mappings.json",
        {
            "vendor_names": {"Acme": "ACME"},
            "part_numbers": {"PN-1": "PN-1"},
        },
    )
    if dut_body is None:
        dut_body = {
            "Ethernet0": {
                "vendor_name": "Acme",
                "vendor_pn": "PN-1",
                "transceiver_configuration": "DR8-800-QSFPDD-8x100G_DR8-0x1-0x1",
            }
        }
    _write_json(inventory / "dut_info/dut-1.json", dut_body)
    return inventory


def test_optional_fec_absent_does_not_require_base_inventory(tmp_path):
    assert build_port_attributes_dict(
        tmp_path,
        _fake_dut(),
        categories={"fec"},
        missing_category_ok=True,
    ) == {}

    with pytest.raises(DutInfoError):
        build_port_attributes_dict(tmp_path, _fake_dut())


def test_optional_missing_policy_requires_one_explicit_category(tmp_path):
    with pytest.raises(ValueError, match="exactly one"):
        build_port_attributes_dict(
            tmp_path,
            _fake_dut(),
            categories={"fec", "eeprom"},
            missing_category_ok=True,
        )


def test_factory_cache_isolated_by_dut_and_load_mode(monkeypatch, tmp_path):
    calls = []

    def fake_builder(ansible_root, duthost, **options):
        calls.append((ansible_root, duthost.hostname, options))
        return {"marker": len(calls)}

    monkeypatch.setattr(pytest_plugin, "build_port_attributes_dict", fake_builder)
    factory = pytest_plugin.port_attributes_dict_factory.__wrapped__(tmp_path)

    fec_result = factory(
        _fake_dut(),
        categories={"fec"},
        missing_category_ok=True,
    )
    assert factory(
        _fake_dut(),
        categories=("fec",),
        missing_category_ok=True,
    ) is fec_result

    strict_result = factory(_fake_dut(), categories=None, missing_category_ok=False)
    other_dut = SimpleNamespace(
        hostname="dut-2",
        facts={"platform": "platform-1", "hwsku": "hwsku-1"},
    )
    other_result = factory(
        other_dut,
        categories={"fec"},
        missing_category_ok=True,
    )

    assert strict_result != fec_result
    assert other_result != fec_result
    assert len(calls) == 3


def test_present_fec_requires_base_inventory(tmp_path):
    _write_json(
        tmp_path / "files/transceiver/inventory/attributes/fec/fec.json",
        {},
    )
    with pytest.raises(DutInfoError, match="normalization_mappings"):
        build_port_attributes_dict(
            tmp_path,
            _fake_dut(),
            categories={"fec"},
            missing_category_ok=True,
        )


def test_present_fec_rejects_empty_dut_inventory(tmp_path):
    inventory = _write_base_inventory(tmp_path, dut_body={})
    _write_json(inventory / "attributes/fec/fec.json", {})

    with pytest.raises(DutInfoError, match="contains no ports"):
        build_port_attributes_dict(
            tmp_path,
            _fake_dut(),
            categories={"fec"},
            missing_category_ok=True,
        )


def test_fec_only_load_ignores_malformed_unrelated_category(tmp_path):
    inventory = _write_base_inventory(tmp_path)
    _write_json(
        inventory / "attributes/fec/fec.json",
        {"defaults": {"supported_speeds": ["100G"]}},
    )
    _write_json(inventory / "attributes/eeprom/eeprom.json", {"unexpected": {}})

    resolved = build_port_attributes_dict(
        tmp_path,
        _fake_dut(),
        categories={"fec"},
        missing_category_ok=True,
    )
    assert resolved["Ethernet0"]["FEC_ATTRIBUTES"]["supported_speeds"] == ["100G"]

    with pytest.raises(AttributeMergeError):
        build_port_attributes_dict(tmp_path, _fake_dut())


def test_fec_schema_validation_requires_explicit_fec_load(tmp_path):
    inventory = _write_base_inventory(tmp_path)
    _write_json(
        inventory / "attributes/eeprom/eeprom.json",
        {"defaults": {"vdm_supported": True}},
    )
    _write_json(
        inventory / "attributes/fec/fec.json",
        {"defaults": {"unknown_fec_key": True}},
    )

    resolved = build_port_attributes_dict(tmp_path, _fake_dut())

    assert resolved["Ethernet0"]["EEPROM_ATTRIBUTES"] == {"vdm_supported": True}
    assert resolved["Ethernet0"]["FEC_ATTRIBUTES"] == {"unknown_fec_key": True}

    with pytest.raises(AttributeMergeError, match="unknown FEC attribute"):
        build_port_attributes_dict(
            tmp_path,
            _fake_dut(),
            categories={"fec"},
            missing_category_ok=True,
        )


@pytest.mark.parametrize(
    "attributes",
    [
        {"basic_fec_stats_supported": "false"},
        {"basic_fec_stats_supported": 1},
        {"fec_mode_restore_timeout_sec": 0},
        {"clear_counters_wait_sec": -1},
        {"clear_counters_wait_sec": False},
        {"clear_counters_wait_sec": 1.5},
        {"supported_speeds": "100G"},
        {"supported_speeds": []},
        {"supported_speeds": ["100G", "100G"]},
        {"critical_histogram_bins": [7, -1]},
        {"critical_histogram_bins": [True]},
        {"critical_histogram_bins": [7, 7]},
        {"misspelled_attribute": True},
    ],
)
def test_fec_schema_rejects_invalid_values(attributes):
    with pytest.raises(FecAttributeValidationError):
        validate_fec_shard("platform", "/tmp/fec.json", {}, attributes)


@pytest.mark.parametrize(
    "attribute_name",
    [
        "fec_stats_supported",
        "fec_histogram_supported",
        "ber_counters_supported",
        "observed_flr_supported",
        "predicted_flr_supported",
    ],
)
def test_fec_schema_rejects_obsolete_attributes(attribute_name):
    with pytest.raises(FecAttributeValidationError, match="unknown FEC attribute"):
        validate_fec_shard("platform", "/tmp/fec.json", {}, {attribute_name: True})


@pytest.mark.parametrize(
    "relative_path,body",
    [
        (
            "attributes/fec/fec.json",
            {"defaults": {"unknown_fec_key": True}},
        ),
        (
            "attributes/fec/fec.json",
            {"dut": {"dut-1": {"basic_fec_stats_supported": "true"}}},
        ),
        (
            "attributes/fec/fec.json",
            {
                "transceivers": {
                    "deployment_configurations": {
                        "8x100G_DR8": {"critical_histogram_bins": [-1]}
                    }
                }
            },
        ),
        (
            "attributes/fec/platforms/platform-1/fec.json",
            {"clear_counters_wait_sec": -1},
        ),
        (
            "attributes/fec/platforms/platform-1/hwskus/hwsku-1.json",
            {"verify_fec_oper_mode_supported": 1},
        ),
        (
            "attributes/fec/transceivers/vendors/ACME/fec.json",
            {"supported_speeds": []},
        ),
        (
            "attributes/fec/transceivers/vendors/ACME/part_numbers/PN-1/fec.json",
            {"configure_fec_oper_mode_supported": None},
        ),
        (
            "attributes/fec/transceivers/vendors/ACME/part_numbers/PN-1/fec.json",
            {
                "platform_hwsku_overrides": {
                    "platform-1+hwsku-1": {"fec_mode_restore_timeout_sec": 0}
                }
            },
        ),
    ],
)
def test_builder_preflights_invalid_fec_values_at_every_scope(
    tmp_path,
    relative_path,
    body,
):
    inventory = _write_base_inventory(tmp_path)
    _write_json(inventory / relative_path, body)

    with pytest.raises(AttributeMergeError, match="validation failed"):
        build_port_attributes_dict(
            tmp_path,
            _fake_dut(),
            categories={"fec"},
            missing_category_ok=True,
        )


def test_builder_resolves_valid_fec_values_from_all_supported_scopes(tmp_path):
    inventory = _write_base_inventory(tmp_path)
    _write_json(
        inventory / "attributes/fec/fec.json",
        {
            "defaults": {
                "supported_speeds": ["100G"],
                "fec_mode_restore_timeout_sec": 30,
                "clear_counters_wait_sec": 60,
                "fec_histogram_stale_error_wait_sec": 600,
                "critical_histogram_bins": [7, 8, 9, 10, 11, 12, 13, 14, 15],
            },
            "dut": {"dut-1": {"clear_counters_wait_sec": 75}},
            "transceivers": {
                "deployment_configurations": {
                    "8x100G_DR8": {"basic_fec_stats_supported": True}
                }
            },
        },
    )
    _write_json(
        inventory / "attributes/fec/platforms/platform-1/fec.json",
        {"verify_fec_oper_mode_supported": True},
    )
    _write_json(
        inventory / "attributes/fec/platforms/platform-1/hwskus/hwsku-1.json",
        {"configure_fec_oper_mode_supported": True},
    )
    _write_json(
        inventory / "attributes/fec/transceivers/vendors/ACME/fec.json",
        {"fec_histogram_stale_error_wait_sec": 500},
    )
    _write_json(
        inventory / "attributes/fec/transceivers/vendors/ACME/part_numbers/PN-1/fec.json",
        {
            "supported_speeds": ["200G"],
            "platform_hwsku_overrides": {
                "platform-1+hwsku-1": {"critical_histogram_bins": [8, 9]}
            },
        },
    )

    resolved = build_port_attributes_dict(
        tmp_path,
        _fake_dut(),
        categories={"fec"},
        missing_category_ok=True,
    )["Ethernet0"]["FEC_ATTRIBUTES"]

    assert resolved == {
        "supported_speeds": ["200G"],
        "basic_fec_stats_supported": True,
        "verify_fec_oper_mode_supported": True,
        "configure_fec_oper_mode_supported": True,
        "fec_mode_restore_timeout_sec": 30,
        "clear_counters_wait_sec": 75,
        "fec_histogram_stale_error_wait_sec": 500,
        "critical_histogram_bins": [8, 9],
    }


def test_builder_preserves_platform_scope_when_hwsku_is_missing(tmp_path):
    inventory = _write_base_inventory(tmp_path)
    _write_json(
        inventory / "attributes/fec/fec.json",
        {"defaults": {"supported_speeds": ["100G"]}},
    )
    _write_json(
        inventory / "attributes/fec/platforms/platform-1/fec.json",
        {"verify_fec_oper_mode_supported": True},
    )
    duthost = _fake_dut()
    duthost.facts = {"platform": "platform-1"}

    resolved = build_port_attributes_dict(
        tmp_path,
        duthost,
        categories={"fec"},
        missing_category_ok=True,
    )["Ethernet0"]["FEC_ATTRIBUTES"]

    assert resolved["verify_fec_oper_mode_supported"] is True


def test_per_port_speed_capability_and_wait_resolution():
    port_attrs = {
        "Ethernet0": {
            "FEC_ATTRIBUTES": {
                "supported_speeds": ["100G"],
                "basic_fec_stats_supported": False,
                "clear_counters_wait_sec": 60,
            }
        },
        "Ethernet4": {
            "FEC_ATTRIBUTES": {
                "supported_speeds": ["400G"],
                "clear_counters_wait_sec": 75,
            }
        },
        "Ethernet8": {
            "FEC_ATTRIBUTES": {
                "basic_fec_stats_supported": True,
                "clear_counters_wait_sec": 120,
            }
        },
    }
    candidates = {
        "Ethernet0": "100G",
        "Ethernet4": "100G",
        "Ethernet8": "800G",
        "Ethernet12": "400G",
    }

    assert filter_interfaces_by_speed(candidates, port_attrs) == [
        "Ethernet0",
        "Ethernet8",
        "Ethernet12",
    ]
    assert get_capability(port_attrs, "Ethernet0", "basic_fec_stats_supported") is False
    assert get_capability(port_attrs, "Ethernet4", "basic_fec_stats_supported") is None
    assert not resolve_capability(
        port_attrs,
        "Ethernet0",
        "basic_fec_stats_supported",
        legacy_supported=True,
    )
    assert resolve_capability(
        port_attrs,
        "Ethernet4",
        "basic_fec_stats_supported",
        legacy_supported=True,
    )
    assert resolve_capability(
        port_attrs,
        "Ethernet8",
        "basic_fec_stats_supported",
        legacy_supported=False,
    )
    assert get_max_wait_for_ports(
        port_attrs,
        ["Ethernet0", "Ethernet4", "Ethernet8"],
        "clear_counters_wait_sec",
    ) == 120


def test_candidate_discovery_queries_live_state_once():
    class FakeDut:
        def __init__(self):
            self.calls = []

        def show_and_parse(self, command):
            self.calls.append(command)
            if command == "show interface status":
                return [
                    {"interface": "Ethernet0", "oper": "up", "speed": "100G"},
                    {"interface": "Ethernet4", "oper": "down", "speed": "400G"},
                    {"interface": "Ethernet8", "oper": "up", "speed": ""},
                ]
            if command == "sudo sfpshow presence":
                return [
                    {"port": "Ethernet0", "presence": "Present"},
                    {"port": "Ethernet4", "presence": "Present"},
                    {"port": "Ethernet8", "presence": "Present"},
                ]
            raise AssertionError(command)

    duthost = FakeDut()
    assert get_fec_candidate_interfaces(duthost) == {"Ethernet0": "100G"}
    assert duthost.calls == ["show interface status", "sudo sfpshow presence"]
