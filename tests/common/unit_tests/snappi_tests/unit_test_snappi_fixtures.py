"""Isolated MACsec setup, ownership, and health-check marker regressions."""

import ast
import json
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, call, mock_open

import pytest


TESTS_PATH = Path(__file__).resolve().parents[3]
MODULE_PATH = TESTS_PATH / "common/snappi_tests/snappi_fixtures.py"
PROFILE_NAME = "256_XPN_SCI"
PROFILE = {
    "priority": 16, "cipher_suite": "GCM-AES-XPN-256", "primary_cak": "test-cak",
    "primary_ckn": "test-ckn", "policy": "security", "send_sci": "true", "rekey_period": 0,
}


def _pytest_assert(condition, message):
    assert condition, message


def _load(*names, **dependencies):
    nodes = [node for node in ast.parse(MODULE_PATH.read_text()).body
             if isinstance(node, ast.FunctionDef) and node.name in names]
    namespace = {"pytest_assert": _pytest_assert, "logger": MagicMock(),
                 "set_macsec_profile": MagicMock(), "delete_macsec_profile": MagicMock()}
    namespace.update(dependencies)
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(MODULE_PATH), "exec"), namespace)
    return namespace


@pytest.mark.parametrize("namespaces", [[None], ["asic0", "asic1"]])
def test_shared_compatible_profile_is_reused_without_deletion(namespaces):
    host = MagicMock(hostname="test_dut", is_multi_asic=namespaces != [None])
    host.get_asic_namespace_list.return_value = namespaces
    host.config_facts.return_value = {"ansible_facts": {
        "MACSEC_PROFILE": {PROFILE_NAME: {key: str(value) for key, value in PROFILE.items()}},
        "PORT": {"Ethernet20": {"macsec": PROFILE_NAME}},
    }}
    namespace = _load("_ensure_macsec_profile")

    assert namespace["_ensure_macsec_profile"](host, PROFILE_NAME, PROFILE) is False

    namespace["delete_macsec_profile"].assert_not_called()
    namespace["set_macsec_profile"].assert_not_called()
    assert host.config_facts.call_args_list == [
        call(host="test_dut", source="running", namespace=asic) for asic in namespaces]


@pytest.mark.parametrize("field, value", [("primary_ckn", "different"), ("enable_replay_protect", "true")])
def test_incompatible_bound_profile_fails_without_modifying_other_ports(field, value):
    profile = dict(PROFILE, **{field: value})
    host = MagicMock(hostname="test_dut", is_multi_asic=False)
    host.config_facts.return_value = {"ansible_facts": {
        "MACSEC_PROFILE": {PROFILE_NAME: profile}, "PORT": {"Ethernet20": {"macsec": PROFILE_NAME}},
    }}
    namespace = _load("_ensure_macsec_profile")

    with pytest.raises(AssertionError, match="while bound to.*Ethernet20"):
        namespace["_ensure_macsec_profile"](host, PROFILE_NAME, PROFILE)

    namespace["delete_macsec_profile"].assert_not_called()
    namespace["set_macsec_profile"].assert_not_called()


@pytest.mark.parametrize("deletion_succeeds", [False, True])
def test_unused_incompatible_profile_requires_successful_deletion(deletion_succeeds):
    old_facts = {"MACSEC_PROFILE": {PROFILE_NAME: dict(PROFILE, primary_ckn="old")}, "PORT": {}}
    host = MagicMock(hostname="test_dut", is_multi_asic=False)
    host.config_facts.side_effect = [
        {"ansible_facts": old_facts},
        {"ansible_facts": {} if deletion_succeeds else old_facts},
    ]
    namespace = _load("_ensure_macsec_profile")

    if deletion_succeeds:
        assert namespace["_ensure_macsec_profile"](host, PROFILE_NAME, PROFILE) is True
        namespace["set_macsec_profile"].assert_called_once_with(
            host, PROFILE_NAME, 16, "GCM-AES-XPN-256", "test-cak", "test-ckn", "security", "true", 0)
    else:
        with pytest.raises(AssertionError, match="Failed to remove MACsec profile"):
            namespace["_ensure_macsec_profile"](host, PROFILE_NAME, PROFILE)
        namespace["set_macsec_profile"].assert_not_called()
    namespace["delete_macsec_profile"].assert_called_once_with(host, PROFILE_NAME)


def _macsec_fixture_context(original_profile):
    host = MagicMock(hostname="test_dut")
    host.get_port_asic_instance.return_value = None
    host.config_facts.return_value = {"ansible_facts": {
        "INTERFACE": {"Ethernet12": {"192.0.2.1/24": {}}},
        "PORT": {"Ethernet12": {} if original_profile is None else {"macsec": original_profile}},
    }}
    port = {"peer_device": "test_dut", "duthost": host, "peer_port": "Ethernet12",
            "port_id": "1", "asic_value": None}
    config, device = MagicMock(), MagicMock()
    config.ports = [SimpleNamespace(name="Port 0"), SimpleNamespace(name="Port 1")]
    config.devices.device.return_value = [device]
    settings = {
        PROFILE_NAME: deepcopy(PROFILE),
        "snappi": {
            "tx_pn_choice": "fixed_pn", "key_derivation_function": "aes_cmac_256",
            "actor_priority": 16, "cak_name": "test-ckn", "cak_value": "test-cak",
            "mka_rekey_mode_choice": "timer_based", "mka_rekey_timer_choice": "continuous",
            "mka_rekey_timer_interval": 240, "cipher_suite": "gcm_aes_xpn_256", "confidentiality_offset": 0,
        },
    }
    namespace = _load(
        "__intf_config_macsec", "cleanup_config", sys=SimpleNamespace(argv=["--snappi_macsec"]),
        os=SimpleNamespace(path=SimpleNamespace(expanduser=lambda path: path)),
        json=json, open=mock_open(read_data=json.dumps(settings)), reconfigure_port={},
        macsec_enabled_ports=[], macsec_profile_duthosts=[], macsec_profile_name="",
        _ensure_macsec_profile=MagicMock(return_value=original_profile != PROFILE_NAME),
        enable_macsec_port=MagicMock(), disable_macsec_port=MagicMock(),
        subnet_mask_from_hosts=lambda count: 24, get_addrs_in_subnet=lambda *args, **kwargs: ["192.0.2.2"],
        __gen_mac=lambda index: "00:00:00:00:00:01", gen_data_flow_dest_ip=MagicMock(),
        SnappiPortConfig=MagicMock(), SnappiPortType=SimpleNamespace(MacsecInterface="macsec"))
    return namespace, host, port, config, device, settings


@pytest.mark.parametrize("original_profile", [None, "original-profile", PROFILE_NAME])
def test_macsec_fixture_preserves_existing_bindings(original_profile):
    namespace, host, port, config, _, _ = _macsec_fixture_context(original_profile)

    assert namespace["__intf_config_macsec"](config, [], host, [port])
    namespace["_ensure_macsec_profile"].assert_called_once_with(host, PROFILE_NAME, PROFILE)

    namespace["cleanup_config"]([host], [port])
    namespace["cleanup_config"]([host], [port])

    if original_profile == PROFILE_NAME:
        namespace["enable_macsec_port"].assert_not_called()
        namespace["disable_macsec_port"].assert_not_called()
        namespace["delete_macsec_profile"].assert_not_called()
    else:
        expected_enables = [call(host, "Ethernet12", PROFILE_NAME)]
        if original_profile is not None:
            expected_enables.append(call(host, "Ethernet12", original_profile))
        assert namespace["enable_macsec_port"].call_args_list == expected_enables
        assert namespace["disable_macsec_port"].call_count == (2 if original_profile else 1)
        namespace["delete_macsec_profile"].assert_called_once_with(host, PROFILE_NAME)


def test_macsec_fixture_configures_a_non_expiring_cak():
    """Verify the configured PSK translates to indefinite CAK validity."""
    mka_adapter = pytest.importorskip("snappi_ixnetwork.device.mka")
    namespace, host, port, config, device, _ = _macsec_fixture_context(None)
    assert namespace["__intf_config_macsec"](config, [], host, [port])

    basic = device.macsec.ethernet_interfaces.add.return_value.secure_entity.key_generation_protocol.mka.basic
    key_source = SimpleNamespace(choice=basic.key_source.choice,
                                 psks=[basic.key_source.psks.add.return_value])
    adapter_basic = SimpleNamespace(key_source=key_source, key_derivation_function=basic.key_derivation_function)
    cak_cache = {}
    adapter = SimpleNamespace(
        logger=MagicMock(), create_node_elemet=lambda *args, **kwargs: cak_cache,
        multivalue=lambda values: values)

    mka_adapter.Mka._config_key_source(adapter, adapter_basic, {})

    assert cak_cache["lifetimeValidity"] == [True]


def test_failed_macsec_binding_restores_the_original_profile():
    namespace, host, port, config, _, _ = _macsec_fixture_context("original-profile")
    namespace["enable_macsec_port"].side_effect = [RuntimeError("MACsec binding failed"), None]

    with pytest.raises(RuntimeError, match="MACsec binding failed"):
        namespace["__intf_config_macsec"](config, [], host, [port])
    namespace["cleanup_config"]([host], [port])
    namespace["cleanup_config"]([host], [port])

    assert namespace["enable_macsec_port"].call_args_list == [
        call(host, "Ethernet12", PROFILE_NAME), call(host, "Ethernet12", "original-profile")]
    namespace["disable_macsec_port"].assert_called_once_with(host, "Ethernet12")
    namespace["delete_macsec_profile"].assert_called_once_with(host, PROFILE_NAME)


@pytest.mark.parametrize("macsec", [False, True])
def test_running_config_baseline_marker_is_macsec_only(macsec):
    path = TESTS_PATH / "snappi_tests/pfc/test_global_pause_with_snappi.py"
    nodes = [
        node for node in ast.parse(path.read_text()).body
        if (isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "pytestmark" for target in node.targets))
        or isinstance(node, ast.If)
    ]
    namespace = {"pytest": pytest, "sys": SimpleNamespace(argv=["--snappi_macsec"] if macsec else [])}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(path), "exec"), namespace)

    marker_names = [marker.name for marker in namespace["pytestmark"]]
    assert ("use_running_config_baseline" in marker_names) is macsec
    assert "topology" in marker_names
