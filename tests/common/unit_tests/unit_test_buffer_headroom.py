"""Exercise buffer headroom checks without importing testbed dependencies."""

import ast
import logging
import math
from pathlib import Path
import re
import shlex
from unittest.mock import Mock

import pytest


MODULE_PATH = Path(__file__).resolve().parents[2] / "qos" / "test_buffer.py"
PROFILE_NAME = "pg_lossless_100000_10m_profile"
PROFILE_OID = "ASIC_STATE:SAI_OBJECT_TYPE_BUFFER_PROFILE:oid:0x1"
POOL_OID = "oid:0x2"


def _assert(condition, message):
    assert condition, message


@pytest.fixture
def buffer_namespace():
    tree = ast.parse(MODULE_PATH.read_text())
    names = {
        "_compose_dict_from_cli", "calculate_headroom_data",
        "mellanox_calculate_headroom_data", "check_buffer_profile_details",
        "_restore_shared_headroom_pool_config", "test_shared_headroom_pool_configure",
    }
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
    namespace = {
        "logging": logging,
        "math": math,
        "re": re,
        "pytest_assert": _assert,
        "pytest": pytest,
        "wait_until": lambda timeout, interval, delay, condition, *args: condition(*args),
        "check_qos_db_fv_reference_with_table": lambda dut: False,
        "get_chip_type": lambda dut: "spectrum3",
        "ASIC_TYPE": "mellanox",
        "ASIC_TABLE_KEYS_LOADED": True,
        "LOSSLESS_TRAFFIC_PATTERN_KEYS_LOADED": True,
        "CELL_SIZE": 144,
        "PIPELINE_LATENCY": 38 * 1024,
        "MAC_PHY_DELAY": 1024,
        "LOSSLESS_MTU": 1024,
        "SMALL_PACKET_PERCENTAGE": 50,
        "LOSSLESS_PROFILE_PATTERN": r"pg_lossless_([1-9][0-9]*000)_([1-9][0-9]*m)_profile",
    }
    exec(compile(ast.Module(body=functions, type_ignores=[]), str(MODULE_PATH), "exec"), namespace)
    return namespace


class Dut:
    facts = {"platform": "x86_64-mlnx_msn4700-r0"}

    def __init__(self, ratio, shp_size, profile):
        self.hashes = {
            "PORT|Ethernet0": {"speed": "100000", "mtu": "9100", "lanes": "0,1,2,3"},
            "CABLE_LENGTH|AZURE": {"Ethernet0": "10m"},
            "DEFAULT_LOSSLESS_BUFFER_PARAMETER|AZURE": {"over_subscribe_ratio": ratio},
            "BUFFER_POOL|ingress_lossless_pool": {"xoff": shp_size},
            "BUFFER_PROFILE_TABLE:" + PROFILE_NAME: profile,
            PROFILE_OID: {
                "SAI_BUFFER_PROFILE_ATTR_XON_TH": profile["xon"],
                "SAI_BUFFER_PROFILE_ATTR_XOFF_TH": profile["xoff"],
                "SAI_BUFFER_PROFILE_ATTR_RESERVED_BUFFER_SIZE": profile["size"],
                "SAI_BUFFER_PROFILE_ATTR_POOL_ID": POOL_OID,
                "SAI_BUFFER_PROFILE_ATTR_THRESHOLD_MODE": "SAI_BUFFER_PROFILE_THRESHOLD_MODE_DYNAMIC",
                "SAI_BUFFER_PROFILE_ATTR_SHARED_DYNAMIC_TH": profile["dynamic_th"],
            },
        }

    def shell(self, command):
        args = shlex.split(command)[1:]
        if args[0] == "-n":
            args = args[2:]
        operation, key = args[:2]
        if operation == "keys":
            value = {
                "DEFAULT_LOSSLESS_BUFFER_PARAMETER*": "DEFAULT_LOSSLESS_BUFFER_PARAMETER|AZURE\n",
                "*CABLE_LENGTH*": "CABLE_LENGTH|AZURE",
                "ASIC_STATE:SAI_OBJECT_TYPE_BUFFER_PROFILE*": PROFILE_OID,
            }[key]
        elif operation == "hgetall":
            value = "\n".join(item for pair in self.hashes[key].items() for item in pair)
        else:
            assert operation == "hget", command
            value = self.hashes.get(key, {}).get(args[2], "")
        return {"stdout": value}


@pytest.mark.parametrize("ratio,shp_size,size,xoff", [
    pytest.param("0", "0", 88064, 49152, id="shp-disabled"),
    pytest.param("2", "0", 38912, 47104, id="shp-enabled-by-ratio"),
    pytest.param("0", "1000000", 38912, 47104, id="shp-enabled-by-size"),
])
def test_headroom_matches_actual_shp_mode(buffer_namespace, ratio, shp_size, size, xoff):
    profile = {"xon": "38912", "xoff": str(xoff), "size": str(size), "dynamic_th": "3"}
    dut = Dut(ratio, shp_size, profile)
    # The current DUT configuration, not the setup-time flag, determines the expected values.
    buffer_namespace["DEFAULT_SHARED_HEADROOM_POOL_ENABLED"] = ratio == "0" and shp_size == "0"
    assert buffer_namespace["check_buffer_profile_details"](
        dut, set(), PROFILE_NAME, None, None, "Ethernet0") == (PROFILE_OID, POOL_OID)


@pytest.mark.parametrize("default_shp_enabled", [False, True])
@pytest.mark.parametrize("ratio,xoff", [("0", 49152), ("2", 47104)])
def test_incorrect_size_is_rejected(buffer_namespace, default_shp_enabled, ratio, xoff):
    size = 88064 if ratio == "0" else 38912
    profile = {"xon": "38912", "xoff": str(xoff), "size": str(size + 1024), "dynamic_th": "3"}
    dut = Dut(ratio, "0", profile)
    buffer_namespace["DEFAULT_SHARED_HEADROOM_POOL_ENABLED"] = default_shp_enabled
    # Isolate the size assertion from Redis detection and XOFF compensation.
    buffer_namespace["calculate_headroom_data"] = lambda *args: (
        True, {"xon": 38912, "xoff": xoff, "size": size})
    with pytest.raises(AssertionError, match="doesn't match the std profile"):
        buffer_namespace["check_buffer_profile_details"](dut, set(), PROFILE_NAME, None, None, "Ethernet0")


class ConfigurableDut(Dut):
    def __init__(self, ratio, shp_size):
        super().__init__(ratio, shp_size, {"xon": "38912", "xoff": "47104", "size": "38912", "dynamic_th": "3"})
        self.hashes["CABLE_LENGTH|AZURE"]["Ethernet0"] = "5m"
        self.hashes["BUFFER_POOL_TABLE:ingress_lossless_pool"] = {
            "size": "123456", "xoff": "1000000" if int(ratio or "0") or int(shp_size or "0") else "0",
        }
        for key, field in [
                ("DEFAULT_LOSSLESS_BUFFER_PARAMETER|AZURE", "over_subscribe_ratio"),
                ("BUFFER_POOL|ingress_lossless_pool", "xoff")]:
            if not self.hashes[key][field]:
                del self.hashes[key][field]
        self.failed_command = None

    def shell(self, command):
        args = shlex.split(command)
        if args[:3] == ["config", "buffer", "shared-headroom-pool"]:
            key, field = (
                ("DEFAULT_LOSSLESS_BUFFER_PARAMETER|AZURE", "over_subscribe_ratio")
                if args[3] == "over-subscribe-ratio" else ("BUFFER_POOL|ingress_lossless_pool", "xoff"))
            self.hashes[key][field] = args[4]
        elif args[:3] == ["config", "interface", "cable-length"]:
            self.hashes["CABLE_LENGTH|AZURE"][args[3]] = args[4]
        elif args[:4] == ["redis-cli", "-n", "4", "hdel"]:
            self.hashes[args[4]].pop(args[5], None)
        else:
            return super().shell(command)
        return {"stdout": ""}

    def shell_cmds(self, cmds, continue_on_fail, module_ignore_errors):
        assert continue_on_fail and module_ignore_errors
        results = []
        for command in cmds:
            rc = 1 if command == self.failed_command else 0
            if not rc:
                self.shell(command)
            results.append({"cmd": command, "rc": rc})
        return {"results": results}


@pytest.mark.parametrize("ratio,configured_size", [("0", "0"), ("2", "0"), ("0", "1000000"), ("", "")])
@pytest.mark.parametrize("shp_enabled", [False, True])
def test_case_failure_restores_original_shp_state(buffer_namespace, ratio, configured_size, shp_enabled):
    dut = ConfigurableDut(ratio, configured_size)
    original_config = {key: values.copy() for key, values in dut.hashes.items()}
    profiles_check = Mock()
    buffer_namespace.update({
        "TESTPARAM_SHARED_HEADROOM_POOL": {"size": 1000000},
        "check_buffer_profiles_for_shp": profiles_check,
        "fetch_initial_asic_db": lambda host: set(),
        "make_expected_profile_name": lambda *args: PROFILE_NAME,
        "check_buffer_profile_details": Mock(side_effect=RuntimeError("injected profile check failure")),
    })

    with pytest.raises(RuntimeError, match="injected profile check failure"):
        buffer_namespace["test_shared_headroom_pool_configure"](
            {"dut": dut}, "dut", {}, "Ethernet0", None, None, None, shp_enabled)

    assert dut.hashes == original_config
    profiles_check.assert_called_with(
        dut, shp_enabled=bool(int(ratio or "0") or int(configured_size or "0")))


def test_restore_attempts_remaining_commands_after_failure(buffer_namespace):
    dut = ConfigurableDut("2", "0")
    dut.hashes["CABLE_LENGTH|AZURE"]["Ethernet0"] = "10m"
    dut.hashes["BUFFER_POOL|ingress_lossless_pool"]["xoff"] = "500000"
    dut.failed_command = "config buffer shared-headroom-pool over-subscribe-ratio 2"

    with pytest.raises(AssertionError, match="restoration commands failed"):
        buffer_namespace["_restore_shared_headroom_pool_config"](
            dut, "Ethernet0", "2", "0", "5m", "123456", "1000000")

    assert dut.hashes["CABLE_LENGTH|AZURE"]["Ethernet0"] == "5m"
    assert dut.hashes["BUFFER_POOL|ingress_lossless_pool"]["xoff"] == "0"


@pytest.mark.parametrize("stale", ["pool-size", "shp-size", "asic-pool"])
def test_restore_rejects_unconverged_pool(buffer_namespace, stale):
    dut = ConfigurableDut("0", "0")
    if stale != "asic-pool":
        field = "size" if stale == "pool-size" else "xoff"
        dut.hashes["BUFFER_POOL_TABLE:ingress_lossless_pool"][field] = "999999"
    buffer_namespace["get_pool_size_from_asic_db"] = Mock(return_value=("999999", "0"))

    with pytest.raises(AssertionError, match="pool sizes were not restored"):
        buffer_namespace["_restore_shared_headroom_pool_config"](
            dut, "Ethernet0", "0", "0", "5m", "123456", "0", POOL_OID)


@pytest.mark.parametrize("setup_fails", [False, True])
def test_all_port_cables_restored_even_when_fixture_setup_fails(setup_fails):
    path = MODULE_PATH.with_name("buffer_helpers.py")
    tree = ast.parse(path.read_text())
    fixture = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                   and node.name == "update_cable_len_for_all_ports")
    fixture.decorator_list = []
    original = {"Ethernet0": "300m"}
    change = Mock(side_effect=[RuntimeError("cable update did not converge") if setup_fails else None, None])
    namespace = {
        "is_mellanox_device": lambda dut: True,
        "get_ports_with_config_exceed_max_headroom": lambda dut: (original, original),
        "gen_ports_cable_info": lambda *args: {"Ethernet0": "50m"},
        "change_ports_cable_len": change,
    }
    exec(compile(ast.Module(body=[fixture], type_ignores=[]), str(path), "exec"), namespace)
    dut = object()
    generator = namespace["update_cable_len_for_all_ports"](dut, None)
    if setup_fails:
        with pytest.raises(RuntimeError, match="cable update did not converge"):
            next(generator)
    else:
        next(generator)
        generator.close()
    assert change.call_count == 2
    change.assert_called_with(dut, original)
