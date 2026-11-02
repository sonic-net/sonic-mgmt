"""Verify the real IPinIP packet-generation chain without a DUT or testbed imports."""

import ast
import hashlib
import itertools
import json
import logging
import random
import secrets
import struct
import subprocess
import sys
from collections import defaultdict
from collections.abc import Iterable
from datetime import datetime
from ipaddress import ip_address, ip_network
from pathlib import Path
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock, patch

import ptf.packet as scapy
import ptf.testutils as testutils
import pytest
import six
from ptf.mask import Mask


ROOT = Path(__file__).resolve().parents[3]
PTF_PATH = ROOT / "ansible" / "roles" / "test" / "files" / "ptftests"


def load_definitions(path, names, namespace):
    tree = ast.parse(path.read_text())
    definitions = [node for node in tree.body if getattr(node, "name", None) in names]
    exec(compile(ast.Module(body=definitions, type_ignores=[]), str(path), "exec"), namespace)


@pytest.fixture
def packet_runner(tmp_path):
    next_hop = SimpleNamespace(
        get_next_hop_list=lambda: list(range(16)),
        get_next_hop=lambda: [[port] for port in range(16)])

    class Fib:
        def __init__(self, _):
            pass

        def __getitem__(self, _):
            return next_hop

    port_map = {str(port): {
        "target_dut": [0], "target_src_mac": ["00:aa:bb:cc:dd:ee"],
        "target_dest_mac": "00:aa:bb:cc:dd:ee"
    } for port in range(18)}
    port_map_path = tmp_path / "port_map.json"
    port_map_path.write_text(json.dumps(port_map))
    namespace = {
        "logging": logging, "random": random, "json": json, "six": six, "itertools": itertools,
        "hashlib": hashlib, "secrets": secrets, "struct": struct, "sys": sys,
        "time": SimpleNamespace(sleep=lambda _: None), "Iterable": Iterable, "defaultdict": defaultdict,
        "retry_call": lambda func, fargs, **kwargs: func(*fargs),
        "ip_address": ip_address, "ip_network": ip_network, "BaseTest": TestCase, "Mask": Mask,
        "scapy": scapy, "fib": SimpleNamespace(Fib=Fib),
    }
    namespace.update({name: getattr(testutils, name) for name in (
        "simple_tcp_packet", "simple_tcpv6_packet", "simple_ipv4ip_packet", "simple_ipv6ip_packet")})
    load_definitions(PTF_PATH / "lpm.py", {"LpmDict"}, namespace)
    namespace["lpm"] = SimpleNamespace(LpmDict=namespace["LpmDict"])
    load_definitions(PTF_PATH / "py3" / "hash_test.py", {"HashTest", "IPinIPHashTest"}, namespace)

    def run(seed, debug=False, ipver="ipv4", v6_outer=False,
            keys=("src-ip", "dst-ip", "src-port", "dst-port", "ingress-port", "ip-proto", "inner_length"),
            unbalanced=False, mac_prefix="02:00:00:00:00"):
        params = {
            "fib_info_files": ["unused"], "ptf_test_port_map": str(port_map_path),
            "src_ip_range": "8.0.0.0,8.255.255.255" if ipver == "ipv4" else "20d0:a800::,20d0:ffff::ffff",
            "dst_ip_range": "9.0.0.0,9.255.255.255" if ipver == "ipv4" else "20d0:a800:0:1::,20d0:ffff:0:1::ffff",
            "ipver": ipver, "is_v6_topo": v6_outer, "topo_name": "t1", "topo_type": "t1",
            "balancing_test_times": 2, "hash_seed": seed, "hash_debug": debug,
        }
        namespace["test_params_get"] = lambda: params
        dataplane = SimpleNamespace(
            ports={(0, port): None for port in range(18)},
            get_mac=lambda device, port: "{}:{:02x}".format(mac_prefix, port))
        namespace["ptf"] = SimpleNamespace(dataplane_instance=dataplane)
        traces = {}
        fingerprints = {}
        last_packet = []

        def send(test, ingress, packet):
            assert isinstance(packet, bytes)
            traces.setdefault(test._hash_key, []).append((ingress, packet))
            last_packet[:] = [packet]

        def receive(test, expected, ports, **kwargs):
            received = scapy.Ether(last_packet[0])
            received.src = "00:aa:bb:cc:dd:ee"
            if v6_outer:
                received["IPv6"].hlim -= 1
            else:
                received["IP"].ttl -= 1
                del received["IP"].chksum
            received_bytes = bytes(received)
            assert expected.pkt_match(received_bytes)
            port_index = 0 if unbalanced or test._hash_key in ("ingress-port", "inner_length") else (
                len(traces[test._hash_key]) - 1) % len(ports)
            return port_index, received_bytes

        namespace["send_packet"] = send
        namespace["verify_packet_any_port"] = receive
        test = namespace["IPinIPHashTest"]()
        test.setUp()
        for key in keys:
            test.check_hash(key)
            fingerprints[key] = test._input_digest.hexdigest()
        return traces, fingerprints, test

    return run


@pytest.mark.parametrize("ipver,v6_outer", [("ipv4", False), ("ipv6", False), ("ipv6", True)])
@pytest.mark.parametrize("seed", [0, 123456])
def test_identical_packets_with_debug_and_global_random_interference(packet_runner, ipver, v6_outer, seed):
    original, fingerprints, _ = packet_runner(seed, ipver=ipver, v6_outer=v6_outer)
    with patch.object(random, "randint", side_effect=AssertionError("shared RNG used")), \
            patch.object(random, "choice", side_effect=AssertionError("shared RNG used")), \
            patch.object(random, "randrange", side_effect=AssertionError("shared RNG used")):
        replay, replay_fingerprints, _ = packet_runner(seed, True, ipver=ipver, v6_outer=v6_outer)
    assert original == replay
    assert fingerprints == replay_fingerprints
    for key, packets in replay.items():
        digest = hashlib.sha256()
        for ingress, packet in packets:
            digest.update(struct.pack("!II", ingress, len(packet)))
            digest.update(packet)
        assert digest.hexdigest() == replay_fingerprints[key]


def test_key_replays_independently_of_previous_keys(packet_runner):
    full, _, _ = packet_runner(123456)
    isolated, _, _ = packet_runner(123456, keys=("ip-proto",))
    assert full["ip-proto"] == isolated["ip-proto"]
    different, _, _ = packet_runner(654321, keys=("ip-proto",))
    assert isolated["ip-proto"] != different["ip-proto"]


def test_protocol_diagnostics_only_when_enabled(packet_runner, caplog):
    caplog.set_level(logging.INFO)
    packets, _, test = packet_runner(123456, keys=("ip-proto",))
    assert not test._protocol_sent
    assert "protocol_sent=" not in caplog.text
    _, _, test = packet_runner(123456, True, keys=("ip-proto",))
    assert sum(test._protocol_sent.values()) == len(packets["ip-proto"])
    assert sum(sum(ports.values()) for ports in test._protocol_received.values()) == len(packets["ip-proto"])
    assert "protocol_sent=" in caplog.text


def test_changed_ptf_mac_is_logged_without_changing_hash_flows(packet_runner, caplog):
    caplog.set_level(logging.INFO)
    original, _, first = packet_runner(123456, keys=("ip-proto",))
    replay, _, second = packet_runner(123456, True, keys=("ip-proto",), mac_prefix="02:01:02:03:04")
    assert original != replay
    for (first_port, first_packet), (second_port, second_packet) in zip(original["ip-proto"], replay["ip-proto"]):
        assert first_port == second_port
        assert first_packet[:6] + first_packet[12:] == second_packet[:6] + second_packet[12:]
    assert "base_mac={}".format(first.base_mac) in caplog.text
    assert "base_mac={}".format(second.base_mac) in caplog.text


def test_original_unbalanced_assertion_and_fingerprint_are_preserved(packet_runner, caplog):
    caplog.set_level(logging.INFO)
    with pytest.raises(AssertionError):
        packet_runner(123456, True, keys=("ip-proto",), unbalanced=True)
    assert "Hash replay ipver=ipv4 key=ip-proto seed=123456 packets=32 input_sha256=" in caplog.text
    assert "protocol_sent=" in caplog.text


def test_auto_seed_is_logged_and_replayable(packet_runner, caplog):
    caplog.set_level(logging.INFO)
    original, _, test = packet_runner(None, keys=("src-ip",))
    replay, _, _ = packet_runner(test.hash_seed, keys=("src-ip",))
    assert original == replay
    assert "IPinIP hash seed={}".format(test.hash_seed) in caplog.text


@pytest.fixture
def diagnostic_namespace():
    class RunAnsibleModuleFail(RuntimeError):
        pass

    namespace = {"pytest": pytest, "shlex": __import__("shlex"), "logger": logging.getLogger(__name__),
                 "RunAnsibleModuleFail": RunAnsibleModuleFail}
    load_definitions(ROOT / "tests" / "fib" / "test_fib.py",
                     {"hash_replay_params", "log_hash_state", "hash_debug_snapshot"}, namespace)
    return namespace


def test_dut_diagnostics_are_gated_and_do_not_mask_failure(diagnostic_namespace, caplog):
    request = Mock()
    request.config.getoption.return_value = False
    generator = diagnostic_namespace["hash_debug_snapshot"].__wrapped__(request, None)
    next(generator)
    with pytest.raises(StopIteration):
        next(generator)
    request.getfixturevalue.assert_not_called()
    request.config.getoption.return_value = True
    dut = Mock(hostname="dut")
    dut.get_asic_namespace_list.return_value = ["", "asic0"]
    dut.shell.return_value = {"rc": 124, "stdout": "", "stderr": "timeout"}
    request.getfixturevalue.return_value = [dut]
    generator = diagnostic_namespace["hash_debug_snapshot"].__wrapped__(request, None)
    next(generator)
    with pytest.raises(AssertionError, match="original failure"):
        generator.throw(AssertionError("original failure"))
    assert dut.shell.call_count == 16
    assert "Hash debug ASIC_DB query failed" in caplog.text
    assert all("timeout 10" in call.args[0] for call in dut.shell.call_args_list)


def test_dut_snapshot_uses_supported_cli_commands(diagnostic_namespace, caplog):
    caplog.set_level(logging.INFO)
    cli = """
sonic-db-cli() {
    case "$2" in
        KEYS)
            if [[ "$3" == *SAI_OBJECT_TYPE_HASH:* ]]; then
                printf '\\n'
            else
                printf '%s\\n' "${3%\\*}oid:0x1"
            fi;;
        HGETALL) [ -n "$3" ] || return 1; printf 'SAI_TEST_ATTR\\nvalue\\n';;
        *) echo "Unsupported sonic-db-cli argument: $2" >&2; return 255;;
    esac
}
export -f sonic-db-cli
"""

    def shell(command, **_):
        result = subprocess.run(["bash", "-c", cli + command], capture_output=True, text=True)
        return {"rc": result.returncode, "failed": result.returncode != 0,
                "stdout": result.stdout, "stderr": result.stderr}

    dut = Mock(hostname="dut")
    dut.get_asic_namespace_list.return_value = [""]
    dut.shell.side_effect = shell
    diagnostic_namespace["log_hash_state"]([dut], "before")
    assert "query failed" not in caplog.text
    for object_type in ("SWITCH", "NEXT_HOP_GROUP", "NEXT_HOP_GROUP_MEMBER"):
        assert "ASIC_STATE:SAI_OBJECT_TYPE_{}:oid:0x1".format(object_type) in caplog.text
    assert "phase=before type=HASH" in caplog.text
    assert caplog.text.count("SAI_TEST_ATTR") == 3


def test_seed_and_debug_are_forwarded(diagnostic_namespace):
    request = Mock()
    request.config.getoption.side_effect = lambda option: {"--hash-seed": 0, "--hash-debug": True}[option]
    assert diagnostic_namespace["hash_replay_params"].__wrapped__(request) == {"hash_seed": 0, "hash_debug": True}


@pytest.mark.parametrize("test_name", ["test_ipinip_hash", "test_ipinip_hash_negative"])
def test_pytest_entry_forwards_replay_parameters_to_ptf(test_name):
    namespace = {
        "logging": logging, "datetime": datetime, "is_ipv6_only_topology": lambda _: False,
        "fib_info_files_per_function": Mock(return_value=["fib"]), "ptf_test_port_map_active_active": Mock(),
        "ptf_runner": Mock(), "pytest_require": Mock(),
        "skip_if_no_ecmp_to_hash_over": Mock(),
        "SRC_IP_RANGE": ["8.0.0.0", "8.255.255.255"], "DST_IP_RANGE": ["9.0.0.0", "9.255.255.255"],
        "VLANIDS": [], "PTF_QLEN": 20000,
    }
    path = ROOT / "tests" / "fib" / "test_fib.py"
    load_definitions(path, {test_name}, namespace)
    tree = ast.parse(path.read_text())
    definition = next(node for node in tree.body if getattr(node, "name", None) == test_name)
    args = {argument.arg: Mock() for argument in definition.args.args}
    args.update(ipver="ipv4", tbinfo={"topo": {"name": "t1", "type": "t1"}},
                hash_replay_params={"hash_seed": 0, "hash_debug": True})
    namespace[test_name](**args)
    params = namespace["ptf_runner"].call_args.kwargs["params"]
    assert params["hash_seed"] == 0
    assert params["hash_debug"] is True
