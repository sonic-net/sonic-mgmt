"""Isolated regressions for service selection, image staging, and PTF traffic lifecycle."""

import ast
import datetime
import hashlib
import importlib.util
import io
import ipaddress
import itertools
import json
from pathlib import Path
import queue
import shlex
import shutil
import sys
import tarfile
import tempfile
import threading
import time
import traceback
from types import SimpleNamespace
from unittest.mock import Mock
from urllib.parse import urlsplit, urlunsplit

import pytest
import ptf.packet as scapy
from ptf.mask import Mask
from ptf.testutils import simple_icmp_packet, simple_tcp_packet
import scapy.all as scapyall


ROOT = Path(__file__).resolve().parents[4]
FIXTURE = ROOT / "tests/common/fixtures/advanced_reboot.py"
PTF = ROOT / "ansible/roles/test/files/ptftests/py3/advanced-reboot.py"
SERVICE_TEST = ROOT / "tests/platform_tests/test_service_warm_restart.py"
HELPER = ROOT / "tests/common/helpers/service_warm_restart.py"


def require(condition, message):
    assert condition, message


def load_definitions(path, names, **extra):
    """Exercise production definitions without importing the Ansible/testbed fixture tree."""
    tree = ast.parse(path.read_text())
    definitions = [node for node in tree.body if isinstance(node, (ast.ClassDef, ast.FunctionDef))
                   and node.name in names]
    namespace = dict(
        BaseTest=object, pytest=pytest, pytest_assert=require, logger=Mock(), logging=Mock(),
        json=json, shlex=shlex, tempfile=tempfile, os=__import__("os"), urlsplit=urlsplit, urlunsplit=urlunsplit,
        threading=threading, datetime=datetime, time=time, traceback=traceback, ipaddress=ipaddress,
        Queue=queue, itertools=itertools, scapy=scapy, scapyall=scapyall,
        Mask=Mask, simple_tcp_packet=simple_tcp_packet, simple_icmp_packet=simple_icmp_packet,
    )
    namespace.update(extra)
    exec(compile(ast.Module(body=definitions, type_ignores=[]), str(path), "exec"), namespace)
    return namespace


spec = importlib.util.spec_from_file_location("service_warm_restart_helpers", HELPER)
helpers = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helpers)


@pytest.fixture(autouse=True)
def service_image_helpers(monkeypatch):
    """Use the same portable helper module that the fixture copies to the PTF host."""
    monkeypatch.setitem(sys.modules, "service_warm_restart", helpers)


def image_info(tag="target"):
    return {"Architecture": "amd64", "Os": "linux", "RootFS": {"Layers": ["sha256:" + "a" * 64]},
            "Config": {"Labels": {"Tag": tag}}}


def make_reload(**extra):
    cls = load_definitions(PTF, ["ReloadTest"], **extra)["ReloadTest"]
    obj = cls.__new__(cls)
    obj.log = Mock()
    obj.fails = {"dut": set(), "infrastructure": set()}
    obj.report = {}
    return obj


@pytest.mark.parametrize("selected,ignored,enabled,expected", [
    (None, "", True, ["lldp"]),
    ("bgp", "", True, ["bgp"]),
    ("bgp", "bgp", True, []),
    ("bgp", "", False, []),
])
def test_service_opt_in_preserves_default_selection(selected, ignored, enabled, expected):
    """Explicit selection must not restart other services or override ignore/disabled gates."""
    namespace = load_definitions(SERVICE_TEST, [
        "get_builtin_services", "get_running_services", "get_ignored_services",
        "ServiceMatchRules", "select_services_to_warmrestart",
    ])
    dut = Mock()
    dut.show_and_parse.side_effect = lambda cmd: (
        [{"name": "lldp", "status": "Built-In"}] if cmd == "spm list" else [
            {"feature": "bgp", "state": "enabled" if enabled else "disabled"},
            {"feature": "lldp", "state": "enabled"},
        ])
    dut.shell.return_value = {"stdout_lines": ["bgp", "lldp"]}
    request = SimpleNamespace(config=SimpleNamespace(getoption=lambda option: {
        "--warm-restart-service": selected, "--ignore_service": ignored,
    }[option]))
    assert namespace["select_services_to_warmrestart"](dut, request) == expected


@pytest.mark.parametrize("topology,selected,allowed", [
    ("t0", None, True),
    ("t0", "bgp", True),
    ("m0", "bgp", True),
    ("mx", "bgp", True),
    ("t1", "bgp", False),
    ("m1", "bgp", False),
    ("m0", None, False),
    ("mx", None, False),
])
def test_service_topology_scope_requires_m0_mx_opt_in(topology, selected, allowed):
    """Reject unsupported DUT topologies before preparing or restarting any service."""
    pytest_require = load_definitions(
        ROOT / "tests/common/helpers/assertions.py", ["pytest_require"])["pytest_require"]
    namespace = load_definitions(
        SERVICE_TEST, ["test_service_warm_restart"], pytest_require=pytest_require,
        select_services_to_warmrestart=Mock(return_value=[selected or "lldp"]))
    get_advanced_reboot = Mock()
    request = SimpleNamespace(config=SimpleNamespace(getoption=Mock(return_value=selected)))
    args = {
        "request": request,
        "duthosts": {"dut": SimpleNamespace(is_multi_asic=False)},
        "enum_rand_one_per_hwsku_frontend_hostname": "dut",
        "verify_dut_health_enum_frontend": None,
        "get_advanced_reboot": get_advanced_reboot,
        "advanceboot_loganalyzer": None,
        "capture_interface_counters": None,
        "tbinfo": {"topo": {"type": topology}},
    }
    if allowed:
        namespace["test_service_warm_restart"](**args)
        get_advanced_reboot.return_value.runRebootTestcase.assert_called_once_with()
        get_advanced_reboot.return_value.disable_service_warmrestart.assert_called_once_with()
    else:
        with pytest.raises(pytest.skip.Exception, match="T0.*M0/MX"):
            namespace["test_service_warm_restart"](**args)
        namespace["select_services_to_warmrestart"].assert_not_called()
        get_advanced_reboot.assert_not_called()


def make_archive(path, count=1):
    image = image_info()
    config = json.dumps({"architecture": image["Architecture"], "os": image["Os"], "config": image["Config"],
                         "rootfs": {"type": "layers", "diff_ids": image["RootFS"]["Layers"]}}).encode()
    manifest = [{"Config": "config.json", "RepoTags": ["docker-fpm-frr:target"], "Layers": []}] * count
    with tarfile.open(path, "w:gz") as archive:
        for name, content in (("config.json", config), ("manifest.json", json.dumps(manifest).encode())):
            member = tarfile.TarInfo(name)
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
    return "sha256:" + hashlib.sha256(config).hexdigest()


def test_archive_identity_and_ambiguous_archive(tmp_path):
    """Image identity comes from config content; multiple images are not an unambiguous upgrade."""
    archive = tmp_path / "image.gz"
    identity = make_archive(archive)
    saved = helpers.docker_archive_image_info(archive)
    assert saved["config_digest"] == identity
    assert saved["fingerprint"] == helpers.docker_image_fingerprint(image_info())
    inspected = image_info()
    inspected["Config"]["OnBuild"] = None
    assert helpers.docker_image_fingerprint(inspected) == saved["fingerprint"]
    with pytest.raises(ValueError, match="expected service image"):
        helpers.docker_archive_image_info(archive, "docker-orchagent")
    make_archive(archive, count=2)
    with pytest.raises(ValueError, match="exactly one"):
        helpers.docker_archive_image_info(archive)


def staging_fixture(url, original="sha256:original"):
    cls = load_definitions(FIXTURE, ["AdvancedReboot"],
                           docker_archive_image_info=helpers.docker_archive_image_info,
                           docker_image_fingerprint=helpers.docker_image_fingerprint)["AdvancedReboot"]
    obj = cls.__new__(cls)
    obj.service_list = ["bgp"]
    obj.service_data = {}
    obj.new_docker_image = url
    obj.bgpServiceRestart = False
    obj.duthost = Mock()
    obj.localhost = Mock()
    obj.image_info = image_info("old")
    obj.duthost.command.side_effect = lambda command, **kwargs: {
        "stdout": json.dumps([obj.image_info] if command.startswith("docker image inspect") else [
            {"Image": original, "Config": {"Image": "docker-fpm-frr:latest"}}])}
    obj.duthost.tempfile.return_value = {"path": "/tmp/unique-service-image.gz"}
    return obj


def test_restart_does_not_download_or_stage_an_image():
    """Omitting the image URL must explicitly select restart-only mode."""
    obj = staging_fixture(None)
    obj._AdvancedReboot__handleDockerImage()
    assert obj.service_data["bgp"]["mode"] == "restart"
    assert obj.service_data["bgp"]["image_path_on_dut"] is None
    obj.localhost.get_url.assert_not_called()
    obj.duthost.copy.assert_not_called()


def test_download_failure_never_falls_back_to_restart():
    """A requested but missing archive must fail before any service operation."""
    obj = staging_fixture("https://images.example/bgp.gz")
    obj.localhost.get_url.side_effect = RuntimeError("HTTP 404")
    with pytest.raises(RuntimeError, match="HTTP 404"):
        obj._AdvancedReboot__handleDockerImage()
    obj.duthost.copy.assert_not_called()
    assert obj.service_data["bgp"]["mode"] == "upgrade"


@pytest.mark.parametrize("same_image", [False, True])
def test_upgrade_identity_is_validated_before_staging(tmp_path, same_image):
    """Only a distinct, valid image may be staged; keep the expected content ID for postchecks."""
    archive = tmp_path / "image.gz"
    identity = make_archive(archive)
    obj = staging_fixture("https://images.example/build", identity if same_image else "sha256:old")
    if same_image:
        obj.image_info = image_info()
    obj.localhost.get_url.side_effect = lambda **kwargs: shutil.copyfile(archive, kwargs["dest"])
    if same_image:
        with pytest.raises(AssertionError, match="running image"):
            obj._AdvancedReboot__handleDockerImage()
        obj.duthost.tempfile.assert_not_called()
    else:
        obj._AdvancedReboot__handleDockerImage()
        assert obj.service_data["bgp"]["target_config_digest"] == identity
        assert obj.service_data["bgp"]["target_image_fingerprint"] == helpers.docker_image_fingerprint(image_info())
        assert obj.service_data["bgp"]["image_path_on_dut"] == "/tmp/unique-service-image.gz"
        assert obj.localhost.get_url.call_args.kwargs["url"] == "https://images.example/build/docker-fpm-frr.gz"
        assert not Path(obj.localhost.get_url.call_args.kwargs["dest"]).exists()


def test_routed_endpoints_resolve_physical_and_lag_ports():
    """Use real next-hop ports and disjoint destinations, including physical non-LAG links."""
    graph = {"minigraph_ptf_indices": {"Ethernet0": 3, "Ethernet4": 5, "Ethernet8": 7},
             "minigraph_portchannels": {"PortChannel1": {"members": ["Ethernet0", "Ethernet4"]}}}
    routes = {
        "192.0.2.0/24": [{"protocol": "bgp", "selected": True,
                         "nexthops": [{"fib": True, "interfaceName": "PortChannel1"}]}],
        "198.51.100.0/24": [{"protocol": "bgp", "selected": True,
                            "nexthops": [{"fib": True, "interfaceName": "Ethernet8"}]}],
    }
    endpoints = helpers.bgp_traffic_endpoints(graph, routes, routed=True)
    assert endpoints == [
        {"prefix": "192.0.2.0/24", "ip": "192.0.2.1", "ports": [3, 5]},
        {"prefix": "198.51.100.0/24", "ip": "198.51.100.1", "ports": [7]},
    ]
    del routes["198.51.100.0/24"]
    with pytest.raises(ValueError, match="disjoint"):
        helpers.bgp_traffic_endpoints(graph, routes, routed=True)
    assert helpers.bgp_traffic_endpoints(graph, routes) == endpoints[:1]


def test_routed_packets_have_return_paths_and_expected_ttl():
    """Both traffic groups use advertised sources and match actual routed egress packets."""
    obj = make_reload()
    obj.dut_mac = "02:00:00:00:00:01"
    obj.test_params = {"bgp_traffic_endpoints": [
        {"ip": "192.0.2.1", "ports": [3, 5]},
        {"ip": "198.51.100.1", "ports": [7]},
    ]}
    obj.generate_routed_traffic()
    for packets, mask, expected_src, expected_dst, expected_ports in (
            (obj.from_t1, obj.from_t1_exp_packet, "192.0.2.1", "198.51.100.1", [3, 5]),
            (obj.from_servers, obj.from_vlan_exp_packet, "198.51.100.1", "192.0.2.1", [7])):
        assert [port for port, _ in packets] == expected_ports
        for _, raw in packets:
            packet = scapyall.Ether(raw)
            assert (packet[scapyall.IP].src, packet[scapyall.IP].dst) == (expected_src, expected_dst)
            packet[scapyall.IP].ttl -= 1
            del packet[scapyall.IP].chksum
            packet[scapyall.Ether].src = obj.dut_mac
            assert mask.pkt_match(bytes(packet))


@pytest.mark.parametrize("mode,path,rc,expected", [
    ("restart", None, 0, None),
    ("upgrade", None, 0, ValueError),
    ("upgrade", "/tmp/target.gz", 255, RuntimeError),
    ("upgrade", "/tmp/target.gz", 0, None),
])
def test_service_execution_is_explicit_and_checks_exit_status(mode, path, rc, expected):
    """Null image paths mean restart only when no upgrade was requested; timeouts fail."""
    obj = make_reload()
    obj.test_params = {"service_list": ["bgp"]}
    obj.service_data = {"bgp": {
        "mode": mode, "image_path_on_dut": path, "image_id": "old",
        "image_fingerprint": helpers.docker_image_fingerprint(image_info("old")),
        "target_image_fingerprint": helpers.docker_image_fingerprint(image_info())}}
    obj.task_timeout = 300
    obj.reboot_type = "service-warm-restart"
    obj.dut_connection = Mock()
    obj.dut_connection.execCommand.return_value = ([], [], rc)
    obj.pre_service_warm_restart = Mock()
    obj.run_dut_command = Mock(return_value=["new" if path else "old"])
    obj.read_dut_json = Mock(return_value=[image_info("target" if path else "old")])
    if expected:
        with pytest.raises(expected):
            obj.restart_service()
    else:
        obj.restart_service()
        commands = [call.args[0] for call in obj.dut_connection.execCommand.call_args_list]
        assert any("upgrade-docker" in command for command in commands) == bool(path)
        assert obj.report["services"]["bgp"]["mode"] == mode


@pytest.mark.parametrize("running_image", ["old", "other"])
def test_upgrade_rejects_unexpected_running_image(running_image):
    """A successful installer exit does not prove that the target image is running."""
    obj = make_reload()
    obj.test_params = {"service_list": ["bgp"]}
    obj.service_data = {"bgp": {
        "mode": "upgrade", "image_path_on_dut": "/tmp/image.gz", "image_id": "old",
        "target_image_fingerprint": helpers.docker_image_fingerprint(image_info())}}
    obj.task_timeout = 300
    obj.reboot_type = "service-warm-restart"
    obj.dut_connection = Mock()
    obj.dut_connection.execCommand.return_value = ([], ["progress"], 0)
    obj.run_dut_command = Mock(return_value=[running_image])
    unexpected_image = image_info()
    unexpected_image["RootFS"]["Layers"] = ["sha256:" + "b" * 64]
    obj.read_dut_json = Mock(return_value=[unexpected_image])
    with pytest.raises(RuntimeError, match="Unexpected image"):
        obj.restart_service()


def test_capture_and_sender_are_ready_before_service_disruption():
    """Start real worker threads before the restart; BGP must not wait for teamd to stop."""
    obj = make_reload(time=SimpleNamespace(sleep=lambda _: None))
    obj.start_sender_delay = 1
    obj.reboot_delay = 0
    obj.reboot_type = "service-warm-restart"
    obj.test_params = {"other_vendor_flag": False}
    obj.service_traffic_error = None
    obj.service_restart_error = None
    obj.service_traffic_started = threading.Event()
    obj.service_restart_done = threading.Event()
    obj.stop_service_traffic = threading.Event()
    capture_ready = threading.Event()
    events = []

    def capture():
        events.append("capture")
        capture_ready.set()
        obj.stop_service_traffic.wait(5)

    def send():
        assert capture_ready.wait(1)
        events.append("sender")
        obj.service_traffic_started.set()
        obj.stop_service_traffic.wait(5)

    obj.sniff_in_background = capture
    obj.send_in_background = send
    obj.restart_service = lambda: events.append("restart")
    obj.wait_until_teamd_goes_down = Mock(side_effect=AssertionError("teamd must remain up"))
    try:
        obj.start_service_traffic()
        obj.reboot_dut()
        assert events == ["capture", "sender", "restart"]
        assert obj.service_restart_done.is_set()
        assert obj.service_restart_error is None
    finally:
        obj.stop_service_traffic.set()
        obj.sender_thr.join(2)
        obj.sniff_thr.join(2)
    assert not obj.sender_thr.is_alive() and not obj.sniff_thr.is_alive()


def test_service_sender_ends_without_a_warmboot_finalizer():
    """Service traffic is bounded by recovery, not the full-switch warmboot-finalizer."""
    testutils = Mock()
    obj = make_reload(time=SimpleNamespace(sleep=lambda _: None), testutils=testutils)
    obj.test_params = {"dut_mac": "02:00:00:00:00:01"}
    obj.sniffer_started = threading.Event()
    obj.sniffer_started.set()
    obj.start_sender_delay = 1
    obj.dataplane_io_lock = threading.Lock()
    obj.apply_filter_all_ports = Mock()
    obj.send_interval = 0
    obj.sent_packet_count = 0
    obj.reboot_start = datetime.datetime.now()
    obj.reboot_type = "service-warm-restart"
    obj.finalizer_state = "inactive"
    obj.stop_service_traffic = threading.Event()
    obj.service_traffic_started = threading.Event()
    obj.packets_list = []
    packet = bytes(simple_tcp_packet())
    obj.from_t1 = [(1, packet)]
    obj.watcher_from_server_iter = itertools.cycle([(2, packet)])
    testutils.send_packet.side_effect = lambda *args: (
        obj.stop_service_traffic.set() if obj.sent_packet_count == 9 else None)
    obj.send_in_background()
    assert obj.sent_packet_count == 10
    assert obj.service_traffic_started.is_set()
    assert obj.kill_sniffer


@pytest.mark.parametrize("neighbor_type,csonic_neighbor", [("eos", False), ("sonic", True)])
def test_bgp_service_does_not_require_or_change_neighbor_lacp(neighbor_type, csonic_neighbor):
    """BGP-only preparation must not require a LAG backend or alter neighbor LACP timers."""
    obj = make_reload()
    obj.bgp_service_restart = True
    obj.reboot_type = "service-warm-restart"
    obj.test_params = {
        "neighbor_type": neighbor_type, "ceos_neighbor_lacp_multiplier": 180,
        "csonic_neighbor": csonic_neighbor, "csonic_lag_backend": "unknown",
        "csonic_neighbor_lacp_multiplier": 180,
    }
    obj._verify_neighbors_reachable = Mock()
    obj._detect_csonic_lag_backend = Mock(side_effect=AssertionError("BGP does not require LACP"))
    obj.ceos_set_lacp_all_neighs = Mock()
    obj.csonic_set_lacp_all_neighs = Mock()
    obj.pre_reboot_test_setup = Mock(side_effect=RuntimeError("preflight failed"))
    obj.stop_service_workers = Mock()
    obj.handle_post_reboot_test_reports = Mock()
    with pytest.raises(RuntimeError, match="preflight failed"):
        obj.runTest()
    obj._detect_csonic_lag_backend.assert_not_called()
    obj.ceos_set_lacp_all_neighs.assert_not_called()
    obj.csonic_set_lacp_all_neighs.assert_not_called()
    obj.stop_service_workers.assert_called_once_with()
    obj.handle_post_reboot_test_reports.assert_not_called()


def test_bgp_peer_monitor_uses_neighbor_handle_without_mutating_shared_parameters():
    """Use the credential-aware neighbor factory while keeping each peer's port mapping isolated."""
    obj = make_reload()
    obj.bgp_service_restart = True
    obj.test_params = {"neighbor_type": "sonic", "csonic_neighbor": True, "port_channel_intf_idx": [99]}
    obj.vm_dut_map = {"peer": {"mgmt_addr": "198.18.0.1", "ptf_ports": [7]}}
    obj._get_neighbor_handle = Mock()
    obj.monitor_bgp_peer = Mock()
    peer_queue = queue.Queue()
    obj.peer_state_check("198.18.0.1", peer_queue)
    obj._get_neighbor_handle.assert_called_once_with(
        "198.18.0.1", queue=peer_queue, connect_timeout=15,
        test_params={"neighbor_type": "sonic", "csonic_neighbor": True, "port_channel_intf_idx": [7]})
    obj.monitor_bgp_peer.assert_called_once_with(
        obj._get_neighbor_handle.return_value, "198.18.0.1", peer_queue)
    assert obj.test_params["port_channel_intf_idx"] == [99]


def test_route_reconciliation_checks_prefixes_and_paired_next_hops():
    """Equal counts are insufficient; ECMP ordering is immaterial but pairings are not."""
    obj = make_reload()
    first = {"ROUTE_TABLE:192.0.2.0/24": {"value": {"nexthop": "10.0.0.1,10.0.0.3", "ifname": "Ethernet0,Ethernet4"}}}
    reordered = {"ROUTE_TABLE:192.0.2.0/24": {
        "value": {"nexthop": "10.0.0.3,10.0.0.1", "ifname": "Ethernet4,Ethernet0"}}}
    wrong = {"ROUTE_TABLE:192.0.2.0/24": {
        "value": {"nexthop": "10.0.0.3,10.0.0.1", "ifname": "Ethernet0,Ethernet4"}}}
    assert obj.route_next_hops(first) == obj.route_next_hops(reordered)
    assert obj.route_next_hops(first) != obj.route_next_hops(wrong)
    changed_prefix = {"ROUTE_TABLE:198.51.100.0/24": first["ROUTE_TABLE:192.0.2.0/24"]}
    assert obj.route_next_hops(first) != obj.route_next_hops(changed_prefix)


@pytest.mark.parametrize("original", ["", "false", "true"])
def test_bgp_warm_restart_enable_state_is_restored(original):
    """Teardown restores an absent, disabled, or enabled flag instead of always disabling it."""
    cls = load_definitions(FIXTURE, ["AdvancedReboot"])["AdvancedReboot"]
    obj = cls.__new__(cls)
    obj.bgpServiceRestart = True
    obj.service_list = ["bgp"]
    obj.service_data = {"bgp": {"warm_restart_enable": original}}
    obj.duthost = Mock()
    obj.disable_service_warmrestart()
    if original:
        action = "enable" if original == "true" else "disable"
        obj.duthost.shell.assert_called_once_with("sudo config warm_restart {} bgp".format(action))
    else:
        obj.duthost.command.assert_called_once_with(
            "sonic-db-cli STATE_DB HDEL 'WARM_RESTART_ENABLE_TABLE|bgp' enable")


@pytest.mark.parametrize("local_mode,remote_mode,preserve,success", [
    ("Restart*", "Helper", True, True),
    ("Helper*", "Helper", True, False),
    ("Restart", "Disable", True, False),
    ("Restart", "Restart", False, False),
])
def test_bgp_preflight_requires_negotiated_restart_and_preservation(local_mode, remote_mode, preserve, success):
    """Do not disrupt a helper-only or unnegotiated DUT, or accept a negated preserve command."""
    obj = staging_fixture(None)
    obj.rebootData = {"arista_vms": ["198.18.0.1"]}
    obj.mgFacts = {
        "minigraph_bgp": [
            {"name": "peer", "addr": "10.0.0.1", "peer_addr": "10.0.0.0"},
            {"name": "peer", "addr": "FC00::2", "peer_addr": "FC00::1"},
        ],
        "minigraph_devices": {"peer": {"mgmt_addr": "198.18.0.1"}},
        "minigraph_lo_interfaces": [{"addr": "2001:db8::1", "prefixlen": 128}],
    }
    peer = {"bgpState": "Established", "gracefulRestartInfo": {
        "localGrMode": local_mode, "remoteGrMode": remote_mode}}

    def command(cmd):
        if "show bgp neighbors" in cmd:
            return {"stdout": json.dumps({"10.0.0.1": peer, "fc00::2": peer})}
        if "show running-config" in cmd:
            return {"stdout": (" " if preserve else " no ") + "bgp graceful-restart preserve-fw-state\n"}
        if "enable" in cmd:
            return {"stdout": "true"}
        if "restore_count" in cmd:
            return {"stdout": "7"}
        if "APPL_DB" in cmd:
            return {"stdout": '{"ROUTE_TABLE:192.0.2.0/24":{"value":{"ifname":"Ethernet0","nexthop":"10.0.0.1"}}}'}
        if "show bgp ipv6 unicast" in cmd:
            return {"stdout": '{"prefix":"2001:db8::/64"}'}
        raise AssertionError(cmd)

    obj.duthost.command.side_effect = command
    data = {}
    if success:
        obj._AdvancedReboot__prepareBgpServiceData(data)
        assert data["restore_count"] == 7
        assert data["peer_addresses"] == {"198.18.0.1": {"ipv4": "10.0.0.0", "ipv6": "FC00::1"}}
    else:
        with pytest.raises(AssertionError, match="GR|preserve-fw-state"):
            obj._AdvancedReboot__prepareBgpServiceData(data)


@pytest.mark.parametrize("state,count,changed_route,established,success", [
    ("reconciled", 4, False, True, True),
    ("reconciled", 3, False, True, False),
    ("restored", 4, False, True, False),
    ("reconciled", 4, True, True, False),
    ("reconciled", 4, False, False, False),
])
def test_warm_recovery_requires_new_attempt_and_exact_routes(state, count, changed_route, established, success):
    """An old reconciled state, equal route counts, or incomplete BGP recovery cannot pass."""
    clock = iter([0, 0, 2])
    obj = make_reload(time=SimpleNamespace(monotonic=lambda: next(clock), sleep=lambda _: None))
    obj.test_params = {"warm_up_timeout_secs": 1}
    obj.service_data = {"bgp": {"restore_count": 3, "bgp_neighbors": ["10.0.0.1"]}}
    baseline = {"ROUTE_TABLE:192.0.2.0/24": {"value": {"ifname": "Ethernet0", "nexthop": "10.0.0.1"}}}
    obj.read_json = Mock(return_value=baseline)

    def query(cmd):
        if "STATE_DB" in cmd:
            return {"WARM_RESTART_TABLE|bgp": {"value": {"state": state, "restore_count": str(count)}}}
        if "show bgp neighbors" in cmd:
            return {"10.0.0.1": {"bgpState": "Established" if established else "Active"}}
        return {"ROUTE_TABLE:198.51.100.0/24": next(iter(baseline.values()))} if changed_route else baseline

    obj.read_dut_json = query
    if success:
        obj.wait_until_bgp_converged()
        assert obj.report["bgp_recovery"]["route_prefixes_and_next_hops_restored"]
    else:
        with pytest.raises(RuntimeError, match="did not complete"):
            obj.wait_until_bgp_converged()
        assert "bgp_recovery" not in obj.report


@pytest.mark.parametrize("payload,valid", [("-1", False), ("0", True), ("9", True), ("10", False), ("other", False)])
def test_tcp_payload_must_identify_a_sent_packet(payload, valid):
    """Foreign or out-of-range packet IDs must not be counted as successful forwarding."""
    obj = make_reload()
    obj.sent_packet_count = 10
    packet = scapyall.Ether() / scapyall.IP() / scapyall.TCP() / scapyall.Raw(payload.encode())
    assert obj.check_tcp_payload(packet) is valid


@pytest.mark.parametrize("neighbor_type", ["eos", "sonic"])
def test_peer_route_queries_support_routed_interfaces_and_ipv6_link_local(neighbor_type):
    """Keep next-hop interface identity rather than assuming PortChannel1 or a global IPv6 next hop."""
    obj = make_reload()
    obj.test_params = {"neighbor_type": neighbor_type}
    if neighbor_type == "sonic":
        output = {"2001:db8::/64": [{"selected": True, "nexthops": [
            {"fib": True, "ip": "fe80::1", "interfaceName": "Ethernet0"}]}]}
    else:
        output = {"vrfs": {"default": {"routes": {"2001:db8::/64": {
            "routeAction": "forward", "vias": [{"nexthopAddr": "fe80::1", "interface": "Ethernet0"}]}}}}}
    ssh = Mock()
    ssh.do_cmd.return_value = json.dumps(output)
    assert obj.peer_route_next_hops(ssh, "2001:db8::/64") == {(ipaddress.ip_address("fe80::1"), "Ethernet0")}


def test_capture_read_failure_is_propagated_from_the_sniffer_thread():
    """The nested capture thread must record a failure and stop traffic, not just log an exception."""
    packets = SimpleNamespace(rdpcap=Mock(side_effect=RuntimeError("capture read failed")))
    obj = make_reload(scapyall=packets, subprocess=Mock(), PHYSICAL_PORT="physical_port")
    obj.reboot_type = "service-warm-restart"
    obj.test_params = {"packet_capture_location": "ptf_port"}
    obj.capture_pcap = "/tmp/unit-capture.pcapng"
    obj.start_sniffer_on_ptf = Mock()
    obj.stop_service_traffic = threading.Event()
    obj.tcpdump_sniff()
    assert "capture read failed" in obj.service_traffic_error
    assert obj.fails["infrastructure"]
    assert obj.stop_service_traffic.is_set()


def test_vlanless_testbed_data_uses_real_routed_endpoints():
    """VLAN-less setup must use routed endpoints without requiring a VLAN or a port channel."""
    vlan_lookup = Mock(side_effect=AssertionError("A routed testbed has no VLAN interface"))
    cls = load_definitions(
        FIXTURE, ["AdvancedReboot"], PHYSICAL_PORT="physical_port",
        bgp_traffic_endpoints=helpers.bgp_traffic_endpoints,
        get_vlan_interface_list=vlan_lookup)["AdvancedReboot"]
    obj = cls.__new__(cls)
    obj.bgpServiceRestart = True
    obj.dual_tor_mode = False
    obj.packet_capture_location = "ptf_port"
    obj.rebootData = {}
    obj.creds = {"sonicadmin_user": "test", "sonicadmin_password": None}
    graph = {
        "minigraph_devices": {
            "peer1": {"hwsku": "Arista-VM", "mgmt_addr": "198.18.0.1"},
            "peer2": {"hwsku": "Arista-VM", "mgmt_addr": "198.18.0.2"},
        },
        "minigraph_portchannels": {}, "minigraph_vlans": {}, "minigraph_vlan_interfaces": [],
        "minigraph_mgmt_interface": {"addr": "198.18.0.3"},
        "minigraph_ptf_indices": {"Ethernet0": 3, "Ethernet4": 7},
        "minigraph_lo_interfaces": [
            {"addr": "203.0.113.1", "prefixlen": 32}, {"addr": "2001:db8::1", "prefixlen": 128}],
    }
    obj.duthost = Mock()
    obj.duthost.facts = {"router_mac": "02:00:00:00:00:01"}
    obj.duthost.get_extended_minigraph_facts.return_value = graph
    obj.duthost.get_running_config_facts.return_value = {}
    obj.duthost.command.return_value = {"stdout": json.dumps({
        "192.0.2.0/24": [{"protocol": "bgp", "selected": True,
                         "nexthops": [{"fib": True, "interfaceName": "Ethernet0"}]}],
        "198.51.100.0/24": [{"protocol": "bgp", "selected": True,
                            "nexthops": [{"fib": True, "interfaceName": "Ethernet4"}]}],
    })}
    obj._AdvancedReboot__buildTestbedData({})
    assert obj.routedTraffic
    assert obj.lagMemberCnt == 0 and obj.vlanMaxCnt == 0
    assert obj.rebootData["vlan_ip_range"] == "{}"
    assert {tuple(endpoint["ports"]) for endpoint in obj.rebootData["bgp_traffic_endpoints"]} == {(3,), (7,)}
    vlan_lookup.assert_not_called()


def test_ptf_port_mapping_includes_physical_bgp_links():
    """M0/MX links without LAGs must still be used for bidirectional VLAN traffic."""
    obj = make_reload()
    obj.bgp_service_restart = True
    obj.vlan_ip_range = {"Vlan1000": "192.0.2.0/24"}
    obj.port_indices = {"Ethernet0": 3, "Ethernet4": 7, "Ethernet8": 9}
    obj.vm_dut_map = {
        "routed_peer": {"ptf_ports": [7]},
        "lag_peer": {"ptf_ports": [9], "dut_portchannel": "PortChannel1"},
    }
    obj.is_dualtor = False
    obj.read_json = lambda name: {
        "portchannel_ports_file": {"PortChannel1": {"name": "PortChannel1", "members": ["Ethernet8"]}},
        "vlan_ports_file": {"Vlan1000": {"members": ["Ethernet0"]}},
    }[name]
    vlans, routed_ports, peer_ports = obj.read_vlan_portchannel_ports()
    assert vlans == {"Vlan1000": [3]}
    assert set(routed_ports) == {7, 9}
    assert peer_ports == []
