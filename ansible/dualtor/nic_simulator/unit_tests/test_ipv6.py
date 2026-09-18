"""Standalone NIC simulator tests; no SONiC integration fixtures or OVS access."""
import json
from pathlib import Path
import socket
import subprocess
import sys
import threading
from types import SimpleNamespace
from unittest.mock import Mock, call

import grpc
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import nic_simulator as simulator  # noqa: E402


V4 = ("10.1.0.36", "10.1.0.38", "10.1.0.39")
V6 = ("fc00::36", "fc00::38", "fc00::39")
PORT = 50075
PB = simulator.nic_simulator_grpc_service_pb2
MGMT_PB = simulator.nic_simulator_grpc_mgmt_service_pb2


@pytest.fixture(autouse=True)
def no_ovs_commands(monkeypatch):
    """Never execute an OVS/shell command, even if a test forgets a mock."""
    monkeypatch.setattr(simulator, "run_command", Mock(side_effect=AssertionError("Unexpected OVS command")))


@pytest.fixture
def ovs(monkeypatch):
    """Mock only the OVS boundary, retaining actual flow and state logic."""
    commands = {}
    for name in vars(simulator.OVSCommand):
        if name.startswith("ovs_"):
            commands[name] = Mock()
            monkeypatch.setattr(simulator.OVSCommand, name, commands[name])
    commands["ovs_vsctl_list_ports"].return_value = SimpleNamespace(
        stdout="iaa-test-1 nic-test-1 tor-a tor-b"
    )
    return commands


def address_info(address="fc00::1", **kwargs):
    """Construct the relevant iproute2 JSON address fields."""
    info = {"family": "inet6", "scope": "global", "local": address,
            "preferred_life_time": 4294967295, "valid_life_time": 4294967295}
    info.update(kwargs)
    return info


def test_ipv6_discovery_stable_and_shell_free(monkeypatch):
    """Sort/deduplicate global IPv6 and pass the interface as a literal argv item."""
    entries = [address_info("2001:db8::2"), address_info("fc00::2"),
               address_info("fc00:0:0:0:0:0:0:2"), address_info("2001:db8::1")]
    run = Mock(return_value=SimpleNamespace(stdout=json.dumps([{"addr_info": entries}])))
    monkeypatch.setattr(simulator.subprocess, "run", run)
    interface = "eth1; touch /do-not-create"
    assert simulator.get_ipv6_addresses(interface) == ["2001:db8::1", "2001:db8::2", "fc00::2"]
    run.assert_called_once_with(
        ["ip", "-j", "-6", "addr", "show", "dev", interface],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, text=True, shell=False
    )


@pytest.mark.parametrize("info", [
    address_info("fe80::1"), address_info("::"), address_info("::1"),
    address_info("ff02::1"), address_info("fec0::1"), address_info("::ffff:192.0.2.1"),
    address_info(scope="link"), address_info(scope="host"), address_info(family="inet"),
    address_info("not-an-ip"), address_info("192.0.2.1"),
    address_info(preferred_life_time=0), address_info(preferred_life_time="0"),
    address_info(valid_life_time=0),
] + [address_info(**{flag: True}) for flag in ("tentative", "dadfailed", "deprecated", "temporary")]
  + [address_info(flags=[flag]) for flag in ("tentative", "dadfailed", "deprecated", "temporary")])
def test_ipv6_discovery_excludes_unusable_addresses(monkeypatch, info):
    """Reject non-global, transient, failed-DAD, deprecated and invalid addresses."""
    monkeypatch.setattr(simulator.subprocess, "run", Mock(
        return_value=SimpleNamespace(stdout=json.dumps([{"addr_info": [info]}]))
    ))
    assert simulator.get_ipv6_addresses("eth1") == []


@pytest.mark.parametrize("failure", [FileNotFoundError(), subprocess.CalledProcessError(1, "ip")])
def test_ipv6_discovery_failure_preserves_ipv4(monkeypatch, failure):
    """Unavailable iproute2/IPv6 discovery is not fatal to IPv4-only deployments."""
    monkeypatch.setattr(simulator.subprocess, "run", Mock(side_effect=failure))
    assert simulator.get_ipv6_addresses("eth1") == []


@pytest.mark.parametrize("output", ["not-json", "[]", '[{"addr_info": []}]'])
def test_ipv6_discovery_empty_or_invalid_json(monkeypatch, output):
    """Return no IPv6 addresses when there is no usable JSON address record."""
    monkeypatch.setattr(simulator.subprocess, "run", Mock(return_value=SimpleNamespace(stdout=output)))
    assert simulator.get_ipv6_addresses("eth1") == []


@pytest.mark.parametrize("has_address", [True, False])
def test_existing_ipv4_ioctl_path(monkeypatch, has_address):
    """Preserve SIOCGIFADDR IPv4 discovery and its missing-address return value."""
    sock = Mock()
    sock.fileno.return_value = 7
    socket_factory = Mock(return_value=sock)
    monkeypatch.setattr(simulator.socket, "socket", socket_factory)
    ioctl = Mock(return_value=b"\0" * 20 + socket.inet_aton("192.0.2.1"))
    if not has_address:
        ioctl.side_effect = OSError()
    monkeypatch.setattr(simulator.fcntl, "ioctl", ioctl)
    assert simulator.get_ip_address("eth1") == ("192.0.2.1" if has_address else None)
    socket_factory.assert_called_once_with(socket.AF_INET, socket.SOCK_DGRAM)
    assert ioctl.call_args.args[:2] == (7, 0x8915)


@pytest.mark.parametrize("option,value", [
    ("--ipv6-loopback-ips", "fc00::1,fc00::2"),
    ("--ipv6-loopback-ips", "fc00::1,fc00::2,fc00::3,fc00::4"),
    ("--ipv6-loopback-ips", "fc00::1,192.0.2.1,fc00::3"),
    ("--ipv6-loopback-ips", "fc00::1,,fc00::3"),
    ("--ipv6-loopback-ips", "fc00::1/64,fc00::2,fc00::3"),
    ("--ipv6-loopback-ips", "fc00::1%eth0,fc00::2,fc00::3"),
    ("--ipv6-loopback-ips", "fc00::1,fc00::2,fc00::3;echo bad"),
    ("-d", "fc00::1,fc00::2,fc00::3"),
    ("-d", "192.0.2.1,192.0.2.2"),
])
def test_cli_rejects_invalid_triplets(monkeypatch, option, value):
    """Validate triplet length, literals and family before touching OVS."""
    monkeypatch.setattr(sys, "argv", ["nic_simulator", "-p", str(PORT), "-v", "test", option, value])
    with pytest.raises(SystemExit) as error:
        simulator.parse_args()
    assert error.value.code == 2


def test_cli_defaults_and_optional_ipv6(monkeypatch):
    """Keep IPv4 defaults and accept the optional IPv6 loopback triplet."""
    argv = ["nic_simulator", "-p", str(PORT), "-v", "test"]
    monkeypatch.setattr(sys, "argv", argv)
    args = simulator.parse_args()
    assert args.loopback_ips == ",".join(V4)
    assert args.ipv6_loopback_ips is None
    monkeypatch.setattr(sys, "argv", argv + ["--ipv6-loopback-ips", ",".join(V6), "-n"])
    args = simulator.parse_args()
    assert simulator.validate_loopback_ips(args.ipv6_loopback_ips, 6) == V6
    assert args.duplicate_nic_upstream


def test_constructor_validates_before_ovs(ovs):
    """Direct callers cannot inject malformed loopback filters into shell commands."""
    with pytest.raises(ValueError):
        simulator.OVSBridge("baa-test-1", V4, False, ["fc00::1;echo bad"] * 3)
    ovs["ovs_vsctl_list_ports"].assert_not_called()


@pytest.mark.parametrize("duplicate", [False, True])
def test_ipv6_flows_mirror_ipv4(ovs, duplicate):
    """Match the IPv4 priorities, ports, per-ToR enables and duplication policy."""
    bridge = simulator.OVSBridge("baa-test-1", V4, duplicate, V6)
    filters = {flow.packet_filter: flow for flow in bridge.flows}
    for index, address in enumerate(V6):
        v6 = filters["ipv6,ipv6_dst=%s" % address]
        v4 = filters["ip,ip_dst=%s" % V4[index]]
        assert (v6.in_port, v6.output_ports, v6.priority) == (v4.in_port, v4.output_ports, v4.priority)
        assert v6.enable_output_ports == [True, True]
    for index, enables in ((1, [False, True]), (2, [True, False])):
        key = "tcp6,ipv6_dst=%s" % V6[index]
        if duplicate:
            assert key not in filters
        else:
            flow = filters[key]
            assert flow.priority == 10
            assert flow.in_port == bridge.server_nic
            assert flow.enable_output_ports == enables
            expected_port = bridge.upper_tor_port if index == 1 else bridge.lower_tor_port
            assert str(flow).endswith("actions=output:%s" % expected_port)
    assert "ipv6,nw_proto=58" in filters
    assert len(bridge.groups) == 1


def test_default_flows_remain_ipv4_compatible(ovs):
    """No opt-in means no new IPv6 loopback flows and the existing ICMPv6 flow remains."""
    bridge = simulator.OVSBridge("baa-test-1", V4)
    assert len(bridge.flows) == 11
    assert not any("ipv6_dst" in (flow.packet_filter or "") for flow in bridge.flows)
    assert bridge.upstream_icmpv6_flow.packet_filter == "ipv6,nw_proto=58"


@pytest.mark.parametrize("duplicate", [False, True])
@pytest.mark.parametrize("ipv6", [None, V6])
@pytest.mark.parametrize("portid", [0, 1])
def test_drop_recovery_covers_both_families(ovs, duplicate, ipv6, portid):
    """All enabled upstream flows drop/recover together, without affecting the other ToR."""
    bridge = simulator.OVSBridge("baa-test-1", V4, duplicate, ipv6)
    upstream = [flow for flow in bridge.flows if isinstance(flow, simulator.OVSUpstreamFlow)]
    original = [str(flow) for flow in upstream]
    bridge.set_drop([portid], [1], False)
    assert bridge.query_forwarding_state([portid, 1 - portid]) == [False, True]
    for flow in upstream:
        assert flow.get_drop(portid) == flow.get_port_enable(portid)
        assert not flow.get_drop(1 - portid)
        if flow.get_port_enable(portid):
            assert "output:%s" % flow.output_ports[portid] not in str(flow)
    before = ovs["ovs_ofctl_mod_flow"].call_count
    bridge.set_drop([portid], [1], False)
    assert ovs["ovs_ofctl_mod_flow"].call_count == before
    bridge.set_drop([portid], [0], False)
    assert bridge.downstream_flows[portid].drop
    bridge.set_drop([portid], [1], True)
    assert not bridge.downstream_flows[portid].drop
    assert [str(flow) for flow in upstream] == original
    assert bridge.query_forwarding_state([0, 1]) == [True, True]


@pytest.mark.parametrize("ipv4,ipv6", [
    ("192.0.2.1", []), (None, ["fc00::1"]), ("192.0.2.1", ["fc00::1", "fc00::2"]), (None, [])
])
def test_simulator_aliases_and_unique_lifecycle(monkeypatch, ipv4, ipv6):
    """One interface has one bridge/server, even with multiple IPv4/IPv6 aliases."""
    monkeypatch.setattr(simulator.NiCSimulator, "_find_all_server_nics", lambda self: ["eth1"])
    monkeypatch.setattr(simulator.NiCSimulator, "_find_all_bridges", lambda self: ["baa-test-1"])
    monkeypatch.setattr(simulator, "get_ip_address", lambda interface: ipv4 if interface == "eth1" else None)
    monkeypatch.setattr(simulator, "get_ipv6_addresses",
                        lambda interface: ipv6 if interface == "eth1" else ["fc00::100"])
    bridge_factory = Mock()
    server_factory = Mock()
    monkeypatch.setattr(simulator, "OVSBridge", bridge_factory)
    monkeypatch.setattr(simulator, "NiCServer", server_factory)
    instance = simulator.NiCSimulator("test", "mgmt", PORT, V4, False, V6)
    addresses = ([ipv4] if ipv4 else []) + ipv6
    assert list(instance.servers) == addresses
    assert instance.mgmt_server.binding_addresses == ("fc00::100",)
    assert instance.mgmt_server.nic_servers is instance.servers
    if not addresses:
        bridge_factory.assert_not_called()
        server_factory.assert_not_called()
        return
    bridge_factory.assert_called_once_with("baa-test-1", V4, False, V6)
    server_factory.assert_called_once_with(addresses[0], bridge_factory.return_value, PORT, addresses)
    assert all(server is server_factory.return_value for server in instance.servers.values())
    assert all(bridge is bridge_factory.return_value for bridge in instance.ovs_bridges.values())
    instance.start_nic_servers()
    instance.stop_nic_servers()
    server_factory.return_value.start.assert_called_once()
    server_factory.return_value.stop.assert_called_once()
    server_factory.return_value.join.assert_called_once()


def test_no_management_address_fails_before_ovs(monkeypatch):
    """Do not create listeners on None/wildcards or alter bridges without a management address."""
    monkeypatch.setattr(simulator.NiCSimulator, "_find_all_server_nics", lambda self: [])
    monkeypatch.setattr(simulator, "get_ip_address", lambda interface: None)
    monkeypatch.setattr(simulator, "get_ipv6_addresses", lambda interface: [])
    with pytest.raises(ValueError, match="management interface"):
        simulator.NiCSimulator("test", "mgmt", PORT, V4)


@pytest.mark.parametrize("addresses", [("192.0.2.1",), ("fc00::1",), ("192.0.2.1", "fc00::1")])
def test_nic_binds_specific_addresses_to_one_grpc_server(monkeypatch, addresses):
    """Each NIC binds only its explicit addresses, registering a single servicer."""
    transport = Mock()
    transport.add_insecure_port.return_value = PORT
    factory = Mock(return_value=transport)
    monkeypatch.setattr(simulator.grpc, "server", factory)
    register = Mock()
    monkeypatch.setattr(simulator.nic_simulator_grpc_service_pb2_grpc,
                        "add_DualToRActiveServicer_to_server", register)
    server = simulator.NiCServer(addresses[0], Mock(), PORT, addresses)
    server.start()
    server.start()
    server.join(timeout=2)
    server.stop()
    factory.assert_called_once()
    register.assert_called_once_with(server, transport)
    assert transport.add_insecure_port.call_args_list == [
        call(simulator.grpc_target(address, PORT)) for address in addresses
    ]
    transport.start.assert_called_once()


@pytest.mark.parametrize("kind", ["nic", "mgmt"])
@pytest.mark.parametrize("failure", [0, RuntimeError("bind failed")])
def test_bind_failure_is_synchronous_and_cleans_up(monkeypatch, kind, failure):
    """An unsuccessful second bind cannot leave a partly active dual-stack service."""
    transport = Mock()
    transport.add_insecure_port.side_effect = [PORT, failure]
    monkeypatch.setattr(simulator.grpc, "server", Mock(return_value=transport))
    if kind == "nic":
        server = simulator.NiCServer("192.0.2.1", Mock(), PORT, ["fc00::1"])
    else:
        server = simulator.MgmtServer("192.0.2.1", PORT, {}, ["fc00::1"])
    with pytest.raises(RuntimeError):
        server.start()
    transport.start.assert_not_called()
    transport.stop.assert_called_once_with(grace=None)
    if kind == "nic":
        assert not server.started
        assert server.thread is None


@pytest.mark.parametrize("addresses", [[], ["::"], ["0.0.0.0"]])
def test_no_wildcard_or_empty_listener_set(addresses):
    """Reject configurations that could cross NIC boundaries or listen nowhere."""
    transport = Mock()
    with pytest.raises(ValueError):
        simulator.bind_grpc_addresses(transport, addresses, PORT)
    transport.add_insecure_port.assert_not_called()
    transport.stop.assert_called_once_with(grace=None)


def test_multiple_nics_keep_separate_state(monkeypatch, ovs):
    """IPv6 aliases share their own NIC's bridge, never another NIC's state."""
    monkeypatch.setattr(simulator.NiCSimulator, "_find_all_server_nics", lambda self: ["eth1", "eth2"])
    monkeypatch.setattr(simulator.NiCSimulator, "_find_all_bridges", lambda self: ["baa-test-1", "baa-test-2"])
    monkeypatch.setattr(simulator, "get_ip_address", lambda interface: {
        "eth1": "192.0.2.1", "eth2": "192.0.2.2", "mgmt": "192.0.2.100"
    }[interface])
    monkeypatch.setattr(simulator, "get_ipv6_addresses", lambda interface: {
        "eth1": ["fc00::1"], "eth2": ["fc00::2"], "mgmt": ["fc00::100"]
    }[interface])
    instance = simulator.NiCSimulator("test", "mgmt", PORT, V4, False, V6)
    assert instance.servers["192.0.2.1"] is instance.servers["fc00::1"]
    assert instance.servers["192.0.2.2"] is instance.servers["fc00::2"]
    assert instance.servers["fc00::1"] is not instance.servers["fc00::2"]
    instance.ovs_bridges["fc00::1"].set_forwarding_state([0], [False])
    assert instance.ovs_bridges["192.0.2.1"].query_forwarding_state([0]) == [False]
    assert instance.ovs_bridges["fc00::2"].query_forwarding_state([0]) == [True]
    assert instance.mgmt_server.binding_addresses == ("192.0.2.100", "fc00::100")


@pytest.mark.parametrize("stage", ["nic", "mgmt"])
def test_main_cleans_up_on_startup_failure(monkeypatch, stage):
    """Clean up previously started NICs if a later NIC or management bind fails."""
    monkeypatch.setattr(sys, "argv", ["nic_simulator", "-p", str(PORT), "-v", "test"])
    monkeypatch.setattr(simulator, "config_env", Mock())
    monkeypatch.setattr(simulator, "config_logging", Mock())
    monkeypatch.setattr(simulator.OVSCommand, "setup_openflow_version", Mock())
    instance = Mock()
    if stage == "nic":
        instance.start_nic_servers.side_effect = RuntimeError("bind failed")
    else:
        instance.start_mgmt_server.side_effect = RuntimeError("bind failed")
    factory = Mock(return_value=instance)
    monkeypatch.setattr(simulator, "NiCSimulator", factory)
    with pytest.raises(RuntimeError, match="bind failed"):
        simulator.main()
    factory.assert_called_once_with("test", "mgmt", PORT, V4, False, None)
    instance.stop_nic_servers.assert_called_once()
    instance.mgmt_server.server.stop.assert_called_once_with(grace=None)


def test_management_dual_bind_and_ipv6_client(monkeypatch):
    """Management listeners and internal client channels bracket IPv6 literals."""
    transport = Mock()
    transport.add_insecure_port.return_value = PORT
    monkeypatch.setattr(simulator.grpc, "server", Mock(return_value=transport))
    channel = Mock()
    monkeypatch.setattr(simulator.grpc, "insecure_channel", channel)
    stub_factory = Mock()
    monkeypatch.setattr(simulator.nic_simulator_grpc_service_pb2_grpc, "DualToRActiveStub", stub_factory)
    server = simulator.MgmtServer("192.0.2.100", PORT, {}, ["fc00::100"])
    server.start()
    assert transport.add_insecure_port.call_args_list == [call("192.0.2.100:50075"), call("[fc00::100]:50075")]
    stub = server._get_client_stub("fc00:0:0:0:0:0:0:1")
    assert stub is server._get_client_stub("fc00::1")
    channel.assert_called_once_with("[fc00::1]:50075", options=simulator.GRPC_CLIENT_OPTIONS)


def test_management_alias_admin_operations(monkeypatch):
    """IPv4 and expanded IPv6 aliases start/stop the same NIC only once per state change."""
    nic = simulator.NiCServer("192.0.2.1", Mock(), PORT, ["fc00::1"])
    transport = Mock()
    transport.add_insecure_port.return_value = PORT
    factory = Mock(return_value=transport)
    monkeypatch.setattr(simulator.grpc, "server", factory)
    mgmt = simulator.MgmtServer("192.0.2.100", PORT, {"192.0.2.1": nic, "fc00::1": nic})
    for state in (True, False):
        response = mgmt.SetNicServerAdminState(MGMT_PB.ListOfNiCServerAdminStateRequest(
            nic_addresses=["192.0.2.1", "fc00:0:0:0:0:0:0:1"], admin_states=[state, state]
        ), Mock())
        assert list(response.successes) == [True, True]
        assert nic.started == state
    factory.assert_called_once()
    transport.stop.assert_called_once()


@pytest.fixture
def ipv6_loopback():
    """Skip real IPv6 tests only when the host cannot bind its IPv6 loopback."""
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as sock:
            sock.bind(("::1", 0))
    except OSError as error:
        pytest.skip("IPv6 loopback unavailable: %s" % error)


@pytest.mark.parametrize("dual_stack", [False, True])
def test_real_grpc_shared_state_and_ipv6_only(ovs, ipv6_loopback, dual_stack):
    """Real IPv4/IPv6 RPCs and management clients share one bridge and flap/drop state."""
    bridge = simulator.OVSBridge("baa-test-1", V4, False, V6)
    addresses = ["127.0.0.1", "::1"] if dual_stack else ["::1"]
    server = simulator.NiCServer(addresses[0], bridge, 0, addresses)
    channels = []
    try:
        server.start()
        stubs = []
        for address in addresses:
            channel = grpc.insecure_channel(simulator.grpc_target(address, server.binding_port))
            channels.append(channel)
            grpc.channel_ready_future(channel).result(timeout=5)
            stubs.append(simulator.nic_simulator_grpc_service_pb2_grpc.DualToRActiveStub(channel))
        response = stubs[0].SetAdminForwardingPortState(PB.AdminRequest(portid=[0, 1], state=[False, True]), timeout=5)
        assert list(response.state) == [False, True]
        query = PB.AdminRequest(portid=[0, 1])
        assert list(stubs[-1].QueryAdminForwardingPortState(query, timeout=5).state) == [False, True]
        assert list(stubs[-1].QueryFlapCounter(PB.FlapCounterRequest(portid=[0, 1]), timeout=5).flaps) == [1, 0]
        stubs[-1].SetDrop(PB.DropRequest(portid=[1], direction=[1], recover=False), timeout=5)
        assert list(stubs[0].QueryAdminForwardingPortState(query, timeout=5).state) == [False, False]
        stubs[-1].SetDrop(PB.DropRequest(portid=[1], direction=[1], recover=True), timeout=5)
        assert bridge.query_forwarding_state([0, 1]) == [False, True]
        mgmt = simulator.MgmtServer("::1", server.binding_port, {address: server for address in addresses})
        # Exercise the actual management internal IPv6 client without replacing it with a mock.
        context = Mock()
        reply = mgmt.QueryAdminForwardingPortState(MGMT_PB.ListOfAdminRequest(
            nic_addresses=["::1"], admin_requests=[PB.AdminRequest(portid=[0, 1])]
        ), context)
        context.set_code.assert_not_called()
        assert list(reply.admin_replies[0].state) == [False, True]
        server.stop()
        server.join(timeout=5)
        server.start()
        # Restarting the transport must not recreate the bridge or reset its state.
        with grpc.insecure_channel(simulator.grpc_target("::1", server.binding_port)) as channel:
            grpc.channel_ready_future(channel).result(timeout=5)
            stub = simulator.nic_simulator_grpc_service_pb2_grpc.DualToRActiveStub(channel)
            assert list(stub.QueryFlapCounter(PB.FlapCounterRequest(portid=[0, 1]), timeout=5).flaps) == [1, 0]
            assert list(stub.QueryAdminForwardingPortState(query, timeout=5).state) == [False, True]
    finally:
        for channel in channels:
            channel.close()
        server.stop()
        server.join(timeout=5)
    assert not server.thread.is_alive()


@pytest.mark.parametrize("dual_stack", [False, True])
def test_real_management_listeners(monkeypatch, ipv6_loopback, dual_stack):
    """Serve management RPCs on real IPv6-only or IPv4+IPv6 loopback listeners."""
    addresses = ["127.0.0.1", "::1"] if dual_stack else ["::1"]
    transport = grpc.server(simulator.futures.ThreadPoolExecutor(max_workers=2))
    monkeypatch.setattr(simulator.grpc, "server", Mock(return_value=transport))
    ready = threading.Event()
    original_wait = transport.wait_for_termination

    def wait_for_termination():
        ready.set()
        original_wait()

    monkeypatch.setattr(transport, "wait_for_termination", wait_for_termination)
    mgmt = simulator.MgmtServer(addresses[0], 0, {}, addresses)
    thread = simulator.InterruptableThread(target=mgmt.start)
    try:
        thread.start()
        assert ready.wait(timeout=5), "Management server did not start"
        for address in addresses:
            with grpc.insecure_channel(simulator.grpc_target(address, mgmt.binding_port)) as channel:
                grpc.channel_ready_future(channel).result(timeout=5)
                stub = simulator.nic_simulator_grpc_mgmt_service_pb2_grpc.DualTorMgmtServiceStub(channel)
                reply = stub.QueryAdminForwardingPortState(MGMT_PB.ListOfAdminRequest(), timeout=5)
                assert list(reply.admin_replies) == []
    finally:
        transport.stop(grace=None)
        thread.join(timeout=5)
    assert not thread.is_alive()
