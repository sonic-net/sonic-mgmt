"""Control utilities to interacts with nic_simulator."""
import grpc
import pytest
import time

from collections import Iterable

from tests.common import utilities
from tests.common.dualtor.dual_tor_common import cable_type                     # lgtm[py/unused-import]
from tests.common.dualtor.dual_tor_common import mux_config                     # lgtm[py/unused-import]
from tests.common.dualtor.dual_tor_common import CableType
from tests.common.dualtor.nic_simulator import nic_simulator_grpc_service_pb2
from tests.common.dualtor.nic_simulator import nic_simulator_grpc_mgmt_service_pb2
from tests.common.dualtor.nic_simulator import nic_simulator_grpc_mgmt_service_pb2_grpc


__all__ = [
    "nic_simulator_info",
    "restart_nic_simulator_session",
    "restart_nic_simulator",
    "nic_simulator_url",
    "toggle_all_ports_both_tors_admin_forwarding_state_to_active",
    "nic_simulator_channel",
    "nic_simulator_client",
    "mux_status_from_nic_simulator",
]


class ForwardingState(object):
    """Forwarding state."""
    ACTIVE = True
    STANDBY = False


@pytest.fixture(scope="session")
def nic_simulator_info(request, tbinfo):
    """Fixture to gather nic_simulator related infomation."""
    if "dualtor-mixed" not in tbinfo["topo"]["name"]:
        return None, None, None

    server = tbinfo["server"]
    vmset_name = tbinfo["group-name"]
    inv_files = request.config.option.ansible_inventory
    ip = tbinfo["netns_mgmt_ip"].split("/")[0]
    _port_map = utilities.get_group_visible_vars(inv_files, server).get('nic_simulator_grpc_port')
    port = _port_map[tbinfo['conf-name']]
    return ip, port, vmset_name


def _restart_nic_simulator(vmhost, vmset_name):
    if vmset_name is not None:
        vmhost.command("systemctl restart nic-simulator-%s" % vmset_name)
        time.sleep(5)


@pytest.fixture(scope="session", autouse=True)
def restart_nic_simulator_session(nic_simulator_info, vmhost):
    """Session level fixture to restart nic_simulator service on the VM server host."""
    _, _, vmset_name = nic_simulator_info
    _restart_nic_simulator(vmhost, vmset_name)


@pytest.fixture(scope="module")
def restart_nic_simulator(nic_simulator_info, vmhost):
    """Fixture to restart nic_simulator service on the VM server host."""
    _, _, vmset_name = nic_simulator_info

    return lambda: _restart_nic_simulator(vmhost, vmset_name)


@pytest.fixture(scope="session")
def nic_simulator_channel(nic_simulator_info):
    """Setup connection to the nic_simulator."""
    channel = []
    server_ip, server_port, _ = nic_simulator_info
    server_url = "%s:%s" % (server_ip, server_port)

    def _setup_grpc_channel_to_nic_simulator():
        if channel:
            return channel[0]

        if server_ip is None:
            return None

        # temporarily disable HTTP proxies
        with utilities.update_environ("http_proxy", "https_proxy"):
            _channel = grpc.insecure_channel(server_url)
            try:
                grpc.channel_ready_future(_channel).result(timeout=2)
            except grpc.FutureTimeoutError as e:
                raise RuntimeError("Failed to establish connection to nic_simulator %s, error(%r)" % (server_url, e))
            channel.append(_channel)
            return _channel

    return _setup_grpc_channel_to_nic_simulator


@pytest.fixture(scope="session")
def nic_simulator_client(nic_simulator_channel):
    """Setup mgmt client stub to the nic_simulator."""
    channel = nic_simulator_channel()
    stub = []

    def _setup_grpc_client_stub():
        if stub:
            return stub[0]

        if channel is None:
            return None

        _stub = nic_simulator_grpc_mgmt_service_pb2_grpc.DualTorMgmtServiceStub(channel)
        stub.append(_stub)
        return _stub

    return _setup_grpc_client_stub


@pytest.fixture(scope="session")
def mux_status_from_nic_simulator(duthost, nic_simulator_client, mux_config, tbinfo):
    """Get mux status from the nic simulator."""
    active_active_ports = {}
    for port, config in mux_config.items():
        if config["SERVER"].get("cable_type", CableType.default_type) == CableType.active_active:
            config["SERVER"]["soc_ipv4"] = config["SERVER"]["soc_ipv4"].split("/")[0]
            active_active_ports[port] = config

    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    ptf_index_map = mg_facts["minigraph_ptf_indices"]
    admin_requests = [nic_simulator_grpc_service_pb2.AdminRequest(portid=[0, 1], state=[True, True]) for _ in range(len(active_active_ports))]

    def _get_mux_status(ports=None):
        if ports is None:
            ports = active_active_ports.keys()
        elif isinstance(ports, Iterable):
            ports = list(ports)
        else:
            ports = [str(ports)]

        client_stub = nic_simulator_client()
        if client_stub is None:
            return {}

        nic_addresses = [active_active_ports[port]["SERVER"]["soc_ipv4"] for port in ports]
        request = nic_simulator_grpc_mgmt_service_pb2.ListOfAdminRequest(
            nic_addresses=nic_addresses,
            admin_requests=admin_requests[:len(nic_addresses)]
        )
        reply = client_stub.QueryAdminForwardingPortState(request)

        mux_status = {}
        for port, port_status in zip(ports, reply.admin_replies):
            mux_status[ptf_index_map[port]] = dict(zip(port_status.portid, port_status.state))

        return mux_status

    return _get_mux_status


@pytest.fixture(scope="session")
def nic_simulator_url(nic_simulator_info):
    """Fixture to return the nic_simulator url."""
    pass


def set_upper_tor_admin_forwarding_state(nic_simulator_url, port, state):
    """Set upper ToR admin forwarding state."""
    pass


def set_lower_tor_admin_forwarding_state(nic_simulator_url, port, state):
    """Set lower ToR admin forwarding state."""
    pass


def set_all_ports_upper_tor_admin_forwarding_state(nic_simulator_url, state):
    """Set all ports lower ToR admin forwarding state."""
    pass


def set_all_ports_lower_tor_admin_forwarding_state(nic_simulator_url, state):
    """Set all ports lower ToR admin forwarding state."""
    pass


@pytest.fixture
def toggle_all_ports_both_tors_admin_forwarding_state_to_active(nic_simulator_url, cable_type):
    """A function level fixture to toggle both ToRs' admin forwarding state to active for all active-active ports."""
    if cable_type == CableType.active_active:
        set_all_ports_upper_tor_admin_forwarding_state(nic_simulator_url, ForwardingState.ACTIVE)
        set_all_ports_lower_tor_admin_forwarding_state(nic_simulator_url, ForwardingState.ACTIVE)
