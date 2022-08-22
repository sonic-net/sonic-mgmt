"""Control utilities to interacts with nic_simulator."""
import grpc
import pytest
import time
import collections
import logging

from tests.common import utilities
from tests.common.dualtor.dual_tor_common import cable_type                     # lgtm[py/unused-import]
from tests.common.dualtor.dual_tor_common import mux_config                     # lgtm[py/unused-import]
from tests.common.dualtor.dual_tor_common import active_active_ports            # lgtm[py/unused-import]
from tests.common.dualtor.dual_tor_common import CableType
from tests.common.dualtor.nic_simulator import nic_simulator_grpc_service_pb2
from tests.common.dualtor.nic_simulator import nic_simulator_grpc_mgmt_service_pb2
from tests.common.dualtor.nic_simulator import nic_simulator_grpc_mgmt_service_pb2_grpc
from tests.common.dualtor.dual_tor_common import cable_type
from tests.common.dualtor.dual_tor_common import CableType


__all__ = [
    "nic_simulator_info",
    "restart_nic_simulator_session",
    "restart_nic_simulator",
    "nic_simulator_url",
    "nic_simulator_channel",
    "nic_simulator_client",
    "mux_status_from_nic_simulator",
    "toggle_active_all_ports_both_tors",
    "set_drop_active_active",
    "TrafficDirection"
]

logger = logging.getLogger(__name__)


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
        elif isinstance(ports, collections.Iterable):
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


def toggle_ports(duthosts, intf_name, state):
    """Toggle port from cmd line"""

    if not isinstance(duthosts, collections.Iterable):
        duthosts = [duthosts]

    toggled_intfs = []
    for duthost in duthosts:
        toggled_intfs.extend(_toggle_cmd(duthost, intf_name, state))
    return toggled_intfs


def _toggle_cmd(dut, intfs, state):
    """Toggle through DUT command line"""

    toggled_intfs = []

    logger.info('Setting {} as {} for intfs {}'.format(dut, state, intfs))
    if type(intfs) == str:
        cmds = ["config muxcable mode {} {}; true".format(state, intfs)]
        toggled_intfs.append((dut, intfs))
    else:
        cmds = []
        for intf in intfs:
            toggled_intfs.append((dut, intf))
            cmds.append("config muxcable mode {} {}; true".format(state, intf))
    dut.shell_cmds(cmds=cmds, continue_on_fail=True)

    return toggled_intfs


@pytest.fixture
def toggle_active_all_ports_both_tors(duthosts, cable_type, active_active_ports):
    """A function level fixture to toggle both ToRs' admin forwarding state to active for all active-active ports."""

    if cable_type == CableType.active_active:
        toggle_ports(duthosts, active_active_ports, state="active")
        yield
        toggle_ports(duthosts, active_active_ports, state="auto")
        return

    yield
    return


class TrafficDirection(object):
    """Traffic direction for link drop."""
    DOWNSTREAM = 0
    UPSTREAM = 1


@pytest.fixture
def set_drop_active_active(mux_config, nic_simulator_client):
    """Return a helper function to simulator link drop for active-active ports."""
    drop_intfs = set()

    def _call_set_drop_nic_simulator(nic_address, portid, direction, recover=False):
        drop_request = nic_simulator_grpc_service_pb2.DropRequest(
            portid=[portid],
            direction=[direction],
            recover=recover
        )
        request = nic_simulator_grpc_mgmt_service_pb2.ListOfDropRequest(
            nic_addresses=[nic_address],
            drop_requests=[drop_request]
        )
        client_stub = nic_simulator_client()
        client_stub.SetDrop(request)

    def _set_drop_active_active(interface_name, portid, direction):
        """
        Simulate link drop on a mux link.

        @param interface_name: interface name
        @param portid: 1 for upper ToR, 0 for lower ToR
        @param direction: 0 for downstream, 1 for upstream
        """
        nic_address = mux_config[interface_name]["SERVER"]["soc_ipv4"].split("/")[0]
        logging.debug(
            "Set drop on port %s, mux server %s, portid %s, direction %s",
            interface_name, nic_address, portid, direction
        )
        drop_intfs.add((interface_name, nic_address, portid, direction))
        _call_set_drop_nic_simulator(nic_address, portid, direction)

    yield _set_drop_active_active

    for (interface_name, nic_address, portid, direction) in drop_intfs:
        logging.debug(
            "Set drop recover on port %s, mux server %s, portid %s",
            interface_name, nic_address, portid,
        )
        _call_set_drop_nic_simulator(nic_address, portid, direction, recover=True)
