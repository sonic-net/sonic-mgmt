"""Control utilities to interacts with nic_simulator."""
import grpc
import pytest
import time
import collections
import logging

from tests.common import utilities
from tests.common.dualtor.dual_tor_common import cable_type                     # noqa F401
from tests.common.dualtor.dual_tor_common import mux_config                     # noqa F401
from tests.common.dualtor.dual_tor_common import ActiveActivePortID             # noqa F401
from tests.common.dualtor.dual_tor_common import active_active_ports            # noqa F401
from tests.common.dualtor.dual_tor_common import active_active_ports_config     # noqa F401
from tests.common.dualtor.dual_tor_common import CableType
from tests.common.dualtor.nic_simulator import nic_simulator_grpc_service_pb2
from tests.common.dualtor.nic_simulator import nic_simulator_grpc_mgmt_service_pb2
from tests.common.dualtor.nic_simulator import nic_simulator_grpc_mgmt_service_pb2_grpc


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
    "TrafficDirection",
    "ForwardingState",
    "toggle_active_active_simulator_ports"
]

logger = logging.getLogger(__name__)


class ForwardingState(object):
    """Forwarding state."""
    ACTIVE = True
    STANDBY = False


def call_grpc(func, args=None, kwargs=None, timeout=5, retries=3, ignore_errors=False):
    if args is None:
        args = []
    if kwargs is None:
        kwargs = {}
    kwargs["timeout"] = timeout
    for i in range(retries - 1):
        try:
            response = func(*args, **kwargs)
        except grpc.RpcError as e:
            # first retries - 1 tries errors are all ignored
            logging.debug("Calling %s %dth time results error(%r)" % (func, i + 1, e))
        else:
            return response

    try:
        response = func(*args, **kwargs)
    except grpc.RpcError as e:
        logging.debug("Calling %s %dth time results error(%r)" % (func, retries, e))
        if not ignore_errors:
            raise

    return response


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


@pytest.fixture(scope="module")
def stop_nic_simulator(nic_simulator_info, vmhost):
    """Fixture to stop nic_simulator service on the VM server host."""

    def _stop_nic_simulator(vmhost, vmset_name):
        if vmset_name is not None:
            vmhost.command("systemctl stop nic-simulator-%s" % vmset_name)

    _, _, vmset_name = nic_simulator_info
    yield lambda: _stop_nic_simulator(vmhost, vmset_name)

    _restart_nic_simulator(vmhost, vmset_name)


@pytest.fixture(scope="session")
def nic_simulator_channel(nic_simulator_info):
    """Setup connection to the nic_simulator."""
    server_ip, server_port, _ = nic_simulator_info
    server_url = "%s:%s" % (server_ip, server_port)

    def _setup_grpc_channel_to_nic_simulator():
        if server_ip is None:
            return None

        # temporarily disable HTTP proxies
        with utilities.update_environ("http_proxy", "https_proxy"):
            return grpc.insecure_channel(server_url)

    return _setup_grpc_channel_to_nic_simulator


@pytest.fixture(scope="session")
def nic_simulator_client(nic_simulator_channel):
    """Setup mgmt client stub to the nic_simulator."""
    channel = nic_simulator_channel()

    def _setup_grpc_client_stub():
        if channel is None:
            return None

        return nic_simulator_grpc_mgmt_service_pb2_grpc.DualTorMgmtServiceStub(channel)

    return _setup_grpc_client_stub


@pytest.fixture(scope="session")
def mux_status_from_nic_simulator(duthost, nic_simulator_client, active_active_ports_config, tbinfo):   # noqa F811
    """Get mux status from the nic simulator."""

    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    ptf_index_map = mg_facts["minigraph_ptf_indices"]
    admin_requests = [nic_simulator_grpc_service_pb2.AdminRequest(portid=[0, 1], state=[True, True])
                      for _ in range(len(active_active_ports_config))]

    def _get_mux_status(ports=None):
        if ports is None:
            ports = active_active_ports_config.keys()
        elif isinstance(ports, list) or isinstance(ports, tuple):
            ports = list(ports)
        else:
            ports = [str(ports)]

        client_stub = nic_simulator_client()
        if client_stub is None:
            return {}

        nic_addresses = [active_active_ports_config[port]["SERVER"]["soc_ipv4"].split("/")[0] for port in ports]
        request = nic_simulator_grpc_mgmt_service_pb2.ListOfAdminRequest(
            nic_addresses=nic_addresses,
            admin_requests=admin_requests[:len(nic_addresses)]
        )
        reply = call_grpc(client_stub.QueryAdminForwardingPortState, [request])

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
def toggle_active_all_ports_both_tors(duthosts, cable_type, active_active_ports):       # noqa F811
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
def set_drop_active_active(mux_config, nic_simulator_client):       # noqa F811
    """Return a helper function to simulator link drop for active-active ports."""
    _interface_names = []
    _nic_addresses = []
    _portids = []
    _directions = []

    def _call_set_drop_nic_simulator(nic_addresses, portids, directions, recover=False):
        drop_requests = []
        for portid, direction in zip(portids, directions):
            drop_request = nic_simulator_grpc_service_pb2.DropRequest(
                portid=[portid],
                direction=[direction],
                recover=recover
            )
            drop_requests.append(drop_request)

        request = nic_simulator_grpc_mgmt_service_pb2.ListOfDropRequest(
            nic_addresses=list(nic_addresses),
            drop_requests=drop_requests
        )
        client_stub = nic_simulator_client()
        call_grpc(client_stub.SetDrop, [request])

    def _set_drop_active_active(interface_names, portids, directions):
        """
        Simulate link drop on a mux link.

        @param interface_names: list of interface names
        @param portids: list of portids, 1 for upper ToR, 0 for lower ToR
        @param directions: list of directions 0 for downstream, 1 for upstream
        """
        nic_addresses = []
        for interface_name, portid, direction in zip(interface_names, portids, directions):
            nic_address = mux_config[interface_name]["SERVER"]["soc_ipv4"].split("/")[0]
            logging.debug(
                "Set drop on port %s, mux server %s, portid %s, direction %s",
                interface_name, nic_address, portid, direction
            )
            nic_addresses.append(nic_address)

        _interface_names.extend(interface_names)
        _nic_addresses.extend(nic_addresses)
        _portids.extend(portids)
        _directions.extend(directions)

        _call_set_drop_nic_simulator(nic_addresses, portids, directions)

    yield _set_drop_active_active

    for (interface_name, nic_address, portid, _) in zip(_interface_names, _nic_addresses, _portids, _directions):
        logging.debug(
            "Set drop recover on port %s, mux server %s, portid %s",
            interface_name, nic_address, portid,
        )
        _call_set_drop_nic_simulator(_nic_addresses, _portids, _directions, recover=True)


@pytest.fixture(scope="function")
def toggle_active_active_simulator_ports(active_active_ports_config, nic_simulator_client):     # noqa F811
    """Toggle nic_simulator forwarding state."""

    def _toggle_active_active_simulator_ports(mux_ports, portid, state):
        logging.info("Toggle simulator ports %s to %s", mux_ports, state)
        if not mux_ports:
            return

        client_stub = nic_simulator_client()
        if client_stub is None:
            return {}

        if portid not in (ActiveActivePortID.UPPER_TOR, ActiveActivePortID.LOWER_TOR):
            raise ValueError(
                "Unsupported portid, please use %s for upper ToR, %s for lower ToR" %
                (ActiveActivePortID.UPPER_TOR, ActiveActivePortID.LOWER_TOR)
            )
        for mux_port in mux_ports:
            if mux_port not in active_active_ports_config:
                raise ValueError("mux port %s is not of cable type 'active-active'" % mux_port)

        nic_addresses = [active_active_ports_config[port]["SERVER"]["soc_ipv4"].split("/")[0] for port in mux_ports]
        admin_requests = [nic_simulator_grpc_service_pb2.AdminRequest(portid=[portid], state=[state])
                          for _ in nic_addresses]
        request = nic_simulator_grpc_mgmt_service_pb2.ListOfAdminRequest(
            nic_addresses=nic_addresses,
            admin_requests=admin_requests
        )

        reply = call_grpc(client_stub.SetAdminForwardingPortState, [request])

        for mux_port, port_status in zip(mux_ports, reply.admin_replies):
            status = dict(zip(port_status.portid, port_status.state))
            if status[portid] != state:
                raise ValueError("failed to toggle port %s, portid %s, state %s" % (mux_port, portid, state))

    return _toggle_active_active_simulator_ports
