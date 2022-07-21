"""Control utilities to interacts with nic_simulator."""
import pytest
import time

from tests.common import utilities
from tests.common.dualtor.dual_tor_common import cable_type                     # lgtm[py/unused-import]
from tests.common.dualtor.dual_tor_common import CableType

__all__ = [
    "nic_simulator_info",
    "restart_nic_simulator_session",
    "restart_nic_simulator",
    "nic_simulator_url",
    "toggle_all_ports_both_tors_admin_forwarding_state_to_active"
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
    ip = utilities.get_test_server_vars(inv_files, server).get('ansible_host')
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
