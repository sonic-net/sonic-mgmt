"""Control utilities to interacts with nic_simulator."""
import pytest

from tests.common.dualtor.dual_tor_common import cable_type                     # lgtm[py/unused-import]
from tests.common.dualtor.dual_tor_common import CableType

__all__ = [
    "nic_simulator_info",
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
    pass


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
