import logging
import pytest
import time

from tests.common.dualtor.control_plane_utils import verify_tor_states
from tests.common.dualtor.dual_tor_utils import upper_tor_host
from tests.common.dualtor.dual_tor_utils import lower_tor_host
from tests.common.dualtor.data_plane_utils import send_server_to_t1_with_action
from tests.common.dualtor.data_plane_utils import send_t1_to_server_with_action
from tests.common.dualtor.mux_simulator_control import set_drop
from tests.common.dualtor.mux_simulator_control import set_output
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_upper_tor
from tests.common.fixtures.ptfhost_utils import run_icmp_responder
from tests.common.fixtures.ptfhost_utils import change_mac_addresses             # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory


def _set_drop_factory(set_drop_func, direction, tor_mux_intfs):
    """Factory to get set drop function for either upper_tor or lower_tor."""
    def _set_drop_all_interfaces():
        logging.debug("Start set drop for %s at %s", direction, time.time())
        for intf in tor_mux_intfs:
            set_drop_func(intf, [direction])
    return _set_drop_all_interfaces


@pytest.fixture(scope="function")
def drop_flow_upper_tor(set_drop, set_output, tor_mux_intfs):
    """Drop the flow to the upper ToR."""
    direction = "upper_tor"
    yield _set_drop_factory(set_drop, direction, tor_mux_intfs)

    for intf in tor_mux_intfs:
        set_output(intf, [direction])


@pytest.fixture(scope="function")
def drop_flow_lower_tor(set_drop, set_output, tor_mux_intfs):
    """Drop the flow to the lower ToR."""
    direction = "lower_tor"
    yield _set_drop_factory(set_drop, direction, tor_mux_intfs)

    for intf in tor_mux_intfs:
        set_output(intf, [direction])


def test_active_link_drop_upstream(
    upper_tor_host,
    lower_tor_host,
    send_server_to_t1_with_action,
    toggle_all_simulator_ports_to_upper_tor,
    drop_flow_upper_tor
):
    """
    Send traffic from servers to T1 and remove the flow between the servers and the active ToR.
    Verify the switchover and disruption last < 1 second.
    """
    send_server_to_t1_with_action(
        upper_tor_host,
        verify=True,
        delay=1,
        action=drop_flow_upper_tor
    )
    verify_tor_states(
        expected_active_host=lower_tor_host,
        expected_standby_host=upper_tor_host,
        expected_standby_health="unhealthy"
    )


def test_active_link_drop_downstream_active(
    upper_tor_host,
    lower_tor_host,
    send_t1_to_server_with_action,
    toggle_all_simulator_ports_to_upper_tor,
    drop_flow_upper_tor
):
    """
    Send traffic from the T1s to the servers via the active Tor and remove the flow between the
    servers and the active ToR.
    Verify the switchover and disruption last < 1 second.
    """
    send_t1_to_server_with_action(
        upper_tor_host,
        verify=True,
        delay=1,
        action=drop_flow_upper_tor
    )
    verify_tor_states(
        expected_active_host=lower_tor_host,
        expected_standby_host=upper_tor_host,
        expected_standby_health="unhealthy"
    )


def test_active_link_drop_downstream_standby(
    upper_tor_host,
    lower_tor_host,
    send_t1_to_server_with_action,
    toggle_all_simulator_ports_to_upper_tor,
    drop_flow_upper_tor
):
    """
    Send traffic from the T1s to the servers via the standby Tor and remove the flow between the
    servers and the active ToR.
    Verify the switchover and disruption last < 1 second.
    """
    send_t1_to_server_with_action(
        lower_tor_host,
        verify=True,
        delay=1,
        action=drop_flow_upper_tor
    )
    verify_tor_states(
        expected_active_host=lower_tor_host,
        expected_standby_host=upper_tor_host,
        expected_standby_health="unhealthy"
    )


def test_standby_link_drop_upstream(
    upper_tor_host,
    lower_tor_host,
    send_server_to_t1_with_action,
    toggle_all_simulator_ports_to_upper_tor,
    drop_flow_lower_tor
):
    """
    Send traffic from servers to T1 and remove the flow between the servers and the standby ToR.
    Verify that no switchover and disruption occur.
    """
    send_server_to_t1_with_action(
        upper_tor_host,
        verify=True,
        delay=1,
        action=drop_flow_lower_tor
    )
    verify_tor_states(
        expected_active_host=upper_tor_host,
        expected_standby_host=lower_tor_host,
        expected_standby_health="unhealthy"
    )


def test_standby_link_drop_downstream_active(
    upper_tor_host,
    lower_tor_host,
    send_t1_to_server_with_action,
    toggle_all_simulator_ports_to_upper_tor,
    drop_flow_lower_tor
):
    """
    Send traffic from the T1s to the servers via the active Tor and remove the flow between the
    servers and the standby ToR.
    Verify that no switchover and disruption occur.
    """
    send_t1_to_server_with_action(
        upper_tor_host,
        verify=True,
        delay=1,
        action=drop_flow_lower_tor
    )
    verify_tor_states(
        expected_active_host=upper_tor_host,
        expected_standby_host=lower_tor_host,
        expected_standby_health="unhealthy"
    )

def test_standby_link_drop_downstream_standby(
    upper_tor_host,
    lower_tor_host,
    send_t1_to_server_with_action,
    toggle_all_simulator_ports_to_upper_tor,
    drop_flow_lower_tor
):
    """
    Send traffic from the T1s to the servers via the standby Tor and remove the flow between the
    servers and the standby ToR.
    Verify that no switchover and disruption occur.
    """
    send_t1_to_server_with_action(
        lower_tor_host,
        verify=True,
        delay=1,
        action=drop_flow_lower_tor
    )
    verify_tor_states(
        expected_active_host=upper_tor_host,
        expected_standby_host=lower_tor_host,
        expected_standby_health="unhealthy"
    )
