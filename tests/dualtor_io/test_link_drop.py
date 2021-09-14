import logging
import json
import pytest
import tabulate
import time

from tests.common.dualtor.control_plane_utils import verify_tor_states
from tests.common.dualtor.dual_tor_utils import upper_tor_host, lower_tor_host # lgtm[py/unused-import]
from tests.common.dualtor.data_plane_utils import send_server_to_t1_with_action # lgtm[py/unused-import]
from tests.common.dualtor.data_plane_utils import send_t1_to_server_with_action # lgtm[py/unused-import]
from tests.common.dualtor.mux_simulator_control import set_drop # lgtm[py/unused-import]
from tests.common.dualtor.mux_simulator_control import set_output # lgtm[py/unused-import]
from tests.common.dualtor.mux_simulator_control import simulator_flap_counter # lgtm[py/unused-import]
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_upper_tor # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import run_icmp_responder, run_garp_service # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import change_mac_addresses             # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory         # lgtm[py/unused-import]
from tests.common.dualtor.constants import MUX_SIM_ALLOWED_DISRUPTION_SEC

pytestmark = [
    pytest.mark.topology("dualtor")
]

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
    return _set_drop_factory(set_drop, direction, tor_mux_intfs)


@pytest.fixture(scope="function")
def drop_flow_lower_tor(set_drop, set_output, tor_mux_intfs):
    """Drop the flow to the lower ToR."""
    direction = "lower_tor"
    return _set_drop_factory(set_drop, direction, tor_mux_intfs)


@pytest.fixture(scope="function")
def check_simulator_flap_counter(
    simulator_flap_counter,
    toggle_all_simulator_ports_to_upper_tor,
    tor_mux_intfs
):
    """Check the flap count for each server-facing interfaces."""
    def set_expected_counter_diff(diff):
        """Set expected counter difference."""
        expected_diff.append(diff)

    expected_diff = []
    tor_mux_intfs = [str(_) for _ in tor_mux_intfs]
    counters_before = {intf: simulator_flap_counter(intf) for intf in tor_mux_intfs}
    yield set_expected_counter_diff
    counters_after = {intf: simulator_flap_counter(intf) for intf in tor_mux_intfs}
    logging.info(
        "\n%s\n",
        tabulate.tabulate(
            [[intf, counters_before[intf], counters_after[intf]] for intf in tor_mux_intfs],
            headers=["port", "flap counter before", "flap counter after"]
        )
    )
    counter_diffs = {intf: counters_after[intf] - counters_before[intf] for intf in tor_mux_intfs}
    if expected_diff:
        not_expected_counter_diffs = [
            intf for intf, counter_diff in counter_diffs.items() if counter_diff != expected_diff[-1]
        ]

        error_str = json.dumps(not_expected_counter_diffs, indent=4)
        if not_expected_counter_diffs:
            logging.error(error_str)
            raise ValueError(error_str)


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
        delay=MUX_SIM_ALLOWED_DISRUPTION_SEC,
        allowed_disruption=3,
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
        delay=MUX_SIM_ALLOWED_DISRUPTION_SEC,
        allowed_disruption=3,
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
        delay=MUX_SIM_ALLOWED_DISRUPTION_SEC,
        allowed_disruption=3,
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
    check_simulator_flap_counter,
    drop_flow_lower_tor
):
    """
    Send traffic from servers to T1 and remove the flow between the servers and the standby ToR.
    Verify that no switchover and disruption occur.
    """
    send_server_to_t1_with_action(
        upper_tor_host,
        verify=True,
        delay=MUX_SIM_ALLOWED_DISRUPTION_SEC,
        allowed_disruption=2,
        action=drop_flow_lower_tor
    )
    verify_tor_states(
        expected_active_host=upper_tor_host,
        expected_standby_host=lower_tor_host,
        expected_standby_health="unhealthy"
    )
    check_simulator_flap_counter(2)


def test_standby_link_drop_downstream_active(
    upper_tor_host,
    lower_tor_host,
    send_t1_to_server_with_action,
    check_simulator_flap_counter,
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
        delay=MUX_SIM_ALLOWED_DISRUPTION_SEC,
        allowed_disruption=2,
        action=drop_flow_lower_tor
    )
    verify_tor_states(
        expected_active_host=upper_tor_host,
        expected_standby_host=lower_tor_host,
        expected_standby_health="unhealthy"
    )
    check_simulator_flap_counter(2)


def test_standby_link_drop_downstream_standby(
    upper_tor_host,
    lower_tor_host,
    send_t1_to_server_with_action,
    check_simulator_flap_counter,
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
        delay=MUX_SIM_ALLOWED_DISRUPTION_SEC,
        allowed_disruption=2,
        action=drop_flow_lower_tor
    )
    verify_tor_states(
        expected_active_host=upper_tor_host,
        expected_standby_host=lower_tor_host,
        expected_standby_health="unhealthy"
    )
    check_simulator_flap_counter(2)
