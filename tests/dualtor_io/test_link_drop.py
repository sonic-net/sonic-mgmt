import logging
import pytest
import time

from tests.common.dualtor.control_plane_utils import verify_tor_states
from tests.common.dualtor.dual_tor_utils import upper_tor_host, lower_tor_host                  # noqa F401
from tests.common.dualtor.dual_tor_utils import check_simulator_flap_counter                    # noqa F401
from tests.common.dualtor.data_plane_utils import send_server_to_t1_with_action                 # noqa F401
from tests.common.dualtor.data_plane_utils import send_t1_to_server_with_action                 # noqa F401
from tests.common.dualtor.mux_simulator_control import set_drop                                 # noqa F401
from tests.common.dualtor.mux_simulator_control import set_drop_all                             # noqa F401
from tests.common.dualtor.mux_simulator_control import set_output                               # noqa F401
from tests.common.dualtor.mux_simulator_control import simulator_flap_counter                   # noqa F401
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_upper_tor  # noqa F401
from tests.common.dualtor.nic_simulator_control import nic_simulator_flap_counter               # noqa F401
from tests.common.dualtor.nic_simulator_control import set_drop_active_active                   # noqa F401
from tests.common.dualtor.nic_simulator_control import TrafficDirection
from tests.common.fixtures.ptfhost_utils import run_icmp_responder, run_garp_service            # noqa F401
from tests.common.fixtures.ptfhost_utils import change_mac_addresses                            # noqa F401
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory                         # noqa F401
# Temporary work around to add skip_traffic_test fixture from duthost_utils
from tests.common.fixtures.duthost_utils import skip_traffic_test                               # noqa F401
from tests.common.dualtor.constants import MUX_SIM_ALLOWED_DISRUPTION_SEC
from tests.common.dualtor.dual_tor_common import ActiveActivePortID
from tests.common.dualtor.dual_tor_common import active_active_ports                            # noqa F401
from tests.common.dualtor.dual_tor_common import active_standby_ports                           # noqa F401
from tests.common.dualtor.dual_tor_common import cable_type                                     # noqa F401
from tests.common.dualtor.dual_tor_common import CableType


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
def drop_flow_upper_tor(set_drop, set_output, active_standby_ports):                    # noqa F811
    """Drop the flow to the upper ToR."""
    direction = "upper_tor"
    return _set_drop_factory(set_drop, direction, active_standby_ports)


@pytest.fixture(scope="function")
def drop_flow_lower_tor(set_drop, set_output, active_standby_ports):                    # noqa F811
    """Drop the flow to the lower ToR."""
    direction = "lower_tor"
    return _set_drop_factory(set_drop, direction, active_standby_ports)


def _set_drop_all_factory(set_drop_all_func, direction, tor_mux_intfs):                         # noqa F811
    """Factory to get set drop function for either upper_tor or lower_tor."""
    def _set_drop_all_interfaces():
        logging.debug("Start set drop all for %s at %s", direction, time.time())
        set_drop_all_func([direction])
    return _set_drop_all_interfaces


@pytest.fixture(scope="function")
def drop_flow_upper_tor_all(set_drop_all, set_output, active_standby_ports):                    # noqa F811
    """Drop the flow to the upper ToR."""
    direction = "upper_tor"
    return _set_drop_all_factory(set_drop_all, direction, active_standby_ports)


@pytest.fixture(scope="function")
def drop_flow_lower_tor_all(set_drop_all, set_output, active_standby_ports):                    # noqa F811
    """Drop the flow to the lower ToR."""
    direction = "lower_tor"
    return _set_drop_all_factory(set_drop_all, direction, active_standby_ports)


@pytest.fixture(scope="function")
def drop_flow_upper_tor_active_active(active_active_ports, set_drop_active_active):     # noqa F811
    direction = TrafficDirection.UPSTREAM
    portid = ActiveActivePortID.UPPER_TOR

    def _drop_flow_upper_tor_active_active():
        logging.debug("Start set drop for upper ToR at %s", time.time())
        for port in active_active_ports:
            logging.debug("Set drop on port %s, portid %s, direction %s" % (port, portid, direction))
        portids = [portid for _ in active_active_ports]
        directions = [direction for _ in active_active_ports]
        set_drop_active_active(active_active_ports, portids, directions)

    return _drop_flow_upper_tor_active_active


@pytest.mark.enable_active_active
def test_active_link_drop_upstream(
    upper_tor_host, lower_tor_host, send_server_to_t1_with_action,      # noqa F811
    toggle_all_simulator_ports_to_upper_tor, drop_flow_upper_tor_all,   # noqa F811
    drop_flow_upper_tor_active_active, cable_type, skip_traffic_test    # noqa F811
):
    """
    Send traffic from servers to T1 and remove the flow between the servers and the active ToR.
    Verify the switchover and disruption last < 1 second.
    """
    if cable_type == CableType.active_standby:
        send_server_to_t1_with_action(
            upper_tor_host,
            verify=True,
            delay=MUX_SIM_ALLOWED_DISRUPTION_SEC,
            allowed_disruption=3,
            action=drop_flow_upper_tor_all,
            skip_traffic_test=skip_traffic_test
        )
        verify_tor_states(
            expected_active_host=lower_tor_host,
            expected_standby_host=upper_tor_host,
            expected_standby_health="unhealthy",
            cable_type=cable_type
        )

    if cable_type == CableType.active_active:
        send_server_to_t1_with_action(
            upper_tor_host,
            verify=True,
            delay=MUX_SIM_ALLOWED_DISRUPTION_SEC,
            allowed_disruption=1,
            action=drop_flow_upper_tor_active_active,
            skip_traffic_test=skip_traffic_test
        )
        verify_tor_states(
            expected_active_host=lower_tor_host,
            expected_standby_host=upper_tor_host,
            expected_standby_health="unhealthy",
            cable_type=cable_type,
            skip_state_db=True
        )


@pytest.mark.enable_active_active
def test_active_link_drop_downstream_active(
    upper_tor_host, lower_tor_host, send_t1_to_server_with_action,      # noqa F811
    toggle_all_simulator_ports_to_upper_tor, drop_flow_upper_tor_all,   # noqa F811
    drop_flow_upper_tor_active_active, cable_type, skip_traffic_test    # noqa F811
):
    """
    Send traffic from the T1s to the servers via the active Tor and remove the flow between the
    servers and the active ToR.
    Verify the switchover and disruption last < 1 second.
    """
    if cable_type == CableType.active_standby:
        send_t1_to_server_with_action(
            upper_tor_host,
            verify=True,
            delay=MUX_SIM_ALLOWED_DISRUPTION_SEC,
            allowed_disruption=3,
            action=drop_flow_upper_tor_all,
            skip_traffic_test=skip_traffic_test
        )
        verify_tor_states(
            expected_active_host=lower_tor_host,
            expected_standby_host=upper_tor_host,
            expected_standby_health="unhealthy",
            cable_type=cable_type
        )

    if cable_type == CableType.active_active:
        send_t1_to_server_with_action(
            upper_tor_host,
            verify=True,
            delay=MUX_SIM_ALLOWED_DISRUPTION_SEC,
            allowed_disruption=1,
            action=drop_flow_upper_tor_active_active,
            skip_traffic_test=skip_traffic_test
        )
        verify_tor_states(
            expected_active_host=lower_tor_host,
            expected_standby_host=upper_tor_host,
            expected_standby_health="unhealthy",
            cable_type=cable_type,
            skip_state_db=True
        )


def test_active_link_drop_downstream_standby(
    upper_tor_host, lower_tor_host, send_t1_to_server_with_action,      # noqa F811
    toggle_all_simulator_ports_to_upper_tor, drop_flow_upper_tor_all,   # noqa F811
    skip_traffic_test                                                   # noqa F811
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
        action=drop_flow_upper_tor_all,
        skip_traffic_test=skip_traffic_test
    )
    verify_tor_states(
        expected_active_host=lower_tor_host,
        expected_standby_host=upper_tor_host,
        expected_standby_health="unhealthy"
    )


def test_standby_link_drop_upstream(
    upper_tor_host, lower_tor_host, send_server_to_t1_with_action,      # noqa F811
    check_simulator_flap_counter, drop_flow_lower_tor_all,              # noqa F811
    toggle_all_simulator_ports_to_upper_tor, skip_traffic_test          # noqa F811
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
        action=drop_flow_lower_tor_all,
        skip_traffic_test=skip_traffic_test
    )
    verify_tor_states(
        expected_active_host=upper_tor_host,
        expected_standby_host=lower_tor_host,
        expected_standby_health="unhealthy"
    )
    check_simulator_flap_counter(2)


def test_standby_link_drop_downstream_active(
    upper_tor_host, lower_tor_host, send_t1_to_server_with_action,      # noqa F811
    check_simulator_flap_counter, drop_flow_lower_tor_all,              # noqa F811
    toggle_all_simulator_ports_to_upper_tor, skip_traffic_test          # noqa F811
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
        action=drop_flow_lower_tor_all,
        skip_traffic_test=skip_traffic_test
    )
    verify_tor_states(
        expected_active_host=upper_tor_host,
        expected_standby_host=lower_tor_host,
        expected_standby_health="unhealthy"
    )
    check_simulator_flap_counter(2)


def test_standby_link_drop_downstream_standby(
    upper_tor_host, lower_tor_host, send_t1_to_server_with_action,      # noqa F811
    check_simulator_flap_counter, drop_flow_lower_tor_all,              # noqa F811
    toggle_all_simulator_ports_to_upper_tor, skip_traffic_test          # noqa F811
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
        action=drop_flow_lower_tor_all,
        skip_traffic_test=skip_traffic_test
    )
    verify_tor_states(
        expected_active_host=upper_tor_host,
        expected_standby_host=lower_tor_host,
        expected_standby_health="unhealthy"
    )
    check_simulator_flap_counter(2)
