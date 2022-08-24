import pytest

from tests.common.dualtor.control_plane_utils import verify_tor_states
from tests.common.dualtor.data_plane_utils import send_t1_to_server_with_action, send_server_to_t1_with_action                                  # lgtm[py/unused-import]
from tests.common.dualtor.dual_tor_utils import upper_tor_host, lower_tor_host, shutdown_fanout_upper_tor_intfs, \
                                                shutdown_fanout_lower_tor_intfs, upper_tor_fanouthosts, lower_tor_fanouthosts, \
                                                shutdown_upper_tor_downlink_intfs, shutdown_lower_tor_downlink_intfs                   # lgtm[py/unused-import]
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_upper_tor                                                  # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import run_icmp_responder, run_garp_service, copy_ptftests_directory, change_mac_addresses             # lgtm[py/unused-import]
from tests.common.dualtor.constants import MUX_SIM_ALLOWED_DISRUPTION_SEC
from tests.common.dualtor.dual_tor_common import cable_type
from tests.common.dualtor.dual_tor_common import CableType


pytestmark = [
    pytest.mark.topology("dualtor")
]


@pytest.mark.enable_active_active
def test_active_link_down_upstream(
    upper_tor_host, lower_tor_host, send_server_to_t1_with_action,
    toggle_all_simulator_ports_to_upper_tor,
    shutdown_fanout_upper_tor_intfs, cable_type
):
    """
    Send traffic from server to T1 and shutdown the active ToR link.
    Verify switchover and disruption lasts < 1 second
    """
    if cable_type == CableType.active_active:
        send_server_to_t1_with_action(
            upper_tor_host, verify=True, delay=MUX_SIM_ALLOWED_DISRUPTION_SEC,
            allowed_disruption=1, action=shutdown_fanout_upper_tor_intfs
        )
        verify_tor_states(
            expected_active_host=lower_tor_host,
            expected_standby_host=upper_tor_host,
            expected_standby_health='unhealthy',
            cable_type=cable_type,
            skip_state_db=True
        )

    if cable_type == CableType.active_standby:
        send_server_to_t1_with_action(
            upper_tor_host, verify=True, delay=MUX_SIM_ALLOWED_DISRUPTION_SEC,
            allowed_disruption=3, action=shutdown_fanout_upper_tor_intfs
        )

        verify_tor_states(
            expected_active_host=lower_tor_host,
            expected_standby_host=upper_tor_host,
            expected_standby_health='unhealthy',
            cable_type=cable_type,
        )


@pytest.mark.enable_active_active
def test_active_link_down_downstream_active(
    upper_tor_host, lower_tor_host, send_t1_to_server_with_action,
    toggle_all_simulator_ports_to_upper_tor,
    shutdown_fanout_upper_tor_intfs, cable_type
):
    """
    Send traffic from T1 to active ToR and shutdown the active ToR link.
    Verify switchover and disruption lasts < 1 second
    """
    if cable_type == CableType.active_standby:
        send_t1_to_server_with_action(
            upper_tor_host, verify=True, delay=MUX_SIM_ALLOWED_DISRUPTION_SEC,
            allowed_disruption=3, action=shutdown_fanout_upper_tor_intfs
        )
        verify_tor_states(
            expected_active_host=lower_tor_host,
            expected_standby_host=upper_tor_host,
            expected_standby_health='unhealthy'
        )

    if cable_type == CableType.active_active:
        send_t1_to_server_with_action(
            upper_tor_host, verify=True, delay=MUX_SIM_ALLOWED_DISRUPTION_SEC,
            allowed_disruption=1, action=shutdown_fanout_upper_tor_intfs
        )
        verify_tor_states(
            expected_active_host=lower_tor_host,
            expected_standby_host=upper_tor_host,
            expected_standby_health='unhealthy',
            cable_type=cable_type,
            skip_state_db=True
        )


def test_active_link_down_downstream_standby(
    upper_tor_host, lower_tor_host, send_t1_to_server_with_action,
    toggle_all_simulator_ports_to_upper_tor,
    shutdown_fanout_upper_tor_intfs
):
    """
    Send traffic from T1 to standby ToR and shutdown the active ToR link.
    Verify switchover and disruption lasts < 1 second
    """
    send_t1_to_server_with_action(
        lower_tor_host, verify=True, delay=MUX_SIM_ALLOWED_DISRUPTION_SEC,
        allowed_disruption=3, action=shutdown_fanout_upper_tor_intfs
    )
    verify_tor_states(
        expected_active_host=lower_tor_host,
        expected_standby_host=upper_tor_host,
        expected_standby_health='unhealthy'
    )


def test_standby_link_down_upstream(
    upper_tor_host, lower_tor_host, send_server_to_t1_with_action,
    toggle_all_simulator_ports_to_upper_tor,
    shutdown_fanout_lower_tor_intfs
):
    """
    Send traffic from server to T1 and shutdown the standby ToR link.
    Verify no switchover and no disruption
    """
    send_server_to_t1_with_action(
        upper_tor_host, verify=True, delay=MUX_SIM_ALLOWED_DISRUPTION_SEC,
        allowed_disruption=2, action=shutdown_fanout_lower_tor_intfs
    )
    verify_tor_states(
        expected_active_host=upper_tor_host,
        expected_standby_host=lower_tor_host,
        expected_standby_health='unhealthy'
    )


def test_standby_link_down_downstream_active(
    upper_tor_host, lower_tor_host, send_t1_to_server_with_action,
    toggle_all_simulator_ports_to_upper_tor,
    shutdown_fanout_lower_tor_intfs
):
    """
    Send traffic from T1 to active ToR and shutdown the standby ToR link.
    Confirm no switchover and no disruption
    """
    send_t1_to_server_with_action(
        upper_tor_host, verify=True, delay=MUX_SIM_ALLOWED_DISRUPTION_SEC,
        allowed_disruption=2, action=shutdown_fanout_lower_tor_intfs
    )
    verify_tor_states(
        expected_active_host=upper_tor_host,
        expected_standby_host=lower_tor_host,
        expected_standby_health='unhealthy'
    )


def test_standby_link_down_downstream_standby(
    upper_tor_host, lower_tor_host, send_t1_to_server_with_action,
    toggle_all_simulator_ports_to_upper_tor,
    shutdown_fanout_lower_tor_intfs
):
    """
    Send traffic from T1 to standby ToR and shutdwon the standby ToR link.
    Confirm no switchover and no disruption
    """
    send_t1_to_server_with_action(
        lower_tor_host, verify=True, delay=MUX_SIM_ALLOWED_DISRUPTION_SEC,
        allowed_disruption=2, action=shutdown_fanout_lower_tor_intfs
    )
    verify_tor_states(
        expected_active_host=upper_tor_host,
        expected_standby_host=lower_tor_host,
        expected_standby_health='unhealthy'
    )


def test_active_tor_downlink_down_upstream(
    upper_tor_host, lower_tor_host, send_server_to_t1_with_action,
    toggle_all_simulator_ports_to_upper_tor,
    shutdown_upper_tor_downlink_intfs
):
    """
    Send traffic from server to T1 and shutdown the active ToR downlink on DUT.
    Verify switchover and disruption lasts < 1 second
    """
    send_server_to_t1_with_action(
        upper_tor_host, verify=True, delay=MUX_SIM_ALLOWED_DISRUPTION_SEC,
        allowed_disruption=1, action=shutdown_upper_tor_downlink_intfs
    )
    verify_tor_states(
        expected_active_host=lower_tor_host,
        expected_standby_host=upper_tor_host,
        expected_standby_health='unhealthy'
    )

def test_active_tor_downlink_down_downstream_active(
    upper_tor_host, lower_tor_host, send_t1_to_server_with_action,
    toggle_all_simulator_ports_to_upper_tor,
    shutdown_upper_tor_downlink_intfs
):
    """
    Send traffic from T1 to active ToR and shutdown the active ToR downlink on DUT.
    Verify switchover and disruption lasts < 1 second
    """
    send_t1_to_server_with_action(
        upper_tor_host, verify=True, delay=MUX_SIM_ALLOWED_DISRUPTION_SEC,
        allowed_disruption=1, action=shutdown_upper_tor_downlink_intfs
    )
    verify_tor_states(
        expected_active_host=lower_tor_host,
        expected_standby_host=upper_tor_host,
        expected_standby_health='unhealthy'
    )


def test_active_tor_downlink_down_downstream_standby(
    upper_tor_host, lower_tor_host, send_t1_to_server_with_action,
    toggle_all_simulator_ports_to_upper_tor,
    shutdown_upper_tor_downlink_intfs
):
    """
    Send traffic from T1 to standby ToR and shutdown the active ToR downlink on DUT.
    Verify switchover and disruption lasts < 1 second
    """
    send_t1_to_server_with_action(
        lower_tor_host, verify=True, delay=MUX_SIM_ALLOWED_DISRUPTION_SEC,
        allowed_disruption=1, action=shutdown_upper_tor_downlink_intfs
    )
    verify_tor_states(
        expected_active_host=lower_tor_host,
        expected_standby_host=upper_tor_host,
        expected_standby_health='unhealthy'
    )


def test_standby_tor_downlink_down_upstream(
    upper_tor_host, lower_tor_host, send_server_to_t1_with_action,
    toggle_all_simulator_ports_to_upper_tor,
    shutdown_lower_tor_downlink_intfs
):
    """
    Send traffic from server to T1 and shutdown the standby ToR downlink on DUT.
    Verify no switchover and no disruption
    """
    send_server_to_t1_with_action(
        upper_tor_host, verify=True, delay=MUX_SIM_ALLOWED_DISRUPTION_SEC,
        allowed_disruption=1, action=shutdown_lower_tor_downlink_intfs
    )
    verify_tor_states(
        expected_active_host=upper_tor_host,
        expected_standby_host=lower_tor_host,
        expected_standby_health='unhealthy'
    )


def test_standby_tor_downlink_down_downstream_active(
    upper_tor_host, lower_tor_host, send_t1_to_server_with_action,
    toggle_all_simulator_ports_to_upper_tor,
    shutdown_lower_tor_downlink_intfs
):
    """
    Send traffic from T1 to active ToR and shutdown the standby ToR downlink on DUT.
    Confirm no switchover and no disruption
    """
    send_t1_to_server_with_action(
        upper_tor_host, verify=True, delay=MUX_SIM_ALLOWED_DISRUPTION_SEC,
        allowed_disruption=1, action=shutdown_lower_tor_downlink_intfs
    )
    verify_tor_states(
        expected_active_host=upper_tor_host,
        expected_standby_host=lower_tor_host,
        expected_standby_health='unhealthy'
    )


def test_standby_tor_downlink_down_downstream_standby(
    upper_tor_host, lower_tor_host, send_t1_to_server_with_action,
    toggle_all_simulator_ports_to_upper_tor,
    shutdown_lower_tor_downlink_intfs
):
    """
    Send traffic from T1 to standby ToR and shutdwon the standby ToR downlink on DUT.
    Confirm no switchover and no disruption
    """
    send_t1_to_server_with_action(
        lower_tor_host, verify=True, delay=MUX_SIM_ALLOWED_DISRUPTION_SEC,
        allowed_disruption=1, action=shutdown_lower_tor_downlink_intfs
    )
    verify_tor_states(
        expected_active_host=upper_tor_host,
        expected_standby_host=lower_tor_host,
        expected_standby_health='unhealthy'
    )
