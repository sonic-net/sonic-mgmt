import random

import pytest

from tests.common.dualtor.control_plane_utils import verify_tor_states
from tests.common.dualtor.data_plane_utils import send_t1_to_server_with_action, send_server_to_t1_with_action                                  # lgtm[py/unused-import]
from tests.common.dualtor.dual_tor_utils import upper_tor_host, lower_tor_host                                                                  # lgtm[py/unused-import]
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_upper_tor                                                  # lgtm[py/unused-import]
from tests.common.dualtor.tor_failure_utils import shutdown_tor_heartbeat                                                                       # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import run_icmp_responder, run_garp_service, copy_ptftests_directory, change_mac_addresses             # lgtm[py/unused-import]
from tests.common.dualtor.constants import MUX_SIM_ALLOWED_DISRUPTION_SEC

pytestmark = [
    pytest.mark.topology("dualtor")
]


def test_active_tor_heartbeat_failure_upstream(
    toggle_all_simulator_ports_to_upper_tor,
    upper_tor_host, lower_tor_host, send_server_to_t1_with_action,
    shutdown_tor_heartbeat):
    """
    Send upstream traffic and stop the LinkProber module on the active ToR.
    Confirm switchover and disruption lasts < 1 second.
    """
    send_server_to_t1_with_action(
        upper_tor_host, verify=True, delay=MUX_SIM_ALLOWED_DISRUPTION_SEC,
        action=lambda: shutdown_tor_heartbeat(upper_tor_host)
    )
    verify_tor_states(
        expected_active_host=lower_tor_host,
        expected_standby_host=upper_tor_host
    )


def test_active_tor_heartbeat_failure_downstream_active(
    toggle_all_simulator_ports_to_upper_tor,
    upper_tor_host, lower_tor_host, send_t1_to_server_with_action,
    shutdown_tor_heartbeat):
    """
    Send downstream traffic from T1 to the active ToR and stop the LinkProber module on the active ToR.
    Confirm switchover and disruption lasts < 1 second.
    """
    send_t1_to_server_with_action(
        upper_tor_host, verify=True, delay=MUX_SIM_ALLOWED_DISRUPTION_SEC,
        action=lambda: shutdown_tor_heartbeat(upper_tor_host)
    )
    verify_tor_states(
        expected_active_host=lower_tor_host,
        expected_standby_host=upper_tor_host
    )


def test_active_tor_heartbeat_failure_downstream_standby(
    toggle_all_simulator_ports_to_upper_tor,
    upper_tor_host, lower_tor_host, send_t1_to_server_with_action,
    shutdown_tor_heartbeat):
    """
    Send downstream traffic from T1 to the standby ToR and stop the LinkProber module on the active ToR.
    Confirm switchover and disruption lasts < 1 second.
    """
    send_t1_to_server_with_action(
        lower_tor_host, verify=True, delay=MUX_SIM_ALLOWED_DISRUPTION_SEC,
        action=lambda: shutdown_tor_heartbeat(upper_tor_host)
    )
    verify_tor_states(
        expected_active_host=lower_tor_host,
        expected_standby_host=upper_tor_host
    )


def test_standby_tor_heartbeat_failure_upstream(
    toggle_all_simulator_ports_to_upper_tor,
    upper_tor_host, lower_tor_host, send_server_to_t1_with_action,
    shutdown_tor_heartbeat):
    """
    Send upstream traffic and stop the LinkProber module on the standby ToR.
    Confirm no switchover and no disruption.
    """
    send_server_to_t1_with_action(
        upper_tor_host, verify=True,
        action=lambda: shutdown_tor_heartbeat(lower_tor_host)
    )
    verify_tor_states(
        expected_active_host=upper_tor_host,
        expected_standby_host=lower_tor_host
    )


def test_standby_tor_heartbeat_failure_downstream_active(
    toggle_all_simulator_ports_to_upper_tor,
    upper_tor_host, lower_tor_host, send_t1_to_server_with_action,
    shutdown_tor_heartbeat):
    """
    Send downstream traffic from T1 to the active ToR and stop the LinkProber module on the standby ToR.
    Confirm no switchover and no disruption.
    """
    send_t1_to_server_with_action(
        upper_tor_host, verify=True,
        action=lambda: shutdown_tor_heartbeat(lower_tor_host)
    )
    verify_tor_states(
        expected_active_host=upper_tor_host,
        expected_standby_host=lower_tor_host
    )


def test_standby_tor_heartbeat_failure_downstream_standby(
    toggle_all_simulator_ports_to_upper_tor,
    upper_tor_host, lower_tor_host, send_t1_to_server_with_action,
    shutdown_tor_heartbeat):
    """
    Send downstream traffic from T1 to the standby ToR and stop the LinkProber module on the standby ToR.
    Confirm no switchover and no disruption.
    """
    send_t1_to_server_with_action(
        lower_tor_host, verify=True,
        action=lambda: shutdown_tor_heartbeat(lower_tor_host)
    )
    verify_tor_states(
        expected_active_host=upper_tor_host,
        expected_standby_host=lower_tor_host
    )
