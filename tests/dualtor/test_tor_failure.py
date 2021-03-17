
import pytest 

from tests.common.dualtor.control_plane_utils import verify_tor_states
from tests.common.dualtor.data_plane_utils import send_t1_to_server_with_action, send_server_to_t1_with_action                                  # lgtm[py/unused-import]
from tests.common.dualtor.dual_tor_utils import upper_tor_host, lower_tor_host                                                                  # lgtm[py/unused-import]
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_upper_tor, toggle_all_simulator_ports_to_lower_tor         # lgtm[py/unused-import] 
from tests.common.dualtor.tor_failure_utils import reboot_tor, tor_blackhole_traffic, wait_for_device_reachable                                 # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import run_icmp_responder, run_garp_service, copy_ptftests_directory, change_mac_addresses             # lgtm[py/unused-import]

pytestmark = [
    pytest.mark.topology("dualtor")
]


def test_active_tor_reboot_upstream(
    upper_tor_host, lower_tor_host, send_server_to_t1_with_action,
    toggle_all_simulator_ports_to_upper_tor, reboot_tor,
    wait_for_device_reachable
):
    """
    Send upstream traffic and reboot the active ToR. Confirm switchover
    occurred and disruption lasts < 1 second
    """
    send_server_to_t1_with_action(
        upper_tor_host, verify=True, delay=1,
        action=lambda: reboot_tor(upper_tor_host)
    )
    wait_for_device_reachable(upper_tor_host)
    verify_tor_states(
        expected_active_host=lower_tor_host,
        expected_standby_host=upper_tor_host
    )


def test_active_tor_reboot_downstream_standby(
    upper_tor_host, lower_tor_host, send_t1_to_server_with_action,
    toggle_all_simulator_ports_to_upper_tor, reboot_tor,
    wait_for_device_reachable
):
    """
    Send downstream traffic to the standby ToR and reboot the active ToR.
    Confirm switchover occurred and disruption lasts < 1 second
    """
    send_t1_to_server_with_action(
        lower_tor_host, verify=True, delay=1,
        action=lambda: reboot_tor(upper_tor_host)
    )
    wait_for_device_reachable(upper_tor_host)
    verify_tor_states(
        expected_active_host=lower_tor_host,
        expected_standby_host=upper_tor_host
    )


def test_standby_tor_reboot_upstream(
    upper_tor_host, lower_tor_host, send_server_to_t1_with_action,
    toggle_all_simulator_ports_to_upper_tor, reboot_tor,
    wait_for_device_reachable
):
    """
    Send upstream traffic and reboot the standby ToR. Confirm no switchover
    occurred and no disruption
    """
    send_server_to_t1_with_action(
        upper_tor_host, verify=True,
        action=lambda: reboot_tor(lower_tor_host)
    )
    wait_for_device_reachable(lower_tor_host)
    verify_tor_states(
        expected_active_host=upper_tor_host,
        expected_standby_host=lower_tor_host
    )


def test_standby_tor_reboot_downstream_active(
    upper_tor_host, lower_tor_host, send_t1_to_server_with_action,
    toggle_all_simulator_ports_to_upper_tor, reboot_tor,
    wait_for_device_reachable
):
    """
    Send downstream traffic to the active ToR and reboot the standby ToR.
    Confirm no switchover occurred and no disruption
    """
    send_t1_to_server_with_action(
        upper_tor_host, verify=True,
        action=lambda: reboot_tor(lower_tor_host)
    )
    wait_for_device_reachable(lower_tor_host)
    verify_tor_states(
        expected_active_host=upper_tor_host,
        expected_standby_host=lower_tor_host
    )
