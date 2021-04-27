import pytest

from tests.common.dualtor.control_plane_utils import verify_tor_states
from tests.common.dualtor.data_plane_utils import send_t1_to_server_with_action, send_server_to_t1_with_action                                  # lgtm[py/unused-import]
from tests.common.dualtor.dual_tor_utils import upper_tor_host, lower_tor_host                                                                  # lgtm[py/unused-import]
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_upper_tor, toggle_all_simulator_ports_to_lower_tor         # lgtm[py/unused-import] 
from tests.common.dualtor.tor_failure_utils import kill_bgpd                                                                                    # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import run_icmp_responder, run_garp_service, copy_ptftests_directory, change_mac_addresses             # lgtm[py/unused-import]
from tests.common.dualtor.tunnel_traffic_utils import tunnel_traffic_monitor
from tests.common.dualtor.constants import MUX_SIM_ALLOWED_DISRUPTION_SEC

pytestmark = [
    pytest.mark.topology("dualtor")
]

'''
Below cases are out of scope:
Case: T1 -> Standby ToR -> Server (Standby ToR BGP Down)
Out of scope: taking down the standby ToR's BGP sessions means the T1 will never send traffic to that ToR
Case: T1 -> Active ToR -> Server (Active ToR BGP Down)
Out of scope: taking down the active ToR's BGP sessions means the T1 will never send traffic to that ToR

Remaining cases for bgp shutdown are defined in this module.
'''

def test_active_tor_kill_bgpd_upstream(
    upper_tor_host, lower_tor_host, send_server_to_t1_with_action,
    toggle_all_simulator_ports_to_upper_tor, kill_bgpd):
    '''
    Case: Server -> ToR -> T1 (Active ToR BGP Down)
    Action: Shutdown all BGP sessions on the active ToR
    Expectation:
        Verify packet flow after the active ToR (A) loses BGP sessions
        ToR A DBs indicate active, ToR B DBs indicate standby
        T1 switch receives packet from the initial active ToR (A) and not the standby ToR (B)
        Verify traffic interruption < 1 second
    '''
    send_server_to_t1_with_action(
        upper_tor_host, verify=True, delay=MUX_SIM_ALLOWED_DISRUPTION_SEC,
        action=lambda: kill_bgpd(upper_tor_host)
    )
    verify_tor_states(
        expected_active_host=upper_tor_host,
        expected_standby_host=lower_tor_host
    )


def test_standby_tor_kill_bgpd_upstream(
    upper_tor_host, lower_tor_host, send_server_to_t1_with_action,
    toggle_all_simulator_ports_to_upper_tor, kill_bgpd):
    '''
    Case: Server -> ToR -> T1 (Standby ToR BGP Down)
    Action: Shutdown all BGP sessions on the standby ToR
    Expectation:
        Verify packet flow after the standby ToR (B) loses BGP sessions
        ToR A DBs indicate active, ToR B DBs indicate standby
        T1 switch receives packet from the active ToR (A), and not the standby ToR (B)
    '''
    send_server_to_t1_with_action(
        upper_tor_host, verify=True,
        action=lambda: kill_bgpd(lower_tor_host)
    )
    verify_tor_states(
        expected_active_host=upper_tor_host,
        expected_standby_host=lower_tor_host
    )


def test_standby_tor_kill_bgpd_downstream_active(
    upper_tor_host, lower_tor_host, send_t1_to_server_with_action,
    toggle_all_simulator_ports_to_upper_tor, kill_bgpd,
    tunnel_traffic_monitor):
    '''
    Case: T1 -> Active ToR -> Server (Standby ToR BGP Down)
    Action: Shutdown all BGP sessions on the standby ToR
    Expectation:
        Verify packet flow after the standby ToR (B) loses BGP sessions
        T1 switch receives no IP-in-IP packet; server receives packet
    '''
    with tunnel_traffic_monitor(lower_tor_host, existing=False):
        send_t1_to_server_with_action(
            upper_tor_host, verify=True,
            action=lambda: kill_bgpd(lower_tor_host)
        )
    verify_tor_states(
        expected_active_host=upper_tor_host,
        expected_standby_host=lower_tor_host
    )


def test_active_tor_kill_bgpd_downstream_standby(
    upper_tor_host, lower_tor_host, send_t1_to_server_with_action,
    toggle_all_simulator_ports_to_upper_tor, kill_bgpd,
    tunnel_traffic_monitor):
    '''
    Case: T1 -> Standby ToR -> Server (Active ToR BGP Down)
    Action: Shutdown all BGP sessions on the active ToR
    Expectation:
        Verify packet flow after the active ToR (A) loses BGP sessions
        T1 switch continues to receive IP-in-IP traffic, from lower to upper ToR
        No switchover occurs
        verify traffic interruption is < 1 second
    '''
    with tunnel_traffic_monitor(lower_tor_host, existing=True):
        send_t1_to_server_with_action(
            lower_tor_host, verify=True, delay=MUX_SIM_ALLOWED_DISRUPTION_SEC,
            action=lambda: kill_bgpd(upper_tor_host)
        )
    verify_tor_states(
        expected_active_host=upper_tor_host,
        expected_standby_host=lower_tor_host
    )
