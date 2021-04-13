import pytest

from tests.common.config_reload import config_reload
from tests.common.dualtor.control_plane_utils import verify_tor_states
from tests.common.dualtor.data_plane_utils import send_t1_to_server_with_action, send_server_to_t1_with_action                                  # lgtm[py/unused-import]
from tests.common.dualtor.dual_tor_utils import upper_tor_host, lower_tor_host, force_active_tor                                                # lgtm[py/unused-import]
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_upper_tor, toggle_all_simulator_ports_to_lower_tor         # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import run_icmp_responder, run_garp_service, copy_ptftests_directory, change_mac_addresses             # lgtm[py/unused-import]
from tests.common.dualtor.constants import MUX_SIM_ALLOWED_DISRUPTION_SEC, CONFIG_RELOAD_ALLOWED_DISRUPTION_SEC

pytestmark = [
    pytest.mark.topology("dualtor")
]


def test_normal_op_upstream(upper_tor_host, lower_tor_host,
                            send_server_to_t1_with_action,
                            toggle_all_simulator_ports_to_upper_tor):
    """Send upstream traffic and confirm no disruption or switchover occurs"""
    send_server_to_t1_with_action(upper_tor_host, verify=True, stop_after=60)
    verify_tor_states(expected_active_host=upper_tor_host,
                      expected_standby_host=lower_tor_host)


def test_normal_op_downstream_active(upper_tor_host, lower_tor_host,
                                     send_t1_to_server_with_action,
                                     toggle_all_simulator_ports_to_upper_tor):
    """
    Send downstream traffic to the active ToR and confirm no disruption or
    switchover occurs
    """
    send_t1_to_server_with_action(upper_tor_host, verify=True, stop_after=60)
    verify_tor_states(expected_active_host=upper_tor_host,
                      expected_standby_host=lower_tor_host)


def test_normal_op_downstream_standby(upper_tor_host, lower_tor_host,
                                      send_t1_to_server_with_action,
                                      toggle_all_simulator_ports_to_upper_tor):
    """
    Send downstream traffic to the standby ToR and confirm no disruption or
    switchover occurs
    """
    send_t1_to_server_with_action(lower_tor_host, verify=True)
    verify_tor_states(expected_active_host=upper_tor_host,
                      expected_standby_host=lower_tor_host)


def test_active_config_reload_upstream(upper_tor_host, lower_tor_host,
                                       send_server_to_t1_with_action,
                                       toggle_all_simulator_ports_to_upper_tor):
    """
    Send upstream traffic and `config reload` the active ToR. Confirm
    switchover occurs and disruption lasted < 1 second
    """
    send_server_to_t1_with_action(upper_tor_host, verify=True, delay=CONFIG_RELOAD_ALLOWED_DISRUPTION_SEC,
                                  action=lambda: config_reload(upper_tor_host, wait=0))
    verify_tor_states(expected_active_host=lower_tor_host,
                      expected_standby_host=upper_tor_host)


def test_standby_config_reload_upstream(upper_tor_host, lower_tor_host,
                                        send_server_to_t1_with_action,
                                        toggle_all_simulator_ports_to_upper_tor):
    """
    Send upstream traffic and `config reload` the standby ToR. Confirm no
    switchover occurs and no disruption
    """
    send_server_to_t1_with_action(upper_tor_host, verify=True,
                                  action=lambda: config_reload(lower_tor_host, wait=0))
    verify_tor_states(expected_active_host=upper_tor_host,
                      expected_standby_host=lower_tor_host)


def test_standby_config_reload_downstream_active(upper_tor_host,
                                                 lower_tor_host,
                                                 send_t1_to_server_with_action,
                                                 toggle_all_simulator_ports_to_upper_tor):
    """
    Send downstream traffic to the active ToR and `config reload` the
    standby ToR. Confirm no switchover occurs and no disruption
    """
    send_t1_to_server_with_action(upper_tor_host, verify=True,
                                  action=lambda: config_reload(lower_tor_host, wait=0))
    verify_tor_states(expected_active_host=upper_tor_host,
                      expected_standby_host=lower_tor_host)


def test_active_config_reload_downstream_standby(upper_tor_host,
                                                 lower_tor_host,
                                                 send_t1_to_server_with_action,
                                                 toggle_all_simulator_ports_to_upper_tor):
    """
    Send downstream traffic to the standby ToR and `config reload` the
    active ToR. Confirm switchover occurs and disruption lasts < 1 second
    """
    send_t1_to_server_with_action(lower_tor_host, verify=True, delay=CONFIG_RELOAD_ALLOWED_DISRUPTION_SEC,
                                  action=lambda: config_reload(upper_tor_host, wait=0))
    verify_tor_states(expected_active_host=lower_tor_host,
                      expected_standby_host=upper_tor_host)


def test_tor_switch_upstream(upper_tor_host, lower_tor_host,
                             send_server_to_t1_with_action,
                             toggle_all_simulator_ports_to_upper_tor,
                             force_active_tor):
    """
    Send upstream traffic and perform switchover via CLI. Confirm switchover
    occurs and disruption lasts < 1 second
    """
    send_server_to_t1_with_action(upper_tor_host, verify=True, delay=MUX_SIM_ALLOWED_DISRUPTION_SEC,
                                  action=lambda: force_active_tor(lower_tor_host, 'all'))
    verify_tor_states(expected_active_host=lower_tor_host,
                      expected_standby_host=upper_tor_host)


def test_tor_switch_downstream_active(upper_tor_host, lower_tor_host,
                                      send_t1_to_server_with_action,
                                      toggle_all_simulator_ports_to_upper_tor,
                                      force_active_tor):
    """
    Send downstream traffic to the active ToR and perform switchover via
    CLI. Confirm switchover occurs and disruption lasts < 1 second
    """
    send_t1_to_server_with_action(upper_tor_host, verify=True, delay=MUX_SIM_ALLOWED_DISRUPTION_SEC,
                                  action=lambda: force_active_tor(lower_tor_host, 'all'))
    verify_tor_states(expected_active_host=lower_tor_host,
                      expected_standby_host=upper_tor_host)


def test_tor_switch_downstream_standby(upper_tor_host, lower_tor_host,
                                       send_t1_to_server_with_action,
                                       toggle_all_simulator_ports_to_upper_tor,
                                       force_active_tor):
    """
    Send downstream traffic to the standby ToR and perform switchover via CLI.
    Confirm switchover occurs and disruption lasts < 1 second
    """
    send_t1_to_server_with_action(lower_tor_host, verify=True, delay=MUX_SIM_ALLOWED_DISRUPTION_SEC,
                                  action=lambda: force_active_tor(lower_tor_host, 'all'))
    verify_tor_states(expected_active_host=lower_tor_host,
                      expected_standby_host=upper_tor_host)
