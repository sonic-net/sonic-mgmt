import pytest

from tests.common.config_reload import config_reload
from tests.common.dualtor.control_plane_utils import verify_tor_states
from tests.common.dualtor.data_plane_utils import send_t1_to_server_with_action, send_server_to_t1_with_action
from tests.common.dualtor.dual_tor_common import cable_type
from tests.common.dualtor.dual_tor_common import CableType
from tests.common.dualtor.dual_tor_utils import upper_tor_host, lower_tor_host, force_active_tor, force_standby_tor
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_upper_tor
from tests.common.dualtor.nic_simulator_control import toggle_active_all_ports_both_tors
from tests.common.fixtures.ptfhost_utils import run_icmp_responder, run_garp_service, copy_ptftests_directory, change_mac_addresses
from tests.common.dualtor.constants import MUX_SIM_ALLOWED_DISRUPTION_SEC, CONFIG_RELOAD_ALLOWED_DISRUPTION_SEC


pytestmark = [
    pytest.mark.topology("dualtor")
]


@pytest.mark.enable_active_active
def test_normal_op_upstream(upper_tor_host, lower_tor_host,
                            send_server_to_t1_with_action,
                            toggle_all_simulator_ports_to_upper_tor,
                            toggle_active_all_ports_both_tors,
                            cable_type):
    """Send upstream traffic and confirm no disruption or switchover occurs"""
    if cable_type == CableType.active_standby:
        send_server_to_t1_with_action(upper_tor_host, verify=True, stop_after=60)
        verify_tor_states(expected_active_host=upper_tor_host,
                          expected_standby_host=lower_tor_host)

    if cable_type == CableType.active_active:
        send_server_to_t1_with_action(upper_tor_host, verify=True, stop_after=60)
        verify_tor_states(expected_active_host=[upper_tor_host, lower_tor_host],
                          expected_standby_host=None,
                          cable_type=cable_type)


def test_normal_op_downstream_upper_tor(upper_tor_host, lower_tor_host,
                                     send_t1_to_server_with_action,
                                     toggle_all_simulator_ports_to_upper_tor,
                                     toggle_active_all_ports_both_tors,
                                     cable_type):
    """
    Send downstream traffic to the upper ToR and confirm no disruption or
    switchover occurs
    """
    if cable_type == CableType.active_standby:
        send_t1_to_server_with_action(upper_tor_host, verify=True, stop_after=60)
        verify_tor_states(expected_active_host=upper_tor_host,
                      expected_standby_host=lower_tor_host)

    if cable_type == CableType.active_active:
        send_t1_to_server_with_action(upper_tor_host, verify=True, stop_after=60)
        verify_tor_states(expected_active_host=[upper_tor_host, lower_tor_host],
                            expected_standby_host=None,
                            cable_type=cable_type)


def test_normal_op_downstream_lower_tor(upper_tor_host, lower_tor_host,
                                      send_t1_to_server_with_action,
                                      toggle_all_simulator_ports_to_upper_tor,
                                      toggle_active_all_ports_both_tors,
                                      cable_type):
    """
    Send downstream traffic to the lower ToR and confirm no disruption or
    switchover occurs
    """
    if cable_type == CableType.active_standby:
        send_t1_to_server_with_action(lower_tor_host, verify=True, stop_after=60)
        verify_tor_states(expected_active_host=upper_tor_host,
                      expected_standby_host=lower_tor_host)

    if cable_type == CableType.active_active:
        send_t1_to_server_with_action(lower_tor_host, verify=True, stop_after=60)
        verify_tor_states(expected_active_host=[upper_tor_host, lower_tor_host],
                            expected_standby_host=None,
                            cable_type=cable_type)


@pytest.mark.disable_loganalyzer
def test_upper_tor_config_reload_upstream(upper_tor_host, lower_tor_host,
                                       send_server_to_t1_with_action,
                                       toggle_all_simulator_ports_to_upper_tor,
                                       toggle_active_all_ports_both_tors,
                                       cable_type):
    """
    Send upstream traffic and `config reload` the active ToR. 
    Confirm switchover occurs and disruption lasted < 1 second for active-standby ports.
    Confirm both ToRs in active after config reload and no disruption for active-active ports.
    """
    if cable_type == CableType.active_standby:
        send_server_to_t1_with_action(upper_tor_host, verify=True, delay=CONFIG_RELOAD_ALLOWED_DISRUPTION_SEC,
                                    action=lambda: config_reload(upper_tor_host, wait=0))
        verify_tor_states(expected_active_host=lower_tor_host,
                      expected_standby_host=upper_tor_host)
    
    if cable_type == CableType.active_active:
        send_server_to_t1_with_action(upper_tor_host, verify=True,
                                    action=lambda: config_reload(upper_tor_host, wait=0))
        verify_tor_states(expected_active_host=[upper_tor_host, lower_tor_host],
                            expected_standby_host=None,
                            cable_type=cable_type)


@pytest.mark.disable_loganalyzer
def test_lower_tor_config_reload_upstream(upper_tor_host, lower_tor_host,
                                        send_server_to_t1_with_action,
                                        toggle_all_simulator_ports_to_upper_tor,
                                        toggle_active_all_ports_both_tors,
                                        cable_type):
    """
    Send upstream traffic and `config reload` the lower ToR. 
    Confirm no switchover occurs and no disruption.
    """
    if cable_type == CableType.active_standby:
        send_server_to_t1_with_action(upper_tor_host, verify=True,
                                    action=lambda: config_reload(lower_tor_host, wait=0))
        verify_tor_states(expected_active_host=upper_tor_host,
                        expected_standby_host=lower_tor_host)

    if cable_type == CableType.active_active:
        send_server_to_t1_with_action(upper_tor_host, verify=True,
                                    action=lambda: config_reload(lower_tor_host, wait=0))
        verify_tor_states(expected_active_host=[upper_tor_host, lower_tor_host],
                            expected_standby_host=None,
                            cable_type=cable_type)


@pytest.mark.disable_loganalyzer
def test_lower_tor_config_reload_downstream_upper_tor(upper_tor_host,
                                                 lower_tor_host,
                                                 send_t1_to_server_with_action,
                                                 toggle_all_simulator_ports_to_upper_tor,
                                                 toggle_active_all_ports_both_tors,
                                                 cable_type):
    """
    Send downstream traffic to the upper ToR and `config reload` the lower ToR. 
    Confirm no switchover occurs and no disruption
    """
    if cable_type == CableType.active_standby:
        send_t1_to_server_with_action(upper_tor_host, verify=True,
                                    action=lambda: config_reload(lower_tor_host, wait=0))
        verify_tor_states(expected_active_host=upper_tor_host,
                        expected_standby_host=lower_tor_host)

    if cable_type == CableType.active_active:
        send_t1_to_server_with_action(upper_tor_host, verify=True,
                                    action=lambda: config_reload(lower_tor_host, wait=0))
        verify_tor_states(expected_active_host=[upper_tor_host, lower_tor_host],
                            expected_standby_host=None,
                            cable_type=cable_type)


@pytest.mark.disable_loganalyzer
def test_upper_tor_config_reload_downstream_lower_tor(upper_tor_host,
                                                 lower_tor_host,
                                                 send_t1_to_server_with_action,
                                                 toggle_all_simulator_ports_to_upper_tor,
                                                 toggle_active_all_ports_both_tors,
                                                 cable_type):
    """
    Send downstream traffic to the lower ToR and `config reload` the upper ToR. 
    Confirm switchover occurs and disruption lasts < 1 second for active-standby ports. 
    Confirm no state change in the end and no disruption for active-active ports.
    """
    if cable_type == CableType.active_standby:
        send_t1_to_server_with_action(lower_tor_host, verify=True, delay=CONFIG_RELOAD_ALLOWED_DISRUPTION_SEC,
                                    action=lambda: config_reload(upper_tor_host, wait=0))
        verify_tor_states(expected_active_host=lower_tor_host,
                        expected_standby_host=upper_tor_host)

    if cable_type == CableType.active_active:
        send_t1_to_server_with_action(lower_tor_host, verify=True,
                                    action=lambda: config_reload(upper_tor_host, wait=0))
        verify_tor_states(expected_active_host=[upper_tor_host, lower_tor_host],
                            expected_standby_host=None,
                            cable_type=cable_type)


def test_tor_switch_upstream(upper_tor_host, lower_tor_host,
                             send_server_to_t1_with_action,
                             toggle_all_simulator_ports_to_upper_tor,
                             force_active_tor,
                             toggle_active_all_ports_both_tors,
                             force_standby_tor,
                             cable_type):
    """
    Send upstream traffic and perform switchover via CLI. 
    Confirm switchover occurs and disruption lasts < 1 second for active-standby ports.
    Confirm switchover occurs and no disruption for active-active ports.
    """
    if cable_type == CableType.active_standby:
        send_server_to_t1_with_action(upper_tor_host, verify=True, delay=MUX_SIM_ALLOWED_DISRUPTION_SEC,
                                    action=lambda: force_active_tor(lower_tor_host, 'all'))
        verify_tor_states(expected_active_host=lower_tor_host,
                        expected_standby_host=upper_tor_host)
    
    if cable_type == CableType.active_active:
        send_server_to_t1_with_action(upper_tor_host, verify=True,
                                    action=lambda: force_standby_tor(upper_tor_host, 'all'))
        verify_tor_states(expected_active_host=lower_tor_host,
                            expected_standby_host=upper_tor_host,
                            cable_type=cable_type)


def test_tor_switch_downstream_active(upper_tor_host, lower_tor_host,
                                      send_t1_to_server_with_action,
                                      toggle_all_simulator_ports_to_upper_tor,
                                      force_active_tor,
                                      toggle_active_all_ports_both_tors,
                                      force_standby_tor,
                                      cable_type):
    """
    Send downstream traffic to the upper ToR and perform switchover via CLI. 
    Confirm switchover occurs and disruption lasts < 1 second for active-standby ports.
    Confirm switchover occurs and disruption lasts < 1 second for active-active ports.
    """
    if cable_type == CableType.active_standby:
        send_t1_to_server_with_action(upper_tor_host, verify=True, delay=MUX_SIM_ALLOWED_DISRUPTION_SEC,
                                    action=lambda: force_active_tor(lower_tor_host, 'all'))
        verify_tor_states(expected_active_host=lower_tor_host,
                        expected_standby_host=upper_tor_host)

    if cable_type == CableType.active_active:
        send_t1_to_server_with_action(upper_tor_host, verify=True, delay=MUX_SIM_ALLOWED_DISRUPTION_SEC,
                                    action=lambda: force_standby_tor(upper_tor_host, 'all'))
        verify_tor_states(expected_active_host=lower_tor_host,
                            expected_standby_host=upper_tor_host,
                            cable_type=cable_type)


def test_tor_switch_downstream_standby(upper_tor_host, lower_tor_host,
                                       send_t1_to_server_with_action,
                                       toggle_all_simulator_ports_to_upper_tor,
                                       force_active_tor,
                                       toggle_active_all_ports_both_tors,
                                       force_standby_tor,
                                       cable_type):
    """
    Send downstream traffic to the lower ToR and perform switchover via CLI.
    Confirm switchover occurs and disruption lasts < 1 second for active-standby ports.
    Confirm switchover occurs and no disruption for active-active ports.
    """
    if cable_type == CableType.active_standby:
        send_t1_to_server_with_action(lower_tor_host, verify=True, delay=MUX_SIM_ALLOWED_DISRUPTION_SEC,
                                    action=lambda: force_active_tor(lower_tor_host, 'all'))
        verify_tor_states(expected_active_host=lower_tor_host,
                        expected_standby_host=upper_tor_host)
                        
    if cable_type == CableType.active_active:
        send_t1_to_server_with_action(lower_tor_host, verify=True,
                                    action=lambda: force_standby_tor(upper_tor_host, 'all'))
        verify_tor_states(expected_active_host=lower_tor_host,
                            expected_standby_host=upper_tor_host,
                            cable_type=cable_type)
