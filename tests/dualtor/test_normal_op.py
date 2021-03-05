import pytest 

from tests.common.config_reload import config_reload
from tests.common.dualtor.control_plane_utils import expect_db_values, APP_DB, STATE_DB
from tests.common.dualtor.data_plane_utils import send_t1_to_server_with_action, send_server_to_t1_with_action                                  # lgtm[py/unused-import]
from tests.common.dualtor.dual_tor_utils import *                                                                                               # lgtm[py/unused-import]
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_upper_tor, toggle_all_simulator_ports_to_lower_tor         # lgtm[py/unused-import] 
from tests.common.fixtures.ptfhost_utils import run_icmp_responder, run_garp_service, copy_ptftests_directory, change_mac_addresses             # lgtm[py/unused-import]

pytestmark = [
    pytest.mark.topology("dualtor")
]

def test_normal_op_upstream(upper_tor_host, lower_tor_host, send_server_to_t1_with_action, toggle_all_simulator_ports_to_upper_tor):
    """Send upstream traffic and confirm no disruption or switchover occurs"""
    send_server_to_t1_with_action(upper_tor_host, standbyhost=lower_tor_host, verify=True)
    expect_db_values(upper_tor_host, APP_DB, 'active')
    expect_db_values(upper_tor_host, STATE_DB, 'active', 'healthy')
    expect_db_values(lower_tor_host, APP_DB, 'standby')
    expect_db_values(lower_tor_host, STATE_DB, 'standby', 'healthy')


def test_normal_op_downstream_active(upper_tor_host, lower_tor_host, send_t1_to_server_with_action, toggle_all_simulator_ports_to_upper_tor):
    """Send downstream traffic to the active ToR and confirm no disruption or switchover occurs"""
    send_t1_to_server_with_action(upper_tor_host, verify=True)
    expect_db_values(upper_tor_host, APP_DB, 'active')
    expect_db_values(upper_tor_host, STATE_DB, 'active', 'healthy')
    expect_db_values(lower_tor_host, APP_DB, 'standby')
    expect_db_values(lower_tor_host, STATE_DB, 'standby', 'healthy')


def test_normal_op_downstream_standby(upper_tor_host, lower_tor_host, send_t1_to_server_with_action, toggle_all_simulator_ports_to_upper_tor):
    """Send downstream traffic to the standby ToR and confirm no disruption or switchover occurs"""
    send_t1_to_server_with_action(lower_tor_host, verify=True)
    expect_db_values(upper_tor_host, APP_DB, 'active')
    expect_db_values(upper_tor_host, STATE_DB, 'active', 'healthy')
    expect_db_values(lower_tor_host, APP_DB, 'standby')
    expect_db_values(lower_tor_host, STATE_DB, 'standby', 'healthy')


def test_active_config_reload_upstream(upper_tor_host, lower_tor_host, send_server_to_t1_with_action, toggle_all_simulator_ports_to_upper_tor):
    """Send upstream traffic and `config reload` the active ToR. Confirm switchover occurs and disruption lasted < 1 second"""
    send_server_to_t1_with_action(upper_tor_host, standbyhost=lower_tor_host, verify=True, delay=1, action=lambda: config_reload(upper_tor_host, wait=0))
    expect_db_values(upper_tor_host, APP_DB, 'standby')
    expect_db_values(upper_tor_host, STATE_DB, 'standby', 'healthy')
    expect_db_values(lower_tor_host, APP_DB, 'active')
    expect_db_values(lower_tor_host, STATE_DB, 'active', 'healthy')


def test_standby_config_reload_upstream(upper_tor_host, lower_tor_host, send_server_to_t1_with_action, toggle_all_simulator_ports_to_upper_tor):
    """Send upstream traffic and `config reload` the standby ToR. Confirm no switchover occurs and no disruption"""
    send_server_to_t1_with_action(upper_tor_host, standbyhost=lower_tor_host, verify=True, delay=1, action=lambda: config_reload(lower_tor_host, wait=0))
    expect_db_values(upper_tor_host, APP_DB, 'active')
    expect_db_values(upper_tor_host, STATE_DB, 'active', 'healthy')
    expect_db_values(lower_tor_host, APP_DB, 'standby')
    expect_db_values(lower_tor_host, STATE_DB, 'standby', 'healthy')


def test_standby_config_reload_downstream_active(upper_tor_host, lower_tor_host, send_t1_to_server_with_action, toggle_all_simulator_ports_to_upper_tor):
    """Send downstream traffic to the active ToR and `config reload` the standby ToR. Confirm no switchover occurs and no disruption"""
    send_t1_to_server_with_action(upper_tor_host, standbyhost=lower_tor_host, verify=True, action=lambda: config_reload(lower_tor_host, wait=0))
    expect_db_values(upper_tor_host, APP_DB, 'active')
    expect_db_values(upper_tor_host, STATE_DB, 'active', 'healthy')
    expect_db_values(lower_tor_host, APP_DB, 'standby')
    expect_db_values(lower_tor_host, STATE_DB, 'standby', 'healthy')


def test_active_config_reload_downstream_standby(upper_tor_host, lower_tor_host, send_t1_to_server_with_action, toggle_all_simulator_ports_to_upper_tor):
    """Send downstream traffic to the standby ToR and `config reload` the active ToR. Confirm no switchover occurs and no disruption"""
    send_t1_to_server_with_action(lower_tor_host, standbyhost=upper_tor_host, verify=True, delay=1, action=lambda: config_reload(upper_tor_host, wait=0))
    expect_db_values(upper_tor_host, APP_DB, 'standby')
    expect_db_values(upper_tor_host, STATE_DB, 'standby', 'healthy')
    expect_db_values(lower_tor_host, APP_DB, 'active')
    expect_db_values(lower_tor_host, STATE_DB, 'active', 'healthy')


def test_tor_switch_upstream(upper_tor_host, lower_tor_host, send_server_to_t1_with_action, toggle_all_simulator_ports_to_upper_tor, force_active_tor):
    """Send upstream traffic and perform switchover via CLI. Confirm switchover occurs and disruption lasts < 1 second"""
    send_server_to_t1_with_action(upper_tor_host, standbyhost=lower_tor_host, verify=True, delay=1, action=lambda: force_active_tor(lower_tor_host, 'all'))
    expect_db_values(upper_tor_host, APP_DB, 'standby')
    expect_db_values(upper_tor_host, STATE_DB, 'standby', 'healthy')
    expect_db_values(lower_tor_host, APP_DB, 'active')
    expect_db_values(lower_tor_host, STATE_DB, 'active', 'healthy')


def test_tor_switch_downstream_active(upper_tor_host, lower_tor_host, send_t1_to_server_with_action, toggle_all_simulator_ports_to_upper_tor, force_active_tor):
    """Send downstream traffic to the active ToR and perform switchover via CLI. Confirm switchover occurs and disruption lasts < 1 second"""
    send_t1_to_server_with_action(upper_tor_host, standbyhost=lower_tor_host, verify=True, delay=1, action=lambda: force_active_tor(lower_tor_host, 'all'))
    expect_db_values(upper_tor_host, APP_DB, 'standby')
    expect_db_values(upper_tor_host, STATE_DB, 'standby', 'healthy')
    expect_db_values(lower_tor_host, APP_DB, 'active')
    expect_db_values(lower_tor_host, STATE_DB, 'active', 'healthy')


def test_tor_switch_downstream_standby(upper_tor_host, lower_tor_host, send_t1_to_server_with_action, toggle_all_simulator_ports_to_upper_tor, force_active_tor):
    """Send downstream traffic to the standby ToR and perform switchover via CLI. Confirm switchover occurs and disruption lasts < 1 second"""
    send_t1_to_server_with_action(lower_tor_host, standbyhost=upper_tor_host, verify=True, delay=1, action=lambda: force_active_tor(lower_tor_host, 'all'))
    expect_db_values(upper_tor_host, APP_DB, 'standby')
    expect_db_values(upper_tor_host, STATE_DB, 'standby', 'healthy')
    expect_db_values(lower_tor_host, APP_DB, 'active')
    expect_db_values(lower_tor_host, STATE_DB, 'active', 'healthy')
