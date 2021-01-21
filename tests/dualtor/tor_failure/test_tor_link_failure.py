def test_active_link_down_upstream(ptf_server_port, t1_lower_tor_port):
    """
    Calls `send_server_to_t1_after_action(ptf_server_port, t1_lower_tor_port, action=shutdown_active_tor_mux_link)`
    Expects `expect_app_db_values(upper_tor, tor_mux_intf, 'unknown')` and `expect_app_db_values(lower_tor, tor_mux_intf, 'active')`
    Expects `expect_state_db_values(upper_tor, tor_mux_intf, 'unknown', 'unhealthy') and `expect_app_db_values(lower_tor, tor_mux_intf, 'active', 'healthy')
    """
    pass

def test_active_link_down_downstream_active(ptf_server_port, t1_upper_tor_port):
    """
    Calls `send_t1_to_server_after_action(ptf_server_port, t1_upper_tor_port, expect_tunnel_packet=True, action=shutdown_active_tor_mux_link)`
    Expects `expect_app_db_values(upper_tor, tor_mux_intf, 'unknown')` and `expect_app_db_values(lower_tor, tor_mux_intf, 'active')`
    Expects `expect_state_db_values(upper_tor, tor_mux_intf, 'unknown', 'unhealthy') and `expect_app_db_values(lower_tor, tor_mux_intf, 'active', 'healthy')
    """
    pass

def test_active_link_down_downstream_standby(ptf_server_port, t1_lower_tor_port):
    """
    Calls `send_t1_to_server_after_action(ptf_server_port, t1_lower_port, action=shutdown_active_tor_mux_link)`
    Expects `expect_app_db_values(upper_tor, tor_mux_intf, 'unknown')` and `expect_app_db_values(lower_tor, tor_mux_intf, 'active')`
    Expects `expect_state_db_values(upper_tor, tor_mux_intf, 'unknown', 'unhealthy') and `expect_app_db_values(lower_tor, tor_mux_intf, 'active', 'healthy')
    """
    pass

def test_standby_link_down_upstream(ptf_server_port, t1_upper_tor_port):
    """
    Calls `send_server_to_t1_after_action(ptf_server_port, t1_upper_tor_port, action=shutdown_standby_tor_mux_link)`
    Expects `expect_app_db_values(upper_tor, tor_mux_intf, 'active')` and `expect_app_db_values(lower_tor, tor_mux_intf, 'unknown')`
    Expects `expect_state_db_values(upper_tor, tor_mux_intf, 'active', 'healthy') and `expect_app_db_values(lower_tor, tor_mux_intf, 'unknown', 'unhealthy')
    """
    pass

def test_standby_link_down_downstream_active(ptf_server_port, t1_upper_tor_port):
    """
    Calls `send_t1_to_server_after_action(ptf_server_port, t1_upper_tor_port, action=shutdown_standby_tor_mux_link)`
    Expects `expect_app_db_values(upper_tor, tor_mux_intf, 'active')` and `expect_app_db_values(lower_tor, tor_mux_intf, 'unknown')`
    Expects `expect_state_db_values(upper_tor, tor_mux_intf, 'active', 'healthy') and `expect_app_db_values(lower_tor, tor_mux_intf, 'unknown', 'unhealthy')
    """
    pass

def test_standby_link_down_downstream_standby(ptf_server_port, t1_lower_tor_port):
    """
    Calls `send_t1_to_server_after_action(ptf_server_port, t1_lower_tor_port, action=shutdown_standby_tor_mux_link)`
    Expects `expect_app_db_values(upper_tor, tor_mux_intf, 'active')` and `expect_app_db_values(lower_tor, tor_mux_intf, 'unknown')`
    Expects `expect_state_db_values(upper_tor, tor_mux_intf, 'active', 'healthy') and `expect_app_db_values(lower_tor, tor_mux_intf, 'unknown', 'unhealthy')
    """
    pass

def test_active_link_drop_upstream(ptf_server_port, t1_lower_tor_port):
    """
    Calls `send_server_to_t1_after_action(ptf_server_port, t1_lower_tor_port, action=drop_active_tor_mux_link)`
    Expects `expect_app_db_values(upper_tor, tor_mux_intf, 'unknown')` and `expect_app_db_values(lower_tor, tor_mux_intf, 'active')`
    Expects `expect_state_db_values(upper_tor, tor_mux_intf, 'unknown', 'unhealthy') and `expect_app_db_values(lower_tor, tor_mux_intf, 'active', 'healthy')
    """
    pass

def test_active_link_drop_downstream_active(ptf_server_port, t1_upper_tor_port):
    """
    Calls `send_t1_to_server_after_action(ptf_server_port, t1_upper_tor_port, expect_tunnel_packet=True, action=drop_active_tor_mux_link)`
    Expects `expect_app_db_values(upper_tor, tor_mux_intf, 'unknown')` and `expect_app_db_values(lower_tor, tor_mux_intf, 'active')`
    Expects `expect_state_db_values(upper_tor, tor_mux_intf, 'unknown', 'unhealthy') and `expect_app_db_values(lower_tor, tor_mux_intf, 'active', 'healthy')
    """
    pass

def test_active_link_drop_downstream_standby(ptf_server_port, t1_lower_tor_port):
    """
    Calls `send_t1_to_server_after_action(ptf_server_port, t1_lower_tor_port, action=drop_active_tor_mux_link)`
    Expects `expect_app_db_values(upper_tor, tor_mux_intf, 'unknown')` and `expect_app_db_values(lower_tor, tor_mux_intf, 'active')`
    Expects `expect_state_db_values(upper_tor, tor_mux_intf, 'unknown', 'unhealthy') and `expect_app_db_values(lower_tor, tor_mux_intf, 'active', 'healthy')
    """
    pass

def test_standby_link_drop_upstream(ptf_server_port, t1_upper_tor_port):
    """
    Calls `send_server_to_t1_after_action(ptf_server_port, t1_upper_tor_port, action=drop_standby_tor_mux_link)`
    Expects `expect_app_db_values(upper_tor, tor_mux_intf, 'active')` and `expect_app_db_values(lower_tor, tor_mux_intf, 'unknown')`
    Expects `expect_state_db_values(upper_tor, tor_mux_intf, 'active', 'healthy') and `expect_app_db_values(lower_tor, tor_mux_intf, 'unknown', 'unhealthy')
    """
    pass

def test_standby_link_drop_downstream_active(ptf_server_port, t1_upper_tor_port):
    """
    Calls `send_t1_to_server_after_action(ptf_server_port, t1_upper_tor_port, action=drop_standby_tor_mux_link)`
    Expects `expect_app_db_values(upper_tor, tor_mux_intf, 'active')` and `expect_app_db_values(lower_tor, tor_mux_intf, 'unknown')`
    Expects `expect_state_db_values(upper_tor, tor_mux_intf, 'active', 'healthy') and `expect_app_db_values(lower_tor, tor_mux_intf, 'unknown', 'unhealthy')
    """
    pass

def test_standby_link_drop_downstream_standby(ptf_server_port, t1_lower_tor_port):
    """
    Calls `send_t1_to_server_after_action(ptf_server_port, t1_lower_tor_port, action=drop_standby_tor_mux_link)`
    Expects `expect_app_db_values(upper_tor, tor_mux_intf, 'active')` and `expect_app_db_values(lower_tor, tor_mux_intf, 'unknown')`
    Expects `expect_state_db_values(upper_tor, tor_mux_intf, 'active', 'healthy') and `expect_app_db_values(lower_tor, tor_mux_intf, 'unknown', 'unhealthy')
    """
    pass