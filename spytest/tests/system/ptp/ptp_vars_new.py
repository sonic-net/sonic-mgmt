from spytest.dicts import SpyTestDict
import re, copy

data = SpyTestDict()

data.skip_traffic = False
data.d1_clx_intf_1_ip = '10.1.1.2'
data.clx_d1_intf_1_ip = '10.1.1.1'
data.d1_clx_intf_1_ip6 = '1001::2'
data.clx_d1_intf_1_ip6 = '1001::1'
data.d1_clx_intf_1_ip_nw = re.sub(r'[0-9]+$','0',data.d1_clx_intf_1_ip)
data.d1_clx_intf_1_ip6_nw = re.sub(r'[0-9]+$','0',data.d1_clx_intf_1_ip6)
data.d1_tg_intf_1_ip = '50.1.1.2'
data.d1_tg_intf_1_ip6 = '5001::2'
data.tg_d1_intf_1_mac = '00:00:00:00:d1:01'
data.tg_d1_intf_1_ip = '50.1.1.100'
data.tg_d1_intf_1_ip6 = '5001::100'

data.d1_d2_intf_1_ip = '10.1.2.1'
data.d2_d1_intf_1_ip = '10.1.2.2'
data.d1_d2_intf_1_ip6 = '1002::1'
data.d2_d1_intf_1_ip6 = '1002::2'
data.d1_d2_intf_1_ip_nw = re.sub(r'[0-9]+$','0',data.d1_d2_intf_1_ip)
data.d1_d2_intf_1_ip6_nw = re.sub(r'[0-9]+$','0',data.d1_d2_intf_1_ip6)


data.d1_d3_intf_1_ip = '10.1.20.1'
data.d3_d1_intf_1_ip = '10.1.20.2'
data.d1_d3_intf_1_ip6 = '1020::1'
data.d3_d1_intf_1_ip6 = '1020::2'
data.d1_d3_intf_1_ip_nw = re.sub(r'[0-9]+$','0',data.d1_d3_intf_1_ip)
data.d1_d3_intf_1_ip6_nw = re.sub(r'[0-9]+$','0',data.d1_d3_intf_1_ip6)

data.d3_d4_intf_1_ip = '10.1.30.1'
data.d4_d3_intf_1_ip = '10.1.30.2'
data.d3_d4_intf_1_ip6 = '1030::1'
data.d4_d3_intf_1_ip6 = '1030::2'
data.d3_d4_intf_1_ip_nw = re.sub(r'[0-9]+$','0',data.d3_d4_intf_1_ip)
data.d3_d4_intf_1_ip6_nw = re.sub(r'[0-9]+$','0',data.d3_d4_intf_1_ip6)

data.d4_d2_intf_1_ip = '10.1.3.2'
data.d2_d4_intf_1_ip = '10.1.3.1'
data.d4_d2_intf_1_ip6 = '1003::2'
data.d2_d4_intf_1_ip6 = '1003::1'
data.d4_d2_intf_1_ip_nw = re.sub(r'[0-9]+$','0',data.d4_d2_intf_1_ip)
data.d4_d2_intf_1_ip6_nw = re.sub(r'[0-9]+$','0',data.d4_d2_intf_1_ip6)

data.d4_clx_intf_1_ip = '10.1.4.2'
data.clx_d4_intf_1_ip = '10.1.4.1'
data.d4_clx_intf_1_ip6 = '1004::2'
data.clx_d4_intf_1_ip6 = '1004::1'
data.d4_clx_intf_1_ip_nw = re.sub(r'[0-9]+$','0',data.d4_clx_intf_1_ip)
data.d4_clx_intf_1_ip6_nw = re.sub(r'[0-9]+$','0',data.d4_clx_intf_1_ip6)
data.d4_tg_intf_1_ip = '50.1.4.2'
data.d4_tg_intf_1_ip6 = '5004::2'
data.tg_d4_intf_1_mac = '00:00:00:00:d4:01'
data.tg_d4_intf_1_ip = '50.1.4.100'
data.tg_d4_intf_1_ip6 = '5004::100'

data.def_ipv4_mask = '24'
data.def_ipv6_mask = '64'

data.tg_traffic_rate = 5000

#BGP parameters.
data.router_id = ['1.1.1.1', '2.2.2.1', '3.3.3.1', '4.4.4.1']
data.as_list = ['100', '200', '300', '400']

data.parent_clock_id = '000000.0000.000001'
data.gm_clock_id = '000000.0000.000001'
data.gm_clock_class = 6
data.gm_clock_accuracy = 32
data.gm_off_scale_log_var = 0
data.gm_priority1 = 1
data.gm_priority2 = 1
data.stats_valid = 'False'

data.mode_bc = 'boundary-clock'
data.mode_tc_e2e = 'end-to-end-transparent-clock'
data.domain_1 = 24
data.domain_profile_1588 = 'ieee1588'
data.nw_transport_ip_mcast = 'UDPv4 multicast'
data.nw_transport_ip6_mcast = 'UDPv6 multicast'
data.nw_transport_ip_ucast = 'UDPv4 unicast'
data.nw_transport_ip6_ucast = 'UDPv6 unicast'
data.priority1 = 255
data.priority2 = 255

data.mode_bc_show = 'BC'
data.mode_tc_e2e_show = 'E2E_TC'

data.role_master = 'master'
data.role_slave = 'slave'
data.role_none = 'none'
data.role_faulty = 'faulty'
data.role_passive = 'passive'


#Calnex Controller 
data.clx_config_file_path = 'C:/calnex/paragon-x/config/'

# Start of S2
data.S2 = {
    'clx_filename': 'calnex-ms-bc-ieee-l2-mc.cst',
    'config_ptp': [
        {'mode': 'boundary-clock', 'domain': 24, 'port_list': []},
        {'mode': 'end-to-end-transparent-clock', 'domain': 24, 'port_list': []},
        {'mode': 'end-to-end-transparent-clock', 'domain': 24, 'port_list': []},
        {'mode': 'boundary-clock', 'domain': 24, 'priority1': 255, 'priority2': 255, 'port_list': []},
    ],
    'disable_ptp': [
        {'mode': 'disable'},
        {'mode': 'disable'},
        {'mode': 'disable'},
        {'mode': 'disable'},
    ],
    'disable_ptp_del_port': [
        {'mode': 'disable', 'port_list': [], 'config': 'del'},
        {'mode': 'disable', 'port_list': [], 'config': 'del'},
        {'mode': 'disable', 'port_list': [], 'config': 'del'},
        {'mode': 'disable', 'port_list': [], 'config': 'del'},
    ],
    'enable_ptp': [
        {'mode': 'boundary-clock'},
        {'mode': 'end-to-end-transparent-clock'},
        {'mode': 'end-to-end-transparent-clock'},
        {'mode': 'boundary-clock'},
    ],
    'verify_ptp': [
        {'mode_list': [data.role_master, data.role_master, data.role_slave], 'port_list': []},
        {'mode_list': [data.role_none, data.role_none], 'port_list': []},
        {'mode_list': [data.role_none, data.role_none], 'port_list': []},
        {'mode_list': [data.role_slave, data.role_passive, data.role_master], 'port_list': []},
    ],
    'verify_ptp_disable': [
        {'mode_list': ['disabled']*3, 'port_list': []},
        {'mode_list': ['disabled']*2, 'port_list': []},
        {'mode_list': ['disabled']*2, 'port_list': []},
        {'mode_list': ['disabled']*3, 'port_list': []},
    ],
    'verify_ptp_clock': [
        {'mode': data.mode_bc_show, 'clock_id': '', 'domain_profile': data.domain_profile_1588, 'domain_number': data.domain_1, 'network_transport': 'L2 multicast', 'priority1': 128, 'priority2': 128, 'two_step': 'Enabled', 'slave_only': 'False', 'number_ports': 3, 'steps_removed': 1},
        {'mode': data.mode_tc_e2e_show, 'domain_profile': data.domain_profile_1588, 'domain_number': data.domain_1, 'network_transport': 'L2 multicast', 'priority1': 128, 'priority2': 128, 'two_step': 'Enabled'},
        {'mode': data.mode_tc_e2e_show, 'domain_profile': data.domain_profile_1588, 'domain_number': data.domain_1, 'network_transport': 'L2 multicast', 'priority1': 128, 'priority2': 128, 'two_step': 'Enabled'},
        {'mode': data.mode_bc_show, 'clock_id': '', 'domain_profile': data.domain_profile_1588, 'domain_number': data.domain_1, 'network_transport': 'L2 multicast', 'priority1': 255, 'priority2': 255, 'two_step': 'Enabled', 'slave_only': 'False', 'number_ports': 3, 'steps_removed': 2},
    ],
    'verify_ptp_parent': [
        {'parent_clock_id': data.parent_clock_id, 'gm_id': data.parent_clock_id, 'gm_clock_class': data.gm_clock_class, 'gm_off_scale_log_var': data.gm_off_scale_log_var, 'gm_clock_accuracy': data.gm_clock_accuracy, 'gm_priority1': data.gm_priority1, 'gm_priority2': data.gm_priority2, 'stats_valid': data.stats_valid},
        {},
        {},
        {'parent_clock_id': '', 'gm_id': data.parent_clock_id, 'gm_clock_class': data.gm_clock_class, 'gm_off_scale_log_var': data.gm_off_scale_log_var, 'gm_clock_accuracy': data.gm_clock_accuracy, 'gm_priority1': data.gm_priority1, 'gm_priority2': data.gm_priority2, 'stats_valid': data.stats_valid},
    ],
    'testcase_id': ['S2', 'FtOpSoRoPTPS2Ft001', 'FtOpSoRoPTPS2Ft002', 'FtOpSoRoPTPS2Ft003', \
                            'FtOpSoRoPTPS2Ft004', 'FtOpSoRoPTPS2Ft005', 'FtOpSoRoPTPS2Ft006'],
    'testcase_summary': ['S2', 'Enable PTP on all devices and verify ports states', \
                                'Flap the slave port of transparent-clock on DUT2', \
                                'Verify PTP with config_reload', \
                                'Disable PTP on all devices and verify ports states', \
                                'Flap the master port of transparent-clock on DUT2', \
                                'Flap the slave port of transparent-clock on DUT2' \
                            ],
}
# End of S2


# Start of S4_S5
data.S4_S5 = {
    'config_ptp': [
        {'mode': 'boundary-clock', 'domain': 24, 'port_list': []},
        {'mode': 'end-to-end-transparent-clock', 'domain': 24, 'port_list': []},
        {},
        {'mode': 'boundary-clock', 'domain': 24, 'priority1': 255, 'priority2': 255, 'port_list': []},
    ],
    'disable_ptp': [
        {'mode': 'disable'},
        {'mode': 'disable'},
        {},
        {'mode': 'disable'},
    ],
    'disable_ptp_del_port': [
        {'mode': 'disable', 'port_list': [], 'config': 'del'},
        {'mode': 'disable', 'port_list': [], 'config': 'del'},
        {},
        {'mode': 'disable', 'port_list': [], 'config': 'del'},
    ],
    'enable_ptp': [
        {'mode': 'boundary-clock'},
        {'mode': 'end-to-end-transparent-clock'},
        {},
        {'mode': 'boundary-clock'},
    ],
    'verify_ptp': [
        {'mode_list': [data.role_master, data.role_slave], 'port_list': []},
        {'mode_list': [data.role_none, data.role_none], 'port_list': []},
        {},
        {'mode_list': [data.role_slave, data.role_master], 'port_list': []},
    ],
    'verify_ptp_disable': [
        {'mode_list': ['disabled']*2, 'port_list': []},
        {'mode_list': ['disabled']*2, 'port_list': []},
        {},
        {'mode_list': ['disabled']*2, 'port_list': []},
    ],
    'verify_ptp_clock': [
        {'mode': data.mode_bc_show, 'clock_id': '', 'domain_profile': data.domain_profile_1588, 'domain_number': data.domain_1, 'priority1': 128, 'priority2': 128, 'two_step': 'Enabled', 'slave_only': 'False', 'number_ports': 2, 'steps_removed': 1},
        {'mode': data.mode_tc_e2e_show, 'domain_profile': data.domain_profile_1588, 'domain_number': data.domain_1, 'priority1': 128, 'priority2': 128, 'two_step': 'Enabled'},
        {},
        {'mode': data.mode_bc_show, 'clock_id': '', 'domain_profile': data.domain_profile_1588, 'domain_number': data.domain_1, 'priority1': 255, 'priority2': 255, 'two_step': 'Enabled', 'slave_only': 'False', 'number_ports': 2, 'steps_removed': 2},
    ],
    'verify_ptp_parent': [
        {'parent_clock_id': data.parent_clock_id, 'gm_id': data.parent_clock_id, 'gm_clock_class': data.gm_clock_class, 'gm_off_scale_log_var': data.gm_off_scale_log_var, 'gm_clock_accuracy': data.gm_clock_accuracy, 'gm_priority1': data.gm_priority1, 'gm_priority2': data.gm_priority2, 'stats_valid': data.stats_valid},
        {},
        {},
        {'parent_clock_id': '', 'gm_id': data.parent_clock_id, 'gm_clock_class': data.gm_clock_class, 'gm_off_scale_log_var': data.gm_off_scale_log_var, 'gm_clock_accuracy': data.gm_clock_accuracy, 'gm_priority1': data.gm_priority1, 'gm_priority2': data.gm_priority2, 'stats_valid': data.stats_valid},
    ],
}
# End of S4_S5


# Start of S4
data.S4 = {
    'dut_list': [0, 1, 3],
    'clx_filename': 'calnex-ms-bc-ieee-ipv4-mc.cst',
    'config_ptp': copy.deepcopy(data['S4_S5']['config_ptp']),
    'disable_ptp': copy.deepcopy(data['S4_S5']['disable_ptp']),
    'disable_ptp_del_port': copy.deepcopy(data['S4_S5']['disable_ptp_del_port']),
    'enable_ptp': copy.deepcopy(data['S4_S5']['enable_ptp']),
    'verify_ptp': copy.deepcopy(data['S4_S5']['verify_ptp']), 
    'verify_ptp_disable': copy.deepcopy(data['S4_S5']['verify_ptp_disable']), 
    'verify_ptp_clock': copy.deepcopy(data['S4_S5']['verify_ptp_clock']),
    'verify_ptp_parent': copy.deepcopy(data['S4_S5']['verify_ptp_parent']),
    'testcase_id': ['S4', 'FtOpSoRoPTPS4Ft001', 'FtOpSoRoPTPS4Ft002', 'FtOpSoRoPTPS4Ft003', \
                          'FtOpSoRoPTPS4Ft004', 'FtOpSoRoPTPS4Ft005'],
    'testcase_summary': ['S4', 'Enable PTP on all devices and verify ports states', \
                                'Flap the slave port of transparent-clock on DUT2', \
                                'Verify PTP with config_reload', \
                                'Disable PTP on all devices and verify ports states', \
                                'Flap the master port of transparent-clock on DUT2' \
                            ],
}

for i in data['S4']['dut_list']: 
    data['S4']['config_ptp'][i]['network_transport'] = 'ipv4 multicast'
    data['S4']['verify_ptp_clock'][i]['network_transport'] = data.nw_transport_ip_mcast

# End of S4

# Start of S5
data.S5 = {
    'dut_list': [0, 1, 3],
    'clx_filename': 'calnex-ms-bc-ieee-ipv6-mc.cst',
    'config_ptp': copy.deepcopy(data['S4_S5']['config_ptp']),
    'disable_ptp': copy.deepcopy(data['S4_S5']['disable_ptp']),
    'disable_ptp_del_port': copy.deepcopy(data['S4_S5']['disable_ptp_del_port']),
    'enable_ptp': copy.deepcopy(data['S4_S5']['enable_ptp']),
    'verify_ptp': copy.deepcopy(data['S4_S5']['verify_ptp']), 
    'verify_ptp_disable': copy.deepcopy(data['S4_S5']['verify_ptp_disable']), 
    'verify_ptp_clock': copy.deepcopy(data['S4_S5']['verify_ptp_clock']),
    'verify_ptp_parent': copy.deepcopy(data['S4_S5']['verify_ptp_parent']),
    'testcase_id': ['S5', 'FtOpSoRoPTPS5Ft001', 'FtOpSoRoPTPS5Ft002', 'FtOpSoRoPTPS5Ft003', 'FtOpSoRoPTPS5Ft004', \
                          'FtOpSoRoPTPS5Ft005', 'FtOpSoRoPTPS5Ft006', 'FtOpSoRoPTPS5Ft007'],
    'testcase_summary': ['S5', 'Enable PTP on all devices and verify ports states', \
                                'Flap the slave port of boundary-clock on DUT1', \
                                'Flap the master port of boundary-clock on DUT4', \
                                'Verify PTP with config_reload', \
                                'Disable PTP on all devices and verify ports states', \
                                'Flap the master port of transparent-clock on DUT2', \
                                'Flap the slave port of transparent-clock on DUT2' \
                            ],
}

for i in data['S5']['dut_list']: 
    data['S5']['config_ptp'][i]['network_transport'] = 'ipv6 multicast'
    data['S5']['verify_ptp_clock'][i]['network_transport'] = data.nw_transport_ip6_mcast

# End of S5




data.S3_S6 = {
    'config_ptp': [
        {'mode': 'boundary-clock', 'domain': 24, 'network_transport': 'ipv4 unicast', 'port_list': [], 'master_table_intf_list': [], 'master_table_addr_list': [data.clx_d1_intf_1_ip, data.d2_d1_intf_1_ip, data.d3_d1_intf_1_ip]},
        {'mode': 'boundary-clock', 'domain': 24, 'network_transport': 'ipv4 unicast', 'priority1': 200, 'priority2': 200, 'port_list': [], 'master_table_intf_list': [], 'master_table_addr_list': [data.d1_d2_intf_1_ip, data.d4_d2_intf_1_ip]},
        {'mode': 'boundary-clock', 'domain': 24, 'network_transport': 'ipv4 unicast', 'priority1': 220, 'priority2': 220, 'port_list': [], 'master_table_intf_list': [], 'master_table_addr_list': [data.d1_d3_intf_1_ip, data.d4_d3_intf_1_ip]},
        {'mode': 'boundary-clock', 'domain': 24, 'network_transport': 'ipv4 unicast', 'priority1': 255, 'priority2': 255, 'port_list': [], 'master_table_intf_list': [], 'master_table_addr_list': [data.d2_d4_intf_1_ip, data.d3_d4_intf_1_ip, data.clx_d4_intf_1_ip]},
    ],
    'disable_ptp': [
        {'mode': 'disable'},
        {'mode': 'disable'},
        {'mode': 'disable'},
        {'mode': 'disable'},
    ],
    'disable_ptp_del_port': [
        {'mode': 'disable', 'port_list': [], 'config': 'del'},
        {'mode': 'disable', 'port_list': [], 'config': 'del'},
        {'mode': 'disable', 'port_list': [], 'config': 'del'},
        {'mode': 'disable', 'port_list': [], 'config': 'del'},
    ],
    'enable_ptp': [
        {'mode': 'boundary-clock'},
        {'mode': 'boundary-clock'},
        {'mode': 'boundary-clock'},
        {'mode': 'boundary-clock'},
    ],
    'verify_ptp': [
        {'mode_list': [data.role_master, data.role_master, data.role_slave], 'port_list': []},
        {'mode_list': [data.role_slave, data.role_master], 'port_list': []},
        {'mode_list': [data.role_slave, data.role_master], 'port_list': []},
        {'mode_list': [data.role_slave, data.role_passive, data.role_master], 'port_list': []},
    ],
    'verify_ptp_disable': [
        {'mode_list': ['disabled']*3, 'port_list': []},
        {'mode_list': ['disabled']*2, 'port_list': []},
        {'mode_list': ['disabled']*2, 'port_list': []},
        {'mode_list': ['disabled']*3, 'port_list': []},
    ],
    'verify_ptp_clock': [
        {'mode': data.mode_bc_show, 'clock_id': '', 'domain_profile': data.domain_profile_1588, 'domain_number': data.domain_1, 'network_transport': data.nw_transport_ip_ucast, 'priority1': 128, 'priority2': 128, 'two_step': 'Enabled', 'slave_only': 'False', 'number_ports': 3, 'steps_removed': 1},
        {'mode': data.mode_bc_show, 'clock_id': '', 'domain_profile': data.domain_profile_1588, 'domain_number': data.domain_1, 'network_transport': data.nw_transport_ip_ucast, 'priority1': 200, 'priority2': 200, 'two_step': 'Enabled', 'slave_only': 'False', 'number_ports': 2, 'steps_removed': 2},
        {'mode': data.mode_bc_show, 'clock_id': '', 'domain_profile': data.domain_profile_1588, 'domain_number': data.domain_1, 'network_transport': data.nw_transport_ip_ucast, 'priority1': 220, 'priority2': 220, 'two_step': 'Enabled', 'slave_only': 'False', 'number_ports': 2, 'steps_removed': 2},
        {'mode': data.mode_bc_show, 'clock_id': '', 'domain_profile': data.domain_profile_1588, 'domain_number': data.domain_1, 'network_transport': data.nw_transport_ip_ucast, 'priority1': 255, 'priority2': 255, 'two_step': 'Enabled', 'slave_only': 'False', 'number_ports': 3, 'steps_removed': 3},
    ],
    'verify_ptp_parent': [
        {'parent_clock_id': data.parent_clock_id, 'gm_id': data.parent_clock_id, 'gm_clock_class': data.gm_clock_class, 'gm_off_scale_log_var': data.gm_off_scale_log_var, 'gm_clock_accuracy': data.gm_clock_accuracy, 'gm_priority1': data.gm_priority1, 'gm_priority2': data.gm_priority2, 'stats_valid': data.stats_valid},
        {'parent_clock_id': '', 'gm_id': data.parent_clock_id, 'gm_clock_class': data.gm_clock_class, 'gm_off_scale_log_var': data.gm_off_scale_log_var, 'gm_clock_accuracy': data.gm_clock_accuracy, 'gm_priority1': data.gm_priority1, 'gm_priority2': data.gm_priority2, 'stats_valid': data.stats_valid},
        {'parent_clock_id': '', 'gm_id': data.parent_clock_id, 'gm_clock_class': data.gm_clock_class, 'gm_off_scale_log_var': data.gm_off_scale_log_var, 'gm_clock_accuracy': data.gm_clock_accuracy, 'gm_priority1': data.gm_priority1, 'gm_priority2': data.gm_priority2, 'stats_valid': data.stats_valid},
        {'parent_clock_id': '', 'gm_id': data.parent_clock_id, 'gm_clock_class': data.gm_clock_class, 'gm_off_scale_log_var': data.gm_off_scale_log_var, 'gm_clock_accuracy': data.gm_clock_accuracy, 'gm_priority1': data.gm_priority1, 'gm_priority2': data.gm_priority2, 'stats_valid': data.stats_valid},
    ],
} #End of S3_S6
        



# Start of S3
data.S3 = {
    'dut_list': [0, 1, 2, 3],
    'clx_filename': 'calnex-ms-bc-ieee-ipv4-uc-OLD.cst',
    'config_ptp': copy.deepcopy(data['S3_S6']['config_ptp']),
    'disable_ptp': copy.deepcopy(data['S3_S6']['disable_ptp']),
    'disable_ptp_del_port': copy.deepcopy(data['S3_S6']['disable_ptp_del_port']),
    'enable_ptp': copy.deepcopy(data['S3_S6']['enable_ptp']),
    'verify_ptp': copy.deepcopy(data['S3_S6']['verify_ptp']), 
    'verify_ptp_disable': copy.deepcopy(data['S3_S6']['verify_ptp_disable']), 
    'verify_ptp_clock': copy.deepcopy(data['S3_S6']['verify_ptp_clock']),
    'verify_ptp_parent': copy.deepcopy(data['S3_S6']['verify_ptp_parent']),
    'testcase_id': ['S3', 'FtOpSoRoPTPS3Ft001', 'FtOpSoRoPTPS3Ft002', 'FtOpSoRoPTPS3Ft003', 'FtOpSoRoPTPS3Ft004', \
                          'FtOpSoRoPTPS3Ft005', 'FtOpSoRoPTPS3Ft006', 'FtOpSoRoPTPS3Ft007'],
    'testcase_summary': ['S3', 'Enable PTP on all devices and verify ports states', \
                                'Flap the slave port of boundary-clock on DUT2', \
                                'Flap the master port of boundary-clock on DUT4', \
                                'Verify PTP with config_reload', \
                                'Disable PTP on all devices and verify ports states', \
                                'Flap the master port of boundary-clock on DUT1', \
                                'Flap the slave port of boundary-clock on DUT1' \
                            ],
}

for i in data['S3']['dut_list']: 
    data['S3']['config_ptp'][i]['announce_timeout'] = 20

# End of S3


# Start of S6
data.S6 = {
    'dut_list': [0, 1, 2, 3],
    'clx_filename': 'calnex-ms-bc-g8275-2-ipv4-uc-OLD.cst',
    'config_ptp': copy.deepcopy(data['S3_S6']['config_ptp']),
    'disable_ptp': copy.deepcopy(data['S3_S6']['disable_ptp']),
    'disable_ptp_del_port': copy.deepcopy(data['S3_S6']['disable_ptp_del_port']),
    'enable_ptp': copy.deepcopy(data['S3_S6']['enable_ptp']),
    'verify_ptp': copy.deepcopy(data['S3_S6']['verify_ptp']), 
    'verify_ptp_disable': copy.deepcopy(data['S3_S6']['verify_ptp_disable']), 
    'verify_ptp_clock': copy.deepcopy(data['S3_S6']['verify_ptp_clock']),
    'verify_ptp_parent': copy.deepcopy(data['S3_S6']['verify_ptp_parent']),
    'testcase_id': ['S6', 'FtOpSoRoPTPS6Ft001', 'FtOpSoRoPTPS6Ft002', 'FtOpSoRoPTPS6Ft003', 'FtOpSoRoPTPS6Ft004', 'FtOpSoRoPTPS6Ft005', \
                          'FtOpSoRoPTPS6Ft006', 'FtOpSoRoPTPS6Ft007', 'FtOpSoRoPTPS6Ft008', 'FtOpSoRoPTPS6Ft009'],
    'testcase_summary': ['S6', 'Enable PTP on all devices and verify ports states', \
                                'Flap the master port of boundary-clock on DUT1', \
                                'Flap the slave port of boundary-clock on DUT2', \
                                'Verify PTP with config_reload', \
                                'Disable PTP on all devices and verify ports states', \
                                'Flap the master port of boundary on DUT4', \
                                'Flap the slave port of boundary-clock on DUT4', \
                                'Verify PTP with warm reboot', \
                                'Verify PTP with cold reboot' \
                            ],
}

for i in data['S6']['dut_list']: 
    data['S6']['config_ptp'][i]['domain'] = 44
    data['S6']['config_ptp'][i]['domain_profile'] = 'g8275.2'
    data['S6']['config_ptp'][i]['announce_timeout'] = 20
    data['S6']['verify_ptp_clock'][i]['domain_number'] = 44
    data['S6']['verify_ptp_clock'][i]['domain_profile'] = 'G.8275.x'
    data['S6']['verify_ptp_parent'][i]['gm_off_scale_log_var'] = 20061
    data['S6']['verify_ptp_parent'][i]['gm_clock_accuracy'] = 33

# End of S6


# Start of S1
data.S1 = {
    'dut_list': [0, 1, 2, 3],
    'clx_filename': 'calnex-ms-bc-ieee-l2-uc.cst',
    'config_ptp': copy.deepcopy(data['S3_S6']['config_ptp']),
    'disable_ptp': copy.deepcopy(data['S3_S6']['disable_ptp']),
    'disable_ptp_del_port': copy.deepcopy(data['S3_S6']['disable_ptp_del_port']),
    'enable_ptp': copy.deepcopy(data['S3_S6']['enable_ptp']),
    'verify_ptp': copy.deepcopy(data['S3_S6']['verify_ptp']),
    'verify_ptp_disable': copy.deepcopy(data['S3_S6']['verify_ptp_disable']),
    'verify_ptp_clock': copy.deepcopy(data['S3_S6']['verify_ptp_clock']),
    'verify_ptp_parent': copy.deepcopy(data['S3_S6']['verify_ptp_parent']),
    'testcase_id': ['S1', 'FtOpSoRoPTPS1Ft001', 'FtOpSoRoPTPS1Ft002', 'FtOpSoRoPTPS1Ft003', \
                            'FtOpSoRoPTPS1Ft004', 'FtOpSoRoPTPS1Ft005', 'FtOpSoRoPTPS1Ft006'],
    'testcase_summary': ['S1', 'Enable PTP on all devices and verify ports states', \
                                'Flap the slave port of boundary-clock on DUT1', \
                                'Flap the slave port of boundary-clock on DUT2', \
                                'Verify PTP with config_reload', \
                                'Disable PTP on all devices and verify ports states', \
                                'Flap the master port of boundary-clock on DUT4' \
                            ],
}

for i in data['S1']['dut_list']:
    data['S1']['config_ptp'][i]['network_transport'] = 'l2 unicast'
    data['S1']['verify_ptp_clock'][i]['network_transport'] = 'L2 unicast'

# End of S1

