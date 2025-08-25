import os
import yaml
import pytest
from spytest import st, tgapi, SpyTestDict
import tests.cisco.tortuga.common.tortuga_common_utils as common_obj
import json
import paramiko
from scp import SCPClient
from apis.system.reboot import config_save_reboot, config_save_reload
import ars_common_utils

ACL_JSON_FILE = "ars_acl.json"
ACL_JSON_FILE_PATH = os.path.dirname(os.path.realpath(__file__)) +  '/' + ACL_JSON_FILE

# Tgen config
data = SpyTestDict()
data.t1d1_ipv6_addr = "2001:200:1::2" #source IPv6
data.t1d1_ip_addr = "200.200.1.2" #source IPv4
data.t1d1_mac_addr = "00:0A:03:00:11:01" #source Mac
data.t1d2_ipv6_addr = "2001:100:1::2"
data.t1d2_ip_addr = "200.100.1.2"
data.t1d2_mac_addr = "00:0A:04:00:12:01"
data.t1d1_ipv6_gateway = "2001:200:1::1" #source Gateway ipv6
data.t1d2_ipv6_gateway = "2001:100:1::1"
data.t1d1_ip_gateway = "200.200.1.1" #source Gateway ipv4
data.t1d2_ip_gateway = "200.100.1.1"
data.tgen1_asn = "65205"
data.tgen2_asn = "65206"
data.v6_mask="64"
f_size='1024'
t_mode='create'
t_l4_protocol="tcp"
t_tcp_src_port=1002
t_high_speed_result_analysis='1'
# Tgen config

IPv4_subnet_24_Ipv6_subnet_64_config = 'ars_basic_cfg.yaml'
@pytest.fixture(scope='module', autouse=True, params=[IPv4_subnet_24_Ipv6_subnet_64_config])
def setup_teardown_basic(request):
    global vars, updated_path, data_glob
    global tg1, tg2, tg_handle_1, tg_handle_2
    global trC1, trB1, trB2, trB4, trB5, trB1M
    config_file = request.param
    initialize_globals(config_file)
    set_frr_cfg_persistent()
    st.config(data_glob.dut1, "sudo config reload -y")
    st.wait(30)
    with open(updated_path) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            for domain, config in config.items():
                common_obj.config_static(node, domain, True, updated_path)
    yield 'setup_teardown_basic'
    with open(updated_path) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            for domain, config in config.items():
                common_obj.config_static(node, domain, False, updated_path)
    common_obj.remove_temp_config(updated_path)

def initialize_globals(config_file):
    global vars, data_glob, tg1, tg2, tg_handle_1, tg_handle_2, updated_path
    vars = st.get_testbed_vars()
    tg1, tg2, tg_handle_1, tg_handle_2 = get_handles()
    data_glob = SpyTestDict()
    data_glob.nodes = [vars.D1, vars.D2]
    data_glob.dut1 = data_glob.nodes[0]
    data_glob.dut2 = data_glob.nodes[1]
    data_glob.interfaces = [vars.D1D2P1, vars.D1D2P2, vars.D1D2P3, vars.D1D2P4,vars.D1D2P5, vars.D1D2P7, vars.D1D2P8]
    data.dut_asn_list = {data_glob.dut1: "65200", data_glob.dut2: "65201"}
    dir_path = os.path.dirname(os.path.realpath(__file__))
    updated_path = common_obj.modify_config_file(f'{dir_path}/{config_file}', vars)

def set_frr_cfg_persistent():
    cfgdb =ConfigDB("D1", "1.3.103.35", username="cisco", password= "cisco123") 
    cfgdb.set_leaf_value(['DEVICE_METADATA', 'localhost', 'docker_routing_config_mode'], 
                                 'split-unified')
    cfgdb.write_db()

def configure_tg_interfaces_v6():
    global tg1_interface, tg2_interface
    st.log("Creating Devices & adding IP Addresses along with ARP requests")
    res1 = tg1.tg_interface_config(port_handle=tg_handle_1, mode='config', ipv6_intf_addr=data.t1d1_ipv6_addr,ipv6_prefix_length='64', ipv6_gateway=data.t1d1_ipv6_gateway, src_mac_addr=data.t1d1_mac_addr, arp_send_req='1')
    st.log("INTFCONF: " + str(res1))
    tg1_interface = res1
    res2 = tg2.tg_interface_config(port_handle=tg_handle_2, mode='config', ipv6_intf_addr=data.t1d2_ipv6_addr,ipv6_prefix_length='64', ipv6_gateway=data.t1d2_ipv6_gateway, src_mac_addr=data.t1d2_mac_addr, arp_send_req='1')
    st.log("INTFCONF: " + str(res2))
    tg2_interface = res2

def configure_tg_interfaces_v4():
    global tg1_interface, tg2_interface
    st.log("Creating Devices & adding IP Addresses along with ARP requests")
    res1 = tg1.tg_interface_config(port_handle=tg_handle_1, mode='config', intf_ip_addr=data.t1d1_ip_addr, gateway=data.t1d1_ip_gateway, src_mac_addr=data.t1d1_mac_addr, arp_send_req='1')
    st.log("INTFCONF: " + str(res1))
    tg1_interface = res1
    res2 = tg2.tg_interface_config(port_handle=tg_handle_2, mode='config', intf_ip_addr=data.t1d2_ip_addr, gateway=data.t1d2_ip_gateway, src_mac_addr=data.t1d2_mac_addr, arp_send_req='1')
    st.log("INTFCONF: " + str(res2))
    tg2_interface = res2

@pytest.fixture(scope = 'class')
def fixture_v6():
    ars_common_utils.reset_tg_interfaces(tg1, tg2, tg_handle_1, tg_handle_2)
    configure_tg_interfaces_v6()
    ping_dut_interface_from_tg(dst_ip1 ="2001:200:1::1", dst_ip2="2001:100:1::1")
    configure_bgp_v6()
    configure_traffic_streams('ipv6')
    yield
    tg1.tg_traffic_config(mode = 'disable', stream_id =trB1['stream_id']) 
    tg1.tg_emulation_bgp_control(handle=bgp_rtr1['handle'], mode='stop')
    tg2.tg_emulation_bgp_control(handle=bgp_rtr2['handle'], mode='stop')
    ars_common_utils.reset_tg_interfaces(tg1, tg2, tg_handle_1, tg_handle_2)
    st.wait(30)
    tg1.tg_interface_config(port_handle=tg_handle_1, handle=tg1_interface['handle'], mode='destroy')
    st.wait(30)
    tg2.tg_interface_config(port_handle=tg_handle_2, handle=tg2_interface['handle'], mode='destroy')
    st.wait(30)

@pytest.fixture(scope = 'class')
def fixture_v4():
    ars_common_utils.reset_tg_interfaces(tg1, tg2, tg_handle_1, tg_handle_2)
    configure_tg_interfaces_v4()
    ping_dut_interface_from_tg(dst_ip1 ="200.200.1.1", dst_ip2="200.100.1.1")
    configure_bgp_v4()
    configure_traffic_streams('ipv4')
    yield
    tg1.tg_traffic_config(mode = 'disable', stream_id =trB1['stream_id']) 
    tg1.tg_emulation_bgp_control(handle=bgp_rtr1['handle'], mode='stop')
    tg2.tg_emulation_bgp_control(handle=bgp_rtr2['handle'], mode='stop')
    ars_common_utils.reset_tg_interfaces(tg1, tg2, tg_handle_1, tg_handle_2)
    st.wait(30)
    tg1.tg_interface_config(port_handle=tg_handle_1, handle=tg1_interface['handle'], mode='destroy')
    st.wait(30)
    tg2.tg_interface_config(port_handle=tg_handle_2, handle=tg2_interface['handle'], mode='destroy')
    st.wait(30)

def configure_bgp_v6():
    st.banner("Configuring BGP on TGEN-T1D1P1 towards DUT1")
    global bgp_rtr1
    bgp_rtr1 = tg1.tg_emulation_bgp_config(handle=tg1_interface['handle'],
                                           mode='enable', active_connect_enable='1',
                                           local_as=data.tgen1_asn, remote_as=data.dut_asn_list[data_glob.dut1], remote_ipv6_addr=data.t1d1_ipv6_gateway,ip_version='6',
                                           enable_4_byte_as='1', graceful_restart_enable='1')
    tg1.tg_emulation_bgp_control(handle=bgp_rtr1['handle'], mode='start')
    st.wait(2)
    st.banner("Configuring BGP on TGEN-T1D2P1 towards DUT2")
    global bgp_rtr2
    bgp_rtr2 = tg2.tg_emulation_bgp_config(handle=tg2_interface['handle'],
                                           mode='enable', active_connect_enable='1',
                                           local_as=data.tgen2_asn, remote_as=data.dut_asn_list[data_glob.dut2],remote_ipv6_addr=data.t1d2_ipv6_gateway, ip_version='6',
                                           enable_4_byte_as='1', graceful_restart_enable='1')
    tg2.tg_emulation_bgp_control(handle=bgp_rtr2['handle'], mode='start')
    st.wait(2)
    global bgp_route1, bgp_route2, bgp_route3
    # Destination Network group
    bgp_route1 = tg2.tg_emulation_bgp_route_config(handle=bgp_rtr2['handle'], mode='add', num_routes='1', prefix='2001:db8::20:20:20', ip_version='6')  
    tg2.tg_emulation_bgp_control(handle=bgp_rtr2['handle'], mode='start')
    st.wait(2)

def configure_bgp_v4():
    st.banner("Configuring BGP on TGEN-T1D1P1 towards DUT1")
    global bgp_rtr1
    bgp_rtr1 = tg1.tg_emulation_bgp_config(handle=tg1_interface['handle'],
                                           mode='enable', active_connect_enable='1',
                                           local_as=data.tgen1_asn, remote_as=data.dut_asn_list[data_glob.dut1], remote_ip_addr=data.t1d1_ip_gateway,
                                           enable_4_byte_as='1', graceful_restart_enable='1')
    tg1.tg_emulation_bgp_control(handle=bgp_rtr1['handle'], mode='start')
    st.wait(2)
    st.banner("Configuring BGP on TGEN-T1D2P1 towards DUT2")
    global bgp_rtr2
    bgp_rtr2 = tg2.tg_emulation_bgp_config(handle=tg2_interface['handle'],
                                           mode='enable', active_connect_enable='1',
                                           local_as=data.tgen2_asn, remote_as=data.dut_asn_list[data_glob.dut2], remote_ip_addr=data.t1d2_ip_gateway,
                                           enable_4_byte_as='1', graceful_restart_enable='1')
    tg2.tg_emulation_bgp_control(handle=bgp_rtr2['handle'], mode='start')
    st.wait(2)
    global bgp_route1, bgp_route2, bgp_route3
    # Destination Network group
    bgp_route1 = tg2.tg_emulation_bgp_route_config(handle=bgp_rtr2['handle'], mode='add', num_routes='1', prefix='20.20.20.1')  
    tg2.tg_emulation_bgp_control(handle=bgp_rtr2['handle'], mode='start')
    st.wait(2)

def configure_traffic_streams(tcircuit_endpoint_type):
    st.banner("Configuring Traffic Stream on TGEN port1 towards DUT1")
    global trDSCP1, trDSCP2, trB1, trDSCP3
    trB1 = tg1.tg_traffic_config(port_handle=tg_handle_1, emulation_src_handle=tg1_interface['handle'],
                                emulation_dst_handle=bgp_route1['handle'], circuit_endpoint_type=tcircuit_endpoint_type, mode=t_mode,
                                high_speed_result_analysis='1', frame_size='1024', transmit_mode='multi_burst',
                                pkts_per_burst='999', inter_burst_gap='2000000', inter_burst_gap_unit='ns', tx_delay='0', tx_delay_unit='bytes',min_gap_bytes='12')
    traffic_args = {}
    if tcircuit_endpoint_type == 'ipv4':
        traffic_args = {'ip_dscp': 57}
        traffic_args2 = {'ip_dscp': 58}
        st.banner("IN IPV4")
    else:
        traffic_args = {'ipv6_traffic_class': 228}
        traffic_args2 = {'ipv6_traffic_class': 232}
        st.banner("IN IPV6")
    trDSCP1 = tg1.tg_traffic_config(port_handle=tg_handle_1, emulation_src_handle=tg1_interface['handle'], emulation_dst_handle= bgp_route1['handle'],
                                circuit_endpoint_type=tcircuit_endpoint_type, mode='create', high_speed_result_analysis='1', length_mode='fixed', transmit_mode='multi_burst',
                                pkts_per_burst='999', inter_burst_gap="2000000", inter_burst_gap_unit='ns', tx_delay='0', tx_delay_unit='bytes',
                                min_gap_bytes='12', **traffic_args)
    trDSCP3 = tg1.tg_traffic_config(port_handle=tg_handle_1, emulation_src_handle=tg1_interface['handle'], emulation_dst_handle= bgp_route1['handle'],
                                circuit_endpoint_type=tcircuit_endpoint_type, mode='create', high_speed_result_analysis='1', length_mode='fixed', transmit_mode='multi_burst',
                                pkts_per_burst='999', inter_burst_gap="2000000", inter_burst_gap_unit='ns', tx_delay='0', tx_delay_unit='bytes',
                                min_gap_bytes='12', **traffic_args2)
    if tcircuit_endpoint_type == 'ipv4':
        traffic_args = {'ip_dscp': 59}
    else:
        traffic_args = {'ipv6_traffic_class': 236}
    trDSCP2 = tg1.tg_traffic_config(port_handle=tg_handle_1, emulation_src_handle=tg1_interface['handle'], emulation_dst_handle= bgp_route1['handle'],
                                circuit_endpoint_type=tcircuit_endpoint_type, mode='create', high_speed_result_analysis='1', length_mode='fixed', transmit_mode='multi_burst',
                                pkts_per_burst='999', inter_burst_gap="2000000", inter_burst_gap_unit='ns', tx_delay='0', tx_delay_unit='bytes',
                                min_gap_bytes='12', **traffic_args)
    
def get_handles():
    tg1, tg_ph_1 = tgapi.get_handle_byname("T1D1P1")
    tg2, tg_ph_2 = tgapi.get_handle_byname("T1D2P1")
    return (tg1, tg2, tg_ph_1, tg_ph_2)

def ping_dut_interface_from_tg(dst_ip1 , dst_ip2):
    res1 = tgapi.verify_ping(src_obj=tg1, port_handle=tg_handle_1, dev_handle=tg1_interface['handle'],
                            dst_ip=dst_ip1, ping_count='1', exp_count='1')
    res2 = tgapi.verify_ping(src_obj=tg2, port_handle=tg_handle_2, dev_handle=tg2_interface['handle'],
                            dst_ip=dst_ip2, ping_count='1', exp_count='1')
    if res1 and res2:
        st.log("Ping succeeded.")
    else:
        st.warn("Ping failed.")

def create_acl_table_and_rule(dut, acl_json_file_path = None):
    st.log("Creating ACL table")
    with open(acl_json_file_path, 'r') as file:
        acl_table_data = json.load(file)
        port_name = vars.D1T1P1
        for table in acl_table_data["ACL_TABLE"].values():
            table["ports"] = [port_name]
    acl_json_string = json.dumps(acl_table_data)
    st.apply_json2(dut, acl_json_string)

def delete_acl_table(dut):
    st.log("Deleting ACL table")
    command1 = "sudo config acl remove table ARS_IPV4"
    command2 = "sudo config acl remove table ARS_IPV6"
    command3 = "sudo config acl remove table NON_ARS_IPV4"
    command4 = "sudo config acl remove table NON_ARS_IPV6"
    st.config(dut, command1)
    st.config(dut, command2)
    st.config(dut, command3)
    st.config(dut, command4)
    
def scp_download(local_path, remote_path, hostaddr, username, password, port=22):
    try:
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(hostaddr, port=port, username=username, password=password)
        with SCPClient(ssh_client.get_transport()) as scp:
            scp.get(remote_path, local_path=local_path)
    finally:
        ssh_client.close()   

def scp_upload(local_path, remote_path, hostaddr, username, password, port=22):
    try:
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(hostaddr, port=port, username=username, password=password)
        with SCPClient(ssh_client.get_transport()) as scp:
            scp.put(local_path, remote_path)
    finally:
        ssh_client.close()    

class ConfigDB(object):
    def __init__(self, dut, address, username, password):
        self._config_db = {}
        self.dut = dut
        self.address = address
        self.username = username
        self.password = password
        self.temp_db = '__config_db_{}__.json'.format(self.dut)
        self.local_temp_db_path = './' + self.temp_db
        self.remote_temp_db_path = '/home/{}/'.format(self.username) + self.temp_db
        self.remote_db_path = '/etc/sonic/config_db.json'
        self.read_db()
    
    def read_db(self):
        try:
            scp_download(local_path=self.local_temp_db_path,
                        remote_path= self.remote_db_path, 
                        hostaddr=self.address,
                        username=self.username, password=self.password)
            with open(self.local_temp_db_path) as fd:
                self._config_db = json.load(fd)
        finally:
            os.system('rm -rf {}'.format(self.local_temp_db_path))


    def write_db(self):
        try:
            db_data_json = json.dumps(self._config_db, indent=4, sort_keys=False)
            with open(self.local_temp_db_path, 'w') as fd:
                fd.write(db_data_json)

            scp_upload(local_path=self.local_temp_db_path, 
                        remote_path=self.remote_temp_db_path, 
                        hostaddr=self.address,
                        username=self.username, password=self.password)
            st.show(self.dut, 'sudo cp {} {}'.format(self.remote_temp_db_path,
                                                     self.remote_db_path), skip_tmpl=True)
        finally:
            os.system('rm -rf {}'.format(self.local_temp_db_path))
            st.show(self.dut, 'sudo rm {}'.format(self.remote_temp_db_path), skip_tmpl=True)

    def _find_key_val_dict(self, keys):
        if type(keys) is str:
            keys = [keys]
        if type(keys) is not list:
            raise Exception('Keys not in list format')
        ret_dict = self._config_db
        for key in keys[:-1]:
            ret_dict = ret_dict[key] 
            if type(ret_dict) is not dict:
                raise Exception('Key is a leaf')
        return ret_dict
    
    def get_leaf_value(self, keys):
        try:
            key_dict = self._find_key_val_dict(keys)
            val = key_dict[keys[-1]]
        except Exception as err:
            raise Exception('Invalid key: {}'.format(err))

    def set_leaf_value(self, keys, value):
        try:
            key_dict = self._find_key_val_dict(keys)
            key = keys[-1]
            val = str(value)
            key_dict[key] = val
        except Exception as err:
            raise Exception('Invalid key: {}'.format(err))

@pytest.mark.usefixtures('fixture_v6')
class Test_IPV6_config_ars():
    def test_ACl(self):
        st.banner("Verify traffic distribution for ARS Flowlet Quality with DSCP")
        ars_common_utils.add_ars(data_glob.dut1, global_mode="false", mode="flowlet-quality", idle_time="1000")
        create_acl_table_and_rule(data_glob.dut1, ACL_JSON_FILE_PATH)
        st.config(data_glob.dut1, "counterpoll acl enable")
        st.banner("ACL Table")
        st.show(data_glob.dut1, "sudo show acl table")
        st.banner("ACL Rule")
        st.show(data_glob.dut1, "sudo show acl rule")
        stream = trDSCP1['stream_id']
        ars_common_utils.run_traffic(stream,tg_handle_1, tg1, data_glob)
        counter1 = st.show(data_glob.dut1, "sudo -s show interface counters")
        if not ars_common_utils.check_traffic_balanced(tg1, tg2, tg_handle_1, tg_handle_2, counter1, data_glob.interfaces):
            st.config(data_glob.dut1, "acl-loader delete ARS_IPV4")
            st.config(data_glob.dut1, "acl-loader delete ARS_IPV6")
            st.config(data_glob.dut1, "acl-loader delete NON_ARS_IPV6")
            st.config(data_glob.dut1, "acl-loader delete NON_ARS_IPV4")
            delete_acl_table(data_glob.dut1)
            ars_common_utils.del_ars(data_glob.dut1)
            st.report_fail("test_case_failed_msg", "Traffic load is not Distributed for DSCP Traffic with ACL rule")
        st.banner("Test Passed: Traffic Load Distributed Evenly for DSCP Traffic with ACL rule with ARS")
        stream = trDSCP2['stream_id']
        ars_common_utils.run_traffic(stream,tg_handle_1, tg1, data_glob)
        counter2 = st.show(data_glob.dut1, "sudo -s show interface counters")
        if not ars_common_utils.check_traffic_single_interface(tg1, tg2, tg_handle_1, tg_handle_2, counter2, data_glob.interfaces):
            st.config(data_glob.dut1, "acl-loader delete ARS_IPV4")
            st.config(data_glob.dut1, "acl-loader delete ARS_IPV6")
            st.config(data_glob.dut1, "acl-loader delete NON_ARS_IPV6")
            st.config(data_glob.dut1, "acl-loader delete NON_ARS_IPV4")
            delete_acl_table(data_glob.dut1)
            ars_common_utils.del_ars(data_glob.dut1)
            st.report_fail("test_case_failed_msg", "Traffic does not flow thorugh single interface for DSCP Traffic without ACL rule")
        st.banner("Test Passed: Traffic passes through Single Interface for DSCP Traffic without ACL rule")
        stream = trDSCP3['stream_id']
        ars_common_utils.run_traffic(stream,tg_handle_1, tg1, data_glob)
        counter3 = st.show(data_glob.dut1, "sudo -s show interface counters")
        if not ars_common_utils.check_traffic_single_interface(tg1, tg2, tg_handle_1, tg_handle_2, counter3, data_glob.interfaces):
            st.config(data_glob.dut1, "acl-loader delete ARS_IPV4")
            st.config(data_glob.dut1, "acl-loader delete ARS_IPV6")
            st.config(data_glob.dut1, "acl-loader delete NON_ARS_IPV6")
            st.config(data_glob.dut1, "acl-loader delete NON_ARS_IPV4")
            delete_acl_table(data_glob.dut1)
            ars_common_utils.del_ars(data_glob.dut1)
            st.report_fail("test_case_failed_msg", "Traffic does not flow thorugh single interface for DSCP Traffic with ACL rule without ARS")
        st.banner("Test Passed: Traffic passes through Single Interface for DSCP Traffic with ACL rule without ARS")
        st.config(data_glob.dut1, "acl-loader delete ARS_IPV4")
        st.config(data_glob.dut1, "acl-loader delete ARS_IPV6")
        st.config(data_glob.dut1, "acl-loader delete NON_ARS_IPV6")
        st.config(data_glob.dut1, "acl-loader delete NON_ARS_IPV4")
        delete_acl_table(data_glob.dut1)
        ars_common_utils.del_ars(data_glob.dut1)
        st.report_pass('test_case_passed')

@pytest.mark.usefixtures('fixture_v4')
class Test_IPV4_config_ars():
    def test_ACl(self):
        st.banner("Verify traffic distribution for ARS Flowlet Quality with DSCP")
        ars_common_utils.add_ars(data_glob.dut1, global_mode="false", mode="flowlet-quality", idle_time="1000")
        create_acl_table_and_rule(data_glob.dut1, ACL_JSON_FILE_PATH)
        st.config(data_glob.dut1, "counterpoll acl enable")
        st.banner("ACL Table")
        st.show(data_glob.dut1, "sudo show acl table")
        st.banner("ACL Rule")
        st.show(data_glob.dut1, "sudo show acl rule")
        stream = trDSCP1['stream_id']
        ars_common_utils.run_traffic(stream,tg_handle_1, tg1, data_glob)
        counter1 = st.show(data_glob.dut1, "sudo -s show interface counters")
        if not ars_common_utils.check_traffic_balanced(tg1, tg2, tg_handle_1, tg_handle_2, counter1, data_glob.interfaces):
            st.config(data_glob.dut1, "acl-loader delete ARS_IPV4")
            st.config(data_glob.dut1, "acl-loader delete ARS_IPV6")
            st.config(data_glob.dut1, "acl-loader delete NON_ARS_IPV6")
            st.config(data_glob.dut1, "acl-loader delete NON_ARS_IPV4")
            delete_acl_table(data_glob.dut1)
            ars_common_utils.del_ars(data_glob.dut1)
            st.report_fail("test_case_failed_msg", "Traffic load is not Distributed for DSCP Traffic with ACL rule")
        st.banner("Test Passed: Traffic Load Distributed Evenly for DSCP Traffic with ACL rule with ARS")
        stream = trDSCP2['stream_id']
        ars_common_utils.run_traffic(stream,tg_handle_1, tg1, data_glob)
        counter2 = st.show(data_glob.dut1, "sudo -s show interface counters")
        if not ars_common_utils.check_traffic_single_interface(tg1, tg2, tg_handle_1, tg_handle_2, counter2, data_glob.interfaces):
            st.config(data_glob.dut1, "acl-loader delete ARS_IPV4")
            st.config(data_glob.dut1, "acl-loader delete ARS_IPV6")
            st.config(data_glob.dut1, "acl-loader delete NON_ARS_IPV6")
            st.config(data_glob.dut1, "acl-loader delete NON_ARS_IPV4")
            delete_acl_table(data_glob.dut1)
            ars_common_utils.del_ars(data_glob.dut1)
            st.report_fail("test_case_failed_msg", "Traffic does not flow thorugh single interface for DSCP Traffic without ACL rule")
        st.banner("Test Passed: Traffic passes through Single Interface for DSCP Traffic without ACL rule")
        stream = trDSCP3['stream_id']
        ars_common_utils.run_traffic(stream,tg_handle_1, tg1, data_glob)
        counter3 = st.show(data_glob.dut1, "sudo -s show interface counters")
        if not ars_common_utils.check_traffic_single_interface(tg1, tg2, tg_handle_1, tg_handle_2, counter3, data_glob.interfaces):
            st.config(data_glob.dut1, "acl-loader delete ARS_IPV4")
            st.config(data_glob.dut1, "acl-loader delete ARS_IPV6")
            st.config(data_glob.dut1, "acl-loader delete NON_ARS_IPV6")
            st.config(data_glob.dut1, "acl-loader delete NON_ARS_IPV4")
            delete_acl_table(data_glob.dut1)
            ars_common_utils.del_ars(data_glob.dut1)
            st.report_fail("test_case_failed_msg", "Traffic does not flow thorugh single interface for DSCP Traffic with ACL rule without ARS")
        st.banner("Test Passed: Traffic passes through Single Interface for DSCP Traffic with ACL rule without ARS")
        st.config(data_glob.dut1, "acl-loader delete ARS_IPV4")
        st.config(data_glob.dut1, "acl-loader delete ARS_IPV6")
        st.config(data_glob.dut1, "acl-loader delete NON_ARS_IPV6")
        st.config(data_glob.dut1, "acl-loader delete NON_ARS_IPV4")
        delete_acl_table(data_glob.dut1)
        ars_common_utils.del_ars(data_glob.dut1)
        st.report_pass('test_case_passed')

    def test_reboot(self):
        st.config(data_glob.dut1, "sudo -s config ars-profile add arsp --enable-all-packets true --mode flowlet-quality --idle-time 1000")
        tg2.tg_emulation_bgp_control(handle=bgp_rtr2['handle'], mode='stop')
        tg1.tg_emulation_bgp_control(handle=bgp_rtr1['handle'], mode='stop')
        config_save_reboot(data_glob.dut1)
        st.wait(100)
        ping_dut_interface_from_tg(dst_ip1 ="200.200.1.1", dst_ip2="200.100.1.1")
        tg2.tg_emulation_bgp_control(handle=bgp_rtr2['handle'], mode='start')
        tg1.tg_emulation_bgp_control(handle=bgp_rtr1['handle'], mode='start')
        res = st.show(data_glob.dut1, "sudo show ars-profile")
        expected_values = {'ars_profile_name': 'arsp', 'enable_all_packets': 'true', 'ars_mode': 'flowlet-quality', 'ars_idle_time': "1000" }
        ars_common_utils.check_ars(res, expected_values)
        stream1 = trB1['stream_id']
        ars_common_utils.run_traffic(stream1,tg_handle_1, tg1, data_glob)
        counter1 = st.show(data_glob.dut1, "sudo -s show interface counters")
        if not ars_common_utils.check_traffic_balanced(tg1, tg2, tg_handle_1, tg_handle_2, counter1, data_glob.interfaces):
            ars_common_utils.del_ars(data_glob.dut1)
            st.report_fail("test_case_failed_msg", "traffic is not distributed ARS not enabled")
        st.banner("Test Passed: Traffic Load Distributed Evenly ARS enabled")
        ars_common_utils.del_ars(data_glob.dut1)
        st.report_pass('test_case_passed')

    def test_reload(self):
        st.config(data_glob.dut1, "sudo -s config ars-profile add arsp --enable-all-packets true --mode flowlet-quality --idle-time 1000")
        tg2.tg_emulation_bgp_control(handle=bgp_rtr2['handle'], mode='stop')
        tg1.tg_emulation_bgp_control(handle=bgp_rtr1['handle'], mode='stop')
        config_save_reload(data_glob.dut1)
        st.wait(100)
        ping_dut_interface_from_tg(dst_ip1 ="200.200.1.1", dst_ip2="200.100.1.1")
        tg2.tg_emulation_bgp_control(handle=bgp_rtr2['handle'], mode='start')
        tg1.tg_emulation_bgp_control(handle=bgp_rtr1['handle'], mode='start')
        res = st.show(data_glob.dut1, "sudo show ars-profile")
        expected_values = {'ars_profile_name': 'arsp', 'enable_all_packets': 'true', 'ars_mode': 'flowlet-quality', 'ars_idle_time': "1000" }
        ars_common_utils.check_ars(res, expected_values)
        stream1 = trB1['stream_id']
        ars_common_utils.run_traffic(stream1,tg_handle_1, tg1, data_glob)
        counter1 = st.show(data_glob.dut1, "sudo -s show interface counters")
        if not ars_common_utils.check_traffic_balanced(tg1, tg2, tg_handle_1, tg_handle_2, counter1, data_glob.interfaces):
            ars_common_utils.del_ars(data_glob.dut1)
            st.report_fail("test_case_failed_msg", "traffic is not distributed ARS not enabled")
        st.banner("Test Passed: Traffic Load Distributed Evenly ARS enabled")
        ars_common_utils.del_ars(data_glob.dut1)
        st.report_pass('test_case_passed')
    