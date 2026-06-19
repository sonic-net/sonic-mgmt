# As of now, we are using bcm cmds to check the CPU queue counters.
# We can not push scripts with bcm cmds to community.
# So, we logged a DUT defect(SONIC-6136) to provide official CLI show commands for the same.
# Once that defect is fixed, we need to modify scripts to use the official command instead of bcm cmd.
import pytest
from spytest import st, tgapi, SpyTestDict

import apis.routing.ip as ip_obj
import apis.system.basic as basic_obj
from apis.system.interface import show_queue_counters, clear_queue_counters
import apis.common.asic as asicapi
import apis.routing.arp as arp_obj
import apis.switching.vlan as vlan_obj
import apis.switching.mac as mac_obj
import apis.qos.cos as cos_obj
import apis.qos.qos as qos_obj

from utilities.common import filter_and_select

@pytest.fixture(scope="module", autouse=True)
def cos_module_hooks(request):
    # add things at the start of this module
    global vars

    st.log("Ensuring minimum topology")
    vars = st.ensure_min_topology("D1T1:2")

    cos_variables()
    cos_module_config(config='yes')

    st.log("Getting TG handlers")
    data.tg1, data.tg_ph_1 = tgapi.get_handle_byname("T1D1P1")
    data.tg2, data.tg_ph_2 = tgapi.get_handle_byname("T1D1P2")
    data.tg = data.tg1

    st.log("Reset and clear statistics of TG ports")
    data.tg.tg_traffic_control(action='reset', port_handle=[data.tg_ph_1,data.tg_ph_2])
    data.tg.tg_traffic_control(action='clear_stats', port_handle=[data.tg_ph_1, data.tg_ph_2])

    st.log("Creating TG streams")
    data.streams = {}
    stream = data.tg.tg_traffic_config(port_handle=data.tg_ph_2, mode='create', length_mode='fixed', frame_size=78,
                                rate_pps=2000, l2_encap='ethernet_ii_vlan', transmit_mode='continuous',
                                vlan_id=data.vlan, mac_src=data.cos_dest_mac, mac_dst='00:0a:12:00:00:01', vlan="enable")
    st.log('Stream output:{}'.format(stream))
    data.streams['vlan_tagged'] = stream['stream_id']
    stream = data.tg.tg_traffic_config(port_handle=data.tg_ph_1, mode='create', length_mode='fixed', frame_size=78,
                                       pkts_per_burst=2020, l2_encap='ethernet_ii_vlan', transmit_mode='single_burst',
                                       vlan_id=data.vlan, mac_src=data.cos_src1, mac_dst= data.cos_dest_mac, vlan="enable",
                                       vlan_user_priority =data.vlan_priority1)
    st.log('Stream output:{}'.format(stream))
    data.streams['cos_transmit'] = stream['stream_id']
    stream = data.tg.tg_traffic_config(port_handle=data.tg_ph_1, mode='create', length_mode='fixed', frame_size=78,
                                       rate_pps=2000, l2_encap='ethernet_ii_vlan',
                                       transmit_mode='continuous',
                                       l3_protocol="arp", arp_operation="arpReply", arp_dst_hw_addr=data.mac_addr,
                                       arp_src_hw_addr=data.src_arp_addr)
    st.log('Stream output:{}'.format(stream))
    data.streams['ARP_Reply'] = stream['stream_id']
    stream = data.tg.tg_traffic_config(port_handle=data.tg_ph_1, mode='create', length_mode='fixed', frame_size=78,
                                       rate_pps=2000, l2_encap='ethernet_ii_vlan',
                                       transmit_mode='continuous',
                                       mac_src=data.src_mac, mac_dst=data.mac_addr)
    st.log('Stream output:{}'.format(stream))
    data.streams['switch_unicast_mac'] = stream['stream_id']
    stream = data.tg.tg_traffic_config(port_handle=data.tg_ph_1, mode='create', length_mode='fixed', frame_size=78,
                                       rate_pps=2000, l2_encap='ethernet_ii_vlan',
                                       transmit_mode='continuous', l3_protocol='ipv4',
                                       mac_src='00:0a:01:01:23:01',
                                       mac_dst=data.dut_rt_int_mac, ip_src_addr=data.ipv4_source_address,
                                       ip_dst_addr=data.ipv4_address, ip_ttl="0")
    st.log('Stream output:{}'.format(stream))
    data.streams['ipv4_ttl_0'] = stream['stream_id']
    stream = data.tg.tg_traffic_config(port_handle=data.tg_ph_1, mode='create', length_mode='fixed', frame_size=78,
                                       rate_pps=2000, l2_encap='ethernet_ii_vlan',
                                       transmit_mode='continuous', l3_protocol='ipv4',
                                       mac_src='00:0a:01:01:23:01',
                                       mac_dst=data.dut_rt_int_mac, ip_src_addr=data.ipv4_source_address,
                                       ip_dst_addr=data.ipv4_address, ip_ttl="255")
    st.log('Stream output:{}'.format(stream))
    data.streams['ipv4_ttl_255'] = stream['stream_id']
    stream = data.tg.tg_traffic_config(port_handle=data.tg_ph_1, mode='create', length_mode='fixed', frame_size=78,
                                       rate_pps=2000, l2_encap='ethernet_ii_vlan',
                                       transmit_mode='continuous', l3_protocol='ipv6',
                                       mac_src='00:0a:01:01:23:01', \
                                       mac_dst=data.dut_rt_int_mac, ipv6_src_addr=data.ipv6_source_address,
                                       ipv6_dst_addr=data.ipv6_address, ipv6_hop_limit="0")
    st.log('Stream output:{}'.format(stream))
    data.streams['ipv6_hop_limit_0'] = stream['stream_id']
    stream = data.tg.tg_traffic_config(port_handle=data.tg_ph_1, mode='create', length_mode='fixed', frame_size=78,
                                       rate_pps=2000, l2_encap='ethernet_ii_vlan',
                                       transmit_mode='continuous', l3_protocol='ipv6',
                                       mac_src='00:0a:01:01:23:01', \
                                       mac_dst=data.dut_rt_int_mac, ipv6_src_addr=data.ipv6_source_address,
                                       ipv6_dst_addr=data.ipv6_address, ipv6_hop_limit="255")
    st.log('Stream output:{}'.format(stream))
    data.streams['ipv6_hop_limit_255'] = stream['stream_id']
    yield
    # add things at the end of this module"
    cos_module_config(config='no')


@pytest.fixture(scope="function", autouse=True)
def cos_func_hooks(request):
    # add things at the start every test case
    yield
    if st.get_func_name(request) == 'test_ft_cos_cpu_counters':
        ip_obj.delete_ip_interface(vars.D1, vars.D1T1P1, data.ipv6_address, data.ipv6_subnet, family="ipv6")
        ip_obj.delete_ip_interface(vars.D1, vars.D1T1P1, data.ipv4_address, data.subnet, family="ipv4")

def cos_module_config(config='yes'):
    if config == 'yes':
        data.mac_addr = basic_obj.get_ifconfig_ether(vars.D1)
        data.dut_rt_int_mac = basic_obj.get_ifconfig_ether(vars.D1, vars.D1T1P1)
    else:
        st.log("Clearing QoS, VLAN config and resetting and clearing TG stats")
        vlan_obj.clear_vlan_configuration(vars.D1, thread=True)
        qos_obj.clear_qos_config(vars.D1)
        data.tg.tg_traffic_control(action='reset', port_handle=[data.tg_ph_1, data.tg_ph_2])
        data.tg.tg_traffic_control(action='clear_stats', port_handle=[data.tg_ph_1, data.tg_ph_2])

def cos_variables():
    global data
    data = SpyTestDict()
    data.ageout_time = 600
    data.ipv4_address = "10.10.10.1"
    data.ipv4_address_tgen = "10.10.10.2"
    data.ipv6_address = "1001::1"
    data.ipv6_address_tgen = "1001::2"
    data.subnet = 24
    data.ipv6_subnet = 64
    data.ipv6_source_address = "2001::1"
    data.rate_percent = 100
    data.ipv4_source_address = "20.20.20.1"
    data.ip_protocol = 58
    data.l4_protocol = "icmp"
    data.ipv6_family = "ipv6"
    data.ipv4_family = "ipv4"
    data.src_arp_addr = "00:01:02:03:04:05"
    data.src_mac = "00:00:00:02:03:04"
    data.multi_addr = "01:00:5e:00:01:01"
    data.cos_name = "COS"
    data.vlan = 555
    data.cos_dest_mac = "00:00:00:00:00:03"
    data.cos_src1 = "00:00:00:00:00:01"
    data.cos_src2 = "00:00:00:00:00:02"
    data.vlan_priority1 = "4"
    data.queue = "5"
    data.pkts_per_burst = "100"


def configuring_ipv4_and_ipv6_address():
    st.log("About to add ipv6 address TGen connected interface")
    ip_obj.config_ip_addr_interface(vars.D1, vars.D1T1P1, data.ipv6_address, data.ipv6_subnet, family="ipv6")
    if not ip_obj.verify_interface_ip_address(vars.D1, vars.D1T1P1, "{}/{}".format(data.ipv6_address, data.ipv6_subnet),
                                              family="ipv6"):
        st.report_fail("ip_routing_int_create_fail", vars.D1T1P1)
    st.log("About to add ipv4 address TGen connected interface")
    ip_obj.config_ip_addr_interface(vars.D1, vars.D1T1P1, data.ipv4_address, data.subnet, family="ipv4")
    if not ip_obj.verify_interface_ip_address(vars.D1, vars.D1T1P1, "{}/{}".format(data.ipv4_address, data.subnet),
                                              family="ipv4"):
        st.report_fail("ip_routing_int_create_fail", vars.D1T1P1)


def configuring_tc_to_queue_map():
    if not cos_obj.config_tc_to_queue_map(vars.D1, data.cos_name, {"4": "5"}):
        st.report_fail("queue_map_not_found",data.vlan_priority1)


def binding_queue_map_to_interfaces():
    qos_map = {'port': vars.D1T1P1, 'map': 'tc_to_queue_map', 'obj_name': data.cos_name}
    if not cos_obj.config_port_qos_map_all(vars.D1, qos_map):
        st.report_fail("content_not_found")


def cos_counters_checking(value=None):
    if not st.is_feature_supported("bcmcmd", vars.D1):
        queue_dict_list = show_queue_counters(vars.D1, "CPU")
        cpu_queue_counter = int(filter_and_select(queue_dict_list, ['pkts_count'], {'txq': 'MC1'})[0]['pkts_count'].replace(',', ''))
        if cpu_queue_counter == 0:
            st.error("{} queue_traffic_failed".format(value))
            return False
        return True
    else:
        queue_dict_list = asicapi.get_counters(vars.D1)
        for queue_dict in queue_dict_list:
            if (queue_dict['key'] == 'MC_PERQ_PKT(1).cpu0'):
                if int(queue_dict['value'].replace(",", "")) == 0:
                    st.error("{} queue_traffic_failed".format(value))
                    return False
        return True


def ping_ipv6_interface():
    h1 = data.tg.tg_interface_config(port_handle=data.tg_ph_1, mode='config', ipv6_intf_addr=data.ipv6_address_tgen, \
                                     ipv6_prefix_length="64", ipv6_gateway=data.ipv6_address,
                                     src_mac_addr='00:0a:01:01:23:01', arp_send_req='1')
    st.log("INTFCONF: " + str(h1))
    # ping from tgen to DUT's TGen connected IPV6 interface
    res = tgapi.verify_ping(src_obj=data.tg, port_handle=data.tg_ph_1, dev_handle=h1['handle'], dst_ip=data.ipv6_address, \
                      ping_count='2', exp_count='2')
    st.log("PING_RES: " + str(res))
    if res:
        st.log("Ping succeeded.")
    else:
        st.log("Ping failed.")
    if not arp_obj.show_ndp(vars.D1, data.ipv6_address_tgen):
        st.report_fail("ARP_entry_dynamic_entry_fail")


def ping_ipv4_interface():
    h1 = data.tg.tg_interface_config(port_handle=data.tg_ph_1, mode='config', intf_ip_addr=data.ipv4_address_tgen, \
                                     gateway=data.ipv4_address, src_mac_addr='00:00:23:11:14:08', arp_send_req='1')
    st.log("INTFCONF: " + str(h1))
    # Ping from tgen to DUT's TGen connected IPV4 interface.
    res = tgapi.verify_ping(src_obj=data.tg, port_handle=data.tg_ph_1, dev_handle=h1['handle'], dst_ip=data.ipv4_address, \
                      ping_count='1', exp_count='1')
    st.log("PING_RES: " + str(res))
    if res:
        st.log("Ping succeeded.")
    else:
        st.log("Ping failed.")
    if not arp_obj.show_arp(vars.D1, data.ipv4_address_tgen):
        st.report_fail("ARP_entry_dynamic_entry_fail")


def fdb_config():
    mac_obj.config_mac_agetime(vars.D1, data.ageout_time)
    if not (mac_obj.get_mac_agetime(vars.D1) == data.ageout_time):
        st.report_fail("mac_aging_time_failed_config")


def vlan_config():
    vlan_obj.create_vlan(vars.D1, data.vlan)
    st.log("Adding TGen port connected interface to the vlan with tagging mode")
    if not vlan_obj.add_vlan_member(vars.D1, data.vlan, [vars.D1T1P1, vars.D1T1P2], tagging_mode=True):
        st.report_fail("vlan_tagged_member_fail", vars.D1T1P2, data.vlan)
    if vlan_obj.verify_vlan_brief(vars.D1, data.vlan, tagged=True):
        st.report_fail("vlan_create_fail")


@pytest.mark.cos_cpu_counters
@pytest.mark.community_unsupported
def test_ft_cos_cpu_counters():
    """
    Author : Sai Durga <pchvsai.durga@broadcom.com>
    FtOpSoQoSCosCqFn001 : Verify that switching, routing, ipv6 and ipv4 packets go into appropriate CPU CoS queue
        #########################################################
        #TestBed : #2
        #2*TGEN ports--- D1---2 links-------D2--------2*TGEN ports
        ##########################################################
    Setup:
    TGen-1 ---------DUT
    Enable ip routing and ipv6 unicast-routing globally.
    Procedure:
    1.  Configure a port based routing interface with valid ipv6 address.
        Configure the routing interface on TG port connected to that port in same subnet.
        Send Ipv6 packets with hop-limit = 255 from TGen-1 destined to the IP address configured on DUT port.
    2. Configure a port based routing interface with valid ipv6 address.
        Configure the routing interface on TG port connected to that port in same subnet.
        Send Ipv6 packets with hop-limit = 0 from TGen-1 destined to the IP address configured on DUT port.
    3. Configure a port based routing interface with valid ipv4 address.
        Configure the routing interface on TG port connected to that port in same subnet.
        Send Ipv4 packets from TGen-1 destined to the IP address configured on DUT port. In that TGen stream, configure TTL = 0.
    4. ARP Reply to router mac
    5. Unicast to switch mac address
    Expected behavior:
    1. Observed that these packets are received on CoS queue# 1.
    """
    status = True
    configuring_ipv4_and_ipv6_address()
    st.log("About to send switching packets")
    st.log("Configuring TGen with ARP reply with switch MAC as destination ARP MAC")
    data.tg.tg_traffic_control(action='run', stream_handle=data.streams['ARP_Reply'])
    if not cos_counters_checking(value="ARP_Packets"):
        status = False
    data.tg.tg_traffic_control(action='stop', stream_handle=data.streams['ARP_Reply'])
    st.log("Sending unicast frames with switch MAC")
    data.tg.tg_traffic_control(action='run', stream_handle=data.streams['switch_unicast_mac'])
    if not cos_counters_checking(value="switching_packets"):
        status = False
    st.log("Switching traffic sent to appropriate queue")
    data.tg.tg_traffic_control(action='stop', stream_handle=data.streams['switch_unicast_mac'])
    ping_ipv6_interface()
    st.log("Sending ipv6 packets with hop limit 0")
    data.tg.tg_traffic_control(action='run', stream_handle=data.streams['ipv6_hop_limit_0'])
    if not cos_counters_checking(value="ipv6_packets_hop_limit_0"):
        status = False
    data.tg.tg_traffic_control(action='stop', stream_handle=data.streams['ipv6_hop_limit_0'])
    st.log("Sending ipv6 packets with hop limit 255")
    data.tg.tg_traffic_control(action='run', stream_handle=data.streams['ipv6_hop_limit_255'])
    if not cos_counters_checking(value="ipv6_packets_hop_limit_255"):
        status = False
    data.tg.tg_traffic_control(action='stop', stream_handle=data.streams['ipv6_hop_limit_255'])
    ping_ipv4_interface()
    st.log("Sending ipv4 packets with TTL value 0")
    data.tg.tg_traffic_control(action='run', stream_handle=data.streams['ipv4_ttl_0'])
    if not cos_counters_checking(value="ipv4_packets_ttl_0"):
        status = False
    data.tg.tg_traffic_control(action='stop', stream_handle=data.streams['ipv4_ttl_0'])
    st.log("Traffic sent to correct queue with v4 and v6 traffic")
    if not status:
        st.report_fail('queue_traffic_failed')
    st.report_pass("test_case_passed")


@pytest.mark.cos_queue
@pytest.mark.community_unsupported
def test_ft_cos_tc_queue_map():
    """
    Author : Sai Durga <pchvsai.durga@broadcom.com>
    FtOpSoQoSCosFn001 : Verify that the traffic is mapped to the correct CoS queues based on the configured 'priority --> CoS map' table
    Setup:
    ==========
    DUT----2TGen
    1) Connect 2 TGen ports (I1 transmitting ports I2 - receiving port)
    2) Set bridge aging-time to be 10 mins.
    3) Send in a layer2 packet from port2 (mac = 000000000002) to the DUT to create an entry in the fwd database.
    4) Change the TC to queue map to 4 to 5
    Procedure:
    ==========
    1) Start transmitting the TGen streams with VLAN priority 4 from port1 to port2.
    Expected Result:
    ==================
    1) Expected mapping is traffic from port1 sent to queue5
    """

    st.log("Configuring MAC age time out")
    fdb_config()
    st.log("Creating vlan and adding the TGen connected ports to it")
    vlan_config()
    st.log("Sending traffic from port 2 to learn the MAC in FDB table")
    data.tg.tg_traffic_control(action='run', stream_handle=data.streams['vlan_tagged'])
    st.wait(10)
    data.tg.tg_traffic_control(action='stop', stream_handle=data.streams['vlan_tagged'])
    st.log("Verifying FDB table")
    if not mac_obj.verify_mac_address_table(vars.D1, data.cos_dest_mac, type='Dynamic'):
        st.report_fail("mac_address_verification_fail")
    st.log("Configuring cos queue and binding it on interfaces")
    configuring_tc_to_queue_map()
    binding_queue_map_to_interfaces()
    clear_queue_counters(vars.D1)
    st.log("Sending traffic from 1st port")
    data.tg.tg_traffic_control(action='run', stream_handle=data.streams['cos_transmit'])
    st.wait(2)
    data.tg.tg_traffic_control(action='stop', stream_handle=data.streams['cos_transmit'])
    st.wait(2)
    counter = show_queue_counters(vars.D1, vars.D1T1P2, queue='UC{}'.format(data.queue))
    if not(counter and counter[0]['pkts_count']):
        st.report_fail("queue_traffic_failed")
    if int(counter[0]['pkts_count'].replace(',', '')) < 2000:
        st.report_fail("queue_traffic_failed")
    st.report_pass("test_case_passed")
