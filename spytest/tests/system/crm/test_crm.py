import pytest
import re

from spytest import st, tgapi, SpyTestDict
from spytest.utils import poll_wait
import tests.system.crm.acl_json_crm_config as acl_data
import apis.system.crm as crm_obj
import apis.switching.vlan as vapi
import apis.switching.mac as macapi
import apis.system.logging as slog_obj
import apis.routing.ip as ipfeature
import apis.routing.bgp as bgp_obj
import apis.system.interface as interface_obj
import apis.qos.acl as acl_obj
import apis.system.basic as base_obj

crm_test_status = False
crm_test_result = dict()
resource_str = {'fdb': 'FDB_ENTRY', 'ipv4_route': 'IPV4_ROUTE', 'ipv6_route': 'IPV6_ROUTE',
                'dnat': 'DNAT_ENTRY', 'snat': 'SNAT_ENTRY', 'ipmc': 'IPMC_ENTRY','acl_table_stats' : 'ACL_TABLE',
                'ipv4_neighbor': 'IPV4_NEIGHBOR', 'ipv6_neighbor': 'IPV6_NEIGHBOR', 'ipv4_nexthop': 'IPV4_NEXTHOP',
                'ipv6_nexthop': 'IPV6_NEXTHOP', 'nexthop_group_object': 'NEXTHOP_GROUP',
                'nexthop_group_member': 'NEXTHOP_GROUP_MEMBER',
                'acl_table': 'ACL_TABLE', 'acl_group': 'ACL_GROUP', 'acl_group_counter': 'ACL_COUNTER',
                'acl_group_entry': "ACL_ENTRY"}
acl_family_list = ['acl_table', 'acl_group', 'acl_group_entry', 'acl_group_counter']


@pytest.fixture(scope='module', autouse=True)
def ft_crm_module_hooks(request):
    # add things at the start of this module
    global vars
    vars = st.ensure_min_topology("D1T1:2")
    ipfeature.clear_ip_configuration(vars.D1,family= "both")
    yield
    # add things at the end of this module'


@pytest.fixture(scope='function', autouse=True)
def ft_crm_func_hooks(request):
    # add things at the start every test case
    # use 'st.get_func_name(request)' to compare
    # if any thing specific a particular test case
    yield
    # add things at the end every test case
    # use 'st.get_func_name(request)' to compare
    # if any thing specific a particular test case


#################################################################################
#                 GENERIC IP ADDR API (can be imported with ipv6 lib)
#################################################################################
def increment_ip_addr(ipaddr, mask):
    s = ''
    if ipaddr.find('.') != -1:
        if mask == 31:
            valid_option, s = ipfeature.increment_ip_addr(ipaddr + '/' + str(mask), "host")
        else:
            valid_option, s = ipfeature.increment_ip_addr(ipaddr + '/' + str(mask), "network")
        s = s.split('/')[0]
        return valid_option, s

    valid_option = True
    if len(re.split('::', ipaddr)) == 2:
        cnt = 8 - len(re.split(':', ipaddr))
        pattern = ':0' + ':0' * cnt + ':'
        ipaddr = re.sub(r'::', pattern, ipaddr)
    ip_split = re.split(':', ipaddr)
    iphex = []

    i = 0
    while i < 8:
        ip_split[i] = '0x' + ip_split[i]
        iphex.append('0x0')
        i = i + 1
    revmask = 128 - mask

    iphex[7 - revmask / 16] = str(hex(pow(2, revmask % 16)))

    # Add 2 IP6 Addresses
    i = 7
    ans = []
    carry = 0
    while i >= 0:
        sum = (int(ip_split[i], 0) + int(iphex[i], 0) + carry)
        carry = 0
        if sum >= 0x10000:
            sum = sum % 0x10000
            carry = 1
        ans.append(':')
        ans.append(hex(sum)[2:])
        i = i - 1
    ans.reverse()
    s = s.join(ans)
    s = s[:-1]

    return valid_option, s


#################################################################################
#                          CRM SYSLOG
#################################################################################
def crm_clear_syslog(dut, maxretries=5, severity_type='WARNING', filters=[]):
    delay = 2
    for retry in range(0, maxretries):
        slog_obj.clear_logging(dut)
        st.log('crminfo: Waiting {} secs for syslog to be cleared.. retry {}\n'.format(delay, retry + 1))
        st.wait(delay)
        if not slog_obj.get_logging_count(dut, severity=severity_type, filter_list=filters):
            return True
    return False


def crm_verify_syslog(dut, resource_name, threshold_msg, threshold_type, threshold, resource_count_max):
    res = resource_str[resource_name]
    syslog_used_counter_offset = 7
    syslog_free_counter_offset = 10

    msglist = slog_obj.show_logging(dut, severity='WARNING', filter_list=threshold_msg)
    if len(msglist) <= 0:
        st.error('No {} {} {} detected in syslog'.format(resource_name, threshold_type, threshold_msg))
        return False

    found = 0
    for msg in msglist:
        if 'repeated' in msg:
            msg = msg.replace(']', ' ')
        words = msg.split()
        if res in words and words.index(res):
            found = 1
            used = int(words[words.index(res) + syslog_used_counter_offset])
            free = int(words[words.index(res) + syslog_free_counter_offset])
            st.log('crminfo: Msg: {} Used:{} Free:{} Type:{} val:{}'.
                   format(threshold_msg, used, free, threshold_type, threshold))

            if threshold_type == 'used':
                value = used
            elif threshold_type == 'free':
                value = free
            else:
                value = int(used * 100 / resource_count_max)

            if threshold_msg == 'THRESHOLD_EXCEEDED' and value < threshold:
                st.error('For {} val:{} should be less than Threshold:{}'.format(threshold_msg, value, threshold))
                return False

            if threshold_msg == 'THRESHOLD_CLEAR' and value > threshold:
                st.error('For {} val:{} should be more than Threshold:{}'.format(threshold_msg, value, threshold))
                return False

    if found == 0:
        st.error('{} for {} not detected in syslog'.format(threshold_msg, resource_name))
        return False
    return True


def crmlogPresent(family, threshold_msg, threshold_type, msglist=[], data=[]):
    lastmsg = ""
    pattern = resource_str[family] + " " + threshold_msg + " for " + threshold_type
    for msg in msglist:
        if pattern in msg:
            lastmsg = msg

    if lastmsg == "":
        return False
    else:
        print("LAST# :", lastmsg)
        return True


#################################################################################
#                 RESOURCE SPECIFIC APIs
#################################################################################
#####################      FDB          #########################################
def crm_fdb_config_clear(data=[]):
    st.log("Clear fdb configuration and delete mac entries")

    for i in range(0, 30):
        macapi.delete_mac(data.D1, '00:11:22:33:44:' + str(10 + i), data.vlanid)


def crm_fdb_config(data=[]):
    st.log("Create vlan and add ports to vlan")
    portList = st.get_all_ports(data.D1)
    vapi.create_vlan(data.D1, data.vlanid)
    vapi.add_vlan_member(data.D1, data.vlanid, portList[5], tagging_mode=True)
    for i in range(0, 30):
        macapi.config_mac(data.D1, '00:11:22:33:44:' + str(10 + i), data.vlanid, portList[5])


def crm_fdb_send_traffic(data=[]):
    st.log("Config mac addresss to interface")
    portList = st.get_all_ports(data.D1)
    for i in range(0, 30):
        macapi.config_mac(data.D1, '00:11:22:33:44:' + str(10 + i), data.vlanid, portList[5])


#####################      BGPv4        #########################################
def tgen_bgpv4(local_asn, remote_asn, data=[]):
    tg_port = data.dut_p1
    intf_ip_addr = data.dut_p1_ipaddr_peer
    gateway = data.dut_p1_ipaddr
    count = data.neighbor_cnt
    num_routes = data.adv_routes_cnt
    prefix = data.adv_routes_prefix

    local_asn = data.local_asn
    remote_asn = data.remote_asn

    handles = tgapi.get_handles(vars, [tg_port])
    tg1, tg_ph_1 = handles["tg1"], handles["tg_ph_1"]

    tg1.tg_traffic_control(action='reset', port_handle=tg_ph_1)
    h1 = tg1.tg_interface_config(port_handle=tg_ph_1, mode='config', intf_ip_addr=intf_ip_addr, gateway=gateway,
                                 netmask='255.255.0.0',
                                 src_mac_addr='00:0a:01:00:00:01', arp_send_req='1', count=count,
                                 gateway_step='0.0.0.0')
    st.log("Config Ixia for v4 route ")
    bgp_conf = tg1.tg_emulation_bgp_config(handle=h1['handle'][0], mode='enable', active_connect_enable='1',
                                           local_as=remote_asn, remote_as=local_asn, remote_ip_addr=gateway)
    tg1.tg_emulation_bgp_route_config(handle=bgp_conf['handle'], mode='add', num_routes=num_routes,
                                      prefix=prefix,as_path='as_seq:1')
    tg1.tg_emulation_bgp_control(handle=bgp_conf['handle'], mode='start')

def dut_bgpv4(local_asn, remote_asn, data=[]):
    st.log("Creating the ipv4 routing interfaces in {}".format(data.D1))

    ipfeature.config_ip_addr_interface(data.D1, data.dut_p1_interface, data.dut_p1_ipaddr, data.dut_p1_ipaddr_subnet,
                                       family="ipv4")
    if not ipfeature.verify_interface_ip_address(data.D1, data.dut_p1_interface,
                                                 data.dut_p1_ipaddr + '/' + str(data.dut_p1_ipaddr_subnet),
                                                 family="ipv4"):
        st.report_fail('ip_routing_int_create_fail', data.dut_p1_ipaddr)

    bgp_obj.create_bgp_router(data.D1, data.local_asn, data.router_id_1)
    bgp_obj.create_bgp_neighbor(dut=data.D1, local_asn=data.local_asn, neighbor_ip=data.dut_p1_ipaddr_peer,
                                remote_asn=data.remote_asn, family="ipv4")
    st.log("Waiting for the eBGP neighbors to get Established")
    st.wait(10)
    #if not poll_wait(bgp_obj.verify_bgp_summary, 60, data.D1, family="ipv4", shell=data.shell_sonic,
     #                neighbor=data.dut_p1_ipaddr_peer, state='Established', asn=data.remote_asn):
     #   st.log('bgp_ip_peer_establish_fail {}'.format(data.dut_p1_ipaddr_peer))


#####################      BGPv6        #########################################
def tgen_bgpv6(local_asn, remote_asn, data=[]):
    tg_port = data.dut_p2
    intf_ip_addr = data.dut_p2_ipaddr_peer
    gateway = data.dut_p2_ipaddr
    count = data.neighbor_cnt_v6
    num_routes = data.adv_routes_cnt_v6
    prefix = data.adv_routes_prefix_v6

    local_asn = data.local_asn
    remote_asn = data.remote_asn

    handles = tgapi.get_handles(vars, [tg_port])
    tg1, tg_ph_1 = handles["tg1"], handles["tg_ph_1"]

    tg1.tg_traffic_control(action='reset', port_handle=tg_ph_1)
    h1 = tg1.tg_interface_config(port_handle=tg_ph_1, mode='config', ipv6_intf_addr=intf_ip_addr,
                                 ipv6_prefix_length='64', ipv6_gateway=gateway,
                                 src_mac_addr='00:0a:01:00:00:01',
                                 arp_send_req='1', count=count, ipv6_gateway_step='0:0:0:0:0:0:0:0')
    st.log("Config Ixia for v4 route ")
    bgp_conf = tg1.tg_emulation_bgp_config(handle=h1['handle'][0], mode='enable', ip_version='6', \
                                           active_connect_enable='1', local_as=remote_asn, \
                                           remote_as=local_asn, remote_ipv6_addr=gateway)
    tg1.tg_emulation_bgp_route_config(handle=bgp_conf['handle'], mode='add', ip_version='6',
                                      num_routes=num_routes, prefix=prefix, as_path='as_seq:1')
    tg1.tg_emulation_bgp_control(handle=bgp_conf['handle'], mode='start')

def dut_bgpv6(local_asn, remote_asn, data=[]):
    st.log("Creating the ipv6 routing interfaces in {}".format(vars.D1))
    ipfeature.config_ip_addr_interface(data.D1, data.dut_p2_interface, data.dut_p2_ipaddr, data.dut_p2_ipaddr_subnet,
                                       family="ipv6")
    if not ipfeature.verify_interface_ip_address(data.D1, data.dut_p2_interface,
                                                 data.dut_p2_ipaddr + '/' + str(data.dut_p2_ipaddr_subnet),
                                                 family="ipv6"):
        st.report_fail('ip6_routing_int_create_fail', data.dut_p2_ipaddr)

    bgp_obj.create_bgp_router(data.D1, data.local_asn, data.router_id_1)
    bgp_obj.create_bgp_neighbor(dut=data.D1, local_asn=data.local_asn, neighbor_ip=data.dut_p2_ipaddr_peer,
                                remote_asn=data.remote_asn, family="ipv6")
    st.log("Waiting for the ecrm_bgp_config_v6 neighbors to get Established")
    st.wait(10)
    #if not poll_wait(bgp_obj.verify_bgp_summary, 60, data.D1, family="ipv6", shell=data.shell_sonic,
    #                 neighbor=data.dut_p2_ipaddr_peer, state='Established', asn=data.remote_asn):
    #    st.log('bgp_ip_peer_establish_fail {}'.format(data.dut_p2_ipaddr_peer))


def crm_bgp_config_v4(local_asn, remote_asn, data=[]):
    tgen_bgpv4(local_asn, remote_asn, data=data)
    dut_bgpv4(local_asn, remote_asn, data=data)


def crm_bgp_config_v6(local_asn, remote_asn, data=[]):
    tgen_bgpv6(local_asn, remote_asn, data=data)
    dut_bgpv6(local_asn, remote_asn, data=data)


#####################      ECMP         #########################################
def crm_ecmp_config(data=[]):
    route = "200.0.0.0"
    partner_base2 = "7.7.7.2"
    stroute = route
    for _ in range(0, 4):
        _, stroute = increment_ip_addr(stroute, data.routing_subnet)
        _, partner_base2 = increment_ip_addr(partner_base2, 31)
        partner = partner_base2
        for _ in range(0, 50):
            _, partner = increment_ip_addr(partner, 31)
            ipfeature.create_static_route(data.D1, static_ip="{}/{}".format(stroute, data.routing_subnet),
                                          next_hop=partner)


#####################      ACL          #########################################
def crm_acl_unconfig(data=[]):
    acl_obj.show_ip_access_list(data.D1)
    tables = ["ACL_TABLE0","ACL_TABLE1"]
    for table in tables:
        acl_obj.delete_acl_table(data.D1, acl_table_name= table,acl_type='ip')
    acl_obj.show_ip_access_list(data.D1)


def add_port_to_acl_table(config, table_name, port):
    config['ACL_TABLE'][table_name]['ports'] = []
    config['ACL_TABLE'][table_name]['ports'].append(port)

def crm_acl_config(data=[]):
    acl_config = acl_data.acl_json_config_crm
    add_port_to_acl_table(acl_config, 'ACL_TABLE0', vars.D1T1P1)
    add_port_to_acl_table(acl_config, 'ACL_TABLE1', vars.D1T1P2)
    acl_obj.apply_acl_config(data.D1, acl_config)
    acl_obj.show_ip_access_list(data.D1)

#################################################################################
#                          CRM VERIFY THREHOLDS and GENERATE TEST RESULTS
#################################################################################
def verify_thresholds(data=[]):
    max_threshold = 999999
    var_delay = 2
    opt_delay = 2
    clear_wait = 8
    final_wait = 20
    mymode = ""
    family_list = crm_obj.crm_get_family_list(data.D1)
    for family in family_list:
        if family != 'all':
            (data.used_counter[family], data.free_counter[family]) = crm_obj.crm_get_resources_count(data.D1, family)
            data.resource_count_max[family] = data.used_counter[family] + data.free_counter[family]
            st.log("verify_thresholds: {} used {} free {} max {}".format(family,
                     data.used_counter[family], data.free_counter[family], data.resource_count_max[family]))
    ##################### USED #############################
    for family in family_list:
        if family != 'all':
            crm_obj.set_crm_thresholds_type(data.D1, family=family, type="used")
            crm_obj.set_crm_thresholds_value(data.D1, family=family, mode="high", value=max_threshold)
            crm_obj.set_crm_thresholds_value(data.D1, family=family, mode="low", value=max_threshold)

    #show logs
    st.log("show log messages:")
    slog_obj.show_logging(data.D1,lines=50)
    # Clear Logs
    slog_obj.clear_logging(data.D1)

    st.log("configure Thresholds for used")
    for family in family_list:
        if family != 'all':
            hi_th = data.used_counter[family] - 1
            if hi_th < 0:
                hi_th = 0
            mymode = "high"
            if family in acl_family_list:
                mymode = "low"
            crm_obj.set_crm_thresholds_value(data.D1, family=family, mode=mymode, value=hi_th)
            mymode = "low"
            if family in acl_family_list:
                mymode = "high"

            low_th = hi_th - 1
            if low_th < 0:
                low_th = 0
            #crm_obj.set_crm_thresholds_type(data.D1, family=family, type="used")
            crm_obj.set_crm_thresholds_value(data.D1, family=family, mode=mymode, value=low_th)
            crm_obj.set_crm_thresholds_type(data.D1, family=family, type="used")
    st.wait(opt_delay)  ## EXCEED
    st.wait(var_delay)  ## EXCEED
    crm_obj.get_crm_resources(data.D1, "all")
    interface_obj.interface_shutdown(data.D1, data.dut_p1_interface, skip_verify=False)
    interface_obj.interface_shutdown(data.D1, data.dut_p2_interface, skip_verify=False)
    macapi.clear_mac(data.D1)
    crm_fdb_config_clear(data)
    st.wait(opt_delay)  ## CLEAR

    # Restore
    interface_obj.interface_noshutdown(data.D1, data.dut_p1_interface, skip_verify=False)
    interface_obj.interface_noshutdown(data.D1, data.dut_p2_interface, skip_verify=False)
    st.wait(opt_delay)  # delay is required to populate tables

    ##################### PERCENTAGE #############################
    for family in family_list:
        if family != 'all':
            crm_obj.set_crm_thresholds_value(data.D1, family=family, mode="high", value=max_threshold)
            crm_obj.set_crm_thresholds_value(data.D1, family=family, mode="low", value=max_threshold)
    crm_fdb_send_traffic(data)
    st.log("Configure Thresholds for percentage")
    for family in family_list:
        if family != 'all' and family != 'snat' and family != 'dnat' and family != 'ipmc':
            hi_th = 0
            mymode = "high"
            crm_obj.set_crm_thresholds_value(data.D1, family=family, mode=mymode, value=hi_th)
            mymode = "low"
            low_th =  100
            #crm_obj.set_crm_thresholds_type(data.D1, family=family, type="percentage")
            crm_obj.set_crm_thresholds_value(data.D1, family=family, mode=mymode, value=low_th)
            crm_obj.set_crm_thresholds_type(data.D1, family=family, type="percentage")
    st.wait(opt_delay)  ## EXCEED
    st.wait(var_delay)  ## EXCEED
    crm_obj.get_crm_resources(data.D1, "all")
    crm_acl_unconfig(data)
    crm_acl_config(data)
    interface_obj.interface_shutdown(data.D1, data.dut_p1_interface, skip_verify=False)
    interface_obj.interface_shutdown(data.D1, data.dut_p2_interface, skip_verify=False)
    macapi.clear_mac(data.D1)
    crm_fdb_config_clear(data)
    st.wait(opt_delay)  ## CLEAR
    st.wait(var_delay)  ## EXCEED

    ##################### FREE #############################
    crm_obj.get_crm_resources(data.D1, "all")
    for family in family_list:
        if family != 'all':
            crm_obj.set_crm_thresholds_type(data.D1, family=family, type="used")
            crm_obj.set_crm_thresholds_value(data.D1, family=family, mode="high", value=max_threshold)
            crm_obj.set_crm_thresholds_value(data.D1, family=family, mode="low", value=max_threshold)
    st.wait(clear_wait)
    st.log("configure Thresholds for free")
    for family in family_list:
        if family != 'all':
            mymode = "high"
            hi_th = 0
            crm_obj.set_crm_thresholds_value(data.D1, family=family, mode=mymode, value=hi_th)
            mymode = "low"
            low_th = max_threshold
            #crm_obj.set_crm_thresholds_type(data.D1, family=family, type="free")
            crm_obj.set_crm_thresholds_value(data.D1, family=family, mode=mymode, value=low_th)
            crm_obj.set_crm_thresholds_type(data.D1, family=family, type="free")

    st.wait(opt_delay)  ## EXCEED
    crm_obj.get_crm_resources(data.D1, "all")
    interface_obj.interface_noshutdown(data.D1, data.dut_p1_interface, skip_verify=False)
    interface_obj.interface_noshutdown(data.D1, data.dut_p2_interface, skip_verify=False)
    crm_fdb_send_traffic(data)
    # CLEAR TH
    st.wait(final_wait)  ## CLEAR
    if not poll_wait(check_logging_result, 60, data):
        crm_obj.get_crm_resources(data.D1, "all")
        st.error('Failed to get threshold logs, CRM threshold tests failed')


def check_logging_result(data=[]):
    st.log('Checking logging result')
    msglist = slog_obj.show_logging(data.D1, severity='WARNING', filter_list=["THRESHOLD"])
    global crm_test_result
    family_list = crm_obj.crm_get_family_list(data.D1)
    for family in family_list:
        crm_test_result[family] = 0
        if family != 'all':
            if crmlogPresent(family, "THRESHOLD_EXCEEDED", "TH_USED", msglist=msglist, data=data):
                crm_test_result[family] += 1
                st.log("Successsfully generated max thresholds for [{}] used".format(family))
            else:
                st.error("Failed to create max thresholds for [{}] used".format(family))
            if crmlogPresent(family, "THRESHOLD_CLEAR", "TH_USED", msglist=msglist, data=data):
                crm_test_result[family] += 1
                st.log("Successsfully generated minimum thresholds for [{}] used".format(family))
            else:
                st.error("Failed to create minimum thresholds for [{}] used".format(family))
            if crmlogPresent(family, "THRESHOLD_EXCEEDED", "TH_PERCENTAGE", msglist=msglist, data=data):
                crm_test_result[family] += 1
                st.log("Successsfully generated max thresholds for [{}] percentage".format(family))
            else:
                st.error("Failed to create max thresholds for [{}] percentage".format(family))

            if crmlogPresent(family, "THRESHOLD_CLEAR", "TH_PERCENTAGE", msglist=msglist, data=data):
                crm_test_result[family] += 1
                st.log("Successsfully generated minimum thresholds for [{}] percentage".format(family))
            else:
                st.error("Failed to create minimum thresholds for [{}] percentage".format(family))
            if crmlogPresent(family, "THRESHOLD_EXCEEDED", "TH_FREE", msglist=msglist, data=data):
                crm_test_result[family] += 1
                st.log("Successsfully generated max thresholds for [{}] free".format(family))
            else:
                st.error("Failed to create max thresholds for [{}] free".format(family))
            if crmlogPresent(family, "THRESHOLD_CLEAR", "TH_FREE", msglist=msglist, data=data):
                crm_test_result[family] += 1
                st.log("Successsfully generated minimum thresholds for [{}] free".format(family))
            else:
                st.error("Failed to create minimum thresholds for [{}] free".format(family))
    for family in family_list:
        if check_test_status(family):
            st.wait(5)
            return False
    return True


def check_test_status(family):
    global crm_test_result
    if family != "all":
        if family not in crm_test_result:
            st.log("Test [{}] NOT Executed".format(family))
            return family
        elif crm_test_result[family] == 6:
            st.log("Test [{}] PASSED".format(family))
            st.log("Successfully generated threshold logs for [{}]".format(family))
            return None
        else:
            slog_obj.show_logging(vars.D1, lines=100)
            st.log("Test [{}] FAILED [{}]".format(family, crm_test_result[family]))
            st.log("Failed to generate threshold logs for [{}]".format(family))
            return family
    else:
        return None


#################################################################################
#                          CRM TEST MAIN
#################################################################################
def crm_ft_test_all():
    data = SpyTestDict()
    data.my_dut_list = st.get_dut_names()
    if len(data.my_dut_list) < 1:
        st.error("DUT Unavailable")
        return False
    data.D1 = data.my_dut_list[0]
    data.fdb_count = 0
    data.crm_polling_interval = 1
    crm_obj.set_crm_clear_config(data.D1)
    crm_obj.set_crm_polling_interval(data.D1, data.crm_polling_interval)
    data.af_ipv4 = "ipv4"
    data.af_ipv6 = "ipv6"
    data.local_asn = 65001
    data.router_id_1 = "110.110.110.1"
    data.router_id_2 = "120.120.120.1"
    data.remote_asn = 65007
    data.loopback_1 = "66.66.66.66"
    data.loopback_2 = "77.77.77.77"
    data.tg_bgp6_route_prfix = "1001::1"
    data.tg_bgp6_routes = '1100'
    data.shell_sonic = 'vtysh'
    data.used_counter = dict()
    data.free_counter = dict()
    data.resource_count_max = dict()
    data.thresh_percent_low = dict()
    data.thresh_percent_high = dict()
    data.thresh_used_low = dict()
    data.thresh_used_high = dict()
    data.thresh_free_low = dict()
    data.thresh_free_high = dict()
    data.cur_thresh_type = dict()
    data.cli_type = st.get_ui_type(data.D1)
    family_list = crm_obj.crm_get_family_list(data.D1)
    if base_obj.get_hwsku(vars.D1).lower() in vars.constants[vars.D1]["TH3_PLATFORMS"]:
        for family in family_list:
            if family in  ['dnat','snat']:
                family_list.remove(family)
    st.log("Verify CRM polling interval:")
    st.wait(data.crm_polling_interval)
    if not crm_obj.verify_crm_summary(data.D1, pollinginterval=data.crm_polling_interval):
        st.error('polling interval did not match with the configured value')
        return False

    st.log("Calculate Max resources:")
    for family in family_list:
        if family != 'acl_group_counter' and family != 'acl_group_entry' and family != 'all':
            (data.used_counter[family], data.free_counter[family]) = crm_obj.crm_get_resources_count(data.D1, family)
            data.resource_count_max[family] = data.used_counter[family] + data.free_counter[family]

    for family in family_list:
        if family != 'acl_group_counter' and family != 'acl_group_entry' and family != 'all':
            st.log('{}  {}/{}/{}'.format(family, data.used_counter[family], data.free_counter[family],
                                         data.resource_count_max[family]))

    data.routing_subnet = 24
    data.dut_p1 = vars.T1D1P1
    data.dut_p1_interface = vars.D1T1P1
    data.dut_p1_ipaddr = '7.7.7.1'
    data.dut_p1_ipaddr_subnet = 24
    data.dut_p1_ipaddr_peer = '7.7.7.2'
    data.adv_routes_cnt = 1000
    data.adv_routes_prefix = "100.0.0.0"
    data.neighbor_cnt = 100
    data.dut_p2 = vars.T1D1P2
    data.dut_p2_interface = vars.D1T1P2
    data.dut_p2_ipaddr = '2001::1'
    data.dut_p2_ipaddr_subnet = 64
    data.dut_p2_ipaddr_peer = '2001::2'
    data.adv_routes_cnt_v6 = 1000
    data.adv_routes_prefix_v6 = '2121::0'
    data.neighbor_cnt_v6 = 100
    data.vlanid = 777
    st.log('crminfo: VLAN ID {}'.format(data.vlanid))
    crm_fdb_config(data)

    crm_acl_config(data)
    crm_bgp_config_v4(data.local_asn, data.remote_asn, data)
    crm_ecmp_config(data)
    if st.is_feature_supported("config-ipv6-command", data.D1):
        crm_bgp_config_v6(data.local_asn, data.remote_asn, data)
    verify_thresholds(data)

    # debug trace
    crm_obj.get_crm_resources(data.D1, "all")

    global crm_test_status
    crm_test_status = True


#################################################################################
#                          CRM TEST LIST
#################################################################################

def crm_ft_verify(*args):
    global crm_test_status
    if not crm_test_status:
        crm_ft_test_all()

    retval = None
    for family in args:
        rv = check_test_status(family)
        if rv: retval = rv

    if not retval:
        st.report_pass('operation_successful')
    else:
        st.report_fail("threshold_no_logs", retval)

@pytest.mark.crm_ft_tests123
def test_ft_crm_fdb():
    crm_ft_verify("fdb")

@pytest.mark.crm_ft_tests
def test_ft_crm_route_v4():
    crm_ft_verify("ipv4_route")

@pytest.mark.crm_ft_tests
def test_ft_crm_route_v6():
    crm_ft_verify("ipv6_route")

@pytest.mark.crm_ft_tests
def test_ft_crm_neighbor_v4():
    crm_ft_verify("ipv4_neighbor")

@pytest.mark.crm_ft_tests
def test_ft_crm_neighbor_v6():
    crm_ft_verify("ipv6_neighbor")

@pytest.mark.crm_ft_tests
def test_ft_crm_nexthop_v4():
    crm_ft_verify("ipv4_nexthop")

@pytest.mark.crm_ft_tests
def test_ft_crm_nexthop_v6():
    crm_ft_verify("ipv6_nexthop")

@pytest.mark.crm_ft_tests
def test_ft_crm_nhop_group_member():
    crm_ft_verify("nexthop_group_member")

@pytest.mark.crm_ft_tests
def test_ft_crm_nhop_group():
    crm_ft_verify("nexthop_group_object")

@pytest.mark.crm_ft_tests
def test_ft_crm_acl_table():
    crm_ft_verify("acl_table")

@pytest.mark.crm_ft_tests
def test_ft_crm_acl_entry():
    crm_ft_verify("acl_group_entry")

@pytest.mark.crm_ft_tests
def test_ft_crm_acl_counter():
    crm_ft_verify("acl_group_counter")

@pytest.mark.crm_ft_tests
def test_ft_crm_acl_group():
    crm_ft_verify("acl_group")
