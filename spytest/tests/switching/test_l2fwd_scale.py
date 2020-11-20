##########################################################################################
# Title: L2 Forwarding Enhancements Script
# Author1: Sneha Ann Mathew <sneha.mathew@broadcom.com>
# Author2: Nagappa Chincholi <nagappa.chincholi@broadcom.com>
##########################################################################################

import pytest
import time
import datetime

from spytest import st, tgapi, SpyTestDict, utils

import apis.switching.vlan as vlan_obj
import apis.routing.ip as ip_obj
import apis.switching.mac as mac_obj
import apis.system.port as port_obj
import apis.system.interface as intf_obj
import apis.system.reboot as boot_obj
import apis.switching.portchannel as po_obj
import apis.system.basic as basic_obj
import apis.switching.stp as stp_obj
import apis.switching.pvst as pvst_obj
import apis.common.asic as asicapi

import utilities.common as utils
import utilities.parallel as pll

###Resource file variables
data = SpyTestDict()
# Platform specific MAC scale numbers - PLEASE EDIT - Add missing platforms .
data.l2_mac_scale_mapping = {'Accton-AS7712-32X' : 136000,
                             'Accton-AS7816-64X' : 256000,
                             'Accton-AS7326-56X' : 288000,
                             'Force10-S6000': 288000}

data.l2_mac_scale_mapping = {'Accton-AS7712-32X' : 129200,
                             'Accton-AS7816-64X' : 256000,
                             'Accton-AS7326-56X' : 273600,
                             'Force10-S6000': 288000}

data.l3_mac_scale_mapping = {'Accton-AS7712-32X' : 38000,
                             'Accton-AS7816-64X' : 38000,
                             'Accton-AS7326-56X' : 38000,
                             'Force10-S6000': 16000}

data.warmreboot_supported_platforms = {'Accton-AS7712-32X'}

### Tgen params
data.tgen_rate_pps = '1000'
data.tgen_rate_stp = '500'
data.traffic_run_time = 120
data.counters_threshold = 5 * data.traffic_run_time
#data.traffic_run_time_stp = 20
po_reconfig_flag = 0

test_po_links = 2
po_link_min_req = 2

### L2/L3 profile params
data.l2_prof_vlan_flag = 1

### MAC table verification
data.mac_chk_iter = 20
data.mac_chk_wait = 3
data.mac_age_wait_time = 150
data.default_macage = 0
data.mac_aging = 80

### Number of Access ports
data.access_port_count = 1
data.base_vlan = 1

### Number of Trunk Ports
data.trunk_port_count = 1
data.trunk_vlan_count = 500

### Maximum Number of LAGs
data.max_lag_count = 64

### Number of Trunk LAGs and number of links in each LAG
data.lagA_count = 1
data.lagA_link_count = 2

### Number of Access LAGs and number of links in each LAG
data.lagT_count = 1
data.lagT_link_count = 2

data.strm_mac_count = 50
data.static_mac_count = 10
data.ip_count = 5
#data.total_mac_count = 20470
data.total_mac_count = 4094
data.common_mac_scale = 4094
data.mac_count_check = (data.total_mac_count * 2) + data.static_mac_count

data.total_vlan_count = 2000

data.warm_reboot_dut = ""
data.tc_specific_vlan = 4001
data.tc_specific_vlan_count = 6
data.tc_specific_mac_count = 6
data.tc_specific_vlan_range = str(data.tc_specific_vlan) + ' ' + str(data.tc_specific_vlan + data.tc_specific_vlan_count - 1)

data.mac_scale_list = []
data.verify_mac_scale = []

def initialize_dut_mac_scale_variables():

    platform_list = []
    if basic_obj.get_config_profiles(data.my_dut_list[0]) == 'l2':
        mac_scale_mapping = data.l2_mac_scale_mapping
        utils.exec_all(True, [[del_vlan1_mem_ports, dut] for dut in data.my_dut_list])
        utils.exec_all(True, [[pvst_obj.config_spanning_tree, dut, "pvst", "disable"] for dut in data.my_dut_list])
        data.mac_chk_iter = 20
        data.mac_chk_wait = 5
    else:
        mac_scale_mapping = data.l3_mac_scale_mapping

    for dut in data.my_dut_list:
        platform_list.append(basic_obj.get_hwsku(dut))

    for key, value in sorted(mac_scale_mapping.items(), key=lambda item: item[1]):
        st.log("%s: %s" % (key, value))
        if key in platform_list:
            data.common_mac_scale = value
            st.log("setting data.common")
            break
    data.total_mac_count = ((data.common_mac_scale / 2) // (data.total_vlan_count - 1)) * (data.total_vlan_count -1)
    data.mac_count_check = (data.total_mac_count * 2) + data.static_mac_count
    flag = 0
    for platform in platform_list:
        for key,value in mac_scale_mapping.items():
            if key in platform:
                data.mac_scale_list.append(value)
                flag = 1
        if flag == 0: data.mac_scale_list.append(data.common_mac_scale)
        flag = 0
    print_log("======= DUT Lowest MAC count=================")
    print_log(data.common_mac_scale)
    print_log("======= DUT MAC LIST=================")
    print_log(data.mac_scale_list)


def print_log(message,alert_type="LOW"):
    '''
    Uses st.log procedure with some formatting to display proper log messages
    :param message: Message to be printed
    :param alert_level:
    :return:
    '''
    log_start = "\n======================================================================================\n"
    log_end =   "\n======================================================================================"
    log_delimiter ="\n###############################################################################################\n"

    if alert_type == "HIGH":
        st.log("{} {} {}".format(log_delimiter,message,log_delimiter))
    elif alert_type == "MED":
        st.log("{} {} {}".format(log_start,message,log_end))
    elif alert_type == "LOW":
        st.log(message)
    elif alert_type == "ERROR":
        st.error("{} {} {}".format(log_start,message,log_start))

def retry_func(func,**kwargs):
    retry_count = kwargs.get("retry_count", 3)
    delay = kwargs.get("delay", 2)
    if 'retry_count' in kwargs: del kwargs['retry_count']
    if 'delay' in kwargs: del kwargs['delay']
    for i in range(retry_count):
        st.log("Attempt %s of %s" %((i+1),retry_count))
        if kwargs.keys() == []:
            if func():
                return True
        else:
            if func(**kwargs):
                return True
        if retry_count != (i+1):
            st.log("waiting for %s seconds before retyring again"%delay)
            st.wait(delay)
    return False


def retry_parallel(func,dict_list=[],dut_list=[],retry_count=3,delay=2):
    for i in range(retry_count):
        st.log("Attempt %s of %s" %((i+1),retry_count))
        result = pll.exec_parallel(True,dut_list,func,dict_list)
        if False not in result[0]:
            return True
        if retry_count != (i+1):
            st.log("waiting for %s seconds before retyring again"%delay)
            st.wait(delay)
    return False


def lag_scale_links_check():
    d1 = data.my_dut_list[0]
    total_links = data.access_port_count + data.trunk_port_count + \
                  (data.lagT_count * data.lagT_link_count) + (data.lagA_count * data.lagA_link_count)
    dut_link_list = []
    for dut in data.my_dut_list[1:]:
        dut_link_list.append(len(st.get_dut_links_local(d1, peer=dut)))
        d1 = dut
    diff_links = min(dut_link_list) - total_links
    data.lagT_count = data.lagT_count + (diff_links // data.lagT_link_count)


def del_vlan1_mem_ports(dut,config="del"):
    mem_ports = st.get_dut_links(dut) + st.get_tg_links(dut)
    ports = []

    for p in mem_ports : ports.append(p[0])
    try:
        for p in ports:
            vlan_obj.config_vlan_members(dut,1,p,config=config)
    except Exception as e1:
        print_log(e1)
        data.l2_prof_vlan_flag = 0

def initialize_topology():
    global vars

    data.memory_usage = []
    data.cpu_orchagt = []
    data.cpu_syncd = []
    data.cpu_vland = []
    data.cpu_teamd = []

    vars = st.get_testbed_vars()
    ### Verify Minimum topology requirement is met
    total_links = data.access_port_count + data.trunk_port_count + \
                  (data.lagT_count * data.lagT_link_count) + (data.lagA_count * data.lagA_link_count)
    st.ensure_min_topology("D1D2:{}".format(total_links), "D1T1:2", "D2T1:2")
    ### Seeing few TC failures with 4 node run.Keeping topology to be 2 node till fix is in.
    data.dut_list = st.get_dut_names()
    data.my_dut_list = [data.dut_list[0], data.dut_list[1]]
    print_log("Start Test with minimum topology D1D2:links=>{}-{}:{}".format(data.my_dut_list[0], data.my_dut_list[1],
                                                                             total_links),
              'HIGH')

    print_log(
        "Test Topology Description\n==============================\n\
        Test script uses a linear topology TGN1---D1---D2--------Dn-1---Dn---TGNn.\n\
        Between each pair of DUTs, 4 types of links will be there: 1) untagged ethernet 2) tagged ethernet 3) tagged PO & 4) untagged PO\n\
        There will be 4 streams send from D1 to Dn which is supposed to forward on these 4 types of links (may forward on different links based on TC triggers)\n\
        Stream1: 00:12:AA:00:00:xx ---------- 00:21:AA:00:00:xx to be forwarded across the untagged ethernet link [X macs in single vlan]\n\
        Stream2: 00:12:BB:00:00:xx ---------- 00:21:BB:00:00:xx to be forwarded across the tagged ethernet link [1 mac each in X vlans]\n\
        Stream3: 00:12:CC:00:00:xx ---------- 00:21:CC:00:00:xx to be forwarded across the tagged portchannel [1 mac each in X vlans]\n\
        Stream4: 00:12:DD:00:00:xx ---------- 00:21:DD:00:00:xx to be forwarded across the untagged portchannel [X macs in single vlan]\n\
        Apart from above basic configs, each test case will have trigger configs/unconfigs and corresponding streams used",
        'HIGH')

    lag_scale_links_check()
    data.default_macage = mac_obj.get_mac_agetime(data.my_dut_list[0])
    ###Initialize base vlans for each type of links
    data.base_access_vlan = data.base_vlan
    data.base_trunk_vlan = data.base_vlan + data.access_port_count
    data.base_lagA_vlan = data.base_trunk_vlan + (data.trunk_port_count * data.trunk_vlan_count)
    data.base_lagT_vlan = data.base_lagA_vlan + data.lagA_count
    data.lagT_vlan_count = (data.total_vlan_count - 1 - (data.trunk_vlan_count * data.trunk_port_count) - data.access_port_count - data.lagA_count - 1) / data.lagT_count

    ###Initialize a dictionary of TGEN ports
    dut1 = data.my_dut_list[0]
    dut2 = data.my_dut_list[-1]
    data.tgen_port = {dut1: st.get_tg_links(dut1)[1][0],
                      dut2: st.get_tg_links(dut2)[1][0]}

    ### TC Validations will be done in first and last DUTs
    data.ver_dut_list = [data.my_dut_list[0],data.my_dut_list[1]]

    # Expected total mac counts on each dut
    data.stream_count = 4
    dut_base_mac_count = data.stream_count * data.strm_mac_count
    data.dut_mac_count_list = [2 * dut_base_mac_count for i in range(len(data.ver_dut_list))]
    data.counters_threshold = (int(data.tgen_rate_pps) * data.traffic_run_time * data.stream_count / 100) + (
                data.traffic_run_time * data.stream_count)
    ### Initialize TGEN handles
    get_tgen_handles()
    initialize_dut_mac_scale_variables()

def validate_topology():
    # Enable all links in the topology and verify links up
    dut_port_dict = {}
    for dut in data.my_dut_list:
        port_list = st.get_dut_links_local(dut, peer=None, index=None)
        dut_port_dict[dut] = port_list
    #Usage: exec_all(use_threads, list_of_funcs)
    [result, exceptions] = utils.exec_all(True, [[intf_obj.interface_operation, dut, dut_port_dict[dut], 'startup',False]
                                          for dut in dut_port_dict.keys()])
    if not all(i is None for i in exceptions):
        print_log(exceptions)
    return False if False in result else True


@pytest.fixture(scope="module",autouse=True)
def prologue_epilogue():
    print_log("Starting to initialize and validate topology...",'MED')

    initialize_topology()
    disable_ipv6()
    #validate_topology()
    print_log("Starting Base Configurations...",'MED')
    l2fwd_base_config()
    #Temp added sleep for config stability
    st.wait(120)
    #Temp added sleep for config stability
    l2fwd_base_traffic_config()
    l2fwd_basic_validations()
    yield
    print_log("Starting Base UnConfigurations...",'MED')
    l2fwd_base_unconfig()
    l2fwd_base_traffic_unconfig()
    enable_ipv6()



def l2fwd_basic_validations():
    '''
    1.    Verify PO summary.
    2.    Verify vlan table.
    '''

    ### Verify all the LAGs configured in the topology is up
    res_flag = True
    vlan_fail = 0
    po_fail = 0
    if not verify_po_state(data.portchannel.keys(),state='up'):
        res_flag = False
        po_fail += 1
        print_log("PortChannel State verification FAILED", "HIGH")
    else:
        print_log("PortChannel State verification PASSED", "HIGH")

    ### Create a list of total vlan count with length equal to number of duts in topology
    [result,exceptions] = utils.exec_all(True,[[verify_vlan_members,dut,data.total_vlan_count] for dut in data.my_dut_list])
    if not all(i is None for i in exceptions):
        print_log(exceptions)
    if False in result:
        print_log("VLAN Table verification FAILED", "HIGH")
        vlan_fail += 1
        res_flag = False
    else:
        print_log("VLAN Table verification PASSED", "HIGH")

    if not res_flag:
        fail_msg = ''
        if vlan_fail > 0:
            fail_msg += 'Vlan count Failed:'
        if po_fail > 0:
            fail_msg += 'PortChannel not UP:'
        st.report_fail("test_case_failure_message", fail_msg.strip(':'))
        #st.report_fail("operation_failed")


def disable_ipv6():
    print_log("Disabling IPv6 Globally to avoid System MAC learned for Ipv6 link local neighbors",'MED')
    utils.exec_all(True,[[ip_obj.config_ipv6, dut,'disable'] for dut in data.my_dut_list])
    #utils.exec_all(True, [[ip_obj.show_ipv6, dut] for dut in data.my_dut_list])


def enable_ipv6():
    print_log("Reverting IPv6 Global configuration", 'MED')
    utils.exec_all(True,[[ip_obj.config_ipv6, dut,'enable'] for dut in data.my_dut_list])
    #utils.exec_all(True, [[ip_obj.show_ipv6, dut] for dut in data.my_dut_list])


def configure_portchannel(dut1, dut2, po_id, vlan, dut1_po_members, dut2_po_members, min_links=None):
    if min_links == None:
        utils.exec_all(True, [[po_obj.create_portchannel, dut1, po_id], [po_obj.create_portchannel, dut2, po_id]])
    else:
        utils.exec_all(True, [[po_obj.create_portchannel, dut1, po_id, False, min_links],
                              [po_obj.create_portchannel, dut2, po_id, False, min_links]])

    if len(dut1_po_members) != len(dut2_po_members):
        st.error("Mismatch in number of portchannel member ports between {} and {}".format(dut1,dut2))
        return False
    ### Add all members of PO on both DUTs
    utils.exec_all(True, [[po_obj.add_portchannel_member,dut1, po_id, dut1_po_members], \
                          [po_obj.add_portchannel_member,dut2, po_id, dut2_po_members]])
    if isinstance(vlan,list):
        for vlan_item in vlan:
            if isinstance(vlan_item,str):
                ### Add PO as a tagged member of given vlan range
                utils.exec_all(True, [[vlan_obj.config_vlan_range_members,dut1, vlan_item, po_id], \
                                      [vlan_obj.config_vlan_range_members,dut2, vlan_item, po_id]])
            else:
                ### Add PO as a tagged member of given vlan
                utils.exec_all(True, [[vlan_obj.add_vlan_member,dut1, vlan_item, po_id, True], \
                                      [vlan_obj.add_vlan_member,dut2, vlan_item, po_id, True]])
    else:
        if isinstance(vlan, str):
            ### Add PO as a tagged member of given vlan range
            utils.exec_all(True, [[vlan_obj.config_vlan_range_members, dut1, vlan, po_id], \
                                 [vlan_obj.config_vlan_range_members, dut2, vlan, po_id]])
        else:
            ###Add PO as an untagged member of given vlan
            utils.exec_all(True, [[vlan_obj.add_vlan_member, dut1, vlan, po_id], \
                                 [vlan_obj.add_vlan_member, dut2, vlan, po_id]])

def configure_empty_portchannel(dut1, dut2, po_id, min_links=None):
    if min_links == None:
        utils.exec_all(True, [[po_obj.create_portchannel, dut1, po_id], [po_obj.create_portchannel, dut2, po_id]])
    else:
        utils.exec_all(True, [[po_obj.create_portchannel, dut1, po_id, False, min_links],
                              [po_obj.create_portchannel, dut2, po_id, False, min_links]])

def unconfigure_portchannel(dut1,dut2,po_id,vlans,dut1_po_members,dut2_po_members):
    if isinstance(vlans, list):
        for vlan_item in vlans:
            if isinstance(vlan_item, str):
                # uses vlan range cli
                ### Remove PO from given vlan range
                ##vlan_obj.config_vlan_range_members(dut, vlan_item, po_id, config='del')
                utils.exec_all(True, [[vlan_obj.config_vlan_range_members, dut1, vlan_item, po_id,'del'], \
                                      [vlan_obj.config_vlan_range_members, dut2, vlan_item, po_id,'del']])
            else:
                # uses vlan range cli
                ### Remove PO from given vlan
                ##vlan_obj.delete_vlan_member(dut, vlan_item, po_id)
                utils.exec_all(True, [[vlan_obj.delete_vlan_member, dut1, vlan_item, po_id, True], \
                                      [vlan_obj.delete_vlan_member, dut2, vlan_item, po_id, True]])
    else:
        if isinstance(vlans, str):
            # uses vlan range cli
            ### Remove PO from given vlan range
            ##vlan_obj.config_vlan_range_members(dut, vlans, po_id, config='del')
            utils.exec_all(True, [[vlan_obj.config_vlan_range_members, dut1, vlans, po_id,'del'], \
                                  [vlan_obj.config_vlan_range_members, dut2, vlans, po_id,'del']])
        else:
            # uses regular vlan cli
            ### Remove PO from given vlan
            ##vlan_obj.delete_vlan_member(dut, vlans, po_id)
            utils.exec_all(True, [[vlan_obj.delete_vlan_member, dut1, vlans, po_id], \
                                  [vlan_obj.delete_vlan_member, dut2, vlans, po_id]])
    ###Remove all member ports of PO on both DUTs
    utils.exec_all(True, [[po_obj.delete_portchannel_member,dut1, po_id, dut1_po_members], \
                          [po_obj.delete_portchannel_member,dut2, po_id, dut2_po_members]])
    ### Delete the PO
    utils.exec_all(True, [[po_obj.delete_portchannel, dut1, po_id], [po_obj.delete_portchannel, dut2, po_id]])


def l2fwd_base_config():
    print_log("Begin base configurations.", "HIGH")
    ### Create VLANs on all DUTs using range command
    vlan_range = "1 " + str(data.total_vlan_count)
    utils.exec_all(True,[[vlan_obj.config_vlan_range,dut, vlan_range] for dut in data.my_dut_list])

    ### Configure all VLANs on first TGEN ports of each DUT, to verify flooding.
    utils.exec_all(True, [[vlan_obj.config_vlan_range_members, dut, vlan_range, st.get_tg_links(dut)[0][0]] \
                          for dut in data.my_dut_list])
    utils.exec_all(True, [[vlan_obj.config_vlan_range_members, dut, vlan_range, st.get_tg_links(dut)[1][0]] \
                          for dut in data.my_dut_list])
    utils.exec_all(True, [[mac_obj.config_mac_agetime, dut, data.mac_aging] for dut in data.my_dut_list])
    d1 = data.my_dut_list[0]
    data.portchannel = {}
    data.po_metadata = {}
    po_index = 1
    for d2 in data.my_dut_list[1:]:
        vlan = data.base_vlan
        link = 0
        all_links = st.get_dut_links(d1, peer=d2)
        # Configure Access ports
        link_dut_index = 0
        for dut in [d1,d2]:
            v = vlan
            for i in range(link,data.access_port_count):
                vlan_obj.add_vlan_member(dut,v, [all_links[i][link_dut_index]])
                v = v + 1
            link_dut_index = 2

        # Configure Trunk ports
        link = data.access_port_count
        vlan = data.base_vlan + data.access_port_count
        link_dut_index = 0
        for dut in [d1,d2]:
            v = vlan
            for i in range(link,(link+data.trunk_port_count)):
                v_range = str(v) + " " + str(v + data.trunk_vlan_count - 1)
                vlan_obj.config_vlan_range_members(dut,v_range, all_links[i][link_dut_index])
                v = v + data.trunk_vlan_count
            link_dut_index = 2

        # Configure PortChannel Trunk
        link = data.access_port_count + data.trunk_port_count
        vlan = data.base_lagT_vlan
        for poi in range (po_index,po_index+data.lagT_count):
            vlan_max_range =  vlan + data.lagT_vlan_count
            if vlan > (data.total_vlan_count - 2): break
            if vlan_max_range > (data.total_vlan_count -1): vlan_max_range = (data.total_vlan_count - 1)
            v_range = str(vlan) + " " + str(vlan_max_range)

            po_name = "PortChannel" + str(poi)
            po_id_str = "po" + str(poi)
            po_id = (d1,po_id_str)
            if poi == po_index:
                data.po_metadata[(d1, 'trunk')] = {'base_id': po_id, 'count': data.lagT_count}

            #print "PO vlan range ====>" + v_range
            D1D2_po_members = []
            D2D1_po_members = []
            for i in range(link,link+data.lagT_link_count):
                D1D2_po_members.append(all_links[i][0])
                D2D1_po_members.append(all_links[i][2])
            data.portchannel.update({
                po_id : {
                    'name' : po_name ,
                    'duts' : [d1, d2] ,
                    'vlan' : v_range ,
                    'dut1_members' : D1D2_po_members ,
                    'dut2_members' : D2D1_po_members
                }
            })
            configure_portchannel(d1, d2, po_name, [v_range], D1D2_po_members, D2D1_po_members)
            vlan = vlan + data.lagT_vlan_count + 1
            link = link + data.lagA_link_count

        # Configure PortChannel Access
        po_index = po_index + data.lagT_count
        link = data.access_port_count + data.trunk_port_count + (data.lagT_count*data.lagT_link_count)
        vlan = data.base_lagA_vlan
        for poi in range (po_index,po_index + data.lagA_count):
            po_name = "PortChannel" + str(poi)
            po_id_str = "po" + str(poi)
            po_id = (d1, po_id_str)
            if poi == po_index:
                data.po_metadata[(d1, 'access')] = {'base_id': po_id, 'count': data.lagA_count}
            D1D2_po_members = []
            D2D1_po_members = []
            for i in range(link,link+data.lagA_link_count):
                D1D2_po_members.append(all_links[i][0])
                D2D1_po_members.append(all_links[i][2])
            data.portchannel.update({
                po_id : {
                    'name' : po_name ,
                    'duts' : [d1, d2] ,
                    'vlan' : vlan ,
                    'dut1_members' : D1D2_po_members ,
                    'dut2_members' : D2D1_po_members
                }
            })
            configure_portchannel(d1, d2, po_name, vlan,D1D2_po_members, D2D1_po_members)
            vlan = vlan + 1
            link = link + data.lagA_link_count
        ### Repeat for next set of DUT pairs
        ### po_index reset to be done for alternate pair of duts only.
        ### Eg; po1-4 configured between DUT1-DUT2, then PO5-8 to be between DUT2-DUT3
        if po_index == (1+data.lagT_count) :
            po_index = data.lagA_count + data.lagT_count + 1
        else:
            po_index = 1

        # Configure Empty PortChannels
        for empty_poi in range(po_index, po_index + data.max_lag_count):
            configure_empty_portchannel(d1, d2, "PortChannel" + str(empty_poi))

        d1 = d2
    # Static MAC Scale

    static_mac_base = "00:21:EE:00:"
    base_mac = '0x1001'
    dst_mac_list = []
    vlan = data.base_lagT_vlan
    for i in range(0,data.static_mac_count ):
        mac_str = base_mac.split("0x")[1]
        static_mac = static_mac_base + mac_str[:2] + ':' + mac_str[2:]
        dst_mac_list.append(static_mac)
        temp_var = int(base_mac,16)
        temp_var += 1
        base_mac = hex(temp_var)

    d1 = data.my_dut_list[0]
    last_dut = data.my_dut_list[-1]
    po_key = data.po_metadata[(d1, 'trunk')]['base_id']
    trunk_lag = data.portchannel[po_key]['name']

    # Configure each static MAC in parallel on each DUT.
    for mac in dst_mac_list:
        api_list = []
        for dut in [data.my_dut_list[:-1]]:
                api_list.append([mac_obj.config_mac, dut[0], mac, vlan, trunk_lag])
        tgen_port = [st.get_tg_links(last_dut)[1][0]][0]
        api_list.append([mac_obj.config_mac, last_dut , mac, vlan, tgen_port])
        utils.exec_all(True, api_list)

    # Configure each IP address on each vlan in parallel on each DUT.
    ip_count = data.ip_count
    dut1_ip_list = []
    dut2_ip_list = []
    dut1_ipv6_list = []
    dut2_ipv6_list = []
    sub_net = 1
    d1 = data.my_dut_list[0]
    dn = data.my_dut_list[-1]
    vlan_int = data.base_lagT_vlan
    mask = "24"
    mask_v6 = "64"
    #enable_ipv6()
    i = 0
    for i in range(0,ip_count):
        api_list = []
        api_listv6 = []
        ip_str = "192.168." + str(sub_net) + "." + '1'
        ipv6_str = "201" + str(sub_net) + "::" + '1'
        dut1_ip_list += [ip_str]
        api_list.append([ip_obj.config_ip_addr_interface,d1,'Vlan'+str(vlan_int),ip_str,mask])
        api_listv6.append([ip_obj.config_ip_addr_interface, d1, 'Vlan' + str(vlan_int), ipv6_str, mask_v6, 'ipv6'])
        dut1_ipv6_list += [ipv6_str]
        ip_str = "192.168." + str(sub_net) + "." + '2'
        ipv6_str = "201" + str(sub_net) + "::" + '2'
        dut2_ip_list += [ip_str]
        dut2_ipv6_list += [ipv6_str]

        api_list.append([ip_obj.config_ip_addr_interface,dn,'Vlan'+str(vlan_int),ip_str,mask])
        api_listv6.append([ip_obj.config_ip_addr_interface, dn, 'Vlan' + str(vlan_int), ipv6_str, mask_v6, 'ipv6'])
        utils.exec_all(True, api_list)
        #utils.exec_all(True, api_listv6)
        sub_net += 1
        vlan_int += 1
    # Temporary sleep
    #-#st.wait(35)

def l2fwd_base_unconfig():
    print_log("Begin base unconfigs.", "HIGH")

    vlan_range = "1 " + str(data.total_vlan_count)

    # Static MAC Scale
    static_mac_base = "00:21:EE:00:"

    base_mac = '0x1001'
    dst_mac_list = []
    vlan = data.base_lagT_vlan
    for i in range(0,data.static_mac_count ):
        mac_str = base_mac.split("0x")[1]
        static_mac = static_mac_base + mac_str[:2] + ':' + mac_str[2:]
        dst_mac_list.append(static_mac)
        temp_var = int(base_mac,16)
        temp_var += 1
        base_mac = hex(temp_var)

    # Configure each static MAC in parallel on each DUT.
    for mac in dst_mac_list:
        api_list = []
        for dut in data.ver_dut_list:
            api_list.append([mac_obj.delete_mac, dut, mac, vlan])
        utils.exec_all(True, api_list)

    ### Tgen port unconfig on first and last DUT.
    utils.exec_all(True, [[vlan_obj.config_vlan_range_members, dut, vlan_range, data.tgen_port[dut],'del'] for dut in
                          data.ver_dut_list])

    ### UnConfigure all VLANs on first TGEN ports of each DUT, to verify flooding.
    utils.exec_all(True, [[vlan_obj.config_vlan_range_members, dut, vlan_range, st.get_tg_links(dut)[0][0],'del'] \
                          for dut in data.my_dut_list])
    # Revert back to default mac aging
    utils.exec_all(True, [[mac_obj.config_mac_agetime, dut, data.default_macage] for dut in data.my_dut_list])

    d1 = data.my_dut_list[0]
    data.portchannel = {}
    po_index = 1
    for d2 in data.my_dut_list[1:]:
        vlan = data.base_vlan
        link = 0
        all_links = st.get_dut_links(d1, peer=d2)
        # Configure Access ports
        link_dut_index = 0
        for dut in [d1,d2]:
            v = vlan
            for i in range(link,data.access_port_count):
                vlan_obj.delete_vlan_member(dut,v, [all_links[i][link_dut_index]])
                v = v + 1
            link_dut_index = 2

        # Configure Trunk ports
        link = data.access_port_count
        vlan = data.base_vlan + data.access_port_count
        link_dut_index = 0
        for dut in [d1,d2]:
            v = vlan
            for i in range(link,(link+data.trunk_port_count)):
                v_range = str(v) + " " + str(v + data.trunk_vlan_count - 1)
                vlan_obj.config_vlan_range_members(dut,v_range, all_links[i][link_dut_index],config='del')
                #vlan_obj.add_vlan_member(dut,v, [all_links[i][link_dut_index]], tagging_mode=True)
                v = v + data.trunk_vlan_count
            link_dut_index = 2

        # Configure PortChannel Trunk
        link = data.access_port_count + data.trunk_port_count
        vlan = data.base_lagT_vlan

        for poi in range(po_index, po_index+data.lagT_count):
            vlan_max_range =  vlan + data.lagT_vlan_count

            if vlan > (data.total_vlan_count - 2): break
            if vlan_max_range > (data.total_vlan_count - 1): vlan_max_range = (data.total_vlan_count  -1)
            po_name = "PortChannel" + str(poi)
            v_range = str(vlan) + " " + str(vlan_max_range )
            D1D2_po_members = []
            D2D1_po_members = []
            for i in range(link, link + data.lagT_link_count):
                D1D2_po_members.append(all_links[i][0])
                D2D1_po_members.append(all_links[i][2])
            unconfigure_portchannel(d1, d2, po_name, [v_range], D1D2_po_members, D2D1_po_members)
            vlan = vlan + data.lagT_vlan_count + 1
            link = link + data.lagA_link_count
        # Unconfigure PortChannel Access
        po_index = po_index + data.lagT_count
        link = data.access_port_count + data.trunk_port_count + (data.lagT_count * data.lagT_link_count)
        vlan = data.base_lagA_vlan

        for poi in range(po_index, po_index + data.lagA_count):
            po_name = "PortChannel" + str(poi)
            D1D2_po_members = []
            D2D1_po_members = []
            for i in range(link, link + data.lagA_link_count):
                D1D2_po_members.append(all_links[i][0])
                D2D1_po_members.append(all_links[i][2])
            unconfigure_portchannel(d1, d2, po_name, vlan, D1D2_po_members, D2D1_po_members)
            vlan = vlan + 1
            link = link + data.lagA_link_count

        #Delete all the port-channel configuration
        po_obj.clear_portchannel_configuration([d1,d2])

        # Repeat for next set of DUT pairs
        d1 = d2
        if po_index == (1+data.lagT_count) :
            po_index = data.lagA_count + data.lagT_count + 1
        else:
            po_index = 1


    # Configure each IP address on each vlan in parallel on each DUT.
    dut1_ip_list = []
    dut2_ip_list = []
    dut1_ipv6_list = []
    dut2_ipv6_list = []
    sub_net = 1
    d1 = data.my_dut_list[0]
    dn = data.my_dut_list[-1]
    vlan_int = data.base_lagT_vlan
    mask = "24"
    mask_v6 = "64"
    #enable_ipv6()
    for i in range(0,data.ip_count):
        api_list = []
        api_listv6 = []
        ip_str = "192.168." + str(sub_net) + "." + '1'
        ipv6_str = "201" + str(sub_net) + "::" + '1'
        dut1_ip_list += [ip_str]
        api_list.append([ip_obj.delete_ip_interface,d1,'Vlan'+str(vlan_int),ip_str,mask])
        api_listv6.append([ip_obj.delete_ip_interface, d1, 'Vlan' + str(vlan_int), ipv6_str, mask_v6, 'ipv6'])
        dut1_ipv6_list += [ipv6_str]
        ip_str = "192.168." + str(sub_net) + "." + '2'
        ipv6_str = "201" + str(sub_net) + "::" + '2'
        dut2_ip_list += [ip_str]
        dut2_ipv6_list += [ipv6_str]

        api_list.append([ip_obj.delete_ip_interface,dn,'Vlan'+str(vlan_int),ip_str,mask])
        api_listv6.append([ip_obj.delete_ip_interface, dn, 'Vlan' + str(vlan_int), ipv6_str, mask_v6, 'ipv6'])
        utils.exec_all(True, api_list)
        #utils.exec_all(True, api_listv6)
        sub_net += 1
        vlan_int += 1
    utils.exec_all(True, [[vlan_obj.config_vlan_range, dut, vlan_range,'del'] for dut in data.my_dut_list])
    if basic_obj.get_config_profiles(data.my_dut_list[0]) == 'l2':
        utils.exec_all(True, [[pvst_obj.config_spanning_tree, dut, "pvst", "enable"] for dut in data.my_dut_list])
        utils.exec_all(True, [[del_vlan1_mem_ports, dut, "add"] for dut in data.my_dut_list])

    boot_obj.config_save(data.my_dut_list)


def get_tgen_handles():
    global tg_h, tg_src_ph, tg_dest_ph, tg_src_ph1, tg_dest_ph1, tgen_handles
    tg_h = tgapi.get_chassis(vars)
    #total_duts = len(data.my_dut_list)
    dut1 = data.my_dut_list[0]
    dutN = data.my_dut_list[-1]
    ### TGN links returned is like [dut_port, peer_device_name, peer_port]. Hence index for TGN port is 2.
    tgn_port_index = 2
    ### Use 2nd port for base traffic configuration
    tgn_list_index = 1
    data.src_tgn_port = st.get_tg_links(dut1)[tgn_list_index][tgn_port_index]
    data.dest_tgn_port = st.get_tg_links(dutN)[tgn_list_index][tgn_port_index]
    tg_src_ph = tg_h.get_port_handle(data.src_tgn_port)
    tg_dest_ph = tg_h.get_port_handle(data.dest_tgn_port)

    tgn_list_index = 0
    data.src_tgn_port1 = st.get_tg_links(dut1)[tgn_list_index][tgn_port_index]
    data.dest_tgn_port1 = st.get_tg_links(dutN)[tgn_list_index][tgn_port_index]
    tg_src_ph1 = tg_h.get_port_handle(data.src_tgn_port1)
    tg_dest_ph1 = tg_h.get_port_handle(data.dest_tgn_port1)

    tgen_handles = (tg_h,tg_src_ph,tg_dest_ph,tg_src_ph1,tg_dest_ph1)
    return (tg_h,tg_src_ph,tg_dest_ph,tg_src_ph1,tg_dest_ph1)

def l2fwd_base_traffic_config():
    # reset statistics and delete if any existing streamblocks --- this now return all 4 tgen handles and resets it
    for item in tgen_handles:
        if item == tg_h:
            continue
        tg_h.tg_traffic_control(action="reset", port_handle=item)

    tg_ph1 = tg_src_ph
    tg_ph2 = tg_dest_ph

    data.stream_data = {}
    # Traffic stream - Tagged traffic
    # DUT1 -- Access Phy ports -- DUTn
    vlan = data.base_vlan
    st_key = 'AA'
    src_mac = '00:12:' + st_key + ':00:00:01'
    dst_mac = '00:21:' + st_key + ':00:00:01'
    vlan_count = data.total_vlan_count - 1
    data.stream_data[st_key] = {'src_mac': src_mac, 'dst_mac': dst_mac, 'vlan': vlan, 'vlan_count': vlan_count,
                                'mac_count': data.total_mac_count, 'rate_pps': data.tgen_rate_pps, 'vlan_mode': 'enable',
                                'tg_port_handles': [tg_ph1, tg_ph2]}
    # DUT1 -- Tagged Phy ports -- DUTn
    vlan = data.base_lagT_vlan
    vlan_count = 1
    st_key = 'EE'
    src_mac = '00:12:' + st_key + ':00:10:01'
    dst_mac = '00:21:' + st_key + ':00:10:01'
    data.stream_data[st_key] = {'src_mac': src_mac, 'dst_mac': dst_mac, 'vlan': vlan, 'vlan_count': vlan_count,
                                'mac_count': data.static_mac_count, 'rate_pps': data.tgen_rate_pps,
                                'vlan_mode': 'enable', 'tg_port_handles': [tg_ph1, tg_ph2]}

    ### Scale Traffic for STP testing
    vlan = data.base_trunk_vlan
    st_key = 'FF'
    #data.stp_macs = data.common_mac_scale / 2
    data.stp_macs = 4096
    src_mac = '00:12:' + st_key + ':00:00:01'
    dst_mac = '00:21:' + st_key + ':00:00:01'
    data.stream_data[st_key] = {'src_mac': src_mac, 'dst_mac': dst_mac, 'vlan': vlan, 'vlan_count': 1,
                                'mac_count': data.stp_macs, 'rate_pps': data.tgen_rate_pps, 'vlan_mode': 'enable',
                                'tg_port_handles': [tg_src_ph1, tg_dest_ph1]}

    # MAC scale -
    st_key = 0
    for dut in data.my_dut_list:
        # Get tgen port handles of dut
        src_tgn_port = st.get_tg_links(dut)[0][2]
        dest_tgn_port = st.get_tg_links(dut)[1][2]
        tg_src_ph_local = tg_h.get_port_handle(src_tgn_port)
        tg_dest_ph_local = tg_h.get_port_handle(dest_tgn_port)
        vlan = data.total_vlan_count
        src_mac = '00:55:' + str(st_key) + '0:00:00:01'
        dst_mac = '00:66:' + str(st_key) + '0:00:00:01'
        vlan_count = 1
        dut_mac_scale = (data.mac_scale_list[st_key]/2) - data.total_mac_count
        data.verify_mac_scale.append((dut_mac_scale + data.total_mac_count)*2 + data.static_mac_count)

        if dut_mac_scale < 2: break
        data.stream_data[st_key] = {'src_mac': src_mac, 'dst_mac': dst_mac, 'vlan': vlan, 'vlan_count': vlan_count,
                                    'mac_count': dut_mac_scale, 'rate_pps': data.tgen_rate_pps,
                                    'vlan_mode': 'enable', 'tg_port_handles': [tg_src_ph_local, tg_dest_ph_local]}
        print_log("Stream data.........")
        print_log(data.stream_data[st_key])
        st_key +=1

    data.base_src_streams = []
    data.base_dst_streams = []
    for st_key,stdata in data.stream_data.items():
        tg_ph11 = stdata['tg_port_handles'][0]
        tg_ph21 = stdata['tg_port_handles'][1]
        stream1 = tg_h.tg_traffic_config(mode='create', port_handle= tg_ph11,rate_pps=data.tgen_rate_pps, mac_src=stdata['src_mac'], mac_src_mode="increment",
        mac_src_count=stdata['mac_count'], transmit_mode="continuous",
        mac_src_step="00:00:00:00:00:01", mac_dst=stdata['dst_mac'], mac_dst_mode="increment",
        mac_dst_count=stdata['mac_count'], mac_dst_step="00:00:00:00:00:01", l2_encap='ethernet_ii_vlan',
        vlan_id=stdata['vlan'], vlan_id_count = stdata['vlan_count'], vlan="enable",vlan_id_mode="increment", vlan_id_step='1',port_handle2=tg_ph21,high_speed_result_analysis=0,enable_stream = 0)
        data.stream_data[st_key]['streamAB'] = stream1['stream_id']
        data.base_src_streams.append(stream1['stream_id'])
        # ,enable_stream=0
        stream2 = tg_h.tg_traffic_config(mode='create',port_handle= tg_ph21, rate_pps=data.tgen_rate_pps, mac_src=stdata['dst_mac'], mac_src_mode="increment",
        mac_src_count=stdata['mac_count'], transmit_mode="continuous",
        mac_src_step="00:00:00:00:00:01", mac_dst=stdata['src_mac'], mac_dst_mode="increment",
        mac_dst_count=stdata['mac_count'], mac_dst_step="00:00:00:00:00:01", l2_encap='ethernet_ii_vlan',
        vlan_id=stdata['vlan'], vlan_id_count = stdata['vlan_count'], vlan="enable",vlan_id_mode="increment", vlan_id_step='1',port_handle2=tg_ph11,high_speed_result_analysis=0, enable_stream = 0)
        data.stream_data[st_key]['streamBA'] = stream2['stream_id']
        data.base_dst_streams.append(stream2['stream_id'])


def l2fwd_base_traffic_unconfig():
    #tgen_data = get_tgen_handles()
    #tg_h = tgen_data[0]
    # reset statistics and delete if any existing streamblocks
    for item in tgen_handles:
        if item == tg_h:
            continue
        tg_h.tg_traffic_control(action="reset", port_handle=item)

def run_verify_traffic(tg_ph_src=None,tg_ph_dest=None,src_stream_list='ALL',dest_stream_list='ALL',direction="both",verify_mode='port',call_func_list=None):
    res_flag = True
    if tg_ph_src == None:
        tg_ph_src = tg_src_ph
    if tg_ph_dest == None:
        tg_ph_dest = tg_dest_ph

    tgen_port = {tg_src_ph:data.src_tgn_port,
                 tg_src_ph1:data.src_tgn_port1,
                 tg_dest_ph:data.dest_tgn_port,
                 tg_dest_ph1:data.dest_tgn_port1}

    start_stop_traffic(tg_h, tg_ph_src, tg_ph_dest, duration=data.traffic_run_time, src_stream_list=src_stream_list,
                       dest_stream_list=dest_stream_list, direction=direction,call_func_list=call_func_list)
    if verify_mode == 'port':
        if not verify_traffic(tg_h, tgen_port[tg_ph_src], tgen_port[tg_ph_dest], src_stream_list='ALL', \
                              dest_stream_list='ALL', direction=direction):
            res_flag = False
    elif verify_mode == 'stream':
        if not verify_traffic(tg_h, tgen_port[tg_ph_src], tgen_port[tg_ph_dest], src_stream_list=src_stream_list, \
                          dest_stream_list=dest_stream_list, direction=direction):
            res_flag = False

    if res_flag:
        print_log("Traffic verification PASSED", "HIGH")
        return True
    else:
        print_log("Traffic verification FAILED", "HIGH")
        return False


def start_stop_traffic(tg_id=None,tg_src_list=None,tg_dest_list=None,duration=data.traffic_run_time,src_stream_list='ALL',\
                       dest_stream_list='ALL',direction="both",stop_stream_list=None,call_func_list=None):
    '''
    :param tg_id: chassis handle
    :param tg_src_list: source porthandle as list or single
    :param tg_dest_list: destination port handle as list
    :param duration: duration for which traffic needs to run
    :param src_stream_list: If source stream list=ALL start traffic using port handles else using this stream handle
    :param dest_stream_list: If source stream list=ALL start reverse traffic using port_handles else using this stream handle
                                Used only when direction is "both"
    :param direction:  Value can be single or both. Default is "both"
    :param stop_stream_list: list of stream_ids to be stopped after starting all streams on a port using porthandle.
    :return:
    '''
    if tg_id == None:
        tg_id = tg_h
    if tg_src_list == None:
        tg_src_list = tg_src_ph
    if tg_dest_list == None:
        tg_dest_list = tg_dest_ph

    tg_src_list = [tg_src_list] if type(tg_src_list) is str else tg_src_list
    tg_dest_list = [tg_dest_list] if type(tg_dest_list) is str else tg_dest_list
    if src_stream_list == 'ALL':
        ### Port Handle not to be used to start & stop traffic as ixia won't support from 9.1 -- obsolete code
        for tg_src,tg_dest in zip(tg_src_list,tg_dest_list):
            tg_id.tg_traffic_control(action='clear_stats',port_handle=tg_src)
            tg_id.tg_traffic_control(action='clear_stats',port_handle=tg_dest)
            # Start running Traffic
            tg_id.tg_traffic_control(action='run',port_handle=tg_src)
            if direction == "both":
                tg_id.tg_traffic_control(action='run',port_handle=tg_dest)
        if stop_stream_list != None:
            ### Starting a list of streams with provided stream_list was taking time
            ### Hence added this part to start all streams on the port and then stop unwanted streams.
            for stream_id in stop_stream_list:
                tg_id.tg_traffic_control(action='stop',handle=stream_id)
            for tg_src,tg_dest in zip(tg_src_list,tg_dest_list):
                tg_id.tg_traffic_control(action='clear_stats',port_handle=tg_src)
                tg_id.tg_traffic_control(action='clear_stats',port_handle=tg_dest)

    else:
        if (len(tg_src_list) > 1) | (len(tg_dest_list) > 1):
            print_log("source and destination port handles cannot be list when stream ID is provided\n \
                        Exiting Traffic validation",'ERROR')
            st.report_fail("operation_failed")
        tg_src = tg_src_list[0]
        tg_dest = tg_dest_list[0]
        tgn_handles = [tg_src, tg_dest]
        tg_id.tg_traffic_control(action="clear_stats", port_handle=tgn_handles)
        src_stream_list = [src_stream_list] if type(src_stream_list) is str else src_stream_list
        dest_stream_list = [dest_stream_list] if type(dest_stream_list) is str else dest_stream_list

        if len(src_stream_list) != len(dest_stream_list):
            ###Compare both source and dest stream_lists are of same length else fail
            if direction == 'both':
                print_log('Need both SRC and DEST stream list to be of same length if bi-directional traffic to be run','ERROR')
                st.report_fail("operation_failed")
            else:
                ### For single direction traffic verification destination stream_list not needed.
                dest_stream_list = ['ANY']* len(src_stream_list)

        stream_list = src_stream_list
        if direction == "both":
            stream_list = stream_list + dest_stream_list
        tg_id.tg_traffic_control(action='run', handle=stream_list)

    st.wait(duration)

    if src_stream_list == 'ALL':
        ### Port Handle not to be used to start & stop traffic as ixia won't support from 9.1 -- obsolete code
        for tg_src, tg_dest in zip(tg_src_list, tg_dest_list):
            # Stop running Traffic
            tg_id.tg_traffic_control(action='stop', port_handle=tg_src)
            if direction == "both":
                tg_id.tg_traffic_control(action='stop', port_handle=tg_dest)
    else:
        src_stream_list = [src_stream_list] if type(src_stream_list) is str else src_stream_list
        dest_stream_list = [dest_stream_list] if type(dest_stream_list) is str else dest_stream_list
        ###If subset of stream list called to stop, ixia not returning success flag and next subset fails to stop.
        # Hence create a single list of stream ids and make single ixia call to stop.
        stream_list = src_stream_list
        if direction == "both":
            stream_list = stream_list + dest_stream_list
        tg_id.tg_traffic_control(action='stop', handle=stream_list)


def verify_traffic(tg_id, tg_src_port, tg_dest_port, src_stream_list='ALL', dest_stream_list='ALL', tx_rx_ratio=1,direction="both"):
    ver_flag = True
    if src_stream_list =='ALL':
        traffic_data = {
            '1': {
                'tx_ports': [tg_src_port],
                'tx_obj': [tg_id],
                'exp_ratio': [tx_rx_ratio],
                'rx_ports': [tg_dest_port],
                'rx_obj': [tg_id],
            },
        }
        if direction == 'both':
            traffic_data['2'] = {
                'tx_ports': [tg_dest_port],
                'tx_obj': [tg_id],
                'exp_ratio': [tx_rx_ratio],
                'rx_ports': [tg_src_port],
                'rx_obj': [tg_id],
            }
       # verify traffic mode aggregate level
        aggrResult = tgapi.validate_tgen_traffic(traffic_details=traffic_data, mode='aggregate', comp_type='packet_count')
        if aggrResult:
            st.log('traffic verification passed for mode aggregate')
        else:
            ver_flag = False
            st.log('traffic verification failed for mode aggregate')
    else:
        src_stream_list = [src_stream_list] if type(src_stream_list) is str else src_stream_list
        dest_stream_list = [dest_stream_list] if type(dest_stream_list) is str else dest_stream_list

        if len(src_stream_list) != len(dest_stream_list):
            ###Compare both source and dest stream_lists are of same length else fail
            if direction == 'both':
                print_log('Need both SRC and DEST stream list to be of same length if bi-directional traffic to be verified','ERROR')
                st.report_fail("operation_failed")
            else:
                ### For single direction traffic verification destination stream_list not needed.
                dest_stream_list = ['ANY']* len(src_stream_list)

        for src_stream_id,dest_stream_id in zip(src_stream_list,dest_stream_list):
            traffic_data = {
                '1': {
                    'tx_ports': [tg_src_port],
                    'tx_obj': [tg_id],
                    'exp_ratio': [tx_rx_ratio],
                    'rx_ports': [tg_dest_port],
                    'rx_obj': [tg_id],
                    'stream_list': [[src_stream_id]],
                },
            }
            if  direction == 'both':
                traffic_data['2'] = {
                    'tx_ports': [tg_dest_port],
                    'tx_obj': [tg_id],
                    'exp_ratio': [tx_rx_ratio],
                    'rx_ports': [tg_src_port],
                    'rx_obj': [tg_id],
                    'stream_list': [[dest_stream_id]],
                }

            # verify traffic mode stream level
            streamResult = tgapi.validate_tgen_traffic(traffic_details=traffic_data, mode='streamblock',comp_type='packet_count')
            if streamResult:
                st.log('traffic verification passed for mode streamblock')
            else:
                ver_flag = False
                st.log('traffic verification failed for mode streamblock')

    if ver_flag:
        return True
    else:
        return False

def verify_flooding_on_dut(dut,portList,threshold):
    '''
    Verify given list of ports is flooding traffic with tx_rate greater than threshold
    :param dut:
    :param portList:
    :param threshold:
    :return: False:, If given port is transmitting less than threshold
    :return: True:, If given port is transmitting more than threshold
    '''
    #Getting interfaces counter values on DUT
    ver_flag = True
    for port in portList:
        DUT_tx_value = intf_obj.get_interface_counters(dut, port, "tx_ok")
        print_log("port:{}, tx_value:{}".format(port,DUT_tx_value),'MED')
        if not DUT_tx_value:
            print_log('Expected port:{} not seen in output'.format(port),'ERROR')
            ver_flag = False
            break
        for i in DUT_tx_value:
            print_log("port:{}, tx_value:{}, i:{}".format(port, DUT_tx_value, i), 'MED')
            p_txmt = i['tx_ok']
            if p_txmt == 'N/A' or p_txmt is None: return False
            p_txmt = p_txmt.replace(",","")
            if int(p_txmt) < threshold:
                ver_flag = False
                break
        if not ver_flag:
            break
    return ver_flag

def verify_flooding(dut_list, src_stream_list='ALL', tx_rx_ratio=1):
    '''
    Verifies the traffic sent from 2nd TGEN port of DUT1 is received on first TGEN port in each of the DUTs in testbed
    Assumes traffic is already started and stopped and here it just compares packet count on TGEN ports

    :param dut_list: list of duts in which first TGEN port will be verified for flooded traffic
    :param src_stream_list: list of source stream ids
    :param dest_stream_list: list of destination stream ids
    :param tx_rx_ratio: Ratio of rx_pkt_count/tx_pkt_count. Default is 1.
    :return:
    '''
    ver_flag = True
    tg_id = tgapi.get_chassis(vars)
    ### TGN links returned is like [dut_port, peer_device_name, peer_port]. Hence index for TGN port is 2.
    tgn_port_index = 2
    ### Use first tgen port for flooding verification
    tgn_list_index = 0
    for dut in dut_list:
        dest_tgn_port = st.get_tg_links(dut)[tgn_list_index][tgn_port_index]
        if not verify_traffic(tg_id, data.src_tgn_port, dest_tgn_port, src_stream_list=src_stream_list, \
                              dest_stream_list='ALL', tx_rx_ratio=tx_rx_ratio,direction='single'):
            ver_flag = False
            print_log("Traffic flooding verification on TGEN port:{} in dut:{} FAILED".format(dest_tgn_port, dut),'ERROR')
        else:
            print_log("Traffic flooding verification on TGEN port:{} in dut:{} PASSED".format(dest_tgn_port, dut),'MED')

    if ver_flag:
        print_log("Traffic Flooding Verification PASSED","HIGH")
        return True
    else:
        print_log("Traffic Flooding verification FAILED","HIGH")
        return False


def verify_portchannel(dut_pair,po_id,po_members_list,state='up'):
    ver_flag = True

    ### Verify PO state
    [result, exceptions] = utils.exec_foreach(True, dut_pair, po_obj.verify_portchannel_state,
                                              portchannel=po_id, state=state)
    if not all(i is None for i in exceptions):
        print_log(exceptions)
    if False in result:
        ver_flag = False

    ### Verify PO member port state
    [result, exceptions] = utils.exec_all(True,[[po_obj.verify_portchannel_member_state,dut,po_id,dut_po_members,state] for dut,dut_po_members in zip(dut_pair,po_members_list)])
    if not all(i is None for i in exceptions):
        print_log(exceptions)
    if False in result:
        ver_flag = False

    if ver_flag:
        print_log("Verify PortChannel-{} State:{} PASSED".format(po_id,state),"HIGH")
        return True
    else:
        print_log("Verify PortChannel-{} State:{} FAILED".format(po_id,state),"HIGH")
        return False


def verify_vlan_members(dut_list,total_vlan_list):
    print_log("Verifying VLAN entries {},{}".format(dut_list, total_vlan_list),"MED")
    ver_flag = True
    # mac_address_list = get_mac_address_list(dut,vlan=None,port=None,type=None)
    dut_list = [dut_list] if type(dut_list) is str else dut_list
    total_vlan_list = [total_vlan_list] if type(total_vlan_list) is not list else total_vlan_list
    for dut, expect_vlan_count in zip(dut_list, total_vlan_list):
        #vlan_list = vlan_obj.get_vlan_count(dut)
        actual_vlan_count = vlan_obj.get_vlan_count(dut)
        if actual_vlan_count != expect_vlan_count:
            print_log("FAIL: Total vlan on {} failed, Expect: {}, Got: {}".format(dut, expect_vlan_count, actual_vlan_count),'ERROR')
            ver_flag = False
            asicapi.dump_vlan(dut)
        else:
            print_log("PASS: Total vlan on {} passed, Expect: {}, Got: {}".format(dut, expect_vlan_count, actual_vlan_count),'MED')

    if ver_flag:
        return True
    else:
        return False


def show_verify_mac_table(dut,expect_mac,vlan=None,port=None,type=None,mac_search=None,comp_flag='equal'):
    mac_count = mac_obj.get_mac_address_count(dut, vlan=vlan, port=port, type=type, mac_search=mac_search)
    if comp_flag == 'equal':
        if mac_count != expect_mac:
            print_log(
                "FAIL:Verify MAC with filter vlan={} port={} type={} on {} failed, Expect: {} = Got: {}".format(vlan,
                                                                                                                port,
                                                                                                                type,
                                                                                                                dut,
                                                                                                                expect_mac,
                                                                                                                mac_count),
                'ERROR')
            asicapi.dump_l2(dut)
            return False
        else:
            print_log(
                "PASS:Verify MAC with filter vlan={} port={} type={} on {} passed, Expect: {} = Got: {}".format(vlan,
                                                                                                                port,
                                                                                                                type,
                                                                                                                dut,
                                                                                                                expect_mac,
                                                                                                                mac_count),
                'MED')
            return True
    else:
        if mac_count == expect_mac:
            print_log(
                "FAIL:Verify MAC with filter vlan={} port={} type={} on {} failed, Expect: {} != Got: {}".format(vlan,
                                                                                                                 port,
                                                                                                                 type,
                                                                                                                 dut,
                                                                                                                 expect_mac,
                                                                                                                 mac_count),
                'ERROR')
            asicapi.dump_l2(dut)
            return False
        else:
            print_log(
                "PASS:Verify MAC with filter vlan={} port={} type={} on {} passed, Expect: {} != Got: {}".format(vlan,
                                                                                                                 port,
                                                                                                                 type,
                                                                                                                 dut,
                                                                                                                 expect_mac,
                                                                                                                 mac_count),
                'MED')
            return True


def check_mac_count(dut,expect_mac,comp_flag='equal'):
    mac_count = mac_obj.get_mac_count(dut)
    if comp_flag == 'equal':
        if mac_count != expect_mac:
            print_log(
                "FAIL:Verify MAC count on {} failed, Expect: {} = Got: {}".format(dut,expect_mac,mac_count),'ERROR')
            show_verify_mac_table(dut,expect_mac,comp_flag=comp_flag)
            return False
        else:
            print_log(
                "PASS:Verify MAC count on {} passed, Expect: {} = Got: {}".format(dut, expect_mac, mac_count), 'MED')
            return True
    elif comp_flag == 'minimum':
        if mac_count < expect_mac:
            print_log(
                "FAIL:Verify MAC count on {} failed, Expect: {} <= Got: {}".format(dut,expect_mac,mac_count),'ERROR')
            show_verify_mac_table(dut,expect_mac,comp_flag=comp_flag)
            return False
        else:
            print_log(
                "PASS:Verify MAC count on {} passed, Expect: {} <= Got: {}".format(dut, expect_mac, mac_count), 'MED')
            return True
    elif comp_flag == 'not-equal':
        if mac_count == expect_mac:
            print_log(
                "FAIL:Verify MAC count on {} failed, Expect: {} = Got: {}".format(dut, expect_mac, mac_count), 'ERROR')
            show_verify_mac_table(dut,expect_mac,comp_flag=comp_flag)
            return False
        else:
            print_log(
                "PASS:Verify MAC count on {} passed, Expect: {} = Got: {}".format(dut, expect_mac, mac_count), 'MED')
            return True


def check_mac_count_list(dut_list,expect_mac_list,comp_flag='equal'):
    '''
    Verify MAC count in given list of duts is as in expect_mac_list
    It can compare the values are equal or not-equal based on comp_flag
    '''
    print_log("Verifying MAC Table DUTs:{}, MACs:{}".format(dut_list,expect_mac_list),'MED')
    ver_flag = True
    dut_list = dut_list if isinstance(dut_list, list) else [dut_list]
    expect_mac_list = expect_mac_list if isinstance(expect_mac_list, list) else [expect_mac_list]
    [result, exceptions] = utils.exec_all(True, [[check_mac_count, dut, expected_mac, comp_flag] \
                                                 for dut, expected_mac in zip(dut_list,expect_mac_list)])
    if not all(i is None for i in exceptions):
        print_log(exceptions)
    if False in result:
        print_log("MAC Count verification FAILED", "HIGH")
        return False
    else:
        print_log("MAC Count verification PASSED", "HIGH")
        return True


def verify_mac_table(dut_list,expect_mac_list,vlan=None,port=None,type=None,mac_search=None,comp_flag='equal'):
    '''
    Verify MAC table entries in given list of duts is as in expect_mac_list
    It can compare the values are equal or not-equal based on comp_flag
    Count will be verified after the provided filters vlan/port/type applied
    '''
    print_log("Verifying MAC Table DUTs:{}, MACs:{} with filter vlan={} port={} type={}".format(dut_list,expect_mac_list,vlan, port, type),'MED')
    ver_flag = True
    dut_list = dut_list if isinstance(dut_list, list) else [dut_list]
    expect_mac_list = expect_mac_list if isinstance(expect_mac_list, list) else [expect_mac_list]
    [result, exceptions] = utils.exec_all(True, [[show_verify_mac_table, dut, expected_mac, vlan, port, type, mac_search, comp_flag] \
                                                 for dut, expected_mac in zip(dut_list,expect_mac_list)])
    if not all(i is None for i in exceptions):
        print_log(exceptions)
    if False in result:
        print_log("MAC Table verification FAILED", "HIGH")
        return False
    else:
        print_log("MAC Table verification PASSED", "HIGH")
        return True

def verify_macs_ageout(dut_list,mac_list,aging_time,poll_interval,max_wait,**kwargs):
    if aging_time:
        #poll_interval should be less than age_time as we check MACs not aged out before age time
        if not poll_interval < aging_time <= max_wait:
            st.error("Expect the api parameters poll_interval < aging_time <= max_wait Got: {} <= {} <= {}".format(poll_interval,aging_time,max_wait))
            return False
    else:
        st.error("This api doesn't verify aging time 0")
        return False
    ### Get current time in seconds
    start_time = time.time()
    fail_dut_list = []
    ### Processing mac_table filters vlan=None,port=None,type=None,mac_search = None
    vlan = kwargs.get('vlan', None)
    port = kwargs.get('port', None)
    type = kwargs.get('type', None)
    mac_search = kwargs.get('mac_search', None)

    for i in range(poll_interval,max_wait,poll_interval):
        st.wait(poll_interval)
        ### counter which keeps track of duts in which MACs successfully aged out
        dut_pass_counter = 0
        [actual_macs, exceptions] = utils.exec_foreach(True, dut_list, mac_obj.get_mac_count)
        if not all(i is None for i in exceptions):
            print_log(exceptions)
        for dut, mac_count, expect_mac in zip(dut_list, actual_macs, mac_list):
            if (mac_count == expect_mac):
                current_time = time.time()
                time_elapsed = current_time - start_time
                if time_elapsed >= aging_time:
                    st.log("PASS: MAC aging Success in Dut-{}. Current wait_time:{}. age_time:{}".format(dut,time_elapsed,aging_time))
                    dut_pass_counter += 1
        ### If MAC successfully aged out in all DUTs, break from polling loop, return True
        if dut_pass_counter == len(dut_list):
            return True

    current_time = time.time()
    time_elapsed = current_time - start_time
    ### Wait for remaining max_wait time
    if time_elapsed < max_wait:
        st.wait(max_wait-time_elapsed)

    dut_pass_counter = 0

    [actual_macs, exceptions] = utils.exec_foreach(True, dut_list, mac_obj.get_mac_count)
    if not all(i is None for i in exceptions):
        print_log(exceptions)
    for dut, mac_count, expect_mac in zip(dut_list, actual_macs, mac_list):
        current_time = time.time()
        time_elapsed = current_time - start_time
        if (mac_count == expect_mac):
            st.log("PASS: MAC aging Success in Dut-{}. Current wait_time:{}. age_time:{}".format(dut, time_elapsed, aging_time))
            dut_pass_counter += 1
        else:
            # Sonic-12601 - Dumping all macs in case of failure
            mac_obj.get_mac(dut)
            st.error("FAIL: MACs did not age out in Dut-{} after waiting for {} seconds.".format(dut,time_elapsed))
            fail_dut_list.append(dut)
    ### l2 show output in scaled scenario is large, commenting for now l If need to re-enabled add maxtimeout=sec in  l2_show api
    #if len(fail_dut_list) > 0 :
        #utils.exec_all(True, [[asicapi.dump_l2, dut] for dut in fail_dut_list])
    if dut_pass_counter == len(dut_list):
        return True
    else:
        return False


def toggle_lag_ports(po_key_list,port_operation="disable",port_order="odd"):
    res_flag = True
    global po_reconfig_flag
    for po_key in po_key_list:
        po_name = data.portchannel[po_key]["name"]
        dut1 = data.portchannel[po_key]["duts"][0]
        dut2 = data.portchannel[po_key]["duts"][1]
        D1D2_po_members = data.portchannel[po_key]["dut1_members"]
        D2D1_po_members = data.portchannel[po_key]["dut2_members"]
        if len(D1D2_po_members) < po_link_min_req:
            print_log("TC cannot be run as min required links-{} not present in LAG-{}".format(po_link_min_req, po_name), 'MED')
            st.report_fail("operation_failed")
        ### Get list of ports to be flapped.
        if port_order == 'even':
            D1D2_po_ports = D1D2_po_members[::2]
            D2D1_po_ports = D2D1_po_members[::2]
        elif port_order == 'odd':
            D1D2_po_ports = D1D2_po_members[1::2]
            D2D1_po_ports = D2D1_po_members[1::2]
        if port_operation == "disable":
            [result, exceptions] = utils.exec_all(True, [[intf_obj.interface_shutdown, dut, dut_po_ports] \
                                    for dut, dut_po_ports in zip([dut1,dut2],[D1D2_po_ports,D2D1_po_ports]) ] )

        elif port_operation == "enable":
            [result, exceptions] = utils.exec_all(True, [[intf_obj.interface_noshutdown, dut, dut_po_ports] \
                                                         for dut, dut_po_ports in
                                                         zip([dut1, dut2], [D1D2_po_ports, D2D1_po_ports])])
        if not all(i is None for i in exceptions):
            print_log(exceptions)
        if False in result:
            print_log("LAG port flap failed for {}".format(po_name))
            res_flag = False
            po_reconfig_flag += 1
            fail_msg = 'Portchannel-{} member port {} Failed'.format(po_name, port_operation)
            st.report_fail("test_case_failure_message", fail_msg)

    return res_flag


def verify_po_state(po_key_list,state='up'):
    '''
    Verify whether PO state is 'up' or 'down'
    Doesn't verify member port states.
    :param po_key_list: list of keys to PO dictionary
    :param state: up or down
    :return:  True or False
    '''
    ver_flag = True
    global po_reconfig_flag
    for po_key in po_key_list:
        po_name = data.portchannel[po_key]["name"]
        dut1 = data.portchannel[po_key]["duts"][0]
        dut2 = data.portchannel[po_key]["duts"][1]
        [result, exceptions] = utils.exec_foreach(True, data.portchannel[po_key]["duts"],po_obj.verify_portchannel_state,portchannel=po_name, state=state)
        if not all(i is None for i in exceptions):
            print_log(exceptions)
        if False in result:
            print_log('Portchannel-{} is not {} in dut{}-dut{}'.format(po_name, state, dut1, dut2), 'MED')
            ver_flag = False
            po_reconfig_flag += 1
            fail_msg = 'Portchannel-{} is not {}'.format(po_name, state)
            st.report_fail("test_case_failure_message", fail_msg)

    return ver_flag


def add_del_lag_member_ports(po_key_list,port_count,flag="del"):
    res_flag = True
    global po_reconfig_flag
    for po_key in po_key_list:
        po_name = data.portchannel[po_key]["name"]
        dut1 = data.portchannel[po_key]["duts"][0]
        dut2 = data.portchannel[po_key]["duts"][1]
        D1D2_po_members = data.portchannel[po_key]["dut1_members"]
        D2D1_po_members = data.portchannel[po_key]["dut2_members"]
        if len(D1D2_po_members) < po_link_min_req:
            print_log("TC cannot be run as min required links-{} not present in LAG-{}".format(po_link_min_req, po_name), 'MED')
            res_flag = False
            st.report_fail("operation_failed")
        ### Get list of ports to be altered.
        D1D2_po_ports = D1D2_po_members[len(D1D2_po_members) - port_count:]
        D2D1_po_ports = D2D1_po_members[len(D2D1_po_members) - port_count:]
        [result, exceptions] = utils.exec_all(True, [
            [po_obj.add_del_portchannel_member, dut, po_name, dut_po_members, flag] for dut, dut_po_members in
            zip([dut1,dut2], [D1D2_po_ports,D2D1_po_ports]) ] )
        if not all(i is None for i in exceptions):
            print_log(exceptions)
        if False in result:
            print_log('Portchannel-{} members-{},{} operation-{} FAILED'.format(po_name,D1D2_po_ports,D2D1_po_ports,flag), 'MED')
            res_flag =False
            po_reconfig_flag += 1
            fail_msg = 'Portchannel-{} member port {} Failed'.format(po_name,flag)
            st.report_fail("test_case_failure_message", fail_msg)
    return res_flag


@pytest.mark.l2fwd_ip
@pytest.mark.l2fwd_static_mac_scale
def test_static_mac_scale():
    final_result = True
    mac_count_fail = 0
    traffic_forward_fail = 0
    flooding_fail = 0
    mac_aging_fail = 0
    tc_list = ['FtOpSoSwL2FwdFn003']
    print_log("START of TC ==> test_static_mac_scale\n TCs:<{}>".format(tc_list), "HIGH")

    # Create new vlan
    vlan_phyA = data.tc_specific_vlan
    vlan_phyT = str(data.tc_specific_vlan + 1) + ' ' + str(data.tc_specific_vlan + 2)
    vlan_lagT = str(data.tc_specific_vlan + 3) + ' ' + str(data.tc_specific_vlan + 4)

    vlan_lagA = data.tc_specific_vlan + 5

    total_static_mac_count = 6

    ### Clear port counters
    utils.exec_all(True, [[port_obj.clear_interface_counters, dut] for dut in data.ver_dut_list])

    st_key = 'EE'
    stream1 = data.stream_data[st_key]['streamAB']
    stream2 = data.stream_data[st_key]['streamBA']
    tg_h.tg_traffic_control(action='run', handle=stream1)
    #tg_h.tg_traffic_control(action='run', handle=stream2)
    st.wait(20)
    [result, exceptions] = utils.exec_all(True, [
        [verify_flooding_on_dut, dut, [st.get_tg_links(dut)[0][0]], data.counters_threshold] \
        for dut in data.ver_dut_list])
    if not all(i is None for i in exceptions):
        print_log(exceptions)
    if True in result:
        print_log('FAIL:Uni-directional Traffic with static MAC flooding is seen, expect_tx_pkt < {}'.format(
            data.counters_threshold), 'ERROR')
        final_result = False
        flooding_fail += 1
    else:
        print_log('PASS:Uni-directional Traffic with static MAC flooding is not seen, expect_tx_pkt < {}'.format(
            data.counters_threshold), 'MED')

    tg_h.tg_traffic_control(action='stop', handle=stream1)

    if final_result:
        st.report_pass("test_case_passed")
    else:
        fail_msg = ''
        if mac_count_fail > 0:
            fail_msg += 'MAC Verification Failed:'
        if traffic_forward_fail > 0:
            fail_msg += 'Traffic Forwarding Failed:'
        if mac_aging_fail > 0:
            fail_msg += 'MAC aging Failed:'
        if flooding_fail > 0:
            fail_msg += 'Flooding Verification Failed:'
        st.report_fail("test_case_failure_message", fail_msg.strip(':'))

def verify_mac_table_count(dut,total_macs=data.mac_count_check,trigger_string='clear fdb table'):
    final_result = True
    mac_count_fail = 0
    start_time = datetime.datetime.now()
    iteration = 0
    max_wait = 70
    actual_mac_count = 0
    platform = basic_obj.get_hwsku(dut)
    prev_mac_count = 0
    while iteration < max_wait:
        actual_mac_count = mac_obj.get_mac_count(dut)
        if prev_mac_count == actual_mac_count: break
        prev_mac_count = actual_mac_count
        if actual_mac_count >= total_macs : break
        st.wait(3)
        iteration +=1
    end_time = datetime.datetime.now()
    diff = (end_time - start_time).total_seconds()
    # Temporary 32000 MAC validation , replace later with actual_mac_count == total_macs
    if (actual_mac_count >= total_macs):
        print_log("DUT: {} - Platform ** {} ** Time taken to learn MACs after trigger:<{}> is {}".format(dut,platform,trigger_string,diff),'MED')
    elif (actual_mac_count < 32000):
        print_log("FAIL:Total MAC on DUT {} Platform ** {} ** in time {} were Expected: {}, Got: {}".format(dut,platform, diff,total_macs, actual_mac_count),'ERROR')
        final_result = False
        mac_count_fail += 1
    else:
        print_log("DUT: {} - Platform ** {} ** Time taken to learn MACs after trigger:<{}> is {}".format(dut,platform,trigger_string,diff),'MED')
    return final_result

def dut_health_check():
    for dut in data.my_dut_list:
        platform = basic_obj.get_hwsku(dut)
        m1 = basic_obj.get_memory_info(dut)
        c1_syncd = basic_obj.get_top_info(dut,'syncd')
        c1_orchagent = basic_obj.get_top_info(dut,'orchagent')
        c1_vlanmgrd = basic_obj.get_top_info(dut,'vlanmgrd')
        c1_teammgrd = basic_obj.get_top_info(dut,'teammgrd')

        print_log("DUT: {} - Platform ** {} **: memory : {} \n CPU syncd : {} "
                  "\n CPU orchagent : {} \n CPU vlanmgrd : {} \n CPU teammgrd : {}".format(dut,platform,m1,c1_syncd,c1_orchagent,c1_vlanmgrd,c1_teammgrd), 'MED')
        data.memory_usage.append([dut,platform,m1])
        data.cpu_orchagt.append([dut,platform,c1_orchagent])
        data.cpu_syncd.append([dut,platform,c1_syncd])
        data.cpu_vland.append([dut,platform,c1_vlanmgrd])
        data.cpu_teamd.append([dut,platform,c1_teammgrd])

def verify_all_po_state():
    for po_key in data.portchannel:
        po_name = data.portchannel[po_key]["name"]
        dut_pair = data.portchannel[po_key]["duts"]
        D1D2_po_members = data.portchannel[po_key]["dut1_members"]
        D2D1_po_members = data.portchannel[po_key]["dut2_members"]
        if not  verify_portchannel(dut_pair,po_name,[D1D2_po_members,D2D1_po_members]):
            return False
    return True



@pytest.fixture(scope="function")
def cleanup_stp_mac_move():
    yield
    print_log("CLEANUP for test_stp_mac_move",'HIGH')
    d1 = data.my_dut_list[0]
    d2 = data.my_dut_list[1]
    trunk_link = data.access_port_count
    d1_trunk_port = st.get_dut_links_local(d1, peer=d2)[trunk_link]
    d2_trunk_port = st.get_dut_links_local(d2, peer=d1)[trunk_link]
    lagT_po_key = data.po_metadata[(d1, 'trunk')]['base_id']
    lagT_po_name = data.portchannel[lagT_po_key]['name']
    lagA_po_key = data.po_metadata[(d1, 'access')]['base_id']
    lagA_po_name = data.portchannel[lagA_po_key]['name']
    print_log("Begin TC:test_stp_mac_move unconfigurations", 'MED')
    ### Disable PVST globally
    utils.exec_all(True, [[pvst_obj.config_spanning_tree, dut, "pvst", "disable"] for dut in
                          [d1,d2]])
    ###Reset aging time -- Comment as age time config/unconfig done as part of module config/unconfig
    #utils.exec_all(True, [[mac_obj.config_mac_agetime, dut,data.default_macage] for dut in [d1, d2]])
    ### UnConfigure base_access_vlan from trunk phyPort
    api_list = []
    api_list.append([vlan_obj.delete_vlan_member, d1, data.base_access_vlan, d1_trunk_port, True])
    api_list.append([vlan_obj.delete_vlan_member, d2, data.base_access_vlan, d2_trunk_port, True])
    utils.exec_all(True, api_list)
    ### UnConfigure trunk phyPort base vlan from trunk PO
    if data.base_trunk_vlan < 255:
        api_list = []
        api_list.append([vlan_obj.delete_vlan_member, d1, data.base_trunk_vlan, lagT_po_name, True])
        api_list.append([vlan_obj.delete_vlan_member, d2, data.base_trunk_vlan, lagT_po_name, True])
        utils.exec_all(True, api_list)
    ### UnConfigure access PO base vlan from trunk PO
    if data.base_lagA_vlan < 255:
        api_list = []
        api_list.append([vlan_obj.delete_vlan_member, d1, data.base_lagA_vlan, lagT_po_name, True])
        api_list.append([vlan_obj.delete_vlan_member, d2, data.base_lagA_vlan, lagT_po_name, True])
        utils.exec_all(True, api_list)
    dut_port_dict = {}
    d1 = data.my_dut_list[0]
    d2 = data.my_dut_list[1]
    dut_port_dict[d1] = st.get_dut_links_local(d1, peer=d2)[0]
    utils.exec_all(True, [[intf_obj.interface_operation, dut, dut_port_dict[dut], 'startup'] for dut in
                          dut_port_dict.keys()])
    toggle_lag_ports([lagT_po_key], 'enable', 'odd')
    print_log("### CLEANUP End####")

def test_stp_mac_perf(cleanup_stp_mac_move):
    final_result = True
    mac_count_fail = 0
    traffic_forward_fail = 0
    flooding_fail = 0
    mac_aging_fail = 0
    tc_list = ['FtOpSoSwL2FwdPe004']
    print_log("START of TC ==> test_stp_mac_perf\n TCs:<{}>".format(tc_list), "HIGH")
    stp_wait_time = 15
    #stp_wait_time = 25
    traffic_time = 20
    d1 = data.my_dut_list[0]
    d2 = data.my_dut_list[1]
    d1_access_port = st.get_dut_links_local(d1, peer=d2)[0]
    d2_access_port = st.get_dut_links_local(d2, peer=d1)[0]
    trunk_link = data.access_port_count
    d1_trunk_port = st.get_dut_links_local(d1, peer=d2)[trunk_link]
    d2_trunk_port = st.get_dut_links_local(d2, peer=d1)[trunk_link]
    lagT_po_key = data.po_metadata[(d1, 'trunk')]['base_id']
    lagT_po_name = data.portchannel[lagT_po_key]['name']
    lagA_po_key = data.po_metadata[(d1, 'access')]['base_id']
    lagA_po_name = data.portchannel[lagA_po_key]['name']
    ### Configure base_access_vlan on trunk phyPort
    api_list = []
    api_list.append([vlan_obj.add_vlan_member, d1, data.base_access_vlan, d1_trunk_port, True])
    api_list.append([vlan_obj.add_vlan_member, d2, data.base_access_vlan, d2_trunk_port, True])
    utils.exec_all(True, api_list)
    ### Configure trunk phyPort base vlan to trunk PO
    if data.base_trunk_vlan < 255:
        api_list = []
        api_list.append([vlan_obj.add_vlan_member, d1, data.base_trunk_vlan, lagT_po_name, True])
        api_list.append([vlan_obj.add_vlan_member, d2, data.base_trunk_vlan, lagT_po_name, True])
        utils.exec_all(True, api_list)
    ### Configure access PO base vlan to trunk PO
    if data.base_lagA_vlan < 255:
        api_list = []
        api_list.append([vlan_obj.add_vlan_member, d1, data.base_lagA_vlan, lagT_po_name, True])
        api_list.append([vlan_obj.add_vlan_member, d2, data.base_lagA_vlan, lagT_po_name, True])
        utils.exec_all(True, api_list)

    print_log("Enable xSTP and verify mac learning and traffic forwarding",'MED')
    ### Before Enabling STP globally, disable it explicitly on vlans in which STP not needed, to avoid STP max instance problem
    stp_vlans = [data.base_access_vlan, data.base_trunk_vlan, data.base_lagA_vlan, data.base_lagT_vlan]
    ### Current fix will increase execution time by ~30 min, need to change to range command once support comes in B+MR
    for vlan_id in range(1,data.total_vlan_count):
        if vlan_id not in stp_vlans:
            utils.exec_foreach(True, [d1, d2], stp_obj.config_stp_vlan_disable, vlanid=vlan_id)
    ### Enable PVST globally and configure lower timer values
    utils.exec_all(True, [[pvst_obj.config_spanning_tree, dut, "pvst", "enable"] for dut in [d1, d2]])
    utils.exec_foreach(True, [d1, d2], pvst_obj.config_stp_parameters, max_age=7)
    utils.exec_foreach(True, [d1, d2], pvst_obj.config_stp_parameters, forward_delay=5)

    ### Configure DUT-1 as root bridge
    utils.exec_foreach(True, [d1], pvst_obj.config_stp_parameters, priority=8192)
    #Temp added sleep for config stability
    st.wait(120)
    ### Configure lower port priority on access links and trunk PO so that it is selected path by default
    api_list = []
    api_list.append([pvst_obj.config_stp_vlan_interface, d1, data.base_access_vlan, d1_access_port, 64, 'priority'])
    api_list.append([pvst_obj.config_stp_vlan_interface, d2, data.base_access_vlan, d2_access_port, 64, 'priority'])
    utils.exec_all(True, api_list)
    utils.exec_foreach(True, [d1, d2], pvst_obj.config_stp_vlan_interface, data.base_trunk_vlan, lagT_po_name, 64,
                       mode='priority')

    print_log("Waiting for {} sec for STP convergence".format(stp_wait_time), 'MED')
    st.wait(stp_wait_time)
    ### show STP
    #vlans = [data.base_access_vlan, data.base_trunk_vlan, data.base_lagA_vlan]
    vlans = [data.base_access_vlan, data.base_trunk_vlan]
    for vlan in vlans:
        utils.exec_all(True, [[pvst_obj.show_stp_vlan, dut, vlan] for dut in [d1, d2]])
    ### Clear MAC in the beginning to ensure clean DUT , avoid mac aging fail and clear fails in previous TC
    utils.exec_all(True, [[mac_obj.clear_mac, dut] for dut in [d1, d2]])
    stp_src_stream_list = [data.stream_data['FF']['streamAB']]
    stp_dst_stream_list = [data.stream_data['FF']['streamBA']]
    start_stop_traffic(src_stream_list=stp_src_stream_list, dest_stream_list=stp_dst_stream_list, duration=traffic_time)

    expected_mac = 2 * data.stp_macs + data.static_mac_count
    expect_mac_list = [expected_mac for dut in [d1,d2]]
    #check_mac_count_list([d1,d2], expect_mac_list)
    #verify_mac_table([d1,d2], expect_mac_list,mac_search='00:')
    if not retry_func(check_mac_count_list, dut_list=[d1,d2], expect_mac_list=expect_mac_list):
        final_result = False
        mac_count_fail += 1
        print_log("FAIL: Verify scale mac failed before STP triggers",'ERROR')
    else:
        print_log("PASS: Verify scale mac passed before STP triggers", 'MED')

    print_log("Change Root Bridge and shut interfaces/LAG and Measure MAC learn time after STP reconvergence.", "HIGH")
    ### Configure DUT-2 as root bridge
    utils.exec_foreach(True, [d2], pvst_obj.config_stp_parameters, priority=4096)
    ### Shut  access links and trunk PO member ports.
    dut_port_dict = {}
    dut_port_dict[d1] = d1_access_port
    #dut_port_dict[d2] = lagA_po_name
    utils.exec_all(True, [[intf_obj.interface_operation, dut, dut_port_dict[dut], 'shutdown'] for dut in
                          dut_port_dict.keys()])
    toggle_lag_ports([lagT_po_key], 'disable', 'odd')
    print_log("Waiting for {} sec for STP convergence".format(stp_wait_time), 'MED')
    st.wait(stp_wait_time)
    ### show STP
    for vlan in vlans:
        utils.exec_all(True, [[pvst_obj.show_stp_vlan, dut, vlan] for dut in [d1, d2]])

    ### Verify MAC learned after STP re-convergence.
    stp_stream_list = [data.stream_data['FF']['streamAB'], data.stream_data['FF']['streamBA']]
    tg_h.tg_traffic_control(action='run', handle=stp_stream_list)
    expected_mac = 2 * data.stp_macs + data.static_mac_count
    expect_mac_list = [expected_mac for dut in data.my_dut_list]
    [result, exceptions] = utils.exec_all(True, [[verify_mac_table_count, dut, expected_mac,'STP re-convergence'] \
                                                 for dut,expected_mac in zip(data.my_dut_list,expect_mac_list)])
    if not all(i is None for i in exceptions):
        print_log(exceptions)
    if False in result:
        print_log("MAC Table verification FAILED", "HIGH")
        final_result = False
        mac_count_fail += 1
    else:
        print_log("MAC Table verification PASSED", "HIGH")

    tg_h.tg_traffic_control(action='stop', handle=stp_stream_list)

    if final_result:
        st.report_pass("test_case_passed")
    else:
        fail_msg = ''
        if mac_count_fail > 0:
            fail_msg += 'MAC Verification Failed:'
        if traffic_forward_fail > 0:
            fail_msg += 'Traffic Forwarding Failed:'
        if mac_aging_fail > 0:
            fail_msg += 'MAC aging Failed:'
        if flooding_fail > 0:
            fail_msg += 'Flooding Verification Failed:'
        st.report_fail("test_case_failure_message", fail_msg.strip(':'))

@pytest.mark.l2fwd_phase3
@pytest.mark.l2fwd_mac_perf
def test_scale_vlans_macs():
    '''
        1. Configure 4K vlans and send scale mac traffic
        2. Create traffic streams for scaled macs
        3. Send traffic streams and verify - Note CPU and memory before and after.
        4. Clear fdb table and measure mac learning. - Note CPU and memory.
        5. Flap lag interface and measure mac learning.- Note CPU and memory.
        6. Save and reload config.
        7. Fast reboot.
        8. Remove traffic streams and vlans.- Note CPU and memory.
        9. Display memory and cpu summary for all DUTs.
    '''

    final_result = True
    mac_count_fail = 0
    traffic_forward_fail = 0
    flooding_fail = 0
    mac_aging_fail = 0
    po_state_fail = 0
    tc_list = ['FtOpSoSwL2FwdSc001','FtOpSoSwL2FwdSc002','FtOpSoSwL2FwdSc004','FtOpSoSwL2FwdNe004',
               'FtOpSoSwL2FwdPe003','FtOpSoSwL2FwdPe005','FtOpSoSwL2FwdPe006','FtOpSoSwL2FwdPe007','FtOpSoSwL2FwdPe008']
    print_log("START of TC ==> test_scale_vlans_macs\n TCs:<{}>".format(tc_list), "HIGH")
    dut1 = data.my_dut_list[0]

    print_log("TC Summary :==> Subtest : Verify MAC learning on max vlans.", "MED")
    sub_tc_result = 0
    po_key = data.po_metadata[(dut1, 'trunk')]['base_id']
    trunk_lag = data.portchannel[po_key]['name']
    st_key = 'AA'
    stream1 = data.stream_data[st_key]['streamAB']
    stream2 = data.stream_data[st_key]['streamBA']
    ############### Start Traffic streams ####################
    # Memory and CPU before starting traffic
    print_log("Memory and CPU of each dut before running traffic")
    dut_health_check()
    tg_h.tg_traffic_control(action='run', handle=stream1)
    tg_h.tg_traffic_control(action='run', handle=stream2)
    for st_key in range(0,len(data.ver_dut_list)):
        dut_mac_scale = (data.mac_scale_list[st_key]/2) - data.total_mac_count
        if dut_mac_scale < 2: break
        stream1 = data.stream_data[st_key]['streamAB']
        stream2 = data.stream_data[st_key]['streamBA']
        tg_h.tg_traffic_control(action='run', handle=stream1)
        tg_h.tg_traffic_control(action='run', handle=stream2)
    print_log("Memory and CPU of each dut after running traffic")
    dut_health_check()
    trigger_str = "After starting traffic streams"
    #Temp added sleep for config stability
    st.wait(60)
    #Temp added sleep for config stability
    [result,exceptions] = utils.exec_all(True, [[verify_mac_table_count, dut, mac_count, trigger_str]
                                                for dut,mac_count in zip(data.my_dut_list,data.verify_mac_scale)])
    if not all(i is None for i in exceptions):
        print_log(exceptions)
    if False in result:
        print_log("MAC Table verification FAILED", "HIGH")
        final_result = False
        mac_count_fail += 1
        sub_tc_result += 1
    else:
        print_log("MAC Table verification PASSED", "HIGH")

    if sub_tc_result > 0:
        st.report_tc_fail("FtOpSoSwL2FwdSc001", "test_case_failure_message",
                          "Max MAC learning failed")
        st.report_tc_fail("FtOpSoSwL2FwdSc002", "test_case_failure_message",
                          "MAC learning on MAX vlans(2K) failed")
        st.report_tc_fail("FtOpSoSwL2FwdNe004", "test_case_failure_message",
                          "MAC learning with MACs send more than platform limit Failed")
    else:
        st.report_tc_pass('FtOpSoSwL2FwdSc001', "test_case_passed")
        st.report_tc_pass('FtOpSoSwL2FwdSc002', "test_case_passed")
        st.report_tc_pass('FtOpSoSwL2FwdNe004', "test_case_passed")

    print_log("Memory and CPU of each dut before clear mac table")
    dut_health_check()
    ################# Clear fdb table ##############
    print_log("Trigger: clear fdb table ...")
    sub_tc_result = 0
    # Measure mac learn time after clear fdb table
    utils.exec_all(True, [[mac_obj.clear_mac, dut] for dut in data.my_dut_list])
    trigger_str = "After clear fdb "
    #Temp added sleep for config stability
    #-#st.wait(200)
    st.wait(data.traffic_run_time)
    #Temp added sleep for config stability

    [result,exceptions] = utils.exec_all(True, [[verify_mac_table_count, dut, mac_count, trigger_str]
                                                for dut,mac_count in zip(data.my_dut_list,data.verify_mac_scale)])
    if not all(i is None for i in exceptions):
        print_log(exceptions)
    if False in result:
        print_log("MAC Table verification FAILED after clear mac table", "HIGH")
        final_result = False
        mac_count_fail += 1
        sub_tc_result += 1
    else:
        print_log("MAC Table verification PASSED after clear mac table", "HIGH")

    if sub_tc_result > 0:
        st.report_tc_fail("FtOpSoSwL2FwdPe005", "test_case_failure_message",
                          "Max MAC re-learning after clear MAC failed")
    else:
        st.report_tc_pass('FtOpSoSwL2FwdPe005', "test_case_passed")


    print_log("Memory and CPU of each dut after clear mac and before port flap ")
    dut_health_check()
    sub_tc_result = 0
    print_log("MAC count after portchannel flap.")
    # Measure mac learn time after LAG shut/no shut
    intf_obj.interface_operation(dut1,trunk_lag, 'shutdown')
    intf_obj.interface_operation(dut1,trunk_lag, 'startup')

    #Temp added sleep for config stability
    #-#st.wait(200)
    st.wait(data.traffic_run_time)
    #Temp added sleep for config stability
    if not verify_all_po_state():
        print_log("PortChannel is down", "HIGH")
        final_result = False
        po_state_fail += 1
        sub_tc_result = 1

    trigger_str = "After portchannel shut/no shut "
    [result,exceptions] = utils.exec_all(True, [[verify_mac_table_count, dut, mac_count, trigger_str]
                                                for dut,mac_count in zip(data.my_dut_list,data.verify_mac_scale)])
    if not all(i is None for i in exceptions):
        print_log(exceptions)
    if False in result:
        print_log("MAC Table verification FAILED after LAG flap", "HIGH")
        final_result = False
        mac_count_fail += 1
        sub_tc_result = 2
    else:
        print_log("MAC Table verification PASSED after LAG flap", "HIGH")

    if sub_tc_result == 1:
        st.report_tc_fail("FtOpSoSwL2FwdSc004", "test_case_failure_message",
                          "Max LAGs failed")
    else:
        st.report_tc_pass('FtOpSoSwL2FwdSc004', "test_case_passed")

    if sub_tc_result == 2:
        st.report_tc_fail("FtOpSoSwL2FwdPe006", "test_case_failure_message",
                          "Re-learn max MACs after link toggle failed")
    else:
        st.report_tc_pass('FtOpSoSwL2FwdPe006', "test_case_passed")


    print_log("Memory and CPU of each dut after port flap and before config save and reload")
    dut_health_check()
    sub_tc_result = 0
    # Config reload
    boot_obj.config_save_reload(data.my_dut_list)
    #Temp added sleep for config stability
    st.wait(200)
    #-#st.wait(data.traffic_run_time)
    #Temp added sleep for config stability
    if not verify_all_po_state():
        print_log("PortChannel is down", "HIGH")
        final_result = False
        po_state_fail += 1
        sub_tc_result = 1
    trigger_str = "After config save and reload "
    [result,exceptions] = utils.exec_all(True, [[verify_mac_table_count, dut, mac_count, trigger_str]
                                                for dut,mac_count in zip(data.my_dut_list,data.verify_mac_scale)])
    if not all(i is None for i in exceptions):
        print_log(exceptions)
    if False in result:
        print_log("MAC Table verification FAILED after config save and reload", "HIGH")
        final_result = False
        mac_count_fail += 1
        sub_tc_result = 2
    else:
        print_log("MAC Table verification PASSED after config save and reload", "HIGH")

    if sub_tc_result == 1:
        st.report_tc_fail("FtOpSoSwL2FwdPe007", "test_case_failure_message",
                          "LAG re-convergence failed")
    else:
        st.report_tc_pass('FtOpSoSwL2FwdPe007', "test_case_passed")

    if sub_tc_result == 2:
        st.report_tc_fail("FtOpSoSwL2FwdPe003", "test_case_failure_message",
                          "Re-learn max MACs after DUT reload failed")
    else:
        st.report_tc_pass('FtOpSoSwL2FwdPe003', "test_case_passed")


    print_log("Memory and CPU of each dut after config save and reload and before Warm Reboot")
    dut_health_check()
    print_log("Warm Reboot ...")
    utils.exec_foreach(True,data.my_dut_list,boot_obj.config_warm_restart,oper="enable",tasks=["system", "teamd"])
    utils.exec_all(True, [[st.reboot, dut, "warm"] for dut in data.my_dut_list])

    st.wait(120)
    if not verify_all_po_state():
        print_log("PortChannel is down", "HIGH")
        final_result = False
        po_state_fail += 1

    trigger_str = "After warm reboot "
    [result, exceptions] = utils.exec_all(True, [[verify_mac_table_count, dut, mac_count, trigger_str]
                                                     for dut, mac_count in zip(data.my_dut_list, data.verify_mac_scale)])
    if not all(i is None for i in exceptions):
        print_log(exceptions)
    if False in result:
        print_log("MAC Table verification FAILED after Warm Reboot", "HIGH")
        final_result = False
        mac_count_fail += 1
    else:
        print_log("MAC Table verification PASSED after Warm Reboot", "HIGH")

    print_log("Memory and CPU of each dut after Warm Reboot.")
    dut_health_check()

    # SONIC-13176 - Commenting teamd restart
    #print_log("Trigger: teamd docker restart ...")
    #utils.exec_all(True,
    #               [[basic_obj.service_operations_by_systemctl, dut, "teamd", "restart"] for dut in data.my_dut_list])
    #st.wait(30)
    #if not verify_all_po_state():
    #    print_log("PortChannel is down", "HIGH")
    #    final_result = False
    #    po_state_fail += 1
    #trigger_str = "After teamd docker restart"
    #[result, exceptions] = utils.exec_all(True, [[verify_mac_table_count, dut, mac_count, trigger_str]
    #                                             for dut, mac_count in zip(data.my_dut_list, data.verify_mac_scale)])
    #if not all(i is None for i in exceptions):
    #    print_log(exceptions)
    #if False in result:
    #    print_log("MAC Table verification FAILED after teamd Docker Restart", "HIGH")
    #    final_result = False
    #    mac_count_fail += 1
    #else:
    #    print_log("MAC Table verification PASSED after teamd Docker Restart", "HIGH")

    #print_log("Memory and CPU of each dut after teamd Docker Restart and before Fast Reboot ")
    #dut_health_check()

    print_log("Trigger: Fast Reboot ...")
    utils.exec_all(True, [[st.reboot, dut, "fast"] for dut in data.my_dut_list])
    # Temp added sleep for config stability
    st.wait(240,"Recommended Wait for PO to come up with scaled configs -JIRA 17890")
    #-#st.wait(data.traffic_run_time)
    if not verify_all_po_state():
        print_log("PortChannel is down", "HIGH")
        final_result = False
        po_state_fail += 1

    trigger_str = "After Fast reboot "
    [result, exceptions] = utils.exec_all(True, [[verify_mac_table_count, dut, mac_count, trigger_str]
                                                 for dut, mac_count in zip(data.my_dut_list, data.verify_mac_scale)])
    if not all(i is None for i in exceptions):
        print_log(exceptions)
    if False in result:
        print_log("MAC Table verification FAILED after Fast Reboot", "HIGH")
        final_result = False
        mac_count_fail += 1
    else:
        print_log("MAC Table verification PASSED after Fast Reboot", "HIGH")

    print_log("Memory and CPU of each dut after fast reboot.")
    dut_health_check()

    st_key = 'AA'
    stream1 = data.stream_data[st_key]['streamAB']
    stream2 = data.stream_data[st_key]['streamBA']
    stream_list = [stream1] + [stream2]
    for st_key in range(0,len(data.ver_dut_list)):
        #dut_mac_scale = (data.mac_scale_list[st_key] - data.common_mac_scale)/2
        dut_mac_scale = (data.mac_scale_list[st_key] / 2) - data.total_mac_count
        if dut_mac_scale < 2: break
        stream1 = data.stream_data[st_key]['streamAB']
        stream2 = data.stream_data[st_key]['streamBA']
        stream_list = stream_list + [stream1] + [stream2]
    tg_h.tg_traffic_control(action='stop', handle=stream_list)
    st.wait(data.mac_age_wait_time)

    dut_mac_zero_list = [data.static_mac_count for i in range(len(data.ver_dut_list))]
    if not verify_macs_ageout(data.ver_dut_list,dut_mac_zero_list,data.mac_aging,data.mac_aging/4,2*data.mac_aging,mac_search=' 00:'):
        final_result = False
        mac_aging_fail += 1

    print_log("Memory and CPU of each dut after stopping traffic.")
    dut_health_check()
    no_duts = len(data.ver_dut_list)
    for j in range(0,no_duts):
        print_log("Summary of Memory usage of DUT: {} - Platform ** {} **".format(data.memory_usage[j][0],data.memory_usage[j][1]), 'MED')
        for i in range(j, len(data.memory_usage), no_duts): print_log(data.memory_usage[i][2])
        print_log("="*80)

    for j in range(0,no_duts):
        print_log("Summary of Orchagent CPU usage of DUT: {} - Platform ** {} **".format(data.cpu_orchagt[j][0],data.cpu_orchagt[j][1]), 'MED')
        for i in range(j, len(data.cpu_orchagt), no_duts): print_log(data.cpu_orchagt[i][2])
        print_log("="*80)

    for j in range(0,no_duts):
        print_log("Summary of Syncd CPU usage of DUT: {} - Platform ** {} **".format(data.cpu_syncd[j][0],data.cpu_syncd[j][1]), 'MED')
        for i in range(j, len(data.cpu_syncd), no_duts): print_log(data.cpu_syncd[i][2])
        print_log("="*80)

    for j in range(0,no_duts):
        print_log("Summary of vlanmgrd CPU usage of DUT: {} - Platform ** {} **".format(data.cpu_vland[j][0],data.cpu_vland[j][1]), 'MED')
        for i in range(j, len(data.cpu_syncd), no_duts): print_log(data.cpu_syncd[i][2])
        print_log("="*80)

    for j in range(0,no_duts):
        print_log("Summary of teammgrd CPU usage of DUT: {} - Platform ** {} **".format(data.cpu_teamd[j][0],data.cpu_teamd[j][1]), 'MED')
        for i in range(j, len(data.cpu_teamd), no_duts): print_log(data.cpu_teamd[i][2])
        print_log("="*80)

    if final_result:
        st.report_pass("test_case_passed")
    else:
        fail_msg = ''
        if mac_count_fail > 0:
            fail_msg += 'MAC Verification Failed:'
        if traffic_forward_fail > 0:
            fail_msg += 'Traffic Forwarding Failed:'
        if mac_aging_fail > 0:
            fail_msg += 'MAC aging Failed:'
        if flooding_fail > 0:
            fail_msg += 'Flooding Verification Failed:'
        if po_state_fail > 0:
            fail_msg += 'PO verification Failed:'
        st.report_fail("test_case_failure_message", fail_msg.strip(':'))

