##########################################################################################
# Title: L2 Forwarding Enhancements Script
# Author1: Sneha Ann Mathew <sneha.mathew@broadcom.com>
# Author2: Nagappa Chincholi <nagappa.chincholi@broadcom.com>
##########################################################################################

import pytest
import time

from spytest import st, tgapi, SpyTestDict

import apis.switching.vlan as vlan_obj
import apis.routing.ip as ip_obj
import apis.switching.mac as mac_obj
import apis.system.interface as intf_obj
import apis.system.port as port_obj
import apis.system.reboot as boot_obj
import apis.switching.portchannel as po_obj
import apis.routing.arp as arp_obj
import apis.switching.stp as stp_obj
import apis.switching.pvst as pvst_obj
import apis.system.basic as basic_obj
import apis.common.asic as asicapi

import utilities.common as utils
import utilities.parallel as pll
import apis.routing.evpn as Evpn

###Resource file variables
data = SpyTestDict()
data.tgen_rate_pps = '1000'
data.traffic_run_time = 5
#data.counters_threshold = 10

test_po_links = 2
po_link_min_req = 2
stp_deconf_flag = 0
po_reconfig_flag = 0
### L2/L3 profile params
data.l2_prof_vlan_flag = 1
data.config_profile = 'l3'
# SONIC-10602
data.slow_mac_del_dut = ['Quanta-IX9-32X','DellEMC-Z9332f-O32','Accton-AS9716-32D','Dell-Z9332F-On']
data.del_mac_wait_time = 4
### Number of Access ports
data.access_port_count = 1
data.base_vlan = 1

### Number of Trunk Ports
data.trunk_port_count = 1
data.trunk_vlan_count = 50

### Number of Access LAGs and number of links in each LAG
data.lagT_count = 1
data.lagT_link_count = 2
data.lagT_vlan_count = 50

### Number of Trunk LAGs and number of links in each LAG
data.lagA_count = 1
data.lagA_link_count = 2

data.default_macage = 0
data.mac_aging = 30
data.strm_mac_count = 50

data.mac_srch_str = " 00:"

data.warm_reboot_dut = ""
data.tc_specific_vlan = 4001
data.tc_specific_vlan_count = 6
data.tc_specific_mac_count = 6
data.tc_specific_vlan_range = str(data.tc_specific_vlan) + ' ' + str(data.tc_specific_vlan + data.tc_specific_vlan_count - 1)
data.platform_list = []

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
    comp_flag = kwargs.get("comp_flag", True)
    if 'retry_count' in kwargs: del kwargs['retry_count']
    if 'delay' in kwargs: del kwargs['delay']
    if 'comp_flag' in kwargs: del kwargs['comp_flag']
    for i in range(retry_count):
        st.log("Attempt %s of %s" %((i+1),retry_count))
        if kwargs.keys() == []:
            if comp_flag:
                if func():
                    return True
            else:
                if not func():
                    return False
        else:
            if comp_flag:
                if func(**kwargs):
                    return True
            else:
                if not func(**kwargs):
                    return False
        if retry_count != (i+1):
            st.log("waiting for %s seconds before retyring again"%delay)
            st.wait(delay)
    if comp_flag:
        return False
    else:
        return True


def retry_parallel(func,dict_list=[],dut_list=[],api_result=True,retry_count=3,delay=2):
    for i in range(retry_count):
        st.log("Attempt %s of %s" %((i+1),retry_count))
        result = pll.exec_parallel(True,dut_list,func,dict_list)
        if api_result:
            if False not in result[0]:
                return api_result
        else:
            if True not in result[0]:
                return api_result
        if retry_count != (i+1):
            st.log("waiting for %s seconds before retyring again"%delay)
            st.wait(delay)
    return  False if api_result else True

def del_vlan1_mem_ports(dut,config="del"):
    mem_ports = st.get_dut_links(dut) + st.get_tg_links(dut)
    for port in mem_ports:
        try:
            vlan_obj.config_vlan_members(dut,1,port[0],config=config)
        except Exception as e1:
            print_log(e1)
            data.l2_prof_vlan_flag = 0

def initialize_topology():
    global vars
    ### Verify Minimum topology requirement is met
    total_links = data.access_port_count + data.trunk_port_count + \
                  (data.lagT_count * data.lagT_link_count) + (data.lagA_count * data.lagA_link_count)
    vars = st.ensure_min_topology("D1D2:{}".format(total_links), "D1T1:2", "D2T1:2")
    ### Seeing few TC failures with 4 node run.Keeping topology to be 2 node till fix is in.
    data.dut_list = st.get_dut_names()
    data.my_dut_list = [data.dut_list[0], data.dut_list[1]]
    print_log("Start Test with minimum topology D1D2:links=>{}-{}:{}".format(data.my_dut_list[0],data.my_dut_list[1],total_links),
        'HIGH')
    for dut in data.my_dut_list:
        data.platform_list.append(basic_obj.get_hwsku(dut))

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

    ### If L2 profile remove members from vlan 1 and disable PVST
    data.config_profile = basic_obj.get_config_profiles(data.my_dut_list[0])
    if data.config_profile == 'l2':
        utils.exec_all(True, [[del_vlan1_mem_ports, dut] for dut in data.my_dut_list])
        utils.exec_all(True, [[pvst_obj.config_spanning_tree, dut, "pvst", "disable"] for dut in data.my_dut_list])

    data.default_macage = mac_obj.get_mac_agetime(data.my_dut_list[0])

    ###Initialize base vlans for each type of links
    data.base_access_vlan = data.base_vlan
    data.base_trunk_vlan = data.base_vlan + data.access_port_count
    data.base_lagT_vlan = data.base_trunk_vlan + (data.trunk_port_count * data.trunk_vlan_count)
    data.base_lagA_vlan = data.base_lagT_vlan + (data.lagT_count * data.lagT_vlan_count)

    # Verify vlans in base config +  buffer vlans (vlans to be used in TCs) doesn't exceed 4000
    if (data.base_lagA_vlan+data.lagA_count) > 4000 :
        st.report_fail("operation_failed")
    data.total_vlan_count = data.access_port_count + (data.trunk_port_count * data.trunk_vlan_count) + \
                            (data.lagT_count * data.lagT_vlan_count) + data.lagA_count + data.tc_specific_vlan_count

    ###Initialize a dictionary of TGEN ports
    dut1 = data.my_dut_list[0]
    dut2 = data.my_dut_list[-1]
    data.tgen_port = {dut1: st.get_tg_links(dut1)[1][0],
                      dut2: st.get_tg_links(dut2)[1][0]}

    ### TC Validations will be done in first and last DUTs
    data.ver_dut_list = [data.my_dut_list[0],data.my_dut_list[-1]]

    # Expected total mac counts on each dut
    data.stream_count = 4
    data.access_strm_macs = (data.access_port_count + data.lagA_count) * data.strm_mac_count
    data.trunk_strm_macs = (data.trunk_port_count * data.trunk_vlan_count) + (data.lagT_count * data.lagT_vlan_count)
    dut_base_mac_count = data.access_strm_macs + data.trunk_strm_macs
    data.dut_mac_count_list = [2 * dut_base_mac_count] * len(data.ver_dut_list)
    data.counters_threshold = (int(data.tgen_rate_pps) * data.traffic_run_time * data.stream_count/ 100) + (data.traffic_run_time * data.stream_count)
    ### Initialize TGEN handles
    get_tgen_handles()

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
    validate_topology()
    print_log("Starting Base Configurations...",'MED')
    l2fwd_base_config()
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

def configure_portchannel(dut1,dut2,po_id,vlan,dut1_po_members,dut2_po_members,min_links=None):
    if min_links == None:
        utils.exec_all(True, [[po_obj.create_portchannel, dut1, po_id], [po_obj.create_portchannel, dut2, po_id]])
    else:
        utils.exec_all(True, [[po_obj.create_portchannel, dut1, po_id, False, min_links], [po_obj.create_portchannel, dut2, po_id, False, min_links]])

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


def unconfigure_portchannel(dut1,dut2,po_id,vlans,dut1_po_members,dut2_po_members):
    if isinstance(vlans, list):
        for vlan_item in vlans:
            if isinstance(vlan_item, str):
                # uses vlan range cli
                ### Remove PO from given vlan range
                utils.exec_all(True, [[vlan_obj.config_vlan_range_members, dut1, vlan_item, po_id,'del'], \
                                      [vlan_obj.config_vlan_range_members, dut2, vlan_item, po_id,'del']])
            else:
                # uses vlan range cli
                ### Remove PO from given vlan
                utils.exec_all(True, [[vlan_obj.delete_vlan_member, dut1, vlan_item, po_id, True], \
                                      [vlan_obj.delete_vlan_member, dut2, vlan_item, po_id, True]])
    else:
        if isinstance(vlans, str):
            # uses vlan range cli
            ### Remove PO from given vlan range
            utils.exec_all(True, [[vlan_obj.config_vlan_range_members, dut1, vlans, po_id,'del'], \
                                  [vlan_obj.config_vlan_range_members, dut2, vlans, po_id,'del']])
        else:
            # uses regular vlan cli
            ### Remove PO from given vlan
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
    vlan_range = str(data.base_vlan) + " " + str(data.base_lagA_vlan+data.lagA_count-1)
    utils.exec_all(True,[[vlan_obj.config_vlan_range,dut, vlan_range] for dut in data.my_dut_list])
    utils.exec_all(True,[[vlan_obj.config_vlan_range,dut, data.tc_specific_vlan_range] for dut in data.my_dut_list])


    ### Tgen port configs on first and last DUT.
    utils.exec_all(True, [[vlan_obj.config_vlan_range_members, dut, vlan_range,data.tgen_port[dut]] for dut in data.ver_dut_list])
    utils.exec_all(True, [[vlan_obj.config_vlan_range_members, dut, data.tc_specific_vlan_range,data.tgen_port[dut]] for dut in data.ver_dut_list])


    ### Configure all VLANs on first TGEN ports of each DUT, to verify flooding.
    utils.exec_all(True, [[vlan_obj.config_vlan_range_members, dut, vlan_range, st.get_tg_links(dut)[0][0]] \
                          for dut in data.my_dut_list])
    utils.exec_all(True, [[vlan_obj.config_vlan_range_members, dut, data.tc_specific_vlan_range, st.get_tg_links(dut)[0][0]] \
                          for dut in data.my_dut_list])

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
            po_name = "PortChannel" + str(poi)
            po_id_str = "po" + str(poi)
            po_id = (d1,po_id_str)
            if poi == po_index:
                data.po_metadata[(d1, 'trunk')] = {'base_id': po_id, 'count': data.lagT_count}
            v_range = str(vlan) + " " + str(vlan + data.trunk_vlan_count - 1)
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
            vlan = vlan + data.trunk_vlan_count
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
        d1 = d2

def l2fwd_base_unconfig():
    print_log("Begin base unconfigs.", "HIGH")

    vlan_range = str(data.base_vlan) + " " + str(data.base_lagA_vlan+data.lagA_count-1)

    ### Tgen port unconfig on first and last DUT.
    utils.exec_all(True, [[vlan_obj.config_vlan_range_members, dut, vlan_range, data.tgen_port[dut],'del'] for dut in
                          data.ver_dut_list])
    utils.exec_all(True, [[vlan_obj.config_vlan_range_members, dut, data.tc_specific_vlan_range, data.tgen_port[dut],'del'] for dut in
                          data.ver_dut_list])

    ### UnConfigure all VLANs on first TGEN ports of each DUT, to verify flooding.
    utils.exec_all(True, [[vlan_obj.config_vlan_range_members, dut, vlan_range, st.get_tg_links(dut)[0][0],'del'] \
                          for dut in data.my_dut_list])
    utils.exec_all(True, [[vlan_obj.config_vlan_range_members, dut, data.tc_specific_vlan_range, st.get_tg_links(dut)[0][0],'del'] \
                          for dut in data.my_dut_list])

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
            po_name = "PortChannel" + str(poi)
            v_range = str(vlan) + " " + str(vlan + data.trunk_vlan_count - 1)
            D1D2_po_members = []
            D2D1_po_members = []
            for i in range(link, link + data.lagT_link_count):
                D1D2_po_members.append(all_links[i][0])
                D2D1_po_members.append(all_links[i][2])
            unconfigure_portchannel(d1, d2, po_name, [v_range], D1D2_po_members, D2D1_po_members)
            vlan = vlan + data.trunk_vlan_count
            link = link + data.lagA_link_count

        # Configure PortChannel Access
        po_index = po_index + data.lagT_count
        link = data.access_port_count + data.trunk_port_count + (data.lagT_count * data.lagT_link_count)
        vlan = data.base_lagA_vlan
        for poi in range(po_index, po_index + data.lagT_count):
            po_name = "PortChannel" + str(poi)
            D1D2_po_members = []
            D2D1_po_members = []
            for i in range(link, link + data.lagA_link_count):
                D1D2_po_members.append(all_links[i][0])
                D2D1_po_members.append(all_links[i][2])
            unconfigure_portchannel(d1, d2, po_name, vlan, D1D2_po_members, D2D1_po_members)
            vlan = vlan + 1
            link = link + data.lagA_link_count
        # Repeat for next set of DUT pairs
        d1 = d2
        if po_index == (1+data.lagT_count) :
            po_index = data.lagA_count + data.lagT_count + 1
        else:
            po_index = 1

    utils.exec_all(True, [[vlan_obj.config_vlan_range, dut, vlan_range,'del'] for dut in data.my_dut_list])
    utils.exec_all(True, [[vlan_obj.config_vlan_range, dut, data.tc_specific_vlan_range,'del'] for dut in data.my_dut_list])
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


def config_diff_traffic_type():
    ### L2 Stream for Access vlan 1 with frame size 128
    # DUT1 -- Access PhyPort -- DUTn
    vlan = data.base_vlan
    v_count = 1
    st_key = 'FF:11'
    src_mac = '00:12:' + st_key + ':00:01'
    dst_mac = '00:21:' + st_key + ':00:01'
    # data.stream_data1[st_key] = {}
    print_log("Create bi-directional L2 stream {} <---> {} with frame size 128 in vlan 1\n\t Expect {}--->{} stream to drop in DUT:2->DUT:1 ingress"\
              .format(src_mac,dst_mac,dst_mac,src_mac),'MED')
    for (src, dst, ph_src, ph_dst) in zip([src_mac, dst_mac], [dst_mac, src_mac], [tg_src_ph1, tg_dest_ph1],
                                          [tg_dest_ph1, tg_src_ph1]):
        stream = tg_h.tg_traffic_config(mode='create', port_handle=ph_src, port_handle2=ph_dst, duration=data.traffic_run_time,
                                        transmit_mode="continuous", rate_pps=data.tgen_rate_pps, frame_size='128', \
                                        l2_encap='ethernet_ii_vlan', vlan="enable", vlan_id=vlan, vlan_id_count=v_count, \
                                        vlan_id_mode="increment", vlan_id_step='1',\
                                        mac_src=src, mac_src_mode="increment", mac_src_step="00:00:00:00:00:01",
                                        mac_src_count=v_count, \
                                        mac_dst=dst, mac_dst_mode="increment", mac_dst_step="00:00:00:00:00:01",
                                        mac_dst_count=v_count)
        if src == src_mac:
            data.stream_data.update({st_key: {'streamAB': stream['stream_id']}})
            data.strm_port[stream['stream_id']] = {'src': data.src_tgn_port, 'dst': data.dest_tgn_port}
            data.strm_macs[stream['stream_id']] = {'src': src, 'dst': dst}
            # data.stream_data[st_key]['streamAB'] = stream['stream_id']
        else:
            data.stream_data[st_key]['streamBA'] = stream['stream_id']
            data.strm_port[stream['stream_id']] = {'src': data.dest_tgn_port, 'dst': data.src_tgn_port}
            data.strm_macs[stream['stream_id']] = {'src': src, 'dst': dst}
    ###IPv4 Stream with frame size 1024
    # DUT1 -- Tagged Phy ports -- DUTn
    vlan = data.base_trunk_vlan
    v_count = data.trunk_vlan_count * data.trunk_port_count
    st_key = 'FF:22'
    src_mac = '00:12:' + st_key + ':00:01'
    dst_mac = '00:21:' + st_key + ':00:01'
    src_ip = '11.1.1.100'
    dst_ip = '21.2.2.100'
    print_log(
        "Create bi-directional IPv4 stream {} <---> {} with frame size 1024\n\t Both streams should forward" \
        .format(src_mac, dst_mac),'MED')
    for (src, dst, s_ip, d_ip, ph_src, ph_dst) in zip([src_mac, dst_mac], [dst_mac, src_mac], [src_ip, dst_ip],
                                                      [dst_ip, src_ip], \
                                                      [tg_src_ph1, tg_dest_ph1], [tg_dest_ph1, tg_src_ph1]):
        stream = tg_h.tg_traffic_config(mode='create', port_handle=ph_src, port_handle2=ph_dst, duration=data.traffic_run_time,
                                        transmit_mode="continuous", rate_pps=data.tgen_rate_pps, frame_size='1024', \
                                        l2_encap='ethernet_ii_vlan', vlan="enable", vlan_id=vlan, vlan_id_count=v_count, \
                                        vlan_id_mode="increment", vlan_id_step='1', \
                                        mac_src=src, mac_src_mode="increment", mac_src_step="00:00:00:00:00:01",
                                        mac_src_count=v_count, \
                                        mac_dst=dst, mac_dst_mode="increment", mac_dst_step="00:00:00:00:00:01",
                                        mac_dst_count=v_count, \
                                        l3_protocol='ipv4', ip_src_addr=s_ip, ip_dst_addr=d_ip)
        if src == src_mac:
            data.stream_data.update({st_key: {'streamAB': stream['stream_id']}})
            data.strm_port[stream['stream_id']] = {'src': data.src_tgn_port, 'dst': data.dest_tgn_port}
            data.strm_macs[stream['stream_id']] = {'src': src, 'dst': dst}
        else:
            data.stream_data[st_key]['streamBA'] = stream['stream_id']
            data.strm_port[stream['stream_id']] = {'src': data.dest_tgn_port, 'dst': data.src_tgn_port}
            data.strm_macs[stream['stream_id']] = {'src': src, 'dst': dst}

    ###IPv6 Stream with frame size 4096
    # DUT1 -- Tagged LAG ports -- DUTn
    vlan = data.base_lagT_vlan
    v_count = data.lagT_vlan_count * data.lagT_count
    st_key = 'FF:33'
    src_mac = '00:12:' + st_key + ':00:01'
    dst_mac = '00:21:' + st_key + ':00:01'
    src_ipv6 = '1001::100'
    dst_ipv6 = '2001::100'
    print_log(
        "Create bi-directional IPv6 stream {} <---> {} with frame size 4096 \n\t  Both streams should forward" \
        .format(src_mac, dst_mac),'MED')
    for (src, dst, s_ip, d_ip, ph_src, ph_dst) in zip([src_mac, dst_mac], [dst_mac, src_mac], [src_ipv6, dst_ipv6],
                                                      [dst_ipv6, src_ipv6], \
                                                      [tg_src_ph1, tg_dest_ph1], [tg_dest_ph1, tg_src_ph1]):
        stream = tg_h.tg_traffic_config(mode='create', port_handle=ph_src, port_handle2=ph_dst, duration=data.traffic_run_time,
                                        transmit_mode="continuous", rate_pps=data.tgen_rate_pps, frame_size='4096', \
                                        l2_encap='ethernet_ii_vlan', vlan="enable", vlan_id=vlan, vlan_id_count=v_count, \
                                        vlan_id_mode="increment", vlan_id_step='1', \
                                        mac_src=src, mac_src_mode="increment", mac_src_step="00:00:00:00:00:01",
                                        mac_src_count=v_count, \
                                        mac_dst=dst, mac_dst_mode="increment", mac_dst_step="00:00:00:00:00:01",
                                        mac_dst_count=v_count, \
                                        l3_protocol='ipv6', ipv6_src_addr=s_ip, ipv6_dst_addr=d_ip)
        if src == src_mac:
            data.stream_data.update({st_key: {'streamAB': stream['stream_id']}})
            data.strm_port[stream['stream_id']] = {'src': data.src_tgn_port, 'dst': data.dest_tgn_port}
            data.strm_macs[stream['stream_id']] = {'src': src, 'dst': dst}
        else:
            data.stream_data[st_key]['streamBA'] = stream['stream_id']
            data.strm_port[stream['stream_id']] = {'src': data.dest_tgn_port, 'dst': data.src_tgn_port}
            data.strm_macs[stream['stream_id']] = {'src': src, 'dst': dst}

    ###Stream with frame size 8192
    # DUT1 -- Access LAG ports -- DUTn
    vlan = data.base_lagA_vlan
    v_count = 1
    st_key = 'FF:44'
    src_mac = '00:12:' + st_key + ':00:01'
    dst_mac = '00:21:' + st_key + ':00:01'
    print_log(
        "Create bi-directional L2 stream {} <---> {} with frame size 8192\n\t Expect {}--->{} stream to drop in DUT:2->DUT:1 ingress" \
        .format(src_mac, dst_mac, dst_mac, src_mac),'MED')
    for (src, dst, ph_src, ph_dst) in zip([src_mac, dst_mac], [dst_mac, src_mac], [tg_src_ph1, tg_dest_ph1],
                                          [tg_dest_ph1, tg_src_ph1]):
        stream = tg_h.tg_traffic_config(mode='create', port_handle=ph_src, port_handle2=ph_dst, duration=data.traffic_run_time,
                                        transmit_mode="continuous", rate_pps=data.tgen_rate_pps, frame_size='8192', \
                                        l2_encap='ethernet_ii_vlan', vlan="enable", vlan_id=vlan, vlan_id_count=v_count, \
                                        vlan_id_mode="increment", vlan_id_step='1', \
                                        mac_src=src, mac_src_mode="increment", mac_src_step="00:00:00:00:00:01",
                                        mac_src_count=v_count, \
                                        mac_dst=dst, mac_dst_mode="increment", mac_dst_step="00:00:00:00:00:01",
                                        mac_dst_count=v_count)
        if src == src_mac:
            data.stream_data.update({st_key: {'streamAB': stream['stream_id']}})
            data.strm_port[stream['stream_id']] = {'src': data.src_tgn_port, 'dst': data.dest_tgn_port}
            data.strm_macs[stream['stream_id']] = {'src': src, 'dst': dst}
        else:
            data.stream_data[st_key]['streamBA'] = stream['stream_id']
            data.strm_port[stream['stream_id']] = {'src': data.dest_tgn_port, 'dst': data.src_tgn_port}
            data.strm_macs[stream['stream_id']] = {'src': src, 'dst': dst}
    ### Vlan tag 0 stream for negative TCs which is expected to drop
    # Vlan tag 0 traffic to trunk port drops
    vlan = 0
    v_count = 1
    st_key = 'FF:55'
    src_mac = '00:12:' + st_key + ':00:01'
    dst_mac = '00:21:' + st_key + ':00:01'
    print_log(
        "Create bi-directional L2 stream {} <---> {} with frame size 256 in vlan 0\n\t Expect both streams to drop in TGEN->DUT ingress" \
        .format(src_mac, dst_mac),'MED')
    for (src, dst, ph_src, ph_dst) in zip([src_mac, dst_mac], [dst_mac, src_mac], [tg_src_ph1, tg_dest_ph1],
                                          [tg_dest_ph1, tg_src_ph1]):
        stream = tg_h.tg_traffic_config(mode='create', port_handle=ph_src, port_handle2=ph_dst, duration=data.traffic_run_time,
                                        transmit_mode="continuous", rate_pps=data.tgen_rate_pps, frame_size='256', \
                                        l2_encap='ethernet_ii_vlan', vlan="enable", vlan_id=vlan, vlan_id_count=v_count, \
                                        vlan_id_mode="increment", vlan_id_step='1', \
                                        mac_src=src, mac_src_mode="increment", mac_src_step="00:00:00:00:00:01",
                                        mac_src_count=v_count, \
                                        mac_dst=dst, mac_dst_mode="increment", mac_dst_step="00:00:00:00:00:01",
                                        mac_dst_count=v_count)
        if src == src_mac:
            data.stream_data.update({st_key: {'streamAB': stream['stream_id']}})
            data.strm_port[stream['stream_id']] = {'src': data.src_tgn_port, 'dst': data.dest_tgn_port}
            data.strm_macs[stream['stream_id']] = {'src': src, 'dst': dst}
        else:
            data.stream_data[st_key]['streamBA'] = stream['stream_id']
            data.strm_port[stream['stream_id']] = {'src': data.dest_tgn_port, 'dst': data.src_tgn_port}
            data.strm_macs[stream['stream_id']] = {'src': src, 'dst': dst}

def l2fwd_base_traffic_config():
    # reset statistics and delete if any existing streamblocks --- this now return all 4 tgen handles and resets it
    tg_ph1 = tg_src_ph
    tg_ph2 = tg_dest_ph

    data.stream_data = {}
    # Traffic stream - Tagged traffic
    # DUT1 -- Access Phy ports -- DUTn
    vlan = data.base_vlan
    st_key = 'AA'
    src_mac = '00:12:' + st_key + ':00:00:01'
    dst_mac = '00:21:' + st_key + ':00:00:01'
    data.stream_data[st_key] = {'src_mac': src_mac, 'dst_mac': dst_mac, 'vlan': vlan, 'vlan_count': data.access_port_count,
                                'mac_count': data.strm_mac_count, 'rate_pps': data.tgen_rate_pps, 'vlan_mode': 'enable',
                                'tg_port_handles': [tg_ph1, tg_ph2]}
    # DUT1 -- Tagged Phy ports -- DUTn
    vlan = data.base_trunk_vlan
    vlan_count = data.trunk_vlan_count * data.trunk_port_count
    st_key = 'BB'
    src_mac = '00:12:' + st_key + ':00:00:01'
    dst_mac = '00:21:' + st_key + ':00:00:01'
    data.stream_data[st_key] = {'src_mac': src_mac, 'dst_mac': dst_mac, 'vlan': vlan, 'vlan_count': vlan_count,
                                'mac_count': data.trunk_vlan_count, 'rate_pps': data.tgen_rate_pps,
                                'vlan_mode': 'enable', 'tg_port_handles': [tg_ph1, tg_ph2]}
    # DUT1 -- Tagged LAG ports -- DUTn
    vlan = data.base_lagT_vlan
    vlan_count = data.lagT_vlan_count * data.lagT_count
    st_key = 'CC'
    src_mac = '00:12:' + st_key + ':00:00:01'
    dst_mac = '00:21:' + st_key + ':00:00:01'
    data.stream_data[st_key] = {'src_mac': src_mac, 'dst_mac': dst_mac, 'vlan': vlan,'vlan_count': vlan_count,
                                'mac_count': data.lagT_vlan_count, 'rate_pps': data.tgen_rate_pps,
                                'vlan_mode': 'enable', 'tg_port_handles': [tg_ph1, tg_ph2]}
    # DUT1 -- Access LAG ports -- DUTn
    vlan = data.base_lagA_vlan
    st_key = 'DD'
    src_mac = '00:12:' + st_key + ':00:00:01'
    dst_mac = '00:21:' + st_key + ':00:00:01'
    data.stream_data[st_key] = {'src_mac': src_mac, 'dst_mac': dst_mac, 'vlan': vlan, 'vlan_count': data.lagA_count,
                                'mac_count': data.strm_mac_count, 'rate_pps': data.tgen_rate_pps, 'vlan_mode': 'enable',
                                'tg_port_handles': [tg_ph1, tg_ph2]}
    data.base_src_streams = []
    data.base_dst_streams = []
    data.strm_port = {}
    data.strm_macs = {}
    for st_key,stdata in data.stream_data.items():
        tg_ph11 = stdata['tg_port_handles'][0]
        tg_ph21 = stdata['tg_port_handles'][1]

        stream1 = tg_h.tg_traffic_config(mode='create', port_handle= tg_ph11,rate_pps=data.tgen_rate_pps, mac_src=stdata['src_mac'], mac_src_mode="increment",
        mac_src_count=stdata['mac_count'], transmit_mode="continuous",
        mac_src_step="00:00:00:00:00:01", mac_dst=stdata['dst_mac'], mac_dst_mode="increment",
        mac_dst_count=stdata['mac_count'], mac_dst_step="00:00:00:00:00:01", l2_encap='ethernet_ii_vlan',
        vlan_id=stdata['vlan'], vlan_id_count = stdata['vlan_count'], vlan="enable", vlan_id_mode="increment", vlan_id_step='1',port_handle2=tg_ph21)
        data.stream_data[st_key]['streamAB'] = stream1['stream_id']
        data.base_src_streams.append(stream1['stream_id'])
        data.strm_port[stream1['stream_id']] = {'src': data.src_tgn_port, 'dst': data.dest_tgn_port}
        data.strm_macs[stream1['stream_id']] = {'src': stdata['src_mac'], 'dst': stdata['dst_mac']}
        print_log(
            "Base traffic stream=:{}, FROM:{} --- TO:{}, SRC:{}--->DST:{}".format(stream1['stream_id'],
                                                                                  data.src_tgn_port, data.dest_tgn_port,
                                                                                  stdata['src_mac'], stdata['dst_mac']),
            'MED')

        stream2 = tg_h.tg_traffic_config(mode='create',port_handle= tg_ph21, rate_pps=data.tgen_rate_pps, mac_src=stdata['dst_mac'], mac_src_mode="increment",
        mac_src_count=stdata['mac_count'], transmit_mode="continuous",
        mac_src_step="00:00:00:00:00:01", mac_dst=stdata['src_mac'], mac_dst_mode="increment",
        mac_dst_count=stdata['mac_count'], mac_dst_step="00:00:00:00:00:01", l2_encap='ethernet_ii_vlan',
        vlan_id=stdata['vlan'], vlan_id_count = stdata['vlan_count'], vlan="enable", vlan_id_mode="increment", vlan_id_step='1',port_handle2=tg_ph11)
        data.stream_data[st_key]['streamBA'] = stream2['stream_id']
        data.base_dst_streams.append(stream2['stream_id'])
        data.strm_port[stream2['stream_id']] = {'src': data.dest_tgn_port, 'dst': data.src_tgn_port}
        data.strm_macs[stream2['stream_id']] = {'src': stdata['dst_mac'], 'dst': stdata['src_mac']}
        print_log(
            "Base traffic stream=:{}, FROM:{} --- TO:{}, SRC:{}--->DST:{}".format(stream2['stream_id'],
                                                                                  data.dest_tgn_port, data.src_tgn_port,
                                                                                  stdata['dst_mac'], stdata['src_mac']),
            'MED')

    ### Configure streams on 1st tgen port- TC specific streams - Will not run by default
    data.stream_data1 = {}
    # Traffic stream - Tagged traffic
    # DUT1 -- Access Phy ports -- DUTn
    vlan = data.tc_specific_vlan
    st_key = 'EE'
    src_mac = '00:12:' + st_key + ':00:00:01'
    dst_mac = '00:21:' + st_key + ':00:10:01'
    data.stream_data1[st_key] = {'src_mac': src_mac, 'dst_mac': dst_mac, 'vlan': vlan, 'vlan_count': data.tc_specific_vlan_count,
                                'mac_count': data.tc_specific_mac_count, 'rate_pps': data.tgen_rate_pps, 'vlan_mode': 'enable',
                                'tg_port_handles': [tg_src_ph1, tg_dest_ph1]}
    for st_key,stdata in data.stream_data1.items():

        tg_ph11 = stdata['tg_port_handles'][0]
        tg_ph21 = stdata['tg_port_handles'][1]

        stream1 = tg_h.tg_traffic_config(mode='create', port_handle= tg_ph11,rate_pps=data.tgen_rate_pps, mac_src=stdata['src_mac'], mac_src_mode="increment",
        mac_src_count=stdata['mac_count'], transmit_mode="continuous",
        mac_src_step="00:00:00:00:00:01", mac_dst=stdata['dst_mac'], mac_dst_mode="increment",
        mac_dst_count=stdata['mac_count'], mac_dst_step="00:00:00:00:00:01", l2_encap='ethernet_ii_vlan',
        vlan_id=stdata['vlan'], vlan_id_count = stdata['vlan_count'], vlan="enable", vlan_id_mode="increment", vlan_id_step='1',port_handle2=tg_ph21)
        data.stream_data1[st_key]['streamAB'] = stream1['stream_id']
        data.strm_port[stream1['stream_id']] = {'src': data.src_tgn_port1, 'dst': data.dest_tgn_port1}
        data.strm_macs[stream1['stream_id']] = {'src': stdata['src_mac'], 'dst': stdata['dst_mac']}
        print_log(
            "Static MAC traffic stream=:{}, FROM:{} --- TO:{}, SRC:{}--->DST:{}".format(stream1['stream_id'],
                                                                                  data.src_tgn_port1, data.dest_tgn_port1,
                                                                                  stdata['src_mac'], stdata['dst_mac']),
            'MED')

        stream2 = tg_h.tg_traffic_config(mode='create',port_handle= tg_ph21, rate_pps=data.tgen_rate_pps, mac_src=stdata['dst_mac'], mac_src_mode="increment",
        mac_src_count=stdata['mac_count'], transmit_mode="continuous",
        mac_src_step="00:00:00:00:00:01", mac_dst=stdata['src_mac'], mac_dst_mode="increment",
        mac_dst_count=stdata['mac_count'], mac_dst_step="00:00:00:00:00:01", l2_encap='ethernet_ii_vlan',
        vlan_id=stdata['vlan'], vlan_id_count = stdata['vlan_count'], vlan="enable", vlan_id_mode="increment", vlan_id_step='1',port_handle2=tg_ph11)
        data.stream_data1[st_key]['streamBA'] = stream2['stream_id']
        data.strm_port[stream2['stream_id']] = {'src': data.dest_tgn_port, 'dst': data.src_tgn_port}
        data.strm_macs[stream2['stream_id']] = {'src': stdata['dst_mac'], 'dst': stdata['src_mac']}
        print_log(
            "Static MAC traffic stream=:{}, FROM:{} --- TO:{}, SRC:{}--->DST:{}".format(stream2['stream_id'],
                                                                                        data.dest_tgn_port1,
                                                                                        data.src_tgn_port1,
                                                                                        stdata['dst_mac'],
                                                                                        stdata['src_mac']),
            'MED')

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
            print_log("DEBUG:Verify stream level statistics to find failed stream", 'MED')
            verify_traffic(tg_h, tgen_port[tg_ph_src], tgen_port[tg_ph_dest], src_stream_list=src_stream_list, \
                          dest_stream_list=dest_stream_list, direction=direction)
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
        #st.wait(duration)
        if stop_stream_list != None:
            #---old fix--#
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

        tgn_handles = [tg_src,tg_dest]
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
                dest_stream_list = ['ANY']*len(src_stream_list)

        stream_list = src_stream_list
        if direction == "both":
            stream_list = stream_list + dest_stream_list
        tg_id.tg_traffic_control(action='run', handle=stream_list)

    st.wait(duration)

    if src_stream_list == 'ALL':
        ### --obsolete code
        for tg_src, tg_dest in zip(tg_src_list, tg_dest_list):
            # Stop running Traffic
            tg_id.tg_traffic_control(action='stop', port_handle=tg_src)
            if direction == "both":
                tg_id.tg_traffic_control(action='stop', port_handle=tg_dest)
    else:
        src_stream_list = [src_stream_list] if type(src_stream_list) is str else src_stream_list
        dest_stream_list = [dest_stream_list] if type(dest_stream_list) is str else dest_stream_list

        stream_list = src_stream_list
        if direction == "both":
            stream_list = stream_list + dest_stream_list
        tg_id.tg_traffic_control(action='stop', handle=stream_list)
    #st.wait(2)

def verify_traffic(tg_id, tg_src_port, tg_dest_port, src_stream_list='ALL', dest_stream_list='ALL', tx_rx_ratio=1,comp_type='packet_count',direction="both"):
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
        aggrResult = tgapi.validate_tgen_traffic(traffic_details=traffic_data, mode='aggregate', comp_type=comp_type)
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
                dest_stream_list = ['ANY']*len(src_stream_list)

        for src_stream_id,dest_stream_id in zip(src_stream_list,dest_stream_list):
            tg_src_port = data.strm_port[src_stream_id]['src']
            tg_dest_port = data.strm_port[src_stream_id]['dst']
            tg_src_mac = data.strm_macs[src_stream_id]['src']
            tg_dst_mac = data.strm_macs[src_stream_id]['dst']
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
            streamResult = tgapi.validate_tgen_traffic(traffic_details=traffic_data, mode='streamblock',comp_type=comp_type)
            if streamResult:
                st.log('traffic verification passed for mode streamblock {}:{} <---> {}:{}'.format(tg_src_port, tg_src_mac, tg_dest_port, tg_dst_mac))
            else:
                ver_flag = False
                st.log('traffic verification failed for mode streamblock {}:{} <---> {}:{}'.format(tg_src_port, tg_src_mac, tg_dest_port, tg_dst_mac))

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
    ### Clear port counters
    #utils.exec_all(True, [[port_obj.clear_interface_counters, dut] for dut in [dut]])
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


def verify_lag_loadbalancing(dut,po_key,threshold):
    ret_value = 'True'
    po_name = data.portchannel[po_key]['name']
    d1d2_po_members = data.portchannel[po_key]["dut1_members"]
    if len(d1d2_po_members) < 2:
        print_log('LAG needs to have 2 or more member ports to check load balancing, SKIPPING the check','MED')
        return True
    for port in d1d2_po_members:
        p_tx_val = intf_obj.get_interface_counters(dut, port, "tx_ok")
        if not p_tx_val:
            print_log('Expected port:{} not seen in output'.format(port), 'ERROR')
            return False
        for i in p_tx_val:
            p_txmt = i['tx_ok']
            if p_txmt == 'N/A' or p_txmt is None: return False
            p_txmt = p_txmt.replace(",", "")
        if (int(p_txmt) < threshold) or (p_txmt == '0'):
            print_log("FAIL: Traffic NOT load balanced on member port:{} in LAG:{} on dut:{}".format(port, po_name, dut), 'ERROR')
            ret_value = False
        else:
            print_log('PASS: Traffic load balanced on member port:{} in LAG:{} on dut:{}'.format(port, po_name, dut),'MED')
    return ret_value

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
    dut_list = dut_list if isinstance(dut_list, list) else [dut_list]
    expect_mac_list = expect_mac_list if isinstance(expect_mac_list, list) else [expect_mac_list]
    dict_list = []
    for i in range(len(dut_list)):
        dict_list += [
            {'expect_mac': expect_mac_list[i], 'comp_flag': comp_flag}]
    if not retry_parallel(check_mac_count, dict_list=dict_list, dut_list=dut_list, retry_count=3, delay=2):
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
    dut_list = dut_list if isinstance(dut_list, list) else [dut_list]
    expect_mac_list = expect_mac_list if isinstance(expect_mac_list, list) else [expect_mac_list]
    dict_list = []
    for i in range(len(dut_list)):
        dict_list += [{'expect_mac': expect_mac_list[i], 'vlan': vlan, 'port':port, 'type':type,'mac_search':mac_search,'comp_flag':comp_flag}]
    if not retry_parallel(show_verify_mac_table, dict_list=dict_list,dut_list=dut_list, retry_count=3, delay=2):
        print_log("MAC Table verification FAILED", "HIGH")
        return False
    else:
        print_log("MAC Table verification PASSED", "HIGH")
        return True


def verify_mac_aging(dut_list,mac_list,aging_time,poll_interval,max_wait,**kwargs):
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
    ### Processing mac_table filters vlan=None,port=None,type=None,mac_search = None
    vlan = kwargs.get('vlan', None)
    port = kwargs.get('port', None)
    type = kwargs.get('type', None)
    mac_search = kwargs.get('mac_search', None)

    for i in range(poll_interval,max_wait,poll_interval):
        st.wait(poll_interval)
        ### counter which keeps track of duts in which MACs successfully aged out
        dut_pass_counter = 0
        [actual_macs, exceptions] = utils.exec_foreach(True, dut_list,mac_obj.get_mac_address_count, vlan=vlan, port=port, type=type, mac_search=mac_search)
        if not all(i is None for i in exceptions):
            print_log(exceptions)
        for dut,mac_count,expect_mac in zip(dut_list,actual_macs,mac_list):
            if (mac_count == expect_mac):
                current_time = time.time()
                time_elapsed = current_time - start_time
                ### To avoid inconsistent result in ixia TBs due to 7748, keep a 3 sec buffer as ixia keep trying in loop of 3 Sec.
                if time_elapsed < (aging_time-5):
                    #If MACs age out before age_time in one DUT, return False and skip verify in remaining DUTs
                    st.error("FAIL: MACs aged out in Dut-{} before aging_time. Current wait_time:{}. age_time:{}".format(dut,time_elapsed,aging_time))
                    asicapi.dump_l2(dut)
                    return False
                elif time_elapsed >= aging_time:
                    st.log("PASS: MAC aging Success in Dut-{}. Current wait_time:{}. age_time:{}".format(dut,time_elapsed,aging_time))
                    dut_pass_counter += 1
        ### If MAC successfully aged out in all DUTs, break from polling loop, return True
        st.log("Iteration: {} - If MAC successfully aged out in all DUTs, break from polling loop, return True.".format(i))
        if dut_pass_counter == len(dut_list):
            return True

    current_time = time.time()
    time_elapsed = current_time - start_time
    ### Wait for remaining max_wait time
    if time_elapsed < max_wait:
        st.wait(max_wait-time_elapsed)
        #i = max_wait
    dut_pass_counter = 0
    [actual_macs, exceptions] = utils.exec_foreach(True, dut_list, mac_obj.get_mac_address_count, vlan=vlan, port=port,
                                                   type=type, mac_search=mac_search)
    if not all(i is None for i in exceptions):
        print_log(exceptions)
    for dut,mac_count,expect_mac in zip(dut_list,actual_macs,mac_list):
        #mac_count = mac_obj.get_mac_address_count(dut, vlan=vlan, port=port, type=type, mac_search=mac_search)
        current_time = time.time()
        time_elapsed = current_time - start_time
        if (mac_count == expect_mac):
            st.log("PASS: MAC aging Success in Dut-{}. Current wait_time:{}. age_time:{}".format(dut, time_elapsed, aging_time))
            dut_pass_counter += 1
        else:
            st.error("FAIL: MACs did not age out in Dut-{} after waiting for {} seconds.".format(dut,time_elapsed))
            asicapi.dump_l2(dut)
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
        dict_list = []
        n = len(data.portchannel[po_key]["duts"])
        for _ in range(n):
            dict_list += [{'portchannel': po_name,'state':state}]
        if not retry_parallel(po_obj.verify_portchannel_state, dict_list=dict_list,
                              dut_list=data.portchannel[po_key]["duts"], retry_count=3, delay=2):
            print_log('Portchannel-{} is not {} in dut{}-dut{}'.format(po_name, state, dut1, dut2), 'MED')
            ver_flag = False
            po_reconfig_flag += 1
            fail_msg = 'Portchannel-{} is not {}'.format(po_name,state)
            st.report_fail("test_case_failure_message", fail_msg)

    return ver_flag

@pytest.mark.l2fwd_phase2
@pytest.mark.l2fwd_sanity
def test_l2fwd_vlan_range():
    '''
        1. Do config as in base_config
        2. Create streams as in base_traffic_config
        3. configure tg11 also member of vlan range in tg12
        3. Start unidirection traffic
        4. Do basic_validations
        5. Verify flooding to  vlan member ports tg11
        6.Verify MAC table
        7. Start reverse traffic also
        8. Verify traffic not flooding
        9. Verify MAC table
        10. Clear MAC all
        11. Verify MAC table
        12. Verify MACs are relearned with traffic
        13. Clear MAC on few vlans
        14. Verify MAC on those vlans cleared and not for other vlans
        15. Clear MAC on all types of ports
        16. Verify MAC on those ports cleared and not for other ports
        17. Verify MACs relearned with traffic
    '''
    final_result = True
    mac_count_fail = 0
    traffic_forward_fail = 0
    flooding_fail = 0
    mac_aging_fail = 0
    tc_list = ['FtOpSoSwL2FwdCli001', 'FtOpSoSwL2FwdFn001']
    print_log("START of TC:test_l2fwd_vlan_range ==>Sub-Test:Verify unidirectional traffic\n TCs:<{}>".format(tc_list), "HIGH")
    ### Clear port counters
    utils.exec_all(True, [[port_obj.clear_interface_counters, dut] for dut in data.my_dut_list])
    ### Send traffic and verify packet count received
    if not run_verify_traffic(src_stream_list=data.base_src_streams,dest_stream_list=data.base_dst_streams,direction="single"):
        final_result = False
        traffic_forward_fail += 1
    ### System MACs will be learned on Access links from LLDP protocol packets
    ### Add number of access links to get total MAC expected.
    access_link_num = data.access_port_count + data.lagA_count
    #data.dut_macs_unidirection = [(i/2)+access_link_num for i in data.dut_mac_count_list]
    data.dut_macs_unidirection = [(i/2) for i in data.dut_mac_count_list]
    if not verify_mac_table(data.ver_dut_list, data.dut_macs_unidirection,mac_search=data.mac_srch_str):
        final_result = False
        mac_count_fail += 1

    expect_flood_packets = int(data.tgen_rate_pps) * data.stream_count * data.traffic_run_time
    dict_list = []
    for dut in data.ver_dut_list:
        dict_list += [{'portList': [st.get_tg_links(dut)[0][0]], 'threshold': expect_flood_packets}]
    if not retry_parallel(verify_flooding_on_dut, dict_list=dict_list, dut_list=data.ver_dut_list, retry_count=3,
                          delay=2):
        print_log('FAIL:Uni-directional Traffic flooding, expect_tx_pkt > {} is not seen'.format(
            expect_flood_packets), 'ERROR')
        final_result = False
        flooding_fail += 1
    else:
        print_log('PASS:Uni-directional Traffic flooding expect_tx_pkt > {} is seen'.format(
            expect_flood_packets), 'MED')

    tc_list = ['FtOpSoSwL2FwdFn002']
    print_log("START of TC:test_l2fwd_vlan_range ==>Sub-Test:Verify bidirectional traffic\n TCs:<{}>".format(tc_list),
              "HIGH")
    ### Clear port counters
    utils.exec_all(True, [[port_obj.clear_interface_counters, dut] for dut in data.my_dut_list])
    ### Start bi-directional traffic and verify no flooding on first TGEN port
    if not run_verify_traffic(tg_ph_src=tg_dest_ph,tg_ph_dest=tg_src_ph,src_stream_list=data.base_dst_streams,dest_stream_list=data.base_src_streams):
        final_result = False
        traffic_forward_fail += 1
    ### System MACs will be learned on Access links from LLDP protocol packets
    ### Add number of access links to get total MAC expected.
    #data.dut_macs_bidirection = [i + access_link_num for i in data.dut_mac_count_list]
    data.dut_macs_bidirection = [i for i in data.dut_mac_count_list]
    if not verify_mac_table(data.ver_dut_list, data.dut_macs_bidirection,mac_search=data.mac_srch_str):
        final_result = False
        mac_count_fail += 1

    dict_list = []
    for dut in data.ver_dut_list:
        dict_list += [{'portList': [st.get_tg_links(dut)[0][0]], 'threshold': data.counters_threshold}]
    if retry_parallel(verify_flooding_on_dut, dict_list=dict_list, dut_list=data.ver_dut_list, api_result=False,
                          retry_count=3, delay=2):
        print_log('FAIL:Bi-directional Traffic flooding is seen, expect_tx_pkt < {}'.format(
            data.counters_threshold), 'ERROR')
        final_result = False
        flooding_fail += 1
    else:
        print_log('PASS:Bi-directional Traffic flooding is not seen, expect_tx_pkt < {}'.format(
            data.counters_threshold), 'MED')

    tc_list = ['FtOpSoSwL2FwdFn010', 'FtOpSoSwL2FwdFn011', 'FtOpSoSwL2FwdFn012']
    print_log("START of TC:test_l2fwd_vlan_range ==>Sub-Test:Verify Clear MAC\n TCs:<{}>".format(tc_list), "HIGH")


    # Clear mac table on all DUTs
    print_log(" Clearing the fdb entries", "HIGH")
    utils.exec_all(True, [[mac_obj.clear_mac, dut] for dut in data.ver_dut_list])
    dut_mac_zero_list = [0] * len(data.ver_dut_list)

    # To handle slow mac deletion on TH3 - Jira SONIC-10602
    for slow_dut in data.slow_mac_del_dut:
        if slow_dut in data.platform_list: st.wait(4)
    ##CLEAR
    if not verify_mac_table(data.ver_dut_list, dut_mac_zero_list, mac_search=data.mac_srch_str):
        final_result = False
        mac_count_fail += 1
    print_log(" Verify fdb entries are relearned after clear", "HIGH")
    start_stop_traffic(src_stream_list=data.base_src_streams,dest_stream_list=data.base_dst_streams)
    if not verify_mac_table(data.ver_dut_list, data.dut_mac_count_list, mac_search=data.mac_srch_str):
        final_result = False
        mac_count_fail += 1

    # Clear mac table using vlan  and port as filter
    print_log(" Clearing the fdb entries with vlan as filter", "HIGH")
    clear_mac_vlans = [data.base_trunk_vlan, data.base_lagT_vlan]
    for dut in data.ver_dut_list:
        for vlan in clear_mac_vlans:
            mac_obj.clear_mac(dut, vlan=vlan)
            # Verify MACs learned in the vlan is cleared
            if data.slow_mac_del_dut in data.platform_list:
                st.wait(data.del_mac_wait_time,"Wait for {} sec for {} plaforms".format(data.del_mac_wait_time,data.slow_mac_del_dut))
            ##CLEAR
            itr_ctr = 0
            itr_ctr_limit = 3
            mac_ver_flag = False
            while itr_ctr < itr_ctr_limit:
                print_log("MAC check Iteration:{}".format(itr_ctr + 1), 'MED')
                if mac_obj.get_mac_address_count(dut, vlan=vlan, mac_search=data.mac_srch_str) != 0:
                    itr_ctr += 1
                    if itr_ctr < itr_ctr_limit:
                        st.wait(3)
                else:
                    mac_ver_flag = True
                    break
            if not mac_ver_flag:
                print_log("FAIL: FDB entries not cleared for vlan {} in Dut:{}".format(vlan, dut), "ERROR")
                final_result = False
                mac_count_fail += 1
            else:
                print_log("PASS: FDB entries are cleared for vlan {} in Dut:{}".format(vlan, dut), "MED")
    # Clear mac with vlan should not clear all macs. Verify mac count is not 0
    print_log(" Clear mac with vlan should not clear all macs. Verify mac count is not 0", "MED")
    if not verify_mac_table(data.ver_dut_list, dut_mac_zero_list, mac_search=data.mac_srch_str, comp_flag='not-equal'):
        final_result = False
        mac_count_fail += 1

    print_log(" Clearing the fdb entries with port as filter", "HIGH")
    ###For every dut, do clear mac on first access/trunk phy ports  and first access/trunk lag
    d1 = data.ver_dut_list[0]
    d2 = data.ver_dut_list[1]
    for d2 in data.ver_dut_list[1:]:
        access_port = st.get_dut_links_local(d1, peer=d2)[0]
        trunk_port = st.get_dut_links_local(d1, peer=d2)[data.access_port_count]
        po_key = data.po_metadata[(d1, 'trunk')]['base_id']
        trunk_lag = data.portchannel[po_key]['name']
        po_key = data.po_metadata[(d1, 'access')]['base_id']
        access_lag = data.portchannel[po_key]['name']
        clear_mac_ports = [access_port, trunk_port, trunk_lag, access_lag]
        for port in clear_mac_ports:
            mac_obj.clear_mac(d1, port=port)
            if data.slow_mac_del_dut in data.platform_list:
                st.wait(data.del_mac_wait_time,
                        "Wait for {} sec for {} plaforms".format(data.del_mac_wait_time, data.slow_mac_del_dut))
            ##CLEAR
            itr_ctr = 0
            itr_ctr_limit = 3
            mac_ver_flag = False
            while itr_ctr < itr_ctr_limit:
                print_log("MAC check Iteration:{}".format(itr_ctr + 1), 'MED')
                if mac_obj.get_mac_address_count(d1, port=port, mac_search=data.mac_srch_str) != 0:
                    itr_ctr += 1
                    if itr_ctr < itr_ctr_limit:
                        st.wait(3)
                else:
                    mac_ver_flag = True
                    break
            if not mac_ver_flag:
                print_log("FAIL: FDB entries not cleared for port {} in Dut:{}".format(port, d1), "ERROR")
                final_result = False
                mac_count_fail += 1
            else:
                print_log("PASS: FDB entries are cleared for port {} in Dut:{}".format(port, d1), "MED")
        dm = d1
        d1 = d2
    ###On last dut, do clear mac on dutN-->dutN-1 ports
    d1 = dm
    access_port = st.get_dut_links_local(d2, peer=d1)[0]
    trunk_port = st.get_dut_links_local(d2, peer=d1)[data.access_port_count]
    clear_mac_ports = [access_port, trunk_port, trunk_lag, access_lag]
    for port in clear_mac_ports:
        mac_obj.clear_mac(d2, port=port)
        if data.slow_mac_del_dut in data.platform_list:
            st.wait(data.del_mac_wait_time,
                    "Wait for {} sec for {} plaforms".format(data.del_mac_wait_time, data.slow_mac_del_dut))
        ##CLEAR
        itr_ctr = 0
        itr_ctr_limit = 3
        mac_ver_flag = False
        while itr_ctr < itr_ctr_limit:
            print_log("MAC check Iteration:{}".format(itr_ctr + 1), 'MED')
            if mac_obj.get_mac_address_count(d2, port=port, mac_search=data.mac_srch_str) != 0:
                itr_ctr += 1
                if itr_ctr < itr_ctr_limit:
                    st.wait(3)
            else:
                mac_ver_flag = True
                break
        if not mac_ver_flag:
            print_log("FAIL: FDB entries not cleared for port {} in Dut:{}".format(port, d2), "ERROR")
            final_result = False
            mac_count_fail += 1
        else:
            print_log("PASS: FDB entries are cleared for port {} in Dut:{}".format(port, d2), "MED")

    # Clear mac with port should not clear all macs. Verify mac count is not 0
    print_log(" Clear mac with port should not clear all macs. Verify mac count is not 0", "MED")
    if not verify_mac_table(data.ver_dut_list, dut_mac_zero_list, mac_search=data.mac_srch_str, comp_flag='not-equal'):
        final_result = False
        mac_count_fail += 1

    print_log(" Verify fdb entries re-learned and forwarding is proper after clear on port and vlan", "HIGH")
    if not run_verify_traffic(src_stream_list=data.base_src_streams,dest_stream_list=data.base_dst_streams):
        final_result = False
        traffic_forward_fail += 1
    if not verify_mac_table(data.ver_dut_list, data.dut_mac_count_list, mac_search=data.mac_srch_str):
        final_result = False
        mac_count_fail += 1

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

@pytest.mark.l2fwd_phase2
@pytest.mark.l2fwd_sanity
def test_mac_aging():
    final_result = True
    mac_count_fail = 0
    traffic_forward_fail = 0
    flooding_fail = 0
    mac_aging_fail = 0
    tc_list = ['FtOpSoSwL2FwdCli002', 'FtOpSoSwL2FwdCli004', 'FtOpSoSwL2FwdFn007', 'FtOpSoSwL2FwdFn008', 'FtOpSoSwL2FwdFn009']
    print_log("START of TC ==> test_mac_aging\n TCs:<{}>".format(tc_list),"HIGH")
    #dut_mac_zero_list = [0 for i in range(len(data.ver_dut_list))]
    dut_mac_zero_list = [0] * len(data.ver_dut_list)
    for dut in data.my_dut_list:
        mac_obj.config_mac_agetime(dut, data.mac_aging)
        retval = mac_obj.get_mac_agetime(dut)
        if retval != data.mac_aging:
            print_log("Failed to configure Mac aging time.","ERROR")
            st.report_fail("mac_aging_time_failed_config")
    start_stop_traffic(src_stream_list=data.base_src_streams,dest_stream_list=data.base_dst_streams)
    ### Need to wait for twice MAC aging-time for MACs to age out
    if not verify_mac_aging(data.ver_dut_list,dut_mac_zero_list,data.mac_aging,
                            int(data.mac_aging/4), 2*data.mac_aging,
                            mac_search=data.mac_srch_str):
        final_result = False
        mac_aging_fail += 1

    print_log("Modify mac aging to default and verify it is set.","HIGH")
    for dut in data.my_dut_list:
        mac_obj.config_mac_agetime(dut, data.default_macage)
        retval = mac_obj.get_mac_agetime(dut)
        if retval != data.default_macage:
            print_log("Failed to configure Mac aging time to {}.".format(data.default_macage),"ERROR")
            st.report_fail("mac_aging_time_failed_config")

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

@pytest.fixture(scope="function")
def lag_function_fixture():
    ### Verify all the LAGs configured in the topology and its members are up
    print_log('Verify all the LAGs configured in the topology and its members are up','MED')
    res_flag = True
    po_fail = 0
    for po_key in data.portchannel:
        po_name = data.portchannel[po_key]["name"]
        dut_pair = data.portchannel[po_key]["duts"]
        D1D2_po_members = data.portchannel[po_key]["dut1_members"]
        D2D1_po_members = data.portchannel[po_key]["dut2_members"]
        if not verify_portchannel(dut_pair, po_name, [D1D2_po_members, D2D1_po_members]):
            res_flag = False
            po_fail += 1
    if not res_flag:
        fail_msg = ''
        if po_fail > 0:
            fail_msg += 'PortChannel not UP:'
        st.report_fail("test_case_failure_message", fail_msg.strip(':'))
    yield
    global po_reconfig_flag
    if po_reconfig_flag >= 1:
        dut1 = data.my_dut_list[0]
        po_key_a = data.po_metadata[(dut1, 'access')]['base_id']
        po_key_t = data.po_metadata[(dut1, 'trunk')]['base_id']
        po_list = [po_key_a, po_key_t]
        for po_key in po_list:
            po_name = data.portchannel[po_key]["name"]
            dut_pair = data.portchannel[po_key]["duts"]
            dut1 = dut_pair[0]
            dut2 = dut_pair[1]
            vlan = data.portchannel[po_key]["vlan"]
            D1D2_po_members = data.portchannel[po_key]["dut1_members"]
            D2D1_po_members = data.portchannel[po_key]["dut2_members"]
            unconfigure_portchannel(dut1, dut2, po_name, vlan, D1D2_po_members, D2D1_po_members)
            configure_portchannel(dut1, dut2, po_name, vlan, D1D2_po_members, D2D1_po_members)
            ## Enable back the member ports explicitly
            [result, exceptions] = utils.exec_all(True, [[intf_obj.interface_noshutdown, dut, dut_po_ports] \
                                                         for dut, dut_po_ports in
                                                         zip([dut1, dut2], [D1D2_po_members, D2D1_po_members])])
            if not all(i is None for i in exceptions):
                print_log(exceptions)
            if False in result:
                print_log("LAG member port enable failed for {}".format(po_name))
            if not verify_portchannel(dut_pair, po_name, [D1D2_po_members, D2D1_po_members]):
                print_log('Portchannel-{} not up after reconfiguring as part of TC config cleanup'.format(po_name), 'HIGH')


@pytest.mark.l2fwd_phase2
@pytest.mark.l2fwdlag
def test_l2fwd_lag(lag_function_fixture):

    global po_reconfig_flag
    final_result = True
    mac_count_fail = 0
    traffic_forward_fail = 0
    flooding_fail = 0
    mac_aging_fail = 0
    po_reconfig_flag = 0
    tc_list = ['FtOpSoSwL2FwdFn024','FtOpSoSwL2FwdFn027','FtOpSoSwL2FwdFn025','FtOpSoSwL2FwdFn030','FtOpSoSwL2FwdFn031']
    print_log("START of TC ==> test_l2fwd_lag\n TCs:<{}>".format(tc_list), "HIGH")
    traffic_time = 1
    print_log("TC Summary :==> Sub-Test:Delete and reconfigure LAG and verify it is UP.", "MED")
    ###Delete Portchannel is not allowed if it has member ports or vlan membership
    ###Hence unconfig the PO between first dut_pair and then reconfigure and verify
    dut1 = data.my_dut_list[0]
    po_key_a = data.po_metadata[(dut1, 'access')]['base_id']
    po_key_t = data.po_metadata[(dut1, 'trunk')]['base_id']
    po_list = [po_key_a,po_key_t]
    for po_key in po_list:
        po_name = data.portchannel[po_key]["name"]
        dut_pair = data.portchannel[po_key]["duts"]
        dut1 = dut_pair[0]
        dut2 = dut_pair[1]
        vlan = data.portchannel[po_key]["vlan"]
        D1D2_po_members = data.portchannel[po_key]["dut1_members"]
        D2D1_po_members = data.portchannel[po_key]["dut2_members"]
        unconfigure_portchannel(dut1, dut2, po_name, vlan, D1D2_po_members, D2D1_po_members)
        configure_portchannel(dut1, dut2, po_name, vlan, D1D2_po_members, D2D1_po_members)
        if not retry_func(verify_portchannel,dut_pair=dut_pair,po_id=po_name,po_members_list=[D1D2_po_members,D2D1_po_members],delay=1,retry_count=3):
            print_log('Portchannel-{} not up after reconfiguring'.format(po_name), 'HIGH')
            st.report_fail("operation_failed")


    print_log("TC Summary :==> Sub-Test:Toggle member ports in LAG and verify traffic forwarding.", "HIGH")
    dut1 = data.my_dut_list[0]
    po_key_a = data.po_metadata[(dut1, 'access')]['base_id']
    po_key_t = data.po_metadata[(dut1, 'trunk')]['base_id']
    po_key_list = [po_key_a, po_key_t]
    if not toggle_lag_ports(po_key_list,port_operation="disable",port_order="odd"):
        final_result = False
    ### verify LAG is up
    print_log('Verify Portchannel after disabling odd member ports', 'MED')
    verify_po_state(po_key_list=po_key_list, state='up')


    if not run_verify_traffic(src_stream_list=data.base_src_streams,dest_stream_list=data.base_dst_streams):
        final_result = False
        traffic_forward_fail += 1
    if not verify_mac_table(data.ver_dut_list, data.dut_mac_count_list,mac_search=data.mac_srch_str):
        final_result = False
        mac_count_fail += 1
    print_log("TC Summary :==> Sub-Test:Verify LAG with default min-links.", "HIGH")
    #Disable even ports
    if not toggle_lag_ports(po_key_list,port_operation="disable",port_order="even"):
        final_result = False
    ### Verify LAG is down and MACs removed as default min-links 1 is not up
    print_log('Verify PO is down after disabling even member ports', 'MED')
    verify_po_state(po_key_list, state='down')
    macs_on_disabled_po = data.lagT_vlan_count + data.strm_mac_count
    expect_mac_list = [i - macs_on_disabled_po for i in data.dut_mac_count_list]
    if not verify_mac_table(data.ver_dut_list, expect_mac_list, mac_search=data.mac_srch_str):
        final_result = False
        mac_count_fail += 1

    ###Enable back odd member ports and verify LAG is up and traffic forwards
    if not toggle_lag_ports(po_key_list,port_operation="enable",port_order="odd"):
        final_result = False
    #verify LAG is up
    print_log('Verify Portchannel after enabling back odd member ports', 'MED')
    verify_po_state(po_key_list=po_key_list, state='up')

    print_log("TC Summary :==> Sub-Test:Verify LAG with non-default min-links.", "HIGH")
    ### Delete LAG and reconfigure with non-default min-links
    for po_key in po_list:
        po_name = data.portchannel[po_key]["name"]
        dut_pair = data.portchannel[po_key]["duts"]
        dut1 = dut_pair[0]
        dut2 = dut_pair[1]
        vlan = data.portchannel[po_key]["vlan"]
        D1D2_po_members = data.portchannel[po_key]["dut1_members"]
        D2D1_po_members = data.portchannel[po_key]["dut2_members"]
        unconfigure_portchannel(dut1, dut2, po_name, vlan, D1D2_po_members, D2D1_po_members)
        min_link = (len(D1D2_po_members) / 2 ) + 1
        configure_portchannel(dut1, dut2, po_name, vlan, D1D2_po_members, D2D1_po_members,min_links=min_link)
    # Verify LAG not up as min-link not satisfied verify no MAC on PO
    ###Disable even ports
    if not toggle_lag_ports(po_key_list,port_operation="disable",port_order="even"):
        final_result = False
    print_log('Verify PO is down after disabling even member ports', 'MED')
    verify_po_state(po_key_list, state='down')
    ### Start traffic
    start_stop_traffic(src_stream_list=data.base_src_streams, dest_stream_list=data.base_dst_streams,duration=traffic_time)
    macs_on_disabled_po = data.lagT_vlan_count + data.strm_mac_count
    expect_mac_list = [i - macs_on_disabled_po for i in data.dut_mac_count_list]
    if not verify_mac_table(data.ver_dut_list, expect_mac_list, mac_search=data.mac_srch_str):
        final_result = False
        mac_count_fail += 1
    #Enable back all ports
    if not toggle_lag_ports(po_key_list,port_operation="enable",port_order="even"):
        final_result = False
    #verify LAG is up
    print_log('Verify Portchannel after enabling back all member ports', 'MED')
    verify_po_state(po_key_list, state='up')
    # Verify traffic and MAC table
    if not run_verify_traffic(src_stream_list=data.base_src_streams, dest_stream_list=data.base_dst_streams):
        final_result = False
        traffic_forward_fail += 1
    if not verify_mac_table(data.ver_dut_list, data.dut_mac_count_list, mac_search=data.mac_srch_str):
        final_result = False
        mac_count_fail += 1
    ### Revert min-links configuration
    for po_key in po_list:
        po_name = data.portchannel[po_key]["name"]
        dut_pair = data.portchannel[po_key]["duts"]
        dut1 = dut_pair[0]
        dut2 = dut_pair[1]
        vlan = data.portchannel[po_key]["vlan"]
        D1D2_po_members = data.portchannel[po_key]["dut1_members"]
        D2D1_po_members = data.portchannel[po_key]["dut2_members"]
        unconfigure_portchannel(dut1, dut2, po_name, vlan, D1D2_po_members, D2D1_po_members)
        configure_portchannel(dut1, dut2, po_name, vlan, D1D2_po_members, D2D1_po_members)
    ###verify LAG is up after reverting min-links configurations
    print_log('Verify Portchannel after enabling back all member ports', 'MED')
    verify_po_state(po_key_list, state='up')

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


@pytest.mark.l2fwd_phase2
@pytest.mark.l2fwd_moveLagMem
@pytest.mark.l2fwdlag
def test_move_lag_member_ports(lag_function_fixture):
    tc_list = ['FtOpSoSwL2FwdFn026','FtOpSoSwL2FwdFn029']
    print_log("START of TC ==> test_move_lag_member_ports\n TCs:<{}>".format(tc_list), "HIGH")
    global po_reconfig_flag
    po_reconfig_flag = 0
    final_result = True
    mac_count_fail = 0
    traffic_forward_fail = 0
    flooding_fail = 0
    mac_aging_fail = 0
    ### Delete a member port from lagA and add to lagT
    print_log('Delete the first port from access LAG to move to trunk LAG', 'MED')
    dut1 = data.my_dut_list[0]
    dut2 = data.my_dut_list[1]
    po_key_a = data.po_metadata[(dut1, 'access')]['base_id']
    po_name_a = data.portchannel[po_key_a]['name']
    d1d2_po_members = data.portchannel[po_key_a]["dut1_members"]
    d1d2_po_member = d1d2_po_members[0]
    d2d1_po_member = data.portchannel[po_key_a]["dut2_members"][0]
    if len(d1d2_po_members) < po_link_min_req:
        print_log("TC cannot be run as min required links-{} not present in LAG-{}".format(po_link_min_req,po_name_a),
                  'MED')
        st.report_fail("operation_failed")
    [result, exceptions] = utils.exec_all(True, [
        [po_obj.add_del_portchannel_member, dut, po_name_a, dut_po_members, 'del'] for dut, dut_po_members in
        zip([dut1, dut2], [d1d2_po_member, d2d1_po_member]) ] )
    if not all(i is None for i in exceptions):
        print_log(exceptions)
    if False in result:
        print_log('Portchannel-{} after deleting a member:{}-{} FAILED'.format(po_name_a, d1d2_po_member, d2d1_po_member),'MED')
    verify_po_state([po_key_a], state='up')

    print_log('Move the first port from access LAG to trunk LAG','MED')
    po_key_t = data.po_metadata[(dut1, 'trunk')]['base_id']
    po_name_t = data.portchannel[po_key_t]['name']
    [result, exceptions] = utils.exec_all(True, [
        [po_obj.add_del_portchannel_member, dut, po_name_t, dut_po_members, 'add'] for dut,dut_po_members in
        zip([dut1, dut2], [d1d2_po_member, d2d1_po_member]) ] )
    if not all(i is None for i in exceptions):
        print_log(exceptions)
    if False in result:
        print_log('Portchannel-{} after adding new member:{}-{} FAILED '.format(po_name_t, d1d2_po_member, d2d1_po_member),'MED')
    verify_po_state([po_key_t], state='up')
    verify_po_state([po_key_a], state='up')
    if not run_verify_traffic(src_stream_list=data.base_src_streams,dest_stream_list=data.base_dst_streams):
        final_result = False
        traffic_forward_fail += 1
    if not verify_mac_table(data.ver_dut_list, data.dut_mac_count_list,mac_search=data.mac_srch_str):
        final_result = False
        mac_count_fail += 1

    print_log('Move the newly added port from trunk LAG back to access LAG','MED')
    [result, exceptions] = utils.exec_all(True, [
        [po_obj.add_del_portchannel_member, dut, po_name_t, dut_po_members, 'del'] for dut, dut_po_members in
        zip([dut1, dut2], [d1d2_po_member, d2d1_po_member])])
    if not all(i is None for i in exceptions):
        print_log(exceptions)
    if False in result:
        print_log('Portchannel-{} after deleting new member:{}-{} FAILED '.format(po_name_t, d1d2_po_member, d2d1_po_member),'MED')
    verify_po_state([po_key_t], state='up')
    verify_po_state([po_key_a], state='up')

    [result, exceptions] = utils.exec_all(True, [
        [po_obj.add_del_portchannel_member, dut, po_name_a, dut_po_members, 'add'] for dut, dut_po_members in
        zip([dut1, dut2], [d1d2_po_member, d2d1_po_member])])
    if not all(i is None for i in exceptions):
        print_log(exceptions)
    if False in result:
        print_log('Portchannel-{} after moving back member:{}-{} FAILED '.format(po_name_a, d1d2_po_member, d2d1_po_member),'MED')
    verify_po_state([po_key_a], state='up')
    verify_po_state([po_key_a], state='up')

    if not run_verify_traffic(src_stream_list=data.base_src_streams,dest_stream_list=data.base_dst_streams):
        final_result = False
        traffic_forward_fail += 1
    if not verify_mac_table(data.ver_dut_list, data.dut_mac_count_list,mac_search=data.mac_srch_str):
        final_result = False
        mac_count_fail += 1

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


@pytest.mark.l2fwd_phase2
@pytest.mark.l2fwd_ip
def test_l3_vlan_interface():
    tc_list = ['FtOpSoSwL2FwdIt001','FtOpSoSwL2FwdIt002']
    print_log("START of TC ==> test_l3_vlan_interface\n TCs:<{}>".format(tc_list), "HIGH")
    final_result = True
    mac_count_fail = 0
    traffic_forward_fail = 0
    flooding_fail = 0
    mac_aging_fail = 0
    ping_fail = 0
    mask = "24"
    mask_v6 = "64"
    enable_ipv6()

    vlan_list = [data.base_vlan,data.base_vlan + data.access_port_count,data.base_lagT_vlan,data.base_lagA_vlan]
    same_net = 1
    dut1_ip_list = []
    dut2_ip_list = []
    dut1_ipv6_list = []
    dut2_ipv6_list = []
    d1 = data.my_dut_list[0]
    d2 = data.my_dut_list[1]
    dn = data.my_dut_list[-1]
    dn_1 = data.my_dut_list[-2]
    print_log(" Configure IPv4 and IPv6 on vlans - Access,Trunk,LAG Access,LAG Trunk.", "HIGH")
    n = len(data.my_dut_list) - 1
    for _ in range(n):
        sub_net = 1
        for vlan_int in vlan_list:
            ip_str = "192.168." + str(sub_net) +"."+ str(same_net)
            ipv6_str = "201:" + str(sub_net) + "::" +str(same_net)
            sub_net += 1
            if same_net == 1:
                dut1_ip_list += [ip_str]
                dut1_ipv6_list += [ipv6_str]
            else:
                dut2_ip_list += [ip_str]
                dut2_ipv6_list += [ipv6_str]
        same_net = 2

    for vlan_int, ip1, ip2 in zip(vlan_list, dut1_ip_list, dut2_ip_list):
        api_list = []
        api_list.append([ip_obj.config_ip_addr_interface,d1,'Vlan'+str(vlan_int),ip1,mask])
        api_list.append([ip_obj.config_ip_addr_interface,dn,'Vlan'+str(vlan_int),ip2,mask])
        utils.exec_all(True, api_list)
    for vlan_int, ip1,ip2 in zip(vlan_list,dut1_ipv6_list,dut2_ipv6_list):
        api_list = []
        api_list.append([ip_obj.config_ip_addr_interface,d1,'Vlan'+str(vlan_int),ip1,mask_v6,'ipv6'])
        api_list.append([ip_obj.config_ip_addr_interface,dn,'Vlan'+str(vlan_int),ip2,mask_v6,'ipv6'])
        utils.exec_all(True, api_list)

    print_log(" Verify - Ping IPv4 and IPv6 from DUT1 to DUT2 ", "HIGH")
    for ip_addr in dut2_ip_list:
        result1 = ip_obj.ping(d1, ip_addr)
        if not result1:
            print_log("FAIL:Ping failed to {} ".format(ip_addr),'ERROR')
            final_result = False
            ping_fail +=1

    for ipv6_addr in dut2_ipv6_list:
        result1 = ip_obj.ping(d1, ipv6_addr,'ipv6')
        if not result1:
            print_log("FAIL:Ping ipv6 failed to {} ".format(ipv6_addr), 'ERROR')
            final_result = False
            ping_fail += 1

    print_log(" Verify - Ping IPv4 and IPv6 after clearing arp, nd table. ", "HIGH")

    utils.exec_all(True, [[arp_obj.clear_arp_table, dut] for dut in [data.my_dut_list[0],data.my_dut_list[-1]]])
    utils.exec_all(True, [[arp_obj.clear_ndp_table, dut] for dut in [data.my_dut_list[0],data.my_dut_list[-1]]])

    for ip_addr in dut2_ip_list:
        result1 = ip_obj.ping(d1, ip_addr)
        if not result1:
            print_log("FAIL:Ping failed after clear arp to {} ".format(ip_addr),'ERROR')
            final_result = False
            ping_fail += 1

    for ipv6_addr in dut2_ipv6_list:
        result1 = ip_obj.ping(d1, ipv6_addr,'ipv6')
        if not result1:
            print_log("FAIL:Ping ipv6 failed after clear nd to {} ".format(ipv6_addr), 'ERROR')
            final_result = False
            ping_fail += 1

    print_log(" Verify - Ping IPv4 and IPv6 after moving vlan from phy port to LAG. ", "HIGH")
    print_log("Remove vlan from access and trunk physical port.", "HIGH")
    vlan_phyA = data.base_vlan
    vlan_phyT = data.base_vlan + data.access_port_count
    all_links = st.get_dut_links(d1, peer=d2)
    dut1_phyA_port = all_links[0][0]
    dut2_phyA_port = all_links[0][2]
    dut1_phyT_port = all_links[data.access_port_count][0]
    dut2_phyT_port = all_links[data.access_port_count][2]

    api_list = []
    api_list.append([vlan_obj.delete_vlan_member, d1, vlan_phyA, dut1_phyA_port])
    api_list.append([vlan_obj.delete_vlan_member, d2, vlan_phyA, dut2_phyA_port])
    utils.exec_all(True, api_list)
    api_list = []
    api_list.append([vlan_obj.delete_vlan_member, d1, vlan_phyT, dut1_phyT_port, True])
    api_list.append([vlan_obj.delete_vlan_member, d2, vlan_phyT, dut2_phyT_port, True])
    utils.exec_all(True, api_list)

    print_log("Configure vlans as Trunk LAG member.", "HIGH")
    po_key = data.po_metadata[(d1, 'trunk')]['base_id']
    trunk_lag = data.portchannel[po_key]['name']
    for vlan in [vlan_phyA, vlan_phyT]:
        api_list = []
        api_list.append([vlan_obj.add_vlan_member, d1, vlan, trunk_lag, True])
        api_list.append([vlan_obj.add_vlan_member, d2, vlan, trunk_lag, True])
        utils.exec_all(True, api_list)

    print_log(" Verify - Ping IPv4 and IPv6 after lag member move. ", "HIGH")
    for ip_addr in dut2_ip_list:
        result1 = ip_obj.ping(d1, ip_addr)
        if not result1:
            print_log("FAIL:Ping failed after clear arp to {} ".format(ip_addr),'ERROR')
            final_result = False
            ping_fail += 1

    for ipv6_addr in dut2_ipv6_list:
        result1 = ip_obj.ping(d1, ipv6_addr,'ipv6')
        if not result1:
            print_log("FAIL:Ping ipv6 failed after clear nd to {} ".format(ipv6_addr), 'ERROR')
            final_result = False
            ping_fail += 1

    print_log("Revert back the configurations done for test_l3_vlan_interface.", "HIGH")
    for vlan in [vlan_phyA, vlan_phyT]:
        api_list = []
        api_list.append([vlan_obj.delete_vlan_member, d1, vlan, trunk_lag, True])
        api_list.append([vlan_obj.delete_vlan_member, d2, vlan, trunk_lag, True])
        utils.exec_all(True, api_list)

    api_list = []
    api_list.append([vlan_obj.add_vlan_member, d1, vlan_phyA, dut1_phyA_port])
    api_list.append([vlan_obj.add_vlan_member, d2, vlan_phyA, dut2_phyA_port])
    utils.exec_all(True, api_list)
    api_list = []
    api_list.append([vlan_obj.add_vlan_member, d1, vlan_phyT, dut1_phyT_port, True])
    api_list.append([vlan_obj.add_vlan_member, d2, vlan_phyT, dut2_phyT_port, True])
    utils.exec_all(True, api_list)
    for vlan_int, ip1, ip2 in zip(vlan_list, dut1_ip_list, dut2_ip_list):
        api_list = []
        api_list.append([ip_obj.delete_ip_interface,d1,'Vlan'+str(vlan_int),ip1,mask])
        api_list.append([ip_obj.delete_ip_interface,dn,'Vlan'+str(vlan_int),ip2,mask])
        utils.exec_all(True, api_list)
    for vlan_int, ip1,ip2 in zip(vlan_list,dut1_ipv6_list,dut2_ipv6_list):
        api_list = []
        api_list.append([ip_obj.delete_ip_interface,d1,'Vlan'+str(vlan_int),ip1,mask_v6,'ipv6'])
        api_list.append([ip_obj.delete_ip_interface,dn,'Vlan'+str(vlan_int),ip2,mask_v6,'ipv6'])
        utils.exec_all(True, api_list)

    #FtOpSoSwL2FwdIt003
    print_log("Unconfigure vlans and configure IP addresses - test_l3_vlan_interface.", "HIGH")
    print_log("Delete existing vlans on first- Access, Trunk,LAG Trunk, LAG Access", "HIGH")
    final_result = True

    # Delete on last DUT
    all_links = st.get_dut_links(d1, peer=d2)
    all_links_n = st.get_dut_links(dn_1, peer=dn)

    # Access vlan removal
    api_list = []
    api_list.append([vlan_obj.delete_vlan_member, d1, data.base_vlan, all_links[0][0]])
    api_list.append([vlan_obj.delete_vlan_member, dn, data.base_vlan, all_links_n[0][2]])
    utils.exec_all(True, api_list)

    # Remove all vlans from first trunk port
    link = data.access_port_count
    v_range_t = str(data.base_trunk_vlan) + " " + str(data.base_trunk_vlan + data.trunk_vlan_count - 1)
    api_list = []
    api_list.append([vlan_obj.config_vlan_range_members, d1, v_range_t, all_links[link][0],'del'])
    api_list.append([vlan_obj.config_vlan_range_members, dn, v_range_t, all_links_n[link][2],'del'])
    utils.exec_all(True, api_list)

    # Remove all vlans from first tagged LAG
    po_key = data.po_metadata[(d1, 'trunk')]['base_id']
    trunk_lag = data.portchannel[po_key]['name']
    v_range_lag = str(data.base_lagT_vlan) + " " + str(data.base_lagT_vlan + data.lagT_vlan_count - 1)
    api_list = []
    api_list.append([vlan_obj.config_vlan_range_members, d1, v_range_lag, trunk_lag, 'del'])
    api_list.append([vlan_obj.config_vlan_range_members, dn, v_range_lag, trunk_lag, 'del'])
    utils.exec_all(True, api_list)

    # Access lag vlan removal
    po_key = data.po_metadata[(d1, 'access')]['base_id']
    access_lag = data.portchannel[po_key]['name']
    api_list = []
    api_list.append([vlan_obj.delete_vlan_member, d1, data.base_lagA_vlan, access_lag])
    api_list.append([vlan_obj.delete_vlan_member, dn, data.base_lagA_vlan, access_lag])
    utils.exec_all(True, api_list)
    port_list1 = [all_links[0][0],all_links[link][0],trunk_lag,access_lag]
    port_listn = [all_links_n[0][2],all_links_n[link][2],trunk_lag,access_lag]

    for p1, p2, ip1, ip2 in zip(port_list1, port_listn, dut1_ip_list, dut2_ip_list):
        api_list = []
        api_list.append([ip_obj.config_ip_addr_interface,d1,p1,ip1,mask])
        api_list.append([ip_obj.config_ip_addr_interface,dn,p2,ip2,mask])
        utils.exec_all(True, api_list)
    for p1,p2,ip1,ip2 in zip(port_list1,port_listn,dut1_ipv6_list,dut2_ipv6_list):
        api_list = []
        api_list.append([ip_obj.config_ip_addr_interface,d1,p1,ip1,mask_v6,'ipv6'])
        api_list.append([ip_obj.config_ip_addr_interface,dn,p2,ip2,mask_v6,'ipv6'])
        utils.exec_all(True, api_list)
    print_log(" Verify - Ping IPv4 and IPv6 from DUT1 to DUT2 ", "HIGH")

    for ip_addr in dut2_ip_list:
        result1 = ip_obj.ping(d1, ip_addr)
        if not result1:
            print_log("FAIL:Ping failed to {} ".format(ip_addr),'ERROR')
            final_result = False
            ping_fail += 1

    for ipv6_addr in dut2_ipv6_list:
        result1 = ip_obj.ping(d1, ipv6_addr,'ipv6')
        if not result1:
            print_log("FAIL:Ping ipv6 failed to {} ".format(ipv6_addr), 'ERROR')
            final_result = False
            ping_fail += 1

    print_log("Below add del range command to validate : defect CS8724153")
    vlan_range = "3000 3010"
    res = vlan_obj.config_vlan_range(d1, vlan_range)
    if not res:
        print_log("FAIL:Vlan range add command failed with IP interfaces on system" , 'ERROR')
        final_result = False
    utils.exec_all(True, [[vlan_obj.config_vlan_range, dut, vlan_range] for dut in data.ver_dut_list])
    utils.exec_all(True, [[vlan_obj.config_vlan_range_members, dut, vlan_range,data.tgen_port[dut]] for dut in data.ver_dut_list])
    utils.exec_all(True, [[vlan_obj.config_vlan_range_members, dut, vlan_range,data.tgen_port[dut], 'del'] for dut in data.ver_dut_list])
    utils.exec_all(True, [[vlan_obj.config_vlan_range, dut, vlan_range,'del'] for dut in data.ver_dut_list])
    if not res:
        print_log("FAIL:Vlan del range command failed with IP interfaces on system" , 'ERROR')
        final_result = False
    print_log("Unconfigure IP addresses - test_l3_vlan_interface.", "HIGH")

    for p1, p2, ip1, ip2 in zip(port_list1, port_listn, dut1_ip_list, dut2_ip_list):
        api_list = []
        api_list.append([ip_obj.delete_ip_interface,d1,p1,ip1,mask])
        api_list.append([ip_obj.delete_ip_interface,dn,p2,ip2,mask])
        utils.exec_all(True, api_list)
    for p1,p2,ip1,ip2 in zip(port_list1,port_listn,dut1_ipv6_list,dut2_ipv6_list):
        api_list = []
        api_list.append([ip_obj.delete_ip_interface,d1,p1,ip1,mask_v6,'ipv6'])
        api_list.append([ip_obj.delete_ip_interface,dn,p2,ip2,mask_v6,'ipv6'])
        utils.exec_all(True, api_list)

    print_log(" Reconfigure deleted vlans.- Access,Trunk,LAG Trunk, LAG Access", "HIGH")

    # Reconfigure vlans and vlan members
    api_list = []
    api_list.append([vlan_obj.add_vlan_member, d1, data.base_vlan, all_links[0][0]])
    api_list.append([vlan_obj.add_vlan_member, dn, data.base_vlan, all_links_n[0][2]])
    utils.exec_all(True, api_list)

    # Remove all vlans from first trunk port
    link = data.access_port_count
    v_range_t = str(data.base_trunk_vlan) + " " + str(data.base_trunk_vlan + data.trunk_vlan_count - 1)
    api_list = []
    api_list.append([vlan_obj.config_vlan_range_members, d1, v_range_t, all_links[link][0]])
    api_list.append([vlan_obj.config_vlan_range_members, dn, v_range_t, all_links_n[link][2]])
    utils.exec_all(True, api_list)

    # Remove all vlans from first tagged LAG
    po_key = data.po_metadata[(d1, 'trunk')]['base_id']
    trunk_lag = data.portchannel[po_key]['name']
    v_range_lag = str(data.base_lagT_vlan) + " " + str(data.base_lagT_vlan + data.lagT_vlan_count - 1)
    api_list = []
    api_list.append([vlan_obj.config_vlan_range_members, d1, v_range_lag, trunk_lag])
    api_list.append([vlan_obj.config_vlan_range_members, dn, v_range_lag, trunk_lag])
    utils.exec_all(True, api_list)

    # Access lag vlan removal
    po_key = data.po_metadata[(d1, 'access')]['base_id']
    access_lag = data.portchannel[po_key]['name']
    api_list = []
    api_list.append([vlan_obj.add_vlan_member, d1, data.base_lagA_vlan, access_lag])
    api_list.append([vlan_obj.add_vlan_member, dn, data.base_lagA_vlan, access_lag])
    utils.exec_all(True, api_list)
    disable_ipv6()
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
        if ping_fail > 0:
            fail_msg += 'Ping Failed:'
        st.report_fail("test_case_failure_message", fail_msg.strip(':'))



@pytest.mark.l2fwd_phase2
@pytest.mark.l2fwd_reconfig
def test_del_reconfig_vlan():
    tc_list = ['FtOpSoSwL2FwdFn004']
    print_log("START of TC ==> test_del_reconfig_vlan\n TCs:<{}>".format(tc_list), "HIGH")

    # Delete first  vlan from phy access, phy Trunk, PO trunk and PO access
    # Delete same vlan from tgen ports
    final_result = True
    mac_count_fail = 0
    traffic_forward_fail = 0
    flooding_fail = 0
    mac_aging_fail = 0
    vlan_a = data.base_vlan
    vlan_t = data.base_vlan + data.access_port_count
    vlan_lagT = data.base_lagT_vlan
    vlan_lagA = data.base_lagA_vlan
    vlan_lst = [vlan_a,vlan_t,vlan_lagT,vlan_lagA]

    print_log(" Delete existing vlans.- Access,Trunk,LAG Trunk, LAG Access", "HIGH")
    # Tgen port unconfigs on first and last DUT.
    for vlan in vlan_lst:
        utils.exec_all(True,[[vlan_obj.delete_vlan_member,dut,vlan,data.tgen_port[dut],True] for dut in [data.my_dut_list[0],data.my_dut_list[-1]]])
        utils.exec_all(True, [[vlan_obj.delete_vlan_member, dut, vlan, st.get_tg_links(dut)[0][0], True] for dut in
                              data.my_dut_list])
    ###d1=d2 miss
    d1 = data.my_dut_list[0]
    for d2 in data.my_dut_list[1:]:
        all_links = st.get_dut_links(d1, peer=d2)
        memberA_d1 = all_links[0][0]
        memberA_d2 = all_links[0][2]
        memberT_d1 = all_links[data.access_port_count][0]
        memberT_d2 = all_links[data.access_port_count][2]

        api_list = []
        api_list.append([vlan_obj.delete_vlan_member, d1, vlan_a, memberA_d1])
        api_list.append([vlan_obj.delete_vlan_member, d2, vlan_a, memberA_d2])
        utils.exec_all(True, api_list)

        api_list = []
        api_list.append([vlan_obj.delete_vlan_member, d1, vlan_t, memberT_d1, True])
        api_list.append([vlan_obj.delete_vlan_member, d2, vlan_t, memberT_d2, True])
        utils.exec_all(True, api_list)
        po_key = data.po_metadata[(d1, 'trunk')]['base_id']
        po_t = data.portchannel[po_key]['name']
        api_list = []
        api_list.append([vlan_obj.delete_vlan_member, d1, vlan_lagT, po_t, True])
        api_list.append([vlan_obj.delete_vlan_member, d2, vlan_lagT, po_t, True])
        utils.exec_all(True, api_list)
        po_key = data.po_metadata[(d1, 'access')]['base_id']
        po_a = data.portchannel[po_key]['name']
        api_list = []
        api_list.append([vlan_obj.delete_vlan_member, d1, vlan_lagA, po_a])
        api_list.append([vlan_obj.delete_vlan_member, d2, vlan_lagA, po_a])
        utils.exec_all(True, api_list)
        d1=d2
    if vlan_a == 1 and data.config_profile == 'l2':
        vlan_sublist = [vlan_t, vlan_lagT, vlan_lagA]
        utils.exec_all(True,[[vlan_obj.delete_vlan,dut, vlan_sublist] for dut in data.my_dut_list])
    else:
        utils.exec_all(True,[[vlan_obj.delete_vlan,dut, vlan_lst] for dut in data.my_dut_list])

    print_log(" Reconfigure deleted vlans.- Access,Trunk,LAG Trunk, LAG Access", "HIGH")
    # Reconfigure vlans and vlan members
    # Tgen port configs on first and last DUT.

    if vlan_a == 1 and data.config_profile == 'l2':
        vlan_sublist = [vlan_t, vlan_lagT, vlan_lagA]
        utils.exec_all(True,[[vlan_obj.create_vlan,dut, vlan_sublist] for dut in data.my_dut_list])
    else:
        utils.exec_all(True,[[vlan_obj.create_vlan,dut, vlan_lst] for dut in data.my_dut_list])

    for vlan in vlan_lst:
        utils.exec_all(True,[[vlan_obj.add_vlan_member,dut,vlan,data.tgen_port[dut],True] for dut in [data.my_dut_list[0],data.my_dut_list[-1]]])
        utils.exec_all(True, [[vlan_obj.add_vlan_member, dut, vlan, st.get_tg_links(dut)[0][0],True] for dut in
                              data.my_dut_list])
    d1 = data.my_dut_list[0]
    for d2 in data.my_dut_list[1:]:
        all_links = st.get_dut_links(d1, peer=d2)
        memberA_d1 = all_links[0][0]
        memberA_d2 = all_links[0][2]
        memberT_d1 = all_links[data.access_port_count][0]
        memberT_d2 = all_links[data.access_port_count][2]

        api_list = []
        api_list.append([vlan_obj.add_vlan_member, d1, vlan_a, memberA_d1])
        api_list.append([vlan_obj.add_vlan_member, d2, vlan_a, memberA_d2])
        utils.exec_all(True, api_list)
        api_list = []
        api_list.append([vlan_obj.add_vlan_member, d1, vlan_t, memberT_d1,True])
        api_list.append([vlan_obj.add_vlan_member, d2, vlan_t, memberT_d2,True])
        utils.exec_all(True, api_list)
        po_key = data.po_metadata[(d1, 'trunk')]['base_id']
        po_t = data.portchannel[po_key]['name']
        api_list = []
        api_list.append([vlan_obj.add_vlan_member, d1, vlan_lagT, po_t, True])
        api_list.append([vlan_obj.add_vlan_member, d2, vlan_lagT, po_t, True])
        utils.exec_all(True, api_list)
        po_key = data.po_metadata[(d1, 'access')]['base_id']
        po_a = data.portchannel[po_key]['name']
        api_list = []
        api_list.append([vlan_obj.add_vlan_member, d1, vlan_lagA, po_a])
        api_list.append([vlan_obj.add_vlan_member, d2, vlan_lagA, po_a])
        utils.exec_all(True, api_list)
        d1=d2

    if not run_verify_traffic(src_stream_list=data.base_src_streams,dest_stream_list=data.base_dst_streams):
        final_result = False
        traffic_forward_fail += 1
    if not verify_mac_table(data.ver_dut_list, data.dut_mac_count_list,mac_search=data.mac_srch_str):
        final_result = False
        mac_count_fail += 1

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


@pytest.mark.l2fwd_phase2
@pytest.mark.l2fwdportmode
def test_modify_port_mode():
    final_result = True
    mac_count_fail = 0
    traffic_forward_fail = 0
    flooding_fail = 0
    mac_aging_fail = 0
    tc_list = ['FtOpSoSwL2FwdFn006']
    print_log("START of TC ==> test_modify_port_mode\n TCs:<{}>".format(tc_list), "HIGH")

    mac_count = data.tc_specific_mac_count

    vlan_phyA = data.tc_specific_vlan
    vlan_phyT = str(data.tc_specific_vlan + 1) + ' ' + str(data.tc_specific_vlan + 2)
    vlan_lagT = str(data.tc_specific_vlan + 3) + ' ' + str(data.tc_specific_vlan + 4)

    vlan_lagA = data.tc_specific_vlan + 5
    d1 = data.my_dut_list[0]
    for d2 in data.my_dut_list[1:]:
        all_links = st.get_dut_links(d1, peer=d2)
        access_port1 = all_links[0][0]
        access_port2 = all_links[0][2]
        trunk_port1  = all_links[data.access_port_count][0]
        trunk_port2  = all_links[data.access_port_count][2]

        po_key = data.po_metadata[(d1, 'trunk')]['base_id']
        trunk_lag   = data.portchannel[po_key]['name']
        po_key = data.po_metadata[(d1, 'access')]['base_id']
        access_lag  = data.portchannel[po_key]['name']

        # Modify vlan on first Trunk phy port and portchannel on each DUT

        print_log(" Access <--> Trunk :Add new range of vlans to existing Access and trunk port physical and portchannel.", "HIGH")
        utils.exec_all(True, [[vlan_obj.config_vlan_range_members, d1, vlan_phyT, access_port1], \
                              [vlan_obj.config_vlan_range_members, d2, vlan_phyT, access_port2]])
        utils.exec_all(True, [[vlan_obj.add_vlan_member, d1, vlan_phyA, trunk_port1], \
                              [vlan_obj.add_vlan_member, d2, vlan_phyA, trunk_port2]])

        utils.exec_all(True, [[vlan_obj.config_vlan_range_members, d1, vlan_lagT, access_lag], \
                              [vlan_obj.config_vlan_range_members, d2, vlan_lagT, access_lag]])
        utils.exec_all(True, [[vlan_obj.add_vlan_member, d1, vlan_lagA, trunk_lag], \
                              [vlan_obj.add_vlan_member, d2, vlan_lagA, trunk_lag]])
        d1 = d2

    print_log(" Use testcase specific traffic streams for the new range of vlans.", "HIGH")
    (tg_ph11, tg_ph21) = (tg_src_ph1, tg_dest_ph1)

    st_key = 'EE'
    src_mac = '00:12:' + st_key + ':00:00:01'
    dst_mac = '00:21:' + st_key + ':00:10:01'
    src_mac_substr = src_mac[:8]
    dst_mac_substr = dst_mac[:8]

    print_log(" Clear fdb entries and start traffic streams.", "HIGH")
    utils.exec_all(True, [[mac_obj.clear_mac, dut] for dut in data.my_dut_list])
    ##CLEAR
    if not run_verify_traffic(tg_ph_src=tg_ph11,tg_ph_dest=tg_ph21,src_stream_list= data.stream_data1[st_key]['streamAB'], dest_stream_list=data.stream_data1[st_key]['streamBA']):
        final_result = False
        traffic_forward_fail += 1

    print_log(" Verify fdb entries for the newly configured range of vlans.", "HIGH")
    [actual_src_macs, exceptions] = utils.exec_foreach(True, data.ver_dut_list, mac_obj.get_mac_address_count,
                                                       mac_search=src_mac_substr)
    if not all(i is None for i in exceptions):
        print_log(exceptions)
    [actual_dst_macs, exceptions] = utils.exec_foreach(True, data.ver_dut_list, mac_obj.get_mac_address_count,
                                                       mac_search=dst_mac_substr)
    if not all(i is None for i in exceptions):
        print_log(exceptions)
    for dut,src_actual_mac_count,dst_actual_mac_count in zip(data.ver_dut_list,actual_src_macs,actual_dst_macs):
        if not (src_actual_mac_count == dst_actual_mac_count == mac_count) :
            print_log("FAIL:Verify MAC with filter on {} failed, Expect: {}, Got: src {} dst {}".format(dut, mac_count, src_actual_mac_count,dst_actual_mac_count),'ERROR')
            final_result = False
            mac_count_fail += 1
            asicapi.dump_l2(dut)
        else:
            print_log("PASS:Verify MAC with filter on {} passed, Expect: {}, Got: src {} dst {}".format(dut, mac_count, src_actual_mac_count,dst_actual_mac_count),'MED')

    print_log(" Removing the newly configured range of vlans.", "HIGH")
    d1 = data.my_dut_list[0]
    for d2 in data.my_dut_list[1:]:
        all_links = st.get_dut_links(d1, peer=d2)
        access_port1 = all_links[0][0]
        access_port2 = all_links[0][2]
        trunk_port1 = all_links[data.access_port_count][0]
        trunk_port2 = all_links[data.access_port_count][2]

        po_key = data.po_metadata[(d1, 'trunk')]['base_id']
        trunk_lag = data.portchannel[po_key]['name']
        po_key = data.po_metadata[(d1, 'access')]['base_id']
        access_lag = data.portchannel[po_key]['name']

        # Modify vlan on first Trunk phy port and portchannel on each DUT

        print_log(" Access <--> Trunk :Add new range of vlans to existing Access and trunk port physical and portchannel.", "HIGH")
        utils.exec_all(True, [[vlan_obj.config_vlan_range_members, d1, vlan_phyT, access_port1, 'del'], \
                              [vlan_obj.config_vlan_range_members, d2, vlan_phyT, access_port2, 'del']])
        utils.exec_all(True, [[vlan_obj.delete_vlan_member, d1, vlan_phyA, trunk_port1], \
                              [vlan_obj.delete_vlan_member, d2, vlan_phyA, trunk_port2]])
        utils.exec_all(True, [[vlan_obj.config_vlan_range_members, d1, vlan_lagT, access_lag,'del'], \
                              [vlan_obj.config_vlan_range_members, d2, vlan_lagT, access_lag,'del']])
        utils.exec_all(True, [[vlan_obj.delete_vlan_member, d1, vlan_lagA, trunk_lag], \
                              [vlan_obj.delete_vlan_member, d2, vlan_lagA, trunk_lag]])

        d1 = d2

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


@pytest.mark.rerun
@pytest.mark.l2fwd_phase2
@pytest.mark.l2fwdstatic
def test_static_mac():
    # Configure static macs - Access(Phy,LAG) , Trunk(Phy,LAG)
    final_result = True
    mac_count_fail = 0
    traffic_forward_fail = 0
    flooding_fail = 0
    mac_aging_fail = 0
    tc_list = ['FtOpSoSwL2FwdFn003']
    print_log("START of TC ==> test_modify_access_vlan\n TCs:<{}>".format(tc_list), "HIGH")

    # Create new vlan
    vlan_phyA = data.tc_specific_vlan
    vlan_phyT = str(data.tc_specific_vlan + 1) + ' ' + str(data.tc_specific_vlan + 2)
    vlan_lagT = str(data.tc_specific_vlan + 3) + ' ' + str(data.tc_specific_vlan + 4)

    vlan_lagA = data.tc_specific_vlan + 5
    total_static_mac_count = 6

    #vlan_lst = [vlan_phyA,vlan_lagA]
    print_log('TC:test_modify_access_vlan :==> Delete previously configured access vlan on physical and lag access ports', 'MED')
    vlan_a = data.base_vlan
    vlan_lag = data.base_lagA_vlan

    d1 = data.my_dut_list[0]
    for d2 in data.my_dut_list[1:]:
        all_links = st.get_dut_links(d1, peer=d2)
        members_d1 = all_links[0][0]
        members_d2 = all_links[0][2]
        utils.exec_all(True, [[vlan_obj.delete_vlan_member, d1, vlan_a, members_d1], \
                              [vlan_obj.delete_vlan_member, d2, vlan_a, members_d2]])
        po_key = data.po_metadata[(d1, 'access')]['base_id']
        po_name = data.portchannel[po_key]['name']
        utils.exec_all(True, [[vlan_obj.delete_vlan_member, d1, vlan_lag, po_name], \
                              [vlan_obj.delete_vlan_member, d2, vlan_lag, po_name]])
        d1 = d2
    print_log('TC:test_modify_access_vlan :==> Modify access port vlans and add new vlans to tagged ports.', 'MED')

    # Modify Access vlan of Phy and PortChannel
    d1 = data.my_dut_list[0]
    base_lagT_link = data.access_port_count

    for d2 in data.my_dut_list[1:]:
        all_links = st.get_dut_links(d1, peer=d2)
        members_d1 = all_links[0][0]
        members_d2 = all_links[0][2]
        utils.exec_all(True, [[vlan_obj.add_vlan_member, d1, vlan_phyA, members_d1], \
                              [vlan_obj.add_vlan_member, d2, vlan_phyA, members_d2]])
        # Configure First Access PortChannel with new vlan on each DUT
        po_key = data.po_metadata[(d1, 'access')]['base_id']
        po_name = data.portchannel[po_key]['name']
        utils.exec_all(True, [[vlan_obj.add_vlan_member, d1, vlan_lagA, po_name], \
                              [vlan_obj.add_vlan_member, d2, vlan_lagA, po_name]])
        all_links = st.get_dut_links(d1, peer=d2)

        # Add new vlan on first Trunk phy port and portchannel on each DUT
        po_key = data.po_metadata[(d1, 'trunk')]['base_id']
        trunk_lag   = data.portchannel[po_key]['name']
        tc_list = ['FtOpSoSwL2FwdFn005']
        print_log("Subtestcase ==> test_new_vlans_add_del\n TCs:<{}>".format(tc_list), "HIGH")
        utils.exec_all(True, [[vlan_obj.config_vlan_range_members, d1, vlan_phyT, all_links[base_lagT_link][0]], \
                              [vlan_obj.config_vlan_range_members, d2, vlan_phyT, all_links[base_lagT_link][2]]])
        utils.exec_all(True, [[vlan_obj.config_vlan_range_members, d1, vlan_lagT, trunk_lag], \
                              [vlan_obj.config_vlan_range_members, d2, vlan_lagT, trunk_lag]])
        d1 = d2

    tc_list = ['FtOpSoSwL2FwdFn015', 'FtOpSoSwL2FwdFn017', 'FtOpSoSwL2FwdFn018', 'FtOpSoSwL2FwdCli003']
    print_log("START of TC ==> test_static_mac\n TCs:<{}>".format(tc_list), "HIGH")
    static_mac_base = "00:21:EE:00:"
    base_mac = 1001
    #static_mac_count = 6
    dst_mac_list = []
    for m in range(base_mac, base_mac + total_static_mac_count ):
        mac_str = str(m)
        static_mac = static_mac_base + mac_str[:2] + ':' + mac_str[2:]
        dst_mac_list.append(static_mac)
    ### FtOpSoSwL2FwdFn015: Static MAC over a physical port and LAG.
    vlan_list = [vlan_phyA,vlan_phyA+1,vlan_phyA+2,vlan_phyA+3,vlan_phyA+4,vlan_lagA]
    d1 = data.my_dut_list[0]
    for d2 in data.my_dut_list[1:]:
        all_links = st.get_dut_links(d1, peer=d2)
        first_phyA_port = all_links[0][0]
        first_phyT_port = all_links[data.access_port_count][0]
        po_key = data.po_metadata[(d1, 'trunk')]['base_id']
        trunk_lag   = data.portchannel[po_key]['name']
        po_key = data.po_metadata[(d1, 'access')]['base_id']
        access_lag  = data.portchannel[po_key]['name']

        port_list = [first_phyA_port,first_phyT_port,first_phyT_port,trunk_lag,trunk_lag,access_lag]
        # Configure static macs
        m_count = 0
        n = int(total_static_mac_count/len(vlan_list))
        for v, p in zip(vlan_list, port_list):
            for _ in range(n):
                mac_obj.config_mac(d1, dst_mac_list[m_count], v, p)
                m_count += 1
        d1 = d2

    # Configure all static macs to tgen port on last DUT
    dut = data.my_dut_list[-1]
    #port = data.tgen_port[dut]
    port = [st.get_tg_links(dut)[0][0]][0]
    m_count = 0
    n = total_static_mac_count/len(vlan_list)
    for v in vlan_list:
        for _ in range(n):
            mac_obj.config_mac(dut, dst_mac_list[m_count], v, port)
            m_count += 1

    st_key = 'EE'
    (tg_ph11, tg_ph21) = (tg_src_ph1, tg_dest_ph1)

    for traffic_direction in ['single','both']:
        print_log("test_static_mac: Starting traffic in direction:{}".format(traffic_direction),'MED')
        print_log(" Clearing any existing fdb entries", "HIGH")
        utils.exec_all(True, [[mac_obj.clear_mac, dut] for dut in data.my_dut_list])
        ### Clear port counters
        utils.exec_all(True, [[port_obj.clear_interface_counters, dut] for dut in data.my_dut_list])
        start_stop_traffic(tg_h,tg_ph11, tg_ph21, src_stream_list=data.stream_data1[st_key]['streamAB'],
                                  dest_stream_list=data.stream_data1[st_key]['streamBA'],direction=traffic_direction)
        ### Verify static mac stream is not flooding
        if traffic_direction == 'single':
            [result, exceptions] = utils.exec_all(True, [[verify_flooding_on_dut, dut, [st.get_tg_links(dut)[1][0]], data.counters_threshold] \
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
        for dut in data.ver_dut_list:
            sa_mac_count = mac_obj.get_mac_address_count(dut, type='Dynamic', mac_search="00:12:")
            if traffic_direction == 'single':
                da_mac_count = mac_obj.get_mac_address_count(dut, type='Static', mac_search="00:21:")
                expect_type = 'Static'
            else:
                da_mac_count = mac_obj.get_mac_address_count(dut, type='Dynamic', mac_search="00:21:")
                expect_type = 'Dynamic'
            if da_mac_count != (total_static_mac_count) :
                print_log(" FAIL :Mismatch in DA mac count, Type:{}, Got:{} and Expect:{} on DUT {}".format(expect_type,da_mac_count,total_static_mac_count,dut),'MED')
                final_result = False
                mac_count_fail += 1
            else:
                print_log(" PASS : DA mac count, Type:{}, Got:{} and Expect:{} on DUT {}".format(expect_type,da_mac_count,total_static_mac_count, dut),'MED')
            if sa_mac_count != (total_static_mac_count) :
                print_log(" FAIL :Mismatch in SA mac count, Type:Dynamic, Got:{} and Expect:{} on DUT {}".format(sa_mac_count,total_static_mac_count,dut),'MED')
                final_result = False
                mac_count_fail += 1
            else:
                print_log(" PASS : SA mac count, Type:Dynamic, Got:{} and Expect:{} on DUT {}".format(sa_mac_count,total_static_mac_count, dut),'MED')

            mac_obj.clear_mac(dut)
            ##CLEAR
            if data.slow_mac_del_dut in data.platform_list: st.wait(4)
            ### FtOpSoSwL2FwdFn018: Clear mac and verify static macs not cleared
            # After clear command only dynamic macs are deleted
            if traffic_direction == 'single':
                expect_mac = total_static_mac_count
            else:
                expect_mac = 0

            if not verify_mac_table(dut, expect_mac, mac_search="00:21:"):
                final_result = False
                mac_count_fail += 1
                print_log("FAIL: Verify static macs after clear mac on DUT {}".format(dut),'MED')

        if traffic_direction == 'single':
            ### Unconfigure Static macs and send bi-direction traffic to verify it is learned as dynamic
            ### FtOpSoSwL2FwdFn017: Send Static mac stream and verify macs are learned as dynamic -- PENDING ?
            d1 = data.my_dut_list[0]

            for d2 in data.my_dut_list[1:]:
                all_links = st.get_dut_links(d1, peer=d2)
                first_phyA_port = all_links[0][0]
                first_phyT_port = all_links[data.access_port_count][0]
                po_key = data.po_metadata[(d1, 'trunk')]['base_id']
                trunk_lag = data.portchannel[po_key]['name']
                po_key = data.po_metadata[(d1, 'access')]['base_id']
                access_lag = data.portchannel[po_key]['name']

                port_list = [first_phyA_port, first_phyT_port, first_phyT_port, trunk_lag, trunk_lag, access_lag]
                m_count = 0
                n = int(total_static_mac_count / len(vlan_list))
                for v,p in zip(vlan_list,port_list):
                    for _ in range(n):
                        mac_obj.delete_mac(d1, dst_mac_list[m_count], v)
                        m_count += 1

                d1=d2
            # Last DUT Tgen static mac deletion
            dut = data.my_dut_list[-1]
            m_count = 0
            n = int(total_static_mac_count / len(vlan_list))
            for v in vlan_list:
                for _ in range(n):
                    mac_obj.delete_mac(dut, dst_mac_list[m_count], v)
                    m_count += 1

    # Unconfigure newly configured vlans and reconfigure base config

    print_log('TC:test_static_mac :==> UnConfigure new set of vlans .', 'MED')

    # Modify Access vlan of Phy and PortChannel
    d1 = data.my_dut_list[0]
    base_lagT_link = data.access_port_count

    for d2 in data.my_dut_list[1:]:
        all_links = st.get_dut_links(d1, peer=d2)
        members_d1 = all_links[0][0]
        members_d2 = all_links[0][2]
        utils.exec_all(True, [[vlan_obj.delete_vlan_member, d1, vlan_phyA, members_d1], \
                              [vlan_obj.delete_vlan_member, d2, vlan_phyA, members_d2]])
        # Configure First Access PortChannel with new vlan on each DUT
        po_key = data.po_metadata[(d1, 'access')]['base_id']
        po_name = data.portchannel[po_key]['name']
        utils.exec_all(True, [[vlan_obj.delete_vlan_member, d1, vlan_lagA, po_name], \
                              [vlan_obj.delete_vlan_member, d2, vlan_lagA, po_name]])
        all_links = st.get_dut_links(d1, peer=d2)

        # Add new vlan on first Trunk phy port and portchannel on each DUT
        po_key = data.po_metadata[(d1, 'trunk')]['base_id']
        trunk_lag   = data.portchannel[po_key]['name']
        utils.exec_all(True, [[vlan_obj.config_vlan_range_members, d1, vlan_phyT, all_links[base_lagT_link][0]], \
                              [vlan_obj.config_vlan_range_members, d2, vlan_phyT, all_links[base_lagT_link][2]]])
        utils.exec_all(True, [[vlan_obj.config_vlan_range_members, d1, vlan_lagT, trunk_lag,'del'], \
                              [vlan_obj.config_vlan_range_members, d2, vlan_lagT, trunk_lag,'del']])
        d1 = d2

    d1 = data.my_dut_list[0]
    for d2 in data.my_dut_list[1:]:
        all_links = st.get_dut_links(d1, peer=d2)
        members_d1 = all_links[0][0]
        members_d2 = all_links[0][2]
        utils.exec_all(True, [[vlan_obj.add_vlan_member, d1, vlan_a, members_d1], \
                              [vlan_obj.add_vlan_member, d2, vlan_a, members_d2]])
        po_key = data.po_metadata[(d1, 'access')]['base_id']
        po_name = data.portchannel[po_key]['name']
        utils.exec_all(True, [[vlan_obj.add_vlan_member, d1, vlan_lag, po_name], \
                              [vlan_obj.add_vlan_member, d2, vlan_lag, po_name]])
        d1 = d2

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


@pytest.mark.l2fwdbum
@pytest.mark.l2fwd_sanity
def test_bum_traffic(lag_function_fixture):
    global po_reconfig_flag
    po_reconfig_flag = 0
    final_result = True
    mac_count_fail = 0
    traffic_forward_fail = 0
    flooding_fail = 0
    mac_aging_fail = 0
    load_balance_fail = 0
    tc_list = ['FtOpSoSwL2FwdFn019','FtOpSoSwL2FwdNe003']
    print_log("START of TC ==> test_bum_traffic\n TCs:<{}>".format(tc_list), "HIGH")

    # Create traffic BUM streams - Broadcast traffic
    print_log("Sub-Test :==> Verify Broadcast traffic stream.", "HIGH")
    (tg_ph11, tg_ph21) = (tg_src_ph, tg_dest_ph)
    src_mac = '00:12:01:00:00:01'
    dst_mac = 'ff:ff:ff:ff:ff:ff'
    vlan = data.base_vlan
    total_vlans = data.base_lagA_vlan+data.lagA_count-1
    ###Clear MAC
    utils.exec_all(True, [[mac_obj.clear_mac, dut] for dut in data.my_dut_list])
    ##CLEAR
    stdata = {'src_mac': src_mac, 'dst_mac': dst_mac, 'vlan': vlan,
                                'vlan_count': total_vlans,'mac_count': (total_vlans), 'rate_pps': data.tgen_rate_pps,
                                'vlan_mode': 'enable', 'tg_port_handles': [tg_ph11, tg_ph21]}

    stream1 = tg_h.tg_traffic_config(mode='create', port_handle=tg_ph11, rate_pps=data.tgen_rate_pps,
                                     mac_src=stdata['src_mac'], mac_src_mode="increment",
                                     mac_src_count=stdata['mac_count'], transmit_mode="continuous",
                                     mac_src_step="00:00:00:00:00:01", mac_dst=stdata['dst_mac'],
                                     l2_encap='ethernet_ii_vlan',vlan_id=stdata['vlan'],
                                     vlan_id_count=stdata['vlan_count'], vlan="enable", vlan_id_mode="increment", vlan_id_step='1',port_handle2=tg_ph21)

    stream2 = tg_h.tg_traffic_config(mode='create', port_handle=tg_ph21, rate_pps=data.tgen_rate_pps,
                                     mac_src=stdata['dst_mac'], mac_dst_mode="increment",
                                     mac_dst_count=stdata['mac_count'], transmit_mode="continuous",
                                     mac_dst_step="00:00:00:00:00:01", mac_dst=stdata['src_mac'],
                                     l2_encap='ethernet_ii_vlan',vlan_id=stdata['vlan'],
                                     vlan_id_count=stdata['vlan_count'], vlan="enable", vlan_id_mode="increment", vlan_id_step='1',port_handle2=tg_ph11)

    ### Clear port counters
    utils.exec_all(True, [[port_obj.clear_interface_counters, dut] for dut in data.my_dut_list])

    ### Start both direction traffic so that SA as broadcast mac is covered.
    start_stop_traffic(tg_h, tg_ph11, tg_ph21, src_stream_list=stream1['stream_id'],dest_stream_list=stream2['stream_id'])

    ### Verify Broadcast stream is Flooding
    print_log('Verify Broadcast stream is flooding','HIGH')
    expect_rate = data.traffic_run_time * int(data.tgen_rate_pps) - (3 * data.counters_threshold)
    dict_list = []
    for dut in data.ver_dut_list:
        dict_list += [{'portList': [st.get_tg_links(dut)[0][0]], 'threshold': expect_rate}]
    if not retry_parallel(verify_flooding_on_dut, dict_list=dict_list, dut_list=data.ver_dut_list, retry_count=3, delay=2):
        print_log('FAIL:Broadcast traffic is not flooded, expect_tx_pkt > {} is not seen'.format(expect_rate), 'ERROR')
        final_result = False
        flooding_fail += 1
    else:
        print_log('PASS:Broadcast traffic is flooded, expect_tx_pkt > {} is seen'.format(expect_rate), 'MED')

    ###Verify LAG load balancing with BUM traffic
    #po_key = data.po_metadata[(dut, 'trunk')]['base_id']
    per_stream_pkts = int(data.tgen_rate_pps) * data.traffic_run_time / total_vlans
    [result,exceptions] = utils.exec_all(True, [[verify_lag_loadbalancing, dut, data.po_metadata[(dut, 'trunk')]['base_id'],per_stream_pkts] for dut in data.my_dut_list[:-1]])
    if not all(i is None for i in exceptions):
        print_log(exceptions)
    if False in result:
        print_log('FAIL: Broadcast Traffic on LAG members is NOT load balanced.', 'ERROR')
        load_balance_fail += 1
        final_result = False
    else :
        print_log('PASS: Broadcast Traffic on LAG members is load balanced.', 'MED')

    ### Verify broadcast MAC is not learned
    mac_search_pattern = 'ff:ff:ff:ff:'
    dut_mac_zero_list = [0]* len(data.ver_dut_list)
    if not verify_mac_table(data.ver_dut_list, dut_mac_zero_list, mac_search=mac_search_pattern):
        final_result = False
        mac_count_fail += 1
        print_log("FAIL:Verify BUM traffic, Broadcast mac as SA is learned, MAC pattern found:{},expect to be dropped" \
                  .format(mac_search_pattern), 'ERROR')
    else:
        print_log("PASS:Verify BUM traffic, Broadcast mac as SA is not learned, MAC pattern not found:{}, dropped as expected"\
                  .format(mac_search_pattern), 'MED')

    print_log("Sub-Test :==> Verify Multicast traffic stream .", "HIGH")
    ### Create traffic BUM streams - Multicast traffic
    src_mac = '00:12:01:00:00:01'
    dst_mac = '01:00:5e:01:01:01'

    stdata = {'src_mac': src_mac, 'dst_mac': dst_mac, 'vlan': vlan,
                                'vlan_count': total_vlans,'mac_count': total_vlans, 'rate_pps': data.tgen_rate_pps,
                                'vlan_mode': 'enable', 'tg_port_handles': [tg_ph11, tg_ph21]}

    stream3 = tg_h.tg_traffic_config(mode='create', port_handle=tg_ph11, rate_pps=data.tgen_rate_pps,
                                     mac_src=stdata['src_mac'], mac_src_mode="increment",
                                     mac_src_count=stdata['mac_count'], transmit_mode="continuous",
                                     mac_src_step="00:00:00:00:00:01", mac_dst=stdata['dst_mac'],
                                     l2_encap='ethernet_ii_vlan',vlan_id=stdata['vlan'],
                                     vlan_id_count=stdata['vlan_count'], vlan="enable", vlan_id_mode="increment", vlan_id_step='1',port_handle2=tg_ph21)

    stream4 = tg_h.tg_traffic_config(mode='create', port_handle=tg_ph21, rate_pps=data.tgen_rate_pps,
                                     mac_src=stdata['dst_mac'], mac_src_mode="increment",
                                     mac_src_count=stdata['mac_count'], transmit_mode="continuous",
                                     mac_src_step="00:00:00:00:00:01", mac_dst=stdata['src_mac'],
                                     l2_encap='ethernet_ii_vlan',vlan_id=stdata['vlan'],
                                     vlan_id_count=stdata['vlan_count'], vlan="enable", vlan_id_mode="increment", vlan_id_step='1',port_handle2=tg_ph11)
    ###Clear MAC
    utils.exec_all(True, [[mac_obj.clear_mac, dut] for dut in data.my_dut_list])
    ##CLEAR
    ### Clear port counters
    utils.exec_all(True, [[port_obj.clear_interface_counters, dut] for dut in data.my_dut_list])

    ### Start both direction traffic so that SA as multicast mac is covered.
    start_stop_traffic(tg_h, tg_ph11, tg_ph21, src_stream_list=stream3['stream_id'],dest_stream_list=stream4['stream_id'])

    ### Verify Multicast stream is Flooding
    print_log('Verify Multicast stream is flooding', 'HIGH')
    expect_rate = data.traffic_run_time * int(data.tgen_rate_pps) - (3 * data.counters_threshold)
    dict_list = []
    for dut in data.ver_dut_list:
        dict_list += [{'portList': [st.get_tg_links(dut)[0][0]], 'threshold': expect_rate}]
    if not retry_parallel(verify_flooding_on_dut, dict_list=dict_list, dut_list=data.ver_dut_list, retry_count=3,
                          delay=2):
        print_log('FAIL:Multicast traffic is not flooded, expect_tx_pkt > {} is not seen'.format(expect_rate), 'ERROR')
        final_result = False
        flooding_fail += 1
    else:
        print_log('PASS:Multicast traffic is flooded, expect_tx_pkt > {} is seen'.format(expect_rate), 'MED')

    ### Verify LAG load balancing with BUM traffic
    per_stream_pkts = int(data.tgen_rate_pps) * data.traffic_run_time / total_vlans
    [result, exceptions] = utils.exec_all(True, [
        [verify_lag_loadbalancing, dut, data.po_metadata[(dut, 'trunk')]['base_id'], per_stream_pkts] for dut in
        data.my_dut_list[:-1]])
    if not all(i is None for i in exceptions):
        print_log(exceptions)
    if False in result:
        print_log('FAIL: Multicast Traffic on LAG members is NOT load balanced.', 'ERROR')
        load_balance_fail += 1
        final_result = False
    else :
        print_log('PASS: Multicast Traffic on LAG members is load balanced.', 'MED')

    ### Verify multicast MAC is not learned
    mac_search_pattern ='01:00:5e:01:'
    dut_mac_zero_list = [0]*len(data.ver_dut_list)
    if not verify_mac_table(data.ver_dut_list, dut_mac_zero_list, mac_search=mac_search_pattern):
        final_result = False
        mac_count_fail += 1
        print_log("FAIL:Verify BUM traffic, Multicast mac as SA is learned, MAC pattern found:{},expect to be dropped" \
                  .format(mac_search_pattern), 'ERROR')
    else:
        print_log("PASS:Verify BUM traffic, Multicast mac as SA is not learned, MAC pattern not found:{}, dropped as expected"\
                  .format(mac_search_pattern), 'MED')
    #tg_h.tg_traffic_config(mode='remove', stream_id=[stream1['stream_id']]+[stream2['stream_id']]+[stream3['stream_id']]+[stream4['stream_id']])
    tg_h.tg_traffic_config(mode='remove', stream_id=stream1['stream_id'])
    tg_h.tg_traffic_config(mode='remove', stream_id=stream2['stream_id'])
    tg_h.tg_traffic_config(mode='remove', stream_id=stream3['stream_id'])
    tg_h.tg_traffic_config(mode='remove', stream_id=stream4['stream_id'])
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
        if  load_balance_fail > 0:
            fail_msg += 'BUM traffic load balancing on LAG Failed:'
        st.report_fail("test_case_failure_message", fail_msg.strip(':'))


@pytest.mark.l2fwd_sanity
def test_traffic_types():
    final_result = True
    mac_count_fail = 0
    traffic_forward_fail = 0
    flooding_fail = 0
    mac_aging_fail = 0
    tc_list = ['FtOpSoSwL2FwdFn020','FtOpSoSwL2FwdFn021','FtOpSoSwL2FwdFn022','FtOpSoSwL2FwdNe001']
    print_log("START of TC ==> test_traffic_types\n TCs:<{}>".format(tc_list), "HIGH")

    ### FtOpSoSwL2FwdNe001 - Change the Access phyport and lag to trunk on Dut1 side
    ### Verify peer end, which is access, forwards the traffic as in SONiC an access port is also trunk in same vlan.
    d1 = data.my_dut_list[0]
    d2 = data.my_dut_list[1]
    d1_access_port = st.get_dut_links_local(d1, peer=d2)[0]
    #all_links = st.get_dut_links(d1, peer=d2)
    #members_d1 = all_links[0][0]
    vlan_obj.delete_vlan_member(d1, data.base_access_vlan, d1_access_port)
    lagA_po_key = data.po_metadata[(d1, 'access')]['base_id']
    lagA_po_name = data.portchannel[lagA_po_key]['name']
    vlan_obj.delete_vlan_member(d1, data.base_lagA_vlan, lagA_po_name)

    vlan_obj.add_vlan_member(d1, data.base_access_vlan, d1_access_port, tagging_mode=True)
    vlan_obj.add_vlan_member(d1, data.base_lagA_vlan, lagA_po_name, tagging_mode=True)

    config_diff_traffic_type()

    ### Run TC specific traffic bidirectional and verify forwarding
    print_log(" Run regular traffic streams with different ethertypes and frame sizes", "HIGH")
    #print_log(" Clear fdb entries and start traffic streams.", "HIGH")
    #utils.exec_all(True, [[mac_obj.clear_mac, dut] for dut in data.my_dut_list])
    rem_stream_list = []
    st_key_list = ['FF:11','FF:22','FF:55']
    src_streams = []
    dst_streams = []
    for st_key in st_key_list:
        ###Create list of source and destination streams
        src_strmid = data.stream_data[st_key]['streamAB']
        dst_strmid = data.stream_data[st_key]['streamBA']
        src_streams.append(src_strmid)
        dst_streams.append(dst_strmid)
    rem_stream_list = rem_stream_list + src_streams + dst_streams
    start_stop_traffic(tg_h, tg_src_ph1, tg_dest_ph1, src_stream_list=src_streams, dest_stream_list=dst_streams)
    #st.wait(data.traffic_run_time)

    ###DUT1---->DUTn Sending 5 streams out of which 4 expected to forward (2 jumbo frames 4096 & 8192 and 2 normal frames 128 & 1024 and 1 to be dropped at ingress.
    print_log("Verify regular Frames of size 128 & 1024 are getting forwarded",'MED')
    exp_ratio = float(2) / 3
    if not verify_traffic(tg_h, data.src_tgn_port1, data.dest_tgn_port1, tx_rx_ratio=exp_ratio,direction='single'):
        final_result = False
        traffic_forward_fail += 1
        print_log("Traffic verification from DUT-1 to DUT-N FAILED",'ERROR')
    else:
        print_log("Traffic verification from DUT-1 to DUT-N PASSED", 'MED')

    exp_ratio = float(1) / 3
    if not verify_traffic(tg_h, data.dest_tgn_port1, data.src_tgn_port1, tx_rx_ratio=exp_ratio, direction='single'):
        final_result = False
        traffic_forward_fail += 1
        print_log("Traffic verification from DUT-N to DUT-1 FAILED", 'ERROR')

    else:
        print_log("Traffic verification from DUT-N to DUT-1 PASSED", 'MED')

    print_log(" Run jumbo traffic streams with different ethertypes and frame sizes", "HIGH")
    st_key_list = ['FF:33', 'FF:44']
    src_streams = []
    dst_streams = []
    for st_key in st_key_list:
        ###Create list of source and destination streams
        src_strmid = data.stream_data[st_key]['streamAB']
        dst_strmid = data.stream_data[st_key]['streamBA']
        src_streams.append(src_strmid)
        dst_streams.append(dst_strmid)
    rem_stream_list = rem_stream_list + src_streams + dst_streams
    start_stop_traffic(tg_h, tg_src_ph1, tg_dest_ph1, src_stream_list=src_streams, dest_stream_list=dst_streams)

    ###DUTn---->DUT1 Sending 5 streams out of which 2 expected to forward, 1 to be dropped at ingress and 2 to be dropped at dut1 ingress.
    print_log("Verify Jumbo Frames of size 4096 & 8192 are getting forwarded", 'MED')
    exp_ratio = float(2) / 2
    if not verify_traffic(tg_h, data.src_tgn_port1, data.dest_tgn_port1, tx_rx_ratio=exp_ratio,
                          comp_type='oversize_count', direction='single'):
        final_result = False
        traffic_forward_fail += 1
        print_log("Traffic verification from DUT-1 to DUT-N FAILED", 'ERROR')
    else:
        print_log("Traffic verification from DUT-1 to DUT-N PASSED", 'MED')

    exp_ratio = float(1) / 2
    if not verify_traffic(tg_h, data.dest_tgn_port1, data.src_tgn_port1, tx_rx_ratio=exp_ratio, comp_type='oversize_count',direction='single'):
        final_result = False
        traffic_forward_fail += 1
        print_log("Traffic verification from DUT-N to DUT-1 FAILED", 'ERROR')

    else:
        print_log("Traffic verification from DUT-N to DUT-1 PASSED", 'MED')

    print_log(" Verify fdb entries for the new traffic types.", "HIGH")
    src_mac_substr = '00:12:FF:'
    dst_mac_substr = '00:21:FF:'
    # Sending these streams at 1 mac per vlan
    expect_mac_count = data.base_lagA_vlan + data.lagA_count - 1
    print_log(" Verify FDB entries for the different traffic type streams.", "HIGH")
    [actual_src_macs, exceptions] = utils.exec_foreach(True, data.ver_dut_list, mac_obj.get_mac_address_count, mac_search=src_mac_substr)
    if not all(i is None for i in exceptions):
        print_log(exceptions)
    [actual_dst_macs, exceptions] = utils.exec_foreach(True, data.ver_dut_list, mac_obj.get_mac_address_count, mac_search=dst_mac_substr)
    if not all(i is None for i in exceptions):
        print_log(exceptions)
    for dut,src_actual_mac_count,dst_actual_mac_count in zip(data.ver_dut_list,actual_src_macs,actual_dst_macs):
        if dut==data.ver_dut_list[0]:
            ###Traffic ingressing in DUT1 from DUT2 will drop on the access links as port is changed to tagged
            comparison_str = 'src_actual_mac_count == dst_actual_mac_count+2 == expect_mac_count'
            if (src_actual_mac_count == dst_actual_mac_count+2 == expect_mac_count):
                print_log("PASS:Verify MAC on {} passed, Expect: ({}), Got :({} == {}+2 == {})".format(dut,\
                                    comparison_str,src_actual_mac_count,dst_actual_mac_count,expect_mac_count),'MED')
            else:
                print_log("FAIL:Verify MAC on {} failed, Expect: ({}), Got :({} == {}+2 == {})".format(dut, \
                                    comparison_str,src_actual_mac_count,dst_actual_mac_count,expect_mac_count),'ERROR')
                final_result = False
                mac_count_fail += 1
                asicapi.dump_l2(dut)
        else:
            comparison_str = 'src_actual_mac_count == dst_actual_mac_count == expect_mac_count'
            if (src_actual_mac_count == dst_actual_mac_count == expect_mac_count):
                print_log("PASS:Verify MAC on {} passed, Expect: ({}), Got :({} == {} == {})".format(dut, \
                                    comparison_str,src_actual_mac_count,dst_actual_mac_count,expect_mac_count),'MED')
            else:
                print_log("FAIL:Verify MAC on {} failed, Expect: ({}), Got :({} == {} == {})".format(dut, \
                                    comparison_str,src_actual_mac_count,dst_actual_mac_count,expect_mac_count),'ERROR')
                final_result = False
                mac_count_fail += 1
                asicapi.dump_l2(dut)

    ### Revert config change done on DUT1
    # Move Trunk port/lag back to Access mode
    vlan_obj.delete_vlan_member(d1, data.base_access_vlan, d1_access_port, True)
    vlan_obj.delete_vlan_member(d1, data.base_lagA_vlan, lagA_po_name, True)

    vlan_obj.add_vlan_member(d1, data.base_access_vlan, d1_access_port)
    vlan_obj.add_vlan_member(d1, data.base_lagA_vlan, lagA_po_name)

    for strm in rem_stream_list:
        tg_h.tg_traffic_config(mode='remove', stream_id=strm)


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
        # st.report_fail("operation_failed")


@pytest.fixture(scope="function")
def cleanup_stp_mac_move():
    yield
    global stp_deconf_flag
    print_log("CLEANUP for test_stp_mac_move",'HIGH')
    d1 = data.my_dut_list[0]
    d2 = data.my_dut_list[1]
    trunk_link = data.access_port_count
    d1_trunk_port = st.get_dut_links_local(d1, peer=d2)[trunk_link]
    d2_trunk_port = st.get_dut_links_local(d2, peer=d1)[trunk_link]
    lagT_po_key = data.po_metadata[(d1, 'trunk')]['base_id']
    lagT_po_name = data.portchannel[lagT_po_key]['name']
    print_log("Begin TC:test_stp_mac_move unconfigurations", 'MED')
    ### Disable PVST globally
    utils.exec_all(True, [[pvst_obj.config_spanning_tree, dut, "pvst", "disable"] for dut in
                          [d1,d2]])
    ###Reset aging time
    utils.exec_all(True, [[mac_obj.config_mac_agetime, dut, data.default_macage] for dut in [d1, d2]])
    ### UnConfigure base_access_vlan from trunk phyPort
    if stp_deconf_flag < 1:
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
    if data.base_lagA_vlan < 255 and stp_deconf_flag < 2:
        api_list = []
        api_list.append([vlan_obj.delete_vlan_member, d1, data.base_lagA_vlan, lagT_po_name, True])
        api_list.append([vlan_obj.delete_vlan_member, d2, data.base_lagA_vlan, lagT_po_name, True])
        utils.exec_all(True, api_list)
    print_log("### CLEANUP End####")


@pytest.mark.l2fwd_stp
def test_stp_mac_move(cleanup_stp_mac_move):
    '''
    1. Add access vlan on  trunk links so that to create loop. Also add trunk phyPort base valn to trunk LAG
    2. Configure PVST [Configure STP priority for access vlans, so that access ports are in fwd in initial config]
    3. Send traffic and verify no loop
    4. Verify MAC table.
    5. Shut access ports and toggle member ports of trunk LAG
    6. Verify MAC table-> verify  w.r.t port
    7. Configure mac age-time and verify aging
    8. Enable back ports and make trunk phyPort forwarding
    9. Verify MAC table-> verify  w.r.t port
    10.Disable STP in vlan 1 and vlan 102 so that there is loop
    11.Send Traffic and verify flooding is there
    12.Shut tunk phyPort and lagA to break loop
    13.Verify no flooding with traffic and MAC table
    14.Enable  tunk phyPort and lagA
    15.Remove port-vlan assosciations from tunk phyPort and lagT for the access vlans to break loop
    16.Verify no flooding with traffic and MAC table
    '''
    final_result = True
    mac_count_fail = 0
    traffic_forward_fail = 0
    flooding_fail = 0
    mac_aging_fail = 0
    tc_list = ['FtOpSoSwL2FwdIt004', 'FtOpSoSwL2FwdIt005', 'FtOpSoSwL2FwdIt006', 'FtOpSoSwL2FwdFn013', 'FtOpSoSwL2FwdFn014','FtOpSoSwL2FwdNe002']
    print_log("START of TC ==> test_stp_mac_move\n TCs:<{}>".format(tc_list), "HIGH")
    stp_wait_time = 15
    ### Increasing age time from 40 to 55 as traffic/start stop some times takes extra time and with minimal age time MACs age out before verification.
    stp_mac_age = 55
    ##stp_mac_age = 500
    traffic_time = 3
    global stp_deconf_flag
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
    utils.exec_all(True,api_list)
    ### Configure trunk phyPort base vlan to trunk PO
    if data.base_trunk_vlan < 255 :
        api_list = []
        api_list.append([vlan_obj.add_vlan_member, d1, data.base_trunk_vlan, lagT_po_name, True])
        api_list.append([vlan_obj.add_vlan_member, d2, data.base_trunk_vlan, lagT_po_name, True])
        utils.exec_all(True, api_list)
    ### Configure access PO base vlan to trunk PO
    if data.base_lagA_vlan < 255 :
        api_list = []
        api_list.append([vlan_obj.add_vlan_member, d1, data.base_lagA_vlan, lagT_po_name, True])
        api_list.append([vlan_obj.add_vlan_member, d2, data.base_lagA_vlan, lagT_po_name, True])
        utils.exec_all(True, api_list)
    tc_list = ['FtOpSoSwL2FwdIt004']
    print_log("START of TC:test_stp_mac_move ==>Sub-Test:Enable xSTP and verify mac learning and traffic forwarding.\n TCs:<{}>".format(tc_list),
              "HIGH")
    ### Before Enabling STP globally, disable it explicitly on vlans in which STP not needed, to avoid STP max instance problem
    stp_vlans = [data.base_access_vlan, data.base_trunk_vlan, data.base_lagA_vlan, data.base_lagT_vlan]
    for vlan_id in range(1, data.total_vlan_count):
        if vlan_id not in stp_vlans:
            utils.exec_foreach(True, [d1, d2], stp_obj.config_stp_vlan_disable, vlanid=vlan_id)
    ### Enable PVST globally
    utils.exec_all(True,[[pvst_obj.config_spanning_tree, dut, "pvst", "enable"] for dut in [d1,d2]])
    utils.exec_foreach(True, [d1, d2], pvst_obj.config_stp_parameters, max_age=7)
    utils.exec_foreach(True, [d1, d2], pvst_obj.config_stp_parameters, forward_delay=5)
    ### Disable STP on first TGEN ports -- to avoid control traffic in traffic rate comparison
    api_list = []
    api_list = []
    api_list.append([pvst_obj.config_stp_enable_interface, d1, st.get_tg_links(d1)[0][0], 'disable'])
    api_list.append([pvst_obj.config_stp_enable_interface, d2, st.get_tg_links(d2)[0][0], 'disable'])
    utils.exec_all(True, api_list)
    ### Disable STP on second TGEN ports -- to avoid control traffic in traffic rate comparison
    api_list = []
    api_list.append([pvst_obj.config_stp_enable_interface, d1, st.get_tg_links(d1)[1][0], 'disable'])
    api_list.append([pvst_obj.config_stp_enable_interface, d2, st.get_tg_links(d2)[1][0], 'disable'])
    utils.exec_all(True, api_list)
    vlans = [data.base_access_vlan,data.base_trunk_vlan,data.base_lagA_vlan]
    for vlan in vlans:
        utils.exec_all(True, [[pvst_obj.show_stp_vlan, dut, vlan] for dut in [d1, d2]])
    ### Configure lower port priority on access links and trunk PO so that it is selected path by default
    api_list = []
    api_list.append([pvst_obj.config_stp_vlan_interface, d1, data.base_access_vlan, d1_access_port, 64, 'priority'])
    api_list.append([pvst_obj.config_stp_vlan_interface, d2, data.base_access_vlan, d2_access_port, 64, 'priority'])
    utils.exec_all(True, api_list)
    utils.exec_foreach(True, [d1, d2], pvst_obj.config_stp_vlan_interface, data.base_lagA_vlan, lagA_po_name, 96,
                       mode='priority')
    utils.exec_foreach(True, [d1, d2], pvst_obj.config_stp_vlan_interface, data.base_trunk_vlan, lagT_po_name, 64,
                       mode='priority')
    print_log("Waiting for {} sec for STP convergence".format(stp_wait_time),'MED')
    st.wait(stp_wait_time)
    ### show STP
    for vlan in vlans:
        utils.exec_all(True,[[pvst_obj.show_stp_vlan,dut,vlan] for dut in [d1,d2]])
    if not run_verify_traffic(src_stream_list=data.base_src_streams,dest_stream_list=data.base_dst_streams):
        final_result = False
        traffic_forward_fail += 1

    for dut,v1_port,v2_port,v3_port in zip([d1,d2],[d1_access_port,d2_access_port],[lagA_po_name,lagA_po_name],[lagT_po_name,lagT_po_name]):
        if dut == d1:
            if not verify_mac_table(dut, data.strm_mac_count, port=v1_port, mac_search='00:21:AA'):
                final_result = False
                mac_count_fail += 1
            if not verify_mac_table(dut, data.strm_mac_count, port=v2_port, mac_search='00:21:DD'):
                final_result = False
                mac_count_fail += 1
            if not verify_mac_table(dut, 1, port=v3_port, mac_search='00:21:BB'):
                final_result = False
                mac_count_fail += 1
        else:
            if not verify_mac_table(dut, data.strm_mac_count, port=v1_port, mac_search='00:12:AA'):
                final_result = False
                mac_count_fail += 1
            if not verify_mac_table(dut, data.strm_mac_count, port=v2_port, mac_search='00:12:DD'):
                final_result = False
                mac_count_fail += 1
            if not verify_mac_table(dut, 1, port=v3_port, mac_search='00:12:BB'):
                final_result = False
                mac_count_fail += 1

    tc_list = ['FtOpSoSwL2FwdIt005', 'FtOpSoSwL2FwdIt006', 'FtOpSoSwL2FwdFn013']
    print_log("START of TC:test_stp_mac_move ==>Sub-Test:Shut interfaces/LAG and verify MAC move after STP reconvergence.\n TCs:<{}>"\
        .format(tc_list),"HIGH")
    ### Shut  access links and trunk PO member ports.
    ##--utils.exec_all(True, [[mac_obj.clear_mac, dut] for dut in [d1,d2]])
    dut_port_dict = {}
    dut_port_dict[d1] = d1_access_port
    dut_port_dict[d2] = lagA_po_name
    utils.exec_all(True,[[intf_obj.interface_operation, dut, dut_port_dict[dut], 'shutdown'] for dut in dut_port_dict.keys()])

    toggle_lag_ports([lagT_po_key],'disable','odd')
    print_log("Waiting for {} sec for STP re-convergence".format(stp_wait_time),'MED')
    st.wait(stp_wait_time)
    ### show STP
    for vlan in vlans:
        utils.exec_all(True,[[pvst_obj.show_stp_vlan,dut,vlan] for dut in [d1,d2]])

    ### Verify MAC learned through new path.
    start_stop_traffic(src_stream_list=data.base_src_streams, dest_stream_list=data.base_dst_streams,duration=traffic_time)
    for dut,v1_port,v2_port,v3_port in zip([d1,d2],[d1_trunk_port,d2_trunk_port],[lagT_po_name,lagT_po_name],[lagT_po_name,lagT_po_name]):
        if dut == d1:
            if not verify_mac_table(dut, data.strm_mac_count, port=v1_port, mac_search='00:21:AA'):
                final_result = False
                mac_count_fail += 1
            if not verify_mac_table(dut, data.strm_mac_count, port=v2_port, mac_search='00:21:DD'):
                final_result = False
                mac_count_fail += 1
            if not verify_mac_table(dut, 1, port=v3_port, mac_search='00:21:BB'):
                final_result = False
                mac_count_fail += 1
        else:
            if not verify_mac_table(dut, data.strm_mac_count, port=v1_port, mac_search='00:12:AA'):
                final_result = False
                mac_count_fail += 1
            if not verify_mac_table(dut, data.strm_mac_count, port=v2_port, mac_search='00:12:DD'):
                final_result = False
                mac_count_fail += 1
            if not verify_mac_table(dut, 1, port=v3_port, mac_search='00:12:BB'):
                final_result = False
                mac_count_fail += 1
    tc_list = ['FtOpSoSwL2FwdFn014']
    print_log("START of TC:test_stp_mac_move ==>Sub-Test:Verify MAC age out after MAC move.\n TCs:<{}>" \
        .format(tc_list), "HIGH")
    ### Configure MAC aging after MAC move and verify MACs age out
    utils.exec_all(True, [[mac_obj.config_mac_agetime, dut, stp_mac_age] for dut in [d1, d2]])
    tc_list = ['FtOpSoSwL2FwdIt005', 'FtOpSoSwL2FwdIt006', 'FtOpSoSwL2FwdFn013','FtOpSoSwL2FwdFn014']
    print_log("START of TC:test_stp_mac_move ==>Sub-Test:Verify MAC re-learn on original ports.\n TCs:<{}>" \
              .format(tc_list), "HIGH")
    ### Revert STP triggers and verify MAC learning on original ports
    utils.exec_foreach(True,[d1,d2],pvst_obj.config_stp_vlan_interface,data.base_trunk_vlan, lagT_po_name, 128, mode='priority')
    utils.exec_foreach(True, [d1, d2], pvst_obj.config_stp_vlan_interface, data.base_trunk_vlan, lagT_po_name, 20000,
                       mode='cost')
    toggle_lag_ports([lagT_po_key], 'enable', 'odd')
    utils.exec_all(True, [[intf_obj.interface_operation, dut, dut_port_dict[dut], 'startup'] for dut in
                          dut_port_dict.keys()])
    print_log("Waiting for {} sec for STP convergence".format(stp_wait_time),'MED')
    st.wait(stp_wait_time)
    ### show STP
    for vlan in vlans:
        utils.exec_all(True, [[pvst_obj.show_stp_vlan, dut, vlan] for dut in [d1, d2]])
    ### Verify MAC learned through new path.
    start_stop_traffic(src_stream_list=data.base_src_streams, dest_stream_list=data.base_dst_streams,duration=traffic_time)
    for dut, v1_port, v2_port, v3_port in zip([d1, d2], [d1_access_port, d2_access_port], [lagA_po_name, lagA_po_name],
                                              [d1_trunk_port, d2_trunk_port]):
        if dut == d1:
            if not verify_mac_table(dut, data.strm_mac_count, port=v1_port, mac_search='00:21:AA'):
                final_result = False
                mac_count_fail += 1
            if not verify_mac_table(dut, data.strm_mac_count, port=v2_port, mac_search='00:21:DD'):
                final_result = False
                mac_count_fail += 1
            if not verify_mac_table(dut, data.strm_mac_count, port=v3_port, mac_search='00:21:BB'):
                final_result = False
                mac_count_fail += 1
        else:
            if not verify_mac_table(dut, data.strm_mac_count, port=v1_port, mac_search='00:12:AA'):
                final_result = False
                mac_count_fail += 1
            if not verify_mac_table(dut, data.strm_mac_count, port=v2_port, mac_search='00:12:DD'):
                final_result = False
                mac_count_fail += 1
            if not verify_mac_table(dut, data.strm_mac_count, port=v3_port, mac_search='00:12:BB'):
                final_result = False
                mac_count_fail += 1

    tc_list = ['FtOpSoSwL2FwdNe002']
    print_log("START of TC:test_stp_mac_move ==>Sub-Test:Create/Break a loop with L2 traffic.\n TCs:<{}>" \
              .format(tc_list), "HIGH")
    ### Create loop in access phyPort vlan and lagA vlan by disabling STP in those vlan instances
    utils.exec_foreach(True, [d1,d2], pvst_obj.config_spanning_tree, mode='disable', vlan=data.base_access_vlan)
    utils.exec_foreach(True, [d1,d2], pvst_obj.config_spanning_tree, mode='disable', vlan=data.base_lagA_vlan)
    st.wait(stp_wait_time)
    #st.wait(5)
    ### -- Clear port counters
    utils.exec_all(True, [[port_obj.clear_interface_counters, dut] for dut in data.my_dut_list])
    ### -- clear MAC
    utils.exec_all(True, [[mac_obj.clear_mac, dut] for dut in [d1, d2]])
    ### Start traffic and Verify flooding
    ## When single direction traffic used to ensure all packets flood, there is a lot of mac events and affecting next TCs MAC table verification
    #start_stop_traffic(src_stream_list=data.base_src_streams, dest_stream_list=data.base_dst_streams,duration=traffic_time, direction='single')
    start_stop_traffic(src_stream_list=data.base_src_streams, dest_stream_list=data.base_dst_streams, duration=traffic_time)
    print_log("test_stp_mac_move:==> Verify flooding in physical ports and LAGs after disbale STP in vlans {} & {}".\
                  format(data.base_access_vlan,data.base_lagA_vlan),'MED')
    #expect_flood_packets = int(data.tgen_rate_pps) * 2 * (traffic_time )
    ## Temp fix
    expect_flood_packets = int(data.tgen_rate_pps) * 1 * (traffic_time)
    print_log("Verify flooding in access link",'MED')
    if not retry_func(verify_flooding_on_dut, dut=d1, portList=[d1_access_port], threshold=expect_flood_packets,
                      delay=3, retry_count=3):
        print_log('FAIL:Traffic flooding , expect_tx_pkt > {} is not seen in Dut:{}, Port:{}'.format(
            expect_flood_packets, d1, d1_access_port), 'ERROR')
        final_result = False
        flooding_fail += 1
    else:
        print_log('PASS:Traffic flooding expect_tx_pkt > {} is seen in Dut:{}, Port:{}'.format(
            expect_flood_packets, d1, d1_access_port), 'MED')
    print_log("Verify flooding in access LAG", 'MED')
    if not retry_func(verify_flooding_on_dut, dut=d2, portList=[lagA_po_name], threshold=expect_flood_packets,
                      delay=3, retry_count=3):
        print_log('FAIL:Traffic flooding, expect_tx_pkt > {} is not seen in Dut:{}, Port:{}'.format(
            expect_flood_packets, d2, lagA_po_name), 'ERROR')
        final_result = False
        flooding_fail += 1
    else:
        print_log('PASS:Traffic flooding expect_tx_pkt > {} is seen in Dut:{}, Port:{}'.format(
            expect_flood_packets, d2, lagA_po_name), 'MED')
    
    print_log("test_stp_mac_move:==> Verify MACs age out after DUT2 trunk port and DUT1 access LAG is shut",'MED')
    ###Shutdown trunk phyPort and lagA
    dut_port_dict = {}
    dut_port_dict[d1] = lagA_po_name
    dut_port_dict[d2] = d2_trunk_port
    utils.exec_all(True, [[intf_obj.interface_operation, dut, dut_port_dict[dut], 'shutdown'] for dut in
                          dut_port_dict.keys()])
    ###Wait for a minute for shut PO to take effect loop traffic to stop then check interface counters-- as per JIRA-19242"
    print_log("Wait for a minute for shut PO to take effect and loop traffic to stop, then check interface counters-- as per JIRA-19242")
    st.wait(60)
    ### -- Clear port counters
    utils.exec_all(True, [[port_obj.clear_interface_counters, dut] for dut in data.my_dut_list])
    loop_break = 1

    print_log("Verify flooding is not seen in access link", 'MED')
    if not retry_func(verify_flooding_on_dut, dut=d1, portList=[d1_access_port], threshold=data.counters_threshold,
                      comp_flag=False, delay=3, retry_count=3):
        print_log('PASS:Traffic flooding is not seen in Dut:{}, Port:{}, expect_tx_pkt < {}'.format(
            d1, d1_access_port,data.counters_threshold), 'MED')
    else:
        print_log('FAIL:Traffic flooding is still seen in Dut:{}, Port:{}, expect_tx_pkt < {}'.format(
            d1, d1_access_port, data.counters_threshold), 'ERROR')
        loop_break = 0
        final_result = False
        flooding_fail += 1

    print_log("Verify flooding is not seen in access LAG", 'MED')
    if not retry_func(verify_flooding_on_dut, dut=d2, portList=[lagA_po_name], threshold=data.counters_threshold,
                      comp_flag=False,delay=3,retry_count=3):
        print_log('PASS:Traffic flooding is not seen in Dut:{}, Port:{}, expect_tx_pkt < {}'.format(
            d2, lagA_po_name, data.counters_threshold), 'MED')
    else:
        print_log('FAIL:Traffic flooding is still seen in Dut:{}, Port:{}, expect_tx_pkt < {}'.format(
            d2, lagA_po_name, data.counters_threshold), 'ERROR')
        loop_break = 0
        final_result = False
        flooding_fail += 1

    if loop_break:
        st.wait(2 * stp_mac_age,"Wait for twice MAC age-time")
        dut_mac_zero_list = [0,0]
        if not verify_mac_table([d1, d2], dut_mac_zero_list, mac_search=data.mac_srch_str):
            final_result = False
            mac_count_fail += 1
        ## With L2 loop created in prev test trigger, ports will be disabled for mac learning for 180 sec.
        ## Next test step has another loop trigger and break with vlan-port unconfig.
        ## If loop seen within 10 sec of a port re-enabled for MAC learning, it will be again disabled for 2*180 sec
        ## To avoid this sleep another 10 sec
        st.wait(20,'Wait for remaining time of 180+10 sec for port to get re-enabled for MAC Learning')
    else:
        st.wait(2 * stp_mac_age + 20, "MAC Dampening: Wait for remaining time of 180+10 sec for port to get re-enabled for MAC Learning")

    ###Enable back the ports and Revert port-vlan assosciation,
    utils.exec_all(True, [[intf_obj.interface_operation, dut, dut_port_dict[dut], 'startup'] for dut in
                          dut_port_dict.keys()])
    ### Start traffic to create traffic loop and modify port-vlan assosciation to see loop is broke.
    start_stop_traffic(src_stream_list=data.base_src_streams, dest_stream_list=data.base_dst_streams,duration=traffic_time)
    ### UnConfigure base_access_vlan from trunk phyPort
    api_list = []
    api_list.append([vlan_obj.delete_vlan_member, d1, data.base_access_vlan, d1_trunk_port, True])
    api_list.append([vlan_obj.delete_vlan_member, d2, data.base_access_vlan, d2_trunk_port, True])
    utils.exec_all(True, api_list)
    stp_deconf_flag += 1
    ### UnConfigure access PO base vlan from trunk PO
    if data.base_lagA_vlan < 255:
        api_list = []
        api_list.append([vlan_obj.delete_vlan_member, d1, data.base_lagA_vlan, lagT_po_name, True])
        api_list.append([vlan_obj.delete_vlan_member, d2, data.base_lagA_vlan, lagT_po_name, True])
        utils.exec_all(True, api_list)
        stp_deconf_flag += 1
    ###Introduce delay before next MAC verification as per SONIC-13217
    ##  This is to make sure MAC move events generated in loop scenario is settled
    mac_dampening_timer = 180
    st.wait(mac_dampening_timer,"MAC Dampening: Wait for {} seconds for MAC learning to get re-enabled".format(mac_dampening_timer))

    utils.exec_all(True, [[mac_obj.clear_mac, dut] for dut in [d1, d2]])
    utils.exec_all(True, [[mac_obj.get_mac, dut] for dut in [d1, d2]])

    print_log("test_stp_mac_move:==> Verify no flooding after DUT2 trunk port and DUT1 access LAG is enabled and loop in vlan {} & {} removed". \
              format(data.base_access_vlan, data.base_lagA_vlan), 'MED')
    ###Verify no flooding with traffic and MAC table
    if not run_verify_traffic(src_stream_list=data.base_src_streams,dest_stream_list=data.base_dst_streams):
        final_result = False
        traffic_forward_fail += 1

    for dut, v1_port, v2_port, v3_port, v4_port in zip([d1, d2], [d1_access_port, d2_access_port], [lagA_po_name, lagA_po_name],
                                              [d1_trunk_port, d2_trunk_port], [lagT_po_name,lagT_po_name]):
        if dut == d1:
            if not verify_mac_table(dut, data.strm_mac_count, port=v1_port, mac_search='00:21:AA'):
                final_result = False
                mac_count_fail += 1
            if not verify_mac_table(dut, data.strm_mac_count, port=v2_port, mac_search='00:21:DD'):
                final_result = False
                mac_count_fail += 1
            if not verify_mac_table(dut, data.strm_mac_count, port=v3_port, mac_search='00:21:BB'):
                final_result = False
                mac_count_fail += 1
            if not verify_mac_table(dut, data.strm_mac_count, port=v4_port, mac_search='00:21:CC'):
                final_result = False
                mac_count_fail += 1
        else:
            if not verify_mac_table(dut, data.strm_mac_count, port=v1_port, mac_search='00:12:AA'):
                final_result = False
                mac_count_fail += 1
            if not verify_mac_table(dut, data.strm_mac_count, port=v2_port, mac_search='00:12:DD'):
                final_result = False
                mac_count_fail += 1
            if not verify_mac_table(dut, data.strm_mac_count, port=v3_port, mac_search='00:12:BB'):
                final_result = False
                mac_count_fail += 1
            if not verify_mac_table(dut, data.strm_mac_count, port=v4_port, mac_search='00:12:CC'):
                final_result = False
                mac_count_fail += 1

    if final_result:
        st.report_pass("test_case_passed")
    else:
        fail_msg =''
        if mac_count_fail > 0:
            fail_msg +='MAC Verification Failed:'
        if traffic_forward_fail > 0:
            fail_msg +='Traffic Forwarding Failed:'
        if mac_aging_fail > 0:
            fail_msg += 'MAC aging Failed:'
        if flooding_fail > 0:
            fail_msg += 'Flooding Verification Failed:'
        st.report_fail("test_case_failure_message", fail_msg.strip(':'))
        #st.report_fail("operation_failed")


def test_FtOpSoSwL2FwdFnCeta31752(lag_function_fixture):
    final_result = True
    cli_type = st.get_ui_type(data.my_dut_list[0])
    if cli_type != "klish":
        st.report_unsupported("test_case_unsupported", "testcase supported for klish only")
    print_log("START of TC ==> test_FtOpSoSwL2FwdFnCeta31752", "HIGH")
    utils.exec_all(True, [[mac_obj.clear_mac, dut] for dut in data.my_dut_list])
    rate_pkts="1000000"
    for st_key, stdata in data.stream_data.items():
        if st_key == "CC":
            tg_ph11 = stdata['tg_port_handles'][0]
            tg_ph21 = stdata['tg_port_handles'][1]
            stream1 = tg_h.tg_traffic_config(mode='create', port_handle=tg_ph11, rate_pps=rate_pkts,
                                             mac_src=stdata['src_mac'], mac_src_mode="increment",
                                             mac_src_count=stdata['mac_count'], transmit_mode="continuous",
                                             mac_src_step="00:00:00:00:00:01", mac_dst=stdata['dst_mac'],
                                             mac_dst_mode="increment",mac_dst_count=stdata['mac_count'],
                                             mac_dst_step="00:00:00:00:00:01",l2_encap='ethernet_ii_vlan',
                                             vlan_id=stdata['vlan'], vlan_id_count=stdata['vlan_count'], vlan="enable",
                                             vlan_id_mode="increment",vlan_id_step='1', port_handle2=tg_ph21)
            stream2 = tg_h.tg_traffic_config(mode='create', port_handle=tg_ph21, rate_pps=rate_pkts,
                                             mac_src=stdata['dst_mac'], mac_src_mode="increment",
                                             mac_src_count=stdata['mac_count'], transmit_mode="continuous",
                                             mac_src_step="00:00:00:00:00:01", mac_dst=stdata['src_mac'],
                                             mac_dst_mode="increment",mac_dst_count=stdata['mac_count'],
                                             mac_dst_step="00:00:00:00:00:01",l2_encap='ethernet_ii_vlan',
                                             vlan_id=stdata['vlan'], vlan_id_count=stdata['vlan_count'], vlan="enable",
                                             vlan_id_mode="increment", vlan_id_step='1', port_handle2=tg_ph11)
            tg_h.tg_traffic_control(action='run',
                            handle=[stream1["stream_id"], stream2["stream_id"]])
    st.wait(20)
    per_stream_pkts = int(rate_pkts) * 5 / data.lagT_vlan_count
    [result,exceptions] = utils.exec_all(True, [[verify_lag_loadbalancing, dut,
                                                 data.po_metadata[(dut, 'trunk')]['base_id'],per_stream_pkts]
                                                for dut in data.my_dut_list[:-1]])
    if not all(i is None for i in exceptions):
        print_log(exceptions)
    if False in result:
        print_log('FAIL: Traffic on LAG members is NOT load balanced.', 'ERROR')
        final_result = False
    else :
        print_log('PASS: Traffic on LAG members is load balanced.', 'MED')
    tx_rate = Evpn.get_port_counters(data.my_dut_list[0], vars.D1T1P2, "rx_pps")
    tx_rate = int(tx_rate[0]['rx_pps'].split(".")[0])
    st.log("########## DUT1, RX_PPS value is : {} ##########".format(tx_rate))
    po_key_t = data.po_metadata[(data.my_dut_list[0], 'trunk')]['base_id']
    mem1_rx = Evpn.get_port_counters(data.my_dut_list[1], data.portchannel[po_key_t]["dut2_members"][0], "rx_pps")
    mem1_rx = int(mem1_rx[0]['rx_pps'].split(".")[0])
    st.log("########## DUT2, RX_PPS value for LAG member port1 is : {} ##########".format(mem1_rx))
    mem2_rx = Evpn.get_port_counters(data.my_dut_list[1], data.portchannel[po_key_t]["dut2_members"][1], "rx_pps")
    mem2_rx = int(mem2_rx[0]['rx_pps'].split(".")[0])
    st.log("########## DUT2, RX_PPS value for LAG member port2 is : {} ##########".format(mem2_rx))
    total_rx = mem1_rx + mem2_rx
    st.log("########## DUT2, SUM of RX_PPS for both member port is: {} ##########".format(total_rx))
    min_rx = tx_rate - 100
    max_rx = tx_rate + 30
    if min_rx <= total_rx and max_rx >= total_rx:
        st.log('PASS: LAG members RX PPS {} is in the range b/w {} and '
               '{}'.format(total_rx,min_rx,max_rx))
    else:
        st.error("FAIL: LAG members RX PPS {} is NOT in the range b/w {} and "
                 "{}".format(total_rx,min_rx,max_rx))
        final_result= False
    tg_h.tg_traffic_control(action='stop',
                            handle=[stream1["stream_id"], stream2["stream_id"]])
    if final_result:
        st.report_pass("test_case_id_passed", "test_FtOpSoSwL2FwdFnCeta31752")
    else:
        st.report_fail("test_case_id_failed", "test_FtOpSoSwL2FwdFnCeta31752")


@pytest.mark.l2fwd_reload
@pytest.mark.l2fwd_ip
def test_l2fwd_config_reload():
    final_result = True
    mac_count_fail = 0
    traffic_forward_fail = 0
    flooding_fail = 0
    mac_aging_fail = 0
    interface_fail = 0
    tc_list = ['FtOpSoSwL2FwdPe001']
    print_log("START of TC ==> test_l2fwd_config_reload\n TCs:<{}>".format(tc_list), "HIGH")
    boot_obj.config_save_reload(data.my_dut_list)
    ### Add delay to avoid port Flap happening after reboot - Jira:21256
    # Delay removed as 21256 is reopened for fix
    #st.wait(5)
    [results, exceptions] = utils.exec_foreach(True, data.my_dut_list, port_obj.get_interfaces_all)
    if not all(i is None for i in exceptions):
        print_log(exceptions)
    if any(port is None for port in results):
        final_result = False
        interface_fail += 1
    #utils.exec_all(True, [[mac_obj.clear_mac, dut] for dut in data.ver_dut_list])
    if not run_verify_traffic(src_stream_list=data.base_src_streams,dest_stream_list=data.base_dst_streams):
        final_result = False
        traffic_forward_fail += 1
    if not verify_mac_table(data.ver_dut_list, data.dut_mac_count_list,mac_search=data.mac_srch_str):
        final_result = False
        mac_count_fail += 1

    utils.exec_foreach(True,data.my_dut_list,st.reboot,"fast")
    ### Add delay to avoid port Flap happening after reboot - Jira:21256
    # Delay removed as 21256 is reopened for fix
    # #st.wait(5)
    [results, exceptions] = utils.exec_foreach(True, data.my_dut_list, port_obj.get_interfaces_all)
    if not all(i is None for i in exceptions):
        print_log(exceptions)
    if any(port is None for port in results):
        final_result = False
        interface_fail += 1
    if not run_verify_traffic(src_stream_list=data.base_src_streams,dest_stream_list=data.base_dst_streams):
        final_result = False
        traffic_forward_fail += 1
    if not verify_mac_table(data.ver_dut_list, data.dut_mac_count_list,mac_search=data.mac_srch_str):
        final_result = False
        mac_count_fail += 1

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
        if interface_fail > 0:
            fail_msg += 'Interface not UP after fast-reboot:'
        st.report_fail("test_case_failure_message", fail_msg.strip(':'))

