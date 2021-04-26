####################################################
# This file contains the STP elasticity logic with wrapper API's
# Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
####################################################
import copy
import random

from spytest import st, tgapi
from spytest.utils import exec_all

import apis.switching.vlan as vlan
import apis.switching.portchannel as portchannel
import apis.switching.pvst as stp

import utilities.utils as utils

tg_info = {}
minimum_duts = 3
min_duts_tg_links = 3
min_links_between_duts = 3
complete_data = dict()
min_tg_links = 1
max_members_in_portchannel = 8
root_bridge_priority = 0
src_tg1_vlan_inc_mac_fix_unknown = "00:80:00:00:00:01"
exclude_list_for_complete_data = ["vlan_data", "portchannel", "dut_partner_list", "states", "dut_vlan_data", "tg_info"]
skip_tg = False
stp_dict = {"pvst": {"stp_wait_time": 40, "non_fwd_state": "BLOCKING"}, "rpvst": {"stp_wait_time": 6, "non_fwd_state": "DISCARDING"}}

def get_dut_list(vars):
    """
    API to get the list of DUT's from vars
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param vars:
    :return:
    """
    if vars and "dut_list" in vars:
        return vars.dut_list
    return []

def apply_and_verify_module_config(vars, stp_protocol):
    """
    API to apply the module config and verifying the configuration.
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param vars:
    :return:
    """
    st.log("Getting list of dut's")
    dut_list = get_dut_list(vars)
    st.log("LIST OF DUT's IDENTIFIED {}".format(dut_list))
    st.log("dut_list: {}".format(dut_list))
    dut_partner_list = get_dut_partner_data(dut_list)
    st.log("DUT PARTNER LIST IS {}".format(dut_partner_list))
    min_link_result = False
    min_tg_link_count = 0
    stp_wait_time = stp_dict[stp_protocol]["stp_wait_time"]
    st.log("Clearing existing VLAN, PORTCHANNEL configuration...")
    vlan.clear_vlan_configuration(dut_list)
    portchannel.clear_portchannel_configuration(dut_list)
    if not dut_list:
        st.log("DUT List is empty ....")
        st.report_env_fail("dut_not_found")
    if len(dut_list) < minimum_duts:
        st.log("Topology not meeting the requirement ..")
        st.report_env_fail("topology_not_matching", minimum_duts, len(dut_list))
    st.log("Getting random vlan's to the number equals to DUT number ...")
    vlan_list = utils.get_random_vlans_in_sequence(len(dut_list))
    st.log("GENERATED VLAN LIST {}".format(vlan_list))
    complete_data["dut_partner_list"] = dut_partner_list
    complete_data["vlan_data"] = dict()
    complete_data["vlan_data"]["vlan_list"] = vlan_list
    dut_vlan_data = dict()
    for index, dut in enumerate(dut_list):
        st.log("Fetching partner DUT's and links for {}".format(dut))
        dut_links_data = st.get_dut_links(dut)
        st.log("Getting dut links information is completed")
        st.log("dut links data : {}" . format(dut_links_data))
        complete_data[dut] = dict()
        complete_data[dut]["partners"] = dict()
        complete_data[dut]["vlan_id"] = vlan_list[index]
        dut_vlan_data[dut] = vlan_list[index]

        st.log("start of verification  of topology meeting requirement or not")

        if len(dut_links_data) > 0:
            for link_data in dut_links_data:
                if link_data[1] not in complete_data[dut]["partners"]:
                    link_details = st.get_dut_links(dut, link_data[1])
                    complete_data[dut]["partners"][link_data[1]] = link_details
        else:
            st.log("Topology not meeting the requirement ..")
            st.report_env_fail("links_not_matching", dut, min_links_between_duts)

        st.log("End of verification  of topology meeting requirement or not")

        utils.banner_log("Verifying minimum TG links {} on {}".format(min_tg_links, dut))
        tg_links = st.get_tg_links(dut)
        st.log("TG LINKS FOR {} are {}".format(dut, tg_links))
        complete_data["vlan_data"][dut] = list()

        if len(tg_links) > min_tg_links:
            min_tg_link_count += 1
            complete_data[dut]["tg_links"] = tg_links
            for tg_link in tg_links:
                complete_data["vlan_data"][dut].append(tg_link[0])
        else:
            complete_data[dut]["tg_links"] = list()
    st.log("no of tglinks  on this dut : {}" . format(min_tg_link_count))
    if min_tg_link_count < min_duts_tg_links:
        st.log("Mismatch in minimum TG links requirement")
        st.report_env_fail("mismatch_minimun_tg_links", min_tg_links, len(tg_links), "dut")
    else:
        st.log("Min tglink requirement is met")
    complete_data["dut_vlan_data"] = dict()
    complete_data["dut_vlan_data"] = dut_vlan_data
    st.log("###################### PREPARING DATA #######################")
    st.log(complete_data)
    if complete_data:
        for key, value in complete_data.items():
            if key not in exclude_list_for_complete_data:
                if "partners" in value:
                    for dut, links in value["partners"].items():
                        if len(links) >= min_links_between_duts:
                            min_link_result = True
                            st.log("Observed links between DUTs as {}".format(len(links)))
                            break
                else:
                    st.log("Partner data not found ..")
                    st.report_fail("no_data_found")
            if min_link_result:
                break
        utils.banner_log("Verifying minimum links {} between DUTs".format(min_links_between_duts))
        if not min_link_result:
            st.log("Minimum links of {} not found between DUTs".format(min_links_between_duts))
            st.report_env_fail("minimum_links_not_matching", min_links_between_duts)
        st.log("Creating VLAN's {} on all DUT's {} ...".format(vlan_list, dut_list))
        config_all_vlan_in_all_duts(dut_list, vlan_list)
        st.log("Displaying created VLAN's on all the DUT's ")
        utils.banner_log("Creating portchannel on the devices met the port channel link requirement ...")
        portchannel_count = 1
        complete_data["portchannel"] = dict()
        for dut_partner in complete_data["dut_partner_list"]:
            portchannel_name = "PortChannel{}".format(portchannel_count)
            device = dut_partner[0]
            partner = dut_partner[1]
            dut_partner_links = st.get_dut_links(device, partner)
            if dut_partner_links:
                complete_data["vlan_data"][device].append(dut_partner_links[0][0])
                complete_data["vlan_data"][partner].append(dut_partner_links[0][2])
                st.log("Creating and adding portchannels and members based on port count ...")
                if len(dut_partner_links) >= 2 and len(dut_partner_links) <= max_members_in_portchannel + 1:
                    if portchannel_name not in complete_data["portchannel"]:
                        complete_data["portchannel"][portchannel_name] = dict()
                    complete_data["portchannel"][portchannel_name]["partners"] = dut_partner
                    if portchannel_name not in complete_data["vlan_data"][device]:
                        complete_data["vlan_data"][device].append(portchannel_name)
                    local_members = list()
                    remote_members = list()
                    if portchannel_name not in complete_data["vlan_data"][device]:
                        complete_data["vlan_data"][device].append(portchannel_name)
                    if portchannel_name not in complete_data["vlan_data"][partner]:
                        complete_data["vlan_data"][partner].append(portchannel_name)
                    for index, link in enumerate(dut_partner_links):
                        if index != 0:
                            local_members.append(link[0])
                            remote_members.append(link[2])
                    complete_data["portchannel"][portchannel_name][device] = local_members
                    complete_data["portchannel"][portchannel_name][partner] = remote_members
                    portchannel.config_portchannel(device, partner, portchannel_name,
                                                       local_members, remote_members, thread=True)
                    portchannel_count += 1
        st.log("Displaying created portchannels on all duts ...")
        show_portchannel_on_duts(dut_list)
        config_vlan_members_to_device(complete_data["vlan_data"])
        show_vlan_breif_on_all_duts(dut_list)
        stp.config_stp_in_parallel(dut_list, feature=stp_protocol, mode="enable")
        stp.show_stp_in_parallel(dut_list)
        priority = get_priority_list_to_configure(dut_list, root_bridge_priority)
        stp.config_stp_vlan_parameters_parallel(dut_list, vlan=vlan_list,
                                                     priority=priority)
        device_data = get_dut_to_tg_links()
        tg_info = config_tg_streams(vars, device_data, vlan_list)
        utils.banner_log(tg_info)
        complete_data["tg_info"] = dict()
        if tg_info:
            complete_data["tg_info"] = tg_info
        st.wait(stp_wait_time)
        stp.check_for_single_root_bridge_per_vlan(dut_list, vlan_list, dut_vlan_data)
        vlan_data = copy.deepcopy(complete_data["vlan_data"])
        vlan_data.pop("vlan_list", None)
        if not stp.poll_root_bridge_interfaces(dut_vlan_data, vlan_data):
            st.log("Root bridge interface state verification failed.")
            st.report_fail("root_bridge_interface_verification_failed")
        complete_data["states"] = dict()
        for dut, vlan_id in dut_vlan_data.items():
            if vlan_id not in complete_data["states"]:
                complete_data["states"][vlan_id] = dict()
            complete_data["states"][vlan_id]["root"] = dut
            complete_data["states"][vlan_id]["non_root"] = dict()
            get_non_root_list_based_on_mac_address(dut_list, dut, vlan_id, complete_data, stp_protocol)
    else:
        st.log("Data not found ...")
        st.report_fail("no_data_found")
    return complete_data

def config_all_vlan_in_all_duts(dut_list, vlan_list, thread=True, action="add"):
    dut_li = list([str(e) for e in dut_list]) if isinstance(dut_list, list) else [dut_list]
    vlan_li = list([str(e) for e in vlan_list]) if isinstance(vlan_list, list) else [vlan_list]
    params = list()
    for dut in dut_li:
        if action == "add":
            params.append([vlan.create_vlan, dut, vlan_li])
        if action == "del":
            params.append([vlan.delete_vlan, dut, vlan_li])
    if params:
        exec_all(thread, params)

def show_vlan_breif_on_all_duts(dut_list, thread=True):
    st.log("Dispalying all the created VLAN's ....")
    dut_li = list([str(e) for e in dut_list]) if isinstance(dut_list, list) else [dut_list]
    params = list()
    for dut in dut_li:
        params.append([vlan.show_vlan_brief, dut])
    if params:
        exec_all(thread, params)

def show_portchannel_on_duts(dut_list, thread=True):
    dut_li = list([str(e) for e in dut_list]) if isinstance(dut_list, list) else [dut_list]
    params = list()
    for dut in dut_li:
        params.append([portchannel.get_portchannel_list, dut])
    if params:
        exec_all(thread, params)

def get_dut_partner_data(dut_list):
    st.log("Getting list of partner dut's combinations ...")
    result = list()
    if dut_list:
        for i, each in enumerate(dut_list):
            for j in dut_list[i + 1:]:
                result.append([each, j])
    return result

def config_vlan_members_to_device(vlan_data, thread=True):
    utils.banner_log("Creating VLAN members in all the DUT's")
    params = list()
    if vlan_data:
        for index, members in vlan_data.items():
            vlan_list = vlan_data["vlan_list"]
            if index != "vlan_list":
                params.append([vlan.config_vlan_members, index, vlan_list, members])
        exec_all(thread, params)
        return True
    st.log("Invalid data provided....")
    return False

def get_priority_list_to_configure(dut_list, priority):
    """
    API to get the list of prioirities to be configured as per the DUT list
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut_list:
    :param priority:
    :return:
    """
    st.log("Getting the list of priorities to configure on DUT's ...")
    return [priority] * len(dut_list)

def get_non_root_list_based_on_mac_address(new_dut_list, root_dut, vlan, complete_data, stp_protocol):
    """
    API to get non root bridge details
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param new_dut_list:
    :param root_dut:
    :param vlan:
    :param complete_data:
    :return:
    """
    if new_dut_list:
        st.log("COMPLETE DUT LIST to find NON ROOT BRIDGE : {}".format(new_dut_list))
        st.log("ROOT BRIDGE {} is for VLAN ID {}".format(root_dut, vlan))
        dut_list_copy = copy.deepcopy(new_dut_list)
        dut_list_copy.remove(root_dut)
        dut_with_blocking_links = dict()
        utils.banner_log("######## NON ROOT DUT LIST ########")
        utils.banner_log(dut_list_copy)
        for dut in dut_list_copy:
            stp_data_init = stp.show_stp_vlan(dut, vlan)
            blocking_cnt = 0
            for data_init in stp_data_init:
                if data_init["port_state"] == stp_dict[stp_protocol]["non_fwd_state"]:
                    blocking_cnt += 1
                    break
            dut_with_blocking_links[dut] = blocking_cnt
        dut_list = list()
        for dut, block_lnk in dut_with_blocking_links.items():
            if block_lnk != 0:
                dut_list.append(dut)
        st.log("DUTs WITH {} LINKS - {}".format(stp_dict[stp_protocol]["non_fwd_state"], dut_list))
        if not dut_list:
            st.log("No blocking interfaces found on any of the devices {} ".format(dut_with_blocking_links))
            st.report_fail("no_blocking_interfaces_found_on_any", dut_with_blocking_links)
        dut_mac_addr = stp.get_duts_mac_address(dut_list)
        if dut_mac_addr:
            st.log("DUT MAC ADDRS: {}".format(dut_mac_addr))
            mac_address = dut_mac_addr.values()
            st.log("MAC_ADDRESSES: {}".format(mac_address))
            complete_data["states"][vlan]["non_root"]["highest_mac"] = dict()
            complete_data["states"][vlan]["non_root"]["other"] = list()
            for dut, mac in dut_mac_addr.items():
                utils.banner_log("HIGHEST MAC ADDRESS VERIFICATION....")
                utils.banner_log("DUT - {}".format(dut))
                utils.banner_log("MAC - {}".format(mac))
                utils.banner_log("MAX MAC - {}".format(max(mac_address)))
                other_dut = dict()
                if mac == max(mac_address):
                    st.log("{} DUT is with highest MAC address {} for vlan {}".format(dut, mac, vlan))
                    complete_data["states"][vlan]["non_root"]["highest_mac"]["name"] = dut
                    st.log("HIGHEST MAC DUT - {}".format(complete_data["states"][vlan]["non_root"]["highest_mac"]))
                else:
                    other_dut["name"] = dut
                    st.log("OTHER MAC DUT - {}".format(other_dut))
                stp_data = stp.show_stp_vlan(dut, vlan)
                if not stp_data:
                    iteration = 5
                    for i in range(1, iteration + 1):
                        st.wait(2)
                        stp_data = stp.show_stp_vlan(dut, vlan)
                        if stp_data:
                            break
                        if not stp_data and i >= iteration + 1:
                            st.log("STP output not found on {} for {} instance".format(dut, vlan))
                            st.report_fail("stp_output_not_found", dut, vlan)
                if stp_data:
                    blocking_interfaces = list()
                    forwarding_interfaces = list()
                    total_interfaces = dict()
                    stp_interfaces = list()
                    for data in stp_data:
                        total_interfaces[data["port_name"]] = data["port_state"]
                        stp_interfaces.append(data["port_name"])
                        if data["port_state"] == stp_dict[stp_protocol]["non_fwd_state"]:
                            blocking_interfaces.append(data["port_name"])
                        if data["port_state"] == "FORWARDING":
                            forwarding_interfaces.append(data["port_name"])
                    if "name" in complete_data["states"][vlan]["non_root"]["highest_mac"] \
                            and "blocking_links" not in complete_data["states"][vlan]["non_root"]["highest_mac"]:
                        complete_data["states"][vlan]["non_root"]["highest_mac"]["blocking_links"] = blocking_interfaces
                        st.log("{} LINKS ON HIGHEST MAC DUT {} -- {}".format(stp_dict[stp_protocol]["non_fwd_state"], dut, blocking_interfaces))
                    else:
                        other_dut["blocking_links"] = blocking_interfaces
                        st.log("{} LINKS ON OTHER DUT {} -- {}".format(stp_dict[stp_protocol]["non_fwd_state"], dut, blocking_interfaces))
                    if forwarding_interfaces:
                        tg_links = list()
                        if "tg_links" in complete_data[dut]:
                            tg_data = complete_data[dut]["tg_links"]
                            for tg_link in tg_data:
                                tg_links.append(tg_link[0])
                        if "name" in complete_data["states"][vlan]["non_root"]["highest_mac"] \
                                and "forwarding_links" not in complete_data["states"][vlan]["non_root"]["highest_mac"]:
                            forwarding_on_highest_mac = utils.list_diff(forwarding_interfaces, tg_links)
                            complete_data["states"][vlan]["non_root"]["highest_mac"]["forwarding_links"] \
                                = forwarding_on_highest_mac
                            st.log("FORWARDING LINKS ON HIGHEST MAC DUT {} -- {}".format(dut, forwarding_on_highest_mac))
                        else:
                            other_dut["forwarding_links"] = utils.list_diff(forwarding_interfaces, tg_links)
                            st.log("FORWARDING LINKS ON OTHER DUT {} -- {}".format(dut, other_dut["forwarding_links"]))
                    st.log("HIGHEST MAC DATA for DUT {} -- {}".format(dut, complete_data["states"][vlan]["non_root"]["highest_mac"]))
                    st.log("OTHER DUT DATA for DUT {} -- {}".format(dut, other_dut))
                    if other_dut:
                        complete_data["states"][vlan]["non_root"]["other"].append(other_dut)
            if not complete_data["states"][vlan]["non_root"]["highest_mac"]:
                st.log("Highest MAC Address DUT not found in the given VLAN {} with DUT MAC ADDRS {}".format(vlan, dut_mac_addr))
                st.report_fail("highest_mac_address_not_found")
            if len(complete_data["states"][vlan]["non_root"]["other"]) == 0:
                st.log("OTHER NON ROOT DUT data not found in the given VLAN {} with DUT MAC ADDRS {}".format(vlan,
                                                                                                             dut_mac_addr))
                st.report_fail("other_non_root_dut_data_not_found")
        else:
            st.log("DUT MAC ADDERSS DATA NOT FOUND ..")
            st.report_fail("dut_mac_address_not_found")

#########################################################################
#                WRAPPER FUNCTION FOR TEST CASES                        #
#       AUTHOR: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)    #
#########################################################################
def get_dut_vlan_mapping():
    """
    API to get the DUT and VLAN mapping, this gives ROOT DUT in VLAN data
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :return:
    """
    dut_vlan_mapping = dict()
    if complete_data:
        for key, value in complete_data.items():
            if key not in exclude_list_for_complete_data:
                dut_vlan_mapping[key] = value["vlan_id"]
    return dut_vlan_mapping

def get_portchannel_details():
    """
    API to get the portchannel details
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :return: {'PortChannel3': {'partners': ['as5712-03', 'as5712-04'], 'as5712-04':
    ['Ethernet1', 'Ethernet2', 'Ethernet3'], 'as5712-03': ['Ethernet1', 'Ethernet2', 'Ethernet3']}}
    """
    result = dict()
    if complete_data:
        if "portchannel" in complete_data:
            portchannel_name = random.sample(complete_data["portchannel"].keys(), k=1)
            result[portchannel_name[0]] = complete_data["portchannel"][portchannel_name[0]]
    return result

def get_root_brigde_details_by_vlan(vlan_id):
    """
    API to get root bridge details in VLAN
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param vlan_id:
    :return:
    """
    result = dict()
    if complete_data:
        root_bridge = complete_data["states"][vlan_id]["root"]
        root_bridge_ports = complete_data["vlan_data"][root_bridge]
        result[root_bridge] = root_bridge_ports
    return result

def get_dut_connected_tg_ports():
    """
    API to get the dut connected tg ports
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :return:
    """
    dut_tg_mapping = dict()
    if complete_data:
        for key, value in complete_data.items():
            if key not in exclude_list_for_complete_data:
                if "tg_links" in value and complete_data[key]["tg_links"]:
                    dut_tg_mapping[key] = dict()
                    dut_tg_mapping[key]["local_links"] = list()
                    dut_tg_mapping[key]["tg_links"] = list()
                    for data in complete_data[key]["tg_links"]:
                        dut_tg_mapping[key]["local_links"].append(data[0])
                        dut_tg_mapping[key]["tg_links"].append(data[2])
    return dut_tg_mapping

def get_dut_to_tg_links(no_of_duts=3, no_of_links=1):
    """
    API to get the dut connected tg ports
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param no_of_duts:
    :param no_of_links:
    :return: {'as7816-01': ['6/26'], 'as5712-04': ['6/31'], 'as5712-03': ['6/30']}
    """
    result = dict()
    dut_tg_mapping = get_dut_connected_tg_ports()
    if dut_tg_mapping:
        dut_list = random.sample(dut_tg_mapping.keys(), k=no_of_duts)
        for dut in dut_list:
            tg_link = random.sample(dut_tg_mapping[dut]["tg_links"], k=no_of_links)
            result[dut] = tg_link
    return result

def get_random_dut_tg_interface(no_of_duts=3, no_of_links=1):
    """
    API to get random DUT to TG interfaces
    :param no_of_duts:
    :param no_of_links:
    :return:
    """
    result=dict()
    dut_tg_port = get_dut_to_tg_links(no_of_duts, no_of_links)
    if dut_tg_port:
        random_dut = random.choice(list(dut_tg_port))
        if random_dut in complete_data:
            if "tg_links" in complete_data[random_dut]:
                for interface, dut, tg_link in complete_data[random_dut]["tg_links"]:
                    st.log("Interface: {}, dut: {}, tg_link:{}".format(interface, dut, tg_link))
                    if tg_link == dut_tg_port[random_dut][0]:
                        result["dut"] = random_dut
                        result["physical_link"] = interface
                        result["tg_link"] = tg_link
                        break
    return result

def get_dut_neighbors(dut):
    """
    API to get the list of provided DUT neighbors
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :return:
    """
    result = dict()
    if complete_data:
        if "dut_partner_list" in complete_data and complete_data["dut_partner_list"]:
            result[dut] = list()
            for dut_data in complete_data["dut_partner_list"]:
                if dut in dut_data:
                    index = dut_data.index(dut)
                    if index == 0:
                        result[dut].append(dut_data[1])
                    else:
                        result[dut].append(dut_data[0])
    return result

def get_dut_neighbors_with_required_links(dut, min_link=2, nodes=1):
    """
    API to get the dut and its neighbors with min links
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param min_link:
    :param nodes:
    :return:
    """
    result = list()
    dut_data = get_dut_neighbors(dut)
    if dut_data:
        for device, neighbor in dut_data.items():
            for neigh_dut in neighbor:
                links = st.get_dut_links(device, neigh_dut)
                if len(links) >= min_link:
                    result.append(neigh_dut)
    return random.sample(result, k=nodes)

def get_dut_links_remote(dut, remote_dut, local_interface):
    """
    API to get remote port using dut, remote dut and local interface
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param remote_dut:
    :param local_interface:
    :return:
    """
    if "PortChannel" in local_interface:
        dut_partner = complete_data["portchannel"][local_interface]["partners"]
        if dut in dut_partner and remote_dut in dut_partner:
            return local_interface
        else:
            return None
    else:
        partner_links = st.get_dut_links(dut, remote_dut)
        for local, partner, remote in partner_links:
            if local == local_interface:
                st.log("Found local interface {} for remote intf {} on partner dut {}".format(local, remote, partner))
                return remote

def get_physical_link_with_partner(dut):
    """
    API to get the physical link details of a DUT and its partner,
    :param dut:
    :return:
    """
    result = dict()
    if complete_data:
        if "partners" in complete_data[dut]:
            response = list()
            for partner, value in complete_data[dut]["partners"].items():
                data = dict()
                if len(value) > 0:
                    data["partner"] = partner
                    data["local"] = value[0][0]
                    data["remote"] = value[0][2]
                if data:
                    response.append(data)
            result[dut] = response
    return result

def get_highest_mac_non_root_details(vlan_id):
    result = dict()
    if complete_data:
        if vlan_id in complete_data["states"]:
            if "highest_mac" in complete_data["states"][vlan_id]["non_root"]:
                highest_mac_details = complete_data["states"][vlan_id]["non_root"]["highest_mac"]
                result[highest_mac_details["name"]] = dict()
                result[highest_mac_details["name"]]["forwarding_links"] = highest_mac_details["forwarding_links"]
                result[highest_mac_details["name"]]["blocking_links"] = highest_mac_details["blocking_links"]
    return result

def get_dut_partner_details_by_dut_interface(dut, interface):
    """
    API to fetch the DUT and partner links by DUT and interface
    :param dut:
    :param interface:
    :return: {'as7816-01': ['Ethernet16', 'PortChannel1'], 'as5712-03': ['Ethernet40', 'PortChannel1']}
    """
    result = dict()
    response = dict()
    st.log("DUT -- {}".format(dut))
    st.log("INTERFACE -- {}".format(interface))
    if complete_data:
        for key, value in complete_data.items():
            if key == dut:
                result[key] = dict()
                result[key]["local"] = list()
                result[key]["remote"] = list()
                if "partners" in value:
                    for partner, links in value["partners"].items():
                        if links:
                            st.log("LINKS -- {}".format(links))
                            for link in links:
                                st.log("LINK DATA -- {}".format(link))
                                if "PortChannel" not in interface:
                                    if link and interface == link[0]:
                                        result[key]["partner"] = partner
                                else:
                                    if "portchannel" in complete_data:
                                        for pc, data in complete_data["portchannel"].items():
                                            if interface == pc:
                                                for index in data:
                                                    if index not in [dut, "partners"]:
                                                        result[key]["partner"] = index
                            if "partner" in result[key]:
                                st.log("DUT PARTNER DATA -- {}".format(result))
                                break
        if result:
            dut_portchannel_interfaces = get_portchannel_interfaces(dut, result[dut]["partner"])
            st.log("DUT PORT CHANNEL INTERFACES -- {}".format(dut_portchannel_interfaces))
            dut_partner_interfaces = get_dut_partner_interfaces(dut, result[dut]["partner"])
            st.log("DUT PARTNER INTERFACES -- {}".format(dut_partner_interfaces))
            local_device = dut
            for local_dut, interfaces in dut_partner_interfaces.items():
                if local_dut == dut:
                    if dut_portchannel_interfaces:
                        if all(elem in interfaces for elem in dut_portchannel_interfaces[local_dut]):
                            diff_list = set(interfaces) - set(dut_portchannel_interfaces[local_dut])
                        if local_dut in result:
                            result[local_dut]["local"].append(dut_portchannel_interfaces["portchannel"])
                    else:
                        diff_list = interfaces
                    for intf in diff_list:
                        if local_dut in result:
                            result[local_dut]["local"].append(intf)
                elif local_dut == result[dut]["partner"]:
                    if dut_portchannel_interfaces:
                        if all(elem in interfaces for elem in dut_portchannel_interfaces[local_dut]):
                            diff_list = set(interfaces) - set(dut_portchannel_interfaces[local_dut])
                        if local_device in result:
                            result[local_device]["remote"].append(dut_portchannel_interfaces["portchannel"])
                    else:
                        diff_list = interfaces
                    for intf in diff_list:
                        if local_device in result:
                            result[local_device]["remote"].append(intf)
            st.log("RESULT -- {}".format(result))
            for key,value in result.items():
                response[key] = value["local"]
                response[value["partner"]] = value["remote"]
    return response

def get_portchannel_interfaces(dut, partner):
    """
    API to get port channel interfaces between the device
    :param dut:
    :param partner:
    :return: {'as7816-01': ['Ethernet17', 'Ethernet18', 'Ethernet19'],
    'as5712-03': ['Ethernet41', 'Ethernet42', 'Ethernet43'], 'portchannel': 'PortChannel1'}
    """
    result = dict()
    if complete_data:
        if "portchannel" in complete_data:
            dut_list = [dut, partner]
            for portchannel, data in complete_data["portchannel"].items():
                if "partners" in data:
                    if set(dut_list) == set(data["partners"]):
                        result["portchannel"] = portchannel
                        for key, value in data.items():
                            if key != "partners":
                                result[key] = value
    return result

def get_dut_partner_interfaces(dut, partner):
    """
    API to get teh DUT to partner connected interfaces
    :param dut:
    :param partner:
    :return:{'as7816-01': ['Ethernet16', 'Ethernet17', 'Ethernet18', 'Ethernet19'],
    'as5712-03': ['Ethernet40', 'Ethernet41', 'Ethernet42', 'Ethernet43']}
    """
    result = dict()
    st.log("DUT in get_dut_partner_interfaces {}".format(dut))
    st.log("PARTNER in get_dut_partner_interfaces {}".format(partner))
    dut_partner = st.get_links(dut, partner)
    if dut_partner:
        result[dut] = list()
        result[partner] = list()
        for local, device, remote in dut_partner:
            st.log("Found local interface {} for remote intf {} on partner dut {}".format(local, remote, device))
            result[dut].append(local)
            result[partner].append(remote)
    return result

def verify_for_stp_convergance(vars, vlan_instance):
    """
    API to verify STP convergence on a VLAN instance.
    :param vlan_instance:
    :return:
    """
    dut_list = get_dut_list(vars)
    poll_for_states = ["LEARNING", "LISTENING"]
    params = list()
    if dut_list:
        st.log("Verifying on the list of devices {}".format(dut_list))
        for dut in dut_list:
            params.append([stp.show_stp_vlan, dut, vlan_instance])
        st.log("Executing parallelly on all the devices ...")
        [out, exceptions] = exec_all(True, params)
        st.log(out)
        st.log(exceptions)
        for value in exceptions:
            if value is not None:
                st.log("Exception occured {}".format(value))
                return False
        if out:
            for stp_data in out:
                for stats in stp_data:
                    if stats["port_state"] in poll_for_states:
                        st.log("Observed portstate for {} is {}".format(stats["port_state"], stats["port_name"]))
                        return False
            st.log("All the interfaces are in steady state ..")
            return True
        else:
            st.log("No response from DUT commands ..")
            return False
    else:
        st.log("DUT LIST not found.")
        return False

def poll_stp_convergence(vars, vlan_instance, iteration=30, delay=1):
    i=1
    while True:
        if verify_for_stp_convergance(vars, vlan_instance):
            st.log("STP convergance happened at {} iteration".format(i))
            return True
        if i>=iteration:
            st.log("Max limit reached, hence exiting")
            return False
        st.wait(delay)
        i+=1

#########################################################################
#            TG STREAM CONFIGURATION AND VERIFICATION APIS              #
#         Author: PRUDVI MANGADU prudvi.mangadu@broadcom.com            #
#########################################################################
def config_tg_streams(vars, device_data, vlan_list, mac_count=1):
    """
    API to configure unicast and unknown traffic streams
    :param vars:
    :param device_data:
    :param vlan_list:
    :return:
    """
    global src_tg1_vlan_inc_mac_fix_unknown, tg_info
    tg_info = {}
    tg_list = [device_data[each][0] for each in device_data.keys()]
    tg_handler = tgapi.get_handles(vars, tg_list)
    tg = tg_handler["tg"]
    tg_ph_1 = tg_handler["tg_ph_1"]
    tg_ph_2 = tg_handler["tg_ph_2"]
    tg_info['tg_info'] = tg_handler
    tg_info['vlan_id'] = vlan_list[0]
    tgapi.traffic_action_control(tg_handler, actions=['reset', 'clear_stats'])

    tg_1 = tg.tg_traffic_config(port_handle=tg_ph_1, mode='create', transmit_mode="single_burst", pkts_per_burst=10000, mac_src="00:00:00:00:00:01", mac_src_mode="fixed", mac_dst="00:00:00:00:00:02", mac_dst_mode="fixed", vlan_id=vlan_list[0], vlan_id_count=len(vlan_list), vlan_id_mode='increment', vlan_id_step=1, l2_encap='ethernet_ii')
    tg_info["tg1_unicast"] = tg_1['stream_id']

    tg_1 = tg.tg_traffic_config(port_handle=tg_ph_1, mode='create', transmit_mode="single_burst", pkts_per_burst=10000, mac_src="00:00:00:00:00:01", mac_src_mode="fixed", mac_dst="00:00:00:00:00:03", mac_dst_mode="fixed", vlan_id=vlan_list[0], vlan_id_count=len(vlan_list), vlan_id_mode='increment', vlan_id_step=1, l2_encap='ethernet_ii')
    tg_info["tg1_unknown"] = tg_1['stream_id']

    tg_2 = tg.tg_traffic_config(port_handle=tg_ph_2, mode='create', transmit_mode="single_burst", pkts_per_burst=10000, mac_src="00:00:00:00:00:02", mac_src_mode="fixed", mac_dst="00:00:00:00:00:01", mac_dst_mode="fixed", vlan_id=vlan_list[0], vlan_id_count=len(vlan_list), vlan_id_mode='increment', vlan_id_step=1, l2_encap='ethernet_ii')
    tg_info["tg2_unicast"] = tg_2['stream_id']

    tg_1 = tg.tg_traffic_config(port_handle=tg_ph_1, mode='create', transmit_mode="single_burst", pkts_per_burst=10000, mac_src="00:00:00:00:00:01", mac_src_mode="fixed",  mac_dst="01:00:5e:01:02:03", mac_dst_mode="fixed", vlan_id=vlan_list[0], vlan_id_count=len(vlan_list), vlan_id_mode='increment', vlan_id_step=1, l2_encap='ethernet_ii')
    tg_info["tg1_multicast"] = tg_1['stream_id']

    tg_1 = tg.tg_traffic_config(port_handle=tg_ph_1, mode='create', transmit_mode="single_burst", pkts_per_burst=10000, mac_src="00:00:00:00:00:01", mac_src_mode="fixed", mac_dst="ff:ff:ff:ff:ff:ff", mac_dst_mode="fixed", vlan_id=vlan_list[0], vlan_id_count=len(vlan_list), vlan_id_mode='increment', vlan_id_step=1, l2_encap='ethernet_ii')
    tg_info["tg1_broadcast"] = tg_1['stream_id']

    tg_1 = tg.tg_traffic_config(port_handle=tg_ph_1, mode='create', rate_pps=10000, transmit_mode="continuous", mac_src="00:80:00:00:00:01", mac_src_mode=" increment", mac_src_count=mac_count, mac_src_step="00:00:00:00:00:01", mac_dst="00:00:90:80:00:01", mac_dst_mode=" increment", mac_dst_count=mac_count, mac_dst_step="00:00:00:00:00:01", vlan_id=vlan_list[0], vlan_id_count=len(vlan_list), vlan_id_mode='increment', vlan_id_step=1, l2_encap='ethernet_ii')
    tg_info["tg1_vlan_inc_mac_fix_unknown"] = tg_1['stream_id']

    return tg_info

def verify_traffic(mode, tg_info, skip_traffic_verify=False, duration=1):
    """
    API to verify the traffic based on unicast or unknown mode
    :param mode:
    :param tg_info:
    :return:
    """
    st.log("Observed the mode as {}".format(mode))
    st.log("Clearing stats before sending traffic ...")
    tgapi.traffic_action_control(tg_info['tg_info'], actions=['clear_stats'])
    st.wait(5)
    tg = tg_info['tg_info']['tg']
    stream_list = list()
    if mode == 'unicast':
        st.log("Enabling unicast traffic and disabling unknown unicast ...")
        tg.tg_traffic_config(mode='enable', stream_id=tg_info['tg1_unicast'])
        tg.tg_traffic_config(mode='enable', stream_id=tg_info['tg2_unicast'])
        tg.tg_traffic_config(mode='disable', stream_id=tg_info['tg1_unknown'])
        tg.tg_traffic_config(mode='disable', stream_id=tg_info['tg1_multicast'])
        tg.tg_traffic_config(mode='disable', stream_id=tg_info['tg1_broadcast'])
        tg.tg_traffic_config(mode='disable', stream_id=tg_info['tg1_vlan_inc_mac_fix_unknown'])
        stream_list = [tg_info['tg1_unicast'],tg_info['tg2_unicast']]
    if mode == 'unknown':
        st.log("Enabling unknown unicast traffic and disabling unicast,multicast and broadcast ...")
        tg.tg_traffic_config(mode='disable', stream_id=tg_info['tg1_unicast'])
        tg.tg_traffic_config(mode='disable', stream_id=tg_info['tg2_unicast'])
        tg.tg_traffic_config(mode='disable', stream_id=tg_info['tg1_multicast'])
        tg.tg_traffic_config(mode='disable', stream_id=tg_info['tg1_broadcast'])
        tg.tg_traffic_config(mode='enable', stream_id=tg_info['tg1_unknown'])
        tg.tg_traffic_config(mode='disable', stream_id=tg_info['tg1_vlan_inc_mac_fix_unknown'])
        stream_list = [tg_info['tg1_unknown']]
    if mode == 'multicast':
        st.log("Enabling multicast traffic and disabling unicast,unknwon and broadcast ...")
        tg.tg_traffic_config(mode='disable', stream_id=tg_info['tg1_unicast'])
        tg.tg_traffic_config(mode='disable', stream_id=tg_info['tg2_unicast'])
        tg.tg_traffic_config(mode='disable', stream_id=tg_info['tg1_unknown'])
        tg.tg_traffic_config(mode='disable', stream_id=tg_info['tg1_broadcast'])
        tg.tg_traffic_config(mode='enable', stream_id=tg_info['tg1_multicast'])
        tg.tg_traffic_config(mode='disable', stream_id=tg_info['tg1_vlan_inc_mac_fix_unknown'])
        stream_list = [tg_info['tg1_multicast']]
    if mode == 'broadcast':
        st.log("Enabling broadcast traffic and disabling unicast,unknown and multicast ...")
        tg.tg_traffic_config(mode='disable', stream_id=tg_info['tg1_unicast'])
        tg.tg_traffic_config(mode='disable', stream_id=tg_info['tg2_unicast'])
        tg.tg_traffic_config(mode='disable', stream_id=tg_info['tg1_unknown'])
        tg.tg_traffic_config(mode='disable', stream_id=tg_info['tg1_multicast'])
        tg.tg_traffic_config(mode='enable', stream_id=tg_info['tg1_broadcast'])
        tg.tg_traffic_config(mode='disable', stream_id=tg_info['tg1_vlan_inc_mac_fix_unknown'])
        stream_list = [tg_info['tg1_broadcast']]
    if mode == 'vlan_inc_mac_fix_unknown':
            tg.tg_traffic_config(mode='enable', stream_id=tg_info['tg1_vlan_inc_mac_fix_unknown'])
            tg.tg_traffic_config(mode='disable', stream_id=tg_info['tg1_unicast'])
            tg.tg_traffic_config(mode='disable', stream_id=tg_info['tg2_unicast'])
            tg.tg_traffic_config(mode='disable', stream_id=tg_info['tg1_unknown'])
            tg.tg_traffic_config(mode='disable', stream_id=tg_info['tg1_multicast'])
            tg.tg_traffic_config(mode='disable', stream_id=tg_info['tg1_broadcast'])
            stream_list = [tg_info['tg1_vlan_inc_mac_fix_unknown']]
    if not skip_traffic_verify:
        st.log("Inside Skip verify block #####")
        tg.tg_traffic_control(action='run', stream_handle= stream_list)
        st.wait(duration)
        tg.tg_traffic_control(action='stop', stream_handle= stream_list)
        st.wait(10)
        stat1 = tgapi.get_traffic_stats(tg, port_handle=tg_info['tg_info']['tg_ph_1'])
        stat2 = tgapi.get_traffic_stats(tg, port_handle=tg_info['tg_info']['tg_ph_2'])
        tx_tg1_99_precentage = (99 * int(stat1.tx.total_packets)) / 100
        tx_tg2_99_precentage = (99 * int(stat2.tx.total_packets)) / 100
        if mode == "unicast":
            st.log("Fetching unicast stats and comparing...")
            if not (stat2.rx.total_packets >= tx_tg1_99_precentage and stat1.rx.total_packets >= tx_tg2_99_precentage):
                st.log("Traffic verification for unicast failed ...")
                return False
        if mode == 'unknown':
            st.log("Fetching unknown unicast stats and comparing...")
            if not stat2.rx.total_packets >= tx_tg1_99_precentage:
                st.log("Traffic verification on stat2 failed.")
                return False
            stat3 = tgapi.get_traffic_stats(tg, port_handle=tg_info['tg_info']['tg_ph_3'])
            if not stat3.rx.total_packets >= tx_tg1_99_precentage:
                st.log("Traffic verification on stat3 failed.")
                return False
        if mode == 'multicast':
            st.log("Fetching multicast stats and comparing...")
            if not stat2.rx.total_packets >= tx_tg1_99_precentage:
                st.log("Traffic verification on stat2 failed.")
                return False
            stat3 = tgapi.get_traffic_stats(tg, port_handle=tg_info['tg_info']['tg_ph_3'])
            if not stat3.rx.total_packets >= tx_tg1_99_precentage:
                st.log("Traffic verification on stat3 failed.")
                return False
        if mode == 'broadcast':
            st.log("Fetching broadcast stats and comparing...")
            if not stat2.rx.total_packets >= tx_tg1_99_precentage:
                st.log("Traffic verification on stat2 failed.")
                return False
            stat3 = tgapi.get_traffic_stats(tg, port_handle=tg_info['tg_info']['tg_ph_3'])
            if not stat3.rx.total_packets >= tx_tg1_99_precentage:
                st.log("Traffic verification on stat3 failed.")
                return False
        if mode =='vlan_inc_mac_fix_unknown':
            st.log("Fetching {} stats and comparing...".format(mode))
            if not (stat2.rx.total_packets >= tx_tg1_99_precentage and stat1.rx.total_packets >= tx_tg2_99_precentage):
                st.log("Traffic verification for {} failed ...".format(mode))
                return False
    return True

def get_blocking_brigde_with_interfaces(vlan_id, stp_protocol):
    #result = dict()
    blocking_dut = ""
    forwarding_links_list_of_blocking_dut = dict()
    blocking_links_list_of_blocking_dut = dict()
    right_blocking_fwding_bridge_found = 0
    st.log("######## complete_data #########")
    st.log(complete_data)
    if complete_data:
        if "states" in complete_data:
            for vlan_no, data in complete_data["states"].items():

                st.log("######## data #########")
                st.log(data)
                st.log(" vlan = {}" . format(vlan_no))
                blocking_fwding_dut_list = list()

                if vlan_no == vlan_id:
                    if "non_root" in data:

                        if "highest_mac" in data["non_root"] and data["non_root"]["highest_mac"]:
                            st.log("Getting blocking DUT and links from the highest mac NON Root DUT ...")
                            highest_mac = data["non_root"]["highest_mac"]
                            if ("blocking_links" in highest_mac and len(highest_mac["blocking_links"]) >= 1) and \
                                    ("forwarding_links" in highest_mac and len(highest_mac["forwarding_links"]) >= 1):

                                blocking_dut = highest_mac["name"]
                                st.log("highest mac blocking_dut = {}" . format(blocking_dut))

                                st.log("this is a prospective blocking and forwarding bridge. So, add this to to-be-processed list.")
                                blocking_fwding_dut_list.append(blocking_dut)

                                blocking_links_list_of_blocking_dut[blocking_dut] = highest_mac["blocking_links"]
                                forwarding_links_list_of_blocking_dut[blocking_dut] = highest_mac["forwarding_links"]

                        else:
                            if "other" in data["non_root"] and data["non_root"]["other"]:
                                st.log("Getting blocking DUT and links from the other NON Root DUT ...")
                                for other_dut in data["non_root"]["other"]:
                                    if ("blocking_links" in other_dut and len(
                                            other_dut["blocking_links"]) >= 1) and \
                                            ("forwarding_links" in other_dut and len(
                                            other_dut["forwarding_links"]) >= 1):

                                        blocking_dut = other_dut["name"]
                                        st.log("highest mac blocking_dut = {}" . format(blocking_dut))


                                        st.log("this is a prospective blocking and forwarding bridge. So, add this to to-be-processed list.")
                                        blocking_fwding_dut_list.append(blocking_dut)

                                        blocking_links_list_of_blocking_dut[blocking_dut] = other_dut["blocking_links"]
                                        forwarding_links_list_of_blocking_dut[blocking_dut] = other_dut["forwarding_links"]

                        st.log(" #### Gathering of prospective list of blocking and forwarding bridges -- is complete. ######  ")

                        st.log(" #### About to scan thru each prospective blocking and forwarding bridge -- to identify the bridge meeting exact requirement. ######  ")

                        for prospective_dut in blocking_fwding_dut_list:
                            result = dict()

                            st.log("######## Prospective {} DUT #########".format(stp_dict[stp_protocol]["non_fwd_state"]))
                            st.log(prospective_dut)

                            st.log("########{} Links list #########".format(stp_dict[stp_protocol]["non_fwd_state"]))
                            st.log(blocking_links_list_of_blocking_dut[prospective_dut])
                            #blocking_link = random.sample(blocking_links, k=1)[0]
                            #st.log("##########SELECTED {} LINK-------{}##############".format(blocking_link).format(stp_dict[stp_protocol]["non_fwd_state"]))

                            st.log("######## FORWARDING Links list of Prospective blocking DUT #########")
                            st.log(forwarding_links_list_of_blocking_dut[prospective_dut])

                            for blocking_link in blocking_links_list_of_blocking_dut[prospective_dut]:
                                #st.log("########## {} LINK-------{} ##############" . format(stp_dict[stp_protocol]["non_fwd_state"], blocking_link))
                                st.log("########## DUT PARTNER DETAILS ###########")
                                dut_partner_details = get_dut_partner_details_by_dut_interface(prospective_dut, blocking_link)
                                st.log(dut_partner_details)

                                if dut_partner_details:

                                    for dut, interface_list in dut_partner_details.items():

                                        st.log("dut = {}" . format(dut))
                                        st.log("interface_list = {}" . format(interface_list))

                                        result[dut] = dict()
                                        result[dut]["forwarding"] = list()
                                        result[dut]["blocking"] = list()

                                        if interface_list and len(interface_list) >= 2:
                                            for interface in interface_list:
                                                st.log("interface = {}" . format(interface))

                                                port_state = stp.get_stp_port_param(dut, vlan_id, interface,
                                                                                     "port_state")
                                                if port_state == "FORWARDING":
                                                    result[dut]["forwarding"].append(interface)
                                                elif port_state == stp_dict[stp_protocol]["non_fwd_state"]:
                                                    result[dut]["blocking"].append(interface)

                                        st.log("##### About to verify whether this DUT meets out requirements  ############")
                                        if len(result[dut]["forwarding"]) >= 1 and  len(result[dut]["blocking"]) >= 1:
                                            st.log("Found the right dut = {}" . format(dut))
                                            right_blocking_fwding_bridge_found = 1
                                            break

                                st.log("### For this blocking link, processing is completed.")
                                if(right_blocking_fwding_bridge_found == 1):
                                    break

                            st.log(" #### Processing of current prospective DUT -- to find the needed blocking bridge and it's partner -- is done ####")
                            if(right_blocking_fwding_bridge_found == 1):
                                break
                        if(right_blocking_fwding_bridge_found == 1):
                            st.log("Right blocking bridge, which has one or more blocking ports and one or more forwarding port, has been found !!!")
                        else:
                            st.log("Right blocking bridge, which has one or more blocking ports and one or more forwarding port, is NOT found. Toology is incorrect !!!")

    st.log("############### RESULT ##################")
    st.log(result)

    return result

