# This file contains the list of API's which show and verify bcmcmd o/p.
# Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
import re
from spytest import st
import utilities.common as utils

import apis.system.interface as interface_obj

from apis.common.asic import dump_l3_egress         # pylint: disable=unused-import
from apis.common.asic import dump_l3_alpm           # pylint: disable=unused-import
from apis.common.asic import dump_l2                # pylint: disable=unused-import
from apis.common.asic import dump_vlan              # pylint: disable=unused-import
from apis.common.asic import dump_multicast         # pylint: disable=unused-import
from apis.common.asic import dump_ipmc_table        # pylint: disable=unused-import
from apis.common.asic import dump_ports_info        # pylint: disable=unused-import
from apis.common.asic import dump_trunk             # pylint: disable=unused-import
from apis.common.asic import dump_counters          # pylint: disable=unused-import
from apis.common.asic import clear_counters         # pylint: disable=unused-import
from apis.common.asic import dump_threshold_info    # pylint: disable=unused-import


def bcmcmd_show(dut, command):
    """
    This is common API for all bcmcmd show commands
    Only Templates files should add for all show brcmcmd commands
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param dut:
    :param command:
    :return:

    EX:
    bcmcmd_show(dut,'l2 show')
    bcmcmd_show(dut,'vlan show')
    bcmcmd_show(dut,'trunk show')
    """
    command = 'bcmcmd "{}"'.format(command)
    return st.config(dut, command)

def read_l2(dut):
    """
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :return: mac, vlan, gport, modid, port, type
    """
    return st.show(dut, 'bcmcmd "l2 show" ')

def verify_bcmcmd_output(dut, command, **kwargs):
    """
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param dut:
    :param command: l2_show, vlan_show, pvlan_show , trunk_show
    :param kwargs: based on command pass the values
    :return:
    """
    if command == "trunk_show":
        output = st.show(dut, 'bcmcmd "trunk show" ')
    else:
        st.error("Invalid command = {}".format(command))
        return False
    for each in kwargs.keys():
        if not utils.filter_and_select(output, None, {each: kwargs[each]}):
            st.error("No match for {} = {} in table".format(each, kwargs[each]))
            return False
    return True

def bcmcmd_show_c(dut, interface=None, skip_tmpl=False):
    """
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param interface:
    :param skip_tmpl:
    :return:
    """
    if not interface:
        command = 'bcmcmd "show c"'
    else:
        command = 'bcmcmd "show c {}"'.format(interface)
    return st.show(dut, command, skip_tmpl=skip_tmpl)

def bcmcmd_show_pmap(dut):
    """
    Author: Chaitanya Vella (chaitanya.vella-kumar@broadcom.com)
    This API is used to get the bcmcmd 'show pmap' output
    :param dut: DUT object
    :return:
    """
    command = 'bcmcmd "show pmap"'
    return st.show(dut, command)


def bcmcmd_show_ps(dut):
    """
    Author: Chaitanya Vella (chaitanya.vella-kumar@broadcom.com)
    This API is used to get the bcmcmd 'ps' output
    :param dut: DUT object
    :return:
    """
    command = 'bcmcmd "ps"'
    return st.show(dut, command)


def bcmcmd_vlan_add(dut):
    """
    Author: Lavanya Harivelam (lavanya.harivelam@broadcom.com)
    This API is used to get the bcmcmd 'ps' output
    :param dut: DUT object
    :return:
    """
    command = 'bcmcmd "vlan add 1000 PortBitMap=CPU"'
    return st.config(dut, command)

def bcm_cmd_l3_intf_show(dut, **kwargs):
    command = "bcmcmd 'l3 intf show'"
    output = st.show(dut, command)
    st.debug(output)
    for each in kwargs.keys():
        if utils.filter_and_select(output, None, {each: kwargs[each]}):
            st.error("No match for {} = {} in table".format(each, kwargs[each]))
            return False
    return True


def bcmcmd_route_config(dut, **kwargs):
    """
    :param: dut:
    :type: dut:
    :param: vrf:
    :type: int:
    :param: ip:
    :type: str:
    :param: mask:
    :type: str:
    :param: intf:
    :type: int:
    :param: af:
    :type: str:
    :return:
    :type: bool:
    """
    st.log("Creating an {} route using bcmcmd".format(kwargs["af"]))
    command = ''
    if not kwargs["vrf"] and not kwargs["ip"] and not kwargs["mask"] and not kwargs["intf"] and not kwargs["action"]:
        st.error("Mandatory params vrf, ip, mask, intf, action are not provided")
        return False

    if kwargs["action"] == "add":
        if kwargs["af"] == "ipv4":
            command = "bcmcmd 'l3 defip add VRF={} IP={} Mask={} INtf={}'".format(kwargs["vrf"], kwargs["ip"],
                                                                                  kwargs["mask"], kwargs["intf"])
            if "ecmp" in kwargs:
                command = "bcmcmd 'l3 defip add VRF={} IP={} Mask={} INtf={} ECMP={}'".format(kwargs["vrf"],
                                                                                              kwargs["ip"],
                                                                                              kwargs["mask"],
                                                                                              kwargs["intf"],
                                                                                              kwargs["ecmp"])
        elif kwargs["af"] == "ipv6":
            command = "bcmcmd 'l3 ip6route add VRF={} IP={} MaskLen={} INtf={}'".format(kwargs["vrf"], kwargs["ip"],
                                                                                        kwargs["mask"], kwargs["intf"])

    if kwargs["action"] == "delete":
        if kwargs["af"] == "ipv4":
            command = "bcmcmd 'l3 defip destroy VRF={} IP={} Mask={} INtf={}'".format(kwargs["vrf"], kwargs["ip"],
                                                                                      kwargs["mask"], kwargs["intf"])

        elif kwargs["af"] == "ipv6":
            command = "bcmcmd 'l3 ip6route destroy VRF={} IP={} MaskLen={} INtf={}'".format(kwargs["vrf"], kwargs["ip"],
                                                                                            kwargs["mask"],
                                                                                            kwargs["intf"])
    st.debug(command)
    st.config(dut, command, skip_error_check=True)
    return True


def bcmcmd_nbr_config(dut, **kwargs):
    """
    :param: dut:
    :type: dut:
    :param: ip:
    :type: str:
    :param: intf:
    :type: int:
    :param: af:
    :type: str:
    :return:
    :type: bool:
    """
    st.log("Creating an {} nbr using bcmcmd".format(kwargs["af"]))
    command = ''
    if not kwargs["ip"] and not kwargs["intf"] and not kwargs["action"]:
        st.error("Mandatory params ip, intf, action are not provided")
        return False

    if kwargs["action"] == "add":
        if kwargs["af"] == "ipv4":
            command = "bcmcmd 'l3 l3table add IP={} INtf={}'".format(kwargs["ip"], kwargs["intf"])

        elif kwargs["af"] == "ipv6":
            command = "bcmcmd 'l3 ip6host add IP={} INtf={}'".format(kwargs["ip"], kwargs["intf"])

    if kwargs["action"] == "delete":
        if kwargs["af"] == "ipv4":
            command = "bcmcmd 'l3 l3table destroy IP={}'".format(kwargs["ip"])

        elif kwargs["af"] == "ipv6":
            command = "bcmcmd 'l3 ip6host destroy IP={}'".format(kwargs["ip"])

    if kwargs["action"] == "clear":
        if kwargs["af"] == "ipv4":
            command = "bcmcmd 'l3 l3table destroy IP={}'".format(kwargs["ip"])

        elif kwargs["af"] == "ipv6":
            command = "bcmcmd 'l3 ip6host clear'"

    st.debug(command)
    st.config(dut, command, skip_error_check=True)
    return True


def bcmcmd_l3_defip_show(dut, match={}, items=[]):
    """
    :param dut:
    :param match:
    :param items:
    :return: vrf, route, nhpmac, intf
    """
    command = "bcmcmd 'l3 defip show'"
    output = st.show(dut, command)
    st.debug(output)
    if match and items:
        return utils.filter_and_select(output, items, match)
    if match and not items:
        return utils.filter_and_select(output, None, match)
    return output


def bcmcmd_l3_ip6route_show(dut, match={}, items=[]):
    """
    :param dut:
    :param match:
    :param items:
    :return: vrf, route, nhpmac, intf
    """
    command = "bcmcmd 'l3 ip6route show'"
    output = st.show(dut, command)
    st.debug(output)
    if match and items:
        return utils.filter_and_select(output, items, match)
    if match and not items:
        return utils.filter_and_select(output, None, match)
    return output


def bcmcmd_l3_l3table_show(dut):
    """
    :param dut:
    :return: nbrip, egrintf
    """
    command = "bcmcmd 'l3 l3table show'"
    return st.show(dut, command)


def bcmcmd_l3_ip6host_show(dut):
    """
    :param dut:
    :return: nbrip, egrintf
    """
    command = "bcmcmd 'l3 ip6host show'"
    return st.show(dut, command)


def verify_bcmcmd_routing_output(dut, command, **kwargs):
    """
    :param dut:
    :param command:
    :type :show command: "l3 defip show", "l3 ip6route show", "l3 l3table show", "l3 ip6host show"
    :param :kwargs:
    :type :based on arguments passed:
    :return:
    """

    if command == "l3_defip_show":
        output = bcmcmd_l3_defip_show(dut)
    elif command == "l3_ip6route_show":
        output = bcmcmd_l3_ip6route_show(dut)
    elif command == "l3_l3table_show":
        output = bcmcmd_l3_l3table_show(dut)
    elif command == "l3_ip6host_show":
        output = bcmcmd_l3_ip6host_show(dut)
    else:
        st.error("Invalid command = {}".format(command))
        return False

    for each in kwargs.keys():
        if not utils.filter_and_select(output, None, {each: kwargs[each]}):
            st.error("No match for {} = {} in table".format(each, kwargs[each]))
            return False
    return True


def bcmcmd_get_l3_entry(dut):
    command = "bcmcmd 'listmem l3_entry'"
    output = st.show(dut, command)
    st.debug(output)
    return output


def bcmcmd_get_defip(dut, name=None):
    """
    To get listmem DEFIP values.
    :param dut:
    :param name:
    :return:
    """
    command = "bcmcmd 'listmem DEFIP'"
    output = st.show(dut, command)
    st.debug(output)
    if not name:
        return output
    else:
        out = utils.filter_and_select(output, ['entries'], {'names': name})
        if out:
            return int(out[0]['entries'])
        else:
            return False


def bcmcmd_l3_entry_only_config(dut, **kwargs):
    if "action" not in kwargs:
        st.error("Mandatory params num, action are not provided")
        return False
    valid = 1
    if kwargs["action"] == "delete":
        valid = 0
    output = bcmcmd_get_l3_entry(dut)
    name_list = utils.dicts_list_values(output, "names")
    if "L3_ENTRY_ONLY" in name_list:
        num = int(utils.filter_and_select(output, [], {"names": "L3_ENTRY_ONLY"})[0]['entries']) - 1
        command = "bcmcmd 'mod L3_ENTRY_ONLY 1 {} VALID={}'".format(num, valid)
    elif "L3_ENTRY_ONLY_SINGLE" in name_list:
        num = int(utils.filter_and_select(output, [], {"names": "L3_ENTRY_ONLY_SINGLE"})[0]['entries']) - 1
        command = "bcmcmd 'mod L3_ENTRY_ONLY_SINGLE 1 {} BASE_VALID={}'".format(num, valid)
    elif "L3_ENTRY_SINGLE" in name_list:
        num = int(utils.filter_and_select(output, [], {"names": "L3_ENTRY_SINGLE"})[0]['entries']) - 1
        command = "bcmcmd 'mod L3_ENTRY_SINGLE 1 {} BASE_VALID={}'".format(num, valid)
    else:
        st.error("L3_ENTRY_ONLY | L3_ENTRY_ONLY_SINGLE | L3_ENTRY_SINGLE not found in - listmem l3_entry")
        return False
    st.config(dut, command)
    return True


def bcmcmd_l3_multipath_add(dut, **kwargs):
    if "size" not in kwargs:
        st.error(" Mandatory param not provided")
        return False
    command = "bcmcmd 'l3 multipath add size={}".format(kwargs["size"])
    if "intf0" in kwargs:
        command += " intf0={}".format(kwargs["intf0"])
    if "intf1" in kwargs:
        command += " intf1={}".format(kwargs["intf1"])
    command += "'"
    st.debug(command)
    st.config(dut, command)
    return True


def bcmcmd_route_count_hardware(dut, timeout=120):
    command = 'bcmcmd "l3 defip show" | wc -l'
    output = st.show(dut, command, skip_tmpl=True, max_time=timeout)
    x = re.search(r"\d+", output)
    if x:
        return int(x.group()) - 5
    else:
        return -1


def bcmcmd_ipv6_route_count_hardware(dut, timeout=120):
    command = 'sudo bcmcmd "l3 ip6route show" | wc -l'
    output = st.show(dut, command, skip_tmpl=True, max_time=timeout)
    x = re.search(r"\d+", output)
    if x:
        return int(x.group()) - 7
    else:
        return -1

def get_interface_pmap_details(dut, interface_name=None):
    """
    Author: Chaitanya Vella (chaitanya.vella-kumar@broadcom.com)
    This API is used to get the interface pmap details
    :param dut: dut
    :param interface_name: List of interface names
    :return:
    """
    ##Passing the cli_type as click in the API call "interface_status_show" because the lanes information is available only in click CLI.
    ##Please refer the JIRA: SONIC-22102 for more information.
    interfaces = utils.make_list(interface_name) if interface_name else ''
    if interfaces:
        if any("/" in interface for interface in interfaces):
            interfaces = st.get_other_names(dut, interfaces)
            key = 'alias'
        else:
            key = 'interface'
        st.debug("The interfaces list is: {}".format(interfaces))
        interface_list = interface_obj.interface_status_show(dut, interfaces=interfaces, cli_type='click')
    else:
        key = 'alias' if interface_obj.show_ifname_type(dut, cli_type='klish') else 'interface'
        interface_list = interface_obj.interface_status_show(dut, cli_type='click')
    interface_pmap = dict()
    pmap_list = bcmcmd_show_pmap(dut)
    for detail in interface_list:
        lane = detail["lanes"].split(",")[0] if "," in detail["lanes"] else detail["lanes"]
        for pmap in pmap_list:
            if pmap["physical"] == lane:
                interface_pmap[detail[key]] = pmap["interface"]
    st.debug(interface_pmap)
    return interface_pmap


def get_param_from_bcmcmd_output(dut,command,param_list,match_dict,**kwargs):
    """
    purpose:
            This definition is used to get a particular field for the matched entry/row
            from bcmcmd show output
    Arguments:
    :param dut: device to be configured
    :type dut: string
    :param command: command to be executed
    :type command: string
    :param param_list: field/parameter list to be returned back
    :type param_list: list
    :param match_dict: key and value to match an entry/row
    :type match_dict: dictionary
    :return: False/output; matched entry/row in Pass case

    usage:
          get_param_from_bcmcmd_output(vars.D1,["gport"],{"mac" : "b8:6a:97:8a:8c:68"})
          get_param_from_bcmcmd_output(vars.D1,["port"],{"mac" : "b8:6a:97:8a:8c:68"})
    """
    command = 'bcmcmd "{}"'.format(command)
    output = st.show(dut, command)
    if not output:
        st.error("output is empty")
        return False
    for key in match_dict.keys():
        if not utils.filter_and_select(output,param_list,{key:match_dict[key]}):
            st.error("No match for key {} with value {}".format(key, match_dict[key]))
            return False
        else:
            st.log("Match found for key {} with value {}".format(key, match_dict[key]))
            return utils.filter_and_select(output,param_list,{key:match_dict[key]})
