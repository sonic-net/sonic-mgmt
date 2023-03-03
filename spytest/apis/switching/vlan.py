# This file contains the list of API's which performs VLAN operations.
# Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
import json
from spytest import st
from utilities.common import random_vlan_list, filter_and_select, exec_foreach, make_list, iterable
from utilities.utils import get_interface_number_from_name, get_portchannel_name_for_rest
from utilities.parallel import ensure_no_exception
from apis.system.rest import config_rest, delete_rest, get_rest, rest_status

http_method = "patch"


def _has_vlan_range(dut):
    if not st.is_feature_supported("vlan-range", dut):
        return False
    return True


def create_vlan(dut, vlan_list, cli_type=''):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """
    To create list of VLANs.
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param dut:
    :param vlan_list:
    :param cli_type:
    :return:
    """

    st.log("Creating vlan {}".format(vlan_list))
    vlan_li = map(str, vlan_list) if isinstance(
        vlan_list, list) else [vlan_list]
    commands = list()
    for each_vlan in vlan_li:
        if cli_type == "click":
            commands.append("config vlan add {}".format(each_vlan))
        elif cli_type == "klish":
            commands.append("interface Vlan {}".format(each_vlan))
            commands.append('exit')
        elif cli_type in ["rest-put", "rest-patch"]:
            vlan_data = dict()
            vlan_data["openconfig-interfaces:interface"] = list()
            vlan_data["openconfig-interfaces:interface"].append(
                {"name": "Vlan{}".format(each_vlan), "config": {"name": "Vlan{}".format(each_vlan)}})
            url = st.get_datastore(dut, "rest_urls")["config_interface"]
            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=vlan_data):
                return False
        else:
            st.log("Unsupported CLI TYPE {}".format(cli_type))
            return False
    if commands:
        st.config(dut, commands, type=cli_type)
    return True


def delete_vlan(dut, vlan_list, cli_type=''):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """
    To delete list of VLANs.
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param dut:
    :param vlan_list:
    :param cli_type:
    :return:
    """

    st.log("Delete vlan")
    vlan_li = map(str, vlan_list) if isinstance(
        vlan_list, list) else [vlan_list]
    commands = list()
    rest_fail_status = False
    try:
        for each_vlan in vlan_li:
            if cli_type == "click":
                commands.append("config vlan del {}".format(each_vlan))
            elif cli_type == "klish":
                commands.append("no interface Vlan {}".format(each_vlan))
            elif cli_type in ["rest-put", "rest-patch"]:
                rest_url = st.get_datastore(dut, "rest_urls")["per_interface_details"].format(
                    "Vlan{}".format(each_vlan))
                output = delete_rest(dut, rest_url=rest_url, get_response=True)
                if not output:
                    st.error("OUTPUT IS EMPTY FROM DELETE VLAN REST CALL")
                    return False
                st.log("STATUS: {}".format(output["status"]))
                if not rest_status(output["status"]):
                    rest_fail_status = True
            else:
                st.log("Unsupported CLI type")
                return False
        if rest_fail_status:
            st.log("One of VLAN DELETE REST call failed")
            return False
        if commands:
            response = st.config(
                dut, commands, skip_error_check=True, type=cli_type)
            if "Error" in response:
                st.log(response)
                return False
            else:
                vlan_list = get_vlan_list(dut, cli_type=cli_type)
                for each_vlan in vlan_li:
                    if each_vlan in vlan_list:
                        st.error(" Vlan{} is not deleted".format(each_vlan))
                        return False
        return True
    except Exception as e1:
        st.log(e1)
        st.error(" Vlan is not deleted due to other reasons")
        return False


def delete_all_vlan(dut, cli_type=''):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """
    To delete All VLANs.
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param dut:
    :param cli_type:
    :return:
    """
    st.log("delete all vlan")
    if cli_type == "click":
        try:
            config_vlan_range(dut, '1 4093', config='del', skip_verify=True)
            return True
        except Exception as e:
            st.log(e)
            st.error("Failed to Delete VLAN(s)")
            return False
    elif cli_type in ["klish", "rest-put", "rest-patch"]:
        return config_vlan_range(dut, '1 4093', config='del', skip_verify=True, cli_type=cli_type)
    else:
        st.log("Unsupported CLI type")
        return False


def show_vlan_config(dut, vlan_id=None, cli_type=''):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """
    To get vlan config from 'show vlan config'
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param vlan_id:
    :param cli_type:
    :return:
    """
    if cli_type == "click":
        st.log("show vlan config")
        command = "show vlan config"
    elif cli_type == "klish":
        command = "show Vlan"
        if vlan_id:
            command += " {}".format(vlan_id)
    elif cli_type in ["rest-put", "rest-patch"]:
        rest_url = st.get_datastore(dut, "rest_urls")["config_interface"]
        get_resp = get_rest(dut, rest_url=rest_url, timeout=600)
        if get_resp and rest_status(get_resp["status"]):
            vlan_data = show_vlan_from_rest_response(get_resp["output"])
            if not vlan_id:
                return vlan_data
            else:
                filter_vlan_data = list()
                for vlans in vlan_data:
                    if str(vlans["vid"].replace("Vlan", "")) == vlan_id:
                        filter_vlan_data.append(vlans)
                return filter_vlan_data
        else:
            return []
    else:
        st.log("Unsupported CLI type")
        return False
    return st.show(dut, command, type=cli_type)


def show_vlan_brief(dut, vlan_id=None, cli_type=''):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """
    To get vlan config from 'show vlan brief'
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param dut:
    :param vlan_id:
    :param cli_type:
    :return:
    """
    if cli_type == "click":
        st.log("show vlan brief")
        command = "show vlan brief"
    elif cli_type == "klish":
        command = "show Vlan"
        if vlan_id:
            command += " {}".format(vlan_id)
    elif cli_type in ["rest-put", "rest-patch"]:
        rest_url = st.get_datastore(dut, "rest_urls")["config_interface"]
        get_resp = get_rest(dut, rest_url=rest_url, timeout=600)
        if get_resp and rest_status(get_resp["status"]):
            vlan_data = show_vlan_from_rest_response(get_resp["output"])
            if not vlan_id:
                return vlan_data
            else:
                filter_vlan_data = list()
                for vlans in vlan_data:
                    if str(vlans["vid"].replace("Vlan", "")) == vlan_id:
                        filter_vlan_data.append(vlans)
                return filter_vlan_data
        else:
            return []
    else:
        st.log("Unsupported CLI type")
        return False

    return st.show(dut, command, type=cli_type)


def get_vlan_count(dut, cli_type=''):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """
    To get the Vlan count using - 'show vlan count' command.
    :param dut:
    :type dut:
    :return:
    :rtype:
    """
    if not _has_vlan_range(dut):
        vlans = get_vlan_list(dut)
        count = len(vlans)
    else:
        if cli_type == "click":
            output = st.show(dut, "show vlan count")
            count = int(output[0]['vlan_count'])
        elif cli_type in ["klish", "rest-put", "rest-patch"]:
            output = get_vlan_list(dut, cli_type=cli_type)
            count = len(output)
        else:
            st.log("Unsupported CLI type")
            return False
    return count


def get_vlan_list(dut, cli_type=''):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """
    Get list of VLANs
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param dut:
    :param cli_type:
    :return:
    """
    st.log("show vlan to get vlan list")
    output = show_vlan_config(dut, cli_type=cli_type)
    vlan_list = list(set([eac['vid'] for eac in output]))
    return vlan_list


def add_vlan_member(dut, vlan, port_list, tagging_mode=False, skip_error=False, no_form=False, cli_type=''):
    """
    Add Members to VLAN
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param vlan:
    :param port_list:
    :param tagging_mode:
    :param skip_error:
    :param no_form:
    :param cli_type:
    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    st.log("Add member {} to the VLAN {}".format(port_list, vlan))
    port_li = make_list(port_list)
    for each_port in port_li:
        if cli_type == "click":

            command_switchport = "config switchport mode trunk {}".format(
                each_port)

            # Here handling the error while configuring switchport mode
            switchport_out = st.config(
                dut, command_switchport, skip_error_check=True)

            if "cannot find port name for alias" in switchport_out:
                st.error("cannot find port name for alias {}".format(each_port))
                return False

            if f"{each_port} does not exist" in switchport_out:
                st.error("{} does not exist".format(each_port))
                return False
            if "is part of portchannel!" in switchport_out:
                st.error("{} is part of portchannel!".format(each_port))
                return False

            if "is a router interface in routed mode!\nRemove IP assigned to it to switch mode!" in switchport_out:
                st.error("{} is a router interface in routed mode!\nRemove IP assigned to it to switch mode!".format(
                    each_port))
                return False

            if "is already in the trunk mode" in switchport_out:
                st.error("{} is already in the trunk mode".format(each_port))
                return False

            if tagging_mode:
                command = "config vlan member add {} {}".format(
                    vlan, each_port)
            else:
                command = "config vlan member add {} {} -u ".format(
                    vlan, each_port)

            # Here handling the error while adding interface to vlan
            out = st.config(dut, command, skip_error_check=True)

            if "is already a member of Vlan{}".format(vlan) in out:
                st.error("{} is already a member of Vlan{}".format(
                    each_port, vlan))
                return False
            if "Vlan{} doesn't exist".format(vlan) in out:
                st.error(" Vlan{} doesn't exist".format(vlan))
                return False
            if "has ip address configured" in out:
                st.error("Error:  {} has ip address configured".format(each_port))
                return False
            if "Vlan{} does not exist".format(vlan) in out:
                st.error(" Vlan{} does not exist".format(vlan))
                return False
        elif cli_type == "klish":
            commands = list()
            interface_details = get_interface_number_from_name(each_port)
            if not interface_details:
                st.log("Interface details not found {}".format(interface_details))
                return False
            commands.append("interface {} {}".format(
                interface_details.get("type"), interface_details.get("number")))
            participation_mode = "trunk" if tagging_mode else "access"
            if participation_mode == "trunk":
                command = "switchport trunk allowed Vlan {} {}"
                commands.append(command.format('remove', vlan)
                                if no_form else command.format('add', vlan))
            elif participation_mode == "access":
                command = "switchport access Vlan"
                commands.append("no {}".format(command)
                                if no_form else "{} {}".format(command, vlan))
            commands.append("exit")
            if commands:
                out = st.config(dut, commands, type=cli_type,
                                skip_error_check=True)
                if "Invalid VLAN:" in out:
                    st.log("Vlan{} doesn't exist".format(vlan))
                    return False
        elif cli_type in ["rest-put", "rest-patch"]:
            cli_type = "rest-patch"
            interface_details = get_interface_number_from_name(each_port)
            if not interface_details:
                st.log("Interface details not found {}".format(interface_details))
                return False
            if "Eth" in interface_details.get("type"):
                url = st.get_datastore(dut, "rest_urls")[
                    "interface_member_config"].format(each_port)
            else:
                intf_name = get_portchannel_name_for_rest(each_port)
                url = st.get_datastore(dut, "rest_urls")[
                    "aggregate_member_config"].format(intf_name)
            if not no_form:
                add_member = json.loads("""
                {"openconfig-vlan:switched-vlan": {"config": {"interface-mode": "ACCESS"}}}""")
                if tagging_mode:
                    vlan_id = str(vlan).split('-')
                    vlan = '{}..{}'.format(vlan_id[0], vlan_id[1]) if len(
                        vlan_id) > 1 else int(vlan)
                    add_member["openconfig-vlan:switched-vlan"]["config"]["trunk-vlans"] = [vlan]
                    add_member["openconfig-vlan:switched-vlan"]["config"]["interface-mode"] = "TRUNK"
                else:
                    add_member["openconfig-vlan:switched-vlan"]["config"]["access-vlan"] = int(
                        vlan)
                if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=add_member):
                    return False
            else:
                if not delete_vlan_member(dut, vlan, each_port,
                                          tagging_mode=tagging_mode,
                                          cli_type=cli_type,
                                          skip_error_check=skip_error):
                    return False
        else:
            st.log("Unsupported CLI type")
            return False
    return True


def delete_vlan_member(dut, vlan, port_list, tagging_mode=False, cli_type='', skip_error_check=False):
    """
    Delete Members in VLAN
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param vlan:
    :param port_list:
    :param participation_mode:
    :param cli_type:
    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    st.log("Delete member {} from the VLAN {}".format(port_list, vlan))
    if tagging_mode:
        participation_mode = "trunk"
    else:
        participation_mode = "access"
    port_li = make_list(port_list)
    commands = list()
    rest_fail_status = False
    for each_port in port_li:
        if cli_type == "click":
            command = "config vlan member del {} {}".format(vlan, each_port)
            out = st.config(dut, command, skip_error_check=skip_error_check)
            if "is not a member of Vlan{}".format(vlan) in out:
                st.error("{} is not a member of Vlan{}".format(each_port, vlan))
                return False
            if "Vlan{} doesn't exist".format(vlan) in out:
                st.error("Vlan{} doesn't exist".format(vlan))
                return False
        elif cli_type == "klish":
            interface_details = get_interface_number_from_name(each_port)
            if not interface_details:
                st.log("Interface details not found {}".format(interface_details))
                return False
            commands.append("interface {} {}".format(
                interface_details.get("type"), interface_details.get("number")))
            if participation_mode == "trunk":
                command = "switchport trunk allowed Vlan remove {}".format(
                    vlan)
                commands.append("{}".format(command))
            elif participation_mode == "access":
                command = "switchport access Vlan"
                commands.append("no {}".format(command))
            commands.append("exit")
        elif cli_type in ["rest-put", "rest-patch"]:
            if participation_mode == "access":
                if "Eth" in get_interface_number_from_name(each_port)["type"]:
                    rest_url = st.get_datastore(dut, "rest_urls")[
                        "interface_access_member_config"].format(each_port)
                else:
                    rest_url = st.get_datastore(dut, "rest_urls")[
                        "aggregate_access_member_config"].format(each_port)
            else:
                vlan_id = str(vlan).split('-')
                vlan = '{}..{}'.format(vlan_id[0], vlan_id[1]) if len(
                    vlan_id) > 1 else vlan
                if "Eth" in get_interface_number_from_name(each_port)["type"]:
                    rest_url = st.get_datastore(dut, "rest_urls")["interface_trunk_member_config"].format(
                        each_port, vlan)
                else:
                    rest_url = st.get_datastore(dut, "rest_urls")["aggregate_trunk_member_config"].format(
                        each_port, vlan)
            output = delete_rest(dut, rest_url=rest_url, get_response=True)
            if not output:
                st.error("OUTPUT IS EMPTY FROM DELETE VLAN MEMBER REST CALL")
                return False
            st.log("STATUS: {}".format(output["status"]))
            if not rest_status(output["status"]):
                rest_fail_status = True
        else:
            st.error("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
            return False
    if rest_fail_status:
        st.log("One of VLAN member DELETE REST call failed")
        return False
    if commands:
        st.config(dut, commands, type=cli_type,
                  skip_error_check=skip_error_check)
    return True


def get_vlan_member(dut, vlan_list=[], cli_type=''):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """
    To Get VLANs vs list of Members.
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param dut:
    :param vlan_list:
    :param cli_type:
    :return:
    """
    vlan_val = {}
    vlan_li = map(str, vlan_list) if isinstance(
        vlan_list, list) else [vlan_list]
    out = show_vlan_config(dut, cli_type=cli_type)
    if vlan_li:
        temp = []
        for each in list(set(vlan_li)):
            temp += filter_and_select(out, None, {"vid": each})
        out = temp

    for each in iterable(out):
        if each['member']:
            if each['vid'] not in vlan_val:
                vlan_val[each['vid']] = [each['member']]
            else:
                vlan_val[each['vid']].append(each['member'])
    return vlan_val


def get_member_vlan(dut, interface_list=[], cli_type=''):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """
    To Get Members vs list of VLANs.
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param dut:
    :param interface_list:
    :param cli_type:
    :return:
    """
    member_val = {}
    interface_li = list(interface_list) if isinstance(
        interface_list, list) else [interface_list]
    out = show_vlan_config(dut, cli_type=cli_type)
    if interface_li:
        temp = []
        for each in list(set(interface_li)):
            temp += filter_and_select(out, None, {"member": each})
        out = temp

    for each in iterable(out):
        if each['member']:
            if each['member'] not in member_val:
                member_val[each['member']] = [each['vid']]
            else:
                member_val[each['member']].append(each['vid'])
    return member_val


def verify_vlan_config(dut, vlan_list, tagged=None, untagged=None, name=None, cli_type=''):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """
    Verify vlan config using 'show vlan config'
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param dut:
    :param vlan_list:
    :param tagged:
    :param untagged:
    :param name:
    :return:
    """

    vlan_li = map(str, vlan_list) if isinstance(
        vlan_list, list) else [vlan_list]
    output = show_vlan_config(dut, cli_type=cli_type)
    for each_vlan in vlan_li:
        entries = filter_and_select(output, None, {"vid": each_vlan})
        if not entries:
            st.log("Provided VLAN {} entry is not exist in table".format(each_vlan))
            return False
        if tagged:
            interface_list = list(tagged) if isinstance(
                tagged, list) else [tagged]
            for each_intr in interface_list:
                if cli_type in ["click", "rest-put", "rest-patch"]:
                    if not filter_and_select(entries, None, {"member": each_intr, "mode": "tagged"}):
                        st.log("Provided interface {} is not a tagged member of Vlan {}".format(
                            each_intr, each_vlan))
                        return False
                elif cli_type == "klish":
                    if not filter_and_select(entries, None, {"member": each_intr, "mode": "T"}):
                        st.log("Provided interface {} is not a tagged member of Vlan {}".format(
                            each_intr, each_vlan))
                        return False
                else:
                    st.log("Unsupported CLI TYPE")
                    return False
        if untagged:
            interface_list = list(untagged) if isinstance(
                untagged, list) else [untagged]
            for each_intr in interface_list:
                if cli_type in ["click", "rest-put", "rest-patch"]:
                    if not filter_and_select(entries, None, {"member": each_intr, "mode": "untagged"}):
                        st.log("Provided interface {} is not a untagged member of Vlan {}".format(
                            each_intr, each_vlan))
                        return False
                elif cli_type == "klish":
                    if not filter_and_select(entries, None, {"member": each_intr, "mode": "A"}):
                        st.log("Provided interface {} is not a tagged member of Vlan {}".format(
                            each_intr, each_vlan))
                        return False
                else:
                    st.log("Unsupported CLI TYPE")
                    return False
        if name and not filter_and_select(entries, None, {"name": name}):
            st.log(
                "Provided and configured VLAN {} name in not match".format(each_vlan))
            return False
    return True


def verify_vlan_brief(dut, vid, tagged=None, untagged=None, ip_address=None, dhcp_helper_add=None, cli_type=''):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """
    Verify vlan config using 'show vlan brief'
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param dut:
    :param vid:
    :param tagged:
    :param untagged:
    :param ip_address:
    :param dhcp_helper_add:
    :return:
    """
    vid = str(vid)
    output = show_vlan_brief(dut, cli_type=cli_type)
    entries = filter_and_select(output, None, {"vid": vid})
    if not entries:
        st.log("Provided VLAN {} entry is not exist in table".format(vid))
        return False
    if tagged and not filter_and_select(entries, None, {"ports": tagged, "porttagging": "tagged"}):
        st.log(
            "Provided interface {} is not a tagged member of Valn {}".format(tagged, vid))
        return False
    if untagged and not filter_and_select(entries, None, {"ports": untagged, "porttagging": "untagged"}):
        st.log("Provided interface {} is not a untagged member of Valn {}".format(
            untagged, vid))
        return False
    if dhcp_helper_add and not filter_and_select(entries, None, {"vid": vid, "dhcphelperadd": dhcp_helper_add}):
        st.log("Provided and configured vlan {} DHCPHelperAdd {} in not match".format(
            vid, dhcp_helper_add))
        return False
    if ip_address and not filter_and_select(entries, None, {"vid": vid, "ipadd": ip_address}):
        st.log("Provided and configured vlan {} IpAdd {} in not match".format(
            vid, ip_address))
        return False
    return True


def _clear_vlan_configuration_helper(dut_list, cli_type=''):
    """
    Find and clear VLAN and its Members.
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param dut_list:
    :return:
    """
    dut_li = list(dut_list) if isinstance(dut_list, list) else [dut_list]
    for dut in dut_li:
        cli_type = st.get_ui_type(dut, cli_type=cli_type)
        st.log("############## {} : VLAN Cleanup ################".format(dut))
        if cli_type == 'click':
            output = show_vlan_config(dut, cli_type=cli_type)

            if not _has_vlan_range(dut):
                (vlans, commands) = ({}, [])
                for eac in output:
                    (vid, member) = (eac['vid'], eac['member'])
                    if vid:
                        vlans[vid] = 1
                        if member:
                            command = "config vlan member del {} {}".format(
                                vid, member)
                            commands.append(command)
                for vid in vlans.keys():
                    command = "config vlan del {}".format(vid)
                    commands.append(command)
                st.config(dut, commands)
                continue

            # Get Vlan list
            vlan_list = list(set([eac['vid'] for eac in output]))
            # Get interface list
            member_list = list(set([eac['member']
                               for eac in output if eac['member'] != '']))
            if member_list:
                if not config_vlan_range_members(dut, '1 4093', member_list, config='del', skip_verify=True):
                    st.log("VLAN all member delete failed")
                    return False
            if vlan_list:
                if not delete_all_vlan(dut, cli_type=cli_type):
                    st.log("VLAN all delete failed")
                    return False
        elif cli_type in ['klish', "rest-put", "rest-patch"]:
            return delete_all_vlan(dut, cli_type=cli_type)
        else:
            st.log("UNSUPPORTED CLI TYPE")
            return False
    return True


def clear_vlan_configuration(dut_list, thread=True, cli_type=''):
    """
    Find and clear VLAN and its Members on list of DUTs
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param dut_list:
    :param thread: True(Default) / False
    :param cli_type:
    :return:
    """
    dut_li = list(dut_list) if isinstance(dut_list, list) else [dut_list]
    cli_type = st.get_ui_type(dut_li[0], cli_type=cli_type)
    [out, exceptions] = exec_foreach(
        thread, dut_li, _clear_vlan_configuration_helper, cli_type=cli_type)
    ensure_no_exception(exceptions)
    return False if False in out else True


def create_vlan_and_add_members(vlan_data, cli_type=''):
    """
    Create VLAN and Add members to VLAN across DUTs
    Author : Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)

    :param vlan_data: List of dictionaries with dut, vlan_id and tagged / untagged members list.
    Sample vlan_data -- [{"dut": [vars.D1, vars.D2], "vlan_id":"100","tagged":["Ethernet0", "Ethernet1"],
                        "untagged":["Ethernet3", "Ethernet4"]},{"dut": [vars.D2], "vlan_id":"200",
                        "tagged":["Ethernet5", "Ethernet6"], "untagged":["Ethernet7", "Ethernet8"]}]
    :param cli_type:
    :return: True / False
    """
    if not isinstance(vlan_data, list):
        return False
    for data in vlan_data:
        if "dut" not in data:
            return False
        dut_list = list(data["dut"]) if isinstance(
            data["dut"], list) else [data["dut"]]
        for dut in dut_list:
            cli_type = st.get_ui_type(dut, cli_type=cli_type)
            if "vlan_id" in data:
                create_vlan(dut, data["vlan_id"], cli_type=cli_type)
                if "tagged" in data and data["tagged"]:
                    add_vlan_member(
                        dut, data["vlan_id"], data["tagged"], tagging_mode=True, cli_type=cli_type)
                if "untagged" in data and data["untagged"]:
                    add_vlan_member(
                        dut, data["vlan_id"], data["untagged"], tagging_mode=False, cli_type=cli_type)
            else:
                return False
    return True


def get_non_existing_vlan(dut, count=1, cli_type=''):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """
    This API will provide number of non existing vlans
    Author : Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)s
    :param dut:
    :param count:
    :return:
    """
    vlan_list = get_vlan_list(dut, cli_type=cli_type)
    return random_vlan_list(count, vlan_list)


def _check_config_vlan_output(output):
    if "VLANs already existing" in output:
        st.error("VLANs already existing were tried to be configured")
        return False
    if "Non-existent VLANs" in output:
        st.error("Non-existent VLANs were tried to be deleted")
        return False
    return True


def config_vlan_range(dut, vlan_range, config="add", skip_verify=False, cli_type=''):
    """
    Author: sneha.mathew@broadcom.com
    Creates/Deletes range of VLANs given as input.
    :param dut:
    :param vlan_range: range of VLAN IDs in string format, separator space: "first-VLAN last_VLAN".
                        can be list of strings.
    :param config: flag which specifies to configure or unconfigure the cli. add for config, del for unconfig.
                        Default:add
    :param skip_verify: True | False
    :return True: The VLANs were successfully created or deleted.
    :return False: Error in parameter passed.
    """

    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    cli_type = 'klish' if cli_type in ['rest-put', 'rest-patch'] else cli_type

    if config == "del":
        st.log("Deleting range of vlans {}".format(vlan_range))
        no_form = 'no '
    else:
        st.log("Creating range of vlans {}".format(vlan_range))
        no_form = ''

    vlan_range_list = list(vlan_range) if isinstance(
        vlan_range, list) else [vlan_range]

    commands = []
    if cli_type == 'click':
        if not _has_vlan_range(dut):
            for vrange in vlan_range_list:
                [range_min, range_max] = [int(vid) for vid in vrange.split()]
                for vid in range(range_min, range_max+1):
                    commands.append("config vlan {} {}".format(config, vid))
            output = st.config(dut, commands)
            return _check_config_vlan_output(output)

        for vrange in vlan_range_list:
            commands.append("config vlan range {} {}".format(config, vrange))

        ver_flag = True
        for command in commands:
            # -w option displays warning, turned on so that existing vlans message can be checked
            if not skip_verify:
                command += " -w"
            output = st.config(dut, command)
            if not _check_config_vlan_output(output):
                ver_flag = False

        return ver_flag
    elif cli_type == 'klish':
        new_vrange = ''
        for vrange in vlan_range_list:
            new_vrange += vrange.replace(' ', '-')
            new_vrange += ','
        new_vrange = new_vrange.strip(',')
        if 'no' not in no_form:
            commands.append(
                'interface range create Vlan {}'.format(new_vrange))
            commands.append('exit')
            commands.append(
                '{}interface range Vlan {}'.format(no_form, new_vrange))
            commands.append('exit')
        else:
            commands.append('{}interface Vlan {}'.format(no_form, new_vrange))
        try:
            st.config(dut, commands, type=cli_type)
            return True
        except Exception as e:
            st.log(e)
            return False


def _check_config_vlan_member_output(output, port=None, vlan=None):
    if "is already a member of Vlan" in output:
        if port and vlan:
            st.error("{} is already a member of Vlan{}".format(port, vlan))
        else:
            st.error("one/more interfaces are already VLAN members")
        return False
    if "doesn't exist" in output:
        if port and vlan:
            st.error(" Vlan{} doesn't exist".format(vlan))
        else:
            st.error(" Vlan(s) doesn't exist")
        return False
    return True


def config_vlan_range_members(dut, vlan_range, port, config="add", skip_verify=False, skip_error=False, cli_type=''):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """
    Author: sneha.mathew@broadcom.com
    Add or remove given member ports to range of VLANs given as input.
    :param dut:
    :param vlan_range: range of VLAN IDs in string format "first-VLAN last_VLAN". can be list of strings.
    :param port: port or list of ports which needs to be added / deleted to vlan_range
    :param config: flag which specifies to configure or unconfigure the cli.
                        add for config, del for unconfig. Default:add
    :param skip_verify: True | False
    :param skip_error: True | False
    :return True: Member ports successfully added or deleted to vlan range.
    :return False: Error in parameter passed.
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    cli_type = 'klish' if cli_type in ['rest-put', 'rest-patch'] else cli_type

    if config == "del":
        st.log("Deleting member ports from range of vlans")
        operation = 'remove'
    else:
        st.log("Adding member ports to range of vlans")
        operation = 'add'

    vlan_range_list = list(vlan_range) if isinstance(
        vlan_range, list) else [vlan_range]
    port_list = list(port) if isinstance(port, list) else [port]

    commands = []
    if cli_type == 'click':
        if not _has_vlan_range(dut):
            if config == "del":
                skip_error = True
            for each_port in port_list:
                for vrange in vlan_range_list:
                    [range_min, range_max] = [int(vid)
                                              for vid in vrange.split()]
                    for vid in range(range_min, range_max+1):
                        commands.append("config vlan member {} {} {}".format(
                            config, vid, each_port))
            output = st.config(dut, commands, skip_error_check=skip_error)
            return _check_config_vlan_member_output(output)

        entries = []
        for vrange in vlan_range_list:
            for each_port in port_list:
                command = "config vlan member range {} {} {}".format(
                    config, vrange, each_port)
                entries.append([command, each_port, vrange])

        ver_flag = True
        for [command, each_port, vrange] in entries:
            if not skip_verify:
                # -w option displays warning, turned on so that existing vlans message can be checked
                command += " -w"
            output = st.config(dut, command, skip_error_check=skip_error)
            if not _check_config_vlan_member_output(output, each_port, vrange):
                ver_flag = False

        return ver_flag
    elif cli_type == 'klish':
        new_vrange = ''
        for vrange in vlan_range_list:
            new_vrange += vrange.replace(' ', '-')
            new_vrange += ','
        new_vrange = new_vrange.strip(',')
        for each_port in port_list:
            interface_details = get_interface_number_from_name(each_port)
            commands.append("interface {} {}".format(
                interface_details.get("type"), interface_details.get("number")))
            commands.append('switchport trunk allowed Vlan {} {}'.format(
                operation, new_vrange))
            commands.append('exit')
        try:
            st.config(dut, commands, skip_error_check=skip_error, type=cli_type)
            return True
        except Exception as e:
            st.log(e)
            return False


def config_vlan_members(dut, vlan_list, port_list, config="add", tagged=True, skip_verify=False, cli_type=''):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    Add or remove given member ports to VLANs given as input.
    :param dut:
    :param vlan_list: range of VLAN IDs is can be list of strings.
    :param port_list: port or list of ports which needs to be added / deleted to vlan_range
    :param config: flag which specifies to configure or unconfigure the cli.
                        add for config, del for unconfig. Default:add
    :param skip_verify: True | False
    :param tagged:
    :param cli_type:
    :return True: Member ports successfully added or deleted to vlan range.
    :return False: Error in parameter passed.
    """
    if config == "del":
        st.log("Deleting member ports from range of vlans")
    else:
        st.log("Adding member ports to range of vlans")

    vlan_li = list(vlan_list) if isinstance(vlan_list, list) else [vlan_list]
    port_li = list(port_list) if isinstance(port_list, list) else [port_list]

    ver_flag = True
    for vlan in vlan_li:
        if cli_type == "click":
            for each_port in port_li:
                command = "config vlan member {} {} {}".format(
                    config, vlan, each_port)
                if not tagged:
                    command += " -u"
                output = st.config(dut, command)
                if "is already a member of Vlan" in output:
                    st.error("{} is already a member of Vlan{}".format(
                        each_port, vlan))
                    ver_flag = False
                if "doesn't exist" in output:
                    st.error(" Vlan{} doesn't exist".format(vlan))
                    ver_flag = False
        elif cli_type in ["klish", "rest-put", "rest-patch"]:
            no_form = True if config == "del" else False
            add_vlan_member(dut, vlan, port_li, tagging_mode=tagged, skip_error=False, no_form=no_form,
                            cli_type=cli_type)
        else:
            st.log("UNSUPPORTED CLI TYPE")
            return False
    return ver_flag


def create_multiple_vlans_and_members(dut, data, cli_type=''):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """
    :param dut:
    :param data: {'G7': {'normal_vlan': {'vlans': [1577, 1578, 1579],
    'members':['Ethernet0', 'PortChannel3', 'PortChannel5', 'PortChannel4']},
    'peer_vlan': {'vlans': 1580, 'members': ['Ethernet12', 'PortChannel2']}},
    'G6':{'normal_vlan': {'vlans': [1577, 1578, 1579],
    'members': ['Ethernet0', 'PortChannel5', 'Ethernet24']}},
    'G4': {'normal_vlan': {'vlans': [1577,    1578, 1579],
    'members': ['Ethernet120', 'PortChannel2', 'PortChannel3',    'PortChannel4', 'Ethernet112']},
    'peer_vlan': {'vlans': 1581, 'members':   ['PortChannel1']}},
    'G3': {'normal_vlan': {'vlans': [1577, 1578, 1579],
    'members': ['Ethernet120', 'PortChannel3', 'PortChannel5', 'PortChannel4']},
    'peer_vlan': {'vlans': 1580, 'members': ['Ethernet0', 'PortChannel2']}},
    'G8': {'normal_vlan': {'vlans': [1577, 1578, 1579],
    'members': ['Ethernet0',  'PortChannel2', 'PortChannel3', 'PortChannel4']},
    'peer_vlan': {'vlans':1581, 'members': ['PortChannel1']}}}
    :return: True | False
    """
    for _, value in data[dut].items():
        create_vlan(dut, value["vlans"], cli_type=cli_type)
        if not config_vlan_members(dut, value["vlans"], value["members"], cli_type=cli_type):
            st.log("ADDING MEMBERS {} to VLAN {} FAILED".format(
                value["members"], value["vlans"]))
            st.report_fail("vlan_tagged_member_fail",
                           value["members"], value["vlans"])
    return True


def show_vlan_from_rest_response(rest_response):
    output = list()
    vlans_output = dict()
    participation_output = list()
    for _, value in rest_response.items():
        if isinstance(value, list):
            for intf_data in value:
                vlan_data = dict()
                vlan_participation_data = dict()
                if "Vlan" in intf_data.get("name"):
                    vlan_data["vid"] = intf_data.get("name")
                    vlan_data["status"] = intf_data.get(
                        "state")["admin-status"] if "admin-status" in intf_data.get("state") else ""
                if intf_data.get("openconfig-if-ethernet:ethernet"):
                    if intf_data["openconfig-if-ethernet:ethernet"].get("openconfig-vlan:switched-vlan"):
                        vlan_participation_data[intf_data["name"]] = dict()
                        vlan_config = intf_data["openconfig-if-ethernet:ethernet"][
                            "openconfig-vlan:switched-vlan"]["config"]
                        if vlan_config.get("access-vlan"):
                            vlan_participation_data[intf_data["name"]
                                                    ]["untagged"] = vlan_config["access-vlan"]
                        if vlan_config.get("trunk-vlans"):
                            vlan_participation_data[intf_data["name"]
                                                    ]["tagged"] = vlan_config["trunk-vlans"]
                if intf_data.get("openconfig-if-aggregate:aggregation"):
                    if intf_data["openconfig-if-aggregate:aggregation"].get("openconfig-vlan:switched-vlan"):
                        vlan_participation_data[intf_data["name"]] = dict()
                        vlan_config = intf_data["openconfig-if-aggregate:aggregation"][
                            "openconfig-vlan:switched-vlan"]["config"]
                        if vlan_config.get("access-vlan"):
                            vlan_participation_data[intf_data["name"]
                                                    ]["untagged"] = vlan_config["access-vlan"]
                        if vlan_config.get("trunk-vlans"):
                            vlan_participation_data[intf_data["name"]
                                                    ]["tagged"] = vlan_config["trunk-vlans"]
                if vlan_data:
                    vlans_output.update({intf_data.get("name"): vlan_data})
                if vlan_participation_data:
                    participation_output.append(vlan_participation_data)
    if participation_output:
        for participation in participation_output:
            for member, tag_data in participation.items():
                if tag_data.get("untagged"):
                    vlan_output = dict()
                    vlan_output["mode"] = "untagged"
                    vlan_output["vid"] = str(tag_data.get("untagged"))
                    vlan_output["member"] = member
                    vlan_output["status"] = vlans_output["Vlan{}".format(
                        vlan_output["vid"])]["status"]
                    output.append(vlan_output)
                if tag_data.get("tagged"):
                    for vlan_id in tag_data.get("tagged"):
                        vlan_output = dict()
                        vlan_output["mode"] = "tagged"
                        vlan_output["vid"] = str(vlan_id)
                        vlan_output["member"] = member
                        vlan_output["status"] = vlans_output["Vlan{}".format(
                            vlan_id)]["status"]
                        output.append(vlan_output)
    elif vlans_output:
        for vlan_id, vlan_status in vlans_output.items():
            vlan_output = dict()
            vlan_output["vid"] = vlan_id.strip("Vlan")
            vlan_output["status"] = vlan_status["status"]
            vlan_output["member"] = ""
            vlan_output["mode"] = ""
            if vlan_output:
                output.append(vlan_output)
    return output
