# This file contains the list of API's which performs Port channel operations.
# Author : Chaitanya Vella (Chaitanya-vella.kumar@broadcom.com)
import re

from spytest import st

from apis.system.rest import config_rest, delete_rest, rest_status
from apis.switching.portchannel_rest import rest_get_per_portchannel_info
from apis.switching.portchannel_rest import rest_get_all_portchannel_info
from apis.switching.portchannel_rest import rest_get_fallback_status

import utilities.common as utils
import utilities.utils as uutils
from utilities.utils import is_a_single_intf, segregate_intf_list_type
from utilities.utils import get_supported_ui_type_list, override_supported_ui
from utilities.utils import cli_type_for_get_mode_filtering, convert_intf_name_to_component
try:
    import apis.yang.codegen.messages.interfaces.Interfaces as umf_intf
    import apis.yang.codegen.messages.aggregate_ext.AggregateExt as umf_aggr_ext
    import apis.yang.codegen.messages.lacp as umf_lacp
    import apis.yang.codegen.messages.network_instance as umf_ni
    from apis.yang.utils.common import Operation
except ImportError:
    pass


errors_list = ['error', 'invalid', 'usage', 'illegal', 'unrecognized']


def force_cli_type_to_klish(cli_type):
    cli_type = "klish" if cli_type in get_supported_ui_type_list() else cli_type
    return cli_type


def create_portchannel(dut, portchannel_list=[], fallback=False, min_link="", static=False, cli_type="", **kwargs):
    """
    API to Create port channel with the provided data
    :param dut:
    :type dut:
    :param portchannel_list:
    :type portchannel_list:
    :return:
    :rtype:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    fast_rate = kwargs.get('fast_rate', False)
    neg_check = kwargs.get('neg_check', False)
    enhance_action = kwargs.get('enhance_action', False)
    config_type = kwargs.get('config_type', 'yes')
    system_mac = kwargs.get('system_mac', False)
    st.log("Creating port channel {} ..".format(portchannel_list), dut=dut)
    if static and fallback:
        st.log("Fallback is not supported for Static LAGs")
        return False
    if cli_type in get_supported_ui_type_list():
        operation = Operation.CREATE
        for portchannel_name in utils.make_list(portchannel_list):
            intf_data = uutils.get_interface_number_from_name(portchannel_name)
            portchannel = "PortChannel{}".format(intf_data["number"])
            lag_obj = umf_intf.Interface(Name=portchannel)
            if enhance_action:
                if min_link:
                    lag_obj.MinLinks = int(min_link)
                if fallback:
                    lag_obj.Fallback = True if config_type == 'yes' else False
                if fast_rate:
                    lag_obj.FastRate = True if config_type == 'yes' else False
                result = lag_obj.configure(dut, operation=operation, cli_type=cli_type)
                from apis.system.interface import interface_noshutdown
                interface_noshutdown(dut, interfaces=portchannel, cli_type=cli_type)
                if not result.ok():
                    st.error("test_step_failed: Failed to Create LAG: {}".format(result.data))
                    return False
            else:
                operation = Operation.CREATE
                if static:
                    lag_obj.LagType = 'STATIC'
                if min_link:
                    lag_obj.MinLinks = int(min_link)
                if fallback:
                    lag_obj.Fallback = True
                if fast_rate:
                    lag_obj.FastRate = True
                result = lag_obj.configure(dut, operation=operation, cli_type=cli_type)
                if not result.ok():
                    st.error("test_step_failed: Failed to Create LAG: {}".format(result.data))
                    return False

            if system_mac:
                lag_obj.SystemMac = system_mac
                if config_type == 'yes':
                    result = lag_obj.configure(dut, cli_type=cli_type)
                else:
                    result = lag_obj.unConfigure(dut, target_attr=lag_obj.SystemMac, cli_type=cli_type)
                if not result.ok():
                    st.error("test_step_failed: Failed to Configure System MAC: {}".format(result.data))
                    return False
        return True
    elif cli_type == "click":
        for portchannel_name in utils.make_list(portchannel_list):
            if not fallback:
                if st.is_feature_supported("config_static_portchannel"):
                    static_flag = "--static=true" if static else "--static=false"
                else:
                    static_flag = ""
                command = "config portchannel add {} {} ".format(portchannel_name, static_flag)
                if min_link:
                    command += "--min-links {}".format(min_link)
            else:
                if static:
                    return False
                if not min_link:
                    command = "config portchannel add {} --fallback=true".format(portchannel_name)
                else:
                    command = "config portchannel add {} --fallback=true --min-links {}".format(portchannel_name, min_link)
            st.config(dut, command, skip_error_check=True)
        return True
    elif cli_type == "klish":
        commands = list()
        for portchannel_name in utils.make_list(portchannel_list):
            intf_data = uutils.get_interface_number_from_name(portchannel_name)
            command = "interface PortChannel {}".format(intf_data["number"])
            if enhance_action:
                commands.append(command)
                if min_link:
                    commands.append("min-links {}".format(min_link)) if config_type == "yes" else commands.append(
                        "no min-links")
                if fallback:
                    commands.append("fallback") if config_type == "yes" else commands.append("no fallback")
                if fast_rate:
                    commands.append("fast_rate") if config_type == "yes" else commands.append("no fast_rate")
                if system_mac:
                    commands.append("system-mac {}".format(system_mac)) if config_type == "yes" else commands.append("no system-mac")
                commands.append("exit")
            else:
                if static:
                    command = "{} mode on".format(command)
                if min_link:
                    command = "{} min-links {}".format(command, min_link)
                if fallback:
                    command = "{} fallback".format(command)
                if fast_rate:
                    command = "{} fast_rate".format(command)
                commands.append(command)
                if system_mac:
                    commands.append("system-mac {}".format(system_mac))
                commands.append("no shutdown")
                commands.append("exit")
        if commands:
            if neg_check:
                response = st.config(dut, commands[0], type=cli_type, skip_error_check=True)
                if "Error" in response:
                    st.log(response)
                    return False
                return True
            else:
                st.config(dut, commands, type=cli_type, skip_error_check=True)
                return True
        return False
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        url = rest_urls['all_interfaces_details']
        for portchannel_name in utils.make_list(portchannel_list):
            intf_data = uutils.get_interface_number_from_name(portchannel_name)
            portchannel = "PortChannel{}".format(intf_data["number"])
            create_pc = {"openconfig-interfaces:interfaces": {"interface": [{"config": {"name": portchannel}, "name": portchannel, "openconfig-if-aggregate:aggregation": {"config": {}}}]}}
            if static:
                create_pc['openconfig-interfaces:interfaces']['interface'][0]['openconfig-if-aggregate:aggregation']['config'].update({'lag-type': 'STATIC'})
            if min_link:
                create_pc['openconfig-interfaces:interfaces']['interface'][0]['openconfig-if-aggregate:aggregation']['config'].update({'min-links': int(min_link)})
            if fallback:
                create_pc['openconfig-interfaces:interfaces']['interface'][0]['openconfig-if-aggregate:aggregation']['config'].update({'openconfig-interfaces-ext:fallback': True})
            if fast_rate:
                create_pc['openconfig-interfaces:interfaces']['interface'][0]['openconfig-if-aggregate:aggregation']['config'].update({'openconfig-if-aggregate:fast-rate': True})
            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=create_pc):
                st.error("Failed to create Port-Channel: {}".format(portchannel_name))
                return False
        return True
    else:
        st.error("Unsupported CLI Type: {}".format(cli_type))
        return False


def delete_portchannel(dut, portchannel_list, **kwargs):
    """
    API to Delete port channel with the provided data
    :param dut:
    :type dut:
    :param portchannel_list:
    :type portchannel_list:
    :return: True	The Portchannel was successfully deleted.
    :return: False  The Portchannel was not successfully deleted.
    :return: False	Error in parameter passed.
    :rtype:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    skip_error = kwargs.get('skip_error', False)
    st.log("Deleting port channel {} ..".format(portchannel_list), dut=dut)
    commands = list()
    rest_fail_status = False
    try:
        for portchannel_name in utils.make_list(portchannel_list):
            if cli_type in get_supported_ui_type_list():
                lag_obj = umf_intf.Interface(Name=portchannel_name)
                result = lag_obj.unConfigure(dut, cli_type=cli_type)
                if not result.ok():
                    st.error("test_step_failed: Failed to Delete PortChannel: {}".format(result.data))
                    return False
            elif cli_type == "click":
                commands.append("config portchannel del {}".format(portchannel_name))
            elif cli_type == "klish":
                intf_data = uutils.get_interface_number_from_name(portchannel_name)
                commands.append("no interface PortChannel {}".format(intf_data["number"]))
            elif cli_type in ["rest-patch", "rest-put"]:
                rest_urls = st.get_datastore(dut, "rest_urls")
                intf_data = uutils.get_interface_number_from_name(portchannel_name)
                portchannel_name = intf_data['type'] + intf_data['number']
                url = rest_urls['per_interface_details'].format(portchannel_name)
                output = delete_rest(dut, rest_url=url, get_response=True)
                if not output:
                    st.error("OUTPUT IS EMPTY FROM DELETE PORTCHANNEL REST CALL")
                    return False
                st.log("STATUS: {}".format(output["status"]))
                if not rest_status(output["status"]):
                    rest_fail_status = True
            else:
                st.log("Unsupported CLI type")
                return False
        if rest_fail_status:
            st.log("One of PC DELETE REST call failed")
            return False
        if commands:
            response = st.config(dut, commands, type=cli_type, skip_error_check=skip_error)
            if "Error" in response:
                st.log(response)
                return False
            for portchannel_name in utils.make_list(portchannel_list):
                if get_portchannel(dut, portchannel_name, cli_type=cli_type):
                    return False
                st.log("Portchannel {} deleted successfully ..".format(portchannel_name), dut=dut)
        return True
    except Exception as e:
        st.error("ERROR: DELETE port channel {} ".format(str(e)))
        return False


def delete_all_portchannels(dut, cli_type=""):
    """
    API to Delete ALL port channels.
    :param dut:
    :type dut:
    :return: True	The Portchannel(s) was successfully deleted.
    :return: False  The Portchannel(s) was not successfully deleted.
    :return: False	Error in parameter passed.
    :rtype:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    available_portchannels = list()
    st.log("Deleting all availabe port channels...", dut=dut)
    for portchannel in get_portchannel_list(dut, cli_type=cli_type):
        if cli_type == "click":
            available_portchannels.append(portchannel["teamdev"])
        elif cli_type in ["klish", "rest-patch", "rest-put"]:
            available_portchannels.append(portchannel["name"])
        else:
            st.error("Unsupported CLI Type: {}".format(cli_type))
            return False
    response = delete_portchannel(dut, available_portchannels, cli_type=cli_type)
    return response


def get_portchannel(dut, portchannel_name="", cli_type="", **kwargs):
    """
    This API is used to get the portchannel details
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param portchannel_name:
    :return:
    FOR KLISH : [{u'group': '1', u'name': 'PortChannel1', u'state': 'D',
    'members': [{u'port_state': 'D', u'port': 'Ethernet56'}, {u'port_state': 'U', u'port': 'Ethernet60'}],
    u'protocol': 'LACP', u'type': 'Eth'}, {u'group': '10', u'name': 'PortChannel10', u'state': 'U',
    'members': [{u'port_state': 'D', u'port': 'Ethernet40'}], u'protocol': 'LACP', u'type': 'Eth'},
    {u'group': '111', u'name': 'PortChannel111', u'state': 'D', 'members': [], u'protocol': 'LACP', u'type': 'Eth'}]
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    yang_data_type = kwargs.get("yang_data_type", "ALL")
    format = kwargs.get("format", True)
    st.log("Getting port channel {} details ...".format(portchannel_name), dut=dut)
    result = dict()
    try:
        if not portchannel_name:
            st.log("Please provide portchannel")
            return False
        if cli_type in get_supported_ui_type_list():
            lag_obj = umf_intf.Interface(Name=portchannel_name)
            if cli_type in cli_type_for_get_mode_filtering():
                query_params_obj = utils.get_query_params(yang_data_type=yang_data_type, cli_type=cli_type)
                rv = lag_obj.get_payload(dut, query_param=query_params_obj, cli_type=cli_type)
            else:
                rv = lag_obj.get_payload(dut, cli_type=cli_type)
            if rv.ok():
                if yang_data_type == "ALL" and format is True:
                    output = _parse_portchannel_data(rv.payload)
                    if output:
                        if output[0].get("protocol") == "LACP":
                            member_data = get_gnmi_portchannel_member_data(dut, portchannel_name, yang_data_type=yang_data_type, format=True)
                        else:
                            member_data = get_gnmi_static_pc_members(dut, rv.payload)
                        output[0]["members"] = list()
                        if member_data:
                            output[0]["members"] = member_data
                        return output
                    return []
                else:
                    return rv.payload
            else:
                return []
        elif cli_type == "click":
            command = "show interfaces portchannel | grep -w {}".format(portchannel_name)
            rv = st.show(dut, command)
            return rv
        elif cli_type == "klish":
            channel_number = uutils.get_interface_number_from_name(portchannel_name)["number"]
            command = "show interface PortChannel {}".format(channel_number)
            output = st.show(dut, command, type=cli_type)
            if output:
                result["group"] = output[0]["channel_number"]
                result["min_links"] = output[0]["min_links"]
                result["fallback_state"] = output[0]["fallback"]
                result["name"] = portchannel_name
                if output[0]["protocol_state"] == "up":
                    result["state"] = 'U'
                elif output[0]["protocol_state"] == "down":
                    result["state"] = 'D'
                result["protocol"] = output[0]["mode"]
                result["members"] = list()
                for each in output:
                    member_list = each["members"]
                    for each_member in member_list:
                        members_dict = dict()
                        if each_member:
                            if "Selected" in each_member:
                                members_dict["port_state"] = 'U'
                            else:
                                members_dict["port_state"] = 'D'
                            members_dict["port"] = each_member.replace("(Selected)", "")
                            result["members"].append(members_dict)
            else:
                st.log("Portchannel {} not found".format(portchannel_name))
                return False
            return [result]
        elif cli_type in ["rest-put", "rest-patch"]:
            result = rest_get_per_portchannel_info(dut, portchannel_name)
            return result
        else:
            st.error("Unsupported CLI Type: {}".format(cli_type))
            return False
    except Exception as e:
        st.error("EXCEPTION: Get PortChannel {}".format(str(e)))
        return False


def delete_portchannels(dut, portchannel_list, cli_type=""):
    """
    API to Delete port channel with the provided data
    :param dut:
    :type dut:
    :param portchannel_list:
    :type portchannel_list:
    :return: True      The Portchannel was successfully deleted.
    :return: False  The Portchannel was not successfully deleted.
    :return: False     Error in parameter passed.
    :rtype:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    st.log("Deleting port channel {} ..".format(portchannel_list), dut=dut)
    commands = []
    try:
        for portchannel_name in utils.make_list(portchannel_list):
            if cli_type in get_supported_ui_type_list():
                result = delete_portchannel(dut, portchannel_list=portchannel_name, cli_type=cli_type)
                if not result:
                    return result
            elif cli_type == "click":
                command = "config portchannel del {}".format(portchannel_name)
                response = st.config(dut, command)
                if "Error" in response:
                    st.log(response)
                    return False
            elif cli_type == "klish":
                commands.append("no interface PortChannel {}".format(portchannel_name.replace("PortChannel", "")))
            elif cli_type in ["rest-put", "rest-patch"]:
                if not delete_portchannel(dut, portchannel_list=portchannel_name, cli_type=cli_type):
                    st.error("Failed to delete Port-Channel: {}".format(portchannel_name))
                    return False
            else:
                st.error("Unsupported CLI TYPE {}".format(cli_type))
                return False
        if commands:
            st.config(dut, commands, type=cli_type)
        return True
    except Exception as e:
        st.error("EXCEPTION: DELETE port channel {} ".format(str(e)))
        return False


def verify_portchannel(dut, portchannel_name, cli_type="", **kwargs):
    """
    This API is used to verify whether the given portchannel exists or not.
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param dut:
    :param portchannel_name:
    :return:
    """
    yang_data_type = kwargs.get("yang_data_type", "ALL")
    depth = kwargs.get("depth", 3)
    verify = kwargs.get("verify", False)
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    st.log("Verifying port channel {} ...".format(portchannel_name), dut=dut)
    if not verify:
        details = get_portchannel(dut, portchannel_name, cli_type=cli_type)
    else:
        if cli_type in get_supported_ui_type_list():
            lag_obj = umf_intf.Interface(Name=portchannel_name)
            query_params_obj = utils.get_query_params(yang_data_type=yang_data_type, depth=depth, cli_type=cli_type)
            if yang_data_type in ["ALL", "CONFIG"]:
                rv = lag_obj.verify(dut, target_path="config", query_param=query_params_obj)
            elif yang_data_type in ["OPERATIONAL", "NON_CONFIG"]:
                rv = lag_obj.verify(dut, query_param=query_params_obj, match_subset=True)
            return True if rv.ok() else False
    return False if not details else True


def get_portchannel_list(dut, cli_type=""):
    """
    This API is used to get the list of portchannel details
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param dut:
    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    if dut:
        st.log("Getting all the list of port channels ..", dut=dut)
        if cli_type == "click":
            command = "show interfaces portchannel"
            response = st.show(dut, command)
            return response
        elif cli_type == "klish":
            result = dict()
            command = "show PortChannel summary"
            output = st.show(dut, command, type=cli_type)
            if output:
                for data in output:
                    portchannel_data = dict()
                    portchannel_data["members"] = list()
                    members = dict()
                    for key, value in data.items():
                        if key not in ["port", "port_state"]:
                            portchannel_data[key] = value
                        else:
                            if value:
                                members[key] = value
                    if members:
                        portchannel_data["members"].append(members)
                    if portchannel_data:
                        if portchannel_data['name'] not in result:
                            result[portchannel_data["name"]] = portchannel_data
                        else:
                            result[portchannel_data["name"]]["members"].append(members)
            response = list()
            if result:
                for _, pc_data in result.items():
                    response.append(pc_data)
            return response
        elif cli_type in ["rest-put", "rest-patch"]:
            result = rest_get_all_portchannel_info(dut)
            return result
        else:
            st.error("Unsupported CLI Type: {}".format(cli_type))
            return False
    else:
        st.error("Get PortChannel List Invalid DUT object")
        return False


def add_portchannel_member(dut, portchannel="", members=[], cli_type=""):
    """
    This API is used to add the members to portchannel
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param dut:
    :param portchannel:
    :param members:
    :return:
    """
    return add_del_portchannel_member(dut, portchannel, members, flag="add", cli_type=cli_type)


def get_portchannel_members(dut, portchannel, with_state=False, cli_type="", **kwargs):
    """
    This API is used to get the members of portchannel
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param dut:
    :param portchannel:
    :param with_state:
    :return:
    """
    st.log("Getting portchannel members ...", dut=dut)
    if not portchannel:
        st.error("PortChannel Member GET Error: Missing portchannel name")
        return False

    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    yang_data_type = kwargs.get("yang_data_type", "ALL")
    format = kwargs.get("format", True)
    portchannel_details = get_portchannel(dut, portchannel, cli_type=cli_type, yang_data_type=yang_data_type, format=format)
    st.debug(portchannel_details)
    if not portchannel_details:
        st.warn("Port Channel Members GET: PortChannel {} not found".format(portchannel))
        return False

    if cli_type == "click":
        ports = portchannel_details[0].get("ports")
        if not ports:
            st.error("Members not found in mentioned portchannel")
            return False
        if with_state:
            return ports.split(" ")
        ports = re.sub(r"\(.*?\)", "", ports)
        return re.findall(r'[\w./]+', ports)

    if cli_type in ["klish", "rest-put", "rest-patch"] + get_supported_ui_type_list():
        members = list()
        if "members" in portchannel_details[0]:
            for member in portchannel_details[0]["members"]:
                if not with_state:
                    members.append(member.get("port"))
                else:
                    members.append("{}({})".format(member.get("port"), member.get("port_state")))
            st.log(members)
            return members
        else:
            st.log("Members not found")
            return False

    st.error("Unsupported CLI Type: {}".format(cli_type))
    return False


def verify_portchannel_member(dut, portchannel, members, flag='add', cli_type="", **kwargs):
    """
    This API is used to verify the members of portchannel
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param dut:
    :param portchannel:
    :param members:
    :param flag:
    :return:
    """
    yang_data_type = kwargs.get("yang_data_type", "ALL")
    depth = kwargs.get("depth", 3)
    verify = kwargs.get("verify", False)
    cli_type = st.get_ui_type(dut, cli_type=cli_type)

    st.log("Verifying port channel members ...", dut=dut)
    if not verify or flag != 'add':
        portchannel_members = get_portchannel_members(dut, portchannel, cli_type=cli_type)
        if flag == 'add':
            if not portchannel_members:
                st.error("ERROR in port channel members")
                return False
            for member in utils.make_list(members):
                if member not in portchannel_members:
                    return False
            return True
        elif flag == 'del':
            for member in utils.make_list(members):
                if member in portchannel_members:
                    return False
            return True
    else:
        # not validating input members list
        portchannel_details = get_portchannel(dut, portchannel, cli_type=cli_type)
        if portchannel_details:
            return verify_gnmi_portchannel_member_data(dut, portchannel_details, members, yang_data_type=yang_data_type,
                                                       depth=depth)
        else:
            return False


def add_del_portchannel_member(dut, portchannel, members, flag="add", skip_verify=True, cli_type="", skip_err_check=False):
    """
    This API is used to add or delete the members of the portchannel
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param dut:
    :param portchannel:
    :param members:
    :param flag:
    :param skip_verify:
    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    if flag != "add" and flag != "del":
        st.error("Invalid input to add del portchannel member internal api call...")
        return False

    action = "Adding" if flag == "add" else "Deleting"
    if not portchannel:
        st.error("Port Channel Member {} Error: Missing portchannel name".format(action))
        return False

    st.log("{} port channel member(s) {} ...".format(action, members), dut=dut)
    if cli_type in get_supported_ui_type_list():
        channel_number = uutils.get_interface_number_from_name(portchannel)["number"]
        port_hash_list = segregate_intf_list_type(intf=members, range_format=False)
        members = port_hash_list['intf_list_all']
        for interface in utils.make_list(members):
            enable_flag = True if flag == 'add' else False
            pc_obj = umf_intf.Interface(Name=interface, AggregateId=portchannel, InterfaceEnabled=enable_flag)
            if flag == "add":
                result = pc_obj.configure(dut, cli_type=cli_type)
            else:
                result = pc_obj.unConfigure(dut, target_attr=pc_obj.AggregateId, cli_type=cli_type)
            if not result.ok():
                st.error("test_step_failed: Failed to {} Members to LAG: {}".format(action, result.data))
                return False

    elif cli_type == "click":
        if not skip_verify:
            portchannel_details = get_portchannel(dut, portchannel, cli_type=cli_type)
            if not portchannel_details:
                st.warn("Port Channel Members {}: PortChannel {} not found".format(action, portchannel))
                return False
        port_hash_list = segregate_intf_list_type(intf=members, range_format=False)
        members = port_hash_list['intf_list_all']
        members = utils.make_list(uutils.convert_intf_name_to_component(dut, members, component="applications"))
        for member in utils.make_list(members):
            command = "config portchannel member {} {} {}".format(flag, portchannel, member)
            response = st.config(dut, command, skip_error_check=skip_err_check)
            if any(error in response.lower() for error in errors_list):
                st.error("The response is: {}".format(response))
                return False
            if not skip_verify:
                if flag == 'add':
                    if not verify_portchannel_member(dut, portchannel, member, flag):
                        st.error("Member {} not present in port channel member list {}".format(member, portchannel))
                        return False
                else:
                    if not verify_portchannel_member(dut, portchannel, member, flag):
                        st.error("Member {} present in port channel member list {}".format(member, portchannel))
                        return False
    elif cli_type == "klish":
        commands = list()
        port_hash_list = segregate_intf_list_type(intf=members, range_format=True)
        members = port_hash_list['intf_list_all']
        for member in utils.make_list(members):
            if not is_a_single_intf(member):
                commands.append("interface range {}".format(member))
            else:
                intf_details = uutils.get_interface_number_from_name(member)
                if not intf_details:
                    st.log("Interface data not found for {} ".format(member))
                commands.append("interface {} {}".format(intf_details["type"], intf_details["number"]))
            if flag == "add":
                channel_number = uutils.get_interface_number_from_name(portchannel)["number"]
                commands.append("channel-group {}".format(channel_number))
            else:
                commands.append("no channel-group")
            commands.append("exit")
        if commands:
            response = st.config(dut, commands, type=cli_type, skip_error_check=skip_err_check)
            if any(error in response.lower() for error in errors_list):
                st.error("The response is: {}".format(response))
                return False
    elif cli_type in ["rest-put", "rest-patch"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        rest_fail_status = False
        channel_number = uutils.get_interface_number_from_name(portchannel)["number"]
        port_hash_list = segregate_intf_list_type(intf=members, range_format=False)
        members = port_hash_list['intf_list_all']
        for interface in utils.make_list(members):
            url = rest_urls['pc_member_add_del'].format(interface)
            if flag == "add":
                add_member = {"openconfig-if-aggregate:aggregate-id": "string"}
                member_status = {"openconfig-interfaces:enabled": False}
                add_member["openconfig-if-aggregate:aggregate-id"] = "{}".format(portchannel)
                if "put" in cli_type:
                    url_put = rest_urls['per_interface_config_enable'].format(interface)
                    if not config_rest(dut, http_method=cli_type, rest_url=url_put, json_data=member_status):
                        return False
                if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=add_member):
                    return False
                if "put" in cli_type:
                    member_status["openconfig-interfaces:enabled"] = True
                    if not config_rest(dut, http_method=cli_type, rest_url=url_put, json_data=member_status):
                        return False
            else:
                output = delete_rest(dut, rest_url=url, get_response=True)
                if not output:
                    st.error("OUTPUT IS EMPTY FROM DELETE PC MEMBER REST CALL")
                    return False
                st.log("STATUS: {}".format(output["status"]))
                if not rest_status(output["status"]):
                    rest_fail_status = True
        if rest_fail_status:
            st.log("One of PC member DELETE REST call failed")
            return False
    else:
        st.error("Unsupported CLI Type: {}".format(cli_type))
        return False
    return True


def delete_portchannel_member(dut, portchannel, members, cli_type=""):
    """
    This API is used to delete the member of the portchannel
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param portchannel:
    :param members:
    :return:
    """
    return add_del_portchannel_member(dut, portchannel, members, flag="del", cli_type=cli_type)


def verify_portchannel_state(dut, portchannel, state="up", error_msg=True, cli_type=""):
    """
    This API is used to verify the portchannel state
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param portchannel:
    :param state:
    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    STATE = state.capitalize()
    st.log("Verifying portchannel state with provided state {}...".format(STATE), dut=dut)
    supported_states = ['up', 'down']
    if state not in supported_states:
        st.error("Invalid states provided in verify portchannel state")
        return False

    if not portchannel:
        st.error("Port Channel state verification Error: Missing portchannel name")
        return False

    portchannel_details = get_portchannel(dut, portchannel, cli_type=cli_type)
    if not portchannel_details:
        st.error("PortChannel {} not found".format(portchannel))
        return False

    if cli_type == "click":
        state = "Up" if state == "up" else "Dw"
        state_match = r'LACP\(A\)\({0}\)|NONE\(A\)\({0}\)'.format(state) if cli_type == "click" else r'LACP|NONE'
        for details in portchannel_details:
            if 'protocol' in details:
                if not re.match(state_match, details['protocol']):
                    st.log("Portchannel state is {} ...".format(STATE))
                    if error_msg:
                        st.error("Portchannel state verification failed with state {}".format(STATE))
                    return False
                else:
                    st.log("Portchannel state is {} ...".format(STATE))
                    if error_msg:
                        st.log("Portchannel state verification passed with state {}".format(STATE))
    elif cli_type in ["klish", "rest-put", "rest-patch"] + get_supported_ui_type_list():
        state = "U" if state == "up" else "D"
        for details in portchannel_details:
            if details["name"] != portchannel:
                st.log("Portchannel name is not matching")
                return False
            if details["state"] != state:
                st.log("Mismatch in portchannel state {} and expecting {}".format(details["state"], state))
                return False
    else:
        st.log("UNSUPPORTED CLI Type - {}".format(cli_type))
        return False
    return True


def poll_for_portchannel_status(dut, portchannel, state="up", iteration=90, delay=1, cli_type=""):
    """
    API to poll for portchannel state
    :param dut:
    :param portchannel:
    :param state:
    :param iteration:
    :param delay:
    :return:
    """
    i = 0
    while True:
        if verify_portchannel_state(dut, portchannel, state, False, cli_type=cli_type):
            st.log("Observed port channel {} with state as {}".format(portchannel, state))
            return True
        if i > iteration:
            st.log("Max iteration count reached {}".format(i))
            return False
        i += 1
        st.wait(delay)


def verify_portchannel_member_state(dut, portchannel, members_list, state='up', cli_type=""):
    """
    This API is used to verify the member state of a portchannel
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param dut:
    :param portchannel:
    :param members_list:
    :param state:
    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    st.log("Verifying portchannel state with provided state ...", dut=dut)

    supported_states = ['up', 'down']
    if state not in supported_states:
        st.error("Invalid states provided in verify portchannel state")
        return False

    if not portchannel:
        st.error("Port Channel state verification Error: Missing portchannel name")
        return False

    members = get_portchannel_members(dut, portchannel, True, cli_type=cli_type)
    if not members:
        st.error("PortChannel {} members {} not found".format(portchannel, members))
        return False

    if cli_type == "click":
        member_state = 'S' if state == 'up' else 'D'
    elif cli_type in ["klish", "rest-put", "rest-patch"] + get_supported_ui_type_list():
        member_state = 'U' if state == 'up' else 'D'
    else:
        st.log("UNSUPPORTED CLI Type - {}".format(cli_type))
        return False
    STATE = state.capitalize()
    for member in utils.make_list(members_list):
        member_state_match = '{}({})'.format(member, member_state)
        if member_state_match not in members:
            st.error("Portchannel member {} state verification failed with state {}".format(member, STATE))
            return False

    st.log("Portchannel all member state verification successful with state {}".format(STATE), dut=dut)
    return True


def verify_portchannel_fallback(dut, portchannel, cli_type=""):
    """
    This API is used to verify the portchannel fallback functionality
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param dut:
    :param portchannel:
    :return:
    """
    # cli_type = st.get_ui_type(dut, cli_type=cli_type)
    command = "teamdctl {} config dump".format(portchannel)
    st.config(dut, command)


def _clear_portchannel_configuration_helper(dut_list, cli_type=""):
    """
    This is the helper function to clear the portchannel configuration
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param dut_list:
    :return:
    """
    dut_li = list(dut_list) if isinstance(dut_list, list) else [dut_list]
    for dut in dut_li:
        st.log("############## {} : Port Channel Cleanup ################".format(dut))
        cli_type = st.get_ui_type(dut, cli_type=cli_type)
        portchannel_list = get_portchannel_list(dut, cli_type=cli_type)
        if portchannel_list:
            for portchannel in portchannel_list:
                portchannel_name = portchannel["teamdev"] if cli_type == "click" else portchannel["name"]
                portchannel_member = get_portchannel_members(dut, portchannel_name)

                if portchannel_member:
                    if not delete_portchannel_member(dut, portchannel_name, portchannel_member):
                        st.log("Error while deleting portchannel members")
                        return False
                if not config_portchannel_ethernet_segment(dut, portchannel_name, config_type='no', cli_type="klish", skip_error="True"):
                    st.log("PortChannel ethernet-segment config deletion failed {}".format(portchannel_name))
                if not delete_portchannel(dut, portchannel_name):
                    st.log("Portchannel deletion failed {}".format(portchannel_name))
                    return False
    return True


def clear_portchannel_configuration(dut_list, thread=True, cli_type=""):
    """
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut_list:
    :param thread: True (Default) / False
    :return:
    """
    if not thread:
        return _clear_portchannel_configuration_helper(dut_list, cli_type)
    out = st.exec_each(utils.make_list(dut_list), _clear_portchannel_configuration_helper, cli_type=cli_type)[0]
    return False if False in out else True


def verify_portchannel_and_member_status(dut, portchannel, members, iter_count=6, iter_delay=1, state='up', cli_type=""):
    """
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param portchannel:
    :param members:
    :param iter_count:
    :param iter_delay:
    :param state:
    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    if cli_type == "click":
        members = utils.make_list(convert_intf_name_to_component(dut, members, component="applications"))

    if not verify_portchannel(dut, portchannel, cli_type=cli_type):
        st.log("Port channel {} not present".format(portchannel))
        return False

    if not verify_portchannel_member(dut, portchannel, members, 'add', cli_type=cli_type):
        st.log("Members are not added to the Port channel {}".format(portchannel))
        return False

    i = 1
    while True:
        st.log("Checking port channel member status iteration {}".format(i), dut=dut)
        if verify_portchannel_member_state(dut, portchannel, members, state, cli_type=cli_type):
            st.log("All members of port channel are {}".format(state))
            return True
        if i > iter_count:
            st.log("Exiting from the loop.. iter_count reaches max {}".format(i))
            return False
        i += 1
        st.wait(iter_delay)


def _config_portchannel(dut, portchannel_name, members, config='add', cli_type=""):
    """
    Configure the port channel between 2 devices and add member to it.
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param portchannel_name:
    :param members:
    :param config:
    :return:
    """
    if config == "add":
        create_portchannel(dut, portchannel_name, cli_type=cli_type)
        if not add_portchannel_member(dut, portchannel_name, members, cli_type=cli_type):
            return False
    else:
        if not delete_portchannel_member(dut, portchannel_name, members, cli_type=cli_type):
            st.error("PortChannel member deletion failed")
            return False
        if not delete_portchannel(dut, portchannel_name, cli_type=cli_type):
            return False
    return True


def config_portchannel(dut1, dut2, portchannel_name, members_dut1, members_dut2, config='add', thread=True, cli_type=""):
    """
    Configure the port channel between 2 devices and add member to it.
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut1:
    :param dut2:
    :param portchannel_name:
    :param members_dut1: member or list of members
    :param members_dut2: member or list of members
    :param config: add | del
    :param thread: True | False
    :return:
    """
    [out, _] = st.exec_all([[_config_portchannel, dut1, portchannel_name, members_dut1, config, cli_type],
                            [_config_portchannel, dut2, portchannel_name, members_dut2, config, cli_type]])
    return False if False in out else True


def config_portchannel_gshut(dut, **kwargs):
    '''
    Author: Sneha Ann Mathew
    email: sneha.mathew@broadcom.com
    Global  command to configure PortChannel Graceful shutdown and interface specific gshut configs
    :param dut:
    :param kwargs:
    :return:

    Usage:
    config_po_graceful_shutdown(dut1)
    config_po_graceful_shutdown(dut1,exception_po_list='PortChannel10')
    config_po_graceful_shutdown(dut1,config_mode='del')
    config_po_graceful_shutdown(dut1,config_mode='del',exception_po_list='PortChannel10')
    ### To disable/enable po gshut only on individual POs.
    ### This will be in effect only if global PO GSHUT enable already configured
    ## 1) To enable PO GSHUT at interface level, config_mode='del',as u need to negate global action
    config_po_graceful_shutdown(dut1,config_level='interface',config_mode='del',\
                                exception_po_list=["PortChannel10","PortChannel11"])
    ## 2) To disable PO GSHUT at interface level, config_mode='add' [default option with global mode]
    config_po_graceful_shutdown(dut1,config_level='interface',config_mode='add',\
                                exception_po_list=["PortChannel10","PortChannel11"])
    '''
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut))

    config_mode = kwargs.pop('config', 'add')
    config_level = kwargs.pop('config_level', 'global')
    if config_level == 'interface' and 'exception_po_list' not in kwargs:
        st.error("Mandatory parameter exception_po_list not found for config_level:interface")
        return False

    cmd = []
    if 'exception_po_list' in kwargs:
        exception_po_list = kwargs['exception_po_list']
        exception_po_list = [exception_po_list] if isinstance(exception_po_list, str) else exception_po_list

    if cli_type in get_supported_ui_type_list():
        global_config_str = 'disable' if config_mode == 'del' else 'enable'
        po_config_str = 'disable' if config_mode == 'add' else 'enable'
        if 'exception_po_list' in kwargs:
            port_hash_list = segregate_intf_list_type(intf=exception_po_list, range_format=False)
            exception_po_list = port_hash_list['intf_list_all']
            for po in exception_po_list:
                lag_obj = umf_intf.Interface(Name=po, GracefulShutdownMode=po_config_str.upper())
                result = lag_obj.configure(dut, cli_type=cli_type)
                if not result.ok():
                    st.error('test_step_failed: GNMI: Configure GSHUT at interface: {}'.format(result.data))
                    return False

        if config_level == 'global':
            lag_gbl_obj = umf_aggr_ext.Aggregate(GracefulShutdownMode=global_config_str.upper())
            result = lag_gbl_obj.configure(dut, cli_type=cli_type)
            if not result.ok():
                st.error('test_step_failed: GNMI: Configure GSHUT globally: {}'.format(result.data))
                return False
        return True

    if cli_type == 'click':
        global_config_str = 'disable' if config_mode == 'del' else 'enable'
        po_config_str = 'disable' if config_mode == 'add' else 'enable'
        if 'exception_po_list' in kwargs:
            port_hash_list = segregate_intf_list_type(intf=exception_po_list, range_format=False)
            exception_po_list = port_hash_list['intf_list_all']
            for po in exception_po_list:
                cmd.append("config portchannel graceful-shutdown {} {}".format(po_config_str, po))
        if config_level == 'global':
            cmd.append("config portchannel graceful-shutdown {}".format(global_config_str))
    elif cli_type == 'klish':
        global_config_str = 'no ' if config_mode == 'del' else ''
        po_config_str = 'no ' if config_mode == 'add' else ''
        if 'exception_po_list' in kwargs:
            port_hash_list = segregate_intf_list_type(intf=exception_po_list, range_format=True)
            exception_po_list = port_hash_list['intf_list_all']
            for po in exception_po_list:
                if not is_a_single_intf(po):
                    cmd.append("interface range {}".format(po))
                else:
                    po_int = uutils.get_interface_number_from_name(po)
                    cmd.append("interface {} {}".format(po_int['type'], po_int['number']))
                cmd.append("{}graceful-shutdown".format(po_config_str))
                cmd.append("exit")
        if config_level == 'global':
            cmd.append("{}portchannel graceful-shutdown".format(global_config_str))
    elif cli_type in ['rest-put', 'rest-patch']:
        # ONLY global gshut handles now.
        global_config_str = 'disable' if config_mode == 'del' else 'enable'
        po_config_str = 'disable' if config_mode == 'add' else 'enable'
        rest_urls = st.get_datastore(dut, "rest_urls")
        global_url = rest_urls['po_gshut_config']
        if 'exception_po_list' in kwargs:
            port_hash_list = segregate_intf_list_type(intf=exception_po_list, range_format=False)
            exception_po_list = port_hash_list['intf_list_all']
        if config_mode == 'add':
            if 'exception_po_list' in kwargs:
                intf_payload = {"openconfig-interfaces-ext:graceful-shutdown-mode": po_config_str.upper()}
                for po in exception_po_list:
                    interface_url = rest_urls['po_ghsut_intf_config'].format(po)
                    if not config_rest(dut, http_method=cli_type, rest_url=interface_url, json_data=intf_payload):
                        st.banner('FAIL-OCYANG: Failed to unconfigure PO gshut at interface level')
                        return False
            if config_level == 'global':
                payload = {"openconfig-aggregate-ext:graceful-shutdown-mode": global_config_str.upper()}
                if not config_rest(dut, http_method=cli_type, rest_url=global_url, json_data=payload):
                    st.banner('FAIL-OCYANG: Config PO gshut globally Failed')
                    return False
        elif config_mode == 'del':
            if 'exception_po_list' in kwargs:
                intf_payload = {"openconfig-interfaces-ext:graceful-shutdown-mode": po_config_str.upper()}
                for po in exception_po_list:
                    interface_url = rest_urls['po_ghsut_intf_config'].format(po)
                    if not config_rest(dut, http_method=cli_type, rest_url=interface_url, json_data=intf_payload):
                        st.banner('FAIL-OCYANG: Failed to configure PO gshut at interface level')
                        return False
            if config_level == 'global':
                if not delete_rest(dut, rest_url=global_url):
                    st.banner('FAIL-OCYANG:UnConfig  PO gshut globally Failed')
        return
    else:
        st.error("UNSUPPORTED cli_type")
        return
    st.config(dut, cmd, type=cli_type)


def verify_lacp_fallback(dut, **kwargs):
    """
    Author: Chandra Sekhar Reddy
    email: chandra.vedanaparthi@broadcom.com
    Verify show interfaces portchannel <portchannel-name> fallback output
    :param dut:
    :param kwargs: Parameters can be <port_channel_name|fallback_config|fallback_oper_status>
    :param kwargs:port_channel_name is mandatory
    :return:

    Usage:

    verify_lacp_fallback(dut1,port_channel_name='PortChannel10", fallback_config='Enabled', fallback_oper_status='Disabled')
    verify_lacp_fallback(dut1,port_channel_name='PortChannel10", fallback_config='Enabled', fallback_oper_status='Enabled')
    verify_lacp_fallback(dut1,port_channel_name='PortChannel10", fallback_config='Disabled', fallback_oper_status='Disabled')
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    kwargs.pop('cli_type', None)
    # Forcing to klish due to JIRA-59697
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    ret_val = True

    if 'port_channel_name' not in kwargs:
        st.error("Mandatory argument Port Channel name Not Found")
        return False
    if cli_type in get_supported_ui_type_list():
        output = get_portchannel(dut, portchannel_name=kwargs['port_channel_name'], cli_type=cli_type)
        output[0]['port_channel_name'] = output[0]["name"]
    elif cli_type == 'click':
        cmd = 'show interfaces portchannel {} fallback'.format(kwargs['port_channel_name'])
        output = st.show(dut, cmd, type=cli_type, config="false", skip_error_check="True")
    elif cli_type == 'klish':
        output = []
        intf_data = uutils.get_interface_number_from_name(kwargs['port_channel_name'])
        cmd = 'show interface PortChannel {}'.format(intf_data["number"])
        raw_output = st.show(dut, cmd, type=cli_type)
        try:
            data = raw_output[0]
            temp = dict()
            temp['port_channel_name'] = "PortChannel{}".format(data['channel_number'])
            temp['fallback_config'] = data['fallback']
            temp['fallback_oper_status'] = 'Enabled' if data['oper_fallback'] == 'Operational' else 'Disabled'
            output.append(temp)
            st.debug(output)
        except Exception as e:
            st.error("{} exception occurred".format(e))
            st.debug("The raw output is: {}".format(raw_output))
            return False
    elif cli_type in ['rest-put', 'rest-patch']:
        output = rest_get_fallback_status(dut, kwargs['port_channel_name'])
    else:
        st.error("Unsupported CLI Type: {}".format(cli_type))
        return False
    if len(output) == 0:
        st.error("Output is Empty, here's the output: {}".format(output))
        return False
    for key in kwargs:
        if str(kwargs[key]) != str(output[0][key]):
            st.error("Match NOT FOUND for {} :  Expected -<{}> Actual-<{}> ".format(key, kwargs[key], output[0][key]))
            ret_val = False
        else:
            st.log("Match FOUND for {} :  Expected -<{}> Actual-<{}> ".format(key, kwargs[key], output[0][key]))
    return ret_val


def verify_portchannel_fallback_status(dut, portchannel, members_list, iter_count=10, iter_delay=1, state='up', static=False, cli_type=""):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    if cli_type == "click":
        proto = "NONE" if static else "LACP"
        if state.lower() == 'up':
            portchannel_state = '{}(A)(Up)'.format(proto)
            portchannel_member_list = []
            for member in members_list:
                portchannel_member_list.append(str(member) + '(S)')
        elif state.lower() == 'down':
            portchannel_state = '{}(A)(Dw)'.format(proto)
        else:
            st.log("Invalid LAG status provided as input to verify")
            return False
        i = 1
        while i <= iter_count:
            st.log("Checking iteration {}".format(i))
            st.wait(iter_delay)
            output_dict = get_portchannel(dut, portchannel_name=portchannel)[0]
            ports_list = (output_dict['ports'].strip()).split(' ')
            if output_dict['teamdev'] == portchannel:
                if (output_dict['protocol'] == portchannel_state):
                    for portchannel_member in portchannel_member_list:
                        if portchannel_member in ports_list:
                            return True
            else:
                st.log("The Portchannel-{} is not found".format(portchannel))
                return False
            i += 1
    elif cli_type == "klish":
        channel_number = portchannel.replace("PortChannel", "")
        portchannel_details = get_interface_portchannel(dut, channel_number=channel_number, cli_type=cli_type)
        if not portchannel_details:
            st.log("PortChannel Details not found -- {}".format(portchannel_details))
            return False
        if state == "up":
            if portchannel_details["fallback"] != "Enabled" or portchannel_details["protocol_state"] != "up":
                st.log("Fallback state is not matching -- Expecting Enabled but it is {}".format(portchannel_details[0]["fallback"]))
                return False
            elif portchannel_details["fallback"] == "Enabled" and portchannel_details["protocol_state"] != "up":
                st.log("Portchannel state is not up eventhough, fallback mode is enabled.")
                return False
            else:
                return True
        if state == "down":
            if portchannel_details["fallback"] != "Disabled" or portchannel_details["protocol_state"] != "down":
                st.log("Fallback state is not matching -- Expecting Disabled but it is {}".format(portchannel_details[0]["fallback"]))
                return False
            elif portchannel_details["fallback"] == "Disabled" and portchannel_details["protocol_state"] != "down":
                st.log("Portchannel state is not down eventhough, fallback mode is disabled.")
                return False
            else:
                return True
    return False


def config_properties(dut, params, cli_type=""):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """
    API to configure portchannel properties like mtu, no mtu, no fallback and no min links
    :param dut:
    :param params: [{"portchannel_name":"PortChannel001","mtu":"9000", "no_mtu":True/False,
     "no_min_links" : True, min_links:1, "fallback":True/False, "v4_address":"2.2.2.2","v4_subnet":24
     "v6_address":"2001::1", "v6_subnet":64, "no_v6":True/False, "no_v4":True/False,"shutdown":True/False}]
    :param cli_type: click, klish
    :return:
    """
    commands = list()
    if params:
        for param in params:
            if not param.get("portchannel_name"):
                st.log("PortChannel Name not provided")
                return False
            if cli_type == "klish":
                commands.append("interface PortChannel {}".format(param.get("portchannel_name").replace("PortChannel", "")))
                if not param.get("no_mtu"):
                    if param.get("mtu"):
                        commands.append("mtu {}".format(param.get("mtu")))
                else:
                    commands.append("no mtu")
                if not param.get("no_min_links"):
                    if param.get("min_links"):
                        commands.append("min-links {}".format(param.get("min_links")))
                else:
                    commands.append("no min-links")
                if param.get("fallback"):
                    commands.append("fallback")
                if param.get("no_fallback"):
                    commands.append("no fallback")
                if param.get("fast_rate"):
                    commands.append("fast_rate")
                if param.get("no_fast_rate"):
                    commands.append("no fast_rate")
                if param.get("shutdown"):
                    commands.append("shutdown")
                else:
                    commands.append("no shutdown")
                if param.get("v4_address") and param.get("v4_subnet"):
                    commands.append("ip address {}/{}".format(param.get("v4_address"), param.get("v4_subnet")))
                if param.get("v4_address") and param.get("no_v4"):
                    commands.append("no ip address {}".format(param.get("v4_address")))
                if param.get("v6_address") and param.get("v6_subnet"):
                    commands.append("ipv6 address {}/{}".format(param.get("v6_address"), param.get("v6_subnet")))
                if param.get("v6_address") and param.get("no_v6"):
                    commands.append("no ipv6 address {}".format(param.get("v6_address")))
                if not param.get("no_system_mac"):
                    if param.get("system_mac"):
                        commands.append("system-mac {}".format(param.get("system_mac")))
                else:
                    commands.append("no system-mac")
                commands.append("exit")
            elif cli_type == "click":
                if not param.get("fallback"):
                    if not param.get("min_links"):
                        command = "config portchannel add {}".format(param.get("portchannel_name"))
                    else:
                        command = "config portchannel add {} --min-links {}".format(param.get("portchannel_name"), param.get("min_links"))
                else:
                    if not param.get("min_links"):
                        command = "config portchannel add {} --fallback=true".format(param.get("portchannel_name"))
                    else:
                        command = "config portchannel add {} --fallback=true --min-links {}".format(
                            param.get("portchannel_name"), param.get("min_links"))
                commands.append(command)
            else:
                st.log("config_portchannel_properties : Unsupported CLI type")
                return False
        if commands:
            st.config(dut, commands, type=cli_type)
            return True
    else:
        st.log("config_portchannel_properties : PARAMS not provided")
        return False


def config_port_mode(dut, channel_number, interface, mode="active", cli_type=""):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """
    API to configure port mode for the given channel group
    :param dut:
    :param channel_number:
    :param mode:
    :param cli_type:
    :return:
    """
    if mode not in ["active", "on"]:
        st.log("Unsupported mode")
        return False
    if cli_type == "klish":
        commands = list()
        commands.append("interface {}".format(interface))
        commands.append("channel-group {} mode {}".format(channel_number, mode))
        commands.append("exit")
        st.config(dut, commands, type=cli_type)
        return True
    else:
        st.log("PORT MODE CONFIGURATION IS NOT SUPPORTED IN {} CLI".format(cli_type.upper()))
    return False


def get_interface_portchannel(dut, channel_number=None, cli_type=""):
    """
    API to execute show interface PortChannel {id} and get the result
    :param dut:
    :param channel_number:
    :param cli_type:
    :return:
    """
    result = dict()
    # Klish only implementation so force click & rest also to Kish
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    cli_type = override_supported_ui("rest-put", "rest-patch", "click", cli_type=cli_type)
    if cli_type == "klish":
        # stats_index = ["pkts","octets","multicasts","broadcasts","unicasts","errors","discards"]
        command = "show interface PortChannel"
        if channel_number:
            command += " {}".format(channel_number)
        output = st.show(dut, command, type=cli_type)
        if output:
            result = output[0]
    else:
        st.report_unsupported("test_case_unsupported", "Supported only in klish UI")

    return result


def verify_interface_portchannel(dut, **kwargs):
    """
    API to verify interface portchannel and its attributes which are passed.
    :param dut:
    :param kwargs: {u'lacp_mode': 'active', u'partner_mac': '00:00:00:00:00:00', 'input_broadcasts': '3369',
     'output_pkts': '74169', u'min_links': '1', 'input_errors': '0', u'ip_mtu': '1500', 'output_multicasts': '70186',
      'input_pkts': '6224', 'input_multicasts': '2855', u'priority': '65535', u'state': 'up', u'partner_port': '0',
       'output_unicasts': '0', 'output_discards': '0', u'actor_port': '56', 'output_errors': '0',
       u'is_selected': 'True', 'output_octets': '10678293', u'members': 'Ethernet56', u'protocol_state': 'down',
        'output_broadcasts': '3983', u'actor_mac': '90:b1:1c:f4:a8:7e', 'input_unicasts': '0', u'mtu': '1532',
         u'channel_number': '1', u'mode': 'LACP', 'input_discards': '3', u'fallback': 'Enabled',
         'input_octets': '1787177', u'pc_mac_address': '90:b1:1c:f4:a8:7e'}
    :param cli_type:
    :return:
    """
    if not kwargs:
        st.log("Parameters not provided")
        return False
    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = override_supported_ui("rest-put", "rest-patch", "click", cli_type=cli_type)
    output = get_interface_portchannel(dut, kwargs.get("channel_number", None), cli_type=cli_type)
    if not output:
        st.log("Empty output")
        return False
    kwargs.pop("cli_type", None)
    for key, value in kwargs.items():
        if str(output[key]) != str(value):
            st.log("Mismatch in {} with value {} but expecting {}".format(key, output[key], value))
            return False
    return True


def config_multiple_portchannels(dut, data, config="add", cli_type=""):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """
    :param dut:
    :param data: {'G7': {'PortChannel4': ['Ethernet48', 'Ethernet34'],'PortChannel5': 'Ethernet36', 'PortChannel2': ['Ethernet13', 'Ethernet14'],'PortChannel3': ['Ethernet32', 'Ethernet33']}, 'G6': {'PortChannel5':['Ethernet27', 'Ethernet36']}, 'G4': {'PortChannel4': ['Ethernet10','Ethernet24'], 'PortChannel2': ['Ethernet2', 'Ethernet3'], 'PortChannel3':['Ethernet8', 'Ethernet9'], 'PortChannel1': ['Ethernet0', 'Ethernet1']},'G3': {'PortChannel4': ['Ethernet18', 'Ethernet40'], 'PortChannel5':'Ethernet112', 'PortChannel2': ['Ethernet1', 'Ethernet2'], 'PortChannel3':['Ethernet16', 'Ethernet17']}, 'G8': {'PortChannel4': ['Ethernet120','Ethernet94'], 'PortChannel2': ['Ethernet126', 'Ethernet127'],'PortChannel3': ['Ethernet92', 'Ethernet93'], 'PortChannel1':['Ethernet124', 'Ethernet125']}}
    :param config: add | del
    :return: True | False
    """
    if data.get(dut):
        for portchannel_name, members in data[dut].items():
            if config == "add":
                create_portchannel(dut, portchannel_name, cli_type=cli_type)
                if not add_portchannel_member(dut, portchannel_name, members, cli_type=cli_type):
                    return False
            else:
                delete_portchannel_member(dut, portchannel_name, members, cli_type=cli_type)
                if not delete_portchannel(dut, portchannel_name, cli_type=cli_type):
                    return False
        return True
    return False


def verify_portchannel_details(dut, portchannel_list, portchannel_status_list, active_members_list, down_members_list, **kwargs):
    """
    API to verify portchannel status, members status
    :param dut:
    :param portchannel_list:
    :param portchannel_status_list:
    :param active_members_list:
    :param down_members_list:
    :param cli_type:
    :return:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    protocol = kwargs.get('protocol', 'LACP')
    # cli_type = force_cli_type_to_klish(cli_type=cli_type)
    if cli_type in ['click', 'klish']:
        portchannel_details = get_portchannel_list(dut, cli_type=cli_type)
    pc_list = utils.make_list(portchannel_list)
    pc_status_list = utils.make_list(portchannel_status_list)
    for index, portchannel in enumerate(pc_list, start=0):
        if cli_type == 'click':
            portchannel_dict = {'protocol': None, 'ports': None}
            portchannel_dict['protocol'] = utils.filter_and_select(portchannel_details, ['protocol'], {'teamdev': portchannel})[0]['protocol']
            portchannel_dict['ports'] = utils.filter_and_select(portchannel_details, ['ports'], {'teamdev': portchannel})[0]['ports']
            if pc_status_list[index] not in re.findall('{}\\(A\\)\\((\\S+)\\)'.format(protocol), portchannel_dict['protocol']):
                st.error('Port-channel state is not matching with the provided state {}'.format(pc_status_list[index]))
                return False
            active_members_set = set(re.findall(r'(Ethernet\d+)\(S\)', portchannel_dict['ports']))
            down_members_set = set(re.findall(r'(Ethernet\d+)\(D\)', portchannel_dict['ports']))
        elif cli_type == "klish":
            po_state = utils.filter_and_select(portchannel_details, ['state'], {'protocol': protocol, 'name': portchannel})
            if not (po_state and isinstance(po_state, list) and isinstance(po_state[0], dict) and 'state' in po_state[0]):
                st.error("Port-Channel status is not found")
                return False
            if po_state[0]['state'] not in pc_status_list[index]:
                st.error('Port-channel state is not matching with the provided state {}'.format(pc_status_list[index]))
                return False
            members_data = utils.filter_and_select(portchannel_details, ['members'], {'protocol': protocol, 'name': portchannel})
            members_data = members_data[0]['members']
            active_members_set = set(member['port'] for member in members_data if member['port_state'] == 'P')
            down_members_set = set(member['port'] for member in members_data if member['port_state'] == 'D')
        elif cli_type in ["rest-put", "rest-patch"] + get_supported_ui_type_list():
            portchannel_details = get_portchannel(dut, portchannel_name=portchannel)
            if portchannel_details[0]['state'] not in pc_status_list[index]:
                st.error('Port-channel state is not matching with the provided state {}'.format(pc_status_list[index]))
                return False
            members_data = portchannel_details[0]['members']
            active_members_set = set(member['port'] for member in members_data if member['port_state'] == 'U')
            down_members_set = set(member['port'] for member in members_data if member['port_state'] == 'D')
        else:
            st.error("Unsupported CLI type: {}".format(cli_type))
            return False
        if active_members_list[index]:
            active_members_input = active_members_list if kwargs.get('complete_check') else utils.make_list(active_members_list[index])
            if not set(active_members_input) == active_members_set:
                st.log('Provided active members list: {}'.format(active_members_list[index]))
                st.log('Active members set after processing is: {}'.format(active_members_set))
                st.error('Verification of active LAG members failed')
                return False
        if down_members_list[index]:
            down_members_input = down_members_list if kwargs.get('complete_check') else utils.make_list(down_members_list[index])
            if not set(down_members_input) == down_members_set:
                st.log('Provided down members list: {}'.format(down_members_list[index]))
                st.log('Down members set after processing is: {}'.format(down_members_set))
                st.error('Verification of down LAG members failed')
                return False
    return True


def get_all_interface_portchannel(dut, **kwargs):
    """
    API to execute show interface PortChannel to get all PortChannels
    :param dut:
    :param cli_type:
    :return:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    if cli_type == "klish":
        command = "show interface PortChannel | grep PortChannel"
        output = st.show(dut, command, type=cli_type)
    elif cli_type == "click":
        command = "show interface PortChannel"
        output = st.show(dut, command, type=cli_type)
    elif cli_type in ["rest-patch", "rest-put"]:
        output = get_portchannel_list(dut, cli_type=cli_type)
    else:
        st.log("Unsupported CLI type: {}".format(cli_type))
        return False
    return output


def get_portchannel_names(dut, cli_type=''):
    """
    API to get all the portchannel names
    :param dut:
    :param cli_type:
    :return: list of portchannel names
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    result = []
    output = get_portchannel_list(dut, cli_type=cli_type)
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    for entry in output:
        if cli_type == "click":
            result.append(entry['teamdev'])
        elif cli_type in ["klish", "rest-put", "rest-patch"]:
            result.append(entry["name"])
        else:
            st.log("Unsupported CLI type: {}".format(cli_type))
            return False
    return result


def config_add_range_members(dut, portchannel, ports, **kwargs):
    """
    To add range of ports as members to PortChannel
    :param :dut:
    :param :portchannel:
    :param :ports:
    #Added range support (pavan.kasula@broadcom.com)
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    config = kwargs.get('config', 'yes')
    skip_error = kwargs.get('skip_error', False)
    flag = "add" if config == "yes" else "del"
    return add_del_portchannel_member(dut, portchannel, ports, flag=flag, skip_err_check=skip_error, cli_type=cli_type)


def _parse_portchannel_data(portchannel_data):
    """
    Function to get the portchannel data
    :param portchannel_data:
    :return:
    """
    result = list()
    pc_data = dict()
    if portchannel_data.get("openconfig-interfaces:interface"):
        oc_intf = portchannel_data.get("openconfig-interfaces:interface")[0]
        pc_data["name"] = oc_intf.get("name")
        pc_data["group"] = re.search(r"(\d+)", pc_data["name"]).group(0)
        pc_fallback_config = oc_intf.get("openconfig-if-aggregate:aggregation").get("config").get("fallback")
        pc_data["fallback_config"] = "Enabled" if pc_fallback_config else "Disabled"
        pc_data["state"] = "U" if oc_intf.get("state").get("oper-status").upper() == "UP" else "D"
        pc_fallback_state = oc_intf.get("openconfig-if-aggregate:aggregation").get("state", {}).get("fallback")
        if pc_fallback_state is None:
            st.error('Expected "state" key is missed in "openconfig-if-aggregate:aggregation"')
        pc_data["fallback_oper_status"] = "Enabled" if pc_fallback_state else "Disabled"
        if oc_intf.get("openconfig-if-aggregate:aggregation"):
            pc_data["protocol"] = "STATIC" if oc_intf.get("openconfig-if-aggregate:aggregation").get("config").get("lag-type") == "STATIC" else "LACP"
        else:
            pc_data["protocol"] = "LACP"
    result.append(pc_data)
    return result


def get_gnmi_portchannel_member_data(dut, portchannel, yang_data_type="ALL", format=True):
    """
    Function to parse the portchannel member data
    :param pc_member_data:
    :return:
    """
    member_data = list()
    cli_type = st.get_ui_type(dut)
    lag_obj = umf_lacp.Lacp()
    lacp_intf = umf_lacp.LacpIntfCfg(Name=portchannel, Lacp=lag_obj)
    if cli_type in cli_type_for_get_mode_filtering():
        query_params_obj = utils.get_query_params(yang_data_type=yang_data_type, cli_type=cli_type)
        rv = lacp_intf.get_payload(dut, query_param=query_params_obj, cli_type=cli_type)
    else:
        rv = lacp_intf.get_payload(dut, cli_type=cli_type)
    if rv.ok():
        if yang_data_type == "ALL" and format is True:
            pc_member_data = rv.payload
            if pc_member_data.get("openconfig-lacp:interface"):
                members_data = pc_member_data.get("openconfig-lacp:interface")[0]
                members_info = members_data.get('members', {}).get('member', [])
                for member_info in members_info:
                    members = dict()
                    members['port'] = member_info.get('interface', '')
                    members['port_state'] = 'U' if member_info.get('state', {}).get('selected', None) else 'D'
                    member_data.append(members)
            return member_data
        else:
            return rv.payload
    else:
        return member_data


def get_gnmi_static_pc_members(dut, portchannel_data, yang_data_type="ALL"):
    """
    Function to parse the STATIC PortChannel data and get the member status
    :param dut:
    :param pc_data:
    :return:
    """
    cli_type = st.get_ui_type(dut)
    member_data = list()
    if portchannel_data.get("openconfig-interfaces:interface"):
        oc_intf = portchannel_data.get("openconfig-interfaces:interface")[0]
        if oc_intf.get("openconfig-if-aggregate:aggregation"):
            members = oc_intf.get("openconfig-if-aggregate:aggregation").get("state", []).get("member", [])
            params = {"cli_type": cli_type}
            if cli_type in cli_type_for_get_mode_filtering():
                query_params_obj = utils.get_query_params(yang_data_type=yang_data_type, cli_type=cli_type)
                params.update({"query_param": query_params_obj})
            for member in members:
                intf_obj = umf_intf.Interface(Name=member)
                rv = intf_obj.get_payload(dut, **params)
                if rv.ok():
                    member_intf = portchannel_data.get("openconfig-interfaces:interface")[0]
                    members = dict()
                    members['port'] = member
                    members['port_state'] = 'U' if member_intf['state']['oper-status'] == "UP" else 'D'
                    member_data.append(members)
    return member_data


def verify_gnmi_portchannel_member_data(dut, portchannel_data, members_list, **kwargs):
    """
    Function to veirfy the gNMI response
    :param dut:
    :param portchannel:
    :param protocol:
    :param yang_data_type:
    :param depth:
    :param verify:
    :return:
    """
    try:
        yang_data_type = kwargs.get("yang_data_type", "ALL")
        depth = kwargs.get("depth", 3)
        cli_type = st.get_ui_type(dut, **kwargs)
        portchannel_name = portchannel_data[0].get("name")
        protocol = portchannel_data[0].get("protocol")
        if protocol.upper() not in ["LACP", "STATIC"]:
            st.error("Invalid protocol - {}".format(protocol))
            return False
        if not portchannel_data[0].get("members"):
            st.log("No members found for {}".format(portchannel_name))
            return False
        lag_obj = umf_lacp.Lacp()
        lacp_intf = umf_lacp.LacpIntfCfg(Name=portchannel_name, Lacp=lag_obj)
        for member in utils.make_list(members_list):
            lacp_mem = umf_lacp.Member(LacpMemberIntf=member, LacpIntfCfg=lacp_intf)
            if cli_type in cli_type_for_get_mode_filtering():
                query_params_obj = utils.get_query_params(yang_data_type=yang_data_type, depth=depth, cli_type=cli_type)
                if yang_data_type in ["ALL", "CONFIG"]:
                    rv = lacp_mem.verify(dut, query_param=query_params_obj, match_subset=True)
                elif yang_data_type in ["OPERATIONAL", "NON_CONFIG"]:
                    rv = lacp_mem.verify(dut, query_param=query_params_obj, match_subset=True)
                else:
                    st.error("Unsupported YANG DATA TYPE - {}".format(yang_data_type))
                    return False
            else:
                rv = lacp_mem.verify(dut, cli_type=cli_type)
            if not rv.ok():
                st.log('test_step_failed: Match NOT Found: Member port:{} for PO:{}'.format(member, portchannel_name))
                return False
        return True
    except Exception as e:
        st.error("EXCEPTION: verify_portchannel_member_data: {}".format(e))
        return False


def config_portchannel_range(dut, type, param_range, config="add", cli_type=''):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    cli_type = 'klish' if cli_type in ['rest-put', 'rest-patch'] + get_supported_ui_type_list() else cli_type

    param_range_list = list(param_range) if isinstance(param_range, list) else [param_range]

    commands = []
    if cli_type == 'klish':
        new_param_range = ''
        for mrange in param_range_list:
            new_param_range += mrange.replace(' ', '-')
            new_param_range += ','
        new_param_range = new_param_range.strip(',')
        if type == 'po_range':
            if config != "del":
                commands.append('interface range create Portchannel {}'.format(new_param_range))
                commands.append('exit')
                commands.append('interface range Portchannel {}'.format(new_param_range))
                commands.append('no shutdown')
                commands.append('exit')
            else:
                commands.append('no interface Portchannel {}'.format(new_param_range))
            st.config(dut, commands, type=cli_type)
        elif type == 'mem_range':
            commands.append('interface range ethernet {}'.format(new_param_range))
            if config == "del":
                commands.append('no channel-group')
                commands.append('exit')
            else:
                st.log("For adding a range of interfaces to portchannel user add_portchannel_member api.")
                return False
            st.config(dut, commands, type=cli_type)
        else:
            st.log("Invalid type specified in the api call. Supported value is param_range|mem_range")
            return False
    else:
        st.log("Unsupported CLI type: {}".format(cli_type))
        return False
    return True


def config_portchannel_ethernet_segment(dut, portchannel_list, cli_type='', **kwargs):
    """
    API to configure ethernet-segment under portchannel interface
    :param dut:
    :type dut:
    :param portchannel_list:
    :type portchannel_list:
    :return:
    :rtype:
    :kwargs:
    :   ethernet_segment - HH:HH:HH:HH:HH:HH:HH:HH:HH:HH, or "auto-system-mac", or "auto-lacp"
    :   df_pref - df preference value
    :examples:
    :    config_portchannel_ethernet_segment(dut, <interface>, ethernet_segment=<ethernet-segment>)  - configure evpn eth-seg with default df-pref
    :    config_portchannel_ethernet_segment(dut, <interface>, ethernet_segment=<ethernet-segment>, df_pref=<df-pref>)  - configure evpn eth-seg with user df-pref
    :    config_portchannel_ethernet_segment(dut, <interface|interface-list>, config_type='no') - unconfigure evpn eth-seg
    :    config_portchannel_ethernet_segment(dut, <interface|interface-list>, ethernet_segment=<ethernet-segment>, df_pref='', config_type='no') - unconfigure df-pref
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    config_type = kwargs.get('config_type', 'yes')
    ethernet_segment = kwargs.get('ethernet_segment', False)
    df_pref = kwargs.get('df_pref', False)
    vrf_name = kwargs.get('vrf_name', 'default')
    skip_error = kwargs.get('skip_error', False)

    st.log("Configure port-channel {} ethernet-segment config_type={}, cli_type={}, es={}, df-pref={} ..".format(portchannel_list, config_type, cli_type, ethernet_segment, df_pref), dut=dut)
    if cli_type in get_supported_ui_type_list():
        ni_obj = umf_ni.NetworkInstance(Name=vrf_name)
        for portchannel_name in utils.make_list(portchannel_list):
            operation = Operation.UPDATE
            eth_seg_obj = umf_ni.EthernetSegment(Name=portchannel_name, Interface=portchannel_name, NetworkInstance=ni_obj)
            if config_type == 'yes':
                if ethernet_segment == 'auto-system-mac':
                    ethernet_segment = 'AUTO'
                    setattr(eth_seg_obj, 'EsiType', 'TYPE_3_MAC_BASED')
                    setattr(eth_seg_obj, 'Esi', ethernet_segment)
                elif ethernet_segment == 'auto-lacp':
                    ethernet_segment = 'AUTO'
                    setattr(eth_seg_obj, 'EsiType', 'TYPE_1_LACP_BASED')
                    setattr(eth_seg_obj, 'Esi', ethernet_segment)
                else:
                    ethernet_segment = ethernet_segment.replace(':', '')
                    setattr(eth_seg_obj, 'EsiType', 'TYPE_0_OPERATOR_CONFIGURED')
                    setattr(eth_seg_obj, 'Esi', ethernet_segment)
                if df_pref is not False:
                    setattr(eth_seg_obj, 'DfElectionMethod', 'PREFERENCE')
                    setattr(eth_seg_obj, 'Preference', df_pref)
                result = eth_seg_obj.configure(dut, operation=operation, cli_type=cli_type)
                if not result.ok():
                    st.error('test_step_failed: Ethernet Segment Config: {}'.format(result.data))
                    return False
            else:
                target_attr_list = list()
                if df_pref is not False:
                    target_attr_list.append(eth_seg_obj.Preference)
                if target_attr_list:
                    for target_attr in target_attr_list:
                        result = eth_seg_obj.unConfigure(dut, target_attr=target_attr, cli_type=cli_type)
                        if not result.ok():
                            st.error('test_step_failed: Ethernet Segment UnConfig: {}'.format(result.data))
                            return False
                else:
                    eth_seg_obj = umf_ni.EthernetSegment(Name=portchannel_name, NetworkInstance=ni_obj)
                    result = eth_seg_obj.unConfigure(dut, cli_type=cli_type)
                    if not result.ok():
                        st.error('test_step_failed: Ethernet Segment UnConfig: {}'.format(result.data))
                        return False
        return True
    elif cli_type == "click":
        # TODO
        return False
    elif cli_type == "klish":
        commands = list()
        for portchannel_name in utils.make_list(portchannel_list):
            intf_data = uutils.get_interface_number_from_name(portchannel_name)
            commands.append("interface PortChannel {}".format(intf_data["number"]))
            # commands.append("interface {} {}".format(intf_data["type"], intf_data["number"]))
            if config_type == 'no':
                if df_pref is not False:
                    if ethernet_segment is False:
                        st.log("Error, ethernet-segment value is required when unconfiguring df_pref", dut=dut)
                        return False
                    commands.append("evpn ethernet-segment {}".format(ethernet_segment))
                    commands.append("no df-preference")
                    commands.append("exit")
                else:
                    commands.append("no evpn ethernet-segment")
            else:
                if ethernet_segment is False:
                    st.log("Error, ethernet_segment parameter is required to configure ethernet-segment on interface {}".format(portchannel_name))
                    return False
                commands.append("evpn ethernet-segment {}".format(ethernet_segment))
                if df_pref is not False:
                    commands.append("df-preference {}".format(df_pref))
                commands.append("exit")
            commands.append("exit")
            st.config(dut, commands, type=cli_type, skip_error_check=skip_error)
        return True
    elif cli_type in ["rest-patch", "rest-put"]:
        # TODO
        return False
    else:
        st.error("Unsupported CLI Type: {}".format(cli_type))
        return False
