# This file contains the list of API's which performs Port channel operations.
# Author : Chaitanya Vella (Chaitanya-vella.kumar@broadcom.com)
import re
from spytest import st
import utilities.common as utils
import utilities.utils as uutils
import utilities.parallel as putils
from apis.system.rest import config_rest, delete_rest, rest_status
from apis.switching.portchannel_rest import rest_get_per_portchannel_info
from apis.switching.portchannel_rest import rest_get_all_portchannel_info
from apis.switching.portchannel_rest import rest_get_fallback_status


def create_portchannel(dut, portchannel_list=[], fallback=False, min_link="", static=False, cli_type=""):
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
    st.log("Creating port channel {} ..".format(portchannel_list), dut=dut)
    if static and fallback:
        st.log("Fallback is not supported for Static LAGs")
        return False
    if cli_type == "click":
        for portchannel_name in utils.make_list(portchannel_list):
            if not fallback:
                if not min_link:
                    static_flag = "--static=true" if static else ""
                    command = "config portchannel add {} {}".format(portchannel_name, static_flag).strip()
                    if not st.is_feature_supported("config_static_portchannel", dut):
                        command = "config portchannel add {}".format(portchannel_name)
                else:
                    command = "config portchannel add {} --min-links {}".format(portchannel_name, min_link)
            else:
                if not min_link:
                    command = "config portchannel add {} --fallback=true".format(portchannel_name)
                else:
                    command = "config portchannel add {} --fallback=true --min-links {}".format(portchannel_name,min_link)
            st.config(dut, command, skip_error_check=True)
        return True
    elif cli_type == "klish":
        commands = list()
        for portchannel_name in utils.make_list(portchannel_list):
            intf_data = uutils.get_interface_number_from_name(portchannel_name)
            command = "interface PortChannel {}".format(intf_data["number"])
            if static:
                command = "{} mode on".format(command)
            if min_link:
                command = "{} min-links {}".format(command, min_link)
            if fallback:
                command = "{} fallback".format(command)
            commands.append(command)
            commands.append("no shutdown")
            commands.append("exit")
        if commands:
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
                create_pc['openconfig-interfaces:interfaces']['interface'][0]['openconfig-if-aggregate:aggregation']['config'].update({'lag-type':  'STATIC'})
            if min_link:
                create_pc['openconfig-interfaces:interfaces']['interface'][0]['openconfig-if-aggregate:aggregation']['config'].update({'min-links': int(min_link)})
            if fallback:
                create_pc['openconfig-interfaces:interfaces']['interface'][0]['openconfig-if-aggregate:aggregation']['config'].update({'openconfig-interfaces-ext:fallback': True})
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
            if cli_type=="click":
                commands.append("config portchannel del {}".format(portchannel_name))
            elif cli_type == "klish":
                intf_data = uutils.get_interface_number_from_name(portchannel_name)
                commands.append("no interface PortChannel {}".format(intf_data["number"]))
            elif cli_type in ["rest-patch","rest-put"]:
                rest_urls = st.get_datastore(dut, "rest_urls")
                url = rest_urls['per_interface_details'].format(portchannel_name)
                output = delete_rest(dut, rest_url= url, get_response=True)
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
                st.log("Portchannel {} deleted successfully ..".format(portchannel_name))
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
    output = get_portchannel_list(dut, cli_type=cli_type)
    for portchannel in utils.iterable(output):
        if cli_type == "click":
            available_portchannels.append(portchannel["teamdev"])
        elif cli_type in ["klish","rest-patch","rest-put"]:
            available_portchannels.append(portchannel["name"])
        else:
            st.error("Unsupported CLI Type: {}".format(cli_type))
            return False
    response = delete_portchannel(dut, available_portchannels, cli_type=cli_type)
    return response


def get_portchannel(dut, portchannel_name="", cli_type=""):
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
    st.log("Getting port channel {} details ...".format(portchannel_name), dut=dut)
    result = dict()
    try:
        if not portchannel_name:
            st.log("Please provide portchannel")
            return False
        if cli_type == "click":
            command = "show interfaces portchannel | grep -w {}".format(portchannel_name)
            rv = st.show(dut, command)
            return rv
        elif cli_type == "klish":
            channel_number = uutils.get_interface_number_from_name(portchannel_name)["number"]
            command = "show interface PortChannel {}".format(channel_number)
            output = st.show(dut, command, type=cli_type)
            if output:
                result["group"] = output[0]["channel_number"]
                result["name"] = portchannel_name
                if output[0]["protocol_state"] == "up":
                    result["state"] = 'U'
                elif output[0]["protocol_state"] == "down":
                    result["state"] = 'D'
                result["protocol"] = output[0]["mode"]
                result["members"] = list()
                for each in output:
                    members_dict = dict()
                    if each["members"]:
                        if "Selected" in each["members"]:
                            members_dict["port_state"] = 'U'
                        else:
                            members_dict["port_state"] = 'D'
                        members_dict["port"] = each["members"].replace("(Selected)","")
                        result["members"].append(members_dict)
            else:
                st.log("Portchannel {} not found".format(portchannel_name))
                return False
            return [result]
        elif cli_type in ["rest-put","rest-patch"]:
            result = rest_get_per_portchannel_info(dut, portchannel_name)
            return result
        else:
            st.error("Unsupported CLI Type: {}".format(cli_type))
            return False
    except Exception as e:
        st.error("ERROR: Get PortChannel {}".format(str(e)))
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
            if cli_type=="click":
                command = "config portchannel del {}".format(portchannel_name)
                response = st.config(dut, command)
                if "Error" in response:
                    st.log(response)
                    return False
            elif cli_type == "klish":
                commands.append("no interface PortChannel {}".format(portchannel_name.replace("PortChannel", "")))
            elif cli_type in ["rest-put","rest-patch"]:
                if not delete_portchannel(dut,portchannel_list=portchannel_name,cli_type=cli_type):
                    st.error("Failed to delete Port-Channel: {}".format(portchannel_name))
                    return False
            else:
                st.error("Unsupported CLI TYPE {}".format(cli_type))
                return False
        if commands:
            st.config(dut, commands, type=cli_type)
        return True
    except Exception as e:
        st.error("ERROR: DELETE port channel {} ".format(str(e)))
        return False


def verify_portchannel(dut, portchannel_name, cli_type=""):
    """
    This API is used to verify the portchannel.
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param dut:
    :param portchannel_name:
    :return:
    """
    st.log("Verifying port channel {} ...".format(portchannel_name), dut=dut)
    details = get_portchannel(dut, portchannel_name, cli_type=cli_type)
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
                        if key not in ["port","port_state"]:
                            portchannel_data[key] = value
                        else:
                            if value:
                                members[key] = value
                    if members:
                        portchannel_data["members"].append(members)
                    if portchannel_data:
                        if not portchannel_data["name"] in result:
                            result[portchannel_data["name"]] = portchannel_data
                        else:
                            result[portchannel_data["name"]]["members"].append(members)
            response = list()
            if result:
                for _, pc_data in result.items():
                    response.append(pc_data)
            return response
        elif cli_type in ["rest-put","rest-patch"]:
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


def get_portchannel_members(dut, portchannel, with_state=False, cli_type=""):
    """
    This API is used to get the members of portchannel
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param dut:
    :param portchannel:
    :param with_state:
    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    st.log("Getting portchannel members ...", dut=dut)
    if not portchannel:
        st.error("PortChannel Member GET Error: Missing portchannel name")
        return False
    portchannel_details = get_portchannel(dut, portchannel, cli_type=cli_type)
    if not portchannel_details:
        st.error("Port Channel Members GET: PortChannel {} not found".format(portchannel))
        return False
    else:
        if cli_type == "click":
            if 'ports' in portchannel_details[0]:
                members = re.findall(r'Ethernet\d+', portchannel_details[0]['ports'])
                if with_state:
                    return portchannel_details[0]['ports'].split(" ")
                return members
            else:
                st.error("Members not found in mentioned portchannel")
                return False
        elif cli_type in ["klish", "rest-put", "rest-patch"]:
            members = list()
            if "members" in portchannel_details[0]:
                for member in portchannel_details[0]["members"]:
                    if not with_state:
                        members.append(member.get("port"))
                    else:
                        members.append("{}({})".format(member.get("port"),member.get("port_state")))
                return members
            else:
                st.log("Members not found")
                return False
        else:
            st.error("Unsupported CLI Type: {}".format(cli_type))
            return False


def verify_portchannel_member(dut, portchannel, members, flag='add', cli_type=""):
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
    st.log("Verifying port channel members ...", dut=dut)
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
            if member in utils.iterable(portchannel_members):
                return False
        return True


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

    st.log("{} port channel member ...".format(action), dut=dut)
    if cli_type == "click":
        if not skip_verify:
            portchannel_details = get_portchannel(dut, portchannel, cli_type=cli_type)
            if not portchannel_details:
                st.error("Port Channel Members {}: PortChannel {} not found".format(action, portchannel))
                return False
        for member in utils.make_list(members):
            command = "config portchannel member {} {} {}".format(flag, portchannel, member)
            st.config(dut, command, skip_error_check=skip_err_check)
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
        for member in utils.make_list(members):
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
            st.config(dut, commands, type=cli_type, skip_error_check=skip_err_check)
    elif cli_type in ["rest-put","rest-patch"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        rest_fail_status = False
        channel_number = uutils.get_interface_number_from_name(portchannel)["number"]
        for interface in utils.make_list(members):
            url = rest_urls['pc_member_add_del'].format(interface)
            if flag == "add":
                add_member = {"openconfig-if-aggregate:aggregate-id": "string"}
                member_status = {"openconfig-interfaces:enabled": False}
                add_member["openconfig-if-aggregate:aggregate-id"] = "{}".format(channel_number)
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


def verify_portchannel_state(dut, portchannel, state="up", error_msg=True,cli_type=""):
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
        state_match = r'LACP\(A\)\({}\)|NONE\(A\)\({}\)'.format(state, state) if cli_type == "click" else r'LACP|NONE'
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
    elif cli_type in ["klish","rest-put","rest-patch"]:
        state = "U" if state == "up" else "D"
        for details in portchannel_details:
            if details["name"] != portchannel:
                st.log("Portchannel name is not matching")
                return False
            if details["state"] != state:
                st.log("Mismatch in portchannel state {} and expecting {}".format(details["state"], state))
                return False
    else:
        st.log("UNSUPPORTED CLI Type")
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
    i=0
    while True:
        if verify_portchannel_state(dut, portchannel, state, False,cli_type=cli_type):
            st.log("Observed port channel {} with state as {}".format(portchannel, state))
            return True
        if i > iteration:
            st.log("Max iteration count reached {}".format(i))
            return False
        i+=1
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
    elif cli_type in ["klish","rest-put","rest-patch"]:
        member_state = 'U' if state == 'up' else 'D'
    else:
        st.log("UNSUPPORTED CLI Type")
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
    #cli_type = st.get_ui_type(dut, cli_type=cli_type)
    command = "teamdctl {} config dump".format(portchannel)
    st.config(dut, command)


def _clear_portchannel_configuration_helper(dut_list,cli_type=""):
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
    dut_li = list(dut_list) if isinstance(dut_list, list) else [dut_list]
    [out, exceptions] = utils.exec_foreach(thread, dut_li, _clear_portchannel_configuration_helper, cli_type=cli_type)
    putils.ensure_no_exception(exceptions)
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
    if not verify_portchannel(dut, portchannel, cli_type=cli_type):
        st.log("Port channel {} not present".format(portchannel))
        return False

    if not verify_portchannel_member(dut, portchannel, members, 'add', cli_type=cli_type):
        st.log("Members are not added to the Port channel {}".format(portchannel))
        return False

    i = 1
    while True:
        st.log("Checking iteration {}".format(i))
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
        create_portchannel(dut, portchannel_name,cli_type=cli_type)
        if not add_portchannel_member(dut, portchannel_name, members,cli_type=cli_type):
            return False
    else:
        if not delete_portchannel_member(dut, portchannel_name, members, cli_type=cli_type):
            st.error("PortChannel member deletion failed")
            return False
        if not delete_portchannel(dut, portchannel_name,cli_type=cli_type):
            return False
    return True


def config_portchannel(dut1, dut2, portchannel_name, members_dut1, members_dut2, config='add', thread=True,cli_type=""):
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
    [out, _] = utils.exec_all(thread, [[_config_portchannel, dut1, portchannel_name, members_dut1, config, cli_type],
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
    if cli_type == 'click':
        global_config_str = 'disable' if config_mode=='del' else 'enable'
        po_config_str = 'disable' if config_mode == 'add' else 'enable'
        if 'exception_po_list'  in kwargs:
            exception_po_list = kwargs['exception_po_list']
            exception_po_list = [exception_po_list] if type(exception_po_list) is str else exception_po_list
            for po in exception_po_list:
                cmd.append("config portchannel graceful-shutdown {} {}".format(po_config_str,po))
        if config_level == 'global':
            cmd.append("config portchannel graceful-shutdown {}".format(global_config_str))
    elif cli_type == 'klish':
        global_config_str = 'no ' if config_mode=='del' else ''
        po_config_str = 'no ' if config_mode == 'add' else ''
        if 'exception_po_list' in kwargs:
            exception_po_list = kwargs['exception_po_list']
            exception_po_list = [exception_po_list] if type(exception_po_list) is str else exception_po_list
            for po in exception_po_list:
                po_int = uutils.get_interface_number_from_name(po)
                cmd.append("interface {} {}".format(po_int['type'], po_int['number']))
                cmd.append("{}graceful-shutdown".format(po_config_str))
                cmd.append("exit")
        if config_level == 'global':
            cmd.append("{}portchannel graceful-shutdown".format(global_config_str))
    elif cli_type in ['rest-put', 'rest-patch']:
        ### ONLY global gshut handles now.
        global_config_str = 'disable' if config_mode == 'del' else 'enable'
        po_config_str = 'disable' if config_mode == 'add' else 'enable'
        rest_urls = st.get_datastore(dut, "rest_urls")
        global_url = rest_urls['po_gshut_config']

        if config_mode =='add':
            if 'exception_po_list' in kwargs:
                exception_po_list = kwargs['exception_po_list']
                exception_po_list = [exception_po_list] if type(exception_po_list) is str else exception_po_list
                intf_payload = {"openconfig-interfaces-ext:graceful-shutdown-mode": po_config_str}
                for po in exception_po_list:
                    interface_url = rest_urls['po_ghsut_intf_config'].format(po)
                    if not config_rest(dut, http_method=cli_type, rest_url=interface_url, json_data=intf_payload):
                        st.banner('FAIL-OCYANG: Failed to unconfigure PO gshut at interface level')
                        return False
            if config_level == 'global':
                payload = {"openconfig-aggregate-ext:graceful-shutdown-mode": global_config_str}
                if not config_rest(dut, http_method=cli_type, rest_url=global_url, json_data=payload):
                    st.banner('FAIL-OCYANG: Config PO gshut globally Failed')
                    return False
        elif config_mode =='del':
            if 'exception_po_list' in kwargs:
                exception_po_list = kwargs['exception_po_list']
                exception_po_list = [exception_po_list] if type(exception_po_list) is str else exception_po_list
                intf_payload = {"openconfig-interfaces-ext:graceful-shutdown-mode": po_config_str}
                for po in exception_po_list:
                    interface_url = rest_urls['po_ghsut_intf_config'].format(po)
                    if not config_rest(dut, http_method=cli_type, rest_url=interface_url, json_data=intf_payload):
                        st.banner('FAIL-OCYANG: Failed to configure PO gshut at interface level')
                        return False
            if config_level == 'global':
                if not delete_rest(dut,rest_url=global_url):
                    st.banner('FAIL-OCYANG:UnConfig  PO gshut globally Failed')
        return
    else:
        st.error("UNSUPPORTED cli_type")
        return
    st.config(dut, cmd, type=cli_type)


def verify_lacp_fallback(dut,**kwargs):
    """
    Klish support not available

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
    ret_val = True
    if 'port_channel_name' not in kwargs:
        st.error("Mandatory argument Port Channel name Not Found")
        return False
    if cli_type == 'click':
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
            temp['fallback_oper_status'] = 'Enabled' if data['oper_fallback']=='Operational' else 'Disabled'
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
    if cli_type == "click":
        proto = "NONE" if static else "LACP"
        if state.lower() == 'up':
            portchannel_state = '{}(A)(Up)'.format(proto)
            portchannel_member_list = []
            for member in  members_list:
                portchannel_member_list.append(str(member)+'(S)')
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
        channel_number = portchannel.replace("PortChannel","")
        portchannel_details = get_interface_portchannel(dut, channel_number=channel_number, cli_type=cli_type)
        if not portchannel_details:
            st.log("PortChannel Details not found -- {}".format(portchannel_details))
            return False
        if state == "up":
            if portchannel_details[0]["fallback"] != "Enabled" or portchannel_details[0]["state"] != "up":
                st.log("Fallback state is not matching -- Expecting Enabled but it is {}".format(portchannel_details[0]["fallback"]))
                return False
            elif portchannel_details[0]["fallback"] == "Enabled" and portchannel_details[0]["state"] != "up":
                st.log("Portchannel state is not up eventhough, fallback mode is enabled.")
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
                commands.append("interface PortChannel {}".format(param.get("portchannel_name").replace("PortChannel","")))
                if not param.get("no_mtu"):
                    if param.get("mtu"):
                        commands.append("mtu {}".format(param.get("mtu")))
                else:
                    commands.append("no mtu")
                if not param.get("no_min_links"):
                    if param.get("min_links"):
                        commands.append("minimum-links {}".format(param.get("min_links")))
                else:
                    commands.append("no minimum-links")
                if param.get("fallback"):
                    commands.append("fallback enable")
                else:
                    commands.append("no fallback")
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
    if mode not in ["active","on"]:
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
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """
    API to execute show interface PortChannel {id} and get the result
    :param dut:
    :param channel_number:
    :param cli_type:
    :return:
    """
    result = dict()
    if cli_type == "klish":
        stats_index = ["pkts","octets","multicasts","broadcasts","unicasts","errors","discards"]
        command = "show interface PortChannel"
        if channel_number:
            command += " {}".format(channel_number)
        output = st.show(dut, command, type=cli_type)
        if output:
            for key,value in output[0].items():
                if key not in stats_index:
                    result[key] = value
            for key,value in output[1].items():
                if key in stats_index:
                    result["input_{}".format(key)] = value
            for key,value in output[2].items():
                if key in stats_index:
                    result["output_{}".format(key)] = value
    return result

def verify_interface_portchannel(dut,**kwargs):
    """
    API to verify interface portchannel
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
    #cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = kwargs.get("cli_type", "klish")
    if kwargs.get("channel_number"):
        output = get_interface_portchannel(dut,channel_number=kwargs.get("channel_number"),cli_type=cli_type)
    else:
        output = get_interface_portchannel(dut,cli_type=cli_type)
    if not output:
        st.log("Empty output")
        return False
    kwargs.pop("cli_type", None)
    for key,value in kwargs.items():
        if str(output[key]) != str(value):
            st.log("Mismatch in {} with value {} but expecting {}".format(key, output[key], value))
            return  False
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

def verify_portchannel_details(dut, portchannel_list, portchannel_status_list, active_members_list, down_members_list, cli_type=''):
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
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    if cli_type == 'click':
        portchannel_details = get_portchannel_list(dut)
    pc_list = utils.make_list(portchannel_list)
    pc_status_list = utils.make_list(portchannel_status_list)
    for index, portchannel in enumerate(pc_list, start=0):
        if cli_type == 'click':
            portchannel_dict = {'protocol': None, 'ports': None}
            portchannel_dict['protocol'] = utils.filter_and_select(portchannel_details, ['protocol'], {'teamdev': portchannel})[0]['protocol']
            portchannel_dict['ports'] = utils.filter_and_select(portchannel_details, ['ports'], {'teamdev': portchannel})[0]['ports']
            if not pc_status_list[index] in re.findall(r'LACP\(A\)\((\S+)\)', portchannel_dict['protocol']):
                st.error('Port-channel state is not matching with the provided state {}'.format(pc_status_list[index]))
                return False
            active_members_set = set(re.findall(r'(Ethernet\d+)\(S\)', portchannel_dict['ports']))
            down_members_set = set(re.findall(r'(Ethernet\d+)\(D\)', portchannel_dict['ports']))
        elif cli_type in ["klish","rest-put","rest-patch"]:
            portchannel_details = get_portchannel(dut, portchannel_name=portchannel)
            if not portchannel_details[0]['state'] in pc_status_list[index]:
                st.error('Port-channel state is not matching with the provided state {}'.format(pc_status_list[index]))
                return False
            members_data = portchannel_details[0]['members']
            active_members_set = set(member['port'] for member in members_data if member['port_state']=='U')
            down_members_set = set(member['port'] for member in members_data if member['port_state']=='D')
        else:
            st.log("Unsupported CLI type: {}".format(cli_type))
            return False
        if active_members_list[index]:
            if not set(utils.make_list(active_members_list[index])) == active_members_set:
                st.log('Provided active members list: {}'.format(active_members_list[index]))
                st.log('Active members set after processing is: {}'.format(active_members_set))
                st.error('Verification of active LAG members failed')
                return False
        if down_members_list[index]:
            if not set(utils.make_list(down_members_list[index])) == down_members_set:
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
    for entry in utils.iterable(output):
        if cli_type == "click":
            result.append(entry['teamdev'])
        elif cli_type in ["klish","rest-put","rest-patch"]:
            result.append(entry["name"])
        else:
            st.log("Unsupported CLI type: {}".format(cli_type))
            return False
    return result
