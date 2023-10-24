# This file contains the list of API's for operations on interface
# @author : Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
# @author2 :Jagadish Chatrasi (jagadish.chatrasi@broadcom.com)

import re
from collections import OrderedDict

from spytest import st

import apis.system.port as portapi
from apis.system.rest import config_rest, get_rest, delete_rest
import apis.system.port_rest as op_processor
from apis.routing.ip_rest import get_subinterface_index

from utilities.common import convert_to_bits, dicts_list_values, exec_all, filter_and_select, make_list, kwargs_to_dict_list
from utilities.utils import get_interface_number_from_name, segregate_intf_list_type, is_a_single_intf, get_supported_ui_type_list, convert_intf_name_to_component
import utilities.common as common_utils
from utilities.common import get_query_params

try:
    import apis.yang.codegen.messages.interfaces.Interfaces as umf_intf
    import apis.yang.codegen.messages.network_instance as umf_ni
    import apis.yang.codegen.messages.qos as umf_qos
    import apis.yang.codegen.messages.system as umf_sys
    import apis.yang.codegen.messages.vxlan.Vxlan as umf_vxlan

except ImportError:
    pass

get_phy_port = lambda intf: re.search(r"(\S+)\.\d+", intf).group(1) if re.search(r"(\S+)\.\d+", intf) else intf


def force_cli_type_to_klish(cli_type):
    cli_type = "klish" if cli_type in get_supported_ui_type_list() else cli_type
    return cli_type


def interface_status_show(dut, interfaces=[], cli_type=''):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """
       Author: Chaitanya Vella (chaitanya.vella-kumar@broadcom.com)
    Function to get the interface(s) status
    :param dut:
    :param interfaces:
    :param cli_type:
    :return:
    """
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    if interfaces:
        interfaces = make_list(interfaces)
    if cli_type == "click":
        if interfaces:
            return portapi.get_status(dut, ','.join(interfaces), cli_type=cli_type)
        return portapi.get_status(dut, interfaces, cli_type=cli_type)
    elif cli_type == "klish":
        command = "show interface status"
        if interfaces:
            command += " | grep \"Name|{} \"".format(" |".join(interfaces))
        return st.show(dut, command, type=cli_type)
    elif cli_type in ["rest-patch", "rest-put"]:
        if interfaces:
            return portapi.get_status(dut, ','.join(interfaces), cli_type=cli_type)
        return portapi.get_status(dut, cli_type=cli_type)
    else:
        st.log("Unsupported CLI TYPE {}".format(cli_type))
        return False


def interface_operation(dut, interfaces, operation="shutdown", skip_verify=True, cli_type="", skip_error_check=False):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """
    This is an internal common function for interface operations
    Author: Chaitanya Vella (chaitanya.vella-kumar@broadcom.com)
    :param dut: dut OBJ
    :param interfaces: interfaces list
    :param operation: shutdown or startup
    :param skip_verify: to skip the verification
    :param cli_type:  (default: click)
    :return: boolean
    """
    interfaces_li = make_list(interfaces)
    if cli_type in get_supported_ui_type_list():
        if not portapi.set_status(dut, interfaces_li, operation, cli_type=cli_type):
            return False
    elif cli_type == "click":
        if not portapi.set_status(dut, interfaces_li, operation, cli_type=cli_type):
            return False
    elif cli_type == "klish":
        if not portapi.set_status(dut, interfaces_li, operation, cli_type=cli_type, skip_error_check=skip_error_check):
            return False
    elif cli_type in ["rest-patch", "rest-put"]:
        if not portapi.set_status(dut, interfaces_li, operation, cli_type=cli_type):
            return False
    else:
        st.log("Unsupported CLI TYPE {}".format(cli_type))
        return False
    if not skip_verify and cli_type != 'klish':
        state = 'down' if operation == 'shutdown' else 'up'
        port_hash_list = segregate_intf_list_type(intf=interfaces_li, range_format=False)
        allportlist = port_hash_list['intf_list_all']
        if not st.poll_wait(verify_interface_status, 5, dut, allportlist, 'oper', state, cli_type=cli_type):
            st.error("Operational state for the ports: {} is not '{}' as expected".format(allportlist, state))
            return False
    return True


def interface_operation_parallel(input, operation='startup', thread=True, cli_type=''):
    """
    Author : Chaitanya Lohith Bollapragada
    This will perform the shutdown and noshutdown of given ports in given DUTs parallel.
    :param input: dic keys = dut, values = list of interfaces
    :param operation: shutdown | startup(default)
    :param thread:
    :return:

    Ex: interface_operation_parallel({vars:D1:[vars.D1D2P1,vars.D1D2P2], vars.D2:[vars.D2D1P1,vars.D2T1P1]},)
    """
    dut_list = list(input.keys())
    if not dut_list:
        return False
    cli_type = st.get_ui_type(dut_list[0], cli_type=cli_type)
    out = exec_all(thread, [[interface_operation, dut, input[dut], operation, True, cli_type] for dut in dut_list])[0]
    return False if False in out else True


def interface_shutdown(dut, interfaces, skip_verify=True, cli_type="", skip_error_check=False):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """
      Function to shutdown interface
    Author: Chaitanya Vella (chaitanya.vella-kumar@broadcom.com)
    :param dut:
    :param interfaces:
    :param skip_verify:
    :param cli_type:
    :return:
    """
    return interface_operation(dut, interfaces, "shutdown", skip_verify, cli_type=cli_type, skip_error_check=skip_error_check)


def interface_noshutdown(dut, interfaces, skip_verify=True, cli_type=''):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """
      Function to no shut the interface
    Author: Chaitanya Vella (chaitanya.vella-kumar@broadcom.com)
    :param dut:
    :param interfaces:
    :param skip_verify:
    :param cli_type:
    :return:
    """
    return interface_operation(dut, interfaces, "startup", skip_verify, cli_type=cli_type)


def interface_properties_set(dut, interfaces_list, property, value, skip_error=False, no_form=False, cli_type=''):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """
        Function to set the interface properties.
    Author: Chaitanya Vella (chaitanya.vella-kumar@broadcom.com)
    :param dut:
    :param interfaces_list:
    :param property:
    :param value:
    :param skip_error:
    :param no_form:
    :param cli_type:
    :return:
    """
    interfaces_li = list(interfaces_list) if isinstance(interfaces_list, list) else [interfaces_list]
    if cli_type in get_supported_ui_type_list():
        port_hash_list = segregate_intf_list_type(intf=interfaces_li, range_format=False)
        intf_list = port_hash_list['intf_list_all']
        value = int(value) if str(value).isdigit() else value
        if property.lower() == 'fec':
            if value == 'none':
                value = 'FEC_DISABLED'
            if value.lower() in ['auto', 'rs', 'fc']:
                value = 'FEC_' + value.upper()

        properties = {
            'mtu': ['InterfaceMtu', value, '9100'],
            'description': ['Description', value, ''],
            'speed': ['PortSpeed', value, 'auto'],
            'autoneg': ['AutoNegotiate', True, False],
            'diag-mode': ['DiagMode', 'DIAG_MODE_ON', 'DIAG_MODE_OFF'],
            'fec': ['PortFec', value, 'FEC_DEFAULT'],
        }

        for intf in intf_list:
            intf_obj = umf_intf.Interface(Name=intf)
            property_value = properties[property][2] if no_form else properties[property][1]
            setattr(intf_obj, properties[property][0], property_value)
            result = intf_obj.configure(dut, cli_type=cli_type)
            if not result.ok():
                print('test_step_failed: Set interface property {}'.format(result.data))
                return False
        return True
    if cli_type == "click":
        port_hash_list = segregate_intf_list_type(intf=interfaces_li, range_format=False)
        interfaces_li = port_hash_list['intf_list_all']
        interfaces_li = make_list(convert_intf_name_to_component(dut, interfaces_li, component="applications"))
        for each_interface in interfaces_li:
            if property.lower() == "speed":
                command = "config interface speed {} {}".format(each_interface, value)
                if skip_error:
                    try:
                        st.config(dut, command)
                    except Exception as e:
                        st.log(e)
                        st.log("Error handled by API..")
                        return False
                else:
                    st.config(dut, command)
            elif property.lower() == "fec":
                if value not in ["rs", "fc", "none"]:
                    st.log("Provided fec value not supported ...")
                    return False
                command = "config interface fec {} {}".format(each_interface, value)
                st.config(dut, command)
            elif property.lower() == "mtu":
                command = "config interface mtu {} {}".format(each_interface, value)
                out = st.config(dut, command, skip_error_check=skip_error)
                if re.search(r'Error: Interface MTU is invalid.*', out):
                    return False
            elif property.lower() == "description":
                command = "config interface description {} {}".format(each_interface, value)
                st.config(dut, command, skip_error_check=skip_error)
            else:
                st.log("Invalid property '{}' used.".format(property))
                return False
        return True
    elif cli_type == "klish":
        properties = {"mtu": "mtu", "description": "description", "ip_address": "ip address",
                      "ipv6_address": "ipv6 address", "speed": "speed", "autoneg": "autoneg",
                      "diag-mode": "diag-mode"}
        commands = list()
        port_hash_list = segregate_intf_list_type(intf=interfaces_li, range_format=True)
        interfaces_li = port_hash_list['intf_list_all']
        for interface in interfaces_li:
            if not is_a_single_intf(interface):
                commands.append("interface range {}".format(interface))
            else:
                intf_details = get_interface_number_from_name(interface)
                if not intf_details:
                    st.log("Interface data not found for {} ".format(interface))
                commands.append("interface {} {}".format(intf_details["type"], intf_details["number"]))
            if not no_form:
                if property.lower() == "autoneg":
                    command = "speed auto"
                elif property.lower() == "fec":
                    if value not in ["auto", "rs", "fc", "none"]:
                        st.log("Provided fec value not supported ...")
                        return False
                    if value != "none":
                        command = " fec {}".format(value.upper())
                    else:
                        command = " fec {}".format(value)
                else:
                    command = "{} {}".format(properties[property.lower()], value)
                commands.append(command)
            else:
                if property.lower() == "autoneg":
                    command = "no speed auto"
                elif property.lower() in ["ip_address", "ipv6_address"]:
                    command = "no {} {}".format(properties[property.lower()], value)
                elif property.lower() == "fec":
                    command = "no fec"
                else:
                    command = "no {}".format(properties[property.lower()])
                commands.append(command)
            commands.append("exit")
        if commands:
            st.config(dut, commands, type=cli_type, skip_error_check=skip_error)
        return True
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        port_hash_list = segregate_intf_list_type(intf=interfaces_li, range_format=False)
        interfaces_li = port_hash_list['intf_list_all']
        for interface in interfaces_li:
            if property.lower() == "mtu":
                url = rest_urls['per_interface_config'].format(interface)
                if not no_form:
                    mtu_config = {"openconfig-interfaces:config": {"mtu": int(value)}}
                    if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=mtu_config):
                        return False
                else:
                    mtu_config = {"openconfig-interfaces:config": {"mtu": 9100}}
                    if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=mtu_config):
                        return False
            elif property.lower() == "description":
                url = rest_urls['per_interface_config'].format(interface)
                if not no_form:
                    description_config = {"openconfig-interfaces:config": {"description": value}}
                    if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=description_config):
                        return False
                else:
                    description_config = {"openconfig-interfaces:config": {"description": ""}}
                    if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=description_config):
                        return False
            elif property.lower() == "fec":
                url = rest_urls['fec_config_unconfig'].format(interface)
                if value not in ["auto", "rs", "fc", "none"]:
                    st.log("Provided fec value not supported ...")
                    return False
                if not no_form:
                    if value == "rs":
                        fec_config = {"openconfig-if-ethernet-ext2:port-fec": "FEC_RS"}
                        if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=fec_config):
                            return False
                    if value == "fc":
                        fec_config = {"openconfig-if-ethernet-ext2:port-fec": "FEC_FC"}
                        if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=fec_config):
                            return False
                    if value == "auto":
                        fec_config = {"openconfig-if-ethernet-ext2:port-fec": "FEC_AUTO"}
                        if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=fec_config):
                            return False
                    if value == "none":
                        fec_config = {"openconfig-if-ethernet-ext2:port-fec": "FEC_DISABLED"}
                        if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=fec_config):
                            return False
                else:
                    if not delete_rest(dut, rest_url=url):
                        return False

            else:
                st.error("Invalid property:{}".format(property))
                return False
        return True
    else:
        st.log("Unsupported CLI TYPE {}".format(cli_type))
        return False


def _get_interfaces_by_status(dut, status, cli_type=""):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """
    Internal function to get the interface status
    Author: Chaitanya Vella (chaitanya.vella-kumar@broadcom.com)
    :param dut: dut obj
    :param status: status of the interface
    :return: list of interface status
    """
    output = interface_status_show(dut, cli_type=cli_type)
    retval = []
    match = {"oper": status} if status else None
    entries = filter_and_select(output, ["interface"], match)
    for ent in entries:
        retval.append(ent["interface"])
    return retval


def get_up_interfaces(dut, cli_type=""):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """
    Author: Chaitanya Vella (chaitanya.vella-kumar@broadcom.com)
    This is to get the list of up interfaces
    :param dut: dut obj
    :return: list of interfaces
    """
    return _get_interfaces_by_status(dut, "up", cli_type=cli_type)


def get_down_interfaces(dut, cli_type=""):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """
    Author: Chaitanya Vella (chaitanya.vella-kumar@broadcom.com)
    :param dut: DUT object
    :return: list of down interfaces
    """
    return _get_interfaces_by_status(dut, "down", cli_type=cli_type)


def get_all_interfaces(dut, int_type=None, cli_type=""):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """
    Author: Chaitanya Vella (chaitanya.vella-kumar@broadcom.com)
    API to get all the interfaces nin DUT
    :param dut: dut object
    :param int_type: physical | port_channel
    :param cli_type:
    :return: interface list
    """
    output = interface_status_show(dut, cli_type=cli_type)
    out = dicts_list_values(output, 'interface')
    if out:
        if int_type == 'physical':
            return [each for each in out if each.startswith("Eth")]
        elif int_type == 'port_channel':
            return [each for each in out if each.lower().startswith("portchannel")]
        else:
            return out
    else:
        return []


def get_all_ports_speed_dict(dut, cli_type=""):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """
    :param dut:
    :return: dict of all ports of same speed
    """
    all_speed_ports = dict()
    output = interface_status_show(dut, cli_type=cli_type)
    physical_port_list = [each['interface'] for each in output if each['interface'].startswith("Eth")]
    for each in physical_port_list:
        speed = filter_and_select(output, ['speed'], {'interface': each})[0]['speed']
        if speed not in all_speed_ports:
            all_speed_ports[speed] = [each]
        else:
            all_speed_ports[speed].append(each)
    return all_speed_ports


def verify_interface_status(dut, interface, property, value, cli_type="", **kwargs):
    """
    Author: Chaitanya Vella (chaitanya.vella-kumar@broadcom.com)
    This API to verify the interface status
    :param dut: dut obj
    :param interface: Interface Name
    :param property: Interface property
    :param value: Property Value
    :param cli_type:
    :return: Boolean
    """
    interface_list = make_list(interface)
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    if cli_type in get_supported_ui_type_list():
        filter_type = kwargs.get('filter_type', 'ALL')
        query_params_obj = common_utils.get_query_params(yang_data_type=filter_type, cli_type=cli_type)
        value = value.upper()
        for intf in interface_list:
            index = get_subinterface_index(dut, intf)
            intf = get_phy_port(intf)
            intf_obj = umf_intf.Interface(Name=intf)
            if property == 'admin':
                intf_obj.AdminStatus = value
            if property == 'oper':
                intf_obj.OperStatus = value
            if int(index):
                sub_intf_obj = umf_intf.Subinterface(Index=index, Interface=intf_obj)
                result = sub_intf_obj.verify(dut, match_subset=True, query_param=query_params_obj, cli_type=cli_type)
            else:
                result = intf_obj.verify(dut, match_subset=True, query_param=query_params_obj, cli_type=cli_type)
            if not result.ok():
                st.log('test_step_failed: Match not found:')
                return False
        return True

    # list of down reasons to match against
    down_reasons = ["admin-down"]

    # adjust the interface list and down reasons for click
    if cli_type == 'click':
        interface_list = make_list(convert_intf_name_to_component(dut, interface_list, component="applications"))
        down_reasons.append("down")

    # fetch the admin status for given interfaces
    interface_details = interface_status_show(dut, interface_list, cli_type=cli_type)

    # update the admin status based on down reasons
    for intf_detail in interface_details:
        intf_detail.update(admin="down" if intf_detail.get("admin") in down_reasons else "up")

    # verify the needed property with needed value
    for port in interface_list:
        match = {"interface": port, property: value}
        entries = filter_and_select(interface_details, ["interface"], match)
        if not bool(entries):
            return False

    return True


def clear_interface_counters(dut, **kwargs):
    cli_type = st.get_ui_type(dut, **kwargs)
    # cli_type = force_cli_type_to_klish(cli_type=cli_type)
    interface_name = kwargs.get("interface_name", "")
    interface_type = kwargs.get("interface_type", "all")
    exec_mode = kwargs.get("exec_mode", "")
    rif = kwargs.get("rif", None)
    if rif and cli_type in get_supported_ui_type_list():
        cli_type = 'klish'
    if cli_type in get_supported_ui_type_list():
        return portapi.clear_interface_counters(dut, **kwargs)
    if cli_type == "klish":
        confirm = kwargs.get("confirm") if kwargs.get("confirm") else "y"
        if interface_type != "all":
            interface_type = get_interface_number_from_name(str(interface_name))
            if interface_type["type"] and interface_type["number"]:
                interface_val = "{} {}".format(interface_type.get("type"), interface_type.get("number"))
            else:
                interface_val = ""
        else:
            interface_val = "all"
        if not interface_val:
            st.log("Invalid interface type")
            return False
        command = "clear counters interface {}".format(interface_val)
        if rif:
            command = "clear counters interface rif"
        st.config(dut, command, type=cli_type, confirm=confirm, conf=False, skip_error_check=True, exec_mode=exec_mode)
    elif cli_type == "click":
        if rif:
            return st.config(dut, "sonic-clear rifcounters")
        else:
            command = "show interfaces counters -c"
            if not st.is_feature_supported("show-interfaces-counters-clear-command", dut):
                st.community_unsupported(command, dut)
                return st.config(dut, "sonic-clear counters")
            return st.show(dut, command)
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        url = rest_urls['clear_interface_counters']
        clear_type = 'all' if interface_type == 'all' else interface_name
        clear_counters = {"sonic-interface:input": {"interface-param": clear_type}}
        if rif:
            url = rest_urls['clear_interface_counters_rif']
            clear_counters = {"sonic-counters:rif_count:input": {"rif": clear_type}}
        if not config_rest(dut, http_method='post', rest_url=url, json_data=clear_counters, timeout=125):
            st.error("Failed to clear interface counters")
            return False
    else:
        st.log("Unsupported CLI TYPE {}".format(cli_type))
        return False
    return True


def show_interfaces_counters(dut, interface=None, property=None, rif=None, cli_type="", option=None):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """
    show interface counter
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param interface:
    :param property:
    :param cli_type:
    :param rif: Boolean Value
    :return:
    (pavan.kasula@broadcom.com) Added intf range support
    """
    # For Fetching All RIF counters in REST support is missing Tracking it with :SONIC-46956
    cli_type = 'klish' if cli_type in ['rest-patch', 'rest-put'] + get_supported_ui_type_list() and rif == 'yes' and \
        (interface is None or 'vlan' in (''.join(interface).lower()) or 'po' in (
            ''.join(interface).lower())) else cli_type
    if cli_type in get_supported_ui_type_list():
        if interface:
            intf_list = make_list(interface)
            op_result = []
            for intf in intf_list:
                interface_name = get_phy_port(intf)
                intf_obj = umf_intf.Interface(Name=interface_name)
                int_obj = intf_obj
                index = get_subinterface_index(dut, intf)
                if index != '0':
                    sub_intf_obj = umf_intf.Subinterface(Index=int(index), Interface=intf_obj)
                    int_obj = sub_intf_obj
                result = int_obj.get_payload(dut, cli_type=cli_type)
                if not result.ok():
                    st.log('test_step_failed: Get Interface counters for {}: {}'.format(intf, result.data))
                    return False
                output = result.payload
                if rif:
                    processed_output = op_processor.process_intf_counters_gnmi_rest_output(output, counter_type='rif_counter', rif="yes")
                else:
                    processed_output = op_processor.process_intf_counters_gnmi_rest_output(output, counter_type='basic')
                if processed_output:
                    # Property is not used in any call. This is not implemented in klish block in this API
                    if property:
                        op_result.extend(filter_and_select(processed_output, [property], {'iface': intf}))
                    else:
                        op_result.extend(processed_output)
            return op_result
        else:
            cli_type = 'klish'
    if cli_type == "click":
        if interface is None:
            command = 'show interfaces counters'
            if rif:
                command += ' rif'
                if option:
                    command += ' -p {}'.format(option)
            output = st.show(dut, command)
            return output
        port_hash_list = segregate_intf_list_type(intf=interface, range_format=False)
        interface_list = port_hash_list['intf_list_all']
        interface_li = '|'.join([str(elem) for elem in interface_list])
        command = "show interfaces counters -a | grep -Ew \"(IFACE|{})\"".format(interface_li)
        if rif:
            command = "show interfaces counters rif | grep -Ew \"(IFACE|{})\"".format(interface_li)
            if option:
                command = "show interfaces counters rif -p {}| grep -Ew \"(IFACE|{})\"".format(option, interface_li)
        output = st.show(dut, command)
        output_value = list()
        for intf in interface_list:
            if property:
                output_value.extend(filter_and_select(output, [property], {'iface': intf}))
            else:
                output_value.extend(filter_and_select(output, None, {'iface': intf}))
        return output_value
    elif cli_type == "klish":
        command = "show interface counters"
        if rif:
            command += " rif"
        if interface is None:
            return st.show(dut, command, type=cli_type)
        port_hash_list = segregate_intf_list_type(intf=interface, range_format=False)
        interface_list = port_hash_list['intf_list_all']
        interface_li = ' |'.join([str(elem) for elem in interface_list])
        command += " | grep \"Interface|{} \"".format(interface_li)
        return st.show(dut, command, type=cli_type)
    elif cli_type in ["rest-patch", "rest-put"]:
        result = []
        if interface:
            ports = make_list(interface)
            for port in ports:
                result.extend(show_specific_interface_counters(dut, port, cli_type=cli_type, rif=rif))
            if property:
                result = filter_and_select(result, [property], {'iface': interface})
        else:
            result = portapi.get_interface_counters_all(dut, cli_type=cli_type)
        return result
    else:
        st.log("Unsupported CLI TYPE {}".format(cli_type))
        return False


def show_interface_counters_all(dut, rif=None, cli_type=''):
    """
    Show interface counter all.
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    cli_type = 'klish' if cli_type in ["rest-patch", "rest-put"] + get_supported_ui_type_list() and rif is True else cli_type
    # cli_type = force_cli_type_to_klish(cli_type=cli_type)
    if cli_type in get_supported_ui_type_list():
        return show_interfaces_counters(dut, cli_type=cli_type)
    if cli_type == 'click':
        command = "show interfaces counters -a"
        if rif:
            command = "show interfaces counters rif"
        return st.show(dut, command, type=cli_type)
    elif cli_type == 'klish':
        command = "show interface counters"
        if rif:
            command += ' rif'
        return st.show(dut, command, type=cli_type)
    elif cli_type in ["rest-patch", "rest-put"]:
        return portapi.get_interface_counters_all(dut, cli_type=cli_type)
    else:
        st.error('Invalid CLI type')
        return False


def get_interface_counters(dut, port, *counter, **kwargs):
    """
    This API is used to get the interface counters.
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param port:
    :param counter:
    :return:
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut, **kwargs))
    exec_mode = kwargs.get("exec_mode", "")
    if cli_type == 'click':
        port = convert_intf_name_to_component(dut, port, component="applications")
    output = show_specific_interface_counters(dut, port, cli_type=cli_type, exec_mode=exec_mode)
    entries = filter_and_select(output, counter, {'iface': port})
    return entries


def show_specific_interface_counters(dut, interface_name, cli_type='', rif=None, **kwargs):
    """
    API to fetch the specific interface counters
    :param dut:
    :param interface_name:
    :return:
    (pavan.kasula@broadcom.com) Added intf range support
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    exec_mode = kwargs.get("exec_mode", "")
    if cli_type == 'click':
        port_hash_list = segregate_intf_list_type(intf=interface_name, range_format=False)
        interface_list = port_hash_list['intf_list_all']
        interface_list = make_list(convert_intf_name_to_component(dut, interface_list, component="applications"))
        if interface_list:
            interface_li = '|'.join([str(elem) for elem in interface_list])
            command = "show interfaces counters -a | grep -Ew \"(IFACE|{})\"".format(interface_li)
            if not st.is_feature_supported("show-interfaces-counters-interface-command", dut):
                st.community_unsupported(command, dut)
                command = "show interfaces counters -a | grep -Ew \"(IFACE|{})\" ".format(interface_li)
        output = st.show(dut, command, type=cli_type)

    elif cli_type == 'klish':
        port_hash_list = segregate_intf_list_type(intf=interface_name, range_format=False)
        interface_list = port_hash_list['intf_list_all']
        interface_li = ' |'.join([str(elem) for elem in interface_list])
        command = "show interface counters | grep \"Interface|{} \"".format(interface_li)
        output = st.show(dut, command, type=cli_type, exec_mode=exec_mode)

    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        url = rest_urls['per_interface_details'].format(interface_name)
        output = []
        if rif:
            if 'Vlan' in interface_name:
                url = rest_urls["rif_counters_vlan"].format(name=interface_name)
            else:
                index = interface_name.split('.')[1] if '.' in interface_name else 0
                interface_name = interface_name.split('.')[0] if '.' in interface_name else interface_name
                url = rest_urls["rif_counters"].format(name=interface_name, index=index)
        result = get_rest(dut, rest_url=url, timeout=60)
        if rif:
            processed_output = op_processor.process_intf_counters_rest_output(result, type='rif_interface')
        else:
            processed_output = op_processor.process_intf_counters_rest_output(result)
        if processed_output:
            output.extend(processed_output)
    st.log(output)
    return output


def poll_for_interfaces(dut, iteration_count=180, delay=1, cli_type=""):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """
    This API is to  poll the DUT to get the list of interfaces
    Author: Chaitanya Vella (chaitanya.vella-kumar@broadcom.com)
    :param dut:
    :param iteration_count:
    :param delay:
    :param cli_type:
    :return:
    """
    i = 1
    while True:
        intefaces_list = get_all_interfaces(dut, cli_type=cli_type)
        if intefaces_list:
            st.log("Interfaces list found ...")
            return True
        if i > iteration_count or st.is_dry_run():
            st.log("Max {} tries Exceeded. Exiting ..".format(i))
            return False
        i += 1
        st.wait(delay)


def poll_for_interface_status(dut, interface, property, value, iteration=5, delay=1, cli_type=""):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """
    API to poll for interface status
    Author: Chaitanya Vella (chaitanya.vella-kumar@broadcom.com)
    :param dut:
    :param interface:
    :param property:
    :param value:
    :param iteration:
    :param delay:
    :param cli_type:
    :return:
    """
    i = 1
    while True:
        if verify_interface_status(dut, interface, property, value, cli_type=cli_type):
            st.log("Observed interface status match at {} iteration".format(i))
            return True
        if i > iteration or st.is_dry_run():
            st.log("Max iterations {} reached".format(i))
            return False
        i += 1
        st.wait(delay)


def get_interface_property(dut, interfaces_list, property, cli_type=""):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """

    :param dut:
    :param interfaces_list: API accepts interfaces list or single interface
    :param property: single property need to provide
    :param cli_type:
    :return: Returns interfaces list properties in the interfaces order passed to api
    """
    interfaces_li = make_list(interfaces_list)
    output = interface_status_show(dut, interfaces_li, cli_type=cli_type)
    return_list = []
    for each_interface in interfaces_li:
        property_val = filter_and_select(output, [property], {'interface': each_interface})
        if not property_val:
            break
        return_list.append(property_val[0][property])

    if not return_list and st.is_dry_run():
        if property == "mtu":
            return_list = [9100] * len(interfaces_li)
        elif property == "speed":
            return_list = [10000] * len(interfaces_li)
    return return_list


def config_static_ip_to_interface(dut, interface_name, ip_address, netmask, gateway):
    """
    API to configure static ip address to an interface
    Author: Chaitanya Vella (chaitanya.vella-kumar@broadcom.com)
    :param dut:
    :param interface_name:
    :param ip_address:
    :param netmask:
    :param gateway:
    :return:
    """
    command = "ifconfig {} {} netmask {}".format(interface_name, ip_address, netmask)
    st.config(dut, command)
    command = 'ip route add default via {}'.format(gateway)
    st.config(dut, command)


def delete_ip_on_interface_linux(dut, interface_name, ip_address):
    """
    :param dut:
    :param interface_name:
    :param ip_address:
    :return:
    """
    command = "ip addr del {} dev {}".format(ip_address, interface_name)
    st.config(dut, command)


def show_queue_counters(dut, interface_name, queue=None, cli_type=''):
    """
    Show Queue counters
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param interface_name:
    :param queue: UC0-UC9 | MC10-MC19 (Default None)
    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    if cli_type == 'click':
        command = "show queue counters {}".format(interface_name)
        output = st.show(dut, command, type=cli_type)
    elif cli_type == 'klish':
        if interface_name == "CPU":
            command = "show queue counters interface CPU"
        else:
            intf_details = get_interface_number_from_name(interface_name)
            command = "show queue counters interface {} {}".format(intf_details['type'], intf_details['number'])
        output = st.show(dut, command, type=cli_type)
    elif cli_type in ['rest-patch', 'rest-put']:
        output = op_processor.rest_get_queue_counters(dut, interface_name)
    else:
        st.log("Unsupported CLI TYPE {}".format(cli_type))
        return False
    if queue:
        return filter_and_select(output, None, {'txq': queue})
    return output


def clear_queue_counters(dut, interfaces_list=[], cli_type=''):
    """
    Clear Queue counters
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    if cli_type in ['rest-put', 'rest-patch']:  # OC-YANG URL is not available to clear counters, reported JIRA: SONIC-23227 for this.
        cli_type = 'klish'
    if cli_type == 'click':
        interface_li = make_list(interfaces_list)
        if not interface_li:
            command = "show queue counters -c"
            st.show(dut, command)
        else:
            for each_port in interface_li:
                command = "show queue counters {} -c".format(each_port)
                st.show(dut, command, type=cli_type)
    elif cli_type == 'klish':
        if interfaces_list:
            port_list = make_list(interfaces_list)
            for port in port_list:
                if port == "CPU":
                    command = "clear queue counters interface CPU"
                else:
                    intf_details = get_interface_number_from_name(port)
                    command = 'clear queue counters interface {} {}'.format(intf_details['type'], intf_details['number'])
                st.config(dut, command, type=cli_type)
        else:
            command = 'clear queue counters'
            st.config(dut, command, type=cli_type)
    else:
        st.log("Unsupported CLI TYPE {}".format(cli_type))
        return False
    return True


def get_free_ports_speed_dict(dut, cli_type=""):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """
    :param dut:
    :param cli_type:
    :return: dict of free ports of same speed
    """
    free_speed_ports = dict()
    free_ports = st.get_free_ports(dut)
    output = interface_status_show(dut, cli_type=cli_type)
    for each in free_ports:
        speed = filter_and_select(output, ['speed'], {'interface': each})[0]['speed']
        if speed not in free_speed_ports:
            free_speed_ports[speed] = [each]
        else:
            free_speed_ports[speed].append(each)
    return free_speed_ports


def enable_dhcp_on_interface(dut, interface_name, type="v4", skip_error_check=False):
    """
    :param dut:
    :param interface_name:
    :return:
    """
    version = ""
    if type == "v6":
        version = "-6"
    command = "dhclient {} {}".format(version, interface_name)
    return st.config(dut, command, skip_error_check=skip_error_check)


def show_interface_counters_detailed(dut, interface, filter_key=None, cli_type=""):
    """
    show interfaces counters detailed <interface>.
    Author : Rakesh Kumar Vooturi (rakesh-kumar.vooturi@broadcom.com)
    :param dut:
    :param interface:
    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    cli_type = "klish" if cli_type in ["rest-put", "rest-patch"] else cli_type
    if cli_type in get_supported_ui_type_list():
        intf_obj = umf_intf.Interface(Name=interface)
        result = intf_obj.get_payload(dut, cli_type=cli_type)
        if not result.ok():
            st.log('test_step_failed: Setting of interface state {}'.format(result.data))
            return False
        output = result.payload
        result = []
        processed_output = op_processor.process_intf_counters_gnmi_rest_output(output, counter_type='detailed')
        if processed_output:
            result.extend(processed_output)
        if not result:
            return False
        if not filter_key:
            return result
        else:
            return result[0][filter_key]

    intf_details = get_interface_number_from_name(interface)
    intf_type = intf_details['type']
    # Adding this logic due to defect SONIC-28659 will revert back once it is fixed
    if intf_type == "PortChannel":
        cli_type = "click"
    if cli_type == "click":
        command = "show interfaces counters detailed {}".format(interface)
    else:
        command = "show interface counters {}".format(interface)
    if not st.is_feature_supported("show-interfaces-counters-detailed-command", dut):
        st.community_unsupported(command, dut)
        output = st.show(dut, command, skip_error_check=True)
    else:
        output = st.show(dut, command, type=cli_type)
    if not filter_key:
        return output
    else:
        if not output:
            return False
        return output[0][filter_key]


def clear_watermark_counters(dut, mode='all', **kwargs):
    """
    Clear  Watermark counters
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param mode:
    :return:
    """
    if mode == '':
        if 'queue' in kwargs and 'interface' in kwargs and kwargs['queue'] == 'unicast':
            command = "clear queue watermark unicast interface {}".format(kwargs['interface'])
        elif 'queue' in kwargs and 'interface' in kwargs and kwargs['queue'] == 'multicast':
            command = "clear queue watermark multicast interface {}".format(kwargs['interface'])
        cli_type = 'klish'
    else:
        if mode == 'multicast' or mode == 'all':
            command = "sonic-clear queue watermark multicast"
        if mode == 'unicast' or mode == 'all':
            command = "sonic-clear queue watermark unicast"
        if mode == 'shared' or mode == 'all':
            command = "sonic-clear priority-group watermark shared"
        if mode == 'headroom' or mode == 'all':
            command = "sonic-clear priority-group watermark headroom"
        cli_type = 'click'
    st.config(dut, command, type=cli_type)
    return True


def show_watermark_counters(dut, mode='all'):
    """
    Show Watermark counters
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param mode:
    :return:
    """
    result = ''
    if mode == 'multicast' or mode == 'all':
        command = "show queue watermark multicast"
        result += st.show(dut, command, skip_tmpl=True)
    if mode == 'unicast' or mode == 'all':
        command = "show queue watermark unicast"
        result += st.show(dut, command, skip_tmpl=True)
    if mode == 'shared' or mode == 'all':
        command = "show priority-group watermark shared"
        result += st.show(dut, command, skip_tmpl=True)
    if mode == 'headroom' or mode == 'all':
        command = "show priority-group watermark headroom"
        result += st.show(dut, command, skip_tmpl=True)
    return result


def get_interface_counter_value(dut, ports, properties, cli_type=""):
    """
    This API is used to get the multiple interfaces counters value in dictionary of dictionaries.
    Author : Ramprakash Reddy (ramprakash-reddy.kanala@broadcom.com)
    :param dut:
    :param ports: Interfaces names ["Ethernet0","Ethernet1"]
    :param property: Interface properties ["rx_ok","tx_ok"]
    :return: {"Ethernet0":{"rx_ok":"1234","tx_ok":"45"},"Ethenrnet1":{"rx_ok"="4325","tx_ok"="2424"}}
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    ports = make_list(ports)
    properties = make_list(properties)
    counters_dict = dict()
    output = show_interface_counters_all(dut, cli_type=cli_type)
    for each_port in ports:
        entries = filter_and_select(output, properties, {'iface': each_port})
        if entries:
            counters_dict[each_port] = entries[0]
        else:
            st.error('The counter entry for interface: {} is not found'.format(each_port))
    return convert_to_bits(counters_dict)


def verify_interface_counters(dut, params, cli_type=""):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """
    :param dut:
    :param params: {"module_type":"mirror","source":["Ethernet1","tx_ok"], "destination":["Ethernet2","rx_ok"],
    "mirrored_port":["Ethernet3","rx_ok"]}
    :param cli_type:
    :return:
    """
    st.log("Verifying interface counters on {}".format(dut))
    output = show_interface_counters_all(dut, cli_type=cli_type)
    if not output:
        st.log("Output not found")
        return False
    if params:
        source_counters, destination_counters, mirror_counters = 0, 0, 0
        module_type = params.get("module_type", "mirror")
        for data in output:
            if params.get("source") and data["iface"] == params["source"][0]:
                source_counters = data[params["source"][1]]
            if params.get("destination") and data["iface"] == params["destination"][0]:
                destination_counters = data[params["destination"][1]]
            if module_type in ["mirror", "mirror_both"] and params.get("mirrored_port"):
                if data["iface"] == params["mirrored_port"][0]:
                    mirror_counters = \
                        data[params["mirrored_port"][1]]
        try:
            st.log('The source counter is {}'.format(source_counters))
            st.log('The destination counter is {}'.format(destination_counters))
            st.log("Mirror Counters:{}".format(mirror_counters))
            float(source_counters.split()[0].replace(",", ""))
            float(destination_counters.split()[0].replace(",", ""))
        except Exception:
            st.report_fail("counters_are_not_initilaized")
        source_counters = int(source_counters.replace(",", ""))
        destination_counters = int(destination_counters.replace(",", ""))
        mirror_counters = int(mirror_counters.replace(",", ""))
        if module_type == "mirror":
            if not ((mirror_counters >= 0.93 * source_counters) and (destination_counters >= 0.93 * source_counters)):
                st.log("Counters mismatch Source Counters:{},Destination Counters:{}Mirror"
                       " Counters:{}".format(source_counters, destination_counters, mirror_counters))
                st.log("Observed mismatch in counter validation")
                st.log("Source Counters:{}".format(source_counters))
                st.log("Destination Counters:{}".format(destination_counters))
                st.log("Mirror Counters:{}".format(mirror_counters))
                return False
            else:
                return True
        elif module_type == "mirror_both":
            mirror_counters_both = int(source_counters) + int(destination_counters)
            # mirror_counters_both = int(mirror_counters_both.replace(",", ""))
            if not (int(mirror_counters) >= 0.93 * mirror_counters_both):
                st.log("Observed mismatch in counter validation")
                st.log("Source Counters:{}".format(source_counters))
                st.log("Destination Counters:{}".format(destination_counters))
                st.log("Mirror Counters:{}".format(mirror_counters))
                st.log("Mirror Counters both:{}".format(mirror_counters_both))
                return False
            else:
                return True
        elif module_type == "bum":
            source_counters = int(round(float(source_counters.split()[0])))
            destination_counters = int(round(float(destination_counters.split()[0])))
            if not destination_counters - source_counters <= 100:
                st.log("Destination counter:{} and Source Counters:{}".format(destination_counters,
                                                                              source_counters))
                return False
            else:
                return destination_counters
        else:
            st.log("Unsupported module type {}".format(module_type))
            return False
    else:
        st.log("Parameters not found - {} ...".format(params))
        return False


def config_portchannel_interfaces(dut, portchannel_data={}, config='yes', cli_type=''):
    # Duplicate API, should not be used in FT. This is used by UT script only

    if config == 'yes' or config == 'add':
        config = 'add'
    elif config == 'no' or config == 'del':
        config = 'del'
    else:
        st.error("Invalid config type {}".format(config))
        return False

    cli_type = st.get_ui_type(dut, cli_type=cli_type)

    command = []

    if config == 'del':
        for if_name, if_data in portchannel_data.items():
            pch_info = get_interface_number_from_name(if_name)
            for link_member in if_data['members']:
                if cli_type == 'click':
                    cmd_str = "sudo config portchannel member {} {} {} ".format(config, if_name, link_member)
                    command.append(cmd_str)
                elif cli_type == 'klish':
                    intf_info = get_interface_number_from_name(link_member)
                    cmd_str = "interface {} {}".format(intf_info["type"], intf_info["number"])
                    command.append(cmd_str)
                    cmd_str = "no channel-group"
                    command.append(cmd_str)
                    command.append('exit')

        if cli_type in ['click', 'klish']:
            try:
                st.config(dut, command, type=cli_type)
            except Exception as e:
                st.log(e)
                return False

    command = []
    for if_name, if_data in portchannel_data.items():
        if cli_type == 'click':
            cmd_str = "sudo config portchannel {} {}  ".format(config, if_name)
            command.append(cmd_str)
        elif cli_type == 'klish':
            pch_info = get_interface_number_from_name(if_name)
            cmd_str = 'no ' if config == 'del' else ''
            cmd_str += "interface {} {}".format(pch_info["type"], pch_info["number"])
            command.append(cmd_str)
            if config == 'add':
                command.append('no shutdown')
                command.append('exit')

    if cli_type in ['click', 'klish']:
        try:
            st.config(dut, command, type=cli_type)
        except Exception as e:
            st.log(e)
            return False

    command = []
    if config == 'add':
        for if_name, if_data in portchannel_data.items():
            pch_info = get_interface_number_from_name(if_name)

            for link_member in if_data['members']:
                if cli_type == 'click':
                    cmd_str = "sudo config portchannel member {} {} {} ".format(config, if_name, link_member)
                    command.append(cmd_str)
                elif cli_type == 'klish':
                    intf_info = get_interface_number_from_name(link_member)
                    cmd_str = "interface {} {}".format(intf_info["type"], intf_info["number"])
                    command.append(cmd_str)
                    cmd_str = "channel-group {}".format(pch_info["number"])
                    command.append(cmd_str)
                    command.append('exit')

                    intf_info = get_interface_number_from_name(link_member)
                    cmd_str = "interface {} {}".format(intf_info["type"], intf_info["number"])
                    command.append(cmd_str)

        if cli_type in ['click', 'klish']:
            try:
                st.config(dut, command, type=cli_type)
            except Exception as e:
                st.log(e)
                return False

    return True


def config_vlan_interfaces(dut, vlan_data={}, config='yes', skip_error=False, cli_type=''):
    # Duplicate API, should not be used in FT. This is used by UT script only

    if config == 'yes' or config == 'add':
        config = 'add'
        operation = 'add'
    elif config == 'no' or config == 'del':
        config = 'del'
        operation = 'remove'
    else:
        st.error("Invalid config type {}".format(config))
        return False

    cli_type = st.get_ui_type(dut, cli_type=cli_type)

    command = []
    if config == 'del':
        for _, if_data in vlan_data.items():
            vlan_id = if_data['vlan_id']

            range_cmd = False
            if 'range' in if_data.keys():
                range_ids = if_data['range']
                if range_ids[0] < range_ids[1]:
                    range_min, range_max = range_ids[0], range_ids[1]
                    range_cmd = True
                elif range_ids[0] > range_ids[1]:
                    range_min, range_max = range_ids[1], range_ids[0]
                    range_cmd = True
                else:
                    vlan_id = range_ids[0]

            for link_member in if_data['members']:

                if cli_type == 'klish':
                    intf_info = get_interface_number_from_name(link_member)
                    cmd_str = 'interface {} {}'.format(intf_info["type"], intf_info["number"])
                    command.append(cmd_str)

                if not range_cmd:
                    if cli_type == 'click':
                        cmd_str = "config vlan member {} {} {} ".format(config, vlan_id, link_member)
                        command.append(cmd_str)
                    elif cli_type == 'klish':
                        cmd_str = "switchport trunk allowed Vlan {} {}".format(operation, vlan_id)
                        command.append(cmd_str)
                elif st.is_feature_supported("vlan-range", dut):
                    if cli_type == 'click':
                        cmd_str = "config vlan member range {} {} {} {}".format(config, range_min, range_max, link_member)
                        command.append(cmd_str)
                    elif cli_type == 'klish':
                        cmd_str = "switchport trunk allowed Vlan {} {}-{}".format(operation, range_min, range_max)
                        command.append(cmd_str)
                else:
                    skip_error = True
                    for vid in range(range_min, range_max + 1):
                        if cli_type == 'click':
                            cmd_str = "config vlan member {} {} {} ".format(config, vid, link_member)
                            command.append(cmd_str)
                        elif cli_type == 'klish':
                            cmd_str = "switchport trunk allowed Vlan {} {}".format(operation, vid)
                            command.append(cmd_str)

                if cli_type == 'klish':
                    command.append('exit')

        if cli_type in ['click', 'klish']:
            try:
                st.config(dut, command, skip_error_check=skip_error, type=cli_type)
            except Exception as e:
                st.log(e)
                return False

    command = []
    for _, if_data in vlan_data.items():
        vlan_id = if_data['vlan_id']

        range_cmd = False
        if 'range' in if_data.keys():
            range_ids = if_data['range']
            if range_ids[0] < range_ids[1]:
                range_min, range_max = range_ids[0], range_ids[1]
                range_cmd = True
            elif range_ids[0] > range_ids[1]:
                range_min, range_max = range_ids[1], range_ids[0]
                range_cmd = True
            else:
                vlan_id = range_ids[0]

        if not range_cmd:
            if cli_type == 'click':
                cmd_str = "sudo config vlan {} {} ".format(config, vlan_id)
                command.append(cmd_str)
            elif cli_type == 'klish':
                cmd_str = 'no ' if config == 'del' else ''
                cmd_str += "interface Vlan {}".format(vlan_id)
                command.append(cmd_str)
                if config == 'add':
                    command.append('exit')
        elif st.is_feature_supported("vlan-range", dut) and cli_type != 'klish':
            if cli_type == 'click':
                cmd_str = "sudo config vlan range {} {} {}".format(config, range_min, range_max)
                command.append(cmd_str)
        else:
            for vid in range(range_min, range_max + 1):
                if cli_type == 'click':
                    cmd_str = "sudo config vlan {} {} ".format(config, vid)
                    command.append(cmd_str)
                elif cli_type == 'klish':
                    cmd_str = 'no ' if config == 'del' else ''
                    cmd_str += "interface Vlan {}".format(vid)
                    command.append(cmd_str)
                    if config == 'add':
                        command.append('exit')

    if cli_type in ['click', 'klish']:
        try:
            st.config(dut, command, type=cli_type)
        except Exception as e:
            st.log(e)
            return False

    command = []
    if config == 'add':
        for _, if_data in vlan_data.items():
            vlan_id = if_data['vlan_id']

            range_cmd = False
            if 'range' in if_data.keys():
                range_ids = if_data['range']
                if range_ids[0] < range_ids[1]:
                    range_min, range_max = range_ids[0], range_ids[1]
                    range_cmd = True
                elif range_ids[0] > range_ids[1]:
                    range_min, range_max = range_ids[1], range_ids[0]
                    range_cmd = True
                else:
                    vlan_id = range_ids[0]

            for link_member in if_data['members']:

                if cli_type == 'klish':
                    intf_info = get_interface_number_from_name(link_member)
                    cmd_str = 'interface {} {}'.format(intf_info["type"], intf_info["number"])
                    command.append(cmd_str)

                if not range_cmd:
                    if cli_type == 'click':
                        cmd_str = "config vlan member {} {} {} ".format(config, vlan_id, link_member)
                        command.append(cmd_str)
                    elif cli_type == 'klish':
                        cmd_str = "switchport trunk allowed Vlan {} {}".format(operation, vlan_id)
                        command.append(cmd_str)
                elif st.is_feature_supported("vlan-range", dut):
                    if cli_type == 'click':
                        cmd_str = "config vlan member range {} {} {} {}".format(config, range_min, range_max, link_member)
                        command.append(cmd_str)
                    elif cli_type == 'klish':
                        cmd_str = "switchport trunk allowed Vlan {} {}-{}".format(operation, range_min, range_max)
                        command.append(cmd_str)
                else:
                    for vid in range(range_min, range_max + 1):
                        if cli_type == 'click':
                            cmd_str = "config vlan member {} {} {} ".format(config, vid, link_member)
                            command.append(cmd_str)
                        elif cli_type == 'klish':
                            cmd_str = "switchport trunk allowed Vlan {} {}".format(operation, vid)
                            command.append(cmd_str)

                if cli_type == 'klish':
                    command.append('exit')

        if cli_type in ['click', 'klish']:
            try:
                st.config(dut, command, type=cli_type)
            except Exception as e:
                st.log(e)
                return False

    return True


def config_interface_vrf_binds(dut, if_vrf_data={}, config='yes', cli_type=''):
    # Duplicate API, should not be used in FT. This is used by UT script only

    if config == 'yes' or config == 'add':
        config = 'bind'
    elif config == 'no' or config == 'del':
        config = 'unbind'
    else:
        st.error("Invalid config type {}".format(config))
        return False

    cli_type = st.get_ui_type(dut, cli_type=cli_type)

    command = []
    for if_name, if_data in if_vrf_data.items():
        vrf = if_data['vrf']
        if cli_type == 'click':
            cmd_str = "sudo config interface vrf {} {} {} ".format(config, if_name, vrf)
            command.append(cmd_str)
        elif cli_type == 'klish':
            intf_info = get_interface_number_from_name(if_name)
            cmd_str = 'interface {} {}'.format(intf_info["type"], intf_info["number"])
            command.append(cmd_str)
            cmd_str = "no " if config == 'unbind' else ''
            cmd_str += "ip vrf forwarding {}".format(vrf)
            command.append(cmd_str)
            command.append('exit')
        elif cli_type in ['rest-patch', 'rest-put']:
            st.log("Spytest API not yet supported for REST type")
            return False
        else:
            st.log("Unsupported CLI TYPE {}".format(cli_type))
            return False

    if cli_type in ['click', 'klish']:
        try:
            st.config(dut, command, type=cli_type)
        except Exception as e:
            st.log(e)
            return False

    return True


def config_portgroup_property(dut, portgroup, value, property="speed", skip_error=False, cli_type=""):
    # Duplicate API, should not be used in FT. Not used in any scripts
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """
    Function to configure portgroup properties
    Author: Ramprakash Reddy (ramprakash-reddy.kanala@broadcom.com)
    :param dut:
    :param portgroup:
    :param value:
    :param property:
    :param skip_error:
    :param cli_type:
    :return:
    """
    command = "config portgroup {} {} {}".format(property, portgroup, value)
    st.config(dut, command, skip_error_check=skip_error, type=cli_type)
    return True


def show_portgroup(dut, interface=None, cli_type=""):
    # Duplicate API, should not be used in FT. Not used in any scripts
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """
    API to get the list of port groups available in DUT
    Author: Chaitanya Vella (chaitanya.vella-kumar@broadcom.com)
    :param dut:
    :param interface:
    :return: [{'ports': ['Ethernet0', 'Ethernet1', 'Ethernet2', 'Ethernet3', 'Ethernet4',
    'Ethernet5', 'Ethernet6', 'Ethernet7', 'Ethernet8', 'Ethernet9', 'Ethernet10', 'Ethernet11'],
    'valid_speeds': ['25000', '10000', '1000'], 'portgroup': '1'},
    {'ports': ['Ethernet12', 'Ethernet13', 'Ethernet14', 'Ethernet15', 'Ethernet16', 'Ethernet17',
    'Ethernet18', 'Ethernet19', 'Ethernet20', 'Ethernet21', 'Ethernet22', 'Ethernet23'],
    'valid_speeds': ['25000', '10000', '1000'], 'portgroup': '2'}, {'ports': ['Ethernet24',
    'Ethernet25', 'Ethernet26', 'Ethernet27', 'Ethernet28', 'Ethernet29', 'Ethernet30', 'Ethernet31',
    'Ethernet32', 'Ethernet33', 'Ethernet34', 'Ethernet35'], 'valid_speeds': ['25000', '10000', '1000'],
    'portgroup': '3'}, {'ports': ['Ethernet36', 'Ethernet37', 'Ethernet38', 'Ethernet39', 'Ethernet40',
    'Ethernet41', 'Ethernet42', 'Ethernet43', 'Ethernet44', 'Ethernet45', 'Ethernet46', 'Ethernet47'],
    'valid_speeds': ['25000', '10000', '1000'], 'portgroup': '4'}]
    """
    response = list()
    command = "show portgroup"
    output = st.show(dut, command, type=cli_type)
    if output:
        for data in output:
            port_range = data["ports"].replace("Ethernet", "").split("-")
            res = dict()
            res["ports"] = list()
            for i in range(int(port_range[0]), int(port_range[1]) + 1):
                if not interface:
                    res["ports"].append("Ethernet{}".format(i))
                else:
                    if interface == "Ethernet{}".format(i):
                        res["ports"].append("Ethernet{}".format(i))
                        break
            if res["ports"]:
                res["portgroup"] = data["portgroup"]
                res["valid_speeds"] = data["valid_speeds"].split(",")
                response.append(res)
            if interface and res["ports"]:
                break
    return response


def verify_portgroup(dut, **kwargs):
    # Duplicate API, should not be used in FT. Not used in any scripts
    """
    API to verify portgroup
    Author: Chaitanya Vella (chaitanya.vella-kumar@broadcom.com)
    :param dut:
    :param kwargs: {"cli_type":"click","interface":"Ethernet5","portgroup":"1","speed":"1000"}
    :return:
    """
    cli_type = kwargs.get("cli_type", "click")
    interface = kwargs.get("interface", None)
    portgroup = kwargs.get("portgroup", None)
    speed = kwargs.get("speed", None)
    result = 0
    output = show_portgroup(dut, interface=interface, cli_type=cli_type)
    if not output:
        st.log("Empty output observed - {}".format(output))
        return False
    for data in output:
        if portgroup and str(data["portgroup"]) != str(portgroup):
            result = 1
        else:
            result = 0
        if speed and str(speed) not in data["speed"]:
            result = 1
        else:
            result = 0
    if result:
        return False
    return True


def is_port_group_supported(dut, cli_type=""):
    # Duplicate API, should not be used in FT. Not used in any scripts
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """
    API to check whether port group is supported or not
    Author: Chaitanya Vella (chaitanya.vella-kumar@broadcom.com)
    :param dut:
    :return: False -- Unsupported
             True  -- Supported
    """
    output = show_portgroup(dut, cli_type=cli_type)
    if not output:
        return False
    else:
        return True


def config_ifname_type(dut, config='yes', cli_type="", ifname_type="alias", **kwargs):
    """
    Function to configure interface naming(Modes: native: Ethernet0, standard: Eth1/1)
    Author: Lakshminarayana D (lakshminarayana.d@broadcom.com)
    :param dut:
    :param config:
    :param cli_type:
    :return:
    """
    faster_cli = kwargs.pop('faster_cli', True)
    skip_error = kwargs.pop('skip_error', False)
    skip_error = kwargs.pop('skip_error_check', skip_error)
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    st.log('config_ifname_type: {}'.format(locals()))
    op_msg = "C" if config == "yes" else "Unc"

    if cli_type in ['click', 'vtysh']:
        st.warn("interface-naming command not available in {}".format(cli_type), dut=dut)
        return False
    elif cli_type in get_supported_ui_type_list():
        if ifname_type == "alias":
            ifname_mode = "STANDARD"
        elif ifname_type == "std-ext":
            ifname_mode = "STANDARD-EXT"
        else:
            ifname_mode = "NATIVE"
        sys_obj = umf_sys.System()
        setattr(sys_obj, 'IntfNamingMode', ifname_mode)
        cli_type_msg = "GNMI" if cli_type in ["gnmi", "gnmi-get", "gnmi-set"] else "REST"
        result = sys_obj.configure(dut, cli_type=cli_type)
        if not result.ok():
            st.error('test_step_failed: {}: {}onfigure INTERFACE NAMING at interface: {}'.format(cli_type_msg, op_msg, result.data))
            return False
    elif cli_type == 'klish':
        config = '' if config == 'yes' else 'no'
        ifname_cmd = "standard extended" if ifname_type == "std-ext" else "standard"
        if config == 'no':
            ifname_cmd = 'standard'
        command = "{} interface-naming {}".format(config, ifname_cmd)
        output = st.config(dut, command, type='klish', faster_cli=faster_cli, skip_error_check=skip_error, **kwargs)
        if skip_error and "Error:" in output:
            st.error('test_step_failed: {}: {}onfigure INTERFACE NAMING'.format(cli_type, op_msg))
            return False
    else:
        st.error("Provided invalid CLI type-{}".format(cli_type))
        return False

    reboot_needed = False
    output = show_ifname_type(dut, cli_type='klish')
    config_mode = output[0]['mode']
    oper_mode = output[0]['oper_mode']
    if config_mode == 'standard-extended':
        if oper_mode != '':
            reboot_needed = True
    else:
        if oper_mode == 'standard-extended':
            reboot_needed = True

    if reboot_needed is True:
        st.log("Save and Reload to enable/disable standard extended configuration")
        st.config(dut, 'write memory', type='klish', conf=False)
        st.reboot(dut)
    else:
        st.log('Reload is not needed for the desired ifname_type')
    return True


def show_ifname_type(dut, **kwargs):
    """
    API to verify interface naming
    Author: Lakshminarayana D (lakshminarayana.d@broadcom.com)
    :param dut:
    :param cli_type:
    :return:
    """
    cli_type = kwargs.pop('cli_type', "klish") or "klish"
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    command = 'show interface-naming'
    if cli_type in ['click', 'vtysh']:
        st.warn("{} command not available in {}".format(command, cli_type), dut=dut)
        return False
    elif cli_type in ['rest-put', 'rest-patch', 'klish']:
        output = st.show(dut, command, type='klish', **kwargs)
    else:
        st.error("Provided invalid CLI type-{}".format(cli_type))
        return False

    return output or None


def verify_ifname_type(dut, mode='native', cli_type=''):
    """
    API to verify interface naming either native or standard
    Author: Lakshminarayana D (lakshminarayana.d@broadcom.com)
    :param dut:
    :param cli_type:
    :param mode: default is native
    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    output = show_ifname_type(dut, cli_type=cli_type)

    if not output:
        st.error("Empty output observed - {}".format(output))
        return False

    if output[0]['mode'] != mode:
        return False
    return True


def get_ifname_alias(dut, intf_list=None, cli_type=''):
    """
    API to return alternate name(s) for given native interface name(s)
    Author: Lakshminarayana D (lakshminarayana.d@broadcom.com)
    :param dut:
    :param cli_type:
    :param intf_list: [Ethernet0, Ethernet1]
    :return: API will return alternate name for provided interface name. Ethernet0-Eth1/1
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)

    if cli_type in ['click']:
        alias_list = get_interface_property(dut, intf_list, 'alias', cli_type=cli_type)
    else:
        alias_list = get_interface_property(dut, intf_list, 'altname', cli_type=cli_type)
    if not alias_list:
        st.error("Empty output observed - {}".format(alias_list))
        return False
    return alias_list


def get_physical_ifname_map(dut, cli_type=''):
    """
    API to return interface native to alias mapping
    Author: Lakshminarayana D (lakshminarayana.d@broadcom.com)
    :param dut:
    :param cli_type:
    :return: API will return native to alias map
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)

    output = interface_status_show(dut, cli_type=cli_type)
    prop = "alias" if cli_type in ['click'] else "altname"
    entries = filter_and_select(output, ["interface", prop])
    retval = OrderedDict()
    for entry in entries:
        interface, alias = entry["interface"], entry[prop]
        if interface.startswith("Ethernet"):
            retval[interface] = alias
        elif interface.startswith("Eth"):
            retval[alias] = interface
    return retval


def get_native_interface_name(dut, if_name, cli_type=''):
    """
    API to return native interface name(s)
    Author: naveen.suvarna@broadcom.com
    :param dut:
    :if_name: Interface name string or list of strings
    :param cli_type:
    :return: API will return native name if its a Ethernet physical
             interface else same input name will be returned
             if input if_name type is list, return type will be list
             else return type will be string
    """

    if isinstance(if_name, list):
        if_name_list = if_name
    else:
        if_name_list = [if_name]

    cli_type = st.get_ui_type(dut, cli_type=cli_type)

    ntv_if_list = []
    show_if_entries = None
    name_field = 'interface'
    alias_field = "alias" if cli_type in ['click'] else "altname"
    phy_if_types = ["Ethernet", "ethernet", "Eth", "eth"]

    for curr_if in if_name_list:
        if curr_if == '':
            ntv_if_list.append('')
            continue

        phy_interface = False
        for intf_prefix in phy_if_types:
            if curr_if.startswith(intf_prefix):
                phy_interface = True
                break

        if phy_interface is not True:
            ntv_if_list.append(curr_if)
            continue

        intf_info = get_interface_number_from_name(curr_if)
        if not intf_info:
            st.error("Interface data not found for {} ".format(curr_if))
            ntv_if_list.append(curr_if)
            continue

        if intf_info["type"] not in phy_if_types:
            ntv_if_list.append(curr_if)
            continue

        if show_if_entries is None:
            output = interface_status_show(dut, cli_type=cli_type)
            show_if_entries = filter_and_select(output, [name_field, alias_field])

        # found = False
        for if_entry in show_if_entries:
            interface, alias_name = if_entry[name_field], if_entry[alias_field]
            if interface == curr_if or alias_name == curr_if:
                if interface.startswith("Ethernet"):
                    ntv_if_list.append(interface)
                    # found = True
                    break
                elif alias_name.startswith("Ethernet"):
                    ntv_if_list.append(alias_name)
                    # found = True
                    break

        # if found is False :
            # ntv_if_list.append(one_if)

    if isinstance(if_name, list):
        st.log("Get Native interface names {} -> {}.".format(if_name, ntv_if_list))
        return ntv_if_list
    else:
        st.log("Get Native interface name {} -> {}.".format(if_name, ntv_if_list[0]))
        return ntv_if_list[0]


def config_interface_polling(dut, poll_interval, load_interval, **kwargs):
    """
    API to configure interface polling interval
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    :param dut:
    :param poll_interval:
    :param load_interval:
    :return:
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut, **kwargs))
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    if cli_type in ['rest-put', 'rest-patch', "klish"]:
        st.log("Warning: Interface Polling interval command is supported only in click mode so fall back to click")
    command = "config interface counter -poll-interval {} -load-interval {}".format(int(poll_interval), int(load_interval))
    st.config(dut, command, type="click")


def show_intf_status_reason(dut, reason, intf, **kwargs):
    """
    API to get the interfaces events for a reason
    Author: Prasanth Kunjum Veettil (prsanth.kunjumveettil@broadcom.com)
    :param dut:
    :param cli_type:
    :return: list of interfaces along with the events for a reason.
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = 'klish' if cli_type == 'click' else cli_type
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    if cli_type == 'klish':
        command = 'show interface status {} | find {}'.format(reason, intf)
        return st.show(dut, command, type=cli_type)
    else:
        st.error("Unsupported CLI_TYPE: {}".format(cli_type))
        return False


def show_interface_down_event(dut, intf_list, **kwargs):
    """
    API to the interface down events output
    Author: Jagadish Chatrasi (jagadish.chatrasi@broadcom.com)
    :param dut:
    :param intf_list:
    :return: list of interfaces along with their down-event
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = 'klish' if cli_type == 'click' else cli_type
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    intfs = make_list(intf_list)
    if cli_type == 'klish':
        output = []
        for intf in intfs:
            output.extend(show_interface(dut, interface=intf, cli_type=cli_type))
        return output
    elif cli_type in ['rest-patch', 'rest-put']:
        return op_processor.rest_get_intf_down_event(dut, intfs)
    else:
        st.error("Unsupported CLI_TYPE: {}".format(cli_type))
        return False


def show_interface_down_reason(dut, **kwargs):
    """
    API to the interface down reasons output
    Author: Jagadish Chatrasi (jagadish.chatrasi@broadcom.com)
    :param dut:
    :param cli_type:
    :return: list of interfaces along with their down-reason
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = 'klish' if cli_type == 'click' else cli_type
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    intfs = make_list(kwargs.get('intf')) if kwargs.get('intf') else []
    if cli_type == 'klish':
        return interface_status_show(dut, interfaces=intfs, cli_type=cli_type)
    elif cli_type in ['rest-patch', 'rest-put']:
        interfaces = intfs if intfs else get_all_interfaces(dut, cli_type=cli_type)
        return op_processor.rest_get_intf_down_reason(dut, interfaces)
    else:
        st.error("Unsupported CLI_TYPE: {}".format(cli_type))
        return False


def config_counters_rif_interval(dut, **kwargs):
    """
        config_counters_rif_interval(vars.D1, interval = 2)
        API to configure interface sample collection interval
        Author: MA Raheem Ali (mohammed.raheem-ali@broadcom.com)
        :param dut:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    # Falling back KLISH as config command is available in HLD but not the unconfig. Will use Klish till we get the data.
    cli_type = 'klish' if cli_type == 'click' else cli_type
    skip_error_check = kwargs.get("skip_error_check", False)
    config = kwargs.get('config', 'yes')
    interval = kwargs.get('interval', '')
    command = ''
    interval = '' if config == 'no' else interval
    if cli_type in get_supported_ui_type_list():
        if config == 'yes':
            ni_obj = umf_ni.NetworkInstance(Name='default', RifCounterInterval=int(interval))
            result = ni_obj.configure(dut, cli_type=cli_type)
        else:
            ni_obj = umf_ni.NetworkInstance(Name='default')
            result = ni_obj.unConfigure(dut, target_attr=ni_obj.RifCounterInterval, cli_type=cli_type)
        if not result.ok():
            st.error("test_step_failed: Configure RIF Interval")
            return False
        return True
    elif cli_type == 'klish':
        config = 'no' if config == 'no' else ''
        command = "{} counters rif interval {}".format(config, interval)
    elif cli_type == 'click':
        config = 'del' if config == 'no' else 'add'
        command = "config rif counters interval {} {}".format(config, interval)
    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, "rest_urls")
        url = rest_urls['config_rif_interval'].format(name='default')
        if config == 'yes':
            data = {"openconfig-network-instance-ext:rif-counter-interval": int(interval)}
            if not config_rest(dut, http_method=cli_type, json_data=data, rest_url=url):
                st.error("Failed to Config RIF Interval")
                return False
        else:
            if not delete_rest(dut, http_method=cli_type, rest_url=url):
                st.error("Failed to Delete Configured RIF Interval")
                return False
        return True
    if cli_type in ['click', 'klish']:
        output = st.config(dut, command, type=cli_type, skip_error_check=skip_error_check)
        if 'Error' in output:
            return False


def config_counters_vxlan_interval(dut, vtep_name, poll_interval, **kwargs):
    """
        Author: Sneha Ann Mathew (sneha.mathew@broadcom.com)

        API to configure vxlan counters sampling interval
        :param dut:
        :param vtep_name: vxlan interface name
        :param poll_interval: sampling interval in seconds (def 5 sec)

        Usage: config_counters_vxlan_interval(vars.D1, interval = 10)
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    # Rest URI is sonic-yang implementation forcing to klish
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    skip_error_check = kwargs.get("skip_error_check", False)
    config = kwargs.get('config', 'yes')

    if cli_type == 'klish':
        poll_interval = 5 if config == 'no' else poll_interval
        command = []
        command.append('interface vxlan {}'.format(vtep_name))
        command.append('counter polling-interval {}'.format(poll_interval))
        command.append('exit')
    elif cli_type == 'click':
        # click interval to be given in ms.
        poll_interval = 5000 if config == 'no' else poll_interval * 1000
        command = "counterpoll tunnel interval {}".format(poll_interval)
    elif cli_type in ['rest-patch', 'rest-put']:
        poll_interval = 5000 if config == 'no' else poll_interval * 1000
        rest_urls = st.get_datastore(dut, "rest_urls")
        url = rest_urls['config_vxlan_interval']
        payload = {"sonic-counters:FLEX_COUNTER_TABLE_LIST": [{
            "id": "TUNNEL",
            "FLEX_COUNTER_STATUS": "enable",
            "POLL_INTERVAL": int(poll_interval)
        }]
        }
        if not config_rest(dut, http_method=cli_type, json_data=payload, rest_url=url):
            st.error("Failed to Config Vxlan tunnel satistics polling interval")
            return False
        return True
    else:
        st.error("Invalid CLI type - {}".format(cli_type))
        return False

    return st.config(dut, command, type=cli_type, skip_error_check=skip_error_check)


def clear_vxlan_counters(dut, **kwargs):
    '''
    Api to clear vxlan tunnel statistics

    author: Sneha Ann Mathew (sneha.mathew@broadcom.com)

    :param dut:
    :param kwargs: tunnel_dest_ip: <dest_ip/''>
    :return:

    Usage: clear_vxlan_counters(vars.D1)
            clear_vxlan_counters(vars.D1,tunnel_dest_ip="4.4.4.4")

    '''
    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    skip_error_check = kwargs.get("skip_error_check", False)

    tunnel_dest_ip = kwargs.get('tunnel_dest_ip', '')
    # Click doesn't have option to clear counters per tunnel
    if cli_type == 'click' and tunnel_dest_ip != '':
        cli_type = 'klish'

    if cli_type == 'klish':
        command = "clear counters vxlan {}".format(tunnel_dest_ip)
    elif cli_type == 'click':
        command = "sonic-clear tunnelcounters"
    elif cli_type in ['rest-patch', 'rest-put']:
        if tunnel_dest_ip == '':
            tunnel_dest_ip = 'all'
        rest_urls = st.get_datastore(dut, "rest_urls")
        url = rest_urls['clear_vxlan_statistics']
        payload = {"openconfig-vxlan-rpc:input": {
            "vxlan_tunnel_iface": tunnel_dest_ip
        }
        }
        if not config_rest(dut, http_method="post", json_data=payload, rest_url=url):
            st.error("Failed to Clear Vxlan tunnel satistics")
            return False
        return True
    else:
        st.error("Invalid CLI type - {}".format(cli_type))
        return False

    return st.config(dut, command, type=cli_type, conf=False, skip_error_check=skip_error_check)


def parse_rest_output_vxlan_counters(response):
    result = []
    dict = {}
    tunnel_state = response['output'].get('openconfig-vxlan:state', {})
    if tunnel_state:
        dict['dip'] = tunnel_state.get('peer-ip', '')
        vxlan_counters = tunnel_state.get('statistics', {})
        if vxlan_counters:
            dict['rx_bytes'] = vxlan_counters.get('in-octets', 0)
            dict['rx_ok'] = vxlan_counters.get('in-pkts', 0)
            dict['rx_bps'] = vxlan_counters.get('in-octets-per-second', 0)
            dict['rx_pps'] = vxlan_counters.get('in-pkts-per-second', 0)
            dict['tx_bytes'] = vxlan_counters.get('out-octets', 0)
            dict['tx_ok'] = vxlan_counters.get('out-pkts', 0)
            dict['tx_bps'] = vxlan_counters.get('out-octets-per-second', 0)
            dict['tx_pps'] = vxlan_counters.get('out-pkts-per-second', 0)
        result.append(dict)
    return result


def parse_umf_output_vxlan_counters(response):
    result = []
    dict = {}
    tunnel_data = response.get('openconfig-vxlan:vxlan-tunnel-info', [])
    if tunnel_data:
        tunnel_data = tunnel_data[0]
        dict['dip'] = tunnel_data.get('state', {}).get('peer-ip', '')
        vxlan_counters = tunnel_data.get('state', {}).get('statistics', {})
        if vxlan_counters:
            dict['rx_bytes'] = vxlan_counters.get('in-octets', 0)
            dict['rx_ok'] = vxlan_counters.get('in-pkts', 0)
            dict['rx_bps'] = vxlan_counters.get('in-octets-per-second', 0)
            dict['rx_pps'] = vxlan_counters.get('in-pkts-per-second', 0)
            dict['tx_bytes'] = vxlan_counters.get('out-octets', 0)
            dict['tx_ok'] = vxlan_counters.get('out-pkts', 0)
            dict['tx_bps'] = vxlan_counters.get('out-octets-per-second', 0)
            dict['tx_pps'] = vxlan_counters.get('out-pkts-per-second', 0)
        result.append(dict)
    return result


def show_vxlan_counters(dut, **kwargs):
    '''
    Api to get vxlan tunnel statistics

    author: Sneha Ann Mathew (sneha.mathew@broadcom.com)

    :param dut:
    :param kwargs: tunnel_dest_ip: <dest_ip/all>
    :return:

    Usage: show_vxlan_counters(vars.D1)
            show_vxlan_counters(vars.D1,tunnel_dest_ip="4.4.4.4")
    '''
    cli_type = st.get_ui_type(dut, **kwargs)
    skip_error_check = kwargs.get("skip_error_check", False)
    tunnel_dest_ip = kwargs.get('tunnel_dest_ip', '')

    if cli_type in get_supported_ui_type_list() + ['rest-put', 'rest-patch']:
        cli_type = 'klish' if not tunnel_dest_ip else cli_type

    if cli_type in get_supported_ui_type_list():
        filter_type = kwargs.get('filter_type', 'ALL')
        query_params_obj = get_query_params(yang_data_type=filter_type, cli_type=cli_type)
        tunnel_obj = umf_vxlan.VxlanTunnelInfo(PeerIp=tunnel_dest_ip)
        st.banner("########## Verify Vxlan Counters to DIP:{} ##########".format(tunnel_dest_ip))
        # result = tunnel_obj.verify(dut, match_subset=True, query_param=query_params_obj, cli_type=cli_type)
        rv = tunnel_obj.get_payload(dut, query_param=query_params_obj, cli_type=cli_type)
        if rv.ok():
            st.log("UMF O/P:{}".format(rv.payload))
            output = parse_umf_output_vxlan_counters(rv.payload)
            if output:
                return output
            return []
        else:
            return []
    elif cli_type == 'klish' or cli_type == 'click':
        command = "show vxlan counters {}".format(tunnel_dest_ip)
        output = st.show(dut, command, type=cli_type, skip_error_check=skip_error_check)
    elif cli_type in ['rest-patch', 'rest-put']:
        st.log('KLISH output for debugging REST')
        st.show(dut, 'show vxlan counters {}'.format(tunnel_dest_ip), type='klish')
        if tunnel_dest_ip == '':
            tunnel_dest_ip = 'all'
        rest_urls = st.get_datastore(dut, "rest_urls")
        url = rest_urls['show_vxlan_counters'].format(tunnel_dest_ip)
        response = get_rest(dut, rest_url=url)
        st.log("Rest O/P:{}".format(response))
        if response and response.get('output'):
            output = parse_rest_output_vxlan_counters(response)
        else:
            st.error("OCYANG-FAIL: show vxlan counters - Get Response is empty")
            return False
    else:
        st.error("Invalid CLI type - {}".format(cli_type))
        return False

    if len(output) == 0:
        st.error("Output is Empty")
        return False

    return output


def parse_rest_output_vxlan_interval(response):
    dict = {}
    vxlan_counter_state = response['output'].get('sonic-counters:FLEX_COUNTER_TABLE_LIST', [])
    if vxlan_counter_state:
        vxlan_counter_state = vxlan_counter_state[0]
        dict['vxlan_polling_interval'] = vxlan_counter_state.get('POLL_INTERVAL', 0)
        dict['counters_id'] = vxlan_counter_state.get('id', '')
        dict['vxlan_counters_status'] = vxlan_counter_state.get('FLEX_COUNTER_STATUS', 'enable')
        return [dict]
    else:
        return []


def verify_vxlan_counters_polling_interval(dut, poll_interval, **kwargs):
    '''
    Api to get vxlan tunnel statistics

    author: Sneha Ann Mathew (sneha.mathew@broadcom.com)

    :param dut:
    :param poll_interval: expected polling_interval in sec
    :return:

    Usage: verify_vxlan_counters_polling_interval(vars.D1,poll_interval==10)
    '''
    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = force_cli_type_to_klish(cli_type=cli_type)

    skip_error_check = kwargs.get("skip_error_check", False)

    tunnel_dest_ip = kwargs.get('tunnel_dest_ip', '')

    if cli_type == 'klish':
        command = "show vxlan counters {}".format(tunnel_dest_ip)
        output = st.show(dut, command, type=cli_type, skip_error_check=skip_error_check)
        if output:
            dut_poll_interval = int(output[0]['vxlan_polling_interval'])
    elif cli_type == 'click':
        command = "counterpoll show"
        output = st.show(dut, command, type=cli_type, skip_error_check=skip_error_check)
        if output:
            dut_poll_interval = int(output[0]['vxlan_polling_interval']) / 1000
    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, "rest_urls")
        url = rest_urls['get_vxlan_counter_interval']
        response = get_rest(dut, rest_url=url)
        st.log('KLISH output for debugging REST')
        st.show(dut, 'show vxlan counters {}'.format(tunnel_dest_ip), type='klish')
        if response and response.get('output'):
            output = parse_rest_output_vxlan_interval(response)
            if output:
                dut_poll_interval = int(output[0]['vxlan_polling_interval']) / 1000
        else:
            st.error("OCYANG-FAIL: show vxlan counters - Get Response is empty")
            return False
    else:
        st.error("Invalid CLI type - {}".format(cli_type))
        return False

    if len(output) == 0:
        st.error("Output is Empty")
        return False
    if "return_op" in kwargs:
        return output

    if dut_poll_interval == poll_interval:
        st.log("Match Found: Expect poll_interval:{} and Got:{}".format(poll_interval, dut_poll_interval))
        return True
    else:
        st.log("Match Not Found: Expect poll_interval:{} but Got:{}".format(poll_interval, dut_poll_interval))
        return False


def show_interface(dut, interface='', cli_type=''):
    """
    Author: Pava Kumar Kasula(pavan.kasula@broadcom.com)
    Function to get the interface
    :param dut:
    :param interfaces:
    :param cli_type:
    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    cli_type = 'klish' if cli_type in ["click"] or 'Eth' in interface else cli_type
    cli_type = force_cli_type_to_klish(cli_type=cli_type)

    if cli_type == "klish":
        intf = get_interface_number_from_name(interface)
        command = "show interface {} {}".format(intf['type'], intf['number'])
        return st.show(dut, command, type=cli_type)
    elif cli_type in ['rest-put', 'rest-patch']:
        transformed_output = dict()
        rest_urls = st.get_datastore(dut, 'rest_urls')
        rest_url = rest_urls['show_interface'].format(interface)
        rest_output = get_rest(dut, rest_url=rest_url)['output']['openconfig-interfaces:interface'][0]
        transformed_output['line_protocol'] = str(rest_output['state']['oper-status']).lower()

        if 'mac-address' in str(rest_output['state']):
            transformed_output['mac'] = str(rest_output['state']['mac-address']).lower()
        transformed_output['interface'] = str(rest_output['state']['name'])
        transformed_output['status'] = str(rest_output['state']['admin-status']).lower()
        if 'vlan' in interface:
            transformed_output['mtu'] = str(rest_output['state']['mtu'])
            if 'openconfig-if-ip:ipv4' in rest_output['openconfig-vlan:routed-vlan'].keys():
                transformed_output['ip_addr'] = str(rest_output['openconfig-vlan:routed-vlan']['openconfig-if-ip:ipv4']['addresses']['address'][0]['state']['ip'])
            if 'openconfig-if-ip:ipv6' in rest_output['openconfig-vlan:routed-vlan'].keys():
                transformed_output['ipv6_addr'] = str(rest_output['openconfig-vlan:routed-vlan']['openconfig-if-ip:ipv6']['addresses']['address'][0]['state']['ip']).lower()

        if 'Loopback' in interface:
            if 'openconfig-if-ip:ipv4' in str(rest_output['subinterfaces']['subinterface'][0]):
                transformed_output['ip_addr'] = str(rest_output['subinterfaces']['subinterface'][0]['openconfig-if-ip:ipv4']['addresses']['address'][0]['ip'])
            if 'addresses' in str(rest_output['subinterfaces']['subinterface'][0]['openconfig-if-ip:ipv6']):
                transformed_output['ipv6_addr'] = str(rest_output['subinterfaces']['subinterface'][0]['openconfig-if-ip:ipv6']['addresses']['address'][0]['ip'])

        return [transformed_output]
    else:
        st.error("Provided invalid CLI type-{}".format(cli_type))
        return False


def verify_interface(dut, **kwargs):
    """
    Author:pavan.kasula@broadcom.com
    :param dut:
    :param kwargs:
    :return:
    This verify api supports for interface type Ethernet, Portchannel, Vlan and Loopback
    """

    cli_type = st.get_ui_type(dut, **kwargs)

    if "Po" in kwargs['interface']:
        import apis.switching.portchannel as pc_api
        return pc_api.verify_portchannel(dut, portchannel_name=kwargs['interface'], cli_type=cli_type)

    if cli_type in ['click']:
        cli_type = 'klish'
    output = show_interface(dut, interface=kwargs['interface'], cli_type=cli_type)
    st.banner(output)

    if len(output) == 0:
        st.error("Output is Empty")
        return False

    if 'return_output' in kwargs:
        return output

    for each in kwargs.keys():
        match = {each: kwargs[each]}
        entries = filter_and_select(output, None, match)
        if not entries:
            st.error("Match not found for {}:   Expected - {} Actual - {} ".format(each, kwargs[each], output[0][each]))
            return False
    return True


def interface_flap(dut, port_list, **kwargs):
    """
    Author: mohammed.raheem-ali@broadcom.com
    :param dut:
    :param port_list:
    :param kwargs:
    :return:
    This API is to trigger a flap without exiting the interface.
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    skip_error_check = kwargs.get("skip_error_check", False)
    # We don't have support of range in REST if we want to flap more than 1 interfaces due to which forced it to KLISH.
    cli_type = 'klish' if cli_type in ["rest-patch", "rest-put"] + get_supported_ui_type_list() and len(port_list) > 1 else cli_type
    if cli_type in get_supported_ui_type_list():
        port_hash_list = segregate_intf_list_type(intf=port_list, range_format=False)
        interface_list = port_hash_list['intf_list_all']
        for interface in interface_list:
            interface_shutdown(dut, interfaces=interface, cli_type=cli_type)
            interface_noshutdown(dut, interfaces=interface, cli_type=cli_type)
    elif cli_type == 'click':
        port_hash_list = segregate_intf_list_type(intf=port_list, range_format=False)
        interface_list = port_hash_list['intf_list_all']
        for interface in interface_list:
            try:
                st.config(dut, "config interface shutdown {}".format(interface))
                st.config(dut, "config interface startup {}".format(interface))
            except ValueError:
                st.warn("Failed to execute command - try alternative")
                st.config(dut, "config interface shutdown {}".format(interface))
                st.config(dut, "config interface startup {}".format(interface))
    elif cli_type == 'klish':
        commands = list()
        port_hash_list = segregate_intf_list_type(intf=port_list, range_format=True)
        interface_list = port_hash_list['intf_list_all']
        for interface in interface_list:
            if not is_a_single_intf(interface):
                commands.append("interface range {}".format(interface))
            else:
                intf_details = get_interface_number_from_name(interface)
                commands.append("interface {} {}".format(intf_details["type"], intf_details["number"]))
            commands.append('shutdown')
            commands.append('no shutdown')
            commands.append("exit")
        if commands:
            st.config(dut, commands, type=cli_type, skip_error_check=skip_error_check)
            return True
        return False
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        port_hash_list = segregate_intf_list_type(intf=port_list, range_format=False)
        interface_list = port_hash_list['intf_list_all']
        for interface in interface_list:
            url = rest_urls['per_interface_config'].format(interface)
            for oper in [False, True]:
                intf_operation = {"openconfig-interfaces:config": {"enabled": oper}}
                if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=intf_operation):
                    return False
        return True
    else:
        st.log("Unsupported CLI TYPE {}".format(cli_type))
        return False


def verify_pg_watermark_interface(dut, intf_name, buffer_type, **kwargs):
    '''
    verifies priority-group watermark for shared, headroom and percentage buffer
    :param dut: Device name where the command to be executed
    :param intf_name: interface where show command to be verified
    :param buffer_type: [shared | headroom | percentage shared | percentage headroom]
    :param pg0, pg1, pg2, pg3, pg4, pg5, pg6, pg7
    :return: True/False  True - success case; False - Failure case

    usage:  verify_pg_watermark_interface(dut,intf_name="Ethernet0",buffer_type="shared",pg7="10")
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    '''
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut, **kwargs))
    if "return_output" in kwargs:
        cli_type = 'klish'

    intf_details = get_interface_number_from_name(intf_name)
    cmd = "{} interface {} {}".format(buffer_type, intf_details["type"], intf_details["number"])

    if cli_type in get_supported_ui_type_list() + ['klish'] and "return_output" not in kwargs:
        qos_obj = umf_qos.Qos()
        dict1 = {}
        for key in kwargs.keys():
            if "pg" in key:
                intf = "{}{}".format(intf_details["type"], intf_details["number"])
                pg_name = "{}:{}".format(intf, key.split("pg")[1])
                buffer_dict = {}
                intf_obj = umf_qos.Interface(InterfaceId=intf, Qos=qos_obj)
                buffer_dict['Interface'] = intf_obj
                if buffer_type == 'headroom':
                    buffer_dict['HeadroomWatermark'] = kwargs[key]
                    pg_obj = umf_qos.PriorityGroup(Name=pg_name, **buffer_dict)
                    out = pg_obj.verify(dut, match_subset=True, cli_type=cli_type)
                    if cli_type in ['klish']:
                        result = out.data
                        if len(result) > 0 and key in result[0]:
                            dict1[key] = result[0][key]
                        else:
                            dict1[key] = "0"
                    else:
                        dict1[key] = out.payload['openconfig-qos:priority-group'][0]['state']['headroom-watermark']
                    output = [dict1]
                elif buffer_type == 'shared':
                    buffer_dict['SharedWatermark'] = kwargs[key]
                    pg_obj = umf_qos.PriorityGroup(Name=pg_name, **buffer_dict)
                    out = pg_obj.verify(dut, match_subset=True, cli_type=cli_type)
                    if cli_type in ['klish']:
                        result = out.data
                        if len(result) > 0 and key in result[0]:
                            dict1[key] = result[0][key]
                        else:
                            dict1[key] = "0"
                    else:
                        dict1[key] = out.payload['openconfig-qos:priority-group'][0]['state']['shared-watermark']
                    output = [dict1]
                elif buffer_type == 'percentage headroom':
                    buffer_dict['HeadroomWatermarkPercent'] = kwargs[key]
                    pg_obj = umf_qos.PriorityGroup(Name=pg_name, **buffer_dict)
                    out = pg_obj.verify(dut, match_subset=True, cli_type=cli_type)
                    if cli_type in ['klish']:
                        result = out.data
                        if len(result) > 0 and key in result[0]:
                            dict1[key] = result[0][key]
                        else:
                            dict1[key] = "0"
                    else:
                        dict1[key] = out.payload['openconfig-qos:priority-group'][0]['state']['headroom-watermark-percent']
                    output = [dict1]
                elif buffer_type == 'percentage shared':

                    buffer_dict['SharedWatermarkPercent'] = kwargs[key]
                    pg_obj = umf_qos.PriorityGroup(Name=pg_name, **buffer_dict)
                    out = pg_obj.verify(dut, match_subset=True, cli_type=cli_type)
                    if cli_type in ['klish']:
                        result = out.data
                        if len(result) > 0 and key in result[0]:
                            dict1[key] = result[0][key]
                        else:
                            dict1[key] = "0"
                    else:
                        dict1[key] = out.payload['openconfig-qos:priority-group'][0]['state']['shared-watermark-percent']
                    output = [dict1]
        if len(output) == 0:
            st.log("Output is empty for GNMI get output")
            return False
    elif cli_type in ['rest-put', 'rest-patch']:
        output = []
        dict1 = {}
        for key in kwargs.keys():
            if "pg" in key:
                rest_urls = st.get_datastore(dut, 'rest_urls')
                if buffer_type == 'headroom':
                    url = rest_urls['get_pg_headroom_watermark'].format(intf_name, intf_name, key.split("pg")[1])
                    response = get_rest(dut, rest_url=url)
                    if "openconfig-qos:headroom-watermark" in response["output"]:
                        dict1[key] = response["output"]["openconfig-qos:headroom-watermark"]
                elif buffer_type == 'shared':
                    url = rest_urls['get_pg_shared_watermark'].format(intf_name, intf_name, key.split("pg")[1])
                    response = get_rest(dut, rest_url=url)
                    if "openconfig-qos:shared-watermark" in response["output"]:
                        dict1[key] = response["output"]["openconfig-qos:shared-watermark"]
                elif buffer_type == 'percentage shared':
                    url = rest_urls['get_pg_shared_watermark_percent'].format(intf_name, intf_name, key.split("pg")[1])
                    response = get_rest(dut, rest_url=url)
                    if "openconfig-qos:shared-watermark-percent" in response["output"]:
                        dict1[key] = response["output"]["openconfig-qos:shared-watermark-percent"]
                elif buffer_type == 'percentage headroom':
                    url = rest_urls['get_pg_headroom_watermark_percent'].format(intf_name, intf_name, key.split("pg")[1])
                    response = get_rest(dut, rest_url=url)
                    if "openconfig-qos:headroom-watermark-percent" in response["output"]:
                        dict1[key] = response["output"]["openconfig-qos:headroom-watermark-percent"]
        output.append(dict1)
        if len(output) == 0:
            st.error("PG arg is not passed so failing")
            return False

    if "return_output" in kwargs:
        return st.show(dut, "show priority-group watermark {}".format(cmd), type=cli_type)
    if len(output) == 0:
        st.error("Output is Empty")
        return False

    ret_val = True
    input_dict_list = kwargs_to_dict_list(**kwargs)
    if input_dict_list:
        for input_dict in input_dict_list:
            for output_dict in output:
                for key in input_dict:
                    if key not in ['intf_name', 'buffer_type']:
                        if int(input_dict[key]) <= int(output_dict[key]):
                            st.log("PASS DUT {} -> {} traffic count {} >= expected count {} for {} {} buffer".format(dut,
                                                                                                                     key, output_dict[key], input_dict[key], intf_name, buffer_type))
                        else:
                            st.log("FAIL DUT {} -> {} traffic count {} not >= expected count {} for {} {} buffer".format(dut,
                                                                                                                         key, output_dict[key], input_dict[key], intf_name, buffer_type))
                            ret_val = False

    return ret_val


def verify_queue_watermark_interface(dut, intf_name, queue_type, **kwargs):
    '''
    verifies queue watermark for unicast, multicast, percentage-multicast and percentage-unicast
    :param dut: Device name where the command to be executed
    :param intf_name: interface where show command to be verified
    :param queue_type: [unicast | multicast | percentage unicast | percentage multicast]
    :param uc0, uc1, uc2, uc3, uc4, uc5, uc6, uc7
    :return: True/False  True - success case; False - Failure case

    usage:  verify_queue_watermark_interface(dut,intf_name="Ethernet0",queue_type="unicast",uc5="10")
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    '''
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut, **kwargs))
    if "return_output" in kwargs:
        cli_type = 'klish'

    intf_details = get_interface_number_from_name(intf_name)
    cmd = "{} interface {} {}".format(queue_type, intf_details["type"], intf_details["number"])
    intf = "{}{}".format(intf_details["type"], intf_details["number"])

    if cli_type in get_supported_ui_type_list() + ['klish'] and "return_output" not in kwargs:
        qos_obj = umf_qos.Qos()
        dict1 = {}
        for key in kwargs.keys():
            intf_obj = umf_qos.Interface(InterfaceId=intf, Qos=qos_obj)
            if "uc" in key:
                q_name = "{}:{}".format(intf, key.split("uc")[1])
                buffer_dict = {}
                buffer_dict['Interface'] = intf_obj
                if queue_type == 'unicast':
                    buffer_dict['Watermark'] = kwargs[key]
                    buffer_dict['TrafficType'] = 'UC'
                    q_obj = umf_qos.OutputQueue(Name=q_name, **buffer_dict)
                    out = q_obj.verify(dut, match_subset=True, cli_type=cli_type)
                    if cli_type in ['klish']:
                        result = out.data
                        if len(result) > 0 and key in result[0]:
                            dict1[key] = result[0][key]
                        else:
                            dict1[key] = "0"
                    else:
                        dict1[key] = out.payload['openconfig-qos:queue'][0]['state']['watermark']
                    output = [dict1]
                elif queue_type == 'percentage unicast':
                    buffer_dict['WatermarkPercent'] = kwargs[key]
                    buffer_dict['TrafficType'] = 'UC'
                    q_obj = umf_qos.OutputQueue(Name=q_name, **buffer_dict)
                    out = q_obj.verify(dut, match_subset=True, cli_type=cli_type)
                    if cli_type in ['klish']:
                        result = out.data
                        if len(result) > 0 and key in result[0]:
                            dict1[key] = result[0][key]
                        else:
                            dict1[key] = "0"
                    else:
                        dict1[key] = out.payload['openconfig-qos:queue'][0]['state']['watermark-percent']
                    output = [dict1]
            if "mc" in key:
                q_name = "{}:{}".format(intf, key.split("mc")[1])
                buffer_dict = {}
                buffer_dict['Interface'] = intf_obj
                if queue_type == 'multicast':
                    buffer_dict['Watermark'] = kwargs[key]
                    buffer_dict['TrafficType'] = 'MC'
                    q_obj = umf_qos.OutputQueue(Name=q_name, **buffer_dict)
                    out = q_obj.verify(dut, match_subset=True, cli_type=cli_type)
                    if cli_type in ['klish']:
                        result = out.data
                        if len(result) > 0 and key in result[0]:
                            dict1[key] = result[0][key]
                        else:
                            dict1[key] = "0"
                    else:
                        dict1[key] = out.payload['openconfig-qos:queue'][0]['state']['watermark']
                    output = [dict1]
                elif queue_type == 'percentage multicast':
                    buffer_dict['WatermarkPercent'] = kwargs[key]
                    buffer_dict['TrafficType'] = 'MC'
                    q_obj = umf_qos.OutputQueue(Name=q_name, **buffer_dict)
                    out = q_obj.verify(dut, match_subset=True, cli_type=cli_type)
                    if cli_type in ['klish']:
                        result = out.data
                        if len(result) > 0 and key in result[0]:
                            dict1[key] = result[0][key]
                        else:
                            dict1[key] = "0"
                    else:
                        dict1[key] = out.payload['openconfig-qos:queue'][0]['state']['watermark-percent']
                    output = [dict1]
    elif cli_type in ['rest-put', 'rest-patch']:
        output = []
        dict1 = {}
        for key in kwargs.keys():
            if "uc" in key or "mc" in key:
                rest_urls = st.get_datastore(dut, 'rest_urls')
                if queue_type == 'unicast':
                    q_name = key.split("uc")[1]
                    url = rest_urls['get_q_watermark'].format(intf, intf, q_name)
                    response = get_rest(dut, rest_url=url)
                    if "openconfig-qos:watermark" in response["output"]:
                        dict1[key] = response["output"]["openconfig-qos:watermark"]
                elif queue_type == 'multicast':
                    q_name = key.split("mc")[1]
                    url = rest_urls['get_q_watermark'].format(intf, intf, q_name)
                    response = get_rest(dut, rest_url=url)
                    if "openconfig-qos:watermark" in response["output"]:
                        dict1[key] = response["output"]["openconfig-qos:watermark"]
                elif queue_type == 'percentage unicast':
                    q_name = key.split("uc")[1]
                    url = rest_urls['get_q_watermark_percent'].format(intf, intf, q_name)
                    response = get_rest(dut, rest_url=url)
                    if "openconfig-qos:watermark-percent" in response["output"]:
                        dict1[key] = response["output"]["openconfig-qos:watermark-percent"]
                elif queue_type == 'percentage multicast':
                    q_name = key.split("mc")[1]
                    url = rest_urls['get_q_watermark_percent'].format(intf, intf, q_name)
                    response = get_rest(dut, rest_url=url)
                    if "openconfig-qos:watermark-percent" in response["output"]:
                        dict1[key] = response["output"]["openconfig-qos:watermark-percent"]
        output.append(dict1)
        if len(output) == 0:
            st.error("PG arg is not passed so failing")
            return False

    if "return_output" in kwargs:
        return st.show(dut, "show priority-group watermark {}".format(cmd), type=cli_type)
    if len(output) == 0:
        st.error("Output is Empty")
        return False

    ret_val = True
    input_dict_list = kwargs_to_dict_list(**kwargs)
    if input_dict_list:
        for input_dict in input_dict_list:
            for output_dict in output:
                for key in input_dict:
                    if key not in ['intf_name', 'queue_type']:
                        if int(input_dict[key]) <= int(output_dict[key]):
                            st.log("PASS DUT {} -> {} traffic count {} >= expected count {} for {} {} queue".format(dut,
                                                                                                                    key, output_dict[key], input_dict[key], intf_name, queue_type))
                        else:
                            st.log("FAIL DUT {} -> {} traffic count {} not >= expected count {} for {} {} queue".format(dut,
                                                                                                                        key, output_dict[key], input_dict[key], intf_name, queue_type))
                            ret_val = False

    return ret_val


def get_fec_status(dut, **kwargs):
    cli_type = st.get_ui_type(dut, **kwargs)
    port = kwargs.get('port', None)
    cli_type = 'klish' if cli_type in get_supported_ui_type_list() else cli_type
    if port is None:
        ret = st.show(dut, "show interface fec status", type=cli_type)
    else:
        ret = st.show(dut, "show interface fec status {}".format(port), type=cli_type)
    return ret
