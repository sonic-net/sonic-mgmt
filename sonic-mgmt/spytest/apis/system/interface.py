# This file contains the list of API's for operations on interface
# @author : Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)

from spytest import st
from utilities.common import filter_and_select, make_list, exec_all, dicts_list_values, convert_to_bits
from utilities.utils import get_interface_number_from_name
import apis.system.port as portapi
import re


def interface_status_show(dut, interfaces=None, cli_type="click"):
    """
       Author: Chaitanya Vella (chaitanya.vella-kumar@broadcom.com)
    Function to get the interface(s) status
    :param dut:
    :param interfaces:
    :param cli_type:
    :return:
    """
    if cli_type == "click":
        if interfaces:
            return portapi.get_status(dut, ','.join(make_list(interfaces)))
        return portapi.get_status(dut, interfaces)
    elif cli_type == "klish":
        command = "show interface status"
        interface = make_list(interfaces)
        if interface:
            command += " | grep \"{}\"".format("|".join(interface))
        return st.show(dut, command, type=cli_type)
    else:
        st.log("Unsupported CLI TYPE {}".format(cli_type))
        return False


def interface_operation(dut, interfaces, operation="shutdown", skip_verify=True, cli_type=""):
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

    if not cli_type:
        cli_type=st.get_ui_type(dut)

    if cli_type == "click":
        interfaces_li = make_list(interfaces)
        response = portapi.set_status(dut, interfaces_li, operation)
        if "Error" in response:
            st.log(response)
            return False

        if not skip_verify:
            concatd_interfaces = ",".join(interfaces_li)
            interface_list = interface_status_show(dut, concatd_interfaces)
            if operation == "shutdown":
                if interface_list[0]["oper"] != "down" and interface_list[0]["admin"] != "down":
                    st.log("Error: Interface {} is not down.".format(concatd_interfaces))
                    return False
            elif operation == "startup":
                if interface_list[0]["admin"] != "up":
                    st.log("Error: Interface {} is not up.".format(concatd_interfaces))
                    return False
        return True
    elif cli_type == "klish":
        interface = make_list(interfaces)
        commands = list()
        if interface:
            for intf in interface:
                intf_details = get_interface_number_from_name(intf)
                if not intf_details:
                    st.error("Interface data not found for {} ".format(intf))
                else:
                    commands.append("interface {} {}".format(intf_details["type"], intf_details["number"]))
                    command = "shutdown" if operation == "shutdown" else "no shutdown"
                    commands.append(command)
                    commands.append("exit")
        if commands:
            st.config(dut, commands, type=cli_type)
            return True
        return False
    else:
        st.log("Unsupported CLI TYPE {}".format(cli_type))
        return False


def interface_operation_parallel(input, operation='startup', thread=True):
    """
    Author : Chaitanya Lohith Bollapragada
    This will perform the shutdown and noshutdown of given ports in given DUTs parallel.
    :param input: dic keys = dut, values = list of interfaces
    :param operation: shutdown | startup(default)
    :param thread:
    :return:

    Ex: interface_operation_parallel({vars:D1:[vars.D1D2P1,vars.D1D2P2], vars.D2:[vars.D2D1P1,vars.D2T1P1]},)
    """
    [out, exceptions] = exec_all(thread, [[interface_operation, duts, input[duts], operation]
                                          for duts in input.keys()])
    st.log(exceptions)
    return False if False in out else True


def interface_shutdown(dut, interfaces, skip_verify=True, cli_type="click"):
    """
      Function to shutdown interface
    Author: Chaitanya Vella (chaitanya.vella-kumar@broadcom.com)
    :param dut:
    :param interfaces:
    :param skip_verify:
    :param cli_type:
    :return:
    """
    return interface_operation(dut, interfaces, "shutdown", skip_verify, cli_type=cli_type)


def interface_noshutdown(dut, interfaces, skip_verify=True, cli_type="click"):
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


def interface_properties_set(dut, interfaces_list, property, value, skip_error=False, no_form=False, cli_type="click"):
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
    if cli_type == "click":
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
            else:
                st.log("Invalid property '{}' used.".format(property))
                return False
        return True
    elif cli_type == "klish":
        properties = {"mtu": "mtu", "description": "description", "ip_address": "ip address",
                      "ipv6_address": "ipv6 address", "speed": "speed", "autoneg": "autoneg"}
        commands = list()
        for interface in interfaces_li:
            intf_details = get_interface_number_from_name(interface)
            if not intf_details:
                st.log("Interface data not found for {} ".format(interface))
            commands.append("interface {} {}".format(intf_details["type"], intf_details["number"]))
            if not no_form:
                if property.lower() == "autoneg":
                    command = "autoneg on"
                else:
                    command = "{} {}".format(properties[property.lower()], value)
                commands.append(command)
            else:
                if property.lower() == "autoneg":
                    command = "autoneg off"
                elif property.lower() in ["ip_address", "ipv6_address"]:
                    command = "no {} {}".format(properties[property.lower()], value)
                else:
                    command = "no {}".format(properties[property.lower()])
                commands.append(command)
            commands.append("exit")
            if commands:
                st.config(dut, commands, type=cli_type)
        return True
    else:
        st.log("Unsupported CLI TYPE {}".format(cli_type))
        return False


def _get_interfaces_by_status(dut, status):
    """
    Internal function to get the interface status
    Author: Chaitanya Vella (chaitanya.vella-kumar@broadcom.com)
    :param dut: dut obj
    :param status: status of the interface
    :return: list of interface status
    """
    output = interface_status_show(dut, None)
    retval = []
    match = {"oper": status} if status else None
    entries = filter_and_select(output, ["interface"], match)
    for ent in entries:
        retval.append(ent["interface"])
    return retval


def get_up_interfaces(dut):
    """
    Author: Chaitanya Vella (chaitanya.vella-kumar@broadcom.com)
    This is to get the list of up interfaces
    :param dut: dut obj
    :return: list of interfaces
    """
    return _get_interfaces_by_status(dut, "up")


def get_down_interfaces(dut):
    """
    Author: Chaitanya Vella (chaitanya.vella-kumar@broadcom.com)
    :param dut: DUT object
    :return: list of down interfaces
    """
    return _get_interfaces_by_status(dut, "down")


def get_all_interfaces(dut, int_type=None, cli_type="click"):
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
            return [each for each in out if each.startswith("Ethernet")]
        elif int_type == 'port_channel':
            return [each for each in out if each.lower().startswith("portchannel")]
        else:
            return out
    else:
        return []


def get_all_ports_speed_dict(dut):
    """
    :param dut:
    :return: dict of all ports of same speed
    """
    all_speed_ports = dict()
    output = interface_status_show(dut)
    physical_port_list = [each['interface'] for each in output if each['interface'].startswith("Ethernet")]
    for each in physical_port_list:
        speed = filter_and_select(output, ['speed'], {'interface': each})[0]['speed']
        if speed not in all_speed_ports:
            all_speed_ports[speed] = [each]
        else:
            all_speed_ports[speed].append(each)
    return all_speed_ports


def verify_interface_status(dut, interface, property, value, cli_type="click"):
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
    is_found = 1
    for port in interface_list:
        interface_details = interface_status_show(dut, port, cli_type=cli_type)
        match = {"interface": port, property: value}
        entries = filter_and_select(interface_details, ["interface"], match)
        if not bool(entries):
            is_found = 0
            break
        else:
            is_found = 1
    if not is_found:
        return False
    return True


def clear_interface_counters(dut):
    """
    Clear interface counters
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :return:
    """
    if st.is_community_build():
        return st.config(dut, "sonic-clear counters")
    else:
        return st.show(dut, "show interfaces counters -c")


def show_interfaces_counters(dut, interface=None, property=None, cli_type="click"):
    """
    show interface counter
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param interface:
    :param property:
    :param cli_type:
    :return:
    """
    if cli_type == "click":
        command = 'show interfaces counters'
        output = st.show(dut, command)
        if interface:
            if property:
                output = filter_and_select(output, [property], {'iface': interface})
            else:
                output = filter_and_select(output, None, {'iface': interface})
        return output
    elif cli_type == "klish":
        command = "show interface counters"
        interface = make_list(interface)
        if interface:
            command += " | grep \"{}\"".format("|".join(interface))
        return st.show(dut, command, type=cli_type)
    else:
        st.log("Unsupported CLI TYPE {}".format(cli_type))
        return False


def show_interface_counters_all(dut):
    """
    Show interface counter all.
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :return:
    """
    command = "show interfaces counters -a"
    return st.show(dut, command)


def get_interface_counters(dut, port, *counter):
    """
    This API is used to get the interface counters.
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param port:
    :param counter:
    :return:
    """
    output = show_specific_interface_counters(dut, port)
    entries = filter_and_select(output, counter, {'iface': port})
    return entries


def poll_for_interfaces(dut, iteration_count=180, delay=1, cli_type="click"):
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
        if i > iteration_count:
            st.log("Max {} tries Exceeded. Exiting ..".format(i))
            return False
        i += 1
        st.wait(delay)


def poll_for_interface_status(dut, interface, property, value, iteration=5, delay=1, cli_type="click"):
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
        if i > iteration:
            st.log("Max iterations {} reached".format(i))
            return False
        i += 1
        st.wait(delay)


def get_interface_property(dut, interfaces_list, property, cli_type="click"):
    """

    :param dut:
    :param interfaces_list: API accepts interfaces list or single interface
    :param property: single property need to provide
    :param cli_type:
    :return: Returns interfaces list properties in the interfaces order passed to api
    """
    if not isinstance(interfaces_list, list):
        interfaces_li = [interfaces_list]
    output = interface_status_show(dut, interfaces_li, cli_type=cli_type)
    return_list = []
    for each_interface in interfaces_li:
        property_val = filter_and_select(output, [property], {'interface': each_interface})
        if not property_val:
            break
        return_list.append(property_val[0][property])
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


def show_queue_counters(dut, interface_name, queue=None):
    """
    Show Queue counters
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param interface_name:
    :param queue: UC0-UC9 | MC10-MC19 (Default None)
    :return:
    """
    command = "show queue counters {}".format(interface_name)
    output = st.show(dut, command)
    if queue:
        return filter_and_select(output, None, {'txq': queue})
    return output


def clear_queue_counters(dut, interfaces_list=[]):
    """
    Clear Queue counters
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :return:
    """
    interface_li = list(interfaces_list) if isinstance(interfaces_list, list) else [interfaces_list]
    if not interface_li:
        command = "show queue counters -c"
        st.config(dut, command)
    else:
        for each_port in interface_li:
            command = "show queue counters {} -c".format(each_port)
            st.config(dut, command)
    return True


def get_free_ports_speed_dict(dut, cli_type="click"):
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


def show_interface_counters_detailed(dut, interface, filter_key=None):
    """
    show interfaces counters detailed <interface>.
    Author : Rakesh Kumar Vooturi (rakesh-kumar.vooturi@broadcom.com)
    :param dut:
    :param interface:
    :return:
    """
    command = "show interfaces counters detailed {}".format(interface)
    if st.is_community_build():
        output = st.show(dut, command, skip_error_check=True)
    else:
        output = st.show(dut, command)
    if not filter_key:
        return output
    else:
        if not output:
            return False
        return output[0][filter_key]


def clear_watermark_counters(dut, mode='all'):
    """
    Clear  Watermark counters
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param mode:
    :return:
    """
    if mode == 'multicast' or mode == 'all':
        command = "sonic-clear queue watermark multicast"
        st.config(dut, command)
    if mode == 'unicast' or mode == 'all':
        command = "sonic-clear queue watermark unicast"
        st.config(dut, command)
    if mode == 'shared' or mode == 'all':
        command = "sonic-clear priority-group watermark shared"
        st.config(dut, command)
    if mode == 'headroom' or mode == 'all':
        command = "sonic-clear priority-group watermark headroom"
        st.config(dut, command)
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


def show_specific_interface_counters(dut, interface_name):
    """
    API to fetch the specific interface counters
    :param dut:
    :param interface_name:
    :return:
    """
    command = "show interfaces counters -a -i {}".format(interface_name)
    if st.is_community_build():
        command = "show interfaces counters -a | grep -w {}".format(interface_name)
    output = st.show(dut, command)
    st.log(output)
    return output


def get_interface_counter_value(dut, ports, properties):
    """
    This API is used to get the multiple interfaces counters value in dictionary of dictionaries.
    Author : Ramprakash Reddy (ramprakash-reddy.kanala@broadcom.com)
    :param dut:
    :param ports: Interfaces names ["Ethernet0","Ethernet1"]
    :param property: Interface properties ["rx_ok","tx_ok"]
    :return: {"Ethernet0":{"rx_ok":"1234","tx_ok":"45"},"Ethenrnet1":{"rx_ok"="4325","tx_ok"="2424"}}
    """
    if not isinstance(ports, list):
        ports = [ports]
    if not isinstance(properties, list):
        properties = [properties]
    counters_dict = dict()
    output = show_interface_counters_all(dut)
    for each_port in ports:
        entries = filter_and_select(output, properties, {'iface': each_port})[0]
        counters_dict[each_port] = entries
    return convert_to_bits(counters_dict)


def verify_interface_counters(dut, params, cli_type="click"):
    """
    :param dut:
    :param params: {"module_type":"mirror","source":["Ethernet1","tx_ok"], "destination":["Ethernet2","rx_ok"],
    "mirrored_port":["Ethernet3","rx_ok"]}
    :param cli_type:
    :return:
    """
    if cli_type == "click":
        st.log("Verifying interface counters on {}".format(dut))
        output = show_interface_counters_all(dut)
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
            except:
                st.report_fail("counters_are_not_initilaized")
            source_counters = int(source_counters.replace(",", ""))
            destination_counters = int(destination_counters.replace(",", ""))
            mirror_counters = int(mirror_counters.replace(",", ""))
            if module_type == "mirror":
                if not ((mirror_counters >= 0.98 * source_counters) and (destination_counters >= 0.98 * source_counters)):
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
                #mirror_counters_both = int(mirror_counters_both.replace(",", ""))
                if not (int(mirror_counters) >= 0.99 * mirror_counters_both):
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

def config_loopback_interfaces(dut, lpbk_if_data={}, config='yes'):

    if config == 'yes' or config == 'add':
        config = 'add'
    elif config == 'no' or config == 'del':
        config = 'del'
    else :
        st.error("Invalid config type {}".format(config))
        return False

    command = []
    for if_name, if_data in lpbk_if_data.items():
        cmd_str = "sudo  config loopback {} {} ".format(config, if_name)
        command.append(cmd_str)

    if command != '':
        try:
            st.config(dut, command)
        except Exception as e:
            st.log(e)
            return False

    return True


def config_portchannel_interfaces(dut, portchannel_data={}, config='yes'):

    if config == 'yes' or config == 'add':
        config = 'add'
    elif config == 'no' or config == 'del':
        config = 'del'
    else :
        st.error("Invalid config type {}".format(config))
        return False

    command = []

    if config == 'del' :
        for if_name, if_data in portchannel_data.items():
            for link_member in if_data['members'] :
                cmd_str = "sudo config portchannel member {} {} {} ".format(config, if_name, link_member)
                command.append(cmd_str)
        try:
            st.config(dut, command)
        except Exception as e:
            st.log(e)
            return False

    command = []
    for if_name, if_data in portchannel_data.items():
        cmd_str = "sudo config portchannel {} {}  ".format(config, if_name)
        command.append(cmd_str)

    try:
        st.config(dut, command)
    except Exception as e:
        st.log(e)
        return False

    command = []
    if config == 'add' :
        for if_name, if_data in portchannel_data.items():
            for link_member in if_data['members'] :
                cmd_str = "sudo config portchannel member {} {} {} ".format(config, if_name, link_member)
                command.append(cmd_str)
        try:
            st.config(dut, command)
        except Exception as e:
            st.log(e)
            return False

    return True


def config_vlan_interfaces(dut, vlan_data={}, config='yes', skip_error=False):

    if config == 'yes' or config == 'add':
        config = 'add'
    elif config == 'no' or config == 'del':
        config = 'del'
    else :
        st.error("Invalid config type {}".format(config))
        return False

    command = []
    if config == 'del' :
        for if_name, if_data in vlan_data.items():
            vlan_id = if_data['vlan_id']

            range_cmd = False
            if 'range' in if_data.keys():
                range_ids = if_data['range']
                if range_ids[0] < range_ids[1] :
                    range_min, range_max = range_ids[0], range_ids[1]
                    range_cmd = True
                elif range_ids[0] > range_ids[1] :
                    range_min, range_max = range_ids[1], range_ids[0]
                    range_cmd = True
                else :
                    vlan_id = range_ids[0]

            for link_member in if_data['members'] :
                if not range_cmd :
                    cmd_str = "config vlan member {} {} {} ".format(config, vlan_id, link_member)
                    command.append(cmd_str)
                elif not st.is_community_build():
                    cmd_str = "config vlan member range {} {} {} {}".format(config, range_min, range_max, link_member)
                    command.append(cmd_str)
                else:
                    skip_error = True
                    for vid in range(range_min, range_max+1):
                        cmd_str = "config vlan member {} {} {} ".format(config, vid, link_member)
                        command.append(cmd_str)

        try:
            st.config(dut, command, skip_error_check=skip_error)
        except Exception as e:
            st.log(e)
            return False

    command = []
    for if_name, if_data in vlan_data.items():
        vlan_id = if_data['vlan_id']

        range_cmd = False
        if 'range' in if_data.keys():
            range_ids = if_data['range']
            if range_ids[0] < range_ids[1] :
                range_min, range_max = range_ids[0], range_ids[1]
                range_cmd = True
            elif range_ids[0] > range_ids[1] :
                range_min, range_max = range_ids[1], range_ids[0]
                range_cmd = True
            else :
                vlan_id = range_ids[0]

        if not range_cmd :
            cmd_str = "sudo config vlan {} {} ".format(config, vlan_id)
            command.append(cmd_str)
        elif not st.is_community_build():
            cmd_str = "sudo config vlan range {} {} {}".format(config, range_min, range_max)
            command.append(cmd_str)
        else :
            for vid in range(range_min, range_max+1):
                cmd_str = "sudo config vlan {} {} ".format(config, vid)
                command.append(cmd_str)

    try:
        st.config(dut, command)
    except Exception as e:
        st.log(e)
        return False

    command = []
    if config == 'add' :
        for if_name, if_data in vlan_data.items():
            vlan_id = if_data['vlan_id']

            range_cmd = False
            if 'range' in if_data.keys():
                range_ids = if_data['range']
                if range_ids[0] < range_ids[1] :
                    range_min, range_max = range_ids[0], range_ids[1]
                    range_cmd = True
                elif range_ids[0] > range_ids[1] :
                    range_min, range_max = range_ids[1], range_ids[0]
                    range_cmd = True
                else :
                    vlan_id = range_ids[0]

            for link_member in if_data['members'] :

                if not range_cmd :
                    cmd_str = "config vlan member {} {} {} ".format(config, vlan_id, link_member)
                    command.append(cmd_str)
                elif not st.is_community_build():
                    cmd_str = "config vlan member range {} {} {} {}".format(config, range_min, range_max, link_member)
                    command.append(cmd_str)
                else:
                    for vid in range(range_min, range_max+1):
                        cmd_str = "config vlan member {} {} {} ".format(config, vid, link_member)
                        command.append(cmd_str)

        try:
            st.config(dut, command)
        except Exception as e:
            st.log(e)
            return False

    return True


def config_interface_vrf_binds(dut, if_vrf_data={}, config='yes'):

    if config == 'yes' or config == 'add':
        config = 'bind'
    elif config == 'no' or config == 'del':
        config = 'unbind'
    else :
        st.error("Invalid config type {}".format(config))
        return False

    command = []
    for if_name, if_data in if_vrf_data.items():
        vrf = if_data['vrf']
        cmd_str = "sudo config interface vrf {} {} {} ".format(config, if_name, vrf)
        command.append(cmd_str)

    try:
        st.config(dut, command)
    except Exception as e:
        st.log(e)
        return False

    return True


def config_portgroup_property(dut, portgroup, value, property="speed", skip_error=False, cli_type="click"):
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

def show_portgroup(dut, interface=None, cli_type="click"):
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
    response=list()
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
    """
    API to verify portgroup
    Author: Chaitanya Vella (chaitanya.vella-kumar@broadcom.com)
    :param dut:
    :param kwargs: {"cli_type":"click","interface":"Ethernet5","portgroup":"1","speed":"1000"}
    :return:
    """
    cli_type = kwargs.get("cli_type","click")
    interface = kwargs.get("interface", None)
    portgroup = kwargs.get("portgroup", None)
    speed = kwargs.get("speed", None)
    result = 0
    output = show_portgroup(dut, interface=interface,cli_type=cli_type)
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

def is_port_group_supported(dut, cli_type="click"):
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
