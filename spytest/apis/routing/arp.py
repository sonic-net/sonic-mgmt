# This file contains the list of API's which performs ARP operations.
# @author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
# @author2 : Jagadish Chatrasi (jagadish.chatrasi@broadcom.com)

from spytest import st
from apis.system.rest import config_rest, delete_rest, get_rest
from apis.switching.vlan import get_vlan_member
from apis.routing.ip_rest import get_subinterface_index
from utilities.common import filter_and_select, dicts_list_values
from utilities.utils import get_interface_number_from_name


def show_arp(dut, ipaddress=None, interface=None, vrf="",cli_type=""):
    """
    To get arp table info
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param ipaddress:
    :param interface:
    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    if cli_type == "click":
        if vrf == "":
            command = "show arp"
            if ipaddress:
                command += " {}".format(ipaddress)
            elif interface:
                command += " -if {}".format(interface)
        elif vrf != "":
            command = "show arp -vrf {}".format(vrf)
            if ipaddress:
                command = "show arp {}".format(ipaddress)
            elif interface:
                command = "show arp -if {}".format(interface)
    elif cli_type == "klish":
        if vrf == "":
            command = "show ip arp"
            if ipaddress:
                command += " {}".format(ipaddress)
            elif interface:
                intf = get_interface_number_from_name(interface)
                command += " interface {} {}".format(intf["type"], intf["number"])
        elif vrf != "":
            command = "show ip arp vrf {}".format(vrf)
            if ipaddress:
                command += " {}".format(ipaddress)
    elif cli_type in ['rest-patch', 'rest-put']:
        output = list()
        if vrf:
            interfaces = _get_rest_l3_interfaces(dut, vrf=vrf)
        else:
            interfaces = _get_rest_l3_interfaces(dut)
        for intf in interfaces:
            output.extend(_get_rest_neighbor_entries(dut, intf))
        st.debug(output)
        if ipaddress:
            return filter_and_select(output, None, {'address': ipaddress})
        elif interface:
            return filter_and_select(output, None, {'iface': interface})
        else:
            return output
    else:
        st.error("Unsupported CLI_TYPE: {}".format(cli_type))
        return False
    return st.show(dut, command, type= cli_type)


def get_arp_count(dut, ipaddress=None, interface=None, cli_type="", **kwargs):
    """
    To get arp count
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param ipaddress:
    :param interface:
    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    if cli_type == "click":
        command = "show arp"
        if ipaddress:
            command += " {}".format(ipaddress)
        if interface:
            command += " -if {}".format(interface)
        command += " | grep 'Total number of entries'"
    elif cli_type == "klish":
        command = "show ip arp"
        if interface:
            intf = get_interface_number_from_name(interface)
            command += " interface {} {}".format(intf["type"], intf["number"])
        if 'vrf' in kwargs:
            command += " vrf {}".format(kwargs["vrf"])
        if ipaddress:
            st.log("Unsupported attribute ipaddress")
            return 0
        command += " summary"
    elif cli_type in ["rest-patch", "rest-put"]:
        show_arp(dut, ipaddress=None, interface=None, vrf="",cli_type="")
        if interface:
            out = show_arp(dut, interface=interface, cli_type=cli_type)
        if 'vrf' in kwargs:
            out = show_arp(dut, vrf=kwargs['vrf'], cli_type=cli_type)
        if ipaddress:
            out = show_arp(dut, ipaddress=ipaddress, cli_type=cli_type)
        if not (interface and kwargs.get('vrf') and ipaddress):
            out = show_arp(dut, cli_type=cli_type)
        return len(out)
    else:
        st.error("Unsupported CLI_TYPE: {}".format(cli_type))
        return False
    output = st.show(dut, command, type= cli_type)
    out = dicts_list_values(output, 'count')
    return int(out[0]) if out else 0


def add_static_arp(dut, ipaddress, macaddress, interface="", cli_type=""):
    """
    To add static arp
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param ipaddress:
    :param macaddress:
    :param interface:
    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    command = ''
    if cli_type == "click":
        command = "arp -s {} {}".format(ipaddress, macaddress)
        if interface:
            command += " -i {}".format(interface)
    elif cli_type == "klish":
        if interface:
            intf = get_interface_number_from_name(interface)
            command = "interface {} {}".format(intf['type'], intf['number'])
            command = command + "\n" + "ip arp {} {}".format(ipaddress, macaddress) + "\n" + "exit"
        else:
            st.error("'interface' option is mandatory for adding static arp entry in KLISH")
            return False
    elif cli_type in ['rest-patch', 'rest-put']:
        if not interface:
            st.error("'interface' option is mandatory for adding static arp entry in REST")
            return False
        port_index = get_subinterface_index(dut, interface)
        rest_urls = st.get_datastore(dut, 'rest_urls')
        url = rest_urls['config_static_arp'].format(name=interface, index=port_index)
        config_data = {"openconfig-if-ip:neighbor": [{"ip": ipaddress, "config": {"ip": ipaddress, "link-layer-address": macaddress}}]}
        if not config_rest(dut, rest_url=url, http_method=cli_type, json_data=config_data):
            st.error("Failed to configure static ARP with IP: {}, MAC: {}, INTF: {}".format(ipaddress, macaddress, interface))
            return False
    else:
        st.error("Unsupported CLI_TYPE: {}".format(cli_type))
        return False
    if command:
        st.config(dut, command, type= cli_type)
    return True


def delete_static_arp(dut, ipaddress, interface="", mac="", cli_type="",vrf=""):
    """
    To delete static arp
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param ipaddress:
    :param interface:
    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    command = ''
    if cli_type == "click":
        command = "arp -d {} ".format(ipaddress)
        if interface:
            command += " -i {}".format(interface)
    elif cli_type == "klish":
        if interface:
            if mac:
                macaddress = mac
            else:
                output = show_arp(dut, ipaddress=ipaddress, interface=interface,vrf=vrf)
                if len(output) == 0:
                    st.error("Did not find static arp entry with IP : {} and Interface : {}".format(ipaddress, interface))
                    return False
                else:
                    macaddress = output[0]["macaddress"]
            intf = get_interface_number_from_name(interface)
            command = "interface {} {}".format(intf['type'], intf['number'])
            command = command + "\n" + "no ip arp {} {}".format(ipaddress, macaddress) + "\n" + "exit"
        else:
            st.error("'interface' option is mandatory for deleting static arp entry in KLISH")
            return False
    elif cli_type in ['rest-patch', 'rest-put']:
        if not interface:
            st.error("'interface' option is mandatory for deleting static arp entry in REST")
            return False
        port_index = get_subinterface_index(dut, interface)
        rest_urls = st.get_datastore(dut, 'rest_urls')
        url = rest_urls['delete_static_arp'].format(name=interface, index=port_index, ip=ipaddress)
        if not delete_rest(dut, rest_url=url):
            st.error("Failed to delete static ARP with INTF: {},  IP: {}".format(interface, ipaddress))
            return False
    else:
        st.error("Unsupported CLI_TYPE: {}".format(cli_type))
        return False
    if command:
        st.config(dut, command, type=cli_type)
    return True


def clear_arp_table(dut, cli_type=""):
    """
    Clear arp table
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    cli_type = "klish" if cli_type in ["rest-put", "rest-patch"] else cli_type
    if cli_type == "click":
        command = "sonic-clear arp"
    elif cli_type == "klish":
        command = "clear ip arp"
    else:
        st.error("Unsupported CLI_TYPE: {}".format(cli_type))
        return False
    st.config(dut, command, type= cli_type)
    return True


def set_arp_ageout_time(dut, timeout, cli_type=""):
    """
    To set arp aging time
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param timeout:
    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    command = ''
    if cli_type == "click":
        command = "sudo bash -c 'echo {} >/proc/sys/net/ipv4/neigh/default/gc_stale_time'".format(timeout)
    elif cli_type == "klish":
        command = "ip arp timeout {}".format(timeout)
    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        url = rest_urls['ageout_set']
        config_data = {"openconfig-neighbor:neighbor-globals": {"neighbor-global": [{"name": "Values", "config": {"ipv4-arp-timeout": int(timeout)}}]}}
        if not config_rest(dut, rest_url=url, http_method=cli_type, json_data=config_data):
            st.error("Failed to configure ARP timeout as: {}".format(timeout))
            return False
    else:
        st.error("Unsupported CLI_TYPE: {}".format(cli_type))
        return False
    if command:
        st.config(dut, command, type= cli_type)
    return True


def get_arp_ageout_time(dut, **kwargs):
    """
    To get arp aging time.
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :return:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    if cli_type in ['click', 'klish']:
        command = "cat /proc/sys/net/ipv4/neigh/default/gc_stale_time"
        out = st.config(dut, command)
        try:
            return out.split("\n")[0]
        except IndexError as e:
            st.log(e)
            st.error("Failed to get the ARP age-out time")
            return None
    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        url = rest_urls['arp_ageout_get'].format(name='Values')
        out = get_rest(dut, rest_url=url)
        if 'output' in out and out.get('output') and 'openconfig-neighbor:ipv4-arp-timeout' in out['output']:
            return out['output']['openconfig-neighbor:ipv4-arp-timeout']
        return 60
    else:
        st.error("Unsupported CLI_TYPE: {}".format(cli_type))
        return False


def verify_arp(dut, ipaddress, macaddress=None, interface=None, vlan=None, cli_type=""):
    """
    To verify arp table
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param ipaddress:
    :param macaddress:
    :param interface:
    :param vlan: in KLISH this represents the Egress Interface column
    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    output = show_arp(dut, ipaddress, cli_type=cli_type)
    entries = filter_and_select(output, None, {"address": ipaddress})
    if not entries:
        st.error("No ARP entry found for the provided IP Address -{}".format(ipaddress))
        return False
    if macaddress and not filter_and_select(entries, None, {"address": ipaddress, "macaddress": macaddress}):
        st.error("Provided and configured macaddress values are not same.")
        return False
    if cli_type == "click":
        if interface and not filter_and_select(entries, None, {"address": ipaddress, 'iface': interface}):
            st.error("Provided and configured interface values are not same.")
            return False
    elif cli_type in ["klish", "rest-patch", "rest-put"]:
        if interface and not filter_and_select(entries, None, {"address": ipaddress, 'iface': interface}):
            st.error("Provided and configured interface values are not same, checking with other field ..")
            if not filter_and_select(entries, None, {"address": ipaddress, 'vlan': interface}):
                return False
    if cli_type == "click":
        if vlan and not filter_and_select(entries, None, {"address": ipaddress, "vlan": vlan}):
            st.error("Provided and configured vlan values are not same.")
            return False
    elif cli_type in ["klish", "rest-patch", "rest-put"]:
        if vlan and not filter_and_select(entries, None, {"address": ipaddress, "iface": "Vlan{}".format(vlan)}):
            st.error("Provided and configured vlan values are not same.")
            return False
    return True


def get_max_arp_entries_supported_count(dut):
    """
    To get max supported arp entries.
    Author: Rakesh Kumar Vooturi (rakesh-kumar.vooturi@broadcom.com)
    :param dut:
    :return:
    """
    command = "cat /proc/sys/net/ipv4/neigh/default/gc_thresh3"
    out = st.config(dut, command)
    try:
        return int(out.split("\n")[0])
    except Exception as e:
        st.log(e)
        st.error("Failed to get the max arp entries supported count.")
        return None


def show_ndp(dut, inet6_address=None, **kwargs):
    """
    to get ndp table info
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param inet6_address:
    :return:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    if cli_type == "click":
        if 'vrf' not in kwargs:
            command = "show ndp"
            if inet6_address:
                command += " {}".format(inet6_address)
            elif "interface" in kwargs and kwargs["interface"]:
                command += " -if {}".format(kwargs["interface"])
        elif 'vrf' in kwargs:
            vrf = kwargs['vrf']
            command = "show ndp -vrf {}".format(vrf)
            if inet6_address:
                command += " {}".format(inet6_address)
            elif "interface" in kwargs and kwargs["interface"]:
                command += " -if {}".format(kwargs["interface"])
    elif cli_type == "klish":
        if 'vrf' not in kwargs:
            command = "show ipv6 neighbors"
            if inet6_address:
                command += " {}".format(inet6_address)
            elif kwargs.get("interface"):
                intf = get_interface_number_from_name(kwargs.get("interface"))
                command += " interface {} {}".format(intf["type"], intf["number"])
        elif 'vrf' in kwargs:
            vrf = kwargs['vrf']
            command = "show ipv6 neighbors vrf {}".format(vrf)
            if inet6_address:
                command += " {}".format(inet6_address)
    elif cli_type in ["rest-patch", "rest-put"]:
        output = list()
        if kwargs.get('vrf'):
            interfaces = _get_rest_l3_interfaces(dut, vrf=kwargs['vrf'])
        else:
            interfaces = _get_rest_l3_interfaces(dut)
        for interface in interfaces:
            output.extend(_get_rest_neighbor_entries(dut, interface, is_arp=False))
        st.debug(output)
        if inet6_address:
            return filter_and_select(output, None, {'address': inet6_address})
        elif kwargs.get('interface'):
            return filter_and_select(output, None, {'interface': kwargs['interface']})
        else:
            return output
    else:
        st.error("Unsupported CLI Type: {}".format(cli_type))
        return False
    return st.show(dut, command, type= cli_type)


def verify_ndp(dut, inet6_address, **kwargs):
    """
    To Verify ndt table info
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param inet6_address
    :param mac_address:
    :param interface:
    :param vlan:
    :param status:
    :return:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    if "interface" in kwargs and kwargs["interface"]:
        response = show_ndp(dut, inet6_address, interface = kwargs["interface"], cli_type=cli_type)
    else:
        response = show_ndp(dut, inet6_address, cli_type=cli_type)
    st.log("Response {}".format(response))
    if not response:
        return False
    st.log("Kwargs {}".format(kwargs))
    entries = filter_and_select(response, None, {"address": inet6_address})
    st.log("Entries {}".format(entries))
    interface = kwargs.get('interface', None)
    macaddress = kwargs.get('macaddress', None)
    vlan = kwargs.get('vlan', None)
    ipaddress = inet6_address
    if not entries:
        st.error("No NDP entry found for the provided IPv6 Address -{}".format(ipaddress))
        return False
    if macaddress and not filter_and_select(entries, None, {"address": ipaddress, "macaddress": macaddress}):
        st.error("Provided and configured macaddress values are not same.")
        return False
    if cli_type == "click":
        if interface and not filter_and_select(entries, None, {"address": ipaddress, 'interface': interface}):
            st.error("Provided and configured interface values are not same.")
            return False
    elif cli_type in ["klish", "rest-patch", "rest-put"]:
        if interface and not filter_and_select(entries, None, {"address": ipaddress, 'interface': interface}):
            st.error("Provided and configured interface values are not same, checking with other field ..")
            if not filter_and_select(entries, None, {"address": ipaddress, 'vlan': interface}):
                return False
    if cli_type == "click":
        if vlan and not filter_and_select(entries, None, {"address": ipaddress, "vlan": vlan}):
            st.error("Provided and configured vlan values are not same.")
            return False
    elif cli_type in ["klish", "rest-patch", "rest-put"]:
        if vlan and not filter_and_select(entries, None, {"address": ipaddress, "interface": "Vlan{}".format(vlan)}):
            st.error("Provided and configured vlan values are not same.")
            return False
    return True


def config_static_ndp(dut, ip6_address, mac_address, interface, operation="add", **kwargs):
    """
    Config static ndp
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param ip6_address:
    :param mac_address:
    :param interface:
    :param operation:
    :return:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    command = ''
    if cli_type == 'click':
        interface = st.get_other_names(dut,[interface])[0] if '/' in interface else interface
        oper = "replace" if operation == "add" else "del"
        command = "ip -6 neighbor {} {} lladdr {} dev {}".format(oper, ip6_address, mac_address, interface)
    elif cli_type == 'klish':
        command = list()
        intf = get_interface_number_from_name(interface)
        command.append('interface {} {}'.format(intf["type"], intf["number"]))
        cmd = 'ipv6 neighbor {} {}'.format(ip6_address, mac_address) if operation == 'add' else 'no ipv6 neighbor {} {}'.format(ip6_address, mac_address)
        command.extend([cmd, 'exit'])
    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        port_index = get_subinterface_index(dut, interface)
        if operation == 'add':
            url = rest_urls['config_static_ndp'].format(name=interface, index=port_index)
            config_data = {"openconfig-if-ip:neighbor": [{"ip": ip6_address, "config": {"ip": ip6_address, "link-layer-address": mac_address}}]}
            if not config_rest(dut, rest_url=url, http_method=cli_type, json_data=config_data):
                st.error("Failed to configure static neighbor with IP: {} MAC: {} on INTF: {}".format(ip6_address, mac_address, interface))
                return False
        else:
            url = rest_urls['delete_static_ndp'].format(name=interface, index=port_index, ip=ip6_address)
            if not delete_rest(dut, rest_url=url):
                st.error("Failed to delete static neighbor with IP: {} MAC: {} on INTF: {}".format(ip6_address, mac_address, interface))
                return False
    else:
        st.error("Unsupported CLI Type: {}".format(cli_type))
        return False
    if command:
        st.config(dut, command, type=cli_type)
    return True


def get_ndp_count(dut, cli_type="", **kwargs):
    """
    To get ndp count
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    if cli_type == 'click':
        command = "show ndp | grep 'Total number of entries'"
        output = st.show(dut, command)
        out = dicts_list_values(output, 'count')
    elif cli_type == 'klish':
        command = "show ipv6 neighbors summary"
        if 'vrf' in kwargs:
            command = "show ipv6 neighbors vrf {} summary".format(kwargs["vrf"])
        output = st.show(dut, command, type='klish')
        out = dicts_list_values(output, 'count')
    elif cli_type in ['rest-patch', 'rest-put']:
        if kwargs.get('vrf'):
            out = show_ndp(dut, vrf=kwargs['vrf'], cli_type=cli_type)
        else:
            out = show_ndp(dut, cli_type=cli_type)
        return len(out)
    else:
        st.error("Unsupported CLI_TYPE: {}".format(cli_type))
        return False
    return int(out[0]) if out else 0


def clear_ndp_table(dut, cli_type=""):
    """
    Clear ndp table
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    cli_type = "klish" if cli_type in ["rest-put", "rest-patch"] else cli_type
    if cli_type == "click":
        command = "sonic-clear ndp"
    elif cli_type == "klish":
        command = "clear ipv6 neighbors"
    else:
        st.error("Unsupported CLI_TYPE: {}".format(cli_type))
        return False
    st.config(dut, command, type= cli_type)
    return True


def set_ndp_ageout_time(dut, timeout, cli_type=""):
    """
    To set ndp aging time
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param timeout:
    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    command = ''
    if cli_type == "click":
        command = "sudo bash -c 'echo {} >/proc/sys/net/ipv6/neigh/default/gc_stale_time'".format(timeout)
    elif cli_type == "klish":
        command = "ipv6 nd cache expire {}".format(timeout)
    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        url = rest_urls['ageout_set']
        config_data = {"openconfig-neighbor:neighbor-globals":{"neighbor-global":[{"name": "Values", "config":{"ipv6-nd-cache-expiry": int(timeout)}}]}}
        if not config_rest(dut, rest_url=url, http_method=cli_type, json_data=config_data):
            st.error("Failed to configure NDP timeout as: {}".format(timeout))
            return False
    else:
        st.error("Unsupported CLI_TYPE: {}".format(cli_type))
        return False
    if command:
        st.config(dut, command, type= cli_type)
    return True


def get_ndp_ageout_time(dut, **kwargs):
    """
    To get ndp aging time.
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :return:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    if cli_type in ['click', 'klish']:
        command = "cat /proc/sys/net/ipv6/neigh/default/gc_stale_time"
        out = st.config(dut, command)
        try:
            return out.split("\n")[0]
        except IndexError as e:
            st.log(e)
            st.error("Failed to get the NDP age-out time")
            return None
    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        url = rest_urls['ndp_ageout_get'].format(name='Values')
        out = get_rest(dut, rest_url=url)
        if 'output' in out and out.get('output') and 'openconfig-neighbor:ipv6-nd-cache-expiry' in out['output']:
            return out['output']['openconfig-neighbor:ipv6-nd-cache-expiry']
        return 60
    else:
        st.error("Unsupported CLI_TYPE: {}".format(cli_type))
        return False


def get_max_ndp_entries_supported_count(dut):
    """
    To get max supported ndp entries.
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :return:
    """
    command = "cat /proc/sys/net/ipv6/neigh/default/gc_thresh3"
    out = st.config(dut, command)
    try:
        return int(out.split("\n")[0])
    except Exception as e:
        st.log(e)
        st.error("Failed to get the max ndp entries supported count.")
        return None


def _get_rest_l3_interfaces(dut, vrf='default'):
    """
    This API returns set of L3 interfaces
    Author: Jagadish Chatrasi (jagadish.chatrasi@broadcom)
    :param dut:
    :return:
    """
    interfaces = {'eth0'}
    rest_urls = st.get_datastore(dut, 'rest_urls')
    url = rest_urls['get_network_instance'].format(name=vrf)
    out = get_rest(dut, rest_url=url)
    ids = out['output']['openconfig-network-instance:interfaces']['interface'] if isinstance(out, dict) and out.get('output') and 'openconfig-network-instance:interfaces' in out['output'] and out['output']['openconfig-network-instance:interfaces'].get('interface') and isinstance(out['output']['openconfig-network-instance:interfaces']['interface'], list) else ''
    if ids:
        for entry in ids:
            if isinstance(entry, dict) and entry.get('id'):
                interfaces.add(entry['id'])
    return list(interfaces)


def _get_rest_neighbor_entries(dut, interface, is_arp=True):
    """
    This API returns ARP/NDP entries
    Author: Jagadish Chatrasi (jagadish.chatrasi@broadcom)
    :param dut:
    :param interfaces:
    :return:
    """
    retval = list()
    non_physical_ports = ['vlan']
    rest_urls = st.get_datastore(dut, 'rest_urls')
    intf_index = get_subinterface_index(dut, interface)
    if is_arp:
        if any(port in interface.lower() for port in non_physical_ports):
            url = rest_urls['get_arp_per_vlan_port'].format(name=interface)
        else:
            url = rest_urls['get_arp_per_port'].format(name=interface, index=intf_index)
    else:
        if any(port in interface.lower() for port in non_physical_ports):
            url = rest_urls['get_ndp_per_vlan_port'].format(name=interface)
        else:
            url = rest_urls['get_ndp_per_port'].format(name=interface, index=intf_index)
    intf = 'iface' if is_arp else 'interface'
    out = get_rest(dut, rest_url=url)
    arp_entries = out['output']['openconfig-if-ip:neighbors']['neighbor'] if isinstance(out, dict) and out.get('output') and 'openconfig-if-ip:neighbors' in out['output'] and out['output']['openconfig-if-ip:neighbors'].get('neighbor') and isinstance(out['output']['openconfig-if-ip:neighbors']['neighbor'], list) else ''
    if arp_entries:
        for arp_entry in arp_entries:
            temp = dict()
            if isinstance(arp_entry, dict) and arp_entry.get('state'): 
                arp = arp_entry['state']
                temp['address'] = arp['ip'] if arp.get('ip') else ''
                temp['macaddress'] = arp['link-layer-address'].lower() if arp.get('link-layer-address') else ''
                temp['count'] = ''
                if interface == 'eth0':
                    temp[intf] = 'Management0'
                    temp['vlan'] = '-'
                elif any(port in interface.lower() for port in non_physical_ports):
                    temp[intf] = interface
                    egr_port = get_vlan_member(dut, vlan_list=interface.replace('Vlan', ''))
                    temp['vlan'] = egr_port[interface.replace('Vlan', '')][0] if isinstance(egr_port, dict) and egr_port.get(interface.replace('Vlan', '')) else '-'
                else:
                    temp[intf] = interface
                    temp['vlan'] = '-'
                retval.append(temp)
    return retval
