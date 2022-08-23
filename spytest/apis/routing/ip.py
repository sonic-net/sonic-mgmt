# This file contains the list of API's which performs IP,Ping related operations.
# Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)

import re
import ipaddress
import subprocess

from spytest import st
from spytest.utils import filter_and_select

from apis.system.rest import config_rest, delete_rest ,get_rest
from apis.routing.ip_rest import get_subinterface_index
from apis.routing.sag import config_sag_ip

import utilities.common as utils
from utilities.utils import get_interface_number_from_name
from utilities.utils import is_valid_ipv4_address
from utilities.utils import is_valid_ipv6_address
from utilities.utils import is_valid_ip_address

def config_ipv6(dut, action='disable'):
    """
    To globally disable or enabled Ipv6
    :param dut:
    :param action: Can be 'disable' or 'enable'.
    :return:
    """
    command = "config ipv6 {}".format(action)
    if st.is_feature_supported("config-ipv6-command", dut):
        return st.config(dut, command)

    st.community_unsupported(command, dut)
    value = "1" if action == "disable" else "0"
    st.config(dut, "sysctl -w net.ipv6.conf.all.disable_ipv6={}".format(value))
    st.config(dut, "sysctl -w net.ipv6.conf.default.disable_ipv6={}".format(value))
    st.config(dut, "sysctl -w net.ipv6.conf.lo.disable_ipv6={}".format(value))

def show_ipv6(dut):
    """
    Display global Ipv6 state
    :param dut:
    :return:
    """
    command = "show ipv6 brief"
    st.show(dut, command, skip_tmpl=True)


def ping(dut, addresses, family='ipv4', **kwargs):
    """
    To Perform ping to ipv4 or ipv6 address.
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param :dut:
    :param :addresses:
    :param :family: ipv4|ipv6
    :param :count: 3(default)
    :param :timeout:
    :param :interface:
    :param :packetsize:
    :param :external: True | False (Default: False) # Used True for Ping from external server. (Ex: VDI)
    :return:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = "klish" if cli_type in ["rest-put", "rest-patch"] else cli_type
    ping_pattern = r'(\d+)\s+packets\s+transmitted,\s+(\d+)\s+received,(.*)\s+(\d+)%\s+packet\s+loss,\s+time\s+(\d+)ms'
    external = kwargs.get("external", False)

    # add defaults
    kwargs['tgen'] = kwargs.get('tgen', False)
    kwargs['count'] = kwargs.get('count', 3)

    if family.lower() == "ipv4":
        if external:
            command = "ping {} -c {} ".format(addresses, kwargs['count'])
        else:
            if cli_type == 'click':
                command = "ping -4 {} -c {} ".format(addresses, kwargs['count'])
            elif cli_type == 'klish':
                if 'interface' in kwargs and 'Vrf' in kwargs['interface']:
                    command = "ping vrf {} {} -c {} ".format(kwargs['interface'], addresses, kwargs['count'])
                    kwargs.pop('interface')
                else:
                    command = "ping {} -c {} ".format(addresses, kwargs['count'])
            else:
                st.log("UNSUPPORTED CLI TYPE")
                return False

    if family.lower() == "ipv6":
        if external:
            command = "ping6 {} -c {} ".format(addresses, kwargs['count'])
        else:
            if cli_type == 'click':
                command = "ping -6 {} -c {} ".format(addresses, kwargs['count'])
            elif cli_type == 'klish':
                if 'interface' in kwargs and 'Vrf' in kwargs['interface']:
                    command = "ping6 vrf {} {} -c {} ".format(kwargs['interface'], addresses, kwargs['count'])
                    kwargs.pop('interface')
                else:
                    command = "ping6 {} -c {} ".format(addresses, kwargs['count'])
            else:
                st.log("UNSUPPORTED CLI TYPE")
                return False

    if 'timeout' in kwargs:
        timeout = utils.integer_parse(kwargs['timeout'])
    else:
        timeout = None

    if st.is_vsonic(dut) or (kwargs['tgen'] and st.is_soft_tgen()):
        if not timeout or timeout < 7:
            timeout = 7

    if timeout:
        command = command + "-W {} ".format(timeout)

    if 'interface' in kwargs:
        command = command + "-I {} ".format(kwargs['interface'])
    if 'source_ip' in kwargs:
        command = command + "-I {} ".format(kwargs['source_ip'])
    if 'packetsize' in kwargs:
        command = command + "-s {} ".format(kwargs['packetsize'])

    if st.is_dry_run():
        return True

    if external:
        st.log(command)
        p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True,
                             universal_newlines=True)
        rv, err = p.communicate()
        st.log(rv)
        st.log(err)
    else:
        rv = st.config(dut, command, type=cli_type)
    out = re.findall(ping_pattern, rv)

    if not out:
        st.error("Failed to get the ping output.")
        return False
    if '0' < out[0][3] <= '100':
        st.error("Ping failed with packet loss.")
        return False
    return True

def config_ip_addr_interface(dut, interface_name='', ip_address='', subnet='', family="ipv4", config='add', skip_error = False, **kwargs):
    """
    Config ip address to interface
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)

    :param dut:
    :param interface_name:
    :param ip_address:
    :param subnet:
    :param family: ipv4|ipv6
    :param config: add | remove
    :return:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    is_secondary_ip = kwargs.get('is_secondary_ip','no').lower()
    if cli_type == 'click':
        if config == 'add':
            try:
                if not interface_name:
                    st.error("Please provide interface name..")
                    return False
                if not ip_address:
                    st.error("Please provide ip|ipv6 address..")
                    return False

                if family == "ipv4":
                    if not is_valid_ipv4_address(ip_address):
                        st.error("Invalid IP address.")
                        return False
                elif family == "ipv6":
                    if not is_valid_ipv6_address(ip_address):
                        st.error("Invalid IPv6 address.")
                        return False
                command = "config interface ip add {} {}/{}".format(interface_name, ip_address, subnet)
                output = st.config(dut, command, skip_error_check=skip_error)
            except Exception as e:
                st.log(e)
                return False
            if "Error: " in output:
                return False
            else:
                return True
        elif config == 'remove':
            return delete_ip_interface(dut, interface_name, ip_address, subnet, family, cli_type=cli_type)
        else:
            st.error("Invalid config used - {}.".format(config))
            return False
    elif cli_type == 'klish':
        if config == 'add':
            try:
                if interface_name =='eth0':
                    command = "interface Management 0"
                    command = command + "\n" + "ip address {}/{}".format(ip_address, subnet)
                else:
                    intf = get_interface_number_from_name(interface_name)
                    command = "interface {} {}".format(intf['type'], intf['number'])
                    fam = "ip" if family=='ipv4' else 'ipv6'
                    command = command + "\n" + "{} address {}/{}".format(fam, ip_address, subnet)
                    if is_secondary_ip == 'yes':
                        command += ' secondary'
                    command = command + "\n" + "exit"
                output = st.config(dut, command, skip_error_check=skip_error, type="klish", conf=True)
                if "Could not connect to Management REST Server" in output:
                    st.error("klish mode not working.")
                    return False
            except Exception as e:
                st.log(e)
                return False
            return True
        elif config == 'remove':
            return delete_ip_interface(dut, interface_name, ip_address, subnet, family, cli_type=cli_type, is_secondary_ip=is_secondary_ip)
    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        index = get_subinterface_index(dut, interface_name)
        if not index:
            st.error("Failed to get index for interface: {}".format(interface_name))
            index = 0
        if config == 'add':
            if "PortChannel" in interface_name:
                if is_secondary_ip == 'yes':
                    url = rest_urls['subinterface_config'].format(interface_name, index)
                    ip_config = {"openconfig-interfaces:subinterface": [ {  "index": int(index), "config": { "index": int(index) },
                            "openconfig-if-ip:{}".format(family): { "addresses": {  "address": [{
                            "ip": ip_address, "config": { "ip": ip_address, "prefix-length": int(subnet),
                            "openconfig-interfaces-ext:secondary":True }} ] }} }]}
                else:
                    url = rest_urls['subinterface_config'].format(interface_name, index)
                    ip_config = {"openconfig-interfaces:subinterface": [ {  "index": int(index), "config": { "index": int(index) },
                            "openconfig-if-ip:{}".format(family): { "addresses": {  "address": [{
                            "ip": ip_address, "config": { "ip": ip_address, "prefix-length": int(subnet) }} ] }} }]}
            elif "Vlan" in interface_name:
                if is_secondary_ip == 'yes':
                    url_identifier = "routed_vlan_config_v6" if family == "ipv6" else "routed_vlan_config_v4"
                    url = rest_urls[url_identifier].format(interface_name)
                    ip_config = {"openconfig-if-ip:{}".format(family): {"addresses": {"address": [{"ip": ip_address,
                                "config": {"ip": ip_address, "prefix-length": int(subnet),"openconfig-interfaces-ext:secondary":True}}]}}}
                else:
                    url_identifier = "routed_vlan_config_v6" if family == "ipv6" else "routed_vlan_config_v4"
                    url = rest_urls[url_identifier].format(interface_name)
                    ip_config = {"openconfig-if-ip:{}".format(family): {"addresses": {"address": [{"ip": ip_address,"config": {"ip": ip_address, "prefix-length": int(subnet)}}]}}}
            elif 'Loopback' in interface_name.capitalize():
                loopback_intfs = get_loopback_interfaces(dut)
                if interface_name.capitalize() not in loopback_intfs:
                    if not config_loopback_interfaces(dut, loopback_name=interface_name.capitalize(), cli_type=cli_type):
                        st.error("msg", "Failed to create loopback interface")
                        return False
                if is_secondary_ip == 'yes':
                    url = rest_urls['sub_interface_config'].format(interface_name)
                    ip_config = {"openconfig-interfaces:subinterfaces": {"subinterface": [{"index": int(index), "config": {"index": int(index)},
                             "openconfig-if-ip:{}".format(family): {"addresses": {"address": [{"ip": ip_address, "config": {"ip": ip_address,
                             "prefix-length": int(subnet),"openconfig-interfaces-ext:secondary":True}}]}}}]}}
                else:
                    url = rest_urls['sub_interface_config'].format(interface_name)
                    ip_config = {"openconfig-interfaces:subinterfaces": {"subinterface": [{"index": int(index), "config": {"index": int(index)},
                             "openconfig-if-ip:{}".format(family): {"addresses": {"address": [{"ip": ip_address, "config": {"ip": ip_address,
                             "prefix-length": int(subnet)}}]}}}]}}
            else:
                if is_secondary_ip == 'yes':
                    url = rest_urls['sub_interface_config'].format(interface_name)
                    ip_config = {"openconfig-interfaces:subinterfaces": {"subinterface": [{"index": int(index), "config": {"index": int(index)},
                             "openconfig-if-ip:{}".format(family): {"addresses": {"address": [{"ip": ip_address,
                             "config": {"ip": ip_address,"prefix-length": int(subnet),"openconfig-interfaces-ext:secondary":True}}]}}}]}}
                else:
                    url = rest_urls['sub_interface_config'].format(interface_name)
                    ip_config = {"openconfig-interfaces:subinterfaces": {"subinterface": [{"index": int(index), "config": {"index": int(index)},
                             "openconfig-if-ip:{}".format(family): {"addresses": {"address": [{"ip": ip_address, "config": {"ip": ip_address, "prefix-length": int(subnet)}}]}}}]}}
            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=ip_config, timeout=100):
                st.error("Failed to configure {} address: {}/{} on interface: {}".format(family, ip_address, subnet, interface_name))
                return False
            return True
        elif config == 'remove':
            return delete_ip_interface(dut, interface_name, ip_address, subnet, family, cli_type=cli_type, is_secondary_ip=is_secondary_ip)
    else:
        st.error("Invalid cli_type for this API - {}.".format(cli_type))
        return False

def delete_ip_interface(dut, interface_name, ip_address, subnet="32", family="ipv4", skip_error=False, **kwargs):
    """
    Deleting ip address to interface
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)

    :param dut:
    :param interface_name:
    :param ip_address:
    :param subnet:
    :param skip_error:
    :param family: ipv4|ipv6
    :return:
    """
    if family == "ipv4":
        if not is_valid_ipv4_address(ip_address):
            st.error("Invalid IP address.")
            return False
    elif family == "ipv6":
        if not is_valid_ipv6_address(ip_address):
            st.error("Invalid IPv6 address.")
            return False
    cli_type = st.get_ui_type(dut, **kwargs)
    is_secondary_ip = kwargs.get('is_secondary_ip','no').lower()
    if cli_type == 'click':
        command = "config interface ip remove {} {}/{}".format(interface_name, ip_address, subnet)
        st.config(dut, command, skip_error_check=skip_error)
        return True
    elif cli_type == 'klish':
        if interface_name == 'eth0':
            command = "interface Management 0"
        else:
            intf = get_interface_number_from_name(interface_name)
            command = "interface {} {}".format(intf['type'], intf['number'])
        fam = "ip" if family=='ipv4' else 'ipv6'
        # Subnet not required while removing IP/IPv6 address.
        command = command + "\n" + "no {} address {}/{}".format(fam, ip_address, subnet)
        if is_secondary_ip == 'yes':
            command += ' secondary'
        command = command + "\n" + "exit"
        output = st.config(dut, command, skip_error_check=skip_error, type="klish", conf=True)
        if "Could not connect to Management REST Server" in output:
            st.error("klish mode not working.")
            return False
        return True
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        if "Vlan" in interface_name:
            if is_secondary_ip == 'yes':
                url = rest_urls['clear_logical_port_sec_ipv4_addr'] if family=='ipv4' else rest_urls['clear_logical_port_ipv6_addr']
            else:
                url = rest_urls['clear_logical_port_ipv4_addr'] if family=='ipv4' else rest_urls['clear_logical_port_ipv6_addr']
            url = url.format(interface_name, ip_address)
        else:
            index = get_subinterface_index(dut, interface_name)
            if is_secondary_ip == 'yes':
                url = rest_urls['ipv4_sec_address_config'] if family=='ipv4' else rest_urls['ipv6_address_config']
            else:
                url = rest_urls['ipv4_address_config'] if family=='ipv4' else rest_urls['ipv6_address_config']
            url = url.format(interface_name, index, ip_address)
        if not delete_rest(dut, rest_url=url, timeout=100):
            st.error("Failed to remove IP address: {} on interface: {}".format(ip_address, interface_name))
            return False
        return True
    else:
        st.log("Unsupported CLI TYPE {}".format(cli_type))
        return False


def get_interface_ip_address(dut, interface_name=None, family="ipv4",cli_type=''):
    """
    To Get  ip address on interface
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)

    :param dut:
    :param interface_name:
    :param family: ipv4 | ipv6
    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    if cli_type in ['rest-patch', 'rest-put']:
        cli_type = 'klish'                      #OC-YANG URLs are not available for show ip/ipv6 interface. Reported JIRA: SONIC-23677 for this.
    if cli_type in ['click', 'klish']:
        command = "show ip interface"
        if family == "ipv6":
            command = "show ipv6 interface"
        output = st.show(dut, command,type=cli_type)
        result = output if family == "ipv4" else prepare_show_ipv6_interface_output(output)
        if interface_name:
            match = {"interface": interface_name}
            output = utils.filter_and_select(result, None, match)
        return output


def verify_interface_ip_address(dut, interface_name, ip_address, family="ipv4", vrfname='', flags = '',cli_type=''):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param interface_name:
    :param ip_address:
    :param family:
    :param vrfname:
    :param flags:
    :return:
    """
    cli_type=st.get_ui_type(dut, cli_type=cli_type)
    if cli_type in ['rest-patch', 'rest-put']:
        cli_type = 'klish'                      #OC-YANG URLs are not available for show ip/ipv6 interface. Reported JIRA: SONIC-23677 for this.
    command = "show ip interface"
    if family == "ipv6":
        command = "show ipv6 interface"
    output = st.show(dut, command,type=cli_type)
    result = output if family == "ipv4" else prepare_show_ipv6_interface_output(output)
    match = {"interface": interface_name, "vrf": vrfname, "ipaddr": ip_address, "flags": flags}
    entries = utils.filter_and_select(result, ["interface"], match)
    return True if entries else False


def create_static_route(dut, next_hop=None, static_ip=None, shell="vtysh", family='ipv4', interface = None, vrf = None, **kwargs):
    """
    To create static route
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param dut:
    :param next_hop:
    :param static_ip:
    :param cli_type: click|klish
    :param family: ipv4|ipv6
    :return:
    """
    if shell != 'vtysh':
        st.log("shell parameter is obsolete and will be ignored. Please use cli_type.")
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut,**kwargs))
    if cli_type == 'click':
        cli_type = 'vtysh'
    cli_type = 'klish' if cli_type in ['rest-patch', 'rest-put'] else cli_type #Due to JIRA: SONIC-28182 we are fallback to klish
    distance = kwargs.pop('distance', None)
    nexthop_vrf = kwargs.pop('nexthop_vrf', None)
    if not (static_ip and '/' in static_ip):
        st.error("Provide static_ip with proper format")
        return False
    if family.lower() == 'ipv4':
        network = ipaddress.IPv4Network(u'{}'.format(static_ip), strict=False)
        static_ip = network.compressed
    elif family.lower() == 'ipv6':
        network = ipaddress.IPv6Network(u'{}'.format(static_ip), strict=False)
        static_ip = network.compressed
    else:
        st.error("IP family should be ipv4/ipv6 but {} found".format(family))
        return False
    if cli_type == "vtysh":
        if family.lower() == "ipv4" or family.lower() == "":
            if next_hop:
                command = "ip route {} {}".format(static_ip, next_hop)
            else:
                command = "ip route {}".format(static_ip)
        elif family.lower() == "ipv6":
            if next_hop:
                command = "ipv6 route {} {}".format(static_ip, next_hop)
            else:
                command = "ipv6 route {}".format(static_ip)
        if interface:
            command +=" {}".format(interface)
        if vrf:
            command +=" vrf {}".format(vrf)
        if nexthop_vrf:
            command += " nexthop-vrf {}".format(nexthop_vrf)
        if "track" in kwargs:
            command += " track {}".format(kwargs["track"])
        st.config(dut, command, type='vtysh')
    elif cli_type == 'click':
        if family.lower() == "ipv4" or family.lower() == "":
            if next_hop:
                command = "ip route add {} via {}".format(static_ip, next_hop)
            else:
                command = "ip route add {}".format(static_ip)
        elif family.lower() == "ipv6":
            if next_hop:
                command = "ip -6 route add {} via {}".format(static_ip, next_hop)
            else:
                command = "ip -6 route add {}".format(static_ip)
        if interface:
            command +=" dev {}".format(interface)
        st.config(dut, command)
    elif cli_type == "klish":
        command = "ip route"
        if family.lower() == "ipv6":
            command = "ipv6 route"
        if vrf:
            command += " vrf {}".format(vrf)
        if static_ip:
            command += " {}".format(static_ip)
        if next_hop:
            intf = get_interface_number_from_name(next_hop)
            if isinstance(intf, dict):
                command += " interface {} {}".format(intf['type'], intf['number'])
                interface = None
            else:
                command += " {}".format(next_hop)
        if interface:
            intf = get_interface_number_from_name(interface)
            command +=" interface {} {}".format(intf['type'], intf['number'])
        if nexthop_vrf:
            command += " nexthop-vrf {}".format(nexthop_vrf)
        if "track" in kwargs:
            command += " track {}".format(kwargs["track"])
        if distance:
            command += " {}".format(distance)
        st.config(dut, command, type="klish", conf=True)

    elif cli_type in ['rest-patch', 'rest-put']:
        cli_type = "rest-patch"
        rest_urls = st.get_datastore(dut, 'rest_urls')
        url = rest_urls['ip_static_route_config']
        params_data = {"index": "", "config": {"index": ""}}
        if '/' not in static_ip:
            st.error('Network ID should be provided along with subnet mask')
            return False
        instance = vrf if vrf else 'default'
        if next_hop:
            if not re.search(r':|\.',next_hop) and not 'blackhole' in next_hop:
                add_data = {"interface-ref": {"config": {"interface": next_hop}}}
                params_data.update(add_data)
                interface = None
            elif 'blackhole' in next_hop:
                next_hop = 'DROP'
                params_data['config'].update({"openconfig-local-routing-ext:blackhole": True})
            else:
                params_data['config'].update({"next-hop": next_hop})
        elif interface:
            add_data = {"interface-ref": {"config": {"interface": interface}}}
            params_data.update(add_data)
        if nexthop_vrf:
            params_data['config'].update({"openconfig-local-routing-ext:nexthop-network-instance": nexthop_vrf})
        if distance:
            params_data['config'].update(metric=int(distance))
        index = "{}_{}_{}".format(interface, next_hop, nexthop_vrf).replace('None', '').replace("__", "_").strip("_")
        params_data["index"] = index
        params_data["config"]["index"] = index
        config_data = {"openconfig-network-instance:network-instances": {"network-instance": [{"name": instance, "config": {"name": instance},
        "protocols": {"protocol": [{"identifier": "STATIC", "name": "static", "config": {"identifier": "STATIC", "name": "static"}, "static-routes": {"static": [{"prefix": static_ip, "config": {"prefix": static_ip}, "next-hops": {"next-hop": [params_data]}}]}}]}}]}}
        if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=config_data):
            st.error("Failed to create IP address")
            return False
    else:
        st.error("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
        return False
    return True


def delete_static_route(dut, next_hop, static_ip, family='ipv4', shell="vtysh", interface = None, vrf = None, **kwargs):
    """
    To delete static route
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param dut:
    :param next_hop:
    :param static_ip:
    :param family: ipv4|ipv6
    :param cli_type: click|klish
    :return:
    """
    if shell != 'vtysh':
        st.log("shell parameter is obsolete and will be ignored. Please use cli_type.")
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut,**kwargs))
    if cli_type == 'click':
        cli_type = 'vtysh'
    cli_type = "klish" if cli_type in ["rest-put", "rest-patch"] else cli_type
    nexthop_vrf = kwargs.pop('nexthop_vrf', None)
    command = ''
    if cli_type == "vtysh":
        if family.lower() == "ipv4" or family.lower() == "":
            if next_hop is None:
                command = "no ip route {}".format(static_ip)
            else:
                command = "no ip route {} {}".format(static_ip, next_hop)
        elif family.lower() == "ipv6":
            if next_hop is None:
                command = "no ipv6 route {}".format(static_ip)
            else:
                command = "no ipv6 route {} {}".format(static_ip, next_hop)
        if interface:
            command +=" {}".format(interface)
        if vrf:
            command +=" vrf {}".format(vrf)
        if nexthop_vrf:
            command += " nexthop-vrf {}".format(nexthop_vrf)
        if "track" in kwargs:
            command += " track {}".format(kwargs["track"])
        st.config(dut, command, type='vtysh')
    elif cli_type == "click":
        if family.lower() == "ipv4" or family.lower() == "":
            if next_hop != None:
                command = "ip route del {} via {}".format(static_ip, next_hop)
            else:
                command = "ip route del {}".format(static_ip)
        elif family.lower() == "ipv6":
            if next_hop != None:
                command = "ip -6 route del {}  via {}".format(static_ip, next_hop)
            else:
                command = "ip -6 route del {}".format(static_ip)
        if interface:
            command +=" dev {}".format(interface)
        st.config(dut, command)
    elif cli_type == "klish":
        command = "no ip route"
        if family.lower() == "ipv6":
            command = "no ipv6 route"
        if vrf:
            command += " vrf {}".format(vrf)
        if static_ip:
            command += " {}".format(static_ip)
        if next_hop:
            intf = get_interface_number_from_name(next_hop)
            if isinstance(intf, dict):
                command += " interface {} {}".format(intf['type'], intf['number'])
                interface = None
            else:
                command += " {}".format(next_hop)
        if interface:
            intf = get_interface_number_from_name(interface)
            command +=" interface {} {}".format(intf['type'], intf['number'])
        if nexthop_vrf:
            command += " nexthop-vrf {}".format(nexthop_vrf)
        st.config(dut, command, type="klish", conf=True)
    else:
        st.error("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
        return False
    return True


def show_ip_route(dut, family="ipv4", shell="sonic", vrf_name=None, **kwargs):
    """
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    show_ip_route(dut1)
    show_ip_route(dut1,shell="vtysh")
    show_ip_route(dut1,vrf_name='Vrf-101')
    To get static route

    :param dut:
    :param family: ipv4|ipv6
    :param shell: sonic|vtysh
    :param vrf_name
    :type vrf_name
    :return:
    """

    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut))
    cli_type = "vtysh" if cli_type == 'click' else "klish"
    summary_routes = ' summary' if kwargs.get('summary_routes') else ''
    if vrf_name:
        cmd = "show ip route vrf " + vrf_name + summary_routes
    else:
        cmd = "show ip route" + summary_routes

    if family == "ipv6":
        if vrf_name:
            cmd = "show ipv6 route vrf " + vrf_name + summary_routes
        else:
            cmd = "show ipv6 route" + summary_routes

    output = st.show(dut, cmd, type=cli_type)
    return output


def verify_ip_route(dut, family="ipv4", shell="sonic", vrf_name=None, **kwargs):
    """
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    verify_ip_route(dut1,family='ipv6',vrf_name='Vrf-101')
    verify_ip_route(dut1,family='ipv6',shell='vtysh',vrf_name='Vrf-101')
    verify_ip_route(dut1,family='ipv6')
    verify_ip_route(dut1,vrf_name='Vrf-101',type='B',nexthop='1.0.1.2',interface='Vlan1')
    verify_ip_route(dut1,vrf_name='Vrf-101')
    To verify static route
    :param :dut:
    :param :family: ipv4|ipv6
    :param :shell: sonic|vtysh
    :param :type:
    :param :selected:
    :param :fib:
    :param :ip_address:
    :param :interface:
    :param :duration:
    :param :nexthop:
    :param :distance:
    :param :cost:
    :param :vrf_name
    :type :vrf_name
    :return:
    """

    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut))
    cli_type = "vtysh" if cli_type == 'click' else "klish"

    if family == "ipv6":
        if vrf_name:
            cmd = "show ipv6 route vrf " + vrf_name
        else:
            cmd = "show ipv6 route"
    else:
        if vrf_name:
            cmd = "show ip route vrf " + vrf_name
        else:
            cmd = "show ip route"

    result = st.show(dut, cmd, type=cli_type)

    ret_val = False

    if 'ip_address' in kwargs:
        st.banner("Verify Route:{}".format(kwargs['ip_address']))
        result = utils.filter_and_select(result, None, match={'ip_address': kwargs['ip_address']})

    for rlist in result:
        count = 0
        for key in kwargs:
            if rlist[key] == kwargs[key]:
                count = count + 1
        if len(kwargs) == count:
            ret_val = True
            for key in kwargs:
                st.log("Match: Match key {} found => {} : {}".format(key, kwargs[key], rlist[key]))
            break
        else:
            for key in kwargs:
                if rlist[key] != kwargs[key]:
                    st.log("No-Match: Match key {} NOT found, Expect:{} =>  Got:{}\nCurrent Route:{}\n".format(key, kwargs[key], rlist[key],rlist))

    if not ret_val:
        st.log("Fail: Not Matched all args in passed dict {} from parsed dict".format(kwargs))
    return ret_val


def fetch_ip_route(dut, family="ipv4", shell="sonic", vrf_name=None, match=None, select=None, **kwargs):
    """

    :param dut:
    :param family:
    :param shell:
    :param vrf_name:
    :param match:
    :param select:
    :return:
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut))
    if family == "ipv4":
        result = show_ip_route(dut, family, shell, vrf_name,cli_type=cli_type)
    else:
        result = show_ip_route(dut, family, shell, vrf_name,cli_type=cli_type)
    entries = utils.filter_and_select(result, select, match)
    return entries


def increment_ip_addr(ipaddr, increment_type,family = "ipv4"):
    """
    Author: Ramprakash Reddy <ramprakash-reddy.kanala@broadcom.com>
    :param ipaddr:
    :type ipaddr:
    :param increment_type:
    :type increment_type:
    :param family:
    :type family:
    :return:
    :rtype:
    """
    # remove the netmask portion as it doesnt render well when passed to ipaddress
    if family == "ipv4":
        ip_split = re.split(r'(.*)\.(.*)\.(.*)\.(.*)/(.*)', ipaddr)
        netmask = ip_split[5]
        ip_split = "{}.{}.{}.{}".format(ip_split[1], ip_split[2], ip_split[3], ip_split[4])
    else:
        ip_split = ipaddr.split('/')[0]
        netmask = int(ipaddr.split('/')[1])
    if not utils.is_unicode(ip_split):
        ip_split = ip_split.decode('utf-8', 'ignore')
    temp_ip = ipaddress.ip_address(ip_split)
    try:
        temp_ip = ipaddress.ip_address(ip_split)
        valid_option = True
    except Exception as e:
        st.log(e)
        valid_option = False
    if valid_option:
        if increment_type == "host":
            temp_ip += 1
        elif increment_type == "network":
            if family=="ipv4":
                temp_ip += 256
            else:
                temp_ip += 2 ** (128 - netmask)
    # repack the netmask to the IP address and return
    retval = str(temp_ip) + "/{}".format(netmask)
    return valid_option, retval


def reset_host_ip_to_start(ipaddr):
    """

    :param ipaddr:
    :type ipaddr:
    :return:
    :rtype:
    """
    # remove the netmask portion as it doesnt render well when passed to ipaddress
    ip_split = re.split(r'(.*)\.(.*)\.(.*)\.(.*)/(.*)', ipaddr)
    netmask = ip_split[5]
    ip_split[4] = 1
    ip_split = "{}.{}.{}.{}".format(ip_split[1], ip_split[2], ip_split[3], ip_split[4])
    # repack the netmask to the IP address and return
    retval = str(ip_split) + "/{}".format(netmask)
    return retval


def _clear_ip_configuration_helper(dut_list, family="ipv4", cli_type='', skip_error_check=False):
    """
    Find and clear ip address in DUT
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param dut_list:
    :param family: ipv4|ipv6|all
    :return:
    """
    dut_li = list(dut_list) if isinstance(dut_list, list) else [dut_list]
    cli_type = st.get_ui_type(dut_li[0], cli_type=cli_type)
    if family == "ipv4":
        family_li = ['ipv4']
    elif family == "ipv6":
        family_li = ['ipv6']
    else:
        family_li = ['ipv4', 'ipv6']

    for dut in dut_li:
        for each_af in family_li:
            st.log("############## {} : {} Address Cleanup ################".format(dut, each_af.upper()))
            output = get_interface_ip_address(dut, family=each_af, cli_type=cli_type)
            for each_ip in output:
                if each_ip['interface'].startswith("Eth") or each_ip['interface'].startswith("Vlan") or \
                        each_ip['interface'].startswith("PortChannel") or each_ip['interface'].startswith("Loopback"):
                    ip_parts = each_ip['ipaddr'].split('/')
                    if len(ip_parts) != 2:
                        st.error("Invalid IP {}".format(each_ip['ipaddr']))
                        continue
                    ip, subnet = ip_parts[0], ip_parts[1]
                    if "A" in each_ip['flags']:
                        config_sag_ip(dut, interface=each_ip['interface'], gateway=ip, mask=subnet, config="remove", cli_type=cli_type)
                    elif not each_ip['ipaddr'].startswith('fe80::'):
                        delete_ip_interface(dut, each_ip['interface'], ip, subnet, family=each_af, cli_type=cli_type, skip_error=skip_error_check)
                    else:
                        ip_link_local = ip.split('%')[0] if '%' in ip else ip
                        delete_ip_interface(dut, each_ip['interface'], ip_link_local, subnet, family=each_af, cli_type=cli_type, skip_error=skip_error_check)
    return True


def clear_ip_configuration(dut_list, family='ipv4', thread=True, cli_type='', skip_error_check=False):
    """
    Find and clear ip address in the list of DUTs
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param dut_list:
    :param family: ipv4 (Default) / ipv6
    :param thread: True (Default) / False
    :return:
    """
    dut_li = list(dut_list) if isinstance(dut_list, list) else [dut_list]
    cli_type = st.get_ui_type(dut_li[0], cli_type=cli_type)
    [out, _] = utils.exec_foreach(thread, dut_li, _clear_ip_configuration_helper, family, cli_type=cli_type, skip_error_check=skip_error_check)
    return False if False in out else True


def get_loopback_interfaces(dut):
    """
    To get list of loopback interfaces.
    """
    output = st.show(dut, "show interfaces loopback")
    st.log("### loopbacks={}".format(output))
    loopbacks = []
    for entry in output:
        if entry['ifname']:
            loopbacks.append(entry['ifname'])
    return loopbacks


def _clear_loopback_config_helper(dut_list):
    """
    Helper internal function to find and clear loopback interfaces.
    """
    dut_li = list(dut_list) if isinstance(dut_list, list) else [dut_list]

    for dut in dut_li:
        st.log("############## {} : Loopback intfs Cleanup ################".format(dut))
        output = get_loopback_interfaces(dut)
        for intf in output:
            configure_loopback(dut,loopback_name=intf,config="no")
    return True


def clear_loopback_interfaces(dut_list, thread=True):
    """
    Find and delete all loopback interfaces.

    :param dut_list
    :return:
    """
    dut_li = list(dut_list) if isinstance(dut_list, list) else [dut_list]
    [out, _] = utils.exec_foreach(thread, dut_li, _clear_loopback_config_helper)
    return False if False in out else True


def get_network_addr(ipaddr):
    """
    Get network address from an ip address
    Author: Lakshminarayana D (lakshminarayana.d@broadcom.com)
    :param ipaddr:
    :type ipaddr:
    :return:
    :rtype:
    """
    if not utils.is_unicode(ipaddr):
        ipaddr = ipaddr.decode('utf-8', 'ignore')
    try:
        iface = ipaddress.ip_interface(ipaddr)
        network = iface.network
        valid_option = True
        # netmask = iface.netmask
        # net_add = iface.network.network_address
    except ValueError:
        network = ""
        valid_option = False
    return valid_option, str(network)


def clear_ip_route(dut, **kwargs):
    """
    Clear ip route
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param :dut:
    :param :not_installed:
    :param :prefix_mask: prefix/mask
    :return:
    """

    command = "clear ip route"
    if 'not_installed' in kwargs:
        command += " {}".format('not_installed')
    if 'prefix_mask' in kwargs:
        command += " {}".format(kwargs['prefix_mask'])
    st.config(dut, command, type='vtysh')
    return True


def verify_ip_route_not_installed(dut, family="ipv4", **kwargs):
    """
    To verify static route not installed
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param :dut:
    :param :family: ipv4|ipv6
    :param :type:
    :param :selected:
    :param :fib:
    :param :ip_address:
    :param :interface:
    :param :duration:
    :param :nexthop:
    :param :distance:
    :param :cost:
    :return:
    """
    if family == "ipv4":
        command = "show ip route not-installed"
        result = st.show(dut, command, type='vtysh')
    else:
        command = "show ipv6 route not-installed"
        result = st.show(dut, command, type='vtysh')

    for each in kwargs.keys():
        match = {each: kwargs[each]}
        entries = utils.filter_and_select(result, None, match)
        if not entries:
            st.log("{} and {} is not match ".format(each, kwargs[each]))
            return False
    return True


def create_neighbor(dut, neigh, mac, interface, family='ipv4'):
    """
    Author: Amit Kaushik (amit.kaushik@broadcom.com)
    :param dut:
    :param neigh:
    :param mac:
    :param interface:
    :param family:
    :return:
    """
    if '/' in interface:
        interface = st.get_other_names(dut,[interface])[0]

    command = ''
    if family.lower() == "ipv4":
        command = "ip neigh replace {} lladdr {} dev {}".format(neigh, mac, interface)
    elif family.lower() == "ipv6":
        command = "ip -6 neigh replace {} lladdr {} dev {}".format(neigh, mac, interface)
    st.config(dut, command)


def delete_neighbor(dut, neigh, mac, interface, family='ipv4'):
    """
    Author: Amit Kaushik (amit.kaushik@broadcom.com)
    :param dut:
    :param neigh:
    :param mac:
    :param interface:
    :param family:
    :return:
    """
    if '/' in interface:
        interface = st.get_other_names(dut,[interface])[0]

    command = ''
    if family.lower() == "ipv4":
        command = "ip neigh del {} lladdr {} dev {}".format(neigh, mac, interface)
    elif family.lower() == "ipv6":
        command = "ip -6 neigh del {} lladdr {} dev {}".format(neigh, mac, interface)
    st.config(dut, command)


def traceroute(dut, addresses, family='ipv4', vrf_name=None, timeout=None, gateway=None, external=False):
    """
    traceroute(dut1,addresses='10.75.224.184')
    traceroute(dut1,addresses='10.75.224.184',vrf_name ='Vrf-RED')
    :param dut:
    :param addresses:
    :param family:
    :param vrf_name:
    :param timeout:
    :param gateway:
    :param external: True | False (Default: False) # Used True for traceroute from external server. (Ex: VDI)
    :return:
    """
    trace_route1 = r'(.*)\s+\(' + addresses + r'\)\s+(\d+\.\d+)\s+ms\s+(\d+\.\d+)\s+ms\s+(\d+\.\d+)\s+ms'
    trace_route2 = r'(\d+)\s+(' + addresses + r')\s+(\d+\.\d+)\s*ms\s+(\d+\.\d+)\s*ms\s+(\d+\.\d+)\s*ms'
    trace_route = r"{}|{}".format(trace_route1, trace_route2)
    command = "traceroute -4 {}".format(addresses)
    if external:
        command = "traceroute {}".format(addresses)
    if family.lower() == "ipv6":
        command = "traceroute -6 {}".format(addresses)
        if external:
            command = "traceroute6 {}".format(addresses)
    if vrf_name:
        command = command + " -i {} ".format(vrf_name)
    if timeout:
        command = command + " -w {} ".format(timeout)
    if gateway:
        command = command + " -g {} ".format(gateway)

    if external:
        st.log(command)
        p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True,
                             universal_newlines=True)
        rv, err = p.communicate()
        st.log(rv)
        st.log(err)
    else:
        rv = st.config(dut, command)
    result = re.findall(trace_route, str(rv))
    if result:
        st.log("Traceroute to destination address " + addresses + " Passed")
        return True
    else:
        st.log("Traceroute to destination address " + addresses + " Failed")
        return False


def config_linux_static_route(dut, **kwargs):
    """
    Author: Priyanka Gupta

    :param :dut:
    :param :next_hop:
    :param :static_ip:
    :param :family: ipv4|ipv6
    :return:
    """
    command = ''
    if kwargs["action"] == "add":
        if kwargs["family"] == "ipv4":
            command = "ip route add {} nexthop via {}".format(kwargs["route"], kwargs["nhp"])
            if "nhp1" in kwargs:
                command += " nexthop via {}".format(kwargs["nhp1"])
        elif kwargs["family"].lower() == "ipv6":
            command = "ip -6 route add {} via {}".format(kwargs["route"], kwargs["nhp"])

    elif kwargs["action"] == "delete":
        if kwargs["family"] == "ipv4":
            command = "ip route delete {}".format(kwargs["route"])
        elif kwargs["family"] == "ipv6":
            command = "ip -6 route delete {}".format(kwargs["route"])
    st.config(dut, command)


def config_route_map(dut, route_map, config='yes', **kwargs):
    """
    :param :dut:
    :param :route-map: name of the route map
    :param :community: name of the community
    :EX: config_route_map(dut, route_map='rmap1', config='yes', sequence='10', community='100:100')
         config_route_map(dut, route_map='rmap1', config='no')
         config_route_map(dut, route_map='rmap1', config='no', sequence='10')
    :Caution: while creating the route-map (config='yes'), sequence number must be mentioned and it should be
              the first parameter of the variable argument, because other arguments have newline appended.
    :return:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = "vtysh" if cli_type == 'click' else "klish"
    if config == 'yes':
        cmd = "route-map {}".format(route_map)
        if kwargs['sequence']:
            cmd += " permit {}".format(kwargs['sequence'])
        if 'metric' in kwargs:
            cmd += "\n set metric {}".format(kwargs['metric'])
        if 'community' in kwargs:
            cmd += "\n set community {}".format(kwargs['community'])
        cmd += "\n"
        cmd += "exit\n"
        st.config(dut, cmd, type=cli_type)
    else:
        cmd = "no route-map {}".format(route_map)
        if 'sequence' in kwargs:
            cmd += " permit {}".format(kwargs['sequence'])
        cmd += "\n"
        st.config(dut, cmd, type=cli_type)


def config_route_map_global_nexthop(dut, route_map='route_map_next_hop_global', sequence='10', config='yes', **kwargs):
    """
    :Author: sooriya.gajendrababu@broadcom.com
    :param dut:
    :param route_map:
    :param sequence:
    :param config:
    :return:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = "vtysh" if cli_type in ['click', 'vtysh'] else "klish"

    if cli_type == 'vtysh':
        if config == 'yes':
            cmd = "route-map {} permit {} \n set ipv6 next-hop prefer-global".format(route_map, sequence)
            st.config(dut, cmd, type='vtysh')
        else:
            cmd = "no route-map {} permit {}\n".format(route_map, sequence)
            st.config(dut, cmd, type='vtysh')
    elif cli_type == 'klish':
        cmd = "route-map {} permit {} \n".format(route_map, sequence)
        if config == 'yes':
            cmd += 'set ipv6 next-hop prefer-global \n'
            cmd += 'exit\n'
        else:
            cmd = 'no ' + cmd
        st.config(dut, cmd, type='klish')


def config_static_route_vrf(dut, dest, dest_subnet, next_hop, family='ipv4', vrf_name=None, config='', **kwargs):
    """
    Author: Manisha Joshi
    :param dut:
    :param dest:
    :param dest_subnet:
    :param next_hop:
    :param family:
    :param vrf_name:
    :param config:
    :return:
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut,**kwargs))
    if cli_type == 'click':
        my_cmd = ''
        if family.lower() == "ipv4" or family.lower() == "":
            my_cmd = "{} ip route {}/{} {} vrf {}".format(config, dest, dest_subnet, next_hop, vrf_name)
            st.config(dut, my_cmd, type='vtysh')
        elif family.lower() == "ipv6":
            my_cmd = "{} ipv6 route {}/{} {} vrf {}".format(config, dest, dest_subnet, next_hop, vrf_name)
            st.config(dut, my_cmd, type='vtysh')
    elif cli_type in ["klish", "rest-put", "rest-patch"]:
        static_ip = '{}/{}'.format(dest, dest_subnet)
        if config == 'no':
            return delete_static_route(dut, next_hop=next_hop, static_ip=static_ip, family=family, vrf=vrf_name, cli_type=cli_type)
        else:
            return create_static_route(dut, next_hop=next_hop, static_ip=static_ip, family=family, vrf=vrf_name, cli_type=cli_type)


def create_static_route_nexthop_vrf(dut, next_hop, static_ip, shell="vtysh", family='ipv4',vrf_name="", nhopvrf="",
                                    config="yes", **kwargs):
    """
    To create static route with nexthop as vrf
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param dut:
    :param next_hop:
    :param static_ip:
    :param shell: sonic|vtysh
    :param family: ipv4|ipv6
    :param config: yes|no
    :return:
    """

    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut,**kwargs))
    if cli_type in ["klish", "rest-put", "rest-patch"]:
        if config == 'no':
            return delete_static_route(dut, next_hop=next_hop, static_ip=static_ip, family=family, vrf=vrf_name, nexthop_vrf=nhopvrf, cli_type=cli_type)
        else:
            return create_static_route(dut, next_hop=next_hop, static_ip=static_ip, family=family, vrf=vrf_name, nexthop_vrf=nhopvrf, cli_type=cli_type)

    if shell == "vtysh":
        if config == "no":
            command = "no "
        else:
            command = ""
        if family.lower() == "ipv4" or family.lower() == "":
            if vrf_name and nhopvrf:
                command += "ip route {} {} vrf {} nexthop-vrf {}".format(static_ip, next_hop,vrf_name,nhopvrf)
                st.config(dut, command, type='vtysh')
            if vrf_name and nhopvrf=="":
                command += "ip route {} {} vrf {}".format(static_ip, next_hop,vrf_name)
                st.config(dut, command, type='vtysh')
            if vrf_name == "" and nhopvrf:
                command += "ip route {} {} nexthop-vrf {}".format(static_ip, next_hop,nhopvrf)
                st.config(dut, command, type='vtysh')
            if vrf_name =="" and nhopvrf=="":
                command += "ip route {} {} ".format(static_ip, next_hop)
                st.config(dut, command, type='vtysh')

        elif family.lower() == "ipv6":
            if vrf_name and nhopvrf:
                command += "ipv6 route {} {} vrf {} nexthop-vrf {}".format(static_ip, next_hop,vrf_name,nhopvrf)
                st.config(dut, command, type='vtysh')
            if vrf_name and nhopvrf=="":
                command += "ipv6 route {} {} vrf {}".format(static_ip, next_hop,vrf_name)
                st.config(dut, command, type='vtysh')
            if vrf_name == "" and nhopvrf:
                command += "ipv6 route {} {} nexthop-vrf {}".format(static_ip, next_hop,nhopvrf)
                st.config(dut, command, type='vtysh')
            if vrf_name == "" and nhopvrf=="":
                command += "ipv6 route {} {} ".format(static_ip, next_hop)
                st.config(dut, command, type='vtysh')
    else:
        if family.lower() == "ipv4" or family.lower() == "":
            command = "ip route add {} via {}".format(static_ip, next_hop)
            st.config(dut, command)
        elif family.lower() == "ipv6":
            command = "ip -6 route add {} via {}".format(static_ip, next_hop)
            st.config(dut, command)



def config_route_map_mode(dut, tag, operation, sequence, config='yes', **kwargs):
    """
    :param dut:
    :param tag: route-map name
    :param operation: deny/permit
    :param sequence
    :param config
    :return:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = 'vtysh' if cli_type in ['vtysh', 'click'] else cli_type
    if cli_type in ['vtysh', 'klish']:
        if config.lower() == 'yes':
            mode = ""
        else:
            mode = 'no'
        command = "{} route-map {} {} {}\n".format(mode, tag, operation, sequence)
        st.config(dut, command, type=cli_type)
    elif cli_type in ['rest-patch', 'rest-put']:
        action = 'ACCEPT_ROUTE' if operation == 'permit' else 'REJECT_ROUTE'
        rest_urls = st.get_datastore(dut, 'rest_urls')
        if config.lower() == 'yes':
            url = rest_urls['route_map_policy_config']
            config_data = {"openconfig-routing-policy:policy-definition": [{"name": tag, "config": {"name": tag}, "statements": {"statement": [{"name": str(sequence), "config": {"name": str(sequence)}, "actions": {"config": {"policy-result": action}}}]}}]}
            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=config_data):
                st.error("Failed to configure route map with name: {}, action: {}, sequence: {}".format(tag, operation, sequence))
                return False
        else:
            url = rest_urls['clear_route_map_policy'].format(tag, sequence)
            if not delete_rest(dut, rest_url=url):
                st.error("Failed to un-configure route map with name: {}, action: {}, sequence: {}".format(tag, operation, sequence))
                return False
    else:
        st.error("Invalid cli_type for this API - {}.".format(cli_type))
        return False
    return True



def config_route_map_match_ip_address(dut, tag, operation, sequence, value, family = 'ipv4',**kwargs):
    """
    :param dut:
    :param tag: route-map name
    :param operation: deny/permit
    :param sequence
    :param value: access_list / prefix-list/ prefix-len
    :return:
    """
    family = 'ip' if family == 'ipv4' else 'ipv6'
    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = 'vtysh' if cli_type in ['vtysh', 'click'] else cli_type
    if not config_route_map_mode(dut, tag, operation, sequence, cli_type=cli_type):
        st.error("Route map mode configuration failed")
        return False
    command = ''
    if cli_type == 'vtysh':
        command += 'match {} address {}\n'.format(family,value)
        command += 'exit\n'
        st.config(dut, command, type = cli_type)
    elif cli_type == 'klish':
        command += 'match {} address prefix-list {}\n'.format(family,value)
        command += 'exit\n'
        st.config(dut, command, type = cli_type)
    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        url = rest_urls['match_prefix_set_config'].format(tag, sequence)
        config_data = {"openconfig-routing-policy:config": {"prefix-set": str(value)}}
        if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=config_data):
            st.error("Failed to configure route map match IP address")
            return False
    else:
        st.error("Invalid cli_type for this API - {}.".format(cli_type))
        return False
    return True


def config_route_map_set_aspath(dut, tag, operation, sequence, value, option='prepend', cli_type=''):
    """
    :param dut:
    :param tag: route-map name
    :param operation: deny/permit
    :param sequence
    :param option : exclude/prepend
    :param value: as-path
    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    cli_type = 'vtysh' if cli_type in ['vtysh', 'click'] else cli_type
    config_route_map_mode(dut, tag, operation, sequence, cli_type=cli_type)
    if cli_type in ['vtysh', 'klish']:
        command = "set as-path {} {}\n".format(option, value)
        command += "exit\n"
        st.config(dut, command, type=cli_type)
    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        url = rest_urls['aspath_config'].format(tag, sequence)
        config_data = {"openconfig-bgp-policy:config": {"openconfig-routing-policy-ext:asn-list": str(value)}}
        if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=config_data):
            st.error("Failed to configure as-path {} value as: {}".format(option, value))
            return False
    else:
        st.error("Invalid cli_type for this API - {}.".format(cli_type))
        return False
    return True


def config_access_list(dut, name, ipaddress, mode='permit', config='yes', family='ipv4', cli_type="", seq_num=''):
    """
    :param dut:
    :param name: access-list name
    :param ipaddress: address/prefix
    :param mode: deny/permit
    :param config: 'yes'
    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    cli_type = "vtysh" if cli_type == 'click' else "klish"

    if config.lower() == 'yes':
        config = ""
    else:
        config = 'no'
    if cli_type == "klish":
        ip_cmd = "ipv6" if family == "ipv6" else "ip"
        if seq_num != '':
            command = "{} {} prefix-list {} seq {} {} {}\n".format(config, ip_cmd, name, seq_num, mode, ipaddress)
        else:
            command = "{} {} prefix-list {} {} {}\n".format(config, ip_cmd, name, mode, ipaddress)
    else:
        if family == 'ipv6':
            command = "{} ipv6 access-list {} {} {}\n".format(config, name, mode, ipaddress)
        else:
            command = "{} access-list {} {} {}\n".format(config, name, mode, ipaddress)

    st.config(dut, command, type=cli_type)


def configure_loopback(dut, **kwargs):
    return config_loopback_interfaces(dut, **kwargs)


def config_unconfig_interface_ip_addresses(dut, if_data_list=[], config='add',cli_type='',ip_type=''):
    """
    Configure IP addresses on multiple interfaces
    Author: Naveena Suvarna (naveen.suvarna@broadcom.com)

    :param dut:
    :param if_data_list:
    :param config:
    :return:
    """
    if config != 'add' and config != 'remove':
        st.error("Invalid config type {}".format(config))
        return False
    cli_type=st.get_ui_type(dut, cli_type=cli_type)

    command = ''
    for if_data in if_data_list:
        if not if_data['name']:
            st.error("Please provide interface name in {} ".format(if_data))
            return False

        if not is_valid_ip_address(if_data['ip'], if_data['family'], if_data['subnet']):
            st.error("Invalid IP address or family or subnet {} ".format(if_data))
            return False
        if cli_type == 'click':
            command += "sudo config interface ip {} {} {}/{} ; ".format(config,
                                                                if_data['name'], if_data['ip'], if_data['subnet'])
        elif cli_type == 'klish':
            #config = '' if config == 'add' else 'no'
            family = 'ip' if if_data['family'] == 'ipv4' else 'ipv6'
            # if config == 'add':
            #     command += "interface {} \n {} address {}/{}\n".format(if_data['name'],family,if_data['ip'],if_data['subnet'])
            if config == 'add':
                intf = get_interface_number_from_name(if_data['name'])
                if ip_type == 'secondary':
                    command += "interface {} {} \n {} address {}/{} secondary \n".format(intf['type'], intf['number'],family,if_data['ip'],if_data['subnet'])
                else:
                    command += "interface {} {} \n {} address {}/{}\n".format(intf['type'], intf['number'],family,if_data['ip'],if_data['subnet'])
            # else:
            #     command += "interface {} \n no {} address {}/{}\n".format(if_data['name'],family,if_data['ip'],if_data['subnet'])
            else:
                intf = get_interface_number_from_name(if_data['name'])
                if ip_type == 'secondary':
                    command += "interface {} {}\n no {} address {}/{} secondary \n".format(intf['type'], intf['number'],family,if_data['ip'],if_data['subnet'])
                else:
                    command += "interface {} {}\n no {} address {}/{}\n".format(intf['type'], intf['number'],family,if_data['ip'],if_data['subnet'])
        elif cli_type in ['rest-patch', 'rest-put']:
            secondary_ip = 'no'
            if ip_type == 'secondary':
                secondary_ip = 'yes'
            if not config_ip_addr_interface(dut, interface_name=if_data['name'], ip_address=if_data['ip'], subnet=if_data['subnet'], family=if_data['family'], config=config, cli_type=cli_type, is_secondary_ip=secondary_ip):
                st.error("Failed to {} IP: {}/{} on interface: {}".format(config, if_data['ip'], if_data['subnet'], if_data['name']))
                return False
        else:
            st.error("Invalid cli_type for this API - {}.".format(cli_type))
            return False
    if command != '':
        if cli_type == 'click':
            try:
                st.config(dut, command)
            except Exception as e:
                st.log(e)
                return False
        elif cli_type == 'klish':
            output = st.config(dut,command,type=cli_type,conf=True,skip_error_check=True)
            if "Could not connect to Management REST Server" in output:
                st.error("klish mode not working.")
                return False
    return True


def config_unconfig_static_routes(dut, route_data_list=[], shell="vtysh", config='add'):
    """
    Configure multiple static route entries
    Author: Naveena Suvarna (naveen.suvarna@broadcom.com)

    :param dut:
    :param route_data_list
    :param shell
    :param config
    :return:
    """
    if config != 'add' and config != 'remove':
        st.error("Invalid config type {}".format(config))
        return False

    command = ''
    for rt_data in route_data_list:
        if not is_valid_ip_address(rt_data['ip'], rt_data['family'], rt_data['subnet']):
            st.error("Invalid IP address or family or subnet {} ".format(rt_data))
            return False

        if not rt_data['nexthop']:
            st.error("Please provide nexthop in {} ".format(rt_data))
            return False

        if shell == "vtysh":
            cfg_mode = '' if config == 'add' else 'no'
            family = 'ip' if rt_data['family'] == 'ipv4' else 'ipv6'
            command += " {} {} route {}/{} {} \n ".format(cfg_mode, family,
                                                          rt_data['ip'], rt_data['subnet'], rt_data['nexthop'])
        else:
            family = '' if rt_data['family'] == 'ipv4' else '-6'
            command += " sudo ip {} route {} {}/{} via {} ; ".format(family, config,
                                                                     rt_data['ip'],
                                                                     rt_data['subnet'], rt_data['nexthop'])

    if command != '':
        try:
            if shell == "vtysh":
                st.config(dut, command, type='vtysh')
            else:
                st.config(dut, command)
        except Exception as e:
            st.log(e)
            return False
    return True


class PrefixList:
    """
    Usage:
    prefix_list = PrefixList("mylist")
    prefix_list.add_description("This_is_my_prefix_list")
    prefix_list.add_match_permit_sequence('0.0.0.0/0', seq_num='10')
    prefix_list.add_match_permit_sequence('1.1.1.1/32')
    prefix_list.add_match_deny_sequence('2.2.2.0/24', seq_num='30', ge='26')
    prefix_list.add_match_permit_sequence('3.3.3.0/24', seq_num='40', ge='26', le='30')
    prefix_list.execute_command(dut, config='yes')
    cmd_string = prefix_list.config_command_string()
    prefix_list.execute_command(dut, config='no')
    """

    def __init__(self, name, family='ipv4',cli_type=''):
        self.name = name
        self.description = ''
        self.family = family
        self.match_sequence = []
        self.cli_type = st.get_ui_type(cli_type=cli_type)
        self.cli_type = 'vtysh' if self.cli_type in ['click','vtysh'] else 'klish'
        if self.family == 'ipv6':
            self.cmdkeyword = 'ipv6 prefix-list'
        else:
            self.cmdkeyword = 'ip prefix-list'

    def add_description(self, description):
        self.description = description

    def add_match_permit_sequence(self, prefix, ge='', le='', seq_num=''):
        if self.cli_type == 'klish':
            if prefix == 'any':
                if self.family == 'ipv4':
                    prefix = '0.0.0.0/0'
                    le = '32'
                else:
                    prefix = '::/0'
                    le = '128'
        self.match_sequence.append((seq_num, 'permit', prefix, ge, le))


    def add_match_deny_sequence(self, prefix, ge='', le='', seq_num=''):
        if self.cli_type == 'klish':
            if prefix == 'any':
                if self.family == 'ipv4':
                    prefix = '0.0.0.0/0'
                    le = '32'
                else:
                    prefix = '::/0'
                    le = '128'
        self.match_sequence.append((seq_num, 'deny', prefix, ge, le))


    def config_command_string(self):
        command = ''
        if self.cli_type == 'vtysh':
            if self.description != '':
                command += '{} {} description {}\n'.format(self.cmdkeyword, self.name, self.description)
            for v in self.match_sequence:
                if v[0] != '':
                    command += '{} {} seq {} {} {}'.format(self.cmdkeyword, self.name, v[0], v[1], v[2])
                else:
                    command += '{} {} {} {}'.format(self.cmdkeyword, self.name, v[1], v[2])
                if v[3] != '':
                    command += ' ge {}'.format(v[3])
                if v[4] != '':
                    command += ' le {}'.format(v[4])
                command += '\n'
        elif self.cli_type == 'klish':
            for v in self.match_sequence:
                if v[0] != '':
                    command += '{} {} seq {} {} {}'.format(self.cmdkeyword, self.name, v[0], v[1], v[2])
                else:
                    command += '{} {} {} {}'.format(self.cmdkeyword, self.name, v[1], v[2])
                if v[3] != '':
                    command += ' ge {}'.format(v[3])
                if v[4] != '':
                    command += ' le {}'.format(v[4])
                command += '\n'
        return command

    def unconfig_command_string(self):
        command = 'no {} {}\n'.format(self.cmdkeyword, self.name)
        return command

    def execute_command(self, dut, config='yes',cli_type=''):
        if config == 'no':
            command = self.unconfig_command_string()
        else:
            command = self.config_command_string()
        if self.cli_type == 'vtysh':
            st.config(dut, command, type='vtysh')
        elif self.cli_type == 'klish':
            output = st.config(dut,command,type='klish',conf=True)
            if "Could not connect to Management REST Server" in output:
                st.error("klish mode not working.")
                return False
        else:
            st.warn("UNSUPPORTED CLI TYPE - {}".format(cli_type))
            return False
        return True



class AccessList:
    """
    Usage:
    access_list = AccessList("aclcfg")
    access_list.add_description("This_is_my_access_list")
    access_list.add_match_permit_sequence('0.0.0.0/0')
    access_list.add_match_permit_sequence('1.1.1.1/32')
    access_list.add_match_deny_sequence('2.2.2.2/24', exact_match="true")
    access_list.add_match_permit_sequence('3.3.3.3/24')
    access_list.execute_command(dut, config='yes')
    cmd_string = access_list.config_command_string()
    access_list.execute_command(dut, config='no')
    """

    def __init__(self, name, family='ipv4', cli_type=''):
        self.name = name
        self.description = ''
        self.family = family
        self.match_sequence = []
        self.cli_type = st.get_ui_type() if not cli_type else cli_type
        self.cli_type = 'vtysh' if self.cli_type == 'click' else 'klish'
        self.def_rule_seq = int(name) if name.isdigit() else 1
        if self.family == 'ipv6':
            self.cmdkeyword = 'ipv6 access-list'
            self.acl_type = 'ipv6'
        else:
            self.acl_type = 'ip'
            self.cmdkeyword = 'access-list' if self.cli_type == 'vtysh' else 'ip access-list'

    def add_description(self, description):
        self.description = description

    def add_match_permit_sequence(self, prefix, exact_match='false', rule_seq = None):
        if self.cli_type == 'klish':
            if not rule_seq:
                rule_seq = self.def_rule_seq
                self.def_rule_seq += 1
        self.match_sequence.append(('permit', prefix, exact_match, rule_seq))

    def add_match_deny_sequence(self, prefix, exact_match='false', rule_seq = None):
        if self.cli_type == 'klish':
            if not rule_seq:
                rule_seq = self.def_rule_seq
                self.def_rule_seq += 1
        self.match_sequence.append(('deny', prefix, exact_match, rule_seq))

    def config_command_string(self):
        command = ''
        if self.cli_type == 'vtysh':
            if self.description:
                command += '{} {} remark {}\n'.format(self.cmdkeyword, self.name, self.description)
            for v in self.match_sequence:
                command += '{} {} {} {}'.format(self.cmdkeyword, self.name, v[0], v[1])
                if v[2] != 'false':
                    command += ' exact-match'
                command += '\n'
            return command
        elif self.cli_type == 'klish':
            command += '{} {}\n'.format(self.cmdkeyword, self.name)
            if self.description:
                command += 'remark {}\n'.format(self.description)
            for v in self.match_sequence:
                command += 'seq {} {} {} {} {}\n'.format(v[3], v[0], self.acl_type, v[1], 'any')
            command += 'exit\n'
        return command

    def unconfig_command_string(self):
        command = 'no {} {}\n'.format(self.cmdkeyword, self.name)
        return command

    def execute_command(self, dut, config='yes'):
        if config == 'no':
            command = self.unconfig_command_string()
        else:
            command = self.config_command_string()
        st.config(dut, command, type=self.cli_type)


def get_link_local_addresses(dut, interface, **kwargs):
    """
    To get the Link local address on port.
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param dut:
    :param interface:
    :return:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = 'klish' if cli_type in ['rest-patch', 'rest-put'] else cli_type
    output = get_interface_ip_address(dut, interface, family="ipv6", cli_type=cli_type)
    ipv6_list = utils.dicts_list_values(output, 'ipaddr')
    st.log("IPV6 LIST: {}".format(ipv6_list))
    if cli_type == 'click':
        return [each.split("%")[0] for each in ipv6_list if '%' in each]
    if cli_type == 'klish':
        return [each.split("/")[0] for each in ipv6_list if each.startswith('fe80::')]

def config_interface_ip6_link_local(dut, interface_list, action='enable', **kwargs):
    """
    Configure IPv6 link local on multiple interfaces
    Author: Kesava Swamy (kesava-swamy.karedla@broadcom.com)

    :param dut:
    :param interface_list:
    :param action:
    :return:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    if action != 'enable' and action != 'disable':
        st.error("Invalid config type {}".format(action))
        return False
    interfaces = list(interface_list) if isinstance(interface_list, list) else [interface_list]
    command = ''
    if cli_type == 'click':
        for interface in interfaces:
            if not interface:
                st.error("Please provide interface name in {} ".format(interface))
                return False
            command += "sudo config interface ipv6 {} use-link-local-only {} ; ".format(action,interface)
    elif cli_type == 'klish':
        command = list()
        for interface in interfaces:
            if not interface:
                st.error("Please provide interface name in {} ".format(interface))
                return False
            intf = get_interface_number_from_name(interface)
            #Need to split interface name due to defect in portchannel
            command.append('interface {} {}'.format(intf["type"], intf["number"]))
            command.append('ipv6 enable' if action.lower() == 'enable' else 'no ipv6 enable')
            command.append('exit')
    elif cli_type in ['rest-patch', 'rest-put']:
        state = True if action == 'enable' else False
        rest_urls = st.get_datastore(dut, 'rest_urls')
        for interface in interfaces:
            index = get_subinterface_index(dut, interface)
            url = rest_urls['ipv6_enable_config'].format(interface, index)
            config_data = {"openconfig-if-ip:config": {"enabled": state}}
            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=config_data, timeout=100):
                st.error("Failed enable/disable ipv6 on interface: {}".format(interface))
                return False
    else:
        st.error("Invalid cli_type for this API - {}.".format(cli_type))
        return False

    if command:
        try:
            st.config(dut, command, type=cli_type)
        except Exception as e:
            st.log(e)
            return False

    return True


def config_interface_ip_addresses(dut, if_data_list={}, config='yes', cli_type=''):

    if config == 'yes' or config == 'add':
        config = 'add'
    elif config == 'no' or config == 'del':
        config = 'remove'
    else :
        st.error("Invalid config type {}".format(config))
        return False

    cli_type = st.get_ui_type(dut, cli_type=cli_type)

    command = []
    for _, if_data in if_data_list.items():
        if not if_data['name']:
            st.error("Please provide interface name in {} ".format(if_data))
            return False

        if not is_valid_ip_address(if_data['ip'], if_data['family'], if_data['subnet']):
            st.error("Invalid IP address or family or subnet {} ".format(if_data))
            return False

        if cli_type == 'click':
            cmd_str = "sudo config interface ip {} {} {}/{} ".format(config,
                                      if_data['name'], if_data['ip'], if_data['subnet'])
            command.append(cmd_str)
        elif cli_type == 'klish':
            intf_info = get_interface_number_from_name(if_data['name'])
            cmd_str = 'interface {} {}'.format(intf_info["type"], intf_info["number"])
            command.append(cmd_str)
            cmd_str = "no " if config == 'remove' else ''
            cmd_str +="ip address {}/{}".format(if_data['ip'], if_data['subnet'])
            command.append(cmd_str)
            command.append('exit')
        elif cli_type in ['rest-patch', 'rest-put']:
            st.error("Spytest API not yet supported for REST type")
            return False

    if cli_type in ['click', 'klish' ] :
        try:
            st.config(dut, command, type=cli_type)
        except Exception as e:
            st.log(e)
            return False

    return True

def config_unnumbered_interface(dut, **kwargs):
    """
    API to config / unconfig unnumbered interface
    :param dut:
    :param kwargs:
    :return:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    family = kwargs.get("family","ipv4")
    action = kwargs.get("action","add")
    interface = kwargs.get("interface", None)
    loop_back = kwargs.get("loop_back", None)
    skip_error = kwargs.get('skip_error', False)
    intf_name = get_interface_number_from_name(interface)

    if cli_type == "click":
        commands = list()
        if action not in ["add","del"]:
            st.log("Unsupported action provided")
            return False
        if not interface:
            st.log("Please provide interface")
            return False
        if not loop_back and action == "add":
            st.log("Please provide loopback interface")
            return False
        if family == "ipv4":
            if action == "add":
                command = "config interface ip unnumbered add {} {}".format(interface, loop_back)
            else:
                command = "config interface ip unnumbered del {}".format(interface)
            commands.append(command)
    elif cli_type == "klish":
        commands = list()
        if interface and loop_back and family == "ipv4":
            command = "interface {} {}".format(intf_name["type"],intf_name["number"])
            commands.append(command)
            if action == "add":
                command = "ip unnumbered {} \n exit \n".format(loop_back)
            elif action == "del":
                command = "no ip unnumbered\n exit \n"
            commands.append(command)
        else:
            st.log("Please provide interface, loop_back and family as ipv4")
            return False
    elif cli_type in ['rest-patch', 'rest-put']:
        if interface and loop_back and family == "ipv4":
            rest_urls = st.get_datastore(dut, 'rest_urls')
            index = get_subinterface_index(dut, interface)
            if action == 'add':
                url = rest_urls['ipv4_unnumbered_interface_config'].format(interface, index)
                config_data = {"openconfig-if-ip:config": {"interface": loop_back, "subinterface": int(index)}}
                if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=config_data, timeout=100):
                    st.error("Failed to configure unnumbered interface")
                    return False
            elif action == "del":
                url = rest_urls['ipv4_unnumbered_interface_config'].format(interface, int(index))
                if not delete_rest(dut, rest_url=url, timeout=100):
                    st.error("Failed to un-configure unnumbered interface")
                    return False
        else:
            st.log("Please provide interface, loop_back and family as ipv4")
            return False
        return True
    if commands:
        if skip_error:
            try:
                st.config(dut, commands, skip_error_check=skip_error, type=cli_type)
                return True
            except Exception:
                st.log("Error handled..by API")
                return False
        else:
            st.config(dut, commands, skip_error_check=skip_error, type=cli_type)
            return True


def prepare_show_ipv6_interface_output(data):
    """
    Helper function to prepare show ipv6 interface output
    :param data:
    :return:
    """
    output = dict()
    result = list()
    for ip_data in data:
        if output.get(ip_data["interface"]):
            output[ip_data["interface"]].append(ip_data)
        else:
            output[ip_data["interface"]] = [ip_data]
    if output:
        ip_keys = ["status", "neighborip", "ipaddr", "flags", "vrf", "neighbor", "interface"]
        for _, value in output.items():
            result.append(value[0])
            if len(value) > 1:
                for attr in ip_keys:
                    value[1][attr] = value[1][attr] if value[1][attr] else value[0][attr]
                result.append(value[1])
    return result


def config_ip_prefix_list(dut, prefix_list, ip_addr, family="ipv4", action="permit", skip_error_check=True, **kwargs):
    """
    API to cpnfigure IP Prefix list
    :param dut:
    :param prefix_list:
    :param family:
    :param action:
    :param ip_addr:
    :param cli_type:
    :return:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    config = kwargs.get('config','')
    seq_num = kwargs.get('seq_num', '')
    cli_type = 'vtysh' if cli_type in ['vtysh', 'click'] else 'klish'
    command = ''
    if config == 'yes' or config == '':
        config = ''
    if family == "ipv4":
        ip_address = "0.0.0.0/0" if ip_addr == "any" else ip_addr
    else:
        ip_address = "0::/64" if ip_addr == "any" else ip_addr
    ip_cmd = "ipv6" if family == "ipv6" else "ip"
    if cli_type == 'vtysh' or cli_type == 'click':
        if config == '':
            command += "{} prefix-list {} {} {}".format(ip_cmd, prefix_list, action, ip_address)
        else:
            command += "{} {} prefix-list {} ".format(config, ip_cmd, prefix_list)
        st.config(dut, command, type=cli_type,skip_error_check=skip_error_check)
    elif cli_type == 'klish':
        if seq_num != '':
            command+= "{} {} prefix-list {} seq {} {} {}".format(config, ip_cmd, prefix_list, seq_num, action, ip_address)
        else:
            command+= "{} {} prefix-list {} {} {}".format(config, ip_cmd, prefix_list, action, ip_address)
        st.config(dut, command, type=cli_type,skip_error_check=skip_error_check)
    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        if config == '':
            url = rest_urls['routing_policy_defined_sets']
            prefix_data = {"openconfig-routing-policy:defined-sets": {"prefix-sets": {"prefix-set": [{"name": "prefix_list", "config": {"name": "prefix_list", "mode": ip_cmd.upper()}, "prefixes": {"prefix": [{"ip-prefix": ip_address, "masklength-range": "exact", "config": {"ip-prefix": ip_address, "masklength-range": "exact", "openconfig-routing-policy-ext:action": action.upper()}}]}}]}}}
            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=prefix_data):
                return False
        else:
            url = rest_urls['routing_policy_prefix_set'].format(prefix_list, ip_address)
            if not delete_rest(dut, rest_url=url):
                return False
    else:
        st.log("Unsupported CLI TYPE {}".format(cli_type))
        return False
    return True


def ping_poll(dut, addresses, family='ipv4', iter=1, delay=1, **kwargs):
    """
    To Perform ping to ipv4 or ipv6 address using poll.
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param addresses:
    :param family:
    :param iter:
    :param delay:
    :param kwargs:
    :return:
    """
    i = 1
    while True:
        if not ping(dut, addresses, family=family, **kwargs):
            if i == iter:
                return False
            i += 1
            st.wait(delay, 'for next try...')
        else:
            return True


def dump_mgmt_connectivity_info(dut):
    """
    To dump MGMT route info
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :return:
    """
    utils.exec_foreach(True, utils.make_list(dut), st.config, "sudo route -n")


def kill_dhclient_on_interface(dut, interface):
    """
    API to kill the dhclient on an interface using the process ID
    :param dut:
    :param interface:
    :return:
    """
    command = "cat /var/run/dhclient.{}.pid".format(interface)
    pid = utils.remove_last_line_from_string(st.config(dut, command))
    if pid:
        cmd = "kill -9 {}".format(pid)
        st.config(dut, cmd)
        return True
    else:
        st.error("PID not found")
        return False

def config_loopback_interfaces(dut, **kwargs):
    """
    :param :loopback_name:
    :type :loopback_name:
    :param :config:
    :type :config:
    :param :dut:
    :type :dut:
    :return:
    :rtype:

    usage:
    config_loopback_interfaces(dut1,loopback_name="Loopback1,Loopback2",config="yes")
    config_loopback_interfaces(dut1,loopback_name="Loopback1",config="no")
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    loopback_name = kwargs.get('loopback_name')
    if not loopback_name:
        st.error("Mandatory parameter - loopback_name not found")
        return False
    loopback_interface = utils.make_list(loopback_name)
    config = kwargs.get("config", "yes")
    if config == 'yes': msg = "Config"
    elif config == 'no': msg = "Unconfig"
    else :
        st.error("Invalid config type {}".format(config))
        return False
    if not st.is_feature_supported("config-loopback-add-command", dut):
        st.log("Community build doesn't need Loopback interface {}uration".format(msg))
        return True
    if cli_type == 'click':
        cmds = []
        for intf in loopback_interface:
            if config == 'yes':
                cmds.append('config loopback add {}'.format(intf))
            elif config == 'no':
                cmds.append('config loopback del {}'.format(intf))
        st.config(dut, cmds)
    elif cli_type == 'klish':
        cmds = []
        for intf in loopback_interface:
            intf_s = get_interface_number_from_name(intf)
            if config == 'yes':
                cmds.append("interface {} {}".format(intf_s['type'], intf_s['number']))
                cmds.append("exit")
            elif config == 'no':
                cmds.append("no interface {} {}".format(intf_s['type'], intf_s['number']))
        output = st.config(dut, cmds, type="klish", conf=True)
        if "Could not connect to Management REST Server" in output:
            st.error("klish mode not working.")
            return False
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        for interface in loopback_interface:
            if config == 'yes':
                url = rest_urls['per_interface_config'].format(interface)
                loopback_data = {"openconfig-interfaces:config": {"name": interface}}
                if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=loopback_data):
                    st.error("Failed to configure Loopback interface: {}".format(interface))
                    return False
            else:
                url = rest_urls['per_interface_details'].format(interface)
                if not delete_rest(dut, rest_url=url):
                    st.error("Failed to delete Loopback interface: {}".format(interface))
                    return False
    else:
        st.log("Unsupported CLI TYPE {}".format(cli_type))
        return False
    return True


def config_ip_sla(dut, sla_num, sla_type='', dst_ip='', config='yes', **kwargs):
    """
    :param dut: DUT name where the CLI needs to be executed
    :type dut: string
    :param sla_num: IP sla instance number
    :type sla_num: string
    :param sla_type: either ICMP or TCP
    :type sla_type: string
    :param dst_ip: destination IP address to be tracked
    :type dst_ip: string
    :param vrf_name: user vrf name
    :type vrf_name: string
    :param src_addr: source address IPV4/IPv6 to be used while sending ICMP/TCP
    :type src_addr: string
    :param src_intf: source interface to be used while sending ICMP
    :type src_intf: string
    :param data_size: requested data size
    :type data_size: string
    :param src_port: source port to be used while sending TCP
    :type src_port: string
    :param frequency: frequency to send ICMP/TCP
    :type frequency: string
    :param threshold: max number of ICMP/TCP unsuccessful attempt
    :type threshold: string
    :param timeout: max time to be waited for ICMP/TCP response
    :type timeout: string
    :return: None
    usage:
        configuration:
        config_ip_sla(dut1, "10", sla_type="icmp-echo", dst_ip="2.2.2.2", src_addr="1.1.1.1")
        config_ip_sla(dut1, "10", sla_type="icmp-echo", dst_ip="2.2.2.2", vrf_name="vrf1", src_intf="Ethernet1")
        config_ip_sla(dut1, "10", sla_type="icmp-echo", dst_ip="2002::2", vrf_name="vrf1", src_intf="Ethernet1",
                      frequency="4",threshold="6",timeout="2",data_size="128")
        config_ip_sla(dut1, "10", sla_type="tcp-connect", dst_ip="2.2.2.2", src_addr="1.1.1.1",
                      vrf_name="vrf1", src_port="200")
        config_ip_sla(dut1, "10", sla_type="tcp-connect", dst_ip="2002::2", src_addr="1001::1",
                      src_intf="Ethernet1", src_port="200")

        deletion:
        config_ip_sla(dut1, sla_num="10", config="no, del_cmd_list=["sla_num"])
        config_ip_sla(dut1, sla_num="10", sla_type="icmp-echo", config="no, del_cmd_list=["sla_type"])
        config_ip_sla(dut1, sla_num="10", sla_type="icmp-echo", src_addr="1.1.1.1", data_size="128", config="no,
                      del_cmd_list=["src_addr","data_size"])
        config_ip_sla(dut1, sla_num="10", sla_type="tcp-connect", src_addr="1.1.1.1", src_intf="Ethernet1", config="no,
                      del_cmd_list=["src_addr","src_intf"])

    Created by: Julius <julius.mariyan@broadcom.com
    """
    cli_type = kwargs.pop('cli_type',st.get_ui_type(dut, **kwargs))
    skip_error = kwargs.pop('skip_error',False)
    if cli_type == "click" or cli_type == 'klish':
        if config == 'yes':
            cmd = "ip sla {} \n {} {}".format(sla_num,sla_type,dst_ip)
            if "tcp_port" in kwargs:
                cmd += " port {}".format(kwargs["tcp_port"])
            if "vrf_name" in kwargs:
                if kwargs["vrf_name"] != 'default':
                    cmd += "\n source-vrf {}".format(kwargs["vrf_name"])
            if "src_addr" in kwargs:
                cmd += "\n source-address {}".format(kwargs["src_addr"])
            if "src_intf" in kwargs:
                if cli_type == 'klish':
                    #src_intf = get_interface_number_from_name(kwargs["src_intf"])
                    #cmd += "\n source-interface {} {}".format(src_intf['type'],src_intf['number'])
                    cmd += "\n source-interface {}".format(kwargs['src_intf'])
                else:
                    cmd += "\n source-interface {}".format(kwargs['src_intf'])
            if "src_port" in kwargs:
                cmd += "\n source-port {}".format(kwargs["src_port"])
            if "tos" in kwargs:
                cmd += "\n tos {}".format(kwargs["tos"])
            if "ttl" in kwargs:
                cmd += "\n ttl {}".format(kwargs["ttl"])
            if "data_size" in kwargs:
                cmd += "\n request-data-size {}".format(kwargs["data_size"])
            cmd += "\nexit\n"
            if "frequency" in kwargs:
                cmd += "\n frequency {}".format(kwargs["frequency"])
            if "threshold" in kwargs:
                cmd += "\n threshold {}".format(kwargs["threshold"])
            if "timeout" in kwargs:
                cmd += "\n timeout {}".format(kwargs["timeout"])
            cmd += "\nexit\n"
        else:
            if "sla_num" in kwargs["del_cmd_list"]:
                cmd = "no ip sla {}".format(sla_num)
            else:
                cmd = "ip sla {}".format(sla_num)
                if "sla_type" in kwargs["del_cmd_list"]:
                    cmd += "\n no {}".format(sla_type)
                    cmd += "\n exit"
                else:
                    cmd += "\n {} {}".format(sla_type,dst_ip)
                    if "tcp_port" in kwargs:
                        cmd += " port {}".format(kwargs["tcp_port"])
                    sla_type_level = True
                    del_cmd_list = kwargs["del_cmd_list"]
                    if len(del_cmd_list) > 0:
                        if "vrf_name" in del_cmd_list:
                            cmd += "\n no source-vrf"
                            sla_type_level =True
                        if "src_addr" in del_cmd_list:
                            cmd += "\n no source-address"
                            sla_type_level =True
                        if "src_intf" in del_cmd_list:
                            cmd += "\n no source-interface"
                            sla_type_level =True
                        if "data_size" in del_cmd_list:
                            cmd += "\n no request-data-size"
                            sla_type_level = True
                        if  "src_port" in del_cmd_list:
                            cmd += "\n no source-port"
                            sla_type_level =True
                        if "tos" in del_cmd_list:
                            cmd += "\n no tos"
                            sla_type_level = True
                        if 'ttl' in del_cmd_list:
                            cmd += "\n no ttl"
                            sla_type_level = True
                        if 'frequency' in del_cmd_list:
                            if sla_type_level: cmd += '\n exit'
                            cmd += '\n no frequency'
                            sla_type_level = False
                        if 'threshold' in del_cmd_list:
                            if sla_type_level: cmd += '\n exit'
                            cmd += '\n no threshold'
                            sla_type_level = False
                        if 'timeout' in del_cmd_list:
                            if sla_type_level: cmd += '\n exit'
                            cmd += '\n no timeout'
                            sla_type_level = False
                    cmd += "\n exit\n exit" if sla_type_level else '\n exit'

        if cli_type == 'click':
            st.config(dut, cmd, type="vtysh",skip_error_check=skip_error)
        else:
            st.config(dut, cmd, type="klish",skip_error_check=skip_error)
        return
    elif cli_type in ['rest-put','rest-patch']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        base_url = rest_urls['config_sla'].format(sla_num)
        ocdata = {}
        key = "openconfig-ip-sla:config"
        sla_type = 'icmp' if 'icmp' in sla_type.lower() else 'tcp'
        ocdata[key] = {}
        if config == 'yes':
            ocdata[key]['enabled'] = True
            ocdata[key]['ip-sla-id'] = int(sla_num)
            ocdata[key]['{}-dst-ip'.format(sla_type)] = dst_ip
            if "tcp_port" in kwargs:
                ocdata[key]['tcp-dst-port'] = int(kwargs['tcp_port'])
            if "vrf_name" in kwargs:
                if kwargs["vrf_name"] != 'default':
                    ocdata[key]['{}-vrf'.format(sla_type)] = kwargs['vrf_name']
            if "src_addr" in kwargs:
                ocdata[key]['{}-source-ip'.format(sla_type)] = kwargs['src_addr']
            if "src_intf" in kwargs:
                ocdata[key]['{}-source-interface'.format(sla_type)] = kwargs['src_intf']
            if "src_port" in kwargs:
                ocdata[key]['tcp-source-port'] = int(kwargs['src_port'])
            if "tos" in kwargs:
                ocdata[key]['{}-tos'.format(sla_type)] = int(kwargs['tos'])
            if "ttl" in kwargs:
                ocdata[key]['{}-ttl'.format(sla_type)] = int(kwargs['ttl'])
            if "data_size" in kwargs:
                ocdata[key]['icmp-size'] = int(kwargs['data_size'])
            if "frequency" in kwargs:
                ocdata[key]['frequency'] = int(kwargs['frequency'])
            if "threshold" in kwargs:
                ocdata[key]['threshold'] = int(kwargs['threshold'])
            if "timeout" in kwargs:
                ocdata[key]['timeout'] = int(kwargs['timeout'])
            response = config_rest(dut,http_method=cli_type, rest_url=base_url, json_data=ocdata)
            if not response:
                return False
        else:
            if "sla_num" in kwargs["del_cmd_list"]:
                rest_urls = st.get_datastore(dut, 'rest_urls')
                delete_url = rest_urls['delete_sla'].format(sla_num)
                response = delete_rest(dut, rest_url=delete_url)
                if not response:
                    return False
            else:
                if "sla_type" in kwargs["del_cmd_list"]:
                    delete_url = base_url + '/{}-dst-ip'.format(sla_type)
                    response = delete_rest(dut, rest_url=delete_url)
                    if not response:
                        return False
                    if 'dst_port' in kwargs['del_cmd_list']:
                        delete_url = base_url + '/tcp-dst-port'
                        response = delete_rest(dut, rest_url=delete_url)
                        if not response:
                            return False
                else:
                    del_cmd_list = kwargs["del_cmd_list"]
                    if len(del_cmd_list) > 0:
                        if "vrf_name" in del_cmd_list:
                            delete_url = base_url + '/{}-vrf'.format(sla_type)
                            response = delete_rest(dut, rest_url=delete_url)
                            if not response:
                                return False
                        if "src_addr" in del_cmd_list:
                            delete_url = base_url + '/{}-source-ip'.format(sla_type)
                            response = delete_rest(dut, rest_url=delete_url)
                            if not response:
                                return False
                        if "src_intf" in del_cmd_list:
                            delete_url = base_url + '/{}-source-interface'.format(sla_type)
                            response = delete_rest(dut, rest_url=delete_url)
                            if not response:
                                return False
                        if "data_size" in del_cmd_list:
                            delete_url = base_url + '/icmp-size'
                            response = delete_rest(dut, rest_url=delete_url)
                            if not response:
                                return False
                        if "src_port" in del_cmd_list:
                            delete_url = base_url + '/tcp-source-port'
                            response = delete_rest(dut, rest_url=delete_url)
                            if not response:
                                return False
                        if "tos" in del_cmd_list:
                            delete_url = base_url + '/{}-tos'.format(sla_type)
                            response = delete_rest(dut, rest_url=delete_url)
                            if not response:
                                return False
                        if 'ttl' in del_cmd_list:
                            delete_url = base_url + '/{}-ttl'.format(sla_type)
                            response = delete_rest(dut, rest_url=delete_url)
                            if not response:
                                return False
                        if 'frequency' in del_cmd_list:
                            delete_url = base_url + '/frequency'
                            response = delete_rest(dut, rest_url=delete_url)
                            if not response:
                                return False
                        if 'threshold' in del_cmd_list:
                            delete_url = base_url + '/threshold'
                            response = delete_rest(dut, rest_url=delete_url)
                            if not response:
                                return False
                        if 'timeout' in del_cmd_list:
                            delete_url = base_url + '/timeout'
                            response = delete_rest(dut, rest_url=delete_url)
                            if not response:
                                return False

        return

def verify_ip_sla(dut,inst,**kwargs):
    '''
    purpose:
            This definition is used to verify the o/p of "show ip sla"

    Arguments:
    :param dut: Device name where the command to be executed
    :type dut: string
    :param inst: ip sla instance number
    :type inst: string
    :param type: ip sla type ICMP-echo/TCP-connect
    :type type: string
    :param dst_addr: target IP/IPv6 address
    :type dst_addr: string
    :param vrf_name: name of the VRF
    :type vrf_name: string
    :param state: status of the SLA
    :type state: string
    :param tx_cnt: number of ICMP/TCP messages generated
    :type tx_cnt: string
    :param return_output: return the show output and no verification required
    :type return_output: string
    :return: returns show o/p
             for the verification returns True/False ; True - success case; False - Failure case

    usage:  verify_ip_sla(dut1,'10',type="ICMP-echo",dst_addr="2.2.2.2",vrf_name="vrf1",state="up",tx_cnt="2")
            verify_ip_sla(dut1,'10',type="TCP-connect",dst_addr="2002::2",vrf_name="vrf1",state="up",tx_cnt="2")
            verify_ip_sla(dut1,'10',return_output="y")
    Created by: Julius <julius.mariyan@broadcom.com
    '''
    success = True

    cli_type = kwargs.pop('cli_type',st.get_ui_type(dut, **kwargs))
    if cli_type == "click":
        cli_type="vtysh"
    if cli_type in ['rest-put','rest-patch']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        rest_url = rest_urls['show_ip_sla']
        output = get_rest(dut,rest_url=rest_url)['output']['openconfig-ip-sla:ip-slas']
        cli_out = convert_sla_rest_output(output,parse_type='summary')
    else:
        cli_out=st.show(dut,"show ip sla",type=cli_type)
    if "return_output" in kwargs:
        return cli_out
    id_list = map(str, inst) if isinstance(inst, list) else [inst]
    id_len = len(id_list)
    for key,value in kwargs.items():
        if len(value) != id_len:
            st.error("Number of elements in each parameter list need to match.")
            return False
    for i in range(len(id_list)):
        fil_out = filter_and_select(cli_out, kwargs.keys(), {"inst": id_list[i]})
        if not fil_out:
            st.error("No entry found for SLA instance: {} in output: {}".format(id_list[i], cli_out))
            return False
        else:
            fil_out = fil_out[0]

            for key,val in kwargs.items():
                if str(fil_out[key]) != str(val[i]):
                    success=False
                    st.error("MATCH NOT found for key \"{}\"; expected: {} but found {}".format(key,val[i],fil_out[key]))
    return True if success else False


def verify_ip_sla_inst(dut,inst,**kwargs):
    '''
    purpose:
            This definition is used to verify the o/p of "show ip sla <instance_num>"

    Arguments:
    :param dut: Device name where the command to be executed
    :type dut: string
    :param inst: ip sla instance number
    :type inst: string
    :param type: ip sla type icmp-echo/tcp-connect
    :type type: string
    :param dst_addr: target IP/IPv6 address
    :type dst_addr: string
    :param dst_port: target TCP port
    :type dst_port: string
    :param src_addr: source IP/IPv6 address
    :type src_addr: string
    :param src_port: source TCP port
    :type src_port: string
    :param vrf_name: name of the VRF
    :type vrf_name: string
    :param icmp_size: icmp data size
    :type icmp_size: string
    :param freq: frequency value
    :type freq: string
    :param time_out: timeout value
    :type time_out: string
    :param oper_state: operation status of SLA
    :type oper_state: string
    :param oper_succ_cnt: operation success counter
    :type oper_succ_cnt: string
    :param oper_fail_cnt: operation failure counter
    :type oper_fail_cnt: string
    :param icmp_req_cnt: ICMP echo request counter
    :type icmp_req_cnt: string
    :param icmp_rep_cnt: ICMP echo reply counter
    :type icmp_rep_cnt: string
    :param icmp_err_cnt: ICMP error counter
    :type icmp_err_cnt: string
    :param tcp_req_cnt: TCP connect request counter
    :type tcp_req_cnt: string
    :param tcp_succ_cnt: TCP connect success counter
    :type tcp_succ_cnt: string
    :param tcp_err_cnt: TCP connect error counter
    :type tcp_err_cnt: string
    :param return_output: return the show output and no verification required
    :type return_output: string
    :return: returns show o/p
             for the verification returns True/False ; True - success case; False - Failure case

    usage:  verify_ip_sla_inst(dut1,'10',type="icmp-echo",dst_addr="2.2.2.2",vrf_name="vrf1",
                               state="scheduled",icmp_req_cnt="2")
            verify_ip_sla_inst(dut1,'10',type="tcp-connect",dst_addr="2002::2",vrf_name="vrf1",
                               state="scheduled",tcp_req_cnt="2")
            verify_ip_sla_inst(dut1,'10',return_output="y")
    Created by: Julius <julius.mariyan@broadcom.com
    '''
    success = True

    cli_type = kwargs.pop('cli_type',st.get_ui_type(dut, **kwargs))
    if cli_type == "click":
        cli_type="vtysh"
    if cli_type in ['rest-patch','rest-put']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        rest_url = rest_urls['show_ip_sla_inst'].format(inst)
        output = get_rest(dut,rest_url=rest_url)['output']['openconfig-ip-sla:ip-sla']
        cli_out = convert_sla_rest_output(output,parse_type='inst')
    else:
        cmd = "show ip sla {}".format(inst)
        cli_out=st.show(dut,cmd,type=cli_type)
    st.log(cli_out)
    if "return_output" in kwargs:
        return cli_out
    fil_out = filter_and_select(cli_out, kwargs.keys(), {"inst": inst})
    if not fil_out:
        st.error("No entry found for SLA instance: {} in output: {}".format(inst, cli_out))
        return False
    else:
        fil_out = fil_out[0]
        for key,val in kwargs.items():
            if str(fil_out[key]) == str(val):
                st.log("MATCH found for key \"{}\"; expected: {}; found {}".format(key,val,fil_out[key]))
            else:
                success=False
                st.error("MATCH NOT found for key \"{}\"; expected: {} but found {}".format(key,val,fil_out[key]))
    return True if success else False


def verify_ip_sla_history(dut,inst,**kwargs):
    '''
    purpose:
            This definition is used to verify the o/p of "show ip sla"

    Arguments:
    :param dut: Device name where the command to be executed
    :type dut: string
    :param inst: ip sla instance number
    :type inst: string
    :param event_time: event_time of SLA events
    :type event_time: string
    :param event: SLA events
    :type event: string or list
    :param verify_sequence: Flag to verify event history sequence
    :type verify_sequence: Boolean
    :param return_output: return the show output and no verification required
    :type return_output: string
    :return: returns show o/p
             for the verification returns True/False ; True - success case; False - Failure case

    usage:  ip_api.verify_ip_sla_history(data.dut3,inst=5,verify_sequence=True,
                           event=['Stopped','Started','State changed to: Up','State changed to: Down','Nexthop/VRF not present'])

    Created by: Sooriya G (Sooriya.Gajendrababu@broadcom.com)
    '''
    success = True

    cli_type = kwargs.pop('cli_type',st.get_ui_type(dut, **kwargs))

    if cli_type == "click":
        cli_type="vtysh"

    if cli_type not in ['rest-patch', 'rest-put']:
        cli_out=st.show(dut,"show ip sla {} history".format(inst),type=cli_type)
    else:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        rest_url = rest_urls['show_ip_sla_history']
        ocdata = {"openconfig-ip-sla:input":{"ip-sla-id":inst}}
        output = config_rest(dut,rest_url=rest_url,http_method='post',json_data=ocdata,get_response=True)['output']
        cli_out = convert_sla_rest_output(output,parse_type='history')

    if "return_output" in kwargs:
        return cli_out
    if len(cli_out) == 0:
        st.error("Output is Empty")
        return False
    verify_sequence = kwargs.pop('verify_sequence',False)
    if verify_sequence:
        event = kwargs.pop('event',None)
        expected_sequence = [event] if type(event) is str else list(event)
        #Sort output based on timestamp
        #Fri Jul 10 11:35:21 2020
        import time
        sorted_output = sorted(cli_out, key=lambda x: time.strptime(x['event_time'],'%a %b %d %H:%M:%S %Y'))
        actual_sequence = [out['event'].rstrip() for out in sorted_output]
        if set(actual_sequence) != set(expected_sequence):
            st.error("FAIL: SLA history Mismatch: Expected-{} Actual- {}".format(expected_sequence,actual_sequence))
            return False
    else:
        for item in cli_out: item['event'] = str(item['event']).rstrip()
        entries = filter_and_select(cli_out,kwargs.keys(),match={'event':kwargs['event']})
        if entries:
            for key in kwargs.keys():
                if str(kwargs[key]) != str(entries[0][key]).rstrip():
                    success=False
                    st.error("MATCH NOT found for key \"{}\"; expected: {} but found {}".format(key,kwargs[key],cli_out[0][key]))
        else:
            st.error("Event {} not found in SLA history".format(kwargs['event']))
            success = False
    return True if success else False



def clear_ip_sla(dut,**kwargs):
    """
    :param dut:
    :param inst:
    :return:
    """
    cli_type = kwargs.pop('cli_type',st.get_ui_type(dut,**kwargs))
    inst = kwargs.pop('inst','all')
    cmd = 'clear ip sla {}'.format(inst)
    if cli_type == 'click':
        st.config(dut,cmd,type='vtysh',conf=False)
    elif cli_type == 'klish':
        st.config(dut, cmd, type='klish', conf=False)
    elif cli_type in ['rest-put','rest-patch']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        rest_url = rest_urls['clear_ip_sla']
        ocdata = {"sonic-ip-sla:input": {"ip_sla_id": inst}}
        response = config_rest(dut,http_method='post',rest_url=rest_url,json_data=ocdata)
        if not response:
            return False



def convert_sla_rest_output(output,parse_type='sla_summary'):
    transformed_output_list =[]
    if 'summary' in parse_type:
        for item in output['ip-sla']:
            transformed_output = {}
            transformed_output['inst'] = item.pop('ip-sla-id', '')
            if 'icmp-dst-ip' in item['config'].keys():
                transformed_output['type'] = 'ICMP-echo';type_str='icmp'
                add_port_str =''
            else:
                transformed_output['type']='TCP-connect';type_str='tcp'
                tcp_dst_port= item.get('state',{}).get('tcp-dst-port','')
                add_port_str = '({})'.format(tcp_dst_port)
            transformed_output['target'] = item.get('state',{}).get('{}-dst-ip'.format(type_str))+add_port_str
            transformed_output['vrf_name'] = item.get('state',{}).get('{}-vrf'.format(type_str),'default')
            state = item.get('state',{}).get('{}-operation-state'.format(type_str),'OPER_UP')
            transformed_output['state'] = 'Up' if 'OPER_UP' in state else 'Down'
            transformed_output['transitions'] = item.get('state',{}).get('transition-count','')
            transformed_output['last_chg'] = (item.get('state',{}).get('timestamp','').strip(r'\s*ago')).rstrip()
            transformed_output_list.append(transformed_output)
    elif 'inst' in parse_type:
        for item in output:
            transformed_output = {}
            transformed_output['inst'] = item.get('ip-sla-id', '')
            if transformed_output['inst'] == '':
                return transformed_output_list
            if 'icmp-dst-ip' in item['config'].keys():
                transformed_output['type'] = 'ICMP-echo'
                transformed_output['icmp_req_cnt'] = item.get('state',{}).get('icmp-echo-req-counter','')
                transformed_output['icmp_succ_cnt'] = item.get('state', {}).get('icmp-echo-reply-counter', '')
                transformed_output['icmp_err_cnt'] = item.get('state', {}).get('icmp-fail-counter', '')
                transformed_output['icmp_size'] = item.get('state', {}).get('icmp-size', '')
                state = item.get('state', {}).get('icmp-operation-state', '')
                transformed_output['dst_addr'] = item.get('state', {}).get('icmp-dst-ip', '')
                transformed_output['vrf_name'] = item.get('state', {}).get('icmp-vrf', 'default')
                transformed_output['src_addr'] = item.get('state', {}).get('icmp-source-ip', '')
                transformed_output['src_intf'] = item.get('state', {}).get('icmp-source-interface', '')
                transformed_output['ttl'] = item.get('state', {}).get('icmp-ttl', '')
                transformed_output['tos'] = item.get('state', {}).get('icmp-tos', '')
            elif 'tcp-dst-ip' in item['config'].keys():
                transformed_output['type']='TCP-connect'
                transformed_output['dst_port'] = item.get('state',{}).get('tcp-dst-port','')
                transformed_output['tcp_req_cnt'] = item.get('state', {}).get('tcp-connect-req-counter', '')
                transformed_output['tcp_succ_cnt'] = item.get('state', {}).get('tcp-connect-success-counter', '')
                transformed_output['tcp_err_cnt'] = item.get('state', {}).get('tcp-connect-fail-counter', '')
                transformed_output['src_port'] = item.get('state', {}).get('tcp-source-port', '')
                state = item.get('state', {}).get('tcp-operation-state', '')
                transformed_output['dst_addr'] = item.get('state', {}).get('tcp-dst-ip', '')
                transformed_output['vrf_name'] = item.get('state', {}).get('tcp-vrf', 'default')
                transformed_output['src_addr'] = item.get('state', {}).get('tcp-source-ip', '')
                transformed_output['src_intf'] = item.get('state', {}).get('tcp-source-interface', '')
                transformed_output['ttl'] = item.get('state', {}).get('tcp-ttl', '')
                transformed_output['tos'] = item.get('state', {}).get('tcp-tos', '')
            else:
                transformed_output['type'] = 'None'
                state='Down'
                key_list=['icmp_req_cnt','icmp_succ_cnt','icmp_err_cnt','icmp_size','dst_addr','vrf_name','src_addr','src_intf',
                          'src_port','dst_port','tcp_req_cnt','tcp_succ_cnt','tcp_err_cnt','ttl','tos']
                for key in key_list: transformed_output[key] = ''

            transformed_output['freq'] = item.get('state', {}).get('frequency', '')
            transformed_output['threshold'] = item.get('state', {}).get('threshold', '')
            transformed_output['timeout'] = item.get('state', {}).get('timeout', '')
            transformed_output['oper_state'] = 'Up' if 'OPER_UP' in state else 'Down'
            transformed_output['tx_cnt'] = item.get('state',{}).get('transition-count','')
            transformed_output['last_chg'] = (item.get('state',{}).get('timestamp','').strip(r'\s*ago')).rstrip()
            transformed_output_list.append(transformed_output)
    else:
        new_output = output.get('sonic-ip-sla:output',{}).get('IPSLA_HISTORY',[])
        for item in new_output:
            transformed_output={}
            transformed_output['event'] = item.get('event','')
            transformed_output['event_time']= item.get('timestamp','')
            transformed_output_list.append(transformed_output)
    return transformed_output_list


def _clear_ipsla_configuration_helper(dut_list, cli_type=''):
    """
    Fidn and clear IP SLA configuration in DUT
    """
    dut_li = list(dut_list) if isinstance(dut_list, list) else [dut_list]
    cli_type = st.get_ui_type(dut_li[0], cli_type=cli_type)

    if cli_type == 'click':
        cli_type = 'vtysh'

    for dut in dut_li:
        st.log("############## {} : IPSLA Cleanup ################".format(dut))

        command = "show ip sla"
        output = st.show(dut, command, type=cli_type, skip_error_check=True)
        if len(output) == 0:
            continue

        for entry in output:
            if 'inst' not in entry or not entry['inst']:
                continue
            config_ip_sla(dut, sla_num=entry['inst'], config="no", del_cmd_list=["sla_num"])

    return True

def clear_ipsla_configuration(dut_list, thread=True, cli_type=''):
    """
    Find and clear IP SLA configuration in the lsit of DUTs
    """
    dut_li = list(dut_list) if isinstance(dut_list, list) else [dut_list]
    cli_type = st.get_ui_type(dut_li[0], cli_type=cli_type)
    [out, _] = utils.exec_foreach(thread, dut_li, _clear_ipsla_configuration_helper, cli_type=cli_type)
    return False if False in out else True



def verify_multiple_routes(dut, family="ipv4", shell="sonic", vrf_name=None, **kwargs):
    """
    Author: Nagappa Chincholi (nagappa.chincholi@broadcom.com)
    verify_multiple_routes(dut1,family='ipv6',vrf_name='Vrf-101')
    verify_ip_route(dut1,family='ipv6',shell='vtysh',vrf_name='Vrf-101')
    verify_ip_route(dut1,family='ipv6')
    verify_ip_route(dut1,vrf_name='Vrf-101',type='B',nexthop='1.0.1.2',interface='Vlan1')
    verify_ip_route(dut1,vrf_name='Vrf-101')
    To verify static route
    :param :dut:
    :param :family: ipv4|ipv6
    :param :shell: sonic|vtysh
    :param :type:
    :param :selected:
    :param :fib:
    :param :ip_address:
    :param :interface:
    :param :duration:
    :param :nexthop:
    :param :distance:
    :param :cost:
    :param :vrf_name
    :type :vrf_name
    :return:
    """

    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut,**kwargs))
    cli_type = "vtysh" if cli_type == 'click' else "klish"

    output = show_ip_route(dut,family=family,vrf_name=vrf_name,cli_type=cli_type)
    ret_val = False
    if 'ip_address' in kwargs:
        st.log("Verify Routes:{}".format(kwargs['ip_address']))
    missing_routes = list(kwargs['ip_address'])
    route_count = len(kwargs['ip_address'])
    match_count = 0

    for i in range(route_count):
        result = utils.filter_and_select(output, None, match={'ip_address': kwargs['ip_address'][i]})
        for rlist in result:
            count = 0
            for key in kwargs:
                if rlist[key] == kwargs[key][i]:
                    count = count + 1
                else:
                    break
            if len(kwargs) == count:
                match_count += 1
                missing_routes.remove(kwargs['ip_address'][i])
                break
    if match_count == route_count:
        ret_val = True

    if not ret_val:
        st.log("Fail: Not all routes Matched with passed parameters list")
    return ret_val



def config_system_max_routes(dut,**kwargs):
    """
    Author: Sooriya.Gajendrababu@broadcom.com
    :param dut:
    :param kwargs:
    :return:
    """
    #This cli is yet to be supported in klish
    cli_type = kwargs.pop('cli_type', 'click')
    route_cnt = kwargs.get('route_count','max')
    cmd =''
    if cli_type == 'click':
        cmd = 'sudo config switch-resource route-scale routes {} -y'.format(route_cnt)
        if not st.is_feature_supported("config_max_route_scale", dut):
            st.community_unsupported(cmd, dut)
            return False
    st.config(dut,cmd,type=cli_type)

def config_ip_loadshare_hash(dut, **kwargs):
    """
    To configure IP load-share hash.
    Author: Sunil Rajendra (sunil.rajendra@broadcom.com)
    :param dut:
    :param kwargs: key (ip|ipv6|seed), val (single or list), config
    :return:
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut,**kwargs))
    # For now this is supported only in klish.
    cli_type = 'klish' if cli_type == 'click' else cli_type

    if "val" not in kwargs:
        st.error("Please provide the value for the key.")
        return False

    config = kwargs.pop('config', 'yes')
    key = kwargs.pop('key', 'ipv4')
    key = 'ipv4' if key=='ip' else key
    val = kwargs.pop('val', '')
    val = [val] if type(val) is str else val
    skiperr = True if kwargs.get('skip_error') else False

    config_type = ''
    if config.lower() != 'yes':
        config_type = 'no '
        if key == 'seed':
            val = ['']
    command = []
    if cli_type == 'klish':
        for v in val:
            command = command + [config_type+'ip load-share hash {} {}'.format(key,v)]
        st.config(dut, command, type=cli_type, skip_error_check=skiperr)
    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        for v in val:
            if key == 'seed':
                v_seed = v
                v = 'ecmp-hash-seed'
            url = rest_urls['ecmp_config_loadshare_'+key].format(v)
            if config_type == 'no ':
                if not delete_rest(dut, rest_url=url):
                    st.error("Failed to delete key={}, val={}.".format(key,v))
                    return False
            else:
                config_data = {"openconfig-loadshare-mode-ext:"+v:True}
                if key == 'seed':
                    config_data = {"openconfig-loadshare-mode-ext:"+v:int(v_seed)}
                if not config_rest(dut, rest_url=url, http_method=cli_type, json_data=config_data):
                    st.error("Failed to configure key={}, val={}".format(key,v))
                    return False
    else:
        st.error("Supported mode is only KLISH")
        return False
    return True

def show_ip_loadshare(dut, **kwargs):
    """
    Show ip load-share
    Author: Sunil Rajendra (sunil.rajendra@broadcom.com)

    :param :dut:
    :param :cli_type:
    :param :skip_error:
    :return:
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut,**kwargs))
    # This is not supported in click.
    cli_type = 'klish' if cli_type == 'click' else cli_type
    skip_error = kwargs.get('skip_error', False)
    if cli_type == 'klish':
        command = "show ip load-share"
        return st.show(dut, command, type=cli_type, skip_error_check=skip_error)
    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        url = rest_urls['ecmp_show_ip_loadshare_hash']
        out = get_rest(dut, rest_url=url)
        var=out['output']['openconfig-loadshare-mode-ext:state']
        ip_var=''
        ipv6_var=''
        seed_var=str(var['ecmp-hash-seed'])
        var.pop('ecmp-hash-seed')
        for v in var.keys():
            if 'ipv6' in v:
                ipv6_var = ipv6_var + ' '+ v
            else:
                ip_var = ip_var + ' '+ v
        ip_var = str(ip_var.strip())
        ipv6_var = str(ipv6_var.strip())
        output = [{'ip':ip_var, 'ipv6':ipv6_var, 'seed':seed_var}]
        return output
    else:
        st.error("Unsupported CLI_TYPE: {}.".format(cli_type))
    return False

def verify_ip_loadshare(dut, **kwargs):
    """
    Verify ip load-share
    Author: Sunil Rajendra (sunil.rajendra@broadcom.com)

    :param :dut:
    :param :ip: ipv4 values (single or list)
    :param :ipv6: ipv6 values (single or list)
    :param :seed: hash seed value
    :param :cli_type:
    :param :skip_error:
    :return:
    """
    return_key = True
    output = show_ip_loadshare(dut, **kwargs)
    st.log("output={}, kwargs={}".format(output,kwargs))
    for key in ['cli_type', 'skip_error']:
        kwargs.pop(key, None)

    for key in kwargs.keys():
        val_list = [kwargs[key]] if type(kwargs[key]) is str else kwargs[key]
        if key in output[0]:
            out_list = output[0][key].split()
            for v in val_list:
                if v not in out_list:
                    st.error("{} not found in {}.".format(v, out_list))
                    return_key = False
        else:
            st.error("{} not found in the output.".format(key))
            return_key = False
    return return_key


def create_route_leak(dut, vrf, network, **kwargs):
    """
    To configure route leak
    Author: Jagadish Chatrasi (jagadish.chatrasi@broadcom.com)
    """
    #cli_type = st.get_ui_type(dut, **kwargs)
    #cli_type = 'vtysh' if cli_type == 'click' else cli_type
    cli_type = 'vtysh' ##CLI_TYPE hard-coded because the route leak configuration support is not available in other UIs
    family = kwargs.get('family', 'ipv4')
    if not (network and '/' in network):
        st.error("Provide network with proper format")
        return False
    if family.lower() == 'ipv4':
        network = ipaddress.IPv4Network(u'{}'.format(network), strict=False)
        network = network.compressed
    elif family.lower() == 'ipv6':
        network = ipaddress.IPv6Network(u'{}'.format(network), strict=False)
        network = network.compressed
    else:
        st.error("IP family should be ipv4/ipv6, but {} found".format(family))
        return False
    if cli_type == 'vtysh':
        command = list()
        command.append("vrf {}".format(vrf))
        cmd = 'ip route {}'.format(network) if family.lower() == 'ipv4' else 'ipv6 route {}'.format(network)
        if kwargs.get('next_hop'):
            cmd+=' {}'.format(kwargs['next_hop'])
        if kwargs.get('interface'):
            cmd+=' {}'.format(kwargs['interface'])
        if kwargs.get('nexthop_vrf'):
            cmd+=' nexthop-vrf {}'.format(kwargs['nexthop_vrf'])
        if kwargs.get('tag'):
            cmd+=' tag {}'.format(kwargs['tag'])
        if kwargs.get('track'):
            cmd+=' track {}'.format(kwargs['track'])
        if kwargs.get('table'):
            cmd+=' table {}'.format(kwargs['table'])
        if kwargs.get('label'):
            cmd+=' label {}'.format(kwargs['label'])
        if kwargs.get('onlink'):
            cmd+=' onlink'
        if kwargs.get('distance'):
            cmd+=' {}'.format(kwargs['distance'])
        command.append(cmd)
        command.append('exit-vrf')
        st.config(dut, command, type='vtysh')
    else:
        st.error("Unsupported CLI_TYPE: {}".format(cli_type))
        return False
    return True
