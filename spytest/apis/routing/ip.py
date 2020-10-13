# This file contains the list of API's which performs IP,Ping related operations.
# Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)

import re
from spytest import st
import socket
import ipaddress
import subprocess
from utilities.utils import get_interface_number_from_name
import utilities.common as utils

def is_valid_ipv4_address(address):
    """
    Validate ipv4 address.
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)

    :param address:
    :return:
    """
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:  # no inet_pton here, sorry
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
        return address.count('.') == 3
    except socket.error:  # not a valid address
        return False
    return True


def is_valid_ipv6_address(address):
    """
    Validate ipv6 address.
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)

    :param address:
    :return:
    """
    try:
        socket.inet_pton(socket.AF_INET6, address)
    except socket.error:  # not a valid address
        return False
    return True


def is_valid_ip_address(address, family, subnet=None):
    """
    Validate ip address.
    Author: Naveena Suvarna (naveen.suvarna@broadcom.com)

    :param address:
    :param family
    :param subnet
    :return:
    """

    if not address or not family:
        st.error("Parameter Family or address is Null")
        return False

    if family == "ipv4":
        if not is_valid_ipv4_address(address):
            st.error("Invalid IPv4 address {} ".format(address))
            return False
        if subnet:
            subnet = int(subnet)
            if subnet < 1 or subnet > 32:
                st.error("Invalid IPv4 subnet {}".format(subnet))
                return False
    elif family == "ipv6":
        if not is_valid_ipv6_address(address):
            st.error("Invalid IPv6 address {} ".format(address))
            return False
        if subnet:
            subnet = int(subnet)
            if subnet < 1 or subnet > 128:
                st.error("Invalid IPv6 subnet {}".format(subnet))
                return False
    else:
        st.error("Invalid address family {} ".format(family))
        return False

    return True


def config_ipv6(dut, action='disable'):
    """
    To globally disable or enabled Ipv6
    :param dut:
    :param action: Can be 'disable' or 'enable'.
    :return:
    """
    if not st.is_community_build():
        command = "config ipv6 {}".format(action)
        st.config(dut, command)
    else:
        st.config(dut, "sysctl -w net.ipv6.conf.all.disable_ipv6=1")
        st.config(dut, "sudo sysctl -w net.ipv6.conf.default.disable_ipv6=1")
        st.config(dut, "sysctl -w net.ipv6.conf.lo.disable_ipv6=1")

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
    ping_pattern = r'(\d+)\s+packets\s+transmitted,\s+(\d+)\s+received,(.*)\s+(\d+)%\s+packet\s+loss,\s+time\s+(\d+)ms'
    external = kwargs.get("external", False)

    if 'count' not in kwargs:
        kwargs['count'] = 3

    command = "ping -4 {} -c {} ".format(addresses, kwargs['count'])
    if external:
        command = "ping {} -c {} ".format(addresses, kwargs['count'])

    if family.lower() == "ipv6":
        command = "ping -6 {} -c {} ".format(addresses, kwargs['count'])
        if external:
            command = "ping6 {} -c {} ".format(addresses, kwargs['count'])

    if 'timeout' in kwargs:
        timeout = utils.integer_parse(kwargs['timeout'])
    else:
        timeout = None

    if st.is_vsonic(dut):
        if not timeout or timeout < 7:
            timeout = 7

    if timeout:
        command = command + "-W {} ".format(timeout)

    if 'interface' in kwargs:
        command = command + "-I {} ".format(kwargs['interface'])
    if 'packetsize' in kwargs:
        command = command + "-s {} ".format(kwargs['packetsize'])

    if external:
        st.log(command)
        p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True,
                             universal_newlines=True)
        rv, err = p.communicate()
        st.log(rv)
        st.log(err)
    else:
        rv = st.config(dut, command)
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
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut))
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
                st.config(dut, command, skip_error_check=skip_error)
            except Exception as e:
                st.log(e)
                return False
            return True
        elif config == 'remove':
            return delete_ip_interface(dut, interface_name, ip_address, subnet, family, cli_type=cli_type)
        else:
            st.error("Invalid config used - {}.".format(config))
            return False
    elif cli_type == 'klish':
        if config == 'add':
            if interface_name =='eth0':
                command = "interface Management 0"
                command = command + "\n" + "ip address {}/{}".format(ip_address, subnet)
            else:
                regex = re.compile(r'(\d+|\s+)')
                intf = regex.split(interface_name)
                command = "interface {} {}".format(intf[0], intf[1])
                fam = "ip" if family=='ipv4' else 'ipv6'
                command = command + "\n" + "{} address {}/{}".format(fam, ip_address, subnet)
                command = command + "\n" + "exit"
            output = st.config(dut, command, skip_error_check=skip_error, type="klish", conf=True)
            if "Could not connect to Management REST Server" in output:
                st.error("klish mode not working.")
                return False
            return True
        elif config == 'remove':
            return delete_ip_interface(dut, interface_name, ip_address, subnet, family, cli_type=cli_type)
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
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut))
    if cli_type == 'click':
        command = "config interface ip remove {} {}/{}".format(interface_name, ip_address, subnet)
        st.config(dut, command, skip_error_check=skip_error)
        return True
    elif cli_type == 'klish':
        regex = re.compile(r'(\d+|\s+)')
        intf = regex.split(interface_name)
        command = "interface {} {}".format(intf[0], intf[1])
        fam = "ip" if family=='ipv4' else 'ipv6'
        # Subnet not required while removing IP/IPv6 address.
        command = command + "\n" + "no {} address {}".format(fam, ip_address)
        command = command + "\n" + "exit"
        output = st.config(dut, command, skip_error_check=skip_error, type="klish", conf=True)
        if "Could not connect to Management REST Server" in output:
            st.error("klish mode not working.")
            return False
        return True

def get_interface_ip_address(dut, interface_name=None, family="ipv4"):
    """
    To Get  ip address on interface
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)

    :param dut:
    :param interface_name:
    :param family: ipv4 | ipv6
    :return:
    """
    command = "show ip interface"
    if family == "ipv6":
        command = "show ipv6 interface"
    output = st.show(dut, command)
    result = output if family == "ipv4" else prepare_show_ipv6_interface_output(output)
    if interface_name:
        match = {"interface": interface_name}
        output = utils.filter_and_select(result, None, match)
    return output


def verify_interface_ip_address(dut, interface_name, ip_address, family="ipv4", vrfname='', flags = ''):
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
    command = "show ip interface"
    if family == "ipv6":
        command = "show ipv6 interface"
    output = st.show(dut, command)
    result = output if family == "ipv4" else prepare_show_ipv6_interface_output(output)
    match = {"interface": interface_name, "vrf": vrfname, "ipaddr": ip_address, "flags": flags}
    entries = utils.filter_and_select(result, ["interface"], match)
    return True if entries else False


def create_static_route(dut, next_hop=None, static_ip=None, shell="vtysh", family='ipv4', interface = None, vrf = None):
    """
    To create static route
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param dut:
    :param next_hop:
    :param static_ip:
    :param shell: sonic|vtysh
    :param family: ipv4|ipv6
    :return:
    """
    if not static_ip:
        st.log("Provide static_ip")
        return False
    if shell == "vtysh":
        if family.lower() == "ipv4" or family.lower() == "":
            if next_hop:
                command = "ip route {} {}".format(static_ip, next_hop)
            else:
                command = "ip route {}".format(static_ip)
        elif family.lower() == "ipv6":
            command = "ipv6 route {} {}".format(static_ip, next_hop)
        if interface:
            command +=" {}".format(interface)
        if vrf:
            command +=" vrf {}".format(vrf)
        st.config(dut, command, type='vtysh')
    else:
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


def delete_static_route(dut, next_hop, static_ip, family='ipv4', shell="vtysh", interface = None, vrf = None):
    """
    To delete static route
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param dut:
    :param next_hop:
    :param static_ip:
    :param family: ipv4|ipv6
    :param shell: sonic|vtysh
    :return:
    """

    if shell == "vtysh":
        if family.lower() == "ipv4" or family.lower() == "":
            if next_hop == None:
                command = "no ip route {}".format(static_ip)
            else:
                command = "no ip route {} {}".format(static_ip, next_hop)
        elif family.lower() == "ipv6":
            command = "no ipv6 route {} {}".format(static_ip, next_hop)
        if interface:
            command +=" {}".format(interface)
        if vrf:
            command +=" vrf {}".format(vrf)
        st.config(dut, command, type='vtysh')
    else:
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


def show_ip_route(dut, family="ipv4", shell="sonic", vrf_name=None):
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
    if vrf_name:
        cmd = "show ip route vrf " + vrf_name
    else:
        cmd = "show ip route"

    if family == "ipv6":
        if vrf_name:
            cmd = "show ipv6 route vrf " + vrf_name
        else:
            cmd = "show ipv6 route"

    if shell == "vtysh":
        output = st.show(dut, cmd, type='vtysh')
    else:
        output = st.show(dut, cmd)
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
    if cli_type == "klish" and "interface" in kwargs:
        del kwargs['interface']

    ret_val = False
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
                if rlist[key] == kwargs[key]:
                    st.log("Match: Match key {} found => {} : {}".format(key, kwargs[key], rlist[key]))
                else:
                    st.log("No-Match: Match key {} NOT found => {} : {}".format(key, kwargs[key], rlist[key]))
            st.log("\n")

    if not ret_val:
        st.log("Fail: Not Matched all args in passed dict {} from parsed dict".format(kwargs))
    return ret_val


def fetch_ip_route(dut, family="ipv4", shell="sonic", vrf_name=None, match=None, select=None):
    """

    :param dut:
    :param family:
    :param shell:
    :param vrf_name:
    :param match:
    :param select:
    :return:
    """
    if family == "ipv4":
        result = show_ip_route(dut, family, shell, vrf_name)
    else:
        result = show_ip_route(dut, family, shell, vrf_name)
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


def _clear_ip_configuration_helper(dut_list, family="ipv4"):
    """
    Find and clear ip address in DUT
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param dut_list:
    :param family: ipv4|ipv6|all
    :return:
    """
    dut_li = list(dut_list) if isinstance(dut_list, list) else [dut_list]

    if family == "ipv4":
        family_li = ['ipv4']
    elif family == "ipv6":
        family_li = ['ipv6']
    else:
        family_li = ['ipv4', 'ipv6']

    for dut in dut_li:
        for each_af in family_li:
            st.log("############## {} : {} Address Cleanup ################".format(dut, each_af.upper()))
            output = get_interface_ip_address(dut, family=each_af)
            for each_ip in output:
                if each_ip['interface'].startswith("Ethernet") or each_ip['interface'].startswith("Vlan") or \
                        each_ip['interface'].startswith("PortChannel") or each_ip['interface'].startswith("Loopback"):
                    ip, subnet = each_ip['ipaddr'].split('/')
                    if not each_ip['ipaddr'].startswith('fe80::'):
                        delete_ip_interface(dut, each_ip['interface'], ip, subnet, family=each_af)
                    else:
                        ip_link_local, interface = ip.split('%')
                        delete_ip_interface(dut, each_ip['interface'], ip_link_local, subnet, family=each_af)
    return True


def clear_ip_configuration(dut_list, family='ipv4', thread=True):
    """
    Find and clear ip address in the list of DUTs
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param dut_list:
    :param family: ipv4 (Default) / ipv6
    :param thread: True (Default) / False
    :return:
    """
    dut_li = list(dut_list) if isinstance(dut_list, list) else [dut_list]
    [out, exceptions] = utils.exec_foreach(thread, dut_li, _clear_ip_configuration_helper, family)
    st.log(exceptions)
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
    [out, exceptions] = utils.exec_foreach(thread, dut_li, _clear_loopback_config_helper)
    st.log(exceptions)
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
    return valid_option, network


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
    if config == 'yes':
        cmd = "route-map {}".format(route_map)
        if kwargs['sequence']:
            cmd += " permit {}".format(kwargs['sequence'])
        if 'metric' in kwargs:
            cmd += "\n set metric {}".format(kwargs['metric'])
        if 'community' in kwargs:
            cmd += "\n set community {}".format(kwargs['community'])
        cmd += "\n"
        st.config(dut, cmd, type='vtysh')
    else:
        cmd = "no route-map {}".format(route_map)
        if 'sequence' in kwargs:
            cmd += " permit {}".format(kwargs['sequence'])
        cmd += "\n"
        st.config(dut, cmd, type='vtysh')


def config_route_map_global_nexthop(dut, route_map='route_map_next_hop_global', sequence='10', config='yes'):
    """
    :Author: sooriya.gajendrababu@broadcom.com
    :param dut:
    :param route_map:
    :param sequence:
    :param config:
    :return:
    """
    if config == 'yes':
        cmd = "route-map {} permit {} \n set ipv6 next-hop prefer-global".format(route_map, sequence)
        st.config(dut, cmd, type='vtysh')
    else:
        cmd = "no route-map {} permit {}\n".format(route_map, sequence)
        st.config(dut, cmd, type='vtysh')


def config_static_route_vrf(dut, dest, dest_subnet, next_hop, family='ipv4', vrf_name=None, config=''):
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
    my_cmd = ''
    if family.lower() == "ipv4" or family.lower() == "":
        my_cmd = "{} ip route {}/{} {} vrf {}".format(config, dest, dest_subnet, next_hop, vrf_name)
        st.config(dut, my_cmd, type='vtysh')
    elif family.lower() == "ipv6":
        my_cmd = "{} ipv6 route {}/{} {} vrf {}".format(config, dest, dest_subnet, next_hop, vrf_name)
        st.config(dut, my_cmd, type='vtysh')

def create_static_route_nexthop_vrf(dut, next_hop, static_ip, shell="vtysh", family='ipv4',vrf_name="", nhopvrf="",
                                    config="yes"):
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



def config_route_map_mode(dut, tag, operation, sequence, config='yes'):
    """
    :param dut:
    :param tag: route-map name
    :param operation: deny/permit
    :param sequence
    :param config
    :return:
    """
    if config.lower() == 'yes':
        mode = ""
    else:
        mode = 'no'

    command = "{} route-map {} {} {}\n".format(mode, tag, operation, sequence)

    st.config(dut, command, type='vtysh')


def config_route_map_match_ip_address(dut, tag, operation, sequence, value, family = 'ipv4'):
    """
    :param dut:
    :param tag: route-map name
    :param operation: deny/permit
    :param sequence
    :param value: access_list / prefix-list/ prefix-len
    :return:
    """
    config_route_map_mode(dut, tag, operation, sequence)
    if family == 'ipv6':
        command = "match ipv6 address {}\n".format(value)
    else:
        command = "match ip address {}\n".format(value)

    command += "exit\n"
    st.config(dut, command, type='vtysh')


def config_route_map_set_aspath(dut, tag, operation, sequence, value, option='prepend'):
    """
    :param dut:
    :param tag: route-map name
    :param operation: deny/permit
    :param sequence
    :param option : exclude/prepend
    :param value: as-path
    :return:
    """
    config_route_map_mode(dut, tag, operation, sequence)
    command = "set as-path {} {}\n".format(option, value)
    command += "exit\n"
    st.config(dut, command, type='vtysh')


def config_access_list(dut, name, ipaddress, mode='permit', config='yes', family='ipv4'):
    """
    :param dut:
    :param name: access-list name
    :param ipaddress: address/prefix
    :param mode: deny/permit
    :param config: 'yes'
    :return:
    """
    if config.lower() == 'yes':
        config = ""
    else:
        config = 'no'
    if family == 'ipv6':
        command = "{} ipv6 access-list {} {} {}\n".format(config, name, mode, ipaddress)
    else:
        command = "{} access-list {} {} {}\n".format(config, name, mode, ipaddress)
    st.config(dut, command, type='vtysh')


def configure_loopback(dut, **kwargs):
    """
    Author:gangadhara.sahu@broadcom.com
    :param :loopback_name:
    :type :loopback_name:
    :param :config:
    :type :config:
    :param :dut:
    :type :dut:
    :return:
    :rtype:

    usage:
    configure_loopback(dut1,loopback_name="Loopback1",config="yes")
    configure_loopback(dut1,loopback_name="Loopback1",config="no")
    """
    my_cmd = ''
    if 'loopback_name' not in kwargs:
        st.error("Mandatory parameter - loopback_name not found")
        return False
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut))
    if cli_type == 'click':
        if 'config' in kwargs and kwargs['config'] == 'yes':
            my_cmd = 'config loopback add {}'.format(kwargs['loopback_name'])
        elif 'config' not in kwargs:
            my_cmd = 'config loopback add {}'.format(kwargs['loopback_name'])
        elif 'config' in kwargs and kwargs['config'] == 'no':
            my_cmd = 'config loopback del {}'.format(kwargs['loopback_name'])
        st.config(dut, my_cmd)
    elif cli_type == 'klish':
        regex = re.compile(r'(\d+|\s+)')
        intf = regex.split(kwargs['loopback_name'])
        if 'config' in kwargs and kwargs['config'] == 'yes':
            command = "interface {} {}".format(intf[0], intf[1])
            command = command + "\n" + "exit"
        elif 'config' not in kwargs:
            command = "interface {} {}".format(intf[0], intf[1])
            command = command + "\n" + "exit"
        elif 'config' in kwargs and kwargs['config'] == 'no':
            command = "no interface {} {}".format(intf[0], intf[1])
        output = st.config(dut, command, type="klish", conf=True)
        if "Could not connect to Management REST Server" in output:
            st.error("klish mode not working.")
            return False


def config_unconfig_interface_ip_addresses(dut, if_data_list=[], config='add'):
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

    command = ''
    for if_data in if_data_list:
        if not if_data['name']:
            st.error("Please provide interface name in {} ".format(if_data))
            return False

        if not is_valid_ip_address(if_data['ip'], if_data['family'], if_data['subnet']):
            st.error("Invalid IP address or family or subnet {} ".format(if_data))
            return False

        command += "sudo config interface ip {} {} {}/{} ; ".format(config,
                                                                    if_data['name'], if_data['ip'], if_data['subnet'])

    if command != '':
        try:
            st.config(dut, command)
        except Exception as e:
            st.log(e)
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

    def __init__(self, name, family='ipv4'):
        self.name = name
        self.description = ''
        self.family = family
        self.match_sequence = []
        if self.family == 'ipv6':
            self.cmdkeyword = 'ipv6 prefix-list'
        else:
            self.cmdkeyword = 'ip prefix-list'

    def add_description(self, description):
        self.description = description

    def add_match_permit_sequence(self, prefix, ge='', le='', seq_num=''):
        self.match_sequence.append((seq_num, 'permit', prefix, ge, le))

    def add_match_deny_sequence(self, prefix, ge='', le='', seq_num=''):
        self.match_sequence.append((seq_num, 'deny', prefix, ge, le))

    def config_command_string(self):
        command = ''
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
        return command

    def unconfig_command_string(self):
        command = 'no {} {}\n'.format(self.cmdkeyword, self.name)
        return command

    def execute_command(self, dut, config='yes'):
        if config == 'no':
            command = self.unconfig_command_string()
        else:
            command = self.config_command_string()
        st.config(dut, command, type='vtysh')


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

    def __init__(self, name, family='ipv4'):
        self.name = name
        self.description = ''
        self.family = family
        self.match_sequence = []
        if self.family == 'ipv6':
            self.cmdkeyword = 'ipv6 access-list'
        else:
            self.cmdkeyword = 'access-list'

    def add_description(self, description):
        self.description = description

    def add_match_permit_sequence(self, prefix, exact_match='false'):
        self.match_sequence.append(('permit', prefix, exact_match))

    def add_match_deny_sequence(self, prefix, exact_match='false'):
        self.match_sequence.append(('deny', prefix, exact_match))

    def config_command_string(self):
        command = ''
        if self.description:
            command += '{} {} remark {}\n'.format(self.cmdkeyword, self.name, self.description)
        for v in self.match_sequence:
            command += '{} {} {} {}'.format(self.cmdkeyword, self.name, v[0], v[1])
            if v[2] != 'false':
                command += ' exact-match'
            command += '\n'
        return command

    def unconfig_command_string(self):
        command = 'no {} {}\n'.format(self.cmdkeyword, self.name)
        return command

    def execute_command(self, dut, config='yes'):
        if config == 'no':
            command = self.unconfig_command_string()
        else:
            command = self.config_command_string()
        st.config(dut, command, type='vtysh')


def get_link_local_addresses(dut, interface):
    """
    To get the Link local address on port.
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param dut:
    :param interface:
    :return:
    """
    output = get_interface_ip_address(dut, interface, family="ipv6")
    ipv6_list = utils.dicts_list_values(output, 'ipaddr')
    return [each.split("%")[0] for each in ipv6_list if '%' in each]

def config_interface_ip6_link_local(dut, interface_list, action='enable'):
    """
    Configure IPv6 link local on multiple interfaces
    Author: Kesava Swamy (kesava-swamy.karedla@broadcom.com)

    :param dut:
    :param interface_list:
    :param action:
    :return:
    """
    if action != 'enable' and action != 'disable':
        st.error("Invalid config type {}".format(action))
        return False
    interfaces = list(interface_list) if isinstance(interface_list, list) else [interface_list]
    command = ''
    for interfaces in interfaces:
        if not interfaces:
            st.error("Please provide interface name in {} ".format(interfaces))
            return False
        command += "sudo config interface ipv6 {} use-link-local-only {} ; ".format(action,interfaces)

    if command != '':
        try:
            st.config(dut, command)
        except Exception as e:
            st.log(e)
            return False

    return True


def config_interface_ip_addresses(dut, if_data_list={}, config='yes'):

    if config == 'yes' or config == 'add':
        config = 'add'
    elif config == 'no' or config == 'del':
        config = 'remove'
    else :
        st.error("Invalid config type {}".format(config))
        return False

    command = []
    for if_name, if_data in if_data_list.items():
        if not if_data['name']:
            st.error("Please provide interface name in {} ".format(if_data))
            return False

        if not is_valid_ip_address(if_data['ip'], if_data['family'], if_data['subnet']):
            st.error("Invalid IP address or family or subnet {} ".format(if_data))
            return False

        cmd_str = "sudo config interface ip {} {} {}/{} ".format(config,
                                   if_data['name'], if_data['ip'], if_data['subnet'])
        command.append(cmd_str)

    try:
        st.config(dut, command)
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
    cli_type = kwargs.get('cli_type', st.get_ui_type(dut))
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
                command = "ip unnumbered {}".format(loop_back)
            elif action == "del":
                command = "no ip unnumbered"
            commands.append(command)
        else:
            st.log("Please provide interface, loop_back and family as ipv4")
            return False

    if commands:
        if skip_error:
            try:
                out = st.config(dut, commands, skip_error_check=skip_error, type=cli_type)
                return True
            except:
                st.log("Error handled..by API")
                return False
        else:
            out = st.config(dut, commands, skip_error_check=skip_error, type=cli_type)
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
        for key, value in output.items():
            result.append(value[0])
            if len(value) > 1:
                for attr in ip_keys:
                    value[1][attr] = value[1][attr] if value[1][attr] else value[0][attr]
                result.append(value[1])
    return result

def config_ip_prefix_list(dut, prefix_list, ip_addr, family="ipv4", action="permit", cli_type="klish", skip_error_check=True):
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
    if cli_type == "klish":
        commands = list()
        if family == "ipv4":
            ip_address = "0.0.0.0/0" if ip_addr == "any" else ip_addr
        else:
            ip_address = "0::/64" if ip_addr == "any" else ip_addr
        ip_cmd = "ipv6" if family == "ipv6" else "ip"
        commands.append("{} prefix-list {} {} {}".format(ip_cmd, prefix_list, action, ip_address))
        st.config(dut, commands, type=cli_type, skip_error_check=skip_error_check)
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
    configure_loopback(dut1,loopback_name="Loopback1",config="yes")
    configure_loopback(dut1,loopback_name="Loopback1",config="no")
    """
    my_cmd = ''
    if not kwargs.get('loopback_name'):
        st.error("Mandatory parameter - loopback_name not found")
        return False
    config = kwargs.get("config", "yes")
    loopback_interface = kwargs.get("loopback_name") if isinstance(kwargs.get("loopback_name"), list) else [kwargs.get("loopback_name")]
    for intf in loopback_interface:
        if config == 'yes':
            my_cmd += 'sudo config loopback add {};'.format(intf)
        elif config == 'no':
            my_cmd += 'sudo config loopback del {};'.format(intf)
    st.config(dut, my_cmd)

