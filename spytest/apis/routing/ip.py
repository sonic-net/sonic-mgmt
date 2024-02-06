# This file contains the list of API's which performs IP,Ping related operations.
# Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)

import re
import time
import ipaddress

from spytest import st

from apis.system.rest import config_rest, delete_rest, get_rest
from apis.routing.ip_rest import get_subinterface_index
from apis.routing.sag import config_sag_ip
import apis.switching.portchannel as pc
import apis.system.boot_up as bootup_api

import utilities.common as utils
from utilities.utils import get_interface_number_from_name
from utilities.utils import segregate_intf_list_type
from utilities.utils import is_a_single_intf
from utilities.utils import get_supported_ui_type_list
from utilities.utils import cli_type_for_get_mode_filtering
from utilities.utils import is_valid_ipv4_address
from utilities.utils import is_valid_ipv6_address
from utilities.utils import is_valid_ip_address
from utilities.utils import get_intf_short_name, convert_intf_name_to_component
from utilities.utils import get_random_space_string

try:
    import apis.yang.codegen.messages.interfaces.Interfaces as umf_intf
    import apis.yang.codegen.messages.network_instance as umf_ni
    import apis.yang.codegen.messages.ip_sla as umf_ipsla
    import apis.yang.codegen.messages.routing_policy as umf_rp
    import apis.yang.codegen.messages.loadshare_mode_ext as umf_loadshare
    import apis.yang.codegen.messages.system as umf_system
    import apis.yang.codegen.bulk as umf_bulk
    from apis.yang.utils.common import Operation
except ImportError:
    pass

# below  time_out is for Rest/Gnmi url timeout
time_out = 125

get_phy_port = lambda intf: re.search(r"(\S+)\.\d+", intf).group(1) if re.search(r"(\S+)\.\d+", intf) else intf


def force_cli_type_to_klish(cli_type):
    cli_type = "klish" if cli_type in get_supported_ui_type_list() else cli_type
    return cli_type


def config_ipv6(dut, action='disable'):
    """
    To globally disable or enabled Ipv6
    :param dut:
    :param action: Can be 'disable' or 'enable'.
    :return:
    """
    command = "config ipv6 {}".format(action)
    if st.is_feature_supported("config-ipv6-command", dut):
        st.config(dut, command)
    elif action == "disable":
        st.community_unsupported(command, dut)
        st.config(dut, "sysctl -w net.ipv6.conf.all.disable_ipv6=1")
        st.config(dut, "sysctl -w net.ipv6.conf.default.disable_ipv6=1")
        st.config(dut, "sysctl -w net.ipv6.conf.lo.disable_ipv6=1")
    else:
        st.community_unsupported(command, dut)
        st.config(dut, "sysctl -w net.ipv6.conf.all.disable_ipv6=0")
        st.config(dut, "sysctl -w net.ipv6.conf.default.disable_ipv6=0")
        st.config(dut, "sysctl -w net.ipv6.conf.lo.disable_ipv6=0")


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
    cli_type = "klish" if cli_type != 'click' else cli_type
    conn_index = kwargs.get("conn_index", None)
    exec_mode = kwargs.get("exec_mode", "")
    ping_pattern = r'(\d+)\s+packets\s+transmitted,\s+(\d+)\s+received,(.*)\s+(\d+)%\s+packet\s+loss,\s+time\s+(\d+)ms'
    ping_pattern1 = r'(\d+)\s+bytes\s+from(.*)time=(.*)\s+ms\s+\(DUP\!\)'
    external = kwargs.get("external", False)

    # add defaults
    kwargs['tgen'] = kwargs.get('tgen', False)
    kwargs['count'] = kwargs.get('count', 3)
    if 'interface' in kwargs and '.' in kwargs['interface']:
        kwargs['interface'] = kwargs['interface'].replace('Ethernet', 'Eth')
        kwargs['interface'] = kwargs['interface'].replace('PortChannel', 'Po')

    '''
    if st.get_ifname_type(dut) == 'std-ext':
        cli_type = 'click'
        if 'interface' in kwargs:
            kwargs['interface'] = convert_intf_name_to_component(dut, kwargs['interface'])
    '''
    if family == "ipv4":
        if is_valid_ipv6_address(addresses):
            family = "ipv6"
    if family.lower() == "ipv4":
        if external:
            command = "ping {} -c {} ".format(addresses, kwargs['count'])
        else:
            if cli_type == 'click':
                command = "ping -4 {} -c {} ".format(addresses, kwargs['count'])
            elif cli_type == 'klish':
                if 'interface' in kwargs and ('Vrf' in kwargs['interface'] or 'mgmt' in kwargs['interface']):
                    command = "ping vrf {} {} -c {} -4 ".format(kwargs['interface'], addresses, kwargs['count'])
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
                if 'interface' in kwargs and ('Vrf' in kwargs['interface'] or 'mgmt' in kwargs['interface']):
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
    if 'interval' in kwargs:
        command = command + "-i {} ".format(kwargs['interval'])

    if st.is_dry_run():
        return True

    if external:
        st.log(command)
        p = utils.process_popen(command)
        rv, err = p.communicate()
        st.log(rv)
        st.log(err)
    else:
        rv = st.config(dut, command, type=cli_type, conn_index=conn_index, exec_mode=exec_mode)
    out = re.findall(ping_pattern, rv)
    out_dup = re.findall(ping_pattern1, rv)

    if not out:
        st.error("Failed to get the ping output.")
        return False
    if '0' < out[0][3] <= '100':
        st.error("Ping failed with packet loss.")
        return False
    if out_dup:
        st.error("Ping failed because of duplicate ping reply.")
        return False
    return True


def config_ip_addr_interface(dut, interface_name='', ip_address='', subnet='', family="ipv4", config='add', skip_error=False, **kwargs):
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
    st.log('API_NAME: config_ip_addr_interface, API_ARGS: {}'.format(locals()))
    cli_type = st.get_ui_type(dut, **kwargs)
    is_secondary_ip = kwargs.get('is_secondary_ip', 'no').lower()
    max_time = kwargs.get('max_time', 600)
    gw_addr = kwargs.get('gw_addr', None)
    if cli_type in get_supported_ui_type_list():
        index = get_subinterface_index(dut, interface_name)
        if not index:
            st.error("Failed to get index for interface: {}".format(interface_name))
            index = 0
        if config in ['add', 'verify']:
            # operation = Operation.UPDATE
            operation = Operation.CREATE
            # Update/Patch is not working for Phy interface.
            if 'Eth' in interface_name and '.' not in interface_name:
                operation = Operation.CREATE
            interface_name = get_phy_port(interface_name)
            intf_obj = umf_intf.Interface(Name=interface_name)
            secondary_ip_flag = True if is_secondary_ip == 'yes' else False
            if "Vlan" in interface_name:
                operation = Operation.CREATE
                if family == "ipv4":
                    intf_ipx_obj = umf_intf.RoutedVlanIpv4Address(Ip=ip_address, PrefixLength=subnet, Secondary=secondary_ip_flag, Interface=intf_obj)
                else:
                    intf_ipx_obj = umf_intf.RoutedVlanIpv6Address(Ip=ip_address, PrefixLength=subnet, Interface=intf_obj)
                if config == 'add':
                    result = intf_ipx_obj.configure(dut, operation=operation, cli_type=cli_type, timeout=time_out)
            else:
                if 'Loopback' in interface_name.capitalize():
                    loopback_intfs = get_loopback_interfaces(dut)
                    if interface_name.capitalize() not in loopback_intfs:
                        if not config_loopback_interfaces(dut, loopback_name=interface_name.capitalize(), cli_type=cli_type):
                            st.error("msg", "Failed to create loopback interface")
                            return False
                sub_intf_obj = umf_intf.Subinterface(Index=int(index), Interface=intf_obj)
                if family == "ipv4":
                    if not gw_addr:
                        intf_ipx_obj = umf_intf.SubinterfaceIpv4Address(Ip=ip_address, PrefixLength=subnet, Secondary=secondary_ip_flag, Subinterface=sub_intf_obj)
                    else:
                        intf_ipx_obj = umf_intf.SubinterfaceIpv4Address(Ip=ip_address, PrefixLength=subnet,
                                                                        Secondary=secondary_ip_flag,
                                                                        Subinterface=sub_intf_obj, GwAddr=gw_addr)
                    sub_intf_obj.add_SubinterfaceIpv4Address(intf_ipx_obj)
                else:
                    intf_ipx_obj = umf_intf.SubinterfaceIpv6Address(Ip=ip_address, PrefixLength=subnet, Subinterface=sub_intf_obj)
                    sub_intf_obj.add_SubinterfaceIpv6Address(intf_ipx_obj)

                if config == 'add':
                    result = sub_intf_obj.configure(dut, operation=operation, cli_type=cli_type, timeout=time_out)

            if config == 'verify':
                return intf_ipx_obj

            # result = intf_ipx_obj.configure(dut, operation=operation, cli_type=cli_type)
            if not result.ok():
                st.log('test_step_failed: Configuring IP Address on Interface {}'.format(result.data))
                return False
            elif result.ok() and skip_error:
                st.log('Negative Scenario: Error/Exception is expected')
                return False
            return True
        elif config == 'remove':
            return delete_ip_interface(dut, interface_name, ip_address, subnet, family, cli_type=cli_type, is_secondary_ip=is_secondary_ip)
    elif cli_type == 'click':
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
                        st.warn("Invalid IP address.")
                        return False
                elif family == "ipv6":
                    if not is_valid_ipv6_address(ip_address):
                        st.error("Invalid IPv6 address.")
                        return False
                interface_name = convert_intf_name_to_component(dut, interface_name, component="applications")
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
                expect_ipchange = False
                if interface_name == 'eth0':
                    expect_ipchange = True
                    zero_or_more_space = get_random_space_string()
                    command = "interface Management{}0".format(zero_or_more_space)
                    if not gw_addr:
                        command = command + "\n" + "ip address {}/{}".format(ip_address, subnet)
                    else:
                        command = command + "\n" + "ip address {}/{} gwaddr {}".format(ip_address, subnet, gw_addr)
                else:
                    intf = get_interface_number_from_name(interface_name)
                    zero_or_more_space = get_random_space_string()
                    command = "interface {}{}{}".format(intf['type'], zero_or_more_space, intf['number'])
                    fam = "ip" if family == 'ipv4' else 'ipv6'
                    command = command + "\n" + "{} address {}/{}".format(fam, ip_address, subnet)
                    if is_secondary_ip == 'yes':
                        command += ' secondary'
                    command = command + "\n" + "exit"
                output = st.config(dut, command, skip_error_check=skip_error, type="klish",
                                   conf=True, expect_ipchange=expect_ipchange, skip_error_report=True)
                if "Could not connect to Management REST Server" in output:
                    st.error("klish mode not working.")
                    return False
                if skip_error and 'Error' in output:
                    return False
            except Exception as e:
                st.log(e)
                return False
            return True
        elif config == 'remove':
            return delete_ip_interface(dut, interface_name, ip_address, subnet, family, cli_type=cli_type, is_secondary_ip=is_secondary_ip, max_time=max_time)
    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        index = get_subinterface_index(dut, interface_name)
        if not index:
            st.error("Failed to get index for interface: {}".format(interface_name))
            index = 0
        if config == 'add':
            interface_name = get_phy_port(interface_name)
            if "PortChannel" in interface_name:
                if is_secondary_ip == 'yes':
                    url = rest_urls['subinterface_config'].format(interface_name, index)
                    ip_config = {"openconfig-interfaces:subinterface": [{"index": int(index), "config": {"index": int(index)},
                                                                         "openconfig-if-ip:{}".format(family): {"addresses": {"address": [{
                                                                             "ip": ip_address, "config": {"ip": ip_address, "prefix-length": int(subnet),
                                                                                                          "openconfig-interfaces-ext:secondary": True}}]}}}]}
                else:
                    url = rest_urls['subinterface_config'].format(interface_name, index)
                    ip_config = {"openconfig-interfaces:subinterface": [{"index": int(index), "config": {"index": int(index)},
                                                                         "openconfig-if-ip:{}".format(family): {"addresses": {"address": [{
                                                                             "ip": ip_address, "config": {"ip": ip_address, "prefix-length": int(subnet)}}]}}}]}
            elif "Vlan" in interface_name:
                if is_secondary_ip == 'yes':
                    url_identifier = "routed_vlan_config_v6" if family == "ipv6" else "routed_vlan_config_v4"
                    url = rest_urls[url_identifier].format(interface_name)
                    ip_config = {"openconfig-if-ip:{}".format(family): {"addresses": {"address": [{"ip": ip_address,
                                                                                                   "config": {"ip": ip_address, "prefix-length": int(subnet), "openconfig-interfaces-ext:secondary": True}}]}}}
                else:
                    url_identifier = "routed_vlan_config_v6" if family == "ipv6" else "routed_vlan_config_v4"
                    url = rest_urls[url_identifier].format(interface_name)
                    ip_config = {"openconfig-if-ip:{}".format(family): {"addresses": {"address": [{"ip": ip_address, "config": {"ip": ip_address, "prefix-length": int(subnet)}}]}}}
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
                                                                                                                                                                                          "prefix-length": int(subnet), "openconfig-interfaces-ext:secondary": True}}]}}}]}}
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
                                                                                                                                                             "config": {"ip": ip_address, "prefix-length": int(subnet), "openconfig-interfaces-ext:secondary": True}}]}}}]}}
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
    :param interface_name: interface name can be list of range ex:['Ethernet0-1','PortChannel10-11'] or ['Ethernet0-1'] or 'Ethernet3' but not the combination of single and range intf.
    :param ip_address:
    :param subnet:
    :param skip_error:
    :param family: ipv4|ipv6
    :return:
    """
    if family == "ipv4":
        if not is_valid_ipv4_address(ip_address):
            st.warn("Invalid IP address.")
    elif family == "ipv6":
        if not is_valid_ipv6_address(ip_address):
            st.error("Invalid IPv6 address.")
    cli_type = st.get_ui_type(dut, **kwargs)
    is_secondary_ip = kwargs.get('is_secondary_ip', 'no').lower()
    max_time = kwargs.get('max_time', 600)

    if cli_type in get_supported_ui_type_list() and not is_a_single_intf(interface_name):
        cli_type = 'klish'

    if cli_type in get_supported_ui_type_list():
        index = get_subinterface_index(dut, interface_name)
        if not index:
            st.error("Failed to get index for interface: {}".format(interface_name))
            index = 0
        interface_name = get_phy_port(interface_name)
        secondary_ip_flag = True if is_secondary_ip == 'yes' else False
        intf_obj = umf_intf.Interface(Name=interface_name)
        if "Vlan" in interface_name:
            if family == "ipv4":
                intf_ipx_obj = umf_intf.RoutedVlanIpv4Address(Ip=ip_address, PrefixLength=subnet, Secondary=secondary_ip_flag, Interface=intf_obj)
            else:
                intf_ipx_obj = umf_intf.RoutedVlanIpv6Address(Ip=ip_address, PrefixLength=subnet, Interface=intf_obj)
        else:
            sub_intf_obj = umf_intf.Subinterface(Index=index, Interface=intf_obj)
            if family == 'ipv4':
                intf_ipx_obj = umf_intf.SubinterfaceIpv4Address(Ip=ip_address, PrefixLength=subnet, Secondary=secondary_ip_flag, Subinterface=sub_intf_obj)
            else:
                intf_ipx_obj = umf_intf.SubinterfaceIpv6Address(Ip=ip_address, PrefixLength=subnet, Subinterface=sub_intf_obj)

        if not secondary_ip_flag:
            target_attr = None
        else:
            target_attr = intf_ipx_obj.Secondary

        result = intf_ipx_obj.unConfigure(dut, target_attr=target_attr, cli_type=cli_type, timeout=time_out)
        if not result.ok():
            st.log('test_step_failed: Configuring IP Address on Interface {}'.format(result.data))
            return False
        return True
    elif cli_type == 'click':
        if not is_a_single_intf(interface_name):
            st.error("Range intf not supported in cli_type CLICK")
            return False
        interface_name = convert_intf_name_to_component(dut, interface_name, component="applications")
        command = "config interface ip remove {} {}/{}".format(interface_name, ip_address, subnet)
        st.config(dut, command, skip_error_check=skip_error)
        return True
    elif cli_type == 'klish':
        fam = "ip" if family == 'ipv4' else 'ipv6'
        interface_name = [interface_name] if isinstance(interface_name, str) else interface_name
        port_hash_list = segregate_intf_list_type(intf=interface_name, range_format=True)
        interface_list = port_hash_list['intf_list_all']
        command = list()
        for ifname in interface_list:
            if not is_a_single_intf(ifname):
                command.append("interface range {}".format(ifname))
                command.append("no {} address".format(fam))
            elif ifname == 'eth0':
                command.append("interface Management 0")
                command.append("no {} address {}/{}".format(fam, ip_address, subnet))
            else:
                intf = get_interface_number_from_name(ifname)
                zero_or_more_space = get_random_space_string()
                command.append("interface {}{}{}".format(intf['type'], zero_or_more_space, intf['number']))
                sub_cmd = "no {} address {}/{}".format(fam, ip_address, subnet)
                if is_secondary_ip == 'yes':
                    sub_cmd += ' secondary'
                command.append(sub_cmd)
            command.append("exit")
            output = st.config(dut, command, skip_error_check=skip_error, type=cli_type, conf=True, max_time=max_time)
        if "Could not connect to Management REST Server" in output:
            st.error("klish mode not working.")
            return False
        if "%Error: Primary IPv4 address delete not permitted when secondary IPv4 address exists" in output:
            st.error("secondary ip address exists")
            return False
        if "cannot be deleted, Vxlan is configured" in output:
            return False
        return True
    elif cli_type in ["rest-patch", "rest-put"]:
        if not is_a_single_intf(interface_name):
            st.error("Range intf not supported in cli_type CLICK")
            return False
        rest_urls = st.get_datastore(dut, 'rest_urls')
        if "Vlan" in interface_name:
            if is_secondary_ip == 'yes':
                url = rest_urls['clear_logical_port_sec_ipv4_addr'] if family == 'ipv4' else rest_urls['clear_logical_port_ipv6_addr']
            else:
                url = rest_urls['clear_logical_port_ipv4_addr'] if family == 'ipv4' else rest_urls['clear_logical_port_ipv6_addr']
            url = url.format(interface_name, ip_address)
        else:
            index = get_subinterface_index(dut, interface_name)
            if is_secondary_ip == 'yes':
                url = rest_urls['ipv4_sec_address_config'] if family == 'ipv4' else rest_urls['ipv6_address_config']
            else:
                url = rest_urls['ipv4_address_config'] if family == 'ipv4' else rest_urls['ipv6_address_config']
            interface_name = get_phy_port(interface_name)
            url = url.format(interface_name, index, ip_address)
        if not delete_rest(dut, rest_url=url, timeout=100):
            st.error("Failed to remove IP address: {} on interface: {}".format(ip_address, interface_name))
            return False
        return True
    else:
        st.log("Unsupported CLI TYPE {}".format(cli_type))
        return False


def get_interface_ip_address(dut, interface_name=None, family="ipv4", cli_type=''):
    """
    To Get  ip address on interface
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)

    :param dut:
    :param interface_name:
    :param family: ipv4 | ipv6
    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    if cli_type == 'click':
        interface_name = get_intf_short_name(interface_name)
    else:
        if interface_name == "eth0":
            interface_name = "Management0"
    if cli_type in ['rest-patch', 'rest-put']:
        cli_type = 'klish'  # OC-YANG URLs are not available for show ip/ipv6 interface. Reported JIRA: SONIC-23677 for this.
    if cli_type in ['click', 'klish']:
        command = "show ip interface"
        if family == "ipv6":
            command = "show ipv6 interface"
        output = st.show(dut, command, type=cli_type)
        result = output if family == "ipv4" else prepare_show_ipv6_interface_output(output)
        if interface_name:
            match = {"interface": interface_name}
            output = utils.filter_and_select(result, None, match)
        return output


def verify_interface_ip_address(dut, interface_name, ip_address, family="ipv4", vrfname='', flags='', cli_type='', **kwargs):
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
    st.log('API_NAME: verify_interface_ip_address, API_ARGS: {}'.format(locals()))
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
#    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    intf_status = kwargs.get('intf_status', None)
    interfaces = utils.make_list(interface_name)
    ip_addrs = utils.make_list(ip_address)
    # adding suport for multiple vrf
    vrf = vrfname
    build_avail = bootup_api.sonic_installer_list(dut)

    # if cli_type in get_supported_ui_type_list():
    #    vrf = 'default' if vrfname == '' else vrfname
    vrfs = utils.make_list(vrf)
    if len(vrfs) != len(interfaces):
        vrfs = vrfs * len(interfaces)
    negative = kwargs.pop('negative', False)
    if cli_type in ['rest-patch', 'rest-put']:
        cli_type = 'klish'  # OC-YANG URLs are not available for show ip/ipv6 interface. Reported JIRA: SONIC-23677 for this.
    # gnmi related code is not complete as some of the values are not available
    if cli_type in get_supported_ui_type_list():
        #        if vrfname != '' and vrfname != 'default': cli_type = 'klish'
        if flags != '':
            cli_type = 'klish'
        for ip_addr in ip_addrs:
            if '/' not in ip_addr:
                cli_type = 'klish'
        st.log('Forcing the cli_type to Klish as either flags is non-blank or / not in ip_addr')
    if cli_type in get_supported_ui_type_list():
        kwargs['cli_type'] = cli_type
        filter_type = kwargs.get('filter_type', 'ALL')
        query_param_obj = utils.get_query_params(yang_data_type=filter_type, cli_type=cli_type)

        for intf, ip_addr, vrf_name in zip(interfaces, ip_addrs, vrfs):
            if vrf_name == '':
                vrf_name = 'default'
            ip = ip_addr.split('/')[0]
            subnet = ip_addr.split('/')[1]
            if 'eth0' in intf:
                if family == 'ipv4':
                    intf_obj = umf_intf.Interface(Name='eth0')
                    intf_ipx_obj = umf_intf.Subinterface(Index=0, Interface=intf_obj)
                    result = intf_ipx_obj.verify(dut, target_path='ipv4/addresses', query_param=query_param_obj)
                    if result.payload and ip == result.payload['openconfig-if-ip:addresses']['address'][0]['state']['ip']:
                        st.log('test_step_passed: Match Found: {} {}'.format(intf, ip))
                        return True
                    else:
                        st.log('test_step_failed: Match Not Found: {} {}'.format(intf, ip))
                        return False
                else:
                    intf_obj = umf_intf.Interface(Name='eth0')
                    sub_intf_obj = umf_intf.Subinterface(Index=0, Interface=intf_obj)
                    intf_ipx_obj = umf_intf.SubinterfaceIpv6Address(Ip=ip, Subinterface=sub_intf_obj)
                    result = intf_ipx_obj.verify(dut, query_param=query_param_obj)

                    if result.payload and ip == result.payload['openconfig-if-ip:address'][0]['state']['ip']:
                        st.log('test_step_passed: Match Found: {} {}'.format(intf, ip))
                        return True
                    else:
                        st.log('test_step_failed: Match Not Found: {} {}'.format(intf, ip))
                        return False
            else:
                verify_ipx_obj = config_ip_addr_interface(dut, interface_name=intf, ip_address=ip, subnet=subnet, family=family, config='verify', **kwargs)
                result = verify_ipx_obj.verify(dut, match_subset=True, query_param=query_param_obj, cli_type=cli_type)
                if negative and result.ok():
                    st.log('test_step_failed: Match Not Expected But Found: {} {}'.format(intf, ip_addr))
                    return False
            if not negative and not result.ok():
                st.log('test_step_failed: Match Not Found: {} {}'.format(intf, ip_addr))
                return False
            if intf_status and '.' not in intf:
                # TBD Code for sub-interfce
                intf_obj = umf_intf.Interface(Name=intf)
                intf_obj.AdminStatus = intf_status.split('/')[0].upper()
                result_admin_status = intf_obj.verify(dut, target_attr=getattr(intf_obj, 'AdminStatus'), match_subset=True, cli_type=cli_type)
                if not result_admin_status.ok():
                    st.log('test_step_failed: AdminStatus Mismatch for Interface {}'.format(intf))
                    return False
                intf_obj.OperStatus = intf_status.split('/')[1].upper()
                result_oper_status = intf_obj.verify(dut, target_attr=getattr(intf_obj, 'OperStatus'), match_subset=True, cli_type=cli_type)
                if not result_oper_status.ok():
                    st.log('test_step_failed: OperStatus Mismatch for Interface {}'.format(intf))
                    return False

            # VRF needs to be validated separately
            if intf == 'eth0' and vrf_name != 'mgmt':
                continue
            ni_obj = umf_ni.NetworkInstance(Name=vrf_name)
            ni_intf_obj = umf_ni.NetworkInstanceInterface(Id=intf, NetworkInstance=ni_obj)
            if vrf_name == 'default':
                filter_type = 'NON_CONFIG'
                query_param_obj = utils.get_query_params(yang_data_type=filter_type, cli_type=cli_type)
            result_vrf = ni_intf_obj.verify(dut, match_subset=True, query_param=query_param_obj, cli_type=cli_type)
            if negative and result_vrf.ok():
                st.log('test_step_failed: Vrf {}, Interface {} found'.format(vrf_name, intf))
                return False
            if not negative and not result_vrf.ok():
                st.log('test_step_failed: Vrf {}, Interface {} not found'.format(vrf_name, intf))
                return False

            if flags == 'U':
                intf_obj = umf_intf.Interface(Name=intf)
                if 'Vlan' in intf:
                    # Enabled attribute is not valid - defect fix 74996
                    # intf_obj.VlanIpv4UnNumEnabled = True
                    result_flag = intf_obj.verify(dut, target_attr=intf_obj.Ipv4Interface, match_subset=True, query_param=query_param_obj, cli_type=cli_type)
                if negative and result_flag.ok():
                    st.log('test_step_failed: Vrf {}, Interface {} found'.format(vrf_name, intf))
                    return False
                if not negative and not result_flag.ok():
                    st.log('test_step_failed: Vrf {}, Interface {} not found'.format(vrf_name, intf))
                    return False
        return True
    else:
        command = "show ip interface"
        if family == "ipv6":
            command = "show ipv6 interface"
        output = st.show(dut, command, type=cli_type)
        result = output if family == "ipv4" else prepare_show_ipv6_interface_output(output)

    for intf, ip_addr, vrf_name in zip(interfaces, ip_addrs, vrfs):
        if cli_type == 'click':
            intf = get_intf_short_name(intf)
        else:
            if intf == "eth0":
                intf = "Management0"
        if vrf_name == 'default':
            vrf_name = ''
        if intf_status:
            match = {"interface": intf, "vrf": vrf_name, "ipaddr": ip_addr, "status": intf_status} if 'master' in build_avail['Current'] else {"interface": intf, "vrf": vrf_name, "ipaddr": ip_addr, "status": intf_status, "flags": flags}
        else:
            match = {"interface": intf, "vrf": vrf_name, "ipaddr": ip_addr} if 'master' in build_avail['Current'] else {"interface": intf, "vrf": vrf_name, "ipaddr": ip_addr, "flags": flags}
        entries = utils.filter_and_select(result, ["interface"], match)
        if negative and entries:
            st.debug("Entries found for the match - {}".format(match))
            return False
        if not negative and not entries:
            st.debug("No entries found for the match - {}".format(match))
            return False
    return True


def create_static_route(dut, next_hop=None, static_ip=None, shell="vtysh", family='ipv4', interface=None, vrf=None, **kwargs):
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
    st.log('API_NAME: create_static_route, API_ARGS: {}'.format(locals()))
    if shell != 'vtysh':
        st.log("shell parameter is obsolete and will be ignored. Please use cli_type.")
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut, **kwargs))
    if cli_type == 'click':
        cli_type = 'vtysh'
    cli_type = 'klish' if cli_type in ['rest-patch', 'rest-put'] else cli_type  # Due to JIRA: SONIC-28182 we are fallback to klish
    distance = kwargs.pop('distance', None)
    nexthop_vrf = kwargs.pop('nexthop_vrf', None)
    track = kwargs.pop('track', None)
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
    if cli_type in get_supported_ui_type_list():
        config = kwargs.get('config', 'yes')
        # ui, operation = get_ui_op(dut, cli_type=cli_type)
        if '/' not in static_ip:
            st.error('Network ID should be provided along with subnet mask')
            return False
        instance = vrf if vrf else 'default'
        ni_obj = umf_ni.NetworkInstance(Name=instance)
        proto_obj = umf_ni.Protocol(ProtoIdentifier="STATIC", Name="static", NetworkInstance=ni_obj)
        static_obj = umf_ni.Static(Prefix=static_ip, Protocol=proto_obj)
        ip_args = {"Static": static_obj}
        if next_hop:
            if not re.search(r':|\.', next_hop) and 'blackhole' not in next_hop:
                ip_args.update({"Interface": next_hop})
                interface = None
            elif 'blackhole' in next_hop:
                next_hop = 'DROP'
                ip_args.update({"Blackhole": True})
            else:
                ip_args.update({"NextHop": next_hop})
            index = "{}_{}".format(next_hop, nexthop_vrf).replace('None', '').replace("__", "_").strip("_")
            if next_hop.lower().startswith('fe80'):
                ip_args.update({"Interface": interface})
                index = "{}_{}_{}".format(interface, next_hop, nexthop_vrf).replace('None', '').replace("__", "_").strip("_")
        elif interface:
            ip_args.update({"Interface": interface})
            index = "{}_{}".format(interface, nexthop_vrf).replace('None', '').replace("__", "_").strip("_")
        if nexthop_vrf:
            ip_args.update({"NetworkInstance": nexthop_vrf})
        if distance:
            ip_args.update({"Metric": int(distance)})
        if track:
            ip_args.update({"Track": track})
        if config == 'yes':
            static_next_hop_obj = umf_ni.StaticNextHop(Index=index, **ip_args)
            static_obj.add_StaticNextHop(static_next_hop_obj)
            operation = Operation.CREATE
            result = static_obj.configure(dut, operation=operation, cli_type=cli_type, timeout=time_out)
        else:
            ip_args.update({'Static': static_obj})
            static_next_hop_obj = umf_ni.StaticNextHop(Index=index, **ip_args)
            if not next_hop:
                static_obj.add_StaticNextHop(static_next_hop_obj)
                result = static_obj.unConfigure(dut, cli_type=cli_type, timeout=time_out)
            else:
                result = static_next_hop_obj.unConfigure(dut, cli_type=cli_type, timeout=time_out)
        if not result.ok():
            st.log('test_step_failed: Configuring Static Route {}'.format(result.data))
            return False
    elif cli_type == "vtysh":
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
            command += " {}".format(interface)
        if vrf:
            command += " vrf {}".format(vrf)
        if nexthop_vrf:
            command += " nexthop-vrf {}".format(nexthop_vrf)
        if track:
            command += " track {}".format(track)
        st.config(dut, command, type='vtysh', **kwargs)
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
            command += " dev {}".format(interface)
        st.config(dut, command, **kwargs)
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
            command += " interface {} {}".format(intf['type'], intf['number'])
        if nexthop_vrf:
            command += " nexthop-vrf {}".format(nexthop_vrf)
        if track:
            command += " track {}".format(track)
        if distance:
            command += " {}".format(distance)
        out = st.config(dut, command, type="klish", conf=True, **kwargs)
        if kwargs.get('skip_error_check') and 'error' in str(out).lower():
            return False

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
            if not re.search(r':|\.', next_hop) and 'blackhole' not in next_hop:
                add_data = {"interface-ref": {"config": {"interface": next_hop}}}
                params_data.update(add_data)
                interface = None
            elif 'blackhole' in next_hop:
                next_hop = 'DROP'
                params_data['config'].update({"blackhole": True})
            else:
                params_data['config'].update({"next-hop": next_hop})
        elif interface:
            add_data = {"interface-ref": {"config": {"interface": interface}}}
            params_data.update(add_data)
        if nexthop_vrf:
            params_data['config'].update({"network-instance": nexthop_vrf})
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


def delete_static_route(dut, next_hop=None, static_ip=None, family='ipv4', shell="vtysh", interface=None, vrf=None, **kwargs):
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
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut, **kwargs))
    if cli_type == 'click':
        cli_type = 'vtysh'
    cli_type = "klish" if cli_type in ["rest-put", "rest-patch"] else cli_type
    nexthop_vrf = kwargs.pop('nexthop_vrf', None)
    command = ''
    if cli_type in get_supported_ui_type_list():
        return create_static_route(dut, next_hop=next_hop, static_ip=static_ip, shell="vtysh", family=family, interface=interface, vrf=vrf, config='no')
    elif cli_type == "vtysh":
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
            command += " {}".format(interface)
        if vrf:
            command += " vrf {}".format(vrf)
        if nexthop_vrf:
            command += " nexthop-vrf {}".format(nexthop_vrf)
        if "track" in kwargs:
            command += " track {}".format(kwargs["track"])
        st.config(dut, command, type='vtysh')
    elif cli_type == "click":
        if family.lower() == "ipv4" or family.lower() == "":
            if next_hop is not None:
                command = "ip route del {} via {}".format(static_ip, next_hop)
            else:
                command = "ip route del {}".format(static_ip)
        elif family.lower() == "ipv6":
            if next_hop is not None:
                command = "ip -6 route del {}  via {}".format(static_ip, next_hop)
            else:
                command = "ip -6 route del {}".format(static_ip)
        if interface:
            command += " dev {}".format(interface)
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
            command += " interface {} {}".format(intf['type'], intf['number'])
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
    yang_data_type = kwargs.get("yang_data_type", "ALL")
    # format = kwargs.get("format", True)
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    if cli_type in ['click', 'vtysh']:
        cli_type = 'click'
    elif cli_type in ["rest-patch", "rest-put"]:
        cli_type = "klish"

    summary_routes = ' summary' if kwargs.get('summary_routes') else ''
    if cli_type in ["rest", "gnmi"] and not summary_routes:
        result = list()
        vrf_name = "default" if not vrf_name else vrf_name
        ni_obj = umf_ni.NetworkInstance(Name=vrf_name)
        if cli_type in cli_type_for_get_mode_filtering():
            query_params_obj = utils.get_query_params(yang_data_type=yang_data_type, cli_type=cli_type)
            rv = ni_obj.get_payload(dut, query_param=query_params_obj, cli_type=cli_type)
        else:
            rv = ni_obj.get_payload(dut, cli_type=cli_type)
        if rv.ok():
            response = rv.payload
            afts_data = response["openconfig-network-instance:network-instance"][0]["afts"]
            unicast_entry = afts_data.get("{}-unicast".format(family)).get("{}-entry".format(family))
            if unicast_entry:
                for entry in unicast_entry:
                    route_data = dict()
                    if entry.get("state").get("origin-protocol"):
                        origin_proto = entry.get("state").get("origin-protocol").replace("openconfig-policy-types:", "")
                        if origin_proto == "DIRECTLY_CONNECTED":
                            route_data["type"] = "C"
                        elif origin_proto in ["BGP", "OSPF", "IGMP", "STATIC", "PIM"]:
                            route_data["type"] = origin_proto[0]
                        else:
                            route_data["type"] = "K"
                    else:
                        route_data["type"] = "K"
                    route_data["selected"] = ""
                    route_data["fib"] = ""
                    route_data["not_installed"] = ""
                    route_data["ip_address"] = entry.get("prefix")
                    route_data["duration"] = entry.get("state").get("uptime")
                    route_data["distance"] = entry.get("state").get("distance")
                    route_data["distance"] = entry.get("state").get("distance")
                    route_data["cost"] = entry.get("state").get("metric")
                    route_data["vrf_name"] = vrf_name
                    route_data["dest_vrf_name"] = ""
                    route_data["weight"] = ""
                    next_hops = entry.get("openconfig-aft-deviation:next-hops")
                    if next_hops:
                        next_hop_data = next_hops.get("next-hop")
                        for next_hop in next_hop_data:
                            next_hop_entry = dict()
                            if next_hop.get("interface-ref").get("state").get("interface"):
                                next_hop_entry["interface"] = next_hop.get("interface-ref").get("state").get("interface")
                            else:
                                next_hop_entry["interface"] = ""
                            if next_hop.get("state").get("ip-address"):
                                next_hop_entry["nexthop"] = next_hop.get("state").get("ip-address")
                            else:
                                next_hop_entry["nexthop"] = ""
                            next_hop_entry["nh_type"] = ""
                            route_data.update(next_hop_entry)
                            result.append(route_data)
                    else:
                        result.append(route_data)
                return result
            else:
                return result
        else:
            return result
    else:
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


def verify_ip_route_summary(dut, match_summary={}, version='ipv4', vrf='default', cli_type=''):
    """
    :param dut:
    :param match_summary:
    :param version:
    :param cli_type:
    :return: True/False
    """

    family = ''
    if version == 'ip' or version == 'ipv4':
        family = 'ipv4'
    elif version == 'ipv6':
        family = 'ipv6'
    else:
        st.error("Invalid version parameter {}".format(version))
        return False

    match_summary[u'vrf'] = vrf

    st.log("IP Routing table summary on DUT {} , vrf {}.".format(dut, match_summary[u'vrf']))

    output = show_ip_route(dut, family=family, vrf_name=vrf, summary_routes='yes')

    summary_entries = utils.filter_and_select(output, None, match_summary)
    if len(summary_entries):
        st.log("IP - {} route summary match successfull".format(version))
        return True
    else:
        st.log("IP - Routing table summary: {}".format(output))
        st.log("IP - {} route summary match failed for {}".format(version, match_summary))
        return False


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

    st.log('API_NAME: verify_ip_route, API_ARGS: {}'.format(locals()))
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut))
    if cli_type == 'click':
        cli_type = 'vtysh'
    if cli_type in ['rest-patch', 'rest-put']:
        cli_type = 'klish'
#    cli_type = force_cli_type_to_klish(cli_type=cli_type)

    if cli_type in get_supported_ui_type_list():
        # Most likely there wont be any call without IP address, however being careful here
        if 'ip_address' not in kwargs:
            cli_type = 'klish'
        # no option to get these info using data_driven APIs
        if 'selected' in kwargs:
            cli_type = 'klish'
        if 'fib' in kwargs:
            cli_type = 'klish'
        # Forcing below line to klish due to defect 62149
        if 'nexthop' in kwargs and 'ffff' in kwargs['nexthop']:
            cli_type = 'klish'
        if cli_type == 'klish':
            st.log('Forcing cli_type to Klish, due to various limitation/defect')

    if cli_type in get_supported_ui_type_list():
        st.log('Cant fetch non-selected routes using GNMI/REST, so check if the route is selected using Klish')
        route_entries = fetch_ip_route(dut, family=family, vrf_name=vrf_name, match={'ip_address': kwargs['ip_address']}, cli_type='klish')
        nexthop_index = 1
        ecmp_count = 0
        for route_entry in route_entries:
            ecmp_count += 1
            if route_entry['selected'] != '>':
                cli_type = 'klish'
                st.log('Forcing cli_type to Klish, route is not selected')
                break
            '''if route_entry['nexthop'] == kwargs.get('nexthop'):
                nexthop_index = ecmp_count
                break'''
            # If route_entry is selected, compare other params like next_hop, interface, protocol type and
            # if all matches pick that route Index for gnmi GET call.
            valid_route = True
            for key in kwargs:
                if route_entry[key] != kwargs.get(key):
                    valid_route = False
                    break
            if valid_route:
                nexthop_index = ecmp_count
                break

    if cli_type in get_supported_ui_type_list():
        if 'ip_address' in kwargs:
            st.banner("Verify Route:{}".format(kwargs['ip_address']))

        filter_type = kwargs.get('filter_type', 'ALL')
        query_param_obj = utils.get_query_params(yang_data_type=filter_type, cli_type=cli_type)
        vrf_name = vrf_name if vrf_name else 'default'
        # for klish, testcase specifies vrf_name as "Vrf1 45.45.45.0/24", it fails in GNMI & REST
        vrf_name = vrf_name.split(" ")[0]
        ni_obj = umf_ni.NetworkInstance(Name=vrf_name)
        if family == 'ipv4':
            route_obj = umf_ni.Ipv4UnicastIpv4Entry(Prefix=kwargs['ip_address'], NetworkInstance=ni_obj)
        else:
            route_obj = umf_ni.Ipv6Entry(Prefix=kwargs['ip_address'], NetworkInstance=ni_obj)

        if 'distance' in kwargs:
            route_obj.Distance = kwargs['distance']
        if 'cost' in kwargs:
            route_obj.Metric = kwargs['cost']
        if 'type' in kwargs:
            route_type_map = {'C': 'DIRECTLY_CONNECTED', 'B': 'BGP', 'O': 'OSPF', 'S': 'STATIC', 'K': 'SYS_KERNEL'}
            route_obj.OriginProtocol = route_type_map[kwargs['type'].upper()]
        if 'duration' in kwargs:
            route_obj.Duration = kwargs['duration']
        if 'nexthop' in kwargs or 'interface' in kwargs:
            if family == 'ipv4':
                nh_obj = umf_ni.Ipv4EntryNextHop(Index=nexthop_index)
                if 'nexthop' in kwargs:
                    nh_obj.IpAddress = kwargs['nexthop']
                if 'interface' in kwargs:
                    nh_obj.Interface = kwargs['interface']
                route_obj.add_Ipv4EntryNextHop(nh_obj)
            else:
                nh_obj = umf_ni.Ipv6EntryNextHop(Index=nexthop_index)
                if 'nexthop' in kwargs:
                    nh_obj.IpAddress = kwargs['nexthop']
                if 'interface' in kwargs:
                    nh_obj.Interface = kwargs['interface']
                route_obj.add_Ipv6EntryNextHop(nh_obj)

        result = route_obj.verify(dut, match_subset=True, query_param=query_param_obj, cli_type=cli_type)
        if not result.ok():
            st.log('test_step_failed: Match Not Found: {}'.format(kwargs['ip_address']))
            return False
        return True

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
    if 'interface' in kwargs and cli_type == 'vtysh':
        kwargs['interface'] = get_intf_short_name(kwargs['interface'])
    if 'interface' in kwargs:
        if kwargs['interface'] == "eth0":
            kwargs['interface'] = "Management0"
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
                    st.log("No-Match: Match key {} NOT found, Expect:{} =>  Got:{}\nCurrent Route:{}\n".format(key, kwargs[key], rlist[key], rlist))

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
        result = show_ip_route(dut, family, shell, vrf_name, cli_type=cli_type)
    else:
        result = show_ip_route(dut, family, shell, vrf_name, cli_type=cli_type)
    entries = utils.filter_and_select(result, select, match)
    return entries


def increment_ip_addr(ipaddr, increment_type, family="ipv4"):
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
            if family == "ipv4":
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
    if not thread:
        return _clear_ip_configuration_helper(dut_list, family, cli_type, skip_error_check)
    out = st.exec_each(utils.make_list(dut_list), _clear_ip_configuration_helper,
                       family, cli_type=cli_type, skip_error_check=skip_error_check)[0]
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
            configure_loopback(dut, loopback_name=intf, config="no")
    return True


def clear_loopback_interfaces(dut_list, thread=True):
    """
    Find and delete all loopback interfaces.

    :param dut_list
    :return:
    """
    if not thread:
        return _clear_loopback_config_helper(dut_list)
    out = st.exec_each(utils.make_list(dut_list), _clear_loopback_config_helper)[0]
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


def fetch_ip_not_installed_summary(dut, vrf='default', version='ip', **kwargs):
    """
    :param dut:
    :param vrf:
    :param version:
    :param key:
    :return:
    """
    # cli_type = st.get_ui_type(dut, **kwargs)
    result = 0
    st.log("Check route not-installed summary on DUT {} for vrf {}".format(dut, vrf))
    key = kwargs.get('key', 'fib_total')
    cmd = "show {} route vrf {} not-installed summary".format(version, vrf)
    output = st.show(dut, cmd, type="klish")
    output = utils.filter_and_select(output, None, {u'vrf': vrf})
    if output[0]:
        output = output[0]
        if key in output.keys():
            result = int(output[key])
    else:
        st.error("Output is not proper; Received output is: {}".format(output))
    return result


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
        interface = st.get_other_names(dut, [interface])[0]

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
        interface = st.get_other_names(dut, [interface])[0]

    command = ''
    if family.lower() == "ipv4":
        command = "ip neigh del {} lladdr {} dev {}".format(neigh, mac, interface)
    elif family.lower() == "ipv6":
        command = "ip -6 neigh del {} lladdr {} dev {}".format(neigh, mac, interface)
    st.config(dut, command)


def traceroute(dut, addresses, family='ipv4', vrf_name=None, timeout=None, gateway=None, external=False, **kwargs):
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

    interface = kwargs.get('interface', '')
    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = "klish" if cli_type != 'click' else cli_type
    trace_route1 = r'(.*)\s+\(' + addresses + r'\)\s+(\d+\.\d+)\s+ms\s+(\d+\.\d+)\s+ms\s+(\d+\.\d+)\s+ms'
    trace_route2 = r'(\d+)\s+(' + addresses + r')\s+(\d+\.\d+)\s*ms\s+(\d+\.\d+)\s*ms\s+(\d+\.\d+)\s*ms'
    trace_route3 = r'(\d+)\s+(' + addresses.rstrip() + r')\s+\(' + addresses.rstrip() + r'\)\s+(\d+\.\d+)\s*ms\s+(\d+\.\d+)\s*ms\s+(\d+\.\d+)\s*ms'
    trace_route4 = r'(\d+)\s+(' + addresses.rstrip() + r'\%' + interface + r')\s+\(' + addresses.rstrip() + r'\%' + interface + r'\)\s+(\d+\.\d+)\s*ms\s+(\d+\.\d+)\s*ms\s+(\d+\.\d+)\s*ms'
    trace_route = r"{}|{}|{}|{}".format(trace_route1, trace_route2, trace_route3, trace_route4)
    if family == "ipv4":
        if is_valid_ipv6_address(addresses):
            family = "ipv6"
    if cli_type == "click":
        command = "traceroute -4 {}".format(addresses)
        if family.lower() == "ipv6":
            command = "traceroute -6 {}".format(addresses)
    if cli_type == "klish" or external:
        command = "traceroute {}".format(addresses)
        if family.lower() == "ipv6":
            command = "traceroute6 {}".format(addresses)
    if vrf_name:
        command = command + " -i {} ".format(vrf_name)
    if interface:
        command = command + " -i {} ".format(interface)
    if timeout:
        command = command + " -w {} ".format(timeout)
    if gateway:
        command = command + " -g {} ".format(gateway)

    if st.is_dry_run():
        return True

    if external:
        st.log(command)
        p = utils.process_popen(command)
        rv, err = p.communicate()
        st.log(rv)
        st.log(err)
    else:
        rv = st.config(dut, command, type=cli_type)
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
    :param :weight: set weight attribute
    :param :match_evpn_vni: match evpn vni
    :param :match_evpn_route_type: match evpn route-type
    :param :match_source_protocol: match source-protocol
    :param :local_preference: set local-preference
    :param :origin: set origin attribute
    :param :action: permit | deny <default is permit if arg is not passed>
    :EX: config_route_map(dut, route_map='rmap1', config='yes', sequence='10', community='100:100')
         config_route_map(dut, route_map='rmap1', config='no')
         config_route_map(dut, route_map='rmap1', config='yes', sequence='10', action="deny", weight="10")
         config_route_map(dut, route_map='rmap1', config='no', sequence='10',weight="100")
         config_route_map(dut, route_map='rmap1', sequence='20',weight="100")
    :Caution: while creating the route-map (config='yes'), sequence number must be mentioned and it should be
              the first parameter of the variable argument, because other arguments have newline appended.
    :return:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = "vtysh" if cli_type == 'click' else "klish"
    if config == 'yes':
        cmd = "route-map {}".format(route_map)
        if kwargs['sequence']:
            if 'action' in kwargs and kwargs['action'] == "deny":
                cmd += " deny {}".format(kwargs['sequence'])
            else:
                cmd += " permit {}".format(kwargs['sequence'])
        if 'metric' in kwargs:
            cmd += "\n set metric {}".format(kwargs['metric'])
        if 'community' in kwargs:
            cmd += "\n set community {}".format(kwargs['community'])
        if 'delcommunity' in kwargs:
            cmd += "\n no set community {}".format(kwargs['delcommunity'])
        if 'weight' in kwargs:
            cmd += "\n set weight {}".format(kwargs['weight'])
        if 'local_preference' in kwargs:
            cmd += "\n set local-preference {}".format(kwargs['local_preference'])
        if 'origin' in kwargs:
            cmd += "\n set origin {}".format(kwargs['origin'])
        if 'match_evpn_vni' in kwargs:
            cmd += "\n match evpn vni {}".format(kwargs['match_evpn_vni'])
        if 'match_evpn_route_type' in kwargs:
            cmd += "\n match evpn route-type {}".format(kwargs['match_evpn_route_type'])
        if 'match_source_protocol' in kwargs:
            cmd += "\n match source-protocol {}".format(kwargs['match_source_protocol'])
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
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut, **kwargs))
    if cli_type in get_supported_ui_type_list():
        config = 'yes' if config != 'no' else config
        static_ip = '{}/{}'.format(dest, dest_subnet)
        return create_static_route(dut, next_hop=next_hop, static_ip=static_ip, family=family, vrf=vrf_name, cli_type=cli_type, config=config)
    elif cli_type == 'click':
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


def create_static_route_nexthop_vrf(dut, next_hop=None, static_ip=None, shell="vtysh", family='ipv4', vrf_name="", nhopvrf="",
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
    interface = kwargs.get('interface')
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut, **kwargs))
    if cli_type in get_supported_ui_type_list():
        config = 'yes' if config != 'no' else config
        return create_static_route(dut, next_hop=next_hop, static_ip=static_ip, family=family, interface=interface, vrf=vrf_name, nexthop_vrf=nhopvrf, cli_type=cli_type, config=config)
    elif cli_type in ["klish", "rest-put", "rest-patch"]:
        if config == 'no':
            return delete_static_route(dut, next_hop=next_hop, static_ip=static_ip, family=family, interface=interface, vrf=vrf_name, nexthop_vrf=nhopvrf, cli_type=cli_type)
        else:
            return create_static_route(dut, next_hop=next_hop, static_ip=static_ip, family=family, interface=interface, vrf=vrf_name, nexthop_vrf=nhopvrf, cli_type=cli_type)

    if shell == "vtysh":
        if config == "no":
            command = "no "
        else:
            command = ""
        if family.lower() == "ipv4" or family.lower() == "":
            if vrf_name and nhopvrf:
                command += "ip route {} {} vrf {} nexthop-vrf {}".format(static_ip, next_hop, vrf_name, nhopvrf)
                st.config(dut, command, type='vtysh')
            if vrf_name and nhopvrf == "":
                command += "ip route {} {} vrf {}".format(static_ip, next_hop, vrf_name)
                st.config(dut, command, type='vtysh')
            if vrf_name == "" and nhopvrf:
                command += "ip route {} {} nexthop-vrf {}".format(static_ip, next_hop, nhopvrf)
                st.config(dut, command, type='vtysh')
            if vrf_name == "" and nhopvrf == "":
                command += "ip route {} {} ".format(static_ip, next_hop)
                st.config(dut, command, type='vtysh')

        elif family.lower() == "ipv6":
            if vrf_name and nhopvrf:
                command += "ipv6 route {} {} vrf {} nexthop-vrf {}".format(static_ip, next_hop, vrf_name, nhopvrf)
                st.config(dut, command, type='vtysh')
            if vrf_name and nhopvrf == "":
                command += "ipv6 route {} {} vrf {}".format(static_ip, next_hop, vrf_name)
                st.config(dut, command, type='vtysh')
            if vrf_name == "" and nhopvrf:
                command += "ipv6 route {} {} nexthop-vrf {}".format(static_ip, next_hop, nhopvrf)
                st.config(dut, command, type='vtysh')
            if vrf_name == "" and nhopvrf == "":
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
    if cli_type in get_supported_ui_type_list():
        action = 'ACCEPT_ROUTE' if operation == 'permit' else 'REJECT_ROUTE'
        rp_pd_obj = umf_rp.PolicyDefinition(Name=tag)
        if config.lower() == 'yes':
            operation = Operation.CREATE
            rp_rule_obj = umf_rp.Statement(StatementName=str(sequence), PolicyResult=action, PolicyDefinition=rp_pd_obj)
            rp_pd_obj.add_Statement(rp_rule_obj)
            result = rp_pd_obj.configure(dut, operation=operation, cli_type=cli_type)
        else:
            rp_rule_obj = umf_rp.Statement(StatementName=str(sequence), PolicyDefinition=rp_pd_obj)
            result = rp_rule_obj.unConfigure(dut, cli_type=cli_type)
        if not result.ok():
            st.log('test_step_failed: Configure Route Map {}'.format(result.data))
            return False
        return True
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


def config_route_map_match_ip_address(dut, tag, operation, sequence, value, family='ipv4', **kwargs):
    """
    :param dut:
    :param tag: route-map name
    :param operation: deny/permit
    :param sequence
    :param value: access_list / prefix-list/ prefix-len
    :return:
    """
    config = kwargs.get("config", "yes")
    mode = "no" if config == "no" else ""
    family = 'ip' if family == 'ipv4' else 'ipv6'
    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = 'vtysh' if cli_type in ['vtysh', 'click'] else cli_type
    community = kwargs.get('community', False)
    command = ''
    if cli_type in get_supported_ui_type_list() and config == 'no':
        # Forcing to klish till infra issue is fixed
        cli_type = 'klish'
    if not config_route_map_mode(dut, tag, operation, sequence, cli_type=cli_type):
        st.error("Route map mode configuration failed")
        return False
    if cli_type in get_supported_ui_type_list():
        rp_pd_obj = umf_rp.PolicyDefinition(Name=tag)
        rp_rule_obj = umf_rp.Statement(StatementName=str(sequence))
        if community:
            setattr(rp_rule_obj, 'CommunitySet', community)
        else:
            if family == 'ip':
                setattr(rp_rule_obj, 'PrefixSet', value)
                target_attr = getattr(rp_rule_obj, 'PrefixSet')
            else:
                setattr(rp_rule_obj, 'Ipv6PrefixSet', value)
                target_attr = getattr(rp_rule_obj, 'Ipv6PrefixSet')
        if config.lower() == 'yes':
            operation = Operation.CREATE
            rp_pd_obj.add_Statement(rp_rule_obj)
            result = rp_pd_obj.configure(dut, operation=operation, cli_type=cli_type)
        else:
            result = rp_rule_obj.unConfigure(dut, target_attr=target_attr, cli_type=cli_type)
        if not result.ok():
            st.log('test_step_failed: Configure Route Map Match {}'.format(result.data))
            return False
        return True

    if cli_type == 'vtysh':
        command += '{} match {} address {}\n'.format(mode, family, value)
        command += 'exit\n'
        st.config(dut, command, type=cli_type)
    elif cli_type == 'klish':
        if community:
            command += '{} match community {}\n'.format(mode, community)
            command += 'exit\n'
        else:
            command += '{} match {} address prefix-list {}\n'.format(mode, family, value)
            command += 'exit\n'
        st.config(dut, command, type=cli_type)
    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        url = rest_urls['match_prefix_set_config'].format(tag, sequence)
        if config == "yes":
            config_data = {"openconfig-routing-policy:config": {"prefix-set": str(value)}}
            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=config_data):
                st.error("Failed to configure route map match IP address")
                return False
        else:
            if not delete_rest(dut, rest_url=url):
                st.error("Failed to DELETE route map match IP address")
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
    if cli_type in get_supported_ui_type_list():
        operation = Operation.CREATE
        rp_pd_obj = umf_rp.PolicyDefinition(Name=tag)
        rp_rule_obj = umf_rp.Statement(StatementName=str(sequence), AsnList=str(value))
        rp_pd_obj.add_Statement(rp_rule_obj)
        result = rp_pd_obj.configure(dut, operation=operation, cli_type=cli_type)
        if not result.ok():
            st.log('test_step_failed: Configure Route Map Match {}'.format(result.data))
            return False
        return True

    if cli_type in ['klish']:
        command = "set as-path {} {}\n".format(option, value)
        command += "exit\n"
        st.config(dut, command, type=cli_type)
    elif cli_type in ['vtysh']:
        command = "set as-path {} {}\n".format(option, value.replace(",", " "))
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


def config_unconfig_interface_ip_addresses(dut, if_data_list=[], config='add', cli_type='', ip_type=''):
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
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    command = ''
    for if_data in if_data_list:
        if not if_data['name']:
            st.error("Please provide interface name in {} ".format(if_data))
            return False

        if not is_valid_ip_address(if_data['ip'], if_data['family'], if_data['subnet']):
            st.error("Invalid IP address or family or subnet {} ".format(if_data))
            return False

        if cli_type in get_supported_ui_type_list():
            kwargs = dict()
            kwargs['cli_type'] = cli_type
            kwargs['is_secondary_ip'] = 'yes' if ip_type == 'secondary' else 'no'
            result = config_ip_addr_interface(dut, interface_name=if_data['name'], ip_address=if_data['ip'], subnet=if_data['subnet'], family=if_data['family'], config=config, skip_error_check=True, **kwargs)
            if not result:
                return result

        elif cli_type == 'click':
            command += "sudo config interface ip {} {} {}/{} ; ".format(config,
                                                                        if_data['name'], if_data['ip'], if_data['subnet'])
        elif cli_type == 'klish':
            # config = '' if config == 'add' else 'no'
            family = 'ip' if if_data['family'] == 'ipv4' else 'ipv6'
            # if config == 'add':
            #     command += "interface {} \n {} address {}/{}\n".format(if_data['name'],family,if_data['ip'],if_data['subnet'])
            if config == 'add':
                intf = get_interface_number_from_name(if_data['name'])
                if ip_type == 'secondary':
                    command += "interface {} {} \n {} address {}/{} secondary \n".format(intf['type'], intf['number'], family, if_data['ip'], if_data['subnet'])
                else:
                    command += "interface {} {} \n {} address {}/{}\n".format(intf['type'], intf['number'], family, if_data['ip'], if_data['subnet'])
            # else:
            #     command += "interface {} \n no {} address {}/{}\n".format(if_data['name'],family,if_data['ip'],if_data['subnet'])
            else:
                intf = get_interface_number_from_name(if_data['name'])
                if ip_type == 'secondary':
                    command += "interface {} {}\n no {} address {}/{} secondary \n".format(intf['type'], intf['number'], family, if_data['ip'], if_data['subnet'])
                else:
                    command += "interface {} {}\n no {} address {}/{}\n".format(intf['type'], intf['number'], family, if_data['ip'], if_data['subnet'])
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
            output = st.config(dut, command, type=cli_type, conf=True, skip_error_check=True)
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

    def __init__(self, name, family='ipv4', cli_type=''):
        self.name = name
        self.description = ''
        self.family = family
        self.match_sequence = []
        self.cli_type = st.get_ui_type(cli_type=cli_type)
        self.cli_type = 'vtysh' if self.cli_type in ['click', 'vtysh'] else 'klish'
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

    def execute_command(self, dut, config='yes', cli_type=''):
        if config == 'no':
            command = self.unconfig_command_string()
        else:
            command = self.config_command_string()
        if self.cli_type == 'vtysh':
            st.config(dut, command, type='vtysh')
        elif self.cli_type == 'klish':
            output = st.config(dut, command, type='klish', conf=True)
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

    def add_match_permit_sequence(self, prefix, exact_match='false', rule_seq=None):
        if self.cli_type == 'klish':
            if not rule_seq:
                rule_seq = self.def_rule_seq
                self.def_rule_seq += 1
        self.match_sequence.append(('permit', prefix, exact_match, rule_seq))

    def add_match_deny_sequence(self, prefix, exact_match='false', rule_seq=None):
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
    if cli_type == 'click':
        interface = get_intf_short_name(interface)
    cli_type = 'klish' if cli_type in ['rest-patch', 'rest-put', 'vtysh'] else cli_type
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    output = get_interface_ip_address(dut, interface, family="ipv6", cli_type=cli_type)
    ipv6_list = utils.dicts_list_values(output, 'ipaddr')
    st.log("{} IPV6 LIST: {}".format(interface, ipv6_list), dut=dut)
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

    if cli_type in get_supported_ui_type_list():
        state = True if action == 'enable' else False
        port_hash_list = segregate_intf_list_type(intf=interfaces, range_format=False)
        interfaces = port_hash_list['intf_list_all']
        for interface in interfaces:
            index = get_subinterface_index(dut, interface)
            interface = get_phy_port(interface)
            intf_obj = umf_intf.Interface(Name=interface)
            sub_intf_obj = umf_intf.Subinterface(Index=int(index), SubIntfIpv6Enabled=state, Interface=intf_obj)
            result = sub_intf_obj.configure(dut, cli_type=cli_type, timeout=time_out)
            if not result.ok():
                st.log('test_step_failed: Config of link-local {}'.format(result.data))
                return False
    elif cli_type == 'click':
        port_hash_list = segregate_intf_list_type(intf=interfaces, range_format=False)
        interfaces = port_hash_list['intf_list_all']
        for interface in interfaces:
            if not interface:
                st.error("Please provide interface name in {} ".format(interface))
                return False
            command += "sudo config interface ipv6 {} use-link-local-only {} ; ".format(action, interface)
    elif cli_type == 'klish':
        command = list()
        port_hash_list = segregate_intf_list_type(intf=interfaces, range_format=True)
        interfaces = port_hash_list['intf_list_all']
        for interface in interfaces:
            if not is_a_single_intf(interface):
                command.append("interface range {}".format(interface))
            else:
                if not interface:
                    st.error("Please provide interface name in {} ".format(interface))
                    return False
                intf = get_interface_number_from_name(interface)
                command.append('interface {} {}'.format(intf["type"], intf["number"]))
            command.append('ipv6 enable' if action.lower() == 'enable' else 'no ipv6 enable')
            command.append('exit')
    elif cli_type in ['rest-patch', 'rest-put']:
        state = True if action == 'enable' else False
        rest_urls = st.get_datastore(dut, 'rest_urls')
        port_hash_list = segregate_intf_list_type(intf=interfaces, range_format=False)
        interfaces = port_hash_list['intf_list_all']
        for interface in interfaces:
            index = get_subinterface_index(dut, interface)
            interface = get_phy_port(interface)
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
    else:
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

        if cli_type in get_supported_ui_type_list():
            kwargs = dict()
            kwargs['cli_type'] = cli_type
            kwargs['is_secondary_ip'] = 'no'
            result = config_ip_addr_interface(dut, interface_name=if_data['name'], ip_address=if_data['ip'], subnet=if_data['subnet'], family=if_data['family'], config=config, skip_error_check=True, **kwargs)
            if not result:
                return result
        elif cli_type == 'click':
            cmd_str = "sudo config interface ip {} {} {}/{} ".format(config,
                                                                     if_data['name'], if_data['ip'], if_data['subnet'])
            command.append(cmd_str)
        elif cli_type == 'klish':
            intf_info = get_interface_number_from_name(if_data['name'])
            cmd_str = 'interface {} {}'.format(intf_info["type"], intf_info["number"])
            command.append(cmd_str)
            cmd_str = "no " if config == 'remove' else ''
            cmd_str += "ip address {}/{}".format(if_data['ip'], if_data['subnet'])
            command.append(cmd_str)
            command.append('exit')
        elif cli_type in ['rest-patch', 'rest-put']:
            st.error("Spytest API not yet supported for REST type")
            return False

    if cli_type in ['click', 'klish']:
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
    family = kwargs.get("family", "ipv4")
    action = kwargs.get("action", "add")
    interface = kwargs.get("interface", None)
    loop_back = kwargs.get("loop_back", None)
    skip_error = kwargs.get('skip_error', False)
    intf_name = get_interface_number_from_name(interface)
    if cli_type in get_supported_ui_type_list():
        index = get_subinterface_index(dut, interface)
        if not index:
            st.error("Failed to get index for interface: {}".format(interface))
            index = 0
        intf_name = get_phy_port(interface)
        intf_obj = umf_intf.Interface(Name=intf_name)
        if 'Vlan' in intf_name:
            # Enabled attribute is not valid - defect fix 74996
            # intf_obj.VlanIpv4UnNumEnabled = True
            intf_obj.Ipv4Interface = loop_back
            intf_obj.Ipv4Subinterface = int(index)
            target_attr = intf_obj.Ipv4Interface
        else:
            sub_intf_obj = umf_intf.Subinterface(Index=int(index))
            # Enabled attribute is not valid - defect fix 74996
            # sub_intf_obj.SubIntfIpv4UnNumEnabled = True
            sub_intf_obj.RefLoopbackIntf = loop_back
            sub_intf_obj.Subinterface = 0
            intf_obj.add_Subinterface(sub_intf_obj)
            target_attr = sub_intf_obj.RefLoopbackIntf
        if action == 'add':
            result = intf_obj.configure(dut, cli_type=cli_type, timeout=time_out)
        else:
            if 'Vlan' in intf_name:
                result = intf_obj.unConfigure(dut, target_attr=target_attr, cli_type=cli_type, timeout=time_out)
            else:
                result = sub_intf_obj.unConfigure(dut, target_attr=target_attr, cli_type=cli_type, timeout=time_out)
        if not result.ok():
            st.log('test_step_failed: Configuring Unnumbered intf {}'.format(result.data))
            return False
        elif result.ok() and skip_error:
            st.log('Negative Scenario: Error/Exception is expected')
            return True
        return True

    if cli_type == "click":
        commands = list()
        if action not in ["add", "del"]:
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
            intf_name = get_interface_number_from_name(interface)
            command = "interface {} {}".format(intf_name["type"], intf_name["number"])
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
            interface = get_phy_port(interface)
            if action == 'add':
                url = rest_urls['ipv4_unnumbered_interface_config'].format(interface, index)
                config_data = {"openconfig-if-ip:config": {"interface": loop_back}}
                rest_response = config_rest(dut, http_method=cli_type, rest_url=url, json_data=config_data, timeout=100)
                if not rest_response:
                    if skip_error:
                        st.log("Skipping the error as skip_error=True")
                        return True
                    else:
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
        try:
            output = st.config(dut, commands, skip_error_check=skip_error, type=cli_type)
            if skip_error and 'Error' in output:
                return False
        except Exception as e:
            st.log(e)
            return False
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
                    value[1][attr] = value[1][attr] if value[1][attr] else ""
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
    config = kwargs.get('config', '')
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
        st.config(dut, command, type=cli_type, skip_error_check=skip_error_check)
    elif cli_type == 'klish':
        if seq_num != '':
            command += "{} {} prefix-list {} seq {} {} {}".format(config, ip_cmd, prefix_list, seq_num, action, ip_address)
        else:
            command += "{} {} prefix-list {} {} {}".format(config, ip_cmd, prefix_list, action, ip_address)
        st.config(dut, command, type=cli_type, skip_error_check=skip_error_check)
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
    st.exec_each(utils.make_list(dut), st.config, "sudo route -n")


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
    skip_error = kwargs.get("skip_error", False)
    if config == 'yes':
        msg = "Config"
    elif config == 'no':
        msg = "Unconfig"
    else:
        st.error("Invalid config type {}".format(config))
        return False
    if not st.is_feature_supported("config-loopback-add-command", dut):
        st.warn("build doesn't need Loopback interface {}uration".format(msg), dut=dut)
        return True
    if cli_type in get_supported_ui_type_list():
        operation = Operation.CREATE
        for intf in loopback_interface:
            intf_obj = umf_intf.Interface(Name=intf)
            if config == 'yes':
                result = intf_obj.configure(dut, operation=operation, cli_type=cli_type, timeout=time_out)
                msg = "Configuring"
            elif config == 'no':
                # result = intf_obj.unConfigure(dut, target_attr=intf_obj.Name, cli_type=cli_type)
                result = intf_obj.unConfigure(dut, cli_type=cli_type, timeout=time_out)
                msg = "Un Configuring"
            if not result.ok():
                st.log('test_step_failed: {} Loopback Interface {}'.format(msg, result.data))
                return False
    elif cli_type == 'click':
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
        output = st.config(dut, cmds, skip_error_check=skip_error, type="klish", conf=True)
        if "Could not connect to Management REST Server" in output:
            st.error("klish mode not working.")
            return False
        if "cannot be deleted, Vxlan is configured" in output:
            st.error("Loopback can not be deleted as present under VxLAN interface")
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
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut, **kwargs))
    skip_error = kwargs.pop('skip_error', False)
    if cli_type in get_supported_ui_type_list():
        sla_type = 'icmp' if 'icmp' in sla_type.lower() else 'tcp'
        ipsla_obj = umf_ipsla.IpSla(IpSlaId=int(sla_num))
        if dst_ip != '':
            kwargs['dst_ip'] = dst_ip
        if sla_type == 'tcp':
            ipsla_attr_list = {
                'frequency': ['Frequency', int(kwargs['frequency']) if 'frequency' in kwargs else None],
                'threshold': ['Threshold', int(kwargs['threshold']) if 'threshold' in kwargs else None],
                'timeout': ['Timeout', int(kwargs['timeout']) if 'timeout' in kwargs else None],
                'tcp_port': ['TcpDstPort', int(kwargs['tcp_port']) if 'tcp_port' in kwargs else None],
                'src_port': ['TcpSourcePort', int(kwargs['src_port']) if 'src_port' in kwargs else None],
                'vrf_name': ['TcpVrf', kwargs['vrf_name'] if 'vrf_name' in kwargs and kwargs['vrf_name'] != 'default' else None],
                'src_addr': ['TcpSourceIp', kwargs['src_addr'] if 'src_addr' in kwargs else None],
                'dst_ip': ['TcpDstIp', kwargs['dst_ip'] if 'dst_ip' in kwargs else None],
                'src_intf': ['TcpSourceInterface', kwargs['src_intf'] if 'src_intf' in kwargs else None],
                'tos': ['TcpTos', int(kwargs['tos']) if 'tos' in kwargs else None],
                'ttl': ['TcpTtl', int(kwargs['ttl']) if 'ttl' in kwargs else None],
            }
        if sla_type == 'icmp':
            ipsla_attr_list = {
                'frequency': ['Frequency', int(kwargs['frequency']) if 'frequency' in kwargs else None],
                'threshold': ['Threshold', int(kwargs['threshold']) if 'threshold' in kwargs else None],
                'timeout': ['Timeout', int(kwargs['timeout']) if 'timeout' in kwargs else None],
                'vrf_name': ['IcmpVrf', kwargs['vrf_name'] if 'vrf_name' in kwargs and kwargs['vrf_name'] != 'default' else None],
                'src_addr': ['IcmpSourceIp', kwargs['src_addr'] if 'src_addr' in kwargs else None],
                'dst_ip': ['IcmpDstIp', kwargs['dst_ip'] if 'dst_ip' in kwargs else None],
                'src_intf': ['IcmpSourceInterface', kwargs['src_intf'] if 'src_intf' in kwargs else None],
                'tos': ['IcmpTos', int(kwargs['tos']) if 'tos' in kwargs else None],
                'ttl': ['IcmpTtl', int(kwargs['ttl']) if 'ttl' in kwargs else None],
                'data_size': ['IcmpSize', int(kwargs['data_size']) if 'data_size' in kwargs else None],
            }

        if config == 'yes':
            operation = Operation.CREATE
            ipsla_obj.Enabled = True
            for key, attr_value in ipsla_attr_list.items():
                if key in kwargs and attr_value[1] is not None:
                    setattr(ipsla_obj, attr_value[0], attr_value[1])
            result = ipsla_obj.configure(dut, operation=operation, cli_type=cli_type)
            if not result.ok():
                st.log('test_step_failed: Config IP SLA {}'.format(result.data))
                return False
        else:
            if 'sla_num' in kwargs['del_cmd_list']:
                result = ipsla_obj.unConfigure(dut, cli_type=cli_type)
                if not result.ok():
                    st.log('test_step_failed: Config IP SLA {}'.format(result.data))
                    return False
            else:
                if 'sla_type' in kwargs['del_cmd_list']:
                    target_attr = ipsla_obj.TcpDstIp if sla_type == 'tcp' else ipsla_obj.IcmpDstIp
                    result = ipsla_obj.unConfigure(dut, target_attr=target_attr, cli_type=cli_type)
                    if not result.ok():
                        st.log('test_step_failed: Config IP SLA {}'.format(result.data))
                        return False
                    if 'dst_port' in kwargs['del_cmd_list']:
                        result = ipsla_obj.unConfigure(dut, target_attr=ipsla_obj.TcpDstPort, cli_type=cli_type)
                        if not result.ok():
                            st.log('test_step_failed: Config IP SLA {}'.format(result.data))
                            return False
                else:
                    del_cmd_list = kwargs['del_cmd_list']
                    for key, attr_value in ipsla_attr_list.items():
                        if key in del_cmd_list:
                            target_attr = getattr(ipsla_obj, attr_value[0])
                            result = ipsla_obj.unConfigure(dut, target_attr=target_attr, cli_type=cli_type)
                            if not result.ok():
                                st.log('test_step_failed: Config IP SLA {}'.format(result.data))
                                return False

        return True

    elif cli_type == "click" or cli_type == 'klish':
        if config == 'yes':
            cmd = "ip sla {} \n {} {}".format(sla_num, sla_type, dst_ip)
            if "tcp_port" in kwargs:
                cmd += " port {}".format(kwargs["tcp_port"])
            if "vrf_name" in kwargs:
                if kwargs["vrf_name"] != 'default':
                    cmd += "\n source-vrf {}".format(kwargs["vrf_name"])
            if "src_addr" in kwargs:
                cmd += "\n source-address {}".format(kwargs["src_addr"])
            if "src_intf" in kwargs:
                if cli_type == 'klish':
                    # src_intf = get_interface_number_from_name(kwargs["src_intf"])
                    # cmd += "\n source-interface {} {}".format(src_intf['type'],src_intf['number'])
                    cmd += "\n source-interface {}".format(kwargs['src_intf'])
                else:
                    kwargs['src_intf'] = get_intf_short_name(kwargs['src_intf'])
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
                    cmd += "\n {} {}".format(sla_type, dst_ip)
                    if "tcp_port" in kwargs:
                        cmd += " port {}".format(kwargs["tcp_port"])
                    sla_type_level = True
                    del_cmd_list = kwargs["del_cmd_list"]
                    if len(del_cmd_list) > 0:
                        if "vrf_name" in del_cmd_list:
                            cmd += "\n no source-vrf"
                            sla_type_level = True
                        if "src_addr" in del_cmd_list:
                            cmd += "\n no source-address"
                            sla_type_level = True
                        if "src_intf" in del_cmd_list:
                            cmd += "\n no source-interface"
                            sla_type_level = True
                        if "data_size" in del_cmd_list:
                            cmd += "\n no request-data-size"
                            sla_type_level = True
                        if "src_port" in del_cmd_list:
                            cmd += "\n no source-port"
                            sla_type_level = True
                        if "tos" in del_cmd_list:
                            cmd += "\n no tos"
                            sla_type_level = True
                        if 'ttl' in del_cmd_list:
                            cmd += "\n no ttl"
                            sla_type_level = True
                        if 'frequency' in del_cmd_list:
                            if sla_type_level:
                                cmd += '\n exit'
                            cmd += '\n no frequency'
                            sla_type_level = False
                        if 'threshold' in del_cmd_list:
                            if sla_type_level:
                                cmd += '\n exit'
                            cmd += '\n no threshold'
                            sla_type_level = False
                        if 'timeout' in del_cmd_list:
                            if sla_type_level:
                                cmd += '\n exit'
                            cmd += '\n no timeout'
                            sla_type_level = False
                    cmd += "\n exit\n exit" if sla_type_level else '\n exit'

        if cli_type == 'click':
            st.config(dut, cmd, type="vtysh", skip_error_check=skip_error)
        else:
            st.config(dut, cmd, type="klish", skip_error_check=skip_error)
        return
    elif cli_type in ['rest-put', 'rest-patch']:
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
            response = config_rest(dut, http_method=cli_type, rest_url=base_url, json_data=ocdata)
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


def verify_ip_sla(dut, inst, **kwargs):
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
    yang_data_type = kwargs.get("yang_data_type", "ALL")
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut, **kwargs))
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    id_list = list(map(str, inst)) if isinstance(inst, list) else [inst]
    if cli_type == "click":
        cli_type = "vtysh"
    if cli_type in get_supported_ui_type_list():
        for sla_inst in id_list:
            ipsla_obj = umf_ipsla.IpSla(IpSlaId=int(sla_inst))
            if cli_type in cli_type_for_get_mode_filtering():
                query_params_obj = utils.get_query_params(yang_data_type=yang_data_type, cli_type=cli_type)
                rv = ipsla_obj.get_payload(dut, query_param=query_params_obj, cli_type=cli_type)
            else:
                rv = ipsla_obj.get_payload(dut, cli_type=cli_type)
            if rv.ok():
                if rv.payload:
                    output = dict()
                    output["ip-sla"] = rv.payload.get("openconfig-ip-sla:ip-sla")
                    cli_out = convert_sla_rest_output(output, parse_type='summary')
                else:
                    st.debug("Rcvd empty payload as response")
                    return False
            else:
                st.debug("Data not found for sla instance - {} using gNMI".format(sla_inst))
                return False
    elif cli_type in ['rest-put', 'rest-patch']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        rest_url = rest_urls['show_ip_sla']
        output = get_rest(dut, rest_url=rest_url)['output']['openconfig-ip-sla:ip-slas']
        cli_out = convert_sla_rest_output(output, parse_type='summary')
    else:
        cli_out = st.show(dut, "show ip sla", type=cli_type)
    if "return_output" in kwargs:
        return cli_out
    id_len = len(id_list)
    for key, value in kwargs.items():
        if len(value) != id_len:
            st.error("Number of elements in each parameter list need to match.")
            return False
    for i in range(len(id_list)):
        fil_out = utils.filter_and_select(cli_out, kwargs.keys(), {"inst": id_list[i]})
        if not fil_out:
            st.error("No entry found for SLA instance: {} in output: {}".format(id_list[i], cli_out))
            return False
        else:
            fil_out = fil_out[0]

            for key, val in kwargs.items():
                if str(fil_out[key]) != str(val[i]):
                    success = False
                    st.error("MATCH NOT found for key \"{}\"; expected: {} but found {}".format(key, val[i], fil_out[key]))
    return True if success else False


def verify_ip_sla_inst(dut, inst, **kwargs):
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

    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut, **kwargs))
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    yang_data_type = kwargs.get("yang_data_type", "ALL")
    if cli_type == "click":
        cli_type = "vtysh"
    if cli_type in get_supported_ui_type_list():
        ipsla_obj = umf_ipsla.IpSla(IpSlaId=int(inst))
        if cli_type in cli_type_for_get_mode_filtering():
            query_params_obj = utils.get_query_params(yang_data_type=yang_data_type, cli_type=cli_type)
            rv = ipsla_obj.get_payload(dut, query_param=query_params_obj, cli_type=cli_type)
        else:
            rv = ipsla_obj.get_payload(dut, cli_type=cli_type)
        if rv.ok():
            if rv.payload:
                output = dict()
                output["ip-sla"] = rv.payload.get("openconfig-ip-sla:ip-sla")
                cli_out = convert_sla_rest_output(output, parse_type='inst')
            else:
                st.debug("Rcvd empty payload as response")
                return False
        else:
            st.debug("Data not found for sla instance - {} using gNMI".format(inst))
            return False
    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        rest_url = rest_urls['show_ip_sla_inst'].format(inst)
        output = get_rest(dut, rest_url=rest_url)['output']['openconfig-ip-sla:ip-sla']
        cli_out = convert_sla_rest_output(output, parse_type='inst')
    else:
        cmd = "show ip sla {}".format(inst)
        cli_out = st.show(dut, cmd, type=cli_type)
    st.log(cli_out)
    if "return_output" in kwargs:
        return cli_out
    fil_out = utils.filter_and_select(cli_out, kwargs.keys(), {"inst": inst})
    if not fil_out:
        st.error("No entry found for SLA instance: {} in output: {}".format(inst, cli_out))
        return False
    else:
        if cli_type == 'vtysh' and 'src_intf' in kwargs:
            kwargs['src_intf'] = get_intf_short_name(kwargs['src_intf'])
        fil_out = fil_out[0]
        for key, val in kwargs.items():
            if str(fil_out[key]) == str(val):
                st.log("MATCH found for key \"{}\"; expected: {}; found {}".format(key, val, fil_out[key]))
            else:
                success = False
                st.error("MATCH NOT found for key \"{}\"; expected: {} but found {}".format(key, val, fil_out[key]))
    return True if success else False


def verify_ip_sla_history(dut, inst, **kwargs):
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

    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut, **kwargs))
    cli_type = force_cli_type_to_klish(cli_type=cli_type)

    if cli_type == "click":
        cli_type = "vtysh"

    if cli_type not in ['rest-patch', 'rest-put']:
        cli_out = st.show(dut, "show ip sla {} history".format(inst), type=cli_type)
    else:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        rest_url = rest_urls['show_ip_sla_history']
        ocdata = {"openconfig-ip-sla:input": {"ip-sla-id": inst}}
        output = config_rest(dut, rest_url=rest_url, http_method='post', json_data=ocdata, get_response=True)['output']
        cli_out = convert_sla_rest_output(output, parse_type='history')

    if "return_output" in kwargs:
        return cli_out
    if len(cli_out) == 0:
        st.error("Output is Empty")
        return False
    verify_sequence = kwargs.pop('verify_sequence', False)
    if verify_sequence:
        event = kwargs.pop('event', None)
        expected_sequence = [event] if isinstance(event, str) else list(event)
        # Sort output based on timestamp
        # Fri Jul 10 11:35:21 2020
        sorted_output = sorted(cli_out, key=lambda x: time.strptime(x['event_time'], '%a %b %d %H:%M:%S %Y'))
        actual_sequence = [out['event'].rstrip() for out in sorted_output]
        if set(actual_sequence) != set(expected_sequence):
            st.error("FAIL: SLA history Mismatch: Expected-{} Actual- {}".format(expected_sequence, actual_sequence))
            return False
    else:
        for item in cli_out:
            item['event'] = str(item['event']).rstrip()
        entries = utils.filter_and_select(cli_out, kwargs.keys(), match={'event': kwargs['event']})
        if entries:
            for key in kwargs.keys():
                if str(kwargs[key]) != str(entries[0][key]).rstrip():
                    success = False
                    st.error("MATCH NOT found for key \"{}\"; expected: {} but found {}".format(key, kwargs[key], cli_out[0][key]))
        else:
            st.error("Event {} not found in SLA history".format(kwargs['event']))
            success = False
    return True if success else False


def clear_ip_sla(dut, **kwargs):
    """
    :param dut:
    :param inst:
    :return:
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut, **kwargs))
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    inst = kwargs.pop('inst', 'all')
    cmd = 'clear ip sla {}'.format(inst)
    if cli_type == 'click':
        st.config(dut, cmd, type='vtysh', conf=False)
    elif cli_type == 'klish':
        st.config(dut, cmd, type='klish', conf=False)
    elif cli_type in ['rest-put', 'rest-patch']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        rest_url = rest_urls['clear_ip_sla']
        ocdata = {"sonic-ip-sla:input": {"ip_sla_id": inst}}
        response = config_rest(dut, http_method='post', rest_url=rest_url, json_data=ocdata)
        if not response:
            return False


def convert_sla_rest_output(output, parse_type='sla_summary'):
    transformed_output_list = []
    if 'summary' in parse_type:
        for item in output['ip-sla']:
            transformed_output = {}
            transformed_output['inst'] = item.pop('ip-sla-id', '')
            if 'icmp-dst-ip' in item['config'].keys():
                transformed_output['type'] = 'ICMP-echo'
                type_str = 'icmp'
                add_port_str = ''
            else:
                transformed_output['type'] = 'TCP-connect'
                type_str = 'tcp'
                tcp_dst_port = item.get('state', {}).get('tcp-dst-port', '')
                add_port_str = '({})'.format(tcp_dst_port)
            transformed_output['target'] = item.get('state', {}).get('{}-dst-ip'.format(type_str)) + add_port_str
            transformed_output['vrf_name'] = item.get('state', {}).get('{}-vrf'.format(type_str), 'default')
            state = item.get('state', {}).get('{}-operation-state'.format(type_str), 'OPER_UP')
            transformed_output['state'] = 'Up' if 'OPER_UP' in state else 'Down'
            transformed_output['transitions'] = item.get('state', {}).get('transition-count', '')
            transformed_output['last_chg'] = (item.get('state', {}).get('timestamp', '').strip(r'\s*ago')).rstrip()
            transformed_output_list.append(transformed_output)
    elif 'inst' in parse_type:
        for item in output:
            transformed_output = {}
            transformed_output['inst'] = item.get('ip-sla-id', '')
            if transformed_output['inst'] == '':
                return transformed_output_list
            if 'icmp-dst-ip' in item['config'].keys():
                transformed_output['type'] = 'ICMP-echo'
                transformed_output['icmp_req_cnt'] = item.get('state', {}).get('icmp-echo-req-counter', '')
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
                transformed_output['type'] = 'TCP-connect'
                transformed_output['dst_port'] = item.get('state', {}).get('tcp-dst-port', '')
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
                state = 'Down'
                key_list = ['icmp_req_cnt', 'icmp_succ_cnt', 'icmp_err_cnt', 'icmp_size', 'dst_addr', 'vrf_name', 'src_addr', 'src_intf',
                            'src_port', 'dst_port', 'tcp_req_cnt', 'tcp_succ_cnt', 'tcp_err_cnt', 'ttl', 'tos']
                for key in key_list:
                    transformed_output[key] = ''

            transformed_output['freq'] = item.get('state', {}).get('frequency', '')
            transformed_output['threshold'] = item.get('state', {}).get('threshold', '')
            transformed_output['timeout'] = item.get('state', {}).get('timeout', '')
            transformed_output['oper_state'] = 'Up' if 'OPER_UP' in state else 'Down'
            transformed_output['tx_cnt'] = item.get('state', {}).get('transition-count', '')
            transformed_output['last_chg'] = (item.get('state', {}).get('timestamp', '').strip(r'\s*ago')).rstrip()
            transformed_output_list.append(transformed_output)
    else:
        new_output = output.get('sonic-ip-sla:output', {}).get('IPSLA_HISTORY', [])
        for item in new_output:
            transformed_output = {}
            transformed_output['event'] = item.get('event', '')
            transformed_output['event_time'] = item.get('timestamp', '')
            transformed_output_list.append(transformed_output)
    return transformed_output_list


def _clear_ipsla_configuration_helper(dut_list, cli_type=''):
    """
    Fidn and clear IP SLA configuration in DUT
    """
    dut_li = list(dut_list) if isinstance(dut_list, list) else [dut_list]
    cli_type = st.get_ui_type(dut_li[0], cli_type=cli_type)
    cli_type = force_cli_type_to_klish(cli_type=cli_type)

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
    if not thread:
        return _clear_ipsla_configuration_helper(dut_list, cli_type=cli_type)
    out = st.exec_each(utils.make_list(dut_list), _clear_ipsla_configuration_helper, cli_type=cli_type)[0]
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

    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut, **kwargs))
    cli_type = "vtysh" if cli_type == 'click' else "klish"

    output = show_ip_route(dut, family=family, vrf_name=vrf_name, cli_type=cli_type)
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
                if key == 'interface' and cli_type == 'vtysh':
                    kwargs[key] = [get_intf_short_name(item) for item in kwargs[key]]
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


def config_ip_reserve(dut, **kwargs):
    """
    Author: Sunil Rajendra (sunil.rajendra@broadcom.com)
    :param dut:
    :param kwargs:
    :return:
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut))
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    skiperr = kwargs.pop('skip_error', False)
    my_cmd = ''
    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = 'yes'
    if config.lower() == 'yes':
        config_cmd = ''
    else:
        config_cmd = 'no'
    if cli_type == 'klish':
        if 'local_neigh' in kwargs:
            local_neigh = kwargs['local_neigh'] if config_cmd == '' else ''
            my_cmd += '{} ip reserve local-neigh {} \n'.format(config_cmd, local_neigh)
            out = st.config(dut, my_cmd, type=cli_type, skip_error_check=skiperr)
            if '%Error:' in out:
                return False
            return True
    else:
        st.log("Unsupported CLI TYPE - {}".format(cli_type))
        return False


def config_system_max_routes(dut, **kwargs):
    """
    Author: Sooriya.Gajendrababu@broadcom.com
    :param dut:
    :param kwargs:
    :return:
    res=ip_api.config_system_max_routes(dut, hosts=True)
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut))
    skiperr = kwargs.pop('skip_error', False)
    my_cmd = ''
    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = 'yes'
    if config.lower() == 'yes':
        config_cmd = ''
    else:
        config_cmd = 'no'

    if cli_type in get_supported_ui_type_list():
        attr_map = {'hosts': 'Hosts', 'route_count': 'Routes'}
        hosts_val_map = {'layer2-layer3-balanced': 'L2_L3_BALANCED', 'layer2-layer3': 'L2_L3', 'default': 'DEFAULT'}
        routes_val_map = {'max': 'MAX', 'max-v6': 'MAX_V6', 'default': 'DEFAULT'}
        # config_value = 'L2_L3_BALANCED' if config == 'yes' else 'DEFAULT'
        resource_obj = umf_system.Resource(Name='ROUTE_SCALE')
        keys = []
        vals = []
        if 'hosts' in kwargs:
            keys.append('hosts')
            val = hosts_val_map[kwargs['hosts']]
            val = val if config == 'yes' else 'DEFAULT'
            vals.append(val)
        if 'route_count' in kwargs:
            keys.append('route_count')
            val = routes_val_map[kwargs['route_count']]
            val = val if config == 'yes' else 'DEFAULT'
            vals.append(val)
        for key, val in zip(keys, vals):
            setattr(resource_obj, attr_map[key], val)
        if config == 'yes':
            result = resource_obj.configure(dut, operation=Operation.CREATE, cli_type=cli_type)
        else:
            result = resource_obj.unConfigure(dut, cli_type=cli_type)
        if not result.ok():
            st.log('test_step_failed: Configure route-scale Hosts')
            return False
        return True

    if cli_type == 'klish' or cli_type == 'click':
        if 'route_count' in kwargs:
            my_cmd += 'switch-resource \n'
            my_cmd += '{} route-scale routes {} \n exit'.format(config_cmd, kwargs['route_count'])
            st.config(dut, my_cmd, type='klish')
        if 'hosts' in kwargs:
            host_type = kwargs['hosts']
            host_type = '' if config_cmd == 'no' else host_type
            my_cmd += 'switch-resource \n'
            my_cmd += '{} route-scale hosts {} \n exit'.format(config_cmd, host_type)
            out = st.config(dut, my_cmd, type=cli_type, skip_error_check=skiperr)
            if '%Error:' in out:
                return False
            return True
    else:
        st.log("Unsupported CLI TYPE - {}".format(cli_type))
        return False


def verify_switch_resource_route_scale(dut, **kwargs):
    """
    Verify the output of 'show switch-resource route-scale'.
    Author: Sunil Rajendra (sunil.rajendra@broadcom.com)
    :param dut:
    :param hosts: hosts='layer2-layer3-balanced'
    :param :cli_type:
    :param :skip_error:
    :param :skip_template:
    :return:
    res=ip_api.verify_switch_resource_route_scale(dut, hosts='layer2-layer3-balanced')
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut, **kwargs))
    if 'hosts' not in kwargs:
        cli_type = cli_type if cli_type not in ["rest-patch", "rest-put", "click"] else "klish"
        cli_type = force_cli_type_to_klish(cli_type=cli_type)
    skip_error = kwargs.get('skip_error', False)
    skip_template = kwargs.get('skip_template', False)
    return_output = kwargs.pop('return_output', False)
    return_flag = True

    if cli_type in get_supported_ui_type_list():
        filter_type = kwargs.get('filter_type', 'ALL')
        query_param_obj = utils.get_query_params(yang_data_type=filter_type, cli_type=cli_type)
        val_map = {'layer2-layer3-balanced': 'L2_L3_BALANCED', 'layer2-layer3': 'L2_L3', 'default': 'DEFAULT', '': 'DEFAULT'}
        out_map = {'L2_L3_BALANCED': 'layer2-layer3-balanced', 'L2_L3': 'layer2-layer3', 'DEFAULT': 'default'}
        resource_obj = umf_system.Resource(Name='ROUTE_SCALE')
        if 'hosts' in kwargs:
            host_val = kwargs['hosts']
            if host_val in val_map.keys():
                host_val = val_map[host_val]
            setattr(resource_obj, 'Hosts', host_val)
            st.log('***IETF_JSON***: {}'.format(resource_obj.get_ietf_json()))
            result = resource_obj.verify(dut, match_subset=True, query_param=query_param_obj, cli_type=cli_type)
            if return_output:
                output = []
                if result.payload and 'openconfig-system-ext:resource' in result.payload:
                    if 'config' in result.payload['openconfig-system-ext:resource'][0]:
                        if 'hosts' in result.payload['openconfig-system-ext:resource'][0]['config']:
                            out_val = result.payload['openconfig-system-ext:resource'][0]['config']['hosts']
                            if out_val in out_map:
                                out_val = out_map[out_val]
                            output = [{'hosts': out_val}]
                return output
            if not result.ok():
                st.log('test_step_failed: Verify route-scale Hosts: result={}.'.format(result.data))
                return_flag = False
        return return_flag
    elif cli_type == 'click':
        st.error("CLI not supported in CLICK. Supported only in KLISH.")
        return False
    elif cli_type == 'klish':
        command = "show switch-resource route-scale"
        output = st.show(dut, command, type=cli_type, skip_error_check=skip_error, skip_tmpl=skip_template)
        st.log("output={}, kwargs={}".format(output, kwargs))
        if return_output:
            return output
        # Removing unwanted keys from kwargs.
        for key in ['cli_type', 'skip_template', 'return_output', 'skip_error', 'filter_type']:
            kwargs.pop(key, None)
        # If output is empty, filling it with empty dict.
        output = [{}] if output == [] else output
        for key in kwargs.keys():
            if key in output[0]:
                if kwargs[key] != output[0][key]:
                    st.error("key : {} - Value is not same - Input : {}, Output : {}.".format(key, kwargs[key], output[0][key]))
                    return_flag = False
                else:
                    st.log('Found for key: {}, val:{}'.format(key, kwargs[key]))
            else:
                st.error("{} not found in the output.".format(key))
                return_flag = False
        return return_flag
    else:
        st.error("Supported modes are only KLISH.")
        return False


def config_ip_loadshare_hash(dut, **kwargs):
    """
    To configure IP load-share hash.
    Author: Sunil Rajendra (sunil.rajendra@broadcom.com)
    :param dut:
    :param kwargs: key (ip|ipv6|seed), val (single or list), config
    :return:
    """
    st.log('API_NAME: config_ip_loadshare_hash, API_ARGS: {}'.format(locals()))
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut, **kwargs))
    # For now this is supported only in klish.
    cli_type = 'klish' if cli_type == 'click' else cli_type
    # cli_type = force_cli_type_to_klish(cli_type=cli_type)

    if "val" not in kwargs:
        st.error("Please provide the value for the key.")
        return False

    config = kwargs.pop('config', 'yes')
    key = kwargs.pop('key', 'ipv4')
    key = 'ipv4' if key == 'ip' else key
    val = kwargs.pop('val', '')
    val = [val] if isinstance(val, str) else val
    skiperr = True if kwargs.get('skip_error') else False

    config_type = ''
    if config.lower() != 'yes':
        config_type = 'no '
        if key == 'seed':
            val = ['']
    command = []
    if cli_type in get_supported_ui_type_list():
        attr_map = {'seed': 'EcmpHashSeed', 'ipv4': 'Ipv4', 'ipv4-l4-src-port': 'Ipv4L4SrcPort', 'ipv4-l4-dst-port': 'Ipv4L4DstPort', 'ipv4-src-ip': 'Ipv4SrcIp', 'ipv4-dst-ip': 'Ipv4DstIp', 'ipv4-ip-proto': 'Ipv4IpProto', 'ipv4-symmetric': 'Ipv4Symmetric', 'ipv6': 'Ipv6', 'ipv6-l4-src-port': 'Ipv6L4SrcPort', 'ipv6-l4-dst-port': 'Ipv6L4DstPort', 'ipv6-src-ip': 'Ipv6SrcIp', 'ipv6-dst-ip': 'Ipv6DstIp', 'ipv6-ip-proto': 'Ipv6IpProto', 'ipv6-symmetric': 'Ipv6Symmetric', 'ipv6-next-hdr': 'Ipv6NextHdr'}
        config_value = 'true' if config == 'yes' else 'false'
        if key == 'seed':
            loadshare_obj = umf_loadshare.Loadshare()
            target_path = '/seed-attrs'
            if config_type == '':
                setattr(loadshare_obj, attr_map[key], int(val[0]))
                result = loadshare_obj.configure(dut, target_path=target_path, cli_type=cli_type)
                if not result.ok():
                    st.log('test_step_failed: Configure Load Share: {}'.format(result.data))
                    return False
            else:
                result = loadshare_obj.unConfigure(dut, target_path=target_path, cli_type=cli_type)
                if not result.ok():
                    st.log('test_step_failed: unConfigure Load Share: {}'.format(result.data))
                    return False
            return True
        else:
            result_list = []
            for v in val:
                loadshare_obj = umf_loadshare.Loadshare()
                target_path = '/ipv4-attrs' if key == 'ipv4' else '/ipv6-attrs'
                setattr(loadshare_obj, attr_map[key], key)
                if v == 'symmetric':
                    v = "{}-{}".format(key, v)
                setattr(loadshare_obj, attr_map[v], str(config_value))
                # Sending the values one by one for symmetric-hashing module to work properly (SONIC-70838).
                result = loadshare_obj.configure(dut, target_path=target_path, cli_type=cli_type)
                if not result.ok():
                    st.log('test_step_failed: Configure Load Share. But continuing with other values.')
                    result_list.append(False)
                else:
                    result_list.append(True)
            if all(result_list) is False:
                st.log('test_step_failed: Configure Load Share')
                return False
            return True
    if cli_type == 'klish':
        for v in val:
            command = command + [config_type + 'ip load-share hash {} {}'.format(key, v)]
        out = st.config(dut, command, type=cli_type, skip_error_check=skiperr)
        if '%Error:' in out:
            return False
        return True
    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        for v in val:
            if key == 'seed':
                v_seed = v
                v = 'ecmp-hash-seed'
            # changing symmetric to ipv4/6-symmetric.
            if v == 'symmetric':
                v = "{}-{}".format(key, v)
            url = rest_urls['ecmp_config_loadshare_' + key].format(v)
            if config_type == 'no ':
                if not delete_rest(dut, rest_url=url):
                    st.error("Failed to delete key={}, val={}.".format(key, v))
                    return False
            else:
                config_data = {"openconfig-loadshare-mode-ext:" + v: True}
                if key == 'seed':
                    config_data = {"openconfig-loadshare-mode-ext:" + v: int(v_seed)}
                if not config_rest(dut, rest_url=url, http_method=cli_type, json_data=config_data):
                    st.error("Failed to configure key={}, val={}".format(key, v))
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
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut, **kwargs))
    # This is not supported in click.
    cli_type = 'klish' if cli_type == 'click' else cli_type
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    skip_error = kwargs.get('skip_error', False)
    if cli_type == 'klish':
        command = "show ip load-share"
        return st.show(dut, command, type=cli_type, skip_error_check=skip_error)
    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        url = rest_urls['ecmp_show_ip_loadshare_hash']
        out = get_rest(dut, rest_url=url)
        var = out['output']['openconfig-loadshare-mode-ext:loadshare']
        ip_var = ''
        ipv6_var = ''
        seed_var = str(var['seed-attrs']['state']['ecmp-hash-seed'])
        ip_mode = 'Default'
        ipv6_mode = 'Default'
        state_keys = []
        if 'state' in var['ipv4-attrs'].keys():
            state_keys = list(var['ipv4-attrs']['state'].keys())
            if 'ipv4-symmetric' in var['ipv4-attrs']['state'].keys():
                ip_mode = 'Symmetric'
                var['ipv4-attrs']['state'].pop('ipv4-symmetric')
        if 'state' in var['ipv6-attrs'].keys():
            state_keys = state_keys + list(var['ipv6-attrs']['state'].keys())
            if 'ipv6-symmetric' in var['ipv6-attrs']['state'].keys():
                ipv6_mode = 'Symmetric'
                var['ipv6-attrs']['state'].pop('ipv6-symmetric')
        for v in state_keys:
            if 'ipv6' in v:
                ipv6_var = ipv6_var + ' ' + v
            else:
                ip_var = ip_var + ' ' + v
        ip_var = str(ip_var.strip())
        ipv6_var = str(ipv6_var.strip())
        output = [{'ip_mode': ip_mode, 'ipv6_mode': ipv6_mode, 'ip': ip_var, 'ipv6': ipv6_var, 'seed': seed_var}]
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
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut, **kwargs))
    st.log('API_NAME: verify_ip_loadshare, API_ARGS: {}'.format(locals()))
    if cli_type in get_supported_ui_type_list():
        filter_type = kwargs.get('filter_type', 'ALL')
        query_param_obj = utils.get_query_params(yang_data_type=filter_type, cli_type=cli_type)
        attr_map = {'seed': 'EcmpHashSeed', 'ipv4': 'Ipv4', 'ipv4-l4-src-port': 'Ipv4L4SrcPort', 'ipv4-l4-dst-port': 'Ipv4L4DstPort', 'ipv4-src-ip': 'Ipv4SrcIp', 'ipv4-dst-ip': 'Ipv4DstIp', 'ipv4-ip-proto': 'Ipv4IpProto', 'ipv4-symmetric': 'Ipv4Symmetric', 'ipv6': 'Ipv6', 'ipv6-l4-src-port': 'Ipv6L4SrcPort', 'ipv6-l4-dst-port': 'Ipv6L4DstPort', 'ipv6-src-ip': 'Ipv6SrcIp', 'ipv6-dst-ip': 'Ipv6DstIp', 'ipv6-ip-proto': 'Ipv6IpProto', 'ipv6-symmetric': 'Ipv6Symmetric', 'ipv6-next-hdr': 'Ipv6NextHdr'}
        loadshare_obj = umf_loadshare.Loadshare()
        for key in kwargs.keys():
            if key == 'ip_mode' or key == 'ipv6_mode':
                if key == 'ip_mode':
                    attr = 'ipv4-symmetric'
                if key == 'ipv6_mode':
                    attr = 'ipv6-symmetric'
                if kwargs[key] == 'Symmetric':
                    setattr(loadshare_obj, attr_map[attr], True)
                if kwargs[key] == 'Default':
                    continue
                    # Default value ipv4/6-symmetric=False is not present in GET calls(Commenting below code)
                    # loadshare_obj_def = umf_loadshare.Loadshare()
                    # filter_type = 'CONFIG'
                    # query_param_obj = utils.get_query_params(yang_data_type=filter_type, cli_type=cli_type)
                    # setattr(loadshare_obj_def, attr_map[attr], False)
                    # result_def = loadshare_obj_def.verify(dut, match_subset=True, query_param=query_param_obj, cli_type=cli_type)
                    # if not result_def.ok():
                    #     st.log('test_step_failed: Verify Loadshare with mode=Default')
                    #     return False
                continue
            if key == 'seed':
                # Default value of 10 is not present in the GET Calls
                if int(kwargs[key]) != 10:
                    setattr(loadshare_obj, attr_map[key], kwargs[key])
                continue
            attr_list = [kwargs[key]] if isinstance(kwargs[key], str) else kwargs[key]
            for attr in attr_list:
                if attr == 'symmetric':
                    attr = "{}-{}".format(key, attr)
                setattr(loadshare_obj, attr_map[attr], True)
        result = loadshare_obj.verify(dut, match_subset=True, query_param=query_param_obj, cli_type=cli_type)
        if not result.ok():
            st.log('test_step_failed: Verify Loadshare')
            return False
        return True

    return_key = True
    output = show_ip_loadshare(dut, **kwargs)
    st.log("output={}, kwargs={}".format(output, kwargs))
    for key in ['cli_type', 'skip_error']:
        kwargs.pop(key, None)

    for key in kwargs.keys():
        val_list = [kwargs[key]] if isinstance(kwargs[key], str) else kwargs[key]
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
    # API_Not_Used: To Be removed in CyrusPlus
    """
    To configure route leak
    Author: Jagadish Chatrasi (jagadish.chatrasi@broadcom.com)
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = 'vtysh' if cli_type == 'click' else cli_type
    cli_type = 'vtysh'  # CLI_TYPE hard-coded because the route leak configuration support is not available in other UIs
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
            cmd += ' {}'.format(kwargs['next_hop'])
        if kwargs.get('interface'):
            cmd += ' {}'.format(kwargs['interface'])
        if kwargs.get('nexthop_vrf'):
            cmd += ' nexthop-vrf {}'.format(kwargs['nexthop_vrf'])
        if kwargs.get('tag'):
            cmd += ' tag {}'.format(kwargs['tag'])
        if kwargs.get('track'):
            cmd += ' track {}'.format(kwargs['track'])
        if kwargs.get('table'):
            cmd += ' table {}'.format(kwargs['table'])
        if kwargs.get('label'):
            cmd += ' label {}'.format(kwargs['label'])
        if kwargs.get('onlink'):
            cmd += ' onlink'
        if kwargs.get('distance'):
            cmd += ' {}'.format(kwargs['distance'])
        command.append(cmd)
        command.append('exit-vrf')
        st.config(dut, command, type='vtysh')
    else:
        st.error("Unsupported CLI_TYPE: {}".format(cli_type))
        return False
    return True


def config_sub_interface(dut, intf, **kwargs):
    """
    :param dut:
    :param kwargs:
    :return:
    """

    cli_type = st.get_ui_type(dut, **kwargs)
    encap_id = kwargs.get('vlan', None)
    config = kwargs.get('config', 'yes')
    skip_error = kwargs.pop('skip_error_check', False)
    del_sub_intf = kwargs.get('del_sub_intf', 'yes')
    create_parent_po = kwargs.get('create_parent_po', False)
    skip_exit = kwargs.pop('skip_exit', False)
    maxtime = kwargs.pop('maxtime', 0)

    if not isinstance(intf, list):
        intf = [intf]
    if encap_id:
        if not isinstance(encap_id, list):
            encap_id = [encap_id]
    else:
        # handling if vlan argument not passed
        encap_id = [encap_id] * len(intf)
    if cli_type in get_supported_ui_type_list():
        for intf_item, encap_item in zip(intf, encap_id):
            parent_intf = intf_item.split('.')[0]
            sub_intf_index = intf_item.split('.')[1]
            intf_obj = umf_intf.Interface(Name=parent_intf)
            sub_intf_obj = umf_intf.Subinterface(Index=int(sub_intf_index), Interface=intf_obj)
            try:
                if config == 'yes':
                    if 'portchannel' in intf_item.lower() and create_parent_po:
                        parent_po = intf_item.split('.')[0]
                        pc.create_portchannel(dut, [parent_po])
                    if encap_item:
                        sub_intf_obj.VlanId = int(encap_item)
                    result = sub_intf_obj.configure(dut, cli_type=cli_type)
                else:
                    if del_sub_intf == 'yes':
                        result = sub_intf_obj.unConfigure(dut, cli_type=cli_type)
                    else:
                        sub_intf_obj.VlanId = int(encap_item)
                        result = sub_intf_obj.unConfigure(dut, target_attr=sub_intf_obj.VlanId, cli_type=cli_type)
                if not result.ok():
                    st.error("test_step_failed: Configure Sub-Interface: {}".format(result.data))
                    return False
            except ValueError as exp:
                if skip_error:
                    st.log('ValueError: {}'.format(exp))
                    st.log('Negative Scenario: Errors/Expception expected')
                    return False
                else:
                    raise
        return True
    elif cli_type == 'click':
        for intf_item, encap_item in zip(intf, encap_id):
            if config == 'yes':
                cmd = 'config subinterface add {}'.format(intf_item)
                if encap_item:
                    cmd += ' {}'.format(encap_item)
            else:
                cmd = 'config subinterface del {}'.format(intf_item)
            out = st.config(dut, cmd=cmd, type='click', max_time=maxtime, skip_error_check=skip_error)
            if 'Error' in out:
                return False
        return True
    elif cli_type == 'klish':
        cmd = []
        for intf_item, encap_item in zip(intf, encap_id):
            interface = get_interface_number_from_name(intf_item)
            if config == 'yes':
                if 'portchannel' in intf_item.lower() and create_parent_po:
                    parent_po = intf_item.split('.')[0]
                    pc.create_portchannel(dut, [parent_po])
                cmd.append('interface {} {}'.format(interface['type'], interface['number']))
                if encap_item:
                    cmd.append('encapsulation dot1q vlan-id {}'.format(encap_item))
                if not skip_exit:
                    cmd.append('exit')
            else:
                if del_sub_intf == 'yes':
                    cmd.append('no interface {} {}'.format(interface['type'], interface['number']))
                else:
                    cmd.append('interface {} {}'.format(interface['type'], interface['number']))
                    cmd.append('no encapsulation')
                    if not skip_exit:
                        cmd.append('exit')
        out = st.config(dut, cmd=cmd, type='klish', skip_error_check=skip_error, max_time=maxtime)
        if 'Error' in out:
            return False
        return True
    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        http_method = kwargs.pop('http_method', cli_type)
        for intf_item, encap_item in zip(intf, encap_id):
            parent_intf = intf_item.split('.')[0]
            sub_intf_index = intf_item.split('.')[1]
            if config == 'yes':
                oc_data = dict()
                oc_data['openconfig-interfaces:subinterfaces'] = dict()
                oc_data['openconfig-interfaces:subinterfaces']["subinterface"] = list()
                list_items = dict()
                list_items['config'] = dict()
                rest_url = rest_urls['config_sub_intf'].format(parent_intf)
                list_items['index'] = int(sub_intf_index)
                list_items['config']['index'] = int(sub_intf_index)
                oc_data['openconfig-interfaces:subinterfaces']["subinterface"].append(list_items)
                response = config_rest(dut, http_method=http_method, rest_url=rest_url, json_data=oc_data)
                if not response:
                    return False
                if encap_item:
                    rest_url = rest_urls['add_del_sub_intf_vlan'].format(parent_intf, sub_intf_index)
                    oc_data = dict()
                    oc_data["openconfig-vlan:vlan-id"] = int(encap_item)
                    response = config_rest(dut, http_method=http_method, rest_url=rest_url, json_data=oc_data)
                    if not response:
                        return False
            else:
                if del_sub_intf == 'yes':
                    rest_url = rest_urls['delete_sub_intf'].format(parent_intf, sub_intf_index)

                else:
                    rest_url = rest_urls['add_del_sub_intf_vlan'].format(parent_intf, sub_intf_index)
                response = delete_rest(dut, rest_url=rest_url)
                if not response:
                    return False
    else:
        st.error("Unsupported CLI_TYPE: {}".format(cli_type))
        return False
    return True


def verify_sub_interface_status(dut, **kwargs):
    """

    :param dut:
    :param kwargs:
    :return:
    """
    ret_val = True
    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    kwargs.pop('cli_type', '')
    skip_tmpl = kwargs.pop('skip_tmpl', False)
    skip_error = kwargs.pop('skip_error', False)
    yang_data_type = kwargs.get("filter_type", "ALL")
    # Converting all kwargs to list type to handle single or list of mroute instances
    if not kwargs.get("interface") and cli_type in get_supported_ui_type_list():
        cli_type = "klish"
    for key in kwargs:
        if isinstance(kwargs[key], list):
            kwargs[key] = list(kwargs[key])
        else:
            kwargs[key] = [kwargs[key]]
    if 'interface' in kwargs and cli_type == 'click':
        kwargs['interface'] = [get_intf_short_name(i) for i in kwargs['interface']]
    output = []
    if cli_type in get_supported_ui_type_list():
        query_params_obj = utils.get_query_params(yang_data_type=yang_data_type, cli_type=cli_type)
        intf_name = kwargs.get("interface_name")
        parent_intf = intf_name.split('.')[0]
        sub_intf_index = intf_name.split('.')[1]
        intf_obj = umf_intf.Interface(Name=parent_intf)
        sub_intf_obj = umf_intf.Subinterface(Index=int(sub_intf_index), Interface=intf_obj)
        rv = sub_intf_obj.get_payload(dut, query_param=query_params_obj, cli_type=cli_type)
        if rv.ok():
            res = rv.payload.get("openconfig-interfaces:subinterface")
            if res:
                output = list()
                result = dict()
                result['interface'] = res[0].get("state").get("name", "")
                result['admin'] = res[0].get("state").get("admin-status", "")
                result['mtu'] = res[0].get("state").get("openconfig-interfaces-ext:mtu", "")
                result['speed'] = res[0].get("state").get("speed", "")
                result['type'] = res[0].get("state").get("type", 'dot1q-encapsulation')
                output.append(result)
            else:
                st.error("Rcvd empty response")
                return False
        else:
            st.error("Rcvd not ok response")
            return False
    elif cli_type in ['click', 'klish']:
        cmd = 'show subinterfaces status'
        output = st.show(dut, cmd, skip_error_check=skip_error, skip_tmpl=skip_tmpl, type=cli_type)
    elif cli_type in ['rest-put', 'rest-patch']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        rest_url = rest_urls['show_sub_intf_status']
        rest_output = get_rest(dut, rest_url=rest_url)['output'].get('sonic-interface:VLAN_SUB_INTERFACE', {}).get('VLAN_SUB_INTERFACE_LIST', {})
        output = convert_sub_intf_rest(rest_output)
        st.log("\nConverted Output : {}\n".format(output))
    if 'return_output' in kwargs:
        return output
    if len(output) == 0:
        st.error("Output is Empty")
        return False

    # convert kwargs into list of dictionary
    input_dict_list = []
    for i in range(len(kwargs[list(kwargs.keys())[0]])):
        temp_dict = {}
        for key in kwargs.keys():
            temp_dict[key] = kwargs[key][i]
        input_dict_list.append(temp_dict)

    for input_dict in input_dict_list:
        entries = utils.filter_and_select(output, None, match=input_dict)
        if not entries:
            st.error("DUT {} -> Match Not Found {}".format(dut, input_dict))
            ret_val = False

    return ret_val


def convert_sub_intf_rest(output):
    for item in output:
        item['interface'] = item.pop('id', '')
        item['admin'] = item.pop('admin_status', '')
        item['mtu'] = item.pop('mtu', '')
        item['speed'] = item.pop('speed', '')
        item['type'] = item.pop('type', 'dot1q-encapsulation')
    return output


def get_running_config_subintf(dut, subinterface, cli_type=''):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    if cli_type in ['klish', 'rest-patch', 'rest-put']:
        interface = get_interface_number_from_name(subinterface)
        return st.show(dut, 'show running-configuration subinterface {} {}'.format(interface['type'], interface['number']), skip_tmpl=True, type='klish')


def verify_running_config(dut, sub_cmd, **kwargs):
    # params for switchport
    # access_mode, trunk_mode, access_vlan, trunk_vlan_list

    cli_type = st.get_ui_type(dut, **kwargs)
    skip_tmpl = kwargs.pop('skip_tmpl', False)
    cli_type = 'klish' if cli_type in ['rest-patch', 'rest-put', 'click'] else cli_type
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    if 'interface ' in sub_cmd.lower():
        intf_info = get_interface_number_from_name(sub_cmd.replace('interface ', ''))
        sub_cmd = 'interface {} {}'.format(intf_info['type'], intf_info['number'])
    output = st.show(dut, 'show running-configuration {}'.format(sub_cmd), type=cli_type, skip_tmpl=skip_tmpl)
    if 'return_output' in kwargs:
        return output
    kwargs.pop('sub_cmd', None)
    kwargs.pop('cli_type', None)
    if 'interface' in kwargs:
        if ' ' in kwargs['interface']:
            kwargs['interface'] = kwargs['interface'].replace(' ', "")
    if cli_type == 'klish':
        for each_param in kwargs.keys():
            match = {each_param: kwargs[each_param]}
            entries = utils.filter_and_select(output, None, match)
            if not entries:
                st.log('Match not found for param: {} value: {}'.format(each_param, kwargs[each_param]))
                return False
        return True
    else:
        return True


def config_nht(dut, **kwargs):
    '''
    Configures Nexthop Tracking.
    Author: sunil.rajendra@broadcom.com
    :param dut:
    :param config: yes/no.
    :param family: address family - ip/ipv6.
    :param vrf: VRF name.
    :param cli_type: CLI type - click/klish/rest-patch (As of now only klish is supported).
    :param skip_error: True/False.
    :return:

    Usage:
    [no] ip [vrf <vrf-name>] nht resolve-via-default
    config_nht(dut)
    config_nht(dut, config='no')
    config_nht(dut, family='ipv6', vrf='Vrf1')
    '''
    # Optional parameters processing
    config = kwargs.get('config', 'yes')
    family = kwargs.get('family', "ip")
    vrf = kwargs.get('vrf', "")
    skip_error = kwargs.get('skip_error', False)
    cli_type = kwargs.get('cli_type', st.get_ui_type(dut, **kwargs))
    # CLI not supported in click
    # Will add Rest support in next checkin after validation.
    cli_type = cli_type if cli_type not in ["rest-patch", "rest-put", "click"] else "klish"

    vrf = 'vrf ' + vrf + ' ' if vrf != "" else ""
    output = False
    if cli_type in get_supported_ui_type_list():
        vrf_name = kwargs.get('vrf', 'default')
        ni_obj = umf_ni.NetworkInstance(Name=vrf_name)
        addr_family = 'IPV4' if family == 'ip' else 'IPV6'
        nht_obj = umf_ni.AddressFamily(Family=addr_family, NetworkInstance=ni_obj)
        if config == 'yes':
            nht_obj.ResolveViaDefault = True
            result = nht_obj.configure(dut, cli_type=cli_type)
        else:
            result = nht_obj.unConfigure(dut, cli_type=cli_type)
        if not result.ok():
            st.error('test_step_failed: Configure NHT: {}'.format(result.data))
            return False
        return True
    elif cli_type == 'klish':
        config = '' if config == "yes" else "no "
        cmd = "{}{} {}nht resolve-via-default".format(config, family, vrf)
        output = st.config(dut, cmd, type=cli_type, conf=True, skip_error_check=skip_error)
        if "Could not connect to Management REST Server" in output:
            st.error("klish mode not working.")
            return False
        if "Error" in output:
            st.error("Error seen while configuring.")
            return False
    return output


def config_ra_retrans_interval(dut, **kwargs):
    """
    :param dut:
    :param interval
    :return:
    """
    config = kwargs.get("config", "yes")
    cli_type = 'vtysh'
    config = ' ' if config == 'yes' else 'no'
    intf_info = get_interface_number_from_name(kwargs['interface'])
    command = 'interface {}{}\n'.format(intf_info["type"], intf_info["number"])
    command += '{} ipv6 nd ra-retrans-interval {}\n'.format(config, kwargs['interval'])
    command += 'exit\n'
    if command:
        try:
            st.config(dut, command, type=cli_type)
        except Exception as e:
            st.log(e)
            return False
    return True


def config_ipv6_ra(dut, interface, **kwargs):
    '''

    :param dut:
    :param interface: interface can be list and in that case same set of parameters will be configured on all given interfac
    :param kwargs:

    :return:
    Usage:
        config_ipv6_ra(dut=dut1,interface='Ethernet0',ra_interval=5,eip="3.3.3.3",config="no")
        config_ipv6_ra(dut=dut1,pip="1.1.1.2",sip="2.2.2.2",eip="3.3.3.3")
    '''

    st.log('API_NAME: config_ipv6_ra, API_ARGS: {}'.format(locals()))
    cli_type = st.get_ui_type(dut, **kwargs)
    if cli_type == 'click':
        cli_type = "vtysh"

    config = kwargs.get('config', 'yes').lower()
    cfg_clean = kwargs.get('cfg_clean', False)
    # skip_error = kwargs.get('skip_error', False)

    prefix_list = kwargs.get('prefix_list', None)
    dnssl_list = kwargs.get('dnssl_list', None)
    rdnss_list = kwargs.get('rdnss_list', None)

    interface_list = utils.make_list(interface)
    t_path = None
    cmd_edit_list = list()

    bulk_conf_mode = True if cli_type in get_supported_ui_type_list() else False

    v6_ra_attrs = {
        'ra_interval_sec': ['Interval', kwargs.get('ra_interval_sec', None)],
        'ra_lifetime': ['Lifetime', kwargs.get('ra_lifetime', None)],
        'ra_suppress': ['Suppress', kwargs.get('ra_suppress', None)],
        'retrans_interval': ['RaRetransInterval', kwargs.get('retrans_interval', None)],
        'ra_interval_msec': ['RaIntervalMsec', kwargs.get('ra_interval_msec', None)],
        'ra_hop_limit': ['RaHopLimit', kwargs.get('ra_hop_limit', None)],
        'reachable_time': ['ReachableTime', kwargs.get('reachable_time', None)],
        'home_agent_conf': ['HomeAgentConfig', kwargs.get('home_agent_conf', None)],
        'home_agent_life': ['HomeAgentLifetime', kwargs.get('home_agent_life', None)],
        'home_agent_pref': ['HomeAgentPreference', kwargs.get('home_agent_pref', None)],
        'ra_mtu': ['RouterAdvertisementMtu', kwargs.get('ra_mtu', None)],
        'def_router_pref': ['RouterPreference', kwargs.get('def_router_pref', None)],
        'ra_fast_retrans': ['RaFastRetrans', kwargs.get('ra_fast_retrans', None)],
        'ra_manage_conf': ['ManagedConfig', kwargs.get('ra_manage_conf', None)],
        'ra_other_conf': ['OtherConfig', kwargs.get('ra_other_conf', None)],
        'ra_adv_interval': ['AdvIntervalOption', kwargs.get('ra_adv_interval', None)]
    }

    if cli_type in get_supported_ui_type_list() + ['klish']:
        for interface in interface_list:
            index = get_subinterface_index(dut, interface)
            interface_name = get_phy_port(interface)
            if 'Vlan' in interface_name:
                intf_obj = umf_intf.Interface(Name=interface_name)
                t_path = "/openconfig-vlan:routed-vlan/openconfig-if-ip:ipv6/router-advertisement/config"
            else:
                temp_obj = umf_intf.Interface(Name=interface_name)
                intf_obj = umf_intf.Subinterface(Index=int(index), Interface=temp_obj)
                t_path = "/openconfig-if-ip:ipv6/router-advertisement/config"

            # intf_obj = umf_intf.Interface(Name=interface_name)
            if config == 'yes':
                gnmi_op = Operation.UPDATE

                for key, attr_value in v6_ra_attrs.items():
                    if key in kwargs and attr_value[1] is not None:
                        if key == 'def_router_pref':
                            setattr(intf_obj, attr_value[0], attr_value[1].upper())
                        else:
                            setattr(intf_obj, attr_value[0], attr_value[1])
                if not bulk_conf_mode:
                    result = intf_obj.configure(dut, operation=gnmi_op, cli_type=cli_type)
                    if not result.ok():
                        st.log('test_step_failed: {}: Config of IPv6 RA params result: {}'
                               .format(cli_type.upper(), result.data))
                        return False
                else:
                    cmd_edit_list.append(umf_bulk.Edit(intf_obj, operation=gnmi_op))

                # adding new prefixes, rdnss or dnssl using gnmi needs CREATE
                gnmi_op = Operation.CREATE

                if prefix_list:
                    for prefix_dict in prefix_list:
                        if 'Vlan' in interface_name:
                            ra_prefix_obj = umf_intf.RoutedVlanRaPrefix(Prefix=prefix_dict['prefix'], Interface=intf_obj)
                        else:
                            ra_prefix_obj = umf_intf.SubinterfaceRaPrefix(Prefix=prefix_dict['prefix'],
                                                                          Subinterface=intf_obj)

                        if 'valid_life' in prefix_dict.keys():
                            value = prefix_dict['valid_life']
                            ra_prefix_obj.ValidLifetime = 4294967295 if value == 'infinite' else value
                        if 'preferred_life' in prefix_dict.keys():
                            value = prefix_dict['preferred_life']
                            ra_prefix_obj.PreferredLifetime = 4294967295 if value == 'infinite' else value
                        if 'no_auto_cfg' in prefix_dict.keys():
                            ra_prefix_obj.NoAutoconfig = prefix_dict['no_auto_cfg']
                        if 'off_link' in prefix_dict.keys():
                            ra_prefix_obj.OffLink = prefix_dict['off_link']
                        if 'router_add' in prefix_dict.keys():
                            ra_prefix_obj.RouterAddress = prefix_dict['router_add']
                        if not bulk_conf_mode:
                            result = ra_prefix_obj.configure(dut, operation=gnmi_op, cli_type=cli_type)
                            if not result.ok():
                                st.log('test_step_failed: {}: Config of IPv6 RA prefix:{} result: {}'
                                       .format(cli_type.upper(), prefix_dict['prefix'], result.data))
                                return False
                        else:
                            cmd_edit_list.append(umf_bulk.Edit(ra_prefix_obj, operation=gnmi_op))
                if dnssl_list:
                    for dnss_dict in dnssl_list:
                        if 'Vlan' in interface_name:
                            ra_dnss_obj = umf_intf.RoutedVlanDnsSearchName(DnsslName=dnss_dict['dnss_name'], Interface=intf_obj)
                        else:
                            ra_dnss_obj = umf_intf.SubinterfaceDnsSearchName(DnsslName=dnss_dict['dnss_name'],
                                                                             Subinterface=intf_obj)

                        if 'valid_life' in dnss_dict.keys():
                            value = dnss_dict['valid_life']
                            ra_dnss_obj.ValidLifetime = 4294967295 if value == 'infinite' else value
                        if not bulk_conf_mode:
                            result = ra_dnss_obj.configure(dut, operation=gnmi_op, cli_type=cli_type)
                            if not result.ok():
                                st.log('test_step_failed: {}: Config of IPv6 RA DNS Name:{} result: {}'
                                       .format(cli_type.upper(), dnss_dict['dnss_name'], result.data))
                                return False
                        else:
                            cmd_edit_list.append(umf_bulk.Edit(ra_dnss_obj, operation=gnmi_op))
                if rdnss_list:
                    for rdnss_dict in rdnss_list:
                        if 'Vlan' in interface_name:
                            ra_rdnss_obj = umf_intf.RoutedVlanRdnssAddress(Address=rdnss_dict['address'], Interface=intf_obj)
                        else:
                            ra_rdnss_obj = umf_intf.SubinterfaceRdnssAddress(Address=rdnss_dict['address'],
                                                                             Subinterface=intf_obj)

                        if 'valid_life' in rdnss_dict.keys():
                            value = rdnss_dict['valid_life']
                            ra_rdnss_obj.ValidLifetime = 4294967295 if value == 'infinite' else value
                        if not bulk_conf_mode:
                            result = ra_rdnss_obj.configure(dut, operation=gnmi_op, cli_type=cli_type)
                            if not result.ok():
                                st.log('test_step_failed: {}: Config of IPv6 RA DNS prefix:{} result: {}'
                                       .format(cli_type.upper(), rdnss_dict['address'], result.data))
                                return False
                        else:
                            cmd_edit_list.append(umf_bulk.Edit(ra_rdnss_obj, operation=gnmi_op))
                '''if cmd_edit_list:
                    result = umf_bulk.bulkRequest(dut, edits=cmd_edit_list, cli_type=cli_type)
                    if not result.ok():
                        st.log('test_step_failed: Config of IPv6 RA Parameters {}'.format(result.data))
                        return False'''
            else:
                gnmi_op = Operation.DELETE
                for key, attr_value in v6_ra_attrs.items():
                    if key in kwargs and attr_value[1] is not None:
                        target_attr = getattr(intf_obj, attr_value[0])
                        if not bulk_conf_mode:
                            result = intf_obj.unConfigure(dut, target_attr=target_attr, target_attr_name=attr_value[0], cli_type=cli_type)
                            # result = intf_obj.unConfigure(dut, target_attr=attr_value[0], cli_type=cli_type)
                            if not result.ok():
                                st.log('test_step_failed: {}: Unconfig IPv6 RA param:{} result: {}'
                                       .format(cli_type.upper(), key, result.data))
                                return False
                        else:
                            cmd_edit_list.append(umf_bulk.Edit(intf_obj, target_attr=target_attr, operation=gnmi_op))
                if prefix_list:
                    for prefix_dict in prefix_list:
                        if "Vlan" in interface_name:
                            ra_prefix_obj = umf_intf.RoutedVlanRaPrefix(Prefix=prefix_dict['prefix'], Interface=intf_obj)
                        else:
                            ra_prefix_obj = umf_intf.SubinterfaceRaPrefix(Prefix=prefix_dict['prefix'],
                                                                          Subinterface=intf_obj)
                        if not bulk_conf_mode:
                            result = ra_prefix_obj.unConfigure(dut, cli_type=cli_type)
                            if not result.ok():
                                st.log('test_step_failed: {}: UnConfig of IPv6 RA prefix:{} result: {}'
                                       .format(cli_type.upper(), prefix_dict['prefix'], result.data))
                                return False
                        else:
                            cmd_edit_list.append(umf_bulk.Edit(ra_prefix_obj, operation=gnmi_op))
                if dnssl_list:
                    for dnss_dict in dnssl_list:
                        if 'Vlan' in interface_name:
                            ra_dnss_obj = umf_intf.RoutedVlanDnsSearchName(DnsslName=dnss_dict['dnss_name'], Interface=intf_obj)
                        else:
                            ra_dnss_obj = umf_intf.SubinterfaceDnsSearchName(DnsslName=dnss_dict['dnss_name'],
                                                                             Subinterface=intf_obj)
                        if not bulk_conf_mode:
                            result = ra_dnss_obj.unConfigure(dut, cli_type=cli_type)
                            if not result.ok():
                                st.log('test_step_failed: {}: UnConfig of IPv6 RA DNS:{} result: {}'
                                       .format(cli_type.upper(), dnss_dict['dnss_name'], result.data))
                                return False
                        else:
                            cmd_edit_list.append(umf_bulk.Edit(ra_dnss_obj, operation=gnmi_op))
                if rdnss_list:
                    for rdnss_dict in rdnss_list:
                        if 'Vlan' in interface_name:
                            ra_rdnss_obj = umf_intf.RoutedVlanRdnssAddress(Address=rdnss_dict['address'], Interface=intf_obj)
                        else:
                            ra_rdnss_obj = umf_intf.SubinterfaceRdnssAddress(Address=rdnss_dict['address'],
                                                                             Subinterface=intf_obj)
                        if not bulk_conf_mode:
                            result = ra_rdnss_obj.unConfigure(dut, cli_type=cli_type)
                            if not result.ok():
                                st.log('test_step_failed: {}: UnConfig of IPv6 RA DNS prefix:{} result: {}'
                                       .format(cli_type.upper(), rdnss_dict['address'], result.data))
                                return False
                        else:
                            cmd_edit_list.append(umf_bulk.Edit(ra_rdnss_obj, operation=gnmi_op))
            if cfg_clean and cli_type in get_supported_ui_type_list():
                # Explicitly delete RA config container as per workaroud given in SONIC-64388
                result = intf_obj.unConfigure(dut, target_path=t_path, cli_type=cli_type)
                if not result.ok():
                    st.log('test_step_failed: {}: Unconfig IPv6 RA Config Container, result: {}'
                           .format(cli_type.upper(), result.data))
                    return False

        if cmd_edit_list:
            result = umf_bulk.bulkRequest(dut, edits=cmd_edit_list, cli_type=cli_type)
            if not result.ok():
                conf_str = 'Config' if config == 'yes' else 'UnConfig'
                st.log('test_step_failed: {} of IPv6 RA Parameters {}'.format(conf_str, result.data))
                return False

    elif cli_type == 'vtysh':
        command = list()
        for interface in interface_list:
            command.append("interface {}".format(interface))
            fields = {"home_agent_conf": "home-agent-config-flag", "ra_suppress": "suppress-ra",
                      "ra_interval_sec": "ra-interval", "ra_interval_msec": "ra-interval msec",
                      "ra_adv_interval": "adv-interval-option", "home_agent_life": "home-agent-lifetime",
                      "home_agent_pref": "home-agent-preference", "ra_manage_conf": "managed-config-flag", "ra_mtu": "mtu",
                      "ra_other_conf": "other-config-flag", "ra_fast_retrans": "ra-fast-retrans",
                      "ra_hop_limit": "ra-hop-limit", "ra_lifetime": "ra-lifetime",
                      "retrans_interval": "ra-retrans-interval", "reachable_time": "reachable-time",
                      "def_router_pref": "router-preference"}
            if "ra_suppress" not in kwargs and config == 'yes':
                cmd = "no ipv6 nd {}".format(fields["ra_suppress"])
                command.append(cmd)
            for param in kwargs.keys():
                if param in ["home_agent_conf", "ra_adv_interval", "ra_suppress", "ra_manage_conf", "ra_other_conf",
                             "ra_fast_retrans"]:
                    param_config = "" if kwargs[param] else "no"
                    cmd = "{} ipv6 nd {}".format(param_config, fields[param])
                    command.append(cmd)
                if param in ["ra_interval_sec", "ra_interval_msec", "home_agent_life", "home_agent_pref", "ra_mtu",
                             "ra_hop_limit", "ra_lifetime", "retrans_interval", "reachable_time", "def_router_pref"]:
                    if config == 'yes':
                        cmd = "ipv6 nd {} {}".format(fields[param], kwargs[param])
                    else:
                        cmd = "no ipv6 nd {}".format(fields[param])
                    command.append(cmd)
            if prefix_list:
                for prefix_dict in prefix_list:
                    if "prefix" in prefix_dict.keys():
                        if config == 'yes':
                            cmd = "ipv6 nd prefix {}".format(prefix_dict["prefix"])
                            if "valid_life" in prefix_dict.keys() and "preferred_life" in prefix_dict.keys():
                                cmd = "{} {} {}".format(cmd, prefix_dict["valid_life"], prefix_dict["preferred_life"])
                            if prefix_dict.get("no_auto_cfg", False):
                                cmd = "{} no-autoconfig".format(cmd)
                            if prefix_dict.get("off_link", False):
                                cmd = "{} off-link".format(cmd)
                            elif prefix_dict.get("router_add", False):
                                cmd = "{} router-address".format(cmd)
                        else:
                            cmd = "no ipv6 nd prefix {}".format(prefix_dict["prefix"])
                        command.append(cmd)
            if dnssl_list:
                for dnssl_dict in dnssl_list:
                    if "dnss_name" in dnssl_dict.keys():
                        if config == 'yes':
                            cmd = "ipv6 nd dnssl {}".format(dnssl_dict["dnss_name"])
                            if "valid_life" in dnssl_dict.keys():
                                cmd = "{} {}".format(cmd, dnssl_dict["valid_life"])
                        else:
                            cmd = "no ipv6 nd dnssl {}".format(dnssl_dict["dnss_name"])
                        command.append(cmd)
            if rdnss_list:
                for rdnss_dict in rdnss_list:
                    if "address" in rdnss_dict.keys():
                        if config == 'yes':
                            cmd = "ipv6 nd rdnss {}".format(rdnss_dict["address"])
                            if "valid_life" in rdnss_dict.keys():
                                cmd = "{} {}".format(cmd, rdnss_dict["valid_life"])
                        else:
                            cmd = "no ipv6 nd rdnss {}".format(rdnss_dict["address"])
                        command.append(cmd)
            command.append("exit")
        if command:
            st.config(dut, command, type='vtysh')
    else:
        st.error("Invalid CLI type - {}".format(cli_type))
        return False

    return True


def verify_ipv6_ra(dut, interface, **kwargs):
    st.log('API_NAME: verify_ipv6_ra, API_ARGS: {}'.format(locals()))
    cli_type = st.get_ui_type(dut, **kwargs)
    if cli_type == 'click':
        cli_type = "vtysh"

    prefix_list = kwargs.get('prefix_list', None)
    dnssl_list = kwargs.get('dnssl_list', None)
    rdnss_list = kwargs.get('rdnss_list', None)

    if cli_type in get_supported_ui_type_list() + ['klish']:

        filter_type = kwargs.get('filter_type', 'ALL')
        query_params_obj = utils.get_query_params(yang_data_type=filter_type, cli_type=cli_type)

        v6_ra_attrs = {
            'ra_interval_sec': ['Interval', kwargs.get('ra_interval_sec', None)],
            'ra_lifetime': ['Lifetime', kwargs.get('ra_lifetime', None)],
            'ra_suppress': ['Suppress', kwargs.get('ra_suppress', None)],
            'retrans_interval': ['RaRetransInterval', kwargs.get('retrans_interval', None)],
            'ra_interval_msec': ['RaIntervalMsec', kwargs.get('ra_interval_msec', None)],
            'ra_hop_limit': ['RaHopLimit', kwargs.get('ra_hop_limit', None)],
            'reachable_time': ['ReachableTime', kwargs.get('reachable_time', None)],
            'home_agent_conf': ['HomeAgentConfig', kwargs.get('home_agent_conf', None)],
            'home_agent_life': ['HomeAgentLifetime', kwargs.get('home_agent_life', None)],
            'home_agent_pref': ['HomeAgentPreference', kwargs.get('home_agent_pref', None)],
            'ra_mtu': ['RouterAdvertisementMtu', kwargs.get('ra_mtu', None)],
            'def_router_pref': ['RouterPreference', kwargs.get('def_router_pref', None)],
            'ra_fast_retrans': ['RaFastRetrans', kwargs.get('ra_fast_retrans', None)],
            'ra_manage_conf': ['ManagedConfig', kwargs.get('ra_manage_conf', None)],
            'ra_other_conf': ['OtherConfig', kwargs.get('ra_other_conf', None)],
            'ra_adv_interval': ['AdvIntervalOption', kwargs.get('ra_adv_interval', None)],
            'ra_pkt_sent': ['RaPktSent', kwargs.get('ra_pkt_sent', None)],
            'ra_pkt_rcvd': ['RaPktRcvd', kwargs.get('ra_pkt_rcvd', None)]
        }

        index = get_subinterface_index(dut, interface)
        interface_name = get_phy_port(interface)
        # intf_obj = umf_intf.Interface(Name=interface_name)
        if 'Vlan' in interface_name:
            intf_obj = umf_intf.Interface(Name=interface_name)
        else:
            temp_obj = umf_intf.Interface(Name=interface_name)
            intf_obj = umf_intf.Subinterface(Index=int(index), Interface=temp_obj)

        for key, attr_value in v6_ra_attrs.items():
            if key in kwargs and attr_value[1] is not None:
                if key == 'def_router_pref':
                    setattr(intf_obj, attr_value[0], attr_value[1].upper())
                elif key == 'home_agent_life':
                    if int(kwargs.get('home_agent_life')) != 0:
                        setattr(intf_obj, attr_value[0], attr_value[1])
                elif key == 'home_agent_pref':
                    if int(kwargs.get('home_agent_pref')) != 0:
                        setattr(intf_obj, attr_value[0], attr_value[1])
                else:
                    setattr(intf_obj, attr_value[0], attr_value[1])

        result = intf_obj.verify(dut, match_subset=True, query_param=query_params_obj, cli_type=cli_type)
        if not result.ok():
            st.log('test_step_failed: Match NOT Found: IPv6 RA Params')
            return False

        if prefix_list:
            for prefix_dict in prefix_list:
                if 'Vlan' in interface_name:
                    ra_prefix_obj = umf_intf.RoutedVlanRaPrefix(Prefix=prefix_dict['prefix'], Interface=intf_obj)
                else:
                    ra_prefix_obj = umf_intf.SubinterfaceRaPrefix(Prefix=prefix_dict['prefix'],
                                                                  Subinterface=intf_obj)
                # ra_prefix_obj = umf_intf.RoutedVlanRaPrefix(Prefix=prefix_dict['prefix'], Interface=intf_obj)
                if 'valid_life' in prefix_dict.keys():
                    value = prefix_dict['valid_life']
                    ra_prefix_obj.ValidLifetime = 4294967295 if value == 'infinite' else value
                if 'preferred_life' in prefix_dict.keys():
                    value = prefix_dict['preferred_life']
                    ra_prefix_obj.PreferredLifetime = 4294967295 if value == 'infinite' else value
                if 'no_auto_cfg' in prefix_dict.keys():
                    ra_prefix_obj.NoAutoconfig = prefix_dict['no_auto_cfg']
                if 'off_link' in prefix_dict.keys():
                    ra_prefix_obj.OffLink = prefix_dict['off_link']
                if 'router_add' in prefix_dict.keys():
                    ra_prefix_obj.RouterAddress = prefix_dict['router_add']

                result = ra_prefix_obj.verify(dut, match_subset=True, query_param=query_params_obj, cli_type=cli_type)
                if not result.ok():
                    st.log('test_step_failed: {}: Verify of IPv6 RA prefix:{} result: {}'
                           .format(cli_type.upper(), prefix_dict['prefix'], result.data))
                    return False
        if dnssl_list:
            for dnss_dict in dnssl_list:
                if 'Vlan' in interface_name:
                    ra_dnss_obj = umf_intf.RoutedVlanDnsSearchName(DnsslName=dnss_dict['dnss_name'], Interface=intf_obj)
                else:
                    ra_dnss_obj = umf_intf.SubinterfaceDnsSearchName(DnsslName=dnss_dict['dnss_name'],
                                                                     Subinterface=intf_obj)
                # ra_dnss_obj = umf_intf.RoutedVlanDnsSearchName(DnsslName=dnss_dict['dnss_name'], Interface=intf_obj)
                if 'valid_life' in dnss_dict.keys():
                    value = dnss_dict['valid_life']
                    ra_dnss_obj.ValidLifetime = 4294967295 if value == 'infinite' else value
                result = ra_dnss_obj.verify(dut, match_subset=True, query_param=query_params_obj, cli_type=cli_type)
                if not result.ok():
                    st.log('test_step_failed: {}: Verify of IPv6 RA DNS Name:{} result: {}'
                           .format(cli_type.upper(), dnss_dict['dnss_name'], result.data))
                    return False
        if rdnss_list:
            for rdnss_dict in rdnss_list:
                if 'Vlan' in interface_name:
                    ra_rdnss_obj = umf_intf.RoutedVlanRdnssAddress(Address=rdnss_dict['address'], Interface=intf_obj)
                else:
                    ra_rdnss_obj = umf_intf.SubinterfaceRdnssAddress(Address=rdnss_dict['address'],
                                                                     Subinterface=intf_obj)
                if 'valid_life' in rdnss_dict.keys():
                    value = rdnss_dict['valid_life']
                    ra_rdnss_obj.ValidLifetime = 4294967295 if value == 'infinite' else value
                result = ra_rdnss_obj.verify(dut, match_subset=True, query_param=query_params_obj, cli_type=cli_type)
                if not result.ok():
                    st.log('test_step_failed: {}: Verify of IPv6 RA DNS prefix:{} result: {}'
                           .format(cli_type.upper(), rdnss_dict['address'], result.data))
                    return False
    elif cli_type == 'vtysh':
        command = "show ipv6 nd ra-interfaces"
        output = st.show(dut, command, type=cli_type)
        args1 = ['ra_interval_sec', 'intf_name', 'reachable_time', 'retrans_interval', 'ra_hop_limit'
                                                                                       'ra_pkt_sent', 'ra_pkt_rcvd',
                 'ra_interval_msec', 'ra_lifetime', 'def_router_pref',
                 'home_agent_life', 'home_agent_pref', 'ra_mtu']
        args2 = ['ra_manage_conf', 'ra_other_conf', 'home_agent_conf', 'ra_adv_interval']
        fields = {'ra_manage_conf': 'DHCP', 'ra_other_conf': '', 'home_agent_conf': 'Home Agent flag bit set',
                  'ra_adv_interval': 'Adv. Interval option'}
        if output:
            for i in output:
                if i['intf_name'] == interface:
                    out1 = i
            for key in args1:
                if key in kwargs:
                    if key == "home_agent_life" and not kwargs[key]:
                        continue
                    if key == "ra_mtu":
                        continue
                    if not str(kwargs[key]) == out1[key]:
                        st.log("Provided and configured address values are not matching for {}.".format(key))
                        return False
            for key in args2:
                if key in kwargs:
                    value = kwargs[key]
                    if value:
                        if not str(fields[key]) == out1[key]:
                            st.log("Provided and configured address values are not matching for {}.".format(key))
                            return False
                    else:
                        value = ''
                        if not value == out1[key]:
                            st.log("Provided and configured address values are not matching for {}.".format(key))
                            return False
            if kwargs.get('prefix_list'):
                for prefix_dict in kwargs['prefix_list']:
                    if 'prefix' in prefix_dict.keys():
                        value = prefix_dict['prefix']
                        try:
                            index = out1['prefix'].index(value)
                        except ValueError:
                            st.log('item is not in the list')
                        if value not in out1['prefix']:
                            st.log("Provided and configured address values are not matching for prefix address.")
                            return False
                    if 'preferred_life' in prefix_dict.keys():
                        value = prefix_dict['preferred_life']
                        if not str(value) == out1['prefix_prefd_lifetime'][index]:
                            st.log("Provided and configured address values are not matching for prefix preferred life.")
                            return False
                    if 'valid_life' in prefix_dict.keys():
                        value = prefix_dict['valid_life']
                        if not str(value) == out1['prefix_valid_lifetime'][index]:
                            st.log("Provided and configured address values are not matching for prefix valid life.")
                            return False
                    if 'no_auto_cfg' in prefix_dict.keys():
                        value = prefix_dict['no_auto_cfg']
                        value = 'no-autoconfig' if value is True else None
                        if not str(value) == out1['prefix_no_auto_cfg'][index]:
                            st.log("Provided and configured address values are not matching for prefix no autoconfig.")
                            return False
                    if 'off_link' in prefix_dict.keys():
                        value = prefix_dict['off_link']
                        value = 'off-link' if value is True else None
                        if not str(value) == out1['prefix_off_link'][index]:
                            st.log("Provided and configured address values are not matching for prefix offlink.")
                            return False
                    if 'router_add' in prefix_dict.keys():
                        value = prefix_dict['router_add']
                        value = 'router-address' if value is True else None
                        if not str(value) == out1['prefix_router_add'][index]:
                            st.log("Provided and configured address values are not matching for prefix routeradd.")
                            return False
            if kwargs.get('dnssl_list'):
                for dnssl_dict in dnssl_list:
                    if 'dnss_name' in dnssl_dict.keys():
                        value = dnssl_dict['dnss_name']
                        try:
                            index = out1['dnssl'].index(value)
                        except ValueError:
                            st.log('item is not in the list')
                        if str(value) not in out1["dnssl"]:
                            st.log("Provided and configured address values are not matching for dnssl name.")
                            return False
                    if 'valid_life' in dnssl_dict.keys():
                        value = dnssl_dict['valid_life']
                        if not str(value) == out1['dnssl_lifetime'][index]:
                            st.log("Provided and configured address values are not matching for dnssl valid life.")
                            return False
            if kwargs.get('rdnss_list'):
                for rdnss_dict in rdnss_list:
                    if 'address' in rdnss_dict.keys():
                        value = rdnss_dict['address']
                        try:
                            index = out1['rdnss'].index(value)
                        except ValueError:
                            st.log('item is not in the list')
                        if str(value) not in out1["rdnss"]:
                            st.log("Provided and configured address values are not matching for rdnss address.")
                            return False
                    if 'valid_life' in rdnss_dict.keys():
                        value = rdnss_dict['valid_life']
                        if not str(value) == out1['rdnss_lifetime'][index]:
                            st.log("Provided and configured address values are not matching for rdnss valid life.")
                            return False
        else:
            return False
    else:
        st.error("Invalid CLI type - {}".format(cli_type))
        return False

    return True


def show_running_config(dut, **kwargs):
    """
    API to verify ntp on DUT
    Author : Nagarjuna Suravarapu (nagarjuna.survarapu@broadcom.com)
    :param dut:
    :return:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    intf = kwargs.get('intf', None)
    cli_type = 'klish' if cli_type in get_supported_ui_type_list() else cli_type
    if cli_type in ["klish", "rest-patch", "rest-put", "click"]:
        cmd = 'show running-configuration interface {}'.format(intf)
        output = st.show(dut, cmd, skip_tmpl=True, type="klish")
        st.banner(output)
    else:
        st.log("UNSUPPORTED CLI TYPE")
        return False
    return output
