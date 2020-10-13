# This file contains the list of API's which performs BGP operations.
# Author : Chaitanya Vella (Chaitanya-vella.kumar@broadcom.com)
from spytest import st
import json
import re
import apis.system.reboot as reboot
from spytest.utils import filter_and_select
import spytest.utils as utils
from utilities.utils import fail_on_error, get_interface_number_from_name


def enable_docker_routing_config_mode(dut):
    """

    :param dut:
    :return:
    """
    data = {"DEVICE_METADATA": {"localhost": {"docker_routing_config_mode": "split"}}}
    split_config = json.dumps(data)
    json.loads(split_config)
    st.apply_json(dut, split_config)
    reboot.config_save(dut)


def enable_router_bgp_mode(dut, **kwargs):
    """

    :param dut:
    :param local_asn:
    :return:
    """
    st.log("Enabling router BGP mode ..")
    if 'local_asn' in kwargs:
        command = "router bgp {}".format(kwargs['local_asn'])
    else:
        command = "router bgp"

    if 'vrf_name' in kwargs and kwargs['vrf_name'] != 'default-vrf':
        command += ' vrf ' + kwargs['vrf_name']
    if 'router_id' in kwargs:
        command += '\n bgp router-id {}'.format(kwargs['router_id'])

    st.config(dut, command, type='vtysh')
    return True


def config_router_bgp_mode(dut, local_asn, config_mode='enable', vrf='default', cli_type="vtysh", skip_error_check=True):
    """

    :param dut:
    :param local_asn:
    :param config_mode:
    :param vrf:
    :return:
    """
    st.log("Config router BGP mode .. {}".format(config_mode))
    mode = "no" if config_mode.lower() == 'disable' else ""
    if vrf.lower() == 'default':
        command = "{} router bgp {}".format(mode, local_asn)
    else:
        command = "{} router bgp {} vrf {}".format(mode, local_asn, vrf)
    output = st.config(dut, command, type=cli_type, skip_error_check=skip_error_check)
    return True


def unconfig_router_bgp(dut, **kwargs):
    """

    :param dut
    :return:
    """
    st.log("Unconfiguring Bgp in {}".format(dut))
    cli_type = "vtysh" if not kwargs.get("cli_type") else kwargs.get("cli_type")
    command = "no router bgp"
    if 'vrf_name' in kwargs and 'local_asn' in kwargs:
        command += '  ' + kwargs['local_asn'] + ' vrf ' + kwargs['vrf_name']
    st.config(dut, command, type=cli_type)
    return True


def cleanup_router_bgp(dut_list, cli_type="vtysh", skip_error_check=True):
    """

    :param dut_list:
    :return:
    """
    dut_li = list(dut_list) if isinstance(dut_list, list) else [dut_list]
    for dut in dut_li:
        st.log("Cleanup BGP mode ..")
        command = "no router bgp"
        st.config(dut, command, type=cli_type, skip_error_check=skip_error_check)
    return True


def _cleanup_bgp_config(dut_list, cli_type="vtysh"):
    """

    :param dut_list:
    :return:
    """
    dut_li = list(dut_list) if isinstance(dut_list, list) else [dut_list]
    for dut in dut_li:
        command = "show running bgp"
        output = st.config(dut, command, type=cli_type, conf=False)
        st.log("Cleanup BGP configuration on %s.." % dut)
        config = output.splitlines()
        line = 0
        count = len(config)
        while line < count:
            _str = config[line]
            if re.match(r'router bgp .*', _str, re.IGNORECASE):
                st.config(dut, "no {}".format(_str), type=cli_type)
                while config[line] != "!":
                    line += 1
            line += 1
    return True


def cleanup_bgp_config(dut_list, cli_type="vtysh", thread=True):
    """

    :param dut_list:
    :param thread:
    :return:
    """
    dut_li = list(dut_list) if isinstance(dut_list, list) else [dut_list]
    [out, exceptions] = utils.exec_foreach(thread, dut_li, _cleanup_bgp_config, cli_type=cli_type)
    st.log(exceptions)
    return False if False in out else True



def config_bgp_router(dut, local_asn, router_id='', keep_alive=60, hold=180, config='yes',**kwargs):
    """

    :param dut:
    :param local_asn:
    :param router_id:
    :param keep_alive:
    :param hold:
    :return:
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut))
    cli_type = "vtysh" if cli_type in ['click',"vtysh"] else "klish"

    command = "router bgp {}\n".format(local_asn)
    if cli_type == 'vtysh':
        if config ==  'yes':
            if router_id:
                command += "\n bgp router-id {}".format(router_id)
            if keep_alive and hold:
                command += "\n timers bgp {} {}".format(keep_alive, hold)
        if config ==  'no' and keep_alive:
            command += "\n no timers bgp\n"
        if config ==  'no' and router_id:
            command += "\n no bgp router-id {}".format(router_id)
    elif cli_type == 'klish':
        if config ==  'yes':
            if router_id:
                command += "router-id {}\n".format(router_id)
            if keep_alive and hold:
                command += "timers {} {}\n".format(keep_alive, hold)
        if config ==  'no' and keep_alive:
            command += "no timers {} {}\n".format(keep_alive, hold)
        if config ==  'no' and router_id:
            command += "no router-id \n"
        command += "exit"

    st.config(dut, command.split("\n") if cli_type == 'klish' else command, type=cli_type)
    return True


def create_bgp_router(dut, local_asn, router_id='', keep_alive=60, hold=180):
    """

    :param dut:
    :param local_asn:
    :param router_id:
    :param keep_alive:
    :param hold:
    :return:
    """
    st.log("Creating BGP router ..")
    config_router_bgp_mode(dut, local_asn)
    # Add validation for IPV4 address
    if router_id:
        command = "bgp router-id {}".format(router_id)
        st.config(dut, command, type='vtysh')
    command = "timers bgp {} {}".format(keep_alive, hold)
    st.config(dut, command, type='vtysh')
    return True


def create_bgp_neighbor(dut, local_asn, neighbor_ip, remote_asn, keep_alive=60, hold=180, password=None, family="ipv4",vrf='default'):
    """

    :param dut:
    :param local_asn:
    :param neighbor_ip:
    :param remote_asn:
    :param keep_alive:
    :param hold:
    :param password:
    :param family:
    :return:
    """
    st.log("Creating BGP neighbor ..")
    # Add validation for IPV4 / IPV6 address
    config_router_bgp_mode(dut, local_asn, vrf=vrf)

    command = "neighbor {} remote-as {}".format(neighbor_ip, remote_asn)
    st.config(dut, command, type='vtysh')
    command = "neighbor {} timers {} {}".format(neighbor_ip, keep_alive, hold)
    st.config(dut, command, type='vtysh')
    if password:
        command = " neighbor {} password {}".format(neighbor_ip, password)
        st.config(dut, command, type='vtysh')
    # Gather the IP type using the validation result
    # ipv6 = False
    if family == "ipv6":
        command = "address-family ipv6 unicast"
        st.config(dut, command, type='vtysh')
        command = "neighbor {} activate".format(neighbor_ip)
        st.config(dut, command, type='vtysh')
    if family == "ipv4":
        command = "address-family ipv4 unicast"
        st.config(dut, command, type='vtysh')
        command = "neighbor {} activate".format(neighbor_ip)
        st.config(dut, command, type='vtysh')
    return True


def config_bgp_neighbor(dut, local_asn, neighbor_ip, remote_asn, family="ipv4", keep_alive=60, hold=180, config='yes', vrf='default', cli_type="vtysh", skip_error_check=True, connect_retry=120):
    """

    :param dut:
    :param local_asn:
    :param neighbor_ip:
    :param remote_asn:
    :param keep_alive:
    :param hold:
    :param family:
    :return:
    """

    cfgmode = 'no' if config != 'yes' else ''
    if family !='ipv4' and family != 'ipv6':
        return False
    if cli_type=="vtysh":
        if vrf.lower() == 'default':
            command  = "router bgp {}".format(local_asn)
        else:
            command = "router bgp {} vrf {}".format(local_asn, vrf)
        command += "\n {} neighbor {} remote-as {}".format(cfgmode, neighbor_ip, remote_asn)

        if config == 'yes' :
            command += "\n neighbor {} timers {} {}".format(neighbor_ip, keep_alive, hold)
            command += "\n neighbor {} timers connect {}".format(neighbor_ip, connect_retry)
            command += "\n address-family {} unicast".format(family)
            command += "\n neighbor {} activate".format(neighbor_ip)

        st.config(dut, command, type=cli_type)
        return True
    elif cli_type=="klish":
        commands = list()
        commands.append("router bgp {}".format(local_asn) if vrf.lower() == 'default' else "router bgp {} vrf {}".format(local_asn, vrf))
        commands.append("{} neighbor {}".format(cfgmode, neighbor_ip))
        if config == "yes":
            commands.append("remote-as {}".format(remote_asn))
            commands.append("timers {} {}".format(keep_alive, hold))
            commands.append("timers connect {}".format(connect_retry))
            commands.append("address-family {} unicast".format(family))
            commands.append("activate")
            commands.append("exit")
        st.config(dut, commands, type=cli_type, skip_error_check=skip_error_check)
        return True
    else:
        st.error("UNSUPPORTED CLI TYPE")
        return False


def config_bgp_neighbor_properties(dut, local_asn, neighbor_ip, family=None, mode=None, **kwargs):
    """

    :param dut:
    :param local_asn:
    :param neighbor_ip:
    :param family:
    :param mode:
    :param kwargs:
    :return:
    """
    st.log("Configuring the BGP neighbor password ..")
    properties = kwargs
    cli_type = kwargs.get("cli_type", "vtysh")
    skip_error_check = kwargs.get("skip_error_check", True)
    # Add validation for IPV4 / IPV6 address
    config_router_bgp_mode(dut, local_asn, cli_type=cli_type)
    no_form = "no" if "no_form" in properties and properties["no_form"] == "no" else ""
    if cli_type == "vtysh":
        if "password" in properties:
            command = "{} neighbor {} password {}".format(no_form, neighbor_ip, properties["password"]).strip()
            st.config(dut, command, type=cli_type)
        if "keep_alive" in properties and "hold_time" in properties:
            command = "{} neighbor {} timers {} {}".format(no_form, neighbor_ip, properties["keep_alive"],
                                                           properties["hold_time"])
            st.config(dut, command, type=cli_type)
        if "neighbor_shutdown" in properties:
            command = "{} neighbor {} shutdown".format(no_form, neighbor_ip)
            st.config(dut, command, type=cli_type)
        if family and mode:
            command = "address-family {} {}".format(family, mode)
            st.config(dut, command, type=cli_type)
            if "activate" in properties:
                if properties["activate"]:
                    command = "{} neighbor {} activate".format(no_form, neighbor_ip)
                    st.config(dut, command, type=cli_type)
            if "default-originate" in properties:
                if properties["default-originate"]:
                    command = "{} neighbor {} default-originate".format(no_form, neighbor_ip)
                    st.config(dut, command, type=cli_type)
            if "maximum-prefix" in properties:
                command = "{} neighbor {} maximum-prefix {}".format(no_form, neighbor_ip, properties["maximum-prefix"])
                st.config(dut, command, type=cli_type)
        return True
    elif cli_type == "klish":
        commands = list()
        neigh_name = get_interface_number_from_name(neighbor_ip)
        if isinstance(neigh_name, dict):
            commands.append("neighbor interface {} {}".format(neigh_name["type"], neigh_name["number"]))
        else:
            commands.append("neighbor {}".format(neigh_name))
        if "password" in properties:
            commands.append("{} password {}".format(no_form, properties["password"]))
        if "keep_alive" in properties and "hold_time" in properties:
            commands.append("{} timers {} {}".format(no_form, properties["keep_alive"],properties["hold_time"]))
        if "neighbor_shutdown" in properties:
            commands.append("{} shutdown".format(no_form))
        if family and mode:
            commands.append("address-family {} {}".format(family, mode))
            if "activate" in properties:
                commands.append("{} activate".format(no_form))
            if "default-originate" in properties:
                commands.append("{} default-originate".format(no_form))
            if "maximum-prefix" in properties:
                commands.append("{} maximum-prefix {}".format(no_form, properties["maximum-prefix"]))
            commands.append("exit")
        st.config(dut, commands, type=cli_type, skip_error_check=skip_error_check)
        return True
    else:
        st.error("UNSUPPORTE CLI TYPE")
        return False


def delete_bgp_neighbor(dut, local_asn, neighbor_ip, remote_asn, vrf='default', cli_type="vtysh", skip_error_check=True):
    """

    :param dut:
    :param local_asn:
    :param neighbor_ip:
    :param remote_asn:
    :return:
    """
    st.log("Deleting BGP neighbor ..")
    # Add validation for IPV4 / IPV6 address
    config_router_bgp_mode(dut, local_asn, vrf=vrf, cli_type=cli_type)
    if cli_type == "vtysh":
        command = "no neighbor {} remote-as {}".format(neighbor_ip, remote_asn)
        st.config(dut, command, type=cli_type, skip_error_check=skip_error_check)
    elif cli_type == "klish":
        commands = list()
        commands.append("neighbor {}".format(neighbor_ip))
        commands.append("no remote-as {}".format(remote_asn))
        commands.append("exit")
        commands.append("no neighbor {}".format(neighbor_ip))
        st.config(dut, commands, type=cli_type, skip_error_check=skip_error_check)
    else:
        st.error("UNSUPPORTE CLI TYPE")
        return False
    return True


def change_bgp_neighbor_admin_status(dut, local_asn, neighbor_ip, operation=1):
    """

    :param dut:
    :param local_asn:
    :param neighbor_ip:
    :param operation:
    :return:
    """
    st.log("Shut/no-shut BGP neighbor ..")
    config_router_bgp_mode(dut, local_asn)
    if operation == 0:
        command = "neighbor {} shutdown".format(neighbor_ip)
        st.config(dut, command, type='vtysh')
    elif operation == 1:
        command = "no neighbor {} shutdown".format(neighbor_ip)
        st.config(dut, command, type='vtysh')
    else:
        st.error("Invalid operation provided.")
        return False

    return True


def advertise_bgp_network(dut, local_asn, network, route_map='', config='yes', family='ipv4', cli_type="vtysh", skip_error_check=True):
    """

    :param dut:
    :param local_asn:
    :param network:
    :return:
    """
    st.log("Advertise BGP network ..")
    # Add validation for IPV4 / IPV6 address
    config_router_bgp_mode(dut, local_asn, cli_type=cli_type)
    mode = "" if config.lower() == 'yes' else "no"
    # Gather IPv6 type using validation
    if cli_type == "vtysh":
        if family == 'ipv6':
            command = "address-family ipv6 unicast"
            st.config(dut, command, type=cli_type, skip_error_check=skip_error_check)

        if route_map.lower() == '':
            command = "{} network {}".format(mode, network)
        else:
            command = "{} network {} route-map {}".format(mode, network,route_map)
        st.config(dut, command, type=cli_type, skip_error_check=skip_error_check)
    elif cli_type == "klish":
        commands = list()
        commands.append("address-family {} unicast".format(family))
        if route_map.lower() == '':
            commands.append("{} network {}".format(mode, network))
        else:
            commands.append("{} network {} route-map {}".format(mode, network, route_map))
        st.config(dut, commands, type=cli_type, skip_error_check=skip_error_check)
    else:
        st.error("UNSUPPORTED CLI TYPE")
        return False
    return True


def config_bgp_network_advertise(dut, local_asn, network, route_map='', addr_family='ipv4', config='yes', cli_type="vtysh", skip_error_check=True):

    cfgmode = 'no' if config != 'yes' else ''
    if cli_type == "vtysh":
        command  = "router bgp {}".format(local_asn)
        command += "\n address-family {} {}".format(addr_family, "unicast")
        command += "\n {} network {}".format(cfgmode, network)
        if route_map != '' :
            command += "route-map {}".format(route_map)
        st.config(dut, command, type=cli_type)
        return True
    elif cli_type == "klish":
        commands = list()
        commands.append("router bgp {}".format(local_asn))
        commands.append("address-family {} {}".format(addr_family, "unicast"))
        cmd = "route-map {}".format(route_map) if route_map else ""
        commands.append("{} network {} {}".format(cfgmode, network, cmd).strip())
        commands.append("exit")
        st.config(dut, commands, type=cli_type, skip_error_check=skip_error_check)
        return True
    else:
        st.error("UNSUPPORTED CLI TYPE")
        return False

def show_bgp_ipv4_summary_vtysh(dut,vrf='default', cli_type="vtysh"):
    """

    :param dut:
    :return:
    """
    if cli_type == "vtysh":
        if vrf == 'default':
            command = "show ip bgp summary"
        else:
            command = "show ip bgp vrf {} summary".format(vrf)
        return st.show(dut, command, type='vtysh')
    elif cli_type == "klish":
        if vrf == 'default':
            command = "show ip bgp summary"
        else:
            command = "show ip bgp vrf {} summary".format(vrf)
        return st.show(dut, command, type=cli_type)
    else:
        st.log("UNSUPPORTED CLI TYPE")
        return False

def show_bgp_ipv6_summary_vtysh(dut,vrf='default', cli_type="vtysh"):
    """

    :param dut:
    :return:
    """
    if cli_type == "vtysh":
        if vrf == 'default':
            command = "show bgp ipv6 summary"
        else:
            command = "show bgp vrf {} ipv6 summary".format(vrf)
        return st.show(dut, command, type='vtysh')
    elif cli_type == "klish":
        if vrf == 'default':
            command = "show ip bgp summary"
        else:
            command = "show ip bgp vrf {} ipv6 summary".format(vrf)
        return st.show(dut, command, type=cli_type)
    else:
        st.log("UNSUPPORTED CLI TYPE")
        return False


def show_bgp_ipv4_summary(dut):
    """

    :param dut:
    :return:
    """
    command = "show bgp ipv4 summary"
    return st.show(dut, command)


def show_bgp_ipv6_summary(dut):
    """

    :param dut:
    :return:
    """
    command = "show bgp ipv6 summary"
    return st.show(dut, command)


def verify_ipv6_bgp_summary(dut, **kwargs):
    """
    :param interface_name:
    :type interface_name:
    :param ip_address:
    :type ip_address:
    :param dut:
    :type dut:
    :return:
    :rtype:

    EX; verify_ipv6_bgp_summary(vars.D1, 'neighbor'= '3341::2')
    """
    output = show_bgp_ipv6_summary(dut)
    for each in kwargs.keys():
        match = {each: kwargs[each]}
        entries = filter_and_select(output, None, match)
        if not entries:
            st.log("{} and {} is not match ".format(each, kwargs[each]))
            return False
    return True


def show_bgp_neighbor(dut, neighbor_ip):
    """

    :param dut:
    :param neighbor_ip:
    :return:
    """
    command = "show bgp neighbor {}".format(neighbor_ip)
    return st.show(dut, command)


def show_bgp_ipv4_neighbor_vtysh(dut, neighbor_ip=None,vrf='default'):
    """

    :param dut:
    :param neighbor_ip:
    :param property:
    :param address_family:
    :return:
    """
    if vrf == 'default':
        command = "show ip bgp neighbors"
    else:
        command = "show ip bgp vrf {} neighbors".format(vrf)
    if neighbor_ip:
        command += " {}".format(neighbor_ip)
    return st.show(dut, command, type='vtysh')


def show_bgp_ipv6_neighbor_vtysh(dut, neighbor_ip=None,vrf='default'):
    """

    :param dut:
    :param neighbor_ip:
    :return:
    """
    if vrf == 'default':
        command = "show bgp ipv6 neighbors"
    else:
        command = "show bgp vrf {} ipv6 neighbors".format(vrf)
    if neighbor_ip:
        command += " {}".format(neighbor_ip)
    return st.show(dut, command, type='vtysh')


def clear_ip_bgp(dut):
    """

    :param dut:
    :return:
    """
    command = "sonic-clear ip bgp"
    st.config(dut, command)


def clear_bgp_vtysh(dut, address_family="all"):
    """

    :param dut:
    :param value:
    :param address_family: ipv4|ipv6|all
    :return:
    """
    af_list = ['ipv4','ipv6']
    if address_family == 'ipv4':
        af_list = ['ipv4']
    elif address_family == 'ipv6':
        af_list = ['ipv6']
    for each_af in af_list:
        command = "clear ip bgp {} *".format(each_af)
        st.config(dut, command, type='vtysh', conf=False)

def clear_ip_bgp_vtysh(dut, value="*"):
    command = "clear ip bgp {}".format(value)
    st.config(dut, command, type='vtysh', conf=False)

def clear_ipv6_bgp_vtysh(dut, value="*"):
    command = "clear bgp ipv6 {}".format(value)
    st.config(dut, command, type='vtysh', conf=False)

def clear_ip_bgp_vrf_vtysh(dut,vrf,family='ipv4',value="*"):
    command = "clear bgp vrf {} {} {}".format(vrf,family,value)
    st.config(dut, command, type='vtysh', conf=False)

def create_bgp_aggregate_address(dut, **kwargs):
    """
    API to create the BGP aggregate address
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param local_asn:
    :param address_range:
    :param as_set:
    :param summary:
    :return:
    """
    if "local_asn" not in kwargs and "address_range" not in kwargs and "config" not in kwargs and "family" not in kwargs:
        st.error("Mandatory parameters not provided")
    skip_error_check = kwargs.get("skip_error_check", True)
    cli_type=kwargs.get("cli_type","vtysh")
    config_router_bgp_mode(dut, kwargs["local_asn"], cli_type=cli_type)
    if cli_type == "vtysh":
        command = "address-family {}\n".format(kwargs["family"])
        if kwargs["config"] == "add":
           command += "aggregate-address {}".format(kwargs["address_range"])
        elif kwargs["config"] == "delete":
           command += "no aggregate-address {}".format(kwargs["address_range"])
        if "summary" in kwargs:
            command += " summary-only"
        if "as_set" in kwargs:
            command += " as-set"
        st.config(dut, command, type=cli_type)
    elif cli_type=="klish":
        commands = list()
        commands.append("address-family {} unicast".format(kwargs["family"]))
        if kwargs.get("config") == "add":
            command = "aggregate-address {}".format(kwargs["address_range"])
            if "summary" in kwargs:
                command += " summary-only"
            if "as_set" in kwargs:
                command += " as-set"
        else:
            command = "no aggregate-address {}".format(kwargs["address_range"])
        commands.append(command)
        commands.append("exit")
        st.config(dut, commands, type=cli_type, skip_error_check=skip_error_check)
    else:
        st.error("Unsupported CLI TYPE")
        return False

def create_bgp_update_delay(dut, local_asn, time=0, cli_type="vtysh", skip_error_check=True):
    """

    :param dut:
    :param local_asn:
    :param time:
    :return:
    """
    config_router_bgp_mode(dut, local_asn, cli_type=cli_type)
    command = "update-delay {}".format(time)
    st.config(dut, command,type=cli_type, skip_error_check=skip_error_check)


def create_bgp_always_compare_med(dut, local_asn):
    """

    :param dut:
    :param local_asn:
    :return:
    """
    config_router_bgp_mode(dut, local_asn)
    command = "bgp always-compare-med"
    st.config(dut, command, type='vtysh')


def create_bgp_best_path(dut, local_asn, user_command):
    """

    :param dut:
    :param local_asn:
    :param user_command:
    :return:
    """
    config_router_bgp_mode(dut, local_asn)
    command = "bgp bestpath {}".format(user_command)
    st.config(dut, command, type='vtysh')


def create_bgp_client_to_client_reflection(dut, local_asn, config='yes', cli_type="vtysh", skip_error_check=True):
    """

    :param dut:
    :param local_asn:
    :return:
    """

    cfgmode = 'no' if config != 'yes' else ''
    if cli_type == "vtysh":
        command  = "router bgp {}".format(local_asn)
        command += "\n {} bgp client-to-client reflection".format(cfgmode)
        '''
        config_router_bgp_mode(dut, local_asn)

        if config == 'yes':
            command = "bgp client-to-client reflection"
        else :
            command = "no bgp client-to-client reflection"
        '''
        st.config(dut, command, type=cli_type)
        return True
    elif cli_type == "klish":
        commands = list()
        commands.append("router bgp {}".format(local_asn))
        commands.append("{} client-to-client reflection".format(cfgmode))
        st.config(dut, commands, type=cli_type, skip_error_check=skip_error_check)
        return True
    else:
        st.error("UNSUPPORTED CLI TYPE")
        return False


def create_bgp_route_reflector_client(dut, local_asn, addr_family, nbr_ip, config='yes', cli_type="vtysh", skip_error_check=True):
    """

    :param dut:
    :param local_asn:
    :param addr_family:
    :param nbr_ip:
    :return:
    """

    cfgmode = 'no' if config != 'yes' else ''
    if cli_type == "vtysh":
        command  = "router bgp {}".format(local_asn)
        command += "\n address-family {} {}".format(addr_family, "unicast")
        command += "\n {} neighbor {} route-reflector-client".format(cfgmode, nbr_ip)
        '''
        config_router_bgp_mode(dut, local_asn)

        command = "address-family {} unicast".format(addr_family)
        st.config(dut, command, type='vtysh')

        if config == 'yes':
            command = "neighbor {} route-reflector-client".format(nbr_ip)
        elif config == 'no' :
            command = "no neighbor {} route-reflector-client".format(nbr_ip)
        else:
            return False
        '''
        st.config(dut, command, type=cli_type)
        return True
    elif cli_type == "klish":
        neigh_name = get_interface_number_from_name(nbr_ip)
        commands = list()
        commands.append("router bgp {}".format(local_asn))
        if isinstance(neigh_name, dict):
            commands.append("{} neighbor interface {} {}".format(cfgmode, neigh_name["type"], neigh_name["number"]))
        else:
            commands.append("{} neighbor {}".format(cfgmode, neigh_name))
        if config == "yes":
            commands.append("address-family {} {}".format(addr_family, "unicast"))
            commands.append("{} route-reflector-client".format(cfgmode))
            commands.append("exit")
        st.config(dut, commands, type=cli_type, skip_error_check=skip_error_check)
        return True
    else:
        st.error("UNSUPPORTED CLI TYPE")
        return False


def create_bgp_next_hop_self(dut, local_asn, addr_family, nbr_ip, force='no', config='yes', cli_type="vtysh", skip_error_check=True):
    """

    :param dut:
    :param local_asn:
    :param addr_family:
    :param nbr_ip:
    :param config:
    :return:
    """
    cfgmode = 'no' if config != 'yes' else ''
    if cli_type == "vtysh":
        command  = "router bgp {}".format(local_asn)
        command += "\n address-family {} {}".format(addr_family, "unicast")
        command += "\n {} neighbor {} next-hop-self".format(cfgmode, nbr_ip)
        if force == 'yes' :
           command += " force"
        '''
        config_router_bgp_mode(dut, local_asn)
        command = "address-family {} unicast".format(addr_family)
        st.config(dut, command, type='vtysh')
        if config == 'yes':
            command = "neighbor {} next-hop-self".format(nbr_ip)
        elif config == 'no' :
            command = "no neighbor {} next-hop-self".format(nbr_ip)
        else:
            return False

        if force == 'yes' :
           command += " force"
        '''
        st.config(dut, command, type=cli_type)
        return True
    elif cli_type == "klish":
        commands = list()
        commands.append("router bgp {}".format(local_asn))
        commands.append("{} neighbor {}".format(cfgmode, nbr_ip))
        commands.append("address-family {} {}".format(addr_family, "unicast"))
        if config == "yes":
            force_cmd = "force" if force == 'yes' else ""
            commands.append("next-hop-self {}".format(force_cmd))
        commands.append("exit")
        st.config(dut, commands, type=cli_type, skip_error_check=skip_error_check)
        return True
    else:
        st.log("UNSUPPORTED CLI TYPE")
        return False


def create_bgp_cluster_id(dut, local_asn, cluster_id, cluster_ip):
    """

    :param dut:
    :param local_asn:
    :param cluster_id:
    :param cluster_ip:
    :return:
    """
    config_router_bgp_mode(dut, local_asn)
    command = "bgp cluster-id {}".format(cluster_id)
    st.config(dut, command, type='vtysh')
    command = "bgp cluster-id {}".format(cluster_ip)
    st.config(dut, command, type='vtysh')


def create_bgp_confideration(dut, local_asn, confd_id_as, confd_peers_as):
    """

    :param dut:
    :param local_asn:
    :param confd_id_as:
    :param confd_peers_as:
    :return:
    """
    config_router_bgp_mode(dut, local_asn)
    command = "bgp confideration identifier {}".format(confd_id_as)
    st.config(dut, command, type='vtysh')
    command = "bgp confideration peers  {}".format(confd_peers_as)
    st.config(dut, command, type='vtysh')


def create_bgp_dampening(dut, local_asn, half_life_time, timer_start, timer_start_supress, max_duration):
    """

    :param dut:
    :param local_asn:
    :param half_life_time:
    :param timer_start:
    :param timer_start_supress:
    :param max_duration:
    :return:
    """
    config_router_bgp_mode(dut, local_asn)
    command = "bgp dampening {} {} {} {}".format(half_life_time, timer_start, timer_start_supress, max_duration)
    st.config(dut, command, type='vtysh')


def config_bgp_default(dut, local_asn, user_command, config='yes', cli_type="vtysh", skip_error_check=True):
    """

    :param dut:
    :param local_asn:
    :param user_command:
    :return:
    """
    cfgmode = 'no' if config != 'yes' else ''
    if cli_type == "vtysh":
        command  = "router bgp {}".format(local_asn)
        command += "\n {} bgp default {}".format(cfgmode, user_command)
        '''
        config_router_bgp_mode(dut, local_asn)
        if config == 'yes':
            command = "bgp default {}".format(user_command)
        else:
            command = "no bgp default {}".format(user_command)
        '''
        st.config(dut, command, type=cli_type, skip_error_check=skip_error_check)
        return True
    elif cli_type == "klish":
        commands = list()
        commands.append("router bgp {}".format(local_asn))
        commands.append("{} default {}".format(cfgmode, user_command))
        st.config(dut, commands, type=cli_type, skip_error_check=skip_error_check)
        return True
    else:
        st.error("UNSUPPORTED CLI TYPE")
        return False



def config_bgp_always_compare_med(dut, local_asn, config='yes'):
    """

    :param dut:
    :param local_asn:
    :return:
    """
    config_router_bgp_mode(dut, local_asn)
    if config == 'yes' :
        command = "bgp always-compare-med"
    else :
        command = "no bgp always-compare-med"

    st.config(dut, command, type='vtysh')
    return True


def config_bgp_deterministic_med(dut, local_asn, config='yes'):
    """

    :param dut:
    :param local_asn:
    :return:
    """
    config_router_bgp_mode(dut, local_asn)

    if config == 'yes' :
       command = "bgp deterministic-med"
    else :
       command = "no bgp deterministic-med"

    st.config(dut, command, type='vtysh')

    return True


def config_bgp_disable_ebgp_connected_route_check(dut, local_asn):
    """

    :param dut:
    :param local_asn:
    :return:
    """
    config_router_bgp_mode(dut, local_asn)
    command = "bgp disable-ebgp-connected-route-check"
    st.config(dut, command, type='vtysh')


def config_bgp_graceful_restart(dut, **kwargs):
    """

    :param dut:
    :param local_asn:
    :param user_command:
    :return:
    """
    if "local_asn" not in kwargs and "config" not in kwargs :
        st.error("Mandatory params not provided")
        return False
    cli_type= kwargs.get("cli_type", "vtysh")
    config_router_bgp_mode(dut, kwargs["local_asn"], cli_type=cli_type)
    if kwargs.get("config") not in ["add","delete"]:
        st.log("Unsupported ACTION")
        return False
    mode = "no " if kwargs.get("config") != "add" else ""
    bgp_mode = "bgp " if cli_type == "vtysh" else ""
    skip_error_check = kwargs.get("skip_error_check", True)
    command = "{}{}graceful-restart".format(mode, bgp_mode)
    if not(mode == 'no ' and cli_type == 'vtysh'):
        if "user_command" in kwargs:
           command += " {}".format(kwargs["user_command"])
    st.config(dut, command, type=cli_type, skip_error_check=skip_error_check)

def config_bgp_graceful_shutdown(dut, local_asn, config="add", cli_type="vtysh", skip_error_check=True):
    """

    :param dut:
    :param local_asn:
    :return:
    """
    config_router_bgp_mode(dut, local_asn, cli_type=cli_type)
    mode = "no" if config != "add" else ""
    bgp_mode = "bgp" if cli_type == "vtysh" else ""
    command = "{} {} graceful-shutdown".format(mode, bgp_mode)
    st.config(dut, command, type=cli_type, skip_error_check=skip_error_check)

def config_bgp_listen(dut, local_asn, neighbor_address, subnet, peer_grp_name, limit, config='yes', cli_type="vtysh", skip_error_check=True):
   """

   :param dut:
   :param local_asn:
   :param neighbor_address:
   :param limit:
   :return:
   """
   config_router_bgp_mode(dut, local_asn, cli_type=cli_type)
   # Verify IPV4/IPV6 address pattern for neighbor address
   mode = "" if config.lower() == 'yes' else "no"
   if cli_type == "vtysh":
       if neighbor_address:
           command = "{} bgp listen range {}/{} peer-group {}".format(mode, neighbor_address, subnet, peer_grp_name)
           st.config(dut, command, type=cli_type, skip_error_check=skip_error_check)
       if limit:
           command = "{} bgp listen limit {}".format(mode, limit)
           st.config(dut, command, type=cli_type, skip_error_check=skip_error_check)
   elif cli_type == "klish":
       if neighbor_address:
           cmd = []
           if mode != 'no':
               cmd = ['peer-group {}'.format(peer_grp_name), 'exit']
           command = "{} listen range {}/{} peer-group {}".format(mode, neighbor_address, subnet, peer_grp_name)
           cmd.append(command)
           st.config(dut, cmd, type=cli_type, skip_error_check=skip_error_check)
       if limit:
           command = "{} listen limit {}".format(mode, limit)
           st.config(dut, command, type=cli_type, skip_error_check=skip_error_check)
   else:
       st.error("UNSUPPORTED CLI TYPE")
       return False

def config_bgp_listen_range(dut,local_asn,**kwargs):
    """

    :param dut:
    :param local_asn:
    :param neighbor_address:
    :param limit:
    :return:
    """

    cli_type = kwargs.get('cli_type', st.get_ui_type())
    neighbor_address = kwargs.get('neighbor_address', '')
    subnet = kwargs.get('subnet', '')
    peer_grp_name = kwargs.get('peer_grp_name', '')
    limit = kwargs.get('limit', '')
    config = kwargs.get('config','yes')
    vrf = kwargs.get('vrf', 'default')
    skip_error_check = kwargs.get('skip_error_check', True)
    if config.lower() == 'yes':
        mode = ""
    else:
        mode = 'no'
    cmd = ''
    if cli_type == 'vtysh' or cli_type == 'click':
        if neighbor_address:
            if vrf != 'default':
                cmd = cmd + 'router bgp {} vrf {}\n'.format(local_asn, vrf)
            else:
                cmd = cmd + 'router bgp {}\n'.format(local_asn)
            cmd = cmd + "{} bgp listen range {}/{} peer-group {}\n".format(mode, neighbor_address, subnet, peer_grp_name)
        if limit:
            if vrf != 'default':
                cmd = cmd + 'router bgp {} vrf {}\n'.format(local_asn, vrf)
            else:
                cmd = cmd + 'router bgp {}\n'.format(local_asn)
            cmd = cmd + "{} bgp listen limit {}".format(mode, limit)
        st.config(dut, cmd, type='vtysh', skip_error_check=skip_error_check)
        return True
    elif cli_type == "klish":
        if neighbor_address:
            if vrf != 'default':
                cmd = cmd + 'router bgp {} vrf {}\n'.format(local_asn, vrf)
            else:
                cmd = cmd + 'router bgp {}\n'.format(local_asn)
            cmd = cmd + "{} listen range {}/{} peer-group {}\n".format(mode, neighbor_address, subnet, peer_grp_name)
            cmd = cmd + "exit\n"
        if limit:
            if vrf != 'default':
                cmd = cmd + 'router bgp {} vrf {}\n'.format(local_asn, vrf)
            else:
                cmd = cmd + 'router bgp {}\n'.format(local_asn)
            cmd = cmd + "{} listen limit {}\n".format(mode, limit)
            cmd = cmd + "exit\n"
        st.config(dut, cmd, type=cli_type, skip_error_check=skip_error_check, conf = True)
        return True
    else:
        st.log("Unsupported CLI TYPE - {}".format(cli_type))
        return False



def config_bgp_log_neighbor_changes(dut, local_asn):
    """

    :param dut:
    :param local_asn:
    :return:
    """
    config_router_bgp_mode(dut, local_asn)
    command = "bgp log-neighbor-changes"
    st.config(dut, command, type='vtysh')


def config_bgp_max_med(dut, local_asn, user_command, config='yes'):
    """

    :param dut:
    :param local_asn:
    :param user_command:
    :return:
    """
    config_router_bgp_mode(dut, local_asn)
    if config == 'yes' :
       command = "bgp max-med {}".format(user_command)
    else :
       command = "no bgp max-med {}".format(user_command)

    st.config(dut, command, type='vtysh')
    return True


def config_route_map_delay_timer(dut, local_asn, timer):
    """

    :param dut:
    :param local_asn:
    :param timer:
    :return:
    """
    config_router_bgp_mode(dut, local_asn)
    command = "bgp route-map delay-timer {}".format(timer)
    st.config(dut, command, type='vtysh')


def enable_address_family_mode(dut, local_asn, mode_type, mode):
    """

    :param dut:
    :param local_asn:
    :param mode_type:
    :param mode:
    :return:
    """
    config_router_bgp_mode(dut, local_asn)
    command = "address-family {} {}".format(mode_type, mode)
    st.config(dut, command, type='vtysh')


def config_address_family_neighbor_ip(dut, local_asn, mode_type, mode, neighbor_ip, user_command):
    """

    :param dut:
    :param local_asn:
    :param mode_type:
    :param mode:
    :param neighbor_ip:
    :param user_command:
    :return:
    """
    enable_address_family_mode(dut, local_asn, mode_type, mode)
    # Verify neighbor IP address
    command = "neighbor {} {}".format(neighbor_ip, user_command)
    st.config(dut, command, type='vtysh')


def create_bgp_peergroup(dut, local_asn, peer_grp_name, remote_asn, keep_alive=60, hold=180, password=None, vrf='default', family='ipv4', skip_error_check = True, **kwargs):
    """

    :param dut:
    :param local_asn:
    :param peer_grp_name:
    :param remote_asn:
    :param keep_alive:
    :param hold:
    :param password:
    :return:
    """
    cli_type = kwargs.get('cli_mode', st.get_ui_type())
    neighbor_ip = kwargs.get('neighbor_ip',None)
    st.log("Creating BGP peer-group ..")
    cmd = ''
    if cli_type == 'vtysh' or cli_type == 'click':
        if vrf.lower() != 'default':
            cmd = cmd + "router bgp {} vrf {}\n".format(local_asn, vrf)
        else:
            cmd = cmd + "router bgp {}\n".format(local_asn)
        cmd = cmd + "neighbor {} peer-group\n".format(peer_grp_name)
        cmd = cmd + "neighbor {} remote-as {}\n".format(peer_grp_name, remote_asn)
        cmd = cmd + "neighbor {} timers {} {}\n".format(peer_grp_name, keep_alive, hold)
        if password:
            cmd = cmd + " neighbor {} password {}\n".format(peer_grp_name, password)
        cmd = cmd + "\n address-family {} unicast\n".format(family)
        cmd = cmd + "\n neighbor {} activate\n".format(peer_grp_name)
        st.config(dut, cmd, type='vtysh', skip_error_check=skip_error_check)
        return True
    elif cli_type == "klish":
        cmd = ''
        if vrf != 'default':
            cmd = cmd + 'router bgp {} vrf {}\n'.format(local_asn, vrf)
        else:
            cmd = cmd + 'router bgp {}\n'.format(local_asn)
        cmd = cmd + "peer-group {}\n".format(peer_grp_name)
        cmd = cmd + "exit\n"
        if neighbor_ip != None:
            cmd = cmd + "neighbor {}\n".format(neighbor_ip)
        cmd = cmd + "peer-group {}\n".format(peer_grp_name)
        cmd = cmd + "remote-as {}\n".format(remote_asn)
        cmd = cmd + "timers {} {}\n".format(keep_alive, hold)
        cmd = cmd + "exit\n"
        cmd = cmd + "exit\n"
        st.config(dut, cmd, type=cli_type, skip_error_check=skip_error_check, conf = True)
        return True
    else:
        st.log("Unsupported CLI TYPE - {}".format(cli_type))
        return False


def remove_bgp_peergroup(dut, local_asn, peer_grp_name, remote_asn, vrf='default'):
    """

    :param dut:
    :param local_asn:
    :param peer_grp_name:
    :param remote_asn:
    :return:
    """
    st.log("Removing BGP peer-group ..")
    # Add validation for IPV4 / IPV6 address
    config_router_bgp_mode(dut, local_asn,vrf=vrf)
    command = "no neighbor {} remote-as {}".format(peer_grp_name, remote_asn)
    st.config(dut, command, type='vtysh')
    command = "no neighbor {} peer-group".format(peer_grp_name)
    st.config(dut, command, type='vtysh')

def config_bgp_peer_group(dut, local_asn, peer_grp_name, config="yes", vrf="default", cli_type="klish", skip_error_check=True):
    config_router_bgp_mode(dut, local_asn, vrf=vrf)
    no_form = "" if config == "yes" else "no"
    if cli_type == "klish":
        config_router_bgp_mode(dut, local_asn, vrf=vrf, cli_type=cli_type)
        commands = list()
        commands.append("{} peer-group {}".format(no_form, peer_grp_name))
        if config == "yes":
            commands.append("exit")
        st.config(dut, commands, type=cli_type, skip_error_check=skip_error_check)
        return True
    elif cli_type == "vtysh":
        command = "{} neighbor {} peer-group".format(no_form, peer_grp_name)
        st.config(dut, command, type=cli_type, skip_error_check=skip_error_check)
        return True
    else:
        st.log("UNSUPPORTED CLI TYPE")
        return False

def create_bgp_neighbor_use_peergroup(dut, local_asn, peer_grp_name, neighbor_ip, family="ipv4", vrf='default', cli_type="vtysh", skip_error_check=True):
    """

    :param dut:
    :param local_asn:
    :param peer_grp_name:
    :param neighbor_ip:
    :param family:
    :param vrf:
    :return:
    """
    st.log("Creating BGP peer using peer-group ..")
    # Add validation for IPV4 / IPV6 address
    config_router_bgp_mode(dut, local_asn, vrf=vrf, cli_type=cli_type)
    if cli_type == "vtysh":
        command = "neighbor {} peer-group {}".format(neighbor_ip, peer_grp_name)
        st.config(dut, command, type='vtysh')
        # Gather the IP type using the validation result
        if family == "ipv6":
            command = "address-family ipv6 unicast"
            st.config(dut, command, type='vtysh')
            command = "neighbor {} activate".format(neighbor_ip)
            st.config(dut, command, type='vtysh')
    elif cli_type == "klish":
        commands = list()
        commands.append("peer-group {}".format(peer_grp_name))
        commands.append("exit")
        commands.append("neighbor {}".format(neighbor_ip))
        commands.append("peer-group {}".format(peer_grp_name))
        if family == "ipv6":
            commands.append("address-family ipv6 unicast")
            commands.append("activate")
            commands.append("exit")
        commands.append("exit")
        st.config(dut, commands, type=cli_type, skip_error_check=skip_error_check)

def create_bgp_neighbor_interface(dut, local_asn, interface_name, remote_asn,family,config='yes', cli_type="vtysh"):
    """

    :param dut:
    :param local_asn:
    :param interface_name:
    :param remote_asn:
    :param family:
    :param cli_type:
    :return:
    """
    st.log("Creating bgp neighbor on interface")
    if config.lower() == 'yes':
        mode = ""
    else:
        mode = 'no'
    # Add validation for IPV4 / IPV6 address
    config_router_bgp_mode(dut, local_asn, cli_type=cli_type)
    commands = list()
    if cli_type == "vtysh":
        commands.append("{} neighbor {} interface remote-as {}".format(mode,interface_name,remote_asn))
        if config == "yes":
            commands.append("address-family {} unicast".format(family))
            commands.append("{} neighbor {} activate".format(mode,interface_name))
    elif cli_type == "klish":
        interface_data = get_interface_number_from_name(interface_name)
        if isinstance(interface_data, dict):
            commands.append("neighbor interface {} {}".format(interface_data["type"], interface_data["number"]))
        else:
            commands.append("neighbor {}".format(interface_data))
        commands.append("{} remote-as {}".format(mode, remote_asn))
        if config == "yes":
            commands.append("address-family {} unicast".format(family))
            commands.append('{} activate'.format(mode))
            commands.append("exit")
        else:
            commands.append("exit")
    if commands:
        if config == "yes":
            commands.append("exit")
        st.config(dut, commands, type=cli_type, skip_error_check=True)
        return True
    else:
        return False

def remove_bgp_neighbor_use_peergroup(dut, local_asn, peer_grp_name, neighbor_ip, family="ipv4", vrf='default'):
    """

    :param dut:
    :param local_asn:
    :param peer_grp_name:
    :param neighbor_ip:
    :param family:
    :param vrf:
    :return:
    """
    st.log("Removing BGP peer using peer-group ..")
    # Add validation for IPV4 / IPV6 address
    config_router_bgp_mode(dut, local_asn, vrf=vrf)
    command = "no neighbor {} peer-group {}".format(neighbor_ip, peer_grp_name)
    st.config(dut, command, type='vtysh')
    # Gather the IP type using the validation result
    if family == "ipv6":
        command = "no neighbor {} activate".format(neighbor_ip)
        st.config(dut, command, type='vtysh')
        command = "address-family ipv6 unicast"
        st.config(dut, command, type='vtysh')


def config_bgp_multi_neigh_use_peergroup(dut, **kwargs):
    """
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    To config BGP peergroup with multi neighbours.
    :param dut:
    :param local_asn:
    :param peer_grp_name:
    :param remote_asn:
    :param neigh_ip_list:
    :param family: ipv4 | ipv6 | all
    :param activate: True | False
    :param password:
    :return:
    """
    if 'local_asn' not in kwargs or 'peer_grp_name' not in kwargs or 'remote_asn' not in kwargs \
            or 'neigh_ip_list' not in kwargs:
        st.error("Mandatory parameters are missing.")
        return False

    af = 'ipv4'
    if 'family' in kwargs:
        af = kwargs['family']

    neigh_ip_li = list(kwargs['neigh_ip_list']) if isinstance(kwargs['neigh_ip_list'], list) else \
        [kwargs['neigh_ip_list']]

    command = "router bgp {} \n".format(kwargs['local_asn'])
    command += "no bgp default ipv4-unicast \n"
    command += "neighbor {} peer-group \n".format(kwargs['peer_grp_name'])
    command += "neighbor {} remote-as {} \n".format(kwargs['peer_grp_name'], kwargs['remote_asn'])
    if 'keep_alive' in kwargs and 'hold' in kwargs:
        command += "neighbor {} timers {} {} \n".format(kwargs['peer_grp_name'], kwargs['keep_alive'], kwargs['hold'])
    if 'password' in kwargs:
        command += "neighbor {} password {} \n".format(kwargs['peer_grp_name'], kwargs['password'])
    for each_neigh in neigh_ip_li:
        command += "neighbor {} peer-group {} \n".format(each_neigh, kwargs['peer_grp_name'])
    if 'activate' in kwargs or 'redistribute' in kwargs  or 'routemap' in kwargs:
        command += "address-family {} unicast \n".format(af)
        if 'activate' in kwargs:
            command += "neighbor {} activate \n".format(kwargs['peer_grp_name'])
        if 'redistribute' in kwargs:
            redis_li = list(kwargs['redistribute']) if isinstance(kwargs['redistribute'], list) else [kwargs['redistribute']]
            for each_ in redis_li:
                command += "redistribute {} \n".format(each_)
        if 'routemap' in kwargs:
            if 'routemap_dir' in kwargs:
                command += "neighbor {} route-map {} {} \n".format(kwargs['peer_grp_name'], kwargs['routemap'], kwargs['routemap_dir'])
            else:
                command += "neighbor {} route-map {} in \n".format(kwargs['peer_grp_name'], kwargs['routemap'])

        command += "exit\n"
    command += "exit\n"
    st.config(dut, command, type='vtysh')
    return True


def verify_bgp_summary(dut, family='ipv4', shell="sonic", **kwargs):
    """

    :param dut:
    :param family:
    :param shell:
    :param kwargs:
    :return:
    """
    if shell not in ["vtysh", "klish"]:
        if 'vrf' in kwargs and shell=='sonic':
            vrf = kwargs.pop('vrf')
            cmd = "show bgp vrf {} {} summary".format(vrf,family.lower())
            output = st.show(dut,cmd)
        else:
            cmd = "show bgp {} summary".format(family.lower())
            output = st.show(dut,cmd)

    if shell in ["vtysh", "klish"]:
        vrf = kwargs.pop('vrf') if 'vrf' in kwargs else "default"
        if family.lower() == 'ipv4':
            output = show_bgp_ipv4_summary_vtysh(dut, vrf=vrf, cli_type=shell)
        elif family.lower() == 'ipv6':
            output = show_bgp_ipv6_summary_vtysh(dut, vrf=vrf, cli_type=shell)
        else:
            st.log("Invalid family {} or shell {}".format(family, shell))
            return False

    st.debug(output)
    # Specifically checking neighbor state
    if 'neighbor' in kwargs and 'state' in kwargs:
        neigh_li = list(kwargs['neighbor']) if isinstance(kwargs['neighbor'], list) else [kwargs['neighbor']]
        for each_neigh in neigh_li:
            match = {'neighbor': each_neigh}
            try:
                entries = filter_and_select(output, None, match)[0]
            except Exception as e:
                st.error(e)
                st.log("Neighbor {} given state {}, matching with {}  ".format(each_neigh, kwargs['state'],
                                                                                "Not Found"))
                return False
            if entries['state']:
                if kwargs['state'] == 'Established':
                    if entries['state'].isdigit() or entries['state'] == "ESTABLISHED":
                        st.log("Neighbor {} given state {}, matching with {}  ".format(each_neigh,
                                                                                kwargs['state'], entries['state']))
                    else:
                        st.error(
                            "Neighbor {} given state {}, matching with {}  ".format(each_neigh,
                                                                                kwargs['state'], entries['state']))
                        return False

                elif kwargs['state'] == 'Active':
                    if entries['state'] == "Active" or entries['state'] == "ACTIVE":
                        st.log("Neighbor {} given state {}, matching with {}  ".format(each_neigh,
                                                                                kwargs['state'], entries['state']))
                    else:
                        st.error(
                            "Neighbor {} given state {}, matching with {}  ".format(each_neigh,
                                                                                kwargs['state'], entries['state']))
                        return False
    for each in kwargs.keys():
        if 'state' not in each and 'neighbor' not in each:
            match = {each: kwargs[each]}
            entries = filter_and_select(output, None, match)
            if not entries:
                st.log("{} and {} is not match ".format(each, kwargs[each]))
                return False
    return True



def verify_bgp_neighbor(dut, neighbor_ip, **kwargs):
    """

    :param dut:
    :param neighbor_ip:
    :param kwargs:
    :return:
    """
    output = show_bgp_neighbor(dut, neighbor_ip)
    st.debug(output)
    for each in kwargs.keys():
        match = {each: kwargs[each]}
        entries = filter_and_select(output, None, match)
        if not entries:
            st.log("{} and {} is not match ".format(each, kwargs[each]))
            return False
    return True


def verify_bgp_ipv4_neighbor_vtysh(dut, neighbor_ip, **kwargs):
    """

    :param dut:
    :param neighbor_ip:
    :param kwargs:
    :return:
    """
    output = show_bgp_ipv4_neighbor_vtysh(dut, neighbor_ip)
    st.debug(output)
    for each in kwargs.keys():
        match = {each: kwargs[each]}
        entries = filter_and_select(output, None, match)
        if not entries:
            st.log("{} and {} is not match ".format(each, kwargs[each]))
            return False
    return True


def verify_bgp_ipv6_neighbor_vtysh(dut, neighbor_ip, **kwargs):
    """

    :param dut:
    :param neighbor_ip:
    :param kwargs:
    :return:
    """
    output = show_bgp_ipv6_neighbor_vtysh(dut, neighbor_ip)
    st.debug(output)
    for each in kwargs.keys():
        match = {each: kwargs[each]}
        entries = filter_and_select(output, None, match)
        if not entries:
            st.log("{} and {} is not match ".format(each, kwargs[each]))
            return False
    return True


def verify_bgp_neighbor_by_property(dut, neighbor_ip, property, value, address_family="ipv4"):
    """

    :param dut:
    :param neighbor_ip:
    :param property:
    :param value:
    :param address_family:
    :return:
    """
    command = "show bgp {} neighbor {} | grep {}".format(address_family, neighbor_ip, property)
    neighbor_details = st.config(dut, command)
    match = neighbor_details.find(value)
    if match < 1:
        return False
    return True


def config_address_family_redistribute(dut, local_asn, mode_type, mode, value, config='yes',vrf='default',skip_error_check=True, **kwargs):
    """
    :param dut:
    :param local_asn:
    :param mode_type:
    :param mode:
    :param value:
    :param config:
    :param vrf
    :return:
    """
    cli_type = kwargs.get('cli_type', st.get_ui_type())
    cfgmode = 'no' if config != 'yes' else ''
    cmd = ''
    if cli_type == 'vtysh' or cli_type == 'click':
        if vrf.lower() != 'default':
            cmd = cmd + "router bgp {} vrf {}\n".format(local_asn, vrf)
        else:
            cmd = cmd + "router bgp {}\n".format(local_asn)
        cmd = cmd + "\n address-family {} {}".format(mode_type, mode)
        cmd = cmd + "\n {} redistribute {}".format(cfgmode, value)
        st.config(dut, cmd, type='vtysh', skip_error_check=skip_error_check)
        return True
    elif cli_type == "klish":
        if vrf != 'default':
            cmd = cmd + 'router bgp {} vrf {}\n'.format(local_asn, vrf)
        else:
            cmd = cmd + 'router bgp {}\n'.format(local_asn)
        cmd = cmd + 'address-family {} {}\n'.format(mode_type, mode)
        cmd = cmd + '{} redistribute {}\n'.format(cfgmode, value)
        cmd = cmd + 'exit\nexit\n'
        st.config(dut, cmd, type=cli_type, skip_error_check=skip_error_check, conf = True)
        return True
    else:
        st.log("Unsupported CLI TYPE - {}".format(cli_type))
        return False


def config_bgp(dut, **kwargs):
    """
    config_bgp(dut = DUT1, router_id = '9.9.9.9', local_as='100', neighbor ='192.168.3.2', remote_as='200', config = 'yes', config_type_list =["neighbor"])
	config_bgp(dut = DUT1, local_as='100', remote_as='200', neighbor ='2001::2', config = 'yes', config_type_list =["neighbor"]
	config_bgp(dut = DUT1, local_as='100',config = 'yes',config_type_list =["redist"], redistribute ='connected')
	config_bgp(dut = DUT1, local_as='100', neighbor ='192.168.3.2',config = 'yes',config_type_list =["bfd"])
	config_bgp(dut = DUT1, local_as='100', neighbor ='192.168.3.2',config = 'yes',config_type_list =["bfd","redist"], redistribute ='connected')
	config_bgp(dut = DUT1, local_as='100', neighbor ='192.168.3.2', config = 'yes', password ='broadcom' ,config_type_list =["pswd"])
	config_bgp(dut = DUT1, local_as='100', neighbor ='192.168.3.2',config = 'no', password ='broadcom' ,config_type_list =["pswd"])
	config_bgp(dut = DUT1, local_as='100', neighbor ='192.168.3.2', config = 'yes', update_src ='2.2.2.1', config_type_list =["update_src"])
	config_bgp(dut = DUT1, local_as='100', neighbor ='192.168.3.2', config = 'no', update_src ='2.2.2.1', config_type_list =["update_src"])
	config_bgp(dut = DUT1, local_as='100',config = 'yes',config_type_list =["max_path_ibgp"], max_path_ibgp ='8')
	config_bgp(dut = DUT1, local_as='100',config = 'no',config_type_list =["max_path_ibgp"], max_path_ibgp ='8')
	config_bgp(dut = DUT1, local_as='100',config = 'yes',addr_family ='ipv6', config_type_list =["max_path_ibgp"], max_path_ibgp ='8')
	config_bgp(dut = DUT1, local_as='100',config = 'no',addr_family ='ipv6', config_type_list =["max_path_ibgp"], max_path_ibgp ='8')
	config_bgp(dut = DUT1, local_as='100',config = 'yes',addr_family ='ipv6', config_type_list =["max_path_ebgp"], max_path_ebgp ='20')
	config_bgp(dut = DUT1, local_as='100', neighbor ='192.168.3.2',config ='yes', config_type_list =["routeMap"], routeMap ='map123', diRection='out')
	config_bgp(dut = DUT1, local_as='100', neighbor ='192.168.3.2',config ='no', config_type_list =["routeMap"], routeMap ='map123', diRection='out')
	config_bgp(dut = DUT1, local_as='100', neighbor ='2001::20', addr_family ='ipv6',config = 'yes', config_type_list =["routeMap"], routeMap ='map123', diRection='out')
	config_bgp(dut = DUT1, local_as='100',config = 'no',  removeBGP='yes', config_type_list =["removeBGP"])
	config_bgp(dut = dut1,local_as = '100', neighbor = '20.20.20.2', config = 'yes', config_type_list =["nexthop_self"])
	config_bgp(dut = dut1,local_as = '100', neighbor = '20.20.20.2', config = 'yes', config_type_list =["ebgp_mhop"],ebgp_mhop ='2')
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut))
    cli_type = "vtysh" if cli_type in ['click', "vtysh"] else "klish"

    st.log('Configure BGP')
    config = kwargs.get('config', "yes")
    vrf_name = kwargs.get('vrf_name', "default")
    router_id = kwargs.get('router_id','')
    config_type_list = kwargs.get('config_type_list', None)
    neighbor = kwargs.get('neighbor', None)
    local_as = kwargs.get('local_as', None)
    remote_as = kwargs.get('remote_as', None)
    peergroup =  kwargs.get('peergroup', '')
    pswd = kwargs.get('pswd', None)
    activate = kwargs.get('activate', None)
    nexthop_self = kwargs.get('nexthop_self', None)
    addr_family = kwargs.get('addr_family', 'ipv4')
    keepalive = kwargs.get('keepalive', '')
    holdtime = kwargs.get('holdtime', '')
    conf_peers = kwargs.get('conf_peers', '')
    conf_identf = kwargs.get('conf_identf', '')
    update_src = kwargs.get('update_src', None)
    interface = kwargs.get('interface', None)
    connect = kwargs.get('connect', None)
    ebgp_mhop = kwargs.get('ebgp_mhop', None)
    failover = kwargs.get('failover', None)
    shutdown = kwargs.get('shutdown', None)
    max_path = kwargs.get('max_path', None)
    redistribute = kwargs.get('redistribute', None)
    network = kwargs.get('network', None)
    password = kwargs.get('password', None)
    max_path_ibgp = kwargs.get('max_path_ibgp', None)
    max_path_ebgp = kwargs.get('max_path_ebgp', None)
    routeMap = kwargs.get('routeMap', None)
    distribute_list = kwargs.get('distribute_list', None)
    filter_list = kwargs.get('filter_list', None)
    prefix_list = kwargs.get('prefix_list', None)
    import_vrf = kwargs.get('import_vrf', None)
    import_vrf_name = kwargs.get('import_vrf_name', None)
    fast_external_failover = kwargs.get('fast_external_failover', None)
    bgp_bestpath_selection = kwargs.get('bgp_bestpath_selection', None)
    removeBGP = kwargs.get('removeBGP', 'no')
    diRection = kwargs.get('diRection', 'in')
    weight = kwargs.get('weight', None)
    config_cmd = "" if config.lower() == 'yes' else "no"
    my_cmd =''
    if cli_type == "vtysh":
        if 'local_as' in kwargs and removeBGP != 'yes':
            if vrf_name != 'default':
                my_cmd = 'router bgp {} vrf {}\n'.format(local_as, vrf_name)
            else:
                my_cmd = 'router bgp {}\n'.format(local_as)

        if router_id != '':
            my_cmd += '{} bgp router-id {}\n'.format(config_cmd, router_id)
        if keepalive != '' and holdtime != '':
            my_cmd += '{} timers bgp {} {}\n'.format(config_cmd, keepalive, holdtime)
        if config_cmd == '':
            if peergroup != '':
                my_cmd += 'neighbor {} peer-group\n'.format(peergroup)
        if conf_peers != '':
            my_cmd += '{} bgp confederation peers {}\n'.format(config_cmd, conf_peers)
        if conf_identf != '':
            my_cmd += '{} bgp confederation identifier {}\n'.format(config_cmd, conf_identf)

        for type1 in config_type_list:
            if type1 == 'neighbor':
                my_cmd += '{} neighbor {} remote-as {}\n'.format(config_cmd, neighbor, remote_as)
            elif type1 == 'shutdown':
                my_cmd += '{} neighbor {} shutdown\n'.format(config_cmd, neighbor)
            elif type1 == 'failover':
                my_cmd += '{} bgp fast-external-failover\n'.format(config_cmd)
            elif type1 == 'router_id':
                st.log("Configuring the router-id on the device")
            elif type1 == 'fast_external_failover':
                st.log("Configuring the fast_external_failover")
                my_cmd += '{} bgp fast-external-failover\n'.format(config_cmd)
            elif type1 == 'bgp_bestpath_selection':
                st.log("Configuring bgp default bestpath selection")
                my_cmd += '{} bgp bestpath {}\n'.format(config_cmd,bgp_bestpath_selection)
            elif type1 == 'activate':
                my_cmd += 'address-family {} unicast\n'.format(addr_family)
                my_cmd += '{} neighbor {} activate\n'.format(config_cmd, neighbor)
            elif type1 == 'nexthop_self':
                my_cmd += 'address-family {} unicast\n'.format(addr_family)
                my_cmd += '{} neighbor {} next-hop-self\n'.format(config_cmd, neighbor)
            elif type1 == 'pswd':
                my_cmd += '{} neighbor {} password {}\n'.format(config_cmd, neighbor, password)
            elif type1 == 'update_src':
                my_cmd += '{} neighbor {} update-source {}\n'.format(config_cmd, neighbor, update_src)
            elif type1 == 'interface':
                my_cmd += '{} neighbor {} interface {}\n'.format(config_cmd, neighbor, interface)
            elif type1 == 'connect':
                my_cmd += '{} neighbor {} timers connect {}\n'.format(config_cmd, neighbor, connect)
            elif type1 == 'ebgp_mhop':
                my_cmd += '{} neighbor {} ebgp-multihop {}\n'.format(config_cmd, neighbor, ebgp_mhop)
            elif type1 == 'peergroup':
                my_cmd += '{} neighbor {} remote-as {}\n'.format(config_cmd, peergroup, remote_as)
                if config_cmd == '':
                    if interface:
                        my_cmd += 'neighbor {} interface peer-group {}\n'.format(neighbor, peergroup)
                    else:
                        my_cmd += 'neighbor {} peer-group {}\n'.format(neighbor, peergroup)
                if config_cmd == 'no':
                    my_cmd += '{} neighbor {} peer-group\n'.format(config_cmd, peergroup)
            elif type1 == 'bfd':
                if peergroup:
                    my_cmd += '{} neighbor {} bfd\n'.format(config_cmd, peergroup)
                elif interface != '' and interface != None:
                    my_cmd += '{} neighbor {} bfd\n'.format(config_cmd, interface)
                else:
                    my_cmd += '{} neighbor {} bfd\n'.format(config_cmd, neighbor)
            elif type1 == 'max_path_ibgp':
                my_cmd += 'address-family {} unicast\n'.format(addr_family)
                my_cmd += '{} maximum-paths ibgp {}\n'.format(config_cmd, max_path_ibgp)
                my_cmd += 'exit\n'
            elif type1 == 'max_path_ebgp':
                my_cmd += 'address-family {} unicast\n'.format(addr_family)
                my_cmd += '{} maximum-paths {}\n'.format(config_cmd, max_path_ebgp)
                my_cmd += 'exit\n'
            elif type1 == 'redist':
                my_cmd += 'address-family {} unicast\n'.format(addr_family)
                my_cmd += '{} redistribute {}\n'.format(config_cmd, redistribute)
                my_cmd += 'exit\n'
            elif type1 == 'network':
                my_cmd += 'address-family {} unicast\n'.format(addr_family)
                my_cmd += '{} network {}\n'.format(config_cmd, network)
                my_cmd += 'exit\n'
            elif type1 == 'import-check':
                my_cmd += '{} bgp network import-check\n'.format(config_cmd)
            elif type1 == 'import_vrf':
                my_cmd += 'address-family {} unicast\n'.format(addr_family)
                my_cmd += '{} import vrf {} \n'.format(config_cmd, import_vrf_name)
                my_cmd += 'exit\n'
            elif type1 == 'routeMap':
                my_cmd += 'address-family {} unicast\n'.format(addr_family)
                my_cmd += '{} neighbor {} route-map {} {}\n'.format(config_cmd, neighbor, routeMap, diRection)
                my_cmd += 'exit\n'
            elif type1 == 'distribute_list':
                my_cmd += 'address-family {} unicast\n'.format(addr_family)
                my_cmd += '{} neighbor {} distribute-list {} {}\n'.format(config_cmd, neighbor, distribute_list, diRection)
                my_cmd += 'exit\n'
            elif type1 == 'filter_list':
                my_cmd += 'address-family {} unicast\n'.format(addr_family)
                my_cmd += '{} neighbor {} filter-list {} {}\n'.format(config_cmd, neighbor, filter_list, diRection)
                my_cmd += 'exit\n'
            elif type1 == 'prefix_list':
                my_cmd += 'address-family {} unicast\n'.format(addr_family)
                my_cmd += '{} neighbor {} prefix-list {} {}\n'.format(config_cmd, neighbor, prefix_list, diRection)
                my_cmd += 'exit\n'
            elif type1 == 'default_originate':
                my_cmd += 'address-family {} unicast\n'.format(addr_family)
                if kwargs.has_key('routeMap'):
                    my_cmd += '{} neighbor {} default-originate route-map {}\n'.format(config_cmd, neighbor, routeMap)
                else:
                    my_cmd += '{} neighbor {} default-originate\n'.format(config_cmd, neighbor)
                my_cmd += 'exit\n'
            elif type1 == 'removePrivateAs':
                my_cmd += 'address-family {} unicast\n'.format(addr_family)
                my_cmd += '{} neighbor {} remove-private-AS\n'.format(config_cmd, neighbor)
                my_cmd += 'exit\n'
            elif type1 == 'multipath-relax':
                my_cmd += '{} bgp bestpath as-path multipath-relax \n'.format(config_cmd)
            elif type1 == 'remote-as':
                my_cmd += '{} neighbor {} interface remote-as {}\n'.format(config_cmd,interface,remote_as)
            elif type1 == 'weight':
                my_cmd += 'address-family {} unicast\n'.format(addr_family)
                my_cmd += '{} neighbor {} weight {}\n'.format(config_cmd, neighbor, weight)
            elif type1 == 'removeBGP':
                st.log("Removing the bgp config from the device")
            else:
                st.log('Invalid BGP config parameter')
        st.config(dut, my_cmd, type=cli_type)
        if vrf_name != 'default' and removeBGP == 'yes':
            my_cmd = '{} router bgp {} vrf {}'.format(config_cmd, local_as, vrf_name)
            st.config(dut, my_cmd, type=cli_type)
        elif vrf_name == 'default' and removeBGP == 'yes':
            if 'local_as' in kwargs:
                my_cmd = '{} router bgp {}'.format(config_cmd,local_as)
            else:
                my_cmd = '{} router bgp'.format(config_cmd)
            st.config(dut, my_cmd, type=cli_type)
    elif cli_type == "klish":
        commands = list()
        neigh_name = get_interface_number_from_name(neighbor)
        shutdown = kwargs.get("shutdown", None) if "shutdown" in config_type_list else None
        activate = kwargs.get("activate", None) if "activate" in config_type_list else None
        nexthop_self = kwargs.get("nexthop_self", None) if "nexthop_self" in config_type_list else None
        pswd = True if "pswd" in config_type_list else False
        update_src = kwargs.get("update_src", "") if "update_src" in config_type_list else ""
        bfd = True if "bfd" in config_type_list else False
        route_map = True if "routeMap" in config_type_list else False
        default_originate = True if "default_originate" in config_type_list else False
        removePrivateAs = True if "removePrivateAs" in config_type_list else False
        no_neighbor = "no" if kwargs.get("no_neigh") else ""
        sub_list = ["neighbor", "routeMap", "shutdown", "activate", "nexthop_self", "pswd", "update_src",
                    "bfd", "default_originate", "removePrivateAs", "no_neigh","remote-as","filter_list",
                    "prefix_list", "weight", "keepalive", "holdtime", "ebgp_mhop","peergroup"]
        if 'local_as' in kwargs and removeBGP != 'yes':
            if vrf_name != 'default':
                my_cmd = 'router bgp {} vrf {}'.format(local_as, vrf_name)
            else:
                my_cmd = 'router bgp {}'.format(local_as)
        commands.append(my_cmd)
        if router_id:
            my_cmd = '{} router-id {}'.format(config_cmd, router_id)
            commands.append(my_cmd)
        if peergroup:
            my_cmd = '{} peer-group {}'.format(config_cmd, peergroup)
            commands.append(my_cmd)
            commands.append("exit")
        # if conf_peers:
        #     my_cmd += '{} bgp confederation peers {}\n'.format(config_cmd, conf_peers)
        # if conf_identf != '':
        #     my_cmd += '{} bgp confederation identifier {}\n'.format(config_cmd, conf_identf)
        for type1 in config_type_list:
            if type1 in sub_list:
                if neigh_name:
                    if isinstance(neigh_name, dict):
                        my_cmd = "{} neighbor interface {} {}".format(no_neighbor, neigh_name["type"], neigh_name["number"])
                    else:
                        my_cmd = "{} neighbor {}".format(no_neighbor, neigh_name)
                    commands.append(my_cmd)
                if no_neighbor:
                    commands.append("exit")
                    continue
                if remote_as and not bfd:
                    my_cmd = '{} remote-as {}'.format(config_cmd, remote_as)
                    commands.append(my_cmd)
                    remote_as = None
                elif shutdown:
                    my_cmd = '{} shutdown'.format(config_cmd)
                    commands.append(my_cmd)
                    shutdown = None
                elif activate or type1 == "activate":
                    my_cmd = 'address-family {} unicast'.format(addr_family)
                    commands.append(my_cmd)
                    my_cmd = '{} activate'.format(config_cmd)
                    commands.append(my_cmd)
                    commands.append("exit")
                    activate = None
                elif  route_map:
                    my_cmd = 'address-family {} unicast'.format(addr_family)
                    commands.append(my_cmd)
                    my_cmd = '{} route-map {} {}'.format(config_cmd, routeMap, diRection)
                    commands.append(my_cmd)
                    commands.append("exit")
                    route_map = False
                elif filter_list:
                    my_cmd = 'address-family {} unicast'.format(addr_family)
                    commands.append(my_cmd)
                    my_cmd = '{} filter-list {} {}'.format(config_cmd, filter_list, diRection)
                    commands.append(my_cmd)
                    commands.append("exit")
                    filter_list = None
                elif prefix_list:
                    my_cmd = 'address-family {} unicast'.format(addr_family)
                    commands.append(my_cmd)
                    my_cmd = '{} prefix-list {} {}\n'.format(config_cmd, prefix_list, diRection)
                    commands.append(my_cmd)
                    commands.append("exit")
                    prefix_list = None
                elif  default_originate:
                    my_cmd = 'address-family {} unicast'.format(addr_family)
                    commands.append(my_cmd)
                    if kwargs.has_key('routeMap'):
                        my_cmd = '{} default-originate route-map {}'.format(config_cmd, routeMap)
                    else:
                        my_cmd = '{} default-originate'.format(config_cmd)
                    commands.append(my_cmd)
                    commands.append("exit")
                    default_originate = False
                elif removePrivateAs:
                    my_cmd = 'address-family {} unicast'.format(addr_family)
                    commands.append(my_cmd)
                    my_cmd = '{} remove-private-AS'.format(config_cmd)
                    commands.append(my_cmd)
                    commands.append("exit")
                    removePrivateAs = False
                elif weight:
                    my_cmd = 'address-family {} unicast'.format(addr_family)
                    commands.append(my_cmd)
                    my_cmd = '{} weight {}'.format(config_cmd, weight)
                    commands.append(my_cmd)
                    commands.append("exit")
                    weight = None
                elif keepalive and holdtime:
                    my_cmd = '{} timers {} {}'.format(config_cmd, keepalive, holdtime)
                    commands.append(my_cmd)
                    keepalive = 0
                    holdtime = 0
                elif nexthop_self:
                    my_cmd = 'address-family {} unicast'.format(addr_family)
                    commands.append(my_cmd)
                    my_cmd = '{} next-hop-self'.format(config_cmd)
                    commands.append(my_cmd)
                    commands.append("exit")
                    nexthop_self = None
                elif pswd:
                    password = "" if config_cmd== 'no' else password
                    my_cmd = '{} password {}'.format(config_cmd, password)
                    commands.append(my_cmd)
                    pswd = False
                elif update_src:
                    my_cmd = '{} update-source {}'.format(config_cmd, update_src)
                    commands.append(my_cmd)
                    update_src = None
                elif ebgp_mhop:
                    my_cmd = '{} ebgp-multihop {}'.format(config_cmd, ebgp_mhop)
                    commands.append(my_cmd)
                    ebgp_mhop = None
                elif peergroup:
                    my_cmd = '{} peer-group {}'.format(config_cmd, peergroup)
                    commands.append(my_cmd)
                    peergroup = None
                elif bfd:
                    if interface and remote_as:
                        my_cmd = "neighbor interface {}".format(interface)
                        commands.append(my_cmd)
                    elif neighbor and not interface and remote_as:
                        my_cmd = "neighbor {}".format(neighbor)
                        commands.append(my_cmd)
                    my_cmd = "remote-as {}".format(remote_as)
                    commands.append(my_cmd)
                    my_cmd = '{} bfd'.format(config_cmd)
                    commands.append(my_cmd)
                    bfd = False
                commands.append("exit")
            # elif type1 == 'failover':
            #     my_cmd += '{} bgp fast-external-failover\n'.format(config_cmd)
            # elif type1 == 'router_id':
            #     st.log("Configuring the router-id on the device")
            elif type1 == 'fast_external_failover':
                st.log("Configuring the fast_external_failover")
                my_cmd = '{} fast-external-failover'.format(config_cmd)
                commands.append(my_cmd)
            elif type1 == 'bgp_bestpath_selection':
                st.log("Configuring bgp default bestpath selection")
                my_cmd = '{} bestpath {}'.format(config_cmd, bgp_bestpath_selection)
                commands.append(my_cmd)
            # elif type1 == 'interface':
            #     my_cmd += '{} neighbor {} interface {}\n'.format(config_cmd, neighbor, interface)
            # elif type1 == 'connect':
            #     my_cmd += '{} neighbor {} timers connect {}\n'.format(config_cmd, neighbor, connect)
            elif type1 == 'max_path_ibgp':
                my_cmd = 'address-family {} unicast'.format(addr_family)
                commands.append(my_cmd)
                my_cmd = '{} maximum-paths ibgp {}'.format(config_cmd, max_path_ibgp)
                commands.append(my_cmd)
                commands.append("exit")
            elif type1 == 'max_path_ebgp':
                my_cmd = 'address-family {} unicast'.format(addr_family)
                commands.append(my_cmd)
                my_cmd = '{} maximum-paths {}'.format(config_cmd, max_path_ebgp)
                commands.append(my_cmd)
                commands.append("exit")
            elif type1 == 'redist':
                my_cmd = 'address-family {} unicast'.format(addr_family)
                commands.append(my_cmd)
                my_cmd = '{} redistribute {}'.format(config_cmd, redistribute)
                commands.append(my_cmd)
                commands.append("exit")
            elif type1 == 'network':
                my_cmd = 'address-family {} unicast'.format(addr_family)
                commands.append(my_cmd)
                my_cmd = '{} network {}'.format(config_cmd, network)
                commands.append(my_cmd)
                commands.append("exit")
            elif type1 == 'import-check':
                my_cmd = '{} network import-check'.format(config_cmd)
                commands.append(my_cmd)
            # elif type1 == 'import_vrf':
            #     my_cmd += 'address-family {} unicast\n'.format(addr_family)
            #     my_cmd += '{} import vrf {} \n'.format(config_cmd, import_vrf_name)
            #     my_cmd += 'exit\n'
            # elif type1 == 'distribute_list':
            #     my_cmd += 'address-family {} unicast\n'.format(addr_family)
            #     my_cmd += '{} neighbor {} distribute-list {} {}\n'.format(config_cmd, neighbor, distribute_list,
            #                                                               diRection)
            #     my_cmd += 'exit\n'
            elif type1 == 'multipath-relax':
                my_cmd = '{} bestpath as-path multipath-relax'.format(config_cmd)
                commands.append(my_cmd)
            elif type1 == 'removeBGP':
                st.log("Removing the bgp config from the device")
            elif type1 == 'router_id':
                st.log("Configuring the router-id on the device")
            elif type1 == 'peer_group':
                st.log("Configuring the peer_group on the device")
            else:
                st.log('Invalid BGP config parameter')
        commands.append('exit\n')
        cli_output = st.config(dut, commands, type=cli_type, skip_error_check=True)
        fail_on_error(cli_output)
        if vrf_name != 'default' and removeBGP == 'yes':
            my_cmd = '{} router bgp vrf {}'.format(config_cmd, vrf_name)
            cli_output = st.config(dut, my_cmd, type=cli_type, skip_error_check=True)
            fail_on_error(cli_output)
        elif vrf_name == 'default' and removeBGP == 'yes':
            my_cmd = '{} router bgp'.format(config_cmd)
            cli_output = st.config(dut, my_cmd, type=cli_type, skip_error_check=True)
            fail_on_error(cli_output)
    else:
        st.log("Unsupported CLI TYPE - {}".format(cli_type))
        return False


def verify_bgp_neighborship(dut, family='ipv4', shell="sonic", **kwargs):
    """
    This API will poll the BGP neighborship with the provided parameters
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param family:
    :param shell:
    :param kwargs: neighbor, state, delay, iterations
    :return:
    """
    iterations = kwargs["iterations"] if "iterations" in kwargs else 5
    delay = kwargs["delay"] if "delay" in kwargs else 1
    if "neighbor" in kwargs and "state" in kwargs:
        i = 1
        while True:
            if verify_bgp_summary(dut, family, shell, neighbor=kwargs["neighbor"], state=kwargs["state"]):
                st.log("BGP neigborship found ....")
                return True
            if i > iterations:
                st.log("Reached max iteration count, Exiting ...")
                return False
            i += 1
            st.wait(delay)
    else:
        st.log("Required values not found ....")
        return False


def show_ip_bgp_route(dut, family='ipv4'):
    """
    API for show ip bgp
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :return:
    """
    command = "show bgp {}".format(family)
    return st.show(dut, command, type='vtysh')

def fetch_ip_bgp_route(dut, family='ipv4', match=None, select=None):
    entries = dict()
    output = show_ip_bgp_route(dut, family=family)
    #match = {'network': network}
    entries = filter_and_select(output, select, match)
    return entries

def get_ip_bgp_route(dut, family='ipv4', **kwargs):
    output = show_ip_bgp_route(dut, family=family)
    st.debug(output)
    for each in kwargs.keys():
        match = {each: kwargs[each]}
        get_list = ["network", "as_path"]
        entries = filter_and_select(output, get_list, match)
        if not entries:
            st.log("Could not get bgp route info")
            return False
    return entries

def verify_ip_bgp_route(dut, family='ipv4', **kwargs):
    """

    EX; verify_ip_bgp_route(vars.D1, network= '11.2.1.2/24')
    """
    output = show_ip_bgp_route(dut, family=family)
    for each in kwargs.keys():
        match = {each: kwargs[each]}
        entries = filter_and_select(output, None, match)
        if not entries:
            st.log("{} and {} is not match ".format(each, kwargs[each]))
            return False
    return True


def verify_ip_bgp_route_network_list(dut, family='ipv4', nw_list=[]):

    output = show_ip_bgp_route(dut, family=family)
    for network in nw_list:
        match = {'network': network}
        entries = filter_and_select(output, None, match)
        if not entries:
            st.log("BGP Network {} is not matching ".format(network))
            return False
    return True


def check_bgp_config_in_startupconfig(dut, config_list):
    """
    API to check the configuration in startup config
    :param dut:
    :param config_list: list of configuration commands to check in statup config
    :return:
    """
    cmd = "show startupconfiguration bgp"
    output = st.show(dut, cmd, skip_error_check=True)
    output_list = output.splitlines()
    for config in config_list:
        if config not in output_list:
            return False
    return True

def show_bgp_ipvx_prefix(dut, prefix, masklen, family='ipv4'):
    """
    API for show bgp ipv4 prefix

    :param dut:
    :param prefix: (ip address)
    :param masklen: length of mask (e.g. 24)
    :param family: ipv4/ipv6
    EX: show_bgp_ipvx_prefix(dut1, prefix="40.1.1.1", masklen=32, family='ipv4')
    :return:
    """

    entries = dict()
    command = "show bgp {} {}/{}".format(family, prefix, masklen)
    entries = st.show(dut, command, type='vtysh')
    st.log(entries)
    return entries


def show_bgp_ip_prefix(dut, ip_prefix, family='ipv4'):
    """
    API for show bgp ipv4 prefix

    :param dut:
    :param prefix: ip address with or without subnet <ip>/<mask>
    :param family: ipv4/ipv6
          EX: show_bgp_ipvx_prefix(dut1, prefix="40.1.1.1/32", family='ipv4')
    :return:
    """

    if family != 'ipv4' and family != 'ipv6' :
        return {}

    command = "show bgp {} {}".format(family, ip_prefix)
    entries = st.show(dut, command, type='vtysh')
    return entries

def activate_bgp_neighbor(dut, local_asn, neighbor_ip, family="ipv4", config='yes',vrf='default', **kwargs):
    """

    :param dut:
    :param local_asn:
    :param neighbor_ip:
    :param family:
    :param config:
    :param vrf:
    :return:
    """

    st.log("Activate BGP neigbor")
    cli_type = kwargs.get('cli_type', st.get_ui_type())
    skip_error_check = kwargs.get('skip_error_check', True)
    remote_asn = kwargs.get('remote_asn', '')
    if config.lower() == 'yes':
        mode = ""
    else:
        mode = 'no'
    if family !='ipv4' and family != 'ipv6':
        return False
    cmd = ''
    if cli_type == 'vtysh' or cli_type == 'click':
        if vrf != 'default':
            cmd = cmd + 'router bgp {} vrf {}\n'.format(local_asn, vrf)
        else:
            cmd = cmd + 'router bgp {}\n'.format(local_asn)
        cmd = cmd + 'address-family {} unicast\n'.format(family)
        cmd = cmd + '{} neighbor {} activate\n'.format(mode, neighbor_ip)
        cmd = cmd + '\n end'
        st.config(dut, cmd, type='vtysh', skip_error_check=skip_error_check)
        return True
    elif cli_type == "klish":
        if vrf != 'default':
            cmd = cmd + 'router bgp {} vrf {}\n'.format(local_asn, vrf)
        else:
            cmd = cmd + 'router bgp {}\n'.format(local_asn)
        cmd = cmd + 'neighbor {}\n'.format(neighbor_ip)
        cmd = cmd + 'remote-as {}\n'.format(remote_asn)
        cmd = cmd + 'address-family {} unicast\n'.format(family)
        cmd = cmd + 'activate\n'
        cmd = cmd + 'exit\nexit\nexit\n'
        st.config(dut, cmd, type=cli_type, skip_error_check=skip_error_check, conf = True)
        return True
    else:
        st.log("Unsupported CLI TYPE - {}".format(cli_type))
        return False

def bgp_debug_config(dut, **kwargs):
    """
    API to enable BGP zebra logs
    :param dut:
    :param prefix: (ip address)
    :param message: eg update
    """

    command = "debug bgp zebra\n"
    if "prefix" in kwargs:
        command += "debug bgp zebra prefix {}\n".format(kwargs["prefix"])
    if "message" in kwargs:
        if kwargs["message"] == "updates":
           command += "debug bgp updates\n"
           command += "debug bgp update-groups\n"
    command += "log stdout\n"
    st.config(dut, command, type='vtysh')

class ASPathAccessList:
    """
    Usage:
    aspath_access_list = ASPathAccessList("testaspath")
    aspath_access_list.add_match_permit_sequence(['_65001', '65002', '65003'])
    aspath_access_list.add_match_deny_sequence(['_1^', '_2$', '_3*'])
    aspath_access_list.add_match_permit_sequence(['_65100^'])
    aspath_access_list.execute_command(dut, config='yes')
    cmd_str = aspath_access_list.config_command_string()
    aspath_access_list.execute_command(dut, config='no')
    """

    def __init__(self, name):
        self.name = name
        self.match_sequence = []
        self.cmdkeyword = 'bgp as-path access-list'

    def add_match_permit_sequence(self, as_path_regex_list):
        self.match_sequence.append(('permit', as_path_regex_list))

    def add_match_deny_sequence(self, as_path_regex_list):
        self.match_sequence.append(('deny', as_path_regex_list))

    def config_command_string(self):
        command = ''
        for v in self.match_sequence:
            command += '{} {} {}'.format(self.cmdkeyword, self.name, v[0])
            for as_path_regex in list(v[1]):
                command += ' {}'.format(as_path_regex)
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


