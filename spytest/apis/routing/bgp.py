# This file contains the list of API's which performs BGP operations.
# Author : Chaitanya Vella (Chaitanya-vella.kumar@broadcom.com)
import re
import json

from spytest import st, putils

import apis.system.reboot as reboot
from apis.system.rest import config_rest, delete_rest, get_rest , rest_status

from utilities.utils import fail_on_error, get_interface_number_from_name, is_valid_ip_address, convert_microsecs_to_time
from utilities.common import filter_and_select

def get_forced_cli_type(cmd_type):
    cmn_type = st.getenv("SPYTEST_BGP_API_UITYPE", "")
    if cmd_type == "show":
        return st.getenv("SPYTEST_BGP_SHOW_API_UITYPE", cmn_type)
    if cmd_type == "config":
        return st.getenv("SPYTEST_BGP_CFG_API_UITYPE", cmn_type)
    return cmn_type

def get_cfg_cli_type(dut, **kwargs):
    cli_type = get_forced_cli_type("config")
    cli_type = cli_type or st.get_ui_type(dut, **kwargs)
    if cli_type in ["click", "vtysh"]:
        cli_type = "vtysh"
    elif cli_type in ["rest-patch","rest-put"]:
        cli_type = "rest-patch"
    else:
        cli_type = "klish"
    return cli_type

def get_show_cli_type(dut, **kwargs):
    cli_type = get_forced_cli_type("show")
    cli_type = cli_type or st.get_ui_type(dut, **kwargs)
    if cli_type in ["click", "vtysh"]:
        cli_type = "vtysh"
    elif cli_type in ["rest-patch","rest-put"]:
        cli_type = "rest-patch"
    else:
        cli_type = "klish"
    return cli_type



def enable_docker_routing_config_mode(dut, **kwargs):
    """

    :param dut:
    :return:
    """
    cli_type = get_cfg_cli_type(dut, **kwargs)
    if cli_type in ["click", "vtysh"]:
        data = {"DEVICE_METADATA": {"localhost": {"docker_routing_config_mode": "split"}}}
        split_config = json.dumps(data)
        json.loads(split_config)
        st.apply_json(dut, split_config)
        reboot.config_save(dut)
    elif cli_type == 'klish':
        pass


def enable_router_bgp_mode(dut, **kwargs):
    """

    :param dut:
    :param local_asn:
    :return:
    """
    cli_type = get_cfg_cli_type(dut, **kwargs)
    st.log("Enabling router BGP mode ..")
    if cli_type in ['vtysh', 'click']:
        cli_type ='vtysh'
        st.log("Enabling router BGP mode ..")
        if 'local_asn' in kwargs:
            command = "router bgp {}".format(kwargs['local_asn'])
        else:
            command = "router bgp"

        if 'vrf_name' in kwargs and kwargs['vrf_name'] != 'default-vrf':
            command += ' vrf ' + kwargs['vrf_name']
        if 'router_id' in kwargs:
            command += '\n bgp router-id {}'.format(kwargs['router_id'])
    elif cli_type == 'klish':
        st.log("Enabling router BGP mode ..")
        if 'local_asn' in kwargs:
            command = "router bgp {}".format(kwargs['local_asn'])
        if 'vrf_name' in kwargs and kwargs['vrf_name'] != 'default-vrf':
            command += ' vrf ' + kwargs['vrf_name']
        if 'router_id' in kwargs:
            command +=  ' router-id {}'.format(kwargs['router_id'])
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        vrf_name = kwargs['vrf_name'] if 'vrf_name' in kwargs and kwargs['vrf_name'] != 'default-vrf' else "default"
        url = rest_urls['bgp_global_config'].format(vrf_name)
        json_data = dict()
        if 'local_asn' in kwargs:
            json_data["openconfig-network-instance:as"] = int(kwargs['local_asn'])
        if 'router_id' in kwargs:
            json_data["openconfig-network-instance:router-id"] = kwargs['router_id']
        if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=json_data):
            st.error("Error in configuring AS number / router ID")
            return False
        return True
    else:
        st.error("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
        return False
    st.config(dut, command, type=cli_type)
    return True


def config_router_bgp_mode(dut, local_asn, config_mode='enable', vrf='default', cli_type="", skip_error_check=True):
    """
    :param dut:
    :param local_asn:
    :param config_mode:
    :param vrf:
    :return:
    """
    cli_type = get_cfg_cli_type(dut, cli_type=cli_type)
    st.log("Config router BGP mode .. {}".format(config_mode))
    mode = "no" if config_mode.lower() == 'disable' else ""
    if cli_type in ['vtysh', 'click']:
        cli_type = 'vtysh'
        if vrf.lower() == 'default':
            command = "{} router bgp {}".format(mode, local_asn)
        else:
            command = "{} router bgp {} vrf {}".format(mode, local_asn, vrf)
    elif cli_type == 'klish':
        if vrf.lower() == 'default':
            if not mode:
                command = "router bgp {}".format(local_asn)
            else:
                command = "no router bgp"
        else:
            if not mode:
                command = "router bgp {} vrf {}".format(local_asn, vrf)
            else:
                command = "no router bgp vrf {}".format(vrf)
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        vrf_name = "default" if vrf.lower() == 'default' else vrf.lower()
        if not mode:
            url = rest_urls['bgp_global_config'].format(vrf_name)
            json_data = dict()
            json_data["openconfig-network-instance:config"] = dict()
            json_data["openconfig-network-instance:config"].update({'as': int(local_asn)})
            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=json_data):
                st.error("Error in configuring AS number")
                return False
            return True
        else:
            url = rest_urls['bgp_as_config'].format(vrf_name)
            if not delete_rest(dut, rest_url=url):
                st.error("Error in Unconfiguring AS number")
                return False
            return True
    else:
        st.error("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
        return False
    st.config(dut, command, type=cli_type, skip_error_check=skip_error_check)
    return True


def unconfig_router_bgp(dut, **kwargs):
    """
    :param dut
    :return:
    """
    st.log("Unconfiguring Bgp in {}".format(dut))
    cli_type = get_cfg_cli_type(dut, **kwargs)
    if cli_type in ['vtysh', 'click']:
        cli_type = 'vtysh'
        command = "no router bgp"
        if 'vrf_name' in kwargs and 'local_asn' in kwargs:
            command += '  ' + kwargs['local_asn'] + ' vrf ' + kwargs['vrf_name']
    elif cli_type == 'klish':
        if kwargs.get("vrf_name"):
            command = "no router bgp vrf {}".format(kwargs.get("vrf_name"))
        else:
            command = "no router bgp"
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        vrf_name = kwargs['vrf_name'] if kwargs.get('vrf_name') else "default"
        url = rest_urls['bgp_as_config'].format(vrf_name)
        if not delete_rest(dut, rest_url=url):
            st.error("Error in Unconfiguring router BGP")
            return False
        return True
    else:
        st.error("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
        return False
    st.config(dut, command, type=cli_type)
    return True


def cleanup_router_bgp(dut_list, cli_type="", skip_error_check=True):
    """

    :param dut_list:
    :return:
    """
    dut_li = list(dut_list) if isinstance(dut_list, list) else [dut_list]
    for dut in dut_li:
        cli_type = get_cfg_cli_type(dut, cli_type=cli_type)
        if cli_type in ["vtysh", "klish"]:
            st.log("Cleanup BGP mode ..")
            command = "no router bgp"
            st.config(dut, command, type=cli_type, skip_error_check=skip_error_check)
        elif cli_type in ["rest-patch", "rest-put"]:
            rest_urls = st.get_datastore(dut, 'rest_urls')
            url = rest_urls['bgp_config'].format("default")
            if not delete_rest(dut, rest_url=url):
                st.error("Error in Unconfiguring router BGP")
                return False
            return True
        else:
            st.error("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
            return False
    return True


def _cleanup_bgp_config(dut_list, cli_type=""):
    """

    :param dut_list:
    :return:
    """
    dut_li = list(dut_list) if isinstance(dut_list, list) else [dut_list]
    for dut in dut_li:
        if cli_type in ["click", "klish", "vtysh"]:
            command = "show running bgp"
            output = st.show(dut, command, type="vtysh", skip_error_check=True)
            st.log("Cleanup BGP configuration on %s.." % dut)
            config = output.splitlines()
            line = 0
            count = len(config)
            bgp_inst = []
            cli_type = get_cfg_cli_type(dut, cli_type=cli_type)
            while line < count:
                _str = config[line]
                if re.match(r'router bgp .*', _str, re.IGNORECASE):
                    if cli_type =="klish":
                        _newstr =' '.join([i for i in _str.split(" ") if not i.isdigit()])
                        if "vrf" in _str:
                            bgp_inst.insert(0, _newstr)
                        else:
                            bgp_inst.append(_newstr)
                    else:
                        if "vrf" in _str:
                            bgp_inst.insert(0, _str)
                        else:
                            bgp_inst.append(_str)

                    while config[line] != "!":
                        line += 1
                line += 1

            for inst in bgp_inst:
                st.config(dut, "no {}".format(inst), type=cli_type)
        elif cli_type in ["rest-patch", "rest-put"]:
            rest_urls = st.get_datastore(dut, 'rest_urls')
            url = rest_urls['bgp_config'].format("default")
            if not delete_rest(dut, rest_url=url):
                st.error("Error in Unconfiguring router BGP")
                return False
            return True
        else:
            st.error("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
            return False
    return True


def cleanup_bgp_config(dut_list, cli_type="", thread=True):
    """

    :param dut_list:
    :param thread:
    :return:
    """
    dut_li = list(dut_list) if isinstance(dut_list, list) else [dut_list]
    [out, _] = putils.exec_foreach(thread, dut_li, _cleanup_bgp_config, cli_type=cli_type)
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
    cli_type = get_cfg_cli_type(dut, **kwargs)
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
    elif cli_type in ["rest-patch", "rest-put"]:

        rest_urls = st.get_datastore(dut, 'rest_urls')
        vrf_name = kwargs['vrf_name'] if 'vrf_name' in kwargs and kwargs['vrf_name'] != 'default-vrf' else "default"
        url = rest_urls['bgp_global_config'].format(vrf_name)
        json_data = dict()
        json_data["openconfig-network-instance:config"] = dict()
        json_data["openconfig-network-instance:config"].update({'as': int(local_asn)})
        if config == 'yes':
            if router_id:
                json_data["openconfig-network-instance:config"].update({'router-id': router_id})
            if keep_alive:
                json_data["openconfig-network-instance:config"].update({'openconfig-bgp-ext:keepalive-interval': str(keep_alive)})
            if hold:
                json_data["openconfig-network-instance:config"].update({'openconfig-bgp-ext:hold-time': str(hold)})
            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=json_data):
                st.error("Error in configuring router BGP")
                return False

        if config == 'no' and keep_alive:
            url = rest_urls['bgp_keepalive_config'].format("default")
            delete_rest(dut, rest_url=url)
        if config == 'no' and hold:
            url = rest_urls['bgp_holdtime_config'].format("default")
            delete_rest(dut, rest_url=url)
        if config == 'no' and router_id:
            url = rest_urls['bgp_routerid_config'].format("default")
            delete_rest(dut, rest_url=url)
        return True
    else:
        st.error("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
        return False

    st.config(dut, command.split("\n") if cli_type == 'klish' else command, type=cli_type)
    return True


def create_bgp_router(dut, local_asn, router_id='', keep_alive=60, hold=180, cli_type=""):
    """

    :param dut:
    :param local_asn:
    :param router_id:
    :param keep_alive:
    :param hold:
    :return:
    """
    st.log("Creating BGP router ..")
    cli_type = get_cfg_cli_type(dut, cli_type=cli_type)
    if cli_type == 'vtysh':
        command = ""
        config_router_bgp_mode(dut, local_asn, cli_type=cli_type)
        # Add validation for IPV4 address
        if router_id:
            command = "bgp router-id {}\n".format(router_id)
        command += "timers bgp {} {}\n".format(keep_alive, hold)
    elif cli_type == 'klish':
        command = list()
        config_router_bgp_mode(dut, local_asn, cli_type=cli_type)
        # Add validation for IPV4 address
        if router_id:
            command.append("router-id {}".format(router_id))
        command.append("timers {} {}".format(keep_alive, hold))
        command.append("exit")
    elif cli_type in ["rest-patch", "rest-put"]:

        rest_urls = st.get_datastore(dut, 'rest_urls')
        vrf_name = "default"
        url = rest_urls['bgp_global_config'].format(vrf_name)
        json_data = dict()
        json_data["openconfig-network-instance:as"] = int(local_asn)
        if router_id:
            json_data["openconfig-network-instance:router-id"] = router_id
        if keep_alive:
            json_data["openconfig-bgp-ext:keepalive-interval"] = str(keep_alive)
        if hold:
            json_data["openconfig-bgp-ext:hold-time"] = str(hold)
        if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=json_data):
            st.error("Error in configuring router BGP")
            return False
        return True
    else:
        st.error("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
        return False
    st.config(dut, command, type=cli_type)
    return True


def create_bgp_neighbor(dut, local_asn, neighbor_ip, remote_asn, keep_alive=60, hold=180, password=None, family="ipv4",vrf='default', cli_type=""):
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
    cli_type = get_cfg_cli_type(dut, cli_type=cli_type)
    st.log("Creating BGP neighbor ..")
    config_router_bgp_mode(dut, local_asn, vrf=vrf, cli_type=cli_type)

    if cli_type == 'vtysh':
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
    elif cli_type == 'klish':
        commands = list()
        commands.append("neighbor {}".format(neighbor_ip))
        commands.append("remote-as {}".format(remote_asn))
        commands.append("timers {} {}".format(keep_alive, hold))
        if password:
            commands.append("password {}\n".format(password))
        if family:
            commands.append("address-family {} unicast".format(family))
            commands.append("activate")
            commands.append("exit")
        commands.append("exit")
        commands.append("exit")
        st.config(dut, commands, type=cli_type)
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        url = rest_urls['bgp_config'].format(vrf)
        data=dict()
        data["openconfig-network-instance:bgp"]=dict()
        data["openconfig-network-instance:bgp"]["global"] = dict()
        data["openconfig-network-instance:bgp"]["global"]["config"] = dict()
        data["openconfig-network-instance:bgp"]["global"]["config"].update({"as":int(local_asn)})
        neigh_data = dict()
        neigh_data["openconfig-network-instance:neighbors"] = dict()
        neigh_data["openconfig-network-instance:neighbors"]["neighbor"] = list()
        neighbors = dict()
        neighbors["neighbor-address"] = neighbor_ip
        neighbors["config"] = dict()
        neighbors["config"]["neighbor-address"] = neighbor_ip
        if str(remote_asn).isdigit():
            neighbors["config"]["peer-as"] = int(remote_asn)
        else:
            if remote_asn == "internal":
                peer_type = "INTERNAL"
            else:
                peer_type = "EXTERNAL"
            neighbors["config"]["peer-type"]=peer_type

        neighbors["timers"] = dict()
        neighbors["timers"]["config"] = dict()
        neighbors["timers"]["config"]["hold-time"] = str(hold)
        neighbors["timers"]["config"]["keepalive-interval"] = str(keep_alive)
        neighbors["afi-safis"] = dict()
        if password:
            neighbors["openconfig-bgp-ext:auth-password"] = dict()
            neighbors["openconfig-bgp-ext:auth-password"]["config"] = dict()
            neighbors["openconfig-bgp-ext:auth-password"]["config"]["password"] = password
        if family:
            if family == "ipv4":
                afi_safi_name = "openconfig-bgp-types:IPV4_UNICAST"
            else:
                afi_safi_name = "openconfig-bgp-types:IPV6_UNICAST"
            neighbors["afi-safis"]["afi-safi"] = list()
            afi_safi_data = dict()
            afi_safi_data["afi-safi-name"] = afi_safi_name
            afi_safi_data["config"] = dict()
            afi_safi_data["config"]["afi-safi-name"] = afi_safi_name
            afi_safi_data["config"]["enabled"] = True
            neighbors["afi-safis"]["afi-safi"].append(afi_safi_data)
        neigh_data["openconfig-network-instance:neighbors"]["neighbor"].append(neighbors)
        data["openconfig-network-instance:bgp"].update(neigh_data)
        if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=data):
            st.error("Error in configuring router neighbor")
            return False
        return True
    else:
        st.error("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
        return False
    return True


def config_bgp_neighbor(dut, local_asn, neighbor_ip, remote_asn, family="ipv4", keep_alive=60, hold=180, config='yes', vrf='default', cli_type="", skip_error_check=True, connect_retry=120):
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
    cli_type = get_cfg_cli_type(dut, cli_type=cli_type)
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
            commands.append("exit") #exit neighbor
        commands.append("exit") #exit router-bgp
        st.config(dut, commands, type=cli_type, skip_error_check=skip_error_check)
        return True
    elif cli_type in ["rest-patch", "rest-put"]:

        rest_urls = st.get_datastore(dut, 'rest_urls')
        data = dict()
        data["openconfig-network-instance:bgp"] = dict()
        data["openconfig-network-instance:bgp"]["global"] = dict()
        data["openconfig-network-instance:bgp"]["global"]["config"] = dict()
        data["openconfig-network-instance:bgp"]["global"]["config"].update({"as": int(local_asn)})
        if family == "ipv4":
            afi_safi_name = "openconfig-bgp-types:IPV4_UNICAST"
        else:
            afi_safi_name = "openconfig-bgp-types:IPV6_UNICAST"
        if config == "yes":
            url = rest_urls['bgp_neighbor_config'].format(vrf)
            neigh_data = dict()
            neigh_data["openconfig-network-instance:neighbors"] = dict()
            neigh_data["openconfig-network-instance:neighbors"]["neighbor"] = list()
            neighbors = dict()
            neighbors["neighbor-address"] = neighbor_ip
            neighbors["config"] = dict()
            neighbors["config"]["neighbor-address"] = neighbor_ip

            if str(remote_asn).isdigit():
                neighbors["config"]["peer-as"] = int(remote_asn)
            else:
                if remote_asn == "internal":
                    peer_type = "INTERNAL"
                else:
                    peer_type = "EXTERNAL"
                neighbors["config"]["peer-type"] = peer_type

            neighbors["timers"] = dict()
            neighbors["timers"]["config"] = dict()
            neighbors["timers"]["config"]["hold-time"] = str(hold)
            neighbors["timers"]["config"]["keepalive-interval"] = str(keep_alive)
            neighbors["timers"]["config"]["connect-retry"] = str(connect_retry)
            neighbors["afi-safis"] = dict()
            neighbors["afi-safis"]["afi-safi"] = list()
            afi_safi_data = dict()
            afi_safi_data["afi-safi-name"] = afi_safi_name
            afi_safi_data["config"] = dict()
            afi_safi_data["config"]["afi-safi-name"] = afi_safi_name
            afi_safi_data["config"]["enabled"] = True
            neighbors["afi-safis"]["afi-safi"].append(afi_safi_data)
            neigh_data["openconfig-network-instance:neighbors"]["neighbor"].append(neighbors)
            data["openconfig-network-instance:bgp"].update(neigh_data)
            url = rest_urls['bgp_config'].format(vrf)
            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=data):
                st.error("Error in configuring router neighbor")
                return False
            return True
        else:
            url = rest_urls['bgp_neighbor_config'].format(vrf)
            if not delete_rest(dut, rest_url=url):
                st.error("Unconfiguring neighbor failed")
                return False
            return True
    else:
        st.error("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
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
    st.log("Configuring the BGP neighbor properties ..")
    properties = kwargs
    peergroup = properties.get('peergroup', None)
    cli_type = get_cfg_cli_type(dut, **kwargs)
    cli_type = "klish" if cli_type in ["rest-patch","rest-put"] else cli_type
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
        if not peergroup:
            neigh_name = get_interface_number_from_name(neighbor_ip)
            if isinstance(neigh_name, dict):
                commands.append("neighbor interface {} {}".format(neigh_name["type"], neigh_name["number"]))
            else:
                commands.append("neighbor {}".format(neigh_name))
        else:
            commands.append("peer-group {}".format(neighbor_ip))
        if "password" in properties:
            password = "" if no_form == 'no' else properties["password"]
            commands.append("{} password {}".format(no_form, password))
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
        st.error("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
        return False


def delete_bgp_neighbor(dut, local_asn, neighbor_ip, remote_asn, vrf='default', cli_type="", skip_error_check=True):
    """

    :param dut:
    :param local_asn:
    :param neighbor_ip:
    :param remote_asn:
    :return:
    """
    cli_type = get_cfg_cli_type(dut, cli_type=cli_type)
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
        commands.append("exit")
        st.config(dut, commands, type=cli_type, skip_error_check=skip_error_check)
    elif cli_type in ["rest-patch", "rest-put"]:
        result = True
        rest_urls = st.get_datastore(dut, 'rest_urls')
        url = rest_urls['bgp_peer_as_config'].format(vrf, neighbor_ip)
        if not delete_rest(dut, rest_url=url):
            st.error("Error in Unconfiguring AS number")
            result = False
        url = rest_urls['bgp_del_neighbor_config'].format(vrf, neighbor_ip)
        if not delete_rest(dut, rest_url=url):
            st.error("Error in Unconfiguring neighbor number")
            result = False
        if not result:
            return False
        return True
    else:
        st.error("UNSUPPORTE CLI TYPE -- {}".format(cli_type))
        return False
    return True


def change_bgp_neighbor_admin_status(dut, local_asn, neighbor_ip, operation=1, cli_type=""):
    """

    :param dut:
    :param local_asn:
    :param neighbor_ip:
    :param operation:
    :return:
    """
    cli_type = get_cfg_cli_type(dut, cli_type=cli_type)
    st.log("Shut/no-shut BGP neighbor ..")
    config_router_bgp_mode(dut, local_asn)
    if cli_type == 'vtysh':
        if operation == 0:
            command = "neighbor {} shutdown".format(neighbor_ip)
            st.config(dut, command, type=cli_type)
        elif operation == 1:
            command = "no neighbor {} shutdown".format(neighbor_ip)
            st.config(dut, command, type=cli_type)
        else:
            st.error("Invalid operation provided.")
            return False
    elif cli_type == 'klish':
        command = list()
        command.append("neighbor {}".format(neighbor_ip))
        if operation == 0:
            command.append("shutdown")
        elif operation == 1:
            command.append("no shutdown")
        else:
            st.error("Invalid operation provided.")
            return False
        st.config(dut, command, type=cli_type)
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        vrf = "default"
        url = rest_urls['bgp_neighbor_config'].format(vrf, neighbor_ip)
        neigh_data = dict()
        neigh_data["openconfig-network-instance:neighbors"] = dict()
        neigh_data["openconfig-network-instance:neighbors"]["neighbor"] = list()
        neighbors = dict()
        neighbors["neighbor-address"] = neighbor_ip
        neighbors["config"] = dict()
        neighbors["config"]["neighbor-address"] = neighbor_ip
        neighbors["config"]["enabled"] = True if operation == 0 else False
        neigh_data["openconfig-network-instance:neighbors"]["neighbor"].append(neighbors)
        if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=neigh_data):
            st.error("Error in configuring router neighbor")
            return False
        return True
    else:
        st.error("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
        return False
    return True


def advertise_bgp_network(dut, local_asn, network, route_map='', config='yes', family='ipv4', cli_type="", skip_error_check=True, network_import_check=False):
    """

    :param dut:
    :param local_asn:
    :param network:
    :return:
    """
    cli_type = get_cfg_cli_type(dut, cli_type=cli_type)
    cli_type = "klish" if cli_type in ["rest-patch","rest-put"] else cli_type
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
        if network_import_check:
            commands.append("no network import-check")
        commands.append("address-family {} unicast".format(family))
        if route_map.lower() == '':
            commands.append("{} network {}".format(mode, network))
            commands.append("exit")
            commands.append("exit")
        else:
            commands.append("{} network {} route-map {}".format(mode, network, route_map))
            commands.append("exit")
            commands.append("exit")
        st.config(dut, commands, type=cli_type, skip_error_check=skip_error_check)
    else:
        st.error("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
        return False
    return True


def config_bgp_network_advertise(dut, local_asn, network, route_map='', addr_family='ipv4', config='yes', cli_type="",
                                 skip_error_check=True, network_import_check=False):

    cli_type = get_cfg_cli_type(dut, cli_type=cli_type)
    cli_type = "klish" if cli_type in ["rest-patch", "rest-put"] else cli_type
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
        if network_import_check:
            commands.append("no network import-check")
        commands.append("address-family {} {}".format(addr_family, "unicast"))
        cmd = "route-map {}".format(route_map) if route_map else ""
        commands.append("{} network {} {}".format(cfgmode, network, cmd).strip())
        commands.append("exit")
        commands.append("exit")
        st.config(dut, commands, type=cli_type, skip_error_check=skip_error_check)
        return True
    else:
        st.error("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
        return False

def show_bgp_ipv4_summary_vtysh(dut, vrf='default', **kwargs):
    """

    :param dut:
    :return:
    """
    cli_type = get_show_cli_type(dut, **kwargs)
    skip_tmpl = kwargs.get("skip_tmpl", False)
    if cli_type == "vtysh":
        if vrf == 'default':
            command = "show ip bgp summary"
        else:
            command = "show ip bgp vrf {} summary".format(vrf)
        return st.show(dut, command, type='vtysh', skip_tmpl=skip_tmpl)
    elif cli_type == "klish":
        if vrf == 'default':
            command = "show bgp ipv4 unicast summary"
        else:
            command = "show bgp ipv4 unicast vrf {} summary".format(vrf)
        return st.show(dut, command, type=cli_type, skip_tmpl=skip_tmpl)
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, 'rest_urls')

        url = rest_urls['bgp_config'].format(vrf)
        output = get_rest(dut, rest_url=url)
        if output and rest_status(output["status"]):
            output = output["output"]
            return parse_bgp_summary_output(output)
        else:
            return []
    else:
        st.log("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
        return []

def show_bgp_ipv6_summary_vtysh(dut, vrf='default', **kwargs):
    """

    :param dut:
    :return:
    """
    cli_type = get_show_cli_type(dut, **kwargs)
    if cli_type == "vtysh":
        if vrf == 'default':
            command = "show bgp ipv6 summary"
        else:
            command = "show bgp vrf {} ipv6 summary".format(vrf)
        return st.show(dut, command, type='vtysh')
    elif cli_type == "klish":
        if vrf == 'default':
            command = "show bgp ipv6 unicast summary"
        else:
            command = "show bgp ipv6 unicast vrf {} summary".format(vrf)
        return st.show(dut, command, type=cli_type)
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, 'rest_urls')

        url = rest_urls['bgp_config'].format(vrf)
        output = get_rest(dut, rest_url=url)
        if output and rest_status(output["status"]):
            output = output["output"]
            return parse_bgp_summary_output(output)
        else:
            return []
        #st.log(output)
        #return  parse_bgp_summary_output(output)
    else:
        st.log("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
        return []

def parse_bgp_summary_output(output):
    st.log("parse output ")
    response = list()
    temp_data = list()
    if not output:
        return response
    bgp_data = output["openconfig-network-instance:bgp"]
    established_cnt = 0
    empty_values = ['peers', 'ribentries', 'peersmemoryinkbytes', 'dynnbr', 'ribmemoryinbytes', 'dynlimit', 'tblver']
    if "neighbors" in bgp_data:
        if "neighbor" in bgp_data["neighbors"]:
            neighbors = bgp_data["neighbors"]["neighbor"]
            for neighbor in neighbors:
                show_output = dict()
                show_output["localasnnumber"] = neighbor["config"]["local-as"] if "local-as" in neighbor["config"] else (neighbor["state"]["local-as"] if "local-as" in neighbor["state"] else "")
                if "queues" in neighbor["state"]:
                    show_output["outq"] = neighbor["state"]["queues"]["output"]
                    show_output["inq"] = neighbor["state"]["queues"]["input"]
                else:
                    show_output["outq"] = show_output["inq"] = 0
                sent_msg_cnt = rcv_msg_cnt = 0
                if "messages" in neighbor["state"]:
                    sent_msgs = neighbor["state"]["messages"]["sent"]
                    rcv_msgs = neighbor["state"]["messages"]["received"]
                else:
                    sent_msg_cnt = rcv_msg_cnt = 0
                for _, value in sent_msgs.items():
                    sent_msg_cnt = sent_msg_cnt + int(value)
                show_output["msgsent"] = sent_msg_cnt
                #rcv_msgs = neighbor["state"]["messages"]["received"]
                for key, value in rcv_msgs.items():
                    rcv_msg_cnt = rcv_msg_cnt + int(value)
                show_output["msgrcvd"] = rcv_msg_cnt
                show_output["updown"] = convert_microsecs_to_time(
                    neighbor["state"]["last-established"]) if "last-established" in neighbor["state"] else "never"
                show_output["routerid"] = bgp_data["global"]["config"]["router-id"] if "router-id" in bgp_data["global"]["config"] else (bgp_data["global"]["state"]["router-id"] if "router-id" in bgp_data["global"]["state"] else "")
                show_output["state"] = neighbor["state"]["session-state"] if "session-state" in neighbor["state"] else ""
                show_output["version"] = 4
                show_output["vrfid"] = "default"
                show_output["neighbor"] = neighbor["neighbor-address"]
                show_output["asn"] = neighbor["config"]["peer-as"] if "peer-as" in neighbor["config"] else (neighbor["state"]["peer-as"] if "peer-as" in neighbor["state"] else "")
                if show_output["state"] == "ESTABLISHED":
                    established_cnt = established_cnt + 1
                for keys in empty_values:
                    show_output[keys] = ""
                temp_data.append(show_output)
            for data in temp_data:
                data.update({"estd_nbr": established_cnt, "total_nbr": len(temp_data)})
                response.append(data)
    return response

def show_bgp_ipv4_summary(dut, **kwargs):
    """

    :param dut:
    :return:
    """
    #added kwargs.update() as Klish output currently does not list RIB entries. RFE SONIC-23559
    kwargs.update({"cli_type": "vtysh"})
    cli_type = get_show_cli_type(dut, **kwargs)
    if cli_type == "vtysh":
        command = "show bgp ipv4 summary"
    elif cli_type == "klish":
        command = 'show bgp ipv4 unicast summary'
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        vrf = "default"
        url = rest_urls['bgp_config'].format(vrf)
        output = get_rest(dut, rest_url=url)
        if output and rest_status(output["status"]):
            output = output["output"]
            return parse_bgp_summary_output(output)
        else:
            return []

    else:
        st.log("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
        return []
    return st.show(dut, command, type=cli_type)


def show_bgp_ipv6_summary(dut, **kwargs):
    """

    :param dut:
    :return:
    """
    # added kwargs.update() as Klish output currently does not list RIB entries. RFE SONIC-23559
    kwargs.update({"cli_type": "vtysh"})
    cli_type = get_show_cli_type(dut, **kwargs)
    if cli_type == "vtysh":
        command = "show bgp ipv6 summary"
    elif cli_type == "klish":
        command = 'show bgp ipv6 unicast summary'
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        vrf = "default"
        url = rest_urls['bgp_config'].format(vrf)
        output = get_rest(dut, rest_url=url)
        if output and rest_status(output["status"]):
            output = output["output"]
            return parse_bgp_summary_output(output)
        else:
            return []

    else:
        st.log("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
        return []
    return st.show(dut, command, type=cli_type)

def get_bgp_nbr_count(dut, **kwargs):
    cli_type = get_show_cli_type(dut, **kwargs)
    vrf = kwargs.get('vrf','default')
    family = kwargs.get('family','ipv4')
    if family == 'ipv6':
        output = show_bgp_ipv6_summary_vtysh(dut, vrf=vrf, cli_type=cli_type)
    else:
        output = show_bgp_ipv4_summary_vtysh(dut, vrf=vrf, cli_type=cli_type)
    estd_nbr = 0
    for i in range(0,len(output)):
        if output[i]['estd_nbr'] != '':
            estd_nbr = int(output[i]['estd_nbr'])
            break
    return estd_nbr


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
    cli_type = get_show_cli_type(dut, **kwargs)
    kwargs.pop("cli_type", None)
    output = show_bgp_ipv6_summary(dut,cli_type=cli_type)
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
    #No usage in scripts, so no klish support added
    command = "show bgp neighbor {}".format(neighbor_ip)
    return st.show(dut, command)


def show_bgp_ipv4_neighbor_vtysh(dut, neighbor_ip=None,vrf='default', **kwargs):
    """

    :param dut:
    :param neighbor_ip:
    :param property:
    :param address_family:
    :return:
    """
    cli_type = get_show_cli_type(dut, **kwargs)
    if cli_type == 'vtysh':
        if vrf == 'default':
            command = "show ip bgp neighbors"
        else:
            command = "show ip bgp vrf {} neighbors".format(vrf)
        if neighbor_ip:
            command += " {}".format(neighbor_ip)
    elif cli_type == 'klish':
        if vrf == 'default':
            command = "show bgp ipv4 unicast neighbors"
        else:
            command = "show bgp ipv4 unicast vrf {} neighbors".format(vrf)
        if neighbor_ip:
            command += " {}".format(neighbor_ip)
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_url = st.get_datastore(dut, 'rest_urls')
        #Getting router id
        url = rest_url["bgp_routerid_state"].format(vrf)
        output_router_id = get_rest(dut, rest_url=url)
        if output_router_id and rest_status(output_router_id["status"]):
            output_router_id = output_router_id["output"]
        else:
            output_router_id ={}
        router_id = ""
        if output_router_id:
            router_id = output_router_id["openconfig-network-instance:router-id"]
        url = rest_url['bgp_neighbor_config'].format(vrf)
        output = get_rest(dut, rest_url=url)
        if output and rest_status(output["status"]):
            output = output["output"]
            return _parse_ip_bgp_data(output, "ipv4", router_id)
        else:
            return []

    return st.show(dut, command, type=cli_type)


def show_bgp_ipv6_neighbor_vtysh(dut, neighbor_ip=None,vrf='default', **kwargs):
    """

    :param dut:
    :param neighbor_ip:
    :return:
    """
    cli_type = get_show_cli_type(dut, **kwargs)
    if cli_type == 'vtysh':
        if vrf == 'default':
            command = "show bgp ipv6 neighbors"
        else:
            command = "show bgp vrf {} ipv6 neighbors".format(vrf)
        if neighbor_ip:
            command += " {}".format(neighbor_ip)
    elif cli_type == 'klish':
        if vrf == 'default':
            command = "show bgp ipv6 unicast neighbors"
        else:
            command = "show bgp ipv6 unicast vrf {} neighbors".format(vrf)
        if neighbor_ip:
            command += " {}".format(neighbor_ip)
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_url = st.get_datastore(dut, 'rest_urls')
        # Getting router id
        url = rest_url["bgp_routerid_state"].format(vrf)
        output_router_id = get_rest(dut, rest_url=url)
        if output_router_id and rest_status(output_router_id["status"]):
            output_router_id = output_router_id["output"]
        else:
            output_router_id = {}
        router_id = ""
        if output_router_id:
            router_id = output_router_id["openconfig-network-instance:router-id"]
        url = rest_url['bgp_neighbor_config'].format(vrf)
        output = get_rest(dut, rest_url=url)
        if output and rest_status(output["status"]):
            output = output["output"]
            return _parse_ip_bgp_data(output, "ipv4", router_id)
        else:
            return []
    return st.show(dut, command, type=cli_type)

def _parse_ip_bgp_data(output, family, router_id):
    """
    Common function to parse BGP neighbors data
    :param output:
    :param family:
    :param router_id:
    :return:
    """
    result = list()
    if output:
        if not router_id:
            return result
        neighbors = output["openconfig-network-instance:neighbors"]
        if "neighbor" in neighbors:
            neighbor_data = neighbors["neighbor"]
            for neighbor in neighbor_data:
                afi_safi_data = neighbor["afi-safis"]["afi-safi"]
                for afi_safi in afi_safi_data:
                    if family in afi_safi["afi-safi-name"].lower():
                        show_output = dict()
                        show_output["localrouterid"] = router_id
                        show_output["updatercvd"] = show_output["updatesent"] = show_output["openrcvd"] = show_output[
                            "opensent"] = \
                            show_output["routerefreshrcvd"] = show_output["routerefreshsent"] = show_output[
                            "capabilityrcvd"] = \
                            show_output["capabilitysent"] = \
                            show_output["keepalivercvd"] = show_output["keepalivesent"] = show_output["inqdepth"] = \
                            show_output[
                                "outqdepth"] = \
                            show_output["holdtime"] = show_output["keepalive"] = show_output["bgplastreset"] = 0
                        show_output["peergroup"] = show_output["neighborip"] = show_output["remrouterid"] = show_output[
                            "lastread"] = \
                            show_output["lastwrite"] = show_output["bfdstatus"] = show_output["localrouterid"] = ""
                        show_output["state"] = "IDLE"
                        keys = ["bgpversion", "bfdrxintr", "bfdtxintr", "subgrp", "updtgrp", "l2vpnevpnncap",
                                "ipv4ucastncap",
                                "bfdmultiplier", "acceptprefix", "grcapability", "senttotal", "rcvdtotal", "bfdtype",
                                "pktql",
                                "endofribsend", "endofribrcv"]
                        for key in keys:
                            show_output[key] = ""
                        show_output["neighborip"] = neighbor[
                            "neighbor-address"] if "neighbor-address" in neighbor else ""
                        if "config" in neighbor:
                            show_output["peergroup"] = neighbor["config"]["peer-group"] if "peer-group" in neighbor[
                                "config"] else ""
                            show_output["localasn"] = neighbor["config"]["local-as"] if "local-as" in neighbor[
                                "config"] else ""
                            show_output["remoteasn"] = neighbor["config"]["peer-as"] if "peer-as" in neighbor[
                                "config"] else ""
                            show_output["bgpdownreason"] = neighbor["config"][
                                "openconfig-bgp-ext:shutdown-message"] if "openconfig-bgp-ext:shutdown-message" in \
                                                                          neighbor["config"] else ""

                        if "state" in neighbor:
                            if "messages" in neighbor["state"]:
                                messages = neighbor["state"]["messages"]
                                if "received" in messages:
                                    show_output["updatercvd"] = messages["received"]["UPDATE"] if "UPDATE" in messages[
                                        "received"] else 0
                                    show_output["openrcvd"] = messages["received"][
                                        "openconfig-bgp-ext:open"] if "openconfig-bgp-ext:open" in messages[
                                        "received"] else 0
                                    show_output["routerefreshrcvd"] = messages["received"][
                                        "openconfig-bgp-ext:route-refresh"] if "openconfig-bgp-ext:route-refresh" in \
                                                                               messages["received"] else 0
                                    show_output["capabilityrcvd"] = messages["received"][
                                        "openconfig-bgp-ext:capablity"] if "openconfig-bgp-ext:capablity" in messages[
                                        "received"] else 0
                                    show_output["keepalivercvd"] = messages["received"][
                                        "openconfig-bgp-ext:keepalive"] if "openconfig-bgp-ext:keepalive" in messages[
                                        "received"] else 0
                                    show_output["notificationrcvd"] = messages["received"][
                                        "NOTIFICATION"] if "NOTIFICATION" in messages["received"] else 0
                                if "sent" in messages:
                                    show_output["updatesent"] = messages["sent"]["UPDATE"] if "UPDATE" in messages[
                                        "sent"] else 0
                                    show_output["opensent"] = messages["sent"][
                                        "openconfig-bgp-ext:open"] if "openconfig-bgp-ext:open" in messages[
                                        "sent"] else 0
                                    show_output["routerefreshsent"] = messages["sent"][
                                        "openconfig-bgp-ext:route-refresh"] if "openconfig-bgp-ext:route-refresh" in \
                                                                               messages[
                                                                                   "sent"] else 0
                                    show_output["capabilitysent"] = messages["sent"][
                                        "openconfig-bgp-ext:capablity"] if "openconfig-bgp-ext:capablity" in messages[
                                        "sent"] else 0
                                    show_output["keepalivesent"] = messages["sent"][
                                        "openconfig-bgp-ext:keepalive"] if "openconfig-bgp-ext:keepalive" in messages[
                                        "sent"] else 0
                                    show_output["notificationsent"] = messages["sent"][
                                        "NOTIFICATION"] if "NOTIFICATION" in \
                                                           messages[
                                                               "sent"] else 0
                            show_output["state"] = neighbor["state"]["session-state"] if "session-state" in neighbor[
                                "state"] else "IDLE"
                            show_output["remrouterid"] = neighbor["state"][
                                "openconfig-bgp-ext:remote-router-id"] if "openconfig-bgp-ext:remote-router-id" in \
                                                                          neighbor[
                                                                              "state"] else ""
                            show_output["lastread"] = neighbor["state"][
                                "openconfig-bgp-ext:last-read"] if "openconfig-bgp-ext:last-read" in neighbor[
                                "state"] else ""
                            show_output["lastwrite"] = neighbor["state"][
                                "openconfig-bgp-ext:last-write"] if "openconfig-bgp-ext:last-write" in neighbor[
                                "state"] else ""
                            show_output["bgplastreset"] = neighbor["state"][
                                "openconfig-bgp-ext:last-reset-time"] if "openconfig-bgp-ext:last-reset-time" in \
                                                                         neighbor[
                                                                             "state"] else ""
                            if "queues" in neighbor["state"]:
                                show_output["inqdepth"] = neighbor["state"]["queues"]["input"]
                                show_output["outqdepth"] = neighbor["state"]["queues"]["output"]
                        if "timers" in neighbor:
                            if "config" in neighbor["timers"]:
                                show_output["holdtime"] = neighbor["timers"]["config"]["hold-time"] if "hold-time" in \
                                                                                                       neighbor[
                                                                                                           "timers"][
                                                                                                           "config"] else 0
                                show_output["keepalive"] = neighbor["timers"]["config"][
                                    "keepalive-interval"] if "keepalive-interval" in neighbor["timers"]["config"] else 0
                        if "openconfig-bfd:enable-bfd" in neighbor:
                            if "config" in neighbor["openconfig-bfd:enable-bfd"]:
                                bfd_status = neighbor["openconfig-bfd:enable-bfd"]["config"]["enabled"]
                                show_output["bfdstatus"] = "" if not bfd_status else bfd_status
                        result.append(show_output)
    return result


def clear_ip_bgp(dut, **kwargs):
    """

    :param dut:
    :return:
    """
    cli_type = get_cfg_cli_type(dut, **kwargs)
    cli_type = "klish" if cli_type in ["rest-put", "rest-patch"] else cli_type
    if cli_type in ["click", "vtysh"]:
        # command = "sonic-clear ip bgp"
        command = "clear ip bgp *"
        st.config(dut, command, type=cli_type, conf=False)
    elif cli_type == 'klish':
        command = 'clear bgp ipv4 unicast *'
        st.config(dut, command, type=cli_type)
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        vrf = "default"
        url = rest_urls['bgp_config'].format(vrf)
        if not delete_rest(dut, rest_url=url):
            st.error("Clearing BGP config failed")
            return False
        return True
    else:
        st.error("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
        return False
    return True

def clear_bgp_vtysh(dut, **kwargs):
    """

    :param dut:
    :param value:
    :param address_family: ipv4|ipv6|all
    :return:
    """
    cli_type = get_cfg_cli_type(dut, **kwargs)
    cli_type = "klish" if cli_type in ["rest-put", "rest-patch"] else cli_type
    address_family = kwargs.get('address_family', 'all')
    af_list = ['ipv4','ipv6']
    if address_family == 'ipv4':
        if cli_type == 'vtysh':
            af_list = ['ipv4']
        elif cli_type == 'klish':
            af_list = ['ipv4 unicast']
    elif address_family == 'ipv6':
        if cli_type == 'vtysh':
            af_list = ['ipv6']
        elif cli_type == 'klish':
            af_list = ['ipv6 unicast']
    else:
        if cli_type == "vtysh":
            af_list=["ipv4", "ipv6"]
        elif cli_type == "klish":
            af_list = ["ipv4 unicast", "ipv6 unicast"]
    for each_af in af_list:
        if cli_type == 'vtysh':
            command = "clear ip bgp {} *".format(each_af)
        elif cli_type == 'klish':
            command = "clear bgp {} *".format(each_af)
        st.config(dut, command, type=cli_type, conf=False)


def clear_ip_bgp_vtysh(dut, value="*", **kwargs):
    cli_type = get_cfg_cli_type(dut, **kwargs)
    cli_type = "klish" if cli_type in ["rest-put", "rest-patch"] else cli_type
    if cli_type == 'vtysh':
        command = "clear ip bgp ipv4 {}".format(value)
        st.config(dut, command, type='vtysh', conf=False)
    elif cli_type == 'klish':
        command = "clear bgp ipv4 unicast {}".format(value)
        st.config(dut, command, type='klish', conf=False)
    else:
        st.error("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
        return False


def clear_ipv6_bgp_vtysh(dut, value="*", **kwargs):
    cli_type = get_cfg_cli_type(dut, **kwargs)
    cli_type = "klish" if cli_type in ["rest-put", "rest-patch"] else cli_type
    if cli_type == 'vtysh':
        command = "clear ip bgp ipv6 {}".format(value)
    elif cli_type == 'klish':
        command = "clear bgp ipv6 unicast {}".format(value)
    st.config(dut, command, type= cli_type, conf=False)

def clear_ip_bgp_vrf_vtysh(dut,vrf,family='ipv4',value="*", **kwargs):
    cli_type = get_cfg_cli_type(dut, **kwargs)
    cli_type = "klish" if cli_type in ["rest-put", "rest-patch"] else cli_type
    if cli_type == 'vtysh':
        command = "clear bgp vrf {} {} {}".format(vrf,family,value)
        st.config(dut, command, type='vtysh', conf=False)
    elif cli_type == 'klish':
        if family == 'ipv4':
            family = 'ipv4 unicast'
        elif family == 'ipv6':
            family = 'ipv6 unicast'
        command = "clear bgp {} vrf {} {}".format(family, vrf, value)
        st.config(dut, command, type='klish', conf=False)
    else:
        st.error("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
        return False


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
    cli_type = get_cfg_cli_type(dut, **kwargs)
    if "local_asn" not in kwargs and "address_range" not in kwargs and "config" not in kwargs and "family" not in kwargs:
        st.error("Mandatory parameters not provided")
    skip_error_check = kwargs.get("skip_error_check", True)
    # cli_type=kwargs.get("cli_type","vtysh")
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
        commands.append("exit")
        st.config(dut, commands, type=cli_type, skip_error_check=skip_error_check)
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        vrf = "default"
        if kwargs["family"] == "ipv4":
            afi_safi_name = "openconfig-bgp-types:IPV4_UNICAST"
        else:
            afi_safi_name = "openconfig-bgp-types:IPV6_UNICAST"
        if kwargs.get("config") == "add":
            url = rest_urls['bgp_config'].format(vrf)
            bgp_data = dict()
            bgp_data["openconfig-network-instance:bgp"] = dict()
            bgp_data["openconfig-network-instance:bgp"]["global"] = dict()
            bgp_data["openconfig-network-instance:bgp"]["global"]["config"] = dict()
            bgp_data["openconfig-network-instance:bgp"]["global"]["config"]["as"] = int(kwargs["local_asn"])
            bgp_data["openconfig-network-instance:bgp"]["global"]["afi-safis"] = dict()
            afi_safi_data = list()
            afi_safi = dict()
            afi_safi["afi-safi-name"] = afi_safi_name
            afi_safi["config"] = dict()
            afi_safi["config"]["afi-safi-name"] = afi_safi_name
            afi_safi["openconfig-bgp-ext:aggregate-address-config"] = dict()
            afi_safi["openconfig-bgp-ext:aggregate-address-config"]["aggregate-address"] = list()
            aggregate_data = dict()
            aggregate_data["prefix"] = kwargs["address_range"]
            aggregate_data["config"] = dict()
            aggregate_data["config"]["prefix"] = kwargs["address_range"]
            if kwargs.get("summary"):
                aggregate_data["config"]["summary-only"] = True
            if kwargs.get("as_set"):
                aggregate_data["config"]["as-set"] = True
            afi_safi["openconfig-bgp-ext:aggregate-address-config"]["aggregate-address"].append(aggregate_data)
            afi_safi_data.append(afi_safi)
            bgp_data["openconfig-network-instance:bgp"]["global"]["afi-safis"]["afi-safi"] = afi_safi_data
            if not config_rest(dut, rest_url=url,http_method=cli_type, json_data=bgp_data):
                st.error("Error in configuring aggregate address")
                return False
            return True
        else:
            url = rest_urls["bgp_aggregate_address_config"].format(name=vrf, afi_safi_name=afi_safi_name, prefix=kwargs["address_range"])
            if not delete_rest(dut,rest_url= url):
                st.error("Error in deleting aggregate address")
                return False
            return True
    else:
        st.error("Unsupported CLI TYPE -- {}".format(cli_type))
        return False

def create_bgp_update_delay(dut, local_asn, time=0, cli_type="", skip_error_check=True):
    """

    :param dut:
    :param local_asn:
    :param time:
    :return:
    """
    cli_type = get_cfg_cli_type(dut, cli_type=cli_type)
    if cli_type in ["click", "vtysh", "klish"]:
        config_router_bgp_mode(dut, local_asn, cli_type=cli_type)
        command = "update-delay {}".format(time)
        st.config(dut, command,type=cli_type, skip_error_check=skip_error_check)
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        vrf = "default"
        url = rest_urls['bgp_config'].format(vrf)
        bgp_data = dict()
        bgp_data["openconfig-network-instance:bgp"] = dict()
        bgp_data["openconfig-network-instance:bgp"]["global"] = dict()
        bgp_data["openconfig-network-instance:bgp"]["global"]["config"] = dict()
        bgp_data["openconfig-network-instance:bgp"]["global"]["config"]["as"] = int(local_asn)
        bgp_data["openconfig-network-instance:bgp"]["global"]["openconfig-bgp-ext:update-delay"] = dict()
        bgp_data["openconfig-network-instance:bgp"]["global"]["openconfig-bgp-ext:update-delay"]["config"] = dict()
        bgp_data["openconfig-network-instance:bgp"]["global"]["openconfig-bgp-ext:update-delay"]["config"]["max-delay"] = int(time)
        if not config_rest(dut, rest_url=url,http_method=cli_type, json_data=bgp_data):
            st.error("Error in configuring update delay")
            return False
        return True
    else:
        st.error("UNSUPPORTED CLI TYPE")
        return False


def create_bgp_always_compare_med(dut, local_asn):
    """

    :param dut:
    :param local_asn:
    :return:
    """
    #No usage in scripts
    config_router_bgp_mode(dut, local_asn)
    command = "bgp always-compare-med"
    st.config(dut, command, type='vtysh')


def create_bgp_best_path(dut, local_asn, user_command, cli_type=""):
    """

    :param dut:
    :param local_asn:
    :param user_command:
    :return:
    """
    cli_type = get_cfg_cli_type(dut, cli_type=cli_type)
    config_router_bgp_mode(dut, local_asn, cli_type=cli_type)
    if cli_type == 'vtysh':
        command = "bgp bestpath {}".format(user_command)
    elif cli_type == 'klish':
        command = list()
        command.append("bestpath {}".format(user_command))
        command.append("exit")
    elif cli_type in ["rest-put", "rest-patch"]:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        vrf = "default"
        url = rest_urls['bgp_config'].format(vrf)
        route_selection_data = dict()
        route_selection_data["openconfig-network-instance:bgp"] = dict()
        if user_command == "compare-routerid":
            route_selection_data["openconfig-network-instance:bgp"]["route-selection-options"]["config"] = dict()
            route_selection_data["openconfig-network-instance:bgp"]["route-selection-options"]["config"]["external-compare-router-id"] = True
        elif user_command == "as-path confed":
            route_selection_data["openconfig-network-instance:bgp"]["route-selection-options"]["config"] = dict()
            route_selection_data["openconfig-network-instance:bgp"]["route-selection-options"][
                "config"]["openconfig-bgp-ext:compare-confed-as-path"] = True
        elif user_command == "as-path ignore":
            route_selection_data["openconfig-network-instance:bgp"]["route-selection-options"]["config"] = dict()
            route_selection_data["openconfig-network-instance:bgp"]["route-selection-options"][
                "config"]["ignore-as-path-length"] = True
        elif user_command == "as-path multipath-relax":
            route_selection_data["openconfig-network-instance:bgp"]["global"] = dict()
            route_selection_data["openconfig-network-instance:bgp"]["global"]["use-multiple-paths"] = dict()
            route_selection_data["openconfig-network-instance:bgp"]["global"]["use-multiple-paths"]["ebgp"] = dict()
            route_selection_data["openconfig-network-instance:bgp"]["global"]["use-multiple-paths"]["ebgp"]["config"] = dict()
            route_selection_data["openconfig-network-instance:bgp"]["global"]["use-multiple-paths"]["ebgp"]["config"]["allow-multiple-as"] = True
        elif user_command == "med confed":
            route_selection_data["openconfig-network-instance:bgp"]["route-selection-options"]["config"] = dict()
            route_selection_data["openconfig-network-instance:bgp"]["route-selection-options"][
                "config"]["openconfig-bgp-ext:med-confed"] = True
        elif user_command == "med confed missing-as-worst":
            route_selection_data["openconfig-network-instance:bgp"]["route-selection-options"]["config"] = dict()
            route_selection_data["openconfig-network-instance:bgp"]["route-selection-options"][
                "config"]["openconfig-bgp-ext:med-missing-as-worst"] = True
        else:
            st.error("Unsupporte user command")
            return False
        if not config_rest(dut,http_method=cli_type, rest_url=url, json_data=route_selection_data):
            st.error("Error in configuring best path")
            return False
        return True
    else:
        st.error("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
        return False
    st.config(dut, command, type=cli_type)


def create_bgp_client_to_client_reflection(dut, local_asn, config='yes', cli_type="", skip_error_check=True):
    """

    :param dut:
    :param local_asn:
    :return:
    """
    cli_type = get_cfg_cli_type(dut, cli_type=cli_type)
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
        commands.append("exit")
        st.config(dut, commands, type=cli_type, skip_error_check=skip_error_check)
        return True
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        vrf = "default"
        url = rest_urls['bgp_global_config'].format(vrf)

        if cfgmode != 'no':
            client_client_reflection = True
        else:
            client_client_reflection = False
        global_data = dict()
        global_data["openconfig-network-instance:config"] = dict()
        global_data["openconfig-network-instance:config"]["as"] = int(local_asn)
        global_data["openconfig-network-instance:config"]["openconfig-bgp-ext:clnt-to-clnt-reflection"] = client_client_reflection
        if not config_rest(dut,http_method=cli_type, rest_url=url, json_data=global_data):
            st.error("Error in configuring client to client reflection")
            return False
        return True
    else:
        st.error("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
        return False


def create_bgp_route_reflector_client(dut, local_asn, addr_family, nbr_ip, config='yes', cli_type="", skip_error_check=True):
    """
    :param dut:
    :param local_asn:
    :param addr_family:
    :param nbr_ip:
    :return:
    """
    cli_type = get_cfg_cli_type(dut, cli_type=cli_type)
    cfgmode = 'no' if config != 'yes' else ''
    if cli_type == "vtysh":
        command  = "router bgp {}".format(local_asn)
        command += "\n address-family {} {}".format(addr_family, "unicast")
        command += "\n {} neighbor {} route-reflector-client".format(cfgmode, nbr_ip)
        st.config(dut, command, type=cli_type)
        return True
    elif cli_type == "klish":
        addr_family_type = "unicast"
        neigh_name = nbr_ip
        commands = list()
        commands.append("router bgp {}".format(local_asn))
        if re.findall(r'Ethernet|Vlan|PortChannel|Eth', nbr_ip):
            neigh_name = get_interface_number_from_name(nbr_ip)
            commands.append("neighbor interface {} {}".format( neigh_name["type"], neigh_name["number"]))
        elif addr_family == 'l2vpn' :
             commands.append("neighbor {}".format(nbr_ip))
        elif is_valid_ip_address(neigh_name, addr_family):
            commands.append("neighbor {}".format(nbr_ip))
        else:
            commands.append("peer-group {}".format(nbr_ip))
        if addr_family == 'l2vpn' : addr_family_type = "evpn"
        commands.append("address-family {} {}".format(addr_family, addr_family_type))
        commands.append("{} route-reflector-client".format(cfgmode))
        commands.append("exit")
        commands.append("exit")
        commands.append("exit")
        st.config(dut, commands, type=cli_type, skip_error_check=skip_error_check)
        return True
    elif cli_type in ["rest-patch", "rest-put"]:

        rest_urls = st.get_datastore(dut, 'rest_urls')
        vrf = "default"
        url = rest_urls['bgp_config'].format(vrf)
        route_reflector_data = dict()
        route_reflector_data["openconfig-network-instance:bgp"] = dict()
        route_reflector_data["openconfig-network-instance:bgp"]["global"] = dict()
        route_reflector_data["openconfig-network-instance:bgp"]["global"]["config"] = dict()
        route_reflector_data["openconfig-network-instance:bgp"]["global"]["config"]["as"] = int(local_asn)

        if addr_family == "ipv4":
            afi_safi_name = "openconfig-bgp-types:IPV4_UNICAST"
        elif addr_family == "l2vpn":
            afi_safi_name = "L2VPN_EVPN"
        else:
            afi_safi_name = "openconfig-bgp-types:IPV6_UNICAST"

        common_data = dict()
        common_data["afi-safis"] = dict()
        common_data["afi-safis"]["afi-safi"] = list()
        afi_safi_data = dict()
        afi_safi_data["afi-safi-name"] = afi_safi_name
        afi_safi_data["config"] = dict()
        afi_safi_data["config"]["afi-safi-name"] = afi_safi_name
        if cfgmode != 'no':
            route_reflector_client = True
        else:
            route_reflector_client = False
        afi_safi_data["config"]["openconfig-bgp-ext:route-reflector-client"] = route_reflector_client

        common_data["afi-safis"]["afi-safi"].append(afi_safi_data)
        if re.findall(r'Ethernet|Vlan|PortChannel|Eth', nbr_ip) or addr_family == 'l2vpn' or is_valid_ip_address(nbr_ip, addr_family):
            route_reflector_data["openconfig-network-instance:bgp"]["neighbors"] = dict()
            route_reflector_data["openconfig-network-instance:bgp"]["neighbors"]["neighbor"] = list()
            neigh_data = dict()
            neigh_data["neighbor-address"] = nbr_ip
            neigh_data["config"]=dict()
            neigh_data["config"]["neighbor-address"]= nbr_ip
            neigh_data.update(common_data)
            route_reflector_data["openconfig-network-instance:bgp"]["neighbors"]["neighbor"].append(neigh_data)
        else:
            route_reflector_data["openconfig-network-instance:bgp"]["peer-groups"] = dict()
            route_reflector_data["openconfig-network-instance:bgp"]["peer-groups"]["peer-group"] = list()
            peer_data = dict()
            peer_data["peer-group-name"] = nbr_ip
            peer_data["config"] = dict()
            peer_data["config"]["peer-group-name"] = nbr_ip
            peer_data.update(common_data)
            route_reflector_data["openconfig-network-instance:bgp"]["peer-groups"]["peer-group"].append(peer_data)

        if not config_rest(dut, rest_url=url, http_method=cli_type,json_data=route_reflector_data):
            st.error("Error while configuring route reflector client")
            return False
        return True
    else:
        st.error("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
        return False


def create_bgp_next_hop_self(dut, local_asn, addr_family, nbr_ip, force='no', config='yes', cli_type="", skip_error_check=True):
    """

    :param dut:
    :param local_asn:
    :param addr_family:
    :param nbr_ip:
    :param config:
    :return:
    """
    cli_type = get_cfg_cli_type(dut, cli_type=cli_type)
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
        if is_valid_ip_address(nbr_ip, addr_family):
            commands.append("{} neighbor {}".format(cfgmode, nbr_ip))
        else:
            commands.append("{} peer-group {}".format(cfgmode, nbr_ip))

        if config == "yes":
            force_cmd = "force" if force == 'yes' else ""
            commands.append("address-family {} {}".format(addr_family, "unicast"))
            commands.append("next-hop-self {}".format(force_cmd))
            commands.append("exit")
            commands.append("exit")
        commands.append("exit")
        st.config(dut, commands, type=cli_type, skip_error_check=skip_error_check)
        return True
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, 'rest_urls')

        vrf = "default"
        if not cfgmode:
            url = rest_urls['bgp_config'].format(vrf)
            route_reflector_data = dict()
            route_reflector_data["openconfig-network-instance:bgp"] = dict()
            route_reflector_data["openconfig-network-instance:bgp"]["global"] = dict()
            route_reflector_data["openconfig-network-instance:bgp"]["global"]["config"] = dict()
            route_reflector_data["openconfig-network-instance:bgp"]["global"]["config"]["as"] = int(local_asn)
            if config == "yes":
                if addr_family == "ipv4":
                    afi_safi_name = "openconfig-bgp-types:IPV4_UNICAST"
                else:
                    afi_safi_name = "openconfig-bgp-types:IPV6_UNICAST"

                common_data = dict()
                common_data["afi-safis"] = dict()
                common_data["afi-safis"]["afi-safi"] = list()
                afi_safi_data = dict()
                afi_safi_data["afi-safi-name"] = afi_safi_name
                afi_safi_data["config"] = dict()
                afi_safi_data["config"]["afi-safi-name"] = afi_safi_name
                afi_safi_data["openconfig-bgp-ext:next-hop-self"] = dict()
                afi_safi_data["openconfig-bgp-ext:next-hop-self"]["config"] = dict()
                force_cmd = True if force == 'yes' else False
                afi_safi_data["openconfig-bgp-ext:next-hop-self"]["config"]["force"] = force_cmd
                afi_safi_data["openconfig-bgp-ext:next-hop-self"]["config"]["enabled"] = True if force != "yes" else False
                common_data["afi-safis"]["afi-safi"].append(afi_safi_data)
            if is_valid_ip_address(nbr_ip, addr_family):
                route_reflector_data["openconfig-network-instance:bgp"]["neighbors"] = dict()
                route_reflector_data["openconfig-network-instance:bgp"]["neighbors"]["neighbor"] = list()
                neigh_data = dict()
                neigh_data["neighbor-address"] = nbr_ip
                neigh_data["config"]=dict()
                neigh_data["config"]["neighbor-address"] = nbr_ip
                neigh_data.update(common_data)
                route_reflector_data["openconfig-network-instance:bgp"]["neighbors"]["neighbor"].append(neigh_data)
            else:
                route_reflector_data["openconfig-network-instance:bgp"]["peer-groups"] = dict()
                route_reflector_data["openconfig-network-instance:bgp"]["peer-groups"]["peer-group"] = list()
                peer_data = dict()
                peer_data["peer-group-name"] = nbr_ip
                peer_data["config"] = dict()
                peer_data["config"]["peer-group-name"] = nbr_ip
                peer_data.update(common_data)
                route_reflector_data["openconfig-network-instance:bgp"]["peer-groups"]["peer-group"].append(peer_data)


            if not config_rest(dut, rest_url=url, http_method=cli_type,json_data=route_reflector_data):
                st.error("Error while configuring next hop self")
                return False
            return True
        else:
            result = True
            url = rest_urls['bgp_del_neighbor_config'].format(vrf,nbr_ip)
            if not delete_rest(dut, rest_url=url):
                st.error("Deleting neighbor with address failed")
                result = False
            url = rest_urls['bgp_peer_group_name_config'].format(vrf,nbr_ip)
            if not delete_rest(dut, rest_url=url):
                st.error("Deleting peergroup with name failed")
                result = False
            if not result:
                return False
            return True
    else:
        st.log("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
        return False


def create_bgp_cluster_id(dut, local_asn, cluster_id, cluster_ip):
    """

    :param dut:
    :param local_asn:
    :param cluster_id:
    :param cluster_ip:
    :return:
    """
    #No usage in test scripts
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
    # No usage in test scripts
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
    # No usage in test scripts
    config_router_bgp_mode(dut, local_asn)
    command = "bgp dampening {} {} {} {}".format(half_life_time, timer_start, timer_start_supress, max_duration)
    st.config(dut, command, type='vtysh')


def config_bgp_default(dut, local_asn, user_command, config='yes', cli_type="", skip_error_check=True):
    """

    :param dut:
    :param local_asn:
    :param user_command:
    :return:
    """
    cli_type = get_cfg_cli_type(dut, cli_type=cli_type)
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
        commands.append("exit")
        st.config(dut, commands, type=cli_type, skip_error_check=skip_error_check)
        return True
    elif cli_type in ["rest-patch", "rest-put"]:

        data = dict()
        data["openconfig-network-instance:bgp"]=dict()
        data["openconfig-network-instance:bgp"]["global"] = dict()
        data["openconfig-network-instance:bgp"]["global"]["config"] = dict()
        data["openconfig-network-instance:bgp"]["global"]["config"].update({"as": int(local_asn)})
        data["openconfig-network-instance:bgp"]["global"]["afi-safis"]=dict()
        data["openconfig-network-instance:bgp"]["global"]["afi-safis"]["afi-safi"]=list()
        data["openconfig-network-instance:bgp"]["global"]["openconfig-bgp-ext:global-defaults"]=dict()
        data_sub=dict()
        data_sub["config"]=dict()

        if user_command == "ipv4-unicast":
            data_sub["config"]["ipv4-unicast"] = True if cfgmode == 'yes' else False
        elif "local-preference" in user_command:
            if cfgmode == "yes":
                data_sub["config"]["local-preference"] = int(user_command.replace('local-preference', '').strip())
            else:
                url = st.get_datastore(dut, "rest_urls")['bgp_del_local_pref']
                if not delete_rest(dut, rest_url=url.format("default")):
                    st.error("failed to delete local-pref")

        elif user_command == "show-hostname":
            data_sub["config"]["show-hostname"] = True if cfgmode == 'yes' else False
        elif user_command == "shutdown":
            data_sub["config"]["shutdown"] = True if cfgmode == 'yes' else False
        elif "subgroup-pkt-queue-max" in user_command:
            if cfgmode == "yes":
                data_sub["config"]["subgroup-pkt-queue-max"] = int(user_command.replace("subgroup-pkt-queue-max", "").strip())
            else:
                url = st.get_datastore(dut, "rest_urls")['bgp_del_subgrp']
                if not delete_rest(dut, rest_url=url.format("default")):
                    st.error("failed to delete subgroup")
        data["openconfig-network-instance:bgp"]["global"]["openconfig-bgp-ext:global-defaults"].update(data_sub)
        url = st.get_datastore(dut,"rest_urls")['bgp_config'].format("default")
        if not config_rest(dut,rest_url=url,http_method=cli_type,json_data=data):
            st.error("bgp default router config failed")
            return False
        return True
    else:
        st.error("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
        return False



def config_bgp_always_compare_med(dut, local_asn, config='yes', cli_type=""):
    """

    :param dut:
    :param local_asn:
    :return:
    """
    cli_type = get_cfg_cli_type(dut, cli_type=cli_type)
    config_router_bgp_mode(dut, local_asn, cli_type=cli_type)

    if cli_type == "vtysh":
        if config == 'yes' :
            command = "bgp always-compare-med"
        else :
            command = "no bgp always-compare-med"
        st.config(dut, command, type=cli_type)
    elif cli_type == 'klish':
        command = list()
        if config == 'yes' :
            command.append("always-compare-med")
        else :
            command.append("no always-compare-med")
        command.append('exit')
        st.config(dut, command, type=cli_type)
    elif cli_type in ["rest-patch", "rest-put"]:
        if config == 'yes':
            url = st.get_datastore(dut, "rest_urls")["bgp_config"]
            data = {"openconfig-network-instance:bgp": {"global": {"config": {"as": int(local_asn)},
                                                                   "route-selection-options": {
                                                                       "config": {"always-compare-med": True}}}}}
            if not config_rest(dut,rest_url=url.format("default"),http_method=cli_type,json_data=data):
                st.error("failed to configure always compare med")
                return False
        else:
            url =st.get_datastore(dut,"rest_urls")["bgp_config_med"].format("default")
            if not delete_rest(dut, rest_url=url):
                st.error("no form of compare med failed")
                return False
            return True
    else:
        st.error("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
        return False
    return True


def config_bgp_deterministic_med(dut, local_asn, config='yes',cli_type=''):
    """

    :param dut:
    :param local_asn:
    :return:
    """
    cli_type = get_cfg_cli_type(dut, cli_type=cli_type)
    config_router_bgp_mode(dut, local_asn, cli_type=cli_type)
    command=""
    if cli_type == "vtysh":
        if config == 'yes' :
           command = "bgp deterministic-med"
        else :
           command = "no bgp deterministic-med"
    elif cli_type == "klish":
        command = list()
        if config == 'yes' :
           command.append("deterministic-med")
        else :
           command.append("no deterministic-med")
        command.append('exit')
    elif cli_type in ["rest-patch", "rest-put"]:
        if config == 'yes':
            url = st.get_datastore(dut, "rest_urls")["bgp_config"].format("default")
            data = {"openconfig-network-instance:bgp": {"global": {"config": {"as": int(local_asn),
                                                                              "openconfig-bgp-ext:deterministic-med": True}}}}
            if not config_rest(dut, rest_url=url, http_method=cli_type, json_data=data):
                st.error("failed to configure deterministic-med")
                return False
        else:
            url = st.get_datastore(dut, "rest_urls")["bgp_del_deter_med"].format("default")
            if not delete_rest(dut, rest_url=url):
                st.error("failed to delete deterministic-med ")
                return False
    else:
        st.error("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
        return False
    st.config(dut, command, type=cli_type)

    return True


def config_bgp_disable_ebgp_connected_route_check(dut, local_asn):
    """

    :param dut:
    :param local_asn:
    :return:
    """
    #No script usage
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
    preserve_state = kwargs.get('preserve_state',None)
    vrf = kwargs.get('vrf', "default")
    skip_error_check = kwargs.get("skip_error_check", True)
    cli_type = get_cfg_cli_type(dut, **kwargs)
    command =""
    if "local_asn" not in kwargs and "config" not in kwargs :
        st.error("Mandatory params not provided")
        return False
    if kwargs.get("config") not in ["add","delete"]:
        st.log("Unsupported ACTION")
        return False
    config_router_bgp_mode(dut, kwargs["local_asn"],vrf=vrf, cli_type=cli_type)
    mode = "no" if kwargs.get("config") != "add" else ""
    bgp_mode = "bgp" if cli_type == "vtysh" else ""
    if cli_type == 'vtysh':
        command = "{} {} graceful-restart\n".format(mode, bgp_mode)
    if cli_type == 'klish':
        command = "{} graceful-restart enable\n".format(mode)
    if preserve_state != None:
        command += "{} {} graceful-restart preserve-fw-state\n".format(mode, bgp_mode)
    if cli_type == 'klish':
        command += "exit\n"
    if cli_type in ["rest-patch","rest-put"]:
        rest_urls=st.get_datastore(dut,"rest_urls")
        data=dict()
        data["openconfig-network-instance:bgp"]=dict()
        data["openconfig-network-instance:bgp"]["global"]=dict()
        data["openconfig-network-instance:bgp"]["global"]["graceful-restart"]=dict()
        if mode !='no':
            data["openconfig-network-instance:bgp"]["global"]["graceful-restart"].update({"config": {"enabled": True}})
            if preserve_state != None:
                data["openconfig-network-instance:bgp"]["global"]["graceful-restart"].update({"config": {"openconfig-bgp-ext:preserve-fw-state": True}})
            else:
                url=rest_urls['bgp_del_graceful'].format(vrf)
                if not delete_rest(dut,rest_url=url):
                    st.error("failed unconfig graceful restart")
            url=rest_urls['bgp_config'].format(vrf)
            if not config_rest(dut,rest_url=url,http_method=cli_type,json_data=data):
                st.error("unable enable graceful restart")
                return False
            return True
        else:
            url=rest_urls['bgp_del_grace'].format(vrf)
            if not delete_rest(dut,rest_url=url):
                st.error("unable to disable graceful restart")
                return False
            return True


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
    cli_type = get_cfg_cli_type(dut, cli_type=cli_type)
    config_router_bgp_mode(dut, local_asn, cli_type=cli_type)
    mode = "no" if config != "add" else ""
    bgp_mode = "bgp" if cli_type == "vtysh" else ""
    command = "{} {} graceful-shutdown".format(mode, bgp_mode)
    st.config(dut, command, type=cli_type, skip_error_check=skip_error_check)
    if cli_type in ["rest-patch","rest-put"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        data = {"openconfig-bgp-ext:graceful-shutdown": True}
        if mode !='no':
            url=rest_urls['bgp_config_graceful_shut'].format("default")
            if not config_rest(dut,rest_url=url,http_method=cli_type,json_data=data):
                st.error("failed to config graceful shutdown")
                return False
            return True
        else:
            url=rest_urls['bgp_del_graceful_shut'].format("default")
            if not delete_rest(dut,rest_url=url):
                st.error("failed to delete graceful shutdown")
                return False
            return True


def config_bgp_listen(dut, local_asn, neighbor_address, subnet, peer_grp_name, limit, config='yes', cli_type="", skip_error_check=True):
   """

   :param dut:
   :param local_asn:
   :param neighbor_address:
   :param limit:
   :return:
   """
   cli_type = get_cfg_cli_type(dut, cli_type=cli_type)
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
           cmd.append("exit")
           st.config(dut, cmd, type=cli_type, skip_error_check=skip_error_check)
       if limit:
           command = ["{} listen limit {}".format(mode, limit)]
           command.append('exit')
           st.config(dut, command, type=cli_type, skip_error_check=skip_error_check)
   elif cli_type in ["rest-patch","rest-put"]:
       config_data = dict()
       config_data["openconfig-network-instance:bgp"] = dict()
       if neighbor_address:
           if mode != 'no':
               config_data["openconfig-network-instance:bgp"]["global"] = dict()
               config_data["openconfig-network-instance:bgp"]["global"]["config"] = dict()
               config_data["openconfig-network-instance:bgp"]["global"]["config"]["as"] = int(local_asn)
               config_data["openconfig-network-instance:bgp"]["peer-groups"] = dict()
               config_data["openconfig-network-instance:bgp"]["peer-groups"]["peer-group"] = list()
               peer_data = dict()
               peer_data.update({"peer-group-name": peer_grp_name})
               peer_data["config"] = dict()
               peer_data["config"].update({"peer-group-name": peer_grp_name})
               config_data["openconfig-network-instance:bgp"]["peer-groups"]["peer-group"].append(peer_data)
               config_data["openconfig-network-instance:bgp"]["global"]["dynamic-neighbor-prefixes"] = dict()
               config_data["openconfig-network-instance:bgp"]["global"]["dynamic-neighbor-prefixes"][
                   "dynamic-neighbor-prefix"] = list()
               prefix_data = dict()
               prefix_data.update({"prefix": "{}/{}".format(neighbor_address, subnet)})
               prefix_data["config"] = dict()
               prefix_data["config"].update(
                   {"prefix": "{}/{}".format(neighbor_address, subnet), "peer-group": peer_grp_name})
               config_data["openconfig-network-instance:bgp"]["global"]["dynamic-neighbor-prefixes"][
                   "dynamic-neighbor-prefix"].append(prefix_data)
               url=st.get_datastore(dut,"rest_urls")['bgp_config'].format("default")
               if not config_rest(dut,rest_url=url,http_method=cli_type,json_data=config_data):
                   st.error("unable to config bgp listen")

           else:

               url = st.get_datastore(dut, "rest_urls")['bgp_del_dyn'].format("default")
               if not delete_rest(dut, rest_url=url):
                   st.error("unable to delete BGP listen config")

       if limit:
           if mode != 'no':
               config_data = {"openconfig-network-instance:max-dynamic-neighbors": limit}
               url = st.get_datastore(dut,"rest_urls")['bgp_config_dyn'].format("default")
               response = config_rest(dut,rest_url=url,http_method=cli_type,json_data=config_data)

           else:
               url=st.get_datastore(dut,"rest_urls")['bgp_del_dyn'].format("default")
               response = delete_rest(dut,rest_url=url)

           if not response:
               st.log(response)
               return False
           return True


   else:
       st.error("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
       return False

def config_bgp_listen_range(dut,local_asn,**kwargs):
    """

    :param dut:
    :param local_asn:
    :param neighbor_address:
    :param limit:
    :return:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    #cli_type = _get_cli_type(cli_type)
    neighbor_address = kwargs.get('neighbor_address', '')
    subnet = str(kwargs.get('subnet', ''))
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
        st.config(dut, cmd, type= 'vtysh', skip_error_check=skip_error_check)
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
    elif cli_type in ['rest-patch','rest-put']:
        http_method = kwargs.pop('http_method',cli_type)
        rest_urls = st.get_datastore(dut,'rest_urls')
        if neighbor_address:
            dynamic_prefix = neighbor_address+'/'+subnet
            if mode == '':
                rest_url = rest_urls['bgp_dynamic_neigh_prefix'].format(vrf)
                ocdata = {"openconfig-network-instance:dynamic-neighbor-prefixes":{"dynamic-neighbor-prefix":[{"prefix": dynamic_prefix,"config":{"prefix": dynamic_prefix,"peer-group": peer_grp_name}}]}}
                response = config_rest(dut, http_method=http_method, rest_url=rest_url, json_data=ocdata)
            elif mode == 'no':
                rest_url = rest_urls['bgp_dynamic_neigh_prefix'].format(vrf)
                response = delete_rest(dut, rest_url=rest_url)
        if limit:
            if mode == '':
                rest_url = rest_urls['bgp_max_dynamic_neighbors'].format(vrf)
                ocdata = {"openconfig-bgp-ext:max-dynamic-neighbors":int(limit)}
                response = config_rest(dut, http_method=http_method, rest_url=rest_url, json_data=ocdata)
            elif mode == 'no':
                rest_url = rest_urls['bgp_max_dynamic_neighbors'].format(vrf)
                response = delete_rest(dut, rest_url=rest_url)
        if not response:
            st.log(response)
            return False
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
    #No script usage
    config_router_bgp_mode(dut, local_asn)
    command = "bgp log-neighbor-changes"
    st.config(dut, command, type='vtysh')


def config_bgp_max_med(dut, local_asn, config='yes',**kwargs):
    """

    :param dut:
    :param local_asn:
    :param user_command:
    :return:
    :usage: config_bgp_max_med(dut=dut7,cli_type='klish',config="yes",local_asn="300", on_start_time=10,on_start_med=40,administrative_med=65)
    :usage: config_bgp_max_med(dut=dut7,cli_type='click',config="no",local_asn="300",administrative_med=65)
    """
    cli_type = get_cfg_cli_type(dut, **kwargs)

    command = ''

    if cli_type == 'vtysh' :
        config_router_bgp_mode(dut, local_asn, cli_type=cli_type)
        if config == 'yes' :
            if 'on_start_time' in kwargs and 'on_start_med' in kwargs:
                 command += "bgp max-med on-startup {} {}\n".format(kwargs['on_start_time'],kwargs['on_start_med'])
            elif 'on_start_time' in kwargs:
                 command += "bgp max-med on-startup {}\n".format(kwargs['on_start_time'])
            if 'administrative_med' in kwargs:
                 command += "bgp max-med administrative {}\n".format(kwargs['administrative_med'])
        else :
            if 'on_start_time' in kwargs and 'on_start_med' in kwargs:
                 command += "no bgp max-med on-startup {} {}\n".format(kwargs['on_start_time'],kwargs['on_start_med'])
            elif 'on_start_time' in kwargs:
                 command += "no bgp max-med on-startup {}\n".format(kwargs['on_start_time'])
            if 'administrative_med' in kwargs:
                 command += "no bgp max-med administrative {}\n".format(kwargs['administrative_med'])
        command += 'exit\n'
        st.config(dut, command.split("\n"),  type=cli_type)
    elif cli_type == 'klish':
        config_router_bgp_mode(dut, local_asn,cli_type=cli_type)
        if config == 'yes' :
            if 'on_start_time' and 'on_start_med' in kwargs:
                 command += "max-med on-startup {} {}\n".format(kwargs['on_start_time'],kwargs['on_start_med'])
            elif 'on_start_time' in kwargs:
                 command += "max-med on-startup {}\n".format(kwargs['on_start_time'])
            if 'administrative_med' in kwargs:
                 command += "max-med administrative {}\n".format(kwargs['administrative_med'])
        else :
            if 'on_start_time' in kwargs and 'on_start_med' in kwargs:
                 command += "no max-med on-startup {} {}\n".format(kwargs['on_start_time'],kwargs['on_start_med'])
            elif 'on_start_time' in kwargs:
                 command += "no max-med on-startup {}\n".format(kwargs['on_start_time'])
            if 'administrative_med' in kwargs:
                 command += "no max-med administrative {}\n".format(kwargs['administrative_med'])
        command += 'exit\n'
        st.config(dut, command.split("\n"),  type=cli_type)

    elif cli_type in ["rest-patch", "rest-put"]:
        config_router_bgp_mode(dut, local_asn, cli_type=cli_type)
        data = dict()
        if config == 'yes':
            if 'on_start_time' and 'on_start_med' in kwargs:
                data.update({"max-med-val": kwargs['on_start_time'], "time":kwargs['on_start_med']})
            elif 'on_start_time' in kwargs:
                data.update({"max-med-val": kwargs['on_start_time']})
            if 'administrative_med' in kwargs:
                data.update({"administrative": kwargs['administrative_med']})
            url = st.get_datastore(dut,"rest_urls")['bgp_config'].format("default")
            if not config_rest(dut,rest_url=url,http_method=cli_type,json_data=data):
                st.error("failed to confgi max med")
                return False
            return True

        else:
            if 'on_start_time' in kwargs and 'on_start_med' in kwargs:
                url = st.get_datastore(dut,"rest_urls")['bgp_del_med'].format("default")
                if not delete_rest(dut,rest_url=url):
                    st.error("failed to delete med on start time")
                    return False
            elif 'on_start_time' in kwargs:
                url = st.get_datastore(dut, "rest_urls")['bgp_del_med'].format("default")
                if not delete_rest(dut, rest_url=url):
                    st.error("failed to delete med on start time")
                    return False
            if 'administrative_med' in kwargs:
                url = st.get_datastore(dut,"rest_urls")['bgp_del_med_ad'].format("default")
                if not delete_rest(dut,rest_url=url):
                    st.error("failed to delete med on start time")
                    return False
                return True
    else:
        st.log("Unsupported CLI TYPE - {}".format(cli_type))
        return False
    return True



def config_route_map_delay_timer(dut, local_asn, timer):
    """

    :param dut:
    :param local_asn:
    :param timer:
    :return:
    """
    # No script usage
    config_router_bgp_mode(dut, local_asn)
    command = "bgp route-map delay-timer {}".format(timer)
    st.config(dut, command, type='vtysh')


def enable_address_family_mode(dut, local_asn, mode_type, mode,cli_type=''):
    """

    :param dut:
    :param local_asn:
    :param mode_type:
    :param mode:
    :return:
    """
    cli_type = get_cfg_cli_type(dut, cli_type=cli_type)
    config_router_bgp_mode(dut, local_asn, cli_type=cli_type)
    command = "address-family {} {}".format(mode_type, mode)
    st.config(dut, command, type=cli_type)


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
    #No script usage
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
    cli_type = get_cfg_cli_type(dut, **kwargs)
    neighbor_ip = kwargs.get('neighbor_ip',None)
    ebgp_multihop = kwargs.get('ebgp_multihop',None)
    update_src = kwargs.get('update_src',None)
    update_src_intf = kwargs.get('update_src_intf',None)
    connect = kwargs.get('connect', None)
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
        if connect != None:
            cmd = cmd + 'neighbor {} timers connect {}\n'.format(peer_grp_name, connect)
        if ebgp_multihop != None:
            cmd = cmd + 'neighbor {} ebgp-multihop {}\n'.format(peer_grp_name, ebgp_multihop)
        if update_src != None:
            cmd = cmd + 'neighbor {} update-source {}\n'.format(peer_grp_name, update_src)
        if update_src_intf != None:
            cmd = cmd + 'neighbor {} update-source {}\n'.format(peer_grp_name, update_src_intf)
        if neighbor_ip != None:
            cmd = cmd + 'neighbor {} peer-group {}\n'.format(neighbor_ip, peer_grp_name)
        st.config(dut, cmd, type='vtysh', skip_error_check=skip_error_check)
        return True
    elif cli_type == "klish":
        neigh_name = get_interface_number_from_name(neighbor_ip)
        if vrf != 'default':
            cmd = cmd + 'router bgp {} vrf {}\n'.format(local_asn, vrf)
        else:
            cmd = cmd + 'router bgp {}\n'.format(local_asn)
        cmd = cmd + "peer-group {}\n".format(peer_grp_name)
        if neighbor_ip != None:
            cmd = cmd + "exit\n"
            if neigh_name:
                if isinstance(neigh_name, dict):
                    cmd = cmd + 'neighbor interface {} {}\n'.format(neigh_name["type"], neigh_name["number"])
                else:
                    cmd = cmd + 'neighbor {}\n'.format(neigh_name)
            cmd = cmd + "peer-group {}\n".format(peer_grp_name)
        if connect != None:
            cmd = cmd + 'timers connect {}\n'.format(connect)
        if ebgp_multihop != None:
            cmd = cmd + 'ebgp-multihop {}\n'.format(ebgp_multihop)
        if update_src != None:
            cmd = cmd + 'update-source {}\n'.format(update_src)
        if update_src_intf != None:
            update_src_intf = get_interface_number_from_name(update_src_intf)
            if isinstance(update_src_intf, dict):
                cmd = cmd + 'update-source interface {} {}'.format(update_src_intf['type'],update_src_intf['number'])
        cmd = cmd + "remote-as {}\n".format(remote_asn)
        cmd = cmd + "address-family {} unicast\n".format(family)
        cmd = cmd + "activate\n"
        cmd = cmd + "timers {} {}\n".format(keep_alive, hold)
        cmd = cmd + "exit\n"
        cmd = cmd + "exit\n"
        cmd = cmd + "exit\n"
        st.config(dut, cmd, type=cli_type, skip_error_check=skip_error_check, conf = True)
        return True
    elif cli_type in ['rest-patch','rest-put']:
        http_method = kwargs.pop('http_method',cli_type)
        rest_urls = st.get_datastore(dut,'rest_urls')
        rest_url_peergroup = rest_urls['bgp_peergroup_config'].format(vrf)
        rest_url_neighbor = rest_urls['bgp_neighbor_config'].format(vrf)
        if peer_grp_name != None:
            ocdata = {"openconfig-network-instance:peer-groups":{"peer-group":[{"peer-group-name":peer_grp_name,"config":{"peer-group-name":peer_grp_name,"local-as":int(local_asn)}}]}}
            response = config_rest(dut, http_method=http_method, rest_url=rest_url_peergroup, json_data=ocdata)
            if not response:
                st.log('Peergroup config failed')
                st.log(response)
                return False
        if neighbor_ip != None:
            ocdata = {'openconfig-network-instance:neighbors':{"neighbor":[{'neighbor-address':neighbor_ip,'config':{'neighbor-address':neighbor_ip,'peer-group':peer_grp_name,'enabled': bool(1)}}]}}
            response = config_rest(dut, http_method=http_method, rest_url=rest_url_neighbor, json_data=ocdata)
            if not response:
                st.log('Peergroup config with Neighbor IP failed')
                st.log(response)
                return False
        if remote_asn != None:
            if str(remote_asn).isdigit():
                ocdata = {"openconfig-network-instance:peer-groups":{"peer-group":[{"peer-group-name":peer_grp_name,"config":{"peer-as":int(remote_asn)}}]}}
            else:
                if remote_asn == "internal":
                    peer_type = "INTERNAL"
                else:
                    peer_type = "EXTERNAL"
                ocdata = {"openconfig-network-instance:peer-groups":{"peer-group": [{"peer-group-name": peer_grp_name, "config": {"peer-type": peer_type}}]}}
            response = config_rest(dut, http_method=http_method, rest_url=rest_url_peergroup, json_data=ocdata)
            if not response:
                st.log('Remote-as config in the Peergroup failed')
                st.log(response)
                return False
        if family != None:
            if family == 'ipv4':
                ocdata = {"openconfig-network-instance:peer-groups":{"peer-group":[{"peer-group-name":peer_grp_name,"afi-safis":{"afi-safi":[{"afi-safi-name":"IPV4_UNICAST","config":{"afi-safi-name":"IPV4_UNICAST","enabled": bool(1)}}]}}]}}
            elif family == 'ipv6':
                ocdata = {"openconfig-network-instance:peer-groups":{"peer-group":[{"peer-group-name":peer_grp_name,"afi-safis":{"afi-safi":[{"afi-safi-name":"IPV6_UNICAST","config":{"afi-safi-name":"IPV6_UNICAST","enabled": bool(1)}}]}}]}}
            response = config_rest(dut, http_method=http_method, rest_url=rest_url_peergroup, json_data=ocdata)
            if not response:
                st.log('Address family activation in the Peergroup failed')
                st.log(response)
                return False
        if keep_alive != None:
            ocdata = {"openconfig-network-instance:peer-groups":{"peer-group":[{"peer-group-name":peer_grp_name,"timers":{"config":{"hold-time":str(hold),"keepalive-interval":str(keep_alive)}}}]}}
            response = config_rest(dut, http_method=http_method, rest_url=rest_url_peergroup, json_data=ocdata)
            if not response:
                st.log('Keepalive and Hold timer config in the Peergroup failed')
                st.log(response)
                return False
        if ebgp_multihop != None:
            ocdata = {"openconfig-network-instance:peer-groups":{"peer-group":[{"peer-group-name":peer_grp_name,"ebgp-multihop":{"config":{"enabled":bool(1),"multihop-ttl":int(ebgp_multihop)}}}]}}
            response = config_rest(dut, http_method=http_method, rest_url=rest_url_peergroup, json_data=ocdata)
            if not response:
                st.log('EBGP multihop config in the peergroup failed')
                st.log(response)
                return False
        if update_src != None:
            ocdata = {"openconfig-network-instance:peer-groups":{"peer-group":[{"peer-group-name":peer_grp_name,"transport":{"config":{"local-address":update_src}}}]}}
            response = config_rest(dut, http_method=http_method, rest_url=rest_url_peergroup, json_data=ocdata)
            if not response:
                st.log('BGP update source config in the peergroup failed')
                st.log(response)
                return False
        if update_src_intf != None:
            ocdata = {"openconfig-network-instance:peer-groups":{"peer-group":[{"peer-group-name":peer_grp_name,"transport":{"config":{"local-address":update_src_intf}}}]}}
            response = config_rest(dut, http_method=http_method, rest_url=rest_url_peergroup, json_data=ocdata)
            if not response:
                st.log('BGP update source interface config in the peergroup failed')
                st.log(response)
                return False
        if connect != None:
            ocdata = {"openconfig-network-instance:peer-groups":{"peer-group":[{"peer-group-name":peer_grp_name,"timers":{"config":{"connect-retry":str(connect)}}}]}}
            response = config_rest(dut, http_method=http_method, rest_url=rest_url_peergroup, json_data=ocdata)
            if not response:
                st.log('BGP update source interface config in the peergroup failed')
                st.log(response)
                return False
        return True
    else:
        st.log("Unsupported CLI TYPE - {}".format(cli_type))
        return False


def remove_bgp_peergroup(dut, local_asn, peer_grp_name, remote_asn, vrf='default',**kwargs):
    """

    :param dut:
    :param local_asn:
    :param peer_grp_name:
    :param remote_asn:
    :return:
    """
    cli_type = get_cfg_cli_type(dut, **kwargs)
    cmd = ''
    neighbor_ip = kwargs.get('neighbor_ip',None)
    st.log("Removing BGP peer-group ..")
    if cli_type == 'vtysh' or cli_type == 'click':
        # Add validation for IPV4 / IPV6 address
        config_router_bgp_mode(dut, local_asn,vrf=vrf)
        command = "no neighbor {} remote-as {}".format(peer_grp_name, remote_asn)
        st.config(dut, command, type='vtysh')
        command = "no neighbor {} peer-group".format(peer_grp_name)
        st.config(dut, command, type='vtysh')
    elif cli_type == 'klish':
        neigh_name = get_interface_number_from_name(neighbor_ip)
        if vrf.lower() != 'default':
            cmd = cmd + "router bgp {} vrf {}\n".format(local_asn, vrf)
        else:
            cmd = cmd + "router bgp {}\n".format(local_asn)
        if neighbor_ip != None:
            if neigh_name:
                if isinstance(neigh_name, dict):
                    cmd = cmd + 'neighbor interface {} {}\n'.format(neigh_name["type"], neigh_name["number"])
                else:
                    cmd = cmd + 'neighbor {}\n'.format(neigh_name)
            cmd = cmd + "no peer-group {}\n".format(peer_grp_name)
            cmd = cmd + "exit\n"
            cmd = cmd + "no peer-group {}\n".format(peer_grp_name)
            cmd = cmd + "exit\n"
        st.config(dut, cmd, type='klish')
    else:
        st.error("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
        return False

def config_bgp_peer_group(dut, local_asn, peer_grp_name, config="yes", vrf="default", cli_type="'", skip_error_check=True):
    cli_type = get_cfg_cli_type(dut, cli_type=cli_type)
    config_router_bgp_mode(dut, local_asn, vrf=vrf, cli_type=cli_type)
    no_form = "" if config == "yes" else "no"
    if cli_type == "klish":
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
        st.log("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
        return False

def create_bgp_neighbor_use_peergroup(dut, local_asn, peer_grp_name, neighbor_ip, family="ipv4", vrf='default', cli_type="", skip_error_check=True):
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
    cli_type = get_cfg_cli_type(dut, cli_type=cli_type)
    # Add validation for IPV4 / IPV6 address
    config_router_bgp_mode(dut, local_asn, vrf=vrf, cli_type=cli_type)
    if cli_type == "vtysh":
        command = "neighbor {} peer-group {}".format(neighbor_ip, peer_grp_name)
        st.config(dut, command, type='vtysh')
        # Gather the IP type using the validation result
        if family == "ipv6":
            command = "address-family ipv6 unicast"
            st.config(dut, command, type=cli_type)
            command = "neighbor {} activate".format(neighbor_ip)
            st.config(dut, command, type=cli_type)
    elif cli_type == "klish":
        commands = list()
        commands.append("peer-group {}".format(peer_grp_name))
        commands.append("address-family {} unicast".format(family))
        commands.append("activate")
        commands.append("exit")
        if family == "ipv6":
            commands.append("address-family ipv4 unicast")
            commands.append("activate")
            commands.append("exit")
        commands.append("exit")
        commands.append("neighbor {}".format(neighbor_ip))
        commands.append("peer-group {}".format(peer_grp_name))
        commands.append("exit")
        commands.append("exit")
        st.config(dut, commands, type=cli_type, skip_error_check=skip_error_check)
    elif cli_type in ["rest-patch","rest_put"]:
        if family == "ipv4":
            afi_safi_name = "openconfig-bgp-types:IPV4_UNICAST"
        elif family == "l2vpn":
            afi_safi_name = "L2VPN_EVPN"
        else:
            afi_safi_name = "openconfig-bgp-types:IPV6_UNICAST"

        data = dict()
        data["openconfig-network-instance:bgp"] = dict()
        data["openconfig-network-instance:bgp"]["global"] = dict()
        data["openconfig-network-instance:bgp"]["global"]["config"] = dict()
        data["openconfig-network-instance:bgp"]["global"]["config"]["as"] = int(local_asn)
        data["openconfig-network-instance:bgp"]["peer-groups"] = dict()
        data["openconfig-network-instance:bgp"]["peer-groups"]["peer-group"] = list()
        peer_data = dict()
        peer_data.update({"peer-group-name": peer_grp_name})
        peer_data["config"] = dict()
        peer_data["config"].update({"peer-group-name": peer_grp_name})
        data["openconfig-network-instance:bgp"]["peer-groups"]["peer-group"].append(peer_data)
        peer_data["afi-safis"] = dict()
        peer_data["afi-safis"]["afi-safi"] = list()
        peer_sub = dict()
        peer_sub.update({"afi-safi-name": afi_safi_name})
        peer_sub["config"] = dict()
        peer_sub["config"].update({"afi-safi-name": afi_safi_name, "enabled": True})
        peer_data["afi-safis"]["afi-safi"].append(peer_sub)
        data["openconfig-network-instance:bgp"]["neighbors"] = dict()
        data["openconfig-network-instance:bgp"]["neighbors"]["neighbor"] = list()
        if family == "ipv6":
            afi_safi_name = "openconfig-bgp-types:IPV4_UNICAST"
            peer_sub.update({"afi-safi-name": afi_safi_name})
            peer_sub["config"].update({"afi-safi-name": afi_safi_name, "enabled": True})
        neigh_data = dict()
        neigh_data.update({"neighbor-address": neighbor_ip})
        neigh_data["config"] = dict()
        neigh_data["config"].update({"neighbor-address": neighbor_ip, "peer-group": peer_grp_name})
        data["openconfig-network-instance:bgp"]["neighbors"]["neighbor"].append(neigh_data)
        url = st.get_datastore(dut,"rest_urls")['bgp_config'].format(vrf)
        if not config_rest(dut,rest_url=url,http_method=cli_type,json_data=data):
            st.error("failed to config peer group")
            return False
        return True

    else:
        st.log("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
        return False

def create_bgp_neighbor_interface(dut, local_asn, interface_name, remote_asn,family,config='yes', cli_type=""):
    """

    :param dut:
    :param local_asn:
    :param interface_name:
    :param remote_asn:
    :param family:
    :param cli_type:
    :return:
    """
    cli_type = get_cfg_cli_type(dut, cli_type=cli_type)
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
            ###Added
            commands.append("exit")
        else:
            commands.append("exit")
    elif cli_type in ["rest-patch","rest-put"]:
        if family == "ipv4":
            afi_safi_data = "openconfig-bgp-types:IPV4_UNICAST"
        elif family == "l2vpn":
            afi_safi_data = "L2VPN_EVPN"
        else:
            afi_safi_data = "openconfig-bgp-types:IPV6_UNICAST"

        data = dict()
        data["openconfig-network-instance:bgp"] = dict()
        data["openconfig-network-instance:bgp"]["global"] = dict()
        data["openconfig-network-instance:bgp"]["global"]["config"] = dict()
        data["openconfig-network-instance:bgp"]["global"]["config"]["as"] = int(local_asn)
        data["openconfig-network-instance:bgp"]["neighbors"] = dict()
        data["openconfig-network-instance:bgp"]["neighbors"]["neighbor"] = list()
        neigh_data = dict()
        neigh_data.update({"neighbor-address": interface_name})
        neigh_data["config"] = dict()
        if str(remote_asn).isdigit():
            neigh_data["config"].update({"neighbor-address": interface_name, "peer-as": int(remote_asn)})
        else:
            if remote_asn == "internal":
                peer_type = "INTERNAL"
            else:
                peer_type = "EXTERNAL"
            neigh_data["config"].update({"neighbor-address": interface_name, "peer-type": peer_type})

        if mode == "":
            neigh_data_sub = dict()
            neigh_data_sub["afi-safis"] = dict()
            neigh_data_sub["afi-safis"]["afi-safi"] = list()
            neigh_data_sub_data = dict()
            neigh_data_sub_data["config"] = dict()
            neigh_data_sub_data.update({"afi-safi-name": afi_safi_data})
            neigh_data_sub_data["config"].update({"afi-safi-name": afi_safi_data, "enabled": True})
            neigh_data_sub["afi-safis"]["afi-safi"].append(neigh_data_sub_data)
            neigh_data.update(neigh_data_sub)
            data["openconfig-network-instance:bgp"]["neighbors"]["neighbor"].append(neigh_data)
            url = st.get_datastore(dut,"rest_urls")['bgp_config'].format("default")
            if not config_rest(dut,rest_url=url,http_method=cli_type,json_data=data):
                st.error("failed to config bgp neighbor")
                return False
            return True
        else:
            neigh_data_sub = dict()
            neigh_data_sub["afi-safis"] = dict()
            neigh_data_sub["afi-safis"]["afi-safi"] = list()
            neigh_data_sub_data = dict()
            neigh_data_sub_data["config"] = dict()
            neigh_data_sub_data.update({"afi-safi-name": afi_safi_data})
            neigh_data_sub_data["config"].update({"afi-safi-name": afi_safi_data, "enabled": False})
            neigh_data_sub["afi-safis"]["afi-safi"].append(neigh_data_sub_data)
            neigh_data.update(neigh_data_sub)
            data["openconfig-network-instance:bgp"]["neighbors"]["neighbor"].append(neigh_data)
            url = st.get_datastore(dut, "rest_urls")['bgp_neighbor_config'].format("default")
            if not config_rest(dut, rest_url=url,http_method=cli_type,json_data=data):
                st.error("failed to un-config bgp neighbor activate")
                return False
            return True
    else:
        st.log("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
        return False
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

    cli_type = get_cfg_cli_type(dut, **kwargs)

    if 'local_asn' not in kwargs or 'peer_grp_name' not in kwargs or 'remote_asn' not in kwargs \
            or 'neigh_ip_list' not in kwargs:
        st.error("Mandatory parameters are missing.")
        return False

    af = kwargs.get('family', 'ipv4')
    vrf = kwargs.get('vrf', 'default')

    neigh_ip_li = list(kwargs['neigh_ip_list']) if isinstance(kwargs['neigh_ip_list'], list) else \
        [kwargs['neigh_ip_list']]

    config_router_bgp_mode(dut, kwargs['local_asn'], vrf=vrf)

    if cli_type == 'vtysh':
        command = "no bgp default ipv4-unicast \n"
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
    elif cli_type == 'klish':
        cmd = "peer-group {} \n".format(kwargs['peer_grp_name'])
        cmd += "remote-as {} \n".format(kwargs['remote_asn'])
        if 'keep_alive' in kwargs and 'hold' in kwargs:
            cmd += "timers {} {} \n".format(kwargs['keep_alive'], kwargs['hold'])
        if 'password' in kwargs:
            cmd += 'password {} \n'.format(kwargs['password'])
        if 'activate' in kwargs:
            cmd += "address-family {} unicast \n".format(af)
            cmd += "activate \n"
            if 'redistribute' in kwargs:
                redis_li = list(kwargs['redistribute']) if isinstance(kwargs['redistribute'], list) else [kwargs['redistribute']]
                for each_ in redis_li:
                    cmd += "redistribute {} \n".format(each_)
            if 'routemap' in kwargs:
                if 'routemap_dir' in kwargs:
                    cmd += "route-map {} {} \n".format(kwargs['routemap'], kwargs['routemap_dir'])
                else:
                    cmd += "route-map {} in \n".format(kwargs['routemap'])
            cmd += "exit \n"
        for each_neigh in neigh_ip_li:
            cmd += 'exit \n'
            cmd += 'neighbor {} \n'.format(each_neigh)
            cmd += 'peer-group {} \n'.format(kwargs['peer_grp_name'])
        cmd += 'exit \n'
        cmd += 'exit \n'
        st.config(dut, cmd, type='klish')
    elif cli_type in ["rest-patch","rest-put"]:
        family = kwargs.get('family', None)
        local_asn = kwargs.get('local_asn', None)

        peergroup = kwargs.get('peer_grp_name', '')
        #remote_as = kwargs.get('remote_asn', None)
        keepalive = kwargs.get('keep_alive', "60")
        holdtime = kwargs.get('hold', "180")
        password = kwargs.get('password', None)
        redistribute = kwargs.get('redistribute', None)
        vrf_name = kwargs.get('vrf', "default")
        routeMap = kwargs.get('routemap', None)
        remote_as = kwargs.get('remote_asn', None)
        config = kwargs.get('config', "yes")
        config_cmd = "" if config.lower() == 'yes' else "no"
        if family == "ipv4":
            afi_safi_name = "openconfig-bgp-types:IPV4_UNICAST"
        elif family == "l2vpn":
            afi_safi_name = "L2VPN_EVPN"
        else:
            afi_safi_name = "openconfig-bgp-types:IPV6_UNICAST"
        data = dict()

        data["openconfig-network-instance:bgp"] = dict()
        data["openconfig-network-instance:bgp"]["global"] = dict()
        data["openconfig-network-instance:bgp"]["global"]["config"] = dict()
        data["openconfig-network-instance:bgp"]["global"]["config"]["as"] = int(local_asn)

        data["openconfig-network-instance:bgp"]["neighbors"] = dict()
        data["openconfig-network-instance:bgp"]["neighbors"]["neighbor"] = list()
        data["openconfig-network-instance:bgp"]["peer-groups"] = dict()
        data["openconfig-network-instance:bgp"]["peer-groups"]["peer-group"] = list()

        peer_data = dict()
        peer_data.update({"peer-group-name": peergroup})
        peer_data["config"] = dict()
        if str(remote_as).isdigit():
            peer_data["config"].update({"peer-group-name": peergroup, "peer-as": int(remote_as)})
        else:
            if remote_as == "internal":
                peer_type = "INTERNAL"
            else:
                peer_type = "EXTERNAL"
            peer_data["config"].update({"peer-group-name": peergroup, "peer-type": peer_type})

        peer_data["afi-safis"] = dict()
        peer_data["afi-safis"]["afi-safi"] = list()
        peer_sub = dict()

        if 'keep_alive' in kwargs and 'hold' in kwargs:
            peer_data["timers"]=dict()
            peer_data["timers"]["config"] = dict()
            peer_data["timers"]["config"].update({"hold-time": str(holdtime), "keepalive-interval": str(keepalive)})

        if 'password' in kwargs:
            peer_data["openconfig-bgp-ext:auth-password"] = dict()
            peer_data["openconfig-bgp-ext:auth-password"]["config"] = dict()
            peer_data["openconfig-bgp-ext:auth-password"]["config"].update({"password": password})
        if 'activate' in kwargs:
            peer_sub.update(
                {"afi-safi-name": afi_safi_name, "config": {"afi-safi-name": afi_safi_name, "enabled": True}})

            open_data = dict()
            open_data["openconfig-network-instance:table-connections"] = dict()
            open_data["openconfig-network-instance:table-connections"]["table-connection"] = list()
            if 'redistribute' in kwargs:
                sub_data = dict()
                redis_li = list(kwargs['redistribute']) if isinstance(kwargs['redistribute'], list) else [
                    kwargs['redistribute']]
                for each in redis_li:
                    if each == 'connected':

                        sub_data["config"] = dict()

                        redist_type = 'DIRECTLY_CONNECTED'
                        if config_cmd != 'no':
                            sub_data.update(
                                {"dst-protocol": "BGP", "address-family": family.upper(), "src-protocol": redist_type})
                            sub_data["config"].update(
                                {"dst-protocol": "BGP", "address-family": family.upper(), "src-protocol": redist_type})
                        else:
                            url = st.get_datastore(dut, "rest_urls")['bgp_del_redist_connected']
                            url = url.format(vrf_name, redist_type)
                            if not delete_rest(dut, rest_url=url):
                                st.error("failed to do unconfig redistribute connected")


                    elif each == 'static':

                        sub_data["config"] = dict()

                        if config_cmd != 'no':
                            sub_data.update(
                                {"dst-protocol": "BGP", "address-family": family.upper(),
                                 "src-protocol": each.upper()})
                            sub_data["config"].update(
                                {"dst-protocol": "BGP", "address-family": family.upper(),
                                 "src-protocol": each.upper()})

                        else:
                            url = st.get_datastore(dut, "rest_urls")['bgp_del_redist_static']
                            url = url.format(vrf_name, each.upper())
                            if not delete_rest(dut, rest_url=url):
                                st.error("failed to do unconfig redistribute connected")


                    elif each == 'ospf':

                        sub_data["config"] = dict()

                        if config_cmd != 'no':
                            sub_data.update(
                                {"dst-protocol": "BGP", "address-family": family.upper(),
                                 "src-protocol": each.upper()})
                            sub_data["config"].update(
                                {"dst-protocol": "BGP", "address-family": family.upper(),
                                 "src-protocol": each.upper()})
                        else:
                            url = st.get_datastore(dut, "rest_urls")['bgp_del_redist_ospf']
                            url = url.format(vrf_name, redistribute.upper())
                            if not delete_rest(dut, rest_url=url):
                                st.error("failed to do unconfig redistribute connected")



                    else:
                        st.error("unsupported redistribute value")
                    if sub_data:
                        open_data["openconfig-network-instance:table-connections"]["table-connection"].append(sub_data)


            if 'routemap' in kwargs:
                if 'routemap_dir' in kwargs:
                    if kwargs['routemap_dir'] == "out":
                        peer_sub.update(
                            {"apply-policy": {
                                "config": {"export-policy": [routeMap], "default-export-policy": "REJECT_ROUTE"}}})
                    else:
                        peer_sub.update(
                            {"apply-policy": {
                                "config": {"import-policy": [routeMap], "default-import-policy": "REJECT_ROUTE"}}})

            for each_neigh in neigh_ip_li:
                neigh = {
                    "neighbor-address": each_neigh,
                    "config": {
                        "peer-group": peergroup,
                        "neighbor-address": each_neigh

                    },
                    "timers": {
                    "config": {
                    "connect-retry": "60"}}

                }
                data["openconfig-network-instance:bgp"]["neighbors"]["neighbor"].append(neigh)

            url = st.get_datastore(dut, "rest_urls")['bgp_config_route_map'].format(vrf_name)
            if not config_rest(dut, rest_url=url, http_method=cli_type, json_data=open_data):
                st.error("failed to config route-map")


        peer_data["afi-safis"]["afi-safi"].append(peer_sub)
        data["openconfig-network-instance:bgp"]["peer-groups"]["peer-group"].append(peer_data)

        url = st.get_datastore(dut, "rest_urls")['bgp_config'].format(vrf_name)
        if not config_rest(dut, rest_url=url, http_method=cli_type, json_data=data):
            st.error("failed configure neighbor")
            return False
        return True

    else:
        st.error("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
        return False

    return True


def verify_bgp_summary(dut, family='ipv4', shell="sonic", **kwargs):
    """

    :param dut:
    :param family:
    :param shell:
    :param kwargs:
    :return:
    """
    if shell not in ["vtysh", "klish", "rest-patch", "rest-put"]:
        if 'vrf' in kwargs and shell=='sonic':
            vrf = kwargs.pop('vrf')
            cmd = "show bgp vrf {} {} summary".format(vrf,family.lower())
        else:
            cmd = "show bgp {} summary".format(family.lower())

        if not st.is_feature_supported("show-bgp-summary-click-command", dut):
            output = st.show(dut,cmd, type="vtysh")
        else:
            output = st.show(dut,cmd)

    cli_type = get_show_cli_type(dut, **kwargs)
    if shell in ["vtysh", "klish", "rest-patch", "rest-put"]:
        vrf = kwargs.pop('vrf') if 'vrf' in kwargs else "default"
        if family.lower() == 'ipv4':
            output = show_bgp_ipv4_summary_vtysh(dut, vrf=vrf, cli_type=cli_type)
        elif family.lower() == 'ipv6':
            output = show_bgp_ipv6_summary_vtysh(dut, vrf=vrf, cli_type=cli_type)
        else:
            st.log("Invalid family {} or shell {}".format(family, cli_type))
            return False

    st.debug(output)


    # Specifically checking neighbor state
    if 'neighbor' in kwargs and 'state' in kwargs:
        neigh_li = list(kwargs['neighbor']) if isinstance(kwargs['neighbor'], list) else [kwargs['neighbor']]
        for each_neigh in neigh_li:
            #For dynamic neighbor, removing *, as it is not displayed in klish
            if shell in ['klish','rest-patch','rest-put'] or cli_type in ['klish','rest-patch','rest-put']:
                st.log('For dynamic neighbor, removing *, as it is not displayed in klish, rest-patch,rest-put')
                each_neigh = each_neigh.lstrip('*')
            match = {'neighbor': each_neigh}
            try:
                entries = filter_and_select(output, None, match)
                if not entries:
                    st.debug("Entries : {}".format(entries))
                    return False
                entries = entries[0]
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
    #No usage in scripts, so no klish support added
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
    No usage in scripts. Template needs changes for this to work
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
    No usage in scripts. Template needs changes for this to work
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
    cli_type = get_cfg_cli_type(dut, **kwargs)
    cfgmode = 'no' if config != 'yes' else ''
    route_map = kwargs.get('route_map')
    cmd = ''
    if cli_type == 'vtysh' or cli_type == 'click':
        if vrf.lower() != 'default':
            cmd = cmd + "router bgp {} vrf {}\n".format(local_asn, vrf)
        else:
            cmd = cmd + "router bgp {}\n".format(local_asn)
        cmd = cmd + "\n address-family {} {}".format(mode_type, mode)
        if route_map:
            cmd = cmd + "\n {} redistribute {} route-map {}".format(cfgmode, value, route_map)
        else:
            cmd = cmd + "\n {} redistribute {}".format(cfgmode, value)
        st.config(dut, cmd, type='vtysh', skip_error_check=skip_error_check)
        return True
    elif cli_type == "klish":
        if vrf != 'default':
            cmd = cmd + 'router bgp {} vrf {}\n'.format(local_asn, vrf)
        else:
            cmd = cmd + 'router bgp {}\n'.format(local_asn)
        cmd = cmd + 'address-family {} {}\n'.format(mode_type, mode)
        if route_map:
            cmd = cmd + "{} redistribute {} route-map {}\n".format(cfgmode, value, route_map)
        else:
            cmd = cmd + "{} redistribute {}\n".format(cfgmode, value)
        cmd = cmd + 'exit\nexit\n'
        st.config(dut, cmd, type=cli_type, skip_error_check=skip_error_check, conf = True)
        return True
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, 'rest_urls')

        #vrf_name1=""
        vrf_name1=vrf.lower()
        vrf_name1 = 'default' if vrf_name1 !=vrf.lower() else vrf_name1
        family=mode_type
        if family == "ipv4":
            afi_safi_name = "openconfig-bgp-types:IPV4_UNICAST"
        elif family == "l2vpn":
            afi_safi_name = "L2VPN_EVPN"
        else:
            afi_safi_name = "openconfig-bgp-types:IPV6_UNICAST"
        data_asn=dict()
        data_asn["openconfig-network-instance:bgp"] = dict()
        data_asn["openconfig-network-instance:bgp"]["global"] = dict()
        data_asn["openconfig-network-instance:bgp"]["global"]["config"] = dict()
        data_asn["openconfig-network-instance:bgp"]["global"]["config"]["as"] = int(local_asn)
        data_asn["openconfig-network-instance:bgp"]["global"]["afi-safis"] = dict()
        data_asn["openconfig-network-instance:bgp"]["global"]["afi-safis"]["afi-safi"] = list()
        afi_data=dict()
        afi_data["config"]=dict()
        afi_data.update({"afi-safi-name": afi_safi_name})
        afi_data["config"].update({"afi-safi-name": afi_safi_name})
        data_asn["openconfig-network-instance:bgp"]["global"]["afi-safis"]["afi-safi"].append(afi_data)
        url=rest_urls['bgp_config'].format(vrf_name1)
        if not config_rest(dut,rest_url=url,http_method=cli_type,json_data=data_asn):
            st.error("failed to config local as")
        if value:
            if value == "connected":
                redist_type = value.upper()
                if redist_type == 'CONNECTED': redist_type = 'DIRECTLY_CONNECTED'
            elif value == "static":
                redist_type = value.upper()
            elif value == "ospf":
                redist_type = value.upper()
            else:
                st.log("invalid redist type")

        if cfgmode != "no":
            if route_map:
                url = rest_urls["bgp_route_redistribute"].format(vrf_name1)
                data = { "openconfig-network-instance:table-connections": {"table-connection": [{
                        "src-protocol": redist_type,
                        "dst-protocol": "BGP",
                        "address-family": family.upper(),
                        "config": {
                            "src-protocol": redist_type,
                            "address-family": family.upper(),
                            "dst-protocol": "BGP",
                            "import-policy": [
                                route_map
                            ]}}]}, "protocols": {"protocol": [{
                        "identifier": "BGP",
                        "name": "bgp",
                        "config": {
                            "identifier": "BGP",
                            "name": "bgp",
                            "enabled": True,
                        }
                        }]}}
                if not config_rest(dut, rest_url=url, http_method=cli_type, json_data=data):
                    st.error("redistribute config failed")

            else:
                url = rest_urls["bgp_route_redistribute"].format(vrf_name1)
                data = {"openconfig-network-instance:table-connections": {"table-connection": [{
                    "src-protocol": redist_type,
                    "dst-protocol": "BGP",
                    "address-family": family.upper(),
                    "config": {
                        "src-protocol": redist_type,
                        "address-family": family.upper(),
                        "dst-protocol": "BGP"}}]}, "protocols": {"protocol": [{
                    "identifier": "BGP",
                    "name": "bgp",
                    "config": {
                        "identifier": "BGP",
                        "name": "bgp"

                    }
                }]}}
                if not config_rest(dut, rest_url=url, http_method=cli_type, json_data=data):
                    st.error("redistribute config failed")
                    return False

        else:
            url = st.get_datastore(dut,"rest_urls")['bgp_del_redist'].format(vrf_name1,redist_type,family.upper())
            if not delete_rest(dut, rest_url=url):
                st.error("redistribute delete config failed")
                return False
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
    cli_type = get_cfg_cli_type(dut, **kwargs)
    st.log('Configure BGP')
    config = kwargs.get('config', "yes")
    vrf_name = kwargs.get('vrf_name', "default")
    router_id = kwargs.get('router_id','')
    config_type_list = kwargs.get('config_type_list', None)
    neighbor = kwargs.get('neighbor', None)
    local_as = kwargs.get('local_as', None)
    remote_as = kwargs.get('remote_as', None)
    peergroup =  kwargs.get('peergroup', '')
    #pswd = kwargs.get('pswd', None)
    #activate = kwargs.get('activate', None)
    #nexthop_self = kwargs.get('nexthop_self', None)
    addr_family = kwargs.get('addr_family', 'ipv4')
    keepalive = kwargs.get('keepalive', '')
    holdtime = kwargs.get('holdtime', '')
    conf_peers = kwargs.get('conf_peers', '')
    conf_identf = kwargs.get('conf_identf', '')
    update_src = kwargs.get('update_src', None)
    update_src_intf = kwargs.get("update_src_intf", "") if "update_src_intf" in config_type_list else ""
    interface = kwargs.get('interface', None)
    connect = kwargs.get('connect', None)
    ebgp_mhop = kwargs.get('ebgp_mhop', None)
    #failover = kwargs.get('failover', None)
    shutdown = kwargs.get('shutdown', None)
    #max_path = kwargs.get('max_path', None)
    redistribute = kwargs.get('redistribute', None)
    network = kwargs.get('network', None)
    password = kwargs.get('password', None)
    max_path_ibgp = kwargs.get('max_path_ibgp', None)
    max_path_ebgp = kwargs.get('max_path_ebgp', None)
    routeMap = kwargs.get('routeMap', None)
    distribute_list = kwargs.get('distribute_list', None)
    filter_list = kwargs.get('filter_list', None)
    prefix_list = kwargs.get('prefix_list', None)
    #import_vrf = kwargs.get('import_vrf', None)
    import_vrf_name = kwargs.get('import_vrf_name', None)
    #fast_external_failover = kwargs.get('fast_external_failover', None)
    bgp_bestpath_selection = kwargs.get('bgp_bestpath_selection', None)
    removeBGP = kwargs.get('removeBGP', 'no')
    diRection = kwargs.get('diRection', 'in')
    weight = kwargs.get('weight', None)
    allowas_in = kwargs.get("allowas_in",None)
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
            elif type1 == 'update_src' or type1 == 'update_src_intf':
                if update_src != None:
                    my_cmd += '{} neighbor {} update-source {}\n'.format(config_cmd, neighbor, update_src)
                elif update_src_intf != None:
                    my_cmd += '{} neighbor {} update-source {}\n'.format(config_cmd, neighbor, update_src_intf)
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
                if 'routeMap' in kwargs:
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
                st.log('Invalid BGP config parameter: {}'.format(type1))
        output = st.config(dut, my_cmd, type=cli_type)
        if "% Configure the peer-group first" in output:
            st.error(output)
            return False
        if "% Specify remote-as or peer-group commands first" in output:
            st.error(output)
            return False
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
        if interface:
            intf_name = get_interface_number_from_name(interface)
        shutdown = kwargs.get("shutdown", None) if "shutdown" in config_type_list else None
        activate = kwargs.get("activate", None) if "activate" in config_type_list else None
        nexthop_self = kwargs.get("nexthop_self", True) if "nexthop_self" in config_type_list else None
        pswd = True if "pswd" in config_type_list else False
        update_src = kwargs.get("update_src", "") if "update_src" in config_type_list else ""
        update_src_intf = get_interface_number_from_name(update_src_intf)
        bfd = True if "bfd" in config_type_list else False
        route_map = True if "routeMap" in config_type_list else False
        default_originate = True if "default_originate" in config_type_list else False
        removePrivateAs = True if "removePrivateAs" in config_type_list else False
        no_neighbor = "no" if kwargs.get("config") == "no"  else ""
        sub_list = ["neighbor", "routeMap", "shutdown", "activate", "nexthop_self", "pswd", "update_src",
                    "bfd", "default_originate", "removePrivateAs", "no_neigh","remote-as","filter_list",
                    "prefix_list", "distribute_list", "weight", "keepalive", "holdtime", "ebgp_mhop","peergroup","update_src_intf","connect","allowas_in"]

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

        config_default_activate = True
        config_remote_as = True

        for type1 in config_type_list:
            if type1 in sub_list:
                if neigh_name and not peergroup:
                    if isinstance(neigh_name, dict):
                        my_cmd = "neighbor interface {} {}".format(neigh_name["type"],neigh_name["number"])
                    else:
                        my_cmd = "neighbor {}".format(neigh_name)
                    commands.append(my_cmd)
                if peergroup:
                    my_cmd_peer = '{} peer-group {}'.format(config_cmd, peergroup)
                    if 'peergroup' in config_type_list:
                        if isinstance(neigh_name, dict):
                            my_cmd = "{} neighbor interface {} {}".format(no_neighbor, neigh_name["type"],
                                                                          neigh_name["number"])
                        else:
                            my_cmd = "{} neighbor {}".format(no_neighbor, neigh_name)
                        if neigh_name:
                            commands.append(my_cmd)
                            commands.append(my_cmd_peer)
                            commands.append('exit')
                            neigh_name = None
                            activate = True
                    commands.append(my_cmd_peer)
                if config_remote_as and remote_as:
                    if interface and not peergroup:
                        my_cmd = "neighbor interface {} {}".format(intf_name['type'], intf_name['number'])
                        commands.append(my_cmd)
                    my_cmd = '{} remote-as {}'.format(config_cmd, remote_as)
                    commands.append(my_cmd)
                    config_remote_as = False
                if config_default_activate and (activate or neigh_name):
                    # show ip bgp summary will list
                    #       v4 neighbor only if activate is done for v4 address family
                    #       v6 neighbor only if activate is done for v4 address family
                    #       both v4 and v6 neighbor only if activate is done for both address families
                    # There is a defect for this issue - 20468
                    if config_cmd == "":
                        my_cmd = 'address-family {} unicast'.format(addr_family)
                        commands.append(my_cmd)
                        my_cmd = '{} activate'.format(config_cmd)
                        commands.append(my_cmd)
                        commands.append("exit")
                        if addr_family == "ipv6":
                            my_cmd = 'address-family ipv4 unicast'
                            commands.append(my_cmd)
                            my_cmd = '{} activate'.format(config_cmd)
                            commands.append(my_cmd)
                            commands.append("exit")
                        config_default_activate = False
                    # Avoid disable of neighbor unless config=no and config_type_list contains activate
                    elif activate and config_cmd == "no":
                        my_cmd = 'address-family {} unicast'.format(addr_family)
                        commands.append(my_cmd)
                        my_cmd = '{} activate'.format(config_cmd)
                        commands.append(my_cmd)
                        commands.append("exit")
                    activate = None
                if shutdown:
                    my_cmd = '{} shutdown'.format(config_cmd)
                    commands.append(my_cmd)
                    shutdown = None
                elif route_map:
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
                elif distribute_list:
                    my_cmd = 'address-family {} unicast'.format(addr_family)
                    commands.append(my_cmd)
                    my_cmd = '{} prefix-list {} {}\n'.format(config_cmd, distribute_list, diRection)
                    commands.append(my_cmd)
                    commands.append("exit")
                    distribute_list = None
                elif default_originate:
                    my_cmd = 'address-family {} unicast'.format(addr_family)
                    commands.append(my_cmd)
                    if 'routeMap' in kwargs:
                        my_cmd = '{} default-originate route-map {}'.format(config_cmd, routeMap)
                    else:
                        my_cmd = '{} default-originate'.format(config_cmd)
                    commands.append(my_cmd)
                    commands.append("exit")
                    default_originate = False
                elif removePrivateAs:
                    my_cmd = 'address-family {} unicast'.format(addr_family)
                    commands.append(my_cmd)
                    my_cmd = '{} remove-private-as'.format(config_cmd)
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
                    if isinstance(neigh_name, dict):
                        my_cmd = "{} neighbor interface {} {}".format(no_neighbor, neigh_name["type"], neigh_name["number"])
                    else:
                        my_cmd = "{} neighbor {}".format(no_neighbor, neigh_name)
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
                    if isinstance(neigh_name, dict):
                        my_cmd = "{} neighbor interface {} {}".format(no_neighbor, neigh_name["type"], neigh_name["number"])
                    else:
                        my_cmd = "{} neighbor {}".format(no_neighbor, neigh_name)
                    my_cmd = '{} update-source {}'.format(config_cmd, update_src)
                    commands.append(my_cmd)
                    update_src = None
                elif update_src_intf:
                    if isinstance(neigh_name, dict):
                        my_cmd = "{} neighbor interface {} {}".format(no_neighbor, neigh_name["type"], neigh_name["number"])
                    else:
                        my_cmd = "{} neighbor {}".format(no_neighbor, neigh_name)
                    if isinstance(update_src_intf, dict):
                        my_cmd = '{} update-source interface {} {}'.format(config_cmd, update_src_intf['type'],update_src_intf['number'])
                        commands.append(my_cmd)
                        update_src_intf = None
                elif ebgp_mhop:
                    if isinstance(neigh_name, dict):
                        my_cmd = "{} neighbor interface {} {}".format(no_neighbor, neigh_name["type"], neigh_name["number"])
                    else:
                        my_cmd = "{} neighbor {}".format(no_neighbor, neigh_name)
                    my_cmd = '{} ebgp-multihop {}'.format(config_cmd, ebgp_mhop)
                    commands.append(my_cmd)
                    ebgp_mhop = None
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
                elif connect:
                    my_cmd = '{} timers connect {}'.format(config_cmd, connect)
                    commands.append(my_cmd)
                    connect = None
                elif allowas_in:
                    my_cmd = 'address-family {} unicast'.format(addr_family)
                    commands.append(my_cmd)
                    my_cmd = '{} allowas-in {}'.format(config_cmd, allowas_in)
                    commands.append(my_cmd)
                    commands.append("exit")
                    allowas_in = None

                st.log('config_bgp command_list: {}'.format(commands))
                #come back to router bgp context
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
                if config_cmd == '' or config_cmd == 'yes':
                    my_cmd = '{} maximum-paths {}'.format(config_cmd, max_path_ebgp)
                else:
                    my_cmd = '{} maximum-paths'.format(config_cmd)
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
            elif type1 == 'import_vrf':
                my_cmd = 'address-family {} unicast\n'.format(addr_family)
                commands.append(my_cmd)
                my_cmd = '{} import vrf {}'.format(config_cmd, import_vrf_name)
                commands.append(my_cmd)
                commands.append("exit")
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
                st.log('Invalid BGP config parameter {}'.format(type1))
        if config_cmd == 'no' and 'neighbor' in config_type_list and neigh_name and not peergroup:
           if isinstance(neigh_name, dict):
               my_cmd = "{} neighbor interface {} {}".format(config_cmd, neigh_name["type"],neigh_name["number"])
           else:
              my_cmd = "{} neighbor {}".format(config_cmd, neigh_name)
           commands.append(my_cmd)
#           commands.append("exit")
        #go back to config terminal prompt
        if removeBGP != 'yes':
            commands.append('exit\n')
        if commands:
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
    elif cli_type in ["rest-patch", "rest-put"]:
        shutdown = kwargs.get("shutdown", None) if "shutdown" in config_type_list else None
        activate = kwargs.get("activate", None) if "activate" in config_type_list else None
        nexthop_self = kwargs.get("nexthop_self", True) if "nexthop_self" in config_type_list else None
        pswd = True if "pswd" in config_type_list else False
        update_src = kwargs.get("update_src", "") if "update_src" in config_type_list else ""
        update_src_intf = get_interface_number_from_name(update_src_intf)
        bfd = True if "bfd" in config_type_list else False
        route_map = True if "routeMap" in config_type_list else False
        default_originate = True if "default_originate" in config_type_list else False
        removePrivateAs = True if "removePrivateAs" in config_type_list else False
        no_neighbor = "no" if kwargs.get("config") == "no" else ""
        sub_list = ["neighbor", "routeMap", "shutdown", "activate", "nexthop_self", "pswd", "update_src",
                    "bfd", "default_originate", "removePrivateAs", "no_neigh", "remote-as", "filter_list",
                    "prefix_list", "distribute_list", "weight", "keepalive", "holdtime", "ebgp_mhop", "peergroup",
                    "update_src_intf", "connect","redist"]
        #bgp_data = dict()
        global_data = dict()
        neigh_data = dict()
        peer_data = dict()
        common_data = dict()

        global_data["openconfig-network-instance:bgp"] = dict()
        global_data["openconfig-network-instance:bgp"]["global"] = dict()
        global_data["openconfig-network-instance:bgp"]["global"]["config"] = dict()

        open_data = dict()
        open_data["openconfig-network-instance:table-connections"] = dict()
        open_data["openconfig-network-instance:table-connections"]["table-connection"] = list()

        neigh_data = dict()

        common_data = dict()

        open_data = dict()
        open_data["openconfig-network-instance:table-connections"] = dict()
        open_data["openconfig-network-instance:table-connections"]["table-connection"] = list()
        if neighbor:
            neigh_data = dict()
            global_data["openconfig-network-instance:bgp"]["neighbors"] = dict()
            global_data["openconfig-network-instance:bgp"]["neighbors"]["neighbor"] = list()
            neigh_data.update({"neighbor-address": neighbor})
            neigh_data["config"] = dict()
        if peergroup:
            peer_data = dict()
            global_data["openconfig-network-instance:bgp"]["peer-groups"] = dict()
            global_data["openconfig-network-instance:bgp"]["peer-groups"]["peer-group"] = list()
            peer_data.update({'peer-group-address': peergroup})
            peer_data['config'] = dict()

        family = kwargs.get('addr_family', "ipv4")
        if family == "ipv4":
            afi_safi_name = "openconfig-bgp-types:IPV4_UNICAST"
        elif addr_family == "l2vpn":
            afi_safi_name = "L2VPN_EVPN"
        else:
            afi_safi_name = "openconfig-bgp-types:IPV6_UNICAST"


        if 'local_as' in kwargs and removeBGP != 'yes':
            global_data["openconfig-network-instance:bgp"]["global"]["config"]["as"] = int(kwargs.get("local_as"))
            if router_id:
                if config_cmd != "no":
                    global_data["openconfig-network-instance:bgp"]["global"]["config"]["router-id"] = router_id
                else:
                    url=st.get_datastore(dut,"rest_urls")["bgp_del_rid"].format(vrf_name)
                    if not delete_rest(dut,rest_url=url):
                        st.error("failed to unconfig router-id")

        if peergroup:
            if config_cmd != 'no':
                peer_data.update({'peer-group-address': peergroup})

                peer_data['config'] = dict()
                peer_data["config"].update({'peer-group-address': peergroup})
            else:
                url=st.get_datastore(dut,"rest_urls")['bgp_del_peer_group'].format(vrf_name,peergroup)
                if not delete_rest(dut,rest_url=url):
                    st.error("failed to unconfig peergroup")

        config_default_activate = True
        config_remote_as = True
        neigh_data_sub = dict()

        for type1 in config_type_list:
            if type1 in sub_list:
                if neighbor and not peergroup:

                    neigh_data.update({"neighbor-address": neighbor})
                    neigh_data["config"] = dict()
                    neigh_data["config"].update({"neighbor-address": neighbor})

                if peergroup:
                    if config_cmd != 'no':
                        peer_data = dict()
                        peer_data.update({'peer-group-address': peergroup})

                        peer_data['config'] = dict()
                        peer_data["config"].update({'peer-group-address': peergroup})
                    else:
                        url = st.get_datastore(dut, "rest_urls")['bgp_del_peer_group'].format(vrf_name,peergroup)
                        if not delete_rest(dut, rest_url=url):
                            st.error("failed to delete peer group")

                    if 'peergroup' in config_type_list:

                        if activate and no_neighbor == "no":
                            url = st.get_datastore(dut, "rest_urls")['bgp_del_neighbor_config']
                            url=url.format(vrf_name, neighbor)
                            if not delete_rest(dut, rest_url=url):
                                st.error("neighbor delete is failed")

                        else:

                            neigh_data.update({"neighbor-address": neighbor})

                            neigh_data["config"].update({"neighbor-address": neighbor})

                if config_remote_as and remote_as:
                    if interface and not peergroup:

                        neigh_data.update({"neighbor-address": neighbor})
                        neigh_data["config"] = dict()
                        neigh_data["config"].update({"neighbor-address": neighbor})

                    if config_cmd != 'no':

                        neigh_data.update({"neighbor-address": neighbor})

                        if str(remote_as).isdigit(): #peer_as = remote_as else peer_type = remote_as
                            neigh_data["config"].update({"neighbor-address": neighbor, "peer-as": int(remote_as)})
                        else:
                            if remote_as == "internal":
                                peer_type= "INTERNAL"
                            else:
                                peer_type="EXTERNAL"
                            neigh_data["config"].update({"neighbor-address": neighbor, "peer-type": peer_type})

                    else:
                        url=st.get_datastore(dut,"rest_urls")['bgp_del_remote_as']
                        url=url.format(vrf_name,neighbor)
                        if not delete_rest(dut,rest_url=url):
                            st.error("failed to delete remote-as")

                    #config_remote_as = False

                if config_default_activate and (activate or neighbor):
                    if config_cmd == "":
                        family = kwargs.get('addr_family', "ipv4")
                        if family == "ipv6":
                            afi_safi_name = "openconfig-bgp-types:IPV6_UNICAST"
                        else:
                            afi_safi_name = "openconfig-bgp-types:IPV4_UNICAST"

                        common_data["afi-safis"] = dict()
                        common_data["afi-safis"]["afi-safi"] = list()
                        neigh_data_sub = dict()
                        neigh_data_sub.update({"afi-safi-name": afi_safi_name})
                        neigh_data_sub["config"] = dict()
                        neigh_data_sub["config"].update({"afi-safi-name": afi_safi_name,"enabled":True})

                        common_data["afi-safis"]["afi-safi"].append(neigh_data_sub)
                        if family == "ipv6":
                            afi_safi_name = "openconfig-bgp-types:IPV4_UNICAST"
                            neigh_data_sub1 = dict()
                            neigh_data_sub1.update({"afi-safi-name": afi_safi_name})
                            neigh_data_sub1["config"] = dict()
                            neigh_data_sub1["config"].update({"afi-safi-name": afi_safi_name, "enabled": True})
                            common_data["afi-safis"]["afi-safi"].append(neigh_data_sub1)
                    elif activate and config_cmd == "no":

                        family = kwargs.get('addr_family', 'ipv4')
                        if family != "ipv4":
                            afi_safi_name = "openconfig-bgp-types:IPV6_UNICAST"
                        else:
                            afi_safi_name = "openconfig-bgp-types:IPV4_UNICAST"
                        common_data["afi-safis"] = dict()
                        common_data["afi-safis"]["afi-safi"] = list()
                        neigh_data_sub = dict()
                        neigh_data_sub.update({"afi-safi-name": afi_safi_name})
                        neigh_data_sub["config"] = dict()
                        neigh_data_sub["config"].update({"afi-safi-name": afi_safi_name, "enabled": False})
                        common_data["afi-safis"]["afi-safi"].append(neigh_data_sub)
                #activate = None

                if shutdown:
                    common_data["config"] = dict()
                    if config_cmd != 'no':
                        common_data["config"].update({"enabled": True})
                    else:
                        common_data["config"].update({"enabled": False})
                    #shutdown = None
                elif route_map:

                    family = kwargs.get('addr_family', "ipv4")
                    if family == "ipv6":
                        afi_safi_name = "openconfig-bgp-types:IPV6_UNICAST"
                    else:
                        afi_safi_name = "openconfig-bgp-types:IPV4_UNICAST"
                    if not common_data:
                        common_data["afi-safis"] = dict()
                        common_data["afi-safis"]["afi-safi"] = list()
                    neigh_data_sub = dict()
                    neigh_data_sub.update({"afi-safi-name": afi_safi_name})
                    neigh_data_sub["config"] = dict()
                    neigh_data_sub["config"].update({"afi-safi-name": afi_safi_name})
                    neigh_data_sub["apply-policy"] = dict()
                    neigh_data_sub["apply-policy"]["config"] = dict()
                    if config_cmd != 'no':
                        if diRection == 'in':
                            neigh_data_sub["apply-policy"]["config"].update({"import-policy": [routeMap]})
                        else:
                            neigh_data_sub["apply-policy"]["config"].update({"export-policy": [routeMap]})
                    else:
                        if diRection == 'in':
                            url=st.get_datastore(dut,"rest_urls")['bgp_del_route_map_in']
                            url=url.format(vrf_name,neighbor,afi_safi_name[21:],routeMap)
                            if not delete_rest(dut,rest_url=url):
                                st.error("failed to delete route-map inboud")

                        else:
                            url = st.get_datastore(dut,"rest_urls")['bgp_del_route_map_out']
                            url = url.format(vrf_name, neighbor, afi_safi_name[21:], routeMap)
                            if not delete_rest(dut, rest_url=url):
                                st.error("failed to delete route-map outbound")

                    common_data["afi-safis"]["afi-safi"].append(neigh_data_sub)
                    #route_map = False
                elif filter_list:
                    family = kwargs.get('addr_family', "ipv4")
                    if family == "ipv6":
                        afi_safi_name = "openconfig-bgp-types:IPV6_UNICAST"
                    else:
                        afi_safi_name = "openconfig-bgp-types:IPV4_UNICAST"
                    if not common_data:
                        common_data["afi-safis"] = dict()
                        common_data["afi-safis"]["afi-safi"] = list()
                    neigh_data_sub = dict()
                    neigh_data_sub.update({"afi-safi-name": afi_safi_name})
                    neigh_data_sub["config"] = dict()
                    neigh_data_sub["config"].update({"afi-safi-name": afi_safi_name})
                    neigh_data_sub["openconfig-bgp-ext:filter-list"] = dict()
                    neigh_data_sub["openconfig-bgp-ext:filter-list"]["config"] = dict()
                    if config_cmd != 'no':
                        if diRection == 'in':
                            neigh_data_sub["openconfig-bgp-ext:filter-list"]["config"].update(
                                {"import-policy": filter_list})
                        else:
                            neigh_data_sub["openconfig-bgp-ext:filter-list"]["config"].update(
                                {"export-policy": filter_list})
                    else:
                        if diRection == 'in':
                            url = st.get_datastore(dut,"rest_urls")['bgp_del_filter_list_in']
                            url = url.format(vrf_name, neighbor, afi_safi_name[21:])
                            if not delete_rest(dut, rest_url=url):
                                st.error("failed to delete filter-list inboud")

                        else:
                            url = st.get_datastore(dut,"rest_urls")['bgp_del_filter_list_out']
                            url = url.format(vrf_name, neighbor, afi_safi_name[21:])
                            if not delete_rest(dut, rest_url=url):
                                st.error("failed to delete filter-list outbound")
                    common_data["afi-safis"]["afi-safi"].append(neigh_data_sub)
                    #filter_list = None
                elif prefix_list:
                    family = kwargs.get('addr_family', "ipv4")
                    if family == "ipv6":
                        afi_safi_name = "openconfig-bgp-types:IPV6_UNICAST"
                    else:
                        afi_safi_name = "openconfig-bgp-types:IPV4_UNICAST"
                    if not common_data:
                        common_data["afi-safis"] = dict()
                        common_data["afi-safis"]["afi-safi"] = list()

                    neigh_data_sub = dict()
                    neigh_data_sub.update({"afi-safi-name": afi_safi_name})
                    neigh_data_sub["config"] = dict()
                    neigh_data_sub["config"].update({"afi-safi-name": afi_safi_name})

                    neigh_data_sub["openconfig-bgp-ext:prefix-list"] = dict()
                    neigh_data_sub["openconfig-bgp-ext:prefix-list"]["config"] = dict()
                    if config_cmd != 'no':
                        if diRection == 'in':
                            neigh_data_sub["openconfig-bgp-ext:prefix-list"]["config"].update(
                                {"import-policy": prefix_list})
                        else:
                            neigh_data_sub["openconfig-bgp-ext:prefix-list"]["config"].update(
                                {"export-policy": prefix_list})
                    else:
                        family = kwargs.get('addr_family', "ipv4")
                        if family == "ipv6":
                            afi_safi_name_del = "IPV6_UNICAST"
                        else:
                            afi_safi_name_del = "IPV4_UNICAST"
                        if diRection == 'in':
                            url = st.get_datastore(dut, "rest_urls")['bgp_del_prefix_list_in']
                            url = url.format(vrf_name, neighbor, afi_safi_name_del)
                            if not delete_rest(dut, rest_url=url):
                                st.error("failed to delete prefix-list inboud")
                                return False
                        else:
                            url = st.get_datastore(dut, "rest_urls")['bgp_del_prefix_list_out']
                            url = url.format(vrf_name, neighbor, afi_safi_name_del)
                            if not delete_rest(dut, rest_url=url):
                                st.error("failed to delete prefix-list outbound")

                    common_data["afi-safis"]["afi-safi"].append(neigh_data_sub)
                    #prefix_list = None
                elif distribute_list:

                    common_data["afi-safis"] = dict()
                    common_data["afi-safis"]["afi-safi"] = list()
                    neigh_data_sub = dict()
                    neigh_data_sub.update({"afi-safi-name": afi_safi_name})
                    neigh_data_sub["config"] = dict()
                    neigh_data_sub["config"].update({"afi-safi-name": afi_safi_name})
                    neigh_data_sub["openconfig-bgp-ext:prefix-list"] = dict()
                    neigh_data_sub["openconfig-bgp-ext:prefix-list"]["config"] = dict()
                    if config_cmd != 'no':
                        if diRection == 'in':
                            neigh_data_sub["openconfig-bgp-ext:prefix-list"]["config"].update(
                                {"import-policy": prefix_list})
                        else:
                            neigh_data_sub["openconfig-bgp-ext:prefix-list"]["config"].update(
                                {"export-policy": prefix_list})
                    else:
                        family = kwargs.get('addr_family', "ipv4")
                        if family == "ipv6":
                            afi_safi_name_del = "IPV6_UNICAST"
                        else:
                            afi_safi_name_del = "IPV4_UNICAST"
                        if diRection == 'in':
                            url = st.get_datastore(dut, "rest_urls")['bgp_del_prefix_list_in']
                            url = url.format(vrf_name, neighbor, afi_safi_name_del,prefix_list)
                            if not delete_rest(dut, rest_url=url):
                                st.error("failed to delete ditribute-list inboud")

                        else:
                            url = st.get_datastore(dut, "rest_urls")['bgp_del_prefix_list_out']
                            url = url.format(vrf_name, neighbor, afi_safi_name_del,prefix_list)
                            if not delete_rest(dut, rest_url=url):
                                st.error("failed to delete distribute-list outbound")

                    common_data["afi-safis"]["afi-safi"].append(neigh_data_sub)
                    #prefix_list = None
                elif default_originate:
                    #family = kwargs.get('addr_family', "ipv4")
                    #if family == "ipv6":
                        #afi_safi_name = "openconfig-bgp-types:IPV6_UNICAST"
                    #else:
                        #afi_safi_name = "openconfig-bgp-types:IPV4_UNICAST"
                    if not common_data:
                        common_data["afi-safis"] = dict()
                        common_data["afi-safis"]["afi-safi"] = list()
                    neigh_data_sub = dict()
                    neigh_data_sub["ipv4-unicast"] = dict()
                    neigh_data_sub["ipv4-unicast"]["config"] = dict()

                    if 'routeMap' in kwargs:
                        if config_cmd != 'no':
                            neigh_data_sub["ipv4-unicast"]["config"].update({"send-default-route": True, "openconfig-bgp-ext:default-policy-name": routeMap})

                        else:
                            neigh_data_sub["ipv4-unicast"]["config"].update({"send-default-route": False})
                    else:
                        neigh_data_sub["ipv4-unicast"]["config"].update({"send-default-route": True})
                    common_data["afi-safis"]["afi-safi"].append(neigh_data_sub)
                    #default_originate = False
                elif removePrivateAs:
                    common_data["afi-safis"] = dict()
                    common_data["afi-safis"]["afi-safi"] = list()
                    neigh_data_sub = dict()
                    neigh_data_sub.update({"afi-safi-name": afi_safi_name})
                    neigh_data_sub["config"] = dict()
                    neigh_data_sub["config"].update({"afi-safi-name": afi_safi_name})
                    neigh_data_sub["openconfig-bgp-ext:remove-private-as"] = dict()
                    neigh_data_sub["openconfig-bgp-ext:remove-private-as"]["config"] = dict()
                    if config_cmd != "no":
                        neigh_data_sub["openconfig-bgp-ext:remove-private-as"]["config"].update({"enabled": True})
                    else:
                        neigh_data_sub["openconfig-bgp-ext:remove-private-as"]["config"].update({"enabled": False})
                    common_data["afi-safis"]["afi-safi"].append(neigh_data_sub)
                    #removePrivateAs = False
                elif weight:

                    family = kwargs.get('addr_family', "ipv4")
                    if family == "ipv6":
                        afi_safi_name = "openconfig-bgp-types:IPV6_UNICAST"
                    else:
                        afi_safi_name = "openconfig-bgp-types:IPV4_UNICAST"
                    common_data["afi-safis"] = dict()
                    common_data["afi-safis"]["afi-safi"] = list()
                    neigh_data_sub = dict()
                    neigh_data_sub.update({"afi-safi-name": afi_safi_name})

                    neigh_data_sub['config'] = dict()
                    if config_cmd!='no':
                        neigh_data_sub['config'].update({"afi-safi-name": afi_safi_name, "enabled": True, "openconfig-bgp-ext:weight": int(weight)})
                    else:
                        if neighbor and not peergroup:
                            url=st.get_datastore(dut,"rest_urls")['bgp_del_weight']
                            url=url.format(vrf_name,neighbor,family)
                            if not delete_rest(dut,rest_url=url):
                                st.error("failed to delete weight")

                        else:
                            url = st.get_datastore(dut, "rest_urls")['bgp_del_weight_peer']
                            url = url.format(vrf_name, peergroup, family)
                            if not delete_rest(dut, rest_url=url):
                                st.error("failed to delete weight")

                    common_data["afi-safis"]["afi-safi"].append(neigh_data_sub)

                    #weight = None
                elif keepalive and holdtime:
                    family=kwargs.get("addr_family",'ipv4')
                    if neighbor:
                        if no_neighbor == "no":
                            url = st.get_datastore(dut, "rest_urls")['bgp_del_neighbor_config'].format("default",neighbor)

                            if not delete_rest(dut, rest_url=url):
                                st.error("neighbor delete is failed")

                        else:
                            neigh_data.update({"neighbor-address":neighbor})
                            neigh_data["config"].update({"neighbor-address": neighbor})

                    common_data["timers"] = dict()
                    common_data["timers"]["config"] = dict()

                    if config_cmd != 'no':
                        common_data["timers"]["config"].update({"hold-time": str(holdtime), "keepalive-interval": str(keepalive)})
                    else:
                        if neighbor and not peergroup:
                            url = st.get_datastore(dut,"rest_urls")['bgp_del_timers']
                            url=url.format(vrf_name,neighbor,family)
                            if not delete_rest(dut,rest_url=url):
                                st.error("failed to delete timers")

                        else:
                            url = st.get_datastore(dut, "rest_urls")['bgp_del_timers_peer']
                            url = url.format(vrf_name, peergroup,family)
                            if not delete_rest(dut, rest_url=url):
                                st.error("failed to delete timers")

                    #keepalive = 0
                    #holdtime = 0
                elif nexthop_self:

                    common_data["afi-safis"] = dict()
                    common_data["afi-safis"]["afi-safi"] = list()
                    neigh_data_sub = dict()
                    neigh_data_sub.update({"afi-safi-name": afi_safi_name})
                    neigh_data_sub["config"] = dict()
                    neigh_data_sub["config"].update({"afi-safi-name": afi_safi_name})
                    neigh_data_sub["openconfig-bgp-ext:next-hop-self"] = dict()
                    neigh_data_sub["openconfig-bgp-ext:next-hop-self"]["config"] = dict()
                    if config_cmd !='no':
                        neigh_data_sub["openconfig-bgp-ext:next-hop-self"]["config"].update(
                        {"enabled": True})
                        common_data["afi-safis"]["afi-safi"].append(neigh_data_sub)
                    else:
                        if neighbor and not peergroup:
                            url = st.get_datastore(dut, "rest_urls")['bgp_del_nexthop_self']
                            url = url.format(vrf_name,neighbor,family)
                            if not delete_rest(dut, rest_url=url):
                                st.error("failed to delete nexthop self")

                        else:
                            url = st.get_datastore(dut, "rest_urls")['bgp_del_nexthop_self_peer']
                            url = url.format(vrf_name, peergroup,family)
                            if not delete_rest(dut, rest_url=url):
                                st.error("failed to delete nexthop self")

                    #nexthop_self = None
                elif pswd:
                    password = "" if config_cmd == 'no' else password
                    #neigh_data_sub = dict()
                    if config_cmd != 'no':
                        neigh_data["openconfig-bgp-ext:auth-password"] = dict()
                        neigh_data["openconfig-bgp-ext:auth-password"]["config"] = dict()
                        neigh_data["openconfig-bgp-ext:auth-password"]["config"].update({"password": password})

                    else:
                        if neighbor and not peergroup:
                            url = st.get_datastore(dut, "rest_urls")['bgp_del_pwd']
                            url = url.format(vrf_name, neighbor)
                            if not delete_rest(dut, rest_url=url):
                                st.error("failed to delete pwd")

                        else:
                            url = st.get_datastore(dut, "rest_urls")['bgp_del_pwd']
                            url = url.format(vrf_name, peergroup)
                            if not delete_rest(dut, rest_url=url):
                                st.error("failed to delete pwd")


                    #pswd = False
                elif update_src:
                    if neighbor:
                        if no_neighbor == 'no':
                            url = st.get_datastore(dut, "rest_urls")['bgp_del_neighbor_config'].format("default",neighbor)

                            if not delete_rest(dut, rest_url=url.format("default", neighbor)):
                                st.error("neighbor is failed")

                        else:
                            neigh_data.update({"neighbor-address": neighbor})
                            neigh_data["config"].update({"neighbor-address": neighbor})
                        common_data.update(neigh_data)
                    neigh_data_sub = dict()
                    neigh_data_sub["transport"]=dict()
                    neigh_data_sub["transport"]["config"] = dict()
                    if config_cmd!='no':
                        neigh_data_sub["transport"]["config"].update({"local-address": update_src})
                        common_data["afi-safis"]["afi-safi"].append(neigh_data_sub)
                    else:
                        if neighbor and not peergroup:
                            url = st.get_datastore(dut, "rest_urls")['bgp_del_update_src']
                            url = url.format(vrf_name, neighbor)
                            if not delete_rest(dut, rest_url=url):
                                st.error("failed to delete update_src")

                        else:
                            url = st.get_datastore(dut, "rest_urls")['bgp_del_update_src_peer']
                            url = url.format(vrf_name, peergroup)
                            if not delete_rest(dut, rest_url=url):
                                st.error("failed to delete update_src")

                    #update_src = None
                elif update_src_intf:
                    if neighbor:
                        if no_neighbor == 'no':
                            url = st.get_datastore(dut, "rest_urls")['bgp_del_neighbor_config'].format("default", neighbor)

                            if not delete_rest(dut, rest_url=url.format("default", neighbor)):
                                st.error("neighbor is failed")

                        else:
                            neigh_data.update({"neighbor-address": neighbor})
                            neigh_data["config"].update({"neighbor-address": neighbor})

                    neigh_data_sub = dict()
                    neigh_data_sub["transport"] = dict()
                    neigh_data_sub["transport"]["config"] = dict()
                    if config_cmd != 'no':
                        neigh_data_sub["transport"]["config"].update({"local-address": update_src})
                        common_data["afi-safis"]["afi-safi"].append(neigh_data_sub)
                    else:
                        if neighbor and not peergroup:
                            url = st.get_datastore(dut, "rest_urls")['bgp_del_update_src']
                            url = url.format(vrf_name, neighbor)
                            if not delete_rest(dut, rest_url=url):
                                st.error("failed to delete update_src")
                        else:
                            url = st.get_datastore(dut, "rest_urls")['bgp_del_update_src_peer']
                            url = url.format(vrf_name, peergroup)
                            if not delete_rest(dut, rest_url=url):
                                st.error("failed to delete update_src")

                    #update_src_intf = None
                elif ebgp_mhop:
                    if neighbor:
                        if no_neighbor == 'no':
                            url = st.get_datastore(dut, "rest_urls")['bgp_del_neighbor_config'].format("default",neighbor)

                            if not delete_rest(dut, rest_url=url.format("default", neighbor)):
                                st.error("neighbor is failed")

                        else:
                            neigh_data.update({"neighbor-address": neighbor})
                            neigh_data["config"].update({"neighbor-address": neighbor})

                    neigh_data_sub = dict()
                    neigh_data_sub["ebgp-multihop"] = dict()
                    neigh_data_sub["ebgp-multihop"]["config"] = dict()
                    if config_cmd != 'no':
                        neigh_data_sub["ebgp-multihop"]["config"].update({"enabled": True,"multihop-ttl": int(ebgp_mhop) })

                        neigh_data.update(neigh_data_sub)
                    else:
                        if neighbor and not peergroup:
                            url = st.get_datastore(dut, "rest_urls")['bgp_del_ebgp_mhop']
                            url = url.format(vrf_name, neighbor)
                            if not delete_rest(dut, rest_url=url):
                                st.error("failed to delete ebgp mhop")

                        else:
                            url = st.get_datastore(dut, "rest_urls")['bgp_del_ebgp_mhop_peer']
                            url = url.format(vrf_name, peergroup)
                            if not delete_rest(dut, rest_url=url):
                                st.error("failed to delete ebgp mhop")

                    #ebgp_mhop = None
                elif bfd:
                    if (neighbor or interface) and remote_as:

                        st.log("interface:")
                        st.log(interface)
                        st.log("neighbor:")
                        st.log(neighbor)
                        if neighbor:

                            neigh_data.update({"neighbor-address": neighbor})
                            neigh_data["config"] = dict()
                            neigh_data["config"].update({"neighbor-address": neighbor})
                            if str(remote_as).isdigit():
                                neigh_data["config"].update({"neighbor-address": neighbor, "peer-as": int(remote_as)})
                            else:
                                if remote_as == "internal":
                                    peer_type = "INTERNAL"
                                else:
                                    peer_type = "EXTERNAL"
                                neigh_data["config"].update({"neighbor-address": neighbor, "peer-type": peer_type})
                        else:
                            neigh_data.update({"neighbor-address": interface})
                            neigh_data["config"] = dict()
                            neigh_data["config"].update({"neighbor-address": interface})
                            if str(remote_as).isdigit():
                                neigh_data["config"].update({"neighbor-address": interface, "peer-as": int(remote_as)})
                            else:
                                if remote_as == "internal":
                                    peer_type = "INTERNAL"
                                else:
                                    peer_type = "EXTERNAL"
                                neigh_data["config"].update({"neighbor-address": interface, "peer-type": peer_type})


                        neigh_data_sub = dict()
                        neigh_data_sub["openconfig-bfd:enable-bfd"] = dict()
                        neigh_data_sub["openconfig-bfd:enable-bfd"]["config"] = dict()
                        if config_cmd != 'no':
                            neigh_data_sub["openconfig-bfd:enable-bfd"]["config"].update({"enabled": True})
                        else:
                            url=st.get_datastore(dut,"rest_urls")['bgp_del_bfd']
                            url=url.format(vrf_name,neighbor)
                            if not delete_rest(dut,rest_url=url):
                                st.error("failed to disable bfd")

                        neigh_data.update(neigh_data_sub)
                        global_data["openconfig-network-instance:bgp"]["neighbors"]=dict()
                        global_data["openconfig-network-instance:bgp"]["neighbors"]["neighbor"]=list()
                        global_data["openconfig-network-instance:bgp"]["neighbors"]["neighbor"].append(neigh_data)
                        #bfd = False
                elif connect:
                    common_data["timers"] = dict()
                    common_data["timers"]["config"] = dict()
                    if config_cmd != 'no':
                        common_data["timers"]["config"].update({"connect-retry": str(connect)})
                    else:
                        if neighbor and not peergroup:
                            url = st.get_datastore(dut, "rest_urls")['bgp_del_connect']
                            url = url.format(vrf_name, neighbor)
                            if not delete_rest(dut, rest_url=url):
                                st.error("failed to delete connect")

                        else:
                            url = st.get_datastore(dut, "rest_urls")['bgp_del_connect_peer']
                            url = url.format(vrf_name, peergroup)
                            if not delete_rest(dut, rest_url=url):
                                st.error("failed to delete connect")

                    #connect = None
                elif type1 == 'fast_external_failover':
                    st.log("Configuring the fast_external_failover")

                    if config_cmd!='no':
                        global_data["openconfig-network-instance:bgp"]["global"]["config"].update({"openconfig-bgp-ext:fast-external-failover": True})
                    else:
                        global_data["openconfig-network-instance:bgp"]["global"]["config"][config].update({"openconfig-bgp-ext:fast-external-failover": False})
                elif type1 == 'bgp_bestpath_selection':
                    global_data["openconfig-network-instance:bgp"]["global"]["route-selection-options"] = dict()
                    global_data["openconfig-network-instance:bgp"]["global"]["route-selection-options"]["config"] = dict()
                    global_data["openconfig-network-instance:bgp"]["global"]["use-multiple-paths"]=dict()
                    global_data["openconfig-network-instance:bgp"]["global"]["use-multiple-paths"]["ebgp"]=dict()
                    global_data["openconfig-network-instance:bgp"]["global"]["use-multiple-paths"]["ebgp"]["config"] = dict()
                    if 'as-path confed' in bgp_bestpath_selection:
                        if config_cmd != 'no':
                            global_data["openconfig-network-instance:bgp"]["global"]["route-selection-options"]["config"].update({"openconfig-bgp-ext:compare-confed-as-path": True})
                        else:
                            url = st.get_datastore(dut, "rest_urls")['bgp_del_bp_as_path_confed']
                            url = url.format(vrf_name)
                            if not delete_rest(dut, rest_url=url):
                                st.error("failed to unconfig as-path confed")

                    if 'as-path ignore' in bgp_bestpath_selection:
                        if config_cmd != 'no':
                            global_data["openconfig-network-instance:bgp"]["global"]["route-selection-options"]["config"].update({"openconfig-network-instance:ignore-as-path-length": True})
                        else:
                            url = st.get_datastore(dut, "rest_urls")['bgp_del_bp_as_path_ig']
                            url = url.format(vrf_name)
                            if not delete_rest(dut, rest_url=url):
                                st.error("failed to unconfig as-path ignore")

                    if 'as-path multipath-relax' in bgp_bestpath_selection:
                        if config_cmd != 'no':
                            global_data["openconfig-network-instance:bgp"]["global"]["use-multiple-paths"]["ebgp"]["config"].update(
                                {"allow-multiple-as": True, "openconfig-bgp-ext:as-set": False})
                        else:
                            url = st.get_datastore(dut, "rest_urls")['bgp_del_bp_as_path_multipath_relax']
                            url = url.format(vrf_name)
                            if not delete_rest(dut, rest_url=url):
                                st.error("failed to unconfig as-path multipath-relax")

                    if 'as-path multipath-relax as-set' in bgp_bestpath_selection:
                        if config_cmd != 'no':
                            global_data["openconfig-network-instance:bgp"]["global"]["use-multiple-paths"]["ebgp"]["config"].update({"allow-multiple-as": True, "openconfig-bgp-ext:as-set": True})
                        else:
                            url = st.get_datastore(dut, "rest_urls")['bgp_del_bp_as_path_multipath_relax_as']
                            url = url.format(vrf_name)
                            if not delete_rest(dut, rest_url=url):
                                st.error("failed to unconfig as-path multipath-relax as-set")

                    if 'compare-routerid' in bgp_bestpath_selection:
                        if config_cmd != 'no':
                            global_data["openconfig-network-instance:bgp"]["global"]["route-selection-options"]["config"].update({"external-compare-router-id": True})
                        else:
                            url = st.get_datastore(dut, "rest_urls")['bgp_del_bp_comp_rid']
                            url = url.format(vrf_name)
                            if not delete_rest(dut, rest_url=url):
                                st.error("failed to unconfig as-path compare-routerid")

                    if 'med confed' in bgp_bestpath_selection:
                        if config_cmd != 'no':
                            global_data["openconfig-network-instance:bgp"]["global"]["route-selection-options"]["config"].update({"openconfig-bgp-ext:med-missing-as-worst": False})
                        else:
                            url = st.get_datastore(dut, "rest_urls")['bgp_del_bp_med']
                            url = url.format(vrf_name)
                            if not delete_rest(dut, rest_url=url):
                                st.error("failed to unconfig med confed")

                    if 'med confed missing-as-worst' in bgp_bestpath_selection:
                        if config_cmd != 'no':
                            global_data["openconfig-network-instance:bgp"]["global"]["route-selection-options"]["config"].update({"openconfig-bgp-ext:med-missing-as-worst": True})
                        else:
                            url = st.get_datastore(dut, "rest_urls")['bgp_del_bp_med']
                            url = url.format(vrf_name)
                            if not delete_rest(dut, rest_url=url):
                                st.error("failed to unconfig med confed")

                    if ('med missing-as-worst confed' or 'med missing-as-worst') in bgp_bestpath_selection:
                        if config_cmd != 'no':
                            global_data["openconfig-network-instance:bgp"]["global"]["route-selection-options"]["config"].update({"openconfig-bgp-ext:med-missing-as-worst": True})
                        else:
                            url = st.get_datastore(dut, "rest_urls")['bgp_del_bp_med']
                            url = url.format(vrf_name)
                            if not delete_rest(dut, rest_url=url):
                                st.error("failed to unconfig med confed")

                elif type1 == 'max_path_ibgp':
                    sub_data = dict()
                    sub_data["config"] = dict()
                    global_data["openconfig-network-instance:bgp"]["global"]["afi-safis"] = dict()
                    global_data["openconfig-network-instance:bgp"]["global"]["afi-safis"]["afi-safi"] = list()
                    if family == "ipv6":
                        afi_safi_name = "openconfig-bgp-types:IPV6_UNICAST"
                    else:
                        afi_safi_name = "openconfig-bgp-types:IPV4_UNICAST"
                    sub_data.update({"afi-safi-name":afi_safi_name})
                    sub_data["config"].update({"afi-safi-name":afi_safi_name})
                    sub_data["use-multiple-paths"] = dict()
                    sub_data["use-multiple-paths"]["ibgp"] = dict()
                    sub_data["use-multiple-paths"]["ibgp"]["config"] = dict()
                    if config_cmd != 'no':
                        sub_data["use-multiple-paths"]["ibpg"]["config"].update({"maximum-paths": max_path_ibgp})
                    else:
                        url = st.get_datastore(dut, "rest_urls")['bgp_del_max_path_ibgp']
                        url = url.format(vrf_name, family)
                        if not delete_rest(dut, rest_url=url):
                            st.error("failed to unconfig max paths ibgp")

                    global_data["openconfig-network-instance:bgp"]["global"]["afi-safis"]["afi-safi"].append(sub_data)
                elif type1 == 'max_path_ebgp':
                    sub_data = dict()
                    sub_data["config"] = dict()
                    global_data["openconfig-network-instance:bgp"]["global"]["afi-safis"] = dict()
                    global_data["openconfig-network-instance:bgp"]["global"]["afi-safis"]["afi-safi"] = list()
                    if family == "ipv6":
                        afi_safi_name = "openconfig-bgp-types:IPV6_UNICAST"
                    else:
                        afi_safi_name = "openconfig-bgp-types:IPV4_UNICAST"
                    sub_data.update({"afi-safi-name":afi_safi_name})
                    sub_data["config"].update({"afi-safi-name":afi_safi_name})
                    sub_data["use-multiple-paths"] = dict()
                    sub_data["use-multiple-paths"]["ebgp"] = dict()
                    sub_data["use-multiple-paths"]["ebgp"]["config"] = dict()
                    if config_cmd != 'no':
                        sub_data["use-multiple-paths"]["ebgp"]["config"].update({"maximum-paths": max_path_ebgp})
                    else:
                        url = st.get_datastore(dut, "rest_urls")['bgp_del_max_path_ebgp']
                        url = url.format(vrf_name, family)
                        if not delete_rest(dut, rest_url=url):
                            st.error("failed to unconfig max paths ebgp")

                    global_data["openconfig-network-instance:bgp"]["global"]["afi-safis"]["afi-safi"].append(sub_data)
                elif type1 == 'redist':
                    if redistribute=="connected":
                        sub_data = dict()
                        sub_data["config"] = dict()
                        redist_type = 'connected'
                        redist_type = redist_type.upper()
                        if redist_type == 'CONNECTED': redist_type = 'DIRECTLY_CONNECTED'
                        if config_cmd != 'no':
                            sub_data.update(
                                {"dst-protocol": "BGP", "address-family": family.upper(), "src-protocol": redist_type})
                            sub_data["config"].update(
                                {"dst-protocol": "BGP", "address-family": family.upper(), "src-protocol": redist_type})
                        else:
                            url = st.get_datastore(dut, "rest_urls")['bgp_del_redist_connected']
                            url = url.format(vrf_name, redist_type)
                            if not delete_rest(dut, rest_url=url):
                                st.error("failed to do unconfig redistribute connected")


                    elif redistribute == 'static':
                        sub_data = dict()
                        sub_data["config"] = dict()
                        redist_type = 'static'
                        redist_type = redist_type.upper()
                        if config_cmd != 'no':
                            sub_data.update(
                                {"dst-protocol": "BGP", "address-family": family.upper(), "src-protocol": redist_type})
                            sub_data["config"].update(
                                {"dst-protocol": "BGP", "address-family": family.upper(), "src-protocol": redist_type})
                        else:
                            url = st.get_datastore(dut, "rest_urls")['bgp_del_redist_static']
                            url = url.format(vrf_name, redist_type)
                            if not delete_rest(dut, rest_url=url):
                                st.error("failed to do unconfig redistribute static")


                    elif redistribute == "ospf":
                        sub_data = dict()
                        sub_data["config"] = dict()
                        redist_type = 'ospf'
                        redist_type = redist_type.upper()
                        if config_cmd != 'no':
                            sub_data.update(
                                {"dst-protocol": "BGP", "address-family": family.upper(), "src-protocol": redist_type})
                            sub_data["config"].update(
                                {"dst-protocol": "BGP", "address-family": family.upper(), "src-protocol": redist_type})
                        else:
                            url = st.get_datastore(dut, "rest_urls")['bgp_del_redist_ospf']
                            url = url.format(vrf_name, redist_type)
                            if not delete_rest(dut, rest_url=url):
                                st.error("failed to do unconfig redistribute ospf")

                    else:
                        st.error("unsupported commands")
                    sub_data1 = dict()
                    sub_data1["config"] = dict()
                    global_data["openconfig-network-instance:bgp"]["global"]["afi-safis"] = dict()
                    global_data["openconfig-network-instance:bgp"]["global"]["afi-safis"]["afi-safi"] = list()
                    if family == "ipv6":
                        afi_safi_name = "openconfig-bgp-types:IPV6_UNICAST"
                    else:
                        afi_safi_name = "openconfig-bgp-types:IPV4_UNICAST"
                    sub_data1.update({"afi-safi-name": afi_safi_name})
                    sub_data1["config"].update({"afi-safi-name": afi_safi_name})
                    global_data["openconfig-network-instance:bgp"]["global"]["afi-safis"]["afi-safi"].append(sub_data1)

                    open_data["openconfig-network-instance:table-connections"]["table-connection"].append(sub_data)

                elif type1 == 'network':
                    sub_data = dict()
                    sub_data["config"] = dict()
                    global_data["openconfig-network-instance:bgp"]["global"]["afi-safis"] = dict()
                    global_data["openconfig-network-instance:bgp"]["global"]["afi-safis"]["afi-safi"] = list()
                    if family == "ipv6":
                        afi_safi_name = "openconfig-bgp-types:IPV6_UNICAST"
                    else:
                        afi_safi_name = "openconfig-bgp-types:IPV4_UNICAST"
                    sub_data.update({"afi-safi-name":afi_safi_name})
                    sub_data["config"].update({"afi-safi-name":afi_safi_name})
                    if config_cmd != 'no':
                        sub_data["openconfig-bgp-ext:network-config"] = dict()
                        sub_data["openconfig-bgp-ext:network-config"]["network"] = list()
                        sub_data_net = dict()
                        sub_data_net["config"] = dict()
                        sub_data_net.update({"prefix": network})
                        sub_data_net["config"].update({"prefix": network})
                        sub_data["openconfig-bgp-ext:network-config"]["network"].append(sub_data_net)
                    else:
                        url = st.get_datastore(dut, "rest_urls")['bgp_del_network']
                        url = url.format(vrf_name, afi_safi_name, network)
                        if not delete_rest(dut, rest_url=url):
                            st.error("failed to unconfig network")

                    global_data["openconfig-network-instance:bgp"]["global"]["afi-safis"]["afi-safi"].append(sub_data)
                elif type1 == 'import-check':
                    global_sub_data = dict()
                    if config_cmd != 'no':
                        global_sub_data.update({"openconfig-bgp-ext:network-import-check": True})
                    else:
                        global_sub_data.update({"openconfig-bgp-ext:network-import-check": False})
                    global_data["openconfig-network-instance:bgp"]["config"].update(global_sub_data)
                elif type1 == 'import_vrf':
                    sub_data = dict()
                    global_data["openconfig-network-instance:bgp"]["global"]["afi-safis"] = dict()
                    global_data["openconfig-network-instance:bgp"]["global"]["afi-safis"]["afi-safi"] = list()
                    if family == "ipv6":
                        afi_safi_name = "openconfig-bgp-types:IPV6_UNICAST"
                    else:
                        afi_safi_name = "openconfig-bgp-types:IPV4_UNICAST"
                    sub_data.update({"afi-safi-name":afi_safi_name})
                    sub_data["config"].update({"afi-safi-name": afi_safi_name})
                    if config_cmd != 'no':
                        sub_data["openconfig-bgp-ext:import-network-instance"] = dict()
                        sub_data["openconfig-bgp-ext:import-network-instance"]["config"] = dict()
                        sub_data["openconfig-bgp-ext:import-network-instance"]["config"].update({"name": vrf_name})
                    else:
                        url = st.get_datastore(dut, "rest_urls")['bgp_del_vrf']
                        url = url.format(vrf_name, afi_safi_name)
                        if not delete_rest(dut, rest_url=url):
                            st.error("failed to delete vrf")

                        global_data["openconfig-network-instance:bgp"]["global"]["afi-safis"]["afi-safi"].append(sub_data)
                elif type1 == 'multipath-relax':
                    if config_cmd != 'no':
                        global_data["config"].update({"allow-multiple-as": True, "openconfig-bgp-ext:as-set": False})
                    else:
                        url = st.get_datastore(dut, "rest_urls")['bgp_del_bp_as_path_multipath_relax']
                        url = url.format(vrf_name)
                        if not delete_rest(dut, rest_url=url):
                            st.error("failed to unconfig as-path multipath-relax")

                elif type1 == 'removeBGP':
                    st.log("Removing the bgp config from the device")
                elif type1 == 'router_id':
                    st.log("Configuring the router-id on the device")
                elif type1 == 'peer_group':
                    st.log("Configuring the peer_group on the device")
                else:
                    st.log('{} Invalid BGP config parameter {} '.format(cli_type,type1))
                if config_cmd == 'no' and 'neighbor' in config_type_list and neighbor and not peergroup:

                    if config_cmd != 'no':

                        neigh_data.update({"neighbor-address": neighbor})

                        neigh_data["config"].update({"neighbor-address": neighbor})

                    else:
                        url=st.get_datastore(dut,"rest_urls")['bgp_del_remote_as']
                        url=url.format(vrf_name,neighbor)
                        if not delete_rest(dut,rest_url=url):
                            st.error("failed to delete remote-as")

                    #config_remote_as = False
                if vrf_name != 'default' and removeBGP == 'yes':
                    global_data["openconfig-network-instance:bgp"]["global"]["config"].update({"as": 0})

            st.log(common_data)
            st.log(global_data)

            if neighbor:
                neigh_data.update(common_data)
                global_data["openconfig-network-instance:bgp"]["neighbors"]["neighbor"].append(neigh_data)
            elif peergroup:
                peer_data.update(common_data)
                global_data["openconfig-network-instance:bgp"]["peer-groups"]["peer-group"].append(peer_data)

            st.log(vrf_name)
            url = st.get_datastore(dut,"rest_urls")["bgp_config"].format(vrf_name)
            if not config_rest(dut,rest_url=url,http_method=cli_type,json_data=global_data):
                st.error("failed to conifg bgp data")
            url = st.get_datastore(dut, "rest_urls")['bgp_config_route_map'].format(vrf_name)
            try:
                if not open_data["openconfig-network-instance:table-connections"]["table-connection"]:
                    st.log("open_data is empty")
                else:
                    if not config_rest(dut, rest_url=url, http_method=cli_type, json_data=open_data):
                        st.error("unable to configure route-map")
            except Exception as e:
                st.log("key not not found")
                st.log(e)
            return True
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


def show_ip_bgp_route(dut, family='ipv4', **kwargs):
    """
    API for show ip bgp
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :return:
    """
    cli_type = get_show_cli_type(dut, **kwargs)
    if cli_type == 'vtysh':
        command = "show bgp {}".format(family)
    elif cli_type == 'klish':
        command = "show bgp {} unicast".format(family)
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_url = st.get_datastore(dut, 'rest_urls')
        vrf = "default"
        url = rest_url["bgp_routerid_state"].format(vrf)
        output_router_id = get_rest(dut, rest_url=url)
        if output_router_id and rest_status(output_router_id["status"]):
            output_router_id = output_router_id["output"]
        else:
            output_router_id ={}
        result = list()
        router_id = ""
        if output_router_id:
            router_id = output_router_id["openconfig-network-instance:router-id"]
        if not router_id:
            return result

        if family != "ipv4":
            url = rest_url['bgp_unicast_config'].format(vrf, "IPV6_UNICAST", "ipv6-unicast")
            key_val = "openconfig-network-instance:ipv6-unicast"
        else:
            url = rest_url['bgp_unicast_config'].format(vrf, "IPV4_UNICAST", "ipv4-unicast")
            key_val = "openconfig-network-instance:ipv4-unicast"
        output = get_rest(dut, rest_url=url)
        if output and rest_status(output["status"]):
            output = output["output"]
        else:
            return result
        st.debug(output)
        if not output:
            st.log("Empty output from GET Call")
            return result
        # routes = output[key_val]["loc-rib"]["routes"]["route"]
        if key_val in output:
            if "loc-rib" in output[key_val]:
                routes = output[key_val]["loc-rib"]["routes"]["route"]
            else:
                return result
        else:
            return result
        as_path = {"IGP":"i", "EGP":"e" ,"?":"incomplete","INCOMPLETE" :"incomplete"}
        for route in routes:
            show_output = dict()
            show_output["router_id"] = router_id
            show_output["network"] =  route["prefix"]
            show_output["weight"] =  route["openconfig-bgp-ext:attr-sets"]["weight"] if "weight" in route["openconfig-bgp-ext:attr-sets"] else 0
            show_output["status_code"] = "*>" if route["state"]["valid-route"] is True else ""
            show_output["metric"] = route["openconfig-bgp-ext:attr-sets"]["med"] if "med" in route["openconfig-bgp-ext:attr-sets"] else 0
            show_output["as_path"] = as_path[route["openconfig-bgp-ext:attr-sets"]["origin"]]
            members = ""
            if "as-path" in route["openconfig-bgp-ext:attr-sets"]:
                route_as_path = route["openconfig-bgp-ext:attr-sets"]["as-path"]
                if "as-segment" in route_as_path:
                    route_as_segment = route_as_path["as-segment"][0]
                    if "state" in route_as_segment:
                        members = ' '.join([str(item) for item in route_as_segment["state"]["member"]])
            show_output["as_path"] = "{} {}".format(members, as_path[route["openconfig-bgp-ext:attr-sets"]["origin"]])
            show_output["next_hop"] = route["openconfig-bgp-ext:attr-sets"]["next-hop"]
            show_output["version"] = ""
            show_output["vrf_id"] = vrf
            show_output["local_pref"] = route["openconfig-bgp-ext:attr-sets"]["local-pref"] if "local-pref" in route["openconfig-bgp-ext:attr-sets"] else 32768
            show_output["internal"] = ""
            result.append(show_output)
        st.debug(result)
        return result
    return st.show(dut, command, type=cli_type)

def fetch_ip_bgp_route(dut, family='ipv4', match=None, select=None, **kwargs):
    cli_type = get_show_cli_type(dut, **kwargs)
    output = show_ip_bgp_route(dut, family=family,cli_type=cli_type)
    #match = {'network': network}
    entries = filter_and_select(output, select, match)
    return entries

def get_ip_bgp_route(dut, family='ipv4', **kwargs):
    cli_type = get_show_cli_type(dut, **kwargs)
    output = show_ip_bgp_route(dut, family=family,cli_type=cli_type)
    st.debug(output)
    kwargs.pop("cli_type", None)
    for each in kwargs.keys():
        match = {each: kwargs[each]}
        get_list = ["network", "as_path"]
        st.log(match)
        entries = filter_and_select(output, get_list, match)
        st.log(entries)
        if not entries:
            st.log("Could not get bgp route info")
            return False
    return entries

def verify_ip_bgp_route(dut, family='ipv4', **kwargs):
    """

    EX; verify_ip_bgp_route(vars.D1, network= '11.2.1.2/24')
    """
    cli_type = get_show_cli_type(dut, **kwargs)
    output = show_ip_bgp_route(dut, family=family,cli_type=cli_type)
    kwargs.pop("cli_type", None)
    for each in kwargs.keys():
        match = {each: kwargs[each]}
        entries = filter_and_select(output, None, match)
        if not entries:
            st.log("{} and {} is not match ".format(each, kwargs[each]))
            return False
    return True


def verify_ip_bgp_route_network_list(dut, family='ipv4', nw_list=[], **kwargs):

    cli_type = get_show_cli_type(dut, **kwargs)
    output = show_ip_bgp_route(dut, family=family,cli_type=cli_type)
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
    #4 place, can use get_ip_bpg_route and/or verify_ip_bgp_route4 place, can use get_ip_bpg_route and/or verify_ip_bgp_route
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
    #1 place, can use get_ip_bpg_route and/or verify_ip_bgp_route4 place, can use get_ip_bpg_route and/or verify_ip_bgp_route

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
    cli_type = get_cfg_cli_type(dut, **kwargs)
    skip_error_check = kwargs.get('skip_error_check', True)
    remote_asn = kwargs.get('remote_asn', '')
    if config.lower() == 'yes':
        mode = ""
    else:
        mode = 'no'
    if family !='ipv4' and family != 'ipv6':
        return False
    cmd = ''
    if cli_type == 'vtysh':
        if vrf != 'default':
            cmd = cmd + 'router bgp {} vrf {}\n'.format(local_asn, vrf)
        else:
            cmd = cmd + 'router bgp {}\n'.format(local_asn)
        if remote_asn != '':
            cmd = cmd + 'neighbor {} remote-as {}\n'.format(neighbor_ip, remote_asn)
        cmd = cmd + 'address-family {} unicast\n'.format(family)
        cmd = cmd + '{} neighbor {} activate\n'.format(mode, neighbor_ip)
        cmd = cmd + '\n end'
        st.config(dut, cmd, type='vtysh', skip_error_check=skip_error_check)
        return True
    elif cli_type == "klish":
        neigh_name = get_interface_number_from_name(neighbor_ip)
        if vrf != 'default':
            cmd = cmd + 'router bgp {} vrf {}\n'.format(local_asn, vrf)
        else:
            cmd = cmd + 'router bgp {}\n'.format(local_asn)
        if neigh_name:
            if isinstance(neigh_name, dict):
                cmd = cmd + 'neighbor interface {} {}\n'.format(neigh_name["type"], neigh_name["number"])
            else:
                cmd = cmd + 'neighbor {}\n'.format(neigh_name)
        cmd = cmd + 'remote-as {}\n'.format(remote_asn)
        cmd = cmd + 'address-family {} unicast\n'.format(family)
        cmd = cmd + ' {} activate\n'.format(mode)
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
    # Debug command, no klish supported needed for this API
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

    def __init__(self, name, cli_type=''):
        self.name = name
        self.cli_type = get_cfg_cli_type(None, cli_type=cli_type)
        self.cli_type = 'klish' if self.cli_type in ['rest-patch','rest-put'] else self.cli_type
        self.match_sequence = []
        if self.cli_type == 'vtysh':
            self.cmdkeyword = 'bgp as-path access-list'
        elif self.cli_type == 'klish':
            self.cmdkeyword = 'bgp as-path-list'

    def add_match_permit_sequence(self, as_path_regex_list):
        self.match_sequence.append(('permit', as_path_regex_list))

    def add_match_deny_sequence(self, as_path_regex_list):
        self.match_sequence.append(('deny', as_path_regex_list))

    def config_command_string(self):
        command = ''
        if self.cli_type == 'vtysh':
            for v in self.match_sequence:
                command += '{} {} {}'.format(self.cmdkeyword, self.name, v[0])
                for as_path_regex in list(v[1]):
                    command += ' {}'.format(as_path_regex)
                command += '\n'
        elif self.cli_type == 'klish':
            for v in self.match_sequence:
                command += '{} {} {} {}'.format(self.cmdkeyword, self.name, v[0], "[{}]".format(','.join(v[1])))
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
        st.config(dut, command, type=self.cli_type)

