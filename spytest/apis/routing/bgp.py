# This file contains the list of API's which performs BGP operations.
# Author : Chaitanya Vella (Chaitanya-vella.kumar@broadcom.com)
import re
import json

from spytest import st, putils, filter_and_select

from apis.system import reboot
from apis.system.rest import config_rest, delete_rest, get_rest, rest_status

from utilities.common import kwargs_to_dict_list
from utilities.common import make_list, get_query_params
from utilities.utils import fail_on_error, get_interface_number_from_name
from utilities.utils import is_valid_ip_address, convert_microsecs_to_time
from utilities.utils import get_supported_ui_type_list
from utilities.utils import override_ui, override_supported_ui
from utilities.utils import convert_intf_name_to_component

try:
    import apis.yang.codegen.messages.network_instance as umf_ni
    from apis.yang.utils.common import Operation
except ImportError:
    pass


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
    elif cli_type in ["rest-patch", "rest-put"]:
        cli_type = "rest-patch"
    elif cli_type in get_supported_ui_type_list():
        return cli_type
    else:
        cli_type = "klish"
    return cli_type


def get_show_cli_type(dut, **kwargs):
    cli_type = get_forced_cli_type("show")
    cli_type = cli_type or st.get_ui_type(dut, **kwargs)
    if cli_type in ["click", "vtysh"]:
        cli_type = "vtysh"
    elif cli_type in ["rest-patch", "rest-put"]:
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

    if cli_type in get_supported_ui_type_list():
        vrf_name = kwargs['vrf_name'] if 'vrf_name' in kwargs and kwargs['vrf_name'] != 'default-vrf' else 'default'
        ni_obj = umf_ni.NetworkInstance(Name=vrf_name)
        if 'local_asn' in kwargs:
            proto_obj = umf_ni.Protocol(ProtoIdentifier='BGP', Name='bgp', As=int(kwargs['local_asn']), NetworkInstance=ni_obj)
        if 'router_id' in kwargs:
            proto_obj.BgpRouterId = kwargs['router_id']
        result = proto_obj.configure(dut, cli_type=cli_type)
        if not result.ok():
            st.log('test_step_failed: Enabling Router BGP mode {}'.format(result.data))
            return False
        return True
    elif cli_type in ['vtysh', 'click']:
        cli_type = 'vtysh'
        st.log("Enabling router BGP mode ..")
        if 'local_asn' in kwargs:
            command = "router bgp {}".format(kwargs['local_asn'])
        else:
            command = "router bgp"
        if 'vrf_name' in kwargs and kwargs['vrf_name'] != 'default-vrf':
            command += ' vrf ' + kwargs['vrf_name']
        command += "\n no bgp ebgp-requires-policy"

        if 'router_id' in kwargs:
            command += '\n bgp router-id {}'.format(kwargs['router_id'])

        st.config(dut, command, type=cli_type)
        return True

    if cli_type == 'klish':
        st.log("Enabling router BGP mode ..")
        if 'local_asn' in kwargs:
            command = "router bgp {}".format(kwargs['local_asn'])
        if 'vrf_name' in kwargs and kwargs['vrf_name'] != 'default-vrf':
            command += ' vrf ' + kwargs['vrf_name']
        if 'router_id' in kwargs:
            command += ' router-id {}'.format(kwargs['router_id'])
        st.config(dut, command, type=cli_type)
        return True

    if cli_type in ["rest-patch", "rest-put"]:
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

    st.error("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
    return False


def config_router_bgp_mode(dut, local_asn, config_mode='enable', vrf='default', cli_type="", skip_error_check=True, ebgp_req_policy=False):
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

    if cli_type in get_supported_ui_type_list():
        vrf_name = 'default' if vrf == 'default' else vrf
        ni_obj = umf_ni.NetworkInstance(Name=vrf_name)
        proto_obj = umf_ni.Protocol(ProtoIdentifier='BGP', Name='bgp', NetworkInstance=ni_obj)
        if not mode:
            proto_obj.As = int(local_asn)
            result = proto_obj.configure(dut, cli_type=cli_type)
        else:
            result = proto_obj.unConfigure(dut, target_path=proto_obj.Name, cli_type=cli_type)
        if not result.ok():
            st.log('test_step_failed: Enabling Router BGP mode {}'.format(result.data))
            return False
        return True
    elif cli_type in ['vtysh', 'click']:
        cli_type = 'vtysh'
        if vrf.lower() == 'default':
            command = "{} router bgp {}".format(mode, local_asn)
        else:
            command = "{} router bgp {} vrf {}".format(mode, local_asn, vrf)
        if not mode and not ebgp_req_policy:
            command += "\n no bgp ebgp-requires-policy"
        st.config(dut, command, type=cli_type, skip_error_check=skip_error_check)
        return True

    if cli_type == 'klish':
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
        st.config(dut, command, type=cli_type, skip_error_check=skip_error_check)
        return True

    if cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        # vrf_name = "default" if vrf.lower() == 'default' else vrf.lower()
        vrf_name = "default" if vrf == 'default' else vrf
        st.log(vrf_name)
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
            url = rest_urls['bgp_remove'].format(vrf_name)
            if not delete_rest(dut, rest_url=url):
                st.error("Error in Unconfiguring AS number")
                return False
            return True

    st.error("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
    return False


def unconfig_router_bgp(dut, **kwargs):
    """
    :param dut
    :return:
    """
    st.log("Unconfiguring BGP", dut=dut)
    cli_type = get_cfg_cli_type(dut, **kwargs)
    if cli_type in get_supported_ui_type_list():
        vrf_name = kwargs['vrf_name'] if 'vrf_name' in kwargs and kwargs['vrf_name'] != 'default-vrf' else 'default'
        return config_router_bgp_mode(dut, local_asn='not_used_with_config_mode_disable', config_mode='disable', vrf=vrf_name, cli_type=cli_type)
    elif cli_type in ['vtysh', 'click']:
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
        url = rest_urls['bgp_remove'].format(vrf_name)
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
        if cli_type in get_supported_ui_type_list():
            config_router_bgp_mode(dut, local_asn='not_used_with_config_mode_disable', config_mode='disable', cli_type=cli_type)
        elif cli_type in ["vtysh", "klish"]:
            st.log("Cleanup BGP mode ..")
            command = "no router bgp"
            st.config(dut, command, type=cli_type, skip_error_check=skip_error_check)
        elif cli_type in ["rest-patch", "rest-put"]:
            rest_urls = st.get_datastore(dut, 'rest_urls')
            url = rest_urls['bgp_remove'].format("default")
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
        cli_type = st.get_ui_type(dut, cli_type=cli_type)
        if cli_type in get_supported_ui_type_list():
            config_router_bgp_mode(dut, local_asn='not_used_with_config_mode_disable', config_mode='disable', cli_type=cli_type)
        elif cli_type in ["click", "klish", "vtysh"]:
            command = "show running bgp"
            output = st.show(dut, command, type="vtysh", skip_error_check=True, skip_tmpl=True)
            st.log("Cleanup BGP configuration on %s.." % dut)
            config = output.splitlines()
            line = 0
            count = len(config)
            bgp_inst = []
            cli_type = get_cfg_cli_type(dut, cli_type=cli_type)
            while line < count:
                _str = config[line]
                if re.match(r'router bgp .*', _str, re.IGNORECASE):
                    if cli_type == "klish":
                        _newstr = ' '.join([i for i in _str.split(" ") if not i.isdigit()])
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


def config_bgp_router(dut, local_asn, router_id='', keep_alive=60, hold=180, config='yes', **kwargs):
    """

    :param dut:
    :param local_asn:
    :param router_id:
    :param keep_alive:
    :param hold:
    :best_path_cmd: compare-routerid/as-path confed/as-path ignore/as-path multipath-relax/med confed/med confed missing-as-worst
    :return:
    """
    cli_type = get_cfg_cli_type(dut, **kwargs)
    if cli_type in get_supported_ui_type_list():
        # kwargs['router_id'] = router_id
        kwargs['keep_alive'] = keep_alive
        kwargs['hold'] = hold
        st.log('config_bgp_router: kwargs: {}'.format(kwargs))
        config = 'yes' if config.lower() in ['yes', ''] else 'no'
        ebgp_req_policy = kwargs.get('ebgp_req_policy', False)
        vrf_name = kwargs.get('vrf_name', 'default')
        family = kwargs.get('family', None)
        if router_id != '':
            kwargs['router_id'] = router_id

        ni_obj = umf_ni.NetworkInstance(Name=vrf_name)
        proto_obj = umf_ni.Protocol(ProtoIdentifier='BGP', Name='bgp', NetworkInstance=ni_obj)

        afi_safi_mapping = {
            'ipv4': 'IPV4_UNICAST',
            'ipv6': 'IPV6_UNICAST',
            'l2vpn': 'L2VPN_EVPN',
        }

        if family:
            afi_safi_name = afi_safi_mapping[family]
            gbl_afi_safi_obj = umf_ni.GlobalAfiSafi(AfiSafiName=afi_safi_name, Protocol=proto_obj)
            gbl_afi_safi_list = {
                'max_path_ibgp': ['IbgpMaximumPaths', int(kwargs['max_path_ibgp']) if 'max_path_ibgp' in kwargs and kwargs['max_path_ibgp'] != '' else None],
                'max_path_ebgp': ['EbgpMaximumPaths', int(kwargs['max_path_ebgp']) if 'max_path_ebgp' in kwargs and kwargs['max_path_ebgp'] != '' else None],
                'import_vrf': ['Name', kwargs.get('import_vrf', None)],
            }

            for key, attr_value in gbl_afi_safi_list.items():
                if key in kwargs and attr_value[1] is not None:
                    setattr(gbl_afi_safi_obj, attr_value[0], attr_value[1])

        gbl_attr_list = {
            'keep_alive': ['KeepaliveInterval', None if int(keep_alive) == 60 else int(keep_alive)],
            'hold': ['HoldTime', None if int(hold) == 180 else int(hold)],
            'update_delay': ['MaxDelay', int(kwargs['update_delay']) if 'update_delay' in kwargs else None],
            'cluster_id': ['RouteReflectorClusterId', kwargs['cluster_id'] if 'cluster_id' in kwargs else None],
            'router_id': ['BgpRouterId', router_id if router_id else None],
            'fast_external_failover': ['FastExternalFailover', True],
            'graceful_shutdown': ['GracefulShutdown', True],
            #     'graceful_restart': ['GracefulRestartEnabled', True],
            'graceful_restart': ['BgpEnabled', True],
            'network_import_check': ['NetworkImportCheck', True],
            'client_client_reflection': ['ClntToClntReflection', True],
            'deterministic_med': ['DeterministicMed', True],
            'always_comp_med': ['AlwaysCompareMed', True],
            # best_path_cmd
            'compare-routerid': ['ExternalCompareRouterId', True],
            'as-path confed': ['CompareConfedAsPath', True],
            'as-path ignore': ['IgnoreAsPathLength', True],
            'as-path multipath-relax': ['AllowMultipleAs', True],
            'as-path multipath-relax as-set': ['AsSet', True],
            'med confed': ['MedConfed', True],
            'med confed missing-as-worst': ['MedMissingAsWorst', True],
            # best_path_cmd
            'on_start_med': ['MaxMedVal', kwargs.get('on_start_med', None)],
            'on_start_time': ['Time', kwargs.get('on_start_time', None)],
            'administrative_med': ['MaxMedAdministrative', bool(kwargs['administrative_med']) if 'administrative_med' in kwargs else None],
            'max_dyn_nbr': ['MaxDynamicNeighbors', int(kwargs['max_dyn_nbr']) if 'max_dyn_nbr' in kwargs else None],
        }

        for key, attr_value in gbl_attr_list.items():
            if key == kwargs.get('best_path_cmd', None):
                setattr(proto_obj, attr_value[0], attr_value[1])
            if key in kwargs and attr_value[1] is not None:
                st.log('key:{}, {}'.format(key, attr_value[1]))
                setattr(proto_obj, attr_value[0], attr_value[1])
                if key == 'graceful_restart' and kwargs.get('preserve_state', None):
                    setattr(proto_obj, 'PreserveFwState', True)

        if config == 'yes':
            operation = Operation.CREATE
            config_router_bgp_mode(dut, local_asn, vrf=vrf_name, cli_type=cli_type, ebgp_req_policy=ebgp_req_policy)
            # Following can be enhanced, call only if needed
            result = proto_obj.configure(dut, cli_type=cli_type)
            if not result.ok():
                st.log('test_step_failed: Config Global attributes {}'.format(result.data))
                return False

            if family:
                result = gbl_afi_safi_obj.configure(dut, operation=operation, cli_type=cli_type)
                if not result.ok():
                    st.log('test_step_failed: Config Global AFI-SAFI attributes {}'.format(result.data))
                    return False
        else:
            for key, attr_value in gbl_attr_list.items():
                if key in kwargs or kwargs.get('best_path_cmd', None) == key:
                    if key == 'graceful_restart' and kwargs.get('preserve_state', None):
                        target_attr = getattr(proto_obj, 'PreserveFwState')
                        result = proto_obj.unConfigure(dut, target_attr=target_attr, cli_type=cli_type)
                    target_attr = getattr(proto_obj, attr_value[0])
                    result = proto_obj.unConfigure(dut, target_attr=target_attr, cli_type=cli_type)
                    if not result.ok():
                        st.log('test_step_failed: unConfigure Neighbor/PeerGroup attributes: {}'.format(result.data))
                        return False

            if family:
                target_attr_list = list()
                for key, attr_value in gbl_afi_safi_list.items():
                    if key in kwargs:
                        target_attr = getattr(gbl_afi_safi_obj, attr_value[0])
                        target_attr_list.append(target_attr)
                if target_attr_list:
                    result = gbl_afi_safi_obj.unConfigure(dut, target_attr=target_attr_list, cli_type=cli_type)
                    if not result.ok():
                        st.log('test_step_failed: UnConfig Global AFI-SAFI attributes {}'.format(result.data))
                        return False
        return True

    ebgp_req_policy = kwargs.get('ebgp_req_policy', False)
    command = ''
    config_router_bgp_mode(dut, local_asn, cli_type=cli_type, ebgp_req_policy=ebgp_req_policy)
    if cli_type == 'vtysh':
        if config == 'yes':
            if router_id:
                command += "bgp router-id {}".format(router_id)
            if keep_alive and hold:
                command += "\n timers bgp {} {}".format(keep_alive, hold)
        if config == 'no' and keep_alive:
            command += "\n no timers bgp\n"
        if config == 'no' and router_id:
            command += "\n no bgp router-id {}".format(router_id)
    elif cli_type == 'klish':
        if config == 'yes':
            if router_id:
                command += "router-id {}\n".format(router_id)
            if keep_alive and hold:
                command += "timers {} {}\n".format(keep_alive, hold)
            if 'cluster_id' in kwargs:
                command += "cluster-id {}\n".format(kwargs['cluster_id'])
        if config == 'no' and keep_alive:
            command += "no timers {} {}\n".format(keep_alive, hold)
        if config == 'no' and 'cluster_id' in kwargs:
            command += "no cluster-id\n"
        if config == 'no' and router_id:
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
                json_data["openconfig-network-instance:config"].update({'openconfig-bgp-ext:keepalive-interval': int(keep_alive)})
            if hold:
                json_data["openconfig-network-instance:config"].update({'openconfig-bgp-ext:hold-time': int(hold)})
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


def create_bgp_router(dut, local_asn, router_id='', keep_alive=60, hold=180, cli_type="", ebgp_req_policy=False):
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
    if cli_type in get_supported_ui_type_list():
        return config_bgp_router(dut, local_asn=local_asn, router_id=router_id, keep_alive=keep_alive, hold=hold, config='yes', cli_type=cli_type)
    elif cli_type == 'vtysh':
        command = ""
        config_router_bgp_mode(dut, local_asn, cli_type=cli_type, ebgp_req_policy=ebgp_req_policy)
        # Add validation for IPV4 address
        if router_id:
            command = "bgp router-id {}\n".format(router_id)
        command += "timers bgp {} {}\n".format(keep_alive, hold)
    elif cli_type == 'klish':
        command = list()
        config_router_bgp_mode(dut, local_asn, cli_type=cli_type, ebgp_req_policy=ebgp_req_policy)
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
            json_data["openconfig-bgp-ext:keepalive-interval"] = int(keep_alive)
        if hold:
            json_data["openconfig-bgp-ext:hold-time"] = int(hold)
        if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=json_data):
            st.error("Error in configuring router BGP")
            return False
        return True
    else:
        st.error("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
        return False
    st.config(dut, command, type=cli_type)
    return True


def create_bgp_neighbor(dut, local_asn, neighbor_ip, remote_asn, keep_alive=60, hold=180, password=None, family="ipv4", vrf='default', cli_type="", ebgp_req_policy=False):
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
    if cli_type in get_supported_ui_type_list():
        kwargs = dict()
        kwargs['remote_asn'] = remote_asn
        kwargs['keep_alive'] = keep_alive
        kwargs['hold'] = hold
        kwargs['password'] = password
        kwargs['vrf'] = vrf
        kwargs['cli_type'] = cli_type
        kwargs['ebgp_req_policy'] = ebgp_req_policy
        kwargs['activate'] = 'af_only'

        return config_bgp_neighbor_properties(dut, local_asn, neighbor_ip, family=family, mode='unicast', **kwargs)

    config_router_bgp_mode(dut, local_asn, vrf=vrf, cli_type=cli_type, ebgp_req_policy=ebgp_req_policy)
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
        data = dict()
        data["openconfig-network-instance:bgp"] = dict()
        data["openconfig-network-instance:bgp"]["global"] = dict()
        data["openconfig-network-instance:bgp"]["global"]["config"] = dict()
        data["openconfig-network-instance:bgp"]["global"]["config"].update({"as": int(local_asn)})
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
        neighbors["timers"]["config"]["hold-time"] = int(hold)
        neighbors["timers"]["config"]["keepalive-interval"] = int(keep_alive)
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


def config_bgp_neighbor(dut, local_asn, neighbor_ip, remote_asn, family="ipv4",
                        keep_alive=60, hold=180, config='yes', vrf='default', cli_type="",
                        skip_error_check=True, connect_retry=120, ebgp_req_policy=False):
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
    if family != 'ipv4' and family != 'ipv6':
        return False

    if cli_type in get_supported_ui_type_list():
        kwargs = dict()
        kwargs['remote_asn'] = remote_asn
        kwargs['keep_alive'] = keep_alive
        kwargs['hold'] = hold
        kwargs['config'] = config
        kwargs['vrf'] = vrf
        kwargs['cli_type'] = cli_type
        kwargs['skip_error_check'] = skip_error_check
        kwargs['connect'] = connect_retry
        kwargs['ebgp_req_policy'] = ebgp_req_policy
        kwargs['activate'] = 'af_only'
        if config != 'yes':
            kwargs['delete_neighbor'] = 'yes'

        return config_bgp_neighbor_properties(dut, local_asn, neighbor_ip, family=family, mode='unicast', **kwargs)

    cfgmode = 'no' if config != 'yes' else ''
    config_router_bgp_mode(dut, local_asn, vrf=vrf, cli_type=cli_type, ebgp_req_policy=ebgp_req_policy)
    if cli_type == "vtysh":
        command = "{} neighbor {} remote-as {}".format(cfgmode, neighbor_ip, remote_asn)
        if config == 'yes':
            command += "\n neighbor {} timers {} {}".format(neighbor_ip, keep_alive, hold)
            command += "\n neighbor {} timers connect {}".format(neighbor_ip, connect_retry)
            command += "\n address-family {} unicast".format(family)
            command += "\n neighbor {} activate".format(neighbor_ip)

        st.config(dut, command, type=cli_type)
        return True
    elif cli_type == "klish":
        commands = list()
        commands.append("{} neighbor {}".format(cfgmode, neighbor_ip))
        if config == "yes":
            commands.append("remote-as {}".format(remote_asn))
            commands.append("timers {} {}".format(keep_alive, hold))
            commands.append("timers connect {}".format(connect_retry))
            commands.append("address-family {} unicast".format(family))
            commands.append("activate")
            commands.append("exit")
            commands.append("exit")  # exit neighbor
        commands.append("exit")  # exit router-bgp
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
            neighbors["timers"]["config"]["hold-time"] = int(hold)
            neighbors["timers"]["config"]["keepalive-interval"] = int(keep_alive)
            neighbors["timers"]["config"]["connect-retry"] = int(connect_retry)
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


def config_bgp_neighbor_properties(dut, local_asn, neighbor_ip, family=None, mode='unicast', **kwargs):
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
    st.log('config_bgp_neighbor_properties: kwargs: {}'.format(kwargs))
    properties = kwargs
    peergroup = properties.get('peergroup', None)
    cli_type = get_cfg_cli_type(dut, **kwargs)
    ebgp_req_policy = kwargs.get('ebgp_req_policy', False)
    cli_type = "klish" if cli_type in ["rest-patch", "rest-put"] else cli_type
    skip_error_check = kwargs.get("skip_error_check", True)
    no_form = "no" if "no_form" in properties and properties["no_form"] == "no" else ""
    if cli_type in get_supported_ui_type_list():
        if 'max_prefix_restart_int' in kwargs and 'max_prefix_warning' in kwargs:
            st.error('max_prefix_restart_int and max_prefix_warning are mutually exclusieve')
            return False
        config = kwargs.get('config', 'yes') if no_form != 'no' else 'no'
        activate = kwargs.get('activate', 'af_default')
        vrf = kwargs.get('vrf', 'default')
        delete_neighbor = kwargs.get('delete_neighbor', None)
        # delete_peergroup = kwargs.get('delete_peergroup', None)

        route_map_dir = kwargs.get('route_map_dir', 'in')
        filter_list_dir = kwargs.get('filter_list_dir', 'in')
        prefix_list_dir = kwargs.get('prefix_list_dir', 'in')

        afi_safi_mapping = {
            'ipv4': 'IPV4_UNICAST',
            'ipv6': 'IPV6_UNICAST',
            'l2vpn': 'L2VPN_EVPN',
        }

        if family:
            afi_safi_name = afi_safi_mapping[family]
            # Add these in kwargs to pass the condition in for loop while configuring
            kwargs['activate'] = activate
            kwargs['afi_safi_name'] = afi_safi_name

        ni_obj = umf_ni.NetworkInstance(Name=vrf)
        proto_obj = umf_ni.Protocol(ProtoIdentifier='BGP', Name='bgp', NetworkInstance=ni_obj)

        nbr_attr_list = {
            'keep_alive': ['KeepaliveInterval', int(kwargs['keep_alive']) if 'keep_alive' in kwargs else None],
            'hold': ['HoldTime', int(kwargs['hold']) if 'hold' in kwargs else None],
            'remote_asn': ['PeerAs', kwargs.get('remote_asn', None)],
            'password': ['Password', kwargs.get('password', None)],
            'connect': ['ConnectRetry', int(kwargs['connect']) if 'connect' in kwargs else None],
            'ebgp_multihop': ['MultihopTtl', int(kwargs['ebgp_multihop']) if 'ebgp_multihop' in kwargs else None],
            'update_src': ['LocalAddress', kwargs.get('update_src', None)],
            'update_src_intf': ['LocalAddress', kwargs.get('update_src_intf', None)],
            'enforce_first_as': ['EnforceFirstAs', True if 'enforce_first_as' in kwargs else None],
            # 'local_as': ['LocalAs', kwargs.get('local_as', None)],
            'local_as_no_prepend': ['LocalAsNoPrepend', True if 'local_as_no_prepend' in kwargs else None],
            'local_as_replace_as': ['LocalAsReplaceAs', True if 'local_as_replace_as' in kwargs else None],
            'bfd': ['EnableBfdEnabled', True if 'bfd' in kwargs else None],
            'dont_negotiate_capability': ['DontNegotiateCapability', kwargs.get('dont_negotiate_capability')],
            'strict_capability_match': ['StrictCapabilityMatch', kwargs.get('strict_capability_match')],
            'bfd_profile': ['BfdProfile', kwargs.get('bfd_profile', None)],
        }

        if nbr_attr_list['remote_asn'][1] is not None:
            if str(nbr_attr_list['remote_asn'][1]).isdigit():
                nbr_attr_list['remote_asn'][1] = int(nbr_attr_list['remote_asn'][1])
            elif str(nbr_attr_list['remote_asn'][1]) == 'internal':
                nbr_attr_list['remote_asn'] = ['PeerType', 'INTERNAL']
            else:
                nbr_attr_list['remote_asn'] = ['PeerType', 'EXTERNAL']

        afi_safi_obj = None

        if peergroup:
            nbr_obj = umf_ni.PeerGroup(PeerGroupName=peergroup, Protocol=proto_obj)
            if family:
                afi_safi_obj = umf_ni.PeerGroupAfiSafi(AfiSafiName=afi_safi_name, PeerGroup=nbr_obj)

            if 'neighbor_shutdown' in kwargs:
                nbr_attr_list['neighbor_shutdown'] = ['PeerGroupEnabled', False]
                if no_form == 'no':
                    nbr_attr_list['neighbor_shutdown'] = ['PeerGroupEnabled', 'true']

        elif neighbor_ip:
            # Following check is not needed, as if not peergroup, then it has to be a valid neigbbor_ip or interface
            # if re.findall(r'Ethernet|Vlan|PortChannel|Eth', neighbor_ip) or family == 'l2vpn' or is_valid_ip_address(neighbor_ip, family):
            nbr_obj = umf_ni.BgpNeighbor(NeighborAddress=neighbor_ip, Protocol=proto_obj)
            if family:
                afi_safi_obj = umf_ni.NeighborAfiSafi(AfiSafiName=afi_safi_name, BgpNeighbor=nbr_obj)

            if 'neighbor_shutdown' in kwargs:
                nbr_attr_list['neighbor_shutdown'] = ['NeighborEnabled', False]
                if no_form == 'no':
                    nbr_attr_list['neighbor_shutdown'] = ['NeighborEnabled', 'true']

        afi_safi_attr_list = {
            # community valid values: {\'STANDARD\': {}, \'EXTENDED\': {}, \'BOTH\': {}, \'LARGE\': {}, \'ALL\': {}, \'NONE\': {}}
            'community': ['SendCommunity', kwargs['community'].upper() if 'community' in kwargs else None],
            'soft_reconfig': ['SoftReconfigurationIn', True if 'soft_reconfig' in kwargs else None],
            'weight': ['Weight', int(kwargs['weight']) if 'weight' in kwargs else None],
            # orf_dir valid values: {\'SEND\': {}, \'RECEIVE\': {}, \'BOTH\': {}}
            'orf_dir': ['OrfType', kwargs['orf_dir'].upper() if 'orf_dir' in kwargs else None],
            'rr_client': ['RouteReflectorClient', True if 'rr_client' in kwargs else None],
            'nh_self': ['NextHopSelfEnabled', True if 'nh_self' in kwargs else None],
            'maximum_prefix': ['Ipv4UnicastMaxPrefixes', kwargs.get('maximum_prefix', None)],
            'max_prefix_threshold': ['Ipv4UnicastWarningThresholdPct', kwargs.get('max_prefix_threshold', None)],
            'max_prefix_restart_int': ['Ipv4UnicastRestartTimer', kwargs.get('max_prefix_restart_int', None)],
            'max_prefix_warning': ['Ipv4UnicastPreventTeardown', True if 'max_prefix_warning' in kwargs else None],
            'route_map': ['ApplyPolicyImportPolicy' if route_map_dir == 'in' else 'ApplyPolicyExportPolicy', kwargs.get('route_map', None)],
            'filter_list': ['FilterListImportPolicy' if filter_list_dir == 'in' else 'FilterListExportPolicy', kwargs.get('filter_list', None)],
            'prefix_list': ['PrefixListImportPolicy' if prefix_list_dir == 'in' else 'PrefixListExportPolicy', kwargs.get('prefix_list', None)],
            'default_originate': ['Ipv4UnicastSendDefaultRoute' if family == 'ipv4' else 'Ipv6UnicastSendDefaultRoute', True if 'default_originate' in kwargs else None],
            'TxAddPaths': ['TxAddPaths', kwargs.get('TxAddPaths')],
            'remove_private_as': ['RemovePrivateAsEnabled', True if 'remove_private_as' in kwargs else None],
        }

        if family and family == 'ipv6':
            afi_safi_attr_list['maximum_prefix'] = ['Ipv6UnicastMaxPrefixes', kwargs.get('maximum_prefix', None)]
            afi_safi_attr_list['max_prefix_threshold'] = ['Ipv6UnicastWarningThresholdPct', kwargs.get('max_prefix_threshold', None)]
            afi_safi_attr_list['max_prefix_restart_int'] = ['Ipv6UnicastRestartTimer', kwargs.get('max_prefix_restart_int', None)]
            afi_safi_attr_list['max_prefix_warning'] = ['Ipv6UnicastPreventTeardown', True if 'max_prefix_warning' in kwargs else None]

        if config == 'yes':
            operation = Operation.CREATE
            config_router_bgp_mode(dut, local_asn, vrf=vrf, cli_type=cli_type, ebgp_req_policy=ebgp_req_policy)

            if 'ebgp_multihop' in kwargs:
                nbr_attr_list['ebgp_multihop_enable'] = ['EbgpMultihopEnabled', True]
                kwargs['ebgp_multihop_enable'] = True

            for attr_name, attr_value in nbr_attr_list.items():
                if attr_name in kwargs and attr_value[1] is not None:
                    setattr(nbr_obj, attr_value[0], attr_value[1])
            st.log('***IETF_JSON***: {}'.format(nbr_obj.get_ietf_json()))
            result = nbr_obj.configure(dut, operation=operation, cli_type=cli_type)
            if not result.ok():
                st.log('test_step_failed: Configure Neighbor/PeerGroup attributes: {}'.format(result.data))
                return False

            # Under Address Family context
            if family and mode:
                if family == 'ipv6' and activate in ['af_default']:
                    afi_safi_attr = dict()
                    afi_safi_attr['AfiSafiName'] = 'IPV4_UNICAST'
                    afi_safi_attr['AfiSafiEnabled'] = True
                    for key, value in afi_safi_attr.items():
                        setattr(afi_safi_obj, key, value)
                    afi_safi_attr = dict()
                    result = afi_safi_obj.configure(dut, operation=operation, cli_type=cli_type)
                    if not result.ok():
                        st.log('test_step_failed: Enable Address Family {}'.format(result.data))
                        return False

                if activate in ['af_only', 'af_default']:
                    afi_safi_attr_list['activate'] = ['AfiSafiEnabled', True]
                    afi_safi_attr_list['afi_safi_name'] = ['AfiSafiName', afi_safi_name]

                if 'nh_self' in kwargs:
                    if kwargs.get('force', None):
                        if kwargs['force'] != 'no':
                            afi_safi_attr_list['force'] = ['Force', True]

                if 'route_map' in kwargs:
                    # default-import-policy is not getting set in REST/GNMI as of now.
                    # This is because 'default_policy' is not passed from script
                    # Check if it is needed or any test case fails.
                    if route_map_dir == 'in':
                        afi_safi_attr_list['default_policy'] = ['DefaultImportPolicy', 'REJECT_ROUTE']
                    else:
                        afi_safi_attr_list['default_policy'] = ['DefaultExportPolicy', 'REJECT_ROUTE']

                for attr_name, attr_value in afi_safi_attr_list.items():
                    if attr_name in kwargs and attr_value[1] is not None:
                        setattr(afi_safi_obj, attr_value[0], attr_value[1])
                        if 'default_originate' in kwargs:
                            if 'route_map' in kwargs:
                                policy_name_attr = 'Ipv4UnicastDefaultPolicyName' if family == 'ipv4' else 'Ipv6UnicastDefaultPolicyName'
                                setattr(afi_safi_obj, policy_name_attr, kwargs['route_map'])
                st.log('***IETF_JSON***: {}'.format(afi_safi_obj.get_ietf_json()))
                result = afi_safi_obj.configure(dut, operation=operation, cli_type=cli_type)
                if not result.ok():
                    st.log('test_step_failed: Configure AFI-SAFI attributes: {}'.format(result.data))
                    return False

        # config == no
        else:
            if delete_neighbor:
                result = nbr_obj.unConfigure(dut, cli_type=cli_type)
                if not result.ok():
                    st.log('test_step_failed: Deleting BGP neighbor: {}'.format(result.data))
                    return False
                return True
            for attr_name, attr_value in nbr_attr_list.items():
                if attr_name in kwargs:
                    target_attr = getattr(nbr_obj, attr_value[0])
                    result = nbr_obj.unConfigure(dut, target_attr=target_attr, cli_type=cli_type)
                    if not result.ok():
                        st.log('test_step_failed: unConfigure Neighbor/PeerGroup attributes: {}'.format(result.data))
                        return False
            for attr_name, attr_value in afi_safi_attr_list.items():
                if family is None:
                    continue
                if attr_name in kwargs:
                    target_attr = getattr(afi_safi_obj, attr_value[0])
                    result = afi_safi_obj.unConfigure(dut, target_attr=target_attr, cli_type=cli_type)
                    if not result.ok():
                        st.log('test_step_failed: unConfigure AFI-SAFI attributes: {}'.format(result.data))
                        return False
            if family and activate in ['af_only', 'af_default']:
                result = afi_safi_obj.unConfigure(dut, target_attr=afi_safi_obj.AfiSafiEnabled, cli_type=cli_type)

        return True

    # Add validation for IPV4 / IPV6 address
    config_router_bgp_mode(dut, local_asn, cli_type=cli_type, ebgp_req_policy=ebgp_req_policy)
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
            if kwargs.get('encrypted'):
                commands.append("password {} encrypted".format(password))
                commands.append("exit")

            else:
                commands.append("{} password {}".format(no_form, password))
        if "keep_alive" in properties and "hold_time" in properties:
            commands.append("{} timers {} {}".format(no_form, properties["keep_alive"], properties["hold_time"]))
        if "neighbor_shutdown" in properties:
            commands.append("{} shutdown".format(no_form))
        if family and mode:
            commands.append("address-family {} {}".format(family, mode))
            if "activate" in properties:
                commands.append("{} activate".format(no_form))
            if "default-originate" in properties:
                commands.append("{} default-originate".format(no_form))
            if "maximum_prefix" in properties:
                cmd = " "
                cmd += " {}".format(properties["maximum_prefix"])
                if "max_prefix_threshold" in properties:
                    cmd += " {}".format(str(properties["max_prefix_threshold"]))
                if "max_prefix_restart" in properties:
                    cmd += " {}".format(str(properties["max_prefix_restart"]))
                if "max_prefix_restart_int" in properties:
                    cmd += " {}".format(str(properties["max_prefix_restart_int"]))
                if "max_prefix_warning" in properties:
                    cmd += " {}".format(str(properties["max_prefix_warning"]))
                commands.append("{} maximum-prefix {}".format(no_form, cmd))

            if "community" in properties:
                # community = "" if no_form == 'no' else properties["community"]
                commands.append("{} send-community {}".format(no_form, properties["community"]))
            if "soft_reconfig" in properties:
                commands.append("{} soft-reconfiguration inbound".format(no_form))
            if "orf_dir" in properties:
                commands.append("{} capability orf prefix-list {}".format(no_form, properties["orf_dir"]))

            commands.append("exit")
        if kwargs.get('encrypted'):
            commands.append("exit")
        else:
            commands.extend(["exit", "exit"])
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

    if cli_type in get_supported_ui_type_list():
        ni_obj = umf_ni.NetworkInstance(Name=vrf)
        proto_obj = umf_ni.Protocol(ProtoIdentifier='BGP', Name='bgp', NetworkInstance=ni_obj)
        nbr_obj = umf_ni.BgpNeighbor(NeighborAddress=neighbor_ip, PeerAs=remote_asn, Protocol=proto_obj)
        result = nbr_obj.unConfigure(dut, cli_type=cli_type)
        if not result.ok():
            st.log('test_step_failed: Deleting BGP neighbor: {}'.format(result.data))
            return False
        return True
    elif cli_type == "vtysh":
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
    # API_Not_Used: To Be removed in CyrusPlus
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


def advertise_bgp_network(dut, local_asn, network, route_map='', config='yes', family='ipv4', cli_type="", skip_error_check=True, network_import_check=False, **kwargs):
    """

    :param dut:
    :param local_asn:
    :param network:
    :return:
    """
    cli_type = get_cfg_cli_type(dut, cli_type=cli_type)
    st.log("Advertise BGP network ..")
    vrf = kwargs.get('vrf', 'default')
    if cli_type in get_supported_ui_type_list():
        ni_obj = umf_ni.NetworkInstance(Name=vrf)
        proto_obj = umf_ni.Protocol(ProtoIdentifier='BGP', Name='bgp', NetworkInstance=ni_obj)
        config_router_bgp_mode(dut, local_asn, vrf=vrf, cli_type=cli_type)
        if network_import_check:
            proto_obj.NetworkImportCheck = False
        else:
            proto_obj.NetworkImportCheck = True
        result = proto_obj.configure(dut, cli_type=cli_type)
        afi_safi_name = 'IPV4_UNICAST' if family == 'ipv4' else 'IPV6_UNICAST'
        gbl_afi_safi_obj = umf_ni.GlobalAfiSafi(AfiSafiName=afi_safi_name, Protocol=proto_obj)
        nw_cfg_obj = umf_ni.NetworkConfigNetwork(Prefix=network, GlobalAfiSafi=gbl_afi_safi_obj)
        if route_map != '':
            nw_cfg_obj.PolicyName = route_map
        if config == 'yes':
            operation = Operation.CREATE
            config_router_bgp_mode(dut, local_asn, vrf=vrf, cli_type=cli_type)
            result = gbl_afi_safi_obj.configure(dut, operation=operation, cli_type=cli_type)
            result = nw_cfg_obj.configure(dut, operation=operation, cli_type=cli_type)
        else:
            if route_map != '':
                result = nw_cfg_obj.unConfigure(dut, nw_cfg_obj.PolicyName, cli_type=cli_type)
            result = nw_cfg_obj.unConfigure(dut, cli_type=cli_type)
            # result = nw_cfg_obj.unConfigure(dut, nw_cfg_obj.Prefix, cli_type=cli_type)
            # result = gbl_afi_safi_obj.unConfigure(dut, cli_type=cli_type)
        if not result.ok():
            st.log('test_step_failed: Configure Network Advertise: {}'.format(result.data))
            return False
        return True

    cli_type = "klish" if cli_type in ["rest-patch", "rest-put"] else cli_type
    # Add validation for IPV4 / IPV6 address
    config_router_bgp_mode(dut, local_asn, cli_type=cli_type, vrf=vrf)
    mode = "" if config.lower() == 'yes' else "no"
    # Gather IPv6 type using validation
    if cli_type == "vtysh":
        command = ""
        if network_import_check:
            command += "no bgp network import-check \n"
        else:
            command += "bgp network import-check \n"

        if family == 'ipv6':
            command += "address-family ipv6 unicast"
            st.config(dut, command, type=cli_type, skip_error_check=skip_error_check)

        if route_map.lower() == '':
            command = "{} network {}".format(mode, network)
        else:
            command = "{} network {} route-map {}".format(mode, network, route_map)
        st.config(dut, command, type=cli_type, skip_error_check=skip_error_check)
    elif cli_type == "klish":
        commands = list()
        if network_import_check:
            commands.append("no network import-check")
        else:
            commands.append("network import-check")
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
    if cli_type in get_supported_ui_type_list():
        return advertise_bgp_network(dut, local_asn=local_asn, network=network, route_map=route_map, config='yes', family=addr_family, cli_type=cli_type, skip_error_check=skip_error_check, network_import_check=network_import_check)

    cli_type = "klish" if cli_type in ["rest-patch", "rest-put"] else cli_type
    cfgmode = 'no' if config != 'yes' else ''
    config_router_bgp_mode(dut, local_asn, cli_type=cli_type)
    if cli_type == "vtysh":
        command = ""
        if network_import_check:
            command += "no bgp network import-check \n"

        command += "address-family {} {}".format(addr_family, "unicast")
        command += "\n {} network {}".format(cfgmode, network)
        if route_map != '':
            command += "route-map {}".format(route_map)
        st.config(dut, command, type=cli_type)
        return True
    elif cli_type == "klish":
        commands = list()
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
        st.log(output)
        return parse_bgp_summary_output(output)
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
                    sent_msgs = rcv_msgs = {}
                for _, value in sent_msgs.items():
                    sent_msg_cnt = sent_msg_cnt + int(value)
                show_output["msgsent"] = sent_msg_cnt
                # rcv_msgs = neighbor["state"]["messages"]["received"]
                for _, value in rcv_msgs.items():
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
    # added kwargs.update() as Klish output currently does not list RIB entries. RFE SONIC-23559
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
    vrf = kwargs.get('vrf', 'default')
    family = kwargs.get('family', 'ipv4')
    if family == 'ipv6':
        output = show_bgp_ipv6_summary_vtysh(dut, vrf=vrf, cli_type=cli_type)
    else:
        output = show_bgp_ipv4_summary_vtysh(dut, vrf=vrf, cli_type=cli_type)
    estd_nbr = 0
    for i in range(0, len(output)):
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
    if cli_type in get_supported_ui_type_list():
        if kwargs['state'].isdigit():
            kwargs['state'] = 'Established'
        vrf = kwargs.pop('vrf') if 'vrf' in kwargs else "default"
        return verify_bgp_neigh_umf(dut, vrf=vrf, family="ipv6", neighborip=kwargs['neighbor'],
                                    state=kwargs['state'], cli_type=cli_type)
    else:
        output = show_bgp_ipv6_summary(dut, cli_type=cli_type)
        for each in kwargs.keys():
            match = {each: kwargs[each]}
            entries = filter_and_select(output, None, match)
            if not entries:
                st.log("{} and {} is not match ".format(each, kwargs[each]))
                return False
        return True


def show_bgp_neighbor(dut, neighbor_ip, **kwargs):
    # API_Not_Used: To Be removed in CyrusPlus
    """

    :param dut:
    :param neighbor_ip:
    :return:
    """
    exec_mode = kwargs.get("exec_mode", "")
    # No usage in scripts, so no klish support added
    command = "show bgp neighbor {}".format(neighbor_ip)
    return st.show(dut, command, exec_mode=exec_mode)


def show_bgp_ipv4_neighbor_vtysh(dut, neighbor_ip=None, vrf='default', **kwargs):
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


def show_bgp_ipv6_neighbor_vtysh(dut, neighbor_ip=None, vrf='default', **kwargs):
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
                # afi_safi_data = neighbor["afi-safis"]["afi-safi"]
                if neighbor.get("afi-safis"):
                    afi_safi_data = neighbor["afi-safis"]["afi-safi"]
                else:
                    continue
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
                                    show_output["openrcvd"] = messages["received"]["OPEN"] if "OPEN" in messages[
                                        "received"] else 0
                                    show_output["routerefreshrcvd"] = messages["received"][
                                        "ROUTE-REFRESH"] if "ROUTE-REFRESH" in messages["received"] else 0
                                    show_output["capabilityrcvd"] = messages["received"][
                                        "CAPABILITY"] if "CAPABILITY" in messages["received"] else 0
                                    show_output["keepalivercvd"] = messages["received"][
                                        "KEEPALIVE"] if "KEEPALIVE" in messages["received"] else 0
                                    show_output["notificationrcvd"] = messages["received"][
                                        "NOTIFICATION"] if "NOTIFICATION" in messages["received"] else 0
                                if "sent" in messages:
                                    show_output["updatesent"] = messages["sent"]["UPDATE"] if "UPDATE" in messages[
                                        "sent"] else 0
                                    show_output["opensent"] = messages["sent"][
                                        "OPEN"] if "OPEN" in messages["sent"] else 0
                                    show_output["routerefreshsent"] = messages["sent"][
                                        "ROUTE-REFRESH"] if "ROUTE-REFRESH" in messages["sent"] else 0
                                    show_output["capabilitysent"] = messages["sent"][
                                        "CAPABILITY"] if "CAPABILITY" in messages["sent"] else 0
                                    show_output["keepalivesent"] = messages["sent"][
                                        "KEEPALIVE"] if "KEEPALIVE" in messages["sent"] else 0
                                    show_output["notificationsent"] = messages["sent"][
                                        "NOTIFICATION"] if "NOTIFICATION" in messages["sent"] else 0
                            show_output["state"] = neighbor["state"]["session-state"] if "session-state" in neighbor[
                                "state"] else "IDLE"
                            show_output["bgpdownreason"] = neighbor["state"][
                                "last-reset-reason"] if "last-reset-reason" in neighbor[
                                "state"] else ""
                            show_output["remrouterid"] = neighbor["state"][
                                "remote-router-id"] if "remote-router-id" in neighbor["state"] else ""
                            show_output["lastread"] = neighbor["state"][
                                "last-read"] if "last-read" in neighbor[
                                "state"] else ""
                            show_output["lastwrite"] = neighbor["state"][
                                "last-write"] if "last-write" in neighbor[
                                "state"] else ""
                            show_output["bgplastreset"] = neighbor["state"][
                                "last-reset-time"] if "last-reset-time" in neighbor["state"] else ""
                            if "queues" in neighbor["state"]:
                                show_output["inqdepth"] = neighbor["state"]["queues"]["input"]
                                show_output["outqdepth"] = neighbor["state"]["queues"]["output"]
                        if "timers" in neighbor:
                            if "config" in neighbor["timers"]:
                                show_output["holdtime"] = neighbor["timers"]["config"]["hold-time"] \
                                    if "hold-time" in neighbor["timers"]["config"] else 0
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
    cli_type = "klish" if cli_type in ["rest-put", "rest-patch"] + get_supported_ui_type_list() else cli_type
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
    cli_type = "klish" if cli_type in get_supported_ui_type_list() else cli_type
    cli_type = "klish" if cli_type in ["rest-put", "rest-patch"] else cli_type
    address_family = kwargs.get('address_family', 'all')
    af_list = ['ipv4', 'ipv6']
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
            af_list = ["ipv4", "ipv6"]
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
    cli_type = "klish" if cli_type in get_supported_ui_type_list() else cli_type
    cli_type = "klish" if cli_type in ["rest-put", "rest-patch"] else cli_type
    soft = kwargs.get("soft", False)
    dir = kwargs.get("dir", "")
    if cli_type == 'vtysh':
        command = "clear ip bgp ipv4 {}".format(value)
        st.config(dut, command, type='vtysh', conf=False)
    elif cli_type == 'klish':
        if soft:
            command = "clear bgp ipv4 unicast {} soft {}".format(value, dir)
        else:
            command = "clear bgp ipv4 unicast {}".format(value)
        st.config(dut, command, type='klish', conf=False)
    else:
        st.error("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
        return False


def clear_ipv6_bgp_vtysh(dut, value="*", **kwargs):
    cli_type = get_cfg_cli_type(dut, **kwargs)
    cli_type = "klish" if cli_type in get_supported_ui_type_list() else cli_type
    cli_type = "klish" if cli_type in ["rest-put", "rest-patch"] else cli_type
    soft = kwargs.get("soft", False)
    dir = kwargs.get("dir", "")
    if cli_type == 'vtysh':
        command = "clear ip bgp ipv6 {}".format(value)
    elif cli_type == 'klish':
        if soft:
            command = "clear bgp ipv6 unicast {} soft {}".format(value, dir)
        else:
            command = "clear bgp ipv6 unicast {}".format(value)
    st.config(dut, command, type=cli_type, conf=False)


def clear_ip_bgp_vrf_vtysh(dut, vrf, family='ipv4', value="*", **kwargs):
    cli_type = get_cfg_cli_type(dut, **kwargs)
    cli_type = "klish" if cli_type in get_supported_ui_type_list() else cli_type
    cli_type = "klish" if cli_type in ["rest-put", "rest-patch"] else cli_type
    if cli_type == 'vtysh':
        command = "clear bgp vrf {} {} {}".format(vrf, family, value)
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
    vrf = kwargs.get('vrf', 'default')
    if cli_type in get_supported_ui_type_list():
        local_asn = kwargs['local_asn']
        family = kwargs['family']
        afi_safi_name = 'IPV4_UNICAST' if family == 'ipv4' else 'IPV6_UNICAST'
        config = 'yes' if kwargs['config'] == 'add' else 'no'

        summary_val = True if 'summary' in kwargs else False
        as_set_val = True if 'as_set' in kwargs else False
        ni_obj = umf_ni.NetworkInstance(Name=vrf)
        proto_obj = umf_ni.Protocol(ProtoIdentifier='BGP', Name='bgp', NetworkInstance=ni_obj)
        gbl_afi_safi_obj = umf_ni.GlobalAfiSafi(AfiSafiName=afi_safi_name, Protocol=proto_obj)
        aggr_addr_obj = umf_ni.AggregateAddress(Prefix=kwargs["address_range"], GlobalAfiSafi=gbl_afi_safi_obj)
        # aggr_addr_obj = umf_ni.AggregateAddress(Prefix=kwargs["address_range"], SummaryOnly=summary_val, AsSet=as_set_val, GlobalAfiSafi=gbl_afi_safi_obj)

        if summary_val:
            aggr_addr_obj.SummaryOnly = True
        if as_set_val:
            aggr_addr_obj.AsSet = True
        if "route_map" in kwargs:
            aggr_addr_obj.PolicyName = kwargs['route_map']

        if config == 'yes':
            operation = Operation.CREATE
            config_router_bgp_mode(dut, local_asn, vrf=vrf, cli_type=cli_type)
            gbl_afi_safi_obj.configure(dut, operation=operation, cli_type=cli_type)
            result = aggr_addr_obj.configure(dut, operation=operation, cli_type=cli_type)
        else:
            result = aggr_addr_obj.unConfigure(dut, cli_type=cli_type)

        if not result.ok():
            st.log('test_step_failed: Configure Aggregate_Address: {}'.format(result.data))
            return False

        return True

    # cli_type=kwargs.get("cli_type","vtysh")
    config_router_bgp_mode(dut, kwargs["local_asn"], vrf=vrf, cli_type=cli_type)
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
        if "route_map" in kwargs:
            command += " route-map {}".format(kwargs['route_map'])
        st.config(dut, command, type=cli_type)
    elif cli_type == "klish":
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
            if "summary" in kwargs:
                command += " summary-only"
            if "as_set" in kwargs:
                command += " as-set"
        if "route_map" in kwargs:
            command += " route-map {}".format(kwargs['route_map'])
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
            if not config_rest(dut, rest_url=url, http_method=cli_type, json_data=bgp_data):
                st.error("Error in configuring aggregate address")
                return False
            return True
        else:
            url = rest_urls["bgp_aggregate_address_config"].format(name=vrf, afi_safi_name=afi_safi_name, prefix=kwargs["address_range"])
            if not delete_rest(dut, rest_url=url):
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
    if cli_type in get_supported_ui_type_list():
        kwargs = dict()
        kwargs['cli_type'] = cli_type
        kwargs['skip_error_check'] = skip_error_check
        kwargs['update_delay'] = time
        return config_bgp_router(dut, local_asn=local_asn, **kwargs)

    if cli_type in ["click", "vtysh", "klish"]:
        config_router_bgp_mode(dut, local_asn, cli_type=cli_type)
        command = "update-delay {}".format(time)
        st.config(dut, command, type=cli_type, skip_error_check=skip_error_check)
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
        if not config_rest(dut, rest_url=url, http_method=cli_type, json_data=bgp_data):
            st.error("Error in configuring update delay")
            return False
        return True
    else:
        st.error("UNSUPPORTED CLI TYPE")
        return False


def create_bgp_always_compare_med(dut, local_asn):
    # API_Not_Used: To Be removed in CyrusPlus
    """

    :param dut:
    :param local_asn:
    :return:
    """
    # No usage in scripts
    config_router_bgp_mode(dut, local_asn)
    command = "bgp always-compare-med"
    st.config(dut, command, type='vtysh')


def create_bgp_best_path(dut, local_asn, user_command, cli_type="", config='yes'):
    """

    :param dut:
    :param local_asn:
    :param user_command:
    :return:
    """
    cli_type = get_cfg_cli_type(dut, cli_type=cli_type)
    if cli_type in get_supported_ui_type_list():
        kwargs = dict()
        kwargs['cli_type'] = cli_type
        kwargs['best_path_cmd'] = user_command
        return config_bgp_router(dut, local_asn=local_asn, config=config, **kwargs)

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
        if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=route_selection_data):
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
    if cli_type in get_supported_ui_type_list():
        kwargs = dict()
        kwargs['skip_error_check'] = skip_error_check
        kwargs['client_client_reflection'] = 1
        return config_bgp_router(dut, local_asn=local_asn, cli_type=cli_type, config=config, **kwargs)

    cfgmode = 'no' if config != 'yes' else ''
    config_router_bgp_mode(dut, local_asn, cli_type=cli_type)
    if cli_type == "vtysh":
        command = "{} bgp client-to-client reflection".format(cfgmode)
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
        if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=global_data):
            st.error("Error in configuring client to client reflection")
            return False
        return True
    else:
        st.error("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
        return False


def create_bgp_route_reflector_client(dut, local_asn, addr_family, nbr_ip, config='yes', cli_type="", skip_error_check=True, ebgp_req_policy=False, **kwargs):
    """
    :param dut:
    :param local_asn:
    :param addr_family:
    :param nbr_ip:
    :return:
    """
    cli_type = get_cfg_cli_type(dut, cli_type=cli_type)
    cfgmode = 'no' if config != 'yes' else ''
    vrf = kwargs.get('vrf', 'default')

    if cli_type in get_supported_ui_type_list():
        kwargs['config'] = config
        kwargs['skip_error_check'] = skip_error_check
        kwargs['ebgp_req_policy'] = ebgp_req_policy
        kwargs['rr_client'] = 1

        if re.findall(r'Ethernet|Vlan|PortChannel|Eth', nbr_ip) or addr_family == 'l2vpn' or is_valid_ip_address(nbr_ip, addr_family):
            kwargs['peergroup'] = None
        else:
            kwargs['peergroup'] = nbr_ip
            nbr_ip = None
        return config_bgp_neighbor_properties(dut, local_asn=local_asn, neighbor_ip=nbr_ip, family=addr_family, **kwargs)

    config_router_bgp_mode(dut, local_asn, vrf=vrf, cli_type=cli_type, ebgp_req_policy=ebgp_req_policy)
    if cli_type == "vtysh":
        command = "address-family {} {}".format(addr_family, "unicast")
        command += "\n {} neighbor {} route-reflector-client".format(cfgmode, nbr_ip)
        st.config(dut, command, type=cli_type)
        return True
    elif cli_type == "klish":
        addr_family_type = "unicast"
        neigh_name = nbr_ip
        commands = list()
        if re.findall(r'Ethernet|Vlan|PortChannel|Eth', nbr_ip):
            neigh_name = get_interface_number_from_name(nbr_ip)
            commands.append("neighbor interface {} {}".format(neigh_name["type"], neigh_name["number"]))
        elif addr_family == 'l2vpn':
            commands.append("neighbor {}".format(nbr_ip))
        elif is_valid_ip_address(neigh_name, 'ipv4') or is_valid_ip_address(neigh_name, 'ipv6'):
            commands.append("neighbor {}".format(nbr_ip))
        else:
            commands.append("peer-group {}".format(nbr_ip))
        if addr_family == 'l2vpn':
            addr_family_type = "evpn"
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
            neigh_data["config"] = dict()
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

        if not config_rest(dut, rest_url=url, http_method=cli_type, json_data=route_reflector_data):
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
    if cli_type in get_supported_ui_type_list():
        kwargs = dict()
        kwargs['force'] = force
        kwargs['config'] = config
        kwargs['cli_type'] = cli_type
        kwargs['skip_error_check'] = skip_error_check
        kwargs['nh_self'] = 1

        if re.findall(r'Ethernet|Vlan|PortChannel|Eth', nbr_ip) or addr_family == 'l2vpn' or is_valid_ip_address(nbr_ip, addr_family):
            kwargs['peergroup'] = None
        else:
            kwargs['peergroup'] = nbr_ip
            nbr_ip = None
        return config_bgp_neighbor_properties(dut, local_asn=local_asn, neighbor_ip=nbr_ip, family=addr_family, **kwargs)

    cfgmode = 'no' if config != 'yes' else ''
    config_router_bgp_mode(dut, local_asn, cli_type=cli_type)
    if cli_type == "vtysh":
        command = "address-family {} {}".format(addr_family, "unicast")
        command += "\n {} neighbor {} next-hop-self".format(cfgmode, nbr_ip)
        if force == 'yes':
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
                neigh_data["config"] = dict()
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

            if not config_rest(dut, rest_url=url, http_method=cli_type, json_data=route_reflector_data):
                st.error("Error while configuring next hop self")
                return False
            return True
        else:
            result = True
            url = rest_urls['bgp_del_neighbor_config'].format(vrf, nbr_ip)
            if not delete_rest(dut, rest_url=url):
                st.error("Deleting neighbor with address failed")
                result = False
            url = rest_urls['bgp_peer_group_name_config'].format(vrf, nbr_ip)
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
    # API_Not_Used: To Be removed in CyrusPlus
    """

    :param dut:
    :param local_asn:
    :param cluster_id:
    :param cluster_ip:
    :return:
    """
    # No usage in test scripts
    config_router_bgp_mode(dut, local_asn)
    command = "bgp cluster-id {}".format(cluster_id)
    st.config(dut, command, type='vtysh')
    command = "bgp cluster-id {}".format(cluster_ip)
    st.config(dut, command, type='vtysh')


def create_bgp_confideration(dut, local_asn, confd_id_as, confd_peers_as):
    # API_Not_Used: To Be removed in CyrusPlus
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
    # API_Not_Used: To Be removed in CyrusPlus
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
    cli_type = "klish" if cli_type in get_supported_ui_type_list() else cli_type
    cfgmode = 'no' if config != 'yes' else ''
    config_router_bgp_mode(dut, local_asn, cli_type=cli_type)
    if cli_type == "vtysh":
        command = "{} bgp default {}".format(cfgmode, user_command)
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
        commands.append("{} default {}".format(cfgmode, user_command))
        commands.append("exit")
        st.config(dut, commands, type=cli_type, skip_error_check=skip_error_check)
        return True
    elif cli_type in ["rest-patch", "rest-put"]:

        data = dict()
        data["openconfig-network-instance:bgp"] = dict()
        data["openconfig-network-instance:bgp"]["global"] = dict()
        data["openconfig-network-instance:bgp"]["global"]["config"] = dict()
        data["openconfig-network-instance:bgp"]["global"]["config"].update({"as": int(local_asn)})
        data["openconfig-network-instance:bgp"]["global"]["afi-safis"] = dict()
        data["openconfig-network-instance:bgp"]["global"]["afi-safis"]["afi-safi"] = list()
        data["openconfig-network-instance:bgp"]["global"]["openconfig-bgp-ext:global-defaults"] = dict()
        data_sub = dict()
        data_sub["config"] = dict()

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
        url = st.get_datastore(dut, "rest_urls")['bgp_config'].format("default")
        if not config_rest(dut, rest_url=url, http_method=cli_type, json_data=data):
            st.error("bgp default router config failed")
            return False
        return True
    else:
        st.error("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
        return False


def config_bgp_always_compare_med(dut, local_asn, config='yes', cli_type="", **kwargs):
    """

    :param dut:
    :param local_asn:
    :return:
    """
    cli_type = get_cfg_cli_type(dut, cli_type=cli_type)
    if cli_type in get_supported_ui_type_list():
        kwargs['always_comp_med'] = True
        kwargs['cli_type'] = cli_type
        return config_bgp_router(dut, local_asn=local_asn, config=config, **kwargs)

    if "vrf" not in kwargs:
        config_router_bgp_mode(dut, local_asn, cli_type=cli_type)
    else:
        config_router_bgp_mode(dut, local_asn, 'enable', kwargs["vrf"], cli_type=cli_type)

    if cli_type == "vtysh":
        if config == 'yes':
            command = "bgp always-compare-med"
        else:
            command = "no bgp always-compare-med"
        st.config(dut, command, type=cli_type)
    elif cli_type == 'klish':
        command = list()
        if config == 'yes':
            command.append("always-compare-med")
        else:
            command.append("no always-compare-med")
        command.append('exit')
        st.config(dut, command, type=cli_type)
    elif cli_type in ["rest-patch", "rest-put"]:
        if config == 'yes':
            url = st.get_datastore(dut, "rest_urls")["bgp_config"]
            data = {"openconfig-network-instance:bgp": {"global": {"config": {"as": int(local_asn)},
                                                                   "route-selection-options": {
                                                                       "config": {"always-compare-med": True}}}}}
            if not config_rest(dut, rest_url=url.format("default"), http_method=cli_type, json_data=data):
                st.error("failed to configure always compare med")
                return False
        else:
            url = st.get_datastore(dut, "rest_urls")["bgp_config_med"].format("default")
            if not delete_rest(dut, rest_url=url):
                st.error("no form of compare med failed")
                return False
            return True
    else:
        st.error("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
        return False
    return True


def config_bgp_deterministic_med(dut, local_asn, config='yes', cli_type=''):
    """

    :param dut:
    :param local_asn:
    :return:
    """
    cli_type = get_cfg_cli_type(dut, cli_type=cli_type)
    if cli_type in get_supported_ui_type_list():
        kwargs = dict()
        kwargs['cli_type'] = cli_type
        kwargs['deterministic_med'] = True
        return config_bgp_router(dut, local_asn=local_asn, config=config, **kwargs)

    config_router_bgp_mode(dut, local_asn, cli_type=cli_type)
    command = ""
    if cli_type == "vtysh":
        if config == 'yes':
            command = "bgp deterministic-med"
        else:
            command = "no bgp deterministic-med"
    elif cli_type == "klish":
        command = list()
        if config == 'yes':
            command.append("deterministic-med")
        else:
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
    # API_Not_Used: To Be removed in CyrusPlus
    """

    :param dut:
    :param local_asn:
    :return:
    """
    # No script usage
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
    preserve_state = kwargs.get('preserve_state', None)
    vrf = kwargs.get('vrf', "default")
    skip_error_check = kwargs.get("skip_error_check", True)
    cli_type = get_cfg_cli_type(dut, **kwargs)
    command = ""
    if "local_asn" not in kwargs and "config" not in kwargs:
        st.error("Mandatory params not provided")
        return False
    if kwargs.get("config") not in ["add", "delete"]:
        st.log("Unsupported ACTION")
        return False

    if cli_type in get_supported_ui_type_list():
        config = 'yes' if kwargs.pop('config') == 'add' else 'no'
        local_asn = kwargs.pop('local_asn')
        kwargs['graceful_restart'] = True
        return config_bgp_router(dut, local_asn=local_asn, config=config, **kwargs)

    config_router_bgp_mode(dut, kwargs["local_asn"], vrf=vrf, cli_type=cli_type)
    mode = "no" if kwargs.get("config") != "add" else ""
    bgp_mode = "bgp" if cli_type == "vtysh" else ""
    if cli_type == 'vtysh':
        command = "{} {} graceful-restart\n".format(mode, bgp_mode)
    if cli_type == 'klish':
        command = "{} graceful-restart enable\n".format(mode)
        if "user_command" in kwargs:
            command += "{} graceful-restart {}\n".format(mode, kwargs["user_command"])
    if preserve_state is not None:
        command += "{} {} graceful-restart preserve-fw-state\n".format(mode, bgp_mode)
    if cli_type == 'klish':
        command += "exit\n"
    if cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        data = dict()
        data["openconfig-network-instance:bgp"] = dict()
        data["openconfig-network-instance:bgp"]["global"] = dict()
        data["openconfig-network-instance:bgp"]["global"]["graceful-restart"] = dict()
        if mode != 'no':
            data["openconfig-network-instance:bgp"]["global"]["graceful-restart"]["config"] = dict()
            data["openconfig-network-instance:bgp"]["global"]["graceful-restart"]["config"].update({"enabled": True})
            if preserve_state is not None:
                data["openconfig-network-instance:bgp"]["global"]["graceful-restart"]["config"].update({"openconfig-bgp-ext:preserve-fw-state": True})
            else:
                url = rest_urls['bgp_del_graceful'].format(vrf)
                if not delete_rest(dut, rest_url=url):
                    st.error("failed unconfig graceful restart")
            url = rest_urls['bgp_config'].format(vrf)
            if not config_rest(dut, rest_url=url, http_method=cli_type, json_data=data):
                st.error("unable enable graceful restart")
                return False
            return True
        else:
            url = rest_urls['bgp_del_grace'].format(vrf)
            if not delete_rest(dut, rest_url=url):
                st.error("unable to disable graceful restart")
                return False
            return True

    st.config(dut, command, type=cli_type, skip_error_check=skip_error_check)


def config_bgp_graceful_shutdown(dut, local_asn, config="add", **kwargs):
    """

    :param dut:
    :param local_asn:
    :return:
    """
    cli_type = get_cfg_cli_type(dut, **kwargs)
    skip_error_check = kwargs.get("skip_error_check", True)

    if cli_type in get_supported_ui_type_list():
        kwargs = dict()
        config = 'yes' if config == 'add' else 'no'
        kwargs['cli_type'] = cli_type
        kwargs['skip_error_check'] = skip_error_check
        kwargs['graceful_shutdown'] = True
        return config_bgp_router(dut, local_asn=local_asn, config=config, **kwargs)

    mode = "no" if config != "add" else ""
    bgp_mode = "bgp" if cli_type == "vtysh" else ""
    if cli_type == 'vtysh':
        config_router_bgp_mode(dut, local_asn, cli_type=cli_type)
        command = "{} {} graceful-shutdown\n".format(mode, bgp_mode)
        command += "exit\n"
        st.config(dut, command, type=cli_type, skip_error_check=skip_error_check)
    elif cli_type == 'klish':
        config_router_bgp_mode(dut, local_asn, cli_type=cli_type)
        command = "{} graceful-shutdown\n".format(mode)
        command += "exit\n"
        st.config(dut, command, type=cli_type, skip_error_check=skip_error_check)
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        data = {"openconfig-bgp-ext:graceful-shutdown": True}
        if mode != 'no':
            url = rest_urls['bgp_config_graceful_shut'].format("default")
            if not config_rest(dut, rest_url=url, http_method=cli_type, json_data=data):
                st.error("failed to config graceful shutdown")
                return False
            return True
        else:
            url = rest_urls['bgp_del_graceful_shut'].format("default")
            if not delete_rest(dut, rest_url=url):
                st.error("failed to delete graceful shutdown")
                return False
            return True


def config_bgp_listen(dut, local_asn, neighbor_address, subnet, peer_grp_name, limit, config='yes', cli_type="", skip_error_check=True, ebgp_req_policy=False, vrf='default'):
    """

    :param dut:
    :param local_asn:
    :param neighbor_address:
    :param limit:
    :return:
    """
    cli_type = get_cfg_cli_type(dut, cli_type=cli_type)
    config_router_bgp_mode(dut, local_asn, vrf=vrf, cli_type=cli_type, ebgp_req_policy=ebgp_req_policy)
    # Verify IPV4/IPV6 address pattern for neighbor address
    mode = "" if config.lower() == 'yes' else "no"
    if cli_type in get_supported_ui_type_list():
        ni_obj = umf_ni.NetworkInstance(Name=vrf)
        proto_obj = umf_ni.Protocol(ProtoIdentifier='BGP', Name='bgp', NetworkInstance=ni_obj)
        if mode != 'no' and peer_grp_name != '':
            operation = Operation.CREATE
            pg_obj = umf_ni.PeerGroup(PeerGroupName=peer_grp_name, Protocol=proto_obj)
            result = pg_obj.configure(dut, operation=operation, cli_type=cli_type)
            if not result.ok():
                st.log('test_step_failed: Configuring PeerGroup: {}'.format(result.data))
                return False
        if neighbor_address:
            prefix = '{}/{}'.format(neighbor_address, subnet)
            dyn_neigh_obj = umf_ni.DynamicNeighborPrefix(Prefix=prefix, PeerGroup=peer_grp_name, Protocol=proto_obj)
            if mode != 'no':
                result = dyn_neigh_obj.configure(dut, operation=operation, cli_type=cli_type)
            else:
                result = dyn_neigh_obj.unConfigure(dut, target_attr=dyn_neigh_obj.PeerGroup, cli_type=cli_type)
            if not result.ok():
                st.log('test_step_failed: Configuring BGP Listen Range: {}'.format(result.data))
                return False
        if limit:
            loc_kwargs = dict()
            loc_kwargs['cli_type'] = cli_type
            loc_kwargs['max_dyn_nbr'] = int(limit)
            return config_bgp_router(dut, local_asn=local_asn, config=config, **loc_kwargs)
        return True

    elif cli_type == "vtysh":
        if neighbor_address:
            command = "{} bgp listen range {}/{} peer-group {}".format(mode, neighbor_address, subnet, peer_grp_name)
            st.config(dut, command, type=cli_type, skip_error_check=skip_error_check)
        if limit:
            command = "{} bgp listen limit {}".format(mode, limit)
            st.config(dut, command, type=cli_type, skip_error_check=skip_error_check)
    elif cli_type == "klish":
        cmd = []
        if neighbor_address:
            if mode != 'no':
                cmd = ['peer-group {}'.format(peer_grp_name), 'exit']
            command = "{} listen range {}/{} peer-group {}".format(mode, neighbor_address, subnet, peer_grp_name)
            cmd.append(command)
        if limit:
            command = "{} listen limit {}".format(mode, limit)
            cmd.append(command)
        cmd.append("exit")
        st.config(dut, cmd, type=cli_type, skip_error_check=skip_error_check)
    elif cli_type in ["rest-patch", "rest-put"]:
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
                url = st.get_datastore(dut, "rest_urls")['bgp_config'].format("default")
                if not config_rest(dut, rest_url=url, http_method=cli_type, json_data=config_data):
                    st.error("unable to config bgp listen")

            else:

                url = st.get_datastore(dut, "rest_urls")['bgp_del_dyn'].format("default")
                if not delete_rest(dut, rest_url=url):
                    st.error("unable to delete BGP listen config")

        if limit:
            if mode != 'no':
                config_data = {"openconfig-network-instance:max-dynamic-neighbors": limit}
                url = st.get_datastore(dut, "rest_urls")['bgp_config_dyn'].format("default")
                response = config_rest(dut, rest_url=url, http_method=cli_type, json_data=config_data)

            else:
                url = st.get_datastore(dut, "rest_urls")['bgp_del_dyn'].format("default")
                response = delete_rest(dut, rest_url=url)

            if not response:
                st.log(response)
                return False
            return True
    else:
        st.error("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
        return False


def config_bgp_listen_range(dut, local_asn, **kwargs):
    """

    :param dut:
    :param local_asn:
    :param neighbor_address:
    :param limit:
    :return:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    # cli_type = _get_cli_type(cli_type)
    neighbor_address = kwargs.get('neighbor_address', '')
    subnet = str(kwargs.get('subnet', ''))
    peer_grp_name = kwargs.get('peer_grp_name', '')
    limit = kwargs.get('limit', '')
    config = kwargs.get('config', 'yes')
    vrf = kwargs.get('vrf', 'default')
    skip_error_check = kwargs.get('skip_error_check', True)
    ebgp_req_policy = kwargs.get('ebgp_req_policy', False)
    if config.lower() == 'yes':
        mode = ""
    else:
        mode = 'no'
    cmd = ''

    if cli_type in get_supported_ui_type_list():
        return config_bgp_listen(dut, local_asn=local_asn, neighbor_address=neighbor_address, subnet=subnet, peer_grp_name=peer_grp_name, limit=limit, config=config, cli_type=cli_type, skip_error_check=skip_error_check, ebgp_req_policy=ebgp_req_policy, vrf=vrf)

    config_router_bgp_mode(dut, local_asn, vrf=vrf, cli_type=cli_type, ebgp_req_policy=ebgp_req_policy)
    if cli_type == 'vtysh' or cli_type == 'click':
        if neighbor_address:
            cmd = cmd + "{} bgp listen range {}/{} peer-group {}\n".format(mode, neighbor_address, subnet, peer_grp_name)
        if limit:
            cmd = cmd + "{} bgp listen limit {}".format(mode, limit)
        st.config(dut, cmd, type='vtysh', skip_error_check=skip_error_check)
        return True
    elif cli_type == "klish":
        if neighbor_address:
            cmd = cmd + "{} listen range {}/{} peer-group {}\n".format(mode, neighbor_address, subnet, peer_grp_name)
        if limit:
            cmd = cmd + "{} listen limit {}\n".format(mode, limit)
        cmd = cmd + "exit\n"
        st.config(dut, cmd, type=cli_type, skip_error_check=skip_error_check, conf=True)
        return True
    elif cli_type in ['rest-patch', 'rest-put']:
        http_method = kwargs.pop('http_method', cli_type)
        rest_urls = st.get_datastore(dut, 'rest_urls')
        if neighbor_address:
            dynamic_prefix = neighbor_address + '/' + subnet
            if mode == '':
                rest_url = rest_urls['bgp_dynamic_neigh_prefix'].format(vrf)
                ocdata = {"openconfig-network-instance:dynamic-neighbor-prefixes": {"dynamic-neighbor-prefix": [{"prefix": dynamic_prefix, "config": {"prefix": dynamic_prefix, "peer-group": peer_grp_name}}]}}
                response = config_rest(dut, http_method=http_method, rest_url=rest_url, json_data=ocdata)
            elif mode == 'no':
                rest_url = rest_urls['bgp_dynamic_neigh_prefix'].format(vrf)
                response = delete_rest(dut, rest_url=rest_url)
        if limit:
            if mode == '':
                rest_url = rest_urls['bgp_max_dynamic_neighbors'].format(vrf)
                ocdata = {"openconfig-bgp-ext:max-dynamic-neighbors": int(limit)}
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
    cli_type = st.get_ui_type(dut)
    cli_type = "vtysh" if cli_type == "click" else cli_type
    vrf_name = "default"
    if cli_type in get_supported_ui_type_list():
        ni_obj = umf_ni.NetworkInstance(Name=vrf_name)
        proto_obj = umf_ni.Protocol(ProtoIdentifier='BGP', As=int(local_asn), Name='bgp', NetworkInstance=ni_obj, LogNeighborStateChanges=True)
        rv = proto_obj.configure(dut, cli_type=cli_type)
        if rv.ok():
            st.log("Configuring log neighbor changes - SUCCESS")
            return True
        else:
            st.log("Configuring log neighbor changes - FAILED")
            return False
    elif cli_type in ["vytsh", "klish"]:
        config_router_bgp_mode(dut, local_asn)
        command = "bgp log-neighbor-changes\n" if cli_type == "vtysh" else "log-neighbor-changes\n"
        command += 'exit\n'
        st.config(dut, command, type=cli_type)
        return True
    else:
        st.error("UNSUPPORTED CLI TYPE")
        return False


def config_bgp_max_med(dut, local_asn, config='yes', **kwargs):
    """

    :param dut:
    :param local_asn:
    :param user_command:
    :return:
    :usage: config_bgp_max_med(dut=dut7,cli_type='klish',config="yes",local_asn="300", on_start_time=10,on_start_med=40,administrative_med=65)
    :usage: config_bgp_max_med(dut=dut7,cli_type='click',config="no",local_asn="300",administrative_med=65)
    """
    cli_type = get_cfg_cli_type(dut, **kwargs)
    if cli_type in get_supported_ui_type_list():
        return config_bgp_router(dut, local_asn=local_asn, config=config, **kwargs)

    command = ''
    if cli_type == 'vtysh':
        config_router_bgp_mode(dut, local_asn, cli_type=cli_type)
        if config == 'yes':
            if 'on_start_time' in kwargs and 'on_start_med' in kwargs:
                command += "bgp max-med on-startup {} {}\n".format(kwargs['on_start_time'], kwargs['on_start_med'])
            elif 'on_start_time' in kwargs:
                command += "bgp max-med on-startup {}\n".format(kwargs['on_start_time'])
            if 'administrative_med' in kwargs:
                command += "bgp max-med administrative {}\n".format(kwargs['administrative_med'])
        else:
            if 'on_start_time' in kwargs and 'on_start_med' in kwargs:
                command += "no bgp max-med on-startup {} {}\n".format(kwargs['on_start_time'], kwargs['on_start_med'])
            elif 'on_start_time' in kwargs:
                command += "no bgp max-med on-startup {}\n".format(kwargs['on_start_time'])
            if 'administrative_med' in kwargs:
                command += "no bgp max-med administrative {}\n".format(kwargs['administrative_med'])
        command += 'exit\n'
        st.config(dut, command.split("\n"), type=cli_type)
    elif cli_type == 'klish':
        config_router_bgp_mode(dut, local_asn, cli_type=cli_type)
        if config == 'yes':
            if 'on_start_time' in kwargs and 'on_start_med' in kwargs:
                command += "max-med on-startup {} {}\n".format(kwargs['on_start_time'], kwargs['on_start_med'])
            elif 'on_start_time' in kwargs:
                command += "max-med on-startup {}\n".format(kwargs['on_start_time'])
            if 'administrative_med' in kwargs:
                command += "max-med administrative {}\n".format(kwargs['administrative_med'])
        else:
            if 'on_start_time' in kwargs and 'on_start_med' in kwargs:
                command += "no max-med on-startup {} {}\n".format(kwargs['on_start_time'], kwargs['on_start_med'])
            elif 'on_start_time' in kwargs:
                command += "no max-med on-startup {}\n".format(kwargs['on_start_time'])
            if 'administrative_med' in kwargs:
                command += "no max-med administrative {}\n".format(kwargs['administrative_med'])
        command += 'exit\n'
        st.config(dut, command.split("\n"), type=cli_type)

    elif cli_type in ["rest-patch", "rest-put"]:
        config_router_bgp_mode(dut, local_asn, cli_type=cli_type)
        data = dict()
        data["openconfig-network-instance:config"] = dict()
        if config == 'yes':
            if 'on_start_time' in kwargs and 'on_start_med' in kwargs:
                data["openconfig-network-instance:config"].update({"max-med-val": kwargs['on_start_med'], "time": kwargs['on_start_time']})
            elif 'on_start_time' in kwargs:
                data["openconfig-network-instance:config"].update({"time": kwargs['on_start_time']})
            if 'administrative_med' in kwargs:
                data["openconfig-network-instance:config"].update({"administrative": kwargs['administrative_med']})
            url = st.get_datastore(dut, "rest_urls")['bgp_max_med'].format("default")
            if not config_rest(dut, rest_url=url, http_method=cli_type, json_data=data):
                st.error("failed to confgi max med")
                return False
            return True

        else:
            if 'on_start_time' in kwargs and 'on_start_med' in kwargs:
                url = st.get_datastore(dut, "rest_urls")['bgp_del_med'].format("default")
                if not delete_rest(dut, rest_url=url):
                    st.error("failed to delete med on start time")
                    return False
            elif 'on_start_time' in kwargs:
                url = st.get_datastore(dut, "rest_urls")['bgp_del_med'].format("default")
                if not delete_rest(dut, rest_url=url):
                    st.error("failed to delete med on start time")
                    return False
            if 'administrative_med' in kwargs:
                url = st.get_datastore(dut, "rest_urls")['bgp_del_med_ad'].format("default")
                if not delete_rest(dut, rest_url=url):
                    st.error("failed to delete med on start time")
                    return False
                return True
    else:
        st.log("Unsupported CLI TYPE - {}".format(cli_type))
        return False
    return True


def config_route_map_delay_timer(dut, local_asn, timer):
    # API_Not_Used: To Be removed in CyrusPlus
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


def enable_address_family_mode(dut, local_asn, mode_type, mode, cli_type=''):
    # API_Not_Used: To Be removed in CyrusPlus
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
    # API_Not_Used: To Be removed in CyrusPlus
    """

    :param dut:
    :param local_asn:
    :param mode_type:
    :param mode:
    :param neighbor_ip:
    :param user_command:
    :return:
    """
    # No script usage
    enable_address_family_mode(dut, local_asn, mode_type, mode)
    # Verify neighbor IP address
    command = "neighbor {} {}".format(neighbor_ip, user_command)
    st.config(dut, command, type='vtysh')


def create_bgp_peergroup(dut, local_asn, peer_grp_name, remote_asn, keep_alive=60, hold=180, password=None, vrf='default', family='ipv4', skip_error_check=True, **kwargs):
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
    neighbor_ip = kwargs.get('neighbor_ip', None)
    ebgp_multihop = kwargs.get('ebgp_multihop', None)
    update_src = kwargs.get('update_src', None)
    update_src_intf = kwargs.get('update_src_intf', None)
    connect = kwargs.get('connect', None)
    ebgp_req_policy = kwargs.get('ebgp_req_policy', False)
    st.log("Creating BGP peer-group ..")
    cmd = ''
    config = kwargs.get('config', 'yes')

    if cli_type in get_supported_ui_type_list():
        kwargs['peergroup'] = peer_grp_name
        kwargs['remote_asn'] = remote_asn
        kwargs['keep_alive'] = keep_alive
        kwargs['hold'] = hold
        kwargs['password'] = password
        kwargs['vrf'] = vrf
        kwargs['skip_error_check'] = skip_error_check
        kwargs['activate'] = 'af_default'
        neighbor_ip = kwargs.pop('neighbor_ip', None)

        ni_obj = umf_ni.NetworkInstance(Name=vrf)
        proto_obj = umf_ni.Protocol(ProtoIdentifier='BGP', Name='bgp', NetworkInstance=ni_obj)
        if config == 'yes':
            operation = Operation.CREATE
            config_bgp_neighbor_properties(dut, local_asn=local_asn, neighbor_ip=None, family=family, **kwargs)
            if neighbor_ip is not None:
                nbr_obj = umf_ni.BgpNeighbor(NeighborAddress=neighbor_ip, PeerGroup=peer_grp_name, NeighborEnabled=True, Protocol=proto_obj)
                result = nbr_obj.configure(dut, operation=operation, cli_type=cli_type)
                if not result.ok():
                    st.log('test_step_failed: Configure Neighbor with PeerGroup: {}'.format(result.data))
                    return False

        else:
            if neighbor_ip is not None:
                nbr_obj = umf_ni.BgpNeighbor(NeighborAddress=neighbor_ip, PeerGroup=peer_grp_name, NeighborEnabled=True, Protocol=proto_obj)
                result = nbr_obj.unConfigure(dut, target_attr=nbr_obj.PeerGroup, cli_type=cli_type)
                if not result.ok():
                    st.log('test_step_failed: Configure Neighbor with PeerGroup: {}'.format(result.data))
                    return False
            pg_obj = umf_ni.PeerGroup(PeerGroupName=peer_grp_name, Protocol=proto_obj)
            result = pg_obj.unConfigure(dut, cli_type=cli_type)
            if not result.ok():
                st.log('test_step_failed: Configure PeerGroup: {}'.format(result.data))
                return False

        return True
    config_router_bgp_mode(dut, local_asn, vrf=vrf, cli_type=cli_type, ebgp_req_policy=ebgp_req_policy)
    if cli_type == 'vtysh' or cli_type == 'click':
        cmd = cmd + "neighbor {} peer-group\n".format(peer_grp_name)
        cmd = cmd + "neighbor {} remote-as {}\n".format(peer_grp_name, remote_asn)
        cmd = cmd + "neighbor {} timers {} {}\n".format(peer_grp_name, keep_alive, hold)
        if password:
            cmd = cmd + " neighbor {} password {}\n".format(peer_grp_name, password)
        cmd = cmd + "\n address-family {} unicast\n".format(family)
        cmd = cmd + "\n neighbor {} activate\n".format(peer_grp_name)
        if connect is not None:
            cmd = cmd + 'neighbor {} timers connect {}\n'.format(peer_grp_name, connect)
        if ebgp_multihop is not None:
            cmd = cmd + 'neighbor {} ebgp-multihop {}\n'.format(peer_grp_name, ebgp_multihop)
        if update_src is not None:
            cmd = cmd + 'neighbor {} update-source {}\n'.format(peer_grp_name, update_src)
        if update_src_intf is not None:
            cmd = cmd + 'neighbor {} update-source {}\n'.format(peer_grp_name, update_src_intf)
        if neighbor_ip is not None:
            cmd = cmd + 'neighbor {} peer-group {}\n'.format(neighbor_ip, peer_grp_name)
        st.config(dut, cmd, type='vtysh', skip_error_check=skip_error_check)
        return True
    elif cli_type == "klish":
        neigh_name = get_interface_number_from_name(neighbor_ip)
        cmd = cmd + "peer-group {}\n".format(peer_grp_name)
        if neighbor_ip is not None:
            cmd = cmd + "exit\n"
            if neigh_name:
                if isinstance(neigh_name, dict):
                    cmd = cmd + 'neighbor interface {} {}\n'.format(neigh_name["type"], neigh_name["number"])
                else:
                    cmd = cmd + 'neighbor {}\n'.format(neigh_name)
            cmd = cmd + "peer-group {}\n".format(peer_grp_name)
        if connect is not None:
            cmd = cmd + 'timers connect {}\n'.format(connect)
        if ebgp_multihop is not None:
            cmd = cmd + 'ebgp-multihop {}\n'.format(ebgp_multihop)
        if update_src is not None:
            cmd = cmd + 'update-source {}\n'.format(update_src)
        if update_src_intf is not None:
            update_src_intf = get_interface_number_from_name(update_src_intf)
            if isinstance(update_src_intf, dict):
                cmd = cmd + 'update-source interface {} {}'.format(update_src_intf['type'], update_src_intf['number'])
        cmd = cmd + "remote-as {}\n".format(remote_asn)
        cmd = cmd + "address-family {} unicast\n".format(family)
        cmd = cmd + "activate\n"
        cmd = cmd + "exit\n"
        if family == "ipv6":
            cmd = cmd + "address-family ipv4 unicast\n"
            cmd = cmd + "activate\n"
            cmd = cmd + "exit\n"
        cmd = cmd + "timers {} {}\n".format(keep_alive, hold)
        cmd = cmd + "exit\n"
        cmd = cmd + "exit\n"
        st.config(dut, cmd, type=cli_type, skip_error_check=skip_error_check, conf=True)
        return True
    elif cli_type in ['rest-patch', 'rest-put']:
        http_method = kwargs.pop('http_method', cli_type)
        rest_urls = st.get_datastore(dut, 'rest_urls')
        rest_url_peergroup = rest_urls['bgp_peergroup_config'].format(vrf)
        rest_url_neighbor = rest_urls['bgp_neighbor_config'].format(vrf)
        if peer_grp_name is not None:
            ocdata = {"openconfig-network-instance:peer-groups": {"peer-group": [{"peer-group-name": peer_grp_name, "config": {"peer-group-name": peer_grp_name, "local-as": int(local_asn)}}]}}
            response = config_rest(dut, http_method=http_method, rest_url=rest_url_peergroup, json_data=ocdata)
            if not response:
                st.log('Peergroup config failed')
                st.log(response)
                return False
        if neighbor_ip is not None:
            ocdata = {'openconfig-network-instance:neighbors': {"neighbor": [{'neighbor-address': neighbor_ip, 'config': {'neighbor-address': neighbor_ip, 'peer-group': peer_grp_name, 'enabled': bool(1)}}]}}
            response = config_rest(dut, http_method=http_method, rest_url=rest_url_neighbor, json_data=ocdata)
            if not response:
                st.log('Peergroup config with Neighbor IP failed')
                st.log(response)
                return False
        if remote_asn is not None:
            if str(remote_asn).isdigit():
                ocdata = {"openconfig-network-instance:peer-groups": {"peer-group": [{"peer-group-name": peer_grp_name, "config": {"peer-as": int(remote_asn)}}]}}
            else:
                if remote_asn == "internal":
                    peer_type = "INTERNAL"
                else:
                    peer_type = "EXTERNAL"
                ocdata = {"openconfig-network-instance:peer-groups": {"peer-group": [{"peer-group-name": peer_grp_name, "config": {"peer-type": peer_type}}]}}
            response = config_rest(dut, http_method=http_method, rest_url=rest_url_peergroup, json_data=ocdata)
            if not response:
                st.log('Remote-as config in the Peergroup failed')
                st.log(response)
                return False
        if family is not None:
            if family == 'ipv4':
                ocdata = {"openconfig-network-instance:peer-groups": {"peer-group": [{"peer-group-name": peer_grp_name, "afi-safis": {"afi-safi": [{"afi-safi-name": "IPV4_UNICAST", "config": {"afi-safi-name": "IPV4_UNICAST", "enabled": bool(1)}}]}}]}}
            elif family == 'ipv6':
                ocdata = {"openconfig-network-instance:peer-groups": {"peer-group": [{"peer-group-name": peer_grp_name, "afi-safis": {"afi-safi": [{"afi-safi-name": "IPV6_UNICAST", "config": {"afi-safi-name": "IPV6_UNICAST", "enabled": bool(1)}}]}}]}}
            response = config_rest(dut, http_method=http_method, rest_url=rest_url_peergroup, json_data=ocdata)
            if not response:
                st.log('Address family activation in the Peergroup failed')
                st.log(response)
                return False
        if keep_alive is not None:
            ocdata = {"openconfig-network-instance:peer-groups": {"peer-group": [{"peer-group-name": peer_grp_name, "timers": {"config": {"hold-time": int(hold), "keepalive-interval": int(keep_alive)}}}]}}
            response = config_rest(dut, http_method=http_method, rest_url=rest_url_peergroup, json_data=ocdata)
            if not response:
                st.log('Keepalive and Hold timer config in the Peergroup failed')
                st.log(response)
                return False
        if ebgp_multihop is not None:
            ocdata = {"openconfig-network-instance:peer-groups": {"peer-group": [{"peer-group-name": peer_grp_name, "ebgp-multihop": {"config": {"enabled": bool(1), "multihop-ttl": int(ebgp_multihop)}}}]}}
            response = config_rest(dut, http_method=http_method, rest_url=rest_url_peergroup, json_data=ocdata)
            if not response:
                st.log('EBGP multihop config in the peergroup failed')
                st.log(response)
                return False
        if update_src is not None:
            ocdata = {"openconfig-network-instance:peer-groups": {"peer-group": [{"peer-group-name": peer_grp_name, "transport": {"config": {"local-address": update_src}}}]}}
            response = config_rest(dut, http_method=http_method, rest_url=rest_url_peergroup, json_data=ocdata)
            if not response:
                st.log('BGP update source config in the peergroup failed')
                st.log(response)
                return False
        if update_src_intf is not None:
            ocdata = {"openconfig-network-instance:peer-groups": {"peer-group": [{"peer-group-name": peer_grp_name, "transport": {"config": {"local-address": update_src_intf}}}]}}
            response = config_rest(dut, http_method=http_method, rest_url=rest_url_peergroup, json_data=ocdata)
            if not response:
                st.log('BGP update source interface config in the peergroup failed')
                st.log(response)
                return False
        if connect is not None:
            ocdata = {"openconfig-network-instance:peer-groups": {"peer-group": [{"peer-group-name": peer_grp_name, "timers": {"config": {"connect-retry": int(connect)}}}]}}
            response = config_rest(dut, http_method=http_method, rest_url=rest_url_peergroup, json_data=ocdata)
            if not response:
                st.log('BGP update source interface config in the peergroup failed')
                st.log(response)
                return False
        return True
    else:
        st.log("Unsupported CLI TYPE - {}".format(cli_type))
        return False


def remove_bgp_peergroup(dut, local_asn, peer_grp_name, remote_asn, vrf='default', **kwargs):
    """

    :param dut:
    :param local_asn:
    :param peer_grp_name:
    :param remote_asn:
    :return:
    """

    cli_type = get_cfg_cli_type(dut, **kwargs)

    if cli_type in get_supported_ui_type_list():
        return create_bgp_peergroup(dut, local_asn=local_asn, peer_grp_name=peer_grp_name, remote_asn=remote_asn, vrf=vrf, config='no', **kwargs)

    config_router_bgp_mode(dut, local_asn, vrf=vrf, cli_type=cli_type)
    cmd = ''
    neighbor_ip = kwargs.get('neighbor_ip', None)
    st.log("Removing BGP peer-group ..")
    if cli_type == 'vtysh' or cli_type == 'click':
        # Add validation for IPV4 / IPV6 address
        command = "no neighbor {} remote-as {}".format(peer_grp_name, remote_asn)
        st.config(dut, command, type='vtysh')
        command = "no neighbor {} peer-group".format(peer_grp_name)
        st.config(dut, command, type='vtysh')
    elif cli_type == 'klish':
        neigh_name = get_interface_number_from_name(neighbor_ip)
        if neighbor_ip is not None:
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


def config_bgp_peer_group(dut, local_asn, peer_grp_name, config="yes", vrf="default", cli_type="'", skip_error_check=True, **kwargs):
    cli_type = get_cfg_cli_type(dut, cli_type=cli_type)
    if cli_type in get_supported_ui_type_list():
        return create_bgp_peergroup(dut, local_asn=local_asn, peer_grp_name=peer_grp_name, remote_asn=None, config=config, **kwargs)

    ebgp_req_policy = kwargs.get('ebgp_req_policy', False)
    config_router_bgp_mode(dut, local_asn, vrf=vrf, cli_type=cli_type, ebgp_req_policy=ebgp_req_policy)
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


def create_bgp_neighbor_use_peergroup(dut, local_asn, peer_grp_name, neighbor_ip, family="ipv4", vrf='default', cli_type="", skip_error_check=True, **kwargs):
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
    ebgp_req_policy = kwargs.get('ebgp_req_policy', False)
    # Add validation for IPV4 / IPV6 address
    if cli_type in get_supported_ui_type_list():
        kwargs['peergroup'] = peer_grp_name
        kwargs['vrf'] = vrf
        kwargs['skip_error_check'] = skip_error_check
        activate = kwargs.get('activate', 'af_default')
        kwargs['activate'] = activate
        kwargs['cli_type'] = cli_type
        config = kwargs.get('config', 'yes')
        if neighbor_ip is None:
            neighbor_ip = list()

        st.log('create_bgp_neighbor_use_peergroup: neighbor_ip: {}, kwargs: {}'.format(neighbor_ip, kwargs))
        ni_obj = umf_ni.NetworkInstance(Name=vrf)
        proto_obj = umf_ni.Protocol(ProtoIdentifier='BGP', Name='bgp', NetworkInstance=ni_obj)

        if config == 'yes':
            config_bgp_neighbor_properties(dut, local_asn=local_asn, neighbor_ip=None, family=family, **kwargs)

            for neighbor in make_list(neighbor_ip):
                operation = Operation.CREATE
                nbr_obj = umf_ni.BgpNeighbor(NeighborAddress=neighbor, PeerGroup=peer_grp_name, NeighborEnabled=True, Protocol=proto_obj)
                result = nbr_obj.configure(dut, operation=operation, cli_type=cli_type)
                if not result.ok():
                    st.log('test_step_failed: Configure Neighbor with PeerGroup: {}'.format(result.data))
                    return False
        else:
            for neighbor in make_list(neighbor_ip):
                nbr_obj = umf_ni.BgpNeighbor(NeighborAddress=neighbor, PeerGroup=peer_grp_name, NeighborEnabled=True, Protocol=proto_obj)
                result = nbr_obj.unConfigure(dut, target_attr=nbr_obj.PeerGroup, cli_type=cli_type)
                if not result.ok():
                    st.log('test_step_failed: Configure Neighbor with PeerGroup: {}'.format(result.data))
                    return False

            pg_obj = umf_ni.PeerGroup(PeerGroupName=peer_grp_name, Protocol=proto_obj)
            result = pg_obj.unConfigure(dut, cli_type=cli_type)
            if not result.ok():
                st.log('test_step_failed: Configure PeerGroup: {}'.format(result.data))
                return False

        return True

    config_router_bgp_mode(dut, local_asn, vrf=vrf, cli_type=cli_type, ebgp_req_policy=ebgp_req_policy)
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
    elif cli_type in ["rest-patch", "rest-put"]:
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
        # data["openconfig-network-instance:bgp"]["peer-groups"]["peer-group"].append(peer_data)
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
            peer_sub1 = dict()
            peer_sub1["config"] = dict()
            peer_sub1.update({"afi-safi-name": afi_safi_name})
            peer_sub1["config"].update({"afi-safi-name": afi_safi_name, "enabled": True})
            peer_data["afi-safis"]["afi-safi"].append(peer_sub1)
        neigh_data = dict()
        neigh_data.update({"neighbor-address": neighbor_ip})
        neigh_data["config"] = dict()
        neigh_data["config"].update({"neighbor-address": neighbor_ip, "peer-group": peer_grp_name})
        data["openconfig-network-instance:bgp"]["peer-groups"]["peer-group"].append(peer_data)
        data["openconfig-network-instance:bgp"]["neighbors"]["neighbor"].append(neigh_data)
        url = st.get_datastore(dut, "rest_urls")['bgp_config'].format(vrf)
        if not config_rest(dut, rest_url=url, http_method=cli_type, json_data=data):
            st.error("failed to config peer group")
            return False
        return True

    else:
        st.log("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
        return False


def create_bgp_neighbor_interface(dut, local_asn, interface_name, remote_asn, family, config='yes', cli_type="", **kwargs):
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
    if cli_type in get_supported_ui_type_list():
        kwargs['remote_asn'] = remote_asn
        kwargs['cli_type'] = cli_type
        kwargs['config'] = config
        kwargs['activate'] = 'af_only'

        return config_bgp_neighbor_properties(dut, local_asn, interface_name, family=family, mode='unicast', **kwargs)

    st.log("Creating bgp neighbor on interface")
    ebgp_req_policy = kwargs.get('ebgp_req_policy', False)
    if config.lower() == 'yes':
        mode = ""
    else:
        mode = 'no'
    # Add validation for IPV4 / IPV6 address
    config_router_bgp_mode(dut, local_asn, cli_type=cli_type, ebgp_req_policy=ebgp_req_policy)
    commands = list()
    if cli_type == "vtysh":
        commands.append("{} neighbor {} interface remote-as {}".format(mode, interface_name, remote_asn))
        if config == "yes":
            commands.append("address-family {} unicast".format(family))
            commands.append("{} neighbor {} activate".format(mode, interface_name))
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
            # Added
            commands.append("exit")
        else:
            commands.append("exit")
    elif cli_type in ["rest-patch", "rest-put"]:
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
            url = st.get_datastore(dut, "rest_urls")['bgp_config'].format("default")
            if not config_rest(dut, rest_url=url, http_method=cli_type, json_data=data):
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
            if not config_rest(dut, rest_url=url, http_method=cli_type, json_data=data):
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
    # API_Not_Used: To Be removed in CyrusPlus
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
    ebgp_req_policy = kwargs.get('ebgp_req_policy', False)

    if 'local_asn' not in kwargs or 'peer_grp_name' not in kwargs or 'remote_asn' not in kwargs \
            or 'neigh_ip_list' not in kwargs:
        st.error("Mandatory parameters are missing.")
        return False

    af = kwargs.get('family', 'ipv4')
    vrf = kwargs.get('vrf', 'default')

    neigh_ip_li = list(kwargs['neigh_ip_list']) if isinstance(kwargs['neigh_ip_list'], list) else \
        [kwargs['neigh_ip_list']]

    if cli_type in get_supported_ui_type_list():
        config = kwargs.get('config', 'yes')
        family = kwargs.get('family', 'ipv4')
        vrf = kwargs.get('vrf', 'default')
        local_asn = kwargs.pop('local_asn')
        kwargs['activate'] = 'af_only'
        peer_grp_name = kwargs.pop('peer_grp_name')
        for param in ['vrf', 'cli_type', 'family', 'config']:
            kwargs.pop(param, None)

        result = create_bgp_neighbor_use_peergroup(dut, local_asn=local_asn, peer_grp_name=peer_grp_name, neighbor_ip=neigh_ip_li, family=family, vrf=vrf, config=config, cli_type=cli_type, **kwargs)
        if not result:
            return result

        if 'redistribute' in kwargs:
            for redis_type in make_list(kwargs['redistribute']):
                result = config_address_family_redistribute(dut, local_asn=local_asn, mode_type=family, mode='unicast', value=redis_type, config=config, vrf=vrf, **kwargs)
                if not result:
                    return result

        if 'routemap' in kwargs:
            kwargs.pop('remote_asn', None)
            for nbr in neigh_ip_li:
                if re.findall(r'Ethernet|Vlan|PortChannel|Eth', nbr) or family == 'l2vpn' or is_valid_ip_address(nbr, family):
                    kwargs['peergroup'] = None
                else:
                    kwargs['peergroup'] = nbr
                    nbr = None
                result = config_bgp_neighbor_properties(dut, local_asn=local_asn, neighbor_ip=nbr, family=family, **kwargs)
                if not result:
                    return result

        return result

    config_router_bgp_mode(dut, kwargs['local_asn'], vrf=vrf, ebgp_req_policy=ebgp_req_policy, cli_type=cli_type)
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
        if 'activate' in kwargs or 'redistribute' in kwargs or 'routemap' in kwargs:
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
    elif cli_type in ["rest-patch", "rest-put"]:
        family = kwargs.get('family', None)
        local_asn = kwargs.get('local_asn', None)

        peergroup = kwargs.get('peer_grp_name', '')
        remote_as = kwargs.get('remote_asn', None)
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
            peer_data["timers"] = dict()
            peer_data["timers"]["config"] = dict()
            peer_data["timers"]["config"].update({"hold-time": int(holdtime), "keepalive-interval": int(keepalive)})

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
    cli_type = get_show_cli_type(dut, **kwargs)
    if cli_type in get_supported_ui_type_list():
        if isinstance(kwargs['neighbor'], list):
            if isinstance(kwargs['state'], str):
                kwargs['state'] = [kwargs['state']] * len(kwargs['neighbor'])
            for neigh in kwargs['neighbor']:
                pos = kwargs['neighbor'].index(neigh)
                kwargs['neighbor'] = kwargs['neighbor'][:pos] + [neigh.lstrip('*')] + kwargs['neighbor'][pos + 1:]
        else:
            kwargs['neighbor'] = kwargs['neighbor'].lstrip('*')
        if isinstance(kwargs['state'], list):
            for elem in kwargs['state']:
                pos = kwargs['state'].index(elem)
                if str(elem).isdigit():
                    kwargs['state'] = kwargs['state'][:pos] + ['Established'] + kwargs['state'][pos + 1:]
        elif isinstance(kwargs['state'], str):
            if kwargs['state'].isdigit():
                kwargs['state'] = 'Established'
        vrf = kwargs.pop('vrf') if 'vrf' in kwargs else "default"
        return verify_bgp_neigh_umf(dut, vrf=vrf, family=family, neighborip=kwargs['neighbor'],
                                    state=kwargs['state'], cli_type=cli_type)
    if cli_type in ["klish", "rest-patch", "rest-put"]:
        vrf = kwargs.pop('vrf') if 'vrf' in kwargs else "default"
        if family.lower() == 'ipv4':
            output = show_bgp_ipv4_summary_vtysh(dut, vrf=vrf, cli_type=cli_type)
        elif family.lower() == 'ipv6':
            output = show_bgp_ipv6_summary_vtysh(dut, vrf=vrf, cli_type=cli_type)
        else:
            st.log("Invalid family {}".format(family))
            return False
    if cli_type in ["click", "vtysh"]:
        if 'vrf' in kwargs:
            vrf = kwargs.pop('vrf')
            cmd = "show bgp vrf {} {} summary".format(vrf, family.lower())
        else:
            cmd = "show bgp {} summary".format(family.lower())

        if not st.is_feature_supported("show-bgp-summary-click-command", dut):
            output = st.show(dut, cmd, type="vtysh")
        else:
            output = st.show(dut, cmd)
    # st.debug(output)

    # Specifically checking neighbor state
    if 'neighbor' in kwargs and 'state' in kwargs:
        neigh_li = list(kwargs['neighbor']) if isinstance(kwargs['neighbor'], list) else [kwargs['neighbor']]
        for each_neigh in neigh_li:
            # For dynamic neighbor, removing *, as it is not displayed in klish
            if shell in ['klish', 'rest-patch', 'rest-put'] or cli_type in ['klish', 'rest-patch', 'rest-put']:
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
    # No usage in scripts, so no klish support added
    exec_mode = kwargs.pop("exec_mode", "")
    output = show_bgp_neighbor(dut, neighbor_ip, exec_mode=exec_mode)
    st.debug(output)
    for each in kwargs.keys():
        match = {each: kwargs[each]}
        entries = filter_and_select(output, None, match)
        if not entries:
            st.log("{} and {} is not match ".format(each, kwargs[each]))
            return False
    return True


def verify_bgp_ipv4_neighbor_vtysh(dut, neighbor_ip, **kwargs):
    # API_Not_Used: To Be removed in CyrusPlus
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
    # API_Not_Used: To Be removed in CyrusPlus
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


def config_address_family_redistribute(dut, local_asn, mode_type, mode, value, config='yes', vrf='default', skip_error_check=True, **kwargs):
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
    route_map = kwargs.get('route_map')

    if cli_type in get_supported_ui_type_list():
        family = mode_type
        redist_type = value.upper()
        if value.upper() == 'CONNECTED':
            redist_type = 'DIRECTLY_CONNECTED'

        ni_obj = umf_ni.NetworkInstance(Name=vrf)
        tbl_obj = umf_ni.TableConnection(SrcProtocol=redist_type, DstProtocol='BGP', AddressFamily=family.upper(), NetworkInstance=ni_obj)
        if route_map:
            tbl_obj.ImportPolicy = route_map

        if config == 'yes':
            operation = Operation.CREATE
            config_router_bgp_mode(dut, local_asn, vrf=vrf, cli_type=cli_type)

            if family == 'ipv4':
                afi_safi_name = 'IPV4_UNICAST'
            if family == 'ipv6':
                afi_safi_name = 'IPV6_UNICAST'
            if family == 'l2vpn':
                afi_safi_name = 'L2VPN_EVPN'
            proto_obj = umf_ni.Protocol(ProtoIdentifier='BGP', Name='bgp', NetworkInstance=ni_obj)
            gbl_afi_safi_obj = umf_ni.GlobalAfiSafi(AfiSafiName=afi_safi_name, Protocol=proto_obj)
            result = gbl_afi_safi_obj.configure(dut, cli_type=cli_type)

            result = tbl_obj.configure(dut, operation=operation, cli_type=cli_type)
        else:
            # result = tbl_obj.unConfigure(dut, target_attr=tbl_obj.SrcProtocol, cli_type=cli_type)
            result = tbl_obj.unConfigure(dut, cli_type=cli_type)

        if not result.ok():
            st.log('test_step_failed: Configure Redistribute: {}'.format(result.data))
            return False

        return True

    cfgmode = 'no' if config != 'yes' else ''
    cmd = ''
    config_router_bgp_mode(dut, local_asn, vrf=vrf, cli_type=cli_type)
    if cli_type == 'vtysh' or cli_type == 'click':
        cmd = cmd + "address-family {} {}".format(mode_type, mode)
        if route_map:
            cmd = cmd + "\n {} redistribute {} route-map {}".format(cfgmode, value, route_map)
        else:
            cmd = cmd + "\n {} redistribute {}".format(cfgmode, value)
        st.config(dut, cmd, type='vtysh', skip_error_check=skip_error_check)
        return True
    elif cli_type == "klish":
        cmd = cmd + 'address-family {} {}\n'.format(mode_type, mode)
        if route_map:
            cmd = cmd + "{} redistribute {} route-map {}\n".format(cfgmode, value, route_map)
        else:
            cmd = cmd + "{} redistribute {}\n".format(cfgmode, value)
        cmd = cmd + 'exit\nexit\n'
        st.config(dut, cmd, type=cli_type, skip_error_check=skip_error_check, conf=True)
        return True
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, 'rest_urls')

        # vrf_name1=""
        # vrf_name1=vrf.lower()
        vrf_name1 = vrf
        vrf_name1 = 'default' if vrf_name1 != vrf else vrf_name1
        family = mode_type
        if family == "ipv4":
            afi_safi_name = "openconfig-bgp-types:IPV4_UNICAST"
        elif family == "l2vpn":
            afi_safi_name = "L2VPN_EVPN"
        else:
            afi_safi_name = "openconfig-bgp-types:IPV6_UNICAST"
        data_asn = dict()
        data_asn["openconfig-network-instance:bgp"] = dict()
        data_asn["openconfig-network-instance:bgp"]["global"] = dict()
        data_asn["openconfig-network-instance:bgp"]["global"]["config"] = dict()
        data_asn["openconfig-network-instance:bgp"]["global"]["config"]["as"] = int(local_asn)
        data_asn["openconfig-network-instance:bgp"]["global"]["afi-safis"] = dict()
        data_asn["openconfig-network-instance:bgp"]["global"]["afi-safis"]["afi-safi"] = list()
        afi_data = dict()
        afi_data["config"] = dict()
        afi_data.update({"afi-safi-name": afi_safi_name})
        afi_data["config"].update({"afi-safi-name": afi_safi_name})
        data_asn["openconfig-network-instance:bgp"]["global"]["afi-safis"]["afi-safi"].append(afi_data)
        url = rest_urls['bgp_config'].format(vrf_name1)
        if not config_rest(dut, rest_url=url, http_method=cli_type, json_data=data_asn):
            st.error("failed to config local as")
        if value:
            if value == "connected":
                redist_type = value.upper()
                if redist_type == 'CONNECTED':
                    redist_type = 'DIRECTLY_CONNECTED'
            elif value == "static":
                redist_type = value.upper()
            elif value == "ospf":
                redist_type = value.upper()
            else:
                st.log("invalid redist type")

        if cfgmode != "no":
            if route_map:
                url = rest_urls["bgp_route_redistribute"].format(vrf_name1)
                data = {"openconfig-network-instance:table-connections": {"table-connection": [{
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
            url = st.get_datastore(dut, "rest_urls")['bgp_del_redist'].format(vrf_name1, redist_type, family.upper())
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
    config_bgp(dut = DUT1, local_as='100', neighbor ='192.168.3.2',config = 'yes',config_type_list =["bfd_profile"])
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
    router_id = kwargs.get('router_id', '')
    config_type_list = kwargs.get('config_type_list', [])
    neighbor = kwargs.get('neighbor', None)
    local_as = kwargs.get('local_as', None)
    remote_as = kwargs.get('remote_as', None)
    peergroup = kwargs.get('peergroup', '')
    pswd = kwargs.get('pswd', None)
    activate = kwargs.get('activate', None)
    nexthop_self = kwargs.get('nexthop_self', None)
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
    # failover = kwargs.get('failover', None)
    shutdown = kwargs.get('shutdown', None)
    # max_path = kwargs.get('max_path', None)
    redistribute = kwargs.get('redistribute', None)
    network = kwargs.get('network', None)
    password = kwargs.get('password', None)
    max_path_ibgp = kwargs.get('max_path_ibgp', None)
    max_path_ebgp = kwargs.get('max_path_ebgp', None)
    routeMap = kwargs.get('routeMap', None)
    distribute_list = kwargs.get('distribute_list', None)
    filter_list = kwargs.get('filter_list', None)
    prefix_list = kwargs.get('prefix_list', None)
    # import_vrf = kwargs.get('import_vrf', None)
    import_vrf_name = kwargs.get('import_vrf_name', None)
    # fast_external_failover = kwargs.get('fast_external_failover', None)
    bgp_bestpath_selection = kwargs.get('bgp_bestpath_selection', None)
    removeBGP = kwargs.get('removeBGP', 'no')
    diRection = kwargs.get('diRection', 'in')
    weight = kwargs.get('weight', None)
    allowas_in = kwargs.get("allowas_in", None)
# allowas_in: Not used in script so far
    neigh_local_as = kwargs.get("neigh_local_as", None)
    no_prepend = kwargs.get("no_prepend", "")
    replace_as = kwargs.get("replace_as", "")
    ebgp_req_policy = kwargs.get('ebgp_req_policy', False)
    bfd_profile = kwargs.get('bfd_profile', "")
    config_cmd = "" if config.lower() == 'yes' else "no"
    if 'import-check' in config_type_list:
        cli_type = "klish"
    if conf_identf != '' or conf_peers != '':
        cli_type = "klish"
    if cli_type in get_supported_ui_type_list():

        family = kwargs.get('addr_family', 'ipv4')
        neigh_name = get_interface_number_from_name(neighbor)
        if interface:
            intf_name = get_interface_number_from_name(interface)

        shutdown = kwargs.get("shutdown", None) if "shutdown" in config_type_list else None
        if config == 'yes':
            activate = kwargs.get("activate", 'af_default') if "activate" in config_type_list else 'af_default'
        else:
            # Avoid disable of neighbor unless config=no and config_type_list contains activate
            activate = kwargs.get("activate", None) if "activate" in config_type_list else None
        nexthop_self = kwargs.get("nexthop_self", True) if "nexthop_self" in config_type_list else None
        pswd = True if "pswd" in config_type_list else False
        update_src = kwargs.get("update_src", "") if "update_src" in config_type_list else ""
        update_src_intf = get_interface_number_from_name(update_src_intf)
        bfd = True if "bfd" in config_type_list else False
        first_as = True if "first_as" in config_type_list else False
        route_map = True if "routeMap" in config_type_list else False
        default_originate = True if "default_originate" in config_type_list else False
        removePrivateAs = True if "removePrivateAs" in config_type_list else False
        no_neighbor = "no" if kwargs.get("config") == "no" else ""

        # Configure attributes under router bpg and router-bgp-address-family
        local_asn = local_as
        bgp_router_kwargs = kwargs.copy()
        bgp_router_kwargs['family'] = family
        router_id = bgp_router_kwargs.pop('router_id', '')
        keep_alive = bgp_router_kwargs.pop('keepalive', 60)
        hold_time = bgp_router_kwargs.pop('holdtime', 180)
        bgp_router_kwargs.pop('config', None)

        if 'bgp_bestpath_selection' in bgp_router_kwargs:
            # This option hasn't been used in scripts.
            bgp_router_kwargs['best_path_cmd'] = bgp_router_kwargs.pop('bgp_bestpath_selection')
            if ('med missing-as-worst confed' or 'med missing-as-worst') in bgp_bestpath_selection:
                bgp_router_kwargs['best_path_cmd'] = 'med confed missing-as-worst'

        if 'import-check' in config_type_list:
            bgp_router_kwargs['network_import_check'] = True
        if 'multipath-relax' in config_type_list:
            bgp_router_kwargs['best_path_cmd'] = 'as-path multipath-relax'

        # This can be enhanced, call only if needed
        result = config_bgp_router(dut, local_asn=local_asn, router_id=router_id, keep_alive=keep_alive, hold=hold_time, config=config, **bgp_router_kwargs)
        if not result:
            return False

        if 'network' in kwargs:
            nw_kwargs = dict()
            nw_kwargs['vrf'] = vrf_name
            result = advertise_bgp_network(dut, local_asn=local_asn, network=network, config=config, family=family, cli_type=cli_type, **nw_kwargs)
            if not result:
                return False
        if 'import_vrf_name' in kwargs and config != 'no':
            result = config_bgp_router(dut, local_asn=local_asn, config=config, family=family,
                                       vrf_name=kwargs['vrf_name'], import_vrf=kwargs['import_vrf_name'])
            if not result:
                return False
        config_remote_as = True
        bgp_nbr = None
        nbr_kwargs = kwargs.copy()
        if neigh_name and not peergroup:
            bgp_nbr = neighbor

        if peergroup:
            create_bgp_neighbor_use_peergroup(dut, local_asn=local_asn, peer_grp_name=peergroup, neighbor_ip=None, family=family, vrf=vrf_name, cli_type=cli_type, config=config, activate=activate)
            bgp_nbr = peergroup
            if 'peergroup' in config_type_list and neigh_name:
                bgp_nbr = neighbor
                create_bgp_neighbor_use_peergroup(dut, local_asn=local_asn, peer_grp_name=peergroup, neighbor_ip=bgp_nbr, family=None, vrf=vrf_name, cli_type=cli_type, config=config, activate=activate)

        if config_remote_as and remote_as:
            if interface and not peergroup:
                bgp_nbr = interface
                config_remote_as = False

        # Configure attributes under neighbour and neighbor-address-family
        nbr_kwargs['activate'] = activate
        if 'keepalive' in nbr_kwargs:
            nbr_kwargs['keep_alive'] = nbr_kwargs.pop('keepalive')
        if 'holdtime' in nbr_kwargs:
            nbr_kwargs['hold'] = nbr_kwargs.pop('holdtime')
        if 'ebgp_mhop' in nbr_kwargs:
            nbr_kwargs['ebgp_multihop'] = nbr_kwargs.pop('ebgp_mhop')
        if 'remote_as' in nbr_kwargs:
            nbr_kwargs['remote_asn'] = nbr_kwargs.pop('remote_as')
        if 'shutdown' in nbr_kwargs:
            nbr_kwargs['neighbor_shutdown'] = nbr_kwargs.pop('shutdown')
#        if pswd: nbr_kwargs['password'] = nbr_kwargs.pop('password')
        if nexthop_self:
            nbr_kwargs['nh_self'] = True
        if 'routeMap' in nbr_kwargs:
            nbr_kwargs['route_map'] = nbr_kwargs.pop('routeMap')
            nbr_kwargs['route_map_dir'] = diRection
        if 'filter_list' in nbr_kwargs:
            nbr_kwargs['filter_list_dir'] = diRection
        if 'prefix_list' in nbr_kwargs:
            nbr_kwargs['prefix_list_dir'] = diRection
        if 'distribute_list' in nbr_kwargs:
            st.error('distribute_list is not supported anymore, use prefix_list instead')
        if removePrivateAs:
            nbr_kwargs['remove_private_as'] = True
        if first_as:
            nbr_kwargs['enforce_first_as'] = True
        if bfd:
            nbr_kwargs['bfd'] = True
        if default_originate:
            nbr_kwargs['default_originate'] = True
        if 'allowas_in' in nbr_kwargs:
            st.log('TBD: Not used in scripts so far')
        if 'neigh_local_as' in nbr_kwargs:
            nbr_kwargs['local_as'] = nbr_kwargs.pop('neigh_local_as')
        if 'no_prepend' in nbr_kwargs:
            nbr_kwargs['local_as_no_prepend'] = True
        if 'replace_as' in nbr_kwargs:
            nbr_kwargs['local_as_replace_as'] = True
        if 'vrf_name' in nbr_kwargs:
            nbr_kwargs['vrf'] = nbr_kwargs.pop('vrf_name')

        if bgp_nbr:
            result = config_bgp_neighbor_properties(dut, local_asn=local_asn, neighbor_ip=bgp_nbr, family=family, **nbr_kwargs)
            if not result:
                return False

        if redistribute:
            result = config_address_family_redistribute(dut, local_asn=local_asn, mode_type=family, mode='unicast', value=redistribute, config=config, vrf=vrf_name, **bgp_router_kwargs)
            if not result:
                return result

        if config_cmd == 'no' and 'neighbor' in config_type_list and neigh_name and not peergroup:
            nbr_kwargs = dict()
            nbr_kwargs['config'] = 'no'
            nbr_kwargs['cli_type'] = cli_type
            nbr_kwargs['delete_neighbor'] = True
            result = config_bgp_neighbor_properties(dut, local_asn=local_asn, neighbor_ip=bgp_nbr, family=family, **nbr_kwargs)
            if not result:
                return False

        if removeBGP == 'yes':
            result = unconfig_router_bgp(dut, vrf_name=vrf_name, cli_type=cli_type)
            if not result:
                return False

        return True

    my_cmd = ''
    if cli_type == "vtysh":
        if 'local_as' in kwargs and removeBGP != 'yes':
            config_router_bgp_mode(dut, local_as, vrf=vrf_name, cli_type=cli_type, ebgp_req_policy=ebgp_req_policy)
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
                my_cmd += '{} bgp bestpath {}\n'.format(config_cmd, bgp_bestpath_selection)
            elif type1 == 'activate':
                my_cmd += 'address-family {} unicast\n'.format(addr_family)
                my_cmd += '{} neighbor {} activate\n'.format(config_cmd, neighbor)
            elif type1 == 'nexthop_self':
                my_cmd += 'address-family {} unicast\n'.format(addr_family)
                my_cmd += '{} neighbor {} next-hop-self\n'.format(config_cmd, neighbor)
            elif type1 == 'pswd':
                my_cmd += '{} neighbor {} password {}\n'.format(config_cmd, neighbor, password)
            elif type1 == 'update_src' or type1 == 'update_src_intf':
                if update_src is not None:
                    my_cmd += '{} neighbor {} update-source {}\n'.format(config_cmd, neighbor, update_src)
                elif update_src_intf is not None:
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
                elif interface != '' and interface is not None:
                    my_cmd += '{} neighbor {} bfd\n'.format(config_cmd, interface)
                else:
                    my_cmd += '{} neighbor {} bfd\n'.format(config_cmd, neighbor)
            elif type1 == 'bfd_profile':
                if peergroup:
                    my_cmd += '{} neighbor {} bfd profile {}\n'.format(config_cmd, peergroup, bfd_profile)
                elif interface != '' and interface is not None:
                    my_cmd += '{} neighbor {} bfd profile {}\n'.format(config_cmd, interface, bfd_profile)
                else:
                    my_cmd += '{} neighbor {} bfd profile {}\n'.format(config_cmd, neighbor, bfd_profile)
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
                my_cmd += '{} neighbor {} interface remote-as {}\n'.format(config_cmd, interface, remote_as)
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
                my_cmd = '{} router bgp {}'.format(config_cmd, local_as)
            else:
                my_cmd = '{} router bgp'.format(config_cmd)
            st.config(dut, my_cmd, type=cli_type)
    elif cli_type == "klish":
        commands = list()
        neigh_name = get_interface_number_from_name(neighbor)
        if interface:
            intf_name = get_interface_number_from_name(interface)
        shutdown = kwargs.get("shutdown", None) if "shutdown" in config_type_list else None
        if config == 'yes':
            activate = kwargs.get("activate", 'af_default') if "activate" in config_type_list else 'af_default'
        else:
            # Avoid disable of neighbor unless config=no and config_type_list contains activate
            activate = kwargs.get("activate", None) if "activate" in config_type_list else None
        nexthop_self = kwargs.get("nexthop_self", True) if "nexthop_self" in config_type_list else None
        pswd = True if "pswd" in config_type_list else False
        if "conf_peers" in kwargs:
            conf_peers = kwargs.get("conf_peers")
        if "conf_identf" in kwargs:
            conf_identf = kwargs.get("conf_identf")
        update_src = kwargs.get("update_src", "") if "update_src" in config_type_list else ""
        update_src_intf = get_interface_number_from_name(update_src_intf)
        bfd = True if "bfd" in config_type_list else False
        first_as = True if "first_as" in config_type_list else False
        route_map = True if "routeMap" in config_type_list else False
        default_originate = True if "default_originate" in config_type_list else False
        removePrivateAs = True if "removePrivateAs" in config_type_list else False
        no_neighbor = "no" if kwargs.get("config") == "no" else ""
        sub_list = ["neighbor", "routeMap", "shutdown", "activate", "nexthop_self", "pswd", "update_src",
                    "bfd", "bfd_profile", "default_originate", "removePrivateAs", "no_neigh", "remote-as", "filter_list",
                    "prefix_list", "distribute_list", "weight", "keepalive", "holdtime", "ebgp_mhop", "peergroup", "update_src_intf", "connect", "allowas_in", "neigh_local_as", "no_prepend", "replace_as", "first_as"]

        if 'local_as' in kwargs and removeBGP != 'yes':
            config_router_bgp_mode(dut, local_as, vrf=vrf_name, cli_type=cli_type, ebgp_req_policy=ebgp_req_policy)
            if router_id:
                my_cmd = '{} router-id {}'.format(config_cmd, router_id)
                commands.append(my_cmd)

        if peergroup:
            my_cmd = '{} peer-group {}'.format(config_cmd, peergroup)
            commands.append(my_cmd)
            commands.append("exit")
        if conf_peers:
            conf_peers = "" if config_cmd == 'no' else conf_peers
            my_cmd += '{} confederation peers {}\n'.format(config_cmd, conf_peers)
            commands.append(my_cmd)
        if conf_identf != '':
            my_cmd += '{} confederation identifier {}\n'.format(config_cmd, conf_identf)
            commands.append(my_cmd)

        config_remote_as = True

        for type1 in config_type_list:
            if type1 in sub_list:
                if neigh_name and not peergroup:
                    if isinstance(neigh_name, dict):
                        my_cmd = "neighbor interface {} {}".format(neigh_name["type"], neigh_name["number"])
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
                            # activate = True
                    commands.append(my_cmd_peer)
                if config_remote_as and remote_as:
                    if interface and not peergroup:
                        my_cmd = "neighbor interface {} {}".format(intf_name['type'], intf_name['number'])
                        commands.append(my_cmd)
                    my_cmd = '{} remote-as {}'.format(config_cmd, remote_as)
                    commands.append(my_cmd)
                    config_remote_as = False
                if activate in ['af_only', 'af_default']:
                    # show ip bgp summary will list
                    #       v4 neighbor only if activate is done for v4 address family
                    #       v6 neighbor only if activate is done for v4 address family
                    #       both v4 and v6 neighbor only if activate is done for both address families
                    # There is a defect for this issue - 20468
                    my_cmd = 'address-family {} unicast'.format(addr_family)
                    commands.append(my_cmd)
                    my_cmd = '{} activate'.format(config_cmd)
                    commands.append(my_cmd)
                    commands.append("exit")
                    if activate in ['af_default'] and addr_family == "ipv6":
                        st.log('Activate under ipv4 also, when addr_family=IPv6')
                        my_cmd = 'address-family ipv4 unicast'
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
                    password = "" if config_cmd == 'no' else password
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
                        my_cmd = '{} update-source interface {} {}'.format(config_cmd, update_src_intf['type'], update_src_intf['number'])
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
                    my_cmd = '{} bfd'.format(config_cmd)
                    commands.append(my_cmd)
                    bfd = False
                elif first_as:
                    my_cmd = '{} enforce-first-as'.format(config_cmd)
                    commands.append(my_cmd)
                    first_as = False
                elif bfd_profile:
                    my_cmd = '{} bfd profile {}'.format(config_cmd, bfd_profile)
                    commands.append(my_cmd)
                    bfd_profile = None
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
                elif neigh_local_as:
                    neigh_local_as = "" if neigh_local_as == "no" else neigh_local_as
                    if config_cmd == "":
                        my_cmd = '{} local-as {} {} {}'.format(config_cmd, neigh_local_as, no_prepend, replace_as)
                        commands.append(my_cmd)
                    else:
                        my_cmd = '{} local-as '.format(config_cmd)
                        commands.append(my_cmd)
                    neigh_local_as = None
                # Remove these message after a successful regression run
                st.log('config_bgp command_list: {}'.format(commands))
                if re.search(r'neighbor ', commands[-1]):
                    commands.pop()
                else:
                    # come back to router bgp context
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
                my_cmd = "{} neighbor interface {} {}".format(config_cmd, neigh_name["type"], neigh_name["number"])
            else:
                my_cmd = "{} neighbor {}".format(config_cmd, neigh_name)
            commands.append(my_cmd)
#           commands.append("exit")
        # go back to config terminal prompt
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
        if config == 'yes':
            activate = kwargs.get("activate", 'af_default') if "activate" in config_type_list else 'af_default'
        else:
            # Avoid disable of neighbor unless config=no and config_type_list contains activate
            activate = kwargs.get("activate", None) if "activate" in config_type_list else None
        nexthop_self = kwargs.get("nexthop_self", True) if "nexthop_self" in config_type_list else None
        pswd = True if "pswd" in config_type_list else False
        update_src = kwargs.get("update_src", "") if "update_src" in config_type_list else ""
        # update_src_intf = get_interface_number_from_name(update_src_intf)
        bfd = True if "bfd" in config_type_list else False
        route_map = True if "routeMap" in config_type_list else False
        default_originate = True if "default_originate" in config_type_list else False
        removePrivateAs = True if "removePrivateAs" in config_type_list else False
        no_neighbor = "no" if kwargs.get("config") == "no" else ""
        # neigh_name = get_interface_number_from_name(neighbor) if neighbor else "0"
        sub_list = ["neighbor", "routeMap", "shutdown", "activate", "nexthop_self", "pswd", "update_src",
                    "bfd", "bfd_profile", "default_originate", "removePrivateAs", "no_neigh", "remote-as", "filter_list",
                    "prefix_list", "distribute_list", "weight", "keepalive", "holdtime", "ebgp_mhop", "peergroup",
                    "update_src_intf", "connect", "redist", "multipath-relax", "network", "import-check", "fast_external_failover",
                    "bgp_bestpath_selection", "max_path_ebgp", "max_path_ibgp", "import_vrf", "neigh_local_as", "no_prepend"]
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

        if interface and not neighbor:
            neighbor = interface

        if neighbor:
            global_data["openconfig-network-instance:bgp"]["neighbors"] = dict()
            global_data["openconfig-network-instance:bgp"]["neighbors"]["neighbor"] = list()
            neigh_data.update({"neighbor-address": neighbor})
            neigh_data["config"] = dict()
        if peergroup:
            global_data["openconfig-network-instance:bgp"]["peer-groups"] = dict()
            global_data["openconfig-network-instance:bgp"]["peer-groups"]["peer-group"] = list()
            peer_data.update({'peer-group-name': peergroup})
            peer_data['config'] = dict()
            if 'peergroup' not in config_type_list:
                neighbor = None

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
                    url = st.get_datastore(dut, "rest_urls")["bgp_del_rid"].format(vrf_name)
                    if not delete_rest(dut, rest_url=url):
                        st.error("failed to unconfig router-id")
            if config_cmd != "no":
                # config router bgp with local_as first before any sub config
                url = st.get_datastore(dut, "rest_urls")["bgp_config"].format(vrf_name)
                if not config_rest(dut, rest_url=url, http_method=cli_type, json_data=global_data):
                    st.error("failed to config bgp data")

        if peergroup:
            if config_cmd != 'no':
                peer_data.update({'peer-group-name': peergroup})
                peer_data['config'] = dict()
                peer_data["config"].update({'peer-group-name': peergroup})
                # global_data["openconfig-network-instance:bgp"]["peer-groups"]["peer-group"].append(peer_data)
                url = st.get_datastore(dut, "rest_urls")["bgp_peergroup_config"].format(vrf_name)
                payload = {"openconfig-network-instance:peer-groups": {"peer-group": [{"config": {"peer-group-name": peergroup}, "peer-group-name": peergroup}]}}
                if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=payload):
                    st.error("failed to created peer-group")
            else:
                url = st.get_datastore(dut, "rest_urls")['bgp_del_peer_group'].format(vrf_name, peergroup)
                if not delete_rest(dut, rest_url=url):
                    st.error("failed to unconfig peergroup")

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
                        peer_data.update({"peer-group-name": peergroup})
                        peer_data["config"] = dict()
                        peer_data["config"].update({'peer-group-name': peergroup})

                    else:
                        url = st.get_datastore(dut, "rest_urls")['bgp_del_peer_group'].format(vrf_name, peergroup)
                        if not delete_rest(dut, rest_url=url):
                            st.error("failed to delete peer group")
                    if "activate" in config_type_list:
                        activate = kwargs.get("activate", 'af_default') if "activate" in config_type_list else 'af_default'
                    if 'peergroup' in config_type_list:

                        if no_neighbor == "no":
                            url = st.get_datastore(dut, "rest_urls")['bgp_del_neighbor_config']
                            url = url.format(vrf_name, neighbor)
                            if not delete_rest(dut, rest_url=url):
                                st.error("neighbor delete is failed")

                        else:
                            st.log(peergroup)
                            neigh_data.update({"neighbor-address": neighbor})
                            neigh_data["config"].update({"neighbor-address": neighbor, "peer-group": peergroup})
                            global_data["openconfig-network-instance:bgp"]["neighbors"]["neighbor"].append(neigh_data)
                            url = st.get_datastore(dut, "rest_urls")["bgp_config"].format(vrf_name)
                            if not config_rest(dut, rest_url=url, http_method=cli_type, json_data=global_data):
                                st.error("failed to conifg bgp data")
                            neighbor = ""
                            activate = kwargs.get("activate", 'af_default') if "activate" in config_type_list else 'af_default'

                if config_remote_as and remote_as:
                    if (interface or neighbor) and not peergroup:
                        neigh_data.update({"neighbor-address": neighbor})
                        neigh_data["config"] = dict()
                        neigh_data["config"].update({"neighbor-address": neighbor})

                    if config_cmd != 'no':
                        if neighbor:
                            neigh_data.update({"neighbor-address": neighbor})

                            if str(remote_as).isdigit():  # peer_as = remote_as else peer_type = remote_as
                                neigh_data["config"].update({"neighbor-address": neighbor, "peer-as": int(remote_as)})
                            else:
                                if remote_as == "internal":
                                    peer_type = "INTERNAL"
                                else:
                                    peer_type = "EXTERNAL"
                                neigh_data["config"].update({"neighbor-address": neighbor, "peer-type": peer_type})
                        if peergroup:
                            peer_data.update({"peer-group-name": peergroup})
                            if str(remote_as).isdigit():  # peer_as = remote_as else peer_type = remote_as
                                peer_data["config"].update({"peer-group-name": peergroup, "peer-as": int(remote_as)})
                            else:
                                if remote_as == "internal":
                                    peer_type = "INTERNAL"
                                else:
                                    peer_type = "EXTERNAL"
                                peer_data["config"].update({"peer-group-name": peergroup, "peer-type": peer_type})

                    else:
                        if neighbor and type1 != "import_vrf":
                            url = st.get_datastore(dut, "rest_urls")['bgp_del_remote_as']
                            url = url.format(vrf_name, neighbor)
                            if not delete_rest(dut, rest_url=url):
                                st.error("failed to delete remote-as")

                    config_remote_as = False

                if activate in ['af_only', 'af_default']:
                    st.log(activate)
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
                    if config_cmd == "":
                        neigh_data_sub["config"].update({"afi-safi-name": afi_safi_name, "enabled": True})
                        if activate in ['af_default'] and family == "ipv6":
                            st.log('Activate under ipv4 also, when addr_family=IPv6')
                            afi_safi_name = "openconfig-bgp-types:IPV4_UNICAST"
                            neigh_data_sub1 = dict()
                            neigh_data_sub1.update({"afi-safi-name": afi_safi_name})
                            neigh_data_sub1["config"] = dict()
                            if config_cmd == "":
                                neigh_data_sub1["config"].update({"afi-safi-name": afi_safi_name, "enabled": True})
                            else:
                                neigh_data_sub1["config"].update({"afi-safi-name": afi_safi_name, "enabled": False})
                            common_data["afi-safis"]["afi-safi"].append(neigh_data_sub1)
                    else:
                        neigh_data_sub["config"].update({"afi-safi-name": afi_safi_name, "enabled": False})
                    common_data["afi-safis"]["afi-safi"].append(neigh_data_sub)
                    activate = None

                if shutdown:
                    common_data["config"] = dict()
                    if config_cmd != 'no':
                        common_data["config"].update({"enabled": False})
                    else:
                        common_data["config"].update({"enabled": True})
                    shutdown = None
                if route_map:
                    activate = kwargs.get("activate", 'af_default') if "activate" in config_type_list else 'af_default'
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
                            url = st.get_datastore(dut, "rest_urls")['bgp_del_route_map_in']
                            url = url.format(vrf_name, neighbor, afi_safi_name[21:], routeMap)
                            if not delete_rest(dut, rest_url=url):
                                st.error("failed to delete route-map inboud")

                        else:
                            url = st.get_datastore(dut, "rest_urls")['bgp_del_route_map_out']
                            url = url.format(vrf_name, neighbor, afi_safi_name[21:], routeMap)
                            if not delete_rest(dut, rest_url=url):
                                st.error("failed to delete route-map outbound")

                    common_data["afi-safis"]["afi-safi"].append(neigh_data_sub)
                    route_map = False
                if filter_list:
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
                            url = st.get_datastore(dut, "rest_urls")['bgp_del_filter_list_in']
                            url = url.format(vrf_name, neighbor, afi_safi_name[21:])
                            if not delete_rest(dut, rest_url=url):
                                st.error("failed to delete filter-list inboud")

                        else:
                            url = st.get_datastore(dut, "rest_urls")['bgp_del_filter_list_out']
                            url = url.format(vrf_name, neighbor, afi_safi_name[21:])
                            if not delete_rest(dut, rest_url=url):
                                st.error("failed to delete filter-list outbound")
                    common_data["afi-safis"]["afi-safi"].append(neigh_data_sub)
                    filter_list = None
                if prefix_list:
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
                    prefix_list = None
                if distribute_list:

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
                            url = url.format(vrf_name, neighbor, afi_safi_name_del, prefix_list)
                            if not delete_rest(dut, rest_url=url):
                                st.error("failed to delete ditribute-list inboud")

                        else:
                            url = st.get_datastore(dut, "rest_urls")['bgp_del_prefix_list_out']
                            url = url.format(vrf_name, neighbor, afi_safi_name_del, prefix_list)
                            if not delete_rest(dut, rest_url=url):
                                st.error("failed to delete distribute-list outbound")

                    common_data["afi-safis"]["afi-safi"].append(neigh_data_sub)
                    prefix_list = None
                if default_originate:
                    family = kwargs.get('addr_family', "ipv4")
                    if family == "ipv6":
                        afi_safi_name = "openconfig-bgp-types:IPV6_UNICAST"
                    else:
                        afi_safi_name = "openconfig-bgp-types:IPV4_UNICAST"
                    if not common_data:
                        common_data["afi-safis"] = dict()
                        common_data["afi-safis"]["afi-safi"] = list()
                    neigh_data_sub = dict()

                    if family == "ipv4":
                        neigh_data_sub["ipv4-unicast"] = dict()
                        neigh_data_sub["ipv4-unicast"]["config"] = dict()
                        if 'routeMap' in kwargs:
                            if config_cmd != 'no':
                                neigh_data_sub["ipv4-unicast"]["config"].update({"send-default-route": True, "openconfig-bgp-ext:default-policy-name": routeMap})

                            else:
                                neigh_data_sub["ipv4-unicast"]["config"].update({"send-default-route": False})
                        else:
                            neigh_data_sub["ipv4-unicast"]["config"].update({"send-default-route": True})

                    else:
                        neigh_data_sub["ipv6-unicast"] = dict()
                        neigh_data_sub["ipv6-unicast"]["config"] = dict()
                        if 'routeMap' in kwargs:
                            if config_cmd != 'no':
                                neigh_data_sub["ipv6-unicast"]["config"].update({"send-default-route": True, "openconfig-bgp-ext:default-policy-name": routeMap})

                            else:
                                neigh_data_sub["ipv6-unicast"]["config"].update({"send-default-route": False})
                        else:
                            neigh_data_sub["ipv6-unicast"]["config"].update({"send-default-route": True})

                    common_data["afi-safis"]["afi-safi"][0].update(neigh_data_sub)
                    default_originate = False
                if removePrivateAs:
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
                    removePrivateAs = False
                if weight:

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
                    if config_cmd != 'no':
                        neigh_data_sub['config'].update({"afi-safi-name": afi_safi_name, "enabled": True, "openconfig-bgp-ext:weight": int(weight)})
                    else:
                        if neighbor and not peergroup:
                            url = st.get_datastore(dut, "rest_urls")['bgp_del_weight']
                            url = url.format(vrf_name, neighbor, afi_safi_name[21:])
                            if not delete_rest(dut, rest_url=url):
                                st.error("failed to delete weight")

                        else:
                            url = st.get_datastore(dut, "rest_urls")['bgp_del_weight_peer']
                            url = url.format(vrf_name, peergroup, afi_safi_name[21:])
                            if not delete_rest(dut, rest_url=url):
                                st.error("failed to delete weight")

                    common_data["afi-safis"]["afi-safi"].append(neigh_data_sub)

                    weight = None
                if keepalive and holdtime:
                    family = kwargs.get("addr_family", 'ipv4')
                    if neighbor:
                        if no_neighbor == "no":
                            url = st.get_datastore(dut, "rest_urls")['bgp_del_neighbor_config'].format("default", neighbor)

                            if not delete_rest(dut, rest_url=url):
                                st.error("neighbor delete is failed")

                        else:
                            neigh_data.update({"neighbor-address": neighbor})
                            neigh_data["config"].update({"neighbor-address": neighbor})

                    common_data["timers"] = dict()
                    common_data["timers"]["config"] = dict()

                    if config_cmd != 'no':
                        common_data["timers"]["config"].update({"hold-time": int(holdtime), "keepalive-interval": int(keepalive)})
                    else:
                        if neighbor and not peergroup:
                            url = st.get_datastore(dut, "rest_urls")['bgp_del_timers']
                            url = url.format(vrf_name, neighbor)
                            if not delete_rest(dut, rest_url=url):
                                st.error("failed to delete timers")
                        else:
                            url = st.get_datastore(dut, "rest_urls")['bgp_del_timers_peer']
                            url = url.format(vrf_name, peergroup)
                            if not delete_rest(dut, rest_url=url):
                                st.error("failed to delete timers")

                    keepalive = 0
                    holdtime = 0
                if nexthop_self:

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
                    neigh_data_sub["openconfig-bgp-ext:next-hop-self"] = dict()
                    neigh_data_sub["openconfig-bgp-ext:next-hop-self"]["config"] = dict()
                    if config_cmd != 'no':
                        neigh_data_sub["openconfig-bgp-ext:next-hop-self"]["config"].update(
                            {"enabled": True})
                        common_data["afi-safis"]["afi-safi"].append(neigh_data_sub)
                    else:
                        if neighbor and not peergroup:
                            url = st.get_datastore(dut, "rest_urls")['bgp_del_nexthop_self']
                            url = url.format(vrf_name, neighbor, afi_safi_name[21:])
                            if not delete_rest(dut, rest_url=url):
                                st.error("failed to delete nexthop self")

                        else:
                            url = st.get_datastore(dut, "rest_urls")['bgp_del_nexthop_self_peer']
                            url = url.format(vrf_name, peergroup, afi_safi_name[21:])
                            if not delete_rest(dut, rest_url=url):
                                st.error("failed to delete nexthop self")

                    nexthop_self = None
                if pswd:
                    password = "" if config_cmd == 'no' else password
                    neigh_data_sub = dict()
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

                    pswd = False
                if update_src:
                    if neighbor:
                        # if no_neighbor == 'no':
                        #     url = st.get_datastore(dut, "rest_urls")['bgp_del_neighbor_config'].format("default",neighbor)
                        #
                        #     if not delete_rest(dut, rest_url=url.format("default", neighbor)):
                        #         st.error("neighbor is failed")
                        #
                        # else:
                        neigh_data.update({"neighbor-address": neighbor})
                        neigh_data["config"].update({"neighbor-address": neighbor})

                        neigh_data_sub = dict()
                        neigh_data_sub["transport"] = dict()
                        neigh_data_sub["transport"]["config"] = dict()
                        if config_cmd != 'no':
                            neigh_data_sub["transport"]["config"].update({"local-address": update_src})
                            neigh_data.update(neigh_data_sub)
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
                        common_data.update(neigh_data)

                    update_src = None
                if update_src_intf:
                    if neighbor:
                        # if no_neighbor == 'no':
                        #     url = st.get_datastore(dut, "rest_urls")['bgp_del_neighbor_config'].format("default", neighbor)
                        #
                        #     if not delete_rest(dut, rest_url=url.format("default", neighbor)):
                        #         st.error("neighbor is failed")
                        #
                        # else:
                        neigh_data.update({"neighbor-address": neighbor})
                        neigh_data["config"].update({"neighbor-address": neighbor})

                        neigh_data_sub = dict()
                        neigh_data_sub["transport"] = dict()
                        neigh_data_sub["transport"]["config"] = dict()
                        if config_cmd != 'no':
                            neigh_data_sub["transport"]["config"].update({"local-address": update_src_intf})
                            neigh_data.update(neigh_data_sub)
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
                        common_data.update(neigh_data)

                    update_src_intf = None
                if ebgp_mhop:
                    if neighbor:
                        # if no_neighbor == 'no':
                        #     url = st.get_datastore(dut, "rest_urls")['bgp_del_neighbor_config'].format("default",neighbor)
                        #
                        #     if not delete_rest(dut, rest_url=url.format("default", neighbor)):
                        #         st.error("neighbor is failed")
                        #
                        #
                        # else:
                        neigh_data.update({"neighbor-address": neighbor})
                        neigh_data["config"].update({"neighbor-address": neighbor})

                        neigh_data_sub = dict()
                        neigh_data_sub["ebgp-multihop"] = dict()
                        neigh_data_sub["ebgp-multihop"]["config"] = dict()
                        if config_cmd != 'no':
                            neigh_data_sub["ebgp-multihop"]["config"].update({"enabled": True, "multihop-ttl": int(ebgp_mhop)})
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
                        common_data.update(neigh_data)

                    ebgp_mhop = None
                if bfd:
                    neigh_data_sub = dict()
                    neigh_data_sub["openconfig-bfd:enable-bfd"] = dict()
                    neigh_data_sub["openconfig-bfd:enable-bfd"]["config"] = dict()
                    neigh_data_sub["openconfig-bfd:enable-bfd"]["config"].update({"enabled": True})
                    if (neighbor or interface):
                        st.log("interface: {}".format(interface))
                        st.log("neighbor: {}".format(neighbor))
                        if config_cmd != 'no':
                            neigh_data.update(neigh_data_sub)
                        else:
                            url = st.get_datastore(dut, "rest_urls")['delete_bgp_neighbor_bfd_enabled']
                            url = url.format(vrf_name, neighbor)
                            if not delete_rest(dut, rest_url=url):
                                st.error("failed to disable bfd")
                    else:
                        if config_cmd != 'no':
                            peer_data.update(neigh_data_sub)
                        else:
                            url = st.get_datastore(dut, "rest_urls")["delete_bgp_peergroup_bfd_enabled"].format(vrf_name, peergroup)
                            if not delete_rest(dut, http_method='delete', rest_url=url):
                                st.error("failed to unconfig bfd from peergroup")
                    bfd = False
                if neigh_local_as:
                    if neighbor:
                        neigh_data.update({"neighbor-address": neighbor})
                        neigh_data["config"].update({"neighbor-address": neighbor})

                        if config_cmd != 'no':
                            neigh_data["config"].update({"local-as": int(neigh_local_as), "openconfig-bgp-ext:local-as-no-prepend": True})

                        else:
                            if neighbor and not peergroup:
                                url = st.get_datastore(dut, "rest_urls")['bgp_del_local_as']
                                url = url.format(vrf_name, neighbor)
                                if not delete_rest(dut, rest_url=url):
                                    st.error("failed to delete neighbor local-as")
                            else:
                                url = st.get_datastore(dut, "rest_urls")['bgp_del_local_as_peer']
                                url = url.format(vrf_name, peergroup)
                                if not delete_rest(dut, rest_url=url):
                                    st.error("failed to delete peer-group local-as")
                        common_data.update(neigh_data)

                    neigh_local_as = None
                if bfd_profile:
                    neigh_data_sub = dict()
                    neigh_data_sub["openconfig-bfd:enable-bfd"] = dict()
                    neigh_data_sub["openconfig-bfd:enable-bfd"]["config"] = dict()
                    neigh_data_sub["openconfig-bfd:enable-bfd"]["config"].update({"enabled": True})
                    if (neighbor or interface):
                        st.log("interface: {}".format(interface))
                        st.log("neighbor: {}".format(neighbor))
                        if config_cmd != 'no':
                            neigh_data_sub["openconfig-bfd:enable-bfd"]["config"].update({"bfd-profile": kwargs['bfd_profile']})
                        else:
                            url = st.get_datastore(dut, "rest_urls")['delete_bgp_neighbor_bfd_profile']
                            url = url.format(vrf_name, neighbor)
                            if not delete_rest(dut, rest_url=url):
                                st.error("failed to delete bfd profile")
                        neigh_data.update(neigh_data_sub)
                    else:
                        if config_cmd != 'no':
                            neigh_data_sub["openconfig-bfd:enable-bfd"]["config"].update({"bfd-profile": kwargs['bfd_profile']})
                            peer_data.update(neigh_data_sub)
                        else:
                            url = st.get_datastore(dut, "rest_urls")["delete_bgp_peergroup_bfd_profile"].format(vrf_name, peergroup)
                            if not delete_rest(dut, http_method='delete', rest_url=url):
                                st.error("failed to unconfig bfd profile from peergroup")
                    bfd_profile = False
                if connect:
                    common_data["timers"] = dict()
                    common_data["timers"]["config"] = dict()
                    if config_cmd != 'no':
                        common_data["timers"]["config"].update({"connect-retry": int(connect)})
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

                    connect = None
                if type1 == 'fast_external_failover':
                    st.log("Configuring the fast_external_failover")

                    if config_cmd != 'no':
                        global_data["openconfig-network-instance:bgp"]["global"]["config"].update({"openconfig-bgp-ext:fast-external-failover": True})
                    else:
                        global_data["openconfig-network-instance:bgp"]["global"]["config"].update({"openconfig-bgp-ext:fast-external-failover": False})
                if type1 == 'bgp_bestpath_selection':
                    global_data["openconfig-network-instance:bgp"]["global"]["route-selection-options"] = dict()
                    global_data["openconfig-network-instance:bgp"]["global"]["route-selection-options"]["config"] = dict()
                    global_data["openconfig-network-instance:bgp"]["global"]["use-multiple-paths"] = dict()
                    global_data["openconfig-network-instance:bgp"]["global"]["use-multiple-paths"]["ebgp"] = dict()
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

                if type1 == 'max_path_ibgp':
                    sub_data = dict()
                    sub_data["config"] = dict()
                    global_data["openconfig-network-instance:bgp"]["global"]["afi-safis"] = dict()
                    global_data["openconfig-network-instance:bgp"]["global"]["afi-safis"]["afi-safi"] = list()
                    if family == "ipv6":
                        afi_safi_name = "openconfig-bgp-types:IPV6_UNICAST"
                    else:
                        afi_safi_name = "openconfig-bgp-types:IPV4_UNICAST"
                    sub_data.update({"afi-safi-name": afi_safi_name})
                    sub_data["config"].update({"afi-safi-name": afi_safi_name})
                    sub_data["use-multiple-paths"] = dict()
                    sub_data["use-multiple-paths"]["ibgp"] = dict()
                    sub_data["use-multiple-paths"]["ibgp"]["config"] = dict()
                    if config_cmd != 'no':
                        sub_data["use-multiple-paths"]["ibgp"]["config"].update({"maximum-paths": int(max_path_ibgp)})
                    else:
                        url = st.get_datastore(dut, "rest_urls")['bgp_del_max_path_ibgp']
                        url = url.format(vrf_name, afi_safi_name[21:])
                        if not delete_rest(dut, rest_url=url):
                            st.error("failed to unconfig max paths ibgp")

                    global_data["openconfig-network-instance:bgp"]["global"]["afi-safis"]["afi-safi"].append(sub_data)
                if type1 == 'max_path_ebgp':
                    sub_data = dict()
                    sub_data["config"] = dict()
                    global_data["openconfig-network-instance:bgp"]["global"]["afi-safis"] = dict()
                    global_data["openconfig-network-instance:bgp"]["global"]["afi-safis"]["afi-safi"] = list()
                    if family == "ipv6":
                        afi_safi_name = "openconfig-bgp-types:IPV6_UNICAST"
                    else:
                        afi_safi_name = "openconfig-bgp-types:IPV4_UNICAST"
                    sub_data.update({"afi-safi-name": afi_safi_name})
                    sub_data["config"].update({"afi-safi-name": afi_safi_name})
                    sub_data["use-multiple-paths"] = dict()
                    sub_data["use-multiple-paths"]["ebgp"] = dict()
                    sub_data["use-multiple-paths"]["ebgp"]["config"] = dict()
                    if config_cmd != 'no':
                        sub_data["use-multiple-paths"]["ebgp"]["config"].update({"maximum-paths": int(max_path_ebgp)})
                    else:
                        url = st.get_datastore(dut, "rest_urls")['bgp_del_max_path_ebgp']
                        url = url.format(vrf_name, afi_safi_name[21:])
                        if not delete_rest(dut, rest_url=url):
                            st.error("failed to unconfig max paths ebgp")

                    global_data["openconfig-network-instance:bgp"]["global"]["afi-safis"]["afi-safi"].append(sub_data)
                if type1 == 'redist':
                    if redistribute == "connected":
                        sub_data = dict()
                        sub_data["config"] = dict()
                        redist_type = 'connected'
                        redist_type = redist_type.upper()
                        if redist_type == 'CONNECTED':
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

                if type1 == 'network':

                    sub_data = dict()
                    sub_data["config"] = dict()
                    global_data["openconfig-network-instance:bgp"]["global"]["afi-safis"] = dict()
                    global_data["openconfig-network-instance:bgp"]["global"]["afi-safis"]["afi-safi"] = list()
                    if family == "ipv6":
                        afi_safi_name = "openconfig-bgp-types:IPV6_UNICAST"
                    else:
                        afi_safi_name = "openconfig-bgp-types:IPV4_UNICAST"
                    sub_data.update({"afi-safi-name": afi_safi_name})
                    sub_data["config"].update({"afi-safi-name": afi_safi_name})
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
                        network = network.replace('/', '%2F')
                        url = url.format(vrf_name, afi_safi_name[21:], network)
                        if not delete_rest(dut, rest_url=url):
                            st.error("failed to unconfig network")

                    global_data["openconfig-network-instance:bgp"]["global"]["afi-safis"]["afi-safi"].append(sub_data)
                if type1 == 'import-check':
                    global_sub_data = dict()
                    if config_cmd != 'no':
                        global_sub_data.update({"openconfig-bgp-ext:network-import-check": True})
                    else:
                        global_sub_data.update({"openconfig-bgp-ext:network-import-check": False})
                    global_data["openconfig-network-instance:bgp"]["global"]["config"].update(global_sub_data)
                if type1 == 'import_vrf':
                    sub_data = dict()
                    sub_data["config"] = dict()
                    global_data["openconfig-network-instance:bgp"]["global"]["afi-safis"] = dict()
                    global_data["openconfig-network-instance:bgp"]["global"]["afi-safis"]["afi-safi"] = list()
                    if family == "ipv6":
                        afi_safi_name = "openconfig-bgp-types:IPV6_UNICAST"
                    else:
                        afi_safi_name = "openconfig-bgp-types:IPV4_UNICAST"
                    sub_data.update({"afi-safi-name": afi_safi_name})
                    sub_data["config"].update({"afi-safi-name": afi_safi_name})
                    if config_cmd != 'no':
                        sub_data["openconfig-bgp-ext:import-network-instance"] = dict()
                        sub_data["openconfig-bgp-ext:import-network-instance"]["config"] = dict()
                        sub_data["openconfig-bgp-ext:import-network-instance"]["config"].update({"name": [import_vrf_name]})
                        global_data["openconfig-network-instance:bgp"]["global"]["afi-safis"]["afi-safi"].append(
                            sub_data)
                    else:
                        url = st.get_datastore(dut, "rest_urls")['bgp_del_vrf']
                        url = url.format(vrf_name, afi_safi_name[21:])
                        if not delete_rest(dut, rest_url=url):
                            st.error("failed to delete vrf")

                if type1 == 'multipath-relax':

                    global_data["openconfig-network-instance:bgp"]["global"]["use-multiple-paths"] = dict()
                    global_data["openconfig-network-instance:bgp"]["global"]["use-multiple-paths"]["ebgp"] = dict()
                    global_data["openconfig-network-instance:bgp"]["global"]["use-multiple-paths"]["ebgp"]["config"] = dict()
                    if config_cmd != 'no':
                        global_data["openconfig-network-instance:bgp"]["global"]["use-multiple-paths"]["ebgp"]["config"].update({"allow-multiple-as": True, "openconfig-bgp-ext:as-set": False})
                    else:
                        url = st.get_datastore(dut, "rest_urls")['bgp_del_bp_as_path_multipath_relax']
                        url = url.format(vrf_name)
                        if not delete_rest(dut, rest_url=url):
                            st.error("failed to unconfig as-path multipath-relax")

                if type1 == 'removeBGP':
                    st.log("Removing the bgp config from the device")
                if type1 == 'router_id':
                    st.log("Configuring the router-id on the device")
                if type1 == 'peer_group':
                    st.log("Configuring the peer_group on the device")

            st.log(common_data)
            st.log(global_data)

            if neighbor:
                neigh_data.update(common_data)
                global_data["openconfig-network-instance:bgp"]["neighbors"]["neighbor"].append(neigh_data)

            # if peergroup and ("peer-group" in neigh_data["config"]) and not (global_data["openconfig-network-instance:bgp"]["peer-groups"]["peer-group"]):
            #     peer_data.update(common_data)
            #     global_data["openconfig-network-instance:bgp"]["peer-groups"]["peer-group"].append(peer_data)

            if peergroup and not neighbor:
                peer_data.update(common_data)
                global_data["openconfig-network-instance:bgp"]["peer-groups"]["peer-group"].append(peer_data)
            # if peergroup and neighbor:
            #     peer_data.update(common_data)
            #     global_data["openconfig-network-instance:bgp"]["neighbors"]["neighbor"].append(neigh_data)
            #     global_data["openconfig-network-instance:bgp"]["peer-groups"]["peer-group"].append(peer_data)

            st.log(vrf_name)
            url = st.get_datastore(dut, "rest_urls")["bgp_config"].format(vrf_name)
            if not config_rest(dut, rest_url=url, http_method=cli_type, json_data=global_data):
                st.error("failed to conifg bgp data")
            url = st.get_datastore(dut, "rest_urls")['bgp_config_route_map'].format(vrf_name)
            try:
                if not open_data["openconfig-network-instance:table-connections"]["table-connection"]:
                    st.log("open_data is empty")
                elif not open_data["openconfig-network-instance:table-connections"]["table-connection"][0]["config"]:
                    st.log("open_data is empty")
                else:
                    if not config_rest(dut, rest_url=url, http_method=cli_type, json_data=open_data):
                        st.error("unable to configure route-map")
            except Exception as e:
                st.log("key not not found")
                st.log(e)
        if len(config_type_list) == 0:
            url = st.get_datastore(dut, "rest_urls")["bgp_config"].format(vrf_name)
            if not config_rest(dut, rest_url=url, http_method=cli_type, json_data=global_data):
                st.error("failed to conifg bgp data")
        if config_cmd == 'no' and 'neighbor' in config_type_list and neighbor and not peergroup:
            if config_cmd != 'no':
                neigh_data.update({"neighbor-address": neighbor})
                neigh_data["config"].update({"neighbor-address": neighbor})

            else:
                url = st.get_datastore(dut, "rest_urls")['bgp_del_remote_as']
                url = url.format(vrf_name, neighbor)
                if not delete_rest(dut, rest_url=url):
                    st.error("failed to delete remote-as")

            config_remote_as = False
        if vrf_name != 'default' and removeBGP == 'yes':
            if config_cmd == 'no':
                url = st.get_datastore(dut, "rest_urls")['bgp_remove'].format(vrf_name)
                if not delete_rest(dut, rest_url=url):
                    st.error("Error in Unconfiguring AS number")
        if vrf_name == 'default' and removeBGP == 'yes':
            if config_cmd == 'no':
                url = st.get_datastore(dut, "rest_urls")['bgp_remove'].format(vrf_name)
                if not delete_rest(dut, rest_url=url):
                    st.error("Error in Unconfiguring AS number")
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
        if "community" in kwargs:
            command += " community {}".format(kwargs['community'])
    elif cli_type == 'klish':
        command = "show bgp {} unicast".format(family)
        if "community" in kwargs:
            command += " community {}".format(kwargs['community'])
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_url = st.get_datastore(dut, 'rest_urls')
        vrf = "default"
        url = rest_url["bgp_routerid_state"].format(vrf)
        output_router_id = get_rest(dut, rest_url=url)
        if output_router_id and rest_status(output_router_id["status"]):
            output_router_id = output_router_id["output"]
        else:
            output_router_id = {}
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
        as_path = {"IGP": "i", "EGP": "e", "?": "incomplete", "INCOMPLETE": "incomplete"}
        for route in routes:
            show_output = dict()
            show_output["router_id"] = router_id
            show_output["network"] = route["prefix"]
            show_output["weight"] = route["openconfig-bgp-deviation:attr-sets"]["weight"] if "weight" in route["openconfig-bgp-deviation:attr-sets"] else 0
            show_output["status_code"] = "*>" if route["state"]["valid-route"] is True else ""
            show_output["metric"] = route["openconfig-bgp-deviation:attr-sets"]["med"] if "med" in route["openconfig-bgp-deviation:attr-sets"] else 0
            show_output["origin"] = as_path[route["openconfig-bgp-deviation:attr-sets"]["state"]["origin"]]
            members = ""
            if "as-path" in route["openconfig-bgp-deviation:attr-sets"]:
                route_as_path = route["openconfig-bgp-deviation:attr-sets"]["as-path"]
                if "as-segment" in route_as_path:
                    route_as_segment = route_as_path["as-segment"][0]
                    if "state" in route_as_segment:
                        members = ' '.join([str(item) for item in route_as_segment["state"]["member"]])
            # show_output["as_path"] = "{} {}".format(members, as_path[route["openconfig-bgp-deviation:attr-sets"]["state"]["origin"]])
            show_output["as_path"] = "{}".format(members)
            show_output["next_hop"] = route["openconfig-bgp-deviation:attr-sets"]["state"]["next-hop"]
            show_output["version"] = ""
            show_output["vrf_id"] = vrf
            show_output["local_pref"] = route["openconfig-bgp-deviation:attr-sets"]["local-pref"] if "local-pref" in route["openconfig-bgp-deviation:attr-sets"] else 32768
            show_output["internal"] = ""
            result.append(show_output)
        st.debug(result)
        return result
    return st.show(dut, command, type=cli_type)


def fetch_ip_bgp_route(dut, family='ipv4', match=None, select=None, **kwargs):
    cli_type = get_show_cli_type(dut, **kwargs)
    entries = dict()
    output = show_ip_bgp_route(dut, family=family, cli_type=cli_type)
    # match = {'network': network}
    entries = filter_and_select(output, select, match)
    return entries


def get_ip_bgp_route(dut, family='ipv4', **kwargs):
    cli_type = get_show_cli_type(dut, **kwargs)
    if "community" in kwargs:
        output = show_ip_bgp_route(dut, family=family, cli_type=cli_type, community=kwargs['community'])
        kwargs.pop('community')
    else:
        output = show_ip_bgp_route(dut, family=family, cli_type=cli_type)
    st.debug(output)
    kwargs.pop("cli_type", None)
    for each in kwargs.keys():
        match = {each: kwargs[each]}
        get_list = ["network", "as_path"]
        st.log(match)
        entries = filter_and_select(output, get_list, match)
        st.log(entries)
        if not entries:
            st.warn("Could not get bgp route info", dut=dut)
            return False
    return entries


def verify_ip_bgp_route(dut, family='ipv4', **kwargs):
    """

    EX; verify_ip_bgp_route(vars.D1, network= '11.2.1.2/24')
    """
    cli_type = get_show_cli_type(dut, **kwargs)
    output = show_ip_bgp_route(dut, family=family, cli_type=cli_type)
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
    output = show_ip_bgp_route(dut, family=family, cli_type=cli_type)
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
    # 4 place, can use get_ip_bpg_route and/or verify_ip_bgp_route4 place, can use get_ip_bpg_route and/or verify_ip_bgp_route
    entries = dict()
    command = "show bgp {} {}/{}".format(family, prefix, masklen)
    entries = st.show(dut, command, type='vtysh')
    st.log(entries)
    if not entries:
        return False
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
    # 1 place, can use get_ip_bpg_route and/or verify_ip_bgp_route4 place, can use get_ip_bpg_route and/or verify_ip_bgp_route

    if family != 'ipv4' and family != 'ipv6':
        return {}

    command = "show bgp {} {}".format(family, ip_prefix)
    entries = st.show(dut, command, type='vtysh')
    return entries


def activate_bgp_neighbor(dut, local_asn, neighbor_ip, family="ipv4", config='yes', vrf='default', **kwargs):
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
    if family != 'ipv4' and family != 'ipv6':
        return False

    if cli_type in get_supported_ui_type_list():
        kwargs['config'] = config
        kwargs['vrf'] = vrf
        kwargs['activate'] = 'af_only'
        return config_bgp_neighbor_properties(dut, local_asn=local_asn, neighbor_ip=neighbor_ip, family=family, **kwargs)

    cmd = ''
    config_router_bgp_mode(dut, local_asn, vrf=vrf, cli_type=cli_type)
    if cli_type == 'vtysh':
        if remote_asn != '':
            cmd = cmd + 'neighbor {} remote-as {}\n'.format(neighbor_ip, remote_asn)
        cmd = cmd + 'address-family {} unicast\n'.format(family)
        cmd = cmd + '{} neighbor {} activate\n'.format(mode, neighbor_ip)
        cmd = cmd + '\n end'
        st.config(dut, cmd, type='vtysh', skip_error_check=skip_error_check)
        return True
    elif cli_type == "klish":
        neigh_name = get_interface_number_from_name(neighbor_ip)
        if neigh_name:
            if isinstance(neigh_name, dict):
                cmd = cmd + 'neighbor interface {} {}\n'.format(neigh_name["type"], neigh_name["number"])
            else:
                cmd = cmd + 'neighbor {}\n'.format(neigh_name)
        cmd = cmd + 'remote-as {}\n'.format(remote_asn)
        cmd = cmd + 'address-family {} unicast\n'.format(family)
        cmd = cmd + ' {} activate\n'.format(mode)
        cmd = cmd + 'exit\nexit\nexit\n'
        st.config(dut, cmd, type=cli_type, skip_error_check=skip_error_check, conf=True)
        return True
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        vrf_name = vrf if vrf != "default" else "default"
        url = rest_urls['bgp_config'].format(vrf_name)
        global_data = dict()
        global_data["openconfig-network-instance:bgp"] = dict()
        global_data["openconfig-network-instance:bgp"]["global"] = dict()
        global_data["openconfig-network-instance:bgp"]["global"]["config"] = dict()
        global_data["openconfig-network-instance:bgp"]["neighbors"] = dict()
        global_data["openconfig-network-instance:bgp"]["neighbors"]["neighbor"] = list()
        global_data["openconfig-network-instance:bgp"]["global"]["config"]["as"] = int(local_asn)
        neigh_data = dict()
        neigh_data.update({"neighbor-address": neighbor_ip})
        neigh_data["config"] = dict()

        if str(remote_asn).isdigit():  # peer_as = remote_as else peer_type = remote_asn
            neigh_data["config"].update({"neighbor-address": neighbor_ip, "peer-as": int(remote_asn)})
        else:
            if remote_asn == "internal":
                peer_type = "INTERNAL"
            else:
                peer_type = "EXTERNAL"
            neigh_data["config"].update({"neighbor-address": neighbor_ip, "peer-type": peer_type})
        if family == "ipv6":
            afi_safi_name = "openconfig-bgp-types:IPV6_UNICAST"
        else:
            afi_safi_name = "openconfig-bgp-types:IPV4_UNICAST"
        if mode != 'no':
            neigh_data["afi-safis"] = dict()
            neigh_data["afi-safis"]["afi-safi"] = list()
            neigh_data_sub = dict()
            neigh_data_sub.update({"afi-safi-name": afi_safi_name})
            neigh_data_sub["config"] = dict()
            neigh_data_sub["config"].update({"afi-safi-name": afi_safi_name, "enabled": True})
            neigh_data["afi-safis"]["afi-safi"].append(neigh_data_sub)
            global_data["openconfig-network-instance:bgp"]["neighbors"]["neighbor"].append(neigh_data)
        else:
            neigh_data["afi-safis"] = dict()
            neigh_data["afi-safis"]["afi-safi"] = list()
            neigh_data_sub = dict()
            neigh_data_sub.update({"afi-safi-name": afi_safi_name})
            neigh_data_sub["config"] = dict()
            neigh_data_sub["config"].update({"afi-safi-name": afi_safi_name, "enabled": False})
            neigh_data["afi-safis"]["afi-safi"].append(neigh_data_sub)
            global_data["openconfig-network-instance:bgp"]["neighbors"]["neighbor"].append(neigh_data)
        if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=global_data):
            st.error("Error in configuring activate neighbor")
            return False
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
    command += "log syslog debugging\n"
    command += "log stdout\n"
    st.config(dut, command, type='vtysh')


def verify_bgp_nexthop(dut, ip_addr, peers, **kwargs):
    """
    verify_bgp_nexthop(vars.D1, ip_addr='fe80::82a2:35ff:fe32:acbb' , peers= ['Ethernet24', 'Ethernet25'], state={"Ethernet24":"(Stale)"})
    :param dut:
    :param kwargs:{u'paths': '0', u'metric': '0', u'ip_addr': '27.0.0.2', u'peers': '27.0.0.2'},
    {u'paths': '0', u'metric': '0', u'ip_addr': '3001::2', u'peers': '3001::2'},
    {u'paths': '0', u'metric': '0', u'ip_addr': 'fe80::82a2:35ff:fe32:acbb', u'peers': 'Ethernet24 Ethernet27'
    :return:
    """
    cli_type = 'vtysh'
    skip_error_check = kwargs.get('skip_error_check', False)
    state = kwargs.get('state')
    cmd = 'show bgp nexthop'
    output = st.show(dut, cmd, skip_error_check=skip_error_check, type=cli_type)
    if len(output) == 0:
        st.error("Output is Empty")
        return False
    match = {'ip_addr': ip_addr}
    entries = filter_and_select(output, None, match)
    if not entries:
        st.log("No match found for ip_addr {}".format(ip_addr))
        return False
    if peers:
        peers_li = putils.utils.make_list(peers)
        for port in peers_li:
            '''
            port_vars = port.split('.')
            if len(port_vars)>1:
                intf_name=port_vars[0]
                intf_sub_id=port_vars[1]
            else:
                intf_name=port_vars[0]
                intf_sub_id = ''
            if '/' in intf_name:
                intf_othr = st.get_other_names(dut, [intf_name])[0]
            else:
                intf_othr = intf_name
            if intf_sub_id:
                peer = intf_othr.replace('Ethernet','Eth').replace('PortChannel','Po')
                peer+='.'+intf_sub_id
            else:
                peer = intf_othr
            '''
            peer = convert_intf_name_to_component(dut, intf_list=port, component='applications')
            if state and state.get(port):
                peer += state.get(port)
            if peer not in entries[0]['peers'].split():
                st.log("No match found for peer {}".format(peer))
                return False
    return True


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
        self.cli_type = 'klish' if self.cli_type in ['rest-patch', 'rest-put'] + get_supported_ui_type_list() else self.cli_type
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


def get_bgp_ipv6_neighbor_vtysh(dut, params):
    """
     out = bgpapi.get_bgp_ipv6_neighbor_vtysh(dut,['neighborintf','updatesent'])
    :param dut:
    :param neighbor_ip:
    :param params:
    :param kwargs:
    :return:
    """
    output = show_bgp_ipv6_neighbor_vtysh(dut)
    st.debug(output)
    params = make_list(params)
    retval = filter_and_select(output, params)
    return retval[0] if isinstance(retval, list) and retval else {}


def config_bgp_community_list(dut, *argv, **kwargs):
    '''

    :param dut:
    :param argv:
    :param kwargs:
    :return:
    '''
    cli_type = override_supported_ui("rest-put", "rest-patch", "click",
                                     cli_type=st.get_ui_type(dut, **kwargs), default="vtysh")

    community_type = kwargs.get('community_type', False)
    community_name = kwargs.get('community_name', False)
    action = kwargs.get('action', False)

    if not (community_type and community_name and action):
        st.log("provide the mandatory params")
        return False

    config_cmd = " " if kwargs.get('config', 'yes') == 'yes' else 'no '
    cmd = "{}bgp community-list {} {} {}".format(config_cmd, community_type, community_name, action)
    if kwargs.get('community_num'):
        cmd += " {}".format(kwargs['community_num'])
    if 'local_as' in argv:
        cmd += " {}".format('local-as')
    if 'no_advertise' in argv:
        cmd += " {}".format('no-advertise')
    if 'no-peer' in argv:
        cmd += " {}".format('no-peer')
    if 'no-export' in argv:
        cmd += " {}".format('no-export')
    if kwargs.get('command_type'):
        cmd += " {}".format(kwargs['command_type'])
    st.config(dut, cmd, type=cli_type)
    return True


def config_bgp_ext_community_list(dut, *argv, **kwargs):
    '''
    To configure extended community list

    Author: Karuppiah Dharmaraj (karuppiah.dharmaraj@dell.com)
    Modified: Naveen Nagaraju (naveen.nagaraju@broadcom.com)
    :param dut:
    :param : attribute : rt|soo
    :param : cli_type : click|klish
    :param : community_type : standard|expanded
    :param : community_name:
    :param : action : permit|deny
    :param : expr : regular expression
    :param : ext_community_num : A.B.C.D | AA:NN
    :param : command_type: any|all
    :param : config : yes|no
    :return:

    Eg : bgp.config_bgp_ext_community_list(dut1, 'rt', community_type='standard', community_name='comm_test2', action='permit', ext_community_num='101:100')
         bgp.config_bgp_ext_community_list(dut1, 'soo', community_type='standard', community_name='comm_test3', action='deny', ext_community_num='64512:10', command_type='all', config='no')
         bgp.config_bgp_ext_community_list(dut1, community_type='expanded', community_name='comm_test1', action='permit', expr='^65100')

         If we need to remove the global ext community list, we needn't pass the action param and config = 'no'
         bgp.config_bgp_ext_community_list(dut1, community_type='standard', community_name='comm_test2',config='no')

    '''

    cli_type = override_supported_ui("rest-put", "rest-patch", "click",
                                     cli_type=st.get_ui_type(dut, **kwargs), default="vtysh")

    community_type = kwargs.get('community_type', False)
    community_name = kwargs.get('community_name', False)
    action = kwargs.get('action', False)
    config = kwargs.get('config', 'yes')

    config_cmd = " " if config == 'yes' else 'no '
    if config == 'yes':
        if not (community_type and community_name and action):
            st.log("provide the mandatory params")
            return False
    else:
        if not (community_type and community_name):
            st.log("provide the mandatory params for unconfig")
            return False

    if action:
        cmd = "{}bgp extcommunity-list {} {} {}".format(config_cmd, community_type, community_name, action)
        if kwargs.get('expr'):
            cmd += " {}".format(kwargs['expr'])
        if 'rt' in argv:
            cmd += " rt {}".format(kwargs['ext_community_num'])
        if 'soo' in argv:
            cmd += " soo {}".format(kwargs['ext_community_num'])
        if kwargs.get('command_type'):
            cmd += " {}".format(kwargs['command_type'])
    else:
        cmd = "{}bgp extcommunity-list {} {}".format(config_cmd, community_type, community_name)

    st.config(dut, cmd, type=cli_type)
    return True


def get_bgp_ipv4_neighbor_vtysh(dut, params):
    """
     out = bgpapi.get_bgp_ipv4_neighbor_vtysh(dut,['neighborintf','updatesent'])
    :param dut:
    :param neighbor_ip:
    :param params:
    :param kwargs:
    :return:
    """
    output = show_bgp_ipv4_neighbor_vtysh(dut)
    st.debug(output)
    params = make_list(params)
    retval = filter_and_select(output, params)
    return retval[0] if isinstance(retval, list) and retval else ""


def config_bgp_dampen(dut, local_asn, **kwargs):
    """
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    :param dut:
    :param local_asn: LOCAL AS no
    :param vrf_name: VRF name
    :param version: ["ipv4"|"ipv6"]
    :param half_life_time: half life time for prenalty
    :param reuse_limit: route reuse limit
    :param suppress_limit: route suppress limit
    :param max_suppress_time: route max suppress time
    :param max_suppress_limit: route max suppress limit
    :param config: config = ["yes"|"no"]
    :return:
    Example:
         config_bgp_dampen(vars.D1,local_asn="100",half_life_time="1",reuse_limit="750",suppress_limit="2000",max_suppress_limit="3")
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut, **kwargs))
    skip_error_check = kwargs['skip_error_check'].lower() if 'skip_error_check' in kwargs else 'no'
    if 'config' not in kwargs:
        kwargs['config'] = "yes"
    if cli_type in get_supported_ui_type_list():
        vrf = kwargs['vrf_name'] if 'vrf_name' in kwargs and kwargs['vrf_name'] != 'default-vrf' else 'default'
        ni_obj = umf_ni.NetworkInstance(Name=vrf)
        proto_obj = umf_ni.Protocol(ProtoIdentifier='BGP', Name='bgp', NetworkInstance=ni_obj)
        proto_kwarg = {}
        if 'config' in kwargs and kwargs['config'] != "no":
            proto_kwarg['RouteFlapDampingEnabled'] = True
            if 'half_life_time' in kwargs:
                proto_kwarg['HalfLife'] = kwargs['half_life_time']
            if 'reuse_limit' in kwargs:
                proto_kwarg['ReuseThreshold'] = kwargs['reuse_limit']
            if 'suppress_limit' in kwargs:
                proto_kwarg['SuppressThreshold'] = kwargs['suppress_limit']
            if 'max_suppress_limit' in kwargs:
                proto_kwarg['MaxSuppress'] = kwargs['max_suppress_limit']
        else:
            proto_kwarg['RouteFlapDampingEnabled'] = False
        gbl_afi_safi_obj = umf_ni.GlobalAfiSafi(AfiSafiName='IPV4_UNICAST', Protocol=proto_obj, **proto_kwarg)
        str1 = ""
        for key in proto_kwarg.keys():
            str1 += " {} = {},".format(key, proto_kwarg[key])
        st.banner("Configure BGP dampending attributes:{}".format(str1))
        result = gbl_afi_safi_obj.configure(dut, cli_type=cli_type)
        if not result.ok():
            st.log('test_step_failed: Configure BGP dampending attributes {}'.format(result.data))
            return False
        return True
    elif cli_type in ["click", "vtysh"]:
        if "vrf_name" not in kwargs:
            command = "router bgp {}".format(local_asn)
        else:
            command = "router bgp {} vrf {}".format(local_asn, kwargs['vrf_name'])
        if 'config' in kwargs and kwargs['config'] == "no":
            command += "\n no bgp dampening"
            command += "\n exit"
            st.config(dut, command, type=cli_type, skip_error_check=skip_error_check)
            return True
        if 'half_life_time' in kwargs:
            command += "\n bgp dampening {}".format(kwargs['half_life_time'])
        if 'reuse_limit' in kwargs:
            command += " {}".format(kwargs['reuse_limit'])
        if 'suppress_limit' in kwargs:
            command += " {}".format(kwargs['suppress_limit'])
        if 'max_suppress_limit' in kwargs:
            command += " {}".format(kwargs['max_suppress_limit'])
        command += "\n exit"
    else:
        if "vrf_name" not in kwargs:
            command = "router bgp {}".format(local_asn)
        else:
            command = "router bgp {} vrf {}".format(local_asn, kwargs['vrf_name'])
        command += "\n address-family ipv4 unicast"
        if 'config' in kwargs and kwargs['config'] == "no":
            command += "\n no dampening"
            command += "\n exit \n exit"
            st.config(dut, command, type=cli_type, skip_error_check=skip_error_check)
            return True
        if 'half_life_time' in kwargs:
            command += "\n dampening {}".format(kwargs['half_life_time'])
        if 'reuse_limit' in kwargs:
            command += " {}".format(kwargs['reuse_limit'])
        if 'suppress_limit' in kwargs:
            command += " {}".format(kwargs['suppress_limit'])
        if 'max_suppress_limit' in kwargs:
            command += " {}".format(kwargs['max_suppress_limit'])
        command += "\n exit \n exit"
    st.config(dut, command, type=cli_type, skip_error_check=skip_error_check)
    return True


def verify_bgp_dampened_attributes(dut, **kwargs):
    """
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    :param dut:
    :param vrf_name: VRF name
    :param half_life_time: half life time for prenalty
    :param reuse_limit: route reuse limit
    :param suppress_limit: route suppress limit
    :param max_suppress_limit: route max suppress limit
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut, **kwargs))
    if cli_type in get_supported_ui_type_list():
        vrf = kwargs['vrf_name'] if 'vrf_name' in kwargs and kwargs['vrf_name'] != 'default-vrf' else 'default'
        ni_obj = umf_ni.NetworkInstance(Name=vrf)
        proto_obj = umf_ni.Protocol(ProtoIdentifier='BGP', Name='bgp', NetworkInstance=ni_obj)
        proto_kwarg = {}
        proto_kwarg['RouteFlapDampingEnabled'] = True
        if 'half_life_time' in kwargs:
            proto_kwarg['HalfLife'] = int(kwargs['half_life_time'])
        if 'reuse_limit' in kwargs:
            proto_kwarg['ReuseThreshold'] = int(kwargs['reuse_limit'])
        if 'suppress_limit' in kwargs:
            proto_kwarg['SuppressThreshold'] = int(kwargs['suppress_limit'])
        if 'max_suppress_time' in kwargs:
            proto_kwarg['MaxSuppress'] = int(kwargs['max_suppress_time'])
        gbl_afi_safi_obj = umf_ni.GlobalAfiSafi(AfiSafiName='IPV4_UNICAST', Protocol=proto_obj, **proto_kwarg)
        str1 = ""
        for key in proto_kwarg.keys():
            str1 += " {} = {},".format(key, proto_kwarg[key])
        st.banner("Verify BGP dampending attributes:{}".format(str1))
        result = gbl_afi_safi_obj.verify(dut, match_subset=True, cli_type="gnmi")
        if not result.ok():
            st.log('test_step_failed: Verify BGP dampending attributes {}'.format(result.data))
            return False
        return True
    elif cli_type == 'klish':
        cmd = "show bgp ipv4 unicast"
        if "vrf_name" in kwargs:
            cmd += " vrf {}".format(kwargs["vrf_name"])
            kwargs.pop("vrf_name")
        cmd += " dampening parameters"
        output = st.show(dut, cmd, type=cli_type)
        if len(output) == 0:
            st.error("Output is Empty")
            return False

        count = 0
        no_common_key = 0
        ret_val1 = False
        dict1 = {}
        common_key_list = ['half_life_time', 'reuse_limit', 'suppress_limit', 'max_suppress_limit']

        for key in kwargs:
            if key in common_key_list:
                no_common_key = no_common_key + 1

        if no_common_key > 0:
            rlist = output[0]
            count = 0
            for key in kwargs:
                if rlist[key] == kwargs[key] and key in common_key_list:
                    count = count + 1
            if no_common_key == count:
                ret_val1 = True
                for key in kwargs:
                    if key in common_key_list:
                        st.log("Match: Match key {} found => {} : {}".format(key, kwargs[key], rlist[key]))
            else:
                for key in kwargs:
                    if key in common_key_list:
                        if rlist[key] == kwargs[key]:
                            st.log("Match: Match key {} found => {} : {}".format(key, kwargs[key], rlist[key]))
                        else:
                            st.log("No-Match: Match key {} NOT found => {} : {}".format(key, kwargs[key], rlist[key]))
                st.log("\n")

            for key in common_key_list:
                if key in kwargs:
                    dict1[key] = kwargs[key]
                    del kwargs[key]

        if no_common_key > 0 and ret_val1 is False:
            st.error("DUT {} -> Match Not Found {}".format(dut, dict1))
            return ret_val1
        return True


def verify_bgp_ipv4_unicast_dampened_paths(dut, **kwargs):
    """
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    verify_bgp_ipv4_unicast_dampened_paths(dut=dut1,path="",origin_code="i",network="131.1.1.0/24")

    To verify bgp ipv4 unicast vrf <vrf-name> dampening dampened-paths
    :param dut:
    :param router_id:
    :param local_as:
    :param local_pref:
    :param origin_code:
    :param path:
    :param status_code:
    :param network:
    :param from_neigh:
    :param reuse:
    :param vrf_name:
    :return:
    """
    cli_type = "klish"

    cmd = "show bgp ipv4 unicast"
    if "vrf_name" in kwargs:
        cmd += " vrf {}".format(kwargs["vrf_name"])
        kwargs.pop("vrf_name")
    cmd += " dampening dampened-paths"
    output = st.show(dut, cmd, type=cli_type)
    if len(output) == 0:
        st.error("Output is Empty")
        return False
    return verify_bgp_ipv4_unicast_dampened_api(dut, output, **kwargs)


def verify_bgp_ipv4_unicast_dampened_flap_stats(dut, **kwargs):
    """
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    verify_bgp_ipv4_unicast_dampened_flap_stats(dut=dut1,path="",origin_code="i",network="131.1.1.0/24")

    To verify bgp ipv4 unicast vrf <vrf-name> dampening flap-statistics
    :param dut:
    :param router_id:
    :param local_as:
    :param local_pref:
    :param origin_code:
    :param path:
    :param status_code:
    :param network:
    :param from_neigh:
    :param flaps:
    :param duration:
    :param vrf_name:
    :return:
    """
    cli_type = "klish"
    cmd = "show bgp ipv4 unicast"
    if "vrf_name" in kwargs:
        cmd += " vrf {}".format(kwargs["vrf_name"])
        kwargs.pop("vrf_name")
    cmd += " dampening flap-statistics"
    output = st.show(dut, cmd, type=cli_type)
    if len(output) == 0:
        st.error("Output is Empty")
        return False

    if 'return_output' in kwargs:
        return output
    return verify_bgp_ipv4_unicast_dampened_api(dut, output, **kwargs)


def verify_bgp_ipv4_unicast_dampened_api(dut, output, **kwargs):
    count = 0
    no_common_key = 0
    ret_val1 = False
    dict1 = {}
    common_key_list = ['local_as', 'router_id', 'local_pref']

    for key in kwargs:
        if key in common_key_list:
            no_common_key = no_common_key + 1

    if no_common_key > 0:
        rlist = output[0]
        count = 0
        for key in kwargs:
            if rlist[key] == kwargs[key] and key in common_key_list:
                count = count + 1
        if no_common_key == count:
            ret_val1 = True
            for key in kwargs:
                if key in common_key_list:
                    st.log("Match: Match key {} found => {} : {}".format(key, kwargs[key], rlist[key]))
        else:
            for key in kwargs:
                if key in common_key_list:
                    if rlist[key] == kwargs[key]:
                        st.log("Match: Match key {} found => {} : {}".format(key, kwargs[key], rlist[key]))
                    else:
                        st.log("No-Match: Match key {} NOT found => {} : {}".format(key, kwargs[key], rlist[key]))
            st.log("\n")

        for key in common_key_list:
            if key in kwargs:
                dict1[key] = kwargs[key]
                del kwargs[key]

    if no_common_key > 0 and ret_val1 is False:
        st.error("DUT {} -> Match Not Found {}".format(dut, dict1))
        return ret_val1

    ret_val = True
    input_dict_list = kwargs_to_dict_list(**kwargs)
    for input_dict in input_dict_list:
        entries = filter_and_select(output, None, match=input_dict)
        if entries:
            st.log("DUT {} -> Match Found {} ".format(dut, input_dict))
        else:
            st.error("DUT {} -> Match Not Found {}".format(dut, input_dict))
            ret_val = False

    return ret_val


def config_bgp_capability(dut, local_as, neighbor, input_param, **kwargs):
    """
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    :param dut:
    :param local_as: LOCAL AS no
    :param neighbor: NEIGHBOR IP
    :param vrf_name: VRF NAME (Optional arg)
    :param config: ["yes"|"no"]
    :param input_param: ["dont_capability_negotiate" | "strict_capability_match"]
    :return: [True | False]
    Example:
         config_bgp_dont_capability_negotiate(vars.D1,local_as="100",neighbor="10.1.1.2",config="yes")
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut, **kwargs))
    cli_type = override_ui(cli_type=cli_type, default="vtysh")
    vrf = kwargs['vrf_name'] if 'vrf_name' in kwargs and kwargs['vrf_name'] != 'default-vrf' else 'default'
    config = "yes" if "config" not in kwargs else kwargs['config']
    config = " " if kwargs['config'].lower() == "yes" else "no"

    skip_error_check = kwargs['skip_error_check'].lower() if 'skip_error_check' in kwargs else 'no'
    if 'vrf_name' in kwargs and vrf == 'default':
        command = "router bgp {}".format(local_as)
    else:
        command = "router bgp {} vrf {}".format(local_as, vrf)

    if cli_type in get_supported_ui_type_list():
        kwarg1 = {}
        kwarg1['cli_type'] = cli_type
        kwarg1['vrf'] = vrf
        kwarg1['config'] = "yes"
        if input_param == "strict_capability_match":
            kwarg1['strict_capability_match'] = True if kwargs['config'].lower() == "yes" else False
        if input_param == "dont_capability_negotiate":
            kwarg1['dont_negotiate_capability'] = True if kwargs['config'].lower() == "yes" else False
        return config_bgp_neighbor_properties(dut, local_asn=local_as, neighbor_ip=neighbor, **kwarg1)
    elif cli_type in ["click", "vtysh"]:
        if input_param == "dont_capability_negotiate":
            command += "\n {} neighbor {} dont-capability-negotiate".format(config, neighbor)
        if input_param == "strict_capability_match":
            command += "\n {} neighbor {} strict-capability-match".format(config, neighbor)
        command += "\n exit"
        st.config(dut, command, type="vtysh", skip_error_check=skip_error_check)
    else:
        command += "\n neighbor {}".format(neighbor)
        if input_param == "dont_capability_negotiate":
            command += "\n {} dont-capability-negotiate".format(config)
        if input_param == "strict_capability_match":
            command += "\n {} strict-capability-match".format(config)
        command += "\n exit \n exit"
        st.config(dut, command, type="klish", skip_error_check=skip_error_check)
    return True


def config_bgp_addpath(dut, local_as, neighbor, version, input_param, **kwargs):
    """
    Author: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    :param dut:
    :param local_as: LOCAL AS no (optional for GNMI but mandetory for klish)
    :param neighbor: NEIGHBOR IP
    :param config: ["yes"|"no"]
    :param input_param: ["addpath_tx_all_paths" | "addpath_tx_bestpath_per_as"]
    :return: [True | False]
    Example:
         config_bgp_addpath(dut,local_as="100",neighbor="1.1.1.1",version="ipv4",
                            input_param="addpath_tx_all_paths",config="yes")
         config_bgp_addpath(dut,local_as="200",neighbor="24.24.1.2",version="ipv4",
                            input_param="addpath_tx_bestpath_per_as",config="yes",cli_type="gnmi")
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut, **kwargs))
    cli_type = override_ui(cli_type=cli_type, default="vtysh")
    config = "yes" if "config" not in kwargs else kwargs['config']
    vrf = kwargs['vrf_name'] if 'vrf_name' in kwargs and kwargs['vrf_name'] != 'default-vrf' else 'default'
    if cli_type in get_supported_ui_type_list():
        kwarg1 = {}
        kwarg1['vrf'] = vrf
        if input_param == "addpath_tx_all_paths":
            kwarg1['TxAddPaths'] = "TX_ALL_PATHS"
        if input_param == "addpath_tx_bestpath_per_as":
            kwarg1['TxAddPaths'] = "TX_BEST_PATH_PER_AS"
        kwarg1['cli_type'] = cli_type
        kwarg1['config'] = config
        return config_bgp_neighbor_properties(dut, local_asn=local_as, neighbor_ip=neighbor, family=version, **kwarg1)
    else:
        skip_error_check = kwargs['skip_error_check'].lower() if 'skip_error_check' in kwargs else 'no'
        config = " " if kwargs['config'].lower() == "yes" else "no"
        if 'vrf_name' in kwargs and vrf == 'default':
            command = "router bgp {}".format(local_as)
        else:
            command = "router bgp {} vrf {}".format(local_as, vrf)
        command += "\n neighbor {}".format(neighbor)
        if version == "ipv4":
            command += "\n address-family ipv4 unicast"
        if version == "ipv6":
            command += "\n address-family ipv6 unicast"
        if input_param == "addpath_tx_all_paths":
            command += "\n {} addpath-tx-all-paths".format(config)
        if input_param == "addpath_tx_bestpath_per_as":
            command += "\n {} addpath-tx-bestpath-per-as".format(config)
        command += "\n exit \n exit \n exit"
        st.config(dut, command, type=cli_type, skip_error_check=skip_error_check)
    return True


def get_ip_bgp_community(dut, family='ipv4', **kwargs):
    cli_type = get_show_cli_type(dut, **kwargs)
    route = kwargs.get('route', None)
    command = "show bgp {} unicast {}".format(family, route)
    del [kwargs['route']]
    output = st.show(dut, command, type=cli_type)
    st.debug(output)
    st.banner(output)
    kwargs.pop("cli_type", None)
    for each in kwargs.keys():
        match = {each: kwargs[each]}
        get_list = ["community"]
        st.log(match)
        entries = filter_and_select(output, get_list, match)
        st.log(entries)
        if not entries:
            st.log("Could not get bgp route info")
            return False
    return entries


def verify_bgp_neigh_umf(dut, vrf, family, **kwargs):
    cli_type = kwargs['cli_type']
    del kwargs['cli_type']
    for key in kwargs:
        if type(kwargs[key]) is list:
            kwargs[key] = list(kwargs[key])
        else:
            kwargs[key] = [kwargs[key]]
    gnmi_result = True
    filter_type = kwargs.get('filter_type', 'ALL')
    query_param_obj = get_query_params(yang_data_type=filter_type, cli_type=cli_type)
    ni_obj = umf_ni.NetworkInstance(Name=vrf)
    proto_obj = umf_ni.Protocol(ProtoIdentifier='BGP', Name='bgp', NetworkInstance=ni_obj)
    afi_safi_mapping = {
        'ipv4': 'IPV4_UNICAST',
        'ipv6': 'IPV6_UNICAST',
        'l2vpn': 'L2VPN_EVPN',
    }
    umf_ni.GlobalAfiSafi(AfiSafiName=afi_safi_mapping[family], Protocol=proto_obj)
    for neigh in kwargs['neighborip']:

        nbr_index = kwargs['neighborip'].index(neigh)
        nbr_attr_list = {
            'keep_alive': ['KeepaliveInterval', int(kwargs['keep_alive'][nbr_index]) if 'keep_alive' in kwargs else None],
            'hold': ['HoldTime', int(kwargs['hold'][nbr_index]) if 'hold' in kwargs else None],
            'remote_asn': ['PeerAs', kwargs['remote_asn'][nbr_index] if 'remote_asn' in kwargs else None],
            'password': ['Password', kwargs['password'][nbr_index] if 'password' in kwargs else None],
            'connect': ['ConnectRetry', int(kwargs['connect'][nbr_index]) if 'connect' in kwargs else None],
            'ebgp_multihop': ['MultihopTtl', int(kwargs['ebgp_multihop'][nbr_index]) if 'ebgp_multihop' in kwargs else None],
            'update_src': ['LocalAddress', kwargs['update_src'][nbr_index] if 'update_src' in kwargs else None],
            'update_src_intf': ['LocalAddress', kwargs['update_src_intf'][nbr_index] if 'update_src_intf' in kwargs else None],
            'enforce_first_as': ['EnforceFirstAs', True if 'enforce_first_as' in kwargs else None],
            # 'local_as': ['LocalAs', kwargs['local_as'][nbr_index] if 'local_as' in kwargs else None],
            'local_as_no_prepend': ['LocalAsNoPrepend', True if 'local_as_no_prepend' in kwargs else None],
            'local_as_replace_as': ['LocalAsReplaceAs', True if 'local_as_replace_as' in kwargs else None],
            'bfd': ['EnableBfdEnabled', True if 'bfd' in kwargs else None],
            'bfd_profile': ['BfdProfile', kwargs['bfd_profile'][nbr_index] if 'bfd_profile' in kwargs else None],
            'state': ['SessionState', kwargs['state'][nbr_index] if 'state' in kwargs else None],
            'bgpdownreason': ['LastResetReason', kwargs['bgpdownreason'][nbr_index] if 'bgpdownreason' in kwargs else None],
        }
        if nbr_attr_list['bgpdownreason'][1] in ['BFD down received', 'Interface down', 'Hold Timer Expired']:
            nbr_attr_list['bgpdownreason'] = ['LastResetReason', 'Waiting for NHT']
        if nbr_attr_list['remote_asn'][1] is not None:
            if str(nbr_attr_list['remote_asn'][1]).isdigit():
                nbr_attr_list['remote_asn'][1] = int(nbr_attr_list['remote_asn'][1])
            elif str(nbr_attr_list['remote_asn'][1]) == 'internal':
                nbr_attr_list['remote_asn'] = ['PeerType', 'INTERNAL']
            else:
                nbr_attr_list['remote_asn'] = ['PeerType', 'EXTERNAL']
        if nbr_attr_list['state'][1] is not None:
            nbr_attr_list['state'] = ['SessionState', nbr_attr_list['state'][1].upper()]
        nbr_obj = umf_ni.BgpNeighbor(NeighborAddress=neigh, Protocol=proto_obj)
        for key in kwargs.keys():
            if key != 'neighborip':
                if key in nbr_attr_list:
                    if nbr_attr_list[key][1] is not None:
                        setattr(nbr_obj, nbr_attr_list[key][0], nbr_attr_list[key][1])
                else:
                    st.error("Kindly add Argument {} to this variable \"nbr_attr_list\" "
                             "in API \"verify_bgp_neigh_umf\"".format(key))
                    return False
        result = nbr_obj.verify(dut, match_subset=True, query_param=query_param_obj, cli_type=cli_type)
        if not result.ok():
            gnmi_result = False
            st.log("Match NOT found for neighbor {}; kindly check actual and expected fields above".format(neigh))
        else:
            st.log("Match found for neighbor {}".format(neigh))
    return gnmi_result


def init_default_config(dut):
    if st.is_feature_supported("remove-default-bgp", dut):
        unconfig_router_bgp(dut)
