from spytest import st, utils
from spytest.utils import filter_and_select
from utilities.utils import get_interface_number_from_name
from apis.system.rest import config_rest, delete_rest, get_rest
from apis.routing.ip import configure_loopback


def verify_vrf(dut, **kwargs):
    """
    verify_vrf(dut1,vrfname="Vrf-103")
    """

    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut))
    # cli_type = "klish" if cli_type in ["rest-put", "rest-patch"] else cli_type
    if 'vrfname' in kwargs:
        if not isinstance(kwargs['vrfname'], list):
            vname_list = [kwargs['vrfname']]
        else:
            vname_list = kwargs['vrfname']
    else:
        st.log("Mandatory parameter vrfname is not found")
        return False
    if cli_type == 'click':
        st.log("verify show vrf output")
        cmd = "show vrf"
        output = st.show(dut, cmd)
        for vname in vname_list:
            match = {"vrfname": vname}
            entries = filter_and_select(output, ["vrfname"], match)
            if not bool(entries):
                return bool(entries)
        return True
    elif cli_type == 'klish':
        cmd = 'show ip vrf'
        output = st.show(dut, cmd, type=cli_type)
        for vname in vname_list:
            match = {"vrfname": vname}
            entries = filter_and_select(output, ["vrfname"], match)
            if not bool(entries):
                return bool(entries)
        return True
    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        for vname in vname_list:
            rest_url = rest_urls['vrf_config'].format(vname)
            payload = get_rest(dut, rest_url=rest_url)['output']['openconfig-network-instance:network-instance']
            for item in payload:
                if item['state']['type'] != 'openconfig-network-instance-types:L3VRF':
                    return False
                if item['state']['name'] != str(vname):
                    return False
        return True
    else:
        st.log("Unsupported cli")


def verify_vrf_verbose(dut, **kwargs):
    """
    verify_vrf_verbose(dut1,vrfname="Vrf-103",interface='Ethernet2')
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut))
    # cli_type = "klish" if cli_type in ["rest-put", "rest-patch"] else cli_type
    vrfname = kwargs['vrfname']
    interface = kwargs['interface']
    if not isinstance(vrfname, list):
        vrfname = [vrfname]
    if cli_type == 'click':
        cmd = "show vrf --verbose"
        if not st.is_feature_supported("show-vrf-verbose-command", dut):
            st.community_unsupported(cmd, dut)
            cmd = "show vrf"
        st.log("verify {} output".format(cmd))
        output = st.show(dut, cmd)
        for vname, intf in zip(vrfname, interface):
            match = {"vrfname": vname, "interfaces": intf}
            entries = filter_and_select(output, ["vrfname"], match)
            if not bool(entries):
                return bool(entries)
        return True
    elif cli_type == 'klish':
        cmd = "show ip vrf"
        output = st.show(dut, cmd, type=cli_type)
        for vname, intf in zip(vrfname, interface):
            match = {"vrfname": vname, "interfaces": intf}
            entries = filter_and_select(output, ["vrfname"], match)
            if not bool(entries):
                return bool(entries)
        return True
    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        for vname, intf in zip(vrfname, interface):
            rest_url = rest_urls['vrf_config'].format(vname)
            payload = get_rest(dut, rest_url=rest_url)['output']['openconfig-network-instance:network-instance']
            for item in payload:
                if item['state']['type'] != 'openconfig-network-instance-types:L3VRF':
                    return False
                if item['state']['name'] != str(vname):
                    return False
                for intface in item['interfaces']['interface']:
                    if intface['state']['id'] == intf:
                        return False
        return True
    else:
        st.log("Unsupported cli")


def get_vrf_verbose(dut, **kwargs):
    """
    get_vrf_verbose(dut1,vrfname="Vrf-1")
    """
    match_dict = {}
    if 'vrfname' in kwargs:
        match_dict['vrfname'] = kwargs['vrfname']
    else:
        st.error("Mandatory parameter peeraddress is not found")
        return False

    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut))
    # cli_type = "klish" if cli_type in ["rest-put", "rest-patch"] else cli_type
    if cli_type == 'click':
        cmd = "show vrf --verbose"
        if not st.is_feature_supported("show-vrf-verbose-command", dut):
            st.community_unsupported(cmd, dut)
            cmd = "show vrf"
        st.log("get {} output".format(cmd))
        output = st.show(dut, cmd)
        if len(output) == 0:
            st.error("OUTPUT is Empty")
            return []
        entries = filter_and_select(output, None, match_dict)
        return entries[0]
    elif cli_type == 'klish':
        cmd = "show ip vrf"
        output = st.show(dut, cmd, type=cli_type)
        entries = filter_and_select(output, None, match_dict)
        if len(output) == 0:
            st.error("OUTPUT is Empty")
            return []
        return entries[0]
    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        vname = kwargs['vrfname']
        vrf_info = {}
        interfaces = []
        rest_url = rest_urls['vrf_config'].format(vname)
        payload = get_rest(dut, rest_url=rest_url)['output']['openconfig-network-instance:network-instance']
        # klish output = {u'interfaces': ['PortChannel10', 'Vlan3'], u'vrfname': 'Vrf-103'}
        for item in payload:
            vrf_info['vrfname'] = item['state']['name']
            for interface in item['interfaces']['interface']:
                interfaces.append(interface['state']['id'])
        vrf_info['interfaces'] = interfaces
        return vrf_info


def config_vrf(dut, **kwargs):
    """
    #Sonic cmd: Config vrf <add | delete> <VRF-name>
    eg: config_vrf(dut = dut1, vrf_name = 'Vrf-test', config = 'yes')
    eg: config_vrf(dut = dut1, vrf_name = 'Vrf-test', config = 'no')
    """
    st.log('Config VRF API')
    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = 'yes'
    if 'vrf_name' in kwargs:
        if not isinstance(kwargs['vrf_name'], list):
            vrf_name = [kwargs['vrf_name']]
        else:
            vrf_name = kwargs['vrf_name']
    else:
        st.log("Mandatory parameter vrfname is not found")
    if 'skip_error' in kwargs:
        skip_error = kwargs['skip_error']
    else:
        skip_error = False
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut))
    if cli_type == 'click':
        my_cmd = ''
        if config.lower() == 'yes':
            for vrf in vrf_name:
                my_cmd += 'sudo config vrf add {}\n'.format(vrf)
        else:
            for vrf in vrf_name:
                my_cmd += 'sudo config vrf del {}\n'.format(vrf)
        if skip_error:
            try:
                st.config(dut, my_cmd)
                return True
            except Exception:
                st.log("Error handled..by API")
                return False
        else:
            st.config(dut, my_cmd)
            return True
    elif cli_type == 'klish':
        command = ''
        if config.lower() == 'yes':
            for vrf in vrf_name:
                command = command + "\n" + "ip vrf {}".format(vrf)
        else:
            for vrf in vrf_name:
                command = command + "\n" + "no ip vrf {}".format(vrf)
        output = st.config(dut, command, skip_error_check=skip_error, type="klish", conf=True)
        if "Could not connect to Management REST Server" in output:
            st.error("klish mode not working.")
            return False
        return True
    elif cli_type in ['rest-patch', 'rest-put']:
        http_method = kwargs.pop('http_method', cli_type)
        rest_urls = st.get_datastore(dut, 'rest_urls')
        if config.lower() == 'yes':
            for vrf in vrf_name:
                rest_url = rest_urls['vrf_config'].format(vrf)
                ocdata = {"openconfig-network-instance:network-instance":
                          [{"name": vrf, "config": {"name": vrf, "enabled": bool(1)}}]}
                response = config_rest(dut, http_method=http_method, rest_url=rest_url, json_data=ocdata)
                if not response:
                    st.log(response)
                    return False
        elif config.lower() == 'no':
            for vrf in vrf_name:
                rest_url = rest_urls['vrf_config'].format(vrf)
                response = delete_rest(dut, rest_url=rest_url)
                if not response:
                    st.log(response)
                    return False
        return True
    else:
        st.log("Unsupported cli")


def bind_vrf_interface(dut, **kwargs):
    """
    #Sonic cmd:
    # config interface bind <interface-name> <vrf-name>
    # config interface unbind <interface-name>
    eg: bind_vrf_interface(dut = dut1, vrf_name = 'Vrf-test', intf_name ='Ethernet8', config = 'no')
    """
    st.log('API to bind interface to VRF')
    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = 'yes'
    if 'vrf_name' in kwargs:
        if not isinstance(kwargs['vrf_name'], list):
            vrf_name = [kwargs['vrf_name']]
        else:
            vrf_name = kwargs['vrf_name']
    else:
        st.log("Mandatory parameter vrfname is not found")
    if 'intf_name' in kwargs:
        if not isinstance(kwargs['intf_name'], list):
            intf_name = [kwargs['intf_name']]
        else:
            intf_name = kwargs['intf_name']
    else:
        st.log("Mandatory parameter intf_name is not found")
    if 'skip_error' in kwargs:
        skip_error = kwargs['skip_error']
    else:
        skip_error = False

    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut))
    if cli_type == 'click':
        my_cmd = ''
        if config.lower() == 'yes':
            for vrf, intf in zip(vrf_name, intf_name):
                if 'Loopback' in intf:
                    if not st.is_feature_supported("config-loopback-add-command", dut):
                        st.log("Community build doesn't need Loopback interface configuration")
                    else:
                        my_cmd += 'sudo config loopback add {}\n'.format(intf)
                my_cmd += 'sudo config interface vrf bind {} {}\n'.format(intf, vrf)
        else:
            for vrf, intf in zip(vrf_name, intf_name):
                if not st.is_feature_supported("vrf-needed-for-unbind", dut):
                    st.log("Unbind operation is not supported in this build")
                else:
                    my_cmd += 'sudo config interface vrf unbind {}\n'.format(intf)
                if 'Loopback' in intf:
                    if not st.is_feature_supported("config-loopback-add-command", dut):
                        st.log("Community build doesn't need Loopback interface un-configuration")
                    else:
                        my_cmd += 'sudo config loopback del {}\n'.format(intf)
        if skip_error:
            st.config(dut, my_cmd, skip_error_check=True)
            return True
        else:
            st.config(dut, my_cmd)
            return True
    elif cli_type == 'klish':
        command = ''
        if config.lower() == 'yes':
            for vrf, intf in zip(vrf_name, intf_name):
                intfv = get_interface_number_from_name(intf)
                command = command + "\n" + "interface {} {}".format(intfv['type'], intfv['number'])
                command = command + "\n" + "ip vrf forwarding {}".format(vrf)
                command = command + "\n" + "exit"
        else:
            for vrf, intf in zip(vrf_name, intf_name):
                intfv = get_interface_number_from_name(intf)
                command = command + "\n" + "interface {} {}".format(intfv['type'], intfv['number'])
                command = command + "\n" + "no ip vrf forwarding {}".format(vrf)
                command = command + "\n" + "exit"
                if 'Loopback' in intf:
                    command = command + "\n" + "no interface {} {}".format(intfv['type'], intfv['number'])
        output = st.config(dut, command, skip_error_check=skip_error, type="klish", conf=True)
        if "Could not connect to Management REST Server" in output:
            st.error("klish mode not working.")
            return False
        return True
    elif cli_type in ['rest-patch', 'rest-put']:
        http_method = kwargs.pop('http_method', cli_type)
        rest_urls = st.get_datastore(dut, 'rest_urls')
        if config.lower() == 'yes':
            for vrf, intf in zip(vrf_name, intf_name):
                intfv = get_interface_number_from_name(intf)
                if 'Loopback' in intfv['type']:
                    configure_loopback(dut, loopback_name=intf, config='yes')
                rest_url = rest_urls['vrf_bind_config'].format(vrf, intf)
                ocdata = {"openconfig-network-instance:interface":
                          [{"id": intf, "config": {"id": intf, "interface": intf}}]}
                response = config_rest(dut, http_method=http_method, rest_url=rest_url, json_data=ocdata)
                if not response:
                    st.log(response)
                    return False
        elif config.lower() == 'no':
            for vrf, intf in zip(vrf_name, intf_name):
                rest_url = rest_urls['vrf_bind_config'].format(vrf, intf)
                response = delete_rest(dut, rest_url=rest_url)
                if not response:
                    st.log(response)
                    return False
                intfv = get_interface_number_from_name(intf)
                if 'Loopback' in intfv['type']:
                    configure_loopback(dut, loopback_name=intf, config='no')
        return True
    else:
        st.log("Unsupported cli")


def config_vrfs(dut, vrf_data_list={}, config='yes', cli_type=''):

    if config == 'yes' or config == 'add':
        config = 'add'
    elif config == 'no' or config == 'del':
        config = 'del'
    else:
        st.error("Invalid config type {}".format(config))
        return False

    cli_type = st.get_ui_type(dut, cli_type=cli_type)

    command = []
    for _, vrf_data in vrf_data_list.items():
        vrf = vrf_data['name']
        if cli_type == 'click':
            cmd_str = "sudo config vrf {} {} ".format(config, vrf)
            command.append(cmd_str)
        elif cli_type == "klish":
            cmd_str = "no " if config == 'del' else ''
            cmd_str += "ip vrf {}".format(vrf)
            command.append(cmd_str)
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


def _clear_vrf_config_helper(dut_list, cli_type=''):
    """
    Helper routine to cleanup VRF config from devices.
    """
    dut_li = list(dut_list) if isinstance(dut_list, list) else [dut_list]
    cli_type = st.get_ui_type(dut_li[0], cli_type=cli_type)
    for dut in dut_li:
        st.log("############## {} : VRF Config Cleanup ################".format(dut))
        if cli_type == 'click':
            output = st.show(dut, "show vrf")
        elif cli_type == 'klish':
            output = st.show(dut, "show ip vrf", type=cli_type)
        st.log("##### VRF : {}".format(output))
        if len(output) == 0:
            continue

        for entry in output:
            if not entry['vrfname']:
                continue
            vrfname = entry['vrfname']
            if type(entry['interfaces']) is list:
                for intf in entry['interfaces']:
                    bind_vrf_interface(dut, vrf_name=vrfname, intf_name=intf, config='no', cli_type=cli_type)

            config_vrf(dut, vrf_name=vrfname, config='no', cli_type=cli_type)

    return True


def clear_vrf_configuration(dut_list, thread=True, cli_type=''):
    """
    Find and cleanup all VRF configuration.

    :param dut_list
    :return:
    """
    dut_li = list(dut_list) if isinstance(dut_list, list) else [dut_list]
    cli_type = st.get_ui_type(dut_li[0], cli_type=cli_type)
    [out, exceptions] = utils.exec_foreach(thread, dut_li, _clear_vrf_config_helper, cli_type=cli_type)
    st.log(exceptions)
    return False if False in out else True
