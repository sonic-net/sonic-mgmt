from spytest import st, utils
from utilities.common import filter_and_select
from utilities.utils import get_interface_number_from_name, is_a_single_intf, segregate_intf_list_type, get_supported_ui_type_list
from apis.system.rest import config_rest, delete_rest, get_rest
from apis.routing.ip import configure_loopback
import utilities.common as common_utils

try:
    import apis.yang.codegen.messages.network_instance as umf_ni
    from apis.yang.utils.common import Operation
except ImportError:
    pass

def verify_vrf(dut,**kwargs):
    """
    verify_vrf(dut1,vrfname="Vrf-103")
    """

    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut))
    #cli_type = "klish" if cli_type in ["rest-put", "rest-patch"] else cli_type
    if 'vrfname' in kwargs:
        if not isinstance(kwargs['vrfname'],list):
            vname_list = [kwargs['vrfname']]
        else:
            vname_list = kwargs['vrfname']
    else:
        st.log("Mandatory parameter vrfname is not found")
        return False

    if cli_type in get_supported_ui_type_list():
        filter_type = kwargs.get('filter_type', 'ALL')
        for vrf_name in vname_list:
            ni_obj = umf_ni.NetworkInstance(Name=vrf_name)
            filter_type = 'NON_CONFIG' if vrf_name in ['mgmt', 'default'] else filter_type
            query_param_obj = common_utils.get_query_params(yang_data_type=filter_type, cli_type=cli_type)
            if vrf_name == 'mgmt':
                mvrf_state = True if kwargs.get('mvrfstate') == 'Enabled' else False
                ni_obj.Enabled = mvrf_state
            target_path = '/state'
            result = ni_obj.verify(dut, match_subset=True, query_param=query_param_obj, target_path=target_path, cli_type=cli_type)
            if not result.ok():
                st.log('test_step_failed: Vrf {} not found'.format(vrf_name))
                return False
        return True
    elif cli_type == 'click':
        st.log("verify show vrf output")
        cmd = "show vrf"
        output = st.show(dut,cmd)
        for vname in vname_list:
            match = {"vrfname":vname}
            entries = filter_and_select(output, ["vrfname"], match)
            if not bool(entries):
                return bool(entries)
        return True
    elif cli_type == 'klish':
        cmd = 'show ip vrf'
        output = st.show(dut,cmd,type=cli_type)
        for vname in vname_list:
            match = {"vrfname":vname}
            entries = filter_and_select(output, ["vrfname"], match)
            if not bool(entries):
                return bool(entries)
        return True
    elif cli_type in ['rest-patch','rest-put']:
        rest_urls = st.get_datastore(dut,'rest_urls')
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

def verify_vrf_verbose(dut,**kwargs):
    """
    verify_vrf_verbose(dut1,vrfname="Vrf-103",interface='Ethernet2')
    """
    st.log('API_NAME: verify_vrf_verbose, API_ARGS: {}'.format(locals()))
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut))
    #cli_type = "klish" if cli_type in ["rest-put", "rest-patch"] else cli_type
    vrfname = kwargs['vrfname']
    interface = kwargs['interface']
    if not isinstance(vrfname,list):
        vrfname = [vrfname]
    if not isinstance(interface,list):
        interface = [interface]

    if cli_type in get_supported_ui_type_list():
        filter_type = kwargs.get('filter_type', 'ALL')
        query_param_obj = common_utils.get_query_params(yang_data_type=filter_type, cli_type=cli_type)
        for vrf_name, intf in zip (vrfname, interface):
            intf_val = intf if intf and not isinstance(intf, list) else intf[0]
            ni_obj = umf_ni.NetworkInstance(Name=vrf_name)
            ni_intf_obj = umf_ni.NetworkInstanceInterface(Id=intf_val, NetworkInstance=ni_obj)
            if vrf_name == 'default':
                filter_type = 'NON_CONFIG'
                query_param_obj = common_utils.get_query_params(yang_data_type=filter_type, cli_type=cli_type)
            result = ni_intf_obj.verify(dut, match_subset=True, query_param=query_param_obj, cli_type=cli_type)
            if not result.ok():
                st.log('test_step_failed: Vrf {}, Interface {} not found'.format(vrf_name,intf_val))
                return False
        return True
    elif cli_type == 'click':
        cmd = "show vrf --verbose"
        if not st.is_feature_supported("show-vrf-verbose-command", dut):
            st.community_unsupported(cmd, dut)
            cmd = "show vrf"
        st.log("verify {} output".format(cmd))
        output = st.show(dut,cmd)
        for vname,intf in zip(vrfname,interface):
            match = {"vrfname":vname,"interfaces": intf}
            entries = filter_and_select(output,["vrfname"],match)
            if not bool(entries):
                return bool(entries)
        return True
    elif cli_type == 'klish':
        cmd = "show ip vrf"
        output = st.show(dut,cmd,type=cli_type)
        for vname,intf in zip(vrfname,interface):
            if intf == "eth0":
                intf = "Management0"
            match = {"vrfname":vname,"interfaces": intf}
            entries = filter_and_select(output,["vrfname"],match)
            if not bool(entries):
                return bool(entries)
        return True
    elif cli_type in ['rest-patch','rest-put']:
        rest_urls = st.get_datastore(dut,'rest_urls')
        for vname,intf in zip(vrfname,interface):
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
    cli_type = "klish" if cli_type in get_supported_ui_type_list() else cli_type
    if cli_type in get_supported_ui_type_list():
        vrf_name=kwargs['vrfname']
        ni_obj = umf_ni.NetworkInstance(Name=vrf_name)
        result = ni_obj.verify(dut, target_attr=ni_obj.Name, cli_type=cli_type)
        if not result.ok():
            st.log('test_step_failed: Vrf {} not found'.format(vrf_name))
            return False
        return result.data
    elif cli_type == 'click':
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
        output = st.show(dut,cmd,type=cli_type)
        entries = filter_and_select(output, None, match_dict)
        if len(output) == 0:
            st.error("OUTPUT is Empty")
            return []
        return entries[0]
    elif cli_type in ['rest-patch','rest-put']:
        rest_urls = st.get_datastore(dut,'rest_urls')
        vname = kwargs['vrfname']
        vrf_info = {}
        interfaces = []
        rest_url = rest_urls['vrf_config'].format(vname)
        payload = get_rest(dut, rest_url=rest_url)['output']['openconfig-network-instance:network-instance']
        #klish output = {u'interfaces': ['PortChannel10', 'Vlan3'], u'vrfname': 'Vrf-103'}
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
        if not isinstance(kwargs['vrf_name'],list):
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
    expect_ipchange = kwargs.get('expect_ipchange', False)

    if cli_type in get_supported_ui_type_list():
        for vrf in vrf_name:
#            vrf_obj = umf_ni.NetworkInstance(Name=vrf, NetworkInstanceEnabled=True)
            vrf_obj = umf_ni.NetworkInstance(Name=vrf, Enabled=True)
            if config.lower()  == 'yes':
                operation = Operation.UPDATE if cli_type == 'gnmi' else Operation.CREATE
                result = vrf_obj.configure(dut, operation=operation, cli_type=cli_type, **kwargs)
            else:
                result = vrf_obj.unConfigure(dut, cli_type=cli_type, **kwargs)
            if not result.ok():
                st.log('test_step_failed: Configuring VRF {}'.format(result.data))
                return False
        return True
    elif cli_type == 'click':
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
            st.config(dut, my_cmd, expect_ipchange=expect_ipchange)
            return True
    elif cli_type == 'klish':
        command = ''
        if config.lower() == 'yes':
            for vrf in vrf_name:
                command = command + "\n" + "ip vrf {}".format(vrf)
        else:
            for vrf in vrf_name:
                command = command + "\n" + "no ip vrf {}".format(vrf)
        output = st.config(dut, command, skip_error_check=skip_error, type="klish",
                           conf=True, expect_ipchange=expect_ipchange, exec_mode='mgmt-config')
        if "Could not connect to Management REST Server" in output:
            st.error("klish mode not working.")
            return False
        elif "%Error:" in output or "% Error:" in output:
            st.error("Observed command failure")
            return False
        return True
    elif cli_type in ['rest-patch','rest-put']:
        http_method = kwargs.pop('http_method',cli_type)
        rest_urls = st.get_datastore(dut,'rest_urls')
        if config.lower() == 'yes':
            for vrf in vrf_name:
                rest_url = rest_urls['vrf_config'].format(vrf)
                ocdata = {"openconfig-network-instance:network-instance":[{"name":vrf,"config":{"name":vrf,"enabled":bool(1)}}]}
                response = config_rest(dut, http_method=http_method, rest_url=rest_url, json_data=ocdata, expect_ipchange=expect_ipchange)
                if not response:
                    st.log(response)
                    return False
        elif config.lower() == 'no':
            for vrf in vrf_name:
                rest_url = rest_urls['vrf_config'].format(vrf)
                response = delete_rest(dut, rest_url=rest_url, expect_ipchange=expect_ipchange)
                if not response:
                    st.log(response)
                    return False
        return True
    else:
        st.log("Unsupported cli")

def bind_vrf_interface_old(dut, **kwargs):
    """
    #Sonic cmd: Config interface <bind |unbind> <interface-name> <vrf-name>
    eg: bind_vrf_interface(dut = dut1, vrf_name = 'Vrf-test', intf_name ='Ethernet8', config = 'no')
    """
    st.log('API to bind interface to VRF')
    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = 'yes'
    if 'vrf_name' in kwargs:
        if not isinstance(kwargs['vrf_name'],list):
            vrf_name = [kwargs['vrf_name']]
        else:
            vrf_name = kwargs['vrf_name']
    else:
        st.log("Mandatory parameter vrfname is not found")
    if 'intf_name' in kwargs:
        if not isinstance(kwargs['intf_name'],list):
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
            for vrf,intf in zip(vrf_name,intf_name):
                if 'Loopback' in intf:
                    if not st.is_feature_supported("config-loopback-add-command", dut):
                        st.warn("build doesn't need Loopback interface configuration", dut=dut)
                    else:
                        my_cmd += 'sudo config loopback add {}\n'.format(intf)
                my_cmd += 'sudo config interface vrf bind {} {}\n'.format(intf, vrf)
        else:
            for vrf,intf in zip(vrf_name,intf_name):
                if not st.is_feature_supported("vrf-needed-for-unbind", dut):
                    my_cmd += 'sudo config interface vrf unbind {}\n'.format(intf)
                else:
                    my_cmd += 'sudo config interface vrf unbind {} {}\n'.format(intf, vrf)
                if 'Loopback' in intf:
                    if not st.is_feature_supported("config-loopback-add-command", dut):
                        st.warn("build doesn't need Loopback interface un-configuration", dut=dut)
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
            for vrf,intf in zip(vrf_name,intf_name):
                intfv = get_interface_number_from_name(intf)
                command = command + "\n" + "interface {} {}".format(intfv['type'], intfv['number'])
                command = command + "\n" + "ip vrf forwarding {}".format(vrf)
                command = command + "\n" + "exit"
        else:
            for vrf,intf in zip(vrf_name,intf_name):
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
    elif cli_type in ['rest-patch','rest-put']:
        http_method = kwargs.pop('http_method',cli_type)
        rest_urls = st.get_datastore(dut,'rest_urls')
        if config.lower() == 'yes':
            for vrf,intf in zip(vrf_name,intf_name):
                intfv = get_interface_number_from_name(intf)
                if 'Loopback' in intfv['type']:
                    configure_loopback(dut, loopback_name=intf, config='yes')
                rest_url = rest_urls['vrf_bind_config'].format(vrf, intf)
                ocdata = {"openconfig-network-instance:interface":[{"id":intf,"config":{"id":intf,"interface":intf}}]}
                response = config_rest(dut, http_method=http_method, rest_url=rest_url, json_data=ocdata)
                if not response:
                   st.log(response)
                   return False
        elif config.lower() == 'no':
            for vrf,intf in zip(vrf_name,intf_name):
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

def bind_vrf_interface(dut, **kwargs):
    """
    Author: pavan.kasula@broadcom.com
    #Sonic cmd: Config interface <bind |unbind> <interface-name> <vrf-name>
    eg: bind_vrf_interface(dut = dut1, vrf_name = 'Vrf-test', intf_name ='Ethernet8', config = 'no')
        bind_vrf_interface(data.dut1, vrf_name = ['Vrf1','Vrf2','Vrf3'], intf_name =['Ethernet1','Ethernet2', 'PortChannel10'])
        bind_vrf_interface(data.dut1, vrf_name = ['Vrf1','Vrf1','Vrf1'], intf_name =['PortChannel5','PortChannel6','Ethernet220-224'])
        bind_vrf_interface(data.dut1, vrf_name = ['Vrf1','Vrf3'], intf_name =['Loopback40','PortChannel40'])
        bind_vrf_interface(data.dut1, vrf_name = ['Vrf1','Vrf1','Vrf1','Vrf1'], intf_name =['Ethernet176','Ethernet180', 'PortChannel20', 'Loopback20'])
        bind_vrf_interface(data.dut1, vrf_name = 'Vrf2', intf_name =['Ethernet188'])
        bind_vrf_interface(data.dut1, vrf_name = ['Vrf1','Vrf2','Vrf3'], intf_name =['Loopback10','Loopback20','Loopback30'],config='no')
    """
    st.log('API to bind interface to VRF')
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut))

    skip_error = kwargs.get('skip_error', False)
    config = kwargs.get('config', 'yes')

    if 'vrf_name' in kwargs:
        if not isinstance(kwargs['vrf_name'], list):
            vrf_name = [kwargs['vrf_name']]
        else:
            vrf_name = kwargs['vrf_name']
    else:
        st.log("Mandatory parameter vrfname is not found")

    if 'intf_name' in kwargs:
        if not isinstance(kwargs['intf_name'], list):
            interface_name = [kwargs['intf_name']]
        else:
            interface_name = kwargs['intf_name']
    else:
        st.log("Mandatory parameter intf_name is not found")

    vrf_name = list(set(vrf_name))
    if len(vrf_name) > 1:
        st.log('vrf_list > 1, support is obsolete')
        return bind_vrf_interface_old(dut, **kwargs)

    vrf_name = vrf_name[0]

    if cli_type in get_supported_ui_type_list():
        port_hash_list = segregate_intf_list_type(intf=interface_name, range_format=False)
        interface_list = port_hash_list['intf_list_all']
        for interface_name in interface_list:
            vrf_obj = umf_ni.NetworkInstance(Name=vrf_name)
            vrf_intf_obj = umf_ni.NetworkInstanceInterface(Id=interface_name, NetworkInstance=vrf_obj)
            if config == 'yes':
                if 'Loopback' in interface_name:
                    configure_loopback(dut, loopback_name=interface_name, config='yes', cli_type=cli_type)
                result = vrf_intf_obj.configure(dut, cli_type=cli_type)
            else:
                result = vrf_intf_obj.unConfigure(dut, cli_type=cli_type)
                if 'Loopback' in interface_name:
                    configure_loopback(dut, loopback_name=interface_name, config='no', cli_type=cli_type)
            if not result.ok():
                st.log('test_step_failed: Binding intf to VRF {}'.format(result.data))
                return False
        return True
    elif cli_type == 'click':
        my_cmd = ''
        port_hash_list = segregate_intf_list_type(intf=interface_name, range_format=False)
        interface_list = port_hash_list['intf_list_all']
        for interface_name in interface_list:
            if config.lower() == 'yes':
                if 'Loopback' in interface_name:
                    if not st.is_feature_supported("config-loopback-add-command", dut):
                        st.warn("build doesn't need Loopback interface configuration", dut=dut)
                    else:
                        my_cmd += 'sudo config loopback add {}\n'.format(interface_name)
                my_cmd += 'sudo config interface vrf bind {} {}\n'.format(interface_name, vrf_name)
            else:
                if not st.is_feature_supported("vrf-needed-for-unbind", dut):
                    my_cmd += 'sudo config interface vrf unbind {}\n'.format(interface_name)
                else:
                    my_cmd += 'sudo config interface vrf unbind {} {}\n'.format(interface_name, vrf_name)
                    if 'Loopback' in interface_name:
                        if not st.is_feature_supported("config-loopback-add-command", dut):
                            st.warn("build doesn't need Loopback interface un-configuration", dut=dut)
                        else:
                            my_cmd += 'sudo config loopback del {}\n'.format(interface_name)
        if skip_error:
            st.config(dut, my_cmd, skip_error_check=True)
            return True
        else:
            st.config(dut, my_cmd)
            return True

    elif cli_type == 'klish':
        command = ''
        config = '' if config.lower() == 'yes' else 'no'
        port_hash_list = segregate_intf_list_type(intf=interface_name, range_format=True)
        interface_list = port_hash_list['intf_list_all']
        for interface_name in interface_list:
            if not is_a_single_intf(interface_name):
                command = command + "\n" + "interface range {}".format(interface_name)
            else:
                intfv = get_interface_number_from_name(interface_name)
                command = command + "\n" + "interface {} {}".format(intfv['type'], intfv['number'])
            command = command + "\n" + " {} ip vrf forwarding {}".format(config, vrf_name)
            command = command + "\n" + "exit" + "\n"
            if config == 'no' and 'Loopback' in interface_name:
                command = command + "\n" + "{} interface {} {}".format(config, intfv['type'], intfv['number'])

        output = st.config(dut, command, skip_error_check=skip_error, type="klish", conf=True, max_time=600)
        if "Could not connect to Management REST Server" in output:
            st.error("klish mode not working.")
            return False
        elif "%Error:" in output or "% Error:" in output:
            st.error("Observed command failure")
            return False
        return True

    elif cli_type in ['rest-patch', 'rest-put']:
        http_method = kwargs.pop('http_method', cli_type)
        rest_urls = st.get_datastore(dut, 'rest_urls')
        port_hash_list = segregate_intf_list_type(intf=interface_name, range_format=False)
        interface_list = port_hash_list['intf_list_all']
        for interface_name in interface_list:
            if config == 'yes':
                intfv = get_interface_number_from_name(interface_name)
                if 'Loopback' in intfv['type']:
                    configure_loopback(dut, loopback_name=interface_name, config='yes')
                rest_url = rest_urls['vrf_bind_config'].format(vrf_name, interface_name)
                ocdata = {"openconfig-network-instance:interface": [
                            {"id": interface_name, "config": {"id": interface_name, "interface": interface_name}}]}
                response = config_rest(dut, http_method=http_method, rest_url=rest_url, json_data=ocdata)
                if not response:
                    st.log(response)
                    return False
            else:
                rest_url = rest_urls['vrf_bind_config'].format(vrf_name, interface_name)
                response = delete_rest(dut, rest_url=rest_url)
                if not response:
                    st.log(response)
                    return False
                intfv = get_interface_number_from_name(interface_name)
                if 'Loopback' in intfv['type']:
                    configure_loopback(dut, loopback_name=interface_name, config='no')
                    return True
        return True
    else:
        st.log("Unsupported cli")
        return False

def config_vrfs(dut, vrf_data_list={}, config='yes', cli_type=''):
# This is used only in UT scripts.

    if config == 'yes' or config == 'add':
        config = 'add'
    elif config == 'no' or config == 'del':
        config = 'del'
    else :
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

    if cli_type in ['click', 'klish' ] :
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
        if cli_type in get_supported_ui_type_list():
            output = st.show(dut, 'show ip vrf', type='klish')
        elif cli_type == 'click':
            output = st.show(dut, "show vrf")
        elif cli_type == 'klish':
            output = st.show(dut, "show ip vrf",type=cli_type)
        st.log("##### VRF : {}".format(output))
        if len(output) == 0:
            continue

        for entry in output:
            if not entry['vrfname']:
                continue
            vrfname = entry['vrfname']
            if vrfname == "default":
                continue
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
