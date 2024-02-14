##########################################
#SAG apis
##########################################
from spytest import st
from utilities.common import filter_and_select
from utilities.utils import get_interface_number_from_name,get_supported_ui_type_list
import utilities.common as utils
from apis.routing.ip_rest import get_subinterface_index
import re

try:
    import apis.yang.codegen.messages.interfaces.Interfaces as umf_intf
    import apis.yang.codegen.messages.network_instance as umf_ni
except ImportError:
    pass

get_phy_port = lambda intf: re.search(r"(\S+)\.\d+", intf).group(1) if re.search(r"(\S+)\.\d+", intf) else intf

def force_cli_type_to_klish(cli_type):
    cli_type = "klish" if cli_type in get_supported_ui_type_list() else cli_type
    return cli_type

def config_sag_ip(dut,**kwargs):
    '''
    Author: sunil.rajendra@broadcom.com
    :param dut:
    :param interface: Interface name on which SAG Gateway has to be configured.
    :param gateway: Gateway IP.
    :param mask: Mask. Default=24.
    :param config: Value can be <add|remove>.
    :param kwargs: parameters can be <interface|gateway|config|cli_type>
    :return:

    usage:
    config_sag_ip(dut1,interface='Vlan20', gateway="20.20.20.2", mask="24", config="add")
    config_sag_ip(dut1,interface='Vlan20', gateway="2002::2", mask="24", config="remove")
    '''
    ### Parameters processing
    intf = kwargs.get('interface', None)
    gateway = kwargs.get('gateway', None)
    mask = kwargs.get('mask', '24')
    config = kwargs.get('config', 'add')
    cli_type = kwargs.get('cli_type', st.get_ui_type(dut))
    cli_type = "klish" if cli_type in ["rest-put", "rest-patch"] else cli_type
    #config = remove is not working , so forcing it to klish, if gnmi and rest.
    cli_type = 'klish' if cli_type in get_supported_ui_type_list() and config == 'remove' else cli_type
    if 'interface' not in kwargs or 'gateway' not in kwargs:
        st.error("Mandatory parameters interface and gateway not found.")
        return False

    if cli_type in get_supported_ui_type_list():
        index = get_subinterface_index(dut, intf)
        if not index:
            st.error("Failed to get index for interface: {}".format(intf))
            index = 0

        config = 'no' if config == 'remove' else 'yes'
        family = 'ipv6' if ':' in gateway else 'ip'
        gw_addr = '{}/{}'.format(gateway, mask)
        intf_name = get_phy_port(intf)
        intf_obj = umf_intf.Interface(Name=intf_name)
        if "Vlan" in intf_name:
            if family == 'ip': intf_obj.SagIpv4StaticAnycastGateway = gw_addr
            if family == 'ipv6': intf_obj.SagIpv6StaticAnycastGateway = gw_addr
        else:
            sub_intf_obj = umf_intf.Subinterface(Index=int(index))
            if family == 'ip': sub_intf_obj.SagIpv4StaticAnycastGateway = gw_addr
            if family == 'ipv6': sub_intf_obj.SagIpv6StaticAnycastGateway = gw_addr
            intf_obj.add_Subinterface(sub_intf_obj)
        if config == 'yes':
            result = intf_obj.configure(dut, cli_type=cli_type)
        else:
            #config = remove is not working , so forcing it to klish.
            if family == 'ip': target_attr = getattr(intf_obj, 'SagIpv4StaticAnycastGateway')
            if family == 'ipv6': target_attr = getattr(intf_obj, 'SagIpv6StaticAnycastGateway')
            result = intf_obj.unConfigure(dut, target_attr=target_attr, cli_type=cli_type)
        if not result.ok():
            st.error('test_step_failed: Configure SAG IP {}'.format(result.data))
            return False

        return True
    elif cli_type == 'click':
        cmd = "config interface ip anycast-address {} {} {}/{}".format(config, intf, gateway, mask)
        output = st.config(dut, cmd)
        if "Missing argument" in output:
            st.error("Argument Missing")
            return False
        if "interface name is invalid" in output:
            st.error("Invalid peer interface")
            return False
        if "is not configured on interface" in output:
            st.error("IP is not configured")
            return False
    elif cli_type == 'klish':
        config = 'no ' if config == 'remove' else ''
        vval = get_interface_number_from_name(intf)
        cmd = "interface {} {}".format(vval['type'], vval['number'])
        type_val = 'ipv6' if ':' in gateway else 'ip'
        cmd = cmd + "\n" + "{}{} anycast-address {}/{}".format(config, type_val, gateway, mask)
        cmd = cmd + "\n" + "exit"
        output = st.config(dut, cmd, type="klish", conf=True)
        if "Could not connect to Management REST Server" in output:
            st.error("klish mode not working.")
            return False
    return True

def config_sag_mac(dut,**kwargs):
    '''
    Author: sunil.rajendra@broadcom.com
    :param dut:
    :param mac: anycast-mac-address.
    :param config: Value can be <add|remove|enable|disable>.
    :param ip_type: Value can be <ip|ipv6>.
    :param kwargs: parameters can be <mac|config|cli_type>
    :return:

    usage:
    config_sag_mac(dut1, mac='00:00:00:01:02:03', config="add")
    config_sag_mac(dut1, mac='00:00:00:01:02:03', config="remove")
    config_sag_mac(dut1, ip_type='ip', config="enable")
    config_sag_mac(dut1, ip_type='ipv6', config="disable")
    '''
    ### Parameters processing
    mac = kwargs.get('mac', '')
    config = kwargs.get('config', 'add')
    ip_type = kwargs.get('ip_type', 'ip')
    cli_type = kwargs.get('cli_type', st.get_ui_type(dut))
    cli_type = "klish" if cli_type in ["rest-put", "rest-patch"] else cli_type
    if config == 'add' or config == 'remove':
        if 'mac' not in kwargs:
            st.error("Mandatory parameter mac not found.")
            return False

    if cli_type in get_supported_ui_type_list():
        ni_obj = umf_ni.NetworkInstance(Name='default')
        if config == 'add':
            ni_obj.AnycastMac = mac
            result = ni_obj.configure(dut, cli_type=cli_type)
        elif config == 'remove':
            result = ni_obj.unConfigure(dut, target_attr=ni_obj.AnycastMac, cli_type=cli_type)
        elif config == 'enable' or config == 'disable':
            enable_flag = True if config == 'enable' else False
            if ip_type == 'ip': ni_obj.Ipv4Enable = enable_flag
            if ip_type == 'ipv6': ni_obj.Ipv6Enable = enable_flag
            result = ni_obj.configure(dut, cli_type=cli_type)
        if not result.ok():
            st.error('test_step_failed: Configure SAG MAC {}'.format(result.data))
            return False
        return True
    if cli_type == 'click':
        cmd = "config {} anycast-mac-address {} {}".format(ip_type, config, mac)
        output = st.config(dut, cmd)
        if "Missing argument" in output:
            st.error("Argument Missing")
            return False
        if "interface name is invalid" in output:
            st.error("Invalid peer interface")
            return False
    elif cli_type == 'klish':
        if config == 'add' or config == 'remove':
            config = 'no ' if config == 'remove' else ''
            cmd = "{}{} anycast-mac-address {}".format(config, ip_type, mac)
        elif config == 'enable' or config == 'disable':
            cmd = "{} anycast-address {}".format(ip_type, config)
        output = st.config(dut, cmd, type="klish", conf=True)
        if "Could not connect to Management REST Server" in output:
            st.error("klish mode not working.")
            return False
    return True

def verify_sag(dut,**kwargs):
    '''
    Author: sunil.rajendra@broadcom.com
    Verify sag output - show <ip|ipv6> static-anycast-gateway
    :param dut:
    :param kwargs: Parameters can be ['ip_type']
        ['mac', 'status', 'total', 'total_admin', 'total_oper']
        ['gateway', 'interface', 'mask', 'vrf', 'admin', 'oper']
    :return:
    Usage:
    verify_sag(dut1, total=10, mac='00:00:00:ba:ba:12', gateway='13.3.3.3', interface='Vlan20')
    verify_sag(dut1, status='enable', gateway='2001::15', ip_type='ipv6')
    '''
    ret_val = True
    cli_type = kwargs.get('cli_type', st.get_ui_type(dut,**kwargs))
    cli_type = "klish" if cli_type in ["rest-put", "rest-patch"] else cli_type
    skip_error = kwargs.get('skip_error_check', False)

    ip_type = kwargs.get('ip_type', 'ip')
    kwargs.pop('ip_type', None)
    status_dict = {'disabled':'disable', 'enabled':'enable'}
    mac_dict = {'Not':''}

    # Marking to klish as GNMI support for below params are not there.
    non_gnmi_params = ['total', 'total_admin', 'total_oper']
    for k in non_gnmi_params:
        if k in kwargs:
            cli_type = 'klish'
            break

    if cli_type in get_supported_ui_type_list():
        if kwargs.get('mac') == 'Not': kwargs.pop('mac')
        sag_attr_list = {
            'mac': ['AnycastMac', kwargs.get('mac', None)],
        }
        map_tf = {'enable': True, 'disable': False}
        if 'status' in kwargs:
            status = kwargs.get('status')
            if status in status_dict.keys():
                status = status_dict[status]
            status = map_tf[status]
            if ip_type == 'ip':
                sag_attr_list['status'] = ['Ipv4Enable', status]
            elif ip_type == 'ipv6':
                sag_attr_list['status'] = ['Ipv6Enable', status]
        filter_type = kwargs.get('filter_type', 'ALL')
        query_params_obj = utils.get_query_params(yang_data_type=filter_type, cli_type=cli_type)
        query_params_obj_vrf = utils.get_query_params(yang_data_type=filter_type, cli_type=cli_type)
        ni_obj = umf_ni.NetworkInstance(Name='default')
        result = None
        for key, attr_value in sag_attr_list.items():
            if key in kwargs and attr_value[1] is not None:
                setattr(ni_obj, attr_value[0], attr_value[1])
        # Checking for interfaces.
        intf = kwargs.get('interface', None)
        gateway = kwargs.get('gateway', None)
        if ip_type == 'ip':
            mask = kwargs.get('mask', '24')
        else:
            mask = kwargs.get('mask', '96')
        if intf:
            index = get_subinterface_index(dut, intf)
            if not index:
                st.error("Failed to get index for interface: {}".format(intf))
                index = 0
            intf_name = get_phy_port(intf)
            intf_obj = umf_intf.Interface(Name=intf_name)
            if gateway:
                gw_addr = '{}/{}'.format(gateway, mask)
                if "Vlan" in intf_name:
                    if ip_type == 'ip': intf_obj.SagIpv4StaticAnycastGateway = gw_addr
                    if ip_type == 'ipv6': intf_obj.SagIpv6StaticAnycastGateway = gw_addr
                else:
                    sub_intf_obj = umf_intf.Subinterface(Index=int(index))
                    if ip_type == 'ip': sub_intf_obj.SagIpv4StaticAnycastGateway = gw_addr
                    if ip_type == 'ipv6': sub_intf_obj.SagIpv6StaticAnycastGateway = gw_addr
                    intf_obj.add_Subinterface(sub_intf_obj)
            if 'admin' in kwargs: intf_obj.AdminStatus = kwargs['admin'].upper()
            if 'oper' in kwargs: intf_obj.OperStatus = kwargs['oper'].upper()
        if 'vrf' in kwargs:
            ni_obj_vrf = umf_ni.NetworkInstance(Name=kwargs.get('vrf'))
            ni_vrf_intf_obj = umf_ni.NetworkInstanceInterface(Id=intf, NetworkInstance=ni_obj_vrf)
            if kwargs.get('vrf') == 'default':
                query_params_obj_vrf = utils.get_query_params(yang_data_type='NON_CONFIG', cli_type=cli_type)
        try:
            result = ni_obj.verify(dut, match_subset=True, query_param=query_params_obj, cli_type=cli_type)
            if not result.ok():
                st.log('test_step_failed ni_obj: Match not found:')
                return False
            if intf:
                result = intf_obj.verify(dut, match_subset=True, query_param=query_params_obj, cli_type=cli_type)
                if not result.ok():
                    st.log('test_step_failed intf_obj: Match not found:')
                    return False
            if 'vrf' in kwargs:
                result = ni_vrf_intf_obj.verify(dut, match_subset=True, query_param=query_params_obj_vrf, cli_type=cli_type)
                if not result.ok():
                    st.log('test_step_failed ni_vrf_intf_obj: Match not found:')
                    return False
            return True
        except ValueError as exp:
            if skip_error:
                st.log('ValueError: {}'.format(exp))
                st.log('Negative Scenario: Errors/Expception expected')
                return False
            else:
                raise
    cmd = 'show {} static-anycast-gateway'.format(ip_type)
    output = st.show(dut, cmd, type=cli_type)
    if len(output) == 0:
        st.error("Output is Empty")
        return False

    if "return_output" in kwargs:
        return output

    list1=['mac', 'status', 'total', 'total_admin', 'total_oper']
    list2=['gateway', 'interface', 'mask', 'vrf', 'admin', 'oper']

    match={}
    for k in list1:
        if kwargs.get(k, None) is not None:
            match[k] = kwargs[k]
    if cli_type == 'klish':
        if kwargs.get('status', None) is not None:
            if match['status'] in status_dict.keys():
                match['status'] = status_dict[match['status']]
        if kwargs.get('mac', None) is not None:
            if match['mac'] in mac_dict.keys():
                match['mac'] = mac_dict[match['mac']]
    entries = filter_and_select(output,None,match=match)
    if match:
        if not entries:
            ret_val = False
            st.error("Match NOT FOUND for {}.".format(match))
        else:
            st.log("Match FOUND for {}.".format(match))

    # API can be enhanced to accept the list for all items in list2.
    match={}
    for k in list2:
        if kwargs.get(k, None) is not None:
            match[k] = kwargs[k]
    entries = filter_and_select(output,None,match=match)
    if match:
        if not entries:
            ret_val = False
            st.error("Match NOT FOUND for {}.".format(match))
        else:
            st.log("Match FOUND for {}.".format(match))

    return ret_val

def _clear_sag_configuration_helper(dut_list, cli_type='', skip_error_check=False):
    """
    Find and clear SAG IP and MAC in DUT

    :param dut_list:
    :return:
    """
    dut_li = list(dut_list) if isinstance(dut_list, list) else [dut_list]
    cli_type = st.get_ui_type(dut_li[0], cli_type=cli_type)
    cli_type = force_cli_type_to_klish(cli_type=cli_type)

    family_li = ['ip', 'ipv6']
    for dut in dut_li:
        sag_mac = None
        for each_af in family_li:
            st.log("############## {} : {} Static-Anycast Address Cleanup ################".format(dut, each_af.upper()))
            cmd = 'show {} static-anycast-gateway'.format(each_af)
            output = st.show(dut, cmd, type=cli_type)
            for entry in output:
                if entry['mac']:
                    sag_mac = entry['mac']
                if not entry['interface']:
                    continue
                config_sag_ip(dut, interface=entry['interface'], gateway=entry['gateway'], mask=entry['mask'], config='remove')
        if sag_mac is not None and ':' in sag_mac:
            config_sag_mac(dut, mac=sag_mac, config='remove')

    return True


def clear_sag_configuration(dut_list, thread=True, cli_type='', skip_error_check=False):
    """
    Find and clear SAG configuration in the list of DUTs
    """
    dut_li = list(dut_list) if isinstance(dut_list, list) else [dut_list]
    cli_type = st.get_ui_type(dut_li[0], cli_type=cli_type)
    [out, _] = utils.exec_foreach(thread, dut_li, _clear_sag_configuration_helper, cli_type=cli_type, skip_error_check=skip_error_check)
    return False if False in out else True
