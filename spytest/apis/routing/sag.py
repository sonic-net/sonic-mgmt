##########################################
#SAG apis
##########################################
from spytest import st
from spytest.utils import filter_and_select
from utilities.utils import get_interface_number_from_name

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

    if 'interface' not in kwargs or 'gateway' not in kwargs:
        st.error("Mandatory parameters interface and gateway not found.")
        return False

    if cli_type == 'click':
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
    cli_type = kwargs.get('cli_type', st.get_ui_type(dut))
    cli_type = "klish" if cli_type in ["rest-put", "rest-patch"] else cli_type

    ip_type = kwargs.get('ip_type', 'ip')
    kwargs.pop('ip_type', None)

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
    status_dict = {'disabled':'disable', 'enabled':'enable'}
    mac_dict = {'Not':''}
    for k in list1:
        if kwargs.get(k, None) != None:
            match[k] = kwargs[k]
    if cli_type == 'klish':
        if kwargs.get('status', None) != None:
            if match['status'] in status_dict.keys():
                match['status'] = status_dict[match['status']]
        if kwargs.get('mac', None) != None:
            if match['mac'] in mac_dict.keys():
                match['mac'] = mac_dict[match['mac']]
    entries = filter_and_select(output,None,match=match)
    if match != {}:
        if entries == []:
            ret_val = False
            st.error("Match NOT FOUND for {}.".format(match))
        else:
            st.log("Match FOUND for {}.".format(match))

    # API can be enhanced to accept the list for all items in list2.
    match={}
    for k in list2:
        if kwargs.get(k, None) != None:
            match[k] = kwargs[k]
    entries = filter_and_select(output,None,match=match)
    if match != {}:
        if entries == []:
            ret_val = False
            st.error("Match NOT FOUND for {}.".format(match))
        else:
            st.log("Match FOUND for {}.".format(match))

    return ret_val

