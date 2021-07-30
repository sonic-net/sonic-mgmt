from spytest import st
from utilities.common import filter_and_select, make_list
from utilities.utils import get_interface_number_from_name
from apis.system.rest import delete_rest,config_rest

def show(dut, *argv, **kwargs):
    """
    Click:
      1. show ip forward_protocol config
      2. show ip helper_address config [OPTIONS] <interface_name>
      3. show ip helper_address statistics [OPTIONS] <interface_name>

    Klish:
      1. show ip forward-protocol
      2. show ip helper-address [interface_name]
      3. show ip helper-address statistics [interface_name]

    To perform show operations of IP helper.
     Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param :dut:
    :param :forward_protocol:
    :param :helper_address:
    :param :statistics:
    Usage:
        show(vars.D1, forward_protocol='')
        show(vars.D1, helper_address='')
        show(vars.D1, helper_address="Ethernet0")
        show(vars.D1, statistics="Ethernet0")
    """

    cli_type = kwargs.get("cli_type", st.get_ui_type(dut, **kwargs))
    command = ''
    cli_type = 'klish' if cli_type in ['rest-patch', 'rest-put'] else cli_type

    if cli_type == 'click':
        cmd = "show ip"
        if 'forward_protocol' in kwargs:
            command = "{} forward_protocol config".format(cmd)
        elif 'helper_address' in kwargs:
            command = "{} helper_address config {}".format(cmd, kwargs['helper_address'])
        elif kwargs.get('statistics'):
            command = "{} helper_address statistics {}".format(cmd, kwargs['statistics'])
        else:
            st.error("Invalid show command selection")
            return False
    elif cli_type == "klish":
        if 'forward_protocol' in kwargs:
            command = "show ip forward-protocol"
        elif 'helper_address' in kwargs:
            command = "show ip helper-address {}".format(kwargs['helper_address'])
        elif kwargs.get('statistics'):
            command = "show ip helper-address statistics {}".format(kwargs['statistics'])
        else:
            st.error("Invalid show command selection")
            return False
    else:
        st.error("Unsupported CLI Type {}".format(cli_type))
        return False
    return st.show(dut, command, type=cli_type)


def verify(dut, *argv, **kwargs):
    """
    To perform Verify operations of IP Helper show cmds.
     Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param :dut:
    :param :verify_list:
    Usage:
        verify(vars.D1, forward_protocol='',
                                verify_list=[{'forwarding':'Enable', 'enable_ports':['23'] ,'disable_ports':['333']}])
        verify(vars.D1, helper_address='', verify_list=[{'interface':'Ethernet0', 'vrf:''black',
                                                                'relay_address':'1.2.3.4'}])
        verify(vars.D1, helper_address="Ethernet0",
                            verify_list=[{'interface':'Ethernet0', 'vrf':'black', 'relay_address':'1.2.3.4'}])
        verify(vars.D1, statistics="Ethernet0", verify_list=[{'packets_received':'0'}])
    """
    result = True
    if not kwargs.get('verify_list'):
        st.error("verify_list values are not provided")
        return False
    output = show(dut, *argv, **kwargs)
    for each in make_list(kwargs['verify_list']):
        if each.get('enable_ports'):
            for port in output[0]['enable_ports'].split(","):
                if port.strip() not in each.get('enable_ports'):
                    st.log("Port {} not in enable_ports {}".format(port.strip(), output))
                    result = False
            each.pop('enable_ports')

        if each.get('disable_ports'):
            for port in output[0]['disable_ports'].split(","):
                if port.strip() not in each.get('disable_ports'):
                    st.log("Port {} not in disable_ports {}".format(port.strip(), output))
                    result = False
            each.pop('disable_ports')

        if not filter_and_select(output, None, each):
            st.log("{} is not matching in the output {} ".format(each, output))
            result = False

    return result


def config(dut, **kwargs):
    """

    1. Add IP helper address on an interface.
       Click : config interface ip helper_address add <interface-name> <ip-address> [-vrf <vrf-name]
       Klish : ip helper-address [vrf <vrf-name>] <ip-address>

    2. Remove IP helper address on an interface.
       Click : config interface ip helper_address remove <interface-name> <ip-address> [-vrf <vrf-name]
       Klish : no ip helper-address [vrf <vrf-name>] <ip-address>

    3. Enable UDP broadcast forwarding.
       Click : config ip forward_protocol udp enable
       Klish : ip forward-protocol udp enable

    4. Disable UDP broadcast forwarding.
       Click : config ip forward_protocol udp disable
       Klish : no ip forward-protocol udp enable

    5. Add UDP port to the list of forwarding ports.
       Click : config ip forward_protocol udp add {[tftp/dns/ntp/netbios-name-server/netbios-datagram-server/tacacs] |
     <port>}
       Klish : ip forward-protocol udp include {[tftp/dns/ntp/netbios-name-server/netbios-datagram-server/tacacs] |
     <port>}

    6. Remove UDP port from the list of forwarding ports.
       Click : config ip forward_protocol udp remove {[tftp/dns/ntp/netbios-name-server/netbios-datagram-server/tacacs] |
     <port>}
       Klish : ip forward-protocol udp exclude {[tftp/dns/ntp/netbios-name-server/netbios-datagram-server/tacacs] |
     <port>}

    7. Configure the UDP broadcast packet rate limiting value in the range 600 - 10000 pps.
       The default value is 6000 pps.
       Click : config ip forward_protocol udp rate_limit <value-in-pps>
       Klish : ip forward-protocol udp rate-limit <value-in-pps>
    """

    helper_address_config_keys = ["action_str", "intf_name", "ip_address"]
    fwd_protocol_config_keys = ["action_str", "protocol_or_port"]
    cli_type = kwargs.get("cli_type", st.get_ui_type(dut, **kwargs))
    skip_error_check = kwargs.get("skip_error_check", True)
    command = ''

    if cli_type == 'click':
        if 'helper_status' in kwargs:
            command = "config ip forward_protocol udp {helper_status}".format(**kwargs)

        elif all(key in kwargs for key in helper_address_config_keys):
            ip_li = ''
            if isinstance(kwargs['ip_address'], list):
                for x in kwargs['ip_address']:
                    ip_li += x + ' '
            else:
                ip_li += kwargs['ip_address']

            command = "config interface ip helper_address {action_str} {intf_name} {}".format(ip_li, **kwargs)
            if 'vrf_name' in kwargs:
                command = "{} -vrf {vrf_name}".format(command, **kwargs)

        elif all(key in kwargs for key in fwd_protocol_config_keys):
            command = "config ip forward_protocol udp {action_str} {protocol_or_port}".format(**kwargs)

        elif 'rate_limit_val' in kwargs:
            command = "config ip forward_protocol udp rate_limit {rate_limit_val}".format(**kwargs)

        else:
            st.log("Required keys are not passed to configure IP helper")
            return False
        if command:
            st.config(dut, command, type=cli_type)
            return True
        return False
    elif cli_type == "klish":
        command = list()
        if 'helper_status' in kwargs:
            if kwargs['helper_status'] == 'enable':
                command.append("ip forward-protocol udp enable")
            elif kwargs['helper_status'] == 'disable':
                command.append("no ip forward-protocol udp enable")
            else:
                st.error("Required enable or disable")
                return False
        elif all(key in kwargs for key in helper_address_config_keys):
            ip_li = ''
            if isinstance(kwargs['ip_address'], list):
                for x in kwargs['ip_address']:
                    ip_li += x + ' '
            else:
                ip_li += kwargs['ip_address']

            intf_data = get_interface_number_from_name(kwargs["intf_name"])
            command.append("interface {} {}".format(intf_data["type"], intf_data["number"]))

            if kwargs['action_str'] == 'add':
                if 'vrf_name' in kwargs:
                    command.append("ip helper-address vrf {vrf_name} {}".format(ip_li, **kwargs))
                    command.append("exit")
                else:
                    command.append("ip helper-address {}".format(ip_li))
                    command.append("exit")
            elif kwargs['action_str'] == 'remove':
                if 'vrf_name' in kwargs:
                    command.append("no ip helper-address vrf {vrf_name} {}".format(ip_li, **kwargs))
                else:
                    command.append("no ip helper-address {}".format(ip_li))
            else:
                st.error("Required add or remove for command")
                return False
        elif all(key in kwargs for key in fwd_protocol_config_keys):
            if kwargs['action_str'] == 'add':
                command.append("ip forward-protocol udp include {protocol_or_port}".format(**kwargs))
            elif kwargs['action_str'] == 'remove':
                command.append("ip forward-protocol udp exclude {protocol_or_port}".format(**kwargs)) 
            else:
                st.error("Required add or remove for command")
                return False
        elif 'rate_limit_val' in kwargs:
            command.append("ip forward-protocol udp rate-limit {rate_limit_val}".format(**kwargs))
        else:
            st.error("Required keys are not passed to configure IP helper")
            return False

        st.config(dut, command, type=cli_type, skip_error_check=skip_error_check)
        return True
    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, "rest_urls")
        if 'helper_status' in kwargs:
            url = rest_urls['fwd_protocol_udp_enable']
            if kwargs['helper_status'] == 'enable':
                data = {"openconfig-ip-helper:enable": True}
                if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=data):
                    return False
            elif kwargs['helper_status'] == 'disable':
                if not delete_rest(dut, rest_url=url):
                    return False
            else:
                st.error("Required enable or disable")
                return False
        elif all(key in kwargs for key in helper_address_config_keys):
            ip_li = ''
            if isinstance(kwargs['ip_address'], list):
                for x in kwargs['ip_address']:
                    ip_li += x + ' '
            else:
                ip_li += kwargs['ip_address']
            if kwargs['action_str'] == 'add':
                if 'vrf_name' in kwargs:
                    index = 0
                    url = rest_urls['vrf_ip_helper_config'].format(kwargs['intf_name'], index, kwargs['vrf_name'], ip_li)
                    data = { "openconfig-ip-helper:servers": {"server": [{"vrf": str(kwargs['vrf_name']),"ip": str(ip_li), "config": { "vrf": str(kwargs['vrf_name']),"ip": str(ip_li)}}]}}
                    if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=data):
                        return False
                else:
                    index = 0
                    url = rest_urls['config_ip_helper_address'].format(kwargs['intf_name'], index)
                    data = { "openconfig-ip-helper:servers": {"server": [{"vrf": "default","ip": str(ip_li), "config": { "vrf": "default","ip": str(ip_li)}}]}}
                    if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=data):
                        return False
            elif kwargs['action_str'] == 'remove':
                if 'vrf_name' in kwargs:
                    index = 0
                    url = rest_urls['vrf_ip_helper_config'].format(kwargs['intf_name'], index, kwargs['vrf_name'], ip_li)
                    if not delete_rest(dut, rest_url=url):
                        return False
                else:
                    index = 0
                    url = rest_urls['config_ip_helper_address'].format(kwargs['intf_name'], index)
                    if not delete_rest(dut, rest_url=url):
                        return False
            else:
                st.error("Required add or remove for command")
                return False
        elif all(key in kwargs for key in fwd_protocol_config_keys):
            if kwargs['action_str'] == 'add':
                url = rest_urls['ip_helper_config_ports']
                data = {"openconfig-ip-helper:ports": [int(kwargs['protocol_or_port'])]}
                if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=data):
                    return False
            elif kwargs['action_str'] == 'remove':
                url = rest_urls['ip_helper_unconfig_ports'].format(int(kwargs['protocol_or_port']))
                if not delete_rest(dut, rest_url=url):
                    return False
            else:
                st.error("Required add or remove for command")
                return False
        elif 'rate_limit_val' in kwargs:
            url = rest_urls['ip_helper_rate_limit']
            data = {"openconfig-ip-helper:incoming-rate-limit": int(kwargs['rate_limit_val'])}
            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=data):
                return False
        else:
            st.error("Required keys are not passed to configure IP helper")
            return False
        return True
    else:
        st.error("Unsupported CLI Type {}".format(cli_type))
        return False

def clear_stats(dut, **kwargs):
    """
    Click:
      1. sonic-clear ip helper_address statistics
      2. sonic-clear ip helper_address statistics <interface_name>

    Klish:
      1. clear ip helper-address statistics
      2. clear ip helper-address statistics <interface_name>
    """
    cli_type = kwargs.get("cli_type", st.get_ui_type(dut, **kwargs))
    skip_error_check = kwargs.get("skip_error_check", True)
    command = ''

    if cli_type == 'click':
        command = "sonic-clear ip helper_address statistics"
        if 'intf_name' in kwargs:
            command += " {intf_name}".format(**kwargs)
        if not st.config(dut, command, type=cli_type, skip_error_check=skip_error_check):
            return False
    elif cli_type == "klish":
        command = list()
        if 'intf_name' in kwargs:
            command.append("clear ip helper-address statistics {intf_name}".format(**kwargs))
        else:
            command.append("clear ip helper-address statistics")

        if not st.config(dut, command, type=cli_type, skip_error_check=skip_error_check):
            return False
    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, "rest_urls")
        url = rest_urls['clear_stats_ip_helper']
        if 'intf_name' in kwargs:
            data = {"openconfig-ip-helper:input": {"interface": str(kwargs['intf_name'])}}
        else:
            data = {"openconfig-ip-helper:input": {}}
        if not config_rest(dut, http_method="post", rest_url=url, json_data=data):
            return False
    else:
        st.error("Unsupported CLI Type {}".format(cli_type))
        return False
    return True
