from spytest import st
from apis.system.rest import config_rest, get_rest, delete_rest
from apis.routing.ip import get_interface_ip_address
from utilities.utils import remove_last_line_from_string, get_interface_number_from_name
from utilities.common import make_list, filter_and_select, iterable



def dhcp_relay_config_add(dut, **kwargs):
    """
     Author Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param vlan:
    :param IP:
    :return:
    """
    kwargs.update({"action":"add"})
    return dhcp_relay_config(dut, **kwargs)


def dhcp_relay_config_remove(dut, **kwargs):
    """
    API to remove DHCP config
    Author Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param Vlan:
    :param IP:
    :return:
    """
    kwargs.update({"action": "remove"})
    return dhcp_relay_config(dut, **kwargs)


def dhcp_relay_config(dut, **kwargs):
    """
    API for DHCP relay configuration
    Author Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param kwargs:
    :return:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    interface = kwargs.get("vlan", kwargs.get("interface", None))
    ip_address = make_list(kwargs.get('IP', []))
    ip_addr_lst = " ".join(ip_address)
    ip_family = kwargs.get("family", "ipv4")
    skip_error_check = kwargs.get("skip_error_check", False)
    action = kwargs.get("action","add")
    if not interface:
        st.error("Required key 'interface' is not passed")
        return False
    command = ""
    if cli_type == "click":
        if ip_family == "ipv4":
            command = "config interface ip dhcp-relay {} {} {}".format(action, interface, ip_addr_lst)
        else:
            command = "config interface ipv6 dhcp-relay {} {} {}".format(action, interface, ip_addr_lst)
        if 'link_select' in kwargs:
            link_select = 'enable'
            command += " -link-select={}".format(link_select)
        if 'src_interface' in kwargs:
            src_interface = kwargs['src_interface']
            command += " -src-intf={}".format(src_interface)
        if 'max_hop_count' in kwargs:
            max_hop_count = kwargs['max_hop_count']
            command += " -max-hop-count={}".format(max_hop_count)
        if 'vrf_name' in kwargs and action == 'add':
            vrf_name = kwargs['vrf_name']
            command += " -vrf-name={}".format(vrf_name)
        if 'vrf_select' in kwargs:
            vrf_select = kwargs['vrf_select']
            command += " -vrf-select={}".format(vrf_select)
    elif cli_type == "klish":
        if ip_family not in ["ipv4", "ipv6"]:
            st.error("INVALID IP FAMILY -- {}".format(ip_family))
            return False
        command = list()
        interface_data = get_interface_number_from_name(interface)
        command.append("interface {} {}".format(interface_data.get("type"), interface_data.get("number")))
        no_form = "" if action == "add" else "no"
        ip_string = "ip" if ip_family == "ipv4" else "ipv6"
        if kwargs.get("link_select") and not kwargs.get("src_interface"):
            st.log("SRC INTF needed for LINK SELECT operation")
            return False
        if ip_addr_lst:
            cmd = "{} {} dhcp-relay {}".format(no_form, ip_string, ip_addr_lst)
            if 'vrf_name' in kwargs and action == 'add':
                cmd += " vrf-name {}".format(kwargs['vrf_name'])
            command.append(cmd)
        if 'src_interface' in kwargs:
            src_interface = kwargs['src_interface']
            command.append("{} {} dhcp-relay source-interface {}".format(no_form, ip_string, src_interface))
        if 'link_select' in kwargs:
            command.append("{} {} dhcp-relay link-select".format(no_form, ip_string))
        if 'max_hop_count' in kwargs:
            max_hop_count = kwargs['max_hop_count']
            command.append("{} {} dhcp-relay max-hop-count {}".format(no_form, ip_string, max_hop_count))
        if 'vrf_select' in kwargs:
            vrf_select = kwargs['vrf_select']
            command.append("{} {} dhcp-relay vrf-select {}".format(no_form, ip_string, vrf_select))
    elif cli_type in ["rest-patch", "rest-put"]:
        if ip_family not in ["ipv4", "ipv6"]:
            st.error("INVALID IP FAMILY -- {}".format(ip_family))
            return False
        ip_string = "" if ip_family == "ipv4" else "v6"
        if kwargs.get("link_select") and not kwargs.get("src_interface"):
            st.log("SRC INTF needed for LINK SELECT operation")
            return False
        config_data = {"openconfig-relay-agent:config": {"id": interface}}
        rest_urls = st.get_datastore(dut, 'rest_urls')
        if ip_address:
            if action == 'add':
                config_data["openconfig-relay-agent:config"].update({"helper-address": ip_address})
                if kwargs.get('vrf_name'):
                    config_data["openconfig-relay-agent:config"].update({"openconfig-relay-agent-ext:vrf": kwargs['vrf_name']})
            else:
                for ip in ip_address:
                    if not delete_rest(dut, rest_url=rest_urls['dhcp{}_relay_address_config'.format(ip_string)].format(id=interface, helper_address=ip)):
                        st.error("Failed to delete DHCP-Relay Helper-Address: {}".format(ip))
                        return False
        if 'src_interface' in kwargs:
            if action == 'add':
                config_data["openconfig-relay-agent:config"].update({"openconfig-relay-agent-ext:src-intf": kwargs['src_interface']})
            else:
                if not delete_rest(dut, rest_url=rest_urls['dhcp{}_relay_src_intf_config'.format(ip_string)].format(id=interface)):
                    st.error("Failed to delete DHCP-Relay source-interface on interface: {}".format(interface))
                    return False
        if 'link_select' in kwargs:
            if action == 'add':
                config_data["openconfig-relay-agent:config"].update({"openconfig-relay-agent-ext:link-select": "ENABLE"})
            else:
                if not delete_rest(dut, rest_url=rest_urls['dhcp{}_relay_link_select_config'.format(ip_string)].format(id=interface)):
                    st.error("Failed to delete DHCP-Relay link-select")
                    return False
        if 'max_hop_count' in kwargs:
            if action == 'add':
                config_data["openconfig-relay-agent:config"].update({"openconfig-relay-agent-ext:max-hop-count": int(kwargs['max_hop_count'])})
            else:
                if not delete_rest(dut, rest_url=rest_urls['dhcp{}_relay_max_hop_count_config'.format(ip_string)].format(id=interface)):
                    st.error("Failed to delete DHCP-Relay max-hop-count on interface: {}".format(interface))
                    return False
        if 'vrf_select' in kwargs:
            if action == 'add':
                config_data["openconfig-relay-agent:config"].update({"openconfig-relay-agent-ext:vrf-select": "ENABLE"})
            else:
                if not delete_rest(dut, rest_url=rest_urls['dhcp{}_relay_vrf_select_config'.format(ip_string)].format(id=interface)):
                    st.error("Failed to delete DHCP-Relay vrf-select on interface: {}".format(interface))
                    return False
        if 'policy_action' in kwargs:
            if action == 'add':
                config_data["openconfig-relay-agent:config"].update({"openconfig-relay-agent-ext:policy-action": kwargs['policy_action'].upper()})
            else:
                if not delete_rest(dut, rest_url=rest_urls['dhcp{}_relay_policy_action_config'.format(ip_string)].format(id=interface)):
                    st.error("Failed to delete DHCP-Relay policy_action on interface: {}".format(interface))
                    return False
        if len(config_data["openconfig-relay-agent:config"]) > 1:
            if not config_rest(dut, rest_url=rest_urls['dhcp{}_relay_config'.format(ip_string)].format(id=interface), http_method=cli_type, json_data=config_data):
                st.error("Failed to configure DHCP-Relay parameters")
                return False
    else:
        st.error("Unsupported CLI_TYPE: {}".format(cli_type))
        return False
    if command:
        st.debug("command is {}".format(command))
        output = st.config(dut, command, skip_error_check=skip_error_check, type=cli_type)
        if "Error" in output:
            if skip_error_check:
                return True
            else:
                return False
    return True


def dhcp_relay_option_config(dut, **kwargs):
    """
    API for DHCP relay option configuration like link-selection, src-interface and max-hop count
    :param dut:
    :param kwargs:
    :return:
    """
    interface = kwargs.get("vlan", kwargs.get("interface", None))
    option = kwargs.get("option", None)
    src_interface = kwargs.get("src_interface", None)
    hop_count = kwargs.get("max_hop_count",0)
    policy_action = kwargs.get("policy_action",None)
    ip_family = kwargs.get("family", "ipv4")
    cli_type = st.get_ui_type(dut, **kwargs)
    skip_error_check = kwargs.get("skip_error_check", False)
    action = kwargs.get("action","add")

    if not (interface):
        st.error("required interface value is not passed")
        return False
    command = ""
    if cli_type == "click":
        if ip_family == "ipv4":
            if option == "policy-action":
                command = "config interface ip dhcp-relay policy-action {} {}".format(interface,policy_action)
            else:
                command = "config interface ip dhcp-relay {} {} {}".format(option, action, interface)
        else:
            command = "config interface ipv6 dhcp-relay {} {} {}".format(option, action, interface)

        if action == "add":
            if option == "src-intf":
                if not src_interface:
                    st.log("required src_interface value is not passed")
                    return False
                command += " {}".format(src_interface)
            if option == "max-hop-count":
                command += " {}".format(hop_count)
    elif cli_type == "klish":
        command = list()
        interface_data = get_interface_number_from_name(interface)
        command.append("interface {} {}".format(interface_data.get("type"), interface_data.get("number")))
        no_form = "" if action == "add" else "no"
        cmd = ""
        if ip_family == "ipv4":
            cmd += "{} ip dhcp-relay".format(no_form)
        else:
            cmd += "{} ipv6 dhcp-relay".format(no_form)
        if option == "src-intf":
            if not src_interface:
                if no_form != 'no':
                    st.error("Required 'src_interface' value is not passed")
                    return False
            src_interface = src_interface if no_form != "no" else ""
            cmd += " source-interface {}".format(src_interface)
        if option == "max-hop-count":
            max_hop_count = hop_count if no_form != "no" else ""
            cmd += " max-hop-count {}".format(max_hop_count)
        if option == "link-select":
            cmd += " link-select"
        if option == "vrf-select":
            cmd += " vrf-select"
        if option == "policy-action":
            cmd += " policy-action {}".format(policy_action)
        command.append(cmd)
    elif cli_type in ["rest-patch", "rest-put"]:
        config_dict = {'action': action, 'interface': interface, 'family': ip_family, 'cli_type': cli_type}
        if option == "src-intf":
            if not src_interface:
                if no_form != 'no':
                    st.error("required src_interface value is not passed")
                    return False
            config_dict['src_interface'] = src_interface
        elif option == "max-hop-count":
            config_dict['max_hop_count'] = hop_count
        elif option == "link-select":
            config_dict['link_select'] = True
        elif option == "vrf-select":
            config_dict['vrf_select'] = True
        elif option == "policy-action":
            config_dict['policy_action'] = policy_action
        else:
            st.error("Invalid option: {}".format(option))
            return False
        if not dhcp_relay_config(dut, **config_dict):
            st.error("Failed to set the option: {}".format(option))
            return False
    else:
        st.error("Unsupported CLI_type: {}".format(cli_type))
        return False
    if command:
        st.debug("command is {}".format(command))
        output = st.config(dut, command, skip_error_check=skip_error_check, type=cli_type)
        if "Error" in output:
            if skip_error_check:
                return True
            else:
                return False
    return True


def dhcp_relay_show(dut, family="ipv4", interface=None, cli_type=""):
    """
    API to show the DHCP relay brief output
    Author Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    if cli_type in ['click', 'klish']:
        ip_val = "ip" if family == "ipv4" else "ipv6"
        command = "show {} dhcp-relay brief".format(ip_val)
        filter = "-w" if cli_type == "click" else ""
        if interface:
            command += " | grep {} {}".format(filter, interface)
        return st.show(dut, command, type=cli_type)
    elif cli_type in ['rest-patch', 'rest-put']:
        return _get_rest_brief_dhcp_relay_data(dut, family=family)
    else:
        st.error('Unsupported CLI_TYPE: {}'.format(cli_type))
        return False


def dhcp_relay_detailed_show(dut, interface="", family="ipv4", cli_type=""):
    """
    API to show the DHCP relay detailed output
    :param dut:
    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    if cli_type in ['click', 'klish']:
        ip_val = "ip" if family == "ipv4" else "ipv6"
        if interface:
            command = "show {} dhcp-relay detailed {}".format(ip_val, interface)
        else:
            command = "show {} dhcp-relay detailed".format(ip_val)
        return st.show(dut, command, type=cli_type)
    elif cli_type in ['rest-patch', 'rest-put']:
        return _get_rest_detailed_dhcp_relay_data(dut, interface=interface, family=family)
    else:
        st.error("Unsupported CLI_TYPE: {}".format(cli_type))
        return False


def dhcp_relay_restart(dut):
    """
    API to restart DHCP relay
    :param dut:
    :param vlan:
    :param IP:
    :return:
    """
    st.config(dut, "systemctl restart dhcp_relay")
    return True


def dhcp_client_start(dut, interface, family="ipv4", run_bckgrnd=False):
    """
    API to start DHCLIENT in foreground for v4 and background for v6
    Author Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :type dut:
    :param portlist:
    :type portlist:
    """
    if interface != None:
        if '/' in interface:
            interface = st.get_other_names(dut,[interface])[0]

    v6_opt = "" if family == "ipv4" else "-6"
    run_bckgrnd = True if (family == "ipv6" or run_bckgrnd) else False
    bckgrd = "&" if run_bckgrnd else ""
    command = "dhclient {} {} {}".format(v6_opt, interface, bckgrd)
    output = st.config(dut, command, skip_error_check=True)
    if bckgrd:
        output = remove_last_line_from_string(output)
        if output:
            return output.split(" ")[1]
        else:
            return None
    else:
        return True


def dhcp_client_stop(dut, interface, pid=None, family="ipv4", skip_error_check=False, show_interface=False):
    """
    API to stop DHCP client either by using process id or dhclient
    Author Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :type dut:
    :param portlist:
    :type portlist:
    """
    if interface != None:
        if '/' in interface:
            interface = st.get_other_names(dut,[interface])[0]

    v6_opt = "" if family == "ipv4" else "-6"
    command = "kill -9 {}".format(pid) if pid else  "dhclient {} -r {}".format(v6_opt, interface)
    st.config(dut, command, skip_error_check=skip_error_check)
    if show_interface:
        get_interface_ip_address(dut, interface_name=interface, family=family)
    return True


def get_dhcp_relay_statistics(dut, interface="", family="ipv4", cli_type="", skip_error_check=True):
    """
    API to get DHCP relay statistics
    Author Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :type dut:
    :param interface:
    :type interface:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    if cli_type in ['click', 'klish']:
        ip_val = "ip" if family == "ipv4" else "ipv6"
        if interface:
            command = "show {} dhcp-relay statistics {}".format(ip_val, interface)
        else:
            command = "show {} dhcp-relay statistics".format(ip_val)
        return st.show(dut, command, type=cli_type, skip_error_check=skip_error_check)
    elif cli_type in ['rest-patch', 'rest-put']:
        return _get_rest_dhcp_relay_statistics(dut, interface=interface, family=family)
    else:
        st.error("Unsupported CLI_TYPE: {}".format(cli_type))
        return False


def clear_statistics(dut, interface, family="ipv4", cli_type=''):
    """
    API to clear the DHCP RELAY statistics
    Author Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param interface:
    :param family:
    :param cli_type:
    :return:
    """
    if not cli_type: cli_type = st.get_ui_type(dut)
    if cli_type in ['rest-patch', 'rest-put']: cli_type = 'klish'
    ip_val = "ip" if family == "ipv4" else "ipv6"
    if cli_type =='click':
        command = "sonic-clear {} dhcp-relay statistics {}".format(ip_val, interface)
    elif cli_type =='klish':
        command = "clear {} dhcp-relay statistics {}".format(ip_val,interface)
    return st.config(dut, command, type=cli_type)


def debug(dut, interface, family="ipv4", cli_type="click"):
    """
    API to enable debug for DHCP relay interface
    Author Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :return:
    """
    ip_val = "ip" if family == "ipv4" else "ipv6"
    command = "debug {} dhcp-relay {}".format(ip_val, interface)
    return st.config(dut, command, type=cli_type)


def verify_dhcp_relay(dut, interface, dhcp_relay_addr, family="ipv4", cli_type=""):
    """
    API to verify DHCP RELAY configuration
    Author Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param interface:
    :param dhcp_relay_addr:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    output = dhcp_relay_show(dut, family=family, interface=interface, cli_type=cli_type)
    dhcp_relay_address = make_list(dhcp_relay_addr)
    filter=list()
    for address in dhcp_relay_address:
        match = {"intf": interface, "dhcprelay_addr": address}
        filter.append(match)
    entries = filter_and_select(output, ["intf"], filter)
    return True if entries else False


def verify_dhcp_relay_detailed(dut, interface, **kwargs):
    """
    API to verify DHCP RELAY datailed configuration
    :param dut:
    """
    #src_interface = kwargs.get("src_interface", None)
    #link_select = kwargs.get("link_select", None)
    #hop_count = kwargs.get("max_hop_count",None)
    ip_family = kwargs.get("family", "ipv4")
    cli_type = st.get_ui_type(dut, **kwargs)
    output = dhcp_relay_detailed_show(dut, interface, family=ip_family, cli_type=cli_type)

    if output == 0:
        st.error("Output is Empty")
        return False
    if kwargs.get("cli_type"):
        del kwargs["cli_type"]
    if kwargs.get("family"):
        del kwargs["family"]
    for each in kwargs.keys():
        if 'src_interface' in each or 'link_select' in each or 'max_hop_count' in each \
            or 'vrf_name' in each or 'policy_action' in each or 'vrf_select' in each:
            match = {each: kwargs[each]}
            st.log(match)
            entries = filter_and_select(output, None, match)
            st.log("entries {}".format(entries))
            if not entries:
                st.log("{} and {} is not match ".format(each, kwargs[each]))
                return False
    if kwargs.get("server_addr"):
        for result in iterable(output):
            if result.get("server_addr"):
                server_addr = result.get("server_addr")
                break
        st.debug("SERVER ADDR: {}".format(server_addr))
        if not server_addr:
            st.log("Server address from output is empty")
            return False
        if  kwargs.get("server_addr") not in server_addr.split(", "):
            st.log("Provided server address is not matching with configured one")
            return False
    return True


def verify_dhcp_relay_statistics(dut, **kwargs):
    """
    API to verify the DHCP relay statistics
    :param dut:
    :param kwargs:
    Kwargs contains the key value pair to verify, values of each key can be <exact number> for exact match,
    "non-zero" for matching of positive non zero values
    :return:
    """
    interface=kwargs.get("interface", "")
    family = kwargs.get("family", "ipv4")
    cli_type = st.get_ui_type(dut, **kwargs)
    if kwargs.get("interface"):
        del kwargs["interface"]
    if kwargs.get("family"):
        del kwargs["family"]
    if kwargs.get("cli_type"):
        del kwargs["cli_type"]
    output = get_dhcp_relay_statistics(dut, interface=interface, family=family, cli_type=cli_type)
    if not output:
        st.error("No output found - {}".format(output))
        return False
    result = 0
    for key,value in kwargs.items():
        if value not in [0, "0", "non-zero"]:
            st.log("Unsupported values provided")
            return False
        if key in output[0]:
            if value == "non-zero":
                if str(output[0][key]) <= "0":
                    result += 1
                    break
            elif str(value) == "0":
                if str(output[0][key]) != "0":
                    result += 1
                    break
            else:
                if str(output[0][key]) != str(value):
                    result += 1
                    break
        else:
            st.log("Specified KEY string is not found in output")
            return False
    if result > 0:
        st.log("Mismatch observed in provided key value pair verification")
        return False
    else:
        return True


def _get_rest_detailed_dhcp_relay_data(dut, interface="", family='ipv4'):
    """
    To get the dhcp-relay detailed data
    Author Jagadish Chatrasi (jagadish.chatrasi@broadcom.com)
    :param dut:
    :param interface:
    :param family:
    :return:
    """
    retval = list()
    rest_urls = st.get_datastore(dut, 'rest_urls')
    ip_string = '' if family == 'ipv4' else 'v6'
    if not interface:
        output = get_interface_ip_address(dut, family=family)
        interfaces = {entry['interface'] for entry in output}
        interfaces.discard('eth0')
    else:
        interfaces = make_list(interface)
    for intf in interfaces:
        url = rest_urls['dhcp{}_relay_config'.format(ip_string)].format(id=intf)
        out = get_rest(dut, rest_url=url)
        if isinstance(out, dict) and out.get('output') and out['output'].get('openconfig-relay-agent:config') and isinstance(out['output']['openconfig-relay-agent:config'], dict):
            data = out['output']['openconfig-relay-agent:config']
            temp = dict()
            temp['intf'] = intf
            temp['server_addr'] = ", ".join(data['helper-address']) if data.get('helper-address') and isinstance(data['helper-address'], list) else ''
            temp['vrf_name'] = data['openconfig-relay-agent-ext:vrf'] if data.get('openconfig-relay-agent-ext:vrf') else 'Not Configured'
            temp['src_interface'] = data['openconfig-relay-agent-ext:src-intf'] if data.get('openconfig-relay-agent-ext:src-intf') else 'Not Configured'
            temp['vrf_select'] = data['openconfig-relay-agent-ext:vrf-select'].lower() if data.get('openconfig-relay-agent-ext:vrf-select') else 'disable'
            temp['max_hop_count'] = str(data['openconfig-relay-agent-ext:max-hop-count']) if data.get('openconfig-relay-agent-ext:max-hop-count') else '10'
            if family == 'ipv4':
                temp['policy_action'] = data['openconfig-relay-agent-ext:policy-action'].lower() if data.get('openconfig-relay-agent-ext:policy-action') else 'discard'
                temp['link_select'] = data['openconfig-relay-agent-ext:link-select'].lower() if data.get('openconfig-relay-agent-ext:link-select') else 'disable'
            retval.append(temp)
    st.debug(retval)
    return retval


def _get_rest_brief_dhcp_relay_data(dut, family='ipv4'):
    """
    To get the dhcp-relay brief data
    Author Jagadish Chatrasi (jagadish.chatrasi@broadcom.com)
    :param dut:
    :param family:
    :return:
    """
    retval = list()
    rest_urls = st.get_datastore(dut, 'rest_urls')
    ip_string = '' if family == 'ipv4' else 'v6'
    output = get_interface_ip_address(dut, family=family)
    interfaces = {entry['interface'] for entry in output}
    interfaces.discard('eth0')
    for intf in interfaces:
        url = rest_urls['get_dhcp{}_relay_helper_address'.format(ip_string)].format(id=intf)
        out = get_rest(dut, rest_url=url)
        if isinstance(out, dict) and out.get('output') and out['output'].get('openconfig-relay-agent:helper-address') and isinstance(out['output']['openconfig-relay-agent:helper-address'], list):
            addresses = out['output']['openconfig-relay-agent:helper-address']
            for address in addresses:
                temp = dict()
                temp['intf'] = intf
                temp['dhcprelay_addr'] = address
                retval.append(temp)
    st.debug(retval)
    return retval


def _get_rest_dhcp_relay_statistics(dut, interface="", family='ipv4'):
    """
    To get the dhcp-relay statistics data
    Author Jagadish Chatrasi (jagadish.chatrasi@broadcom.com)
    :param dut:
    :param interface:
    :param family:
    :return:
    """
    retval = list()
    rest_urls = st.get_datastore(dut, 'rest_urls')
    ip_string = '' if family == 'ipv4' else 'v6'
    if not interface:
        output = get_interface_ip_address(dut, family=family)
        interfaces = {entry['interface'] for entry in output}
        interfaces.discard('eth0')
    else:
        interfaces = make_list(interface)
    for intf in interfaces:
        url = rest_urls['get_dhcp{}_relay_counters'.format(ip_string)].format(id=intf)
        out = get_rest(dut, rest_url=url)
        if isinstance(out, dict) and out.get('output') and out['output'].get('openconfig-relay-agent:counters') and isinstance(out['output']['openconfig-relay-agent:counters'], dict):
            data = out['output']['openconfig-relay-agent:counters']
            temp = dict()
            if family == 'ipv4':
                temp['bootrequest_msgs_received_by_the_relay_agent'] = str(data['bootrequest-received']) if data.get('bootrequest-received') else '0'
                temp['bootrequest_msgs_forwarded_by_the_relay_agent'] = str(data['bootrequest-sent']) if data.get('bootrequest-sent') else '0'
                temp['bootreply_msgs_forwarded_by_the_relay_agent'] = str(data['bootreply-sent']) if data.get('bootreply-sent') else '0'
                temp['dhcp_ack_msgs_sent_by_the_relay_agent'] = str(data['dhcp-ack-sent']) if data.get('dhcp-ack-sent') else '0'
                temp['dhcp_decline_msgs_received_by_the_relay_agent'] = str(data['dhcp-decline-received']) if data.get('dhcp-decline-received') else '0'
                temp['dhcp_discover_msgs_received_by_the_relay_agent'] = str(data['dhcp-discover-received']) if data.get('dhcp-discover-received') else '0'
                temp['dhcp_inform_msgs_received_by_the_relay_agent'] = str(data['dhcp-inform-received']) if data.get('dhcp-inform-received') else '0'
                temp['dhcp_nack_msgs_sent_by_the_relay_agent'] = str(data['dhcp-nack-sent']) if data.get('dhcp-nack-sent') else '0'
                temp['dhcp_offer_msgs_sent_by_the_relay_agent'] = str(data['dhcp-offer-sent']) if data.get('dhcp-offer-sent') else '0'
                temp['dhcp_release_msgs_received_by_the_relay_agent'] = str(data['dhcp-release-received']) if data.get('dhcp-release-received') else '0'
                temp['dhcp_request_msgs_received_by_the_relay_agent'] = str(data['dhcp-request-received']) if data.get('dhcp-request-received') else '0'
                temp['number_of_dhcp_pkts_drpd_due_to_an_invd_opcode'] = str(data['invalid-opcode']) if data.get('invalid-opcode') else '0'
                temp['number_of_dhcp_pkts_drpd_due_to_an_invd_option'] = str(data['invalid-options']) if data.get('invalid-options') else '0'
                temp['total_nbr_of_dhcp_pkts_drpd_by_the_relay_agent'] = str(data['total-dropped']) if data.get('total-dropped') else '0'
            else:
                temp['dhcpv6_advt_msgs_sent_by_the_relay_agent'] = str(data['dhcpv6-adverstise-sent']) if data.get('dhcpv6-adverstise-sent') else '0'
                temp['dhcpv6_confirm_msgs_rcvd_by_the_relay_agent'] = str(data['dhcpv6-confirm-received']) if data.get('dhcpv6-confirm-received') else '0'
                temp['dhcpv6_decline_msgs_rcvd_by_the_relay_agent'] = str(data['dhcpv6-decline-received']) if data.get('dhcpv6-decline-received') else '0'
                temp['dhcpv6_info_rqst_msgs_rcvd_by_the_relay_agent'] = str(data['dhcpv6-info-request-received']) if data.get('dhcpv6-info-request-received') else '0'
                temp['dhcpv6_rebind_msgs_rcvd_by_the_relay_agent'] = str(data['dhcpv6-rebind-received']) if data.get('dhcpv6-rebind-received') else '0'
                temp['dhcpv6_reconfig_msgs_sent_by_the_relay_agent'] = str(data['dhcpv6-reconfigure-sent']) if data.get('dhcpv6-reconfigure-sent') else '0'
                temp['dhcpv6_relay_fwd_msgs_sent_by_the_relay_agent'] = str(data['dhcpv6-relay-forw-sent']) if data.get('dhcpv6-relay-forw-sent') else '0'
                temp['dhcpv6_relay_reply_msgs_rcvd_by_the_relay_agent'] = str(data['dhcpv6-relay-reply-received']) if data.get('dhcpv6-relay-reply-received') else '0'
                temp['dhcpv6_release_msgs_rcvd_by_the_relay_agent'] = str(data['dhcpv6-release-received']) if data.get('dhcpv6-release-received') else '0'
                temp['dhcpv6_reply_msgs_sent_by_the_relay_agent'] = str(data['dhcpv6-reply-sent']) if data.get('dhcpv6-reply-sent') else '0'
                temp['dhcpv6_rqst_msgs_rcvd_by_the_relay_agent'] = str(data['dhcpv6-request-received']) if data.get('dhcpv6-request-received') else '0'
                temp['dhcpv6_solic_msgs_rcvd_by_the_relay_agent'] = str(data['dhcpv6-solicit-received']) if data.get('dhcpv6-solicit-received') else '0'
                temp['number_of_dhcpv6_pkts_drpd_due_to_an_inv_opcode'] = str(data['invalid-opcode']) if data.get('invalid-opcode') else '0'
                temp['number_of_dhcpv6_pkts_drpd_due_to_an_inv_option'] = str(data['invalid-options']) if data.get('invalid-options') else '0'
                temp['total_nbr_of_dhcpv6_pkts_drpd_by_the_relay_agent'] = str(data['total-dropped']) if data.get('total-dropped') else '0'
            retval.append(temp)
    st.debug(retval)
    return retval
