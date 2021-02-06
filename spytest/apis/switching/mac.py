import re
import json

from spytest import st

import apis.common.wait as waitapi

from apis.system.rest import get_rest,delete_rest,config_rest
from utilities.utils import get_interface_number_from_name
from utilities.common import filter_and_select, iterable


def get_mac(dut,**kwargs):

    """
    :param dut:
    :type dut:
    :return:
    :rtype:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    if cli_type == "click":
        return st.show(dut, "show mac")
    elif cli_type == "klish":
        response = dict()
        attrs = ["address", "interface", "type", "vlan", "count"]
        command = "show mac address-table"
        if kwargs.get("count"):
            command += " count"
            output = st.show(dut, command, type=cli_type)
            if output:
                for data in output:
                    for key, value in data.items():
                        if value:
                            response[key] = value
            return response
        else:
            for attr in attrs:
                if kwargs.get(attr):
                    if attr not in ["type", "count"]:
                        if attr == "interface":
                            interface_number = get_interface_number_from_name(kwargs.get(attr))
                            if interface_number:
                                command += " {} {} {}".format(attr, interface_number["type"], interface_number["number"])
                        else:
                            command += " {} {}".format(attr, kwargs.get(attr))
                    else:
                        command += " {}".format(kwargs.get(attr))
            return st.show(dut, command,  type=cli_type)
    elif cli_type in ["rest-patch", "rest-put"]:
        network_instance_name = 'default'
        rest_urls = st.get_datastore(dut, "rest_urls")
        url = rest_urls['all_mac_entries'].format(network_instance_name)
        output = get_rest(dut, rest_url=url)
        rest_get_output = processed_output_based_macentries(output)
        return rest_get_output
    else:
        st.log("Invalid cli type")
        return False



def get_mac_all_intf(dut, intf, cli_type=""):
    """
    :param dut:
    :type dut:
    :return:
    :rtype:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    output = get_mac(dut, cli_type=cli_type)
    retval = []
    entries = filter_and_select(output, ["macaddress"], {'port': str(intf)})
    for ent in entries:
        retval.append(ent["macaddress"])
    return retval


def get_mac_all(dut, vlan, cli_type=""):
    """
    :param dut:
    :type dut:
    :return:
    :rtype:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    output = get_mac(dut, cli_type=cli_type)
    retval = []
    entries = filter_and_select(output, ["macaddress"], {'vlan': str(vlan)})
    for ent in entries:
        retval.append(ent["macaddress"])
    return retval


def get_mac_entries_by_mac_address(dut, mac_address, **kwargs):
    '''
    Display MAC entries with a MAC search pattern and return the output.

    :param mac_address:
    :param cli_type:
    :return:
    '''
    cli_type = st.get_ui_type(dut, **kwargs)
    if cli_type == 'click':
        command="show mac | grep {}".format(mac_address)
        mac_entries = st.show(dut, command)
    elif cli_type == 'klish':
        command="show mac address-table | grep {}".format(mac_address)
        mac_entries = st.show(dut, command,type=cli_type)
    elif cli_type in ["rest-patch", "rest-put"]:
        entries = get_mac(dut, cli_type=cli_type)
        mac_entries = []
        for entry in iterable(entries):
            exp = "^{}".format(mac_address.strip())
            if re.search(exp, entry['macaddress'], re.IGNORECASE):
                mac_entries.append(entry)
        st.debug(mac_entries)
    else:
        st.log("Unsupported cli")
        return False
    return mac_entries


def get_mac_count(dut, cli_type=""):
    """
    To get the MAC count using - 'show mac count' command.
    :param dut:
    :type dut:
    :return:
    :rtype:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    if cli_type == 'click':
        field = "mac_count"
        command = "show mac count"
        if not st.is_feature_supported("show-mac-count-command", dut):
            st.community_unsupported(command, dut)
            return 0
        output = st.show(dut, command, type=cli_type)
    elif cli_type == 'klish':
        field =  "count"
        command = "show mac address-table count"
        output = st.show(dut, command, type=cli_type)
    elif cli_type in ["rest-patch", "rest-put"]:
        result = get_mac(dut, cli_type=cli_type)
        mac_count = len(result)
        return  mac_count
    else:
        st.log("Unsupported cli")
        return False
    if not output:
        ### When MAC table is empty, klish doesn't display output so return 0
        return 0
    return int(output[0][field])

def get_mac_address_count(dut, vlan=None, port=None, type=None, mac_search=None, cli_type=""):
    """
     To verify the MAC count after applying given filters vlan/port/type/mac_pattern
    :param dut:
    :param vlan: vlan id which needs to be filtered
    :param port: port which needs to be filtered like Ethernet4/PortChannel1
    :param type: mac type to be filtered, Values can be Static/Dynamic
    :param mac_search: mac_pattern to be grepped from show mac output
    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    dec_flag = 0
    if mac_search:
        entries = get_mac_entries_by_mac_address(dut, mac_search, cli_type=cli_type)
    else:
        entries = get_mac(dut, cli_type=cli_type)
        ###Decrement by 1 as output has "Total number of entries" as one list element in click output
        if cli_type == 'click':
            dec_flag = 1
    if entries == list or entries is None:
        ### If entries is null, no need to apply filter, return 0
        return 0

    if vlan:
        entries = filter_and_select(entries, None, {"vlan": str(vlan)})
        dec_flag = 0
    if port:
        entries = filter_and_select(entries, None, {"port": port})
        dec_flag = 0
    if type:
        type = type if cli_type == 'click' else type.upper()
        entries = filter_and_select(entries, None, {"type": type})
        dec_flag = 0
    return len(entries)-1 if dec_flag==1 else len(entries)


def verify_mac_address(dut, vlan, mac_addr, cli_type=""):
    """

    :param dut:
    :param vlan:
    :param mac_addr:
    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)

    waitapi.vsonic_mac_learn()

    st.log("Checking provided mac entries are present in mac table under specified vlan")
    mac_address_all = get_mac_all(dut, vlan, cli_type=cli_type)
    mac_addr_list = [mac_addr] if type(mac_addr) is str else mac_addr
    return set(mac_addr_list).issubset(set(mac_address_all))


def get_sbin_intf_mac(dut, interface=None):
    """
    This proc is to return the mac address of the interface from the ifconfig o/p.
    :param dut: DUT Number
    :param interface: Interface number
    :return:
    """
    if st.get_args("filemode"):
        return "00:00:ba:db:ad:ba"

    interface = interface or st.get_mgmt_ifname(dut)
    if '/' in interface:
        interface = st.get_other_names(dut,[interface])[0]
    my_cmd = "/sbin/ifconfig {}".format(interface)
    output = st.show(dut, my_cmd)
    output = dict(output[0])
    mac = output['mac']
    return mac


def clear_mac(dut,port=None,vlan=None,**kwargs):
    """
    This proc is to clear mac address/fdb entries of the dut.
    :param dut: DUT Number
    :return:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = 'klish' if cli_type in ['rest-patch', 'rest-put'] else cli_type
    if cli_type == "click":
        if not st.is_feature_supported("sonic-clear-fdb-type-command", dut):
            command = "sonic-clear fdb all"
        elif port:
            command = "sonic-clear fdb port {}".format(port)
        elif vlan:
            command = "sonic-clear fdb vlan Vlan{}".format(vlan)
        else:
            command = "sonic-clear fdb all"
        st.config(dut, command, type=cli_type)
    elif cli_type == "klish":
        if 'address' in kwargs:
            command = "clear mac address-table dynamic address  {}".format(kwargs['address'])
        elif vlan:
            command = "clear mac address-table dynamic Vlan {}".format(vlan)
        elif port:
            intf_data = get_interface_number_from_name(port)
            command = "clear mac address-table dynamic interface {} {}".format(intf_data["type"],intf_data["number"])
        else:
            command = "clear mac address-table dynamic all"

        st.config(dut, command,type=cli_type)
    else:
        st.error("Unsupported CLI: {}".format(cli_type))
        return False
    return True

def _json_mac_add(dut, mac, vlan, intf):
    data = json.loads("""
            [{{
              "FDB_TABLE:Vlan{0}:{1}":
              {{
                "type": "static",
                "port": "{2}"
              }},
              "OP": "SET"
            }}]
           """.format(vlan, mac, intf))
    from apis.system.basic import swss_config
    swss_config(dut, json.dumps(data))

def _json_mac_del(dut, mac, vlan):
    data = json.loads("""
            [{{
              "FDB_TABLE:Vlan{0}:{1}":
              {{
                "type": "static"
              }},
              "OP": "DEL"
            }}]
           """.format(vlan, mac))
    from apis.system.basic import swss_config
    swss_config(dut, json.dumps(data))

def config_mac(dut, mac, vlan, intf, cli_type=""):
    """
    :param dut:
    :type dut:
    :return:
    :rtype:
    """
    #st.log("config mac add <mac> <vlan> <intf>")
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    if cli_type == 'click':
        command = "config mac add {} {} {}".format(mac, vlan, intf)
        if not st.is_feature_supported("config-mac-add-command", dut):
            st.community_unsupported(command, dut)
            _json_mac_add(dut, mac, vlan, intf)
        else:
            st.config(dut, command, type='click')
    elif cli_type == 'klish':
        interface = get_interface_number_from_name(intf)
        command = "mac address-table {} vlan {} {} {}".format(mac, vlan, interface["type"],interface["number"])
        st.config(dut, command, type=cli_type)
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        url = rest_urls['static_mac_config']
        json = {"openconfig-network-instance:network-instances": {"network-instance": [{"name": "default", "fdb": {"mac-table": {"entries": {"entry": [{"mac-address": mac, "vlan": int(vlan), "config": {"mac-address": mac, "vlan": int(vlan)}, "interface": {"interface-ref": {"config": {"interface": intf, "subinterface": 0}}}}]}}}}]}}
        if not config_rest(dut, http_method = cli_type, rest_url=url, json_data=json):
            return False
    else:
        st.log("Unsupported cli")
        return False
    return True


def delete_mac(dut, mac, vlan, cli_type=""):
    """
    :param dut:
    :type dut:
    :return:
    :rtype:
    """
    #st.log("config mac del <mac> <vlan>")
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    if cli_type == 'click':
        command = "config mac del {} {}".format(mac, vlan)
        if not st.is_feature_supported("config-mac-add-command", dut):
            st.community_unsupported(command, dut)
            _json_mac_del(dut, mac, vlan)
        else:
            st.config(dut, command, type=cli_type)
    elif cli_type == 'klish':
        command = "no mac address-table {} vlan {}".format(mac, vlan)
        st.config(dut, command, type=cli_type)
    elif cli_type in ["rest-patch", "rest-put"]:
        network_instance_name = 'default'
        rest_urls = st.get_datastore(dut, "rest_urls")
        url = rest_urls['mac_entry_based_vlan_interface'].format(network_instance_name, mac, vlan)
        delete_rest(dut, rest_url=url)
    else:
        st.log("Unsupported cli")
        return False
    return True

def config_mac_agetime(dut, agetime, cli_type="", config= "add", **kwargs):
    """
    This proc is to config mac aging and setting it back to default.
    :param dut: DUT Number
    :param agetime: fdb age time in seconds
    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    skip_error_check = kwargs.get('skip_error', False)
    command = ''
    if cli_type == 'click':
        command = "config mac aging_time {}".format(int(agetime))
        if not st.is_feature_supported("config-mac-aging_time-command", dut):
            st.community_unsupported(command, dut)
            skip_error_check=True
    elif cli_type == 'klish':
        if config == 'add':
            command = "mac address-table aging-time {}".format(int(agetime))
        else:
            command = "no mac address-table aging-time"
    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        url = rest_urls['mac_aging'].format(name='default')
        config_data = {"openconfig-network-instance:mac-aging-time": int(agetime)}
        if not config_rest(dut, rest_url=url, http_method=cli_type, json_data=config_data):
              st.error("Failed to configure aging as {}".format(agetime))
              return False
    if command:
        st.config(dut, command, skip_error_check=skip_error_check, type=cli_type)
    return True


def get_mac_agetime(dut, cli_type=""):
    """
    :param dut:
    :type dut:
    :return:
    :rtype:
    """
    command = ''
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    if cli_type == 'click':
        if st.is_feature_supported("show-mac-aging-time-command", dut):
            command = "show mac aging-time"
        elif st.is_feature_supported("show-mac-aging_time-command", dut):
            command = "show mac aging_time"
        else:
            st.community_unsupported("show mac aging-time", dut)
            return 300
    elif cli_type == 'klish':
        command = "show mac address-table aging-time"
    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        url = rest_urls["mac_aging"].format(name='default')
        out = get_rest(dut, rest_url= url)
        if isinstance(out, dict) and out.get('output') and 'openconfig-network-instance:mac-aging-time' in out['output']:
            return int(out['output']['openconfig-network-instance:mac-aging-time'])

    else:
        st.error("Unsupported CLI_TYPE: {}".format(cli_type))
        return False

    if command:
        output = st.show(dut, command, type=cli_type)
        return int(output[0]["aging_time"])
    return True


def get_mac_address_list(dut, mac=None, vlan=None, port=None, type=None, cli_type=""):
    """

    :param dut:
    :param mac:
    :param vlan:
    :param port:
    :param type:
    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    entries = get_mac(dut, cli_type=cli_type)
    if mac:
        entries = filter_and_select(entries, None, {"macaddress": str(mac)})
    if vlan:
        entries = filter_and_select(entries, None, {"vlan": str(vlan)})
    if port:
        entries = filter_and_select(entries, None, {"port": port})
    if type:
        entries = filter_and_select(entries, None, {"type": type})
    return [ent["macaddress"] for ent in filter_and_select(entries, ['macaddress'], None)]


def verify_mac_address_table(dut, mac_addr, vlan=None, port=None, type=None, dest_ip=None, cli_type=""):
    """
    To verify the MAC parameters
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param mac_addr:
    :param vlan:
    :param port:
    :param type:
    :param dest_ip:
    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    if cli_type == "klish" or cli_type in ['rest-patch', 'rest-put']:
        if type != None:
            type = type.upper()

    waitapi.vsonic_mac_learn()

    output = get_mac(dut, cli_type=cli_type)
    entries = filter_and_select(output, None, {"macaddress": mac_addr})
    if not entries:
        st.log("Provided MAC {} entry is not exist in table".format(mac_addr))
        return False
    if vlan and not filter_and_select(entries, None, {"vlan": str(vlan)}):
        st.log("Provided VLAN {} is not exist in table with MAC  {}".format(vlan, mac_addr))
        return False
    if port and not filter_and_select(entries, None, {"port": port}):
        st.log("Provided Port {} is not exist in table with MAC  {}".format(port, mac_addr))
        return False
    if type and not filter_and_select(entries, None, {"type": type}):
        st.log("Provided Type {} is not exist in table with MAC  {}".format(type, mac_addr))
        return False
    if dest_ip and not filter_and_select(entries, None, {"dest_ip": dest_ip}):
        st.log("Provided DEST_IP {} is not exist in table with MAC {}".format(dest_ip, mac_addr))
        return False
    return True


def get_mac_all_dut(dut_list, thread=True, **kwargs):
    cli_type = st.get_ui_type(dut_list, **kwargs)
    if isinstance(dut_list, list):
        st.log("Displaying mac ..in all dut")
        st.exec_each(dut_list, get_mac, cli_type=cli_type)
    else:
        get_mac(dut_list, cli_type=cli_type)

def processed_output_based_macentries(data):
    ret_val = []
    if data and data.get("output"):
        actual_data = data['output']['openconfig-network-instance:entries']['entry']
        for each in actual_data:
            temp= {}
            temp['vlan'] =  each['state']['vlan']
            temp['macaddress'] = each['config']['mac-address']
            if 'entry-type' in each['state']:
                temp['type'] = each['state']['entry-type']
            else:
                temp['type'] = ""
            if 'interface' in each:
                temp['port'] = each['interface']['interface-ref']['config']['interface']
            else:
                temp['port'] = ""
            if 'openconfig-vxlan:peer' in each:
                temp['dest_ip'] = each['openconfig-vxlan:peer']['state']['peer-ip']
            ret_val.append(temp)
    return ret_val


def processed_output_based_macentries_vlan(data):
    ret_val = []
    if data and data.get("output"):
        actual_data = data['output']['openconfig-network-instance:entry']
        for each in actual_data:
            temp= {}
            temp['vlan'] =  each['state']['vlan']
            temp['macaddress'] = each['config']['mac-address']
            temp['type'] = each['state']['entry-type']
            temp['port'] = each['interface']['interface-ref']['config']['interface']
            ret_val.append(temp)
    return ret_val

def clear_mac_dampening(dut,**kwargs):

    """
    Author :
    :param dut:
    :param interface:
    :return:
    usage
    clear_mac_dampening(dut1,interface="Ethernet0")
    clear_mac_dampening(dut1)
    """

    cli_type = kwargs.get("cli_type", st.get_ui_type(dut))
    if cli_type in ["click","rest-put", "rest-patch"]: cli_type = 'klish'
    if cli_type == "klish":
        if  'interface' in kwargs:
            intf_data = get_interface_number_from_name(kwargs['interface'])
            command = "clear mac dampening-disabled-ports {} {}\n".format(intf_data["type"],intf_data["number"])
        else:
            command = "clear mac dampening-disabled-ports all\n"
    elif cli_type in ["rest-put", "rest-patch"]:
        st.log('Needs to add rest url support')
        #url = st.get_datastore(dut, "rest_urls")["config_interface"]
        #if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=):
        #return False
    else:
        st.log("Unsupported CLI TYPE {}".format(cli_type))
        return False
    if command:
        st.config(dut, command, type=cli_type)
    return True

def configure_macmove_threshold(dut, **kwargs):
    """
    Author :
    :param dut:
    :param port:
    :
    :return:
    usage
    configure_macmove_threshold(dut1,count=5)
    configure_macmove_threshold(dut1,interval=5)
    """

    cli_type = kwargs.get("cli_type", st.get_ui_type(dut))
    if cli_type in ["rest-put", "rest-patch"]: cli_type = 'klish'
    command =''
    if cli_type == "click":
        if 'count' in kwargs:
            command = "config mac dampening_threshold {}\n".format(kwargs['count'])
        if 'interval' in kwargs:
            command += " config mac dampening_threshold_interval {}\n".format(kwargs['interval'])
    elif cli_type == "klish":
        if 'count' in kwargs:
            command = "mac address-table dampening-threshold {}\n".format(kwargs['count'])
        if 'interval' in kwargs:
            command += "mac address-table dampening-interval {}\n".format(kwargs['interval'])
    elif cli_type in ["rest-put", "rest-patch"]:
        st.log('Needs to add rest url support')
        #url = st.get_datastore(dut, "rest_urls")["config_interface"]
        #if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=):
        #return False
    else:
        st.log("Unsupported CLI TYPE {}".format(cli_type))
        return False
    if command:
        st.config(dut, command, type=cli_type)
    return True

def verify_mac_dampening_threshold(dut, **kwargs):
    """
    Author :
    :param dut:
    :param port:
    :
    :return:
    usage
    verify_mac_dampening_threshold(dut1,count=2)
    """
    #cli_type = kwargs.get("cli_type", st.get_ui_type(dut))
    #if cli_type in ['rest-patch', 'rest-put']: cli_type = 'klish'
    ## Changes in klish command as part of bug fix, fallback to click till fixing templates.
    cli_type = 'click'
    if cli_type == 'click':
        cmd = "show mac dampening_threshold"
    else:
        cmd = "show mac dampening"
    parsed_output = st.show(dut,cmd,type=cli_type)
    if len(parsed_output) == 0:
        st.error("OUTPUT is Empty")
        return False
    match = {"count": kwargs['count']}
    entries = filter_and_select(parsed_output, ["count"], match)
    return True if entries else False


def verify_mac_dampening_disabled_ports(dut, **kwargs):
    """
    Author :
    :param dut:
    :param port_list:
    :
    :return:
    usage
    verify_mac_dampening_disabled_ports(data.dut1, port_list = ['Ethernet127','Ethernet126'])

    """
    parsed_output = []
    cli_type = kwargs.get("cli_type", st.get_ui_type(dut))
    if cli_type in ['rest-patch', 'rest-put']: cli_type = 'klish'
    if cli_type == 'click':
        cmd = "show mac dampening_disabled_ports"
    else:
        cmd = "show mac dampening-disabled-ports"

    parsed_output = st.show(dut,cmd,type=cli_type)

    if len(parsed_output) == 0:
        ### Klish output empty when disabled ports are not there
        parsed_output = [{'port_list':['None']}]
    st.log("DEBUG==>{}".format(parsed_output))

    if 'return_output' in kwargs:
        return parsed_output

    match = {"port_list": kwargs['port_list']}
    entries = filter_and_select(parsed_output, ["port_list"], match)
    return True if entries else False

