import re
import json

from spytest import st

import apis.common.wait as waitapi
from apis.system.basic import get_ifconfig
from apis.system.rest import get_rest, delete_rest, config_rest

import utilities.common as common_utils
from utilities.utils import get_interface_number_from_name
from utilities.utils import override_supported_ui
from utilities.utils import get_supported_ui_type_list
from utilities.utils import convert_intf_name_to_component
from utilities.utils import get_random_space_string

try:
    import apis.yang.codegen.messages.network_instance as umf_ni
    from apis.yang.utils.common import Operation
except ImportError:
    pass


def force_cli_type_to_klish(cli_type):
    cli_type = "klish" if cli_type in get_supported_ui_type_list() else cli_type
    return cli_type


def get_mac(dut, **kwargs):
    """
    :param dut:
    :type dut:
    :return:
    :rtype:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
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
            return st.show(dut, command, type=cli_type)
    elif cli_type in ["rest-patch", "rest-put"]:
        network_instance_name = 'default'
        rest_urls = st.get_datastore(dut, "rest_urls")
        url = rest_urls['all_mac_entries'].format(network_instance_name)
        output = get_rest(dut, rest_url=url)
        rest_get_output = processed_output_based_macentries(output)
        if kwargs.get("count"):
            fdb_count_res = list()
            fdb_result = {"dynamic_cnt": 0, "count": 0, "static_cnt": 0, "vlan_cnt": 0}
            if rest_get_output:
                for value in rest_get_output:
                    if value.get("type") == "DYNAMIC":
                        fdb_result.update({"dynamic_cnt": fdb_result.get("dynamic_cnt") + 1})
                    elif value.get("type") == "STATIC":
                        fdb_result.update({"static_cnt": fdb_result.get("static_cnt") + 1})
                    if value.get("vlan"):
                        fdb_result.update({"vlan_cnt": fdb_result.get("vlan_cnt") + 1})
                    fdb_result.update({"count": fdb_result.get("count") + 1})
            fdb_count_res.append(fdb_result)
            return fdb_count_res
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
    entries = common_utils.filter_and_select(output, ["macaddress"], {'port': str(intf)})
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
    entries = common_utils.filter_and_select(output, ["macaddress"], {'vlan': str(vlan)})
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
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    if cli_type == 'click':
        # Some scripts pass MAC search pattern with beginning or trailing spaces to be grepped
        # Hence include the pattern within  quotes ""
        command = 'show mac | grep "{}"'.format(mac_address)
        mac_entries = st.show(dut, command)
    elif cli_type == 'klish':
        # Some scripts pass MAC search pattern with beginning or trailing spaces to be grepped
        # Hence include the pattern within  quotes ""
        command = 'show mac address-table | grep "{}"'.format(mac_address)
        mac_entries = st.show(dut, command, type=cli_type)
    elif cli_type in ["rest-patch", "rest-put"]:
        entries = get_mac(dut, cli_type=cli_type)
        st.debug(entries)
        mac_entries = []
        # MAC search pattern can be in the beginning or in between the MAC address string
        # Hence force the reg_exp search to start of line only if first char is space
        if mac_address[0] == ' ':
            exp = "^{}".format(mac_address.strip())
        else:
            exp = "{}".format(mac_address.strip())
        for entry in entries:
            if re.search(exp, entry['macaddress'], re.IGNORECASE):
                mac_entries.append(entry)
        st.debug(mac_entries)
    else:
        st.log("Unsupported cli")
        return False
    return mac_entries


def verify_mac_count_with_retry(dut, user_mac_count, retry_count, delay):
    mac_count = get_mac_count(dut)
    a = False
    for i in range(1, retry_count + 1):
        st.log("Attempt {} of {}".format(i, retry_count))
        if mac_count < user_mac_count:
            st.log("waiting for {} seconds before retyring again".format(delay))
            st.wait(delay)
            mac_count = get_mac_count(dut)
        else:
            a = True
            break
    return a


def get_mac_count(dut, cli_type=""):
    """
    To get the MAC count using - 'show mac count' command.
    :param dut:
    :type dut:
    :return:
    :rtype:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    if cli_type == 'click':
        field = "mac_count"
        command = "show mac count"
        if not st.is_feature_supported("show-mac-count-command", dut):
            st.community_unsupported(command, dut)
            return 0
        output = st.show(dut, command, type=cli_type)
    elif cli_type == 'klish':
        field = "count"
        command = "show mac address-table count"
        output = st.show(dut, command, type=cli_type)
    elif cli_type in ["rest-patch", "rest-put"]:
        result = get_mac(dut, cli_type=cli_type)
        mac_count = len(result)
        return mac_count
    else:
        st.log("Unsupported cli")
        return False
    if not output:
        # When MAC table is empty, klish doesn't display output so return 0
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
        # Decrement by 1 as output has "Total number of entries" as one list element in click output
        if cli_type == 'click':
            dec_flag = 1
    if entries == list or entries is None:
        # If entries is null, no need to apply filter, return 0
        return 0

    if vlan:
        entries = common_utils.filter_and_select(entries, None, {"vlan": str(vlan)})
        dec_flag = 0
    if port:
        entries = common_utils.filter_and_select(entries, None, {"port": port})
        dec_flag = 0
    if type:
        type = type if cli_type == 'click' else type.upper()
        entries = common_utils.filter_and_select(entries, None, {"type": type})
        dec_flag = 0
    return len(entries) - 1 if dec_flag == 1 else len(entries)


def verify_mac_address(dut, vlan, mac_addr, cli_type="", **kwargs):
    """

    :param dut:
    :param vlan:
    :param mac_addr:
    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)

    waitapi.vsonic_mac_learn()

    msg = "Checking provided mac entries are present in mac table under specified vlan ({})"
    st.debug(msg.format(vlan), dut=dut)
    mac_addr_list = common_utils.make_list(mac_addr)

    if cli_type in get_supported_ui_type_list():
        for mac_address in mac_addr_list:
            if not verify_mac_address_table(dut, mac_addr=mac_address, vlan=vlan, cli_type=cli_type, **kwargs):
                return False
        return True

    mac_address_all = get_mac_all(dut, vlan, cli_type=cli_type)
    return set(mac_addr_list).issubset(set(mac_address_all))


def get_sbin_intf_mac(dut, interface=None, **kwargs):
    """
    This proc is to return the mac address of the interface from the ifconfig o/p.
    :param dut: DUT Number
    :param interface: Interface number
    :return:
    """
    if st.get_args("filemode"):
        return "00:00:ba:db:ad:ba"

    output = get_ifconfig(dut, interface, **kwargs)
    if not output:
        mac = ''
    else:
        output = dict(output[0])
        mac = output.get('mac')
    return mac


def clear_mac(dut, port=None, vlan=None, **kwargs):
    """
    This proc is to clear mac address/fdb entries of the dut.
    :param dut: DUT Number
    :return:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = 'klish' if cli_type in ['rest-patch', 'rest-put'] else cli_type
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
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
            zero_or_more_space = get_random_space_string()
            command = "clear mac address-table dynamic Vlan{}{}".format(zero_or_more_space, vlan)
        elif port:
            zero_or_more_space = get_random_space_string()
            intf_data = get_interface_number_from_name(port)
            command = "clear mac address-table dynamic interface {}{}{}".format(intf_data["type"], zero_or_more_space, intf_data["number"])
        else:
            command = "clear mac address-table dynamic all"

        st.config(dut, command, type=cli_type)
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
    # st.log("config mac add <mac> <vlan> <intf>")
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    if cli_type in get_supported_ui_type_list():
        operation = Operation.CREATE
        ni_obj = umf_ni.NetworkInstance(Name='default')
        vlan_obj = umf_ni.Vlan(VlanId=int(vlan))
        ni_obj.add_Vlan(vlan_obj)
        entry_obj = umf_ni.Entry(MacAddress=mac, Vlan=vlan_obj, Interface=intf, Subinterface=0, NetworkInstance=ni_obj)
        result = entry_obj.configure(dut, operation=operation, cli_type=cli_type)
        if not result.ok():
            st.error("test_step_failed: Configure MAC")
            return False
    elif cli_type == 'click':
        command = "config mac add {} {} {}".format(mac, vlan, intf)
        if not st.is_feature_supported("config-mac-add-command", dut):
            st.community_unsupported(command, dut)
            _json_mac_add(dut, mac, vlan, intf)
        else:
            st.config(dut, command, type='click')
    elif cli_type == 'klish':
        interface = get_interface_number_from_name(intf)
        command = "mac address-table {} vlan {} {} {}".format(mac, vlan, interface["type"], interface["number"])
        st.config(dut, command, type=cli_type)
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        url = rest_urls['static_mac_config']
        json = {"openconfig-network-instance:network-instances": {"network-instance": [{"name": "default", "fdb": {"mac-table": {"entries": {"entry": [{"mac-address": mac, "vlan": int(vlan), "config": {"mac-address": mac, "vlan": int(vlan)}, "interface": {"interface-ref": {"config": {"interface": intf, "subinterface": 0}}}}]}}}}]}}
        if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=json):
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
    # st.log("config mac del <mac> <vlan>")
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    if cli_type in get_supported_ui_type_list():
        ni_obj = umf_ni.NetworkInstance(Name='default')
        vlan_obj = umf_ni.Vlan(VlanId=int(vlan))
        ni_obj.add_Vlan(vlan_obj)
        entry_obj = umf_ni.Entry(MacAddress=mac, Vlan=vlan_obj, Subinterface=0, NetworkInstance=ni_obj)
        result = entry_obj.unConfigure(dut, cli_type=cli_type)
#        result = entry_obj.unConfigure(dut, target_attr=entry_obj.MacAddress, cli_type=cli_type)
        if not result.ok():
            st.error("test_step_failed: Delete MAC: {}".format(result.data))
            return False
    elif cli_type == 'click':
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


def config_mac_agetime(dut, agetime, cli_type="", config="add", **kwargs):
    """
    This proc is to config mac aging and setting it back to default.
    :param dut: DUT Number
    :param agetime: fdb age time in seconds
    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    skip_error_check = kwargs.get('skip_error', False)
    command = ''
    if cli_type in get_supported_ui_type_list():
        #        operation = Operation.CREATE
        ni_obj = umf_ni.NetworkInstance(Name='default', MacAgingTime=int(agetime))
        # Workaround for default values. Setting of defult values are not working in FT runs
        if int(agetime) == 600:
            config = 'no'
        if config == 'add':
            st.log('***IETF_JSON***: {}'.format(ni_obj.get_ietf_json()))
            result = ni_obj.configure(dut, cli_type=cli_type)
        else:
            result = ni_obj.unConfigure(dut, target_attr=ni_obj.MacAgingTime, cli_type=cli_type)
        if not result.ok():
            st.error("test_step_failed: Failed to Configure MAC agetime")
            return False
    elif cli_type == 'click':
        command = "config mac aging_time {}".format(int(agetime))
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
    if not st.is_feature_supported("config-mac-aging_time-command", dut):
        st.community_unsupported(command, dut)
        skip_error_check = True

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
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    if cli_type == 'click':
        command = "show mac aging-time"
    elif cli_type == 'klish':
        command = "show mac address-table aging-time"
    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        url = rest_urls["mac_aging"].format(name='default')
        out = get_rest(dut, rest_url=url)
        if isinstance(out, dict) and out.get('output') and 'openconfig-network-instance:mac-aging-time' in out['output']:
            return int(out['output']['openconfig-network-instance:mac-aging-time'])
    else:
        st.error("Unsupported CLI_TYPE: {}".format(cli_type))
        return False
    if not st.is_feature_supported("show-mac-aging_time-command", dut):
        st.community_unsupported(command, dut)
        return 300
    if command:
        output = st.show(dut, command, type=cli_type)
        if not output:
            st.error("Output is Empty")
            return False
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
        entries = common_utils.filter_and_select(entries, None, {"macaddress": str(mac)})
    if vlan:
        entries = common_utils.filter_and_select(entries, None, {"vlan": str(vlan)})
    if port:
        entries = common_utils.filter_and_select(entries, None, {"port": port})
    if type:
        entries = common_utils.filter_and_select(entries, None, {"type": type})
    return [ent["macaddress"] for ent in common_utils.filter_and_select(entries, ['macaddress'], None)]


def verify_mac_address_table(dut, mac_addr, vlan=None, port=None, type=None, dest_ip=None, cli_type="", **kwargs):
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

    if cli_type in get_supported_ui_type_list():
        # mac_addr and vlan are must for message driven infra
        # Forcing it to klish is vlan is provided
        if vlan is None:
            cli_type = 'klish'

    if cli_type in get_supported_ui_type_list():
        filter_type = kwargs.get('filter_type', 'ALL')
        ni_obj = umf_ni.NetworkInstance(Name='default')
        vlan_obj = umf_ni.Vlan(VlanId=int(vlan))
        ni_obj.add_Vlan(vlan_obj)
        # entry_obj = umf_ni.Entry(MacAddress=mac_addr, Vlan=vlan_obj, NetworkInstance=ni_obj)
        # GNMI get call is not working if mac_addr is in uppercase
        entry_obj = umf_ni.Entry(MacAddress=mac_addr.lower(), Vlan=vlan_obj, NetworkInstance=ni_obj)
        if port:
            setattr(entry_obj, 'Interface', port)
        if type:
            setattr(entry_obj, 'EntryType', type.upper())
            filter_type = 'NON_CONFIG' if type.upper() != 'STATIC' else filter_type
        else:
            filter_type = 'NON_CONFIG'
        if dest_ip:
            setattr(entry_obj, 'PeerIp', dest_ip)

        query_param_obj = common_utils.get_query_params(yang_data_type=filter_type, cli_type=cli_type)
        result = entry_obj.verify(dut, match_subset=True, query_param=query_param_obj, cli_type=cli_type)
        if not result.ok():
            st.error('test_step_failed: Match Not Found')
            return False

        return True

    if cli_type != 'click':
        if type is not None:
            type = type.upper()
    elif port:
        port = convert_intf_name_to_component(dut, port, component="applications")

    waitapi.vsonic_mac_learn()

    match_field_map = dict()
    match_field_map['macaddress'] = mac_addr
    if vlan:
        match_field_map['vlan'] = str(vlan)
    if port:
        match_field_map['port'] = port
    if type:
        match_field_map['type'] = type
    if dest_ip:
        match_field_map['dest_ip'] = dest_ip

    output = get_mac(dut, cli_type=cli_type)
    entries = common_utils.filter_and_select(output, None, match_field_map)
    if not entries:
        st.error("Provided MAC {} entry is not exist in table".format(match_field_map))
        return False
    else:
        st.log("Provided MAC {} entry exists in table".format(match_field_map))
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
            temp = {}
            temp['vlan'] = each['state']['vlan']
            temp['macaddress'] = each['config']['mac-address']
            temp['macaddress'] = temp['macaddress'].upper()
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
            temp = {}
            temp['vlan'] = each['state']['vlan']
            temp['macaddress'] = each['config']['mac-address']
            temp['type'] = each['state']['entry-type']
            temp['port'] = each['interface']['interface-ref']['config']['interface']
            ret_val.append(temp)
    return ret_val


def clear_mac_dampening(dut, **kwargs):
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
    cli_type = override_supported_ui("rest-put", "rest-patch", "click", cli_type=cli_type)
    if cli_type == "klish":
        if 'interface' in kwargs:
            intf_data = get_interface_number_from_name(kwargs['interface'])
            command = "clear mac dampening-disabled-ports {} {}\n".format(intf_data["type"], intf_data["number"])
        else:
            command = "clear mac dampening-disabled-ports all\n"
    elif cli_type in ["rest-put", "rest-patch"]:
        st.log('Needs to add rest url support')
        # url = st.get_datastore(dut, "rest_urls")["config_interface"]
        # if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=):
        # return False
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
    if cli_type in ["rest-put", "rest-patch"]:
        cli_type = 'klish'

    if cli_type in get_supported_ui_type_list():
        ni_obj = umf_ni.NetworkInstance(Name='default')
        if 'count' in kwargs:
            setattr(ni_obj, 'Threshold', int(kwargs['count']))
        if 'interval' in kwargs:
            setattr(ni_obj, 'Interval', int(kwargs['interval']))
        result = ni_obj.configure(dut, cli_type=cli_type)
        if not result.ok():
            st.error('test_step_failed: Config of MAC Dampening')
            return False

        return True

    command = ''
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
        # url = st.get_datastore(dut, "rest_urls")["config_interface"]
        # if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=):
        # return False
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
    cli_type = kwargs.get("cli_type", st.get_ui_type(dut))
    if cli_type in ['rest-patch', 'rest-put']:
        cli_type = 'klish'

    if cli_type in get_supported_ui_type_list():
        filter_type = kwargs.get('filter_type', 'NON_CONFIG')
        query_param_obj = common_utils.get_query_params(yang_data_type=filter_type, cli_type=cli_type)
        ni_obj = umf_ni.NetworkInstance(Name='default')
        if 'count' in kwargs:
            setattr(ni_obj, 'Threshold', int(kwargs['count']))
        if 'interval' in kwargs:
            setattr(ni_obj, 'Interval', int(kwargs['interval']))
        if 'port_list' in kwargs:
            setattr(ni_obj, 'Interfaces', kwargs['port_list'])
        result = ni_obj.verify(dut, match_subset=True, target_path='/mac-dampening', query_param=query_param_obj, cli_type=cli_type)
        if not result.ok():
            st.error('test_step_failed: Match Not Found')
            return False

        return True

    if cli_type == 'click':
        cmd = "show mac dampening-threshold"
    else:
        cmd = "show mac dampening"
    parsed_output = st.show(dut, cmd, type=cli_type)
    if len(parsed_output) == 0:
        st.error("OUTPUT is Empty")
        return False
    match = {"count": kwargs['count']}
    entries = common_utils.filter_and_select(parsed_output, ["count"], match)
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
    if cli_type in ['rest-patch', 'rest-put']:
        cli_type = 'klish'
    if 'port_list' in kwargs and kwargs['port_list'] == ['None']:
        cli_type = 'klish'
    if 'return_output' in kwargs:
        cli_type = 'klish'
    if cli_type in get_supported_ui_type_list():
        return verify_mac_dampening_threshold(dut, **kwargs)
    if cli_type == 'click':
        cmd = "show mac dampening-disabled-ports"
    else:
        cmd = "show mac dampening-disabled-ports"

    parsed_output = st.show(dut, cmd, type=cli_type)

    if len(parsed_output) == 0:
        # Klish output empty when disabled ports are not there
        parsed_output = [{'port_list': ['None']}]
    st.log("DEBUG==>{}".format(parsed_output))

    if 'return_output' in kwargs:
        return parsed_output

    match = {"port_list": kwargs['port_list']}
    entries = common_utils.filter_and_select(parsed_output, ["port_list"], match)
    return True if entries else False


def verify_mac_table(dut, **kwargs):
    """
    API to verify whether mac address table is empty or not
    :param dut:
    :param interface:
    :return:
    """
    check_for_empty = kwargs.get("check_for_empty", False)
    if kwargs.get("interface"):
        mac_list = get_mac(dut, interface=kwargs.get("interface"))
    elif kwargs.get("vlan"):
        mac_list = get_mac(dut, vlan=kwargs.get("vlan"))
    else:
        mac_list = get_mac(dut)
    if not mac_list:
        return True if check_for_empty else False
    else:
        return False if check_for_empty else True


def config_system_l2nhg_profile(dut, **kwargs):
    """
    :param dut:
    :param kwarfs:
    :return:
    res=mac_api.config_system_l2nhg_profile(dut, config='yes')
    res=mac_api.config_system_l2nhg_profile(dut, config='no')
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut))
    skiperr = kwargs.pop('skip_error', False)
    my_cmd = ''
    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = 'yes'
    if config.lower() == 'yes':
        config_cmd = ''
    else:
        config_cmd = 'no'

    if cli_type == 'klish' or cli_type == 'click':
        my_cmd += 'switch-resource \n'
        my_cmd += '{} l2-nexthop-group \n exit'.format(config_cmd)
        out = st.config(dut, my_cmd, type=cli_type, skip_error_check=skiperr)
        if '%Error:' in out:
            return False
        return True
    else:
        st.log("Unsupported CLI TYPE - {}".format(cli_type))
        return False
