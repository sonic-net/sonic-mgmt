# This file contains the list of API's which performs LLDP operations.
# Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
from spytest import st
from utilities.common import filter_and_select
from utilities.utils import get_interface_number_from_name, get_supported_ui_type_list, is_a_single_intf, segregate_intf_list_type
from utilities.common import make_list, get_query_params
import json
from apis.system.rest import get_rest, config_rest, delete_rest
import base64

try:
    import apis.yang.codegen.messages.lldp as umf_lldp
    import apis.yang.codegen.messages.network_policy_ext as umf_np
    from apis.yang.utils.common import Operation
except ImportError:
    pass


def force_cli_type_to_klish(cli_type):
    cli_type = "klish" if cli_type in get_supported_ui_type_list() else cli_type
    return cli_type


def get_lldp_table(dut, interface=None, cli_type="", **kwargs):
    """
    Get LLDP table Info
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param interface: localport
    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    mac = kwargs.get('mac', None)
    # cli_type = force_cli_type_to_klish(cli_type=cli_type)

    if cli_type in get_supported_ui_type_list():
        filter_type = kwargs.get('filter_type', 'ALL')
        query_param_obj = get_query_params(yang_data_type=filter_type, cli_type=cli_type)
        lldp_obj = umf_lldp.Lldp()
        if interface:
            lldp_intf_obj = umf_lldp.Interface(Name=interface, Lldp=lldp_obj)
            rv = lldp_intf_obj.get_payload(dut, query_param=query_param_obj, cli_type=cli_type)
            if rv.ok():
                actual_output = rv.payload.get("openconfig-lldp:interface")
            else:
                return []
        else:
            rv = lldp_obj.get_payload(dut, query_param=query_param_obj, cli_type=cli_type)
            if rv.ok():
                lldp_output = rv.payload.get("openconfig-lldp:lldp")
                actual_output = lldp_output.get("interfaces").get("interface")
            else:
                return []
        if actual_output:
            ret_val = _parse_lldp_data(actual_output)
            st.debug(ret_val)
            return ret_val
        else:
            return []
    elif cli_type in ["click", 'klish']:
        command = "show lldp table"
        output = st.show(dut, command, type=cli_type)
        if interface:
            if mac:
                return filter_and_select(output, None, {"localport": interface, "remotedevice": mac})
            else:
                return filter_and_select(output, None, {"localport": interface})
        return output
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        if interface:
            url = rest_urls['get_lldp_table_intf'].format(interface)
            output = get_rest(dut, rest_url=url)
            actual_data = output['output']['openconfig-lldp:interface']
        else:
            url = rest_urls['config_lldp']
            output = get_rest(dut, rest_url=url)
            actual_data = output['output']['openconfig-lldp:interfaces']['interface']
        ret_val = _parse_lldp_data(actual_data)
        return ret_val
    else:
        st.log("Unsupported cli type")
        return False


def _parse_lldp_data(lldp_intf_data):
    """
    Common logic to parse and frame lldp data
    :param lldp_intf_data:
    :return:
    """
    ret_val = []
    for each in lldp_intf_data:
        if each.get("neighbors"):
            temp = {}
            each2 = each['neighbors']['neighbor'][0]
            temp['remoteportid'] = each2['state']['port-id']
            temp['localport'] = each2['id']
            temp['remoteportdescr'] = each2['state']['port-description']
            temp['remotedevice'] = each2['state']['system-name']
            cap = []
            temp['capability'] = ''
            if each2.get('capabilities'):
                for e_cap in each2['capabilities']['capability']:
                    cap.append(e_cap['name'].split(":")[1][0])
                temp['capability'] = ' '.join(cap)
            ret_val.append(temp)
    return ret_val


def verify_lldp_neighbor(dut, intf, **kwargs):

    st.log('{} - verify_lldp_neighbor - {}'.format(dut, kwargs))

    num_args = len(kwargs)
    cmd_output = get_lldp_neighbors(dut, interface=intf)

    if num_args == 0:
        st.log('Provide at least one parameter to verify')
        return True

    for kv in kwargs.items():
        if not filter_and_select(cmd_output, None, {kv[0]: kv[1]}):
            st.error('{} is not matching on {}'.format(kv[0], dut))
        else:
            num_args -= 1

    return True if num_args == 0 else False


def get_lldp_neighbors(dut, interface=None, cli_type='', **kwargs):
    """
    Get LLDP Neighbours Info
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param interface: localport
    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    # cli_type = force_cli_type_to_klish(cli_type=cli_type)
    if cli_type in get_supported_ui_type_list():
        filter_type = kwargs.get('filter_type', 'ALL')
        query_param_obj = get_query_params(yang_data_type=filter_type, cli_type=cli_type)
        lldp_obj = umf_lldp.Lldp()
        lldp_intf_obj = umf_lldp.Interface(Name=interface, Lldp=lldp_obj)
        rv = lldp_intf_obj.get_payload(dut, query_param=query_param_obj, cli_type=cli_type)
        if rv.ok():
            neighbors_data = rv.payload.get("openconfig-lldp:interface", [])
            if neighbors_data:
                actual_data = neighbors_data[0].get("neighbors", {}).get("neighbor", {})
                ret_val = _parse_lldp_neighbor_data(actual_data)
                st.debug(ret_val)
                return ret_val
            else:
                return []
        else:
            return []
    elif cli_type == "click":
        command = "show lldp neighbors"
        if interface:
            command = "show lldp neighbors {}".format(interface)
        return st.show(dut, command, type=cli_type)
    elif cli_type == "klish":
        command = "show lldp neighbor"
        if interface:
            command = "show lldp neighbor {}".format(interface)
        return st.show(dut, command, type=cli_type)
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        url = rest_urls['get_lldp_neighbors_intf'].format(interface)
        output = get_rest(dut, rest_url=url)
        ret_val = []
        if 'output' in output and output['output'] and 'openconfig-lldp:neighbors' in output['output'] and 'neighbor' in output['output']['openconfig-lldp:neighbors']:
            actual_data = output['output']['openconfig-lldp:neighbors']['neighbor']
        else:
            return ret_val
        ret_val = _parse_lldp_neighbor_data(actual_data)
        st.debug(ret_val)
        return ret_val
    else:
        st.error('Unsupported UI TYPE - {}'.format(cli_type))
        return False


def _parse_lldp_neighbor_data(lldp_neighbor_data):
    """
    Common logic to parse lldp neighbor data
    :param lldp_neighbor_data:
    :return:
    """
    ret_val = list()
    for each in lldp_neighbor_data:
        temp = {}
        temp1 = {}
        temp1['chassis_mgmt_ipv6'] = each['state']['management-address']
        for val in temp1.values():
            list1 = val
            list2 = list1.split(",")
        temp['chassis_mgmt_ipv6'] = list2[1] if len(list2) == 2 else ""
        temp['chassis_capability_router'] = each['capabilities']['capability'][0]['state'][
            'enabled'] if 'capabilities' in each else ''
        temp['chassis_id_value'] = each['state']['chassis-id']
        temp['chassis_name'] = each['state']['system-name']
        temp['chassis_descr'] = each['state']['system-description']
        temp['chassis_ttl'] = each['state']['ttl']
        temp['chassis_mgmt_ip'] = list2[0]
        temp['interface'] = each['id']
        temp['portid_value'] = each['state']['port-id']
        temp['portid_type'] = each['state']['port-id-type']
        temp['portdescr'] = each['state']['port-description']
        temp['id'] = each['state']['id']
        if 'custom-tlvs' in each:
            temp['oui'] = each['custom-tlvs']['tlv'][0]['state']['oui']
            temp['oui_subtype'] = each['custom-tlvs']['tlv'][0]['state']['oui-subtype']
            temp['type'] = each['custom-tlvs']['tlv'][0]['state']['type']
            temp['value'] = each['custom-tlvs']['tlv'][0]['state']['value']
            temp['portvlanid_value'] = int(base64.b64decode(temp['value']))
        else:
            temp['portvlanid_value'] = ''
        ret_val.append(temp)
    return ret_val


def lldp_config_intf_params(dut, intf, **kwargs):
    cli_type = st.get_ui_type(dut, **kwargs)
    config = kwargs.get('config', 'yes')
    if cli_type in get_supported_ui_type_list():
        lldp_intf_attr_list = {
        }
        if 'status' in kwargs:
            status = kwargs['status']
            if status in ['enable', 'rx-and-tx']:
                lldp_intf_attr_list['status'] = ['Enabled', True]
            if status in ['disabled']:
                lldp_intf_attr_list['status'] = ['Enabled', False]
            if status in ['tx']:
                lldp_intf_attr_list['status'] = ['Mode', 'TRANSMIT']
            if status in ['rx']:
                lldp_intf_attr_list['status'] = ['Mode', 'RECEIVE']

        lldp_gbl_obj = umf_lldp.Lldp()
        lldp_intf_obj = umf_lldp.Interface(Name=intf, Lldp=lldp_gbl_obj)

        if config == 'yes':
            if status in ['port-vlan-id']:
                target_attr = getattr(lldp_intf_obj, 'SuppressTlvAdvertisement')
                result = lldp_intf_obj.unConfigure(dut, target_attr=target_attr, cli_type=cli_type)
            for key, attr_value in lldp_intf_attr_list.items():
                if key in kwargs and attr_value[1] is not None:
                    setattr(lldp_intf_obj, attr_value[0], attr_value[1])
            result = lldp_intf_obj.configure(dut, cli_type=cli_type)
            if not result.ok():
                st.log('test_step_failed: Config LLDP Intf Params {}'.format(result.data))
                return False
        else:
            if status in ['port-vlan-id']:
                setattr(lldp_intf_obj, 'SuppressTlvAdvertisement', 'PORT_VLAN_ID')
                result = lldp_intf_obj.configure(dut, cli_type=cli_type)
            else:
                for key, attr_value in lldp_intf_attr_list.items():
                    if key in kwargs:
                        target_attr = getattr(lldp_intf_obj, attr_value[0])
                        result = lldp_intf_obj.unConfigure(dut, target_attr=target_attr, cli_type=cli_type)
            if not result.ok():
                st.log('test_step_failed: Config LLDP Intf Params {}'.format(result.data))
                return False
        return True


def lldp_config(dut, **kwargs):
    """
    Set LLDP non default config parameters
    Author: Prasad Darnasi (prasad.darnasi@broadcom.com)
    :param dut:
    :param txinterval:LLDP update packet interval
    txinterval in klish is timer
    :param txhold:LLDP hold time
    txhold in klish is multiplier
    :param interface:remote interface
    :param status:LLDP rx|tx|rx-and-tx|disabled|enable
    :param hostname:remote system name
    hostname in klish is system-name
    :param description:remote system description
    :param capability:LLDP optional capabilities
    capability in klish is tlv-select
    :return:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    config = kwargs.get('config', 'yes')
    no_form = '' if config == 'yes' else 'no'
    rest_urls = st.get_datastore(dut, "rest_urls")
    if cli_type in get_supported_ui_type_list():
        lldp_gbl_attr_list = {
            'txinterval': ['HelloTimer', int(kwargs['txinterval']) if 'txinterval' in kwargs else None],
            'txhold': ['Multiplier', int(kwargs['txhold']) if 'txhold' in kwargs else None],
            'hostname': ['SystemName', kwargs['hostname'] if 'hostname' in kwargs else None],
            'description': ['SystemDescription', kwargs['description'] if 'description' in kwargs else None],
            #            'capability': ['', kwargs['capability'] if 'capability' in kwargs else None],
        }
        if 'capability' in kwargs:
            for each_cap in make_list(kwargs['capability']):
                if 'management-addresses-advertisements' in each_cap:
                    lldp_gbl_attr_list['capability'] = ['SuppressTlvAdvertisement', 'MANAGEMENT_ADDRESS']
                if 'capabilities-advertisements' in each_cap:
                    lldp_gbl_attr_list['capability'] = ['SuppressTlvAdvertisement', 'SYSTEM_CAPABILITIES']

        if 'status' in kwargs and 'interface' not in kwargs:
            status = kwargs['status']
            if status in ['enable', 'rx-and-tx']:
                lldp_gbl_attr_list['status'] = ['Enabled', True]
            if status in ['disabled']:
                lldp_gbl_attr_list['status'] = ['Enabled', False]
            if status in ['tx']:
                lldp_gbl_attr_list['status'] = ['Mode', 'TRANSMIT']
            if status in ['rx']:
                lldp_gbl_attr_list['status'] = ['Mode', 'RECEIVE']

        lldp_gbl_obj = umf_lldp.Lldp()
        if config == 'yes':
            attr_count = 0
            for key, attr_value in lldp_gbl_attr_list.items():
                if key in kwargs and attr_value[1] is not None:
                    attr_count += 1
                    setattr(lldp_gbl_obj, attr_value[0], attr_value[1])
            if attr_count > 0:
                result = lldp_gbl_obj.configure(dut, cli_type=cli_type)
                if not result.ok():
                    st.log('test_step_failed: Config LLDP Global Params {}'.format(result.data))
                    return False
        else:
            for key, attr_value in lldp_gbl_attr_list.items():
                cmds = list()
                if key in kwargs:
                    # Forcing to klish as deletion of leaf-list (specific value) is not supported in new API Infra
                    if kwargs[key] == 'management-addresses-advertisements':
                        cmds.append('no lldp tlv-select management-address')
                        output = st.config(dut, cmds, type='klish')
                    elif kwargs[key] == 'capabilities-advertisements':
                        cmds.append('no lldp tlv-select system-capabilities')
                        output = st.config(dut, cmds, type='klish')
                    else:
                        target_attr = getattr(lldp_gbl_obj, attr_value[0])
                        result = lldp_gbl_obj.unConfigure(dut, target_attr=target_attr, cli_type=cli_type)
                        if not result.ok():
                            st.log('test_step_failed: Config LLDP Global Params {}'.format(result.data))
                            return False
        if 'status' in kwargs and 'interface' in kwargs:
            intf = kwargs['interface']
            result = lldp_config_intf_params(dut, intf=intf, **kwargs)
            if not result:
                return result

        return True
    if cli_type == 'click':
        if 'txinterval' in kwargs:
            command = "configure lldp {} {}".format('tx-interval', kwargs['txinterval'])
            st.config(dut, command, type='lldp')
        if 'txhold' in kwargs:
            command = "configure lldp {} {}".format('tx-hold', kwargs['txhold'])
            st.config(dut, command, type='lldp')
        if 'status' in kwargs:
            if kwargs['status'] == "enable":
                kwargs['status'] = "rx-and-tx"
            if 'interface' in kwargs:
                command = "configure ports {} lldp status {}".format(kwargs['interface'], kwargs['status'])
            else:
                command = "configure lldp status {}".format(kwargs['status'])
            st.config(dut, command, type='lldp')
        if 'hostname' in kwargs:
            command = "configure system hostname {}".format(kwargs['hostname'])
            st.config(dut, command, type='lldp')
        if 'capability' in kwargs and 'config' in kwargs:
            cap = kwargs['capability']
            cap_li = list(cap) if isinstance(cap, list) else [cap]
            for each_cap in cap_li:
                if kwargs['config'] == 'yes':
                    command = "config lldp {}".format(each_cap)
                else:
                    command = "unconfigure lldp {}".format(each_cap)
                st.config(dut, command, type='lldp')
        return True

    elif cli_type == 'klish':
        cmds = []
        if 'txinterval' in kwargs:
            cmds.append("{} lldp timer {}".format(no_form, kwargs['txinterval']))
        if 'txhold' in kwargs:
            cmds.append("{} lldp multiplier {}".format(no_form, kwargs['txhold']))
        if 'hostname' in kwargs:
            cmds.append("{} lldp system-name {}".format(no_form, kwargs['hostname']))
        if 'description' in kwargs:
            cmds.append("{} lldp system-description {}".format(no_form, kwargs['description']))
        if 'capability' in kwargs:
            cap = kwargs['capability']
            cap_li = list(cap) if isinstance(cap, list) else [cap]
            for e_cap in cap_li:
                if 'management-addresses-advertisements' in e_cap:
                    cmds.append("{} lldp tlv-select management-address".format(no_form))
                if 'capabilities-advertisements' in e_cap:
                    cmds.append("{} lldp tlv-select system-capabilities".format(no_form))
        if 'status' in kwargs:
            if 'interface' in kwargs:
                port_hash_list = segregate_intf_list_type(intf=kwargs['interface'], range_format=False)
                intf_list = port_hash_list['intf_list_all']
                for each_intf in intf_list:
                    if not is_a_single_intf(each_intf):
                        cmds.append("interface range {}".format(each_intf))
                    else:
                        interface_details = get_interface_number_from_name(each_intf)
                        cmds.append("interface {} {}".format(interface_details.get("type"), interface_details.get("number")))
            intf_mode = {"rx": "receive", "tx": "transmit", "rx-and-tx": "enable", "disabled": "disable", "enable": "enable", 'port-vlan-id': "tlv-select port-vlan-id",
                         "network-policy": "med-tlv-select network-policy", "med-power-management": "med-tlv-select power-management", "power-management": "tlv-select power-management"}
            status = intf_mode[kwargs['status']]
            if status == 'disable':
                no_form = "no"
                status = "enable"
            cmds.append("{} lldp {}".format(no_form, status))
            if 'interface' in kwargs:
                cmds.append('exit')
        output = st.config(dut, cmds, type=cli_type)
        if "Error:" in output:
            st.error("LLDP config failed")
            st.log(output)
            return False
        return True
    elif cli_type in ["rest-put", "rest-patch"]:
        if 'status' in kwargs and 'interface' not in kwargs:
            status = kwargs['status']
            if status in ['enable', 'rx-and-tx']:
                url = rest_urls['config_lldp_enabled']
                json_data = {"openconfig-lldp:enabled": True}
                if config == 'yes':
                    config_rest(dut, http_method=cli_type, rest_url=url, json_data=json_data)
                else:
                    delete_rest(dut, rest_url=url)
            elif status == 'disabled':
                url = rest_urls['config_lldp_enabled']
                json_data = {"openconfig-lldp:enabled": False}
                if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=json_data):
                    st.error("Failed to disable LLDP")
                    return False
            elif status == 'tx':
                json_data = {"openconfig-lldp-ext:mode": "TRANSMIT"}
                url = rest_urls['tx_rx_lldp_enable']
                if kwargs.get('config', 'yes') == 'yes':
                    config_rest(dut, http_method=cli_type, rest_url=url, json_data=json_data)
                else:
                    delete_rest(dut, rest_url=url)
            elif status == 'rx':
                json_data = {"openconfig-lldp-ext:mode": "RECEIVE"}
                url = rest_urls['tx_rx_lldp_enable']
                if kwargs.get('config', 'yes') == 'yes':
                    config_rest(dut, http_method=cli_type, rest_url=url, json_data=json_data)
                else:
                    delete_rest(dut, rest_url=url)

        if 'txinterval' in kwargs:
            url = rest_urls['txinterval_config']
            json_data = {"openconfig-lldp:hello-timer": str(kwargs['txinterval'])}
            if kwargs.get('config', 'yes') == 'yes':
                config_rest(dut, http_method=cli_type, rest_url=url, json_data=json_data)
            else:
                delete_rest(dut, rest_url=url)
        if 'txhold' in kwargs:
            json_data = {"openconfig-lldp-ext:multiplier": kwargs['txhold']}
            url = rest_urls['txhold_config']
            if kwargs.get('config', 'yes') == 'yes':
                config_rest(dut, http_method=cli_type, rest_url=url, json_data=json_data)
            else:
                delete_rest(dut, rest_url=url)
        if 'hostname' in kwargs:
            json_data = {"openconfig-lldp:system-name": str(kwargs['hostname'])}
            url = rest_urls['system_name_config']
            if kwargs.get('config', 'yes') == 'yes':
                config_rest(dut, http_method=cli_type, rest_url=url, json_data=json_data)
            else:
                delete_rest(dut, rest_url=url)
        if 'description' in kwargs:
            json_data = {"openconfig-lldp:system-description": kwargs['description']}
            url = rest_urls['system_description_config']
            if kwargs.get('config', 'yes') == 'yes':
                config_rest(dut, http_method=cli_type, rest_url=url, json_data=json_data)
            else:
                delete_rest(dut, rest_url=url)
        if 'capability' in kwargs:
            cap = kwargs['capability']
            cap_li = list(cap) if isinstance(cap, list) else [cap]
            for e_cap in cap_li:
                if 'management-addresses-advertisements' in e_cap:
                    if kwargs.get('config', 'yes') == 'yes':
                        url = rest_urls['clear_tlv_advertise'].format("MANAGEMENT_ADDRESS")
                        if not delete_rest(dut, rest_url=url):
                            st.error("Failed to enable LLDP TLV: MANAGEMENT_ADDRESS")
                            return False
                    else:
                        json_data = {"openconfig-lldp:suppress-tlv-advertisement": ["MANAGEMENT_ADDRESS"]}
                        url = rest_urls['suppress_tlv_advertisement']
                        if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=json_data):
                            st.error("Failed to disable LLDP TLV: MANAGEMENT_ADDRESS")
                            return False
                if 'capabilities-advertisements' in e_cap:
                    if kwargs.get('config', 'yes') == 'yes':
                        url = rest_urls['clear_tlv_advertise'].format("SYSTEM_CAPABILITIES")
                        if not delete_rest(dut, rest_url=url):
                            st.error("Failed to enable LLDP TLV: SYSTEM_CAPABILITIES")
                            return False
                    else:
                        json_data = {"openconfig-lldp:suppress-tlv-advertisement": ["SYSTEM_CAPABILITIES"]}
                        url = rest_urls['suppress_tlv_advertisement']
                        if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=json_data):
                            st.error("Failed to disable LLDP TLV: SYSTEM_CAPABILITIES")
                            return False
        if 'interface' in kwargs and 'status' in kwargs:
            status = kwargs['status']
            url = rest_urls['config_lldp']
            params_data = {"name": kwargs['interface']}
            if status == 'disabled':
                params_data.update(enabled=False)
            if status == 'enable' or status == "rx-and-tx":
                params_data.update(enabled=True)
            if status == 'tx':
                if config == 'yes':
                    params_data.update({"openconfig-lldp-ext:mode": "TRANSMIT"})
                else:
                    del_url = rest_urls['tx_rx_lldp_enable_intf'].format(kwargs['interface'])
                    if not delete_rest(dut, rest_url=del_url):
                        return False
            if status == 'rx':
                if config == 'yes':
                    params_data.update({"openconfig-lldp-ext:mode": "RECEIVE"})
                else:
                    del_url = rest_urls['tx_rx_lldp_enable_intf'].format(kwargs['interface'])
                    if not delete_rest(dut, rest_url=del_url):
                        return False

            if status == 'port-vlan-id':
                if config == 'yes':
                    params_data.update({"openconfig-lldp-ext:suppress-tlv-advertisement": ["PORT_VLAN_ID"]})
                else:
                    del_url = rest_urls['suppress_tlv_advert_lldp_intf'].format(kwargs['interface'])
                    if not delete_rest(dut, rest_url=del_url):
                        return False

            if len(params_data) > 1:
                json_data = {"openconfig-lldp:interfaces": {"interface": [{"name": kwargs['interface'], "config": params_data}]}}
                if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=json_data):
                    return False
        return True
    else:
        st.error('Unsupported UI TYPE - {}'.format(cli_type))
        return False


def set_lldp_local_parameters(dut, name, **kwargs):
    """
    Set LLDP Local parameters
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param name:
    :param mgmt_addr:
    :param hwsku:
    :param lo_addr:
    :param local_port:
    :param local_port:
    :param type:
    :param port:
    :return:
    """
    st.log("Adding local lldp data")
    temp_local_data = {}
    lldp_local_final = {}
    if not kwargs:
        st.error("SET LLDP Local parameters failed because of invalid data.")
        return False
    if 'mgmt_addr' in kwargs:
        temp_local_data['mgmt_addr'] = kwargs['mgmt_addr']
    if 'hwsku' in kwargs:
        temp_local_data['hwsku'] = kwargs['hwsku']
    if 'lo_addr' in kwargs:
        temp_local_data['lo_addr'] = kwargs['lo_addr']
    if 'local_port' in kwargs:
        temp_local_data['local_port'] = kwargs['local_port']
    if 'type' in kwargs:
        temp_local_data['type'] = kwargs['type']
    if 'port' in kwargs:
        temp_local_data['port'] = kwargs['port']

    lldp_local_final['DEVICE_NEIGHBOR'] = {name: temp_local_data}
    lldp_local_final_json = json.dumps(lldp_local_final)
    st.apply_json(dut, lldp_local_final_json)
    return True


def poll_lldp_neighbors(dut, iteration_count=180, delay=1, interface=None):
    """
    Poll for LLDP Neighbours Info
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param iteration_count:
    :param delay:
    :param interface:
    :return:
    """
    i = 1
    while True:
        rv = get_lldp_neighbors(dut, interface)
        if rv:
            return rv
        if i > iteration_count:
            st.log(" Max {} tries Exceeded for lldp neighbors polling .Exiting ...".format(i))
            return False
        i += 1
        st.wait(delay)


def get_lldp_statistics(dut, **kwargs):
    """
    To get LLDP statistics
    Author: Jagadish Chatrasi (jagadish.chatrasi@broadcom.com)
    :param dut:
    :param kwargs:
    :return:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    # cli_type = force_cli_type_to_klish(cli_type=cli_type)
    ports = make_list(kwargs.get('ports')) if kwargs.get('ports') else None
    if cli_type in get_supported_ui_type_list():
        filter_type = kwargs.get('filter_type', 'ALL')
        query_param_obj = get_query_params(yang_data_type=filter_type, cli_type=cli_type)
        lldp_obj = umf_lldp.Lldp()
        output = list()
        output_dict = dict()
        if ports:
            for port in ports:
                lldp_intf_obj = umf_lldp.Interface(Name=port, Lldp=lldp_obj)
                rv = lldp_intf_obj.get_payload(dut, query_param=query_param_obj, cli_type=cli_type)
                if rv.ok():
                    output_dict["output"] = rv.payload
                    output.extend(_get_rest_lldp_statistics(output_dict))
        else:
            rv = lldp_obj.get_payload(dut, query_param=query_param_obj, cli_type=cli_type)
            if rv.ok():
                lldp_output = rv.payload.get("openconfig-lldp:lldp")
                output_dict["output"] = lldp_output
                output = _get_rest_lldp_statistics(output_dict)
        st.debug(output)
        return output
    elif cli_type == "click":
        if not st.is_feature_supported("show-lldp-statistics-command", dut):
            command = 'show statistics ports {}'.format(','.join(ports)) if ports else 'show statistics'
            command = "docker exec -it lldp lldpcli {}".format(command)
        else:
            command = 'show lldp statistics {}'.format(','.join(ports)) if ports else 'show lldp statistics'
        return st.show(dut, command, type=cli_type)
    elif cli_type == "klish":
        output = list()
        if ports:
            for port in ports:
                intf = get_interface_number_from_name(port)
                command = 'show lldp statistics {} {}'.format(intf['type'], intf['number'])
                output.extend(st.show(dut, command, type=cli_type))
        else:
            command = 'show lldp statistics'
            output = st.show(dut, command, type=cli_type)
        return output
    elif cli_type in ["rest-patch", "rest-put"]:
        output = list()
        rest_urls = st.get_datastore(dut, "rest_urls")
        if ports:
            for port in ports:
                url = rest_urls['get_lldp_table_intf'].format(port)
                out = get_rest(dut, rest_url=url)
                output.extend(_get_rest_lldp_statistics(out))
        else:
            url = rest_urls['config_lldp']
            out = get_rest(dut, rest_url=url)
            output = _get_rest_lldp_statistics(out)
        return output
    else:
        st.error('Unsupported CLI_TYPE: {}'.format(cli_type))
        return False


def _get_rest_lldp_statistics(out, cli_type=None):
    """
    To get REST LLDP statistics
    Author: Jagadish Chatrasi (jagadish.chatrasi@broadcom.com)
    :param out:
    """
    retval = list()
    if cli_type not in ["gnmi", "rest"]:
        if isinstance(out, dict) and out.get('output') and isinstance(out['output'], dict) and 'openconfig-lldp:interface' in out['output'] and isinstance(out['output']['openconfig-lldp:interface'], list):
            entries = out['output']['openconfig-lldp:interface']
        elif isinstance(out, dict) and out.get('output') and isinstance(out['output'], dict) and 'openconfig-lldp:interfaces' in out['output'] and isinstance(out['output']['openconfig-lldp:interfaces'], dict) and out['output']['openconfig-lldp:interfaces'].get('interface') and isinstance(out['output']['openconfig-lldp:interfaces']['interface'], list):
            entries = out['output']['openconfig-lldp:interfaces']['interface']
        else:
            st.error("The REST GET data format is not as expected")
            return retval
    else:
        entries = out
    for entry in entries:
        temp = dict()
        temp['interface'] = entry['name'] if isinstance(entry, dict) and entry.get('name') else ''
        if isinstance(entry, dict) and entry.get('state') and entry['state'].get('counters') and isinstance(entry['state']['counters'], dict):
            counters_dict = entry['state']['counters']
            temp['transmitted'] = counters_dict['frame-out'] if counters_dict.get('frame-out') else '0'
            temp['received'] = counters_dict['frame-in'] if counters_dict.get('frame-in') else '0'
            temp['discarded'] = counters_dict['frame-discard'] if counters_dict.get('frame-discard') else '0'
            temp['unrecognized'] = counters_dict['tlv-unknown'] if counters_dict.get('tlv-unknown') else '0'
            temp['ageout'] = counters_dict['openconfig-lldp-ext:ageout'] if counters_dict.get('openconfig-lldp-ext:ageout') else '0'
            retval.append(temp)
    st.debug(retval)
    return retval


def check_chassis_mgmt_ip(dut, iter_cnt, intf):
    i = 1
    while True:
        rv = get_lldp_neighbors(dut, intf)
        if rv and len(rv) > 0 and 'chassis_mgmt_ip' in rv[0] and rv[0]['chassis_mgmt_ip']:
            return rv
        if i > iter_cnt:
            st.log(" Max {} tries Exceeded for lldp neighbors polling .Exiting ...".format(i))
            return rv
        i += 1
        st.wait(1)


def configure_network_policy_per_interface(dut, **kwargs):
    """
    Author: Praveen Kumar Kota (praveenkumar.kota@broadcom.com)
    :param dut:
    :param kwargs:
    :return:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    profile = kwargs.get('profile', 1)
    interface = kwargs.get('interface')
    config = kwargs.get('config', 'yes')
    if cli_type in get_supported_ui_type_list() + ['klish']:
        lldp_intf_obj = umf_lldp.Interface(Name=interface, NetworkPolicy=profile)
        if config == 'yes':
            result = lldp_intf_obj.configure(dut, cli_type=cli_type)
        else:
            result = lldp_intf_obj.unConfigure(dut, cli_type=cli_type)
        if not result.ok():
            st.log('test_step_failed: Failure to configure policy')
            return False
        return True
    else:
        st.error('Unsupported CLI_TYPE: {}'.format(cli_type))
        return False


def configure_network_policy(dut, **kwargs):
    """
    Author: Praveen Kumar Kota (praveenkumar.kota@broadcom.com)
    :param dut:
    :param kwargs:
    :return:
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut, **kwargs))
    vlan_id = kwargs.get('vlan_id', 0)
    cos = kwargs.get('cos', 0)
    dscp = kwargs.get('dscp', 0)
    profile = kwargs.get('profile', 1)
    config = kwargs.get('config', 'yes')
    tagged = kwargs.get('tagged', True)
    if cli_type in get_supported_ui_type_list() + ['klish']:
        operation = Operation.CREATE
        policy_obj = umf_np.NetworkPolicy(Number=profile)
        if config == 'yes':
            policy_obj.configure(dut, operation=operation, cli_type=cli_type)
            application_obj = umf_np.Application(Type='VOICE', NetworkPolicy=policy_obj)
            if vlan_id == 0:
                application_obj.VlanId = 0
            else:
                application_obj.VlanId = vlan_id
            if cos:
                application_obj.Priority = int(cos)
            if dscp:
                application_obj.Dscp = int(dscp)
            if not tagged:
                if cli_type == 'klish':
                    application_obj.Tagged = True
                else:
                    application_obj.Tagged = False

            result = application_obj.configure(dut, operation=operation, cli_type=cli_type)
        else:
            result = policy_obj.unConfigure(dut, cli_type=cli_type)
        if not result.ok():
            st.log('test_step_failed: Failure to configure policy')
            return False
        return True
    else:
        st.error('Unsupported CLI_TYPE: {}'.format(cli_type))
        return False


def init_default_config(dut):
    if not st.is_soft_tgen():
        pass
    elif not st.is_feature_supported("scapy-lldp-default-enable", dut):
        st.config(dut, "config feature state lldp disabled")
