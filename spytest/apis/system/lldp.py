# This file contains the list of API's which performs LLDP operations.
# Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
from spytest import st
from spytest.utils import filter_and_select
from utilities.utils import get_interface_number_from_name
import json
from apis.system.rest import get_rest,config_rest,delete_rest

def get_lldp_table(dut, interface=None, cli_type=""):
    """
    Get LLDP table Info
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param interface: localport
    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    if cli_type == "click":
        command = "show lldp table"
        output = st.show(dut, command)
        if interface:
            return filter_and_select(output, None, {"localport": interface})
        return output
    elif cli_type == "klish":
        command = "show lldp table"
        output = st.show(dut, command)
        if interface:
            return filter_and_select(output, None, {"localport": interface})
        return output
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        url = rest_urls['get_lldp_table_intf'].format(interface)
        output = get_rest(dut, rest_url = url)
        ret_val = []
        actual_data = output['output']['openconfig-lldp:interface'][0]['neighbors']['neighbor']
        for each in actual_data:
            temp = {}
            temp['remoteportid'] = each['state']['port-id']
            temp['localport'] = each['id']
            temp['remoteportdescr'] = each['state']['port-description']
            temp['remotedevice'] = each['state']['system-name']
            ret_val.append(temp)
        return ret_val
    else:
        st.log("Unsupported cli type")
        return False


def get_lldp_neighbors(dut, interface=None, cli_type=''):
    """
    Get LLDP Neighbours Info
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param interface: localport
    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    if cli_type == "click":
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
        output = get_rest(dut, rest_url = url)
        ret_val = []
        if 'output' in output and output['output'] and 'openconfig-lldp:neighbors' in output['output'] and 'neighbor' in output['output']['openconfig-lldp:neighbors']:
            actual_data = output['output']['openconfig-lldp:neighbors']['neighbor']
        else:
            return ret_val
        for each in actual_data:
            temp = {}
            temp1 = {}
            temp1['chassis_mgmt_ipv6'] = each['state']['management-address']
            for val in temp1.values():
                list = val
                list2 = list.split(",")
            temp['chassis_mgmt_ipv6'] = list2[1] if len(list2)==2 else ""
            temp['chassis_capability_router'] = each['capabilities']['capability'][0]['state']['enabled'] if 'capabilities' in each else ''
            temp['portdescr'] = each['state']['port-description']
            temp['chassis_id_value'] = each['state']['chassis-id']
            temp['chassis_mgmt_ip'] = list2[0]
            temp['chassis_descr'] = each['state']['system-description']
            temp['interface'] = each['id']
            temp['portid_value'] = each['state']['port-id']
            temp['chassis_name'] = each['state']['system-name']
            ret_val.append(temp)
        st.debug(ret_val)
        return ret_val
    else:
        st.error('Unsupported UI TYPE - {}'.format(cli_type))
        return False


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
        if 'hostname'in kwargs:
            cmds.append("{} lldp system-name {}".format(no_form, kwargs['hostname']))
        if 'description'in kwargs:
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
                port = get_interface_number_from_name(kwargs['interface'])
                cmds.append('interface {} {}'.format(port['type'], port['number']))
            intf_mode = {"rx": "receive", "tx": "transmit", "rx-and-tx": "enable", "disabled": "disable", "enable":"enable"}
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
            if status in ['enable','rx-and-tx']:
                url = rest_urls['config_lldp_enabled']
                json_data = {"openconfig-lldp:enabled": True}
                if config == 'yes':
                    config_rest(dut, http_method=cli_type, rest_url=url, json_data=json_data)
                else:
                    delete_rest(dut, rest_url=url)
            elif status == 'disabled':
                url = rest_urls['tx_rx_lldp_enable']
                delete_rest(dut,rest_url = url)
            elif status == 'tx':
                json_data = {"openconfig-lldp-ext:mode": "TRANSMIT"}
                url = rest_urls['tx_rx_lldp_enable']
                if kwargs.get('config', 'yes') == 'yes':
                    config_rest(dut, http_method=cli_type, url= url, json_data=json_data)
                else:
                    delete_rest(dut, rest_url = url)
            elif status == 'rx':
                json_data = {"openconfig-lldp-ext:mode": "RECEIVE"}
                url = rest_urls['tx_rx_lldp_enable']
                if kwargs.get('config', 'yes') == 'yes':
                    config_rest(dut, http_method=cli_type, url= url, json_data=json_data)
                else:
                    delete_rest(dut, rest_url = url)
        if 'txinterval' in kwargs:
            url = rest_urls['txinterval_config']
            json_data = { "openconfig-lldp:hello-timer": str(kwargs['txinterval']) }
            if kwargs.get('config', 'yes') == 'yes':
                config_rest(dut, http_method=cli_type, rest_url = url, json_data=json_data)
            else:
                delete_rest(dut, rest_url = url)
        if 'txhold' in kwargs:
            json_data = { "openconfig-lldp-ext:multiplier": kwargs['txhold'] }
            url = rest_urls['txhold_config']
            if kwargs.get('config', 'yes') == 'yes':
                config_rest(dut, http_method=cli_type, rest_url = url, json_data=json_data)
            else:
                delete_rest(dut, rest_url = url)
        if 'hostname'in kwargs:
            json_data = { "openconfig-lldp:system-name": str(kwargs['hostname']) }
            url = rest_urls['system_name_config']
            if kwargs.get('config', 'yes') == 'yes':
                config_rest(dut, http_method=cli_type, rest_url = url, json_data=json_data)
            else:
                delete_rest(dut, rest_url = url)
        if 'description'in kwargs:
            json_data= { "openconfig-lldp:system-description": kwargs['description'] }
            url = rest_urls['system_description_config']
            if kwargs.get('config', 'yes') == 'yes':
                config_rest(dut, http_method=cli_type, rest_url = url, json_data=json_data)
            else:
                delete_rest(dut, rest_url = url)
        if 'capability' in kwargs:
            cap = kwargs['capability']
            cap_li = list(cap) if isinstance(cap, list) else [cap]
            for e_cap in cap_li:
                if 'management-addresses-advertisements' in e_cap:
                    if kwargs.get('config', 'yes') == 'yes':
                        url = rest_urls['clear_tlv_advertise'].format("MANAGEMENT_ADDRESS")
                        if not delete_rest(dut, rest_url = url):
                            st.error("Failed to enable LLDP TLV: MANAGEMENT_ADDRESS")
                            return False
                    else:
                        json_data = {"openconfig-lldp:suppress-tlv-advertisement": ["MANAGEMENT_ADDRESS"]}
                        url = rest_urls['suppress_tlv_advertisement']
                        if not config_rest(dut, http_method=cli_type, rest_url = url, json_data=json_data):
                            st.error("Failed to disable LLDP TLV: MANAGEMENT_ADDRESS")
                            return False
                if 'capabilities-advertisements' in e_cap:
                    if kwargs.get('config', 'yes') == 'yes':
                        url = rest_urls['clear_tlv_advertise'].format("SYSTEM_CAPABILITIES")
                        if not delete_rest(dut, rest_url = url):
                            st.error("Failed to enable LLDP TLV: SYSTEM_CAPABILITIES")
                            return False
                    else:
                        json_data = {"openconfig-lldp:suppress-tlv-advertisement": ["SYSTEM_CAPABILITIES"]}
                        url = rest_urls['suppress_tlv_advertisement']
                        if not config_rest(dut, http_method=cli_type, rest_url = url, json_data=json_data):
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
                    if not delete_rest(dut, rest_url = del_url):
                        return False
            if status == 'rx':
                if config == 'yes':
                    params_data.update({"openconfig-lldp-ext:mode": "RECEIVE"})
                else:
                    del_url = rest_urls['tx_rx_lldp_enable_intf'].format(kwargs['interface'])
                    if not delete_rest(dut, rest_url = del_url):
                        return False
            if len(params_data) > 1:
                json_data = {"openconfig-lldp:interfaces": {"interface": [{"name": kwargs['interface'], "config": params_data}]}}
                if not config_rest(dut, http_method=cli_type, rest_url = url, json_data=json_data):
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
