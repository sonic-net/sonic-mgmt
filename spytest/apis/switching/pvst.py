import re

from spytest import st, cutils

import apis.switching.portchannel as portchannel
import apis.system.basic as basic
import apis.switching.mac as mac_api
import json
import copy
import utilities.utils as utils
from utilities.parallel import ensure_no_exception, exec_foreach, exec_all, ExecAllFunc
from apis.system.rest import config_rest, delete_rest, get_rest

debug_log_path = r"/var/log/stplog"
SHOW_STP_VLAN = "show spanning_tree vlan {}"
SHOW_STP_VLAN_KLISH = "show spanning-tree vlan {}"
BLOCKING_STATE = "BLOCKING"
CONFIGURED_STP_PROTOCOL = dict()

def config_spanning_tree(dut, feature="pvst", mode="enable", vlan=None, cli_type=""):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """

    :param dut:
    :param feature:
    :param mode:
    :param vlan:
    :param cli_type:
    :return:
    """
    global CONFIGURED_STP_PROTOCOL
    CONFIGURED_STP_PROTOCOL[dut] = feature
    featureMap = {"pvst":"pvst", "rpvst":"rapid-pvst"}
    command = ''
    no_form = 'no' if mode != 'enable' else ""
    st.log("{} spanning_tree {}".format(mode, feature))
    if cli_type == 'click':
        if vlan:
            command = "config spanning_tree vlan {} {}".format(mode, vlan)
        else:
            command = "config spanning_tree {} {}".format(mode, feature)
        st.config(dut, command, type=cli_type)
    elif cli_type == 'klish':
        if mode == 'disable':
            featureMap[feature] = ''
        if vlan:
            command = "{} spanning-tree vlan {}".format(no_form, vlan)
        else:
            command = "{} spanning-tree mode {}".format(no_form, featureMap[feature])
        st.config(dut, command, type=cli_type)
    elif cli_type in ["rest-put", "rest-patch"]:
        cli_type = "rest-patch" if cli_type == "rest-put" else cli_type
        rest_urls = st.get_datastore(dut, "rest_urls")
        if vlan:
            if mode == "disable":
                url = rest_urls['stp_global_config_disabled_vlans_disable']
                payload = {"openconfig-spanning-tree-ext:disabled-vlans": [vlan]}
                if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=payload):
                    return False
            else:
                url = rest_urls['stp_global_config_disabled_vlans_enable'].format(vlan)
                if not delete_rest(dut, rest_url=url):
                    return False
        else:
            featureMap = {"pvst": "openconfig-spanning-tree-ext:PVST", "rpvst": "openconfig-spanning-tree-types:RAPID_PVST"}
            if mode == "enable":
                url = rest_urls['stp_global_protocol_config']
                payload = json.loads("""{
                    "openconfig-spanning-tree:config": {
                        "bpdu-filter": false,
                        "enabled-protocol": [
                            "openconfig-spanning-tree-types:RAPID_PVST"
                        ],
                        "openconfig-spanning-tree-ext:bridge-priority": 32768,
                        "openconfig-spanning-tree-ext:forwarding-delay": 15,
                        "openconfig-spanning-tree-ext:hello-time": 2,
                        "openconfig-spanning-tree-ext:max-age": 20,
                        "openconfig-spanning-tree-ext:rootguard-timeout": 30
                    }
                }""")
                payload["openconfig-spanning-tree:config"]["enabled-protocol"] = [featureMap[feature]]
                if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=payload):
                    return False
            else:
                url = rest_urls['stp_global_protocol_config']
                if not delete_rest(dut, rest_url=url):
                    return False
    else:
        st.log("Invalid cli_type provided: {}".format(cli_type))
        return False

def config_stp_parameters(dut, no_form='', **kwargs):
    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = 'klish' if cli_type in ['rest-patch', 'rest-put'] else cli_type
    """

    :param dut:
    :param cli_type:
    :param no_form:
    :param kwargs:
    :return:
    """
    no_form = 'no' if no_form else ''

    for each_key in kwargs.keys():
        if cli_type == 'click':
            command = "config spanning_tree {} {}".format(each_key, kwargs[each_key])
        elif cli_type == 'klish':
            if each_key == 'max_age':
                command = "{} spanning-tree max-age {}".format(no_form, kwargs[each_key])
            elif each_key == 'forward_delay':
                command = "{} spanning-tree forward-time {}".format(no_form, kwargs[each_key])
            else:
                command = "{} spanning-tree {} {}".format(no_form, each_key, kwargs[each_key])
        else:
            st.error("Invalid CLI type - {}".format(cli_type))
            return
        st.config(dut, command, type=cli_type)


def config_stp_vlan_parameters(dut, vlan, **kwargs):
    cli_type = st.get_ui_type(dut, **kwargs)
    """

    :param dut:
    :param vlan:
    :param kwargs:
    :return:
    """
    no_form = 'no' if kwargs.setdefault('no_form', False) else ''
    if 'cli_type' in kwargs:
        del kwargs['cli_type']
    del kwargs['no_form']
    click_2_klish = {'forward_delay': 'forward-time', 'hello': 'hello-time', 'max_age': 'max-age'}

    for each_key, value in kwargs.items():
        if cli_type == 'click':
            command = "config spanning_tree vlan {} {} {}".format(each_key, vlan, value)
            st.config(dut, command, type=cli_type)
        elif cli_type == 'klish':
            each_key1 = click_2_klish.get(each_key, each_key)
            if not each_key1:
                st.error("Provided Key not found")
                return False
            command = "{} spanning-tree vlan {} {} {}".format(no_form, vlan, each_key1, value)
            st.config(dut, command, type=cli_type)
        elif cli_type in ["rest-put", "rest-patch"]:
            cli_type = "rest-patch" if cli_type == "rest-put" else cli_type
            rest_urls = st.get_datastore(dut, "rest_urls")
            map = {'forward_delay': 'forwarding-delay', 'hello': 'hello-time', 'max_age': 'max-age', 'priority': 'bridge-priority'}
            url = rest_urls['{}_vlan_parameters_config'.format(CONFIGURED_STP_PROTOCOL[dut])].format(vlan, map[each_key])
            if CONFIGURED_STP_PROTOCOL[dut] == "pvst":
                if each_key == "forward_delay":
                    payload = json.loads("""{"openconfig-spanning-tree-ext:forwarding-delay": 0}""")
                    payload["openconfig-spanning-tree-ext:forwarding-delay"] = value
                elif each_key == "hello":
                    payload = json.loads("""{"openconfig-spanning-tree-ext:hello-time": 0}""")
                    payload["openconfig-spanning-tree-ext:hello-time"] = value
                elif each_key == "max_age":
                    payload = json.loads("""{"openconfig-spanning-tree-ext:max-age": 0}""")
                    payload["openconfig-spanning-tree-ext:max-age"] = value
                elif each_key == "priority":
                    payload = json.loads("""{"openconfig-spanning-tree-ext:bridge-priority": 0}""")
                    payload["openconfig-spanning-tree-ext:bridge-priority"] = value
            elif CONFIGURED_STP_PROTOCOL[dut] == "rpvst":
                if each_key == "forward_delay":
                    payload = json.loads("""{"openconfig-spanning-tree:forwarding-delay": 0}""")
                    payload["openconfig-spanning-tree:forwarding-delay"] = value
                elif each_key == "hello":
                    payload = json.loads("""{"openconfig-spanning-tree:hello-time": 0}""")
                    payload["openconfig-spanning-tree:hello-time"] = value
                elif each_key == "max_age":
                    payload = json.loads("""{"openconfig-spanning-tree:max-age": 0}""")
                    payload["openconfig-spanning-tree:max-age"] = value
                elif each_key == "priority":
                    payload = json.loads("""{"openconfig-spanning-tree:bridge-priority": 0}""")
                    payload["openconfig-spanning-tree:bridge-priority"] = value
            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=payload):
                return False
        else:
            st.log("Invalid cli_type provided: {}".format(cli_type))
            return False

def config_stp_vlan_parameters_parallel(dut_list, thread=True, **kwargs):
    cli_type = st.get_ui_type(dut_list[0], **kwargs)
    """
    Author : chaitanya lohith bollapragada
    This will configure the "config_stp_vlan_parameters" in parallel to all DUTs mentioned.
    :param dut_list:
    :param vlan: list of vlans
    :param priority: list of STP priorities
    :param thread: True | False
    :return:
    """
    st.log("Configuring STP vlan parameters in paraller on all DUT's ... ")
    dut_li = list(dut_list) if isinstance(dut_list, list) else [dut_list]
    vlan_li = list(kwargs['vlan']) if isinstance(kwargs['vlan'], list) else [kwargs['vlan']]
    priority_li = list(kwargs['priority']) if isinstance(kwargs['priority'], list) else [kwargs['priority']]
    if not len(dut_li) == len(vlan_li) == len(priority_li):
        return False
    params = list()
    for i,each in enumerate(dut_list):
        params.append(ExecAllFunc(config_stp_vlan_parameters, each, vlan_li[i], priority=priority_li[i], cli_type=cli_type))
    [out, exceptions] = exec_all(thread, params)
    ensure_no_exception(exceptions)
    return False if False in out else True


def config_stp_vlan_interface(dut, vlan, iface, value, mode='cost', **kwargs):
    cli_type = st.get_ui_type(dut, **kwargs)
    """

    :param dut:
    :param vlan:
    :param iface:
    :param value:
    :param mode:
    :return:
    """
    no_form = 'no' if kwargs.get('no_form') else ''

    if mode in ['cost', 'priority']:
        if cli_type == 'click':
            command = "config spanning_tree vlan interface {} {} {} {} ".format(mode, vlan, iface, value)
            st.config(dut, command, type=cli_type)
        elif cli_type == 'klish':
            mode = "port-priority" if mode == "priority" else mode
            interface_data = utils.get_interface_number_from_name(iface)
            command = ['interface {} {}'.format(interface_data["type"], interface_data["number"]),
                       '{} spanning-tree vlan {} {} {}'.format(no_form, vlan, mode, value), "exit"]
            st.config(dut, command, type=cli_type)
        elif cli_type in ["rest-put", "rest-patch"]:
            cli_type = "rest-patch" if cli_type == "rest-put" else cli_type
            rest_urls = st.get_datastore(dut, "rest_urls")
            url = rest_urls['{}_vlan_interface_parameters_config'.format(CONFIGURED_STP_PROTOCOL[dut])]
            if CONFIGURED_STP_PROTOCOL[dut] == "pvst":
                node = "openconfig-spanning-tree-ext:vlan"
                payload = json.loads("""{"openconfig-spanning-tree-ext:vlan": [
                                            {
                                              "vlan-id": 0,
                                              "interfaces": {
                                                "interface": [
                                                  {
                                                    "name": "string",
                                                    "config": {
                                                      "name": "string"
                                                    }
                                                  }
                                                ]
                                              }
                                            }
                                          ]
                                        }""")
            elif CONFIGURED_STP_PROTOCOL[dut] == "rpvst":
                node = "openconfig-spanning-tree:vlan"
                payload = json.loads("""{"openconfig-spanning-tree:vlan": [
                                        {
                                          "vlan-id": 0,
                                          "interfaces": {
                                            "interface": [
                                              {
                                                "name": "string",
                                                "config": {
                                                  "name": "string"
                                                }
                                              }
                                            ]
                                          }
                                        }
                                      ]
                                    }""")

            if mode == "cost":
                payload[node][0]["vlan-id"] = vlan
                payload[node][0]["interfaces"]["interface"][0]["name"] = iface
                payload[node][0]["interfaces"]["interface"][0]["config"]["name"] = iface
                payload[node][0]["interfaces"]["interface"][0]["config"]["cost"] = value
            else:
                payload[node][0]["vlan-id"] = vlan
                payload[node][0]["interfaces"]["interface"][0]["name"] = iface
                payload[node][0]["interfaces"]["interface"][0]["config"]["name"] = iface
                payload[node][0]["interfaces"]["interface"][0]["config"]["port-priority"] = value
            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=payload):
                return False
        else:
            st.log("Invalid cli_type provided: {}".format(cli_type))
            return False
    else:
        st.log("Invalid mode = {}".format(mode))
        return

def config_stp_enable_interface(dut, iface, mode="enable", cli_type=""):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """

    :param dut:
    :param iface:
    :param mode:
    :return:
    """
    if cli_type == "click":
        command = "config spanning_tree interface {} {}".format(mode, iface)
        st.config(dut, command, type=cli_type)
    elif cli_type == "klish":
        interface_data = utils.get_interface_number_from_name(iface)
        command = ['interface {} {}'.format(interface_data["type"], interface_data["number"])]
        if mode =="enable":
            command.append("spanning-tree {}".format(mode))
        else:
            command.append("no spanning-tree enable")
        command.append("exit")
        st.config(dut, command, type=cli_type)
    elif cli_type in ["rest-put", "rest-patch"]:
        cli_type = "rest-patch" if cli_type == "rest-put" else cli_type
        rest_urls = st.get_datastore(dut, "rest_urls")
        url = rest_urls['stp_interface_config_enable'].format(iface)
        if CONFIGURED_STP_PROTOCOL[dut] == "pvst":
            if mode == "enable":
                payload = json.loads("""{"openconfig-spanning-tree-ext:spanning-tree-enable": true}""")
            else:
                payload = json.loads("""{"openconfig-spanning-tree-ext:spanning-tree-enable": false}""")
        elif CONFIGURED_STP_PROTOCOL[dut] == "rpvst":
            if mode == "enable":
                payload = json.loads("""{"openconfig-spanning-tree:spanning-tree-enable": true}""")
            else:
                payload = json.loads("""{"openconfig-spanning-tree:spanning-tree-enable": false}""")
        if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=payload):
            return False
    else:
        st.log("Invalid cli_type provided: {}".format(cli_type))
        return False

def config_stp_interface_params(dut, iface, **kwargs):
    cli_type = st.get_ui_type(dut, **kwargs)
    """

    :param dut:
    :param iface:
    :param cli_type:
    :param kwargs:
    :return:
    """
    click_2_klish = {"root_guard": " guard root", "bpdu_guard": "bpduguard ", "portfast": "portfast",
                     "uplink_fast": "uplinkfast"}

    if cli_type == 'click':
        for each_key in kwargs.keys():
            if each_key == "priority" or each_key == "cost":
                command = "config spanning_tree interface {} {} {}".format(each_key, iface, kwargs[each_key])
            elif each_key == "bpdu_guard_action":
                command = "config spanning_tree interface bpdu_guard enable {} {}".format(iface, kwargs[each_key])
            else:
                command = "config spanning_tree interface {} {} {}".format(each_key, kwargs[each_key], iface)
            if not st.config(dut, command):
                return False
            return True
    elif cli_type == 'klish':
        interface_data = utils.get_interface_number_from_name(iface)
        command = ['interface {} {}'.format(interface_data["type"], interface_data["number"])]
        for each_key in kwargs.keys():
            no_form = 'no' if kwargs[each_key] == 'disable' else ''
            if each_key == "priority" or each_key == "cost":
                command.append('spanning-tree {} {}'.format(each_key, kwargs[each_key]))
            elif each_key == "bpdu_guard_action":
                command.append('{} spanning-tree bpduguard port-shutdown'.format(no_form))
            elif each_key == "loop_guard":
                if kwargs[each_key] == "enable":
                    command.append('spanning-tree guard loop')
                elif kwargs[each_key] == "none":
                    command.append('spanning-tree guard none')
                elif kwargs[each_key] == "disable":
                    command.append('no spanning-tree guard')
            elif each_key == "root_guard":
                if kwargs[each_key] == "enable":
                    command.append('spanning-tree guard root')
                elif kwargs[each_key] == "none":
                    command.append('spanning-tree guard none')
                elif kwargs[each_key] == "disable":
                    command.append('no spanning-tree guard')
            else:
                command.append("{} spanning-tree {}".format(no_form, click_2_klish[each_key]))
        command.append('exit')
        out = st.config(dut, command, skip_error_check=True, type=cli_type)
        if "%Error" in out:
            return False
        return True
    elif cli_type in ["rest-put", "rest-patch"]:
        cli_type = "rest-patch" if cli_type == "rest-put" else cli_type
        rest_urls = st.get_datastore(dut, "rest_urls")
        for each_key in kwargs.keys():
            flag = True
            mode = 'disable' if kwargs[each_key] == 'disable' else 'enable'
            if each_key == "bpdufilter":
                url = rest_urls['stp_interface_config_bpdufilter'].format(iface)
                if mode == "enable":
                    payload = json.loads("""{"openconfig-spanning-tree:bpdu-filter": true}""")
                elif mode == "disable":
                    payload = json.loads("""{"openconfig-spanning-tree:bpdu-filter": false}""")
            elif each_key == "root_guard":
                url = rest_urls['stp_interface_config_rootguard'].format(iface)
                if mode == "enable":
                    payload = json.loads("""{"openconfig-spanning-tree:guard": "ROOT"}""")
                elif mode == "disable":
                    flag = False
                    if not delete_rest(dut, rest_url=url):
                        return False
            elif each_key == "loop_guard":
                url = rest_urls['stp_interface_config_rootguard'].format(iface)
                if mode == "enable":
                    payload = json.loads("""{"openconfig-spanning-tree:guard": "LOOP"}""")
                elif mode == "disable":
                    flag = False
                    if not delete_rest(dut, rest_url=url):
                        return False
            elif each_key == "bpdu_guard":
                url = rest_urls['stp_interface_config_bpduguard'].format(iface)
                if mode == "enable":
                    payload = json.loads("""{"openconfig-spanning-tree:bpdu-guard": true}""")
                elif mode == "disable":
                    payload = json.loads("""{"openconfig-spanning-tree:bpdu-guard": false}""")
            elif each_key == "bpdu_guard_action":
                url = rest_urls['stp_interface_config_bpduguard_port_shutdown'].format(iface)
                if mode == "enable":
                    payload = json.loads("""{"openconfig-spanning-tree-ext:bpdu-guard-port-shutdown": true}""")
                elif mode == "disable":
                    payload = json.loads("""{"openconfig-spanning-tree-ext:bpdu-guard-port-shutdown": false}""")
            elif each_key == "cost":
                url = rest_urls['stp_interface_config_cost'].format(iface)
                if mode == "enable":
                    payload = json.loads("""{"openconfig-spanning-tree-ext:cost": 0}""")
                    payload["openconfig-spanning-tree-ext:cost"] = kwargs[each_key]
            elif each_key == "enable":
                url = rest_urls['stp_interface_config_enable'].format(iface)
                if mode == "enable":
                    payload = json.loads("""{"openconfig-spanning-tree-ext:spanning-tree-enable": true}""")
                elif mode == "disable":
                    payload = json.loads("""{"openconfig-spanning-tree-ext:spanning-tree-enable": false}""")
            elif each_key == "link-type":
                url = rest_urls['stp_interface_config_linktype'].format(iface)
                if mode == "enable":
                    payload = json.loads("""{"openconfig-spanning-tree:link-type": "P2P"}""")
                    payload["openconfig-spanning-tree:link-type"] = kwargs[each_key]
            elif each_key == "portfast":
                url = rest_urls['stp_interface_config_portfast'].format(iface)
                if mode == "enable":
                    payload = json.loads("""{"openconfig-spanning-tree-ext:portfast": true}""")
                elif mode == "disable":
                    payload = json.loads("""{"openconfig-spanning-tree-ext:portfast": false}""")
            elif each_key == "priority":
                url = rest_urls['stp_interface_config_port_priority'].format(iface)
                if mode == "enable":
                    payload = json.loads("""{"openconfig-spanning-tree-ext:port-priority": 0}""")
                    payload["openconfig-spanning-tree-ext:port-priority"] = kwargs[each_key]
            elif each_key == "port-type":
                url = rest_urls['stp_interface_config_edgeport'].format(iface)
                if mode == "enable":
                    payload = json.loads("""{"openconfig-spanning-tree:edge-port": "openconfig-spanning-tree-types:EDGE_ENABLE"}""")
                elif mode == "disable":
                    payload = json.loads("""{"openconfig-spanning-tree:edge-port": "openconfig-spanning-tree-types:EDGE_DISABLE}""")
            elif each_key == "uplink_fast":
                url = rest_urls['stp_interface_config_uplinkfast'].format(iface)
                if mode == "enable":
                    payload = json.loads("""{"openconfig-spanning-tree-ext:uplink-fast": true}""")
                elif mode == "disable":
                    payload = json.loads("""{"openconfig-spanning-tree-ext:uplink-fast": false}""")
            if flag:
                if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=payload):
                    return False
    else:
        st.log("Invalid cli_type provided: {}".format(cli_type))
        return False

def config_stp_interface(dut, iface, mode="enable", cli_type=""):
    """

    :param dut:
    :param iface:
    :param mode:
    :return:
    """
    #cli_type = st.get_ui_type(dut, cli_type=cli_type)
    command = "config spanning_tree interface {} {} ".format(mode, iface)
    st.config(dut, command)

def show_stp(dut, **kwargs):
    cli_type = st.get_ui_type(dut, **kwargs)
    """

    :param dut:
    :return:
    """
    # There is no single rest URI equivalent to "show spanning-tree". Multiple URIs need to be called and framed to match the o/p equivalent to "show spanning-tree". But those multiple URIs are already covered in other APIs. Hence not implementing this for REST as its redundant and not required. Also this API is used just at one place to display the o/p.
    # There is no rest URI equivalent to "show spanning-tree inconsistent ports". Multiple times URI needs to be called for all STP enabled interfaces and framed to match the o/p equivalent to "show spanning-tree inconsistent ports". But the URI is already covered in other API. Hence not implementing this for REST as its redundant and not required. Also this API is used just at one place to display the o/p.
    cli_type = "klish" if cli_type in ["rest-put", "rest-patch"] else cli_type
    if cli_type == "click":
        command = "show spanning_tree"
    else:
        command = "show spanning-tree"
    if 'sub_cmd' in kwargs:
        if cli_type == "click":
            command = "show spanning_tree {}".format(kwargs['sub_cmd'])
        else:
            if kwargs['sub_cmd'] == "root_guard":
                command = "show spanning-tree inconsistentports"
            else:
                command = "show spanning-tree {}".format(kwargs['sub_cmd'])
    return st.show(dut, command, type=cli_type)

def show_stp_vlan(dut, vlan, cli_type=""):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """

    :param dut:
    :param vlan:
    :param cli_type:
    :return:
    """
    output = ""
    st.log("show spanning_tree vlan <id>")
    if cli_type=="click":
        command = SHOW_STP_VLAN.format(vlan)
        output = st.show(dut, command, type=cli_type)
    elif cli_type == "klish":
        command = SHOW_STP_VLAN_KLISH.format(vlan)
        output = st.show(dut, command, type=cli_type)
    elif cli_type in ["rest-put", "rest-patch"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        stp_output = []
        url = rest_urls['{}_vlan_show'.format(CONFIGURED_STP_PROTOCOL[dut])].format(vlan)
        if CONFIGURED_STP_PROTOCOL[dut] == "pvst":
            payload = get_rest(dut, rest_url=url)["output"]["openconfig-spanning-tree-ext:vlan"][0]
        elif CONFIGURED_STP_PROTOCOL[dut] == "rpvst":
            payload = get_rest(dut, rest_url=url)["output"]["openconfig-spanning-tree:vlan"][0]
        table_data = {'br_lasttopo': '0', 'rt_pathcost': '0', 'br_hello': '2', 'vid': '10', 'rt_maxage': '20', 'port_name': 'Ethernet0', 'port_pathcost': '2000', 'rt_fwddly': '15', 'br_id': '800a80a23597eac1', 'br_topoch': '0', 'port_desigcost': '0', 'stp_mode': 'PVST', 'port_state': 'LISTENING', 'role': '', 'br_maxage': '20', 'port_desigrootid': '800a80a23597eac1', 'rt_hello': '2', 'port_portfast': 'Y', 'p2pmac': '', 'port_priority': '128', 'inst': '0', 'br_fwddly': '15', 'edgeport': '', 'rt_id': '800a80a23597eac1', 'br_hold': '1', 'port_uplinkfast': 'N', 'rt_port': 'Root', 'rt_desigbridgeid': '800a80a23597eac1', 'port_desigbridgeid': '800a80a23597eac1', 'port_bpdufilter': ''}

        table_data["stp_mode"] = CONFIGURED_STP_PROTOCOL[dut].upper()
        table_data["vid"] = payload["config"]["vlan-id"]
        if CONFIGURED_STP_PROTOCOL[dut] == "pvst":
            table_data["inst"] = payload["state"]["stp-instance"]
        elif CONFIGURED_STP_PROTOCOL[dut] == "rpvst":
            table_data["inst"] = payload["state"]["openconfig-spanning-tree-ext:stp-instance"]
        table_data["br_id"] = payload["state"]["bridge-address"]
        table_data["br_maxage"] = payload["state"]["max-age"]
        table_data["br_hello"] = payload["state"]["hello-time"]
        table_data["br_fwddly"] = payload["state"]["forwarding-delay"]
        table_data["br_hold"] = payload["state"]["hold-time"]
        table_data["br_lasttopo"] = payload["state"]["last-topology-change"]
        table_data["br_topoch"] = payload["state"]["topology-changes"]

        table_data["rt_id"] = payload["state"]["designated-root-address"]
        table_data["rt_pathcost"] = payload["state"]["root-cost"]
        table_data["rt_desigbridgeid"] = payload["state"]["designated-root-address"]
        if CONFIGURED_STP_PROTOCOL[dut] == "pvst":
            table_data["rt_port"] = payload["state"]["root-port-name"]
            table_data["rt_maxage"] = payload["state"]["root-max-age"]
            table_data["rt_hello"] = payload["state"]["root-hello-time"]
            table_data["rt_fwddly"] = payload["state"]["root-forward-delay"]
        elif CONFIGURED_STP_PROTOCOL[dut] == "rpvst":
            table_data["rt_port"] = payload["state"]["openconfig-spanning-tree-ext:root-port-name"]
            table_data["rt_maxage"] = payload["state"]["openconfig-spanning-tree-ext:root-max-age"]
            table_data["rt_hello"] = payload["state"]["openconfig-spanning-tree-ext:root-hello-time"]
            table_data["rt_fwddly"] = payload["state"]["openconfig-spanning-tree-ext:root-forward-delay"]

        for row in payload["interfaces"]["interface"]:
            table_data["port_name"] = row["name"]
            table_data["port_priority"] = row["state"]["port-priority"]
            table_data["port_pathcost"] = row["state"]["cost"]
            table_data["port_portfast"] = ""
            table_data["port_uplinkfast"] = ""
            table_data["port_bpdufilter"] = ""
            table_data["port_state"] = row["state"]["port-state"].strip("openconfig-spanning-tree-types:").strip("openconfig-spanning-tree-ext:")
            table_data["port_desigcost"] = row["state"]["designated-cost"]
            table_data["port_desigrootid"] = row["state"]["designated-root-address"]
            table_data["port_desigbridgeid"] = row["state"]["designated-bridge-address"]
            stp_output.append(copy.deepcopy(table_data))
        output = stp_output
    else:
        st.log("Invalid cli_type provided: {}".format(cli_type))
        return False
    return output

def show_stp_vlan_iface(dut, vlan, iface, cli_type=""):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """

    :param dut:
    :param vlan:
    :param iface:
    :return:
    """
    if cli_type == "click":
        command = "show spanning_tree vlan interface {} {}".format(vlan, iface)
    elif cli_type == "klish":
        command = "show spanning-tree vlan {} interface {}".format(vlan, iface)
    else:
        st.log("Unsupported CLI type {}".format(cli_type))
        return list()
    return st.show(dut, command, type=cli_type)

def show_stp_stats(dut, cli_type=""):
    """

    :param dut:
    :return:
    """
    #cli_type = st.get_ui_type(dut, cli_type=cli_type)
    command = "show spanning_tree statistics"
    return st.show(dut, command)

def show_stp_stats_vlan(dut, vlan, cli_type=""):
    """

    :param dut:
    :param vlan:
    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    if cli_type == "click":
        command = "show spanning_tree statistics vlan {} ".format(vlan)
        return st.show(dut, command, type=cli_type)
    elif cli_type == "klish":
        command = "show spanning-tree counters vlan {}".format(vlan)
        return st.show(dut, command, type=cli_type)
    elif cli_type in ["rest-put", "rest-patch"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        stp_output = []
        url = rest_urls['{}_vlan_show'.format(CONFIGURED_STP_PROTOCOL[dut])].format(vlan)
        if CONFIGURED_STP_PROTOCOL[dut] == "pvst":
            payload = get_rest(dut, rest_url=url)["output"]["openconfig-spanning-tree-ext:vlan"][0]
        elif CONFIGURED_STP_PROTOCOL[dut] == "rpvst":
            payload = get_rest(dut, rest_url=url)["output"]["openconfig-spanning-tree:vlan"][0]

        table_data = {'st_portno': '', 'st_inst': '', 'st_tcnrx': '0', 'st_bpdutx': '0', 'st_tcntx': '0', 'st_vid': '', 'st_bpdurx': '0'}
        table_data["st_vid"] = payload["state"]["vlan-id"]
        if CONFIGURED_STP_PROTOCOL[dut] == "pvst":
            table_data["st_inst"] = payload["state"]["stp-instance"]
        elif CONFIGURED_STP_PROTOCOL[dut] == "rpvst":
            table_data["st_inst"] = payload["state"]["openconfig-spanning-tree-ext:stp-instance"]

        for row in payload["interfaces"]["interface"]:
            table_data["st_portno"] = row["name"]
            table_data["st_bpdutx"] = int(row["state"]["counters"]["bpdu-sent"])
            table_data["st_bpdurx"] = int(row["state"]["counters"]["bpdu-received"])
            if CONFIGURED_STP_PROTOCOL[dut] == "pvst":
                table_data["st_tcntx"] = int(row["state"]["counters"]["tcn-sent"])
                table_data["st_tcnrx"] = int(row["state"]["counters"]["tcn-received"])
            elif CONFIGURED_STP_PROTOCOL[dut] == "rpvst":
                table_data["st_tcntx"] = int(row["state"]["counters"]["openconfig-spanning-tree-ext:tcn-sent"])
                table_data["st_tcnrx"] = int(row["state"]["counters"]["openconfig-spanning-tree-ext:tcn-received"])
            stp_output.append(copy.deepcopy(table_data))
        return stp_output
    else:
        st.log("Invalid cli_type provided: {}".format(cli_type))
        return False

def debug_stp(dut, *argv):
    """

    :param dut:
    :param argv:
    :return:

    Usage:
    debug_stp(dut)
    debug_stp(dut, "reset")
    debug_stp(dut, "vlan 100", "interface Ethernet0")
    debug_stp(dut, "vlan 100 -d", "interface Ethernet0 -d")
    """
    command = 'debug spanning_tree'
    if not argv:
        st.config(dut, command)
    for each in argv:
        command2 = "{} {}".format(command, each)
        st.config(dut, command2)
    return True

def get_debug_stp_log(dut, filter_list=[]):
    """"

    :param dut:
    :param filter_list:
    :return:
    """
    if isinstance(filter_list, list):
        filter_list = list(filter_list)
    else:
        filter_list = [filter_list]
    command = "cat {}".format(debug_log_path)
    for each_filter in filter_list:
        command += " | grep '{}'".format(each_filter)
    output = st.show(dut, command, skip_tmpl=True, skip_error_check=True)
    reg_output = utils.remove_last_line_from_string(output)
    out_list = reg_output.split('\n')
    return out_list

def clear_debug_stp_log(dut):
    """
    :param dut:
    :return:
    """
    command = "dd if=/dev/null of={}".format(debug_log_path)
    st.config(dut, command)
    return True

def verify_stp_vlan_iface(dut, **kwargs):
    """

    :param dut:
    :param kwargs:
    :return:
    """
    output = show_stp_vlan_iface(dut, kwargs["vlan"], kwargs["iface"])
    for each in kwargs.keys():
        match = {each: kwargs[each]}
        entries = cutils.filter_and_select(output, None, match)
        if not entries:
            st.log("{} and {} is not match ".format(each, kwargs[each]))
            return False
    return True

def verify_stp_statistics_vlan(dut, **kwargs):
    cli_type = st.get_ui_type(dut, **kwargs)
    """

    :param dut:
    :param kwargs:
    :return:
    """
    output = show_stp_stats_vlan(dut, kwargs["vlan"], cli_type=cli_type)
    for each in kwargs.keys():
        match = {each: kwargs[each]}
        entries = cutils.filter_and_select(output, None, match)
        if not entries:
            st.log("{} and {} is not match ".format(each, kwargs[each]))
            return False
    return True

def check_dut_is_root_bridge_for_vlan(dut, vlanid, cli_type=""):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """

        :param dut:
        :param vlanid:
        :return:
    """
    if cli_type == "click":
        cmd = SHOW_STP_VLAN.format(vlanid)
        stp_output = st.show(dut, cmd, type=cli_type)
    elif cli_type == "klish":
        cmd = SHOW_STP_VLAN_KLISH.format(vlanid)
        stp_output = st.show(dut, cmd, type=cli_type)
    elif cli_type in ["rest-put", "rest-patch"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        stp_output = []
        url = rest_urls['{}_vlan_show'.format(CONFIGURED_STP_PROTOCOL[dut])].format(vlanid)
        table_data = {"rt_id": '', "br_id": '', "rt_port": ''}
        if CONFIGURED_STP_PROTOCOL[dut] == "pvst":
            payload = get_rest(dut, rest_url=url)["output"]["openconfig-spanning-tree-ext:vlan"][0]
            table_data["br_id"] = payload["state"]["bridge-address"]
            table_data["rt_id"] = payload["state"]["designated-root-address"]
            table_data["rt_port"] = payload["state"]["root-port-name"]
        elif CONFIGURED_STP_PROTOCOL[dut] == "rpvst":
            payload = get_rest(dut, rest_url=url)["output"]["openconfig-spanning-tree:vlan"][0]
            table_data["br_id"] = payload["state"]["bridge-address"]
            table_data["rt_id"] = payload["state"]["designated-root-address"]
            table_data["rt_port"] = payload["state"]["openconfig-spanning-tree-ext:root-port-name"]
        stp_output.append(copy.deepcopy(table_data))
    else:
        st.log("Invalid cli_type provided: {}".format(cli_type))
        return False

    if len(stp_output) > 0:
        root_bridge=stp_output[0]["rt_id"]
        dut_bridge_id=stp_output[0]["br_id"]
        return (root_bridge == dut_bridge_id) and stp_output[0]["rt_port"] == "Root"
    else:
        return False

def get_stp_bridge_param(dut, vlanid, bridge_param, cli_type=""):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """
        This is used to provide value of the  bridge_param for given dut and vlanid
        :param dut:
        :param vlanid:
        :param bridge_param: should be one of the below strings

                                stp_mode  				Returns STP mode
                                vid  					Returns vlanid
                                inst  					Returns STP intance id
                                br_id  			    	Returns Bridge id
                                br_maxage  				Returns Bridge max age
                                br_hello  				Returns Bridge Hello timer value
                                br_fwddly  				Returns Bridge Forward Delay
                                br_hold  				Returns Bridge Hold Timer value
                                rt_id  					Returns Root Bridge id
                                rt_pathcost  			Returns RootPath Cost
                                rt_desigbridgeid  		Returns DesignatedBridge id
                                rt_port  				Returns Root
                                rt_maxage  				Returns Root max age
                                rt_hello  				Returns Root Bridge Hello Timer value
                                rt_fwddly  				Returns Root Bridge Forward Delay

        :return: Returns value of the  bridge_param for given dut and vlanid
    """
    stp_bridge_param_list = ['stp_mode',
                             'vid',
                             'inst',
                             'br_id',
                             'br_maxage',
                             'br_hello',
                             'br_fwddly',
                             'br_hold',
                             'br_lasttopo',
                             'br_topoch',
                             'rt_id',
                             'rt_pathcost',
                             'rt_desigbridgeid',
                             'rt_port',
                             'rt_maxage',
                             'rt_hello',
                             'rt_fwddly']

    if bridge_param not in stp_bridge_param_list:
        st.error("Please provide the valid stp bridge parameter")
        return
    if cli_type == "click":
        cmd = SHOW_STP_VLAN.format(vlanid)
        stp_output = st.show(dut, cmd, type=cli_type)
    elif cli_type == "klish":
        cmd = SHOW_STP_VLAN_KLISH.format(vlanid)
        stp_output = st.show(dut, cmd, type=cli_type)
    elif cli_type in ["rest-put", "rest-patch"]:
        stp_output = show_stp_vlan(dut, vlanid)
    else:
        st.log("Invalid cli_type provided: {}".format(cli_type))
        return False
    return stp_output[0][bridge_param]

def get_stp_port_param(dut, vlanid, ifname, ifparam, cli_type=""):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """
        This is used to provide value of the  bridge_param for given dut and vlanid
        :param dut:
        :param vlanid:
        :param bridge_param: should be one of the below strings

                                port_name  				Returns  Port Name
                                port_priority  			Returns Port Priority
                                port_pathcost  			Returns Port pathcost
                                port_portfast  			Returns Portfast Enabled(Y) or Not(N)
                                port_uplinkfast  		Returns Uplinkfast is Enabled(Y) or Not(N)
                                port_state  			Returns Port state
                                port_desigcost  		Returns Port Designated cost
                                port_desigrootid  		Returns Port Designated Root id
                                port_desigbridgeid  	Returns Port Designated Bridge id
        :return:
    """
    stp_port_param_list = ['port_name',
                           'port_priority',
                           'port_pathcost',
                           'port_portfast',
                           'port_uplinkfast',
                           'port_state',
                           'port_desigcost',
                           'port_desigrootid',
                           'port_desigbridgeid']

    if ifparam not in stp_port_param_list:
        st.error("Please provide the valid stp port parameter")
        return
    if cli_type == "click":
        cmd = SHOW_STP_VLAN.format(vlanid)+" interface {}".format(ifname)
        stp_output = st.show(dut, cmd, type=cli_type)
    elif cli_type == "klish":
        cmd = SHOW_STP_VLAN_KLISH.format(vlanid)+" interface {}".format(ifname)
        stp_output = st.show(dut, cmd, type=cli_type)
    elif cli_type in ["rest-put", "rest-patch"]:
        stp_output = []
        rest_urls = st.get_datastore(dut, "rest_urls")
        url = rest_urls['{}_vlan_interface_parameters_show'.format(CONFIGURED_STP_PROTOCOL[dut])].format(vlanid, ifname)
        if CONFIGURED_STP_PROTOCOL[dut] == "pvst":
            payload = get_rest(dut, rest_url=url)["output"]["openconfig-spanning-tree-ext:state"]
        elif CONFIGURED_STP_PROTOCOL[dut] == "rpvst":
            payload = get_rest(dut, rest_url=url)["output"]["openconfig-spanning-tree:state"]
        table_data = {}
        table_data["port_name"] = payload["name"]
        table_data["port_priority"] = payload["port-priority"]
        table_data["port_pathcost"] = payload["cost"]
        temp_var = payload["port-state"].strip("openconfig-spanning-tree-types:").strip("openconfig-spanning-tree-ext:")
        if temp_var == "BPDU_DIS":
            portstate = "BPDU-DIS"
        elif temp_var == "ROOT_INC":
            portstate = "ROOT-INC"
        else:
            portstate = temp_var
        table_data["port_state"] = portstate
        table_data["port_desigcost"] = payload["designated-cost"]
        table_data["port_desigrootid"] = payload["designated-root-address"]
        table_data["port_desigbridgeid"] = payload["designated-bridge-address"]
        table_data["port_portfast"] = "Y" if str(get_rest(dut, rest_url=rest_urls['stp_interface_show_portfast'].format(ifname))["output"]["openconfig-spanning-tree-ext:portfast"]) == "True" else "N"
        table_data["port_uplinkfast"] = "Y" if str(get_rest(dut, rest_url=rest_urls['stp_interface_show_uplinkfast'].format(ifname))["output"]["openconfig-spanning-tree-ext:uplink-fast"]) == "True" else "N"
        stp_output.append(copy.deepcopy(table_data))
    else:
        st.log("Invalid cli_type provided: {}".format(cli_type))
        return False
    return None if len(stp_output) == 0 else stp_output[0][ifparam]

def get_default_root_bridge(dut_list, cli_type=""):
    cli_type = st.get_ui_type(dut_list[0], cli_type=cli_type)
    """
        This is used to get the root bridge with default config
        :param vars : Testbed Vars
        :return: Returns root bridge like D1 or D2
    """
    duts_mac_list = get_duts_mac_address(dut_list, cli_type=cli_type)
    if duts_mac_list:
        min_mac_addr = min(duts_mac_list.values())
        root_bridge = [dut for dut, mac_addr in duts_mac_list.items() if mac_addr == min_mac_addr][0]
        return  [dut for dut in dut_list if dut==root_bridge][0]
    else:
        return None

def get_duts_mac_address(duts, cli_type=""):
    """
        This is used to get the Duts and its mac addresses mapping
        :param duts: List of DUTs
        :return : Duts and its mac addresses mapping

    """
    #cli_type = st.get_ui_type(duts[0], cli_type=cli_type)
    duts_mac_addresses = {}
    for dut in duts:
        if st.is_vsonic(dut):
            mac = basic.get_ifconfig_ether(dut)
            duts_mac_addresses[dut] = mac
            continue
        duts_mac_addresses[dut] = mac_api.get_sbin_intf_mac(dut, "eth0").replace(":","")
    st.log("DUT MAC ADDRESS -- {}".format(duts_mac_addresses))
    return duts_mac_addresses

def _get_duts_list_in_order(vars, cli_type=""):
    cli_type = st.get_ui_type(vars, cli_type=cli_type)
    """
        This is used to get the DUTs and their mac addresses in ascending order of Mac addresses
        :param duts: List of DUTs
        :return : Duts and its mac addresses mapping

    """
    duts_mac_addresses = get_duts_mac_address(vars["dut_list"],cli_type=cli_type)

    return sorted(zip(duts_mac_addresses.values(), duts_mac_addresses.keys()))

def get_ports_based_on_state(vars, vlanid, port_state, dut=None, cli_type=""):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """
            This is used to get the blocked ports on none-root bridge
            :param duts: List of DUTs
            :return : Duts and its mac addresses mapping

    """

    selected_non_root = ""
    if dut is None:
        duts_list = _get_duts_list_in_order(vars, cli_type=cli_type)
        dut_with_max_mac_address = duts_list[len(duts_list) - 1][1]
        selected_non_root = [dut_key for dut_key, dut_value in vars.items() if dut_value == dut_with_max_mac_address][0]
    else:
        selected_non_root = [dut_key for dut_key, dut_value in vars.items() if dut_value == dut][0]
    stp_output = show_stp_vlan(vars[selected_non_root], vlanid, cli_type=cli_type)
    ports_list = [row["port_name"] for row in stp_output if
                     row["port_state"] == port_state and int(row["vid"]) == vlanid]

    return ports_list

def poll_for_root_switch(dut, vlanid, iteration=20, delay=1, cli_type=""):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """
    API to poll for root switch

    :param dut:
    :param vlanid:
    :param iteration:
    :param delay:
    :return:
    """

    i = 1
    while True:
        if check_dut_is_root_bridge_for_vlan(dut, vlanid, cli_type=cli_type):
            st.log("Observed dut is root bridge {} iteration".format(i))
            return True
        if i > iteration:
            st.log("Max iterations {} reached".format(i))
            return False
        i += 1
        st.wait(delay)

def poll_for_stp_status(dut, vlanid, interface, status, iteration=20, delay=1, cli_type=""):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """
    API to poll for stp stauts for an interface

    :param dut:
    :param vlanid:
    :param iteration:
    :param delay:
    :return:
    """
    i = 1
    while True:
        if get_stp_port_param(dut, vlanid, interface, "port_state", cli_type=cli_type) == status:
            st.log("Port status is changed to  {} after {} sec".format(status, i))
            return True
        if i > iteration:
            st.log("Max iterations {} reached".format(i))
            return False
        i += 1
        st.wait(delay)

def get_root_guard_details(dut, vlan=None, ifname=None , rg_param="rg_timeout", cli_type=""):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """
     API will return Root Guard timeout if vlan and interface won't provide , otherwise Root Guard state will return
    :param dut:
    :param vlan:
    :param ifname:
    :return:
    """
    rg_value = ""
    if cli_type == "click":
        cmd = "show spanning_tree root_guard"
        output = st.show(dut, cmd, type=cli_type)
    elif cli_type == "klish":
        cmd = "show spanning-tree inconsistentports"
        output = st.show(dut, cmd, type=cli_type)
    elif cli_type in ["rest-put", "rest-patch"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        if rg_param == "rg_timeout":
            url = rest_urls['stp_global_root_guard_timeout']
            rg_value = int(get_rest(dut, rest_url=url)["output"]["openconfig-spanning-tree-ext:rootguard-timeout"])
        elif rg_param == "rg_status":
            url = rest_urls['{}_vlan_interface_root_guard_timer'.format(CONFIGURED_STP_PROTOCOL[dut])].format(vlan, ifname)
            timerVal = int(get_rest(dut, rest_url=url)["output"]["openconfig-spanning-tree-ext:root-guard-timer"])
            if timerVal == 0:
                rg_value = "Consistent state"
            else:
                rg_value = "Inconsistent State"
        return rg_value
    else:
        st.log("Invalid cli_type provided: {}".format(cli_type))
        return False

    if vlan is None and ifname is None:
        rg_value = int(output[0][rg_param])
    else:
        for row in output:
            if row["rg_ifname"] == ifname and int(row["rg_vid"]) == vlan:
                rg_value = row[rg_param]
    return rg_value

def check_rg_current_state(dut, vlan, ifname, cli_type=""):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """
    API will check the  Root Guard status for given interface and vlan
    :param dut:
    :param vlan:
    :param ifname:
    :return:
    """
    rg_status = get_root_guard_details(dut, vlan, ifname, "rg_status", cli_type=cli_type)
    if cli_type in ["click", "rest-put", "rest-patch"]:
        return rg_status == "Consistent state"
    else:
        return rg_status == ""

def check_bpdu_guard_action(dut, ifname, **kwargs):
    cli_type = st.get_ui_type(dut, **kwargs)
    """
    API will check the BPDU Guard action config and it's operational status
    :param dut:
    :param ifname:
    :param kwargs:
                   config_shut : BPDU shutdown configuration
                   opr_shut : status of the port shut due to BPDU Guard
    :return:
    """
    if cli_type == "click":
        cmd = "show spanning_tree bpdu_guard"
        show_out = st.show(dut, cmd, type=cli_type)
    elif cli_type == "klish":
        cmd = "show spanning-tree bpdu-guard"
        show_out = st.show(dut, cmd, type=cli_type)
    elif cli_type in ["rest-put", "rest-patch"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        show_out = []
        url = rest_urls['stp_interface_show'].format(ifname)
        table_data = {"bg_ifname": '', "bg_cfg_shut": '', "bg_oper_shut": ''}
        payload = get_rest(dut, rest_url=url)["output"]["openconfig-spanning-tree:state"]
        table_data["bg_ifname"] = payload["name"]
        if "openconfig-spanning-tree-ext:bpdu-guard-port-shutdown" in payload:
            table_data["bg_cfg_shut"] = str(payload["openconfig-spanning-tree-ext:bpdu-guard-port-shutdown"])
        else:
            table_data["bg_cfg_shut"] = ""
        table_data["bg_oper_shut"] = str(payload["openconfig-spanning-tree-ext:bpdu-guard-shutdown"])
        if str(table_data["bg_cfg_shut"]) == "False":
            table_data["bg_oper_shut"] = "NA"
        show_out.append(copy.deepcopy(table_data))
    else:
        st.log("Invalid cli_type provided: {}".format(cli_type))
        return False

    if show_out:
        if_out = [row for row in show_out if row['bg_ifname'] == ifname][0]
        if if_out['bg_cfg_shut'] in ["N", "No", "False"]:
            if_out['bg_cfg_shut'] = "No"
        if if_out['bg_cfg_shut'] in ["Y", "Yes", "True"]:
            if_out['bg_cfg_shut'] = "Yes"
        if if_out['bg_oper_shut'] in ["N", "No", "False"]:
            if_out['bg_oper_shut'] = "No"
        if if_out['bg_oper_shut'] in ["Y", "Yes", "True"]:
            if_out['bg_oper_shut'] = "Yes"
        config_shut, opr_shut = if_out['bg_cfg_shut'], if_out['bg_oper_shut']
    else:
        config_shut, opr_shut = "", ""
    return kwargs['config_shut'] == config_shut and kwargs['opr_shut'] == opr_shut

def stp_clear_stats(dut, **kwargs):
    """

    :param dut:
    :param kwargs:
                    vlan :vlan id
                    interface : interface name
    :return:
    """
    cmd = "sonic-clear spanning_tree statistics"
    if 'vlan' in kwargs and 'interface' not in kwargs:
        cmd += ' vlan {}'.format(kwargs['vlan'])
    if 'vlan' in kwargs and 'interface' in kwargs:
        cmd += ' vlan-interface {} {}'.format(kwargs['vlan'], kwargs['interface'])
    st.config(dut, cmd)

def get_stp_stats(dut, vlan, interface, param, cli_type=""):
    """

    :param dut:
    :param vlan:
    :param interface:
    :param param:
                    tx_bpdu : BPDU Transmission count
                    rx_bpdu : BPDU Receive count
                    tx_tcn  : TCN Transmission count
                    rx_tcn  : TCN Receive count

    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    output = show_stp_stats_vlan(dut, vlan, cli_type=cli_type)
    value_list = [row[param] for row in output if int(row['st_vid']) == vlan and row['st_portno'] == interface]
    st.banner(value_list)
    return None if len(output) == 0 else int(value_list[0])

def verify_stp_ports_by_state(dut, vlan, port_state, port_list, cli_type=""):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """
    API Will check the port state in the VLAN.
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param vlan:
    :param state:
    :param port_list:
    :param cli_type:
    :return:
    """
    port_li = list(port_list) if isinstance(port_list, list) else [port_list]
    stp_output = show_stp_vlan(dut, vlan, cli_type=cli_type)
    ports_list = [row["port_name"] for row in stp_output if
                     row["port_state"] == port_state and int(row["vid"]) == vlan]

    result = True
    for each_port in port_li:
        if each_port not in ports_list:
           st.log("{} is not {} state ".format(each_port, port_state))
           result = False
        else:
           st.log("{} is {} state ".format(each_port, port_state))
    return result

def get_stp_port_list(dut, vlan, exclude_port=[], cli_type=""):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """
     API will return all ports of VLAN instance.
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param vlan:
    :param exclude_port:
    :param cli_type:
    :return:
    """
    ex_port_li = list(exclude_port) if isinstance(exclude_port, list) else [exclude_port]
    stp_output = show_stp_vlan(dut, vlan, cli_type=cli_type)
    ports_list = [row["port_name"] for row in stp_output]
    for each_int in ex_port_li:
        if each_int in ports_list:
            ports_list.remove(each_int)
            st.log("{} is excluded".format(each_int))
    return ports_list

def get_stp_root_port(dut, vlan, cli_type=""):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """
    API will return Root/Forwarding port of the device in the VLAN.
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param vlan:
    :param cli_type:
    :return:
    """
    out = show_stp_vlan(dut, vlan, cli_type=cli_type)
    if not out:
        st.error("No Root/Forwarding port found")
        return False
    if out[0]['rt_port'] == "Root":
        st.error("Given device is ROOT Bridge.")
        return False
    return out[0]['rt_port']

def get_stp_next_root_port(dut, vlan, cli_type=""):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """
    API will return Next possible Root/Forwarding port of the device in the VLAN.
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param vlan:
    :param cli_type:
    :return:
    """

    partner = None
    next_root_port = None
    sort_list = lambda list1, list2: [x for _, x in sorted(zip(list2, list1))]

    out = show_stp_vlan(dut, vlan, cli_type=cli_type)
    if not out:
        st.error("No Initial Root/Forwarding port found")
        return next_root_port

    if out[0]['rt_port'] == "Root":
        st.error("Given device is ROOT Bridge.")
        return next_root_port

    partner_ports = st.get_dut_links(dut)
    root_port = out[0]['rt_port']
    tempVar = cutils.filter_and_select(out, ['port_pathcost'], {'port_name': root_port})
    if len(tempVar) != 0:
        root_cost = int(tempVar[0]['port_pathcost'])
    else:
        root_cost = 0
    st.log('root_port : {}, root_cost: {}'.format(root_port, root_cost))

    # Finding the Root port connected partner
    for each in partner_ports:
        if not partner:
            if root_port == each[0]:
                partner = each[1]
                st.log("partner : {}".format(partner))

    if not partner:
        st.error("No Partner found for Root/Forwarding Port.")
        return next_root_port

    # Dut Partner port mapping
    dut_partner_ports = st.get_dut_links(dut, partner)
    dut_partner_ports_map = {all[0]: all[2] for all in dut_partner_ports}
    dut_partner_ports_map_rev = {all[2]: all[0] for all in dut_partner_ports}
    st.log('dut_partner_ports_map : {}'.format(str(dut_partner_ports_map)))
    st.log('dut_partner_ports_map_rev : {}'.format(str(dut_partner_ports_map_rev)))

    # Preparing DATA to process and find the next Root/Forwarding port.
    cut_data = {}
    pc_list = []
    for lag_intf in cutils.iterable(portchannel.get_portchannel_list(partner)):
        if cli_type == "click":
            pc_list.append(lag_intf["teamdev"])
        elif cli_type in ["klish", "rest-put", "rest-patch"]:
            pc_list.append(lag_intf["name"])
    for each in out:
        port = each['port_name']
        if "Eth" in port and port in dut_partner_ports_map:
            port = dut_partner_ports_map[each['port_name']]
            ifindex = int(re.findall(r'\d+', port)[0])
            cut_data[port] = [ifindex, each['port_state'], int(each['port_pathcost'])]
        elif port in pc_list:
            ifindex = int(re.findall(r'\d+', port)[0])
            cut_data[port] = [ifindex, each['port_state'], int(each['port_pathcost'])]
        else:
            pass
    st.log('cut_data == {}'.format(str(cut_data)))

    cost_vs_port = {}
    for each in cut_data:
        if each != dut_partner_ports_map[root_port]:
            if 'Ethernet' in each:
                if cut_data[each][2] not in cost_vs_port:
                    cost_vs_port[cut_data[each][2]] = [[each], []]
                else:
                    cost_vs_port[cut_data[each][2]][0].append(each)
            else:
                if cut_data[each][2] not in cost_vs_port:
                    cost_vs_port[cut_data[each][2]] = [[], [each]]
                else:
                    cost_vs_port[cut_data[each][2]][1].append(each)

    sorted_cost = sorted(cost_vs_port.keys())
    st.log("cost_vs_port : {}".format(cost_vs_port))
    st.log("sorted_cost : {}".format(sorted_cost))

    # Logic to find next Root/Forwarding port
    if root_cost in cost_vs_port and (len(cost_vs_port[root_cost][0]) or len(cost_vs_port[root_cost][1])):
        st.debug("When 2 or more ports has configured with same root port cost.")
        if len(cost_vs_port[root_cost][0]):
            port_list = cost_vs_port[root_cost][0]
            port_index_li = [cut_data[e][0] for e in port_list]
            next_root_port = sort_list(port_list, port_index_li)[0]
            return dut_partner_ports_map_rev[next_root_port]
        else:
            port_list = cost_vs_port[root_cost][1]
            port_index_li = [cut_data[e][0] for e in port_list]
            next_root_port = sort_list(port_list, port_index_li)[0]
            return next_root_port

    elif len(sorted_cost):
        st.debug("When NO 2 or more ports has root port cost configured. So checking next larger cost ports")
        next_root_cost = sorted_cost[0]
        if len(cost_vs_port[next_root_cost][0]):
            port_list = cost_vs_port[next_root_cost][0]
            port_index_li = [cut_data[e][0] for e in port_list]
            next_root_port = sort_list(port_list, port_index_li)[0]
            return dut_partner_ports_map_rev[next_root_port]
        else:
            port_list = cost_vs_port[next_root_cost][1]
            port_index_li = [cut_data[e][0] for e in port_list]
            next_root_port = sort_list(port_list, port_index_li)[0]
            return next_root_port
    else:
        st.error("No Match")
    return next_root_port

def config_stp_in_parallel(dut_list, feature="pvst", mode="enable", vlan=None, thread=True, cli_type=""):
    cli_type = st.get_ui_type(dut_list, cli_type=cli_type)
    """
    API to configure stp in parallel on all the provided DUT's
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut_list:
    :param feature:
    :param mode:
    :param vlan:
    :param thread:
    :return:
    """
    st.log("Configuring {} on all the DUT's with mode as {}".format(feature.capitalize(), mode))
    dut_li = list([str(e) for e in dut_list]) if isinstance(dut_list, list) else [dut_list]
    params = list()
    for dut in dut_li:
        params.append([config_spanning_tree, dut, feature, mode, vlan, cli_type])
    if params:
        exec_all(thread, params)

def show_stp_in_parallel(dut_list, thread=True, cli_type=""):
    cli_type = st.get_ui_type(dut_list, cli_type=cli_type)
    """
    API to show the stp configuration in parallel in all the provided DUT's
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut_list:
    :param thread:
    :param cli_type:
    :return:
    """
    st.log("Displaying STP result on all the DUT's in parallel ....")
    dut_li = cutils.make_list(dut_list)
    exec_foreach(thread, dut_li, show_stp, cli_type=cli_type)

def get_root_bridge_for_vlan(dut_vlan_data, thread=True, cli_type=""):
    cli_type = st.get_ui_type(dut_vlan_data, cli_type=cli_type)
    params = list()
    result = dict()
    for dut, vlan in dut_vlan_data.items():
        params.append([check_dut_is_root_bridge_for_vlan, dut, vlan, cli_type])
    if params:
        [out, _] = exec_all(thread, params)
        st.banner("Getting root bridge details")
        for i,response in enumerate(out):
            result[params[i][1]] = response
    return result

def check_for_single_root_bridge_per_vlan(dut_list, vlan_list, dut_vlan_data, cli_type=""):
    cli_type = st.get_ui_type(dut_list, cli_type=cli_type)
    """
    API to check for single root bridge per VLAN
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param vlanid:
    :param cli_type:
    :return:
    """
    st.log("Verifying the single root bridge per vlan ...")
    dut_li = list([str(e) for e in dut_list]) if isinstance(dut_list, list) else [dut_list]
    vlan_li = list([str(e) for e in vlan_list]) if isinstance(vlan_list, list) else [vlan_list]
    st.log("DUT LIST : {}, VLAN LIST :{}".format(dut_list, vlan_list))
    if len(vlan_list) != len(dut_list):
        st.log("Invalid data provided to check the root bridge per vlan ...")
        st.report_fail("invalid_data_for_root_bridge_per_vlan")
    for vlan in vlan_li:
        root_count = 0
        params = list()
        for dut in dut_li:
            params.append([show_stp_vlan, dut, vlan, cli_type])
        stp_output, exceptions = exec_all(True, params)
        st.log(stp_output)
        for value in exceptions:
            if value is not None:
                st.log("Exception occured {}".format(value))
                return False
        if not stp_output:
            st.log("STP output not found on {} for {} instance".format(dut_li, vlan))
            st.report_fail("stp_output_not_found", dut_li, vlan)
        for index, stp_out in enumerate(stp_output):
            if len(stp_out) <= 0:
                st.log("STP OUTPUT IS NOT OBSERVED --- {}".format(stp_out))
                st.report_fail("stp_output_not_found", dut_li, vlan)
            root_bridge = stp_out[0]["rt_id"]
            dut_bridge_id = stp_out[0]["br_id"]
            if root_bridge == dut_bridge_id and stp_out[0]["rt_port"] == "Root":
                st.log("Expected DUT to VLAN root: {}".format(dut_vlan_data))
                if dut_vlan_data[dut_li[index]] != int(vlan.strip()):
                    st.error("Observed DUT to VLAN root: {} - {}".format(dut_li[index], vlan))
                    st.report_fail("expected_dut_not_root", dut_li[index], vlan)
                else:
                    st.log("Observed DUT to VLAN root: {} - {}".format(dut_li[index], vlan))
                root_count += 1
            if root_count > 1:
                st.log("Observed more than 1 root bridge per {} instance".format(vlan))
                st.report_fail("observed_more_than_1_root_bridge", vlan)
    return True

def verify_root_bridge_interface_state(dut, vlan, interface_list, cli_type=""):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """
    API to verify the root bridge interface state to be forwarded
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param vlan:
    :param interface_list:
    :param cli_type:
    :return:
    """
    fail_states = ["BLOCKING", "DISABLED", "DISCARDING"]
    pass_states = ["FORWARDING"]
    forwarding_counter = 0
    result = show_stp_vlan(dut, vlan, cli_type=cli_type)
    if result:
        for data in result:
            if data["port_name"] not in interface_list:
                st.log("Interface {} not found in expected list ...".format(data["port_name"]))
            if data["port_state"] in fail_states:
                st.log("Observed that interface {} state is {} for root bridge".format(data["port_name"],fail_states))
            if data["port_state"] in pass_states:
                forwarding_counter+=1
        if forwarding_counter != len(interface_list):
            return False
        else:
            return True
    else:
        st.log("No STP data found for {} and {} instance".format(dut, vlan))
        return False

def poll_root_bridge_interfaces(dut_vlan_list, interfaces_list, iteration=30, delay=1, cli_type=""):
    cli_type = st.get_ui_type()
    """
    API to get the root bridge interfaces to be forwarded
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut_vlan_list:
    :param interfaces_list:
    :param iteration:
    :param delay:
    :return:
    """
    st.log("Polling for root bridge interfaces ...")
    if dut_vlan_list and interfaces_list:
        no_of_duts = len(dut_vlan_list)
        check=0
        for dut, vlan in dut_vlan_list.items():
            i=1
            while True:
                if verify_root_bridge_interface_state(dut, vlan, interfaces_list[dut], cli_type=cli_type):
                    st.log("Root bridge interface verification succeeded.")
                    check+=1
                    break
                if i > iteration:
                    st.log("Max iteration limit reached.")
                    break
                i+=1
                st.wait(delay)
        if check != no_of_duts:
            st.log("Number of root DUTs check failed ...")
            return False
        return True
    else:
        st.log("Empty DUT VLAN LIST dut_vlan_list AND INTERFACE LIST interfaces_list")
        return False

def verify_root_bridge_on_stp_instances(dut_list, vlan, bridge_identifier, cli_type=""):
    cli_type = st.get_ui_type(dut_list, cli_type=cli_type)
    """
    API to verify the bridge identifier with root bridge identifier
    :param dut_list:
    :param vlan:
    :param bridge_identifier:
    :return:
    """
    dut_li = list(dut_list) if isinstance(dut_list, list) else [dut_list]
    params = list()
    for dut in dut_li:
        params.append([get_stp_bridge_param, dut, vlan, "rt_id", cli_type])
    if params:
        [out, exceptions] = exec_all(True, params)
        for value in exceptions:
            if value is not None:
                st.log("Exception occured {}".format(value))
                return False
        for identifier in out:
            st.log("Comparing ROOT bridge ID {} with Provided ID {}".format(identifier, bridge_identifier))
            if identifier != bridge_identifier:
                st.log("Mismatch in root and bridge identifiers")
                return False
            else:
                st.log("Root Bridge Identifier {} is matched with provided identifier {}".format(identifier, bridge_identifier))
                return True
    return False

def config_bpdu_filter(dut, **kwargs):
    cli_type = st.get_ui_type(dut, **kwargs)
    """
    API to config BPDU filter for global and interface level
    Usage:
    ======
    Interface level config:
    =========================
    config_bpdu_filter(dut, interface="Ethernet8", action="enable", cli_type="klish")
    config_bpdu_filter(dut, interface="Ethernet8", no_form=True, cli_type="klish")

    Global level config:
    ====================
    config_bpdu_filter(dut, cli_type="klish")
    config_bpdu_filter(dut, ,no_form=True, cli_type="klish")

    :param dut:
    :param kwargs:
    :return:
    """
    interface=kwargs.get("interface",None)
    no_form=kwargs.get("no_form", None)
    action=kwargs.get("action", "enable")
    if cli_type in ["click", "klish"]:
        commands = list()
        if not interface:
            command = "spanning-tree edge-port bpdufilter default"
            if no_form:
                command = "no {}".format(command)
            commands.append(command)
        else:
            interface_details = utils.get_interface_number_from_name(interface)
            if not interface_details:
                st.log("Interface details not found {}".format(interface_details))
                return False
            commands.append("interface {} {}".format(interface_details.get("type"), interface_details.get("number")))
            command = "spanning-tree bpdufilter"
            if no_form:
                command = "no {}".format(command)
            elif action:
                command = "{} {}".format(command, action)
            else:
                command = ""
            if command:
                commands.append(command)
        if commands:
            st.config(dut, commands, type="klish")
            return True
        return False
    elif cli_type in ["rest-put", "rest-patch"]:
        cli_type = "rest-patch" if cli_type == "rest-put" else cli_type
        rest_urls = st.get_datastore(dut, "rest_urls")
        if not interface:
            url = rest_urls['stp_global_config_bpdufilter']
        else:
            url = rest_urls['stp_interface_config_bpdufilter'].format(interface)

        if no_form:
            if delete_rest(dut, rest_url=url):
                return True
            else:
                return False
        elif action == "disable":
            payload = json.loads("""{"openconfig-spanning-tree:bpdu-filter": false}""")
        else:
            payload = json.loads("""{"openconfig-spanning-tree:bpdu-filter": true}""")
        if config_rest(dut, http_method=cli_type, rest_url=url, json_data=payload):
            return True
        else:
            return False
    else:
        st.log("Invalid cli_type provided: {}".format(cli_type))
        return False

def config_stp_root_bridge_by_vlan(stp_data, cli_type=""):
    """
    :param stp_data: {dut1: {"vlan":10, "priority": "0"}, dut2: {"vlan":20, "priority": "0"}, dut3: {"vlan":30, "priority": "0"}}
    """
    params = list()
    for dut, data in stp_data.items():
        cli_type = st.get_ui_type(dut, cli_type=cli_type)
        cli_type = "rest-patch" if cli_type == "rest-put" else cli_type
        params.append(ExecAllFunc(config_stp_vlan_parameters, dut, data["vlan"], priority=data["priority"], cli_type=cli_type))
    [_, exceptions] = exec_all(True, params)
    ensure_no_exception(exceptions)

def config_port_type(dut, interface, stp_type="rpvst", port_type="edge", no_form=False, cli_type=""):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """
    API to config/unconfig the port type in RPVST
    :param dut:
    :param port_type:
    :param no_form:
    :return:
    """
    if cli_type in ["click", "klish"]:
        commands = list()
        command = "spanning-tree port type {}".format(port_type) if not no_form else "no spanning-tree port type"
        interface_details = utils.get_interface_number_from_name(interface)
        if not interface_details:
            st.log("Interface details not found {}".format(interface_details))
            return False
        commands.append("interface {} {}".format(interface_details.get("type"), interface_details.get("number")))
        commands.append(command)
        commands.append('exit')
        st.config(dut, commands, type="klish")
        return True
    elif cli_type in ["rest-put", "rest-patch"]:
        cli_type = "rest-patch" if cli_type == "rest-put" else cli_type
        rest_urls = st.get_datastore(dut, "rest_urls")
        url = rest_urls['stp_interface_config_edgeport'].format(interface)
        payload = json.loads("""{"openconfig-spanning-tree:edge-port": "string"}""")
        payload["openconfig-spanning-tree:edge-port"] = "openconfig-spanning-tree-types:EDGE_ENABLE"
        if not no_form:
            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=payload):
                return False
        else:
            if not delete_rest(dut, rest_url=url):
                return False
    else:
        st.log("Invalid cli_type provided: {}".format(cli_type))
        return False

def show_stp_config_using_klish(dut, type="", vlan="", intf="", cli_type=""):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    if type == 'statistics':
        command = "show spanning-tree counters vlan {}".format(vlan)
    elif type == 'root_guard':
        command = "show spanning-tree inconsistentports vlan {}".format(vlan)
    elif type == 'bpdu_guard':
        command = "show spanning-tree bpdu-guard"
    elif type == "vlan_intf":
        command = "show spanning-tree vlan {} interface {}".format(vlan, intf)
    # elif type == "vlan":
        # command = "show spanning-tree vlan {}".format(vlan)
    st.show(dut, command, type=cli_type, skip_tmpl=True)

def verify_stp_intf_status(dut, vlanid, interface, status, cli_type=""):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """
    API to poll for stp stauts for an interface

    :param dut:
    :param vlanid:
    :param interface:
    :param status:
    :return:
    """
    if get_stp_port_param(dut, vlanid, interface, "port_state", cli_type=cli_type) == status:
        st.log("Port status is changed to  {}".format(status))
        return True
    return False

def get_loop_guard_details(dut, vlan=None, ifname=None , lg_param="lg_global_mode", cli_type=""):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    lg_value = ""
    if cli_type == "click" or cli_type == "klish":
        cmd = "show spanning-tree inconsistentports"
        output = st.show(dut, cmd, type=cli_type)
        if len(output) >= 2:
            output = output[1:]
    else:
        st.log("Invalid cli_type provided: {}".format(cli_type))
        return False

    if len(output) != 0:
        if vlan is None and ifname is None:
            lg_value = output[0][lg_param]
        else:
            for row in output:
                if row["rg_ifname"] == ifname and int(row["rg_vid"]) == vlan:
                    lg_value = row[lg_param]
    return lg_value

def check_lg_current_state(dut, vlan, ifname, cli_type=""):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    lg_status = get_root_guard_details(dut, vlan, ifname, "rg_status", cli_type=cli_type)
    if cli_type in ["click"]:
        return lg_status == "Consistent state"
    else:
        return lg_status == ""


def config_loopguard_global(dut, mode=None, cli_type=""):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    if cli_type == 'klish':
        if mode == 'enable':
            cmd = "spanning-tree loopguard default"
        else:
            cmd = "no spanning-tree loopguard default"
        out = st.config(dut, cmd, type=cli_type, skip_error_check=True)
        if "%Error" in out:
            return False
        return True
    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, "rest_urls")
        url = rest_urls['config_stp_loop_guard']
        if mode == 'enable':
            data = {"openconfig-spanning-tree:loop-guard": True}
            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=data):
                return False
        else:
            if not delete_rest(dut, rest_url=url):
                return False
        return True
    else:
        st.log("UNSUPPORTED CLI TYPE")
        return False

