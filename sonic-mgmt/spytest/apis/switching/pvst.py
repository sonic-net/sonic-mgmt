import re
import json
import copy

from spytest import st

from apis.switching import portchannel
from apis.system import basic
import apis.switching.mac as mac_api
from apis.system.rest import config_rest, delete_rest, get_rest

from utilities import utils
import utilities.common as cutils
from utilities.parallel import ExecAllFunc, exec_all, exec_foreach
from utilities.utils import segregate_intf_list_type, is_a_single_intf
from utilities.utils import get_interface_number_from_name, get_supported_ui_type_list
from utilities.utils import get_random_space_string
from utilities.utils import add_zero_or_more_spaces_to_intf

try:
    import apis.yang.codegen.messages.spanning_tree.SpanningTree as umf_stp
except ImportError:
    pass


def force_cli_type_to_klish(cli_type):
    cli_type = "klish" if cli_type in get_supported_ui_type_list() else cli_type
    return cli_type


debug_log_path = r"/var/log/stplog"
SHOW_STP_VLAN = "show spanning_tree Vlan {}"
SHOW_STP_VLAN_KLISH = "show spanning-tree Vlan {}"
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
    CONFIGURED_STP_PROTOCOL[dut] = feature
    featureMap = {"pvst": "pvst", "rpvst": "rapid-pvst", "mstp": "mst"}
    if featureMap[feature] == 'mst':
        cli_type = "klish" if cli_type == "click" else cli_type
    command = ''
    no_form = 'no' if mode != 'enable' else ""
    st.log("{} spanning_tree {}".format(mode, feature))
    if cli_type in get_supported_ui_type_list():
        result_val = True
        if vlan:
            stp_gbl_obj = umf_stp.Stp(DisabledVlans=[vlan])
            if mode == 'disable':
                result = stp_gbl_obj.configure(dut, cli_type=cli_type)
            else:
                command = "spanning-tree Vlan {}".format(vlan)
                st.config(dut, command, type='klish')
                result_val = False
        else:
            featureMap = {"pvst": "PVST", "rpvst": "RAPID_PVST", "mstp": "MSTP"}
            if feature == 'mstp':
                stp_gbl_obj = umf_stp.Stp(EnabledProtocol=featureMap[feature], GlobalHelloTime=2, GlobalMaxAge=20, GlobalForwardingDelay=15, BridgePriority=32768, BpduFilter=False)
            else:
                stp_gbl_obj = umf_stp.Stp(EnabledProtocol=featureMap[feature], GlobalHelloTime=2, GlobalMaxAge=20, GlobalForwardingDelay=15, BridgePriority=32768, BpduFilter=False, RootguardTimeout=30)
            if mode == 'enable':
                result = stp_gbl_obj.configure(dut, cli_type=cli_type)
                if feature != 'mstp':
                    result = stp_gbl_obj.unConfigure(dut, target_attr=stp_gbl_obj.RootguardTimeout, cli_type=cli_type)
            else:
                result = stp_gbl_obj.unConfigure(dut, cli_type=cli_type)
        if result_val and not result.ok():
            st.log('test_step_failed: Enabling of STP {}'.format(result.data))
            return False
        return True
    elif cli_type == 'click':
        if vlan:
            command = "config spanning_tree vlan {} {}".format(mode, vlan)
        else:
            command = "config spanning_tree {} {}".format(mode, feature)
        st.config(dut, command, type=cli_type)
    elif cli_type == 'klish':
        if mode == 'disable':
            featureMap[feature] = ''
        if vlan:
            zero_or_more_space = get_random_space_string()
            command = "{} spanning-tree Vlan{}{}".format(no_form, zero_or_more_space, vlan)
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
    return True


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

    if cli_type in get_supported_ui_type_list():
        stp_gbl_obj = umf_stp.Stp()
        for each_key in kwargs.keys():
            if each_key == "forward_delay":
                setattr(stp_gbl_obj, 'GlobalForwardingDelay', int(kwargs[each_key]))
            elif each_key == "max_age":
                setattr(stp_gbl_obj, 'GlobalMaxAge', int(kwargs[each_key]))
            else:
                setattr(stp_gbl_obj, 'BridgePriority', int(kwargs[each_key]))
        result = stp_gbl_obj.configure(dut, cli_type=cli_type)
        if not result.ok():
            st.log('test_step_failed: Configuring global STP parameters {}'.format(result.data))
            return False
    elif cli_type == 'click':
        for each_key in kwargs.keys():
            command = "config spanning_tree {} {}".format(each_key, int(kwargs[each_key]))
            st.config(dut, command, type=cli_type)
    elif cli_type == 'klish':
        for each_key in kwargs.keys():
            if each_key == 'max_age':
                command = "{} spanning-tree max-age {}".format(no_form, int(kwargs[each_key]))
            elif each_key == 'forward_delay':
                command = "{} spanning-tree forward-time {}".format(no_form, int(kwargs[each_key]))
            else:
                command = "{} spanning-tree {} {}".format(no_form, each_key, int(kwargs[each_key]))
            st.config(dut, command, type=cli_type)
    else:
        st.error("Invalid CLI type - {}".format(cli_type))
        return False
    return True


def config_stp_vlan_parameters(dut, vlan, **kwargs):
    cli_type = st.get_ui_type(dut, **kwargs)
    """

    :param dut:
    :param vlan:
    :param kwargs:
    :return:
    """
    no_form = 'no' if kwargs.setdefault('no_form', False) else ''
    instance = kwargs.pop('instance', None)
    if 'cli_type' in kwargs:
        del kwargs['cli_type']
    del kwargs['no_form']
    click_2_klish = {'forward_delay': 'forward-time', 'hello': 'hello-time', 'max_age': 'max-age', 'max_hops': 'max-hops'}
    mode = kwargs.pop('mode', 'pvst')
    if mode == 'mstp':
        cli_type = 'klish' if cli_type == 'click' else cli_type
    if cli_type in get_supported_ui_type_list():
        stp_gbl_obj = umf_stp.Stp()
        res = True
        flag1, flag2 = False, False
        if mode == 'mstp':
            for each_key, value in kwargs.items():
                if each_key == "forward_delay":
                    flag1 = True
                    setattr(stp_gbl_obj, 'MstpForwardingDelay', int(value))
                elif each_key == "hello":
                    flag1 = True
                    setattr(stp_gbl_obj, 'MstpHelloTime', int(value))
                elif each_key == "max_age":
                    flag1 = True
                    setattr(stp_gbl_obj, 'MstpMaxAge', int(value))
                elif each_key == "priority":
                    flag2 = True
                    stp_mst_inst_obj = umf_stp.MstInstance(MstId=int(instance), Stp=stp_gbl_obj)
                    setattr(stp_mst_inst_obj, 'BridgePriority', int(value))
            if flag1 is True and flag2 is True:
                result = stp_gbl_obj.configure(dut, cli_type=cli_type)
                if not result.ok():
                    res = False
                result = stp_mst_inst_obj.configure(dut, cli_type=cli_type)
                if not result.ok():
                    res = False
            elif flag1 is True:
                result = stp_gbl_obj.configure(dut, cli_type=cli_type)
                if not result.ok():
                    res = False
            else:
                result = stp_mst_inst_obj.configure(dut, cli_type=cli_type)
                if not result.ok():
                    res = False
        elif CONFIGURED_STP_PROTOCOL[dut] == "pvst":
            stp_vlan_obj = umf_stp.Vlans(VlanId=int(vlan), Stp=stp_gbl_obj)
            for each_key, value in kwargs.items():
                if each_key == "forward_delay":
                    setattr(stp_vlan_obj, 'ForwardingDelay', int(value))
                elif each_key == "hello":
                    setattr(stp_vlan_obj, 'HelloTime', int(value))
                elif each_key == "max_age":
                    setattr(stp_vlan_obj, 'MaxAge', int(value))
                elif each_key == "priority":
                    setattr(stp_vlan_obj, 'BridgePriority', int(value))
            result = stp_vlan_obj.configure(dut, cli_type=cli_type)
            if not result.ok():
                res = False
        elif CONFIGURED_STP_PROTOCOL[dut] == "rpvst":
            stp_vlan_obj = umf_stp.Vlan(VlanId=int(vlan), Stp=stp_gbl_obj)
            for each_key, value in kwargs.items():
                if each_key == "forward_delay":
                    setattr(stp_vlan_obj, 'ForwardingDelay', int(value))
                elif each_key == "hello":
                    setattr(stp_vlan_obj, 'HelloTime', int(value))
                elif each_key == "max_age":
                    setattr(stp_vlan_obj, 'MaxAge', int(value))
                elif each_key == "priority":
                    setattr(stp_vlan_obj, 'BridgePriority', int(value))
            result = stp_vlan_obj.configure(dut, cli_type=cli_type)
            if not result.ok():
                res = False
        if not res:
            st.log('test_step_failed: Configuring STP vlan interface parameters {}'.format(result.data))
            return False
        return True
    elif cli_type == 'click':
        for each_key, value in kwargs.items():
            command = "config spanning_tree vlan {} {} {}".format(each_key, vlan, value)
            st.config(dut, command, type=cli_type)
    elif cli_type == 'klish':
        for each_key, value in kwargs.items():
            each_key1 = click_2_klish.get(each_key, each_key)
            if not each_key1:
                st.error("Provided Key not found")
                return False
            value = "" if no_form else value
            if mode == 'mstp':
                if each_key1 == 'priority':
                    command = ["{} spanning-tree mst {} {} {}".format(no_form, instance, each_key1, value)]
                else:
                    command = ["{} spanning-tree mst {} {}".format(no_form, each_key1, value)]
            else:
                command = "{} spanning-tree Vlan {} {} {}".format(no_form, vlan, each_key1, value)
            st.config(dut, command, type=cli_type)
    elif cli_type in ["rest-put", "rest-patch"]:
        for each_key, value in kwargs.items():
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
    return True


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
    st.log("kwargs : {}".format(kwargs))
    mode = kwargs.pop('mode', 'pvst')
    if mode == "mstp":
        inst_li = list(kwargs['instance']) if isinstance(kwargs['instance'], list) else [kwargs['instance']]
    dut_li = list(dut_list) if isinstance(dut_list, list) else [dut_list]
    vlan_li = list(kwargs['vlan']) if isinstance(kwargs['vlan'], list) else [kwargs['vlan']]
    priority_li = list(kwargs['priority']) if isinstance(kwargs['priority'], list) else [kwargs['priority']]
    if not len(dut_li) == len(vlan_li) == len(priority_li):
        return False
    params = list()
    for i, each in enumerate(dut_list):
        if mode == "mstp":
            params.append(ExecAllFunc(config_stp_vlan_parameters, each, vlan_li[i], instance=inst_li[i], priority=priority_li[i], mode=mode, cli_type=cli_type))
        else:
            params.append(ExecAllFunc(config_stp_vlan_parameters, each, vlan_li[i], priority=priority_li[i], cli_type=cli_type))
    [out, _] = exec_all(thread, params)
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
    st_mode = kwargs.get('st_mode', 'pvst')
    st_inst = kwargs.pop('st_inst', 0)
    if st_mode == "mstp":
        cli_type = 'klish' if cli_type == 'click' else cli_type
    if mode in ['cost', 'priority']:
        command = list()
        if cli_type in get_supported_ui_type_list():
            port_hash_list = segregate_intf_list_type(intf=iface, range_format=False)
            interface_list = port_hash_list['intf_list_all']
            for intf in interface_list:
                stp_gbl_obj = umf_stp.Stp()
                if st_mode == "mstp":
                    stp_mst_inst_obj = umf_stp.MstInstance(MstId=st_inst, Stp=stp_gbl_obj)
                    if mode == 'cost':
                        stp_mst_intf_obj = umf_stp.MstInstanceInterface(Name=intf, Cost=value, MstInstance=stp_mst_inst_obj)
                    else:
                        stp_mst_intf_obj = umf_stp.MstInstanceInterface(Name=intf, PortPriority=value, MstInstance=stp_mst_inst_obj)
                    result = stp_mst_intf_obj.configure(dut, cli_type=cli_type)
                elif CONFIGURED_STP_PROTOCOL[dut] == "pvst":
                    stp_vlan_obj = umf_stp.Vlans(VlanId=vlan, Stp=stp_gbl_obj)
                    if mode == 'cost':
                        stp_vlan_intf_obj = umf_stp.VlansInterface(Name=intf, Cost=value, Vlans=stp_vlan_obj)
                    else:
                        stp_vlan_intf_obj = umf_stp.VlansInterface(Name=intf, PortPriority=value, Vlans=stp_vlan_obj)
                    result = stp_vlan_intf_obj.configure(dut, cli_type=cli_type)
                elif CONFIGURED_STP_PROTOCOL[dut] == "rpvst":
                    stp_vlan_obj = umf_stp.Vlan(VlanId=vlan, Stp=stp_gbl_obj)
                    if mode == 'cost':
                        stp_vlan_intf_obj = umf_stp.VlanInterface(Name=intf, Cost=value, Vlan=stp_vlan_obj)
                    else:
                        stp_vlan_intf_obj = umf_stp.VlanInterface(Name=intf, PortPriority=value, Vlan=stp_vlan_obj)
                    result = stp_vlan_intf_obj.configure(dut, cli_type=cli_type)
                if not result.ok():
                    st.log('test_step_failed: Configuring of vlan interface/mstp instance parameters {}'.format(result.data))
                    return False
            return True
        elif cli_type == 'click':
            port_hash_list = segregate_intf_list_type(intf=iface, range_format=False)
            interface_list = port_hash_list['intf_list_all']
            for intf in interface_list:
                command.append("config spanning_tree vlan interface {} {} {} {} ".format(mode, vlan, intf, value))
            st.config(dut, command, type=cli_type)
        elif cli_type == 'klish':
            mode = "port-priority" if mode == "priority" else mode
            port_hash_list = segregate_intf_list_type(intf=iface, range_format=False)
            interface_list = port_hash_list['intf_list_all']
            for intf in interface_list:
                if not is_a_single_intf(intf):
                    command.append("interface range {}".format(intf))
                else:
                    intf = get_interface_number_from_name(intf)
                    command.append("interface {} {}".format(intf['type'], intf['number']))
                value = '' if no_form else value
                if st_mode == "mstp":
                    command.append('{} spanning-tree mst {} {} {}'.format(no_form, st_inst, mode, value))
                else:
                    command.append('{} spanning-tree Vlan {} {} {}'.format(no_form, vlan, mode, value))
                command.append("exit")
            st.config(dut, command, type=cli_type)
        elif cli_type in ["rest-put", "rest-patch"]:
            cli_type = "rest-patch" if cli_type == "rest-put" else cli_type
            rest_urls = st.get_datastore(dut, "rest_urls")
            url = rest_urls['{}_vlan_interface_parameters_config'.format(CONFIGURED_STP_PROTOCOL[dut])]
            if CONFIGURED_STP_PROTOCOL[dut] == "pvst":
                node = "openconfig-spanning-tree-ext:vlans"
                payload = json.loads("""{"openconfig-spanning-tree-ext:vlans": [
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

            port_hash_list = segregate_intf_list_type(intf=iface, range_format=False)
            interface_list = port_hash_list['intf_list_all']
            for intf in interface_list:
                payload[node][0]["vlan-id"] = vlan
                payload[node][0]["interfaces"]["interface"][0]["name"] = intf
                payload[node][0]["interfaces"]["interface"][0]["config"]["name"] = intf
                if mode == "cost":
                    payload[node][0]["interfaces"]["interface"][0]["config"]["cost"] = value
                else:
                    payload[node][0]["interfaces"]["interface"][0]["config"]["port-priority"] = value
                if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=payload):
                    return False
        else:
            st.log("Invalid cli_type provided: {}".format(cli_type))
            return False
    else:
        st.log("Invalid mode = {}".format(mode))
        return False


def config_stp_enable_interface(dut, iface, mode="enable", cli_type="", **kwargs):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """

    :param dut:
    :param iface:
    :param mode:
    :return:
    """
    command = list()
    port_hash_list = segregate_intf_list_type(intf=iface, range_format=False)
    interface_list = port_hash_list['intf_list_all']
    if cli_type in get_supported_ui_type_list():
        mode_dict = {'enable': True, 'disable': False}
        for intf in interface_list:
            stp_intf_obj = umf_stp.StpInterface(Name=intf, SpanningTreeEnable=mode_dict[mode])
            result = stp_intf_obj.configure(dut, cli_type=cli_type)
            if not result.ok():
                st.log('test_step_failed: Enabling of STP on interface {}'.format(result.data))
                return False
        return True
    elif cli_type == "click":
        for intf in interface_list:
            command.append("config spanning_tree interface {} {}".format(mode, intf))
        st.config(dut, command, type=cli_type)
    elif cli_type == "klish":
        for intf in interface_list:
            if not is_a_single_intf(intf):
                command.append("interface range {}".format(intf))
            else:
                intf = get_interface_number_from_name(intf)
                command.append("interface {} {}".format(intf['type'], intf['number']))
            if mode == "enable":
                command.append("spanning-tree {}".format(mode))
            else:
                command.append("no spanning-tree enable")
            command.append("exit")
        st.config(dut, command, type=cli_type)
    elif cli_type in ["rest-put", "rest-patch"]:
        cli_type = "rest-patch" if cli_type == "rest-put" else cli_type
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
        for intf in interface_list:
            rest_urls = st.get_datastore(dut, "rest_urls")
            url = rest_urls['stp_interface_config_enable'].format(intf)
            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=payload):
                return False
    else:
        st.log("Invalid cli_type provided: {}".format(cli_type))
        return False
    return True


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
                     "uplink_fast": "uplinkfast", "priority": "port-priority"}
    command = list()
    mode = kwargs.pop('mode', None)
    if cli_type in get_supported_ui_type_list():
        port_hash_list = segregate_intf_list_type(intf=iface, range_format=False)
        interface_list = port_hash_list['intf_list_all']
        mode_dict = {'enable': True, 'disable': False}
        guard_dict = {'root_guard': 'ROOT', 'loop_guard': "LOOP"}
        ptype_dict = {'enable': 'EDGE_ENABLE', 'disable': 'EDGE_DISABLE'}
        for intf in interface_list:
            stp_gbl_obj = umf_stp.Stp()
            stp_intf_obj = umf_stp.StpInterface(Name=intf, Stp=stp_gbl_obj)
            for each_key in kwargs.keys():
                flag = True
                mode = 'disable' if kwargs[each_key] in ['disable', 'none'] else 'enable'
                if each_key == "bpdufilter":
                    setattr(stp_intf_obj, 'BpduFilter', mode_dict[mode])
                elif each_key == "bpdu_guard":
                    setattr(stp_intf_obj, 'BpduGuard', mode_dict[mode])
                elif each_key == "bpdu_guard_action":
                    setattr(stp_intf_obj, 'BpduGuardPortShutdown', mode_dict[mode])
                elif each_key == "enable":
                    setattr(stp_intf_obj, 'SpanningTreeEnable', mode_dict[mode])
                elif each_key == "portfast":
                    setattr(stp_intf_obj, 'Portfast', mode_dict[mode])
                elif each_key == "port-type":
                    setattr(stp_intf_obj, 'EdgePort', ptype_dict[mode])
                elif each_key == "uplink_fast":
                    setattr(stp_intf_obj, 'UplinkFast', mode_dict[mode])
                elif each_key == "cost":
                    if mode == 'enable':
                        setattr(stp_intf_obj, 'Cost', int(kwargs[each_key]))
                elif each_key == "link-type":
                    if mode == 'enable':
                        setattr(stp_intf_obj, 'LinkType', kwargs[each_key])
                elif each_key == "priority":
                    if mode == 'enable':
                        setattr(stp_intf_obj, 'PortPriority', kwargs[each_key])
                elif each_key in ["root_guard", "loop_guard"]:
                    if mode == 'enable':
                        setattr(stp_intf_obj, 'Guard', guard_dict[each_key])
                    elif mode == "disable":
                        flag = False
            if flag:
                result = stp_intf_obj.configure(dut, cli_type=cli_type)
            else:
                result = stp_intf_obj.unConfigure(dut, target_attr=stp_intf_obj.Guard, cli_type=cli_type)
            if not result.ok():
                st.log('test_step_failed: Configuring STP interface parameters {}'.format(result.data))
                return False
        return True
    elif cli_type == 'click':
        port_hash_list = segregate_intf_list_type(intf=iface, range_format=False)
        interface_list = port_hash_list['intf_list_all']
        for intf in interface_list:
            for each_key in kwargs.keys():
                if each_key == "priority" or each_key == "cost":
                    command.append("config spanning_tree interface {} {} {}".format(each_key, intf, kwargs[each_key]))
                elif each_key == "bpdu_guard_action":
                    command.append("config spanning_tree interface bpdu_guard enable {} {}".format(intf, kwargs[each_key]))
                else:
                    command.append("config spanning_tree interface {} {} {}".format(each_key, kwargs[each_key], intf))
            if not st.config(dut, command):
                return False
        return True
    elif cli_type == 'klish':
        port_hash_list = segregate_intf_list_type(intf=iface, range_format=False)
        interface_list = port_hash_list['intf_list_all']
        for intf in interface_list:
            if not is_a_single_intf(intf):
                command.append("interface range {}".format(intf))
            else:
                intf = get_interface_number_from_name(intf)
                command.append("interface {} {}".format(intf['type'], intf['number']))
            for each_key in kwargs.keys():
                no_form = 'no' if kwargs[each_key] == 'disable' else ''
                if each_key == "priority" or each_key == "cost":
                    value = kwargs[each_key]
                    each_key = "port-priority" if each_key == "priority" else each_key
                    if value == "disable":
                        command.append('{} spanning-tree {}'.format(no_form, each_key))
                    else:
                        command.append('spanning-tree {} {}'.format(each_key, value))
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
        port_hash_list = segregate_intf_list_type(intf=iface, range_format=False)
        interface_list = port_hash_list['intf_list_all']
        for intf in interface_list:
            for each_key in kwargs.keys():
                flag = True
                mode = 'disable' if kwargs[each_key] == 'disable' else 'enable'
                if each_key == "bpdufilter":
                    url = rest_urls['stp_interface_config_bpdufilter'].format(intf)
                    if mode == "enable":
                        payload = json.loads("""{"openconfig-spanning-tree:bpdu-filter": true}""")
                    elif mode == "disable":
                        payload = json.loads("""{"openconfig-spanning-tree:bpdu-filter": false}""")
                elif each_key == "root_guard":
                    url = rest_urls['stp_interface_config_rootguard'].format(intf)
                    if mode == "enable":
                        payload = json.loads("""{"openconfig-spanning-tree:guard": "ROOT"}""")
                    elif mode == "disable":
                        flag = False
                        if not delete_rest(dut, rest_url=url):
                            return False
                elif each_key == "loop_guard":
                    url = rest_urls['stp_interface_config_rootguard'].format(intf)
                    if mode == "enable":
                        payload = json.loads("""{"openconfig-spanning-tree:guard": "LOOP"}""")
                    elif mode == "disable":
                        flag = False
                        if not delete_rest(dut, rest_url=url):
                            return False
                elif each_key == "bpdu_guard":
                    url = rest_urls['stp_interface_config_bpduguard'].format(intf)
                    if mode == "enable":
                        payload = json.loads("""{"openconfig-spanning-tree:bpdu-guard": true}""")
                    elif mode == "disable":
                        payload = json.loads("""{"openconfig-spanning-tree:bpdu-guard": false}""")
                elif each_key == "bpdu_guard_action":
                    url = rest_urls['stp_interface_config_bpduguard_port_shutdown'].format(intf)
                    if mode == "enable":
                        payload = json.loads("""{"openconfig-spanning-tree-ext:bpdu-guard-port-shutdown": true}""")
                    elif mode == "disable":
                        payload = json.loads("""{"openconfig-spanning-tree-ext:bpdu-guard-port-shutdown": false}""")
                elif each_key == "cost":
                    url = rest_urls['stp_interface_config_cost'].format(intf)
                    if mode == "enable":
                        payload = json.loads("""{"openconfig-spanning-tree-ext:cost": 0}""")
                        payload["openconfig-spanning-tree-ext:cost"] = kwargs[each_key]
                elif each_key == "enable":
                    url = rest_urls['stp_interface_config_enable'].format(intf)
                    if mode == "enable":
                        payload = json.loads("""{"openconfig-spanning-tree-ext:spanning-tree-enable": true}""")
                    elif mode == "disable":
                        payload = json.loads("""{"openconfig-spanning-tree-ext:spanning-tree-enable": false}""")
                elif each_key == "link-type":
                    url = rest_urls['stp_interface_config_linktype'].format(intf)
                    if mode == "enable":
                        payload = json.loads("""{"openconfig-spanning-tree:link-type": "P2P"}""")
                        payload["openconfig-spanning-tree:link-type"] = kwargs[each_key]
                elif each_key == "portfast":
                    url = rest_urls['stp_interface_config_portfast'].format(intf)
                    if mode == "enable":
                        payload = json.loads("""{"openconfig-spanning-tree-ext:portfast": true}""")
                    elif mode == "disable":
                        payload = json.loads("""{"openconfig-spanning-tree-ext:portfast": false}""")
                elif each_key == "priority":
                    url = rest_urls['stp_interface_config_port_priority'].format(intf)
                    if mode == "enable":
                        payload = json.loads("""{"openconfig-spanning-tree-ext:port-priority": 0}""")
                        payload["openconfig-spanning-tree-ext:port-priority"] = kwargs[each_key]
                elif each_key == "port-type":
                    url = rest_urls['stp_interface_config_edgeport'].format(intf)
                    if mode == "enable":
                        payload = json.loads(
                            """{"openconfig-spanning-tree:edge-port": "openconfig-spanning-tree-types:EDGE_ENABLE"}""")
                    elif mode == "disable":
                        payload = json.loads(
                            """{"openconfig-spanning-tree:edge-port": "openconfig-spanning-tree-types:EDGE_DISABLE}""")
                elif each_key == "uplink_fast":
                    url = rest_urls['stp_interface_config_uplinkfast'].format(intf)
                    if mode == "enable":
                        payload = json.loads("""{"openconfig-spanning-tree-ext:uplink-fast": true}""")
                    elif mode == "disable":
                        payload = json.loads("""{"openconfig-spanning-tree-ext:uplink-fast": false}""")
                if flag:
                    if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=payload):
                        return False
        return True
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
    return config_stp_enable_interface(dut, iface, mode=mode, cli_type=cli_type)


def show_stp(dut, **kwargs):
    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    skiperr = kwargs.pop('skip_error', False)
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
    return st.show(dut, command, type=cli_type, skip_error_check=skiperr)


def show_stp_vlan(dut, vlan, cli_type="", **kwargs):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    skip_error_check = kwargs.get("skip_error_check", False)
    """

    :param dut:
    :param vlan:
    :param cli_type:
    :return:
    """
    output = ""
    st.log("show spanning_tree vlan <id>")
    if cli_type == "click":
        command = SHOW_STP_VLAN.format(vlan)
        output = st.show(dut, command, type=cli_type)
    elif cli_type == "klish":
        command = SHOW_STP_VLAN_KLISH.format(vlan)
        try:
            output = st.show(dut, command, skip_error_check=skip_error_check, type=cli_type)
        except Exception:
            return False
    elif cli_type in ["rest-put", "rest-patch"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        stp_output = []
        url = rest_urls['{}_vlan_show'.format(CONFIGURED_STP_PROTOCOL[dut])].format(vlan)
        if CONFIGURED_STP_PROTOCOL[dut] == "pvst":
            payload = get_rest(dut, rest_url=url)["output"]["openconfig-spanning-tree-ext:vlans"][0]
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
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    """

    :param dut:
    :param vlan:
    :param iface:
    :return:
    """
    if cli_type == "click":
        command = "show spanning_tree vlan interface {} {}".format(vlan, iface)
    elif cli_type == "klish":
        command = "show spanning-tree Vlan {} interface {}".format(vlan, iface)
    else:
        st.log("Unsupported CLI type {}".format(cli_type))
        return list()
    return st.show(dut, command, type=cli_type)


def show_stp_stats(dut, cli_type=""):
    """

    :param dut:
    :return:
    """
    # cli_type = st.get_ui_type(dut, cli_type=cli_type)
    command = "show spanning_tree statistics"
    return st.show(dut, command)


def show_stp_stats_vlan(dut, vlan, cli_type=""):
    """

    :param dut:
    :param vlan:
    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
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
            payload = get_rest(dut, rest_url=url)["output"]["openconfig-spanning-tree-ext:vlans"][0]
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
    stp_output = show_stp_vlan(dut, vlanid, cli_type=cli_type)
    if len(stp_output) > 0:
        root_bridge = stp_output[0]["rt_id"]
        dut_bridge_id = stp_output[0]["br_id"]
        return (root_bridge == dut_bridge_id) and stp_output[0]["rt_port"] == "Root"
    else:
        return False


def get_stp_bridge_param(dut, vlanid, bridge_param, cli_type="", **kwargs):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
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
                             'rt_fwddly', 'oper_hello_time', 'oper_fwd_delay', 'oper_max_age', 'mst_instance', 'vlan_map', 'bridge_address', 'root_address', 'regional_root_address',
                             'max_hops', 'internal_cost', 'rem_hops', 'path_cost']

    mstp_mode = kwargs.get("mstp_mode", None)
    cli_type = "klish" if (mstp_mode and cli_type == "click") else cli_type

    if bridge_param not in stp_bridge_param_list:
        st.error("Please provide the valid stp bridge parameter")
        return
    if cli_type == "click":
        stp_output = show_stp_vlan(dut, vlanid, cli_type=cli_type)
    elif cli_type == "klish":
        if mstp_mode:
            cmd = "show spanning-tree mst"
            stp_output = st.show(dut, cmd, type=cli_type)
            stp_output = cutils.filter_and_select(stp_output, None, {'mst_instance': vlanid})
        else:
            stp_output = show_stp_vlan(dut, vlanid, cli_type=cli_type)
    elif cli_type in ["rest-put", "rest-patch"]:
        stp_output = show_stp_vlan(dut, vlanid, cli_type=cli_type)
    else:
        st.log("Invalid cli_type provided: {}".format(cli_type))
        return False
    return stp_output[0][bridge_param]


def get_stp_port_param(dut, vlanid, ifname, ifparam, cli_type="", **kwargs):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
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
                           'port_desigbridgeid',
                           'port_edgeport']

    mstp_mode = kwargs.get("mstp_mode", None)
    cli_type = "klish" if (mstp_mode and cli_type == "click") else cli_type

    if ifparam not in stp_port_param_list:
        st.error("Please provide the valid stp port parameter")
        return
    if cli_type == "click":
        cmd = SHOW_STP_VLAN.format(vlanid) + " interface {}".format(ifname)
        stp_output = st.show(dut, cmd, type=cli_type)
    elif cli_type == "klish":
        if mstp_mode:
            cmd = "show spanning-tree mst" + " interface {}".format(ifname)
            stp_output = st.show(dut, cmd, type=cli_type)
            stp_output = cutils.filter_and_select(stp_output, None, {'instance': vlanid})
            if len(stp_output):
                stp_output[0]["port_edgeport"] = "Y" if stp_output[0]["port_edgeport"] == "True" else "N"
        else:
            cmd = SHOW_STP_VLAN_KLISH.format(vlanid) + " interface {}".format(ifname)
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
        return [dut for dut in dut_list if dut == root_bridge][0]
    else:
        return None


def get_duts_mac_address(duts, cli_type=""):
    """
        This is used to get the Duts and its mac addresses mapping
        :param duts: List of DUTs
        :return : Duts and its mac addresses mapping

    """
    # cli_type = st.get_ui_type(duts[0], cli_type=cli_type)
    duts_mac_addresses = {}
    for dut in duts:
        if st.is_vsonic(dut):
            mac = basic.get_ifconfig_ether(dut)
            duts_mac_addresses[dut] = mac
            continue
        duts_mac_addresses[dut] = mac_api.get_sbin_intf_mac(dut, "eth0").replace(":", "")
    st.log("DUT MAC ADDRESS -- {}".format(duts_mac_addresses))
    return duts_mac_addresses


def _get_duts_list_in_order(vars, cli_type=""):
    cli_type = st.get_ui_type(vars, cli_type=cli_type)
    """
        This is used to get the DUTs and their mac addresses in ascending order of Mac addresses
        :param duts: List of DUTs
        :return : Duts and its mac addresses mapping

    """
    duts_mac_addresses = get_duts_mac_address(vars["dut_list"], cli_type=cli_type)

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


def poll_for_stp_status(dut, vlanid, interface, status, iteration=20, delay=1, cli_type="", **kwargs):
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
        if get_stp_port_param(dut, vlanid, interface, "port_state", cli_type=cli_type, **kwargs) == status:
            st.log("Port status is changed to  {} after {} sec".format(status, i))
            return True
        if i > iteration:
            st.log("Max iterations {} reached".format(i))
            return False
        i += 1
        st.wait(delay)


def get_root_guard_details(dut, vlan=None, ifname=None, rg_param="rg_timeout", cli_type=""):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
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
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
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
    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    cli_type = 'klish' if cli_type in ["rest-put", "rest-patch"] else cli_type
    if cli_type == "click":
        cmd = "sonic-clear spanning_tree statistics"
    elif cli_type == "klish":
        cmd = "clear spanning-tree counters"
    if 'vlan' in kwargs and 'interface' not in kwargs:
        zero_or_more_space = get_random_space_string()
        cmd += ' Vlan{}{}'.format(zero_or_more_space, kwargs['vlan'])
    if 'vlan' in kwargs and 'interface' in kwargs:
        cmd += ' vlan-interface {} {}'.format(kwargs['vlan'], kwargs['interface'])
    if 'vlan' not in kwargs and 'interface' in kwargs:
        kwargs['interface'] = add_zero_or_more_spaces_to_intf(kwargs['interface'])
        cmd += ' interface {}'.format(kwargs['interface'])
    st.config(dut, cmd, type=cli_type)


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


def get_mstp_stats(dut, instance, interface, param, cli_type=""):
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
    cli_type = 'klish' if cli_type == 'click' else cli_type
    output = show_mstp(dut, mstp_instance=instance, mstp_detail=True, cli_type=cli_type)
    value_list = [row[param] for row in output if int(row['instance']) == instance and row['interface'] == interface]
    st.banner(value_list)
    return None if len(output) == 0 else int(value_list[0])


def verify_stp_ports_by_state(dut, vlan, port_state, port_list, cli_type="", **kwargs):
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
    depth = kwargs.get("depth", 3)
    filter_type = kwargs.get("filter_type", "NON_CONFIG")
    port_li = list(port_list) if isinstance(port_list, list) else [port_list]
    result = True
    if cli_type in get_supported_ui_type_list():
        stp_gbl_obj = umf_stp.Stp()
        if CONFIGURED_STP_PROTOCOL[dut] == "pvst":
            stp_vlan_obj = umf_stp.Vlans(VlanId=int(vlan), Stp=stp_gbl_obj)
        else:
            stp_vlan_obj = umf_stp.Vlan(VlanId=int(vlan), Stp=stp_gbl_obj)
        for each_port in port_li:
            if CONFIGURED_STP_PROTOCOL[dut] == "pvst":
                stp_vlan_intf_obj = umf_stp.VlansInterface(Name=each_port, PortState=port_state, Vlans=stp_vlan_obj)
            else:
                stp_vlan_intf_obj = umf_stp.VlanInterface(Name=each_port, PortState=port_state, Vlan=stp_vlan_obj)
            query_params_obj = cutils.get_query_params(yang_data_type=filter_type, depth=depth, cli_type=cli_type)
            rv = stp_vlan_intf_obj.verify(dut, query_param=query_params_obj, match_subset=True)
            if not rv.ok():
                st.log('test_step_failed: {} is not is {} state'.format(each_port, port_state))
                result = False
            else:
                st.log("{} is {} state ".format(each_port, port_state))
    else:
        stp_output = show_stp_vlan(dut, vlan, cli_type=cli_type)
        ports_list = [row["port_name"] for row in stp_output if row["port_state"] == port_state and int(row["vid"]) == vlan]
        for each_port in port_li:
            if each_port not in ports_list:
                st.log("{} is not {} state ".format(each_port, port_state))
                result = False
            else:
                st.log("{} is {} state ".format(each_port, port_state))
    return result


def get_stp_port_list(dut, vlan, exclude_port=[], **kwargs):

    cli_type = st.get_ui_type(dut, **kwargs)
    """
     API will return all ports of VLAN instance.
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param vlan:
    :param exclude_port:
    :param cli_type:
    :return:
    """
    mstp_instance = kwargs.get('mstp_instance', 0)
    ex_port_li = list(exclude_port) if isinstance(exclude_port, list) else [exclude_port]
    if mstp_instance:
        stp_output = show_mstp(dut, mstp_instance=mstp_instance, cli_type=cli_type)
        ports_list = [row["interface"] for row in stp_output]
    else:
        stp_output = show_stp_vlan(dut, vlan, cli_type=cli_type)
        ports_list = [row["port_name"] for row in stp_output]
    for each_int in ex_port_li:
        if each_int in ports_list:
            ports_list.remove(each_int)
            st.log("{} is excluded".format(each_int))
    return ports_list


def get_stp_root_port(dut, vlan, cli_type="", **kwargs):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """
    API will return Root/Forwarding port of the device in the VLAN.
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param vlan:
    :param cli_type:
    :return:
    """
    mstp_mode = kwargs.get("mstp_mode", False)
    mstp_inst = kwargs.get("mstp_inst", False)

    if mstp_mode:
        cli_type = 'klish' if cli_type == 'click' else cli_type
        out = show_mstp(dut, mstp_instance=mstp_inst, cli_type=cli_type)
    else:
        out = show_stp_vlan(dut, vlan, cli_type=cli_type)

    if not out:
        st.error("No Root/Forwarding port found")
        return False

    if mstp_mode:
        if out[0]['root_port'] == "Root":
            st.error("Given device is ROOT Bridge.")
            return False
        else:
            return out[0]['root_port']
    else:
        if out[0]['rt_port'] == "Root":
            st.error("Given device is ROOT Bridge.")
            return False
        else:
            return out[0]['rt_port']


def get_stp_next_root_port(dut, vlan, cli_type="", **kwargs):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """
    API will return Next possible Root/Forwarding port of the device in the VLAN.
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param vlan:
    :param cli_type:
    :return:
    """
    mstp_mode = kwargs.get("mstp_mode", False)
    mstp_inst = kwargs.get("mstp_inst", False)
    partner = kwargs.get("partner", None)
    next_root_port = None
    sort_list = lambda list1, list2: [x for _, x in sorted(zip(list2, list1))]
    if mstp_mode:
        cli_type = 'klish' if cli_type == 'click' else cli_type
        out = show_mstp(dut, mstp_instance=mstp_inst, cli_type=cli_type)
    else:
        out = show_stp_vlan(dut, vlan, cli_type=cli_type)
    if not out:
        st.error("No Initial Root/Forwarding port found")
        return next_root_port

    if mstp_mode:
        if out[0]['root_port'] == "Root":
            st.error("Given device is ROOT Bridge.")
            return next_root_port
    else:
        if out[0]['rt_port'] == "Root":
            st.error("Given device is ROOT Bridge.")
            return next_root_port

    partner_ports = st.get_dut_links(dut)
    if mstp_mode:
        root_port = out[0]['root_port']
        tempVar = cutils.filter_and_select(out, ['cost'], {'interface': root_port})
    else:
        root_port = out[0]['rt_port']
        tempVar = cutils.filter_and_select(out, ['port_pathcost'], {'port_name': root_port})
    if len(tempVar) != 0:
        if mstp_mode:
            root_cost = int(tempVar[0]['cost'])
        else:
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
    for lag_intf in portchannel.get_portchannel_list(partner):
        if cli_type == "click":
            pc_list.append(lag_intf["teamdev"])
        elif cli_type in ["klish", "rest-put", "rest-patch", "rest", "gnmi"]:
            pc_list.append(lag_intf["name"])
    if mstp_mode:
        for each in out:
            port = each['interface']
            if "Eth" in port and port in dut_partner_ports_map:
                port = dut_partner_ports_map[each['interface']]
                ifindex = int(re.findall(r'\d+', port)[0])
                cut_data[port] = [ifindex, each['state'], int(each['cost'])]
            elif port in pc_list:
                ifindex = int(re.findall(r'\d+', port)[0])
                cut_data[port] = [ifindex, each['state'], int(each['cost'])]
            else:
                pass
    else:
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
        for i, response in enumerate(out):
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


def verify_root_bridge_interface_state(dut, vlan, interface_list, cli_type="", **kwargs):
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
    mstp_instance = kwargs.get('mstp_instance', False)
    fail_states = ["BLOCKING", "DISABLED", "DISCARDING"]
    pass_states = ["FORWARDING"]
    forwarding_counter = 0
    filter_type = kwargs.get("filter_type", "ALL")
    result = True
    if cli_type in get_supported_ui_type_list():
        stp_gbl_obj = umf_stp.Stp()
        if mstp_instance:
            stp_vlan_obj = umf_stp.MstInstance(MstId=int(mstp_instance), Stp=stp_gbl_obj)
        elif CONFIGURED_STP_PROTOCOL[dut] == "pvst":
            stp_vlan_obj = umf_stp.Vlans(VlanId=int(vlan), Stp=stp_gbl_obj)
        else:
            stp_vlan_obj = umf_stp.Vlan(VlanId=int(vlan), Stp=stp_gbl_obj)
        query_params_obj = cutils.get_query_params(yang_data_type=filter_type, cli_type=cli_type)
        rv = stp_vlan_obj.get_payload(dut, query_param=query_params_obj, cli_type=cli_type)
        if rv.ok():
            stp_data = rv.payload
            if CONFIGURED_STP_PROTOCOL[dut] == "mstp":
                if stp_data.get("openconfig-spanning-tree:mst-instance"):
                    stp_vlan_data = stp_data.get("openconfig-spanning-tree:mst-instance")[0]['interfaces']['interface']
                else:
                    result = False
            elif CONFIGURED_STP_PROTOCOL[dut] == "pvst":
                if stp_data.get("openconfig-spanning-tree-ext:vlans"):
                    stp_vlan_data = stp_data.get("openconfig-spanning-tree-ext:vlans")[0]['interfaces']['interface']
                else:
                    result = False
            elif CONFIGURED_STP_PROTOCOL[dut] == "rpvst":
                if stp_data.get("openconfig-spanning-tree:vlan"):
                    stp_vlan_data = stp_data.get("openconfig-spanning-tree:vlan")[0]['interfaces']['interface']
                else:
                    result = False

            intf_name_list = []
            port_state_list = []
            for data in stp_vlan_data:
                intf_name_list.append(data["name"])
                port_state_list.append(data["state"]["port-state"].strip("openconfig-spanning-tree-types:").strip("openconfig-spanning-tree-ext:"))

            for intf_name, port_state in zip(intf_name_list, port_state_list):
                st.log("Intf name : {}, Port state : {}".format(intf_name, port_state))
                if intf_name not in interface_list:
                    st.log("Interface {} not found in expected list ...".format(intf_name))
                if port_state in fail_states:
                    st.log("Observed that interface {} state is {} for root bridge".format(intf_name, fail_states))
                if port_state in pass_states:
                    forwarding_counter += 1
            if forwarding_counter != len(interface_list):
                result = False
        else:
            st.log("test_step_failed: No STP data found for {} and {} instance".format(dut, mstp_instance))
            result = False
    else:
        if mstp_instance:
            output = show_mstp(dut, mstp_instance=mstp_instance, cli_type=cli_type)
            if output:
                for data in output:
                    if data["interface"] not in interface_list:
                        st.log("Interface {} not found in expected list ...".format(data["interface"]))
                    if data["state"] in fail_states:
                        st.log("Observed that interface {} state is {} for root bridge".format(data["interface"], fail_states))
                    if data["state"] in pass_states:
                        forwarding_counter += 1
                if forwarding_counter != len(interface_list):
                    result = False
            else:
                st.log("No STP data found for {} and {} instance".format(dut, mstp_instance))
                result = False
        else:
            output = show_stp_vlan(dut, vlan, cli_type=cli_type)
            if output:
                for data in output:
                    if data["port_name"] not in interface_list:
                        st.log("Interface {} not found in expected list ...".format(data["port_name"]))
                    if data["port_state"] in fail_states:
                        st.log("Observed that interface {} state is {} for root bridge".format(data["port_name"], fail_states))
                    if data["port_state"] in pass_states:
                        forwarding_counter += 1
                if forwarding_counter != len(interface_list):
                    result = False
            else:
                st.log("No STP data found for {} and {} instance".format(dut, vlan))
                result = False
    return result


def poll_root_bridge_interfaces(dut_vlan_list, interfaces_list, iteration=30, delay=1, cli_type="", **kwargs):
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
    mode = kwargs.get('mode', None)
    if dut_vlan_list and interfaces_list:
        no_of_duts = len(dut_vlan_list)
        check = 0
        for dut, vlan in dut_vlan_list.items():
            i = 1
            while True:
                if mode == "mstp":
                    if verify_root_bridge_interface_state(dut, vlan, interfaces_list[dut], cli_type=cli_type, mstp_instance=vlan):
                        st.log("Root bridge interface verification succeeded.")
                        check += 1
                        break
                    if i > iteration:
                        st.log("Max iteration limit reached.")
                        break
                    i += 1
                else:
                    if verify_root_bridge_interface_state(dut, vlan, interfaces_list[dut], cli_type=cli_type):
                        st.log("Root bridge interface verification succeeded.")
                        check += 1
                        break
                    if i > iteration:
                        st.log("Max iteration limit reached.")
                        break
                    i += 1
                st.wait(delay)
        if check != no_of_duts:
            st.log("Number of root DUTs check failed ...")
            return False
        return True
    else:
        st.log("Empty DUT VLAN LIST dut_vlan_list AND INTERFACE LIST interfaces_list")
        return False


def verify_root_bridge_on_stp_instances(dut_list, vlan, bridge_identifier, cli_type="", **kwargs):
    cli_type = st.get_ui_type(dut_list, cli_type=cli_type)
    """
    API to verify the bridge identifier with root bridge identifier
    :param dut_list:
    :param vlan:
    :param bridge_identifier:
    :return:
    """
    mstp_mode = kwargs.get('mstp_mode', None)
    dut_li = list(dut_list) if isinstance(dut_list, list) else [dut_list]
    filter_type = kwargs.get("filter_type", "ALL")
    result = True
    if cli_type in get_supported_ui_type_list():
        stp_gbl_obj = umf_stp.Stp()
        for each_dut in dut_li:
            if CONFIGURED_STP_PROTOCOL[each_dut] == "pvst":
                stp_vlan_obj = umf_stp.Vlans(VlanId=int(vlan), Stp=stp_gbl_obj)
            elif CONFIGURED_STP_PROTOCOL[each_dut] == "rpvst":
                stp_vlan_obj = umf_stp.Vlan(VlanId=int(vlan), Stp=stp_gbl_obj)
            else:
                stp_vlan_obj = umf_stp.MstInstance(MstId=int(vlan), Stp=stp_gbl_obj)
            query_params_obj = cutils.get_query_params(yang_data_type=filter_type, cli_type=cli_type)
            rv = stp_vlan_obj.get_payload(each_dut, query_param=query_params_obj, cli_type=cli_type)
            if rv.ok():
                stp_vlan_data = rv.payload
                identifier = ""
                if CONFIGURED_STP_PROTOCOL[each_dut] == "pvst":
                    if stp_vlan_data.get("openconfig-spanning-tree-ext:vlans"):
                        identifier = stp_vlan_data.get("openconfig-spanning-tree-ext:vlans")[0]['state']['designated-root-address']
                elif CONFIGURED_STP_PROTOCOL[each_dut] == "rpvst":
                    if stp_vlan_data.get("openconfig-spanning-tree:vlan"):
                        identifier = stp_vlan_data.get("openconfig-spanning-tree:vlan")[0]['state']['designated-root-address']
                else:
                    if stp_vlan_data.get("openconfig-spanning-tree:mst-instance"):
                        identifier = stp_vlan_data.get("openconfig-spanning-tree:mst-instance")[0]['state']['designated-root-address']
                st.log("Comparing ROOT bridge ID {} with Provided ID {}".format(identifier, bridge_identifier))
                if identifier != bridge_identifier:
                    st.log("test_step_failed: Mismatch in root and bridge identifiers")
                    result = False
                else:
                    st.log("Root Bridge Identifier {} is matched with provided identifier {}".format(identifier, bridge_identifier))
            else:
                result = False
    else:
        if mstp_mode:
            params = {"vlanid": vlan, "bridge_param": "root_address", "mstp_mode": mstp_mode, "cli_type": cli_type}
        else:
            params = {"vlanid": vlan, "bridge_param": "rt_id", "cli_type": cli_type}
        [out, _] = st.exec_each2(dut_li, get_stp_bridge_param, [params] * len(dut_li))
        for identifier in out:
            st.log("Comparing ROOT bridge ID {} with Provided ID {}".format(identifier, bridge_identifier))
            if identifier != bridge_identifier:
                st.log("Mismatch in root and bridge identifiers")
                result = False
            else:
                st.log("Root Bridge Identifier {} is matched with provided identifier {}".format(identifier, bridge_identifier))
    return result


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
    interface = kwargs.get("interface", None)
    no_form = kwargs.get("no_form", None)
    action = kwargs.get("action", "enable")
    if interface:
        port_hash_list = segregate_intf_list_type(intf=interface, range_format=False)
        interface_list = port_hash_list['intf_list_all']
    if cli_type in get_supported_ui_type_list():
        mode_dict = {'enable': True, 'disable': False}
        if interface:
            for intf in interface_list:
                if no_form:
                    stp_intf_obj = umf_stp.StpInterface(Name=intf)
                    result = stp_intf_obj.unConfigure(dut, target_attr=stp_intf_obj.BpduFilter, cli_type=cli_type)
                else:
                    stp_intf_obj = umf_stp.StpInterface(Name=intf, BpduFilter=mode_dict[action])
                    result = stp_intf_obj.configure(dut, cli_type=cli_type)
                if not result.ok():
                    st.log('test_step_failed: Configuring of BpduFilter on interface {}'.format(result.data))
                    return False
            return True
        else:
            if no_form:
                stp_glb_obj = umf_stp.Stp(BpduFilter=None)
                result = stp_glb_obj.unConfigure(dut, target_attr=stp_glb_obj.BpduFilter, cli_type=cli_type)
            else:
                stp_glb_obj = umf_stp.Stp(BpduFilter=mode_dict[action])
                result = stp_glb_obj.configure(dut, cli_type=cli_type)
            if not result.ok():
                st.log('test_step_failed: Configuring of BpduFilter on global {}'.format(result.data))
                return False
            return True
    elif cli_type in ["click", "klish"]:
        commands = list()
        if not interface:
            command = "spanning-tree edge-port bpdufilter default"
            if no_form:
                command = "no {}".format(command)
            commands.append(command)
        else:
            for intf in interface_list:
                if not is_a_single_intf(intf):
                    commands.append("interface range {}".format(intf))
                else:
                    intf = get_interface_number_from_name(intf)
                    commands.append("interface {} {}".format(intf['type'], intf['number']))
                command = "spanning-tree bpdufilter"
                if no_form:
                    command = "no {}".format(command)
                elif action:
                    command = "{} {}".format(command, action)
                else:
                    command = ""
                if command:
                    commands.append(command)
                commands.append('exit')
        if commands:
            st.config(dut, commands, type="klish")
            return True
        return False
    elif cli_type in ["rest-put", "rest-patch"]:
        cli_type = "rest-patch" if cli_type == "rest-put" else cli_type
        rest_urls = st.get_datastore(dut, "rest_urls")
        if not interface:
            url = rest_urls['stp_global_config_bpdufilter']
            if no_form:
                if delete_rest(dut, rest_url=url):
                    return True
                else:
                    return False
            elif action == "disable":
                payload = json.loads("""{"openconfig-spanning-tree:bpdu-filter": false}""")
                if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=payload):
                    return False
            else:
                payload = json.loads("""{"openconfig-spanning-tree:bpdu-filter": true}""")
                if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=payload):
                    return False
        else:
            for intf in interface_list:
                url = rest_urls['stp_interface_config_bpdufilter'].format(intf)
                if no_form:
                    if not delete_rest(dut, rest_url=url):
                        return False
                elif action == "disable":
                    payload = json.loads("""{"openconfig-spanning-tree:bpdu-filter": false}""")
                    if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=payload):
                        return False
                else:
                    payload = json.loads("""{"openconfig-spanning-tree:bpdu-filter": true}""")
                    if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=payload):
                        return False
        return True
    else:
        st.log("Invalid cli_type provided: {}".format(cli_type))
        return False


def config_stp_root_bridge_by_vlan(stp_data, cli_type=""):
    """
    :param stp_data: {dut1: {"vlan":10, "priority": "0"}, dut2: {"vlan":20, "priority": "0"}, dut3: {"vlan":30, "priority": "0"}}
    """
    params = list()
    for dut, data in stp_data.items():
        mode = data.get("mode", False)
        st.log('mode is {}'.format(mode))
        cli_type = st.get_ui_type(dut, cli_type=cli_type)
        cli_type = "rest-patch" if cli_type == "rest-put" else cli_type
        if mode:
            params.append(
                ExecAllFunc(config_stp_vlan_parameters, dut, data["vlan"], priority=data["priority"], cli_type=cli_type,
                            instance=data["instance"], mode=data["mode"]))
        else:
            params.append(ExecAllFunc(config_stp_vlan_parameters, dut, data["vlan"], priority=data["priority"], cli_type=cli_type))
    exec_all(True, params)


def config_port_type(dut, interface, stp_type="rpvst", port_type="edge", no_form=False, cli_type="", skip_error=False):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """
    API to config/unconfig the port type in RPVST
    :param dut:
    :param port_type:
    :param no_form:
    :return:
    """
    port_hash_list = segregate_intf_list_type(intf=interface, range_format=False)
    interface_list = port_hash_list['intf_list_all']
    if cli_type in get_supported_ui_type_list():
        for intf in interface_list:
            if not no_form:
                stp_intf_obj = umf_stp.StpInterface(Name=intf, EdgePort='EDGE_ENABLE')
                result = stp_intf_obj.configure(dut, cli_type=cli_type)
            else:
                stp_intf_obj = umf_stp.StpInterface(Name=intf)
                result = stp_intf_obj.unConfigure(dut, target_attr=stp_intf_obj.EdgePort, cli_type=cli_type)
            if not result.ok():
                st.log('test_step_failed: Enabling of EdgePort on interface {}'.format(result.data))
                return False
        return True
    elif cli_type in ["click", "klish"]:
        commands = list()
        command = "spanning-tree port type {}".format(port_type) if not no_form else "no spanning-tree port type"
        for intf in interface_list:
            if not is_a_single_intf(intf):
                commands.append("interface range {}".format(intf))
            else:
                intf = get_interface_number_from_name(intf)
                commands.append("interface {} {}".format(intf['type'], intf['number']))
            commands.append(command)
            commands.append('exit')
        out = st.config(dut, commands, type="klish", skip_error_check=skip_error)
        if "%Error" in out:
            return False
        return True
    elif cli_type in ["rest-put", "rest-patch"]:
        cli_type = "rest-patch" if cli_type == "rest-put" else cli_type
        rest_urls = st.get_datastore(dut, "rest_urls")
        for intf in interface_list:
            url = rest_urls['stp_interface_config_edgeport'].format(intf)
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
        command = "show spanning-tree Vlan {} interface {}".format(vlan, intf)
    # elif type == "vlan":
        # command = "show spanning-tree vlan {}".format(vlan)
    st.show(dut, command, type=cli_type, skip_tmpl=True)


def verify_stp_intf_status(dut, vlanid, interface, status, cli_type="", **kwargs):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """
    API to poll for stp stauts for an interface

    :param dut:
    :param vlanid:
    :param interface:
    :param status:
    :return:
    """
    depth = kwargs.get("depth", 3)
    filter_type = kwargs.get('filter_type', 'NON_CONFIG')
    result = True
    if cli_type in get_supported_ui_type_list():
        stp_gbl_obj = umf_stp.Stp()
        query_params_obj = cutils.get_query_params(yang_data_type=filter_type, depth=depth, cli_type=cli_type)
        if CONFIGURED_STP_PROTOCOL[dut] == "pvst":
            stp_vlan_obj = umf_stp.Vlans(VlanId=int(vlanid), Stp=stp_gbl_obj)
            stp_intf_obj = umf_stp.VlansInterface(Name=interface, PortState=status, Vlans=stp_vlan_obj)
        elif CONFIGURED_STP_PROTOCOL[dut] == "rpvst":
            stp_vlan_obj = umf_stp.Vlan(VlanId=int(vlanid), Stp=stp_gbl_obj)
            stp_intf_obj = umf_stp.VlanInterface(Name=interface, PortState=status, Vlan=stp_vlan_obj)
        else:
            stp_mst_inst_obj = umf_stp.MstInstance(MstId=int(vlanid), Stp=stp_gbl_obj)
            stp_intf_obj = umf_stp.MstInstanceInterface(Name=interface, PortState=status, MstInstance=stp_mst_inst_obj)
        rv = stp_intf_obj.verify(dut, query_param=query_params_obj, match_subset=True)
        if not rv.ok():
            st.log("test_step_failed: Port status is not changed to  {}".format(status))
            result = False
        else:
            st.log("Port status is changed to  {}".format(status))
    else:
        if get_stp_port_param(dut, vlanid, interface, "port_state", cli_type=cli_type, **kwargs) == status:
            st.log("Port status is changed to  {}".format(status))
        else:
            result = False
    return result


def get_loop_guard_details(dut, vlan=None, ifname=None, lg_param="lg_global_mode", cli_type=""):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    lg_value = ""
    cli_type = "klish" if cli_type in ["click", "rest-put", "rest-patch"] else cli_type
    cmd = "show spanning-tree inconsistentports"
    output = st.show(dut, cmd, type=cli_type)
    if len(output) >= 2:
        output = output[1:]

    if len(output) != 0:
        if vlan is None and ifname is None:
            lg_value = output[0][lg_param]
        else:
            for row in output:
                if row["rg_ifname"] == ifname and int(row["rg_vid"]) == vlan:
                    if lg_param == "rg_status":
                        lg_value = "" if row[lg_param].strip() != 'Loop Inconsistent' else row[lg_param].strip()
                    else:
                        lg_value = row[lg_param].strip()
    return lg_value


def check_lg_current_state(dut, vlan, ifname, cli_type=""):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    lg_status = get_loop_guard_details(dut, vlan, ifname, "rg_status", cli_type=cli_type)
    if cli_type in ["click"]:
        return lg_status == "Consistent state"
    else:
        return lg_status == ""


def config_loopguard_global(dut, mode=None, cli_type=""):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    if cli_type in get_supported_ui_type_list():
        mode_dict = {'enable': True, 'disable': False}
        stp_obj = umf_stp.Stp(LoopGuard=mode_dict[mode])
        result = stp_obj.configure(dut, cli_type=cli_type)
        if not result.ok():
            st.log('test_step_failed: Enabling of LoopGuard {}'.format(result.data))
            return False
        return True
    elif cli_type == 'klish':
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


def config_mstp(dut, **kwargs):
    """This api is used for the mstp config parameters in mst config mode
       region name,revision number,instance to vlan mapping,activate and abort
       author : anil.kumar@broadcom.com
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = 'klish' if cli_type == 'click' else cli_type
    config = kwargs.get('config', 'yes')
    mstp_cleanup = kwargs.get('mstp_cleanup', False)
    if cli_type in get_supported_ui_type_list():
        stp_glb_obj = umf_stp.Stp()
        if not mstp_cleanup:
            if 'region' in kwargs:
                if config == 'yes':
                    kwargs['region'] = '' if kwargs['region'] == "\"\"" else kwargs['region']
                    setattr(stp_glb_obj, 'Name', kwargs['region'])
                else:
                    result = stp_glb_obj.unConfigure(dut, target_attr=stp_glb_obj.Name, cli_type=cli_type)
            if 'revision' in kwargs:
                if config == 'yes':
                    setattr(stp_glb_obj, 'Revision', kwargs['revision'])
                else:
                    result = stp_glb_obj.unConfigure(dut, target_attr=stp_glb_obj.Revision, cli_type=cli_type)
            if 'instance' in kwargs:
                if config == 'yes':
                    if 'vlan' in kwargs:
                        stp_mst_inst_obj = umf_stp.MstInstance(MstId=kwargs['instance'], Vlan=[kwargs['vlan']])
                        stp_glb_obj.add_MstInstance(stp_mst_inst_obj)
                else:
                    if 'vlan' in kwargs:
                        stp_mst_inst_obj = umf_stp.MstInstance(MstId=kwargs['instance'], Vlan=[kwargs['vlan']], Stp=stp_glb_obj)
                        result = stp_mst_inst_obj.unConfigure(dut, target_attr=stp_mst_inst_obj.Vlan, cli_type=cli_type)
                    else:
                        stp_mst_inst_obj = umf_stp.MstInstance(MstId=kwargs['instance'], Stp=stp_glb_obj)
                        result = stp_mst_inst_obj.unConfigure(dut, cli_type=cli_type)
            result = stp_glb_obj.configure(dut, cli_type=cli_type)
        else:
            result = stp_glb_obj.unConfigure(dut, cli_type=cli_type)
        if not result.ok():
            st.log('test_step_failed: MSTP configuration {}'.format(result.data))
            return False
        return True
    elif cli_type == 'klish':
        cmd_list = list()
        if not mstp_cleanup:
            cmd_list.append('spanning-tree mst configuration')
            if 'region' in kwargs:
                if config == 'yes':
                    cmd_list.append('name {}'.format(kwargs['region']))
                else:
                    cmd_list.append('no name')
            if 'revision' in kwargs:
                if config == 'yes':
                    cmd_list.append('revision {}'.format(kwargs['revision']))
                else:
                    cmd_list.append('no revision')
            if 'instance' in kwargs:
                if config == 'yes':
                    if 'vlan' in kwargs:
                        zero_or_more_space = get_random_space_string()
                        cmd_list.append('instance {} Vlan{}{}'.format(kwargs['instance'], zero_or_more_space, kwargs['vlan']))
                else:
                    if 'vlan' in kwargs:
                        zero_or_more_space = get_random_space_string()
                        cmd_list.append('no instance {} Vlan{}{}'.format(kwargs['instance'], zero_or_more_space, kwargs['vlan']))
                    else:
                        cmd_list.append('no instance {}'.format(kwargs['instance']))
            if 'mode' in kwargs:  # mode values are activate or abort
                cmd_list.append(kwargs['mode'])
        else:
            cmd_list = 'no spanning-tree mst configuration'
        st.config(dut, cmd_list, type=cli_type)
    elif cli_type in ['rest-patch', 'rest-put']:
        # Code will be added later
        pass
    else:
        st.error("Unsupported CLI_TYPE: {}".format(cli_type))
        return False
    return True


def show_mstp_config(dut, **kwargs):
    '''

    :param dut:
    :return:
    author: anil.kumar@broadcom.com
    '''
    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    cli_type = 'klish' if cli_type == 'click' else cli_type
    if cli_type == 'klish':
        cmd = 'show spanning-tree mst configuration'
        return st.show(dut, cmd, type=cli_type)
    elif cli_type in ["rest-put", "rest-patch"]:
        # code will be added later
        pass
    else:
        st.error("Unsupported CLI_TYPE: {}".format(cli_type))
        return False


def show_mstp(dut, **kwargs):
    '''

    :param dut:
    :param kwargs:
    :return:

    '''
    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    cli_type = 'klish' if cli_type == 'click' else cli_type
    mstp_instance = kwargs.get('mstp_instance', False)
    mstp_detail = kwargs.get('mstp_detail', False)
    mstp_intf = kwargs.get('mstp_intf', False)
    skip_error_check = kwargs.get("skip_error_check", False)

    if cli_type == 'klish':
        if mstp_instance and mstp_detail:
            cmd = 'show spanning-tree mst {} detail'.format(mstp_instance)
        elif mstp_instance:
            cmd = 'show spanning-tree mst {}'.format(mstp_instance)
        elif mstp_intf:
            intf_details = get_interface_number_from_name(mstp_intf)
            cmd = 'show spanning-tree mst interface {} {}'.format(intf_details['type'], intf_details['number'])
        else:
            cmd = 'show spanning-tree mst'
        try:
            output = st.show(dut, cmd, skip_error_check=skip_error_check, type=cli_type)
        except Exception:
            return False
        return output
    elif cli_type in ["rest-put", "rest-patch"]:
        # code will be added later
        pass
    else:
        st.error("Unsupported CLI_TYPE: {}".format(cli_type))
        return False


def check_for_single_root_bridge_per_mstp_instance(dut_list, mstp_inst_list, dut_inst_data, cli_type=""):
    cli_type = st.get_ui_type(dut_list, cli_type=cli_type)
    """
    API to check for single root bridge per MSTP instance
    check_for_single_root_bridge_per_vlan(get_dut_list(vars), [1,2,3], {1:1,2:2})
    :dut_list = no of duts list
    :mstp_instance_list = no of mstp intances
    :dut_inst_data = dut to mstp mapping dict
    :param dut:
    :param mstp instance list:
    :param cli_type:
    :return:
    """
    st.log("Verifying the single root bridge per vlan ...")
    dut_li = cutils.make_list(dut_list)
    mstp_inst_li = cutils.make_list(mstp_inst_list)
    st.log("DUT LIST : {}, VLAN LIST :{}".format(dut_list, mstp_inst_list))
    if len(mstp_inst_list) != len(dut_list):
        st.log("Invalid data provided to check the root bridge per instance...")
        return False
    for inst in mstp_inst_li:
        root_count = 0
        params = list()
        for dut in dut_li:
            params.append(ExecAllFunc(show_mstp, dut, mstp_instance=inst, cli_type=cli_type))
        stp_output, exceptions = exec_all(True, params)
        for value in exceptions:
            if value is not None:
                st.log("Exception occured {}".format(value))
                return False
        if not stp_output:
            st.log("STP output not found on {} for {} instance".format(dut_li, inst))
            return False
        for index, stp_out in enumerate(stp_output):
            if len(stp_out) <= 0:
                st.log("STP OUTPUT IS NOT OBSERVED --- {}".format(stp_out))
                return False
            root_bridge = stp_out[0]["root_address"]
            dut_bridge_id = stp_out[0]["bridge_address"]
            if root_bridge == dut_bridge_id and stp_out[0]["role"] == "Root":
                st.log("Expected DUT to instance root: {}".format(dut_inst_data))
                if dut_inst_data[dut_li[index]] != int(inst.strip()):
                    st.error("Observed DUT to MSTP instance root: {} - {}".format(dut_li[index], inst))
                    return False
                else:
                    st.log("Observed DUT to MSTP instance root: {} - {}".format(dut_li[index], inst))
                root_count += 1
            if root_count > 1:
                st.log("Observed more than 1 root bridge per {} instance".format(inst))
                return False
    return True


def check_dut_is_root_bridge_for_mstp_inst(dut, mstp_inst, cli_type=""):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    """

        :param dut:
        :param mstp_inst:
        :return:
    """
    cli_type = "klish" if cli_type == "click" else cli_type
    if cli_type == "klish":
        cmd = "show spanning-tree mst {}".format(mstp_inst)
        stp_output = st.show(dut, cmd, type=cli_type)
    elif cli_type in ["rest-put", "rest-patch"]:
        # code will be added later
        pass
    else:
        st.log("Invalid cli_type provided: {}".format(cli_type))
        return False

    if len(stp_output) > 0:
        root_bridge = stp_output[0]["root_address"]
        dut_bridge_id = stp_output[0]["bridge_address"]
        return (root_bridge == dut_bridge_id)
    else:
        return False


def config_mstp_root_bridge_by_mstp_inst_vlan(mstp_data, cli_type=""):
    """
    :param mstp_data: {dut1: {"vlan":1,"instance":10, "priority": "0","mode":"mstp"}, dut2: {"vlan":2,"instance":20, "priority": "0","mode":"mstp"}, dut3: {"vlan":3,"instance":30, "priority": "0","mode":"mstp"}}
    """
    cli_type = "klish" if cli_type == "click" else cli_type
    dut_li = []
    data_li = []
    for dut, data in mstp_data.items():
        dut_li.append(dut)
        data_li.append({'vlan': data["vlan"], 'instance': data["instance"], 'priority': data["priority"], 'mode': data["mode"], 'cli_type': cli_type})
    st.exec_each2(dut_li, config_stp_vlan_parameters, data_li)
    return True


def verify_mstp_ports_by_state(dut, mstp_inst, port_state, port_list, cli_type="", **kwargs):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    """
    API Will check the port state in the mstp instance.

    :param dut:
    :param mstp_inst:
    :param state:
    :param port_list:
    :param cli_type:
    :return:
    """
    depth = kwargs.get("depth", 3)
    filter_type = kwargs.get("filter_type", "NON_CONFIG")
    port_li = cutils.make_list(port_list)
    result = True
    if cli_type in get_supported_ui_type_list():
        stp_gbl_obj = umf_stp.Stp()
        stp_mst_inst_obj = umf_stp.MstInstance(MstId=int(mstp_inst), Stp=stp_gbl_obj)
        for each_port in port_li:
            stp_mst_intf_obj = umf_stp.MstInstanceInterface(Name=each_port, PortState=port_state, MstInstance=stp_mst_inst_obj)
            query_params_obj = cutils.get_query_params(yang_data_type=filter_type, depth=depth, cli_type=cli_type)
            rv = stp_mst_intf_obj.verify(dut, query_param=query_params_obj, match_subset=True)
            if not rv.ok():
                st.log("test_step_failed: {} is not {} state ".format(each_port, port_state))
                result = False
            else:
                st.log("{} is {} state ".format(each_port, port_state))
    else:
        stp_output = show_mstp(dut, mstp_instance=mstp_inst, cli_type=cli_type)
        ports_list = [row["interface"] for row in stp_output if row["state"] == port_state and int(row["mst_instance"]) == int(mstp_inst)]
        for each_port in port_li:
            if each_port not in ports_list:
                st.log("{} is not {} state ".format(each_port, port_state))
                result = False
            else:
                st.log("{} is {} state ".format(each_port, port_state))
    return result


def get_mstp_param(dut, params, **kwargs):
    '''
     get_mstp_param(vars.D1, ['bpdu_sent', 'bpdu_rcvd'], mstp_instance=10, mstp_detail=True)
    :param dut:
    :param params:
    :param kwargs:
    :return:
    '''
    output = show_mstp(dut, **kwargs)
    params = cutils.make_list(params)
    retval = cutils.filter_and_select(output, params)
    return retval[0] if isinstance(retval, list) and retval else ""


def verify_mstp_config(dut, verify_list, **kwargs):
    '''
    verify_mstp_config(vars.D1, {'bpdu_sent': '13', 'bpdu_rcvd': '252'}, mstp_instance=10, mstp_detail=True)
    :param dut:
    :param verify_list:
    :param kwargs:
    :return:
    '''
    output = show_mstp(dut, **kwargs)
    verify_entries = cutils.make_list(verify_list)
    for verify_entry in verify_entries:
        if not cutils.filter_and_select(output, None, verify_entry):
            st.error("Entry: {} is not found in the output: {}".format(verify_entry, output))
            return False
    return True


def verify_mstp_config_param(dut, verify_list, **kwargs):
    '''
    verify_mstp_config_param(vars.D1,{'name':'test'})
    :param dut:
    :param verify_list:
    :param kwargs:
    :return:
    '''
    output = show_mstp_config(dut, **kwargs)
    verify_entries = cutils.make_list(verify_list)
    for verify_entry in verify_entries:
        if not cutils.filter_and_select(output, None, verify_entry):
            st.error("Entry: {} is not found in the output: {}".format(verify_entry, output))
            return False
    return True


def verify_stp_scale(dut):
    """
    This api will verify stp convergence of all ports in 5k vlan ports
    :param dut:
    :return:
    """
    output = show_stp(dut)
    for i in output:
        if i['port_state'] not in ["LEARNING", "LISTENING", "DISABLED"]:
            return True
    return False
