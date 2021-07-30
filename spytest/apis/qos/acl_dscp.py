# This file contains the list of API's which performs FBS operations.
#Author: prudviraj k (prudviraj.kristipati.@broadcom.com)

from spytest import st
from spytest.utils import filter_and_select
import re
from utilities.utils import get_interface_number_from_name
from apis.system.rest import config_rest, delete_rest,get_rest


def config_policy_table(dut, **kwargs):
    """
    Creating policies
    Author: prudviraj k (prudviraj.kristipati@broadcom.com)
    :param dut:
    :param kwargs: Needed arguments to build policy table
    :return:
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut, **kwargs))
    policy_data = kwargs
    if 'policy_name' not in policy_data:
        st.error("policy name not provided ...")
        return False
    if cli_type == "click":
        if policy_data['enable'] == "create":
            command = "config policy add {} -t {}".format(policy_data['policy_name'], policy_data['policy_type'])
        elif policy_data['enable'] == "del":
            command = "config policy del {}".format(policy_data['policy_name'])
    elif cli_type == 'klish':
        command = list()
        if policy_data['enable'] == "create":
            command.append("policy-map {} type {}".format(policy_data['policy_name'], policy_data['policy_type']))
            command.append('exit')
        elif policy_data['enable'] == "del":
            command.append("no policy-map {}".format(policy_data['policy_name']))
    elif cli_type in ['rest-patch','rest-put']:
        rest_urls = st.get_datastore(dut,'rest_urls')
        http_method = kwargs.pop('http_method',cli_type)
        if policy_data['enable'] == "create":
            rest_url = rest_urls['policy_table_config']
            ocdata = {"openconfig-fbs-ext:policy": [{"policy-name":policy_data['policy_name'],
                                                     "config": {"type": "POLICY_"+policy_data['policy_type'].upper(),
                                                                "name": policy_data['policy_name']}}]}
            response = config_rest(dut, http_method=http_method, rest_url=rest_url, json_data=ocdata)
            if not response:
                st.log(response)
                return False
        elif policy_data['enable'] == "del":
            rest_url = rest_urls['policy_table_delete'].format(policy_data['policy_name'])
            response = delete_rest(dut, rest_url=rest_url)
            if not response:
                st.log(response)
                return False
        return True
    else:
        st.error("Invalid config command selection")
        return False
    st.config(dut, command, type=cli_type)
    if cli_type == "klish":
        st.config(dut, "exit", type=cli_type)
    return True


def config_classifier_table(dut, **kwargs):
    """
    Creating classifiers
    Author: prudviraj k (prudviraj.kristipati@broadcom.com)
    :param dut:
    :param kwargs: Needed arguments to build classifier table
    :return:
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut, **kwargs))
    class_data = kwargs
    skip_error = kwargs.get("skip_error", False)
    if 'class_name' not in class_data:
        st.error("classifier name not provided ...")
        return False

    class_criteria_list = list()
    criteria_val_list = list()
    if 'class_criteria' in class_data.keys() and 'criteria_value' in class_data.keys():
        class_criteria = class_data['class_criteria']
        criteria_val = class_data['criteria_value']
        class_criteria_list = list(class_criteria) if type(class_criteria) is list else [class_criteria]
        criteria_val_list = list(criteria_val) if type(criteria_val) is list else [criteria_val]

    command = ''
    if cli_type == "click":
        if class_data['enable'] == "create":
            command = "config classifier add {} -m  {}".format(class_data['class_name'], class_data['match_type'])
        elif class_data['enable'] == "yes":
            command = "config classifier update {} ".format(class_data['class_name'])
            for class_criteria, criteria_val in zip(class_criteria_list, criteria_val_list):
                if '--no-' in class_criteria:
                    if criteria_val != '':
                        command += '{} {} '.format(class_criteria, criteria_val)
                    else:
                        command += '{} '.format(class_criteria)
                else:
                    command += '{} {} '.format(class_criteria, criteria_val)
        elif class_data['enable'] == "no":
            command = "config classifier update {} ".format(class_data['class_name'])
            for class_criteria in class_criteria_list:
                if '--no-' in class_criteria: command += '{} '.format(class_criteria)
        elif class_data['enable'] == "del":
            command = "config classifier del {}".format(class_data['class_name'])
    elif cli_type == 'klish':
        command = list()
        config = kwargs.get('config', 'yes')
        config_cmd = '' if config == 'yes' else 'no'
        class_data.update({"match_type": kwargs.get("match_type", "acl")})
        if 'match_type' in class_data.keys() and class_data['match_type'] != 'acl':
            class_data['match_type'] = 'fields match-all'
        if class_data['enable'] != 'del':
            command.append('class-map {} match-type {}'.format(class_data['class_name'], class_data['match_type']))
            if 'description' in class_data:
                if config_cmd == 'no': class_data['description'] = ''
                command.append('{} description {}'.format(config_cmd, class_data['description']))
            for criteria, value in zip(class_criteria_list, criteria_val_list):
                prefix = 'no match' if '--no-' in criteria else 'match'
                criteria_val = '' if '--no-' in criteria else value
                criteria = criteria.replace("--", "")
                if 'acl' in criteria:
                    infer_acl_type = None
                    if 'acl_table_l2' in criteria_val: infer_acl_type = 'mac'
                    if 'acl_table_v4' in criteria_val: infer_acl_type = 'ip'
                    if 'acl_table_v6' in criteria_val: infer_acl_type = 'ipv6'
                    if not kwargs.get("acl_type") and not infer_acl_type:
                        st.error("ACL Type is Mandatory")
                        return False
                    acl_type = kwargs.get("acl_type", infer_acl_type)
                    cmd = '{} access-group {} {}'.format(prefix, acl_type, criteria_val)
                elif 'src-mac' in criteria:
                    mac_cmd = criteria_val if '/' in criteria_val else 'host {}'.format(criteria_val)
                    cmd = '{} source-address mac {}'.format(prefix, mac_cmd)
                elif 'src-ipv6' in criteria:
                    ip_cmd = criteria_val if '/' in criteria_val else 'host {}'.format(criteria_val)
                    cmd = '{} source-address ipv6 {}'.format(prefix, ip_cmd)
                elif 'src-ip' in criteria:
                    ip_cmd = criteria_val if '/' in criteria_val else 'host {}'.format(criteria_val)
                    cmd = '{} source-address ip {}'.format(prefix, ip_cmd)
                elif 'dst-mac' in criteria:
                    mac_cmd = criteria_val if '/' in criteria_val else 'host {}'.format(criteria_val)
                    cmd = '{} destination-address mac {}'.format(prefix, mac_cmd)
                elif 'dst-ipv6' in criteria:
                    ip_cmd = criteria_val if '/' in criteria_val else 'host {}'.format(criteria_val)
                    cmd = '{} destination-address ipv6 {}'.format(prefix, ip_cmd)
                elif 'dst-ip' in criteria:
                    ip_cmd = criteria_val if '/' in criteria_val else 'host {}'.format(criteria_val)
                    cmd = '{} destination-address ip {}'.format(prefix, ip_cmd)
                elif 'ether' in criteria:
                    if criteria_val == '0x800' or criteria_val == '0x0800' : criteria_val = 'ip'
                    if criteria_val.lower() == '0x86dd':criteria_val = 'ipv6'
                    if criteria_val == '0x806' or criteria_val == '0x0806': criteria_val = 'arp'
                    cmd = '{} ethertype {}'.format(prefix, criteria_val)
                elif 'pcp' in criteria:
                    cmd = '{} pcp {}'.format(prefix, criteria_val)
                elif 'ip-proto' in criteria:
                    cmd = '{} ip protocol {}'.format(prefix, criteria_val)
                elif 'src-port' in criteria:
                    string = 'eq' if criteria_val != '' else ''
                    if criteria_val != '' and '-' in str(criteria_val):
                        string = 'range';
                        criteria_val = criteria_val.split('-')
                    if type(criteria_val) is list:
                        cmd = '{} l4-port source {} {} {}'.format(prefix, string, criteria_val[0],criteria_val[1])
                    else:
                        cmd = '{} l4-port source {} {}'.format(prefix, string, criteria_val)
                elif 'dst-port' in criteria:
                    string = 'eq' if criteria_val != '' else ''
                    if criteria_val != '' and '-' in str(criteria_val):
                        string = 'range';
                        criteria_val = criteria_val.split('-')
                    if type(criteria_val) is list:
                        cmd = '{} l4-port destination {} {} {}'.format(prefix, string, criteria_val[0], criteria_val[1])
                    else:
                        cmd = '{} l4-port destination {} {}'.format(prefix, string, criteria_val)
                elif 'dscp' in criteria:
                    cmd = '{} dscp {}'.format(prefix, criteria_val)
                elif 'tcp-flags' in criteria:
                    if value != '':
                        cmd = '{} tcp-flags {}'.format(prefix, value)
                    else:
                        cmd = '{} tcp-flags'.format(prefix)
                else:
                    cmd = '{} {} {}'.format(prefix, criteria, criteria_val)
                command.append(cmd)
        elif class_data['enable'] == 'del':
            command.append('no class-map {}'.format(class_data['class_name']))
    elif cli_type in ['rest-patch','rest-put']:
        config = kwargs.get('config','yes')
        http_method = kwargs.pop('http_method',cli_type)
        config_cmd = '' if config == 'yes' else 'no'
        rest_urls = st.get_datastore(dut,'rest_urls')
        delete_base_url = rest_urls['classifier_update_delete'].format(class_data['class_name'])
        ocdata = {}
        ocdata["openconfig-fbs-ext:classifiers"] ={}
        ocdata["openconfig-fbs-ext:classifiers"]['classifier'] =[]
        temp_dict = {}
        temp_dict['class-name'] = class_data['class_name']
        temp_dict['config'] = {}
        temp_dict['match-acl'] = {}
        temp_dict['match-acl']['config'] = {}
        temp_dict['match-hdr-fields'] = {}
        temp_dict['match-hdr-fields']['config'] = {}
        temp_dict['match-hdr-fields']['l2'] = {}
        temp_dict['match-hdr-fields']['l2']['config'] = {}
        temp_dict['match-hdr-fields']['ip'] = {}
        temp_dict['match-hdr-fields']['ip']['config'] = {}
        temp_dict['match-hdr-fields']['ipv4'] = {}
        temp_dict['match-hdr-fields']['ipv4']['config'] = {}
        temp_dict['match-hdr-fields']['ipv6'] = {}
        temp_dict['match-hdr-fields']['ipv6']['config'] = {}
        temp_dict['match-hdr-fields']['transport'] = {}
        temp_dict['match-hdr-fields']['transport']['config'] = {}
        temp_dict['config']['name'] = class_data['class_name']
        if class_data['enable'] != 'del':
            temp_dict['config']['match-type'] = 'MATCH_' + class_data['match_type'].upper()
            rest_url=rest_urls['classifier_table_config']
            if 'description' in class_data:
                if config_cmd != 'no':
                    temp_dict['config']['description'] = class_data['description']
                else:
                    response = delete_rest(dut, rest_url=delete_base_url + '/config/description')
                    if not response:
                        return False
            for criteria,value in zip(class_criteria_list,criteria_val_list):
                prefix = 'no match' if '--no-' in criteria else 'match'
                criteria_val = '' if '--no-' in criteria else value
                if 'acl' in criteria:
                    acl_type = kwargs.get('acl_type','ip') if criteria_val != '' else ''
                    if acl_type == 'ip' : acl_type = "ACL_IPV4"
                    if acl_type == 'ipv6': acl_type = "ACL_IPV6"
                    if acl_type == 'mac': acl_type = "ACL_L2"
                    if prefix == 'match':
                        temp_dict['match-acl']['config']['acl-name'] = criteria_val
                        temp_dict['match-acl']['config']['acl-type'] = acl_type
                    else:
                        response = delete_rest(dut,rest_url=delete_base_url +'/match-acl/config')
                        if not response:
                            return False
                elif 'src-mac' in criteria:
                    if prefix == 'match':
                        temp_dict['match-hdr-fields']['l2']['config']['source-mac'] = criteria_val
                    else:
                        response = delete_rest(dut,rest_url=delete_base_url+'/match-hdr-fields/l2/config/source-mac')
                        if not response:
                            return False
                elif 'src-ipv6' in criteria:
                    ip_cmd = criteria_val if '/' in criteria_val else 'host {}'.format(criteria_val)
                    if 'host' in ip_cmd: criteria_val += '/128'
                    if prefix == 'match':
                        temp_dict['match-hdr-fields']['ipv6']['config']['source-address'] = criteria_val
                    else:
                        response = delete_rest(dut,rest_url=delete_base_url+'/match-hdr-fields/ipv6/config/source-address')
                        if not response:
                            return False
                elif 'src-ip' in criteria:
                    ip_cmd = criteria_val if '/' in criteria_val else 'host {}'.format(criteria_val)
                    if 'host' in ip_cmd: criteria_val += '/32'
                    if prefix == 'match':
                        temp_dict['match-hdr-fields']['ipv4']['config']['source-address'] = criteria_val
                    else:
                        response = delete_rest(dut,rest_url=delete_base_url+'/match-hdr-fields/ip/config/source-address')
                        if not response:
                            return False
                elif 'dst-mac' in criteria:
                    if prefix == 'match':
                        temp_dict['match-hdr-fields']['l2']['config']['destination-mac'] = criteria_val
                    else:
                        response = delete_rest(dut,rest_url=delete_base_url+'/match-hdr-fields/l2/config/destination-mac')
                        if not response:
                            return False
                elif 'dst-ipv6' in criteria:
                    ip_cmd = criteria_val if '/' in criteria_val else 'host {}'.format(criteria_val)
                    if 'host' in ip_cmd: criteria_val += '/128'
                    if prefix == 'match':
                        temp_dict['match-hdr-fields']['ipv6']['config']['destination-address'] = criteria_val
                    else:
                        response = delete_rest(dut,rest_url=delete_base_url+'/match-hdr-fields/ipv6/config/destination-address')
                        if not response:
                            return False
                elif 'dst-ip' in criteria:
                    ip_cmd = criteria_val if '/' in criteria_val else 'host {}'.format(criteria_val)
                    if 'host' in ip_cmd: criteria_val += '/32'
                    if prefix == 'match':
                        temp_dict['match-hdr-fields']['ipv4']['config']['destination-address'] = criteria_val
                    else:
                        response = delete_rest(dut,rest_url=delete_base_url+'/match-hdr-fields/ip/config/destination-address')
                        if not response:
                            return False
                elif 'ether' in criteria:
                    if prefix == 'match':
                        ether_type = 'ETHERTYPE_IPV6' if 'ipv6' in criteria else 'ETHERTYPE_IPV4'
                        temp_dict['match-hdr-fields']['l2']['config']['ethertype'] = ether_type
                    else:
                        response = delete_rest(dut,rest_url=delete_base_url+'/match-hdr-fields/l2/config/ethertype')
                        if not response:
                            return False
                elif 'pcp' in criteria:
                    if prefix == 'match':
                        temp_dict['match-hdr-fields']['l2']['config']['pcp'] = criteria_val
                    else:
                        response = delete_rest(dut,rest_url=delete_base_url+'/match-hdr-fields/l2/config/pcp')
                        if not response:
                            return False
                elif 'ip-proto' in criteria:
                    if prefix == 'match':
                        ip_proto = 'IP_TCP' if criteria_val =='tcp' or criteria_val =='6' else 'IP_UDP'
                        temp_dict['match-hdr-fields']['ip']['config']['protocol'] = ip_proto
                    else:
                        response = delete_rest(dut,rest_url=delete_base_url+'/match-hdr-fields/ip/config/protocol')
                        if not response:
                            return False
                elif 'src-port' in criteria:
                    if prefix == 'match':
                        if '-' in str(criteria_val): criteria_val = criteria_val.replace('-', '..')
                        if ".." not in str(criteria_val): criteria_val = int(criteria_val)
                        temp_dict['match-hdr-fields']['transport']['config']['source-port'] = criteria_val
                    else:
                        response = delete_rest(dut,rest_url=delete_base_url+'/match-hdr-fields/transport/config/source-port')
                        if not response:
                            return False
                elif 'dst-port' in criteria:
                    if prefix == 'match':
                        if '-' in str(criteria_val): criteria_val = criteria_val.replace('-', '..')
                        if ".." not in str(criteria_val): criteria_val = int(criteria_val)
                        temp_dict['match-hdr-fields']['transport']['config']['destination-port'] = criteria_val
                    else:
                        response = delete_rest(dut,rest_url=delete_base_url+'/match-hdr-fields/transport/config/destination-port')
                        if not response:
                            return False
                elif 'dscp' in criteria:
                    if prefix == 'match':
                        temp_dict['match-hdr-fields']['ip']['config']['dscp'] = int(criteria_val)
                    else:
                        response = delete_rest(dut,rest_url=delete_base_url+'/match-hdr-fields/ip/config/dscp')
                        if not response:
                            return False
                elif 'tcp-flags' in criteria:
                    if prefix == 'match':
                        criteria_val = criteria_val.split(' ')
                        flag_list = []
                        for item in criteria_val:
                            if 'no' in item:
                                item = item.split('-')
                                flag_list.append('TCP_NOT_{}'.format(item[1].upper()))
                            else:
                                flag_list.append('TCP_{}'.format(item.upper()))
                        temp_dict['match-hdr-fields']['transport']['config']['tcp-flags'] = flag_list
                    else:
                        response = delete_rest(dut, rest_url=delete_base_url+'/match-hdr-fields/transport/config/tcp-flags')
                        if not response:
                            return False
                else:
                    criteria_field = 'vlanid' if 'vlan' in criteria else criteria
                    if prefix == 'match':
                        temp_dict['match-hdr-fields']['l2']['config'][criteria_field] = int(criteria_val)
                    else:
                        rest_url = delete_base_url + '/' + '/match-hdr-fields/l2/config/' + criteria_field
                        response = delete_rest(dut, rest_url=rest_url)
                        if not response:
                           return False
            if temp_dict['config'] == {}:del temp_dict['config']
            if temp_dict['match-acl']['config'] == {}: del temp_dict['match-acl']['config']
            if temp_dict['match-acl'] == {}:del temp_dict['match-acl']
            if temp_dict['match-hdr-fields']['config'] == {}: del temp_dict['match-hdr-fields']['config']
            if temp_dict['match-hdr-fields']['l2']['config'] == {}: del temp_dict['match-hdr-fields']['l2']['config']
            if temp_dict['match-hdr-fields']['l2'] == {}: del temp_dict['match-hdr-fields']['l2']
            if temp_dict['match-hdr-fields']['ip']['config'] == {}: del temp_dict['match-hdr-fields']['ip']['config']
            if temp_dict['match-hdr-fields']['ip'] == {}: del temp_dict['match-hdr-fields']['ip']
            if temp_dict['match-hdr-fields']['ipv4']['config'] == {}: del temp_dict['match-hdr-fields']['ipv4']['config']
            if temp_dict['match-hdr-fields']['ipv4'] == {}: del temp_dict['match-hdr-fields']['ipv4']
            if temp_dict['match-hdr-fields']['ipv6']['config'] == {}: del temp_dict['match-hdr-fields']['ipv6']['config']
            if temp_dict['match-hdr-fields']['ipv6'] == {}: del temp_dict['match-hdr-fields']['ipv6']
            if temp_dict['match-hdr-fields']['transport']['config'] == {}: del temp_dict['match-hdr-fields']['transport']['config']
            if temp_dict['match-hdr-fields']['transport'] == {}: del temp_dict['match-hdr-fields']['transport']
            if temp_dict['match-hdr-fields'] == {}: del temp_dict['match-hdr-fields']

            ocdata["openconfig-fbs-ext:classifiers"]['classifier'].append(temp_dict)
            if len(ocdata["openconfig-fbs-ext:classifiers"]['classifier']) > 0:
                response = config_rest(dut,http_method=http_method,rest_url= rest_url,json_data=ocdata)
                if not response:
                    return False
        elif class_data['enable'] =='del':
            rest_url = rest_urls['classifier_update_delete'].format(class_data['class_name'])
            response = delete_rest(dut,rest_url=rest_url)
            if not response:
                st.log(response)
                return False
        return True
    else:
        st.error("Invalid config command selection")
        return False
    out = st.config(dut, command,type=cli_type,skip_error_check=skip_error)
    if re.search(r'Error',out):
        if cli_type == "klish":
            st.config(dut, "exit", type=cli_type)
        return False
    if cli_type == "klish":
        st.config(dut, "exit", type=cli_type)
    return True


def convert_tcp_flags_to_hex(tcp_flags=''):
    hex_dict ={}
    hex_dict['fin'] = hex_dict['not-fin'] = 1
    hex_dict['syn'] = hex_dict['not-syn'] = 2
    hex_dict['rst'] = hex_dict['not-rst'] = 4
    hex_dict['psh'] = hex_dict['not-psh'] = 8
    hex_dict['ack'] = hex_dict['not-ack'] = 16
    hex_dict['urg'] = hex_dict['not-urg'] = 32

    tcp_flags = tcp_flags.rstrip().split(' ')
    total = 0;total_no_not = 0
    for flag in tcp_flags:
        total += hex_dict[flag]
        if 'not' not in flag:
            total_no_not += hex_dict[flag]
    total_hex = hex(total)
    total_no_not_hex = hex(total_no_not)
    if total_no_not == 0:
        return ('{}/{}'.format(total_hex,total_hex))
    else:
        return ('{}/{}'.format(total_no_not_hex,total_hex))


def config_flow_update_table(dut, skip_error=False, **kwargs):
    """
    Creating to update the classifier table
    Author: prudviraj k (prudviraj.kristipati@broadcom.com)
    :param dut:
    :param kwargs: Needed arguments to update the flow table
    :return:
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut, **kwargs))
    flow_data = kwargs
    policy_type = kwargs.get('policy_type', 'qos')
    if not flow_data:
        st.error("flow update table failed because of invalid data ..")
    if cli_type == "click":
        if flow_data['flow'] == "update":
            if flow_data['priority_option'] == "--police":
                command = "config flow update {} {} --police --cir {} --cbs {} --pir {} --pbs {}".format(
                    flow_data['policy_name'], flow_data['class_name'], flow_data['priority_value_1'],
                    flow_data['priority_value_2'], flow_data['priority_value_3'], flow_data['priority_value_4'])
                st.config(dut, command, type='click')
            else:
                command = "config flow update {} {} {} {}".format(flow_data['policy_name'], flow_data['class_name'],
                                                                  flow_data['priority_option'],
                                                                  flow_data['priority_value'])
                out = st.config(dut, command, type='click', skip_error_check=skip_error)
                if re.search(r'Error: Invalid value for.*', out):
                    return False
        elif flow_data['flow'] == "update_del":
            command = "config flow update {} {} {}".format(flow_data['policy_name'], flow_data['class_name'],
                                                           flow_data['priority_option'])
            st.config(dut, command)
        elif flow_data['flow'] == "add":
            command = "config flow add {} {} -p {} -d {}".format(flow_data['policy_name'], flow_data['class_name'],
                                                                 flow_data['priority_value'], flow_data['description'])
            out = st.config(dut, command, type='click', skip_error_check=skip_error)
            if "Failed" not in out or "Error" not in out:
                return False
        elif flow_data['flow'] == "del":
            command = "config flow del {} {}".format(flow_data['policy_name'], flow_data['class_name'])
            st.config(dut, command, type='click')
    elif cli_type == 'klish':
        config = kwargs.get('config', 'yes')
        config_cmd = '' if config == 'yes' else 'no'
        set_action = flow_data.get('priority_option', None)
        version = flow_data.get('version', 'ip')
        next_hop = flow_data.get('next_hop', None)
        vrf_name = flow_data.get('vrf_name', None)
        next_hop_priority = flow_data.get('next_hop_priority', None)
        set_interface = flow_data.get('set_interface', None)
        set_interface_priority = flow_data.get('set_interface_priority', None)

        action_cmd = list()
        if set_action and set_action == 'next-hop':
            next_hop = list(next_hop) if type(next_hop) is list else [next_hop]
            if vrf_name:
                vrf_name = list(vrf_name) if type(vrf_name) is list else [vrf_name]
            if next_hop_priority:
                next_hop_priority = list(next_hop_priority) if type(next_hop_priority) is list else [next_hop_priority]

            if not vrf_name and not next_hop_priority:
                for nh in next_hop:
                    action_cmd.append('{} set {} next-hop {}'.format(config_cmd, version, nh))
            elif not vrf_name and next_hop_priority:
                for nh, prio in zip(next_hop, next_hop_priority):
                    prio_cmd = '' if prio == '' else ' priority {}'.format(prio)
                    action_cmd.append('{} set {} next-hop {}{}'.format(config_cmd, version, nh, prio_cmd))
            elif vrf_name and not next_hop_priority:
                for nh, vrf in zip(next_hop, vrf_name):
                    vrf_cmd = '' if vrf == '' else ' vrf {}'.format(vrf)
                    action_cmd.append('{} set {} next-hop {}{}'.format(config_cmd, version, nh, vrf_cmd))
            elif vrf_name and next_hop_priority:
                for nh, vrf, prio in zip(next_hop, vrf_name, next_hop_priority):
                    vrf_cmd = '' if vrf == '' else ' vrf {}'.format(vrf)
                    prio_cmd = '' if prio == '' else ' priority {}'.format(prio)
                    action_cmd.append('{} set {} next-hop {}{}{}'.format(config_cmd, version, nh, vrf_cmd, prio_cmd))
        elif set_action and set_action == 'interface':
            set_interface = list(set_interface) if type(set_interface) is list else [set_interface]
            if set_interface_priority:
                set_interface_priority = list(set_interface_priority) if type(set_interface_priority) is list else [
                    set_interface_priority]
            if not set_interface_priority:
                for intf in set_interface:
                    interface = get_interface_number_from_name(intf)
                    if isinstance(interface, dict):
                        action_cmd.append('{} set interface {} {}'.format(config_cmd,interface['type'],interface['number']))
                    else:
                        action_cmd.append('{} set interface {}'.format(config_cmd,intf))
            else:
                for intf,priority in zip(set_interface,set_interface_priority):
                    interface = get_interface_number_from_name(intf)
                    if isinstance(interface, dict):
                        action_cmd.append('{} set interface {} {} priority {}'.format(config_cmd,interface['type'],interface['number'],priority))
                    else:
                        action_cmd.append('{} set interface {} priority {}'.format(config_cmd,intf,priority))
        elif set_action and 'police' in set_action:

            if 'priority_value_1' in flow_data:
                flow_data['cir'] = flow_data['priority_value_1']
                flow_data['cbs'] = flow_data['priority_value_2']
                flow_data['pir'] = flow_data['priority_value_3']
                flow_data['pbs'] = flow_data['priority_value_4']
            if config_cmd == '':
                action_cmd.append('{} police cir {} cbs {} pir {} pbs {}\n'.format(config_cmd, flow_data['cir'],
                                                                               flow_data['cbs'], flow_data['pir'],
                                                                               flow_data['pbs']))
            else:
                action_cmd.append('no police cir cbs pir pbs')
        elif set_action and 'dscp' in set_action:
            action_cmd.append('no set dscp' if '--no' in set_action else 'set dscp {}'.format(
                flow_data['priority_value']))
        elif set_action and 'pcp' in set_action:
            action_cmd.append('no set pcp' if '--no' in set_action else 'set pcp {}'.format(flow_data['priority_value']))
        elif set_action and 'mirror-session' in set_action:
            action_cmd.append('no set mirror-session' if '--no' in set_action else 'set mirror-session {}'.format(flow_data['priority_value']))
        command = ['policy-map {} type {}'.format(flow_data['policy_name'], policy_type)]
        check = False
        if flow_data['flow'] != 'del':
            if flow_data['flow'] == 'add' and 'priority_value' in flow_data:
                flow_data['flow_priority'] = flow_data['priority_value']
                check = True
            if 'flow_priority' in flow_data:
                command.append('class {} priority {}'.format(flow_data['class_name'], flow_data['flow_priority']))
                check = True
            else:
                command.append('class {}'.format(flow_data['class_name']))
                check = True
            if 'description' in flow_data:
                if config_cmd == 'no': flow_data['description'] = ''
                command.append('{} description {}'.format(config_cmd, flow_data['description']))
                check = True

            if flow_data['class_name']=="test_non_exist":
                check = False

            if check:
                action_cmd.append("exit")
                #check = False
            command = command + action_cmd
            command.append("exit")
        else:
            command.append('no class {}'.format(flow_data['class_name']))
            command.append("exit")
        st.log(command)
        out = st.config(dut, command, type='klish',skip_error_check=skip_error)
        if "Error" in out:
            return False
    elif cli_type in ['rest-patch','rest-put']:
        http_method = kwargs.pop('http_method',cli_type)
        config = kwargs.get('config','yes')
        config_cmd = '' if config == 'yes' else 'no'
        set_action = flow_data.get('priority_option',None)
        version = flow_data.get('version','ip').upper()
        next_hop = flow_data.get('next_hop',None)
        vrf_name = flow_data.get('vrf_name',None)
        next_hop_priority = flow_data.get('next_hop_priority',None)
        set_interface = flow_data.get('set_interface',None)
        set_interface_priority = flow_data.get('set_interface_priority',None)
        traffic_class = flow_data.get('traffic_class','')
        rest_urls = st.get_datastore(dut,'rest_urls')
        ocdata = {}
        ocdata["openconfig-fbs-ext:sections"] = {}
        ocdata["openconfig-fbs-ext:sections"]['section'] = []
        section_dict = {}
        section_dict['config'] = {}
        section_dict['qos'] = {}
        section_dict['qos']['remark'] = {}
        section_dict['qos']['remark']['config'] = {}
        section_dict['qos']['policer'] = {}
        section_dict['qos']['policer']['config'] = {}
        section_dict['qos']['queuing'] = {}
        section_dict['qos']['queuing']['config'] = {}
        section_dict['monitoring'] = {}
        section_dict['monitoring']['mirror-sessions'] = {}
        section_dict['monitoring']['mirror-sessions']['mirror-session'] = []
        monitoring_dict = {}
        monitoring_dict['config'] = {}
        section_dict['forwarding'] = {}
        section_dict['forwarding']['config'] ={}
        section_dict['forwarding']['egress-interfaces'] = {}
        section_dict['forwarding']['egress-interfaces']['egress-interface'] = []
        egress_dict = {}
        egress_dict['config'] ={}
        section_dict['forwarding']['next-hops'] = {}
        section_dict['forwarding']['next-hops']['next-hop'] = []
        nexthop_dict = {}
        nexthop_dict['config']={}

        base_url = rest_urls['policy_flow_create'].format(flow_data['policy_name'])
        delete_oc_url = rest_urls['policy_flow_delete'].format(flow_data['policy_name'],flow_data['class_name'])
        delete_base_url = rest_urls['policy_flow_nexthop_delete'].format(flow_data['policy_name'], flow_data['class_name'])
        if flow_data['flow'] != 'del':
            result = config_policy_table(dut, enable='create',policy_name=flow_data['policy_name'],
                                         policy_type=flow_data['policy_type'],
                                         cli_type=cli_type)
            if not result: return False
            if flow_data['flow'] == 'add' and 'priority_value' in flow_data:
                flow_data['flow_priority'] = int(flow_data['priority_value'])

            section_dict['class'] = flow_data['class_name']
            section_dict['config']['name'] = flow_data['class_name']
            if 'flow_priority' in flow_data:
                section_dict['config']['priority'] = flow_data['flow_priority']
            if 'description' in flow_data:
                if config_cmd != 'no':
                    section_dict['config']['description']= flow_data['description']
                else:
                    rest_url = rest_urls['policy_flow_delete'].format(flow_data['policy_name'])
                    response = delete_rest(dut,rest_url=rest_url+'/config/description')
                    if not response:
                        return False

            if set_action and set_action == 'next-hop':
                set_version = 'SET_IP_NEXTHOP' if version == 'IP' else 'SET_IPV6_NEXTHOP'
                rest_url = delete_oc_url+'/forwarding/next-hops/next-hop'
                next_hop = list(next_hop) if type(next_hop) is list else [next_hop]
                if vrf_name:
                    vrf_name = list(vrf_name) if type(vrf_name) is list else [vrf_name]
                if next_hop_priority:
                    next_hop_priority = list(next_hop_priority) if type(next_hop_priority) is list else [next_hop_priority]

                if not vrf_name and not next_hop_priority:
                    if config_cmd != 'no':
                        for nh in next_hop:
                            nexthop_dict = dict()
                            nexthop_dict['config'] = dict()
                            nexthop_dict['ip-address'] = nh
                            nexthop_dict['network-instance'] = "openconfig-fbs-ext:INTERFACE_NETWORK_INSTANCE"
                            nexthop_dict['config']['ip-address'] = nh
                            nexthop_dict['config']['network-instance'] = "openconfig-fbs-ext:INTERFACE_NETWORK_INSTANCE"
                            section_dict['forwarding']['next-hops']['next-hop'].append(nexthop_dict)
                    else:
                        for nh in next_hop:
                            delete_url = rest_url+'={},openconfig-fbs-ext:INTERFACE_NETWORK_INSTANCE'.format(nh)
                            response = delete_rest(dut,rest_url=delete_url)
                            if not response:
                                return False
                elif not vrf_name and  next_hop_priority:
                    if config_cmd != 'no':
                        for nh, prio in zip(next_hop, next_hop_priority):
                            nexthop_dict = dict()
                            nexthop_dict['config'] = dict()
                            nexthop_dict['ip-address'] = nh
                            nexthop_dict['network-instance'] = "openconfig-fbs-ext:INTERFACE_NETWORK_INSTANCE"
                            nexthop_dict['config']['ip-address'] = nh
                            nexthop_dict['config']['network-instance'] = "openconfig-fbs-ext:INTERFACE_NETWORK_INSTANCE"
                            nexthop_dict['config']['priority'] = prio
                            section_dict['forwarding']['next-hops']['next-hop'].append(nexthop_dict)
                    else:
                        for nh,prio in zip(next_hop,next_hop_priority):
                            delete_url = delete_base_url+set_version+'={}||{}'.format(nh,prio)
                            response = delete_rest(dut,rest_url=delete_url)
                            if not response:
                                return False
                elif vrf_name and  not next_hop_priority:
                    if config_cmd != 'no':
                        for nh, vrf in zip(next_hop, vrf_name):
                            if vrf == '': vrf = "openconfig-fbs-ext:INTERFACE_NETWORK_INSTANCE"
                            nexthop_dict = dict()
                            nexthop_dict['config'] = dict()
                            nexthop_dict['ip-address'] = nh
                            nexthop_dict['network-instance'] = vrf
                            nexthop_dict['config']['ip-address'] = nh
                            nexthop_dict['config']['network-instance'] = vrf
                            section_dict['forwarding']['next-hops']['next-hop'].append(nexthop_dict)
                    else:
                        for nh,vrf in zip(next_hop, vrf_name):
                            delete_url = rest_url+'={},{}'.format(nh,vrf)
                            response = delete_rest(dut, rest_url=delete_url)
                            if not response:
                                return False
                elif vrf_name and next_hop_priority:
                    if config_cmd != 'no':
                        for nh, vrf, prio in zip(next_hop, vrf_name, next_hop_priority):
                            if vrf == '': vrf = "openconfig-fbs-ext:INTERFACE_NETWORK_INSTANCE"
                            nexthop_dict = dict()
                            nexthop_dict['config'] = dict()
                            nexthop_dict['ip-address'] = nh
                            nexthop_dict['network-instance'] = vrf
                            nexthop_dict['config']['ip-address'] = nh
                            nexthop_dict['config']['network-instance'] = vrf
                            nexthop_dict['config']['priority'] =prio
                            section_dict['forwarding']['next-hops']['next-hop'].append(nexthop_dict)
                    else:
                        for nh,vrf,prio in zip(next_hop, vrf_name,next_hop_priority):
                            delete_url = delete_base_url+ set_version + '={}|{}|{}'.format(nh,vrf,prio)
                            st.log(delete_url)
                            response = delete_rest(dut, rest_url=delete_url)
                            if not response:
                                return False
            elif set_action and set_action == 'interface':
                interface_str = '/forwarding/egress-interfaces/egress-interface'
                null_str = '/forwarding/config/discard'
                rest_url = delete_oc_url + interface_str
                set_interface = list(set_interface) if type(set_interface) is list else [set_interface]
                if set_interface_priority:
                    set_interface_priority = list(set_interface_priority) if type(set_interface_priority) is list else [set_interface_priority]
                if not set_interface_priority:

                    if config_cmd != 'no':
                        for intf in set_interface:
                            if 'null' not in intf:
                                egress_dict = dict()
                                egress_dict['config'] = dict()
                                egress_dict['intf-name'] = intf
                                egress_dict['config']['intf-name'] = intf
                                section_dict['forwarding']['egress-interfaces']['egress-interface'].append(egress_dict)
                            else:
                                section_dict['forwarding']['config']['discard'] = True
                                #section_dict['forwarding']['next-hops']['next-hop'].append(nexthop_dict)
                    else:
                        null_str = 'DEFAULT_PACKET_ACTION'
                        for intf in set_interface:
                            if 'null' not in intf:
                                delete_url = rest_url + '={}'.format(intf)
                            else:
                                delete_url = delete_base_url + null_str
                            response = delete_rest(dut, rest_url=delete_url)
                            if not response:
                                return False
                else:
                    if config_cmd != 'no':
                        for intf, priority in zip(set_interface, set_interface_priority):
                            if 'null' not in intf:
                                egress_dict = dict()
                                egress_dict['config'] = dict()
                                egress_dict['intf-name'] = intf
                                egress_dict['config']['intf-name'] = intf
                                egress_dict['config']['priority'] = priority
                                section_dict['forwarding']['egress-interfaces']['egress-interface'].append(egress_dict)
                            else:
                                section_dict['forwarding']['config']['discard'] = False
                                section_dict['forwarding']['next-hops']['next-hop'].append(nexthop_dict)
                    else:
                        for intf,priority in zip(set_interface,set_interface_priority):
                            delete_url = delete_base_url + interface_str + '={},{}'.format(intf, priority)
                            response = delete_rest(dut, rest_url=delete_url)
                            if not response:
                                 return False
            elif set_action and 'police' in set_action:
                 if 'priority_value_1' in flow_data:
                    flow_data['cir'] = str(flow_data['priority_value_1'])
                    flow_data['cbs'] = str(flow_data['priority_value_2'])
                    flow_data['pir'] = str(flow_data['priority_value_3'])
                    flow_data['pbs'] = str(flow_data['priority_value_4'])
                 if config_cmd == '':
                     section_dict['qos']['policer']['config']['cir'] = flow_data['cir']
                     section_dict['qos']['policer']['config']['pir'] = flow_data['pir']
                     section_dict['qos']['policer']['config']['cbs'] = flow_data['cbs']
                     section_dict['qos']['policer']['config']['pbs'] = flow_data['pbs']
                 else:
                     ocdata = {"openconfig-fbs-ext:config":{}}
                     response = config_rest(dut, http_method='rest-put', rest_url=delete_oc_url + '/qos/policer/config',
                                            json_data=ocdata)
                     if not response:
                         return False
            elif set_action and 'dscp' in set_action:
                if '--no' not in set_action:
                    section_dict['qos']['remark']['config']['set-dscp'] = int(flow_data['priority_value'])
                else:
                    response = delete_rest(dut,rest_url=delete_oc_url+'/qos/remark/config/set-dscp')
                    if not response:
                        return False

            elif set_action and 'pcp' in set_action:
                if '--no' not in set_action:
                    section_dict['qos']['remark']['config']['set-dot1p'] = int(flow_data['priority_value'])
                else:
                    response = delete_rest(dut,rest_url=delete_oc_url+'/qos/remark/config/set-dot1p')
                    if not response:
                        return False
            elif set_action and 'traffic_class' in set_action:
                if config_cmd != 'no':
                    section_dict['qos']['queuing']['config']['output-queue-index'] = traffic_class
                else:
                    response = delete_rest(dut,rest_url= delete_oc_url+'/qos/queuing/config/output-queue-index')
                    if not response:
                        return False
            elif set_action and "mirror-session" in set_action:
                rest_url = delete_oc_url + '/monitoring/mirror-sessions/mirror-session'
                if config_cmd != 'no':
                    monitoring_dict['session-name'] = flow_data['priority_value']
                    monitoring_dict['config']['session-name'] = flow_data['priority_value']
                    section_dict['monitoring']['mirror-sessions']['mirror-session'].append(monitoring_dict)
                else:
                    response = delete_rest(dut,rest_url=rest_url)
                    if not response:
                        return False


            if section_dict['config'] == {}: del section_dict['config']
            if section_dict['qos']['remark']['config'] == {}: del section_dict['qos']['remark']['config']
            if section_dict['qos']['remark'] == {}: del section_dict['qos']['remark']
            if section_dict['qos']['policer']['config'] == {}:del section_dict['qos']['policer']['config']
            if section_dict['qos']['policer'] == {}: del section_dict['qos']['policer']
            if section_dict['qos']['queuing']['config'] == {}: del section_dict['qos']['queuing']['config']
            if section_dict['qos']['queuing'] == {}: del section_dict['qos']['queuing']
            if section_dict['qos'] == {}: del section_dict['qos']
            if section_dict['monitoring']['mirror-sessions']['mirror-session'] == []:del section_dict['monitoring']['mirror-sessions']['mirror-session']
            if section_dict['monitoring']['mirror-sessions'] == {}: del section_dict['monitoring']['mirror-sessions']
            if section_dict['monitoring'] == {}: del section_dict['monitoring']
            if monitoring_dict['config'] == {}:del monitoring_dict['config']
            if section_dict['forwarding']['egress-interfaces']['egress-interface'] == []:del section_dict['forwarding']['egress-interfaces']['egress-interface']
            if section_dict['forwarding']['egress-interfaces'] == {}: del section_dict['forwarding']['egress-interfaces']
            if section_dict['forwarding']['config'] == {}: del section_dict['forwarding']['config']
            if egress_dict['config'] == {}:del egress_dict['config']
            if section_dict['forwarding']['next-hops']['next-hop'] == []: del section_dict['forwarding']['next-hops'][
                'next-hop']
            if section_dict['forwarding']['next-hops'] == {}:del section_dict['forwarding']['next-hops']
            if nexthop_dict['config'] == {}:del nexthop_dict['config']
            if section_dict['forwarding'] == {}: del section_dict['forwarding']

            ocdata["openconfig-fbs-ext:sections"]['section'].append(section_dict)
            if config_cmd != 'no':
                if len(ocdata["openconfig-fbs-ext:sections"]['section']) > 0:
                    response = config_rest(dut,http_method=http_method,rest_url=base_url,json_data=ocdata)
                    if not response:
                        return False
        else:
            response = delete_rest(dut,rest_url=delete_oc_url)
            if not response:
                return False
        return True
    else:
        st.error("Invalid config command selection")
        return False

    return True


def config_service_policy_table(dut, skip_error=False, **kwargs):
    """
    Creating to update the classifier table
    Author: prudviraj k (prudviraj.kristipati@broadcom.com)
    :param dut:
    :param kwargs: Needed arguments to update the  service_policy table
    :return:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    service_data = kwargs
    policy_type = kwargs.get('policy_type', 'qos')
    if not service_data:
        st.error("service policy data failed because of invalid data ..")
    if cli_type == "click":
        if service_data['policy_kind'] == "bind":
            command = "config service-policy bind {} {} {} {}".format(service_data['interface_name'], policy_type,
                                                                       service_data['stage'],
                                                                       service_data['service_policy_name'])
            out = st.config(dut, command, type='click', skip_error_check=skip_error)
            if re.search(r'Error: Another policy.*', out):
                return False
            elif "Failed" in out or "Error" in out:
                return False
        elif service_data['policy_kind'] == "unbind":
            command = "config service-policy unbind {} {} {}".format(service_data['interface_name'], policy_type,
                                                                      service_data['stage'])
            st.config(dut, command, type='click')
        elif service_data['policy_kind'] == "clear_policy":
            command = "show service-policy policy {} -c".format(service_data['service_policy_name'])
            st.config(dut, command, type='click', skip_error_check=skip_error)
        elif service_data['policy_kind'] == "clear_interface":
            command = "show service-policy interface {} -c".format(service_data['interface_name'])
            st.config(dut, command, type='click')
    elif cli_type == 'klish':
        interface = kwargs.get('interface_name', None)
        direction = 'in' if policy_type != 'qos' else kwargs.get('stage','in')
        policy_name = kwargs.get('service_policy_name', '')

        command = list()
        if service_data['policy_kind'] == "clear_policy":
            command.append("clear counters service-policy policy-map {}".format(policy_name))
            st.config(dut, command, type='klish',conf=False,skip_error_check=skip_error)
        elif service_data['policy_kind'] == "clear_interface":
            interface = get_interface_number_from_name(interface)
            if isinstance(interface, dict):
                command.append("clear counters service-policy interface {} {}".format(interface['type'], interface['number']))
            else:
                command.append("clear counters service-policy interface {}".format(interface))
            st.config(dut, command, type='klish', conf=False,skip_error_check=skip_error)
        else:
            if kwargs['policy_kind'] == 'unbind':
                config_cmd = 'no'
                policy_name = ''
            elif kwargs['policy_kind'] == 'bind':
                config_cmd = ''
            if interface:
                if interface != 'Switch':
                    interface_details = get_interface_number_from_name(interface)
                    command.append("interface {} {}".format(interface_details.get("type"),
                                                          interface_details.get("number")))
                command.append('{} service-policy type {} {} {}\n'.format(config_cmd, policy_type, direction, policy_name))
                out = st.config(dut, command, type='klish', skip_error_check=skip_error)
                if re.search(r'Error.*', out):
                    if interface and interface != "Switch":
                        st.config(dut, "exit", type="klish")
                    return False
                if interface and interface != "Switch":
                    st.config(dut, "exit", type="klish", skip_error_check=skip_error)
            else:
                command.append('{} service-policy type {} {} {}'.format(config_cmd, policy_type, direction, policy_name))
                out =st.config(dut, command, type='klish', skip_error_check=skip_error)
                if re.search(r'Error.*', out):
                    return False
    elif cli_type in ['rest-patch','rest-put']:
        http_method = kwargs.get('http_mathod',cli_type)
        interface = kwargs.get('interface_name',None)
        policy_type = kwargs.get('policy_type','qos')
        direction = kwargs.get('stage','in')
        policy_name = kwargs.get('service_policy_name','')
        rest_urls = st.get_datastore(dut,'rest_urls')
        stage = 'ingress' if direction == 'in' else 'egress'
        if service_data['policy_kind'] == "clear_policy":
            rest_url = rest_urls['clear_service_policy_counters']
            ocdata = {"sonic-flow-based-services:input": {"POLICY_NAME": policy_name}}
            response = config_rest(dut, http_method='post', rest_url=rest_url, json_data=ocdata)
            if not response:
                st.log(response)
                return False
        elif service_data['policy_kind'] == "clear_interface":
            rest_url = rest_urls['clear_service_policy_counters']
            ocdata = {"sonic-flow-based-services:input": {"INTERFACE_NAME": interface}}
            response = config_rest(dut, http_method='post', rest_url=rest_url, json_data=ocdata)
            if not response:
                return False
        else:
            intf = interface if interface else 'Switch'
            rest_url = rest_urls['service_policy_bind_unbind'].format(intf,stage,policy_type)
            if kwargs['policy_kind'] == 'unbind':
                response = delete_rest(dut,rest_url=rest_url)
                if not response:
                    return False
            elif kwargs['policy_kind'] == 'bind':
                rest_url = rest_urls['service_policy_bind_unbind'].format(intf, stage, policy_type)
                ocdata = {"openconfig-fbs-ext:{}".format(policy_type): {'config': {'policy-name':policy_name} }}
                response = config_rest(dut, http_method=http_method, rest_url=rest_url, json_data=ocdata)
                if not response:
                    return False
        return True
    else:
        st.error("Invalid config command selection")
        return False

    return True


def show(dut,*argv,**kwargs):
    """
    show commands summary
    Author: prudviraj k (prudviraj.kristipati@broadcom.com)
    :param dut:
    :param kwargs:
    :param classifier:
    :param match_type:
    :param class_name:
    :param policy_name:
    :param interface_name:
    :param servie_policy_summary:
    :return:
    """
    rest_urls = st.get_datastore(dut, "rest_urls")
    cli_type = kwargs.get("cli_type",st.get_ui_type(dut,**kwargs))
    input_data = {}
    yang_model = kwargs.pop('yang_model','ocyang')

    if "classifier" in argv:
        command = "show class-map" if cli_type == 'klish' else "show classifier"
        rest_url =rest_urls['show_classifier_{}'.format(yang_model)]
        input_data = {"sonic-flow-based-services:input": {}}
        parse_type='CLASSIFIERS'
    elif 'match_type' in kwargs:
        if cli_type == 'click':
            command = "show classifier -m {} {}".format(kwargs['match_type'], kwargs['class_name'])
        elif cli_type == 'klish':
            command = "show class-map match-type {}".format(kwargs['match_type'])
        if 'class_name' in kwargs:
           rest_url = rest_urls['show_classifier_sonic'] if yang_model == 'sonic' \
                else rest_urls['show_classifier_name_ocyang'].format(kwargs['class_name'])
        else:
            rest_url = rest_urls['show_classifier_{}'.format(yang_model)]
        input_data = {"sonic-flow-based-services:input":{"MATCH_TYPE":kwargs['match_type'].upper()}}
        parse_type = 'CLASSIFIERS'
    elif 'policy' in argv:
        command = "show policy" if cli_type == 'click' else "show policy-map"
        rest_url = rest_urls['show_policy_{}'.format(yang_model)]
        input_data = {"sonic-flow-based-services:input":{}}
        parse_type = 'POLICIES'
    elif 'policy_name' in kwargs:
        command = "show policy {}".format(kwargs['policy_name']) if cli_type == 'click' else "show policy-map {}".format(kwargs['policy_name'])
        rest_url = rest_urls['show_policy_sonic'] if yang_model =='sonic' else rest_urls['show_policy_id_ocyang'].format(kwargs['policy_name'])
        input_data = {"sonic-flow-based-services:input":{"POLICY_NAME":kwargs['policy_name']}}
        parse_type = 'POLICIES'
    elif 'service_policy_name' in kwargs:
        yang_model='sonic'
        if cli_type == 'click':
            command = "show service-policy policy {}".format(kwargs['service_policy_name'])
        else:
            command = "show service-policy policy-map {}".format(kwargs['service_policy_name'])
        rest_url = rest_urls['show_service_policy_sonic']
        input_data = {"sonic-flow-based-services:input":{"POLICY_NAME":kwargs['service_policy_name']}}
        parse_type = 'INTERFACES'
    elif 'interface_name' in kwargs:
        if cli_type == 'klish':
            if kwargs.get("interface_name") != "Switch":
                interface = get_interface_number_from_name(kwargs['interface_name'])
                command = "show service-policy interface {} {}".format(interface['type'],interface['number'])
            else:
                command = "show service-policy {}".format(kwargs['interface_name'])
        elif cli_type == 'click':
            command = "show service-policy interface {}".format(kwargs['interface_name'])
        rest_url = rest_urls['show_service_policy_sonic'] if yang_model =='sonic' \
            else rest_urls['show_service_policy_ocyang'].format(kwargs['interface_name'])
        input_data = {"sonic-flow-based-services:input":{"INTERFACE_NAME":kwargs['interface_name']}}
        parse_type = 'INTERFACES'
    elif 'service_policy_summary' in argv:
        command = "show service-policy summary"
        rest_url = rest_urls['show_service_policy_summary']
        input_data = None
        parse_type = 'SUMMARY'
    else:
        st.error("incorrect arguments given for the show")
        return False

    if 'rest' in cli_type:
        if input_data:
            if yang_model == 'ocyang':
                output = get_rest(dut,rest_url=rest_url)['output']
            else:
                output =  st.rest_create(dut,path=rest_url,data=input_data)['output'].get('sonic-flow-based-services:output',{})
                st.log(output)
            output = convert_rest_key_to_template(parse_type,output,yang_model=yang_model,**kwargs)
            return output
        else:
            output = st.rest_read(dut,path=rest_url)['output'].get('sonic-flow-based-services:POLICY_BINDING_TABLE_LIST',[])
            st.log(output)
            output = convert_rest_key_to_template(parse_type,output,yang_model=yang_model,**kwargs)
            return output

    output = st.show(dut, command, type=cli_type)
    return output


def get(dut, *argv, **kwargs):
    """
    To Get counters matched from show service-policy interface
    Author : prudviraj k (prudviraj.kristipati@broadcom.com)

    :param dut:
    :return:
    """
    output = show(dut, *argv, **kwargs)
    st.log(output)
    entries = filter_and_select(output, [kwargs["value"]])
    if entries:
        if not kwargs.get("full_output"):
            return entries[0][kwargs['value']]
        else:
            return entries



def verify(dut,*argv,**kwargs):
    """
    show commands summary
    Author: prudviraj k (prudviraj.kristipati@broadcom.com)
    :param dut:
    :param kwargs:
    :param :verify_list:
    :return:
    """
    result = True
    yang_model = 'ocyang'
    cli_type = kwargs.get("cli_type", st.get_ui_type(dut,**kwargs))
    for item in kwargs['verify_list']:
        if 'classifier' in kwargs or 'class_name' in kwargs or 'match_type' in kwargs:
            if 'policy_name' in item.keys() or 'priority_val' in item.keys():
                yang_model = 'sonic'
        elif 'policy' in argv or 'policy_name' in kwargs:
            if 'interface' in item.keys() or 'stage' in item.keys():
                yang_model = 'sonic'
    if "classifier" in argv:
        output = show(dut,'classifier',yang_model=yang_model,cli_type=cli_type)
    elif 'match_type' in kwargs and 'class_name' in kwargs:
        output = show(dut, match_type=kwargs['match_type'],class_name=kwargs['class_name'],yang_model=yang_model,cli_type=cli_type)
    elif 'match_type' in kwargs and 'class_name' not in kwargs:
        output = show(dut, match_type=kwargs['match_type'],yang_model=yang_model,cli_type=cli_type)
    elif 'policy_name' in kwargs:
        output = show(dut, policy_name=kwargs['policy_name'],yang_model=yang_model,cli_type=cli_type)
    elif 'policy' in argv:
        output = show(dut,'policy',yang_model=yang_model,cli_type=cli_type)
    elif 'service_policy_name' in kwargs:
        yang_model = 'sonic'
        output = show(dut, service_policy_name=kwargs['service_policy_name'],yang_model=yang_model,cli_type=cli_type)
    elif 'service_policy_interface' in kwargs:
        output = show(dut, interface_name=kwargs['service_policy_interface'],yang_model=yang_model,cli_type=cli_type)
    elif 'service_policy_summary' in argv:
        output = show(dut, 'service_policy_summary', cli_type=cli_type)
    else:
        st.error("incorrect arguments given for verification")
        return False

    if 'rest' in cli_type and yang_model =='sonic':
        if 'classifier' in argv or 'match_type' in kwargs:
            for each,index in zip(kwargs['verify_list'],range(len(kwargs['verify_list']))):
                if 'tcp_flags_type' in each.keys():
                    kwargs['verify_list'][index]['tcp_flags_type'] = convert_tcp_flags_to_hex(each['tcp_flags_type'])

    for each in kwargs['verify_list']:
        if not filter_and_select(output, None, each):
            st.log("{} is not matching in the output \n {}".format(each, output))
            result = False
    return result


def convert_rest_key_to_template(type,output,yang_model='ocyang',**kwargs):
    transformed_output_list = []
    if type == 'CLASSIFIERS' and yang_model == 'sonic':
        for item in output.get('CLASSIFIERS',[]):
            transformed_output = {}
            transformed_output['class_name'] = item.pop('CLASSIFIER_NAME', '')
            transformed_output['acl_name'] = item.pop('ACL_NAME', '')
            transformed_output['match_type'] = item.pop('MATCH_TYPE', '').lower()
            transformed_output['desc_name'] = item.pop('DESCRIPTION', '')
            transformed_output['field_value'] = item.pop('ETHER_TYPE', '').lower()
            transformed_output['src_port_val'] = item.pop('L4_SRC_PORT', '')
            transformed_output['dst_port_val'] = item.pop('L4_DST_PORT', '')
            transformed_output['src_ip_val'] = item.pop('SRC_IP', '')
            transformed_output['dst_ip_val'] = item.pop('DST_IP', '')
            transformed_output['src_mac_val'] = item.pop('SRC_MAC', '')
            transformed_output['dst_mac_val'] = item.pop('DST_MAC', '')
            transformed_output['src_ipv6_val'] = item.pop('SRC_IPV6', '')
            transformed_output['dst_ipv6_val'] = item.pop('DST_IPV6', '')
            transformed_output['tcp_flags_type'] = item.pop('TCP_FLAGS', '')
            ip_protocol_val = item.pop('IP_PROTOCOL', '')
            if ip_protocol_val:
                transformed_output['ip_protocol_val'] = 'tcp' if str(ip_protocol_val) == '6' else 'udp'
            reference = item.pop('REFERENCES', [])
            for index in range(len(reference)):
                transformed_output1 = transformed_output.copy()
                transformed_output1['policy_name'] = reference[index].pop('POLICY_NAME', '')
                transformed_output1['priority_val'] = reference[index].pop('PRIORITY', '')
                transformed_output_list.append(transformed_output1)
            if not (ip_protocol_val and len(reference)):
                transformed_output_list.append(transformed_output)
    elif type == 'CLASSIFIERS' and yang_model =='ocyang':
        output = output.get('openconfig-fbs-ext:classifier',[]) if 'class_name' in kwargs else \
            output.get('openconfig-fbs-ext:classifiers',{}).get('classifier',[])
        for item in output:
            transformed_output = {}
            transformed_output['class_name'] = item.get('state',{}).get('name','')
            transformed_output['acl_name'] = item.get('match-acl',{}).get('acl-name','')
            match_type = item.get('state', {}).get('match-type','').lower().split('_')
            transformed_output['match_type'] = '' if len(match_type) ==  0 else match_type[1]
            transformed_output['desc_name'] = item.get('state',{}).get('description', '')
            transformed_output['field_value'] = item.get('match-hdr-fields',{}).get('l2',{}).get('state',{}).get('ethertype', '')
            if transformed_output['field_value']:
                if 'openconfig-packet-match' in transformed_output['field_value']:
                    transformed_output['field_value'] = transformed_output['field_value'].split('_')[1]
                else:
                    transformed_output['field_value'] = hex(int(transformed_output['field_value']))
            transformed_output['src_port_val'] = item.get('match-hdr-fields',{}).get('transport',{}).get('state',{}).get('source-port', '')
            transformed_output['dst_port_val'] = item.get('match-hdr-fields',{}).get('transport',{}).get('state',{}).get('destination-port', '')
            transformed_output['src_ip_val'] = item.get('match-hdr-fields',{}).get('ipv4',{}).get('state',{}).get('source-address', '')
            transformed_output['dst_ip_val'] = item.get('match-hdr-fields',{}).get('ipv4',{}).get('state',{}).get('destination-address', '')
            transformed_output['src_mac_val'] = item.get('match-hdr-fields',{}).get('l2',{}).get('state',{}).get('source-mac', '')
            transformed_output['dst_mac_val'] = item.get('match-hdr-fields',{}).get('l2',{}).get('state',{}).get('destination-mac', '')
            transformed_output['src_ipv6_val'] = item.get('match-hdr-fields',{}).get('ipv6',{}).get('state',{}).get('source-address', '')
            transformed_output['dst_ipv6_val'] = item.get('match-hdr-fields',{}).get('ipv6',{}).get('state',{}).get('destination-address', '')
            tcp_flag_type = item.get('match-hdr-fields',{}).get('transport',{}).get('state',{}).get('tcp-flags', [])
            if tcp_flag_type:
                tcp_flags = ''
                for flag in tcp_flag_type:
                    flag = flag.split(':')[1]
                    if 'TCP_NOT_' not in flag:
                        if tcp_flags: tcp_flags+=' '
                        tcp_flags += flag.replace('TCP_','').lower()
                    else:
                        if tcp_flags: tcp_flags += ' '
                        tcp_flags += flag.replace('TCP_NOT_','no-').lower()
                transformed_output['tcp_flags_type'] = tcp_flags
            else:
                transformed_output['tcp_flags_type'] = ''
            ip_protocol_val = item.get('match-hdr-fields',{}).get('ip',{}).get('state',{}).get('protocol', '')
            if ip_protocol_val:
                transformed_output['ip_protocol_val'] = 'tcp' if 'IP_TCP' in str(ip_protocol_val) else 'udp'
            else:
                transformed_output['ip_protocol_val'] = ''
            transformed_output_list.append(transformed_output)
    elif type == 'POLICIES' and yang_model == 'sonic':
        for item in output.get('POLICIES',[]):
            ip_next_hop = ipv6_next_hop = egress_interface = ""
            default_packet_action = False
            transformed_output = {}
            transformed_output['policy_name'] = item.pop("POLICY_NAME", '')
            transformed_output['policy_type'] = item.pop("TYPE", '').lower()
            transformed_output['desc_name'] = item.pop("DESCRIPTION", '')
            flows = item.pop('FLOWS', [])
            for flow_index in range(len(flows)):
                transformed_output['class_name'] = flows[flow_index].get("CLASS_NAME", '')
                transformed_output['priority_val'] = flows[flow_index].get("PRIORITY", '')
                transformed_output['dscp_val'] = flows[flow_index].get('SET_DSCP','')
                transformed_output['pcp_val'] = flows[flow_index].get('SET_PCP', '')
                transformed_output['mirror_session'] = flows[flow_index].get("SET_MIRROR_SESSION", '')
                ip_next_hop = flows[flow_index].pop("SET_IP_NEXTHOP", [])
                if ip_next_hop:
                    for nh_index in range(len(ip_next_hop)):
                        transformed_output1 = transformed_output.copy()
                        transformed_output1['next_hop'] = ip_next_hop[nh_index].get('IP_ADDRESS', '')
                        transformed_output1['next_hop_vrf'] = ip_next_hop[nh_index].get('VRF', '')
                        transformed_output1['next_hop_priority'] = ip_next_hop[nh_index].get('PRIORITY', '')
                        transformed_output_list.append(transformed_output1)
                ipv6_next_hop = flows[flow_index].pop("SET_IPV6_NEXTHOP", [])
                if ipv6_next_hop:
                    for nh_index in range(len(ipv6_next_hop)):
                        transformed_output2 = transformed_output.copy()
                        transformed_output2['next_hop'] = ipv6_next_hop[nh_index].get('IP_ADDRESS', '')
                        transformed_output2['next_hop_vrf'] = ipv6_next_hop[nh_index].get('VRF', '')
                        transformed_output2['next_hop_priority'] = ipv6_next_hop[nh_index].get('PRIORITY', '')
                        transformed_output_list.append(transformed_output2)
                egress_interface = flows[flow_index].pop("SET_INTERFACE", [])
                if egress_interface:
                    for nh_index in range(len(egress_interface)):
                        transformed_output3 = transformed_output.copy()
                        transformed_output3['next_hop_interface'] = egress_interface[nh_index].get('INTERFACE', '')
                        transformed_output3['interface_priority'] = egress_interface[nh_index].get('PRIORITY', '')
                        transformed_output_list.append(transformed_output3)

                if 'DEFAULT_PACKET_ACTION' in flows[flow_index].keys():
                    default_packet_action = True
                    transformed_output4 = transformed_output.copy()
                    transformed_output4['next_hop_interface'] = 'null'
                    transformed_output_list.append(transformed_output4)

            applied_ports = item.pop('APPLIED_INTERFACES',[])
            for port_index in range(len(applied_ports)):
                transformed_output5 = transformed_output.copy()
                transformed_output5['interface'] = applied_ports[port_index].get("INTERFACE_NAME",'')
                transformed_output5['stage'] = applied_ports[port_index].get("STAGE",'').capitalize()
                transformed_output_list.append(transformed_output5)

            if not (len(applied_ports) and ip_next_hop and ipv6_next_hop and egress_interface and default_packet_action):
                transformed_output_list.append(transformed_output)
    elif type == 'POLICIES' and yang_model == 'ocyang':
        for item in output.get('openconfig-fbs-ext:policy',[]):
            transformed_output = {}
            transformed_output['policy_name'] = item.get('state',{}).get("name", '')
            policy_type = item.get('state',{}).get("type", '').lower()
            if 'openconfig-fbs-ext' in policy_type:
                transformed_output['policy_type'] = policy_type.split('_')[1]
            else:
                transformed_output['policy_type'] = ''
            transformed_output['desc_name'] = item.get('state',{}).get("description", '')
            flows = item.get('sections',{}).get('section', [])
            for flow_index in range(len(flows)):
                transformed_output['class_name'] = flows[flow_index].get('state',{}).get("name", '')
                transformed_output['priority_val'] = flows[flow_index].get('state',{}).get("priority", '')
                transformed_output['dscp_val'] = flows[flow_index].get('qos',{}).get('state',{}).get('set-dscp','')
                transformed_output['pcp_val'] = flows[flow_index].get('qos',{}).get('state',{}).get('set-dot1p','')
                mirror_session = flows[flow_index].get('monitoring',{}).get('mirror-sessions',{}).get('mirror-session',[])
                if mirror_session:
                    transformed_output['mirror_session'] = mirror_session[0]
                else:
                    transformed_output['mirror_session'] = ''
                ip_next_hop = flows[flow_index].get('forwarding',{}).get('next-hops', {}).get('next-hop',[])
                if ip_next_hop:
                    for nh_index in range(len(ip_next_hop)):
                        transformed_output1 = transformed_output.copy()
                        transformed_output1['next_hop'] = ip_next_hop[nh_index].get('state',{}).get('ip-address', '')
                        next_hop_vrf = ip_next_hop[nh_index].get('state',{}).get('network-instance', '')
                        if 'openconfig-fbs-ext' in next_hop_vrf:
                            next_hop_vrf = next_hop_vrf.split('_')[1]
                            if 'NETWORK' in next_hop_vrf:next_hop_vrf=''
                        transformed_output1['next_hop_vrf'] =  next_hop_vrf
                        transformed_output1['next_hop_priority'] = ip_next_hop[nh_index].get('state',{}).get('priority', '')
                        transformed_output_list.append(transformed_output1)
                egress_interface = flows[flow_index].get('forwarding',{}).get('egress-interfaces', {}).get('egress-interface',[])
                if egress_interface:
                    for nh_index in range(len(egress_interface)):
                        transformed_output3 = transformed_output.copy()
                        transformed_output3['next_hop_interface'] = egress_interface[nh_index].get('state',{}).get('intf-name', '')
                        transformed_output3['interface_priority'] = egress_interface[nh_index].get('state',{}).get('priority', '')
                        transformed_output_list.append(transformed_output3)

                discard_action = flows[flow_index].get('forwarding',{}).get('config',{}).get('discard',False)
                if discard_action:
                    #default_packet_action = True
                    transformed_output4 = transformed_output.copy()
                    transformed_output4['next_hop_interface'] = 'null'
                    transformed_output_list.append(transformed_output4)
            transformed_output_list.append(transformed_output)
    elif type == 'INTERFACES' and yang_model =='sonic':
        transformed_output = {}
        for item in output.get('INTERFACES',[]):
            transformed_output['interface_name'] = item.pop('INTERFACE_NAME','')
            policy_list = item.pop("APPLIED_POLICIES",[])
            default_packet_action = False
            if policy_list:
              for index in range(len(policy_list)):
                transformed_output1 = transformed_output.copy()
                transformed_output1['policy_name'] = policy_list[index].pop('POLICY_NAME','')
                transformed_output1['policy_type'] = policy_list[index].pop('TYPE','').lower()
                transformed_output1['stage'] = policy_list[index].pop('STAGE','').lower()
                transformed_output_list.append(transformed_output1)
                default_packet_action = True

                flows = policy_list[index].pop('FLOWS',[])
                if flows:
                  for flow_index in range(len(flows)):
                    default_flow_action = False
                    transformed_output2 = transformed_output1.copy()
                    transformed_output2['class_name'] = flows[flow_index].get("CLASS_NAME", '')
                    transformed_output2['priority_val'] = flows[flow_index].get("PRIORITY", '')
                    transformed_output2['dscp_val'] = flows[flow_index].get("SET_DSCP", '')
                    transformed_output2['pcp_val'] = flows[flow_index].get("SET_PCP", '')
                    transformed_output2['mirror_session'] = flows[flow_index].get("SET_MIRROR_SESSION", '')
                    transformed_output2['cir_val'] = flows[flow_index].get("SET_POLICER_CIR", '')
                    transformed_output2['cbs_val'] = flows[flow_index].get("SET_POLICER_CBS", '')
                    transformed_output2['pir_val'] = flows[flow_index].get("SET_POLICER_PIR", '')
                    transformed_output2['pbs_val'] = flows[flow_index].get("SET_POLICER_PBS", '')
                    transformed_output2['tc_val'] = flows[flow_index].get("SET_TC", '')

                    state = flows[flow_index].pop("STATE", '')
                    selected_dict = {}
                    if state:
                        transformed_output3 = transformed_output2.copy()
                        flow_state = state.get('STATUS', '')
                        transformed_output3['flow_state'] = '('+str(flow_state)+')'
                        transformed_output3['match_pkts_val'] = state.get('MATCHED_PACKETS', '')
                        transformed_output3['match_bytes_val'] = state.get('MATCHED_BYTES', '')
                        selected_entry = state.get('FORWARDING_SELECTED',{})
                        selected_dict['next_hop'] = selected_entry.get('IP_ADDRESS','')
                        selected_dict['next_hop_vrf'] = selected_entry.get('VRF','')
                        selected_dict['next_hop_priority'] = selected_entry.get('PRIORITY','')
                        selected_dict['next_hop_interface'] = selected_entry.get('INTERFACE_NAME')
                        selected_dict['null'] = selected_entry.get('PACKET_ACTION','')
                        transformed_output_list.append(transformed_output3)
                        default_packet_action = default_flow_action = True
                    ip_next_hop = flows[flow_index].pop("SET_IP_NEXTHOP", [])
                    if ip_next_hop:
                        for nh_index in range(len(ip_next_hop)):
                            transformed_output4 = transformed_output3.copy()
                            transformed_output4['next_hop'] = ip_next_hop[nh_index].get('IP_ADDRESS', '')
                            transformed_output4['next_hop_vrf'] = ip_next_hop[nh_index].get('VRF', '')
                            transformed_output4['next_hop_priority'] = ip_next_hop[nh_index].get('PRIORITY', '')
                            if selected_dict['next_hop'] == transformed_output4['next_hop'] and selected_dict['next_hop_vrf'] == transformed_output4['next_hop_vrf']:
                              transformed_output4['selected'] = 'Selected'
                            transformed_output_list.append(transformed_output4)
                            default_packet_action = default_flow_action = True
                    ipv6_next_hop = flows[flow_index].pop("SET_IPV6_NEXTHOP", [])
                    if ipv6_next_hop:
                        for nh_index in range(len(ipv6_next_hop)):
                            transformed_output5 = transformed_output3.copy()
                            transformed_output5['next_hop'] = ipv6_next_hop[nh_index].get('IP_ADDRESS', '')
                            transformed_output5['next_hop_vrf'] = ipv6_next_hop[nh_index].get('VRF', '')
                            transformed_output5['next_hop_priority'] = ipv6_next_hop[nh_index].get('PRIORITY', '')
                            if selected_dict['next_hop'] == transformed_output5['next_hop'] and selected_dict['next_hop_vrf'] == transformed_output5['next_hop_vrf']:
                              transformed_output5['selected'] = 'Selected'
                            transformed_output_list.append(transformed_output5)
                            default_packet_action = default_flow_action = True
                    egress_interface = flows[flow_index].pop("SET_INTERFACE", [])
                    if egress_interface:
                        for nh_index in range(len(egress_interface)):
                            transformed_output6 = transformed_output3.copy()
                            transformed_output6['next_hop_interface'] = egress_interface[nh_index].get('INTERFACE', '')
                            transformed_output6['interface_priority'] = egress_interface[nh_index].get('PRIORITY', '')
                            if selected_dict['next_hop_interface'] == transformed_output6['next_hop_interface'] and selected_dict['next_hop_priority'] == transformed_output6['interface_priority']:
                              transformed_output6['selected'] = 'Selected'
                            transformed_output_list.append(transformed_output6)
                            default_packet_action = default_flow_action = True

                    if 'DEFAULT_PACKET_ACTION' in flows[flow_index].keys():
                        transformed_output7 = transformed_output3.copy()
                        transformed_output7['next_hop_interface'] = 'null'
                        if selected_dict['null'] == 'DROP':
                          transformed_output7['selected'] = 'Selected'
                        transformed_output_list.append(transformed_output7)
                        default_packet_action = default_flow_action = True
                    if not default_flow_action:
                        transformed_output_list.append(transformed_output2)
                        default_packet_action = True
            if not default_packet_action:
                transformed_output_list.append(transformed_output)
    elif type == 'INTERFACES' and yang_model == 'ocyang':
        transformed_output1 = {}
        for item in output.get('openconfig-fbs-ext:interface',[]):
          transformed_output1['interface_name'] = item.get('state',{}).get('id','')
          for direction in ['ingress','egress']:
              for policy_type in item.get("{}-policies".format(direction),{}).keys():
                transformed_output1['policy_name'] = item.get('{}-policies'.format(direction),{}).get(policy_type,{}).get('state',{}).get('policy-name','')
                transformed_output1['policy_type'] = policy_type
                transformed_output1['stage'] = direction
                transformed_output_list.append(transformed_output1)

                flows = item.get('{}-policies'.format(direction),{}).get(policy_type,{}).get('sections',{}).get('section',[])
                if flows:
                  for flow_index in range(len(flows)):
                    #default_flow_action = False
                    transformed_output2 = transformed_output1.copy()
                    transformed_output2['class_name'] = flows[flow_index].get('state',{}).get("class-name", '')
                    transformed_output2['cir_val'] = flows[flow_index].get('state',{}).get("cir", '')
                    transformed_output2['cbs_val'] = flows[flow_index].get('state',{}).get("cbs", '')
                    transformed_output2['pir_val'] = flows[flow_index].get('state',{}).get("pir", '')
                    transformed_output2['pbs_val'] = flows[flow_index].get('state',{}).get("pbs", '')
                    discard = flows[flow_index].get('state', {}).get("discard", False)

                    flow_state = flows[flow_index].get('state',{}).get("active",False)
                    if flow_state:
                        transformed_output2['flow_state'] = '(Active)'
                    else:
                        transformed_output2['flow_state'] = '(Inactive)'
                    transformed_output2['match_pkts_val'] = flows[flow_index].get('state',{}).get("matched-packets", '0')
                    transformed_output2['match_bytes_val'] = flows[flow_index].get('state',{}).get("matched-octets", '0')
                    transformed_output2['next_hop'] = flows[flow_index].get('next-hop',{}).get('state',{}).get('ip-address','')
                    transformed_output2['next_hop_vrf'] = flows[flow_index].get('next-hop',{}).get('state',{}).get('network-instance','')
                    transformed_output2['next_hop_priority'] = flows[flow_index].get('next-hop',{}).get('state',{}).get('priority','')
                    transformed_output2['next_hop_interface'] = flows[flow_index].get('egress-interface',{}).get('state',{}).get('intf-name','')
                    transformed_output2['selected'] = 'Selected'
                    if discard:
                        transformed_output2['next_hop_interface'] = 'null'
                    transformed_output_list.append(transformed_output2)
    elif type =='SUMMARY':
        for item in output:
            transformed_output ={}
            transformed_output['interface_name'] = item.get('INTERFACE_NAME', '')
            for k in item.keys():
                if 'INTERFACE' not in k:
                    match = k.split('_')
                    if match:
                        transformed_output1 = transformed_output.copy()
                        transformed_output1['stage'] = match[0].lower()
                        transformed_output1['policy_type'] = match[1].lower()
                        transformed_output1['policy_name'] = item.pop('{}_{}_POLICY'.format(match[0],match[1]))
                        transformed_output_list.append(transformed_output1)

    return transformed_output_list
