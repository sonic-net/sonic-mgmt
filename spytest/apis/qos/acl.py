# This file contains the list of API's which performs ACL operations.
# Author : Chaitanya Vella (Chaitanya-vella.kumar@broadcom.com) and Prudvi Mangadu (prudvi.mangadu@broadcom.com)
import os
import re
import json
import tempfile
from spytest import st
from spytest.utils import filter_and_select
from apis.system.rest import config_rest, delete_rest, get_rest
import utilities.utils as util_obj

def create_acl_table(dut, acl_type=None, skip_verify=True, **kwargs):
    """
    Create the ACL table
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param kwargs:
    :param skip_verify: True(Default) / False
    :return:
    Ex: Create_acl_table(1, name="DATAACL", stage = "INGRESS", type="L3", description="Testing",
        ports=["Ethernet0", "Ethernet2"])
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    table_name = kwargs.get("table_name") if kwargs.get("table_name") else kwargs.get("name")
    acl_type = acl_type if acl_type else kwargs.get("type")
    if cli_type == "click":
        st.log("Creating ACL table ...")
        acl_data = kwargs
        if acl_type:
            acl_data.update({"type":acl_type})
        if not acl_data:
            st.error("ACL table creation failed because of invalid data ..")
        acl_table_data = dict()
        acl_table = dict()
        acl_table[acl_data["name"]] = dict()
        acl_table[acl_data["name"]]["type"] = acl_data["type"] if 'type' in acl_data else ''
        acl_table[acl_data["name"]]["policy_desc"] = acl_data["description"] if 'description' in acl_data else ''
        acl_table[acl_data["name"]]["ports"] = acl_data["ports"] if 'ports' in acl_data else []
        acl_table[acl_data["name"]]["stage"] = acl_data["stage"] if 'stage' in acl_data else ''
        acl_table_data["ACL_TABLE"] = acl_table
        acl_table_data = json.dumps(acl_table_data)
        json.loads(acl_table_data)
        st.apply_json2(dut, acl_table_data)
        if not skip_verify:
            if not verify_acl_table(dut, acl_data["name"]):
                return False
    elif cli_type == "klish":
        if not table_name or not acl_type:
            st.log("Mandatory parameter table name / acl_type not passed")
            return False
        click_klish_acl_direction_mapping = {"INGRESS": "in", "EGRESS":"out"}
        skip_port_binding = True if "CTRLPLANE" in acl_type else False
        acl_type = acl_type.replace("CTRLPLANE", "")
        if acl_type in ["L3", "L3V6", "L2"]:
            acl_type_mapping = {"L3": "ip", "L3V6": "ipv6", "L2": "mac"}
            acl_type = acl_type_mapping[acl_type]
        if acl_type not in ["ip", "ipv6", "mac"]:
            st.log("UNSUPPORTED ACL TYPES PROVIDED -> {}".format(acl_type))
            return False
        commands = list()
        commands.append("{} access-list {}".format(acl_type, table_name))
        if kwargs.get("description"):
            commands.append("remark \"{}\"".format(kwargs.get("description")))
        if kwargs.get("remark"):
            commands.append("remark \"{}\"".format(kwargs.get("remark")))
        commands.append("exit")
        st.config(dut, commands, type=cli_type, skip_error_check=skip_verify)
        if not skip_port_binding:
            if not kwargs.get("ports"):
                st.error("PORTS ARE MANDATORY FOR CREATING ACCESS GROUP {}".format(table_name))
                return False
            ports = kwargs.get("ports")
            stage = click_klish_acl_direction_mapping[kwargs.get("stage")]
            if not config_access_group(dut, acl_type=acl_type, table_name=table_name, port=ports, access_group_action=stage, cli_type=cli_type):
                st.error("ACCESS GROUP CREATION FAILED FOR ACL TABLE -- {}, INTFS -- {}, DIRECTION -- {}".format(table_name, ports, stage))
                return False
        else:
            if not bind_ctrl_plane(dut, table_name, acl_type):
                st.error("Access group binding failed for table: {}".format(table_name))
                return False

    elif cli_type in ["rest-patch","rest-put"]:
        if not table_name or not acl_type:
            st.log("Mandatory parameter table name / acl_type not passed")
            return False
        skip_port_binding = True if "CTRLPLANE" in acl_type else False
        acl_type = acl_type.replace("CTRLPLANE","")
        if acl_type in ["L3", "L3V6", "L2"]:
            acl_type_mapping = {"L3": "ip", "L3V6": "ipv6", "L2": "mac"}
            acl_type = acl_type_mapping[acl_type]
        if acl_type not in ["ip", "ipv6", "mac"]:
            st.log("UNSUPPORTED ACL TYPES PROVIDED")
            return False
        acl_type_mapping = {"ip": "ACL_IPV4", "ipv6": "ACL_IPV6", "mac": "ACL_L2", "L3": "ACL_IPV4", "L3V6": "ACL_IPV6", "L2": "ACL_L2"}
        acl_type = acl_type_mapping[acl_type]
        rest_urls = st.get_datastore(dut, "rest_urls")
        url = rest_urls['config_acl_table'].format(table_name,acl_type)
        config_table = {"acl-set": [{"config": {"type": acl_type, "name": table_name,"description": table_name},
                                     "type": acl_type, "name": table_name}]}
        if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=config_table):
            return False
        if not skip_port_binding:
            if not kwargs.get("ports"):
                st.error("PORTS ARE MANDATORY FOR CREATING ACCESS GROUP {}".format(table_name))
                return False
            ports = kwargs.get("ports")
            stage = kwargs.get("stage").lower()
            if not config_access_group(dut, acl_type=acl_type, table_name=table_name, port=ports, access_group_action=stage,
                                       cli_type=cli_type):
                st.error("ACCESS GROUP CREATION FAILED FOR ACL TABLE -- {}, INTFS -- {}, DIRECTION -- {}".format(table_name,
                                                                                ports, stage))
                return False
        else:
            if not bind_ctrl_plane(dut, table_name, acl_type):
                st.error("Access group binding failed for table: {}".format(table_name))
                return False
    else:
        st.log("Unsupported CLI TYPE {}".format(cli_type))
        return False
    return True


def create_acl_rule(dut, skip_verify=True, acl_type=None, host_1=None, host_2=None, **kwargs):
    """
    Create the ACL rule
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param kwargs:
    :param skip_verify: True(Default) / False
    :return:
    create_acl_rule(1, table_name="DATAACL",rule_name = "DATARULE", <REST OF THE PARAMETERS CHECK REF LINK>)
    REF: https://github.com/sonic-net/SONiC/wiki/ACL-High-Level-Design -- Follow the rule attributes names from this link
    """
    st.log("KWARGS : {}".format(kwargs))
    cli_type = st.get_ui_type(dut, **kwargs)
    table_name = kwargs.get("table_name", None)
    rule_name = kwargs.get("rule_name", None)
    packet_action = kwargs.get("packet_action", "deny")
    l4_protocol = kwargs.get("ip_protocol", kwargs.get("l4_protocol","tcp"))
    src_ip = kwargs.get("SRC_IP", kwargs.get("src_ip", "any"))
    dst_ip = kwargs.get("DST_IP", kwargs.get("dst_ip", "any"))
    dscp_value = kwargs.get("DSCP", kwargs.get("dscp_value",None))
    tcp_flag = kwargs.get("TCP_FLAG", kwargs.get("tcp_flag", None))
    src_port = kwargs.get("SRC_PORT", kwargs.get("src_port", None))
    src_comp_operator = kwargs.get("src_comp_operator", "eq") if src_port else ""
    src_port_range = kwargs.get("SRC_PORT_RANGE",kwargs.get("src_port_range", None))
    dst_port = kwargs.get("DST_PORT", kwargs.get("dst_port", None))
    dst_comp_operator = kwargs.get("dst_comp_operator", "eq") if dst_port else ""
    dst_port_range = kwargs.get("DST_PORT_RANGE", kwargs.get("dst_port_range",None))
    vlan_id = kwargs.get("VLAN", kwargs.get("vlan_id", None))
    description = kwargs.get("DESCRIPTION", kwargs.get("description", None))
    type_any = kwargs.get("any", None)
    src_mac = kwargs.get("SRC_MAC", kwargs.get("src_mac","any"))
    dst_mac = kwargs.get("DST_MAC", kwargs.get("dst_mac","any"))
    pcp_val = kwargs.get("PCP", kwargs.get("pcp_val",  None))
    dei_val = kwargs.get("DEI",kwargs.get("dei_val", None))
    if kwargs.get("ETHER_TYPE"):
        eth_type = util_obj.hex_conversion(kwargs.pop("ETHER_TYPE"))
    elif kwargs.get("eth_type"):
        eth_type = util_obj.hex_conversion(kwargs.pop("eth_type"))
    else:
        eth_type = ""
    if not table_name or not rule_name:
        st.error("Please provide table_name / rule_name")
        return False
    dscp = "dscp {}".format(dscp_value) if dscp_value else ""
    src_port_range_cmd = "range {}".format(src_port_range) if src_port_range else ""
    dst_port_range_cmd = "range {}".format(dst_port_range) if dst_port_range else ""
    remark = "remark \"{}\"".format(description) if description else ""
    pcp = "pcp {}".format(pcp_val) if pcp_val else ""
    dei = "dei {}".format(dei_val) if dei_val else ""
    st.log("Creating ACL rule ...")
    if cli_type == "click":
        acl_rule_data = kwargs
        if not acl_rule_data:
            st.error("ACL rule creation failed because of invalid data")
            return False
        acl_table_rules = dict()
        acl_rules = dict()
        excluded_keys = ["table_name", "rule_name", "type", "acl_type", "l4_protocol"]
        if l4_protocol in ["ip", "4", 4]:
            excluded_keys.append("ip_protocol")
        acl_rules["{}|{}".format(acl_rule_data["table_name"], acl_rule_data["rule_name"])] = dict()
        for key, value in acl_rule_data.items():
            if key not in excluded_keys:
                acl_rules["{}|{}".format(acl_rule_data["table_name"], acl_rule_data["rule_name"])][key.upper()] = value
        acl_table_rules["ACL_RULE"] = acl_rules
        acl_table_rules = json.dumps(acl_table_rules)
        json.loads(acl_table_rules)
        st.apply_json2(dut, acl_table_rules)
        # reboot.config_save(dut)
        if not skip_verify:
            if not verify_acl_table_rule(dut, acl_rule_data["table_name"], acl_rule_data["rule_name"]):
                return False
        return True
    elif cli_type == "klish":
        action_mapping = {"FORWARD": "permit", "DROP": "deny", "REDIRECT": "deny", "DO_NOT_NAT": "do-not-nat"}
        acl_type = acl_type if acl_type else kwargs.get("type")
        if acl_type: acl_type = acl_type.replace("CTRLPLANE", "")
        protocol_mapping = {"6":"tcp", "4":"ip", "17": "udp"}
        if l4_protocol and str(l4_protocol) in protocol_mapping.keys():
            l4_protocol = protocol_mapping[str(l4_protocol)]
        acl_type = get_acl_type(acl_type)
        if not acl_type:
            st.error("ACL TYPE IS NOT PROVIDED")
            return False
        commands = list()
        vlan_cmd = "vlan {}".format(vlan_id) if vlan_id else ""
        commands.append("{} access-list {}".format(acl_type, table_name))
        command = "seq"
        st.debug("RULE NAME -- {}".format(rule_name))
        rule_seq = kwargs.pop('rule_seq', int(re.findall(r'\d+', rule_name)[0]) if re.findall(r'\d+', rule_name) else "")
        if not rule_seq:
            st.log("RULE SEQ VALUE NOT FOUND.. HENCE ABORTING ...")
            return False
        if packet_action.upper() in action_mapping.keys():
            packet_action = action_mapping[packet_action.upper()]
        if acl_type in ["ip", "ipv6"]:
            if (src_ip != "any" and "/" not in src_ip):
                host_1 = "host"
            if (dst_ip != "any" and "/" not in dst_ip):
                host_2 = "host"
            full_seq = [rule_seq, packet_action, l4_protocol, type_any, host_1, src_ip, src_comp_operator, src_port, src_port_range_cmd,
                        type_any, host_2, dst_ip, dst_comp_operator, dst_port, dst_port_range_cmd, dscp,
                        tcp_flag, vlan_cmd, remark]
        elif acl_type == "mac":
            if "/" in src_mac:
                src_mac_val = src_mac.split("/")[0]
                host_1 = "host"
            else:
                src_mac_val = src_mac
                host_1 = ""
            if "/" in dst_mac:
                dst_mac_val = dst_mac.split("/")[0]
                host_2 = "host"
            else:
                dst_mac_val = dst_mac
                host_2 = ""
            full_seq = [rule_seq, packet_action, type_any, host_1, src_mac_val, type_any, host_2, dst_mac_val, eth_type,
                        vlan_cmd, pcp, dei, remark]
        else:
            st.error("ACL TYPE IS UNSUPPORTED")
            return False
        for cmd in full_seq:
            if cmd:
                command += " "+str(cmd)
        commands.append(command)
        commands.append('exit')
        st.config(dut, commands, type=cli_type, skip_error_check=skip_verify)
    elif cli_type in ["rest-patch","rest-put"]:
        acl_type_mapping = {"ip": "ipv4", "ipv6": "ipv6", "mac": "l2", "L3":"ipv4", "L3V6": "ipv6", "L2":"l2"}
        acl_type = acl_type if acl_type else kwargs.get("type")
        acl_type = acl_type.replace("CTRLPLANE","")
        rest_urls = st.get_datastore(dut, "rest_urls")
        if acl_type in acl_type_mapping.keys():
            acl_type = acl_type_mapping[acl_type]
        else:
            st.log("ACL TYPE IS UNSUPPORTED -- {}".format(acl_type))
            return False
        action_mapping = {"permit":"ACCEPT","deny":"DROP", "forward":"ACCEPT", "drop":"DROP", "do_not_nat":"DO_NOT_NAT"}
        packet_action = action_mapping[packet_action.lower()]
        rule_create = json.loads("""
        {
    "openconfig-acl:acl-entries": {
        "acl-entry": [{
            "sequence-id": 0,
            "config": {"sequence-id": 0,"description": "string"},
            "actions": {"config": {"forwarding-action": "string"}},
            "transport": {"config": {}}
        }]
    }
}
        """)
        config = dict()
        transport_data = dict()
        config["config"] = {}
        # acl_type config
        if acl_type == "l2":
            if vlan_id:
                config["config"]["vlanid"] = int(vlan_id)
            if dst_mac != "any":
                config["config"]["destination-mac"] = dst_mac.split("/")[0]
            if src_mac != "any":
                config["config"]["source-mac"] = src_mac.split("/")[0]
            if eth_type:
                config["config"]["ethertype"] = int(eth_type, 16)
        else:
            if l4_protocol in ["58", 58]:
                config["config"]["protocol"] = int(l4_protocol)
            elif l4_protocol not in ["ip", "4", 4, "ipv6"]:
                try:
                    l4_protocol = int(l4_protocol)
                    if l4_protocol == 17:
                        l4_protocol = "udp"
                    elif l4_protocol == 6:
                        l4_protocol = "tcp"
                    elif l4_protocol == 1:
                        l4_protocol = "icmp"
                except Exception:
                    pass
                if l4_protocol:
                    config["config"]["protocol"] = "IP_{}".format(l4_protocol.upper())
            if dscp_value:
                config["config"]["dscp"] = dscp_value
            if dst_ip != "any":
                config["config"]["destination-address"] = dst_ip
            if src_ip != "any":
                config["config"]["source-address"] = src_ip
        # config ports
        if dst_comp_operator == 'lt':
            dst_port_range = "0 {}".format(dst_port)
            transport_data["destination-port"] = "{}..{}".format(dst_port_range.split()[0],dst_port_range.split()[1])
        elif dst_comp_operator == 'gt':
            dst_port_range = "{} 65500".format(dst_port)
            transport_data["destination-port"] = "{}..{}".format(dst_port_range.split()[0],dst_port_range.split()[1])
        elif dst_port:
            transport_data["destination-port"] = int(dst_port)
            st.log(transport_data)
        elif dst_port_range:
            transport_data["destination-port"] = "{}..{}".format(dst_port_range.split()[0],dst_port_range.split()[1])
        if src_comp_operator == 'lt':
            src_port_range = "0 {}".format(src_port)
            transport_data["source-port"] = "{}..{}".format(src_port_range.split()[0],src_port_range.split()[1])
        elif src_comp_operator == 'gt':
            src_port_range = "{} 65500".format(src_port)
            transport_data["source-port"] = "{}..{}".format(src_port_range.split()[0],src_port_range.split()[1])
        elif src_port:
            transport_data["source-port"] = int(src_port)
            st.log(transport_data)
        elif src_port_range:
            st.log(src_port_range)
            transport_data["source-port"] = "{}..{}".format(src_port_range.split()[0],src_port_range.split()[1])
            st.log(transport_data)
        if tcp_flag:
            transport_data["tcp-flags"] = ["TCP_{}".format(temp.upper().replace('-','_')) for temp in tcp_flag.split()]
            st.log(transport_data)
            if tcp_flag == "established":
                transport_data["openconfig-acl-ext:tcp-session-established"] = True
                transport_data.pop("tcp-flags")
        rule_create["openconfig-acl:acl-entries"]["acl-entry"][0]["transport"]["config"] = transport_data
        if acl_type == "ip":
            acl_type = "ipv4"
        rule_create["openconfig-acl:acl-entries"]["acl-entry"][0][acl_type] = config
        rule_seq = kwargs.pop('rule_seq',int(re.findall(r'\d+', rule_name)[0]) if re.findall(r'\d+', rule_name) else "")
        rule_create["openconfig-acl:acl-entries"]["acl-entry"][0]["sequence-id"] = rule_create[
            "openconfig-acl:acl-entries"]["acl-entry"][0]["config"]["sequence-id"] = int(rule_seq)
        rule_create[
            "openconfig-acl:acl-entries"]["acl-entry"][0]["config"]["description"] = "\"{}\"".format(description)
        rule_create["openconfig-acl:acl-entries"]["acl-entry"][0]["actions"]["config"]["forwarding-action"] = packet_action
        url = rest_urls['config_acl_rule'].format(table_name,acl_type.upper())
        if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=rule_create):
            return False
    else:
        st.log("Unsupported CLI TYPE {}".format(cli_type))
        return False
    return True


def show_acl_table(dut, acl_table=""):
    """
    Get the ACL table
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param acl_table:
    :return:
    """
    st.log("Showing ACL table data ...")
    command = "show acl table"
    if acl_table:
        command += " {}".format(acl_table)
    acl_table_data = st.show(dut, command)
    if acl_table_data:
        bindings = dict()
        data = list()
        for table_data in acl_table_data:
            if table_data["name"] not in bindings.keys():
                bindings[table_data["name"]] = {"binding": "", "description": "", "type": ""}
            bindings[table_data["name"]]["binding"] += table_data["binding"] + " "
            bindings[table_data["name"]]["description"] = table_data["description"]
            bindings[table_data["name"]]["type"] = table_data["type"]
        data.append(bindings)
        return data
    else:
        st.log("ACL table data not found, hence returning empty data..")
        return acl_table_data


def show_acl_rule(dut, acl_table=None, acl_rule=None):
    """
    Get the ACL rule
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param acl_table:
    :param acl_rule:
    :return:
    """
    st.log("Showing ACL rule table data ..")
    command = "show acl rule"
    if acl_table:
        command += " {}".format(acl_table)
    acl_rule_data = st.show(dut, command)
    if not acl_rule_data:
        st.log("ACL table data not found, hence returning empty data..")
        return acl_rule_data
    final_data = {}
    for each in acl_rule_data:
        key = "{}|{}".format(each['table'], each['rule'])
        if key not in final_data.keys():
            final_data[key] = {'priority': each['priority'], 'match': [each['match']], 'action': each['action'],
                               'table': each['table'], 'rule': each['rule']}
        else:
            final_data[key]['match'].append(each['match'])
    if not acl_rule:
        return final_data
    else:
        return final_data["{}|{}".format(acl_table, acl_rule)] if "{}|{}".format(acl_table,
                                                                               acl_rule) in final_data else {}

def get_acl_rule_count(dut):
    """
    Get the ACL table vs rule count
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :return:
    """
    output = show_acl_rule(dut)
    count = {}
    for each in output:
        table = each.split("|")[0]
        if table not in count:
            count[table] = 1
        else:
            count[table] += 1
    return count


def verify_acl_table(dut, acl_table):
    """
    Verify the ACL table
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param acl_table:
    :return:
    """
    st.log("Verifying  ACL table {} data ...".format(acl_table))
    if not show_acl_table(dut, acl_table):
        st.error("ACL table {} not found ....".format(acl_table))
        return False
    return True


def verify_acl_table_rule(dut, acl_table, acl_rule):
    """
    Get the ACL table and rule
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param acl_table:
    :param acl_rule:
    :return:
    """
    st.log("Verifying  ACL table {} and ACL rule {} data ...".format(acl_table, acl_rule))
    if not show_acl_rule(dut, acl_table, acl_rule):
        st.error("ACL table {} and ACL rule {} not found ....".format(acl_table, acl_rule))
        return False
    return True


def show_acl_counters(dut, acl_table=None, acl_rule=None, acl_type="ip", cli_type=""):
    """
    Get the ACL table
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param acl_table:
    :param acl_rule:
    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    if cli_type == "click":
        command = "aclshow"
        if acl_table:
            command += " -t {}".format(acl_table)
        if acl_rule:
            command += " -r {}".format(acl_rule)
        return st.show(dut, command)
    elif cli_type in ["klish","rest-put","rest-patch"]:
        output = show_ip_access_list(dut, acl_table, acl_type=acl_type, cli_type=cli_type, acl_rule=acl_rule)
        return output
    else:
        st.log("Unsupported CLI TYPE {}".format(cli_type))
        return []


def delete_acl_rule_via_acl_loader(dut, acl_table, acl_rule):
    """
    Delete the ACL rule
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param acl_table:
    :param acl_rule:
    :return:
    """
    command = "acl-loader delete {} {}".format(acl_table, acl_rule)
    st.config(dut, command)


def clear_acl_counter(dut, acl_table=None, acl_rule=None, acl_type=None):
    """
    Clear ACl counters
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param acl_table:
    :param acl_rule:
    :return:
    """
    cli_type=st.get_ui_type(dut)

    cli_type="klish" if cli_type in ["rest-patch", "rest-put"] else cli_type
    if cli_type == "click":
        command = "aclshow -c"
        if acl_table:
            command += " -t {}".format(acl_table)
        if acl_rule:
            command += " -r {}".format(acl_rule)
    elif cli_type == "klish":
        acl_type = get_acl_type(acl_type)
        if not acl_type:
            return False
        command = "clear {} access-list counters".format(acl_type)
    else:
        st.log("Unsupported CLI TYPE - {}".format(cli_type))
        return False
    st.config(dut, command, type=cli_type)
    return True


def config_acl_loader_update(dut, type_name, json_data, config_type="acl_loader"):
    """
    Config ACL loader update and add.
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param type_name:
    :param json_data:
    :param config_type: acl_loader and config_update
    :return:
    """
    try:
        if type_name not in ["full", "incremental", "add"]:
            st.log("Invalid type - {}".format(type_name))
            return False
        temp_file_path = tempfile.gettempdir()
        current_datetime = util_obj.get_current_datetime()
        file_name = "sonic_{}.json".format(current_datetime)
        file_path = "{}/{}".format(temp_file_path, file_name)
        file_path = util_obj.write_to_json_file(json_data, file_path)
        st.upload_file_to_dut(dut, file_path, file_name)
        if config_type == "acl_loader" and type_name != 'add':
            command = "acl-loader update {} {}".format(type_name, file_path)
        elif config_type == "acl_loader" and type_name == 'add':
            command = "acl-loader {} {}".format(type_name, file_path)
        else:
            if type_name == "add":
                command = "config acl {} {}".format(type_name, file_path)
            else:
                command = "config acl update {} {}".format(type_name, file_path)
        st.config(dut, command)
        os.remove(file_path)
        return True
    except ValueError as e:
        st.log(e)
        return False


def delete_acl_table(dut, acl_type=None, acl_table_name=None, cli_type=""):
    """
    API to delete the ACL table from DUT
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param acl_table_name: table name can be a string or list
    :return:
    """
    st.log("Deleting ACL table ...")
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    if cli_type == "click":
        command = "sudo config acl table delete"
        if not st.is_feature_supported("config-acl-table-delete-command", dut):
            command = "sudo config acl remove table"
        if acl_table_name:
            table_name = list([str(e) for e in acl_table_name]) if isinstance(acl_table_name, list) \
                else [acl_table_name]
            commands = ""
            for acl_table in table_name:
                commands += "{} {};".format(command, acl_table)
            if commands:
                st.config(dut, commands)
        else:
            st.config(dut, command)
    elif cli_type == "klish":
        acl_type = get_acl_type(acl_type)
        if not (acl_table_name and acl_type):
            st.report_fail("required_params_not_provided")
        acl_tables = util_obj.make_list(acl_table_name)
        command = list()
        for table_name in acl_tables:
            command.append("no {} access-list {}".format(acl_type, table_name))
        output = st.config(dut, command, type=cli_type, skip_error_check=True)
        if "Entry not found" in output:
            st.log("acl_table_not_found")
    elif cli_type in ["rest-patch","rest-put"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        if not (acl_table_name and acl_type):
            st.report_fail("required_params_not_provided")
        acl_type_mapping = {"ip": "ACL_IPV4", "ipv6": "ACL_IPV6", "mac": "ACL_L2", "L3": "ACL_IPV4", "L3V6": "ACL_IPV6",
                            "L2": "ACL_L2"}
        acl_type = acl_type_mapping[acl_type]
        acl_tables = util_obj.make_list(acl_table_name)
        for table_name in acl_tables:
            url = rest_urls['config_acl_table'].format(table_name,acl_type)
            if not delete_rest(dut, rest_url=url):
                return False
    else:
        st.log("Unsupported CLI TYPE {}".format(cli_type))
        return False
    return True


def delete_acl_rule(dut, acl_table_name=None, acl_type = None, acl_rule_name=None,rule_seq=None,cli_type=""):
    """
    API to delete ACL rule of an ACL table
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param acl_table_name:
    :param acl_rule_name: Rule can be a string or list
    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    st.log("Deleting ACL rule ...")
    if acl_table_name:
        if cli_type == "click":
            command = "config acl rule delete {}".format(acl_table_name)
            if acl_rule_name:
                rule_name = list([str(e) for e in acl_rule_name]) if isinstance(acl_rule_name, list) else [acl_rule_name]
                for acl_rule in rule_name:
                    command = "config acl rule delete {} {}".format(acl_table_name, acl_rule)
                    if not st.is_feature_supported("config-acl-rule-delete-command", dut):
                        st.community_unsupported(command, dut)
                        delete_acl_rule_via_acl_loader(dut, acl_table_name, acl_rule)
                    else:
                        st.config(dut, command)
            else:
                st.config(dut, command)
        elif cli_type == "klish":
            acl_type = get_acl_type(acl_type)
            if not acl_type:
                return False
            if acl_rule_name:
                commands = list()
                commands.append("{} access-list {}".format(acl_type, acl_table_name))
                if not rule_seq:
                    rule_seq = int(re.findall(r'\d+', acl_rule_name)[0])
                commands.append("no seq {}".format(rule_seq))
                commands.append("exit")
            else:
                commands = "no {} access-list {}".format(acl_type, acl_table_name)
            output = st.config(dut, commands, type=cli_type, skip_error_check=True)
            if "Entry not found" in output:
                st.report_fail("acl_rule_table_not_found")
        elif cli_type in ["rest-patch","rest-put"]:
            acl_type_mapping = {"ip": "ACL_IPV4", "ipv6": "ACL_IPV6", "mac": "ACL_L2", "L3": "ACL_IPV4", "L3V6": "ACL_IPV6", "L2": "ACL_L2"}
            rest_urls = st.get_datastore(dut, "rest_urls")
            if acl_type in acl_type_mapping.keys():
                acl_type = acl_type_mapping[acl_type]
            else:
                st.log("ACL TYPE IS UNSUPPORTED -- {}".format(acl_type))
                return False
            if not rule_seq:
                rule_seq = int(re.findall(r'\d+', acl_rule_name)[0])
            if acl_rule_name:
                url = rest_urls['delete_acl_rule'].format(acl_table_name, acl_type, rule_seq)
            else:
                url = rest_urls['config_acl_table'].format(acl_table_name, acl_type)
            if not delete_rest(dut, rest_url=url):
                return False
        else:
            st.log("Unsupported CLI TYPE {}".format(cli_type))
            return False
        return True
    else:
        st.report_fail("acl_table_name_missing")


def clear_acl_config(dut, acl_table_name=None, acl_type=None):
    """
    API to clear ACL configuration from DUT
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param acl_table_name:
    :return:
    """
    if acl_table_name:
        delete_acl_rule(dut, acl_table_name)
    delete_acl_table(dut, acl_type, acl_table_name)


def verify_acl_stats(dut, table_name, rule_name, packet_count=None, bindpoint=None, acl_type=''):
    """
    API to verify acl stats
     Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param table_name:
    :param rule_name:
    :param packet_count:
    :param bindpoint:
    :return:
    """
    result = True
    acl_stats = show_acl_counters(dut, table_name, rule_name, acl_type=acl_type)
    if packet_count:
        match = {"rulename": rule_name, "tablename": table_name, "packetscnt": packet_count}
        if not filter_and_select(acl_stats, ["packetscnt"], match):
            result = False
    if bindpoint:
        match = {"rulename": rule_name, "tablename": table_name, "bindpoint": bindpoint}
        if not filter_and_select(acl_stats, ["bindpoint"], match):
            result = False
    return result


def poll_for_acl_counters(dut, acl_table=None, acl_rule=None, itr=5, delay=2, acl_type=None):
    """
    Author:kesava-swamy.karedla@broadcom.com
    :param dut:
    :param acl_table:
    :param acl_rule:
    :param itr:
    :param delay:
    :return:
    """
    i = 1
    while True:
        result = show_acl_counters(dut, acl_table, acl_rule, acl_type=acl_type)
        if result:
            return result
        if i >= itr:
            return None
        st.wait(delay)
        i += 1


def config_hw_acl_mode(dut, **kwargs):
    """
    config hardware access-list modes
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param :dut:
    :param :counter:
    :param :lookup:
    :return:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    if cli_type == "click":
        command = "config hardware access-list"
        if kwargs.get('counter'):
            command += " -c {}".format(kwargs['counter'])
        elif kwargs.get('lookup'):
            command += " -l {}".format(kwargs['lookup'])
        response = st.config(dut, command)
        if "Error" in response:
            return False
        return True
    elif cli_type == "klish":
        commands = list()
        commands.append("hardware")
        commands.append("access-list")
        counter = {'per-interface-rule': 'per-interface-entry',
                   'per-rule': 'per-entry'}
        if kwargs.get('counter'):
            commands.append("counters {}".format(counter[kwargs.get('counter')]))
            commands.append("exit")
        commands.append("exit")
        response = st.config(dut, commands, type=cli_type, skip_error_check=True)
        if "Error" in response:
            return False
        return True
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        url = rest_urls['config_hw_acl_mode']
        if kwargs.get('counter') == "per-rule":
            acl_mode = {"openconfig-acl-ext:counter-capability": "AGGREGATE_ONLY"}
        elif kwargs.get('counter') == "per-interface-rule":
            acl_mode = {"openconfig-acl-ext:counter-capability": "INTERFACE_ONLY"}
        if kwargs.get('counter'):
            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=acl_mode):
                return False
        return True
    else:
        st.log("Unsupported CLI TYPE {}".format(cli_type))
        return False

def verify_hw_acl_mode(dut, **kwargs):
    """
    verify config hardware access-list modes
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param kwargs: lookup_configured, lookup_active, counter_configured, counter_active
    :return:
    """
    output = st.show(dut, 'show hardware access-list')
    result = True
    for each in kwargs:
        entries = filter_and_select(output, None, {each: kwargs[each]})
        if not entries:
            st.log("{} and {} is not match ".format(each, kwargs[each]))
            result = False
    return result


def config_access_group(dut, acl_type=None, **kwargs):
    """
    API to map interface to Access-list
    Author : Pradeep Bathula (pradeep.b@broadcom.com)
    :param dut:
    :type dut:
    :param cli_type:
    :type cli_type:klish
    :param table_name:
    :type table_name:
    :param port:
    :type interface:
    :param access_group_action:
    :type access_group_action:in|out
    :return:
    """
    cli_type = kwargs.get("cli_type", "klish")
    table_name = kwargs.get("table_name", None)
    port = kwargs.get("port", None)
    access_group_action = kwargs.get("access_group_action", None)
    skip_error_check = kwargs.get("skip_error_check", True)
    config = kwargs.get("config", "yes")
    mode = "" if config == "yes" else "no "
    ports = util_obj.make_list(port) if port else []
    st.log("Assigning Access-group action on interface")
    if not (cli_type in ["klish","rest-patch","rest-put"]):
        st.log("Unsupported CLI type {} provided, required klish/rest".format(cli_type))
        return False
    if not (table_name and port and access_group_action and config ):
        st.log("Mandatory parameters like table_name and/or port and/or access_group_action and/or config not passed")
        return False
    if cli_type == "klish":
        commands = list()
        for intf in ports:
            if intf == "CtrlPlane":
                if not bind_ctrl_plane(dut, table_name=table_name, acl_type=acl_type):
                    st.error("Access group binding to control plane failed for table: {}".format(table_name))
                    return False
            elif intf != "Switch":
                interface_details = util_obj.get_interface_number_from_name(intf)
                commands.append("interface {} {}".format(interface_details.get("type"), interface_details.get("number")))
                commands.append("{} {} access-group {} {}".format(mode, acl_type, table_name, access_group_action))
                commands.append("exit")
            else:
                commands.append("{} {} access-group {} {}".format(mode, acl_type, table_name, access_group_action))
        response = st.config(dut, commands, type=cli_type, skip_error_check=skip_error_check)
        if "Error" in response:
            return False
    elif cli_type in ["rest-patch","rest-put"]:
        config_group = json.loads("""
                    {
            "openconfig-acl:interface": [{
                "id": "string",
                "config": {
                    "id": "string"
                },
                "interface-ref": {
                    "config": {
                        "interface": "string"
                    }
                }
            }]
        }
                    """)
        acl_set = json.loads("""
        [{
            "type": "string",
            "config": {
                "type": "string",
                "set-name": "string"
            },
            "set-name": "string"
        }]
        """)
        acl_set[0]["type"] = acl_set[0]["config"]["type"] = acl_type
        acl_set[0]["set-name"] = acl_set[0]["config"]["set-name"] = table_name
        grop_dict = dict()
        action,set_action = "openconfig-acl:{}-acl-sets".format(access_group_action),"{}-acl-set".format(access_group_action)
        grop_dict[set_action] = acl_set
        config_group["openconfig-acl:interface"][0][action] = grop_dict
        rest_urls = st.get_datastore(dut, "rest_urls")
        for each_port in ports:
            url = rest_urls['config_access_group'].format(each_port)
            config_group["openconfig-acl:interface"][0]["id"] = config_group["openconfig-acl:interface"][0]["config"][
                "id"] = each_port
            config_group["openconfig-acl:interface"][0]["interface-ref"]["config"]["interface"] = each_port
            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=config_group):
                return False
    else:
        st.log("Unsupported CLI TYPE {}".format(cli_type))
        return False
    return True


def apply_acl_config(dut, config):
    cli_type = st.get_ui_type(dut)
    json_config = json.dumps(config)
    if cli_type == "click":
        json.loads(json_config)
        st.apply_json2(dut, json_config)
        return True
    elif cli_type in ["klish","rest-patch","rest-put"]:
        acl_config = json.loads(json_config)
        click_klish_acl_type_mapping = {"L3":"ip", "L3V6": "ipv6", "L2": "mac"}
        action_mapping = {"FORWARD": "permit", "DROP": "deny", "REDIRECT": "deny","ACCEPT":"permit"}
        tcp_flag_mapping = {"4/4":"rst"}
        table_type_mapping = {}
        st.banner("Creating ACL TABLES")
        if not acl_config.get("ACL_TABLE"):
            st.error("ACL TABLE INFO NOT FOUND")
            return False
        for table_name, table_props in acl_config.get("ACL_TABLE").items():
            if not table_props.get("type"):
                st.error("ACL TABLE TYPE NOT FOUND FOR ACL TABLE {}".format(table_name))
                return False
            if table_props.get("type") == "CTRLPLANE":
                ether_type = acl_config["ACL_RULE"]["{}|DEFAULT_RULE100".format(table_name)]["ETHER_TYPE"]
                if ether_type == "0x0800":
                    click_klish_acl_type_mapping["CTRLPLANE"] = "ipCTRLPLANE"
                elif ether_type == "0x86dd":
                    click_klish_acl_type_mapping["CTRLPLANE"] = "ipv6CTRLPLANE"
            table_type_mapping.update({table_name:click_klish_acl_type_mapping[table_props.get("type")]})
            if not create_acl_table(dut, acl_type=click_klish_acl_type_mapping[table_props.get("type")],
                                    ports=table_props.get("ports"), stage=table_props.get("stage"),
                                    table_name=table_name, description=table_props.get("policy_desc"), cli_type=cli_type):
                st.error("ACL TABLE CREATION FAILED FOR TABLE {}".format(table_name))
                return False
        if not acl_config.get("ACL_RULE"):
            st.error("ACL RULE INFO NOT FOUND")
            return False
        st.log("TABLE TYPE MAPPING -- {}".format(table_type_mapping))
        for rule_name, rule_details in acl_config.get("ACL_RULE").items():
            acl_table_name, acl_rule_name = rule_name.split("|")
            data_dict = dict()
            data_dict.update({"cli_type":cli_type})
            data_dict.update({"table_name":acl_table_name})
            data_dict.update({"rule_name":acl_rule_name})
            if rule_details.get("PACKET_ACTION"):
                packet_action = rule_details.get("PACKET_ACTION") if "REDIRECT" not in rule_details.get("PACKET_ACTION") else "REDIRECT"
                data_dict.update({"packet_action": action_mapping[packet_action.upper()]})
            if table_type_mapping[acl_table_name] in ["ip", "ipCTRLPLANE"]:
                if rule_details.get("SRC_IP"):
                    data_dict.update({"src_ip": rule_details.get("SRC_IP")})
                if rule_details.get("DST_IP"):
                    data_dict.update({"dst_ip": rule_details.get("DST_IP")})
            elif table_type_mapping[acl_table_name] in ["ipv6" , "ipv6CTRLPLANE"]:
                if rule_details.get("SRC_IPV6"):
                    data_dict.update({"src_ip": rule_details.get("SRC_IPV6")})
                if rule_details.get("DST_IPV6"):
                    data_dict.update({"dst_ip": rule_details.get("DST_IPV6")})
            if rule_details.get("IP_PROTOCOL"):
                data_dict.update({"l4_protocol": rule_details.get("IP_PROTOCOL")})
            else:
                data_dict.update({"l4_protocol": "tcp"})
            if rule_details.get("DSCP"):
                data_dict.update({"dscp_value": rule_details.get("DSCP")})
            if rule_details.get("TCP_FLAGS"):
                data_dict.update({"tcp_flag": tcp_flag_mapping[rule_details.get("TCP_FLAGS")]})
            if rule_details.get("L4_SRC_PORT"):
                data_dict.update({"src_port": rule_details.get("L4_SRC_PORT")})
            if rule_details.get("L4_DST_PORT"):
                data_dict.update({"dst_port": rule_details.get("L4_DST_PORT")})
            if rule_details.get("L4_SRC_PORT_RANGE"):
                data_dict.update({"src_port_range": rule_details.get("L4_SRC_PORT_RANGE").replace("-"," ")})
            if rule_details.get("L4_DST_PORT_RANGE"):
                data_dict.update({"dst_port_range": rule_details.get("L4_DST_PORT_RANGE").replace("-"," ")})
            if rule_details.get("DESCRIPTION"):
                data_dict.update({"description": rule_details.get("DESCRIPTION")})
            else:
                data_dict.update({"description": "RULE FOR {} {}".format(acl_table_name, rule_name)})
            if rule_details.get("SRC_MAC"):
                data_dict.update({"src_mac": rule_details.get("SRC_MAC")})
            if rule_details.get("DST_MAC"):
                data_dict.update({"dst_mac": rule_details.get("DST_MAC")})
            if rule_details.get("PCP"):
                data_dict.update({"pcp_val": rule_details.get("PCP")})
            if rule_details.get("DEI"):
                data_dict.update({"dei_val": rule_details.get("DEI")})
            if rule_details.get("ETHER_TYPE"):
                data_dict.update({"eth_type": rule_details.get("ETHER_TYPE")})
            if rule_details.get("VLAN"):
                vlans = util_obj.make_list(rule_details.get("VLAN"))
                for vlan_id in vlans:
                    data_dict.update({"vlan_id": vlan_id})
                    create_acl_rule(dut, acl_type= table_type_mapping[acl_table_name], **data_dict)
            else:
                create_acl_rule(dut, acl_type=table_type_mapping[acl_table_name], **data_dict)
        return True
    else:
        st.log("Unsupported CLI TYPE {}".format(cli_type))
        return False


def show_ip_access_list(dut, table_name=None, acl_type="ip", cli_type="", acl_rule=None):
    """
    API to get the output of show ip access-lists
    :param dut:
    :param table_name:
    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    if cli_type == "click":
        show_acl_counters(dut, acl_table=table_name, acl_type=acl_type, cli_type=cli_type)
    if cli_type == "klish":
        acl_type=get_acl_type(acl_type)
        if not acl_type:
            return False
        command = "show {} access-lists".format(acl_type)
        if table_name:
            command += " {}".format(table_name)
        if acl_rule:
            rule_seq = int(re.findall(r'\d+', acl_rule)[0]) if re.findall(r'\d+', acl_rule) else ""
            if not rule_seq:
                st.error("rule_seq is mandatory for KLISH")
                return False
            result = list()
            output = st.show(dut, command, type=cli_type, skip_error_check=True)
            if output:
                for acl_data in output:
                    if int(acl_data["rule_no"]) == int(rule_seq):
                        result.append(acl_data)
            return result
        else:
            return st.show(dut, command, type=cli_type, skip_error_check=True)
    elif cli_type in ["rest-patch","rest-put"]:
        output = []
        rest_urls = st.get_datastore(dut, "rest_urls")
        url = rest_urls['acl_set']
        get_resp = get_rest(dut, rest_url=url)["output"]
        if not get_resp:
            return output
        try:
            acl_sets = get_resp["openconfig-acl:acl"]["acl-sets"]["acl-set"]
        except Exception:
            return []
        for acl_set in acl_sets:
            if acl_set.get("acl-entries"):
                for acl_entry in acl_set.get("acl-entries")["acl-entry"]:
                    acl_data = dict()
                    acl_data["access_list_name"] = acl_set.get("name")
                    acl_data["rule_no"] = acl_entry.get("sequence-id")
                    acl_data["acl_type"] = ""
                    if "ACCEPT" in acl_entry["actions"]["config"]["forwarding-action"]:
                        acl_data["action"] = "permit"
                    elif "DO_NOT_NAT" in acl_entry["actions"]["config"]["forwarding-action"]:
                        acl_data["action"] = "do_not_nat"
                    else:
                        acl_data["action"] = "deny"
                    l3_data_mapping = {"source-address": "src_ip", "destination-address": "dst_ip", "dscp": "dscp",
                                       "protocol": "proto"}
                    l2_data_mapping = {"source-mac": "src_mac_address", "destination-mac": "dst_mac_address",
                                       "openconfig-acl-ext:vlanid": "vlan"}
                    l4_data_mapping = {"source-port": "src_port", "destination-port": "dst_port"}
                    packet_mapping = {"matched-octets": "bytescnt", "matched-packets": "packetscnt"}
                    for _, value in l3_data_mapping.items():
                        acl_data[value] = ""
                    for _, value in l2_data_mapping.items():
                        acl_data[value] = ""
                    for _, value in l4_data_mapping.items():
                        acl_data[value] = ""
                    for _, value in packet_mapping.items():
                        acl_data[value] = "0"
                    proto_mapping = {"IP_TCP": "tcp", "IP_UDP": "udp"}
                    if "ACL_IPV4" in acl_set.get("type"):
                        acl_data["acl_type"] = "ip"
                        for rest_key, temp_key in l3_data_mapping.items():
                            if acl_entry.get("ipv4") and rest_key in acl_entry["ipv4"]["config"]:
                                if rest_key == "protocol":
                                    if acl_entry["ipv4"]["config"][rest_key] in proto_mapping:
                                        acl_data[temp_key] = proto_mapping[acl_entry["ipv4"]["config"][rest_key]]
                                    else:
                                        acl_data[temp_key] = "ip"
                                else:
                                    acl_data[temp_key] = acl_entry["ipv4"]["config"][rest_key]
                            else:
                                acl_data["src_ip"] = "any"
                                acl_data["dst_ip"] = "any"
                                acl_data["proto"] = "ip"
                        if acl_entry.get("ipv4") and "config" in acl_entry.get("ipv4"):
                            if "dscp" in acl_entry["ipv4"]["config"]:
                                acl_data["dscp"] = "dscp"
                                acl_data["dscp_val"] = acl_entry["ipv4"]["config"]["dscp"]
                            else:
                                acl_data["dscp"] = acl_data["dscp_val"] = ""
                        else:
                            acl_data["dscp"] = acl_data["dscp_val"] = ""
                    elif "ACL_IPV6" in acl_set.get("type"):
                        acl_data["acl_type"] = "ipv6"
                        for rest_key, temp_key in l3_data_mapping.items():
                            if acl_entry.get("ipv6") and rest_key in acl_entry["ipv6"]["config"]:
                                if rest_key == "protocol":
                                    if acl_entry["ipv6"]["config"][rest_key] in proto_mapping:
                                        acl_data[temp_key] = proto_mapping[acl_entry["ipv6"]["config"][rest_key]]
                                    else:
                                        acl_data[temp_key] = "ip"
                                else:
                                    acl_data[temp_key] = acl_entry["ipv6"]["config"][rest_key]
                            else:
                                acl_data["src_ip"] = "any"
                                acl_data["dst_ip"] = "any"
                                acl_data["proto"] = "ipv6"
                        if acl_entry.get("ipv6") and "config" in acl_entry.get("ipv6"):
                            if "dscp" in acl_entry["ipv6"]["config"]:
                                acl_data["dscp"] = "dscp"
                                acl_data["dscp_val"] = acl_entry["ipv6"]["config"]["dscp"]
                            else:
                                acl_data["dscp"] = acl_data["dscp_val"] = ""
                        else:
                            acl_data["dscp"] = acl_data["dscp_val"] = ""
                    elif "ACL_L2" in acl_set.get("type"):
                        acl_data["acl_type"] = "mac"
                        for rest_key, temp_key in l2_data_mapping.items():
                            if acl_entry.get("mac") and rest_key in acl_entry["mac"]["config"]:
                                acl_data[temp_key] = acl_entry["mac"]["config"][rest_key]
                    if "transport" in acl_entry:
                        for rest_key, temp_key in l4_data_mapping.items():
                            if rest_key in acl_entry["transport"]["config"]:
                                acl_data[temp_key] = acl_entry["transport"]["config"][rest_key]
                        if "tcp-flags" in acl_entry["transport"]["state"]:
                            acl_data["proto_flag"] = acl_entry["transport"]["state"]["tcp-flags"]
                    if "state" in acl_entry:
                        for rest_key, temp_key in packet_mapping.items():
                            if rest_key in acl_entry["state"]:
                                acl_data[temp_key] = acl_entry["state"][rest_key]
                    if acl_data:
                        output.append(acl_data)
        st.log(output)
        result = list()
        if output:
            if table_name:
                for acls in output:
                    if table_name == acls["access_list_name"]:
                        if acl_rule:
                            rule_seq = int(re.findall(r'\d+', acl_rule)[0]) if re.findall(r'\d+', acl_rule) else ""
                            if int(acls["rule_no"]) == int(rule_seq):
                                result.append(acls)
                        else:
                            result.append(acls)
            elif acl_rule:
                for acls in output:
                    rule_seq = int(re.findall(r'\d+', acl_rule)[0]) if re.findall(r'\d+', acl_rule) else ""
                    if int(acls["rule_no"]) == int(rule_seq):
                        result.append(acls)
            else:
                result = output
        st.log(result)
        return result
    else:
        st.log("Unsupported CLI TYPE {}".format(cli_type))
        return []



def get_access_lists(dut, acl_types=["ip", "ipv6", "mac"]):
    """
    API to get the list of access lists along wiht their types
    :param dut:
    :return: {"ip":["L3_IPV4_INGRESS", "L3_IPV4_EGRESS"], "ipv6":["L3_IPV4_INGRESS", "L3_IPV4_EGRESS"], "mac":["L2_MAC_INGRESS"]}
    """
    result = dict()
    acl_types = util_obj.make_list(acl_types)
    for acl_type in acl_types:
        output = show_ip_access_list(dut, acl_type=acl_type)
        st.log("GET ACCESS LISTS - {}".format(output))
        if output:
            data = list()
            for access_list in output:
                data.append(access_list["access_list_name"])
            if data:
                result.update({acl_type:list(set(data))})
    return result


def acl_delete(dut):
    cli_type = st.get_ui_type(dut)
    if not st.is_feature_supported("config-acl-table-delete-command", dut):
        names = show_acl_table(dut)
        acl_name = list()
        for name in names:
            acl_name.append(name.keys())
        for name in acl_name:
            for i in name:
                if "Name" in i:
                    pass
                else:
                    delete_acl_table(dut, acl_table_name=i)
    else:
        if cli_type == "click":
            delete_acl_table(dut)
        elif cli_type == "klish":
            access_lists = get_access_lists(dut)
            st.log("ACCESS LISTS -- {}".format(access_lists))
            if access_lists:
                for acl_type, access_list in access_lists.items():
                    delete_acl_table(dut, acl_type=acl_type, acl_table_name=access_list, cli_type=cli_type)
        elif cli_type in ["rest-patch","rest-put"]:
            rest_urls = st.get_datastore(dut, "rest_urls")
            url = rest_urls["acl_set"]
            if not delete_rest(dut, rest_url=url):
                return False
        else:
            st.log("Unsupported CLI TYPE {}".format(cli_type))
            return False


def get_acl_type(acl_type):
    """
    Helper function to validate/get the acl_type
    :param acl_type:
    :return:
    """
    if acl_type not in ["L3", "ip", "L3V6", "ipv6", "L2", "mac","CTRLPLANE"]:
        st.log("UNSUPPORTED ACL TYPE == {}".format(acl_type))
        return False
    click_klish_acl_type_mapping = {"L3": "ip", "L3V6": "ipv6", "L2": "mac","CRTLPLANE":"CTRLPLANE"}
    if acl_type:
        acl_type = click_klish_acl_type_mapping.get(acl_type, acl_type)
    else:
        st.log("ACL TYPE IS REQUIRED")
        return False
    return acl_type


def bind_ctrl_plane(dut, table_name, acl_type, config="yes", skip_error_check=True, cli_type=""):
    """
    Api to bind acl table to control plane
    :param dut:
    :param table_name:
    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    if cli_type == "klish":
        acl_type_mapping = {"ACL_IPV4":"ip", "ACL_IPV6":"ipv6", "ACL_L2":"mac"}
        acl_type = acl_type_mapping.get(acl_type,acl_type)
        bind = "" if config=="yes" else "no "
        commands = list()
        commands.append("line vty")
        commands.append("{}{} access-group {} in".format(bind,acl_type,table_name))
        commands.append("exit")
        output = st.config(dut, commands, type=cli_type,skip_error_check=skip_error_check)
        if "Error" in output:
            st.error("Table {} failed to bind".format(table_name))
            return False
    elif cli_type in ["rest-patch","rest-put"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        url = rest_urls['control_plane_acl']
        if config == "yes":
            json_data = {"openconfig-acl-ext:control-plane": {"ingress-acl-sets": {"ingress-acl-set":[
        {"set-name": table_name,"type": acl_type,"config": {"set-name": table_name,"type": acl_type}}]}}}
            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=json_data):
                return False
        else:
            if not delete_rest(dut, rest_url=url):
                return False
    else:
        st.error("Unsupported cli type :{}".format(cli_type))
        return False
    return True


