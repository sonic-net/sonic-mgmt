# This file contains the list of API's which performs ACL operations.
# Author : Chaitanya Vella (Chaitanya-vella.kumar@broadcom.com) and Prudvi Mangadu (prudvi.mangadu@broadcom.com)
import os
import re
import json
import tempfile

from spytest import st

from apis.common.asic import asic_show
from apis.system.rest import config_rest, delete_rest, get_rest
from apis.system.switch_configuration import write_config_db

from utilities.common import filter_and_select
import utilities.utils as util_obj

try:
    import apis.yang.codegen.messages.acl as umf_acl
except ImportError:
    pass

errors_list = ['error', 'invalid', 'usage', 'illegal', 'unrecognized']


def force_cli_type_to_klish(cli_type):
    cli_type = "klish" if cli_type in util_obj.get_supported_ui_type_list() else cli_type
    return cli_type


def rule_name_to_seq(name, default=""):
    rv = re.findall(r'\d+', str(name))
    return int(rv[0]) if rv else default


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
    skip_bind = kwargs.get('skip_bind', False)
    if not table_name or not acl_type:
        st.error("Mandatory parameter table name / acl_type not passed")
        return False
    if cli_type in util_obj.get_supported_ui_type_list():
        skip_port_binding = True if "CTRLPLANE" in acl_type else False
        acl_type = acl_type.replace("CTRLPLANE", "")
        if acl_type in ["L3", "L3V6", "L2"]:
            acl_type_mapping = {"L3": "ip", "L3V6": "ipv6", "L2": "mac"}
            acl_type = acl_type_mapping[acl_type]
        acl_obj = umf_acl.Root()
        acl_table_obj = umf_acl.Acl(Name=table_name, Type=acl_type)
        if kwargs.get("description"):
            acl_table_obj.Description = kwargs["description"]
        if kwargs.get("remark"):
            acl_table_obj.Description = kwargs["remark"]
        acl_obj.add_Acl(acl_table_obj)
        result = acl_obj.configure(dut, cli_type=cli_type)
        if not result.ok():
            st.error('test_step_failed: Create ACL table: {}'.format(result.data))
            return False
        if not skip_port_binding:
            if not skip_bind:
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
                st.error("'test_step_failed': Access group binding failed for table: {}".format(table_name))
                return False
    elif cli_type == "click":
        st.log("Creating ACL table ...")
        acl_data = kwargs
        acl_data.update({"type": acl_type})
        acl_data.update({"name": table_name})
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
        click_klish_acl_direction_mapping = {"INGRESS": "in", "EGRESS": "out"}
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
            if not skip_bind:
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

    elif cli_type in ["rest-patch", "rest-put"]:
        skip_port_binding = True if "CTRLPLANE" in acl_type else False
        acl_type = acl_type.replace("CTRLPLANE", "")
        if acl_type in ["L3", "L3V6", "L2"]:
            acl_type_mapping = {"L3": "ip", "L3V6": "ipv6", "L2": "mac"}
            acl_type = acl_type_mapping[acl_type]
        if acl_type not in ["ip", "ipv6", "mac"]:
            st.log("UNSUPPORTED ACL TYPES PROVIDED")
            return False
        acl_type_mapping = {"ip": "ACL_IPV4", "ipv6": "ACL_IPV6", "mac": "ACL_L2", "L3": "ACL_IPV4", "L3V6": "ACL_IPV6", "L2": "ACL_L2"}
        acl_type = acl_type_mapping[acl_type]
        rest_urls = st.get_datastore(dut, "rest_urls")
        url = rest_urls['config_acl_table'].format(table_name, acl_type)
        if not isinstance(table_name, list):
            config_table = {"acl-set": [{"config": {"type": acl_type, "name": table_name}, "type": acl_type, "name": table_name}]}
        else:
            li1 = []
            li2 = []
            acl_type = "openconfig-acl:" + acl_type
            for acl1 in table_name:
                di1 = {}
                di1["config"] = {"type": acl_type, "name": acl1, "description": ""}
                di1["type"] = acl_type
                di1["name"] = acl1
                li1.append([di1])
            li2 = [item for sublist in li1 for item in sublist]
            config_table = {"openconfig-acl:acl-set": li2}
            url = rest_urls['config_acl_table_global']
            if not config_rest(dut, http_method='post', rest_url=url, json_data=config_table):
                return False
            else:
                return True
        if kwargs.get("description"):
            config_table["acl-set"][0]['config'].update({"description": kwargs.get("description")})
        if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=config_table):
            return False
        if not skip_port_binding:
            if not skip_bind:
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
    REF: https://github.com/Azure/SONiC/wiki/ACL-High-Level-Design -- Follow the rule attributes names from this link
    """
    st.debug("KWARGS : {}".format(kwargs), dut=dut)
    cli_type = st.get_ui_type(dut, **kwargs)
    table_name = kwargs.get("table_name", None)
    rule_name = kwargs.get("rule_name", None)
    packet_action = kwargs.get("packet_action", "deny")
    l4_protocol = kwargs.get("ip_protocol", kwargs.get("l4_protocol", "tcp"))
    src_ip = kwargs.get("SRC_IP", kwargs.get("src_ip", "any"))
    dst_ip = kwargs.get("DST_IP", kwargs.get("dst_ip", "any"))
    dscp_value = kwargs.get("DSCP", kwargs.get("dscp_value", None))
    tcp_flag = kwargs.get("TCP_FLAG", kwargs.get("tcp_flag", None))
    src_port = kwargs.get("SRC_PORT", kwargs.get("src_port", None))
    src_comp_operator = kwargs.get("src_comp_operator", "eq") if src_port else ""
    src_port_range = kwargs.get("SRC_PORT_RANGE", kwargs.get("src_port_range", None))
    dst_port = kwargs.get("DST_PORT", kwargs.get("dst_port", None))
    dst_comp_operator = kwargs.get("dst_comp_operator", "eq") if dst_port else ""
    dst_port_range = kwargs.get("DST_PORT_RANGE", kwargs.get("dst_port_range", None))
    vlan_id = kwargs.get("VLAN", kwargs.get("vlan_id", None))
    description = kwargs.get("DESCRIPTION", kwargs.get("description", None))
    type_any = kwargs.get("any", None)
    src_mac = kwargs.get("SRC_MAC", kwargs.get("src_mac", "any"))
    dst_mac = kwargs.get("DST_MAC", kwargs.get("dst_mac", "any"))
    pcp_val = kwargs.get("PCP", kwargs.get("pcp_val", None))
    dei_val = kwargs.get("DEI", kwargs.get("dei_val", None))
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
    vlan_tag_format = kwargs.get(False, kwargs.get("vlan_tag_format", None))
    st.notice("Creating ACL rule ...", dut=dut)
    if cli_type in util_obj.get_supported_ui_type_list():
        acl_type = acl_type if acl_type else kwargs.get("type")
        if acl_type:
            acl_type = acl_type.replace("CTRLPLANE", "")
        acl_type_mapping = {"ipv4": "ip", "l2": "mac", "L3": "ip", "L3V6": "ipv6", "L2": "mac"}
        if acl_type in acl_type_mapping:
            acl_type = acl_type_mapping[acl_type]
        action_mapping = {"permit": "ACCEPT", "deny": "DROP", "forward": "ACCEPT", "drop": "DROP",
                          "do_not_nat": "DO_NOT_NAT", "discard": "DISCARD"}
        packet_action = action_mapping[packet_action.lower()]
        acl_table_obj = umf_acl.Acl(Name=table_name, Type=acl_type)
        st.debug("RULE NAME -- {}".format(rule_name))
        rule_seq = kwargs.pop('rule_seq', rule_name_to_seq(rule_name))
        if not rule_seq:
            st.log("RULE SEQ VALUE NOT FOUND.. HENCE ABORTING ...")
            return False
        rule_obj = umf_acl.AclRule(SeqNum=int(rule_seq), Action=packet_action, Acl=acl_table_obj)
        if description:
            rule_obj.Description = description
        if acl_type == "mac":
            if vlan_id:
                rule_obj.Vlanid = int(vlan_id)
            if dst_mac != "any":
                rule_obj.DstMac = dst_mac.split("/")[0]
            if src_mac != "any":
                rule_obj.SrcMac = src_mac.split("/")[0]
            if eth_type:
                rule_obj.Ethertype = int(eth_type, 16)
            if vlan_tag_format:
                rule_obj.VlanTagFormat = 'MULTI_TAGGED'
        else:
            protocol_dict = {"icmpv6": "58"}
            if l4_protocol in protocol_dict.keys():
                l4_protocol = protocol_dict[l4_protocol]
            if l4_protocol in ["58", 58]:
                rule_obj.Ipv6Proto = int(l4_protocol)
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
                    if acl_type == "ip":
                        rule_obj.IpProto = l4_protocol
                    if acl_type == "ipv6":
                        rule_obj.Ipv6Proto = l4_protocol
            if dscp_value:
                if acl_type == "ip":
                    rule_obj.Ipv4Dscp = dscp_value
                if acl_type == "ipv6":
                    rule_obj.Ipv6Dscp = dscp_value
            if dst_ip != "any":
                if acl_type == "ip":
                    if "/" not in dst_ip:
                        dst_ip = dst_ip + "/32"
                    rule_obj.Dip = dst_ip
                if acl_type == "ipv6":
                    if "/" not in dst_ip:
                        dst_ip = dst_ip + "/128"
                    rule_obj.Dipv6 = dst_ip
            if src_ip != "any":
                if acl_type == "ip":
                    if "/" not in src_ip:
                        src_ip = src_ip + "/32"
                    rule_obj.Sip = src_ip
                if acl_type == "ipv6":
                    if "/" not in src_ip:
                        src_ip = src_ip + "/128"
                    rule_obj.Sipv6 = src_ip
        # config ports
        if dst_comp_operator == 'lt':
            dst_port_range = "0 {}".format(dst_port)
            rule_obj.DstPort = "{}..{}".format(dst_port_range.split()[0], dst_port_range.split()[1])
            dst_port = None
        elif dst_comp_operator == 'gt':
            dst_port_range = "{} 65500".format(dst_port)
            rule_obj.DstPort = "{}..{}".format(dst_port_range.split()[0], dst_port_range.split()[1])
            dst_port = None
        elif dst_port:
            rule_obj.DstPort = int(dst_port)
        elif dst_port_range:
            rule_obj.DstPort = "{}..{}".format(dst_port_range.split()[0], dst_port_range.split()[1])
        if src_comp_operator == 'lt':
            src_port_range = "0 {}".format(src_port)
            rule_obj.SrcPort = "{}..{}".format(src_port_range.split()[0], src_port_range.split()[1])
            src_port = None
        elif src_comp_operator == 'gt':
            src_port_range = "{} 65500".format(src_port)
            rule_obj.SrcPort = "{}..{}".format(src_port_range.split()[0], src_port_range.split()[1])
            src_port = None
        elif src_port:
            rule_obj.SrcPort = int(src_port)
        elif src_port_range:
            rule_obj.SrcPort = "{}..{}".format(src_port_range.split()[0], src_port_range.split()[1])
        if tcp_flag:
            if tcp_flag == "established":
                rule_obj.TcpConnEst = True
            else:
                rule_obj.TcpFlags = [temp for temp in tcp_flag.split()]
        acl_table_obj.add_AclRule(rule_obj)
        result = acl_table_obj.configure(dut, cli_type=cli_type)
        if not result.ok():
            st.error("test_step_failed: Create ACL table: {}".format(result.data))
            return False
    elif cli_type == "click":
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
        if acl_type:
            acl_type = acl_type.replace("CTRLPLANE", "")
        protocol_mapping = {"6": "tcp", "4": "ip", "17": "udp"}
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
        rule_seq = kwargs.pop('rule_seq', rule_name_to_seq(rule_name))
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
            if vlan_tag_format is True:
                tag_format = 'vlan-tag-format'
                multi_tag = 'multi-tagged'
                full_seq = [rule_seq, packet_action, type_any, host_1, src_mac_val, type_any, host_2, dst_mac_val, tag_format, multi_tag, eth_type,
                            vlan_cmd, pcp, dei, remark]
        else:
            st.error("ACL TYPE IS UNSUPPORTED")
            return False
        for cmd in full_seq:
            if cmd:
                command += " " + str(cmd)
        commands.append(command)
        commands.append('exit')
        st.config(dut, commands, type=cli_type, skip_error_check=skip_verify)
    elif cli_type in ["rest-patch", "rest-put"]:
        acl_type_mapping = {"ip": "ipv4", "ipv6": "ipv6", "mac": "l2", "L3": "ipv4", "L3V6": "ipv6", "L2": "l2"}
        acl_type = acl_type if acl_type else kwargs.get("type")
        acl_type = acl_type.replace("CTRLPLANE", "")
        rest_urls = st.get_datastore(dut, "rest_urls")
        if acl_type in acl_type_mapping.keys():
            acl_type = acl_type_mapping[acl_type]
        else:
            st.log("ACL TYPE IS UNSUPPORTED -- {}".format(acl_type))
            return False
        action_mapping = {"permit": "ACCEPT", "deny": "DROP", "forward": "ACCEPT", "drop": "DROP", "do_not_nat": "DO_NOT_NAT"}
        packet_action = action_mapping[packet_action.lower()]
        rule_create = json.loads("""
        {
    "openconfig-acl:acl-entries": {
        "acl-entry": [{
            "sequence-id": 0,
            "config": {"sequence-id": 0},
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
            transport_data["destination-port"] = "{}..{}".format(dst_port_range.split()[0], dst_port_range.split()[1])
            dst_port = None
        elif dst_comp_operator == 'gt':
            dst_port_range = "{} 65500".format(dst_port)
            transport_data["destination-port"] = "{}..{}".format(dst_port_range.split()[0], dst_port_range.split()[1])
            dst_port = None
        elif dst_port:
            transport_data["destination-port"] = int(dst_port)
        elif dst_port_range:
            transport_data["destination-port"] = "{}..{}".format(dst_port_range.split()[0], dst_port_range.split()[1])
        if src_comp_operator == 'lt':
            src_port_range = "0 {}".format(src_port)
            transport_data["source-port"] = "{}..{}".format(src_port_range.split()[0], src_port_range.split()[1])
            src_port = None
        elif src_comp_operator == 'gt':
            src_port_range = "{} 65500".format(src_port)
            transport_data["source-port"] = "{}..{}".format(src_port_range.split()[0], src_port_range.split()[1])
            src_port = None
        elif src_port:
            transport_data["source-port"] = int(src_port)
        elif src_port_range:
            transport_data["source-port"] = "{}..{}".format(src_port_range.split()[0], src_port_range.split()[1])
        if tcp_flag:
            transport_data["tcp-flags"] = ["TCP_{}".format(temp.upper().replace('-', '_')) for temp in tcp_flag.split()]
            if tcp_flag == "established":
                transport_data["openconfig-acl-ext:tcp-session-established"] = True
                transport_data.pop("tcp-flags")
        rule_create["openconfig-acl:acl-entries"]["acl-entry"][0]["transport"]["config"] = transport_data
        if acl_type == "ip":
            acl_type = "ipv4"
        rule_create["openconfig-acl:acl-entries"]["acl-entry"][0][acl_type] = config
        rule_seq = kwargs.pop('rule_seq', rule_name_to_seq(rule_name))
        rule_create["openconfig-acl:acl-entries"]["acl-entry"][0]["sequence-id"] = rule_create[
            "openconfig-acl:acl-entries"]["acl-entry"][0]["config"]["sequence-id"] = int(rule_seq)
        if description:
            rule_create["openconfig-acl:acl-entries"]["acl-entry"][0]["config"]["description"] = "\"{}\"".format(description)
        rule_create["openconfig-acl:acl-entries"]["acl-entry"][0]["actions"]["config"]["forwarding-action"] = packet_action
        url = rest_urls['config_acl_rule'].format(table_name, acl_type.upper())
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


def show_acl_counters(dut, acl_table=None, acl_rule=None, acl_type="ip", **kwargs):
    """
    Get the ACL table
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param acl_table:
    :param acl_rule:
    :return:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = force_cli_type_to_klish(cli_type)
    if cli_type == "click":
        command = "aclshow"
        if acl_table:
            command += " -t {}".format(acl_table)
        if acl_rule:
            command += " -r {}".format(acl_rule)
        return st.show(dut, command)
    elif cli_type in ["klish", "rest-put", "rest-patch"]:
        output = show_ip_access_list(dut, acl_table, acl_type=acl_type, cli_type=cli_type, acl_rule=acl_rule, **kwargs)
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


def clear_acl_counter(dut, acl_table=None, acl_rule=None, acl_type=None, **kwargs):
    """
    Clear ACl counters
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param acl_table:
    :param acl_rule:
    :return:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = "klish" if cli_type in ["rest-patch", "rest-put"] else cli_type
    cli_type = force_cli_type_to_klish(cli_type)
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
        if acl_table:
            command = command + " {}".format(acl_table)
            if kwargs.get('interface'):
                intf_details = util_obj.get_interface_number_from_name(kwargs['interface'])
                command = command + " interface {} {}".format(intf_details['type'], intf_details['number'])
            elif kwargs.get('switch'):
                command = command + " Switch"
            else:
                pass
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
    if cli_type in util_obj.get_supported_ui_type_list():
        if acl_type in ["L3", "L3V6", "L2"]:
            acl_type_mapping = {"L3": "ip", "L3V6": "ipv6", "L2": "mac"}
            acl_type = acl_type_mapping[acl_type]
        acl_tables = util_obj.make_list(acl_table_name)
        for table in acl_tables:
            acl_table_obj = umf_acl.Acl(Name=table, Type=acl_type)
            result = acl_table_obj.unConfigure(dut, cli_type=cli_type)
            if not result.ok():
                st.error("test_step_failed: Delete ACL table: {}".format(result.data))
                return False
    elif cli_type == "click":
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
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        if not (acl_table_name and acl_type):
            st.report_fail("required_params_not_provided")
        acl_type_mapping = {"ip": "ACL_IPV4", "ipv6": "ACL_IPV6", "mac": "ACL_L2", "L3": "ACL_IPV4", "L3V6": "ACL_IPV6",
                            "L2": "ACL_L2"}
        acl_type = acl_type_mapping[acl_type]
        acl_tables = util_obj.make_list(acl_table_name)
        for table_name in acl_tables:
            url = rest_urls['config_acl_table'].format(table_name, acl_type)
            if not delete_rest(dut, rest_url=url):
                return False
    else:
        st.log("Unsupported CLI TYPE {}".format(cli_type))
        return False
    return True


def delete_acl_rule(dut, acl_table_name=None, acl_type=None, acl_rule_name=None, rule_seq=None, cli_type=""):
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
        if cli_type in util_obj.get_supported_ui_type_list():
            if not rule_seq:
                rule_seq = rule_name_to_seq(acl_rule_name)
            if acl_type in ["L3", "L3V6", "L2"]:
                acl_type_mapping = {"L3": "ip", "L3V6": "ipv6", "L2": "mac"}
                acl_type = acl_type_mapping[acl_type]
            acl_table_obj = umf_acl.Acl(Name=acl_table_name, Type=acl_type)
            rule_obj = umf_acl.AclRule(SeqNum=rule_seq, Acl=acl_table_obj)
            result = rule_obj.unConfigure(dut, cli_type=cli_type)
            if not result.ok():
                st.error("test_step_failed: Delete ACL rule: {}".format(result.data))
                return False
        elif cli_type == "click":
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
                    rule_seq = rule_name_to_seq(acl_rule_name)
                commands.append("no seq {}".format(rule_seq))
                commands.append("exit")
            else:
                commands = "no {} access-list {}".format(acl_type, acl_table_name)
            output = st.config(dut, commands, type=cli_type, skip_error_check=True)
            if "Entry not found" in output:
                st.report_fail("acl_rule_table_not_found")
        elif cli_type in ["rest-patch", "rest-put"]:
            acl_type_mapping = {"ip": "ACL_IPV4", "ipv6": "ACL_IPV6", "mac": "ACL_L2", "L3": "ACL_IPV4", "L3V6": "ACL_IPV6", "L2": "ACL_L2"}
            rest_urls = st.get_datastore(dut, "rest_urls")
            if acl_type in acl_type_mapping.keys():
                acl_type = acl_type_mapping[acl_type]
            else:
                st.log("ACL TYPE IS UNSUPPORTED -- {}".format(acl_type))
                return False
            if not rule_seq:
                rule_seq = rule_name_to_seq(acl_rule_name)
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
            match = {"rule_no": rule_name, "access_list_name": table_name, "packetscnt": packet_count}
            if not filter_and_select(acl_stats, ["packetscnt"], match):
                result = False
    if bindpoint:
        match = {"rulename": rule_name, "tablename": table_name, "bindpoint": bindpoint}
        if not filter_and_select(acl_stats, ["bindpoint"], match):
            match = {"rule_no": rule_name, "access_list_name": table_name, "bindpoint": bindpoint}
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
    if cli_type in util_obj.get_supported_ui_type_list():
        acl_mode = kwargs.get('counter')
        if kwargs.get('counter'):
            acl_obj = umf_acl.Root(CounterMode=acl_mode)
            result = acl_obj.configure(dut, cli_type=cli_type)
            if not result.ok():
                st.error("test_step_failed: Set hardware ACL mode: {}".format(result.data))
                return False
        return True
    elif cli_type == "click":
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
    if cli_type in ["click"]:
        st.log("Unsupported CLI type {} provided, required klish/rest".format(cli_type))
        return False
    if not (table_name and port and access_group_action and config):
        st.log("Mandatory parameters like table_name and/or port and/or access_group_action and/or config not passed")
        return False
    if cli_type in util_obj.get_supported_ui_type_list():
        if acl_type in ["L3", "L3V6", "L2"]:
            acl_type_mapping = {"L3": "ip", "L3V6": "ipv6", "L2": "mac"}
            acl_type = acl_type_mapping[acl_type]
        for intf in ports:
            intf_obj = umf_acl.Interface(Name=intf)
            if access_group_action.lower() in ["in", "ingress"]:
                acl_obj = umf_acl.IntfIngBindAcl(Acl=table_name, Type=acl_type, Interface=intf_obj)
            else:
                acl_obj = umf_acl.IntfEgrBindAcl(Acl=table_name, Type=acl_type, Interface=intf_obj)
            result = acl_obj.configure(dut, cli_type=cli_type) if config == "yes" else acl_obj.unConfigure(dut, cli_type=cli_type)
            if not result.ok():
                return False
    elif cli_type == "klish":
        commands = list()
        for intf in ports:
            if intf == "CtrlPlane":
                if not bind_ctrl_plane(dut, table_name=table_name, acl_type=acl_type):
                    st.error("Access group binding to control plane failed for table: {}".format(table_name))
                    return False
            elif intf != "Switch":
                interface_details = util_obj.get_interface_number_from_name(intf)
                commands.append("interface {} {}".format(interface_details.get("type"), interface_details.get("number")))
                commands.append("{}{} access-group {} {}".format(mode, acl_type, table_name, access_group_action))
                commands.append("exit")
            else:
                commands.append("{}{} access-group {} {}".format(mode, acl_type, table_name, access_group_action))
        response = st.config(dut, commands, type=cli_type, skip_error_check=skip_error_check)
        if "Error" in response:
            return False
    elif cli_type in ["rest-patch", "rest-put"]:
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
        action, set_action = "openconfig-acl:{}-acl-sets".format(access_group_action), "{}-acl-set".format(access_group_action)
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
    cli_type = force_cli_type_to_klish(cli_type)
    json_config = json.dumps(config)
    if cli_type == "click":
        json.loads(json_config)
        st.apply_json2(dut, json_config)
        return True
    elif cli_type in ["klish", "rest-patch", "rest-put"]:
        acl_config = json.loads(json_config)
        click_klish_acl_type_mapping = {"L3": "ip", "L3V6": "ipv6", "L2": "mac"}
        action_mapping = {"FORWARD": "permit", "DROP": "deny", "REDIRECT": "deny", "ACCEPT": "permit"}
        tcp_flag_mapping = {"4/4": "rst"}
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
            table_type_mapping.update({table_name: click_klish_acl_type_mapping[table_props.get("type")]})
            skip_bind = False if table_props.get("ports", '') else True
            if not create_acl_table(dut, acl_type=click_klish_acl_type_mapping[table_props.get("type")],
                                    ports=table_props.get("ports"), stage=table_props.get("stage"), skip_bind=skip_bind,
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
            data_dict.update({"cli_type": cli_type})
            data_dict.update({"table_name": acl_table_name})
            data_dict.update({"rule_name": acl_rule_name})
            if rule_details.get("PACKET_ACTION"):
                packet_action = rule_details.get("PACKET_ACTION") if "REDIRECT" not in rule_details.get("PACKET_ACTION") else "REDIRECT"
                data_dict.update({"packet_action": action_mapping[packet_action.upper()]})
            if table_type_mapping[acl_table_name] in ["ip", "ipCTRLPLANE"]:
                if rule_details.get("SRC_IP"):
                    data_dict.update({"src_ip": rule_details.get("SRC_IP")})
                if rule_details.get("DST_IP"):
                    data_dict.update({"dst_ip": rule_details.get("DST_IP")})
            elif table_type_mapping[acl_table_name] in ["ipv6", "ipv6CTRLPLANE"]:
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
                data_dict.update({"src_port_range": rule_details.get("L4_SRC_PORT_RANGE").replace("-", " ")})
            if rule_details.get("L4_DST_PORT_RANGE"):
                data_dict.update({"dst_port_range": rule_details.get("L4_DST_PORT_RANGE").replace("-", " ")})
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
                    create_acl_rule(dut, acl_type=table_type_mapping[acl_table_name], **data_dict)
            else:
                create_acl_rule(dut, acl_type=table_type_mapping[acl_table_name], **data_dict)
        return True
    else:
        st.log("Unsupported CLI TYPE {}".format(cli_type))
        return False


def show_ip_access_list(dut, table_name=None, acl_type="ip", cli_type="", acl_rule=None, **kwargs):
    """
    API to get the output of show ip access-lists
    :param dut:
    :param table_name:
    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    cli_type = force_cli_type_to_klish(cli_type)
    include_seq = kwargs.get('include_seq', False)
    if cli_type == "click":
        show_acl_counters(dut, acl_table=table_name, acl_type=acl_type, cli_type=cli_type)
    if cli_type == "klish":
        acl_type = get_acl_type(acl_type)
        if not acl_type:
            return False
        command = 'show {} access-lists {}'.format(acl_type, table_name) if table_name else 'show {} access-lists'.format(acl_type)
        if kwargs.get('interface'):
            intf_details = util_obj.get_interface_number_from_name(kwargs['interface'])
            command += ' interface {} {}'.format(intf_details['type'], intf_details['number'])
        elif kwargs.get('switch'):
            command += ' Switch'
        else:
            pass
        if acl_rule:
            rule_seq = rule_name_to_seq(acl_rule)
            if not rule_seq:
                st.error("rule_seq is mandatory for KLISH")
                return False
            if include_seq:
                command += ' | grep "seq {}"'.format(rule_seq)
            result = list()
            output = st.show(dut, command, type=cli_type, skip_error_check=True)
            if output:
                for acl_data in output:
                    if int(acl_data["rule_no"]) == int(rule_seq):
                        result.append(acl_data)
            return result
        else:
            return st.show(dut, command, type=cli_type, skip_error_check=True)
    elif cli_type in ["rest-patch", "rest-put"]:
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
                    if kwargs.get('counter_mode') == "per-interface-rule":
                        acl_type_map = {"openconfig-acl:ACL_L2": "mac", "openconfig-acl:ACL_IPV4": "ip", "openconfig-acl:ACL_IPV6": "ipv6"}
                        acl_counter = []
                        intf_entries = get_resp["openconfig-acl:acl"]["interfaces"]["interface"]
                        for intf_entry in intf_entries:
                            ingress_sets = intf_entry["ingress-acl-sets"]["ingress-acl-set"]
                            egress_sets = intf_entry["egress-acl-sets"]["egress-acl-set"]
                            for ingress_set in ingress_sets:
                                for rule in ingress_set["acl-entries"]["acl-entry"]:
                                    temp = {}
                                    temp["access_list_name"] = ingress_set["set-name"]
                                    temp["rule_no"] = str(rule["state"]["sequence-id"])
                                    temp["bytescnt"] = str(rule["state"]["matched-octets"])
                                    temp["packetscnt"] = str(rule["state"]["matched-packets"])
                                    temp["acl_type"] = acl_type_map.get(ingress_set["type"])
                                    acl_counter.append(temp)
                            for egress_set in egress_sets:
                                for rule in egress_set["acl-entries"]["acl-entry"]:
                                    temp = {}
                                    temp["access_list_name"] = egress_set["set-name"]
                                    temp["rule_no"] = str(rule["state"]["sequence-id"])
                                    temp["bytescnt"] = str(rule["state"]["matched-octets"])
                                    temp["packetscnt"] = str(rule["state"]["matched-packets"])
                                    temp["acl_type"] = acl_type_map.get(egress_set["type"])
                                    acl_counter.append(temp)
                        return acl_counter
                    if acl_data:
                        output.append(acl_data)
        st.log(output)
        result = list()
        if output:
            if table_name:
                for acls in output:
                    if table_name == acls["access_list_name"]:
                        if acl_rule:
                            rule_seq = rule_name_to_seq(acl_rule)
                            if int(acls["rule_no"]) == int(rule_seq):
                                result.append(acls)
                        else:
                            result.append(acls)
            elif acl_rule:
                for acls in output:
                    rule_seq = rule_name_to_seq(acl_rule)
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
                result.update({acl_type: list(set(data))})
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
        if cli_type in util_obj.get_supported_ui_type_list():
            acl_obj = umf_acl.Root()
            result = acl_obj.unConfigure(dut, cli_type=cli_type)
            if not result.ok():
                st.error('test_step_failed: Delete all ACLs: {}'.format(result.data))
                return False
        elif cli_type == "click":
            delete_acl_table(dut)
        elif cli_type == "klish":
            access_lists = get_access_lists(dut)
            st.log("ACCESS LISTS -- {}".format(access_lists))
            if access_lists:
                for acl_type, access_list in access_lists.items():
                    delete_acl_table(dut, acl_type=acl_type, acl_table_name=access_list, cli_type=cli_type)
        elif cli_type in ["rest-patch", "rest-put"]:
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
    if acl_type not in ["L3", "ip", "L3V6", "ipv6", "L2", "mac", "CTRLPLANE"]:
        st.log("UNSUPPORTED ACL TYPE == {}".format(acl_type))
        return False
    click_klish_acl_type_mapping = {"L3": "ip", "L3V6": "ipv6", "L2": "mac", "CRTLPLANE": "CTRLPLANE"}
    if acl_type:
        acl_type = click_klish_acl_type_mapping.get(acl_type, acl_type)
    else:
        st.warn("ACL TYPE IS REQUIRED")
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
    if cli_type in util_obj.get_supported_ui_type_list():
        acl_obj = umf_acl.CtrlPlaneIngBindAcl(Acl=table_name, Type=acl_type)
        result = acl_obj.configure(dut, cli_type=cli_type) if config == "yes" else acl_obj.unConfigure(dut, cli_type=cli_type)
        if not result.ok():
            st.error("Table {} failed to bind/unbind".format(table_name))
            return False
    elif cli_type == "klish":
        acl_type_mapping = {"ACL_IPV4": "ip", "ACL_IPV6": "ipv6", "ACL_L2": "mac"}
        acl_type = acl_type_mapping.get(acl_type, acl_type)
        bind = "" if config == "yes" else "no "
        commands = list()
        commands.append("line vty")
        commands.append("{}{} access-group {} in".format(bind, acl_type, table_name))
        commands.append("exit")
        output = st.config(dut, commands, type=cli_type, skip_error_check=skip_error_check)
        if "Error" in output:
            st.error("Table {} failed to bind".format(table_name))
            return False
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        url = rest_urls['control_plane_acl']
        if config == "yes":
            json_data = {"openconfig-acl-ext:control-plane": {"ingress-acl-sets": {"ingress-acl-set": [
                {"set-name": table_name, "type": acl_type, "config": {"set-name": table_name, "type": acl_type}}]}}}
            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=json_data):
                return False
        else:
            if not delete_rest(dut, rest_url=url):
                return False
    else:
        st.error("Unsupported cli type :{}".format(cli_type))
        return False
    return True


def config_acl_scale_rules(dut, table_name, **kwargs):
    """
    To Configure ACL rules as per scaling constant
    Author: Jagadish Chatrasi (jagadish.chatrasi@broadcom.com)
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    acl_type = kwargs.get('acl_type', 'L3')
    max_rules = kwargs.get('max_rules', 256)
    protocol = kwargs.get('protocol', 'UDP')
    skip_error = kwargs.get('skip_error', False)
    config = kwargs.get('config', 'yes')
    start_rule = kwargs.get('start_rule', 1)
    cli_type = 'klish' if cli_type == 'click' and config != 'yes' else cli_type
    if cli_type in util_obj.get_supported_ui_type_list():
        acl_type_mapping = {"L3": "ip", "L3V6": "ipv6", "L2": "mac"}
        action = lambda id: 'ACCEPT' if int(id) % 2 == 0 else 'DROP'
        macs = util_obj.get_random_mac_address(max_rules * 2)
        src_macs, dst_macs = macs[:max_rules], macs[max_rules:]
        acl_obj = umf_acl.Root()
        acl_table_obj = umf_acl.Acl(Name=table_name, Type=acl_type_mapping[acl_type.upper()])
        if config == 'yes':
            for id, src_mac, dst_mac in zip(range(int(start_rule), int(max_rules) + 1), src_macs, dst_macs):
                rule_desc = '{}_scale_rule_{}'.format(acl_type_mapping[acl_type.upper()], id)
                rule_obj = umf_acl.AclRule(SeqNum=int(id), Action=action(id), Description=rule_desc)
                if acl_type.upper() == 'L2':
                    setattr(rule_obj, 'SrcMac', src_mac)
                    setattr(rule_obj, 'DstMac', dst_mac)
                else:
                    setattr(rule_obj, 'IpProto', 'IP_{}'.format(protocol.upper()))
                    setattr(rule_obj, 'SrcPort', id)
                    setattr(rule_obj, 'DstPort', int(max_rules) - (id - 1))
                acl_table_obj.add_AclRule(rule_obj)
                acl_obj.add_Acl(acl_table_obj)
            result = acl_obj.configure(dut, cli_type=cli_type, timeout=120)
        else:
            for id in range(int(start_rule), int(max_rules) + 1):
                rule_obj = umf_acl.AclRule(SeqNum=int(id), Acl=acl_table_obj)
                result = rule_obj.unConfigure(dut, cli_type=cli_type)
            # result = acl_table_obj.unConfigure(dut, cli_type=cli_type)
        if not result.ok():
            st.log('test_step_failed: Config ACL SCALE: {}'.format(result.data))
            return False

    elif cli_type == 'click':
        rule_json = dict()
        action = lambda id: 'FORWARD' if int(id) % 2 == 0 else 'DROP'
        protocol_map = {"TCP": "6", "UDP": "17"}
        for id in range(int(start_rule), int(max_rules) + 1):
            rule_json["{}|RULE_{}".format(table_name, id)] = {"IP_PROTOCOL": protocol_map[protocol.upper()],
                                                              "L4_SRC_PORT": str(id), "L4_DST_PORT": str(int(max_rules) - (id - 1)), "PACKET_ACTION": action(id), "PRIORITY": str(65535 - (id - 1))}
        rule_json = {"ACL_RULE": rule_json}
        write_config_db(dut, rule_json)
    elif cli_type == 'klish':
        acl_type_mapping = {"L3": "ip", "L3V6": "ipv6", "L2": "mac"}
        commands = list()
        acl_type = acl_type_mapping[acl_type.upper()]
        action = lambda id: 'permit' if int(id) % 2 == 0 else 'deny'
        commands.append("{} access-list {}".format(acl_type, table_name))
        macs = util_obj.get_random_mac_address(max_rules * 2)
        src_macs, dst_macs = macs[:max_rules], macs[max_rules:]
        for id, src_mac, dst_mac in zip(range(int(start_rule), int(max_rules) + 1), src_macs, dst_macs):
            if config == 'yes':
                if acl_type == 'mac':
                    commands.append("seq {} {} host {} host {}".format(id, action(id), src_mac, dst_mac))
                else:
                    commands.append("seq {0} {1} {2} any eq {0} any eq {3}".format(id, action(id), protocol.lower(), int(max_rules) - (id - 1)))
            else:
                commands.append("no seq {}".format(id))
        commands.append("exit")
        response = st.config(dut, commands, type=cli_type, skip_error_check=skip_error)
        if any(error in response.lower() for error in errors_list):
            st.error("Failed to create ACL rules")
            return False
    elif cli_type in ['rest-patch', 'rest-put']:
        acl_type_mapping = {"L3": "ip", "L3V6": "ipv6", "L2": "mac"}
        action = lambda id: 'ACCEPT' if int(id) % 2 == 0 else 'DROP'
        rest_urls = st.get_datastore(dut, 'rest_urls')
        macs = util_obj.get_random_mac_address(max_rules * 2)
        src_macs, dst_macs = macs[:max_rules], macs[max_rules:]
        if config == 'yes':
            rule_create = {"openconfig-acl:acl-entries": {"acl-entry": []}}
            for id, src_mac, dst_mac in zip(range(int(start_rule), int(max_rules) + 1), src_macs, dst_macs):
                if acl_type.upper() == 'L2':
                    acl_rule = {acl_type_mapping[acl_type.upper()]: {"config": {"source-mac": src_mac, "destination-mac": dst_mac}},
                                "sequence-id": id, "actions": {"config": {"forwarding-action": action(id)}},
                                "config": {"sequence-id": id, "description": "{}_scale_rule_{}".format(acl_type_mapping[acl_type.upper()], id)}}
                else:
                    acl_rule = {acl_type_mapping[acl_type.upper()]: {"config": {"protocol": "IP_{}".format(protocol.upper())}},
                                "sequence-id": id,
                                "config": {"sequence-id": id, "description": "{}_scale_rule_{}".format(acl_type_mapping[acl_type.upper()], id)},
                                "actions": {"config": {"forwarding-action": action(id)}},
                                "transport": {"config": {"source-port": id, "destination-port": int(max_rules) - (id - 1)}}}
                rule_create["openconfig-acl:acl-entries"]["acl-entry"].append(acl_rule)
            url = rest_urls['config_acl_rule'].format(table_name, acl_type_mapping[acl_type.upper()].upper())
            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=rule_create, timeout=120):
                st.error("Failed to create ACL rules")
                return False
        else:
            for id in range(int(start_rule), int(max_rules) + 1):
                url = rest_urls['delete_acl_rule'].format(table_name, "ACL_{}".format(acl_type_mapping[acl_type.upper()].upper()), id)
                if not delete_rest(dut, rest_url=url):
                    st.error("Failed to delete ACL rules")
                    return False
    return True


def get_group_id(dut):
    """
    To get ACL group ID
    Author: Jagadish Chatrasi (jagadish.chatrasi@broadcom.com)
    """
    group_ids = list()
    command = "sonic-db-cli ASIC_DB keys *ACL_TABLE:oid*"
    out = st.show(dut, command)
    acl_oids = [entry['oid'] for entry in out if 'oid' in entry]
    for acl_oid in acl_oids:
        command = "sonic-db-cli ASIC_DB HGET VIDTORID oid:{}".format(acl_oid)
        out = st.show(dut, command)
        group_ids.append((int("0x{}".format(out[0]['oid'][-8:]), 16) & int(0xFFFFFFFF)) if isinstance(out, list) and out and 'oid' in out[0] and len(out[0]['oid']) >= 10 else 5)
    return group_ids


def verify_tcam_entries(dut, group_ids, acl_entries):
    """
    To get number of TCAM entries
    Author: Jagadish Chatrasi (jagadish.chatrasi@broadcom.com)
    """
    result_list = list()
    for group_id in group_ids:
        out = asic_show(dut, "fp show group {} brief".format(group_id))
        b = re.findall(r"entries_total\s*\=\s*(\d+)\s*\,\s*entries_free\s*\=\s*(\d+)\s*.*", out)
        if not (b and isinstance(b, list) and isinstance(b[0], tuple) and len(b[0]) >= 2):
            continue
        total_entries, free_entries = int(b[0][0]), int(b[0][1]) if b else [0, 0]
        st.debug("For group ID: {}, Total entries: {}, Free entries: {}".format(group_id, total_entries, free_entries))
        tcam_entries = total_entries - free_entries
        st.banner("For group ID: {}, Expected entries: {}, Actual entries: {}".format(group_id, acl_entries, tcam_entries))
        result_list.append(True if tcam_entries >= acl_entries else False)
    return all(result_list) if result_list else False


def show_access_group(dut, acl_type='ip', **kwargs):
    """
    :param dut:
    :param acl_type:
    :param kwargs:
    :return:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    if cli_type in ['rest-patch', 'rest-put']:
        cli_type = 'klish'
    cli_type = force_cli_type_to_klish(cli_type)
    if acl_type == 'ip':
        cmd = "show ip access-group"
    else:
        cmd = "show ipv6 access-group"

    output = st.show(dut, cmd, type=cli_type)
    return output


def verify_access_group(dut, acl_type='ip', **kwargs):
    """
    :param dut:
    :param kwargs:
    :return:
    """
    if 'remove_inactive' in kwargs:
        remove_inactive = True
        kwargs.pop('remove_inactive')
    else:
        remove_inactive = False
    parsed_output = show_access_group(dut, acl_type, **kwargs)
    if len(parsed_output) == 0:
        st.error("OUTPUT is Empty")
        return False

    if 'return_output' in kwargs:
        return parsed_output
    if remove_inactive:
        for ln in parsed_output:
            if ln['acl_state'] == 'Inactive':
                parsed_output.remove(ln)

    for each in kwargs.keys():
        match = {each: kwargs[each]}
        entries = filter_and_select(parsed_output, None, match)
        if not entries:
            st.error("Match not found for {}:   Expected - {} Actual - {} ".format(each, kwargs[each], parsed_output[0][each]))
            return False
    return True


def verify_access_list(dut, table_name=None, acl_type='ip', acl_rule=None, **kwargs):
    """
    :param dut:
    :param kwargs:
    :return:
    """
    parsed_output = show_ip_access_list(dut, table_name=table_name, acl_type=acl_type, acl_rule=acl_rule, **kwargs)
    if len(parsed_output) == 0:
        st.error("OUTPUT is Empty")
        return False

    if 'return_output' in kwargs:
        return parsed_output
    for each in kwargs.keys():
        match = {each: kwargs[each]}
        entries = filter_and_select(parsed_output, None, match)
        if not entries:
            st.error("Match not found for {}:   Expected - {} Actual - {} ".format(each, kwargs[each], parsed_output[0][each]))
            return False
    return True


def acl_cc_config(dut, action, **kwargs):
    """
    API To perform config operations of ACL Consistency Checker feature.
    Author: Jagadish Chatrasi (jagadish.chatrasi@broadcom.com)
    :param dut:
    :param action:
    :return: boolean
    """
    cli_type = "klish"  # Hard-coding cli_type as "klish" because this feature will be supported only in KLISH as per HLD
    skip_error = kwargs.get('skip_error', False)
    if action != "start" and action != "stop":
        st.error("Actions only start/stop supported")
        return False
    cmd = "consistency-check {} access-list".format(action)
    if kwargs.get("acl_type"):
        kwargs["acl_type"] = 'ipv4' if kwargs["acl_type"] == 'ip' else kwargs["acl_type"]
        if kwargs["acl_type"] not in ["ipv4", "ipv6", "mac"]:
            st.error("acl_type(s) only 'ipv4'/'ipv6'/'mac' are supported")
            return False
        cmd = cmd + " {}".format(kwargs["acl_type"])
        if kwargs.get("table_name"):
            cmd = cmd + " {}".format(kwargs["table_name"])
    response = st.show(dut, cmd, type=cli_type, skip_error_check=skip_error, skip_tmpl=True)
    if any(error in response.lower() for error in errors_list):
        st.error("Failed to create ACL rules")
        return False
    return True


def acl_cc_show(dut, type="status", **kwargs):
    """
    API to return show output of ACL Consistency Checker.
    Author: Jagadish Chatrasi (jagadish.chatrasi@broadcom.com)
    :param dut:
    :param type:
    :return: list
    """
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut, **kwargs))
    # CLI not supported in click and Rest.
    cli_type = cli_type if cli_type not in ["rest-patch", "rest-put", "click"] else "klish"
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    skip_error = kwargs.get('skip_error', False)
    skip_template = kwargs.get('skip_template', False)
    # cli_type = "klish" #Hard-coding cli_type as "klish" because this feature will be supported only in KLISH as per HLD
    if type not in ["status", "brief", "detail", "detail errors", "brief errors"]:
        st.error("Invalid show command type: {}".format(type))
        return []
    if type == "status":
        cmd = "show consistency-check status access-list"
    else:
        cmd = "show consistency-checker status access-list {}".format(type)
    return st.show(dut, cmd, type=cli_type, skip_error_check=skip_error, skip_tmpl=skip_template)


def acl_cc_verify(dut, type, verify_list):
    """
    API to verify ACL Consistency Checker show output.
    Author: Jagadish Chatrasi (jagadish.chatrasi@broadcom.com)
    :param dut:
    :param type:
    :param verify_list:
    :return: boolean
    """
    output = acl_cc_show(dut, type)
    for each in util_obj.make_list(verify_list):
        if not filter_and_select(output, None, each):
            st.error("'{}' is not matching in the output: {} ".format(each, output))
            return False
    return True


def get_access_group_interface_obj(dut, acl_name, acl_type='ip', key=None, **kwargs):
    """
    :param dut:
    :param kwargs:
    :return:
    acl_api.get_access_group_param(data.dut1, 'dot1xipv4acl1', key='obj_grp')
    """
    ret_val = {}
    acl_name = util_obj.make_list(acl_name)

    parsed_output = show_access_group(dut, acl_type, **kwargs)
    if len(parsed_output) == 0:
        st.error("OUTPUT is Empty")
        return ret_val

    for acl in acl_name:
        entries = filter_and_select(parsed_output, None, {u'access_list': acl})
        if not len(entries):
            st.log("ACL record not found for {}".format(acl))
            return ret_val
        else:
            for entry in entries:
                if 'interface' in entry.keys():
                    ret_val[entry['interface']] = entry['obj_grp']
                else:
                    st.log("ACL - Access-list interface details not found")
                    return ret_val
    return ret_val


def get_access_group_param(dut, acl_name, acl_type='ip', key=None, **kwargs):
    """
    :param dut:
    :param kwargs:
    :return:
    acl_api.get_access_group_param(data.dut1, 'dot1xipv4acl1', key='obj_grp')
    """
    ret_val = []
    acl_name = util_obj.make_list(acl_name)

    parsed_output = show_access_group(dut, acl_type, **kwargs)
    if len(parsed_output) == 0:
        st.error("OUTPUT is Empty")
        return ret_val

    for acl in acl_name:
        entries = filter_and_select(parsed_output, None, {u'access_list': acl})
        if not len(entries):
            st.log("ACL record not found for {}".format(acl))
            return ret_val
        else:
            for entry in entries:
                if key in entry.keys():
                    ret_val.append(entry[key])
                else:
                    st.log("ACL - Access-list {} did not match {}".format(acl, key))
                    return ret_val
    st.log("Access-lists - {} found match - {}".format(acl_name, ret_val))
    return ret_val


def verify_object_groups(dut, **kwargs):
    """
    :param dut:
    :param kwargs:
    :return:
    acl_api.verify_object_groups(data.dut1, obj_group='PAC_IPV4_SIP_ObjGrp_2', host_ip=['100.100.100.2'])
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    type = kwargs.pop('type', None)
    obj_group = kwargs.get('obj_group', None)
    if cli_type != 'klish':
        cli_type = 'klish'
    cmd = 'show object-groups '
    if type:
        cmd += 'type network'
    elif obj_group:
        cmd += obj_group
    output = st.show(dut, cmd, type=cli_type)

    if len(output) == 0:
        st.error("OUTPUT is Empty")
        return False

    if 'return_output' in kwargs:
        return output

    if 'host_ip' in kwargs:
        kwargs['host_ip'] = util_obj.make_list(kwargs['host_ip'])
        if output and 'host_ip' in output[0]:
            for ip in kwargs['host_ip']:
                if ip not in output[0]['host_ip']:
                    st.error("The expected host_ip {} is not found in actual entries {}".format(ip, output[0]['host_ip']))
                    return False
        kwargs.pop('host_ip', '')

    for each in kwargs.keys():
        match = {each: kwargs[each]}
        entries = filter_and_select(output, None, match)
        if not entries:
            st.error("Match not found for key '{}': Expected: {}, Actual - {}".format(each, kwargs[each], output[0][each]))
            return False
    return True


def config_key_profiles(dut, acl_type, **kwargs):
    '''
    To enable pac profile "config='yes'", To disable or set default profile "config='no'"
    config_key_profiles(dut1, acl_type='ip', direction='engress', config='yes')
    config_key_profiles(dut1, 'ip', direction='ingress', config='no')
    config_key_profiles(dut1, 'ipv6', direction='ingress', config='no')
    :param dut:
    :param acl_type: mac|ip|ipv6
    :param kwargs:
    :return:
    '''

    cli_type = st.get_ui_type(dut, **kwargs)
    if cli_type != 'klish':
        cli_type = 'klish'
    direction = kwargs.get('direction', 'ingress')
    config = kwargs.get('config', 'yes')
    skip_error = kwargs.pop('skip_error_check', False)
    profile, config = (direction + ' key-profile pac', '') if config == 'yes' else (direction + ' key-profile', 'no')

    cmd = list()
    cmd.append('hardware')
    cmd.append('tcam')
    cmd.append('{} {}-acl {}'.format(config, acl_type, profile))
    cmd.extend(['exit'] * 2)

    out = st.config(dut, cmd, type=cli_type, skip_error_check=skip_error)
    if 'Error' in out:
        return False
    return True


def config_flow_based_key_profiles(dut, profile_type, fbs_type, **kwargs):
    '''
    config_flow_based_key_profiles(dut1, profile_type='ipv4', fbs_type='qos')
    config_flow_based_key_profiles(dut1, 'ipv6', fbs_type='monitoring')
    config_flow_based_key_profiles(dut1, 'ipv4', fbs_type='qos', config='no')
    :param dut:
    :param profile_type: l2 | ipv4 | ipv6 | l2-ipv4 | l2-ipv6 | ip
    :param fbs_type: qos | monitoring | forwarding
    :param kwargs:
    :return:
    '''

    cli_type = st.get_ui_type(dut, **kwargs)
    if cli_type != 'klish':
        cli_type = 'klish'
    direction = kwargs.get('direction', 'ingress')
    config = kwargs.get('config', 'yes')
    skip_error = kwargs.pop('skip_error_check', False)
    profile, config = (direction + ' key-profile ' + profile_type, '') if config == 'yes' else (direction + ' key-profile', 'no')
    cmd = list()
    cmd.append('hardware')
    cmd.append('tcam')
    cmd.append('{} {}-fbs {}'.format(config, fbs_type, profile))
    cmd.extend(['exit'] * 2)

    out = st.config(dut, cmd, type=cli_type, skip_error_check=skip_error)
    if 'Error' in out:
        return False
    return True


def verify_hardware_key_profiles(dut, **kwargs):
    '''
    verify_hardware_key_profiles(dut1, key_profile='ip-acl', profile_type='pac', qualifier='DSCP', ingress_dir='Yes')
    verify_hardware_key_profiles(dut1, key_profile='ip-acl', profile_type='default', qualifier='DSCP', ingress_dir='Yes')
    verify_hardware_key_profiles(dut1, return_output='')
    verify_hardware_key_profiles(dut1, key_profile='fbs', profile_type='l2', qualifier='DEI', egress_dir='Yes')
    :param dut:
    :param kwargs:
    :return:
    '''
    cli_type = st.get_ui_type(dut, **kwargs)
    if cli_type != 'klish':
        cli_type = 'klish'
    key_profile = kwargs.get('key_profile', '')
    profile_type = kwargs.get('profile_type', '')

    cmd = 'show hardware tcam key-profile'
    if key_profile:
        cmd += ' {}'.format(key_profile)
    if profile_type:
        cmd += ' {}'.format(profile_type)

    output = st.show(dut, cmd, type=cli_type)

    if len(output) == 0:
        st.error("OUTPUT is Empty")
        return False

    if 'return_output' in kwargs:
        return output

    for item in ['key_profile', 'profile_type']:
        if item in kwargs:
            kwargs.pop(item, '')

    for entry in output:
        if 'qualifier' in entry:
            entry['qualifier'] = entry['qualifier'].strip()

    for each in kwargs.keys():
        match = {each: kwargs[each]}
        entries = filter_and_select(output, None, match)
        if not entries:
            st.error("Match not found for key '{}': Expected: {}, Actual - {}".format(each, kwargs[each], output[0][each]))
            return False
    return True
