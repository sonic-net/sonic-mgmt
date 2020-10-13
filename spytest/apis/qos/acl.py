# This file contains the list of API's which performs ACL operations.
# Author : Chaitanya Vella (Chaitanya-vella.kumar@broadcom.com) and Prudvi Mangadu (prudvi.mangadu@broadcom.com)

from spytest import st
import json
import tempfile
import utilities.utils as util_obj
from spytest.utils import filter_and_select
import os
import re


def create_acl_table(dut, skip_verify=True, **kwargs):
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
    cli_type = kwargs.get("cli_type","click")
    table_name = kwargs.get("table_name", None)
    if cli_type == "click":
        st.log("Creating ACL table ...")
        acl_data = kwargs
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
        # reboot.config_save(dut)
        if not skip_verify:
            if not verify_acl_table(dut, acl_data["name"]):
                return False
    else:
        if not table_name:
            st.log("Mandatory parameter table name not passed")
            return False
        commands = list()
        commands.append("ip access-list {}".format(table_name))
        commands.append("exit")
        st.config(dut, commands, type=cli_type, skip_error_check=skip_verify)
    return True


def create_acl_rule(dut, skip_verify=True, type1=None, type2=None, **kwargs):
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
    cli_type = kwargs.get("cli_type","click")
    table_name = kwargs.get("table_name", None)
    rule_name = kwargs.get("rule_name", None)
    packet_action = kwargs.get("packet_action", "deny")
    l4_protocol = kwargs.get("l4_protocol", None)
    src_ip = kwargs.get("SRC_IP", "any")
    dst_ip = kwargs.get("DST_IP","any")
    dscp_value = kwargs.get("dscp_value")
    tcp_flag = kwargs.get("tcp_flag", None)

    st.log("Creating ACL rule ...")
    if cli_type == "click":
        acl_rule_data = kwargs
        if not acl_rule_data:
            st.error("ACL rule creation failed because of invalid data")
            return False
        acl_table_rules = dict()
        acl_rules = dict()
        excluded_keys = ["table_name", "rule_name"]
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
    else:
        if not (table_name and l4_protocol):
            st.log("Mandatory parameters like table name and/or rule name and/or l4 protocol not passed")
            return False
        commands = list()
        commands.append("ip access-list {}".format(table_name))
        if rule_name:
            rule_seq = int(re.findall(r'\d+', rule_name)[0])
            if type1 and type2:
                command = "seq {} {} {} {} {} {} {}".format(rule_seq, packet_action, l4_protocol, type1, src_ip, type2,
                                                            dst_ip)
            elif type1:
                command = "seq {} {} {} {} {} {}".format(rule_seq, packet_action, l4_protocol, type1, src_ip, dst_ip)
            elif type2:
                command = "seq {} {} {} {} {} {}".format(rule_seq, packet_action, l4_protocol, src_ip, type2, dst_ip)
            else:
                command = "seq {} {} {} {} {}".format(rule_seq, packet_action, l4_protocol, src_ip, dst_ip)
            if tcp_flag:
                if not l4_protocol == "tcp":
                    st.log("l4 protocol should be tcp")
                    return False
                command += " tcp_flag".format(tcp_flag)
            if dscp_value:
                command += " dscp {}".format(dscp_value)
            commands.append(command)
        commands.append('exit')
        st.config(dut, commands, type=cli_type, skip_error_check=skip_verify)
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


def show_acl_counters(dut, acl_table=None, acl_rule=None):
    """
    Get the ACL table
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)

    :param dut:
    :param acl_table:
    :param acl_rule:
    :return:
    """
    command = "aclshow"
    if acl_table:
        command += " -t {}".format(acl_table)
    if acl_rule:
        command += " -r {}".format(acl_rule)
    return st.show(dut, command)


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


def clear_acl_counter(dut, acl_table=None, acl_rule=None):
    """
    Clear ACl counters
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)

    :param dut:
    :param acl_table:
    :param acl_rule:
    :return:
    """
    command = "aclshow -c"
    if acl_table:
        command += " -t {}".format(acl_table)
    if acl_rule:
        command += " -r {}".format(acl_rule)
    st.config(dut, command)
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


def delete_acl_table(dut, acl_table_name=None, cli_type="click"):
    """
    API to delete the ACL table from DUT
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param acl_table_name: table name can be a string or list
    :return:
    """
    st.log("Deleting ACL table ...")
    if cli_type == "click":
        command = "config acl table delete"
        if st.is_community_build():
            command = "config acl remove table"
        if acl_table_name:
            table_name = list([str(e) for e in acl_table_name]) if isinstance(acl_table_name, list) \
                else [acl_table_name]
            for acl_table in table_name:
                command = "{} {}".format(command, acl_table)
                st.config(dut, command)
        else:
            st.config(dut, command)
    else:
        if not acl_table_name:
            st.report_fail("acl_table_name_missing")
        command = "no ip access-list {}".format(acl_table_name)
        output = st.config(dut, command, type=cli_type, skip_error_check=True)
        if "Entry not found" in output:
            st.log("acl_table_not_found")


def delete_acl_rule(dut, acl_table_name=None, acl_rule_name=None, cli_type="click"):
    """
    API to delete ACL rule of an ACL table
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param acl_table_name:
    :param acl_rule_name: Rule can be a string or list
    :return:
    """
    st.log("Deleting ACL rule ...")
    if acl_table_name:
        if cli_type == "click":
            command = "config acl rule delete {}".format(acl_table_name)
            if acl_rule_name:
                rule_name = list([str(e) for e in acl_rule_name]) if isinstance(acl_rule_name, list) else [acl_rule_name]
                for acl_rule in rule_name:
                    command = "config acl rule delete {} {}".format(acl_table_name, acl_rule)
                    st.config(dut, command)
            else:
                st.config(dut, command)
        else:
            if acl_rule_name:
                commands = list()
                commands.append("ip access-list {}".format(acl_table_name))
                rule_seq = int(re.findall(r'\d+', acl_rule_name)[0])
                commands.append("no seq {}".format(rule_seq))
                commands.append("exit")
            else:
                commands = "no ip access-list {}".format(acl_table_name)
            output = st.config(dut, commands, type=cli_type, skip_error_check=True)
            if "Entry not found" in output:
                st.report_fail("acl_rule_table_not_found")
    else:
        st.report_fail("acl_table_name_missing")


def clear_acl_config(dut, acl_table_name=None):
    """
    API to clear ACL configuration from DUT
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param acl_table_name:
    :return:
    """
    if acl_table_name:
        delete_acl_rule(dut, acl_table_name)
    delete_acl_table(dut)


def verify_acl_stats(dut, table_name, rule_name, packet_count=None, bindpoint=None):
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
    acl_stats = show_acl_counters(dut, table_name, rule_name)
    if packet_count:
        match = {"rulename": rule_name, "tablename": table_name, "packetscnt": packet_count}
        if not filter_and_select(acl_stats, ["packetscnt"], match):
            result = False
    if bindpoint:
        match = {"rulename": rule_name, "tablename": table_name, "bindpoint": bindpoint}
        if not filter_and_select(acl_stats, ["bindpoint"], match):
            result = False
    return result


def poll_for_acl_counters(dut, acl_table=None, acl_rule=None, itr=5, delay=2):
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
        result = show_acl_counters(dut, acl_table, acl_rule)
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
    command = "config hardware access-list"
    if kwargs.get('counter'):
        command += " -c {}".format(kwargs['counter'])
    elif kwargs.get('loockup'):
        command += " -l {}".format(kwargs['loockup'])
    st.config(dut, command)


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

def config_access_group(dut, **kwargs):
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


    st.log("Assigning Access-group action on interface")
    if not cli_type == "klish":
        st.log("Unsupported CLI type {} provided, required klish".format(cli_type))
        return False
    if not (table_name and port and access_group_action and config ):
        st.log("Mandatory parameters like table_name and/or port and/or access_group_action and/or config not passed")
        return False
    interface_details = util_obj.get_interface_number_from_name(port)
    commands = list()
    commands.append("interface {} {}".format(interface_details.get("type"), interface_details.get("number")))
    commands.append("{}ip access-group {} {}".format(mode,table_name,access_group_action))
    commands.append("exit")
    st.config(dut, commands, type=cli_type, skip_error_check=skip_error_check)
    return True


