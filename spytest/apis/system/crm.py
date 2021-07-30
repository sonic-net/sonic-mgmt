# This file contains the list of API's which performs CRM operations.
# Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
import re
import ast
import copy
from spytest import st
from spytest.utils import filter_and_select
from apis.system.rest import config_rest, delete_rest, get_rest
import apis.system.logging as lapi
import utilities.utils as uapi
from utilities.common import make_list


# Global values (Any addition, modification and deletion of below list can be done here only.)
type_list = ['percentage', 'used', 'free']
mode_list = ['high', 'low']
g_family_list = ['dnat', 'fdb', 'ipmc', 'ipv4_route', 'ipv4_neighbor', 'ipv4_nexthop', 'ipv6_route', 'ipv6_neighbor', 'ipv6_nexthop',
               'nexthop_group_member', 'nexthop_group_object', 'acl_table', 'acl_table_stats', 'acl_group', 'acl_group_entry',
               'acl_group_counter', 'snat', 'all']
counter_type = {'used': 'usedcount', 'free': 'availablecount'}
config_error_message = 'Error! Could not get CRM configuration.'

def crm_get_family_list(dut):
    retval = list(g_family_list)
    if not st.is_feature_supported("crm-all-families", dut):
        exclude = ["dnat", "ipmc", "snat"]
        exclude.extend(['acl_group_entry', 'acl_group_counter'])
        exclude.extend(['acl_table_stats'])
        for exc in exclude: retval.remove(exc)
    return retval

def crm_get_resources_count(dut, family,cli_type=""):
    """
    To get the CRM Resources counter
    Author : Amit Kaushik (amit.kaushik@broadcom.com)
    :param dut:
    :param family:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    family_cmd = family
    st.log("FAMILY: family={}".format(family))
    if family == 'acl_table':
        family_cmd = 'acl_group'
    elif family == 'acl_table_stats':
        family_cmd = 'acl_table'
    st.log("FAMILY: family_cmd={}".format(family_cmd))
    output = get_crm_resources(dut, family_cmd,cli_type=cli_type)
    st.log(output)
    # Handling family change in command and output in verify calls.
    if family == 'fdb':
        family = 'fdb_entry'
    elif family == 'dnat':
        family = 'dnat_entry'
    elif family == 'ipmc':
        family = 'ipmc_entry'
    elif family == 'snat':
        family = 'snat_entry'
    elif family == 'acl_group_entry':
        family = 'acl_entry'
    elif family == 'acl_group_counter':
        family = 'acl_counter'
    elif family == 'nexthop_group_object':
        family = 'nexthop_group'
    elif family == 'acl_table_stats':
        family = 'acl_table'
    entries = filter_and_select(output, None, {"resourcename": family})
    if not entries:
        st.report_fail("msg", family + ", entry_not_found")
    max_val = 0
    if family == 'acl_entry':
        for k in range(0, len(entries)):
            if entries[k]['tableid'] > entries[max_val]['tableid']:
                max_val = k
    st.log("Max Entries  {}".format(entries[max_val]))
    return (int(entries[max_val][counter_type["used"]]), int(entries[max_val][counter_type["free"]]))

def crm_get_aclgroup_resources_count(dut, family, bindpoint ="None", stage="INGRESS",cli_type=""):
    """
    To get the CRM Resources counter
    Author : Amit Kaushik (amit.kaushik@broadcom.com)
    :param dut:
    :param family:
    :param bindpoint:
    :param stage:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    st.log("FAMILY: family={}".format(family))
    output = get_crm_resources(dut, family, cli_type=cli_type)
    st.log(output)
    st.log("BindPoint {} Stage {}".format(bindpoint, stage))

    # Extract the entry
    entries = filter_and_select(output, None, {"resourcename": family, "bindpoint": bindpoint, "stage": stage })
    st.log(entries)
    if not entries:
        st.report_fail("Entry not found")
    return (int(entries[0][counter_type["used"]]), int(entries[0][counter_type["free"]]))

def crm_get_aclgroup_resources_min_allocated(dut, family,cli_type=""):
    """
    To get the CRM Resources counter
    Author : Amit Kaushik (amit.kaushik@broadcom.com)
    :param dut:
    :param family:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    st.log("FAMILY: family={}".format(family))
    output = get_crm_resources(dut, family,cli_type=cli_type)
    st.log(output)

    # Extract the entry
    entries = filter_and_select(output, None, {"resourcename": family})
    st.log(entries)
    if not entries:
        st.report_fail("Entry not found")
    max_val = 0
    if family == 'acl_entry':
        for k in range(0, len(entries)):
            if entries[k][counter_type["used"]] > entries[max_val][counter_type["used"]]:
                max_val = k
    st.log("Max Entries  {}".format(entries[max_val]))
    return int(entries[max_val][counter_type["used"]])

def set_crm_polling_interval(dut, polling_interval, cli_type=""):
    """
    Set CRM polling interval in seconds.
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param polling_interval: interface in seconds
    :param cli_type: click or klish designation:
    :return:
    """
    cli_type = st.get_ui_type(dut,cli_type=cli_type)
    command = ""
    if cli_type == "click":
        command = "crm config polling interval {}".format(polling_interval)
    elif cli_type == "klish":
        command = "crm polling interval {}".format(polling_interval)
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        url = rest_urls['crm_polling_interval']
        config_json = {"openconfig-system-crm:config": {"polling-interval": int(polling_interval)}}
        if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=config_json):
            return False
    else:
        st.error("Unsupported cli type: {}".format(cli_type))
        return False
    if command:
        rv = st.config(dut, command, type=cli_type, skip_error_check=True)
        if 'Error' in rv:
            st.error("{}".format(rv))
            return False
    return True

def set_crm_nopolling_interval(dut,cli_type=""):
    """
    Set no CRM polling (default).
    :param dut:
    :param cli_type: click or klish designation:
    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    if cli_type == "click":
        command = "crm config clear"
    elif cli_type == "klish":
        command = "no crm polling interval"
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        url = rest_urls['crm_summary']
        if not delete_rest(dut, rest_url=url):
            return False
    else:
        st.error("Unsupported cli type: {}".format(cli_type))
        return False
    rv = st.config(dut, command, type=cli_type)

    if 'Error' in rv:
        st.error("{}".format(rv))
        return False
    return True

def set_crm_nothresholds(dut, cli_type=""):
    """
    Set no thresholds (default).
    :param dut:
    :param cli_type: click or klish designation:
    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    command = ""
    if cli_type == "click":
        command = "crm config clear"
    elif cli_type == "klish":
        command = "no crm thresholds all"
    elif cli_type in ["rest-patch","rest-put"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        url = rest_urls['crm_thresholds']
        if not delete_rest(dut,rest_url=url):
            return False
    else:
        st.error("Unsupported cli type: {}".format(cli_type))
        return False
    if command:
        rv = st.config(dut, command, type=cli_type)
        if 'Error' in rv:
            st.error("{}".format(rv))
            return False
    return True

def get_crm_summary(dut, cli_type=""):
    """
    Get CRM polling interval in seconds.
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param cli_type: click or klish designation:
    :return: List of dictionary polling interface
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    if cli_type == "click":
        command = "crm show summary"
        output = st.show(dut, command, type=cli_type)
    elif cli_type == "klish":
        command = "show crm summary"
        output = st.show(dut, command, type=cli_type)
    elif cli_type in ["rest-patch", "rest-put"]:
        output = list()
        polling_interval = dict()
        rest_urls = st.get_datastore(dut, "rest_urls")
        url = rest_urls['crm_summary']
        result = get_rest(dut, rest_url=url)["output"]
        if "openconfig-system-crm:polling-interval" in result:
            polling_interval["pollinginterval"] = str(result["openconfig-system-crm:polling-interval"])
        output.append(polling_interval)
    else:
        st.error("Unsupported cli type: {}".format(cli_type))
    return output

def verify_crm_nopolling_interval(dut, cli_type=""):
    """
    Verify if CRM polling interval is configured
    :param dut:
    :param cli_type: click or klish designation:
    :return: bool
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    rv = get_crm_summary(dut,cli_type=cli_type)
    return ("Polling Interval" not in rv)

def set_crm_thresholds_type(dut, family, type, cli_type=""):
    """
    Configuring CRM Threshold Type.
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param family:
    :param type:
    :param cli_type: click or klish designation:
    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)

    family_list = crm_get_family_list(dut)
    if family not in family_list:
        st.log("CRM config for {} is not supported -- ignoring".format(family))
        return True

    family = family.lower()
    type = type.lower()
    if family == 'acl_table_stats':
        family = 'acl_table'
    family_list = crm_get_family_list(dut)
    if family not in family_list:
        log = "family: '{}' is invalid , use any of valid family from - {}".format(family, ','.join(family_list))
        st.error(log)
        return False
    if type not in type_list:
        log = "type:'{}' is invalid , use any of valid type from - {}".format(type, ','.join(type_list))
        st.error(log)
        return False
    command = ""
    if cli_type == "click":
        command = 'crm config thresholds {} type {}'.format(family.replace('_', ' '), type)
        if family == 'all':
            st.warn("Command: '{}' is not a Click command".format(command))
    elif cli_type == "klish":
        command = 'crm thresholds {} type {}'.format(family.replace('_', ' '), type)
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        url = rest_urls['crm_thresholds']
        config_json = {"openconfig-system-crm:threshold": {}}
        k = {"config": {}}
        k["config"]["type"] = type.upper()
        temp = dict()
        list1 = family.split("_")
        if len(list1) == 3:
            if "acl" in list1:
                temp = {list1[1]:{list1[2]:k}}
            else:
                temp["{}-{}".format(list1[1], list1[2])] =  k
            config_json["openconfig-system-crm:threshold"][list1[0]] = temp
        elif len(list1) == 2:
            temp[list1[0]] = {list1[1]: k}
            config_json["openconfig-system-crm:threshold"] = temp
        else:
            temp[list1[0]] = k
            config_json["openconfig-system-crm:threshold"] = temp
        if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=config_json):
            return False

    else:
        st.error("Unsupported cli type: {}".format(cli_type))
        return False
    if command:
        rv = st.config(dut, command, type=cli_type)
        if 'Error' in rv:
            st.error("{}".format(rv))
            return False
    return True

def set_crm_thresholds_value(dut, family, mode, value, cli_type=""):
    """
    Configuring CRM Threshold values.
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param family:
    :param mode:
    :param value:
    :param cli_type: click or klish designation:
    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    family = family.lower()
    mode = mode.lower()
    if family == 'acl_table_stats':
        family = 'acl_table'
    family_list = crm_get_family_list(dut)
    if family not in family_list:
        log = "family: '{}' is  invalid , use any of valid family from - {}".format(family, ','.join(family_list))
        st.error(log)
        return False
    if mode not in mode_list:
        log = "mode:'{}' is invalid , use any of valid mode from - {}".format(mode, ','.join(mode_list))
        st.error(log)
        return False
    command = ""
    if cli_type == "click":
        command = 'crm config thresholds {} {} {}'.format(family.replace('_', ' '), mode, value)
        if family == 'all':
            st.warn("Command: '{}' is not a Click command".format(command))
    elif cli_type == "klish":
        command = 'crm thresholds {} {} {}'.format(family.replace('_', ' '), mode, value)
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        url = rest_urls['crm_thresholds']
        config_json = {"openconfig-system-crm:threshold": {}}
        k = {"config": {}}
        k["config"][mode] = int(value)
        temp = dict()
        list1 = family.split("_")
        if len(list1) == 3:
            if "acl" in list1:
                temp = {list1[1]: {list1[2]: k}}
            else:
                temp["{}-{}".format(list1[1], list1[2])] = k
            config_json["openconfig-system-crm:threshold"][list1[0]] = temp
        elif len(list1) == 2:
            temp[list1[0]] = {list1[1]: k}
            config_json["openconfig-system-crm:threshold"] = temp
        else:
            temp[list1[0]] = k
            config_json["openconfig-system-crm:threshold"] = temp
        if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=config_json):
            return False

    else:
        st.error("Unsupported cli type: {}".format(cli_type))
        return False
    if command:
        rv = st.config(dut, command, type=cli_type)
        if 'Error' in rv:
            st.error("{}".format(rv))
            return False
    return True

def get_crm_thresholds(dut, family, cli_type=""):
    """
    GET CRM Threshold w.r.t family.
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param family:
    :param cli_type: click or klish designation:
    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    family = family.lower()
    # Handling few show crm family cli commands
    if family in ['acl_group_entry', 'acl_group_counter', 'acl_table_stats']:
        if st.is_feature_supported("crm-all-families", dut):
            family = 'all'
            cli_type = 'klish'
    family_list = crm_get_family_list(dut)
    if family not in family_list:
        log = "family:'{}' is invalid , use any of valid family from - {}".format(family, ','.join(family_list))
        st.error(log)
        return False
    if cli_type == "click":
        command = 'crm show thresholds {}'.format(family.replace('_', ' '))
        output = st.show(dut, command, type=cli_type)
    elif cli_type == "klish":
        command = 'show crm thresholds {}'.format(family.replace('_', ' '))
        output = st.show(dut, command, type=cli_type)
    elif cli_type in ["rest-patch","rest-put"]:
        output = list()
        rest_urls = st.get_datastore(dut, "rest_urls")
        url = rest_urls['crm_thresholds']
        result = get_rest(dut,rest_url=url)["output"]["openconfig-system-crm:threshold"]
        family_mapping = {"nexthop_group_member": "nexthop_group-member",
                          "nexthop_group_object": "nexthop_group-object"}
        families = make_list(family)
        if "all" in families:
            families = family_list
            families.remove("all")
        for family2 in families:
            crm_threshold = {}
            crm_threshold["resourcename"] = family2
            family2 = family_mapping.get(family2, family2).split("_")
            for each in family2:
                result = result[each]
            if result["state"].get("type",""):
                crm_threshold["thresholdtype"] = result["state"]["type"].lower()
                crm_threshold["highthreshold"] = result["state"]["high"]
                crm_threshold["lowthreshold"] = result["state"]["low"]
                output.append(crm_threshold)
    else:
        st.error("Unsupported cli type: {}".format(cli_type))
        return False
    return output

def get_crm_resources(dut, family, cli_type=""):
    """
    GET CRM resources w.r.t family.
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param family:
    :param cli_type: click or klish designation:
    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    family = family.lower()
    family_list = crm_get_family_list(dut)
    if family not in family_list:
        log = "family:'{}' is invalid , use any of valid family from - {}".format(family, ','.join(family_list))
        st.error(log)
        return False
    if family in ['acl_table']:
        family = 'acl_group'
    if family in ['acl_table_entry', 'acl_table_counter', 'acl_table_stats', 'acl_group_entry', 'acl_group_counter']:
        temp = family
        family = 'acl_table'
    if cli_type == "click":
        command = 'crm show resources {}'.format(family.replace('_', ' '))
        output = st.show(dut, command, type=cli_type)
    elif cli_type == "klish":
        command = 'show crm resources {}'.format(family.replace('_', ' '))
        output = st.show(dut, command, type=cli_type)
    elif cli_type in ["rest-patch","rest-put"]:
        output = list()
        rest_urls = st.get_datastore(dut, "rest_urls")
        if family == "all":
            family = ['dnat', 'fdb', 'ipmc', 'ipv4_route','ipv4_neighbor','ipv4_nexthop','ipv6_route','ipv6_neighbor',
                      'ipv6_nexthop', 'nexthop_group_member', 'nexthop_group_object', 'acl_table','acl_group']
            for each_family in family:
                output.append(get_crm_resources(dut,each_family))
        elif "acl" not in family:
            resource = dict()
            url = rest_urls['crm_resources'].format("statistics")
            result = get_rest(dut, rest_url=url)["output"]["openconfig-system-crm:statistics"]
            if "_" not in family:
                resource["resourcename"] = "{}_entry".format(family)
                resource["usedcount"] = str(result["{}-entries-used".format(family)])
                resource["availablecount"] = str(result["{}-entries-available".format(family)])
            else:
                family = family.replace("_object","")
                resource["resourcename"] = "{}".format(family)
                resource["usedcount"] = str(result["{}s-used".format(family.replace("_","-"))])
                resource["availablecount"] = str(result["{}s-available".format(family.replace("_","-"))])
            output.append(resource)
        else:
            if family == "acl_table":
                url = rest_urls['crm_resources'].format("acl-table-statistics")
                result = get_rest(dut, rest_url=url)["output"]["openconfig-system-crm:acl-table-statistics"]
                for each in result["acl-table-statistics-list"]:
                    temp = {}
                    temp["tableid"] = each["id"]
                    temp["resourcename"] = "acl_counter"
                    temp["availablecount"] = str(each["counter"]["available"])
                    temp["usedcount"] = str(each["counter"]["used"])
                    output.append(copy.copy(temp))
                    temp["resourcename"] = "acl_entry"
                    temp["availablecount"] = str(each["entry"]["available"])
                    temp["usedcount"] = str(each["entry"]["used"])
                    output.append(copy.copy(temp))
            else:
                url = rest_urls['crm_resources'].format("acl-statistics")
                result = get_rest(dut, rest_url=url)["output"]["openconfig-system-crm:acl-statistics"]
                for stage,stage_val in result.items():
                    resource = {}
                    resource["state"] = stage.upper()
                    for bindpoint, bindpoint_value in stage_val.items():
                        resource["bindpoint"] = bindpoint.upper()
                        families = ["acl_group","acl_table"]
                        for each in families:
                            resource["resourcename"] = each
                            acl = each.replace("acl_","")+"s"
                            resource["availablecount"] = int(bindpoint_value["{}-available".format(acl)])
                            resource["usedcount"] = int(bindpoint_value["{}-used".format(acl)])
                            output.append(copy.copy(resource))
    else:
        st.error("Unsupported cli type: {}".format(cli_type))
        return False
    return output

def verify_crm_summary(dut, pollinginterval=None, cli_type=""):
    """
    To Verify the CRM parameters
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param pollinginterval:
    :param cli_type: click or klish designation:
    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    output = get_crm_summary(dut, cli_type)
    entries = filter_and_select(output, None, {"pollinginterval": str(pollinginterval)})
    if not entries:
        st.error("Given {} and configured pollinginterval is not same.".format(pollinginterval))
        return False
    return True

def verify_crm_thresholds(dut, family, thresholdtype=None, highthreshold=None, lowthreshold=None, cli_type=""):
    """
    To verify the CRM Threshold parameters
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param family:
    :param thresholdtype:
    :param highthreshold:
    :param lowthreshold:
    :param cli_type: click or klish designation:
    :return:
    """

    family_list = crm_get_family_list(dut)
    if family not in family_list:
        st.log("CRM config for {} is not supported -- ignoring".format(family))
        return True

    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    output = get_crm_thresholds(dut, family, cli_type)
    # Handling few crm family cli commands for verify
    if cli_type in ['click', 'klish']:
        if family == "fdb":
            family = 'fdb_entry'
    if family == "dnat":
        family = 'dnat_entry'
    if family == "ipmc":
        family = 'ipmc_entry'
    if family == "snat":
        family = 'snat_entry'
    if family == "acl_group_entry":
        family = 'acl_entry'
    if family == "acl_group_counter":
        family = 'acl_counter'
    if family == 'nexthop_group_object':
        family = 'nexthop_group'
    entries = filter_and_select(output, None, {"resourcename": family})
    if not entries:
        st.error("No Entry found for given family in the table - {}".format(family))
        return False
    if thresholdtype and not filter_and_select(entries, None, {"resourcename": family, "thresholdtype": thresholdtype}):
        st.error("Configured and Provided thresholdtype is not match.")
        return False
    if lowthreshold and not filter_and_select(entries, None, {"resourcename": family, 'lowthreshold': lowthreshold}):
        st.error("Configured and Provided lowthreshold is not match.")
        return False
    if highthreshold and not filter_and_select(entries, None, {"resourcename": family, "highthreshold": highthreshold}):
        st.error("Configured and Provided highthreshold is not match.")
        return False
    return True

def verify_crm_resources(dut, family, availablecount=None, usedcount=None, tableid=None, bindpoint=None, stage=None, cli_type=""):
    """
    To verify the CRM Resources parameters
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param family:
    :param availablecount:
    :param usedcount:
    :param tableid:
    :param bindpoint:
    :param stage:
    :param cli_type: click or klish designation:
    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    if family == 'acl_entry':
        family = 'acl_table_entry'
    elif family == 'acl_counter':
        family = 'acl_table_counter'
    elif family == 'acl_table_stats':
        family = 'acl_table'

    output = get_crm_resources(dut, family, cli_type)
    # Handling few crm family cli commands for verify
    if family == "fdb":
        family = 'fdb_entry'
    if family == "dnat":
        family = 'dnat_entry'
    if family == "ipmc":
        family = 'ipmc_entry'
    if family == "snat":
        family = 'snat_entry'
    if family == "acl_group_entry":
        family = 'acl_entry'
    if family == "acl_group_counter":
        family = 'acl_counter'
    if family == "acl_table_counter":
        family = 'acl_counter'
    if family == "acl_table_entry":
        family = 'acl_entry'
    if family == 'nexthop_group_object':
        family = 'nexthop_group'

    entries = filter_and_select(output, None, {"resourcename": family})
    if not entries:
        st.error("No Entry found for given family in the table - {}".format(family))
        return False
    if availablecount and not filter_and_select(entries, None,
                                                {"resourcename": family, "availablecount": availablecount}):
        st.error("Available and Provided availablecount is not match.")
        return False
    if usedcount and not filter_and_select(entries, None, {"resourcename": family, 'usedcount': usedcount}):
        st.error("Available and Provided usedcount is not match.")
        return False
    if tableid and not filter_and_select(entries, None, {"resourcename": family, "tableid": tableid}):
        st.error("Available and Provided tableid is not match.")
        return False
    if bindpoint and not filter_and_select(entries, None, {"resourcename": family, "bindpoint": bindpoint}):
        st.error("Available and Provided bindpoint is not match.")
        return False
    if stage and not filter_and_select(entries, None, {"resourcename": family, "stage": stage}):
        st.error("Available and Provided stage is not match.")
        return False
    return True

def verify_crm_clear_config(dut, clear_type='all'):
    """
    API to check cleared CRM configuration.
    :param dut:
    :param cli_type: click or klish designation:
    :param clear_type: verify flag; 'all' or not
    :return: Pass or Fail (True or False)
    """

    cmd = "redis-dump -d 4 -k 'CRM|Config' -y"
    cfg = st.show(dut, cmd, skip_tmpl = True, skip_error_check = True)
    if clear_type == 'threshold':
        return ("_threshold" not in cfg)
    elif clear_type == 'all':
        return ("_threshold" not in cfg) and ("polling" not in cfg)

    return False

def get_crm_logging_details(dut, severity=None, filter_list=None, lines=None):
    """
    To get the CRM log parameters
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param dut:
    :param severity:
    :param filter_list:
    :param lines:
    :return:
    """
    temp = {}
    crm_log = r"checkCrmThresholds:\s+(\S+)\s+(\S+)\s+for\s+(\S+)\s+(\d+)\%\s+Used\s+count\s+(\d+)\s+" \
              r"free\s+count\s+(\d+)"

    all_logs = lapi.show_logging(dut, severity, filter_list, lines)
    if not all_logs:
        st.error("No logs found.")
        return temp
    log_data = uapi.log_parser(all_logs[-1])
    if not log_data:
        st.error("Unable to parse the log message - {}".format(log_data))
        return temp
    log_data = log_data[0]['message']
    out = re.findall(crm_log, log_data)
    if not out:
        st.error("Not match with CRM log pattern - {}".format(log_data))
        return temp
    temp['family'] = out[0][0]
    temp['action'] = out[0][1]
    temp['type'] = out[0][2]
    temp['percentage'] = ast.literal_eval(out[0][3])
    temp['used'] = ast.literal_eval(out[0][4])
    temp['free'] = ast.literal_eval(out[0][5])
    return temp

def threshold_polling(dut, severity=None, filter_list=None, lines=None, iteration=10, delay=1):
    """
    API to poll the threshold
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param severity:
    :param filter_list:
    :param lines:
    :param iteration:
    :param delay:
    :return:
    """
    i=1
    while True:
        out =  get_crm_logging_details(dut, severity, filter_list, lines)
        if out:
            st.log("Threshold message found in {} iteration".format(i))
            return out
        if i > iteration:
            st.log("Max tries {} reached".format(i))
            return False
        i += 1
        st.wait(delay)

def set_crm_clear_config(dut, cli_type=""):
    """
    API to clear CRM configuration.
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param cli_type: click or klish designation:
    :return: Command output
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    if cli_type == "click":
        command = "crm config clear"
        if not st.is_feature_supported("crm-config-clear-command", dut):
            st.community_unsupported(command, dut)
            command = "crm config polling interval 9999999"
    elif cli_type == "klish":
        command = "no crm all"
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        url = rest_urls['crm_all']
        if not delete_rest(dut, rest_url=url):
            return False
        return True
    else:
        st.error("Unsupported cli type: {}".format(cli_type))
        return False
    return st.config(dut, command, type=cli_type)

