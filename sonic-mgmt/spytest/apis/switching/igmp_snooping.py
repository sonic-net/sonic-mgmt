# This file contains the list of API's to performs IGMP Snooping operations.
# Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)

from spytest import st
import utilities.common as utils
import json
from apis.system.switch_configuration import write_config_db
from re import search
from apis.system.rest import config_rest, delete_rest, get_rest

DEFAULTS = {
            "version": 2,
            "query_interval": 125,
            "last_member_query_interval": 1000,
            "query_max_response_time": 10,
            }


def config(dut, *argv, **kwargs):
    """
    Calls to Configure IGMP Snooping.
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param :dut:
    :param :vlan:
    :param :mode:
    :param :querier:
    :param :fast_leave:
    :param :query_interval:
    :param :last_member_query_interval:
    :param :query_max_response_time:
    :param :version:
    :param :mrouter_interface:
    :param :static_group_interface:
    :param :static_group_address:
    :param :cli_type:   default - klish
    :param :no_form:   default - False
    :return:

    Usage:
    config(vars.D1, 'mode', 'querier', 'fast_leave', query_interval=100, last_member_query_interval=300,
    query_max_response_time=400, version=2, mrouter_interface=vars.D1D2P1, static_group_interface=vars.D1D2P2,
    static_group_address='224.1.2.3', cli_type='klish')

    config(vars.D1, 'no_form' , 'mode', 'querier', 'fast_leave', query_interval='',
    last_member_query_interval='', query_max_response_time='', version='', mrouter_interface=vars.D1D2P1,
    static_group_interface=vars.D1D2P2, static_group_address='224.1.2.3', cli_type='klish')

    """
    result = True
    cli_type = st.get_ui_type(dut, **kwargs)
    no_form = 'no' if 'no_form' in argv else ''
    if not kwargs.get('vlan'):
        st.error('vlan - Mandatory parameter is missing.')
        return False
    vlan = kwargs.get('vlan')
    if cli_type == 'klish':
        command = "ip igmp snooping"
        sub_cmd = []
        if 'mode' in argv:
            sub_cmd.append('')
        if "querier" in argv:
            sub_cmd.append("querier")
        if "fast_leave" in argv:
            sub_cmd.append("fast-leave")
        for each_cmd in kwargs:
            if each_cmd in ['query_interval', 'last_member_query_interval', 'query_max_response_time', 'version']:
                if no_form:
                    kwargs[each_cmd] = ''
                sub_cmd.append("{} {}".format(each_cmd.replace('_', '-'), kwargs[each_cmd]))
        if "mrouter_interface" in kwargs:
            sub_cmd.append("mrouter interface {}".format(kwargs['mrouter_interface']))
        if "static_group_interface" in kwargs and "static_group_address" in kwargs:
            sub_cmd.append("static-group {} interface {}".format(kwargs['static_group_address'],
                                                                 kwargs['static_group_interface']))
        command_list = ["{} {} {}".format(no_form, command, each) for each in sub_cmd]
        st.config(dut, ["interface Vlan {}".format(vlan)] + command_list + ["exit"], type=cli_type)
    elif cli_type == 'click':
        command = 'sudo config igmp_snooping'
        config0 = 'disable' if no_form else 'enable'
        config1 = 'del' if no_form else 'add'
        sub_cmd = []
        if "mode" in argv:
            sub_cmd.append("{} {}".format(config0, vlan))
        if "querier" in argv:
            sub_cmd.append("querier-{} {}".format(config0, vlan))
        if "fast_leave" in argv:
            sub_cmd.append("fast-leave-{} {}".format(config0, vlan))
        for each_cmd in kwargs:
            if each_cmd in ['query_interval', 'last_member_query_interval', 'query_max_response_time', 'version']:
                if no_form:
                    kwargs[each_cmd] = DEFAULTS[each_cmd]
                sub_cmd.append("{} {} {}".format(each_cmd.replace('_', '-'), vlan, kwargs[each_cmd]))
        if "mrouter_interface" in kwargs:
            sub_cmd.append("mrouter-{} {} {}".format(config1, vlan, kwargs['mrouter_interface']))
        if "static_group_interface" in kwargs and "static_group_address" in kwargs:
            sub_cmd.append("static-group-{} {} {} {}".format(config1, vlan, kwargs['static_group_interface'],
                                                             kwargs['static_group_address']))
        command_list = ["{} {}".format(command, each) for each in sub_cmd]
        st.config(dut, '; '.join(command_list), type=cli_type)
    elif cli_type in ["rest-put", "rest-patch"]:
        vlanid = "Vlan{}".format(vlan)
        rest_urls = st.get_datastore(dut, "rest_urls")
        if "mode" in argv:
            url = rest_urls['igmp_snooping_vlan_config_mode'].format(vlanid)
            if no_form:
                payload = json.loads("""{"openconfig-network-instance-deviation:enabled": false}""")
            else:
                payload = json.loads("""{"openconfig-network-instance-deviation:enabled": true}""")
            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=payload):
                result = False
        if "querier" in argv:
            url = rest_urls['igmp_snooping_vlan_config_querier'].format(vlanid)
            if no_form:
                payload = json.loads("""{"openconfig-network-instance-deviation:querier": false}""")
            else:
                payload = json.loads("""{"openconfig-network-instance-deviation:querier": true}""")
            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=payload):
                result = False
        if "fast_leave" in argv:
            url = rest_urls['igmp_snooping_vlan_config_fast_leave'].format(vlanid)
            if no_form:
                payload = json.loads("""{"openconfig-network-instance-deviation:fast-leave": false}""")
            else:
                payload = json.loads("""{"openconfig-network-instance-deviation:fast-leave": true}""")
            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=payload):
                result = False
        for each_cmd in kwargs:
            if each_cmd in ['query_interval', 'last_member_query_interval', 'query_max_response_time', 'version']:
                url = rest_urls['igmp_snooping_vlan_config_{}'.format(each_cmd)].format(vlanid)
                if no_form:
                    if not delete_rest(dut, rest_url=url):
                        result = False
                else:
                    payload = {"openconfig-network-instance-deviation:{}".format(each_cmd.replace('_', '-')): int(kwargs[each_cmd])}
                    if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=payload):
                        result = False
            elif each_cmd in ['mrouter_interface']:
                if no_form:
                    url = rest_urls['igmp_snooping_vlan_delete_{}'.format(each_cmd)].format(vlanid, [kwargs[each_cmd]])
                    if not delete_rest(dut, rest_url=url):
                        result = False
                else:
                    cliType = "rest-patch" if cli_type == "rest-put" else cli_type
                    url = rest_urls['igmp_snooping_vlan_config_{}'.format(each_cmd)].format(vlanid)
                    payload = json.loads("""{"openconfig-network-instance-deviation:interface": [{"name": "string","config": {"enabled": true,"mrouter-interface": ["string"]}}]}""")
                    payload["openconfig-network-instance-deviation:interface"][0]["name"] = vlanid
                    payload["openconfig-network-instance-deviation:interface"][0]["config"]["mrouter-interface"] = [kwargs[each_cmd]]
                    if not config_rest(dut, http_method=cliType, rest_url=url, json_data=payload):
                        result = False
        if "static_group_interface" in kwargs and "static_group_address" in kwargs:
            if no_form:
                url = rest_urls['igmp_snooping_vlan_config_static_entry_delete'].format(vlanid, kwargs["static_group_address"], "0.0.0.0", kwargs["static_group_interface"])
                if not delete_rest(dut, rest_url=url):
                    result = False
            else:
                url = rest_urls['igmp_snooping_vlan_config_static_entry'].format(vlanid)
                payload = json.loads("""{"openconfig-network-instance-deviation:interface": [
                      {
                      "name": "",
                      "config": {
                        "name": "",
                        "enabled": true
                      },
                      "staticgrps": {
                        "static-multicast-group": [
                          {
                            "group": "",
                            "source-addr": "0.0.0.0",
                            "config": {
                              "group": "",
                              "source-addr": "0.0.0.0",
                              "outgoing-interface": [
                                {}
                              ]
                            }
                          }
                        ]
                      }
                    }
                  ]
                }""")
                payload["openconfig-network-instance-deviation:interface"][0]["name"] = vlanid
                payload["openconfig-network-instance-deviation:interface"][0]["config"]["name"] = vlanid
                payload["openconfig-network-instance-deviation:interface"][0]["staticgrps"]["static-multicast-group"][0]["group"] = kwargs["static_group_address"]
                payload["openconfig-network-instance-deviation:interface"][0]["staticgrps"]["static-multicast-group"][0]["config"]["group"] = kwargs["static_group_address"]
                payload["openconfig-network-instance-deviation:interface"][0]["staticgrps"]["static-multicast-group"][0]["config"]["outgoing-interface"] = [kwargs["static_group_interface"]]
                if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=payload):
                    result = False
    else:
        st.log("Invalid cli_type provided: {}".format(cli_type))
        result = False
    return result


def show(dut, *argv, **kwargs):
    """
    To Perform IGMP Snooping show command calls.
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param :dut:
    :param :vlan:
    :param :groups:
    :param :groups_vlan:
    :param :cli_type:   default - klish
    :return:

    Usage:
    show(vars.D1, cli_type='klish')
    show(vars.D1, vlan=200, cli_type='klish')
    show(vars.D1, 'groups', cli_type='klish')
    show(vars.D1, groups_vlan=200, cli_type='klish')

    """
    cli_type = st.get_ui_type(dut, **kwargs)
    if cli_type in ["click", "klish"]:
        cmd_prefix = ' all' if cli_type == 'click' else ''
        command = "show ip igmp snooping"
        if "groups" in argv:
            sub_cmd = "groups{}".format(cmd_prefix)
        elif "groups_vlan" in kwargs:
            sub_cmd = "groups vlan {}".format(kwargs['groups_vlan'])
        elif "vlan" in kwargs:
            sub_cmd = "vlan {}".format(kwargs['vlan'])
        else:
            sub_cmd = "{}".format(cmd_prefix)
        show_cmd = "{} {}".format(command, sub_cmd) if sub_cmd != '' else command
        output = st.show(dut, show_cmd, type=cli_type)
    elif cli_type in ["rest-put", "rest-patch"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        output = []

        if "groups" in argv:
            url = rest_urls['igmp_snooping_show']
            payload = get_rest(dut, rest_url=url)["output"]["openconfig-network-instance-deviation:interfaces"][
                "interface"]
            for row in payload:
                if "staticgrps" in row:
                    for each_item in row["staticgrps"]["static-multicast-group"]:
                        table_data = {}
                        table_data["vlan"] = row["state"]["name"].strip("Vlan")
                        table_data["group_address"] = each_item["state"]["group"]
                        table_data["source_address"] = "*" if each_item["state"]["source-addr"] == "0.0.0.0" else each_item["state"]["source-addr"]
                        table_data["outgoing_ports"] = ', '.join(each_item["state"]["outgoing-interface"])
                        table_data["number_of_entries"] = len(row["staticgrps"]["static-multicast-group"])
                        output.append(table_data)
        elif "groups_vlan" in kwargs:
            groups_vlanid = "Vlan{}".format(kwargs['groups_vlan'])
            url = rest_urls['igmp_snooping_show_vlan'].format(groups_vlanid)
            payload = get_rest(dut, rest_url=url)["output"]["openconfig-network-instance-deviation:interface"]
            for row in payload:
                if "staticgrps" in row:
                    for each_item in row["staticgrps"]["static-multicast-group"]:
                        table_data = {}
                        table_data["vlan"] = row["state"]["name"].strip("Vlan")
                        table_data["group_address"] = each_item["state"]["group"]
                        table_data["source_address"] = "*" if each_item["state"]["source-addr"] == "0.0.0.0" else each_item["state"]["source-addr"]
                        table_data["outgoing_ports"] = ', '.join(each_item["state"]["outgoing-interface"])
                        table_data["number_of_entries"] = len(row["staticgrps"]["static-multicast-group"])
                        output.append(table_data)

        elif "vlan" in kwargs:
            vlanid = "Vlan{}".format(kwargs['vlan'])
            url = rest_urls['igmp_snooping_show_vlan'].format(vlanid)
            payload = get_rest(dut, rest_url=url)["output"]["openconfig-network-instance-deviation:interface"]
            for row in payload:
                table_data = {'igmp_operation_mode': '', 'vlan': '', 'last_member_query_interval': '', 'query_max_response_time': '', 'querier': '', 'fast_leave': '', 'query_interval': '', 'mrouter_interface': ''}
                if "version" in row["state"]:
                    table_data["igmp_operation_mode"] = "IGMPv{}".format(row["state"]["version"])
                if "name" in row["state"]:
                    table_data["vlan"] = row["state"]["name"].strip("Vlan")
                if "last-member-query-interval" in row["state"]:
                    table_data["last_member_query_interval"] = row["state"]["last-member-query-interval"]
                if "query-max-response-time" in row["state"]:
                    table_data["query_max_response_time"] = row["state"]["query-max-response-time"]
                if "querier" in row["state"]:
                    table_data["querier"] = row["state"]["querier"]
                if "fast-leave" in row["state"]:
                    table_data["fast_leave"] = row["state"]["fast-leave"]
                if "query-interval" in row["state"]:
                    table_data["query_interval"] = row["state"]["query-interval"]
                if "mrouter-interface" in row["state"]:
                    table_data["mrouter_interface"] = ", ".join(row["state"]["mrouter-interface"])
                output.append(table_data)
        else:
            url = rest_urls['igmp_snooping_show']
            payload = get_rest(dut, rest_url=url)["output"]["openconfig-network-instance-deviation:interfaces"]["interface"]
            for row in payload:
                table_data = {'igmp_operation_mode': '', 'vlan': '', 'last_member_query_interval': '', 'query_max_response_time': '', 'querier': '', 'fast_leave': '', 'query_interval': '', 'mrouter_interface': ''}
                if "version" in row["state"]:
                    table_data["igmp_operation_mode"] = "IGMPv{}".format(row["state"]["version"])
                if "name" in row["state"]:
                    table_data["vlan"] = row["state"]["name"].strip("Vlan")
                if "last-member-query-interval" in row["state"]:
                    table_data["last_member_query_interval"] = row["state"]["last-member-query-interval"]
                if "query-max-response-time" in row["state"]:
                    table_data["query_max_response_time"] = row["state"]["query-max-response-time"]
                if "querier" in row["state"]:
                    table_data["querier"] = row["state"]["querier"]
                if "fast-leave" in row["state"]:
                    table_data["fast_leave"] = row["state"]["fast-leave"]
                if "query-interval" in row["state"]:
                    table_data["query_interval"] = row["state"]["query-interval"]
                if "mrouter-interface" in row["state"]:
                    table_data["mrouter_interface"] = ", ".join(row["state"]["mrouter-interface"])
                output.append(table_data)
    else:
        st.log("Invalid cli_type provided: {}".format(cli_type))
        return False
    return output


def verify(dut, **kwargs):
    """
    Call to verify - show ip igmp snooping
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param :dut:
    :param :cli_type:   default - klish
    :param :vlan
    :param :mrouter_interface
    :param :querier
    :param :igmp_operation_mode
    :param :fast_leave
    :param :query_max_response_time
    :param :last_member_query_interval
    :param :query_interval
    :return:
    """
    result = True
    output = show(dut, **kwargs)
    match = {e: kwargs[e] for e in kwargs if e not in ['cli_type', 'mrouter_interface']}
    entries = utils.filter_and_select(output, None, match)
    if not entries:
        st.log("match {} is not in output {}".format(match, entries))
        result = False
    if "mrouter_interface" in kwargs:
        interface_li = utils.make_list(kwargs['mrouter_interface'])
        for each in interface_li:
            if each not in entries[0]['mrouter_interface'].split(', '):
                st.log("Mrouter interface {} is not found under mentioned vlan".format(each))
                result = False
    return result


def verify_groups(dut, *argv, **kwargs):
    """
    Call to verify - show ip igmp snooping groups *
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param :dut:
    :param :argv: groups | groups_vlan |  vlan
    :param :verify_list [{"vlan':"500",
                        "source_address":"192.168.1.2",
                        "group_address":"224.1.2.2",
                        "outgoing_ports":["Ethernet2","Ethernet4"],
                        'number_of_entries': '10'},
                        {"vlan": "600",
                        "source_address":"192.168.3.2",
                        "group_address":"224.4.2.2",
                        "outgoing_ports":"Ethernet8"}]
    :return:
    """
    result = True
    previous_vlan = None
    output = []
    cli_type = st.get_ui_type(dut, **kwargs)

    if not kwargs.get('verify_list'):
        st.error("verify_list - mandatory parameter missing.")
        return False
    for data in kwargs.get("verify_list"):
        if not data.get('vlan'):
            st.error("vlan key is not found in verify_list data.")
            return False

        if "groups" in argv:
            if not output:
                output = show(dut, 'groups', cli_type=cli_type)
        elif "groups_vlan" in argv:
            if previous_vlan != data.get('vlan'):
                output = show(dut, groups_vlan=data.get('vlan'), cli_type=cli_type)
        elif "vlan" in argv:
            if previous_vlan != data.get('vlan'):
                output = show(dut, vlan=data.get('vlan'), cli_type=cli_type)
        else:
            if not output:
                output = show(dut, cli_type=cli_type)

        match = {"vlan": data.get('vlan')}
        if data.get("source_address"):
            match["source_address"] = data.get("source_address")
        if data.get("group_address"):
            match["group_address"] = data.get("group_address")
        entries = utils.filter_and_select(output, None, match)
        if not entries:
            st.log("No match found for - {}".format(data))
            return False

        if data.get("outgoing_ports"):
            outgoing_ports_li = utils.make_list(data['outgoing_ports'])
            for each in outgoing_ports_li:
                if each not in entries[0]['outgoing_ports'].split(', '):
                    st.log("Outgoing interface {} is not found in  vlan {}".format(each, data.get('vlan')))
                    result = False

        if data.get('number_of_entries'):
            if not utils.filter_and_select(entries, None, {"vlan": data.get('vlan'),
                                                           'number_of_entries': str(data['number_of_entries'])}):
                st.log("number_of_entries {} for Vlan {} is not match".format(data['number_of_entries'],
                                                                              data.get('vlan')))
                result = False
        previous_vlan = data.get('vlan')
    return result


def debug(dut, **kwargs):
    """
    To Perform IGMP Snooping DEBUG command calls.
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param :dut:
    :param :cli_type:
    """
    cli_type = kwargs.get("cli_type", "click")
    command = 'show debug l2mcd_debug all'
    output = st.show(dut, command, skip_tmpl=True, type=cli_type)
    return output


def poll_igmp_groups_count(dut, toatl_entry, iteration_count=30, delay=1, cli_type=''):
    """
    Poll for the IGMP group entries.
    :param dut:
    :param toatl_entry:
    :param iteration_count:
    :param delay:
    :param cli_type:
    :return:
    """
    if not cli_type: cli_type = st.get_ui_type(dut)
    i = 1
    while True:
        output = show(dut, 'groups', cli_type=cli_type)
        st.log("Found {} Entries".format(len(output)))
        if int(toatl_entry) <= len(output):
            st.log("Count Match...")
            return True
        if i > iteration_count:
            st.log("Max {} tries Exceeded. Exiting..".format(i))
            return False
        i += 1
        st.wait(delay)


def config_igmp_snooping(dut, vlan, version, mode, clitype=""):
    """
    :param dut: D1
    :param vlan: List of vlans
    :param version: 1,2 or 3
    :param mode: enable or disable
    :param clitype:
    """
    if not clitype : clitype = st.get_ui_type(dut)
    vlan_list = utils.make_list(vlan)
    if mode == "enable":
        for i in vlan_list:
            config(dut, "mode", vlan=i, version=version, cli_type=clitype)
    else:
        for i in vlan_list:
            config(dut, "no_form", "mode", vlan=i, cli_type=clitype)


def config_igmp_max_vlan_static_groups_db(dut, max_vlan, interface_list=[], max_group=0, group_ip_list=[]):
    """
    This create max Vlan , adding members and enable IGMP on  MAX Valn. Also create Max static groups.
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param max_vlan:
    :param max_group:
    :param interface_list:
    :param group_ip_list:
    Usage:
    config_igmp_max_vlan_static_groups_db(vars.D1, 4093, interface_list=['Ethernet0', 'Ethernet2'], max_group=512,
                                           group_ip_list=['225.1.2.3', '225.1.2.5'] )
    """
    max_igmp_config = {'CFG_L2MC_TABLE': {}, 'CFG_L2MC_STATIC_MEMBER_TABLE': {}, 'CFG_L2MC_STATIC_GROUP_TABLE': {},
                       'VLAN': {}, 'VLAN_MEMBER': {}}
    for each in range(1, max_vlan+1):
        max_igmp_config['VLAN']['Vlan{}'.format(each)] = {"members": interface_list, "vlanid": str(each)}
        if each <= max_group:
            for grp in group_ip_list:
                max_igmp_config['CFG_L2MC_STATIC_GROUP_TABLE']["Vlan{}|{}".format(each, grp)] = \
                    {"static-members": interface_list}
        for interface in interface_list:
            max_igmp_config['VLAN_MEMBER']['Vlan{}|{}'.format(each, interface)] = {"tagging_mode": "tagged"}
            if each <= max_group:
                for grp in group_ip_list:
                    max_igmp_config['CFG_L2MC_STATIC_MEMBER_TABLE']["Vlan{}|{}|{}".format(each, grp, interface)] = \
                        {"port": interface}
        max_igmp_config['CFG_L2MC_TABLE']["Vlan{}".format(each)] = \
            {"enabled": "true", "fast-leave": "false", "last-member-query-interval": "1000",
             "querier": "false", "query-interval": "125", "query-max-response-time": "10", "version": "2"}

    return write_config_db(dut, max_igmp_config)


def config_igmp_on_vlan_list_db(dut, vlan_list, version='2', mode='true'):
    """
    Enable IGMP on list of vlan using config db.
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param vlan_list:
    :param version: 1 | 2 | 3
    :param mode: true | false
    Usage:
    config_igmp_on_vlan_list_db(vars.D1, range(1,4094), version='2', mode='true')
    config_igmp_on_vlan_list_db(vars.D1, [100, 200], version='2', mode='true')
    """
    max_igmp_config = {'CFG_L2MC_TABLE': {}}
    for each in vlan_list:
        max_igmp_config['CFG_L2MC_TABLE']["Vlan{}".format(each)] = \
            {"enabled": str(mode), "fast-leave": "false", "last-member-query-interval": "1000",
             "querier": "false", "query-interval": "125", "query-max-response-time": "10", "version": str(version)}
    return write_config_db(dut, max_igmp_config)


def get(dut, **kwargs):
    """
    Get entries count w.r.t igmp feature
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param :dut:
    :param :value:  vlan_count
    :param :cli_type:
    :Usage:
        get(vars.D1, value='vlan_count', cli_type='click')
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = "klish" if cli_type in ["rest-put", "rest-patch"] else cli_type
    if cli_type == 'click':
        command = "show ip igmp snooping all "
        if kwargs.get('value'):
            if 'vlan_count' in kwargs.get('value'):
                sub_cmd = "| grep 'Vlan ID:'"
            else:
                return None
            show_cmd = "{} {} | wc -l".format(command,sub_cmd)
        output = st.show(dut, show_cmd, skip_tmpl=True, max_time=300, type=cli_type)
        x = search(r"\d+", output)
        if x:
            return int(x.group())
    elif cli_type == "klish":
        show_cmd = "show ip igmp snooping | grep ID"
        output = st.show(dut, show_cmd, skip_tmpl=True, max_time=300, type=cli_type)
        x = output.split('\n')
        x = [i for i in x if 'mgmt' not in i]
        return len(x)
