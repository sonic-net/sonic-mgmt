# This file contains the list of API's which performs Error handling operations.
# Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)

import re
from spytest import st, SpyTestDict
import apis.common.asic as asicapi
from apis.common import redis
from apis.system.interface import verify_ifname_type

from utilities.common import filter_and_select

vars = SpyTestDict()

def verify_error_db(dut, table, **kwargs):
    """
    Verify error db using redis cli
    :param dut:
    :param table:
    :param kwargs:
    :return:
    """
    match = ""
    if table == "ERROR_ROUTE_TABLE":
        vrfKey = ""
        if 'vrf' in kwargs:
            vrfKey = kwargs["vrf"] + ":"
        command = redis.build(dut, redis.ERROR_DB, "hgetall {}:{}{}/{}".format(table, vrfKey, kwargs["route"], kwargs["mask"]))
        if kwargs["opcode"] == "create":
            match = {"nhp": kwargs["nhp"], "rc": kwargs["rc"], "ifname": kwargs["port"], "opcode": kwargs["opcode"]}
        elif kwargs["opcode"] == "remove":
            match = {"rc": kwargs["rc"], "opcode": kwargs["opcode"]}
        elif "rc" not in kwargs and "opcode" not in kwargs:
            match = {"nhp": kwargs["nhp"], "ifname": kwargs["port"]}

    elif table == "ERROR_NEIGH_TABLE":
        st.log("table")
        command = redis.build(dut, redis.ERROR_DB, "hgetall {}:{}:{}".format(table, kwargs["port"], kwargs["nhp"]))
        if kwargs["opcode"] == "create":
            match = {"mac": kwargs["mac"], "rc": kwargs["rc"], "ifname": kwargs["port"], "opcode": kwargs["opcode"]}
        elif kwargs["opcode"] == "remove":
            match = {"rc": kwargs["rc"], "opcode": kwargs["opcode"]}
        elif "rc" not in kwargs and "opcode" not in kwargs:
            match = {"ifname": kwargs["port"], "mac": kwargs["mac"]}
    output = st.show(dut, command)
    output = _get_entries_with_native_port(dut, output, **kwargs)
    st.debug(output)
    if not filter_and_select(output, None, match):
        st.error("No match found")
        return False
    return True


def verify_show_error_db(dut, table=None, **kwargs):
    """
    Verify Error Database.
    :param dut:
    :param table:
    :param kwargs:
    :return:
    """
    command = "show error_database"
    if table:
        command = "show error_database {}".format(table)
    output = st.show(dut, command)
    output = _get_entries_with_native_port(dut, output, **kwargs)
    st.debug(output)
    for each in kwargs.keys():
        if not filter_and_select(output, None, {each: kwargs[each]}):
            st.error("No match for {} = {} in table".format(each, kwargs[each]))
            return False
    return True


def verify_show_error_db_multi(dut, table, *argv, **kwargs):
    """
    Verify multiple Error Database entries.
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param : dut:
    :param : table:
    :param : result: Expected result(Default True)
    :param : iteration: default(30)
    :param : argv: list  of dict arguments to verify
    :return:
    """
    exp_result = kwargs.get("result", True)
    iteration = kwargs.get("iteration", 30)
    cli_type = st.get_ui_type(dut, **kwargs)
    if kwargs.get("interface"):
        intf_entry_val = kwargs.get("interface")
        if cli_type == "klish":
            if vars.config.ifname_type == "alias":
                intf_entry_val = st.get_other_names(vars.D1, [kwargs.get("interface")])[0]
        kwargs.update({"interface":intf_entry_val})
    command = "show error_database"
    if table:
        command = "show error_database {}".format(table)
    i = 1
    while True:
        output = st.show(dut, command)
        output = _get_entries_with_native_port(dut, output, **kwargs)
        st.debug(output)
        result = True
        for each_row in argv:
            row_match = filter_and_select(output, None, each_row)
            if not row_match:
                st.log("Entry not found - {}".format(', '.join(["{}='{}'".format(k, each_row[k]) for k in each_row])))
                result = False
            else:
                st.log("Entry found - {}".format(', '.join(["{}='{}'".format(k, each_row[k]) for k in each_row])))
        if result == exp_result:
            return True
        if i >= iteration:
            return False
        i += 1
        st.wait(1)


def get_num_entries_error_db(dut, ifname_type=None):
    """
    To Get total entries in Error Database using redis cli
    :param dut:
    :return:
    """
    command = redis.build(dut, redis.ERROR_DB, "keys ERROR.*")
    output = st.show(dut, command)
    output = _get_entries_with_native_port(dut, output, ifname_type=ifname_type)
    st.debug(output)
    return len(output)


def get_num_entries_show_error_db(dut, table=None, error=None, ifname_type=None):
    """
    To Get total entries in Error Database using show command
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param table:
    :param error:
    :return:
    """
    command = "show error_database"
    if table:
        command += " {}".format(table)
    if error:
        command += " | grep {}".format(error)
    output = st.show(dut, command)
    output = _get_entries_with_native_port(dut, output, ifname_type=ifname_type)
    st.debug(output)
    return len(output)


def get_num_entries_show_error_db_simple(dut, table=None, error=None):
    """
    To Get total entries in Error Database using show command using wc -l
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param table:
    :param error:
    :return:
    """
    command = "show error_database"
    if table:
        command += " {}".format(table)
    if error:
        command += " | grep {}".format(error)
    command += " | wc -l"
    output = st.config(dut, command)
    x = re.search(r"\d+", output)
    return int(x.group())


def clear_error_db(dut, table=None):
    """
    Clear Error database
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param table:
    :return:
    """
    command = "sonic-clear error_database"
    if table:
        command = "sonic-clear error_database {}".format(table)
    st.config(dut, command)
    return True


def config_bgp_error_handling(dut, **kwargs):
    """
    To Configure BGP error handling.
    :param : dut:
    :param : action: enable|disable
    :return:
    """
    if "action" not in kwargs:
        st.error("Mandatory param 'action' not provided")
        return False
    command = "config bgp error-handling {}".format(kwargs["action"])
    st.config(dut, command)
    return True


def verify_error_db_redis(dut, table, **kwargs):
    """
    Verify error db using redis cli
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param :dut:
    :param :table:
    :param :route:
    :param :mask:
    :param :ifname:
    :param :nhp:
    :param :operation:
    :param :rc:
    :param :result: (Default True)
    :param :iteration: default(30)
    :return:
    """
    port = kwargs.pop("ifname")
    port = st.get_other_names(dut, [port])[0] if "/" in port else port
    exp_result = kwargs.get("result", True)
    iteration = kwargs.get("iteration", 30)
    command = ''
    if table == "ERROR_ROUTE_TABLE":
        command = redis.build(dut, redis.ERROR_DB, "hgetall {}:{}/{}".format(table, kwargs.pop("route"), kwargs.pop("mask")))
    elif table == "ERROR_NEIGH_TABLE":
        command = redis.build(dut, redis.ERROR_DB, "hgetall {}:{}:{}".format(table, port, kwargs.pop("nhp")))
    else:
        st.error("Invalid table name - {}".format(table))

    i = 1
    while True:
        output = st.show(dut, command)
        st.debug(output)
        result = True
        for each in kwargs.keys():
            if not filter_and_select(output, None, {each: kwargs[each]}):
                st.error("No match for {} = {} in redis cli".format(each, kwargs[each]))
                result = False
        if result == exp_result:
            return True
        if i >= iteration:
            return False
        i += 1
        st.wait(1)


def verify_route_count_bcmshell(dut, route_count, af='ipv4', itter=30, delay=1, flag='ge', timeout=120):
    """
    Poll and verify the route count using asic api
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param route_count:
    :param af:
    :param itter:
    :param delay:
    :param flag:
    :param timeout:
    :return:
    """
    i = 1
    while True:
        if af == 'ipv4':
            curr_count = asicapi.get_ipv4_route_count(dut, timeout=timeout)
        if af == 'ipv6':
            curr_count = asicapi.get_ipv6_route_count(dut, timeout=timeout)

        if flag == 'ge' and int(curr_count) >= int(route_count):
            st.log("Route count matched Provided {}, Detected {} - flag = {}".format(route_count, curr_count, flag))
            return True
        if flag == 'e' and int(curr_count) == int(route_count):
            st.log("Route count matched Provided {}, Detected {} - flag = {}".format(route_count, curr_count, flag))
            return True
        if flag == 'le' and int(curr_count) <= int(route_count):
            st.log("Route count matched Provided {}, Detected {} - flag = {}".format(route_count, curr_count, flag))
            return True
        if i > itter:
            st.log("Max {} tries Exceeded. Exiting..".format(i))
            return False
        i += 1
        st.log("Route count NOT matched Provided {}, Detected {} - flag = {}".format(route_count, curr_count, flag))
        st.wait(delay)


def check_for_container_error(out):
    """
    Error handing - Check and failed the test case if container error detected.
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param out:
    :return:
    """
    if "Error response from daemon" in out:
        st.report_fail('container_not_running')


def eh_not_installed_route_options(dut, **kwargs):
    """
    Error handing - Not installed route Show / Get / Clear API.
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param kwargs:
    :return:
    """
    if 'mode' not in kwargs:
        st.error("Mandatory parameter mode not found")

    af1 = 'ipv6'
    af2 = 'ipv6'
    if 'ipv4' in kwargs['mode']:
        af1 = 'ipv4'
        af2 = 'ip'

    if kwargs['mode'] == "clear_{}_route_vtysh_not_installed".format(af1):
        out = st.config(dut, 'clear {} route not-installed '.format(af2), type='vtysh', conf=False)
        return out
    if kwargs['mode'] == "clear_{}_route_sonic_not_installed".format(af1):
        out = st.config(dut, 'sonic-clear {} route not-installed '.format(af2))
        return out

    # Sonic - MODE
    if "{}_route_sonic_not_installed".format(af1) in kwargs['mode']:
        command = 'show {} route not-installed'.format(af2)
        if 'show' in kwargs['mode']:
            out = st.show(dut, command)
            out = _get_entries_with_native_port(dut, out, **kwargs)
            st.debug(out)
            return out
        else:
            out = st.config(dut, command + ' | wc -l', skip_error_check=True)
            check_for_container_error(out)
            count = re.search(r"\d+", out).group()
            st.log("Detected route count {}".format(count))
            return int(count)

    if "{}_route_sonic_for_not_installed".format(af1) in kwargs['mode']:
        command = 'show {} route | grep "#" '.format(af2)
        if 'show' in kwargs['mode']:
            out = st.show(dut, command)
            out = _get_entries_with_native_port(dut, out, **kwargs)
            st.debug(out)
            return out
        else:
            out = st.config(dut, command + ' | wc -l', skip_error_check=True)
            check_for_container_error(out)
            count = re.search(r"\d+", out).group()
            st.log("Detected route count {}".format(count))
            return int(count)

    # vtysh = MODE
    if "{}_route_vtysh_not_installed".format(af1) in kwargs['mode']:
        out = st.show(dut, 'show {} route not-installed'.format(af2), type='vtysh')
        out = _get_entries_with_native_port(dut, out, **kwargs)
        st.debug(out)
        if 'show' in kwargs['mode']:
            return out
        else:
            st.log("Detected route count {}".format(len(out)))
            return len(out)

    if "{}_route_vtysh_for_not_installed".format(af1) in kwargs['mode']:
        out = st.show(dut, 'show {} route | grep "#"'.format(af2), type='vtysh')
        out = _get_entries_with_native_port(dut, out, **kwargs)
        st.debug(out)
        if 'show' in kwargs['mode']:
            return out
        else:
            st.log("Detected route count {}".format(len(out)))
            return len(out)


def verify_num_entries_show_error_db(dut, entry_count, itter=30, delay=1, flag='ge', table=None, error=None):
    """
    Poll and verify the show error db entries
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param entry_count:
    :param itter:
    :param delay:
    :param flag:
    :param table:
    :param error:
    :return:
    """

    i = 1
    while True:
        curr_count = get_num_entries_show_error_db_simple(dut, table=table, error=error)
        if flag == 'ge' and int(curr_count) >= int(entry_count):
            st.log("Entry count matched Provided {}, Detected {} - flag = {}".format(entry_count, curr_count, flag))
            return True
        if flag == 'e' and int(curr_count) == int(entry_count):
            st.log("Entry count matched Provided {}, Detected {} - flag = {}".format(entry_count, curr_count, flag))
            return True
        if flag == 'le' and int(curr_count) <= int(entry_count):
            st.log("Entry count matched Provided {}, Detected {} - flag = {}".format(entry_count, curr_count, flag))
            return True
        if i > itter:
            st.log("Max {} tries Exceeded. Exiting..".format(i))
            return False
        i += 1
        st.log("Route count NOT matched Provided {}, Detected {} - flag = {}".format(entry_count, curr_count, flag))
        st.wait(delay)


def eh_bcm_debug_show(dut, af='both', table_type='all', ifname_type=None):
    """
    Error handling debug API
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param af:
    :param table_type:
    :return:
    """
    st.banner("Error handling DEBUG Calls - START")
    if af == 'ipv4' or af == 'both':
        if table_type == 'route' or table_type == 'all':
            asicapi.dump_l3_defip(dut)
        if table_type == 'nbr' or table_type == 'all':
            asicapi.dump_l3_l3table(dut)
    if af == 'ipv6' or af == 'both':
        if table_type == 'route' or table_type == 'all':
            asicapi.dump_l3_ip6route(dut)
        if table_type == 'nbr' or table_type == 'all':
            asicapi.dump_l3_ip6host(dut)
    if table_type == 'all':
        verify_show_error_db(dut, ifname_type=ifname_type)
    st.banner("Error handling DEBUG Calls - END")


def _get_entries_with_native_port(dut, output, **kwargs):
    cli_type = st.get_ui_type(dut, **kwargs)
    ifname_type = kwargs.get("ifname_type", "")
    verify_ifname_type(dut, mode='standard')
    st.log("OUTPUT:{}".format(output))
    for entry in output:
        if (cli_type == 'klish' and ifname_type == "alias"):
            st.log("Interface : {}".format(st.get_other_names(dut, [entry['interface']])[0]))
        else:
            st.log("Else Interface : {}".format(entry.get('interface')))
        entry.update(interface=st.get_other_names(dut, [entry['interface']])[0] if (cli_type == 'klish' and ifname_type == "alias") else entry.get('interface'))
    st.log("OUTPUT1:{}".format(output))
    return output
