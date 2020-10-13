import re
import utilities.utils as utils
from spytest import st
from spytest.utils import filter_and_select
from spytest.utils import exec_foreach, exec_all
import utilities.common as utility
import apis.switching.portchannel as portchannel
import apis.system.basic as basic
from utilities.parallel import ensure_no_exception
from datetime import  datetime,timedelta

debug_log_path = r"/var/log/stplog"
SHOW_STP_VLAN = "show spanning_tree vlan {}"
BLOCKING_STATE = "BLOCKING"


def config_spanning_tree(dut, feature="pvst", mode="enable", vlan=None, cli_type='click'):
    """

    :param dut:
    :param feature:
    :param mode:
    :param vlan:
    :param cli_type:
    :return:
    """
    command = ''
    no_form = 'no'
    if mode == 'enable':
        no_form = ''

    st.log("{} spanning_tree {}".format(mode, feature))
    if cli_type == 'click':
        if vlan:
            command = "config spanning_tree vlan {} {}".format(mode, vlan)
        else:
            command = "config spanning_tree {} {}".format(mode, feature)
    elif cli_type == 'klish':
        if mode == 'disable':
            feature = ''
        if vlan:
            command = "{} spanning-tree vlan {}".format(no_form, vlan)
        else:
            command = "{} spanning-tree mode {}".format(no_form, feature)

    st.config(dut, command, type=cli_type)


def config_stp_parameters(dut, cli_type='click', no_form='', **kwargs):
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
            command = "{} spanning-tree {} {}".format(no_form, each_key, kwargs[each_key])
        else:
            st.error("Invalid CLI type - {}".format(cli_type))
            return
        st.config(dut, command, type=cli_type)


def config_stp_vlan_parameters(dut, vlan, **kwargs):
    """

    :param dut:
    :param vlan:
    :param kwargs:
    :return:
    """
    cli_type = kwargs.setdefault('cli_type', 'click')
    no_form = 'no' if kwargs.setdefault('no_form', False) else ''
    del kwargs['cli_type']
    del kwargs['no_form']
    click_2_klish = {'forward_delay': 'forward-time', 'hello': 'hello-time', 'max_age': 'max-age'}

    for each_key, value in kwargs.items():
        if cli_type == 'click':
            command = "config spanning_tree vlan {} {} {}".format(each_key, vlan, value)
        elif cli_type == 'klish':
            each_key1 = click_2_klish.get(each_key, each_key)
            command = "{} spanning-tree vlan {} {} {}".format(no_form, vlan, each_key1, value)
        else:
            st.error("Invalid CLI type - {}".format(cli_type))
            return
        st.config(dut, command, type=cli_type)


def config_stp_vlan_parameters_parallel(dut_list, thread=True, **kwargs):
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
        params.append(utility.ExecAllFunc(config_stp_vlan_parameters, each, vlan_li[i], priority=priority_li[i]))
    [out, exceptions] = exec_all(thread, params)
    st.log(exceptions)
    return False if False in out else True


def config_stp_vlan_interface(dut, vlan, iface, value, mode='cost', **kwargs):
    """

    :param dut:
    :param vlan:
    :param iface:
    :param value:
    :param mode:
    :return:
    """
    cli_type = kwargs.get('cli_type', 'click')
    no_form = 'no' if kwargs.get('no_form') else ''

    if mode in ['cost', 'priority']:
        if cli_type == 'click':
            command = "config spanning_tree vlan interface {} {} {} {} ".format(mode, vlan, iface, value)
        elif cli_type == 'klish':
            if mode == 'priority':
                mode = 'port-priority'
            interface_data = utils.get_interface_number_from_name(iface)
            command = ['interface {} {}'.format(interface_data["type"], interface_data["number"]),
                       '{} spanning-tree vlan {} {} {}'.format(no_form, vlan, mode, value), "exit"]
        else:
            st.error("Invalid CLI type - {}".format(cli_type))
            return
    else:
        st.log("Invalid mode = {}".format(mode))
        return
    st.config(dut, command, type=cli_type)


def config_stp_enable_interface(dut, iface, mode="enable"):
    """

    :param dut:
    :param iface:
    :param mode:
    :return:
    """
    command = "config spanning_tree interface {} {}".format(mode, iface)
    st.config(dut, command)

def config_stp_interface_params(dut, iface, **kwargs):
    """

    :param dut:
    :param iface:
    :param cli_type:
    :param kwargs:
    :return:
    """
    cli_type = kwargs.setdefault('cli_type', 'click')
    del kwargs['cli_type']

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
            st.config(dut, command)

    elif cli_type == 'klish':
        interface_data = utils.get_interface_number_from_name(iface)
        command = ['interface {} {}'.format(interface_data["type"], interface_data["number"])]
        for each_key in kwargs.keys():
            no_form = 'no' if kwargs[each_key] == 'disable' else ''
            if each_key == "priority" or each_key == "cost":
                command.append('spanning-tree {} {}'.format(each_key, kwargs[each_key]))
            elif each_key == "bpdu_guard_action":
                command.append('{} spanning-tree bpduguard port-shutdown'.format(no_form))
            else:
                command.append("{} spanning-tree {}".format(no_form, click_2_klish[each_key]))
        command.append('exit')
        st.config(dut, command, type=cli_type)


def config_stp_interface(dut, iface, mode="enable"):
    """

    :param dut:
    :param iface:
    :param mode:
    :return:
    """
    command = "config spanning_tree interface {} {} ".format(mode, iface)
    st.config(dut, command)

def show_stp(dut, **kwargs):
    """

    :param dut:
    :return:
    """
    cli_type = kwargs.get("cli_type", 'click')
    command = "show spanning_tree"
    if 'sub_cmd' in kwargs:
        command = "show spanning_tree {}".format(kwargs['sub_cmd'])
    return st.show(dut, command, type=cli_type)

def show_stp_vlan(dut, vlan, cli_type="click"):
    """

    :param dut:
    :param vlan:
    :param cli_type:
    :return:
    """
    st.log("show spanning_tree vlan <id>")
    command = SHOW_STP_VLAN.format(vlan)
    return st.show(dut, command, type=cli_type)


def show_stp_vlan_iface(dut, vlan, iface, cli_type="click"):
    """

    :param dut:
    :param vlan:
    :param iface:
    :return:
    """
    if cli_type == "click":
        command = "show spanning_tree vlan interface {} {}".format(vlan, iface)
    elif cli_type == "klish":
        command = "show spanning_tree vlan {} interface {}".format(vlan, iface)
    else:
        st.log("Unsupported CLI type {}".format(cli_type))
        return list()
    return st.show(dut, command, type="cli_type")

def show_stp_stats(dut):
    """

    :param dut:
    :return:
    """
    command = "show spanning_tree statistics"
    return st.show(dut, command)

def show_stp_stats_vlan(dut, vlan):
    """

    :param dut:
    :param vlan:
    :return:
    """
    command = "show spanning_tree statistics vlan {} ".format(vlan)
    return st.show(dut, command)

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
        entries = filter_and_select(output, None, match)
        if not entries:
            st.log("{} and {} is not match ".format(each, kwargs[each]))
            return False
    return True

def verify_stp_statistics_vlan(dut, **kwargs):
    """

    :param dut:
    :param kwargs:
    :return:
    """
    output = show_stp_stats_vlan(dut, kwargs["vlan"])
    for each in kwargs.keys():
        match = {each: kwargs[each]}
        entries = filter_and_select(output, None, match)
        if not entries:
            st.log("{} and {} is not match ".format(each, kwargs[each]))
            return False
    return True

def check_dut_is_root_bridge_for_vlan(dut, vlanid):
    """

        :param dut:
        :param vlanid:
        :return:
    """
    cmd = SHOW_STP_VLAN.format(vlanid)
    stp_output = st.show(dut, cmd)
    root_bridge=stp_output[0]["rt_id"]
    dut_bridge_id=stp_output[0]["br_id"]
    return (root_bridge == dut_bridge_id) and stp_output[0]["rt_port"] == "Root"

def get_stp_bridge_param(dut, vlanid, bridge_param):
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
    cmd = SHOW_STP_VLAN.format(vlanid)
    stp_output = st.show(dut, cmd)
    return stp_output[0][bridge_param]

def get_stp_port_param(dut, vlanid, ifname, ifparam):
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

    cmd = SHOW_STP_VLAN.format(vlanid)+" interface {}".format(ifname)
    stp_output = st.show(dut, cmd)
    return None if len(stp_output) == 0 else stp_output[0][ifparam]

def get_default_root_bridge(dut_list):
    """
        This is used to get the root bridge with default config
        :param vars : Testbed Vars
        :return: Returns root bridge like D1 or D2
    """
    duts_mac_list = basic.get_dut_mac_address_thread(dut_list)
    if duts_mac_list:
        min_mac_addr = min(duts_mac_list.values())
        root_bridge = [dut for dut, mac_addr in duts_mac_list.items() if mac_addr == min_mac_addr][0]
        return  [dut for dut in dut_list if dut==root_bridge][0]
    else:
        return None

def get_duts_mac_address(duts):
    """
        This is used to get the Duts and its mac addresses mapping
        :param duts: List of DUTs
        :return : Duts and its mac addresses mapping

    """
    duts_mac_addresses = {}
    cmd = "show platform syseeprom"
    for dut in duts:
        if st.is_vsonic(dut):
            mac = basic.get_ifconfig_ether(dut)
            duts_mac_addresses[dut] = mac
            continue
        eeprom_details = st.show(dut, cmd, skip_error_check=True)
        if not eeprom_details:
            iteration=3
            for i in range(1, iteration+1):
                st.wait(2)
                eeprom_details = st.show(dut, cmd, skip_error_check=True)
                if eeprom_details:
                    break
                if not eeprom_details and i >= iteration + 1:
                    st.log("EEPROM data not found for {}".format(dut))
                    st.report_fail("eeprom_data_not_found", dut)
        st.log("EEPROM DETAILS -- {}".format(eeprom_details))
        if eeprom_details:
            for data in eeprom_details:
                if "tlv_name" in data and data["tlv_name"] == "Base MAC Address":
                    duts_mac_addresses[dut] = data["value"].replace(":","")
    st.log("DUT MAC ADDRESS -- {}".format(duts_mac_addresses))
    return duts_mac_addresses

def _get_duts_list_in_order(vars):
    """
        This is used to get the DUTs and their mac addresses in ascending order of Mac addresses
        :param duts: List of DUTs
        :return : Duts and its mac addresses mapping

    """
    duts_mac_addresses = get_duts_mac_address(vars["dut_list"])

    return sorted(zip(duts_mac_addresses.values(), duts_mac_addresses.keys()))

def get_ports_based_on_state(vars, vlanid, port_state, dut=None, cli_type='click'):
    """
            This is used to get the blocked ports on none-root bridge
            :param duts: List of DUTs
            :return : Duts and its mac addresses mapping

    """

    selected_non_root = ""
    if dut is None:
        duts_list = _get_duts_list_in_order(vars)
        dut_with_max_mac_address = duts_list[len(duts_list) - 1][1]
        selected_non_root = [dut_key for dut_key, dut_value in vars.items() if dut_value == dut_with_max_mac_address][0]
    else:
        selected_non_root = [dut_key for dut_key, dut_value in vars.items() if dut_value == dut][0]
    stp_output = show_stp_vlan(vars[selected_non_root], vlanid, cli_type=cli_type)
    ports_list = [row["port_name"] for row in stp_output if
                     row["port_state"] == port_state and int(row["vid"]) == vlanid]

    return ports_list

def poll_for_root_switch(dut, vlanid, iteration=20, delay=1):
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
        if check_dut_is_root_bridge_for_vlan(dut, vlanid):
            st.log("Observed dut is root bridge {} iteration".format(i))
            return True
        if i > iteration:
            st.log("Max iterations {} reached".format(i))
            return False
        i += 1
        st.wait(delay)

def poll_for_stp_status(dut, vlanid, interface, status, iteration=20, delay=1):
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
        if get_stp_port_param(dut, vlanid, interface, "port_state") == status:
            st.log("Port status is changed to  {} after {} sec".format(status, i))
            return True
        if i > iteration:
            st.log("Max iterations {} reached".format(i))
            return False
        i += 1
        st.wait(delay)

def get_root_guard_details(dut, vlan=None, ifname=None , rg_param="rg_timeout"):
    """
     API will return Root Guard timeout if vlan and interface won't provide , otherwise Root Guard state will return
    :param dut:
    :param vlan:
    :param ifname:
    :return:
    """
    cmd = "show spanning_tree root_guard"
    output = st.show(dut, cmd)
    if vlan is None and ifname is None:
        rg_value = int(output[0][rg_param])
    else:
        rg_value = [row[rg_param] for row in output if row["rg_ifname"] == ifname and int(row["rg_vid"]) == vlan][0]
    return rg_value

def check_rg_current_state(dut, vlan, ifname):
    """
    API will check the  Root Guard status for given interface and vlan
    :param dut:
    :param vlan:
    :param ifname:
    :return:
    """
    rg_status = get_root_guard_details(dut, vlan, ifname, "rg_status")
    #show_stp_config_using_klish(dut, "root_guard", vlan)
    return rg_status == "Consistent state"

def check_bpdu_guard_action(dut, ifname, **kwargs):
    """
    API will check the BPDU Guard action config and it's operational status
    :param dut:
    :param ifname:
    :param kwargs:
                   config_shut : BPDU shutdown configuration
                   opr_shut : status of the port shut due to BPDU Guard
    :return:
    """
    cmd = "show spanning_tree bpdu_guard"
    show_out = st.show(dut, cmd)
    #show_stp_config_using_klish(dut, "bpdu_guard")
    if_out = [row for row in show_out if row['bg_ifname'] == ifname][0]
    config_shut, opr_shut = if_out['bg_cfg_shut'], if_out['bg_oper_shut']
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
    output = st.config(dut, cmd)

def get_stp_stats(dut, vlan, interface, param):
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
    output = show_stp_stats_vlan(dut, vlan)
    #show_stp_config_using_klish(dut, 'statistics', vlan)
    value_list = [row[param] for row in output if int(row['st_vid']) == vlan and row['st_portno'] == interface]
    utils.banner_log(value_list)
    return None if len(output) == 0 else int(value_list[0])

def verify_stp_ports_by_state(dut, vlan, port_state, port_list, cli_type='click'):
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

def get_stp_port_list(dut, vlan, exclude_port=[], cli_type='click'):
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

def get_stp_root_port(dut, vlan, cli_type='click'):
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

def get_stp_next_root_port(dut, vlan, cli_type='click'):
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
    root_cost = int(filter_and_select(out, ['port_pathcost'], {'port_name': root_port})[0]['port_pathcost'])
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
    pc_list = [each['teamdev'] for each in portchannel.get_portchannel_list(partner)]
    for each in out:
        port = each['port_name']
        if "Ethernet" in port and port in dut_partner_ports_map:
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

def config_stp_in_parallel(dut_list, feature="pvst", mode="enable", vlan=None, thread=True):
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
        params.append([config_spanning_tree, dut, feature, mode, vlan])
    if params:
        exec_all(thread, params)

def show_stp_in_parallel(dut_list, thread=True, cli_type='click'):
    """
    API to show the stp configuration in parallel in all the provided DUT's
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut_list:
    :param thread:
    :param cli_type:
    :return:
    """
    st.log("Displaying STP result on all the DUT's in parallel ....")
    dut_li = utility.make_list(dut_list)
    exec_foreach(thread, dut_li, show_stp, cli_type=cli_type)

def get_root_bridge_for_vlan(dut_vlan_data, thread=True):
    params = list()
    result = dict()
    for dut, vlan in dut_vlan_data.items():
        params.append([check_dut_is_root_bridge_for_vlan, dut, vlan])
    if params:
        [out, exceptions] = exec_all(thread, params)
    utils.banner_log("Getting root bridge details")
    for i,response in enumerate(out):
        result[params[i][1]] = response
    print(result)
    return result

def check_for_single_root_bridge_per_vlan(dut_list, vlan_list, dut_vlan_data, cli_type='click'):
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
        st.log(exceptions)
        for value in exceptions:
            st.log("Exceptions observed {}".format(value))
            if value is not None:
                st.log("Exception occured {}".format(value))
                return False
        if not stp_output:
            st.log("STP output not found on {} for {} instance".format(dut_li, vlan))
            st.report_fail("stp_output_not_found", dut_li, vlan)
        for index, stp_out in enumerate(stp_output):
            if len(stp_out) <= 0:
                st.log("STP OUTPUT IS NOT OBSERVED --- {}".format(stp_out))
                st.report_fail("stp_output_not_found")
            root_bridge = stp_out[0]["rt_id"]
            dut_bridge_id = stp_out[0]["br_id"]
            if root_bridge == dut_bridge_id and stp_out[0]["rt_port"] == "Root":
                if dut_vlan_data[dut_li[index]] != int(vlan.strip()):
                    st.log("Expected DUT {} is not root for {} instance".format(dut_li[index], vlan))
                    st.report_fail("expected_dut_not_root", dut_li[index], vlan)
                root_count += 1
            if root_count > 1:
                st.log("Observed more than 1 root bridge per {} instance".format(vlan))
                st.report_fail("observed_more_than_1_root_bridge", vlan)
    return True

def verify_root_bridge_interface_state(dut, vlan, interface_list, cli_type='click'):
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

def poll_root_bridge_interfaces(dut_vlan_list, interfaces_list, iteration=30, delay=1):
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
                if verify_root_bridge_interface_state(dut, vlan, interfaces_list[dut]):
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

def verify_root_bridge_on_stp_instances(dut_list, vlan, bridge_identifier):
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
        params.append([get_stp_bridge_param, dut, vlan, "rt_id"])
    if params:
        [out, exceptions] = exec_all(True, params)
        st.log("#########OUTPUT###########")
        st.log(out)
        st.log(exceptions)
        for value in exceptions:
            st.log("Exceptions observed {}".format(value))
            if value is not None:
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
    cli_type = kwargs.get("cli_type", "klish")
    interface=kwargs.get("interface",None)
    no_form=kwargs.get("no_form", None)
    action=kwargs.get("action", "enable")
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
        st.config(dut, commands, type=cli_type)
        return True
    return False

def config_stp_root_bridge_by_vlan(stp_data):
    """
    :param stp_data: {dut1: {"vlan":10, "priority": "0"}, dut2: {"vlan":20, "priority": "0"}, dut3: {"vlan":30, "priority": "0"}}
    """
    params = list()
    for dut, data in stp_data.items():
        params.append(utility.ExecAllFunc(config_stp_vlan_parameters, dut, data["vlan"], priority=data["priority"]))
    [out, exceptions] = exec_all(True, params)
    ensure_no_exception(exceptions)

def config_port_type(dut, interface, stp_type="rpvst", port_type="edge", no_form=False, cli_type="klish"):
    """
    API to config/unconfig the port type in RPVST
    :param dut:
    :param port_type:
    :param no_form:
    :return:
    """
    commands = list()
    command = "spanning-tree port type {}".format(port_type) if not no_form else "no spanning-tree port type"
    interface_details = utils.get_interface_number_from_name(interface)
    if not interface_details:
        st.log("Interface details not found {}".format(interface_details))
        return False
    commands.append("interface {} {}".format(interface_details.get("type"), interface_details.get("number")))
    commands.append(command)
    commands.append('exit')
    st.config(dut, commands, type=cli_type)
    return True

def show_stp_config_using_klish(dut, type="", vlan="", intf=""):
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
    st.show(dut, command, type="klish", skip_tmpl=True)


def verify_stp_intf_status(dut, vlanid, interface, status):
    """
    API to poll for stp stauts for an interface

    :param dut:
    :param vlanid:
    :param interface:
    :param status:
    :return:
    """
    if get_stp_port_param(dut, vlanid, interface, "port_state") == status:
        st.log("Port status is changed to  {}".format(status))
        return True
    return False