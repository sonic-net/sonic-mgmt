import re
import random

from spytest import st

from apis.system import basic
from apis.system.rest import config_rest, delete_rest, get_rest
import apis.system.port_rest as op_processor

import utilities.common as utils
from utilities.common import filter_and_select, make_list
from utilities.utils import get_interface_number_from_name, retry_api
from utilities.utils import segregate_intf_list_type, is_a_single_intf
from utilities.utils import get_supported_ui_type_list, convert_intf_name_to_component
from utilities.utils import override_ui

try:
    import apis.yang.codegen.messages.interfaces.Interfaces as umf_intf
    import apis.yang.codegen.messages.platform.Platform as umf_plat
    import apis.yang.codegen.messages.port_group as umf_port_gp
    import apis.yang.codegen.messages.interfaces_private.InterfacesPrivateRpc as umf_intf_pvt_rpc
    from apis.yang.codegen.yang_rpc_service import YangRpcService

except ImportError:
    pass


def force_cli_type_to_klish(cli_type, *more):
    cli_type = "klish" if cli_type in get_supported_ui_type_list(*more) else cli_type
    return cli_type


def _has_intf_range(dut):
    if not st.is_feature_supported("intf-range", dut):
        return False
    return True


def _get_klish_portmap(dut, portlist, ifname_type_oper):

    retval, portlist = {}, make_list(portlist)
    for port in portlist:
        retval[port] = port

    if ifname_type_oper is None:
        # no need to check ifname_type
        return retval

    command = "show interface status | grep \"Name|{} \"".format(" |".join(portlist))
    output = st.show(dut, command, type="klish")
    if not output:
        return retval

    for port in portlist:
        entries = filter_and_select(output, ["interface", "altname"], {"interface": port})
        if not entries:
            entries = filter_and_select(output, ["interface", "altname"], {"altname": port})
        if entries:
            retval[port] = entries[0]["interface"]

    return retval


def set_status(dut, portlist, status, **kwargs):
    """
    :param dut:
    :type dut:
    :param portlist:
    :type portlist:
    :param status: "shutdown" or "startup"
    :type status: string
    :return:
    :rtype:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    ifname_type_oper = kwargs.pop("ifname_type_oper", None)
    portlist = make_list(portlist)

    if cli_type in get_supported_ui_type_list():
        oper = False if status == 'shutdown' else 'true'
        port_hash_list = segregate_intf_list_type(intf=portlist, range_format=False)
        portlist = port_hash_list['intf_list_all']
        for port in portlist:
            if 'Management' in port:
                port = 'eth0'
            intf_obj = umf_intf.Interface(Name=port, InterfaceEnabled=oper)
            result = intf_obj.configure(dut, cli_type=cli_type)
            if not result.ok():
                st.log('test_step_failed: Setting of interface state {}'.format(result.data))
                return False
        return True
    elif cli_type == "click":
        port_hash_list = segregate_intf_list_type(intf=portlist, range_format=False)
        portlist = port_hash_list['intf_list_all']
        portlist = make_list(convert_intf_name_to_component(dut, portlist, component="applications"))
        if '-' in portlist:
            return st.config(dut, "config interface {} {}".format(status, portlist))

        # check if there is interface range support
        if _has_intf_range(dut):
            try:
                port = ",".join(portlist)
                return st.config(dut, "config interface {} {}".format(status, port))
            except Exception:
                st.warn("Failed to execute {} command - try alternative".format(status))

        for port in portlist:
            try:
                st.config(dut, "config interface {} {}".format(status, port))
            except ValueError:
                st.warn("Failed to execute {} command - try alternative".format(status))
                st.config(dut, "config interface {} {}".format(port, status))
    elif cli_type == "klish":
        commands = list()
        if ifname_type_oper is not None:
            port_hash_list = segregate_intf_list_type(intf=portlist, range_format=False)
            portlist = list(_get_klish_portmap(dut, port_hash_list['intf_list_all'], ifname_type_oper).values())
        port_hash_list = segregate_intf_list_type(intf=portlist, range_format=True)
        portlist = port_hash_list['intf_list_all']
        for each_port in portlist:
            if not is_a_single_intf(each_port):
                commands.append("interface range {}".format(each_port))
            else:
                intf_details = get_interface_number_from_name(each_port)
                commands.append("interface {} {}".format(intf_details["type"], intf_details["number"]))
            command = "shutdown" if status == "shutdown" else "no shutdown"
            commands.append(command)
            commands.append("exit")
        if commands:
            st.config(dut, commands, type=cli_type, **kwargs)
            return True
        return False
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        oper = False if status == 'shutdown' else True
        port_hash_list = segregate_intf_list_type(intf=portlist, range_format=False)
        portlist = port_hash_list['intf_list_all']
        for port in portlist:
            url = rest_urls['per_interface_config'].format(port)
            intf_operation = {"openconfig-interfaces:config": {"enabled": oper}}
            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=intf_operation):
                return False
        return True
    else:
        st.log("Unsupported CLI TYPE {}".format(cli_type))
        return False
    return ""


def shutdown(dut, portlist, **kwargs):
    set_status(dut, portlist, "shutdown", **kwargs)


def noshutdown(dut, portlist, **kwargs):
    set_status(dut, portlist, "startup", **kwargs)


def get_status(dut, port=None, cli_type=''):
    """
    :param dut:
    :type dut:
    :param port:
    :type port:
    :return:
    :rtype:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    if cli_type == "click":
        if not port:
            return st.show(dut, "show interfaces status")

        # get all interfaces status if there is no interface range support
        if not _has_intf_range(dut):
            if "," in port or "-" in port:
                return st.show(dut, "show interfaces status")

        # port could be range switch to all when failed
        try:
            return st.show(dut, "show interfaces status {}".format(port))
        except ValueError:
            st.warn("Failed to use interface command - try global")

        return st.show(dut, "show interfaces status")
    elif cli_type == "klish":
        command = "show interface status"
        if port:
            interface = port.split(",")
            command += " | grep \"{} \"".format(" |".join(interface))
        return st.show(dut, command, type=cli_type)
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        result = []
        if port:
            ports = port.split(",")
            for port2 in ports:
                url = rest_urls['per_interface_details'].format(port2)
                output = get_rest(dut, rest_url=url, timeout=60)
                processed_output = op_processor.process_intf_status_rest_output(output)
                if processed_output:
                    result.extend(processed_output)
                st.log("REST output is: {}".format(output))
        else:
            url = rest_urls['all_interfaces_details']
            output = get_rest(dut, rest_url=url, timeout=60)
            processed_output = op_processor.process_intf_status_rest_output(output)
            if processed_output:
                result.extend(processed_output)
        return result
    else:
        st.log("Unsupported CLI TYPE {}".format(cli_type))
        return False


def get_interfaces_by_status(dut, status, cli_type=''):
    """
    :param dut:
    :type dut:
    :param status:
    :type status:
    :return:
    :rtype:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    output = get_status(dut, None, cli_type=cli_type)
    retval = []
    match = {"oper": status} if status else None
    entries = filter_and_select(output, ["interface"], match)
    for ent in entries:
        retval.append(ent["interface"])
    return retval


def get_interfaces_up(dut, cli_type=''):
    """
    :param dut:
    :type dut:
    :return:
    :rtype:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    return get_interfaces_by_status(dut, "up", cli_type=cli_type)


def get_interfaces_down(dut, cli_type=''):
    """
    :param dut:
    :type dut:
    :return:
    :rtype:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    return get_interfaces_by_status(dut, "down", cli_type=cli_type)


def get_interfaces_all(dut, cli_type=''):
    """
    :param dut:
    :type dut:
    :return:
    :rtype:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    return get_interfaces_by_status(dut, None, cli_type=cli_type)


def get_interface_status(dut, port, cli_type=''):
    """
    :param dut:
    :type dut:
    :param port:
    :type port:
    :return:
    :rtype:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    output = get_status(dut, port, cli_type=cli_type)
    match = {"interface": port}
    entries = filter_and_select(output, ["oper"], match)
    for ent in entries:
        return ent["oper"]
    return None


def verify_oper_state(dut, port, state, cli_type='', **kwargs):
    """
    :param dut:
    :type dut:
    :param port:
    :type port:
    :param state:
    :type state:
    :return:
    :rtype:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    if cli_type in get_supported_ui_type_list():
        filter_type = kwargs.get('filter_type', 'ALL')
        query_params_obj = utils.get_query_params(yang_data_type=filter_type, cli_type=cli_type)
        intf_obj = umf_intf.Interface(Name=port)
        intf_obj.OperStatus = state.upper()
        result = intf_obj.verify(dut, match_subset=True, query_param=query_params_obj, cli_type=cli_type)
        if not result.ok():
            st.log('test_step_failed: Match not found:')
            return False
        return True
    if get_interface_status(dut, port, cli_type=cli_type) != state:
        return False
    return True


def get_interface_counters_all(dut, port=None, cli_type=''):
    '''
    :param dut:
    :param port:
    :param cli_type:
    :return:
    (pavan.kasula@broadcom.com) Added intf range support
    '''
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    # Klish CLIs does convert the counter value in Mbps, where as in yang it is bps.
    # So keeping it in klish to avoid the convertion in API
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    if cli_type in get_supported_ui_type_list():
        if port:
            intf_obj = umf_intf.Interface(Name=port)
            result = intf_obj.get_payload(dut, cli_type=cli_type)
            if not result.ok():
                st.log('test_step_failed: Setting of interface state {}'.format(result.data))
                return False
            output = result.payload
            result = []
            processed_output = op_processor.process_intf_counters_gnmi_rest_output(output, counter_type='rate')
            if processed_output:
                result.extend(processed_output)
            return result
        else:
            cli_type = 'klish'
    if cli_type == 'click':
        if port:
            port_hash_list = segregate_intf_list_type(intf=port, range_format=False)
            interface_list = port_hash_list['intf_list_all']
            interface_li = '|'.join([str(elem) for elem in interface_list])
            command = "show interfaces counters -a | grep -Ew \"(IFACE|{})\" ".format(interface_li)
            if not st.is_feature_supported("show-interfaces-counters-interface-command", dut):
                st.community_unsupported(command, dut)
                command = "show interfaces counters -a | grep -Ew \"(IFACE|{})\" ".format(interface_li)
            # To avoid traffic rate inaccuracy, run and ignore first show command in click & use second one
            st.show(dut, command)
            return st.show(dut, command)
        else:
            return st.show(dut, "show interfaces counters -a", type=cli_type)
    elif cli_type == 'klish':
        if port:
            port_hash_list = segregate_intf_list_type(intf=port, range_format=False)
            interface_list = port_hash_list['intf_list_all']
            interface_li = ' |'.join([str(elem) for elem in interface_list])
            cmd = "show interface counters rate | grep \"Interface|{} \"".format(interface_li)
        else:
            cmd = "show interface counters rate"
        cmd_op = st.show(dut, cmd, type=cli_type)
        for i in range(0, len(cmd_op)):
            # Creating rx_bps and tx_bps for legacy script.
            # Click doesnt have mpbs data
            cmd_op[i]['rx_bps'] = cmd_op[i]['rx_mbps']
            cmd_op[i]['tx_bps'] = cmd_op[i]['tx_mbps']
        return cmd_op
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        result = []
        url = rest_urls['all_interfaces_details']
        output = get_rest(dut, rest_url=url, timeout=60)
        processed_output = op_processor.process_intf_counters_rest_output(output)
        if processed_output:
            result.extend(processed_output)
        return result
    else:
        st.log("Unsupported CLI TYPE {}".format(cli_type))
        return False


def clear_interface_counters(dut, **kwargs):
    cli_type = st.get_ui_type(dut, **kwargs)
    # cli_type = force_cli_type_to_klish(cli_type=cli_type)
    interface_name = kwargs.get("interface_name", "")
    interface_type = kwargs.get("interface_type", "all")
    if cli_type in get_supported_ui_type_list():
        service = YangRpcService()
        rpc = umf_intf_pvt_rpc.ClearCountersRpc()
        clear_type = 'all' if interface_type == 'all' else interface_name
        rpc.Input.interface_param = clear_type
        result = service.execute(dut, rpc, timeout=60, cli_type=cli_type)
        if not result.ok():
            st.log('test_step_failed: Clear interface counters failed: {}'.format(result.data))
            return False

        return True
    if cli_type == "klish":
        confirm = kwargs.get("confirm") if kwargs.get("confirm") else "y"
        if interface_type != "all":
            interface_type = get_interface_number_from_name(str(interface_name))
            if interface_type["type"] and interface_type["number"]:
                interface_val = "{} {}".format(interface_type.get("type"), interface_type.get("number"))
            else:
                interface_val = ""
        else:
            interface_val = "all"
        if not interface_val:
            st.log("Invalid interface type")
            return False
        command = "clear counters interface {}".format(interface_val)
        st.config(dut, command, type=cli_type, confirm=confirm, conf=False, skip_error_check=True)
    elif cli_type == "click":
        command = "show interfaces counters -c"
        if not st.is_feature_supported("show-interfaces-counters-clear-command", dut):
            st.community_unsupported(command, dut)
            return st.config(dut, "sonic-clear counters")
        return st.show(dut, command)
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        url = rest_urls['clear_interface_counters']
        clear_type = 'all' if interface_type == 'all' else interface_name
        clear_counters = {"sonic-interface:input": {"interface-param": clear_type}}
        if not config_rest(dut, http_method='post', rest_url=url, json_data=clear_counters):
            st.error("Failed to clear interface counters")
            return False
    else:
        st.log("Unsupported CLI TYPE {}".format(cli_type))
        return False
    return True


def get_interface_counters(dut, port, *counter, **kwargs):
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut, **kwargs))
    output = get_interface_counters_all(dut, port=port, cli_type=cli_type)
    entries = filter_and_select(output, counter, {'iface': port})
    return entries


def check_current_breakout(dut, data_port):
    errs, no_info_msg = [], "No valid breakout configuration"
    output = st.show(dut, "show interface breakout", type='klish')
    if not output or no_info_msg in output:
        errs.append(no_info_msg)
        return errs

    for x in range(0, len(data_port), 2):
        opt = data_port[x + 1].strip()
        port = data_port[x].replace("port ", "")
        match = {'port': port, 'status': 'Completed', 'breakout_mode': opt}
        if not filter_and_select(output, None, match):
            errs.append("breakout mode on {} not correct".format(port))
            errs.append("breakout mode match {}".format(match))
    return errs

# data = ["Ethernet0", "4x10", "Etherne40", "4x10"]


def breakout(dut, data, undo=False, brk_verify=True, cli_type="",
             skip_error=False, redo=True, dpb_type='static', dpb_seed=0):

    st.log('API_NAME: breakout, API_ARGS: {}'.format(locals()))
    # determine ui type to be used
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    cli_type = override_ui('rest-put', 'rest-patch', cli_type=cli_type)

    # local variables
    cmds, cmds_1 = [], []
    data_port = list(data)

    # see if we need platform check
    platform_check = False
    dut_type = basic.get_hwsku(dut)
    if dut_type:
        if ("9716" in dut_type or "IX9" in dut_type) and not st.is_feature_supported("flex-dpb", dut):
            platform_check = True

    # fix the breakout name
    for x in range(0, len(data_port), 2):
        data_port[x + 1] = data_port[x + 1].strip()
        if not data_port[x + 1].endswith("G"):
            data_port[x + 1] = "{}G".format(data_port[x + 1])

    # Randomizing the ports
    if dpb_type == 'random':
        st.log("The ports will be randomized to effectively utilize different interfaces from the yaml file")
        data1 = [[data_port[i]] + [data_port[i + 1]] for i in range(0, len(data_port), 2)]
        if dpb_seed == 0:
            dpb_seed = utils.get_random_seed()

        st.log('The seed value used for this run is {}'.format(dpb_seed))
        random.Random(dpb_seed).shuffle(data1)

        data_port = []
        for dport in data1:
            data_port.extend(dport)
        st.log("The data port after randomization are {}".format(data_port))

    if cli_type == "klish" or cli_type in get_supported_ui_type_list():

        # validate the interfaces
        modes = st.show(dut, "show interface breakout modes", type='klish')
        if not modes:
            st.error('Show interface breakout modes is not yielding any output, DPB might not be supported on this platform')
            return False

        # join the supported modes
        for mode in modes:
            mode['supported_modes'] = ' '.join(mode['supported_modes'])

        # validate the breakout needs
        valid = True
        for x in range(0, len(data_port), 2):
            interface1 = _get_breakout_interface(dut, data_port[x], False)
            res1 = filter_and_select(modes, ['port'], {'iface': interface1})
            if res1:
                data_port[x] = 'port ' + res1[0]['port']
                continue
            interface2 = _get_breakout_interface(dut, data_port[x], True)
            if interface1 == interface2:
                st.error('Cannot breakout interface {}/{} at index {}'.format(data_port[x], interface1, x))
                valid = False
                continue
            st.warn('Cannot breakout interface {}/{} at index {} - trying alias {}'.format(data_port[x], interface1, x, interface2))
            res1 = filter_and_select(modes, ['port'], {'iface': interface2})
            if res1:
                st.log('Using interface {}/{} at index {} for breakout'.format(data_port[x], interface2, x))
                data_port[x] = 'port ' + res1[0]['port']
                continue
            st.error('Cannot breakout port {}/{} at index {}'.format(data_port[x], interface2, x))
            valid = False

        if not valid:
            return False

        # verify if the current breakout is same as what is needed
        if not redo:
            errs = check_current_breakout(dut, data_port)
            if not errs:
                st.log("Current breakout configuration matches with needed")
                return True
            for err in errs:
                st.error(err)

        for index in range(0, len(data_port), 2):
            intf, opt = data_port[index].strip(), data_port[index + 1].strip()
            if intf in ['port 1/31', 'port 1/32'] and platform_check:
                if intf == 'port 1/31':
                    intf1 = 'Ethernet240'
                else:
                    intf1 = 'Ethernet248'
                st.log("The platform used is {}, if the ports are 1/31 (Intf: Ethernet240) or 1/32 (Intf: Ethernet248) it will be broken into 8x10G by default".format(dut_type))
                if undo:
                    cmds_1.append("config interface breakout {} 1x400G -y".format(intf1))
                else:
                    cmds_1.append("config interface breakout {} 8x10G -y".format(intf1))
            else:
                if undo:
                    if cli_type == 'klish':
                        cmds.append("no interface breakout {}".format(intf))
                    if cli_type in get_supported_ui_type_list():
                        port = intf.strip('port ')
                        # comp_obj = umf_plat.Component(Name=port, MediaFecMode='IEEE')
                        comp_obj = umf_plat.Component(Name=port)
                        port_obj = umf_plat.Group(Index=int(port.split('/')[0]), Component=comp_obj)
                        result = port_obj.unConfigure(dut, cli_type=cli_type)
                        if not result.ok():
                            st.log('test_step_failed: Breakout on port: {} {}'.format(port, result.data))
                            return False
                else:
                    if cli_type == 'klish':
                        cmds.append("interface breakout {} mode {}".format(intf, opt))
                    if cli_type in get_supported_ui_type_list():
                        port = intf.strip('port ')
                        speed = opt.split('x')
                        breakout_speed = 'SPEED_{}GB'.format(speed[1].replace('G', ''))
                        # comp_obj = umf_plat.Component(Name=port, MediaFecMode='IEEE')
                        comp_obj = umf_plat.Component(Name=port)
                        port_obj = umf_plat.Group(Index=int(port.split('/')[0]), NumBreakouts=int(speed[0]), BreakoutSpeed=breakout_speed)
                        comp_obj.add_Group(port_obj)
                        result = comp_obj.configure(dut, cli_type=cli_type)
                        if not result.ok():
                            st.log('test_step_failed: Breakout on port: {} {}'.format(port, result.data))
                            return False

    elif cli_type == "click":
        for index in range(0, len(data), 2):
            intf, opt = data[index].strip(), data[index + 1].strip()
            if intf in ['Ethernet240', 'Ethernet248'] and platform_check:
                st.log("The platform used is {}, if the ports are Ethernet240 or Ethernet248 it will be broken into 8x10G by default".format(dut_type))
                if undo:
                    cmds.append("config interface breakout {} 1x400G -y -f".format(intf))
                else:
                    cmds.append("config interface breakout {} 8x10G -y -f".format(intf))
            else:
                if undo:
                    cmds.append("config interface breakout {} 1x100G -y -f".format(intf))
                else:
                    cmds.append("config interface breakout {} {} -y -f".format(intf, opt))
    else:
        st.error("Unsupported CLI TYPE {}".format(cli_type))
        return False

    if len(cmds_1) > 0:
        st.config(dut, cmds_1, type='click', skip_error_check=skip_error, on_cr_recover="retry5")

    if len(cmds) > 0:
        st.config(dut, cmds, type=cli_type, skip_error_check=skip_error, on_cr_recover="retry5")

    if brk_verify and (cli_type in get_supported_ui_type_list() or cli_type == "klish") and not undo:
        for index in range(0, len(data), 2):
            intf, opt = data_port[index].strip(), data_port[index + 1].strip()
            intf = "Ethernet".join(intf.split("Ethernet"))
            if 'port' in intf:
                if retry_api(verify_dpb_status, dut, on_cr_recover="retry5", port=intf,
                             breakout_mode=opt, retry_count=30, delay=10):
                    st.log("Breakout of {} to speed {} is successful".format(intf, opt))
            elif retry_api(verify_dpb_status, dut, on_cr_recover="retry5", interface=intf,
                           breakout_mode=opt, retry_count=30, delay=10):
                st.log("Breakout of {} to speed {} is successful".format(intf, opt))
            else:
                st.error("Breakout is not successful for {} of speed {}, even after 300 seconds".format(intf, opt))
                return False

    return True

# data = ["Ethernet0", 10000, "Etherne40", 40000]


def set_speed(dut, data, **kwargs):
    ifname_type_oper = kwargs.pop("ifname_type_oper", None)
    skip_error = kwargs.pop("skip_error", False)
    cli_type = kwargs.pop("cli_type", "")
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    cli_type = force_cli_type_to_klish(cli_type, 'rest-patch', 'rest-put')
    flexdpb_speed = kwargs.pop("flexdpb_speed", False)

    platform = basic.get_hwsku(dut)
    if platform:
        platform = platform.lower()

    ports_per_pg = 12 if platform in ["accton-as7326-56x"] else 4
    hw_constants = st.get_datastore(dut, "constants")

    non_portgroup_platforms = hw_constants["NON_PORTGROUP_PLATFORMS"]
    port_group_speed_platform = hw_constants['NON_PORTGROUP_PLATFORMS_SPEED_SUPPORTED']

    # if platform in port_group_speed_platform:
    #     st.config(dut, "port-group 1 speed 10000", type="klish", **kwargs)

    if not st.is_feature_supported("port-group", dut):
        non_portgroup_platforms.append(platform)

    ports_dict = dict()
    port_name_dict = dict()
    klish_port_name_dict = dict()
    for index in range(0, len(data), 2):
        port = st.get_other_names(dut, [data[index]])[0] if "/" in data[index] else data[index]
        klish_port_name_dict[data[index]] = data[index + 1]
        port_name_dict[port] = data[index + 1]
        id = re.search(r"\d+", port).group(0)
        id = (int(int(id) / ports_per_pg)) + 1
        if platform in port_group_speed_platform:
            # in this platforms portgroup starts from Ethernet48 compared to other devices.
            output = verify_port_group(dut, return_output=True)
            id = output[0]['portgroup']
        ports_dict[str(id)] = data[index + 1]
    st.debug("port-group speed data: {}".format(ports_dict))

    commands = list()
    if cli_type == 'click':
        if platform not in non_portgroup_platforms:
            commands = ["config portgroup speed {} {}".format(index, speed) for index, speed in ports_dict.items()]
        else:
            commands = ["portconfig -p {} -s {}".format(port, speed) for port, speed in port_name_dict.items()]
    elif cli_type == 'klish':
        if platform not in non_portgroup_platforms and not flexdpb_speed:
            commands = ["port-group {} speed {}".format(index, speed) for index, speed in ports_dict.items()]
        else:
            portmap = _get_klish_portmap(dut, list(klish_port_name_dict.keys()), ifname_type_oper)
            for port, speed in klish_port_name_dict.items():
                port = portmap[port]
                intf_details = get_interface_number_from_name(port)
                if not intf_details:
                    st.error("Interface data not found for {} ".format(port))
                    continue
                commands.append("interface {} {}".format(intf_details["type"], intf_details["number"]))
                commands.append("speed {}".format(speed))
                commands.append("exit")
    else:
        st.error("Unsupported CLI_TYPE: {}".format(cli_type))
    if commands:
        st.config(dut, commands, type=cli_type, skip_error_check=skip_error, **kwargs)
    return True


def verify_port_group(dut, **kwargs):
    '''
    :param dut:
    :param portgroup: port-group id to be verified
    :param start_intf: start phy interface in the port-group
    :param end_intf: end phy interface in the port-group
    :param valid_speeds: list of valid speeds for the port-group
    :param default_speed: default speed for the port-group when no config in place.
    :param current_speed: Current speed of the port-group
    :return:

    Usage:
    Each of the parameter can be passed as list as well.
    [click shows the speed in MB(25000) and klish in GB (25G)]
         port.verify_port_group(dut1,portgroup=1,start_intf='Ethernet0',end_intf='Ethernet12',\
                                    valid_speeds=['10G','25G'],default_speed='25G',current_speed='10G')
    '''
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut, **kwargs))
    # Rest supported with new infra
    cli_type = 'klish' if cli_type in ['rest-put', 'rest-patch'] else cli_type

    skip_error = kwargs.pop('skip_error_check', True)

    # Processing input params
    portgroup = kwargs.get('portgroup', None)
    start_intf = kwargs.get('start_intf', None)
    end_intf = kwargs.get('end_intf', None)
    valid_speeds = kwargs.get('valid_speeds', None)
    default_speed = kwargs.get('default_speed', None)
    current_speed = kwargs.get('current_speed', None)

    if portgroup:
        portgroup_l = portgroup if type(portgroup) is list else [portgroup]
    else:
        portgroup_l = []

    if start_intf:
        start_intf_l = start_intf if type(start_intf) is list else [start_intf]
    else:
        start_intf_l = [None] * len(portgroup_l)

    if end_intf:
        end_intf_l = end_intf if type(end_intf) is list else [end_intf]
    else:
        end_intf_l = [None] * len(portgroup_l)

    if valid_speeds:
        valid_speeds_l = valid_speeds if type(valid_speeds[0]) is list else [valid_speeds]
    else:
        valid_speeds_l = [None] * len(portgroup_l)

    if default_speed:
        default_speed_l = default_speed if type(default_speed) is list else [default_speed]
    else:
        default_speed_l = [None] * len(portgroup_l)

    if current_speed:
        current_speed_l = current_speed if type(current_speed) is list else [current_speed]
    else:
        current_speed_l = [None] * len(portgroup_l)

    # Marking to klish based on parameter to be verified.
    if cli_type in get_supported_ui_type_list():
        non_gnmi_params = ['return_output']
        for param in non_gnmi_params:
            if param in kwargs:
                cli_type = 'klish'
                break

    if cli_type in get_supported_ui_type_list():
        filter_type = kwargs.get('filter_type', 'ALL')
        query_params_obj = utils.get_query_params(yang_data_type=filter_type, cli_type=cli_type)
        for portgroup, start_intf, end_intf, valid_speeds, default_speed, current_speed in \
                zip(portgroup_l, start_intf_l, end_intf_l, valid_speeds_l, default_speed_l, current_speed_l):
            port_group_obj = umf_port_gp.PortGroup(Id=portgroup)
            if start_intf:
                port_group_obj.MemberIfStart = start_intf
            if end_intf:
                port_group_obj.MemberIfEnd = end_intf
            if valid_speeds:
                oc_speed = []
                for speed in valid_speeds:
                    if speed == '10G':
                        oc_speed.extend(['SPEED_10GB'])
                    if speed == '25G':
                        oc_speed.extend(['SPEED_25GB'])
                st.log("Valid Speed List:{}".format(oc_speed))
                port_group_obj.ValidSpeeds = oc_speed
            if default_speed:
                port_group_obj.DefaultSpeed = 'SPEED_' + default_speed + 'B'
                st.log("Default Speed:{}".format(port_group_obj.DefaultSpeed))
            if current_speed:
                port_group_obj.Speed = 'SPEED_' + current_speed + 'B'
                st.log("Current Speed:{}".format(port_group_obj.Speed))
            result = port_group_obj.verify(dut, match_subset=True, query_param=query_params_obj, cli_type=cli_type)
            if not result.ok():
                st.log('test_step_failed: Match NOT Found: Port Group Params')
                return False
        return True
    elif cli_type == 'click':
        cmd = 'show portgroup'
    elif cli_type == 'klish':
        cmd = 'show port-group'
    else:
        st.error("Invalid CLI type - {}".format(cli_type))
        return False

    output = st.show(dut, cmd, skip_error_check=skip_error, type=cli_type)

    if len(output) == 0:
        st.error("Output is Empty")
        return False
    if "return_output" in kwargs:
        return output

    success = True
    for portgroup, start_intf, end_intf, valid_speeds, default_speed, current_speed in \
            zip(portgroup_l, start_intf_l, end_intf_l, valid_speeds_l, default_speed_l, current_speed_l):
        match_dict = {"portgroup": portgroup}
        if start_intf:
            match_dict['start_intf'] = start_intf
        if end_intf:
            match_dict['end_intf'] = end_intf
        if valid_speeds:
            speed_l = ''
            for speed in valid_speeds:
                speed_l += speed + ', '
            speed_l = speed_l.strip(', ')
            speed_l += ' '
            st.log("Speed List:{}".format(speed_l))
            match_dict['valid_speeds'] = speed_l
        if default_speed:
            match_dict['default_speed'] = default_speed
        if current_speed:
            match_dict['current_speed'] = current_speed

        filtered_output = filter_and_select(output, None, match_dict)
        if filtered_output:
            st.log('Match FOUND: for Portgroup:{}, Expected: {} Got: {} '.format(portgroup, match_dict, filtered_output))
        else:
            st.error('Match NOT FOUND: for Portgroup:{}, Expected: {} Got: {} '.format(portgroup, match_dict, filtered_output))
            success = False

    return True if success else False


def dyn_port_breakout(dut, **kwargs):
    """
     Author:naveen.nagaraju@broadcom.com
    :param dut:
    :param portlist:
    :param speed : 1x40G  2x100G 2x50G  4x100G 4x25G  4x10G:
    :param cli_type:
    :return:
    :rtype:

    :Usuage :  port.dyn_port_breakout(dut7,portlist=["Ethernet0","Ethernet4"],speed="4x10",config="yes",skip_error="yes")
               port.dyn_port_breakout(dut7,portlist=["Ethernet0","Ethernet4"],config="no")


    """
    st.log('API_NAME: dyn_port_breakout, API_ARGS: {}'.format(locals()))
    config = kwargs.get('config', 'yes')
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut, **kwargs))
    speed = kwargs.get("speed", None)
    skip_error = kwargs.pop('skip_error', False)
    if 'return_output' in kwargs:
        cli_type = 'klish'

    if 'portlist' in kwargs:
        if type(kwargs['portlist']) is not list:
            kwargs['portlist'] = [kwargs['portlist']]
        data_port = kwargs['portlist']
        # clone the list to avoid the unexpcted list memory updates
        if (data_port is not None) and isinstance(data_port, list):
            data_port = list(data_port)
        for x in range(len(data_port)):
            res1 = get_interface_breakout_mode(dut, interface=data_port[x])
            if res1:
                data_port[x] = 'port ' + res1[0]['port']
            else:
                st.error('Invalid interface, cannot breakout')
                return False
    elif 'dpbport' in kwargs:
        if 'port' in kwargs['dpbport']:
            data_port = [kwargs['dpbport']]
        else:
            data_port = ['port ' + kwargs['dpbport']]
    else:
        st.error("Mandatory arg portlist or dpbport is not present")
        return False

    my_cmd = ''

    if cli_type in get_supported_ui_type_list():
        for port in data_port:
            port = port.strip('port ')
            # defect 70247, is seen if media-fed-mode is set in gnmi+std-ext mode.
            # Above issue is not seen with alias mode
            # comp_obj = umf_plat.Component(Name=port, MediaFecMode='IEEE')
            comp_obj = umf_plat.Component(Name=port)
            if config.lower() == "yes":
                if speed is None:
                    st.error(':Speed parameter is required to breakout a port')
                    return False
                speed = speed.split('x')
                port_obj = umf_plat.Group(Index=int(port.split('/')[0]), NumBreakouts=int(speed[0]), BreakoutSpeed='SPEED_{}GB'.format(speed[1]))
                comp_obj.add_Group(port_obj)
                result = comp_obj.configure(dut, cli_type=cli_type)

                if not result.ok():
                    if skip_error is True or skip_error == 'yes':
                        st.log('Negative Scenario: Error/Exception is expected')
                        return False
                    else:
                        st.log('test_step_failed: Breakout on port: {} {}'.format(port, result.data))
                        return False
            else:
                port_obj = umf_plat.Group(Index=int(port.split('/')[0]), Component=comp_obj)
                result = port_obj.unConfigure(dut, cli_type=cli_type)
                if not result.ok():
                    st.log('test_step_failed: Breakout on port: {} {}'.format(port, result.data))
                    return False
        return True

    if cli_type == 'klish':

        if config.lower() == "yes":
            if speed is None:
                st.error(':Speed parameter is required to breakout a port')
                return False
            for port in data_port:
                if 'lane_count' in kwargs:
                    my_cmd += 'interface breakout {} mode {}G total-lane-count {} \n'.format(port, speed.strip('G'), kwargs['lane_count'])
                else:
                    my_cmd += 'interface breakout {} mode {}G\n'.format(port, speed.strip('G'))
        else:
            for port in data_port:
                my_cmd += 'no interface breakout {}\n'.format(port)

        if 'return_output' in kwargs:
            return st.config(dut, my_cmd, type='klish', skip_error_check=skip_error)
        else:
            output = st.config(dut, my_cmd, type='klish', skip_error_check=skip_error)

        st.wait(2)
        if "%Error: Maximum ports per pipeline reached" in output:
            st.log('Maximum port exceeded cannot break this port.')
            return False
        elif "No change in port breakout mode" in output:
            st.log('No change in port breakout mode.')
        elif "Dynamic Port Breakout in-progress" in output:
            st.log('Breakout is progress, verify show command to check the status')
        elif "% Error: Invalid input detected" in output:
            st.log('Either port/interface name supplied is wrong or breakout is not supported')
            return False

    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        ocdata = {}
        if config.lower() == "yes":
            if speed is None:
                st.error(':Speed parameter is required to breakout a port')
                return False
            for port in data_port:
                port = port.replace('/', '%2F')
                port = port.strip('port ')
                base_url = rest_urls['config_dpb'].format(port)
                speed = speed.split('x')
                ocdata['openconfig-platform-port:config'] = {"num-channels": int(speed[0]), "channel-speed": "SPEED_{}GB".format(int(speed[1]))}
                response = config_rest(dut, http_method=cli_type, rest_url=base_url, json_data=ocdata)
                if not response:
                    return False

        else:
            for port in data_port:
                port = port.replace('/', '%2F')
                port = port.strip('port ')
                base_url = rest_urls['config_dpb'].format(port)
                response = delete_rest(dut, rest_url=base_url)
                if not response:
                    return False

    return True


def verify_dpb_status(dut, **kwargs):
    """
    Author: Naveen Nag
    email : naveen.nagaraju@broadcom.com
    :param dut:
    :param interface:
    :type string or list
    :param speed:
    :type string or list
    :param status:
    :type status in string or list
    :return:


    Usage:
     port.verify_dpb_status(dut1,interface='Port 1/1',status='Completed',breakout_mode='4x10G')
    """

    if 'interface' in kwargs:
        res1 = get_interface_port_mapping(dut, kwargs['interface'])
        if not res1:
            st.error('Invalid interface, cannot get the status')
            return False
    elif 'port' in kwargs:
        if 'port' in kwargs['port']:
            res1 = kwargs['port']
        else:
            res1 = 'port ' + kwargs['port']
    else:
        st.error("Mandatory argument \'interface\' or \'port\' is missing")
        return False

    dpb_state = kwargs.get('status', "Completed")
    on_cr_recover = kwargs.pop("on_cr_recover", None)

    if on_cr_recover is None:
        output = st.show(dut, "show interface breakout {}".format(res1), type='klish')
    else:
        output = st.show(dut, "show interface breakout {}".format(res1), type='klish', on_cr_recover=on_cr_recover)

    if not output or output[0]['err'] == "configurations":
        st.error("No valid breakout configurations")
    else:
        if 'breakout_mode' in kwargs:
            if output[0]['status'] != dpb_state or output[0]['breakout_mode'].strip('G') != kwargs['breakout_mode'].strip('G'):
                st.error("Interface breakout status or mode not as expected, Expected - {},{} Actual - {},{} ".format(dpb_state, kwargs['breakout_mode'], output[0]['status'], output[0]['breakout_mode']))
                return False
        elif output[0]['status'] != dpb_state:
            st.error("Interface breakout status not as expected, Expected - {} Actual - {} ".format(dpb_state, output[0]['status']))
            return False
    return True


def _get_breakout_interface(dut, interface, other):
    if '/' not in interface and other:
        interface = st.get_other_names(dut, [interface])[0]
    if '/' in interface:
        interface = '/'.join([interface.split('/')[0], interface.split('/')[1]])
    return interface


def get_interface_breakout_mode(dut, **kwargs):
    """
    Author: Naveen Nag
    email : naveen.nagaraju@broadcom.com
    :param dut:
    :param interface:
    :param fields:
    :return: port,interface,supported_modes,default mode

    Usage:
    port.get_interface_breakout_mode(dut1, interface='Ethernet4')
    :return  - [{'supported_modes': '1x100G[40G], 4x25G[10G]', 'port': '1/2'}]

    """

    if 'port' in kwargs:
        output = st.show(dut, "show interface breakout modes port {}".format(kwargs['port']), type='klish')
    else:
        output = st.show(dut, "show interface breakout modes", type='klish')

    if output:
        if 'interface' in kwargs:
            interface = _get_breakout_interface(dut, kwargs['interface'], False)
            entries = filter_and_select(output, None, {'iface': interface})
            if not entries:
                interface = _get_breakout_interface(dut, kwargs['interface'], True)
                entries = filter_and_select(output, None, {'iface': interface})
            if entries:
                entries[0]['supported_modes'] = ', '.join(entries[0]['supported_modes'])
        else:
            entries = filter_and_select(output)

        if entries:
            return entries
        else:
            st.error("{} is not part of the output".format(kwargs['interface']))
            return False
    else:
        st.error("Breakout is not supported on this platform")
        return False


def default_interface(dut, **kwargs):
    """
    TO configure default interface
    Author: Naveen (naveen.nagaraju@broadcom.com)

    :param dut:
    :param interface_name:
    :param range: 'True', if Range is True, please provide interfaces range with "-" for eg Ethernet 0-10
    :return:

    Eg : port.default_interface(dut1, interface = 'Ethernet 4-7',range='yes/True')
         port.default_interface(dut1, interface = 'Ethernet 4')
    """
    cli_type = st.get_ui_type(dut, **kwargs)

    if 'interface' not in kwargs:
        st.error("Mandatory arg interface is not present")
        return False
    else:
        interface = kwargs['interface']

    skip_error = kwargs.pop('skip_error', False)
    command = ''

    if cli_type == 'klish':
        if 'range' in kwargs:
            command = command + "\n" + "default interface range {}".format(interface)
        else:
            command = command + "\n" + "default interface {}".format(interface)
    else:
        st.error("Invalid cli_type for this API - {}.".format(cli_type))
        return False

    st.config(dut, command, type='klish', skip_error_check=skip_error)
    return True


def get_interface_breakout_param(dut, **kwargs):
    """
    Author: Naveen Nag
    email : naveen.nagaraju@broadcom.com
    :param dut:
    :param interface:
    :param fields:
    :param port
    :return: interface breakout speed or interface breakout params if dpb_param is used

    Usage:
    port.get_interface_breakout_param(dut1, 'Ethernet4')
    :return  - ['4x10G', 'Completed']

     res = port_api.get_interface_breakout_param(data.dut1,port='1/1',dpb_param='all')
     :return - [{'port': '1/1', 'interface': 'Eth1/1', 'breakout_mode': 'Default', 'status': 'Completed', 'err': ''}]


    """
    param_breakout = []

    if 'port' in kwargs:
        output = st.show(dut, "show interface breakout port {}".format(kwargs['port'].strip('port ')), type='klish')
    elif 'interface' in kwargs:
        res = get_interface_port_mapping(dut, kwargs['interface'])
        if not res:
            st.error('Invalid interface, cannot get the status')
            return False
        output = st.show(dut, "show interface breakout {}".format(res), type='klish')
    else:
        st.error("Mandatory argument \'interface\' or \'port\' is missing")
        return False

    if len(output) == 0:
        st.error("Provided interface is not a breakout port")
        return False
    elif 'dpb_param' in kwargs:
        return output
    else:
        param_breakout.append(str(output[0]['breakout_mode'].strip('G')))
        param_breakout.append(output[0]['status'])
        return param_breakout


def get_interface_details_by_alt_name(dut, alt_name):
    cli_type = st.get_ui_type(dut)
    interface_details = get_status(dut, cli_type=cli_type)
    default_intf = dict()
    if interface_details:
        for intf_data in interface_details:
            if intf_data["interface"] == alt_name:
                default_intf = intf_data
            if cli_type == "click":
                if intf_data["interface"] == alt_name:
                    return intf_data
            else:
                if intf_data["altname"] == alt_name:
                    return intf_data
    return default_intf


# TODO: remove this after refactoring
def check_corefiles(dut, **kwargs):
    return basic.check_core_files(dut, **kwargs)


def get_interface_port_mapping(dut, interface):
    """
    Author: Naveen Nag
    email : naveen.nagaraju@broadcom.com
    :param dut:
    :param interface:
    :return: port

    Usage:
    port.map_interface_port(dut1,interface)
    :return  - [{'port 1/1'}]

    """

    st.log('Mapping interface name to port number')
    res1 = get_interface_breakout_mode(dut, interface=interface)
    if res1:
        return 'port ' + res1[0]['port']

    return False


def get_interface_breakout_resource(dut, **kwargs):
    """
    Author: Naveen Nag
    email : naveen.nagaraju@broadcom.com
    :param dut:
    :param fields:
    :return: port,system_maxport, pipeline etc

    Usage:
    port.get_interface_breakout_resource(dut1)
    :return  - [{u'pline_port': '19', u'pline': '4', u'pline_maxport': '32', u'ftpanel_port': ['1/25, 1/26, 1/27, 1/28, 1/29, 1/30, 1/31, 1/32, 1/57, 1/58, 1/59, 1/60, 1/61, 1/62, 1/63, 1/64']}]
    """

    if 'interface' in kwargs:
        res = get_interface_port_mapping(dut, kwargs['interface'])
        if res:
            res1 = res.strip('port ') + ',' + '|' + res.strip('port ') + " "
            # we need the above code to grep the required port number from the output, for eg - show interface breakout resources | grep "1/61,|1/61 ".
            output = st.show(dut, "show interface breakout resources | grep \"{}\"".format(res1), type='klish')
        else:
            return False
    else:
        output = st.show(dut, "show interface breakout resources", type='klish')

    entries = filter_and_select(output)

    if entries:
        return entries
    else:
        st.error("show interface breakout resources didn't yield any expected output, please check")
        return False
