import re
from spytest import st
from utilities.utils import get_interface_number_from_name, retry_api
from utilities.common import filter_and_select, make_list
from apis.system import basic
from apis.system.port_rest import process_intf_status_rest_output
from apis.system.port_rest import process_intf_counters_rest_output
from apis.system.rest import config_rest, delete_rest ,get_rest

def _has_intf_range(dut):
    if not st.is_feature_supported("intf-range", dut):
        return False
    return True

def set_status(dut, portlist, status, cli_type=''):
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
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    if cli_type == "click":
        if '-' in portlist:
            st.config(dut, "config interface {} {}".format(status, portlist))
            return

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
        if portlist:
            for intf in make_list(portlist):
                intf_details = get_interface_number_from_name(intf)
                if not intf_details:
                    st.error("Interface data not found for {} ".format(intf))
                else:
                    commands.append("interface {} {}".format(intf_details["type"], intf_details["number"]))
                    command = "shutdown" if status == "shutdown" else "no shutdown"
                    commands.append(command)
                    commands.append("exit")
        if commands:
            st.config(dut, commands, type=cli_type)
            return True
        return False
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        oper = False if status == 'shutdown' else True
        portlist = make_list(portlist)
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

def shutdown(dut, portlist, cli_type=''):
    """
    :param dut:
    :type dut:
    :param portlist:
    :type portlist:
    :return:
    :rtype:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    set_status(dut, portlist, "shutdown", cli_type=cli_type)

def noshutdown(dut, portlist, cli_type=''):
    """
    :param dut:
    :type dut:
    :param portlist:
    :type portlist:
    :return:
    :rtype:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    set_status(dut, portlist, "startup", cli_type=cli_type)

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
            command += " | grep \"{}\"".format("|".join(interface))
        return st.show(dut, command, type=cli_type)
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        result = []
        if port:
            ports = port.split(",")
            for port2 in ports:
                url = rest_urls['per_interface_details'].format(port2)
                output = get_rest(dut, rest_url = url, timeout=60)
                processed_output = process_intf_status_rest_output(output)
                if processed_output:
                    result.extend(processed_output)
                st.log("REST output is: {}".format(output))
        else:
            url = rest_urls['all_interfaces_details']
            output = get_rest(dut, rest_url = url, timeout=60)
            processed_output = process_intf_status_rest_output(output)
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


def verify_oper_state(dut, port, state, cli_type=''):
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
    if get_interface_status(dut, port, cli_type=cli_type)!= state:
        return False
    return True

def get_interface_counters_all(dut, port=None, cli_type=''):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    if cli_type == 'click':
        # To avoid traffic rate inaccuracy, run and ignore first show command in click & use second one
        st.show(dut, "show interfaces counters -a", type=cli_type)
        if port:
            command = "show interfaces counters -a -i {}".format(port)
            if not st.is_feature_supported("show-interfaces-counters-interface-command", dut):
                st.community_unsupported(command, dut)
                command = "show interfaces counters -a | grep -w {}".format(port)
            return st.show(dut, command)
        else:
            return st.show(dut, "show interfaces counters -a", type=cli_type)
    elif cli_type == 'klish':
        if port:
            cmd = "show interface counters rate | grep \"{} \"".format(port)
        else:
            cmd = "show interface counters rate"
        cmd_op = st.show(dut, cmd, type=cli_type)
        for i in range(0,len(cmd_op)):
            # Creating rx_bps and tx_bps for legacy script.
            # Click doesnt have mpbs data
            cmd_op[i]['rx_bps'] = cmd_op[i]['rx_mbps']
            cmd_op[i]['tx_bps'] = cmd_op[i]['tx_mbps']
        return cmd_op
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        result = []
        url = rest_urls['all_interfaces_details']
        output = get_rest(dut, rest_url = url, timeout=60)
        processed_output = process_intf_counters_rest_output(output)
        if processed_output:
            result.extend(processed_output)
        return result
    else:
        st.log("Unsupported CLI TYPE {}".format(cli_type))
        return False


def clear_interface_counters(dut, **kwargs):
    cli_type = st.get_ui_type(dut, **kwargs)
    interface_name = kwargs.get("interface_name", "")
    interface_type = kwargs.get("interface_type", "all")
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
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut,**kwargs))
    output = get_interface_counters_all(dut, port=port, cli_type=cli_type)
    entries = filter_and_select(output, counter, {'iface': port})
    return entries


# data = ["Ethernet0", "4x10", "Etherne40", "4x10"]
def breakout(dut, data, undo=False, brk_verify=True, cli_type="", skip_error=False):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    platform_check=False
    cmds = []
    cmds_1 =[]

    dut_type=basic.get_hwsku(dut)
    if dut_type:
        if "9716" in dut_type or "IX9" in dut_type:
            platform_check=True

    data_port = list(data)
    if cli_type == "klish":
        for x in range(0,len(data_port),2):
            res1 = get_interface_breakout_mode(dut, data_port[x], 'port')
            if res1:
                data_port[x] = 'port ' + res1[0]['port']
            else:
                st.error('Invalid interface, cannot breakout')
                return False

        for index in range(0, len(data_port), 2):
            intf, opt = data_port[index].strip(), data_port[index+1].strip()
            if not opt.endswith("G"): opt = "{}G".format(opt)
            if intf in ['port 1/31','port 1/32'] and platform_check:
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
                    cmds.append("no interface breakout {}".format(intf))
                else:
                    cmds.append("interface breakout {} mode {}".format(intf, opt))
    elif cli_type == "click":
        for index in range(0, len(data), 2):
            intf, opt = data[index].strip(), data[index+1].strip()
            if not opt.endswith("G"): opt = "{}G".format(opt)
            if intf in ['Ethernet240','Ethernet248'] and platform_check:
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
        st.config(dut, cmds_1, type='click', skip_error_check=skip_error)

    try:
        st.config(dut, cmds, type=cli_type, skip_error_check=skip_error)
    except Exception as e:
        st.log(e)

    if brk_verify and cli_type == "klish" and not undo:
        for index in range(0, len(data), 2):
            intf, opt = data_port[index].strip(), data_port[index+1].strip()
            if not opt.endswith("G"): opt = "{}G".format(opt)
            intf = "Ethernet".join(intf.split("Ethernet"))
            if retry_api(verify_dpb_status,dut,interface=intf,status='Completed',breakout_mode=opt,retry_count=12, delay=5):
                st.log("Breakout of {} to speed {} is successful".format(intf,opt))
            else:
                st.error("Breakout is not successful for {} of speed {}, even after 60 seconds".format(intf,opt))
                return False

    return True

# data = ["Ethernet0", 10000, "Etherne40", 40000]
def set_speed(dut, data, cli_type=""):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    cli_type = 'klish' if cli_type in ['rest-patch', 'rest-put'] else cli_type
    platform = basic.get_hwsku(dut)
    ports_per_pg = 12 if platform in ["Accton-AS7326-56X"] else 4
    non_portgroup_platforms = ["Accton-AS7712-32X","Quanta-IX8A-BWDE-56X","AS5835-54X"]

    if not st.is_feature_supported("port-group", dut):
        non_portgroup_platforms.append(platform)

    ports_dict = dict()
    port_name_dict = dict()
    for index in range(0, len(data), 2):
        port = st.get_other_names(dut, [data[index]])[0] if "/" in data[index] else data[index]
        port_name_dict[port] = data[index+1]
        id = re.search(r"\d+", port).group(0)
        id = (int(int(id)/ports_per_pg))+1
        ports_dict[str(id)] = data[index+1]
    st.debug("port-group speed data: {}".format(ports_dict))
    commands = list()
    if cli_type == 'click':
        if platform not in non_portgroup_platforms:
            commands = ["config portgroup speed {} {}".format(index, speed) for index, speed in ports_dict.items()]
        else:
            commands = ["portconfig -p {} -s {}".format(port, speed) for port, speed in port_name_dict.items()]
    elif cli_type == 'klish':
        if platform not in non_portgroup_platforms:
            commands = ["port-group {} speed {}".format(index, speed) for index, speed in ports_dict.items()]
        else:
            for port, speed in port_name_dict.items():
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
        st.config(dut, commands, type=cli_type)
    return True


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

    config = kwargs.get('config','yes')
    cli_type = kwargs.pop('cli_type',st.get_ui_type(dut,**kwargs))

    if 'portlist' not in kwargs:
        st.error("Mandatory arg portlist is not present")
        return False
    elif type(kwargs['portlist']) is not list:
        kwargs['portlist'] = [kwargs['portlist']]


    if 'speed' in kwargs:
        speed = kwargs['speed']

    skip_error = kwargs.pop('skip_error', False)

    data_port = kwargs['portlist']
    for x in range(len(data_port)):
        res1 = get_interface_breakout_mode(dut, data_port[x], 'port')
        if res1:
            data_port[x] = 'port ' + res1[0]['port']
        else:
            st.error('Invalid interface, cannot breakout')
            return False

    my_cmd = ''

    if cli_type == 'klish':

        if config.lower() == "yes":
            if 'speed' not in kwargs:
                st.error(':Speed parameter is required to breakout a port')
                return False
            else:
                for port in data_port:
                    my_cmd += 'interface breakout {} mode {}G\n'.format(port,speed)
        else:
            for port in data_port:
                my_cmd += 'no interface breakout {}\n'.format(port)

        st.config(dut, my_cmd, type='klish',skip_error_check=skip_error)

    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        ocdata = {}
        if config.lower() == "yes":
            if 'speed' not in kwargs:
                st.error(':Speed parameter is required to breakout a port')
                return False
            else:
                for port in data_port:
                    port=port.replace('/','%2F')
                    port = port.strip('port ')
                    base_url = rest_urls['config_dpb'].format(port)
                    speed= speed.split('x')
                    ocdata['openconfig-platform-port:config'] = {"num-channels" : int(speed[0]), "channel-speed" : "SPEED_{}GB".format(int(speed[1]))}
                    response = config_rest(dut,http_method=cli_type, rest_url=base_url, json_data=ocdata)
                    if not response:
                        return False

        else:
            for port in data_port:
                port=port.replace('/','%2F')
                port = port.strip('port ')
                base_url = rest_urls['config_dpb'].format(port)
                response = delete_rest(dut, rest_url=base_url)
                if not response:
                    return False



def verify_dpb_status(dut,**kwargs):
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

    if 'interface' not in kwargs :
        st.error("Mandatory argument \'interface\' is missing")
        return False

    if 'Eth' in kwargs['interface']:
        st.log('Physical interface name is provided, mapping it to a port group')
        res1 = get_interface_breakout_mode(dut, kwargs['interface'], 'port')
        if res1:
            kwargs['interface'] = 'port ' + res1[0]['port']
        else:
            st.error('Invalid interface, cannot get the status')
            return False


    output = st.show(dut, "show interface breakout {}".format(kwargs['interface']), type='klish')
    if len(output) == 0:
        st.error("OUTPUT is Empty")
        return False

    for each in kwargs.keys():
        if each == 'interface':
            continue
        else:
            match = {each: kwargs[each]}
            entries = filter_and_select(output, None, match)
            if not entries :
                st.error("Match not found for {}:   Expected - {} Actual - {} ".format(each, kwargs[each],output[0][each]))
                return False
    return True

def get_interface_breakout_mode(dut, interface, *fields):

    """
    Author: Naveen Nag
    email : naveen.nagaraju@broadcom.com
    :param dut:
    :param interface:
    :param fields:
    :return: port,interface,supported_modes,default mode

    Usage:
    port.get_interface_breakout_mode(dut1, 'Ethernet4', 'port','supported_modes')
    :return  - [{'supported_modes': '1x100G[40G], 4x25G[10G]', 'port': '1/2'}]

    """
    if '/' not in interface:
        temp_vars = st.get_testbed_vars()
        if temp_vars.config.ifname_type == 'alias':
            interface = st.get_other_names(dut,[interface])[0]
    if '/' in interface:
        interface = '/'.join([interface.split('/')[0], interface.split('/')[1]])
    output = st.show(dut, "show interface breakout modes | grep \"{} \"".format(interface), type='klish')
    entries = filter_and_select(output, fields, {'iface': interface})
    if entries:
        return entries
    else:
        st.error("{} is not part of the output".format(interface))
        return False


def default_interface(dut,**kwargs):
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

    st.config(dut, command, type='klish',skip_error_check=skip_error)
    return True


def get_interface_breakout_param(dut,**kwargs):

    """
    Author: Naveen Nag
    email : naveen.nagaraju@broadcom.com
    :param dut:
    :param interface:
    :param fields:
    :return: interface breakout speed

    Usage:
    port.get_interface_breakout_param(dut1, 'Ethernet4')
    :return  - ['4x10G', 'Completed']

    """
    param_breakout = []
    if 'interface' not in kwargs :
        st.error("Mandatory argument \'interface\' is missing")
        return False

    if 'Eth' in kwargs['interface']:
        st.log('Physical interface name is provided, mapping it to a port group')
        res1 = get_interface_breakout_mode(dut, kwargs['interface'], 'port')
    if res1:
        kwargs['interface'] = 'port ' + res1[0]['port']
    else:
        st.error('Invalid interface, cannot get the status')
        return False

    output = st.show(dut, "show interface breakout {}".format(kwargs['interface']), type='klish')

    if len(output) == 0:
        st.error("Provided interface is not a breakout port")
        return False
    else:
        param_breakout.append(str(output[0]['breakout_mode'].strip('G')))
        param_breakout.append(output[0]['status'])
        return param_breakout


def get_interface_details_by_alt_name(dut, alt_name):
    cli_type= st.get_ui_type(dut)
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
