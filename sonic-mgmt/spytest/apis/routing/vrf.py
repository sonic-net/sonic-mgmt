import re
from spytest import st, utils
from spytest.utils import filter_and_select

def verify_vrf(dut,**kwargs):
    st.log("verify show vrf output")
    """
    verify_vrf(dut1,vrfname="Vrf-103")
    """
    cmd = "show vrf"
    output = st.show(dut,cmd)
    if 'vrfname' in kwargs:
        if not isinstance(kwargs['vrfname'],list):
            vname_list = [kwargs['vrfname']]
        else:
            vname_list = kwargs['vrfname']
    else:
        st.log("Mandatory parameter vrfname is not found")
        return False
    for vname in vname_list:
        match = {"vrfname":vname}
        entries = filter_and_select(output, ["vrfname"], match)
        if not bool(entries):
            return bool(entries)
    return True

def verify_vrf_verbose(dut,vrfname,interface):
    st.log("verify show vrf --verbose output")
    """
    verify_vrf_verbose(dut1,vrfname="Vrf-103",interface='Ethernet2')
    """
    cmd = "show vrf --verbose"
    output = st.show(dut,cmd)
    if not isinstance(vrfname,list):
        vrfname = [vrfname]
    for vname,intf in zip(vrfname,interface):
        match = {"vrfname":vname,"interfaces": intf}
        entries = filter_and_select(output,["vrfname"],match)
        print("entries")
        if not bool(entries):
            return bool(entries)
    return True


def get_vrf_verbose(dut, **kwargs):
    st.log("get show vrf --verbose output")
    """
    get_vrf_verbose(dut1,vrfname="Vrf-1")
    """
    cmd = "show vrf --verbose"
    output = st.show(dut, cmd)
    if len(output) == 0:
        st.error("OUTPUT is Empty")
        return []
    match_dict = {}
    if 'vrfname' in kwargs:
        match_dict['vrfname'] = kwargs['vrfname']
    else:
        st.error("Mandatory parameter peeraddress is not found")
        return False
    entries = filter_and_select(output, None, match_dict)
    return entries[0]

def config_vrf(dut, **kwargs):
    """
    #Sonic cmd: Config vrf <add | delete> <VRF-name>
    eg: config_vrf(dut = dut1, vrf_name = 'Vrf-test', config = 'yes')
    eg: config_vrf(dut = dut1, vrf_name = 'Vrf-test', config = 'no')
    """
    st.log('Config VRF API')
    if kwargs.has_key('config'):
        config = kwargs['config']
    else:
        config = 'yes'
    if 'vrf_name' in kwargs:
        if not isinstance(kwargs['vrf_name'],list):
            vrf_name = [kwargs['vrf_name']]
        else:
            vrf_name = kwargs['vrf_name']
    else:
        st.log("Mandatory parameter vrfname is not found")
    if kwargs.has_key('skip_error'):
        skip_error = kwargs['skip_error']
    else:
        skip_error = False
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut))
    if cli_type == 'click':
        my_cmd = ''
        if config.lower() == 'yes':
            for vrf in vrf_name:
                my_cmd += 'sudo config vrf add {}\n'.format(vrf)
        else:
            for vrf in vrf_name:
                my_cmd += 'sudo config vrf del {}\n'.format(vrf)
        if skip_error:
            try:
                out = st.config(dut, my_cmd)
                return True
            except:
                st.log("Error handled..by API")
                return False
        else:
            out = st.config(dut, my_cmd)
            return True
    elif cli_type == 'klish':
        command = ''
        if config.lower() == 'yes':
            for vrf in vrf_name:
                command = command + "\n" + "ip vrf {}".format(vrf)
        else:
            for vrf in vrf_name:
                command = command + "\n" + "no ip vrf {}".format(vrf)
        output = st.config(dut, command, skip_error_check=skip_error, type="klish", conf=True)
        if "Could not connect to Management REST Server" in output:
            st.error("klish mode not working.")
            return False
        return True


def bind_vrf_interface(dut, **kwargs):
    """
    #Sonic cmd: Config interface <bind |unbind> <interface-name> <vrf-name>
    eg: bind_vrf_interface(dut = dut1, vrf_name = 'Vrf-test', intf_name ='Ethernet8', config = 'no')
    """
    st.log('API to bind interface to VRF')
    if kwargs.has_key('config'):
        config = kwargs['config']
    else:
        config = 'yes'
    if 'vrf_name' in kwargs:
        if not isinstance(kwargs['vrf_name'],list):
            vrf_name = [kwargs['vrf_name']]
        else:
            vrf_name = kwargs['vrf_name']
    else:
        st.log("Mandatory parameter vrfname is not found")
    if 'intf_name' in kwargs:
        if not isinstance(kwargs['intf_name'],list):
            intf_name = [kwargs['intf_name']]
        else:
            intf_name = kwargs['intf_name']
    else:
        st.log("Mandatory parameter intf_name is not found")
    if kwargs.has_key('skip_error'):
        skip_error = kwargs['skip_error']
    else:
        skip_error = False

    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut))
    if cli_type == 'click':
        my_cmd = ''
        if config.lower() == 'yes':
            for vrf,intf in zip(vrf_name,intf_name):
                if 'Loopback' in intf:
                    my_cmd += 'sudo config loopback add {}\n'.format(intf)
                    my_cmd += 'sudo config interface vrf bind {} {}\n'.format(intf, vrf)
                else:
                    my_cmd += 'sudo config interface vrf bind {} {}\n'.format(intf, vrf)
        else:
            for vrf,intf in zip(vrf_name,intf_name):
                if 'Loopback' in intf:
                    my_cmd += 'sudo config interface vrf unbind {} {}\n'.format(intf, vrf)
                    my_cmd += 'sudo config loopback del {}\n'.format(intf)
                else:
                    my_cmd += 'config interface vrf unbind {} {}\n'.format(intf, vrf)
        if skip_error:
                out = st.config(dut, my_cmd, skip_error_check=True)
                return True
        else:
            out = st.config(dut, my_cmd)
            return True
    elif cli_type == 'klish':
        regex = re.compile(r'(\d+|\s+)')
        command = ''
        if config.lower() == 'yes':
            for vrf,intf in zip(vrf_name,intf_name):
                intfv = regex.split(intf)
                command = command + "\n" + "interface {} {}".format(intfv[0], intfv[1])
                command = command + "\n" + "ip vrf forwarding {}".format(vrf)
                command = command + "\n" + "exit"
        else:
            for vrf,intf in zip(vrf_name,intf_name):
                intfv = regex.split(intf)
                command = command + "\n" + "interface {} {}".format(intfv[0], intfv[1])
                command = command + "\n" + "no ip vrf forwarding {}".format(vrf)
                command = command + "\n" + "exit"
                if 'Loopback' in intf:
                    command = command + "\n" + "no interface {} {}".format(intfv[0], intfv[1])
        output = st.config(dut, command, skip_error_check=skip_error, type="klish", conf=True)
        if "Could not connect to Management REST Server" in output:
            st.error("klish mode not working.")
            return False
        return True




def config_vrfs(dut, vrf_data_list={}, config='yes'):

    if config == 'yes' or config == 'add':
        config = 'add'
    elif config == 'no' or config == 'del':
        config = 'del'
    else :
        st.error("Invalid config type {}".format(config))
        return False

    command = []
    for vrf_name, vrf_data in vrf_data_list.items():
        vrf = vrf_data['name']
        cmd_str = "sudo config vrf {} {} ".format(config, vrf)
        command.append(cmd_str)

    try:
        st.config(dut, command)
    except Exception as e:
        st.log(e)
        return False

    return True


def _clear_vrf_config_helper(dut_list):
    """
    Helper routine to cleanup VRF config from devices.
    """
    dut_li = list(dut_list) if isinstance(dut_list, list) else [dut_list]
    for dut in dut_li:
        st.log("############## {} : VRF Config Cleanup ################".format(dut))
        output = st.show(dut, "show vrf")
        st.log("##### VRF : {}".format(output))
        if len(output) == 0:
            continue

        for entry in output:
            if not entry['vrfname']:
                continue

            vrfname = entry['vrfname']
            if type(entry['interfaces']) is list:
                for intf in entry['interfaces']:
                    bind_vrf_interface(dut, vrf_name=vrfname, intf_name=intf, config='no')

            config_vrf(dut, vrf_name=vrfname, config='no')

    return True


def clear_vrf_configuration(dut_list, thread=True):
    """
    Find and cleanup all VRF configuration.

    :param dut_list
    :return:
    """
    dut_li = list(dut_list) if isinstance(dut_list, list) else [dut_list]
    [out, exceptions] = utils.exec_foreach(thread, dut_li, _clear_vrf_config_helper)
    st.log(exceptions)
    return False if False in out else True

