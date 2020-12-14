from spytest import st
import re
import time

def config_pim_global_mgmt (dut, vrf, **kwargs):
    """
    Example invocation:

    # config_pim_global_mgmt(data.dut1, 'Vrf_pim3', config='yes', **cmd_dict)

    Apply pim configuration commands for the specified VRF.

    Inputs and keyword parameters:

    :param dut: Device under test
    :param vrf: name of the VRF for which configuration is to be applied
    :param config: bool value: True to apply configuration; False to remove it
    :param jp_interval: string specifying the jp interval value
    :param keepalive_time: string specifying the keepalive timer value
    :param ecmp: set to 'ecmp' to enable ecmp
    :param ecmp_rebalance: set to 'ecmp rebalance' to enable ecmp rebalance
    :param ssm_range_prefix: name of an SSM range prefix list
    :return: Output from configuration command execution
    """
    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = 'yes'

    if config.lower() == 'yes':
        no_str = ""
    else:
        no_str = 'no '

    if vrf == 'default':
        vrf_str = ""
    else:
        vrf_str = 'vrf ' + vrf

    maxtime = kwargs['maxtime'] if 'maxtime' in kwargs else 0

    cmd_batch = ""
    val_str = ""
    if 'jp_interval' in kwargs:
        if no_str == "":
            val_str = kwargs['jp_interval']
        cmd_batch += (no_str + 'ip pim ' + vrf_str + ' join-prune-interval ' +
                      val_str + '\n')

    if 'keepalive_time' in kwargs:
        if no_str == "":
            val_str = kwargs['keepalive_time']
        cmd_batch += (no_str + 'ip pim ' + vrf_str + ' keep-alive-timer ' +
                      val_str + '\n')

    if no_str == 'no ':
        # Execute the "no" form of "ecmp rebalance" before possible executing
        # the "no" form of "ecmp".
        if 'ecmp_rebalance' in kwargs:
            cmd_batch += no_str + 'ip pim ' + vrf_str + ' ecmp rebalance \n'
        if 'ecmp' in kwargs:
            cmd_batch += no_str + 'ip pim ' + vrf_str + ' ecmp \n'
    else:
        if 'ecmp' in kwargs:
            cmd_batch += no_str + 'ip pim ' + vrf_str + ' ecmp \n'
        if 'ecmp_rebalance' in kwargs:
            cmd_batch += no_str + 'ip pim ' + vrf_str + ' ecmp rebalance \n'

    if 'ssm_range_prefix' in kwargs:
        if no_str == "":
            val_str = kwargs['ssm_range_prefix']
        cmd_batch += (no_str + 'ip pim ' + vrf_str + ' ssm prefix-list ' +
                      val_str + '\n')

    skip_error = bool(kwargs.get('skip_error', False))
    return st.config(dut, cmd_batch, type='klish',
                     skip_error_check=skip_error, max_time=maxtime)

def config_pim_intf_mgmt(dut, intf, **kwargs):
    """
    Example invocation:

    config_pim_intf_mgmt(data.dut1, intf='Ethernet 4', config='yes', **cmd_dict)

    Apply pim configuration commands for the specified interface.

    Inputs and keyword parameters:

    :param dut: Device under test
    :param intf: Interface or list of interfaces to be configured
    :param config: bool value: True to apply configuration; False to remove it
    :param pim_mode: PIM mode enabled on the interface
    :param dr_priority: string specifying the designated router priority
    :param hello_intvl: string specifying the Hello interval
    :param bfd_enable: (value ignored; enable bfd)
    :return: Output from configuration command execution
    """

    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = 'yes'

    if config.lower() == 'yes':
        no_str = ""
    else:
        no_str = 'no '

    maxtime = kwargs['maxtime'] if 'maxtime' in kwargs else 0

    cmd_batch = ""
    val_str = ""
    skip_error = bool(kwargs.get('skip_error', False))
    cmd_batch += 'interface {}\n'.format(intf)

    if 'pim_mode' in kwargs:
        cmd_batch += '{} ip pim {}\n'.format(no_str, kwargs['pim_mode'])

    if 'hello_intvl' in kwargs:
        if no_str == "":
            val_str = kwargs['hello_intvl']
        cmd_batch += '{} ip pim hello {}\n'.format(no_str, val_str)

    if 'dr_priority' in kwargs:
        if no_str == "":
            val_str = kwargs['dr_priority']
        cmd_batch += '{} ip pim drpriority {}\n'.format(no_str, val_str)

    if 'bfd_enable' in kwargs:
        cmd_batch += '{} ip pim bfd\n'.format(no_str)

    cmd_batch += "exit\n"
    output = st.config(dut, cmd_batch, type='klish',
                       skip_error_check=skip_error,max_time=maxtime)

    return output

def verify_pim_global_mgmt(dut, vrf, output=None, **vrf_parms):
    """

    Verify pim configuration commands for the specified VRF.

    Example invocation:

    verify_pim_global_mgmt(data.dut1, vrf='Vrf_pim3', **cfg_parm_dict)

    Inputs and keyword parameters:

    :param dut: Device under test
    :param vrf: name of the VRF for which configuration is to be verified
    :param output: cached result from previous "show running-configuration"
     command execution
    :param vrf_parms: Dictionary specifying expected configuration
     attributes and values
    :return: output from "show running-configuration" if verification is
     successful. (Otherwise, this return parameter is set to None.)
    """

    if vrf == 'default':
        vrf_str = ""
    else:
        vrf_str = vrf

    if 'skip_error' in vrf_parms:
        skip_error = vrf_parms['skip_error']
    else:
        skip_error = False

    if output is None:
        output = []
        output = st.show(dut, 'show running-config pimd',
                         skip_error_check=skip_error, type='vtysh')
        if ((output is None) or (output == [])):
            st.log("PIM configuration is empty.")
            return None

    # Find the dictionary for the target VRF in the 'show' output
    vrf_found = False
    tgt_vrf_dict = None
    vrf_dict = {}
    for vrf_dict in output:
        if vrf_dict['pim_vrf'] == vrf_str:
            vrf_found = True
            tgt_vrf_dict = vrf_dict
            break
    if not vrf_found:
        st.log("Failed to find PIM global configuration for VRF {} "
               "in configuration output".format(vrf))
        return None

    # Verify the configuration values for the target VRF.
    for cfg_key, cfg_value in vrf_parms.items():
        if ((cfg_key not in tgt_vrf_dict) or
            (tgt_vrf_dict[cfg_key] != cfg_value)):
            st.log("Failed to find {} = {} in configuration "
                   "output".format(cfg_key, cfg_value))
            return None

    return output

def verify_pim_intf_mgmt(dut, intf, output=None, **intf_parms):
    """

    Verify pim configuration commands for the specified interface.

    Example invocation:

    verify_pim_intf_mgmt(data.dut1, intf='Ethernet 4', **cfg_parm_dict)

    Inputs and keyword parameters:

    :param dut: Device under test
    :param intf: name of the interface for which configuration is to be verified
    :param output: cached result from previous "show running-configuration"
     command execution
    :parm intf_parms: Dictionary specifying expected configuration
     attributes and values
    :return: bool set to True if all expected configuration is present
    """

    intf_nospc = re.sub(r"(PortChannel|Ethernet|Management) (\d+)", "\\1\\2",
                        intf)

    if 'skip_error' in intf_parms:
        skip_error = intf_parms['skip_error']
    else:
        skip_error = False

    if output is None:
        output = []
        output = st.show(dut, 'show running-config pimd',
                         skip_error_check=skip_error, type='vtysh')
        if ((output is None) or (output == [])):
            st.log("PIM configuration is empty.")
            return None

    # Find the dictionary for the target interface in the 'show' output
    intf_found = False
    tgt_intf_dict = None
    intf_dict = {}
    for intf_dict in output:
        if intf_dict['interface'] == intf_nospc:
            intf_found = True
            tgt_intf_dict = intf_dict
            break
    if not intf_found:
        st.log("Failed to find PIM interface configuration for interface {} "
               "in configuration output".format(intf))
        return None

    # Verify the configuration values for the target interface.
    for cfg_key, cfg_value in intf_parms.items():
        if ((cfg_key not in tgt_intf_dict) or
            (tgt_intf_dict[cfg_key] != cfg_value)):
            st.log("Failed to find {} = {} in configuration "
                   "output".format(cfg_key, cfg_value))
            return None

    return output

def pim_execute_bgp_restart(dut):
    """
    :param dut: Device under test
    :return: bool indication set to True if successful
    """

    cmd = "service bgp restart"
    try:
        output = st.show(dut, cmd, exec_mode='root-user', skip_tmpl=True)
        if output is None:
            st.log("Empty output executing 'service bgp restart.")
            return False

        if re.search("%Error", output):
            st.log("Failure executing 'service bgp restart: "
                   "Error message: " + output)
            return False
        else:
            st.log("Succeeded executing 'service bgp restart'")

    except ValueError as err_msg:
        st.log("Exception executing 'service bgp restart': "
               "Error message: " + str(err_msg))
        return False

    st.log("Waiting for 'system ready' after BGP restart")
    ready = False
    retries_remaining = 10
    while ((not ready) and (retries_remaining > 0)):
        time.sleep(10)
        output = st.show(dut, "show system status", exec_mode='root-user',
                         skip_tmpl=True)
        if (re.search("System is ready", output)):
            ready = True
            break

        retries_remaining -= 1

    if not ready:
        st.log("Timed out waiting for System Ready after BGP restart")
        return False

    st.log("System ready after BGP restart.")
    return True

