
import time
from spytest import st
from spytest.utils import filter_and_select
from apis.common import redis
from utilities.utils import get_interface_number_from_name

def config_ptp(dut, **kwargs):
    '''

    :param dut:
        :param mode:
        :param delay_mechanism:
        :param network_transport:
        :param source_ip:
        :param domain:
        :param domain_profile:
        :param two_step:
        :param priority1:
        :param priority2:
        :param announce_interval:
        :param announce_timeout:
        :param sync_interval:
        :param delay_request_min_interval:
        :param port_list:
    :param master_table_intf_list
    :param master_table_addr_list
    :param config:
        :param conf:
    :return:

    '''

    '''
    sub_cmd: one of following
        mode
            value: boundary-clock / slave-only / master-only / transparent-clock / disable
        delay_mechanism
            value: e2e / p2p
        network_transport
            value: l2 / ipv4 / ipv6
        source_ip
            value: <ip address>
        domain
            value: <0-127>
        domain_profile
            value: default / g8275.1 / g8275.2
        two_step
            value: enable / disable
        priority1
            value: 1-255
        priority2
            value: 1-255
        announce_interval
            value: 1-255
        announce_timeout
            value: 1-255
        sync_interval
            value: 1-255
        delay_request_min_interval
            value: 1-255
        port_list
            value: list of ports to add/del
        config:
            value: add/del, default is add
        conf
            value: True/False
    '''

    conf = kwargs.pop('conf',True)
    skip_error_check = kwargs.pop('conf',False)
    st.log('{} - config_ptp - {}'.format(dut, kwargs))

    cmd = ''
    if kwargs.get('mode'):
        cmd += '\n  ptp mode {}'.format(kwargs['mode'])
    if kwargs.get('domain'):
        cmd += '\n  ptp domain {}'.format(kwargs['domain'])
    if kwargs.get('domain_profile'):
        cmd += '\n  ptp domain-profile {}'.format(kwargs['domain_profile'])
    if kwargs.get('network_transport'):
        cmd += '\n  ptp network-transport {}'.format(kwargs['network_transport'])
    if kwargs.get('delay_mechanism'):
        cmd += '\n  ptp delay-mechanism {}'.format(kwargs['delay_mechanism'])
    if kwargs.get('source_ip'):
        cmd += '\n  ptp source-ip {}'.format(kwargs['source_ip'])
    if kwargs.get('two_step'):
        cmd += '\n  ptp two-step {}'.format(kwargs['two_step'])
    if kwargs.get('priority1'):
        cmd += '\n  ptp priority1 {}'.format(kwargs['priority1'])
    if kwargs.get('priority2'):
        cmd += '\n  ptp priority2 {}'.format(kwargs['priority2'])
    if kwargs.get('announce_interval'):
        cmd += '\n  ptp announce-interval {}'.format(kwargs['announce_interval'])
    if kwargs.get('announce_timeout'):
        cmd += '\n  ptp announce-timeout {}'.format(kwargs['announce_timeout'])
    if kwargs.get('sync_interval'):
        cmd += '\n  ptp sync-interval {}'.format(kwargs['sync_interval'])
    if kwargs.get('delay_request_min_interval'):
        cmd += '\n  ptp delay-request-min-interval {}'.format(kwargs['delay_request_min_interval'])
    if kwargs.get('port_list'):
        action = kwargs.get('config','add')
        skip_error_check = True if action != 'add' else False
        for port in kwargs['port_list']:
            port_k = get_interface_number_from_name(port)
            cmd += '\n  ptp port {} {} {}'.format(action, port_k['type'], port_k['number'])

    if cmd:
        st.config(dut,cmd,type='klish',conf=conf,skip_error_check=skip_error_check)
        cmd_executed = 1

    if  kwargs.get('master_table_intf_list') and kwargs.get('master_table_addr_list'):
        cmd = ''
        action = kwargs.get('config','add')
        skip_error_check = True if action != 'add' else False
        st.wait(3)

        for intf,addr in zip(kwargs['master_table_intf_list'], kwargs['master_table_addr_list']):
            port_k = get_interface_number_from_name(intf)
            cmd += '\n ptp port master-table {} {} {} {}'.format(port_k['type'], port_k['number'], action, addr)

        if cmd:
            st.config(dut,cmd,type='klish',conf=conf,skip_error_check=skip_error_check)
            return True

    if cmd_executed:
        return True
    else:
        return False


def verify_ptp(dut, **kwargs):
    '''

    :param dut:
        :param port_list:
        :param mode_list:

    '''

    st.log('{} - verify_ptp - {}'.format(dut, kwargs))
    kwargs.pop('conf',True)

    num_args = len(kwargs['port_list'])
    cmd_output = st.show(dut,'show ptp',type='klish')

    if num_args == 0:
        st.log('Provide at least one parameter to verify')
        return True

    for port,mode in zip(kwargs['port_list'], kwargs['mode_list']):
        if not filter_and_select(cmd_output,None,{'port': port, 'mode': mode}):
            st.error('{} - State not matching for port {}: Expected: {}'.format(dut, port, mode))
        else:
            num_args -= 1

    return True if num_args == 0 else False


def verify_ptp_clock(dut, **kwargs):
    '''

    :param dut:
    :param mode:
        :param domain_profile:
        :param domain_number:
    :param clock_id:
        :param priority1:
        :param priority2:
        :param two_step:
        :param slave_onl:y
        :param number_ports:
        :param clock_class:
        :param clock_accuracy:
        :param ofst_log_var:
    :param mean_path_delay:

    '''

    st.log('{} - verify_ptp_clock - {}'.format(dut, kwargs))
    kwargs.pop('conf',True)

    num_args = len(kwargs)
    cmd_output = st.show(dut,'show ptp clock',type='klish')

    if num_args == 0:
        st.log('Provide at least one parameter to verify')
        return True

    for kv in kwargs.items():
        if not filter_and_select(cmd_output,None,{kv[0]: kv[1]}):
            st.error('{} is not matching on {}'.format(kv[0], dut))
        else:
            num_args -= 1

    return True if num_args == 0 else False


def verify_ptp_time_property(dut, **kwargs):
    '''

    :param dut:
        :param cur_utc_offset_valid:
        :param cur_utc_offset:
        :param leap59:
        :param leap61:
        :param time_traceable:
        :param freq_traceable:
        :param ptp_timescale:

    '''

    st.log('verify_ptp_time_property - {}'.format(kwargs))
    kwargs.pop('conf',True)

    num_args = len(kwargs)
    cmd_output = st.show(dut,'show ptp time-property',type='klish')

    if num_args == 0:
        st.log('Provide at least one parameter to verify')
        return True

    for kv in kwargs.items():
        if not filter_and_select(cmd_output,None,{kv[0]: kv[1]}):
            st.error('{} is not matching'.format(kv[0]))
        else:
            num_args -= 1

    return True if num_args == 0 else False


def verify_ptp_parent(dut, **kwargs):
    '''

    :param dut:
        :param parent_clock_id:
        :param port_number:
        :param gm_clock_class:
        :param gm_off_scale_log_var:
        :param gm_clock_accuracy:
        :param gm_id:
        :param gm_priority1:
        :param gm_priority2:
        :param stats_valid:
        :param observed_off_scale_log_var:
        :param observed_clock_phase_change_rate:


    '''
    st.log('{} - verify_ptp_parent - {}'.format(dut, kwargs))
    kwargs.pop('conf',True)

    num_args = len(kwargs)
    cmd_output = st.show(dut,'show ptp parent',type='klish')

    if num_args == 0:
        st.log('Provide at least one parameter to verify')
        return True

    for kv in kwargs.items():
        if not filter_and_select(cmd_output,None,{kv[0]: kv[1]}):
            st.error('{} is not matching on {}'.format(kv[0], dut))
        else:
            num_args -= 1

    return True if num_args == 0 else False


def verify_ptp_port_found(dut, **kwargs):
    '''

    :param dut:
        :param port:

    '''

    st.log('verify_ptp_port_found - {}'.format(kwargs))

    kwargs.pop('conf', True)

    if kwargs.get('port'):
        port = kwargs.pop('port')
    else:
        st.error('Mandatory parameter port is missing')
        return False

    port_k = get_interface_number_from_name(port)
    cmd_output = st.show(dut, 'show ptp port {} {}'.format(port_k['type'], port_k['number']), type='klish')

    if cmd_output:
        return True
    else:
        return False


def verify_ptp_port(dut, **kwargs):
    '''

    :param dut:
        :param log_sync_interval:
        :param delay_mechanism:
        :param port_state:
        :param peer_mean_path_delay:
        :param port_number:
        :param version_number:
        :param log_announce_interval:
        :param log_min_pdelay_req_interval:

    '''

    st.log('verify_ptp_port - {}'.format(kwargs))
    kwargs.pop('conf',True)

    if kwargs.get('port'):
        port = kwargs.pop('port')
    else:
        st.error('Mandatory parameter port is missing')
        return False

    num_args = len(kwargs)

    port_k = get_interface_number_from_name(port)
    cmd_output = st.show(dut, 'show ptp port {} {}'.format(port_k['type'], port_k['number']), type='klish')

    if num_args == 0:
        st.log('Provide at least one parameter to verify')
        return True
    for kv in kwargs.items():
        if not filter_and_select(cmd_output,None,{kv[0]: kv[1]}):
            st.error('{} is not matching {}'.format(kv[0], kv[1]))
        else:
            num_args -= 1

    return True if num_args == 0 else False


def config_port(dut, **kwargs):
    """
    Author:prasanth.kunjumveettil@broadcom.com
    :param dut:
    :type ptp:


    usage:

    ptp.config_port(dut1, port=dut2_ports[0], profile=default, mode=bc)

   """
    result = False

    result = st.cli_config(dut, "ptp port add Ethernet {}".format(kwargs['port'].strip("Ethernet")), "mgmt-config")

    return result


def verify_hw_ts_cap(dut, **kwargs):
    """
    API to verify HW timestamping capability of PTP ports
    :param dut:
    :param kwargs:
    :return:
    """

    result = False

    if 'port' in kwargs:
        output = st.config(dut, "sudo ethtool -T {} | grep 'PTP Hardware Clock'".format(kwargs['port']))
    else:
        st.log("Mandatory parameter port not passed")
        return result

    if 'none' not in output:
        result = True

    return result

def verify_ptp_debug(dut, **kwargs):
    """
    API to verify  PTP logs works.
    :param dut:
    :param kwargs:
    :return:
    """

    result = False

    output = st.config(dut, "swssloglevel -c PTP -l INFO")
    output = st.config(dut, "sonic-clear logging")
    output = st.config(dut, "swssloglevel -p | grep PTP")
    if 'INFO' in output:
        st.cli_config(dut, "ptp mode boundary-clock", "mgmt-config")
        st.cli_config(dut, "ptp domain-profile default", "mgmt-config")
        st.cli_config(dut, "ptp port add Ethernet 0", "mgmt-config")
        st.cli_config(dut, "ptp port add Ethernet 4", "mgmt-config")
        output = st.config(dut, "show logging ptp4l | grep -e INFO -e NOTICE")
        if 'INFO swss#ptp4l' not in output:
            st.log("No ptp4l INFO log detected")
        else:
            if 'NOTICE swss#ptp4l' in output:
                output = st.config(dut, "swssloglevel -c PTP -l NOTICE")
                output = st.config(dut, "sonic-clear logging")
                output = st.config(dut, "swssloglevel -p | grep PTP")
                st.cli_config(dut, "ptp port del Ethernet 0", "mgmt-config")
                st.cli_config(dut, "ptp port del Ethernet 4", "mgmt-config")
                st.cli_config(dut, "ptp mode disable", "mgmt-config")
                output = st.config(dut, "show logging ptp4l -l 50 | grep INFO")
                if 'INFO swss#ptp4l' not in output:
                    result = True
                else:
                    st.log("ptp4l INFO log detected when logevel set is NOTICE")
            else:
                st.log("ptp4l NOTICE log not detected")
    else:
        st.log("loglevel change command failed")

    return result


def verify_ptp_init(dut, **kwargs):
    """
    API to verify PTP initialization
    :param dut:
    :param kwargs:
    :return:
    """
    result = False
    output = st.config(dut, "bcmcmd mcss | grep KNETSYNC")
    if 'KNETSYNC' in output:
        output = st.config(dut, "lsmod | grep linux_bcm_ptp")
        if 'linux_bcm_ptp' not in output:
            output = st.config(dut, "insmod /lib/modules/4.9.0-9-2-amd64/extra/linux-bcm-ptp-clock.ko debug=0x0 network_transport=4 fw_core=0")
        # Check PTP clock  driver is loaded
        output = st.config(dut, "lsmod | grep linux_bcm_ptp")
        if 'linux_bcm_ptp' in output:
            # Check for PTP devices
            output = st.config(dut, "ls -l /dev/ptp*")
            if 'No such file'  not in output:
                result = True
            else:
                st.log("/dev/ptp device is not present")
        else:
            st.log("PTP clock driver is not loaded")
    else:
        st.log("KNETSync FW is not loaded")
    return result

def verify_ptp_port_count(dut, **kwargs):
    """
    API to verify PTP port count
    :param dut:
    :param kwargs:
    :return:
    """

    result = False
    st.cli_config(dut, "ptp mode boundary-clock", "mgmt-config")
    time.sleep(10)
    if 'count' in kwargs:
        output = st.cli_config(dut, "show ptp clock", "mgmt-user")
        if 'Number Ports          {}'.format(kwargs['count']) in output:
            result = True
    else:
        st.log("Mandatory parameter count not passed")
    return result

def verify_ptp_db_entry(dut, db, key, **kwargs):
    """
    API to verify DB entries.
    :param dut:
    :param kwargs:
    :return:
    """
    if db == "CONFIG_DB":
        command = redis.build(dut, redis.CONFIG_DB, "hgetall '{}'".format(key))
    elif (db == "APP_DB"):
        command = redis.build(dut, redis.APPL_DB, "hgetall '{}'".format(key))
    elif (db == "STATE_DB"):
        command = redis.build(dut, redis.STATE_DB, "hgetall '{}'".format(key))
    else:
        st.log("Not supported for {}".format(db))
        return False

    st.debug(command)
    output = st.show(dut, command)
    st.debug(output)
    for each in kwargs.keys():
        match = {'donor_intf': kwargs[each]}
        entries = filter_and_select(output, None, match)
        if not entries:
            st.log("{} and {} did not match in {} in DUT {}".format(each, kwargs[each], db, dut))
            return False
    return True

def verify_ptp_knet_stats(dut, **kwargs):
    """
    API to verify DB entries.
    :param dut:
    :param kwargs:
    :return:
    """
    command = "sudo cat /proc/bcm/ksync/stats"
    output = st.config(dut, command)
    for each in kwargs.keys():
        match = {each: kwargs[each]}
        entries = filter_and_select(output, None, match)
        if not entries:
            st.log("{} and {} did not match in DUT {}".format(each, kwargs[each], dut))
            return False
    return True
