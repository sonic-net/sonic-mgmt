# This file contains the list of API's which performs config and reboot operation.
# Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
from spytest import st, utils

def config_save(dut,shell='sonic', skip_error_check=True):
    """
    To perform config save.
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param dut: single or list of duts
    :return:
    """
    dut_li = list(dut) if isinstance(dut, list) else [dut]
    st.log("Performing config save")
    if shell == 'sonic':
        command = 'config save -y'
        [retvals, exceps] = utils.exec_foreach(True, dut_li, st.config, command)
    elif shell == "vtysh":
        command = 'do copy running-config startup-config'
        [retvals, exceps] = utils.exec_foreach(True, dut_li, st.config, command, type=shell, skip_error_check=skip_error_check)
    else:
        command = "do write memory"
        [retvals, exceps] = utils.exec_foreach(True, dut_li, st.config, command, type=shell, skip_error_check=skip_error_check)
    st.debug([retvals, exceps])
    return True


def config_reload(dut):
    """
    To perform config reload.
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param dut: single or list of duts
    :return:
    """
    st.log("Performing config reload")
    dut_li = list(dut) if isinstance(dut, list) else [dut]
    [retvals, exceps] = utils.exec_foreach(True, dut_li, st.config_db_reload)
    st.debug([retvals, exceps])
    return True


def config_save_reload(dut):
    """
    To perform config save and reload.
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param dut: single or list of duts
    :return:
    """
    st.log("Performing config save and reload")
    dut_li = list(dut) if isinstance(dut, list) else [dut]
    [retvals, exceps] = utils.exec_foreach(True, dut_li, st.config_db_reload, True)
    st.debug([retvals, exceps])
    return True


def get_reboot_cause(dut):
    """
    To get reboot cause.
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param dut:
    :return:
    """
    command = "show reboot-cause"
    return st.show(dut, command)


def config_warm_restart(dut, **kwargs):
    """
    Config Warm Restart operation state and parameters.
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param dut:
    :param oper: enable | disable
    :param tasks: single task name | list of task name
    :param bgp_timer:
    :param neighsyncd_timer:
    :param teamsyncd_timer:
    :return:

    config_warm_restart,oper="enable")
    config_warm_restart,oper="enable",tasks="bgp")
    config_warm_restart,oper="enable", bgp_timer=120)
    config_warm_restart,oper="enable",tasks="bgp",bgp_timer=120,neighsyncd_timer=60,teamsyncd_timer=60)
    config_warm_restart,oper="enable",tasks=["bgp","system","teamd"], bgp_timer=120,neighsyncd_timer=60,teamsyncd_timer=60)

    """
    if "oper" in kwargs and 'tasks' not in kwargs:
        command = "config warm_restart {}".format(kwargs['oper'])
        st.config(dut, command)
    if "oper" in kwargs  and "tasks" in kwargs:
        task_list = list(kwargs['tasks']) if isinstance(kwargs['tasks'], list) else [kwargs['tasks']]
        for each_task in task_list:
            command = "config warm_restart {} {}".format(kwargs['oper'], each_task)
            st.config(dut, command)
    if "bgp_timer" in kwargs:
        command = "config warm_restart bgp_timer {}".format(kwargs['bgp_timer'])
        st.config(dut, command)
    if "neighsyncd_timer" in kwargs:
        command = "config warm_restart neighsyncd_timer {}".format(kwargs['neighsyncd_timer'])
        st.config(dut, command)
    if "teamsyncd_timer" in kwargs:
        command = "config warm_restart teamsyncd_timer {}".format(kwargs['teamsyncd_timer'])
        st.config(dut, command)
    return True


def verify_warm_restart(dut, **kwargs):
    """
    To verify warm restart state and config
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param dut:
    :param mode: config | state
    :param name:
    :param restore_count:
    :param state:
    :param enable:
    :param timer_name:
    :param timer_duration:
    :return:
    """

    if 'mode' not in kwargs:
        st.error("mode is not passed as argument to API.")
        return False
    if kwargs['mode'] in ['config', 'state']:
        command = "show warm_restart {}".format(kwargs['mode'])
    else:
        st.error("Invalid mode provided, supported - mode or config")
        return False
    del kwargs['mode']
    output = st.show(dut, command, type="click")
    st.debug(output)

    entries = utils.filter_and_select(output, None, kwargs)
    if not entries:
        return False

    return True


def poll_for_warm_restart_status(dut, pname, state, iteration=20, delay=2):
    """
    To verify warm restart state poll.
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param pname:
    :param state:
    :param iteration:
    :param delay:
    :return:
    """
    itercount = 1
    while True:
        if verify_warm_restart(dut, mode='state', name=pname, state=state):
            return True
        if itercount > iteration:
            st.error("For warm restart {}:{} status verification max iteration count {} reached".format(pname, state,
                                                                                                        itercount))
            return False
        itercount += delay
        st.wait(delay)
