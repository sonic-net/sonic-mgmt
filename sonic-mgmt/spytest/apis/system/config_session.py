import re
from spytest import st
from utilities.common import filter_and_select


def verify_config_session_details(dut, **kwargs):
    """
    Author: Naveen Nag
    email : naveen.nagaraju@broadcom.com
    :param dut:
    :return:

    Usage:
     session_api.verify_config_session_details(dut1)
    """
    st.banner("verify config session details")
    return_output = kwargs.get("return_output", False)
    output = st.show(dut, "show config session details", type='klish', skip_error_check="True")
    if return_output:
        if len(output) != 0:
            return output[0]
        else:
            st.error('No config session is present')
            return False


def verify_config_checkpoints(dut, **kwargs):
    """
    Author: Ramprakash Reddy(ramprakash-reddy.kanala@broadcom.com)
    :param dut:
    :return: True/False
    """
    checkpoints = kwargs.get("checkpoints", [])
    output = []
    data = st.show(dut, "show config checkpoints brief", type='klish')
    for each in data:
        output.append(each['id'])
    for check_point in checkpoints:
        if check_point not in output:
            return False
    return True


def verify_config_checkpoints_details(dut, **kwargs):
    """
    Author: Ramprakash Reddy (ramprakash-reddy.kanala@broadcom.com)
    :param dut:
    :return: api to verify config checkpoint details
    :Usuage: ses_api.verify_config_chekpoints_details(data.dut1,return_output='output')
    :Usuage: ses_api.verify_config_chekpoints_details(data.dut1,id='value')
    """
    st.banner("verify config checkpoints details")
    id = kwargs.get("id", "")
    label = kwargs.get("label", "")
    return_output = kwargs.pop('return_output', False)

    if 'label' in kwargs:
        command = "show config checkpoints {} details".format(label)
    elif 'id' in kwargs:
        command = "show config checkpoints {} details".format(id)
    else:
        command = "show config checkpoints details"

    output = st.show(dut, command, type="klish")

    if return_output:
        return output
    elif filter_and_select(output, match=kwargs):
        return True
    else:
        st.error("config checkpoints details verification failed")
        return False


def verify_active_session(dut, **kwargs):
    """
    Author: Naveen Nag
    email : naveen.nagaraju@broadcom.com
    :param dut:
    :return:

    Usage:
     session_api.verify_active_session(dut1)
    """
    state = kwargs.get("state", "Active")
    return_output = kwargs.get("return_output", False)
    exec_mode = kwargs.get("exec_mode", "")
    if exec_mode:
        output = st.show(dut, "show config session", type='klish', skip_error_check="True", exec_mode=exec_mode)
    else:
        output = st.show(dut, "show config session", type='klish', skip_error_check="True")
    if return_output:
        return output

    if len(output) == 0:
        st.error('No config session is present')
    else:
        if output[0]['state'] == state:
            return True
        else:
            st.error('\n Expected session state : {} \n Actual Session state: {}'.format(state, output[0]['state']))

    return False


def config_commit(dut, **kwargs):
    """
    Author : Ramprakash Reddy
    Email  : ramprakash-reddy.kanala@broadcom.com
    :param dut:
    :param label: optional field
    :return: commit_id
    usage: config_commit(dut1,timeout=180,expect_mode="mgmt-config"),config_commit(dut1,label="L1"), config_commit(dut1)
            config_commit(dut1, confirm="confirm", label="L2"), config_commit(dut1, confirm="confirm")
    """
    exec_mode = kwargs.get("exec_mode", "mgmt-config")
    expect_mode = kwargs.get("expect_mode", "mgmt-user")
    conn_index = kwargs.get("conn_index", None)
    exit_session = kwargs.get("exit", False)
    min_time = kwargs.get("min_time", 0)

    command = "commit"
    if 'confirm' in kwargs:
        command = "{} {}".format(command, kwargs['confirm'])
    if 'label' in kwargs:
        command = "{} label {}".format(command, kwargs['label'])
    elif 'timeout' in kwargs:
        expect_mode = "mgmt-config"
        command = "{} timeout {}".format(command, kwargs['timeout'])
    try:
        if min_time:
            st.wait(min_time, "Delay before committing the config")
            output = st.config(dut, command, type="klish", exec_mode=exec_mode, expect_mode=expect_mode,
                               conn_index=conn_index, skip_error_report=True, min_time=5)
        else:
            output = st.config(dut, command, type="klish", exec_mode=exec_mode, expect_mode=expect_mode,
                               conn_index=conn_index, skip_error_report=True)
        if exit_session:
            expect_mode = "mgmt-user"
            st.config(dut, "exit", type="klish", exec_mode=exec_mode, expect_mode=expect_mode, conn_index=conn_index)
    except Exception as e:
        st.error(e)
        return False
    result = re.findall("\\d+-\\d+", output)
    if result:
        return result[0]
    else:
        return []


def exit_config_session(dut, **kwargs):
    exec_mode = kwargs.get("exec_mode", "mgmt-config")
    expect_mode = kwargs.get("expect_mode", "mgmt-user")
    conn_index = kwargs.get("conn_index", None)
    st.config(dut, "exit", type="klish", exec_mode=exec_mode, expect_mode=expect_mode, conn_index=conn_index)


def abort_config_session(dut):
    """
    Author: Ramprakash Reddy(ramprakash-reddy.kanala@broadcom.com)
    :param dut:
    :return:
    """
    return st.config(dut, "abort", confirm="Y", skip_error_check=True, type="klish", exec_mode="mgmt-config",
                     expect_mode="mgmt-user")


def clear_config_session(dut, **kwargs):
    """
    Author: Ramprakash Reddy(ramprakash-reddy.kanala@broadcom.com)
    :param dut:
    :return:
    """
    conn_index = kwargs.get("conn_index", None)
    return st.show(dut, "clear config session", confirm="Y", skip_error_check=True, type="klish",
                   exec_mode="mgmt-user", skip_tmpl=True, conn_index=conn_index)


def verify_clear_config_session(dut, **kwargs):
    """
    :param dut:
    :param name:
    :return:
    """
    name = kwargs.get("name", "unnamed")
    conn_index = kwargs.get("conn_index", None)
    output = clear_config_session(dut, conn_index=conn_index)
    if "Aborted {} config session".format(name) in output:
        return True
    else:
        st.debug(output)
        return False


def show_config_session_diff(dut, **kwargs):
    """
    Author: Ramprakash Reddy
    email : ramprakash-reddy.kanala@broadcom.com
    :param dut:
    :return:
    """
    exec_mode = kwargs.get("exec_mode", "mgmt-user")
    conn_index = kwargs.get("conn_index", None)
    output = st.show(dut, "show config session diff", type='klish', skip_error_check="True", skip_tmpl=True, exec_mode=exec_mode, conn_index=conn_index)
    k = output.split("\n\n")
    rv = []
    for e in k:
        rv1 = {'-': [], '+': []}
        key = e.split('\n')[0].strip()
        for ee in e.split('\n'):
            if "++" in key or "--" in key:
                continue
            ee = ee.strip()
            if ee.startswith('-') and ee.lstrip("-").strip():
                rv1['-'].append(ee.lstrip("-").strip())
            elif ee.startswith('+') and ee.lstrip("+").strip():
                rv1['+'].append(ee.lstrip("+").strip())
            else:
                rv1['-'].append(ee.strip())
                rv1['+'].append(ee.strip())
        if rv1['-'] and rv1['+']:
            if len(rv1['-']) == 1 and (rv1['-'][0] == rv1['+'][0]):
                rv1['-'] = []
            if len(rv1['+']) == 1 and (rv1['+'][0] == rv1['-'][0]):
                rv1['+'] = []
        if rv1['-'] or rv1['+']:
            rv.append(rv1)
    if len(output) == 0:
        st.error("No difference in config session")
        return output
    else:
        return rv


def verify_config_session_diff(dut, **kwargs):
    """
    Author : Ramprakash Reddy (ramprakash-reddy.kanala@broadcom.com)
    :param dut:
    :param config:
    :return:
    """
    config = kwargs.get("config", [])
    no_config = kwargs.get("no_config", [])
    exec_mode = kwargs.get("exec_mode", "mgmt-config")
    verify_run_config = kwargs.get("verify_run_config", False)
    conn_index = kwargs.get("conn_index", None)
    st.banner("Verify config session difference")
    output = show_config_session_diff(dut, exec_mode=exec_mode, conn_index=conn_index)
    st.debug(output)
    if verify_run_config:
        command = 'show running-configuration'
        result = st.show(dut, command, type="klish", skip_tmpl=True, exec_mode=exec_mode, conn_index=conn_index)
    return_result = True
    if config:
        res = False
        if verify_run_config:
            for each in config:
                if each in result:
                    st.error("uncomitted config is exist in show running config")
                    return_result = False
        for each in output:
            if set(config).issubset(each['+']):
                res = True
        if not res:
            st.error("uncomitted config is not exist in show config session diff")
            return_result = False
    if no_config:
        res = False
        if verify_run_config:
            for each in no_config:
                if each not in result:
                    st.error("uncomitted no config is exist in show running config")
                    return_result = False
        for each in output:
            if set(no_config).issubset(each['-']):
                res = True
        if not res:
            st.error("uncomitted no config is not exist in show config session diff")
            return_result = False
    if not (config or no_config):
        for each in output:
            if each['+'] or each['-']:
                st.error("unexpected config is present in show config diff")
                st.debug(each)
                return_result = False
    return return_result


def run_config_session_command(dut, **kwargs):
    """
    :param dut:
    :param kwargs:
    :return:
    """
    conn_index = kwargs.get("conn_index", None)
    exec_mode = kwargs.get("exec_mode", "mgmt-user")
    expect_mode = kwargs.get("expect_mode", "mgmt-config")
    skip_error = kwargs.get("skip_error", False)
    output = st.config(dut, "configure session", conn_index=conn_index, exec_mode=exec_mode,
                       expect_mode=expect_mode, type="klish", skip_error_check=skip_error)
    if "Error" in output:
        return False
    else:
        return True
