from spytest.framework import get_work_area as getwa


def banner(msg, width=80, delimiter="#", wrap=True, tnl=True, lnl=True, dut=None):
    getwa().banner(msg, width, delimiter, wrap, tnl=tnl, lnl=lnl, dut=dut)
    return msg


def debug(msg, dut=None, split_lines=False):
    getwa().debug(msg, dut=dut, split_lines=split_lines)
    return msg


def verbose(msg, dut=None, split_lines=False):
    getwa().verbose(msg, dut=dut, split_lines=split_lines)
    return msg


def log(msg, dut=None, split_lines=False, lvl=None):
    getwa().log(msg, dut=dut, split_lines=split_lines, lvl=lvl)
    return msg


def dut_log(dut, msg):
    getwa().dut_log(dut, msg)
    return msg


def warn(msg, dut=None):
    getwa().warn(msg, dut=dut)
    return msg


def exception(msg):
    getwa().exception(msg)
    return msg


def error(msg, dut=None):
    getwa().error(msg, dut=dut)
    return msg


def notice(msg, dut=None):
    getwa().notice(msg, dut=dut)
    return msg


def audit(msg, split_lines=False, audit_only=False):
    getwa().audit(msg, split_lines=split_lines, audit_only=audit_only)
    return msg


def wait(val, msg=None, dut=None):
    getwa().wait(val, msg, dut)


def tg_wait(val, msg=None):
    getwa().tg_wait(val, msg)


def vsonic_wait(val, msg=None, dut=None):
    if is_vsonic(dut):
        wait(val, msg)


"""
Infrastructure API used by test scripts to report result
:param msgid: message identifier from /messages/*.yaml files
:param args: arguments required in message identifier specification
:param kwargs: options to denote the error
:       type: pass|fail|unsupported|env|topo|tgen|config|dutfail|script|timeout|cmdfail
:           - default is fail
:       tcid: <test case ID> if used it will be same as report_tc_xxx
:           - default is None
:       support: True|False to override support data collection
:           - default is True
:       abort: True|False to override abort/continue decision
:           - default is True for type != pass and tcid == None else False
:return: result message
"""


def report(msgid, *args, **kwargs):
    return getwa().report(msgid, *args, **kwargs)


def report_tc_pass(tcid, msgid, *args):
    getwa().report_tc_pass(tcid, msgid, *args)


def report_tc_fail(tcid, msgid, *args):
    getwa().report_tc_fail(tcid, msgid, *args)


def report_tc_unsupported(tcid, msgid, *args):
    getwa().report_tc_unsupported(tcid, msgid, *args)


def report_msg(msgid, *args):
    return getwa().report_msg(msgid, *args)


def report_result(errs, *args, **kwargs):
    pass_msgid = kwargs.get("pass_msgid", None)
    fail_msgid = kwargs.get("fail_msgid", None)
    first_only = kwargs.get("first_only", False)
    msg_list = [item for item in args]
    if not errs:
        def_pass_msgid = "msg" if msg_list else "test_case_passed"
        getwa().report_pass(pass_msgid or def_pass_msgid, ". ".join(msg_list))
        return
    if not isinstance(errs, list):
        errs = [errs]
    elif first_only:
        getwa().report_fail(fail_msgid or "msg", errs[0])
    else:
        msg_list.extend(errs)
        getwa().report_fail(fail_msgid or "msg", ". ".join(msg_list))


def report_pass(msgid, *args):
    """
    Infrastructure API used by test scripts to report pass
    :param msgid: message identifier from /messages/*.yaml files
    :param args: arguments required in message identifier specification
    :return:
    """
    getwa().report_pass(msgid, *args)


def report_fail(msgid, *args):
    """
    Infrastructure API used by test scripts to report fail
    :param msgid: message identifier from /messages/*.yaml files
    :param args: arguments required in message identifier specification
    :return:
    """
    getwa().report_fail(msgid, *args)


def report_env_fail(msgid, *args):
    """
    Infrastructure API generally used with in framework to report
    test failure because of environment issue
    :param msgid: message identifier from /messages/*.yaml files
    :param args: arguments required in message identifier specification
    :return:
    """
    getwa().report_env_fail(msgid, *args)


def report_topo_fail(msgid, *args):
    getwa().report_topo_fail(msgid, *args)


def report_tgen_fail(msgid, *args):
    getwa().report_tgen_fail(msgid, *args)


def report_unsupported(msgid, *args):
    getwa().report_unsupported(msgid, *args)


def report_config_fail(msgid, *args):
    getwa().report_config_fail(msgid, *args)


def report_sysinfo(dut, scope, mem, cpu, output):
    getwa().report_sysinfo(dut, scope, mem, cpu, output)


def report_scale(dut, name, value, platform=None, chip=None, module=None, func=None):
    getwa().report_scale(dut, name, value, platform, chip, module, func)


def report_featcov(dut, name, value, platform=None, chip=None, module=None, func=None):
    getwa().report_featcov(dut, name, value, platform, chip, module, func)


def apply_script(dut, cmdlist):
    return getwa().apply_script(dut, cmdlist)


def apply_json(dut, json, **kwargs):
    return getwa().apply_json(dut, json, **kwargs)


def apply_json2(dut, json, **kwargs):
    return getwa().apply_json2(dut, json, **kwargs)


def apply_files(dut, file_list):
    return getwa().apply_files(dut, file_list)


def run_script(dut, script_path, *args):
    return getwa().run_script(dut, 600, script_path, *args)


def run_script_with_timeout(dut, timeout, script_path, *args):
    return getwa().run_script(dut, timeout, script_path, *args)


def clear_config(dut):
    return getwa().clear_config(dut)


def erase_config(dut, erase=True, reboot=True):
    return getwa().erase_config(dut, erase, reboot)


def config_db_reload(dut, save=False, max_time=0):
    return getwa().config_db_reload(dut, save, max_time=max_time)


def upgrade_image(dut, url, skip_reboot=False, port_break=True,
                  port_speed=True, method=None):
    return getwa().upgrade_image(dut, url, skip_reboot, port_break,
                                 port_speed, method=method)


def reboot(dut, method=None, skip_port_wait=False, skip_exception=False,
           skip_fallback=False, ret_logs=False, abort_on_fail=False, **kwargs):
    if method == "warm" and not is_feature_supported("warm-reboot"):
        return "" if ret_logs else True
    return getwa().reboot(dut, method, skip_port_wait, skip_exception,
                          skip_fallback, ret_logs, abort_on_fail, **kwargs)


def get_dut_names():
    """
    This method is used to get all the DUT names

    :return: names of all the duts
    :rtype: list
    """
    return getwa().get_dut_names()


def get_tg_names():
    """
    This method is used to get all the TG names

    :return: names of all the tg
    :rtype: list
    """
    return getwa().get_tg_names()


def get_tg_type(name=None):
    return getwa().get_tg_type(name)


def get_free_ports(dut, native=None):
    """
    This method gets all the ports that are not connected to either
    partner DUT or Traffic Generator

    :param dut: device under test
    :type dut:
    :return: all the free ports
    :rtype: list
    """
    return getwa().get_free_ports(dut, native)


def get_all_ports(dut, native=None):
    """
    This method gets all the ports that are not reserved

    :param dut: device under test
    :type dut:
    :return: all the free ports
    :rtype: list
    """
    return getwa().get_all_ports(dut, native)


def get_other_names(dut, port_list):
    return getwa().get_other_names(dut, port_list)


def get_ifname_type(dut, oper=False):
    return getwa().get_ifname_type(dut, oper)


def get_tg_info(tg=None):
    return getwa().get_tg_info(tg)


def get_links(dut, peer=None, native=None):
    return getwa().get_links(dut, peer, native)


def get_dut_links_local(dut, peer=None, index=None, native=None):
    return getwa().get_dut_links_local(dut, peer, index, native)


def get_dut_links(dut, peer=None, native=None):
    return getwa().get_dut_links(dut, peer, native)


def get_tg_links(dut, peer=None, native=None):
    return getwa().get_tg_links(dut, peer, native)


def get_service_info(dut, name):
    return getwa().get_service_info(dut, name)


def do_rps(dut, op, on_delay=None, off_delay=None, recon=True):
    """
    This method performs the RPS operations such as on/off/reset.
    RPS models supported are Raritan, ServerTech, Avocent
    and all are through telnet.
    The RPS information is obtained from the testbed file.
    :param op: operation i.e. on/off/reset
    :param dut: DUT identifier
    :type dut: basestring
    :return: True if the operation is successful else False
    """
    return getwa().do_rps(dut, op, on_delay, off_delay, recon, True)


def get_testbed_vars(native=None):
    """
    returns the testbed variables in a dictionary
    :return: testbed variables dictionary
    :rtype: dict
    """
    return getwa().get_testbed_vars(native)


def lock_topology(*args):
    """
    locks the topology to specified specification though
    current testbed topology has more than specified
    :param spec: needed topology specification
    :type spec: basestring
    :return: True if the operation is successful else False
    :rtype: bool
    """
    return getwa().lock_topology(*args)


def ensure_min_topology(*args, **kwargs):
    """
    verifies if the current testbed topology satisfies the
    minimum topology required by test script
    :param spec: needed topology specification
    :type spec: basestring
    : use fail=False to avoid reporting as topo fail
    :return: True if current topology is good enough else False
    :rtype: bool
    """
    return getwa().ensure_min_topology(*args, **kwargs)


def get_config(dut, scope="current"):
    return getwa().get_config(dut, scope)


def get_build(dut, scope="current"):
    return getwa().get_build(dut, scope)


def get_breakout(dut, port_list=None):
    return getwa().get_breakout(dut, port_list)


def get_param(name, default):
    return getwa().get_param(name, default)


def get_device_param(dut, name, default):
    return getwa().get_device_param(dut, name, default)


def get_link_param(dut, local, name, default):
    return getwa().get_link_param(dut, local, name, default)


def get_args(arg):
    return getwa().get_args(arg)


def get_ui_type(dut=None, **kwargs):
    return getwa().get_ui_type(dut, **kwargs)


def record_ui_type(dut=None, **kwargs):
    return getwa().record_ui_type(dut, **kwargs)


def get_run_config():
    return getwa().get_run_config()


def get_mgmt_ifname(dut):
    return getwa().get_mgmt_ifname(dut)


def get_mgmt_ip(dut):
    return getwa().get_mgmt_ip(dut)


def get_datastore(dut, name, scope="default"):
    return getwa().get_datastore(dut, name, scope)


def get_device_alias(name, only=False, retid=False):
    return getwa().get_device_alias(name, only, retid)


def set_device_alias(dut, name):
    return getwa().set_device_alias(dut, name)


def exec_ssh(dut, username=None, password=None, cmdlist=[]):
    return getwa().exec_ssh(dut, username, password, cmdlist)


def change_passwd(dut, username, password):
    return getwa().change_passwd(dut, username, password)

# cft - console file transfer support
# 0: default 1: fallback 2: always 3: not supported


def upload_file_to_dut(dut, src_file, dst_file, cft=0):
    return getwa().upload_file_to_dut(dut, src_file, dst_file, cft)


def download_file_from_dut(dut, src_file, dst_file=None):
    return getwa().download_file_from_dut(dut, src_file, dst_file)


def ansible_dut(dut, playbook, **kwargs):
    return getwa().ansible_dut(dut, playbook)


def ansible_service(service, playbook, **kwargs):
    return getwa().ansible_service(service, playbook)


def add_addl_auth(dut, username, password):
    return getwa().add_addl_auth(dut, username, password)


def set_port_defaults(dut, breakout=True, speed=True):
    return getwa().set_port_defaults(dut, breakout, speed)


def wait_system_status(dut, max_time):
    return getwa().wait_system_status(dut, max_time)


def wait_system_reboot(dut):
    return getwa().wait_system_reboot(dut)


def add_prevent(what):
    return getwa().add_prevent(what)


def exec_remote(ipaddress, username, password, scriptpath, wait_factor=2):
    return getwa().exec_remote(ipaddress, username, password, scriptpath, wait_factor)


def add_module_vars(dut, name, value):
    return getwa().add_module_vars(dut, name, value)

# supported faster_cli=0/1 tryssh=0/1 ts=0/1 core=0/1
#           conf_session=0/1 syslog=0/1


def set_module_params(dut=None, **kwargs):
    return getwa().set_module_params(dut, **kwargs)

# supported faster_cli=0/1 ts=0/1 core=0/1 syslog=0/1


def set_function_params(dut=None, **kwargs):
    return getwa().set_function_params(dut, **kwargs)


def instrument(dut, scope):
    return getwa().instrument(dut, scope)


def change_prompt(dut, mode, **kwargs):
    return getwa().change_prompt(dut, mode, **kwargs)


def cli_config(dut, cmd, mode=None, skip_error_check=False, delay_factor=0, **kwargs):
    return getwa().cli_config(dut, cmd, mode, skip_error_check, delay_factor, **kwargs)


def cli_show(dut, cmd, mode=None, skip_tmpl=False, skip_error_check=False, **kwargs):
    return getwa().cli_show(dut, cmd, mode, skip_tmpl, skip_error_check, **kwargs)


def get_logs_path(for_file=None):
    return getwa().get_logs_path(for_file)


def is_dry_run():
    return getwa().is_dry_run()


def is_batch_run():
    return getwa().is_batch_run()


def get_run_arg(name, default=None):
    return getwa().get_run_arg(name, default)


def profiling_start(msg, max_time, skip_report=False):
    return getwa().profiling_start(msg, max_time, skip_report)


def profiling_stop(pid):
    return getwa().profiling_stop(pid)


def get_config_profile():
    return getwa().get_config_profile()


def get_device_type(dut):
    return getwa().get_device_type(dut)


def community_unsupported(cmd, dut=None):
    getwa().error("command {} is not supported in community build".format(cmd), dut=dut)


def is_sonic_device(dut):
    return getwa().is_sonic_device(dut)


def is_vsonic(dut=None):
    return getwa().is_vsonic(dut)


def is_sonicvs(dut=None):
    return getwa().is_sonicvs(dut)


def is_soft_tgen(vars=None):
    return getwa().is_soft_tgen(vars)


def open_config(dut, template, var=None, **kwargs):
    return getwa().open_config(dut, template, var=var, **kwargs)


def rest_create(dut, path, data, *args, **kwargs):
    return getwa().rest_create(dut, path, data, *args, **kwargs)


def rest_update(dut, path, data, *args, **kwargs):
    return getwa().rest_update(dut, path, data, *args, **kwargs)


def rest_modify(dut, path, data, *args, **kwargs):
    return getwa().rest_modify(dut, path, data, *args, **kwargs)


def yang_patch(dut, path, data, *args, **kwargs):
    yang_headers = dict()
    yang_headers.update({"Accept": "application/yang-data+json", "Content-Type": "application/yang-patch+json"})
    if kwargs.get("headers"):
        kwargs.get("headers").update(yang_headers)
    else:
        kwargs.update({"headers": yang_headers})
    if hasattr(data, 'req'):
        data = data.req
    return getwa().rest_modify(dut, path, data, *args, **kwargs)


def rest_init(dut, username, password, altpassword, cached=False, ip_changed=False):
    return getwa().rest_init(dut, username, password, altpassword, cached=cached, ip_changed=ip_changed)


def rest_read(dut, path, *args, **kwargs):
    return getwa().rest_read(dut, path, *args, **kwargs)


def rest_delete(dut, path, *args, **kwargs):
    return getwa().rest_delete(dut, path, *args, **kwargs)


def rest_parse(dut, filepath=None, all_sections=False, paths=[], **kwargs):
    return getwa().rest_parse(dut, filepath, all_sections, paths, **kwargs)


def rest_apply(dut, data):
    return getwa().rest_apply(dut, data)


def rest_send(dut, api='', method='get', params=None, data=None, retAs='json', **kwargs):
    return getwa().rest_send(dut, method=method, api=api, params=params, data=data, retAs=retAs, **kwargs)


def exec_ssh_remote_dut(dut, ipaddress, username, password, command=None, timeout=30, **kwargs):
    return getwa().exec_ssh_remote_dut(dut, ipaddress, username, password, command, timeout, **kwargs)


def parse_show(dut, cmd, output, tmpl=None):
    return getwa().parse_show(dut, cmd, output, tmpl)


def remove_prompt(dut, output):
    return getwa().remove_prompt(dut, output)


def show(dut, cmd, **kwargs):
    return getwa().show(dut, cmd, **kwargs)


def config(dut, cmd, **kwargs):
    return getwa().config(dut, cmd, **kwargs)


def vtysh(dut, cmd):
    return getwa().config(dut, cmd, type="vtysh", conf=False)


def vtysh_config(dut, cmd):
    return getwa().config(dut, cmd, type="vtysh", conf=True)


def vtysh_show(dut, cmd, skip_tmpl=False, skip_error_check=False):
    return getwa().show(dut, cmd, type="vtysh", skip_tmpl=skip_tmpl, skip_error_check=skip_error_check)


def generate_tech_support(dut, name, force=False):
    return getwa().generate_tech_support(dut, name, force)


def collect_core_files(dut, name, force=False):
    return getwa().collect_core_files(dut, name, force)


def save_sairedis(dut, name, clear=False):
    return getwa().save_sairedis(dut, name, clear)


def syslog_check(dut, scope, lvl, name):
    return getwa().syslog_check(dut, scope, lvl, name)


def get_credentials(dut):
    return getwa().get_credentials(dut)


def is_valid_base_config():
    return getwa().is_valid_base_config()


def dump_all_commands(dut, type='click'):
    return getwa().dump_all_commands(dut, type)


def poll_wait(method, timeout, *args, **kwargs):
    return getwa().poll_wait(1, timeout, method, *args, **kwargs)


def poll_wait2(delay, timeout, method, *args, **kwargs):
    return getwa().poll_wait(delay, timeout, method, *args, **kwargs)


def exec_all(entries, first_on_main=False):
    return getwa().exec_all(entries, first_on_main=first_on_main)


def exec_each(items, func, *args, **kwargs):
    return getwa().exec_each(items, func, *args, **kwargs)


def exec_each2(items, func, kwarg_list, *args):
    return getwa().exec_each2(items, func, kwarg_list, *args)


def unused(*args, **kwargs):
    pass


def get_dut_var(dut, name, default=None):
    return getwa().get_dut_var(dut, name, default)


def get_func_name(request):
    import sys
    if sys.version_info[0] >= 3:
        return request.function.__name__
    return request.function.func_name


def refresh_files():
    return getwa().refresh_files()


def is_feature_supported(name, dut=None):
    return getwa().is_feature_supported(name, dut)


def getenv(name, default=None):
    return getwa().getenv(name, default)


def infra_debug(msg):
    return getwa().infra_debug(msg)


def init_base_config_db(dut):
    return getwa().init_base_config_db(dut)


def apply_base_config_db(dut):
    return getwa().apply_base_config_db(dut)


def save_config_db(dut, type="base"):
    return getwa().save_config_db(dut, type)


def mktemp(dir=None):
    return getwa().mktemp(dir)


def unsupported_cli(cli_type, ret=False, lvl=1):
    return getwa().unsupported_cli(cli_type, ret, lvl + 1)


def get_result():
    return getwa().get_result()


def set_hostname(dut, hname=None):
    return getwa().set_hostname(dut, hname)

# kwargs: altpassword, port, blocking_timeout, access_model,
#         conn_index, dut, user_role


def do_ssh(ipaddress, username, password, **kwargs):
    return getwa().do_ssh(ipaddress, username, password, **kwargs)


def do_ssh_disconnect(dut, conn_index):
    return getwa().do_ssh_disconnect(dut, conn_index)


def get_current_testid():
    return getwa().get_current_testid()


def get_cache(name, dut=None, default=None):
    return getwa().get_cache(name, dut, default)


def set_cache(name, value, dut=None):
    return getwa().set_cache(name, value, dut)


def del_cache(name, dut=None):
    return getwa().del_cache(name, dut)


def get_logger():
    return getwa().get_logger()


def run_cmd(cmd, **kwargs):
    return getwa().run_cmd(cmd, **kwargs)


def get_login_password(dut):
    return getwa().get_login_password(dut)


def register_cleanup(func, *args, **kwargs):
    return getwa().register_cleanup(func, *args, **kwargs)


def tryssh_switch(dut, *args, **kwargs):
    return getwa().tryssh_switch(dut, *args, **kwargs)


def abort_run(code, reason, hang=False, line=None):
    return getwa().abort_run(code, reason, hang, line)


def abort_module(msgid, *args, **kwargs):
    return getwa().abort_module(msgid, *args, **kwargs)


def fetch_and_get_mgmt_ip(dut, try_again=3, wait_for_ip=0, wait_for_ready=None):
    return getwa().fetch_and_get_mgmt_ip(dut, try_again=try_again,
                                         wait_for_ip=wait_for_ip, wait_for_ready=wait_for_ready)
