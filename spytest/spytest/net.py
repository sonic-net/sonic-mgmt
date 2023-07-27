from __future__ import unicode_literals, print_function
import os
import sys
import json
import re
import logging
import signal
import time
import copy
import math
from random import randint
from collections import OrderedDict

import utilities.common as utils
import utilities.parallel as putils
from utilities.exceptions import DeviceConnectionTimeout
from utilities.exceptions import DeviceConnectionError
from utilities.exceptions import DeviceAuthenticationFailure
from utilities.exceptions import SPyTestException
from utilities.exceptions import SPyTestCmdException

from spytest import profile
from spytest.dicts import SpyTestDict
from spytest.logger import Logger
from spytest.logger import LEVEL_TXTFSM
from spytest.template import Template
from spytest.access.connection import DeviceConnection, DeviceFileUpload, DeviceFileDownload
from spytest.access.connection import initDeviceConnectionDebug
from spytest.access.utils import max_time_to_delay_factor
from spytest.access.utils import max_time_from_delay_factor
from spytest.access.utils import is_scmd
from spytest.ansible import ansible_playbook
from spytest.rest import Rest
from spytest.st_time import get_timenow
from spytest.st_time import get_elapsed
from spytest import env
import spytest.syslog as syslog

lldp_prompt = r"\[lldpcli\]\s*#\s*$"
regex_password = r"[Pp]assword:\s*$"
regex_password_anywhere = r"[Pp]assword:\s*"
regex_onie = r"(\s*ONIE:\/ #\s*|\s*ONIE:~ #\s*)$"

regex_grub_rescue = r"\s*grub rescue>\s*$"
regex_onie_sleep = r"\s*Info: Sleeping for [0-9]+ seconds\s*"
regex_onie_resque_msg = "Please press Enter to activate this console."
regex_onie_resque = r"{}\s*$".format(regex_onie_resque_msg)
regex_onie_resque_anywhere = r"{}\s*.*$".format(regex_onie_resque_msg)
regex_onie_install = r"\s+ONIE: Executing installer: http:\/\/"
regex_onie_fetch = r"\s+Info: (Fetching|Attempting) (http|tftp):\/\/"
sonic_mgmt_hostname = "--sonic-mgmt--"
nl = "\n"
end_exit = nl.join(["end", "exit"])

onie_success_patterns = ["ONIE: Executing installer:", "Verifying image checksum ... OK.",
                         "Preparing image archive ... OK.", "Installing SONiC in ONIE",
                         "Installing SONiC to", "Success: Support tarball created:",
                         "Installed SONiC base image SONiC-OS successfully",
                         "ONIE: NOS install successful:"]


class Net(object):

    def __init__(self, cfg=None, file_prefix=None, logger=None, testbed=None):
        initDeviceConnectionDebug(file_prefix)
        self.logger = logger or Logger()
        self.tb = testbed
        self.topo = SpyTestDict()
        self.topo.duts = SpyTestDict()
        self.tmpl = dict()
        self.rest = dict()
        self.gnmi = dict()
        self.syslogs = dict()
        self.skip_trans_helper = dict()
        self.last_mode = dict()
        self.image_install_status = OrderedDict()
        self.devices_used_in_tc = OrderedDict()
        self.devices_used_collection = False
        self.abort_without_mgmt_ip = False
        # 0: disabled 1: on-demand 2: always
        self.trace_callback_support = env.get("SPYTEST_LIVE_TRACE_OUTPUT", "0")
        self.relogin_on_connect = env.match("SPYTEST_RELOGIN_ONCONNECT", "1", "0")
        self.relogin_on_config_reload = env.match("SPYTEST_RELOGIN_ON_CONFIG_RELOAD", "1", "0")
        self.fix_sonic_51743 = env.match("SPYTEST_FIX_SONIC_51743", "1", "1")
        self.cmd_lock_support = env.match("SPYTEST_CONCURRENT_CONFIG_LOCK", "1", "0")
        self.onie_noip_recover = bool(env.get("SPYTEST_RECOVER_FROM_ONIE_WTIHOUT_IP", "1") != "0")
        self.session_start_time = get_timenow()
        self.module_start_time = None
        self.module_max_timeout_triggered = False
        self.tc_start_time = None
        self.tc_max_timeout_triggered = False
        self.tc_get_tech_support = False
        self.tc_fetch_core_files = False
        self.cfg = cfg
        if not self.cfg:
            self.session_max_timeout = 0
            self.module_max_timeout = 0
            self.tc_max_timeout = 0
            self.module_faster_cli = 0
            self.tryssh = 0
        else:
            self.session_max_timeout = self.cfg.session_max_timeout
            self.module_max_timeout = self.cfg.module_max_timeout
            self.tc_max_timeout = self.cfg.tc_max_timeout
            self.module_faster_cli = 1 if self.cfg.faster_cli else 0
            self.tryssh = 1 if self.cfg.tryssh else 0
        self.function_faster_cli = self.module_faster_cli
        self.profile_max_timeout_msg = None
        self.profile_skip_report = False
        self.prevent_list = []
        self.wa = None
        self.prev_testcase = None
        self.use_sample_data = env.match("SPYTEST_USE_SAMPLE_DATA", "1", "0")
        self.cmd_tmpl_cache = dict()
        self.debug_find_prompt = env.match("SPYTEST_DEBUG_FIND_PROMPT", "1", "0")
        self.dry_run_cmd_delay = env.getint("SPYTEST_DRYRUN_CMD_DELAY", "0")
        self.default_trace_log = env.getint("SPYTEST_DEFAULT_TRACE_LOG", "3")
        self.connect_retry_delay = 4
        self.orig_time_sleep = time.sleep
        # 1: fallback 2: always 3: not supported
        self.console_file_transfer = env.getint("SPYTEST_CONSOLE_FILE_TRANSFER", "1")
        self.max_cmds_once = 100
        self.pending_downloads = dict()
        self.log_dutid_fmt = env.get("SPYTEST_LOG_DUTID_FMT", "LABEL")
        self.dut_log_lock = putils.Lock()
        self.use_no_more = env.match("SPYTEST_USE_NO_MORE", "1", "1")
        self.addl_mode_change_cmds = {}
        self.addl_mode_change_kwargs = {}
        if not self.use_no_more:
            self.addl_mode_change_cmds["mgmt-user"] = "terminal length 0"
            self.addl_mode_change_kwargs["mgmt-user"] = {"on_cr_recover": "retry5"}
        self.addl_mode_change_kwargs["vtysh-config"] = {"conf_terminal": True}

    def get_logs_path(self, for_file=None, subdir=None):
        try: return self.wa.get_logs_path(for_file, subdir)
        except Exception: return None

    def _init_dev(self, devname):
        if devname not in self.topo.duts:
            self.topo.duts.update({devname: SpyTestDict()})
            self.syslogs.update({devname: []})

        access = self._get_dev_access(devname)
        access["flags"] = {}
        access["type"] = "unknown"
        access["errors"] = SpyTestDict()
        access["current_handle"] = 0
        access["num_tech_support"] = 0
        access["tryssh"] = False
        access["conf_session"] = False
        access["force_conn_index"] = None
        access["force_confirm"] = None
        access["force_conf_session"] = False
        access["force_conf_terminal"] = False
        access["user_role"] = SpyTestDict()
        access["user_conn"] = SpyTestDict()
        access["filemode"] = False
        access["current_prompt_mode"] = "unknown-prompt"
        access["module-get-tech-support"] = 1
        access["module-fetch-core-files"] = 1
        access["function-get-tech-support"] = 1
        access["function-fetch-core-files"] = 1
        access["module-syslog-check"] = 1
        access["function-syslog-check"] = 1
        self._cli_lock_data_set(access, 0, suffix="cli")
        self._cli_lock_data_set(access, 0, suffix="cmd")
        self._update_device_start(devname)

        return access

    def _update_device_start(self, devname):
        access = self._get_dev_access(devname)
        old = access.get("uptime_offset", 0)
        access["uptime_offset"] = 100
        return old

    def set_device_alias(self, devname, name):
        access = self._get_dev_access(devname)
        access["alias"] = name

    def _reset_device_aliases(self):
        for _devname in self.topo.duts:
            access = self._get_dev_access(_devname)
            access["alias"] = access["alias0"]

    def _reset_prompt_hostname(self):
        for _devname in self.topo.duts:
            access = self._get_dev_access(_devname)
            access["prompts"].add_user_hostname(None)

    def _get_dut_label(self, devname):
        # revert this back as it breaks set_device_alias
        # return self.tb.get_dut_label(devname)
        access = self._get_dev_access(devname)
        if access["dut_name"] == access["alias"]:
            return access["dut_name"]
        return "{}-{}".format(access["dut_name"], access["alias"])

    def _get_dev_access(self, devname):
        return self.topo.duts[devname]

    def _get_handle(self, devname, index=None):
        index = self._check_handle_index(devname, index)
        return self._get_param(devname, "handle", index)

    def _set_handle(self, devname, handle, index=None):
        index = self._check_handle_index(devname, index)
        self._set_param(devname, "handle", handle, index)

    def _check_force_conn(self, devname):
        access = self._get_dev_access(devname)
        if access["force_conn_index"] is not None:
            if access["force_conn_index"] in access["user_conn"]:
                return access["force_conn_index"]
        return None

    def _check_handle_index(self, devname, index=None):
        if index is not None: return index
        retval = self._check_force_conn(devname)
        if retval is not None: return retval
        return self._get_handle_index(devname)

    def _get_handle_index(self, devname):
        access = self._get_dev_access(devname)
        return access["current_handle"]

    def _get_param(self, devname, name, index=None):
        index = self._check_handle_index(devname, index)
        name2 = "{}.{}".format(name, index)
        access = self._get_dev_access(devname)
        if name2 in access:
            return access[name2]
        if index != 0:
            return None
        if name in access:
            return access[name]
        return None

    def _set_param(self, devname, name, value, index=None):
        index = self._check_handle_index(devname, index)
        access = self._get_dev_access(devname)
        access["{}.{}".format(name, index)] = value
        access[name] = value

    def _get_cli_prompt(self, devname, index=None):
        devname = self._check_devname(devname)
        access = self._get_dev_access(devname)
        index = self._check_handle_index(devname, index)
        prompts = access["prompts"].get_normal_user_prompts(index)
        return "|".join(prompts)

    def _set_cli_prompt(self, devname, prompt, index=None):
        index = self._check_handle_index(devname, index)
        access = self._get_dev_access(devname)
        access["prompts"].set_normal_user_prompt(prompt, index)

    def _switch_connection(self, devname, index=None, line=None):
        index = self._check_handle_index(devname, index)
        access = self._get_dev_access(devname)
        old = access["current_handle"]
        if old != index:
            line = line or utils.get_line_number(1)
            msg = "{} switching from handle {} to {}".format(line, old, index)
            self.dut_warn(devname, msg)
            access["current_handle"] = index
            self._set_last_prompt(access, None)
            return True
        return False

    def is_sonic_device(self, devname):
        return bool(self.tb.get_device_type(devname) in ["sonic", "sonicvs", "vsonic"])

    def is_sonicvs_device(self, devname):
        return bool(self.tb.get_device_type(devname) in ["sonicvs"])

    def is_vsonic_device(self, devname):
        return bool(self.tb.get_device_type(devname) in ["vsonic"])

    def is_fastpath_device(self, devname):
        return bool(self.tb.get_device_type(devname) in ["fastpath"])

    def is_icos_device(self, devname):
        return bool(self.tb.get_device_type(devname) in ["icos"])

    def is_any_fastpath_device(self, devname):
        return bool(self.is_fastpath_device(devname) or self.is_icos_device(devname))

    def is_linux_device(self, devname):
        return bool(self.tb.get_device_type(devname) in ["linux"])

    def is_poe_device(self, devname):
        return bool(self.tb.get_device_type(devname) in ["poe"])

    def is_filemode(self, devname):
        access = self._get_dev_access(devname)
        if access["filemode"]: return True
        if self.is_sonic_device(devname): return False
        if self.is_any_fastpath_device(devname): return False
        if self.is_linux_device(devname): return False
        if self.is_poe_device(devname): return False
        return True

    def _is_console_connection(self, devname, connection_param=None):
        if not connection_param:
            access = self._get_dev_access(devname)
            if self.is_filemode(devname): return True
            connection_param = access["connection_param"]
        if connection_param["access_model"].endswith("_terminal"):
            return True
        if connection_param["access_model"].endswith("_sshcon"):
            return True
        return False

    def tryssh_switch(self, devname, recover=None, reconnect=True, check=True):

        # nothing to be done if tryssh is not enabled
        if not self.tryssh and check:
            return False

        # nothing to be done if not console run
        if not self._is_console_connection(devname):
            return False

        # switch to console
        if recover is None:
            return self._switch_connection(devname, 0)

        # switch to ssh
        if recover is False:
            return self._switch_connection(devname, 1)

        # reconnect? and switch to ssh
        if not reconnect:
            return self._switch_connection(devname, 1)

        # reconnect and switch to ssh
        self.dut_warn(devname, "reconnect and switch to ssh")
        hndl = self._get_handle(devname, 1)
        if hndl:
            hndl.disconnect()
            self._set_handle(devname, None, 1)
            self._switch_connection(devname, 0)

        return self._tryssh_init(devname, False)

    @staticmethod
    def cmd_fmt(cmd):
        cmd = nl.join(utils.make_list(cmd))
        cmd = cmd.replace("\r", "")
        cmd = cmd.replace(nl, "\\n")
        return cmd if cmd else "''"

    def cmd_log(self, devname, fcli, msg, log_file):
        dst = ["all", "dut", "cmd", "module"]
        prefix = "FCMD" if fcli else "SCMD"
        msg = "{}: {}".format(prefix, msg)
        self.dut_log(devname, msg, dst=dst)
        if log_file:
            utils.write_file(log_file, msg + "\n", "a")

    def cli_log(self, devname, msg, log_file):
        dst = ["all", "dut", "cli", "module"]
        if log_file:
            utils.write_file(log_file, msg + "\n", "a")
        else:
            self.dut_log(devname, msg, dst=dst)

    def dut_dbg(self, devname, msg, cond=True, dst=None, prefix=""):
        return self.dut_log(devname, msg, logging.DEBUG, cond, dst, prefix)

    def dut_warn(self, devname, msg, cond=True, dst=None, prefix=""):
        return self.dut_log(devname, msg, logging.WARNING, cond, dst, prefix)

    def dut_err(self, devname, msg, cond=True, dst=None, prefix=""):
        return self.dut_log(devname, msg, logging.ERROR, cond, dst, prefix)

    def dut_log(self, devname, msg, lvl=logging.INFO, cond=True,
                dst=None, prefix="", split_lines=True):
        if not cond: return
        if self.dut_log_lock: self.dut_log_lock.acquire()
        try:
            access = self._get_dev_access(devname)
            conn = self._check_force_conn(devname)
            if conn:
                conn = "SSH{}".format(conn)
            elif access["current_handle"] == 0:
                conn = None
            else:
                conn = "SSH"
            log_dutid_fmt = self.log_dutid_fmt.upper()
            if log_dutid_fmt == "ID":
                dut_name = access["dut_name"]
            elif log_dutid_fmt == "ALIAS":
                dut_name = access["alias"]
            else:
                dut_name = self._get_dut_label(devname)
            self.logger.dut_log(dut_name, msg, lvl, split_lines, conn=conn,
                                dst=dst, prefix=prefix)
        except Exception:
            msg = utils.stack_trace(None, True)
            self.logger.trace(msg)
        finally:
            if self.dut_log_lock: self.dut_log_lock.release()

    def register_devices(self, _topo):
        for devname in _topo.duts:
            dut = _topo.duts[devname]
            self._init_dev(devname)
            self.set_console_only(bool(not self.tryssh), False)
            access = self._get_dev_access(devname)
            if "ip" not in dut:
                msg = "'ipaddr' parameter missing in topology input"
                raise ValueError(msg)
            utils.dict_copy(dut, access, "sshcon_username", "sshcon_password")
            utils.dict_copy(dut, access, "dut_name", "access_model")
            if "alias" in dut:
                access.update({"alias0": dut["alias"]})
                access.update({"alias": dut["alias"]})
            device_model = dut.get("device_model", "sonic")
            access.update({"device_model": device_model})
            utils.dict_copy(dut, access, "username", "password",
                            "altpassword", "oniepassword")
            if "auth" in dut:
                access.update({"testbed_auth": dut["auth"]})
            utils.dict_copy(dut, access, "onie_image", "errors")
            utils.dict_copy(dut, access, "mgmt_ipmask", "mgmt_gw")
            utils.dict_copy(dut, access, "port", "ip", "mgmt_ifname")
            self.rest.update({devname: Rest(logger=self.logger)})
            self.register_gnmi(devname, dut)
        self.register_templates()

    def unregister_devices(self):
        for _devname in self.topo.duts:
            for index in [0, 1]:
                self._disconnect_device(_devname, index)
        self.topo.duts = {}

    def register_gnmi(self, devname, devinfo):
        from spytest.gnmi import gNMI
        access = self._get_dev_access(devname)
        self.gnmi.update({devname: gNMI(logger=self.logger, devName=devname)})
        self.gnmi[devname].configure(ip=devinfo.get('gnmi_ip', access.get('ip')),
                                     port=devinfo.get('gnmi_port', 8080),
                                     username=devinfo.get('gnmi_username', access['username']),
                                     password=devinfo.get('gnmi_password', access['password']))

    def register_templates(self):
        for _devname in self.topo.duts:
            access = self._get_dev_access(_devname)
            device_model = access["device_model"]
            root, model = self.wa.hooks.get_templates_info(_devname, device_model)
            self.tmpl.update({_devname: Template(model, root=root)})

    def _trace_received(self, devname, cmd, hndl, msg1, msg2, line, trace_dump=None):
        if msg1:
            self.dut_warn(devname, msg1)
        if msg2:
            self.dut_warn(devname, "{}: {}".format(line, msg2))
        retval = ""
        try:
            self.dut_warn(devname, "============={}: DATA Rcvd ============".format(line))
            for msg in hndl.get_cached_read_lines():
                self.dut_warn(devname, "'{}'".format(msg))
            self.dut_warn(devname, "======================================")
        except Exception:
            self.dut_warn(devname, "{}: DATA Rcvd: {}".format(line, "UNKNOWN"))
        if trace_dump is not None:
            trace_dump.append(retval)
        return retval

    def _handle_find_prompt(self, devname, hndl, attempt, use_cache=True):
        delay_factor = 2 if attempt > 0 else 1
        return hndl.find_prompt_new(delay_factor, use_cache)

    def abort_run(self, val, reason, hang):
        if self.wa:
            self.wa.abort_run(val, reason, hang)
        else:
            os._exit(val)

    def _node_fail(self, devname, result, msg, dead=True):
        if self.wa and result: self.wa.report_env_fail_int(devname, False, result, msg)
        if msg: self.dut_err(devname, msg)
        if not dead: return
        if self.wa: self.wa.set_node_dead(devname, msg, True)
        self.abort_run(15, msg, True)

    def _check_prompt_onie(self, devname, prompt):
        if not utils.re_match_any(prompt.replace("\\", ""),
                                  regex_onie_resque, regex_onie):
            return

        msg = "Device Stuck in ONIE."
        self.dut_warn(devname, msg)

        if not self.recover_from_onie(devname, False, False):
            msg = "Failed to recover node from ONIE"
            self._node_fail(devname, "onie_stuck_dead", msg)
        else:
            msg = "Recovered node from ONIE"
            self._node_fail(devname, "onie_stuck_recovered_reboot", msg, False)

    def verify_prompt(self, devname, hndl, value):
        retval, again = self.wa.hooks.verify_prompt(devname, value)
        if retval is None:
            retval = hndl.verify_prompt(value)
            again = False
        return retval, again

    def _find_prompt_locked(self, access, net_connect=None, count=15, sleep=2,
                            line=None, recovering=False, use_cache=True):
        devname = access["devname"]
        hndl = self._get_handle(devname) if not net_connect else net_connect
        line = line or utils.get_line_number(1)
        reconnect_attempt = 0
        for i in range(count):
            wait_time = sleep * (i + 1)
            try:
                ########### Try connecting again #####################
                if (i > 0 and not net_connect) or not hndl:
                    if reconnect_attempt < 2:
                        reconnect_attempt = reconnect_attempt + 1
                        self.dut_log(devname, "Try reading prompt after reconnect {} try {}".format(hndl, reconnect_attempt))
                        if not self.reconnect(devname=devname):
                            if sleep > 0:
                                msg = "Waiting for {} secs before reconnect again..".format(wait_time)
                                self.dut_warn(devname, msg)
                                time.sleep(wait_time)
                            continue
                        hndl = self._get_handle(devname)
                ########### Try connecting again #####################
                if not hndl:
                    self.dut_warn(devname, "Failed to read prompt: Null handle @{}".format(line))
                else:
                    verified, try_again_count = False, 5
                    while 1:
                        output = self._handle_find_prompt(devname, hndl, i, use_cache=use_cache)
                        access["last-prompt"] = output
                        this_retval, this_again = self.verify_prompt(devname, hndl, output)
                        if this_retval:
                            verified = True
                            break
                        use_cache = False
                        self.dut_log(devname, "{}: invalid-prompt: {}".format(line, output))
                        self._check_error(access, nl, output, False, line)
                        if not this_again:
                            try_again_count = try_again_count - 1
                        if try_again_count < 0:
                            break
                    if not verified:
                        self.dut_err(devname, "find-prompt-failed({})".format(line))
                        self.dut_warn(devname, utils.get_call_stack_all(0, "CurrentCallStack:"))
                    output = utils.to_string(output)
                    if self.debug_find_prompt:
                        self.dut_log(devname, "find-prompt({}): {}".format(line, output))
                    try:
                        access["current_prompt_mode"] = self.get_mode_for_prompt(devname, output)
                    except Exception:
                        access["current_prompt_mode"] = "unknown-prompt"
                    return output
            except Exception as exp:
                msg1 = utils.stack_trace(None, True)
                msg2 = "Failed to read prompt .. handle: '{}', try: {}".format(hndl, i)
                self._trace_received(devname, "find_prompt", hndl, msg1, msg2, line)
                if "connection closed" in str(exp):
                    self.dut_err(devname, "Remote connection closed {}".format(i))
                    hndl = None
                    continue

            try:
                if not hndl: break
                if hndl and not hndl.is_alive():
                    hndl = None
            except Exception: pass

            if sleep > 0:
                msg = "Waiting for {} secs before retry..".format(wait_time)
                self.dut_warn(devname, msg)
                time.sleep(wait_time)

            if i % 2 == 0:
                if env.get("SPYTEST_RECOVERY_CTRL_C", "1") == "1":
                    msg = "Trying CTRL+C: attempt {}..".format(i)
                    self.dut_warn(devname, msg)
                    try: hndl.send_command_timing("\x03")
                    except Exception: self.dut_err(devname, "Failed to send CTRL+C")
            elif i % 2 == 1:
                if env.get("SPYTEST_RECOVERY_CTRL_Q", "1") == "1":
                    msg = "Trying CTRL+Q: attempt {}..".format(i)
                    self.dut_warn(devname, msg)
                    try: hndl.send_command_timing("\x11")
                    except Exception: self.dut_err(devname, "Failed to send CTRL+Q")

        # dump sysrq traces
        if hndl and env.get("SPYTEST_SYSRQ_ENABLE", "0") != "0":
            try:
                output = hndl.sysrq_trace()
                if output:
                    self.dut_warn(devname, output)
            except Exception as exp:
                self.dut_err(devname, str(exp))

        # no recovery using RPS in case very early - is this needed ???
        if not self.wa:
            msg = "Failed to find prompt - no recovery"
            self.dut_err(devname, msg)
            sys.exit(0)

        # recover using RPS and report result
        try:
            if self.wa.is_tech_support_onerror("console_hang"):
                if self._get_handle_index(devname) == 0:
                    if self._get_handle(devname, 1) is None:
                        hndl, ipaddr, _ = self._connect_to_device_ssh(devname)
                        if hndl:
                            self._set_handle(devname, hndl, 1)
                            self.init_normal_prompt(devname, 1)
                            self._switch_connection(devname, 1, line=line)
                            self.set_login_timeout(devname)
                            self.generate_tech_support(devname, "console_hang")
                            hndl.disconnect()
                            self._set_handle(devname, None, 1)
                        else:
                            linets = utils.get_line_number()
                            self.dut_log(devname, "{} failed to ssh {}".format(linets, ipaddr))
                    else:
                        self._switch_connection(devname, 1)
                        self.generate_tech_support(devname, "console_hang")
                    self._switch_connection(devname, 0)
                else:
                    self._switch_connection(devname, 0)
                    self.generate_tech_support(devname, "console_hang")
                    self._switch_connection(devname, 1)

            if self._get_handle_index(devname) == 0:
                if not self._rps_reset_console_hang(devname):
                    msg = "Failed to perform RPS reboot"
                    self._node_fail(devname, None, msg)
                if not self.wa.session_init_completed:
                    if not recovering:
                        # try finding the prompt once again
                        # as the session init is not completed
                        return self._find_prompt_locked(access, line=line,
                                                        recovering=True, use_cache=False)
                    msg = "Failed to recover the DUT even after RPS reboot"
                    self._node_fail(devname, None, msg)
            else:
                # Disconnect the handle
                if hndl: hndl.disconnect()
                # Set the ssh handle in access as None
                self._set_handle(devname, None, 1)
                # tryssh as False
                access["tryssh"] = False
                # Switch connection to console handle
                self._switch_connection(devname, 0)
                # Find Prompt on console handle
                self._find_prompt_locked(access, line=line, use_cache=False)
        except Exception as exp:
            self.dut_err(devname, str(exp))

        self.wa.report_env_fail_int(devname, True, "console_hang_observed")
        ######################### TODO #############################
        ###### check the console if not accessible use reset console
        ###### to recover and if you fail so call os.exit(0)
        ###########################################################
        sys.exit(0)

    def _find_prompt(self, access, net_connect=None, count=15,
                     sleep=2, line=None, use_cache=True):
        line = line or utils.get_line_number(1)
        self._cli_lock(access, "find-prompt", line)
        try:
            retval = self._find_prompt_locked(access, net_connect, count, sleep,
                                              line, use_cache=use_cache)
            self._cli_unlock(access, "find-prompt", line)
        except Exception as exp:
            self._cli_unlock(access, "find-prompt", line)
            raise exp
        return retval

    def _msg_append_log(self, msg, msgs, devname):
        msgs.append(msg)
        if devname:
            self.dut_log(devname, msg)

    def _do_connect_cinfo(self, cinfo, retry, msgs, devname=None):
        connected, net_connect = False, None
        for count in range(retry + 1):
            try:
                if count > 0:
                    if self.connect_retry_delay > 0:
                        time.sleep(self.connect_retry_delay * count)
                    self._msg_append_log("Re-Trying {}..".format(count + 1), msgs, devname)
                dut_name = self._get_dut_label(devname) if devname else None
                net_connect = DeviceConnection(devname=dut_name, logger=self.logger, **cinfo)
                connected = True
                break
            except DeviceAuthenticationFailure:
                self._msg_append_log("Auth-Err..", msgs, devname)
            except DeviceConnectionError:
                self._msg_append_log("connection-Err..", msgs, devname)
            except DeviceConnectionTimeout:
                self._msg_append_log("Timed-out..", msgs, devname)
            except Exception:
                msg = utils.stack_trace(None, True)
                self.dut_warn(devname, msg)

        if connected:
            net_connect.set_logger(self.logger)
            return net_connect

        msg = "Cannot connect: {}:{}".format(cinfo["ip"], cinfo["port"])
        self._msg_append_log(msg, msgs, devname)

        for line in utils.dump_connections("Existing Connections: "):
            self._msg_append_log(line, msgs, devname)

        return None

    def _connect_to_device(self, cinfo, access, retry=0, recover=False,
                           update_prompt=False):
        msgs = []
        devname = access["devname"]
        net_connect = self._do_connect_cinfo(cinfo, retry, msgs, devname)
        if net_connect:
            self.dut_dbg(devname, "Connected ...")
            if update_prompt:
                if recover:
                    prompt = self._find_prompt_locked(access, net_connect, use_cache=False)
                else:
                    prompt = self._find_prompt(access, net_connect, use_cache=False)
                self._set_param(devname, "prompt", prompt)
        return net_connect

    def _disconnect_device(self, devname, index=None):
        self.dut_log(devname, "Disconnecting ...")
        if devname not in self.topo.duts:
            self.logger.error("Invalid device {} to disconnect".format(devname))
            return
        hndl = self._get_handle(devname, index)
        if not hndl:
            self.dut_warn(devname, "already disconnected")
            return
        if env.get("SPYTEST_RECOVERY_CTRL_C", "1") == "1":
            try: hndl.send_command_timing("\x03")
            except Exception: pass
        hndl.disconnect()
        self._set_handle(devname, None, index)

    def trace_callback_set(self, devname, val, force=False):
        if self.is_filemode(devname): return
        if not self._is_console_connection(devname): return
        hndl = self._get_handle(devname)
        if not hndl: return
        func = getattr(hndl, "trace_callback_set")
        if not func: return
        if not val:
            func(None, None, None)
            return

        def trace_callback(self, devname, msg):
            try: self.dut_log(devname, msg, prefix="LIVE: ")
            except Exception: pass
        if self.trace_callback_support in ["0"]: return
        if self.trace_callback_support in ["1"] and not force: return
        self.dut_log(devname, "LIVE Console {}".format("Enable" if val else "Disable"))
        func(trace_callback, self, devname)

    def trace_callback_set_debug(self, devname, value):
        if self.debug_find_prompt:
            self.trace_callback_set(devname, value)

    def early_init(self, devname):
        if not self.is_sonic_device(devname):
            pass  # nothing to be done
        elif self.cfg.pde or self.cfg.ut_mode:
            pass  # nothing to be done
        elif not self.wa.is_feature_supported("ztp", devname):
            pass  # nothing to be done
        elif "ztp" in self.prevent_list:
            pass  # nothing to be done
        elif self._is_console_connection(devname):
            self.dut_dbg(devname, "disable ztp to avoid console messages")
            self.trace_callback_set(devname, True)
            self.wa.hooks.ztp_disable(devname)
            self.trace_callback_set(devname, False)

    def fix_hostname(self, devname):
        self._enter_linux(devname)
        prompt = self.init_normal_prompt(devname)
        msg = "=== re-init base prompt to {}".format(prompt)
        self.dut_log(devname, msg)

    def verify_device_info(self, devname, phase):
        return self.wa.hooks.verify_device_info(devname, phase)

    def get_user_role(self, devname, **kwargs):
        devname = self._check_devname(devname)
        access = self._get_dev_access(devname)
        index = kwargs.get("conn_index", None)
        index = self._check_handle_index(devname, index)
        return access.user_role.get(index, "admin")

    def is_admin_role(self, devname, **kwargs):
        user_role = self.get_user_role(devname, **kwargs)
        return bool(user_role in ["admin"])

    def post_login(self, devname, **kwargs):
        if not self.is_admin_role(devname, **kwargs):
            # kwargs["type"] = "klish"
            # self.wa.hooks.post_login(devname, **kwargs)
            return
        self.wa.hooks.post_login(devname, **kwargs)
        if self.is_sonic_device(devname):
            try: self.check_uptime(devname)
            except Exception: pass

    def set_login_timeout(self, devname):
        self.fix_hostname(devname)
        self.post_login(devname)

    def check_uptime(self, devname):
        devname = self._check_devname(devname)
        access = self._get_dev_access(devname)
        value = self._config(devname, "cat /proc/uptime", type="click",
                             skip_error_check=True, on_cr_recover="retry3", sudo=False)
        if value:
            value = value.split()
            self.dut_log(devname, "UPTIME: {}".format(value[0]))
        else:
            self.dut_warn(devname, "Failed to Read UPTIME")

        value = utils.parse_float(value[0], 0)
        if value < (100 - access["uptime_offset"]):
            self.dut_warn(devname, "IS REBOOTED?")
        elif value > 200:
            access["uptime_offset"] = 0

    def ensure_base_prompt(self, devname, force=False):
        devname = self._check_devname(devname)
        access = self._get_dev_access(devname)
        if force or not access.get("baseprompt", None):
            prompts = access["prompts"]
            access["hostname"] = self.wa.hooks.get_base_prompt(devname)
            access["baseprompt"] = prompts.update_with_hostname(access["username"], access["hostname"])
        return access["baseprompt"]

    def update_prompts_hostname(self, devname):
        devname = self._check_devname(devname)
        access = self._get_dev_access(devname)
        if self.cfg.pde:
            access["hostname"] = "sonic"
            access["baseprompt"] = "(sonic)#"
            return access["baseprompt"]

        self.ensure_base_prompt(devname, True)
        msg = "Base Prompt: {}".format(access["hostname"])
        self.dut_log(devname, msg)
        return access["baseprompt"]

    # phase 0: init 1: upgrade 2: reboot, 3: reboot-again
    def do_common_init(self, devname, phase=2, max_ready_wait=0):
        sys_status = True
        if phase not in [0]:
            self.set_login_timeout(devname)
            self.early_init(devname)
        self.update_prompts_hostname(devname)
        sys_status = self.wa.wait_system_status(devname, max_time=max_ready_wait)
        if self.is_any_fastpath_device(devname):
            self.update_prompts_hostname(devname)
        self._set_mgmt_ip(devname, sys_status)
        self._fetch_mgmt_ip(devname)
        if phase in [0, 1, 3]:
            self.reset_restinit(devname)
        self.wa.instrument(devname, "post-reboot")

        # tasks after every reboot
        reboot_again = self.wa.hooks.post_reboot(devname, bool(phase in [0, 1]))
        if reboot_again:
            sys_status = self.do_common_init(devname, 3, max_ready_wait)
        else:
            self._fetch_mgmt_ip(devname, 5, 2)

        # show date on the device
        self.wa.hooks.show_dut_time(devname)

        return sys_status

    def connect_to_device_current(self, devname, retry=0, recover=True):
        access = self._get_dev_access(devname)
        if access["current_handle"] == 0:
            return self.connect_to_device(devname, retry, True, recover)
        return self._tryssh_init(devname, False)

    def init_normal_prompt(self, devname, index=None):
        if self.is_filemode(devname):
            return "dummy"
        index = self._check_handle_index(devname, index)
        devname = self._check_devname(devname)
        access = self._get_dev_access(devname)
        prompt = self._relogin(devname, True)  # go to enable
        if not prompt:
            prompt = self._find_prompt(access, use_cache=False)
        prompt2 = prompt.replace("\\", "")
        self._set_param(devname, "prompt", prompt, index)
        self._set_cli_prompt(devname, prompt, index)
        return prompt2

    def _init_connection_param(self, devname):
        connection_param = {
            'access_model': 'sonic_ssh',
            'username': 'admin',
            'password': 'YourPaSsWoRd',
            'blocking_timeout': 30,
            'keepalive': 1,
            'port': 22
        }
        if os.getenv("SPYTEST_NETMIKO_DEBUG", None):
            session_log = self.get_logs_path("netmiko_session.log")
            connection_param["session_log"] = session_log
        access = self._get_dev_access(devname)

        utils.dict_copy(access, connection_param, "access_model", "verbose")
        utils.dict_copy(access, connection_param, "ip", "port")
        utils.dict_copy(access, connection_param, "username", "password", "altpassword")
        utils.dict_copy(access, connection_param, "mgmt_ipmask", "mgmt_gw")
        utils.dict_copy(access, connection_param, "addl_auth")
        utils.dict_copy(access, connection_param, "sshcon_username", "sshcon_password")

        connection_param['default_pass'] = self.wa.hooks.get_default_pass(devname)
        connection_param['parent'] = self
        connection_param['net_devname'] = devname
        connection_param['net_login'] = self._net_login
        return connection_param

    @staticmethod
    def connection_param_string(cinfo):
        parts = []
        parts.append("IP = {}".format(str(cinfo.get("mgmt-ip", ""))))
        parts.append(str(cinfo.get("password", "")))
        parts.append(str(cinfo.get("altpassword", "")))
        return "/".join(parts)

    def icos_login(self, access, expect):
        devname = access["devname"]
        output = self._send_command(access, "ls -d /tmp", expect, ufcli=False,
                                    skip_error_check=True, use_cache=False)
        if "/tmp" not in output:
            return False
        expect = "|".join([expect, "password for admin:"])
        output = self._send_command(access, "sudo icos-console -r -f", expect, ufcli=False,
                                    skip_error_check=True, use_cache=False)
        for password in [access['password'], access['altpassword']]:
            if "password for admin:" in output:
                output = self._send_command(access, password, expect, ufcli=False,
                                            skip_error_check=True, use_cache=False)
        if "password for admin:" in output:
            msg = "Failed to run icos-console"
            self.dut_err(devname, msg)
            self.abort_run(15, msg, False)

        return True

    def _relogin(self, devname, recon):
        if not self.is_any_fastpath_device(devname):
            return None

        # identify needed prompt
        access = self._get_dev_access(devname)
        expect = self.wa.hooks.get_regex(devname, "anyprompt")

        # icos logout
        if self.is_icos_device(devname) and not recon:
            self._send_command(access, "\x1A\x1A\x03\x03\x1A\x1A\x03\x03", expect, ufcli=False,
                               skip_error_check=True, use_cache=False, use_send_bytes=True)

        # goto unpriv mode
        output = self._send_command(access, "end", expect, ufcli=False,
                                    skip_error_check=True, use_cache=False)
        if "bash: end: command not found" in output:
            skip_logout = self.icos_login(access, expect)
        else:
            skip_logout = False
            self._send_command(access, "end", expect, ufcli=False,
                               skip_error_check=True, use_cache=False)

        # only enable on reconnect
        if recon:
            self._send_command(access, "enable", expect, ufcli=False,
                               skip_error_check=True, use_cache=False)
        elif not skip_logout:
            # logout
            prompt = "(y/n)"
            expect = self.wa.hooks.get_regex(devname, "login")
            expect = "|".join([expect, prompt])
            expect = "|".join([expect, "Closing console session"])
            op = self._send_command(access, "logout", expect, ufcli=False,
                                    skip_error_check=True, use_cache=False,
                                    strip_prompt=False, strip_command=False,
                                    on_cr_recover="ignore")
            if re.match(prompt, op.strip(), re.IGNORECASE | re.DOTALL):
                self._send_command(access, "y", expect, ufcli=False,
                                   skip_error_check=True, use_cache=False,
                                   on_cr_recover="ignore")

            # login
            self._enter_linux(devname)

        # return base prompt
        return self.ensure_base_prompt(devname)

    def init_onie_recover(self, devname, connection_param, prompt):

        if not self._is_console_connection(devname, connection_param):
            return None

        # check if we are in onie diag-shell
        prompt2 = prompt.replace("\\", "")
        diag_prompt = r"root\@\(none\)\:\/\#"
        diag_prompt2 = diag_prompt.replace("\\", "")
        if diag_prompt in prompt or diag_prompt2 in prompt2:
            self.recover_from_onie(devname, False, False, prompt="DIAG-SHELL")
            self.init_normal_prompt(devname)
            prompt = self._get_param(devname, "prompt")

        # detect if we are in ONIE discovery prompt
        if "ONIE" in prompt:
            install = False
            if not self.recover_from_onie(devname, install):
                if not self.recover_from_onie(devname, bool(not install)):
                    return False
            self.init_normal_prompt(devname)
            prompt = self._get_param(devname, "prompt")

        # detect if we are in ONIE rescue prompt
        if "grub rescue" in prompt:
            if not self.recover_from_grub_rescue(devname, True):
                if not self.recover_from_onie(devname, True):
                    return False
            self.init_normal_prompt(devname)

        return True

    def connect_to_device(self, devname, retry=0, recon=False, recover=True):

        access = self._get_dev_access(devname)
        connection_param = self._init_connection_param(devname)

        # update additional auth
        access["connection_param"] = connection_param
        self.add_addl_auth(devname, None, None)

        access["filemode"] = self.cfg.filemode
        access["devname"] = devname
        access["last-prompt"] = None
        model = access.get("device_model", None)
        access["normal_user_mode"] = self.wa.hooks.get_mode(devname, "normal-user")
        access["prompts"] = self.wa.hooks.init_prompts(model, self.logger,
                                                       devname, access["normal_user_mode"])

        self.dut_log(devname, "Connecting to device (%s): %s: %s:%s .." %
                     (access["alias"], connection_param["access_model"],
                      connection_param['ip'], connection_param['port']))

        if not self.is_filemode(devname):
            show_ver_output = self.connect_to_device_real(access, retry, recon, recover)
            if show_ver_output is None:
                return False
        else:
            self._set_cli_prompt(devname, "dummy")
            show_ver_output = dict()

        prompt = self._get_cli_prompt(devname)
        msg = "Prompt at the connection finish: '{}' ".format(prompt.replace("\\", ""))
        self.dut_log(devname, msg)
        self.wa.hooks.show_dut_time(devname)

        # wait for Management IP
        self._fetch_mgmt_ip(devname, 30, 2)

        if not access.get("curr_pwd") and not self.is_filemode(devname):
            if self.cfg.ui_type in ["rest-patch", "rest-put"]:
                if not show_ver_output.get("product"):
                    return True
                exp = self.rest[devname]._get_init_exception()
                if exp:
                    msg = "EXITING RUN: Identified an exception : '{}', please check the dut and try again".format(exp)
                else:
                    msg = "EXITING RUN: Identified an exception, something went wrong. please check the dut and try again"
                self._node_fail(devname, "msg", msg, True)
        return True

    def login_again(self, devname):
        access = self._get_dev_access(devname)
        regex_login = self.wa.hooks.get_regex(devname, "login")
        regex_anyprompt = self.wa.hooks.get_regex(devname, "anyprompt")
        while True:
            prompt_terminator = "|".join([regex_anyprompt, regex_login])
            output = self._send_command(access, "exit", prompt_terminator,
                                        skip_error_check=True, use_cache=False)
            if re.search(regex_login, output):
                self._enter_linux(devname)
                self.init_normal_prompt(devname)
                break

    def connect_to_device_real(self, access, retry=0, recon=False, recover=True):
        devname = access["devname"]
        dut_label = self._get_dut_label(devname)
        load = self.wa.get_cfg_load_image(devname)
        boot_from_grub = env.get("SPYTEST_BOOT_FROM_GRUB", "0")
        if load == "onie2" or boot_from_grub == "1":
            if load != "none" and not self.wa.session_init_completed:
                if not self.moveto_grub_mode(devname):
                    msg = "Failed to bring the device {} to GRUB mode".format(dut_label)
                    self.dut_err(devname, msg)
                    return None
            load = "onie2"

        connection_param = access["connection_param"]
        net_connect = self._connect_to_device(connection_param, access, retry=retry)
        if not net_connect:
            msg = "Failed to connect to device {}".format(dut_label)
            self.dut_err(devname, msg)

            reachable = bool(os.getenv("SPYTEST_DUT_CONSOLE_SKIP_REACHABLE_CHECK", "1") != "0")
            if not reachable:
                reachable = utils.ipcheck(connection_param['ip'], max_attempts=3)
            if not reachable:
                msg = "Ping Failed for IP : '{}'".format(connection_param['ip'])
                self.dut_warn(devname, msg)

            if env.get("SPYTEST_RECOVERY_MECHANISMS", "1") == "0":
                # no recovery enabled
                return None

            if not self._is_console_connection(devname, connection_param):
                # cannot recover non-console runs
                return None

            if not self.is_sonic_device(devname):
                # cannot recover non-sonic device
                return None

            if not net_connect:
                net_connect = self._recover_reset_console(devname, retry)

            if not net_connect and not self.wa.session_init_completed:
                if boot_from_grub == "2":
                    msg = "Performing RPS reboot and taking the DUT '{}' to ONIE mode".format(dut_label)
                    self.dut_warn(devname, msg)
                    if not self.moveto_grub_mode(devname):
                        return None
                    net_connect = self._connect_to_device(connection_param, access, retry=retry)

        if not net_connect and recover:
            net_connect = self._recover_rps_reboot(devname, retry, abort=False)
            if not net_connect:
                msg = "Performing RPS reboot and recovering the DUT '{}' to ONIE mode".format(dut_label)
                self.dut_warn(devname, msg)
                if self.moveto_grub_mode(devname):
                    net_connect = self._connect_to_device(connection_param, access, retry=retry)
                    load = "onie2"
            if not net_connect:
                msg = "Failed to recover even after onie2"
                self._node_fail(devname, "console_hang_node_dead", msg)

        if not net_connect:
            return None

        # store handle
        self._set_handle(devname, net_connect)

        # install image using onie2 if asked for
        if load == "onie2":
            prompt2 = self._find_prompt(access, use_cache=False).replace("\\", "")
            if not re.compile(regex_onie).match(prompt2):
                msg = "Failed to bring the device {} to ONIE mode".format(dut_label)
                self._node_fail(devname, None, msg)
                return None
            self.recover_from_onie(devname, True)

        # handle devices in onie prompt on connect
        prompt = self._find_prompt(access, use_cache=False)
        self.init_onie_recover(devname, connection_param, prompt)

        # relogin
        self._relogin(devname, recon)

        # go to sudo mode if needed
        regex_sudopass = self.wa.hooks.get_regex(devname, "sudopass", access["username"])
        if regex_sudopass:
            regex_anyprompt = self.wa.hooks.get_regex(devname, "anyprompt")
            prompt_terminator = "|".join([regex_anyprompt, regex_sudopass])
            output = self._send_command(access, "sudo -i", prompt_terminator,
                                        skip_error_check=True, use_cache=False)
            if re.search(regex_sudopass, output):
                self._send_command(access, access["password"], regex_anyprompt,
                                   skip_error_check=True, use_cache=False)

        # init starting prompt
        prompt2 = self.init_normal_prompt(devname)
        msg = "Prompt at the connection start: '{}' ".format(prompt2)
        self.dut_log(devname, msg)

        if self.is_any_fastpath_device(devname) or self.is_linux_device(devname):
            self.update_prompts_hostname(devname)

        if not self.wa.session_init_completed:
            self.image_install_status[devname] = False

        for _ in range(1):

            retval = self.init_onie_recover(devname, connection_param, prompt2)
            if retval is None:
                break  # nothing to do non console connection

            if not retval:
                return None  # failed to recover from onie

            # check if this is sonic device
            if not self.is_sonic_device(devname):
                break

            if self.relogin_on_connect:
                self.login_again(devname)

            ##################################################################
            # Ensure that we are at normal user mode to be able to
            # continue after reboot from test scripts
            ##################################################################
            # verify run start when the DUT is in below mode
            # login, password
            # admin@sonic, root@sonic
            # klish, klish config, klish interface config
            # vtysh, vtysh config, vtysh bgp router af config
            # lldpcli
            ##################################################################
            try:
                self._enter_linux(devname)
                prompt = self.init_normal_prompt(devname)
                output1 = self._send_command(access, "whoami", ufcli=False,
                                             skip_error_check=True, delay_factor=4) or ""
                output = output1.replace(prompt, "")
                if "Unknown command" in output:
                    self._exit_vtysh(devname, onconnect=1)
                    self.init_normal_prompt(devname)
                    output = self._send_command(access, "whoami")
                whoami = output.strip().split(nl)[0].strip()
                if connection_param["username"] != whoami:
                    msg = "current user '{}' from output '{}' is not same in testbed {}"
                    msg = msg.format(whoami, output1, connection_param["username"])
                    self.dut_warn(devname, msg)
                    regex_login = self.wa.hooks.get_regex(devname, "login")
                    regex_anyprompt = self.wa.hooks.get_regex(devname, "anyprompt")
                    prompt_terminator = "|".join([regex_anyprompt, regex_login])
                    output2 = self._send_command(access, end_exit, prompt_terminator,
                                                 skip_error_check=True, use_cache=False)
                    if "diagnostic" in output2:
                        raise SPyTestException("Stuck in ONIE Diag")
                    self._enter_linux(devname)
                    self.init_normal_prompt(devname)
            except Exception as exp:
                msg = "Please report this issue ({})".format(exp)
                self.logger.error(msg)
                msg = utils.stack_trace(None, True)
                self.dut_warn(devname, msg)

        # perform post-login operations like set console timeout
        self.post_login(devname)

        # perform early initialization line ztp disable
        self.early_init(devname)

        # no need to call post_login again
        set_login_timeout_again = True

        # perform post reboot operations
        connection_param["mgmt-ip"] = None
        show_ver_output = dict()

        # wait for short time when we are going to upgrade
        max_ready_wait = 0 if self.wa.get_cfg_load_image(devname) == "none" else 1
        if not self._is_console_connection(devname, connection_param):
            max_ready_wait = 0
        if not recon:
            if not self.cfg.ut_mode:
                if not self._is_console_connection(devname, connection_param):
                    if not self.wa.session_init_completed:
                        self.wa.hooks.clear_logging(devname)
                else:
                    self.wa.hooks.clear_logging(devname)
            self.do_common_init(devname, phase=0, max_ready_wait=max_ready_wait)
            show_ver_output = self._show_version(devname, "reading initial version")
            self._fetch_mgmt_ip(devname, 5, 2)
        elif not set_login_timeout_again:
            self.fix_hostname(devname)
        else:
            self.set_login_timeout(devname)

        # open ssh connection to switch execution to
        if env.get("SPYTEST_SESSION_INIT_TRYSSH", "1") != "0":
            self._tryssh_init(devname)

        return show_ver_output

    def _recover_reset_console(self, devname, retry):
        connection_param = self._init_connection_param(devname)
        access = self._get_dev_access(devname)
        dut_label = self._get_dut_label(devname)

        if not self._is_console_connection(devname, connection_param):
            return None

        if env.get("SPYTEST_RESET_CONSOLES", "0") == "0":
            # no kill consoles enabled
            msg = "Terminal server console reset is not enabled"
            self.dut_dbg(devname, msg)
            return None

        if not self.tb.get_ts(devname):
            # no terminal server information in testbed file
            msg = "Terminal server information is not available for {}".format(dut_label)
            self.dut_err(devname, msg)
            return None

        msg = "Trying terminal server console reset to recover {}".format(dut_label)
        self.dut_warn(devname, msg)
        self.wa.do_ts(devname, "show-kill")
        net_connect = self._connect_to_device(connection_param, access,
                                              retry=2 if retry else 0,
                                              recover=True, update_prompt=True)
        if net_connect:
            msg = "Recovered {} after console session reset".format(dut_label)
            self.dut_warn(devname, msg)
        else:
            msg = "Failed to connect to {} even after terminal server console reset".format(dut_label)
            self.dut_err(devname, msg)

        return net_connect

    def _do_rps_reset(self, devname, recon=True, debug=True):
        try:
            if debug:
                self.dut_warn(devname, "Collecting RPS debug information")
                self.wa.gen_rps_debug_info(devname)
            return self.wa.do_rps_int(devname, "reset", recon=recon)[0]
        except Exception:
            msg = "Exception performing RPS reset"
            self._node_fail(devname, "console_hang_node_dead", msg)

    def _rps_reset_console_hang(self, devname):
        if env.get("SPYTEST_ONCONSOLE_HANG", "recover") == "dead":
            msg = "Bailout the node from run for manual inspection"
            self._node_fail(devname, "console_hang_node_dead", msg)

        msg = "Console hang proceeding with RPS Reboot"
        self.dut_warn(devname, msg)
        return self._do_rps_reset(devname)

    def _recover_rps_reboot(self, devname, retry, abort=True):
        access = self._get_dev_access(devname)
        connection_param = self._init_connection_param(devname)
        dut_label = self._get_dut_label(devname)

        msg = "Trying RPS reboot to recover {}".format(dut_label)
        self.dut_warn(devname, msg)

        # disconnect device
        if self.is_sonicvs_device(devname) or self.is_vsonic_device(devname):
            msg = "Disconnect before RPS reboot {}".format(dut_label)
            self.dut_warn(devname, msg)
            try: self._disconnect_device(devname)
            except Exception:
                msg = utils.stack_trace(None, True)
                self.dut_warn(devname, msg)

        self._do_rps_reset(devname, recon=False)
        net_connect = self._connect_to_device(connection_param, access,
                                              retry=2 if retry else 0)
        msg = "Failed to connect to {} even after RPS reboot".format(dut_label)
        if net_connect:
            msg = "Recovered {} after RPS reboot".format(dut_label)
            self.dut_warn(devname, msg)
        elif abort:
            self._node_fail(devname, "console_hang_node_dead", msg)
        else:
            self.dut_err(devname, msg)
        return net_connect

    def _show_version(self, devname, msg):
        try:
            self.dut_log(devname, msg)
            return self.wa.hooks.show_version(devname)
        except Exception:
            msg = utils.stack_trace(None, True)
            self.dut_warn(devname, msg)

    def _tryssh_init(self, devname, init=True):
        access = self._get_dev_access(devname)
        if not access["tryssh"] or self.is_filemode(devname):
            return True

        if not self._is_console_connection(devname):
            return True

        line = utils.get_line_number()
        self._ensure_latest_ip(devname, access["tryssh"], init, line)
        self.verify_device_info(devname, "pre-tryssh")
        rv, ipaddr = self._attempt_ssh_connection(devname, 1, line, False)
        if not rv:
            msg = "{} failed to ssh {} fallback to CONSOLE".format(line, ipaddr)
            self.dut_warn(devname, msg)
        elif self.verify_device_info(devname, "post-tryssh"):
            return True
        else:
            msg = "{} ssh/console info mismatch fallback to CONSOLE".format(line)
            self.dut_warn(devname, msg)
        access["tryssh"] = False
        self._switch_connection(devname, 0, line=line)
        self._set_handle(devname, None, 1)
        return False

    def _attempt_ssh_connection(self, devname, conn_index, line=None, show_err=True):
        line = line or utils.get_line_number()
        hndl, ipaddr, errs = self._connect_to_device_ssh(devname)
        if hndl:
            self._set_handle(devname, hndl, conn_index)
            self.init_normal_prompt(devname, conn_index)
            self._switch_connection(devname, conn_index, line=line)
            self.set_login_timeout(devname)
        elif show_err:
            errs.insert(0, "{} failed to ssh-{} {}".format(line, conn_index, ipaddr))
            self.dut_warn(devname, errs)
        return bool(hndl), ipaddr

    def _ensure_latest_ip(self, devname, tryssh, init, line=None):
        access = self._get_dev_access(devname)
        line = line or utils.get_line_number()
        old = access["connection_param"].get("mgmt-ip")
        if tryssh and not init:
            self._fetch_mgmt_ip(devname, 5, 2)
            new = access["connection_param"].get("mgmt-ip")
            if old != new:
                msg = "{} IP address changed from {} to {}".format(line, old, new)
                self.dut_warn(devname, msg)

        if init and not old:
            msg = "{} Trying to get the device mgmt-ip..".format(line)
            self.dut_log(devname, msg)
            self._fetch_mgmt_ip(devname, 5, 2)

    def _ensure_ssh_connection(self, devname, conn_index, line=None):
        if self._get_handle(devname, conn_index): return True
        return self._attempt_ssh_connection(devname, conn_index, line)

    def _connect_to_device_ssh(self, devname):
        msgs = []
        access = self._get_dev_access(devname)
        device = copy.copy(access["connection_param"])
        if not device["mgmt-ip"]:
            return [None, None, msgs]
        device["ip"] = device["mgmt-ip"]
        device["port"] = 22
        device["blocking_timeout"] = 30
        device["access_model"] = "sonic_ssh"
        del device["mgmt-ip"]
        self.dut_log(devname, "initiate ssh to {}".format(device["ip"]))
        hndl = self._do_connect_cinfo(device, 2, msgs, devname)
        return [hndl, device["ip"], msgs]

    def _renew_mgmt_ip(self, devname):
        mgmt_ifname = self.get_mgmt_ifname(devname)
        self.wa.hooks.renew_mgmt_ip(devname, mgmt_ifname)

    def _set_mgmt_ip(self, devname, renew=True):
        access = self._get_dev_access(devname)
        access["static-mgmt-ip"] = False

        # no need to set static mgmt ip if not run from terminal
        connection_param = access["connection_param"]
        if not self._is_console_connection(devname):
            return False

        # check if mgmt option is specified in testbed
        mgmt_ipmask = connection_param.get("mgmt_ipmask", None)
        mgmt_gw = connection_param.get("mgmt_gw", None)
        if not mgmt_ipmask or not mgmt_gw:
            if env.get("SPYTEST_ONREBOOT_RENEW_MGMT_IP", "0") != "0":
                if renew:
                    self._renew_mgmt_ip(devname)
            return False

        # no-op when not enabled
        if env.get("SPYTEST_SET_STATIC_IP", "1") != "1":
            return False

        # TODO: check if mgmt is already used in network
        # utils.ipcheck(mgmt)

        prompt = self._enter_linux(devname)
        if prompt is None:
            prompt = self._find_prompt(access, use_cache=False)
        self._set_param(devname, "prompt", prompt)
        self.wa.hooks.set_mgmt_ip_gw(devname, mgmt_ipmask, mgmt_gw)
        access["static-mgmt-ip"] = True
        self.rest_init(devname, access.get("username"), access.get("password"), access.get("altpassword"), False)
        self._gnmi_init(devname, False)
        return True

    def fetch_and_get_mgmt_ip(self, devname, try_again=3, wait_for_ip=0):
        self._fetch_mgmt_ip(devname, try_again=try_again, wait_for_ip=wait_for_ip)
        ip = self.get_mgmt_ip(devname)
        return ip

    def _fetch_mgmt_ip(self, devname, try_again=3, wait_for_ip=0):
        if not self.is_sonic_device(devname) and \
           not self.is_any_fastpath_device(devname): return

        access = self._get_dev_access(devname)
        if self.is_filemode(devname): return

        switched, reconnect = False, True
        try:
            switched = self.tryssh_switch(devname)  # switch to console
            old = access["connection_param"].get("mgmt-ip")
            self._fetch_mgmt_ip2(devname, try_again, wait_for_ip)
            new = access["connection_param"].get("mgmt-ip")
            if old and new and old == new:
                # no need to reconnect to SSH
                reconnect = False
            if switched: self.tryssh_switch(devname, True, reconnect)
        except Exception as e:
            msg = utils.stack_trace(None, True)
            self.dut_warn(devname, msg)
            if switched: self.tryssh_switch(devname, False)
            raise e

    def _fetch_mgmt_ip2(self, devname, try_again=3, wait_for_ip=0):
        access = self._get_dev_access(devname)
        connection_param = access["connection_param"]

        # if the device type is terminal issue ifconfig to get eth0 ip address
        if not self._is_console_connection(devname):
            connection_param["mgmt-ip"] = None
            self.rest_init(devname, access.get("username"), access.get("password"), access.get("altpassword"), True)
            self._gnmi_init(devname, True)
            return

        prompt = self._enter_linux(devname)
        if prompt is None:
            prompt = self._find_prompt(access, use_cache=False)
        self._set_param(devname, "prompt", prompt)
        mgmt_ifname = self.get_mgmt_ifname(devname)
        try:
            output = self.read_mgmt_ip(devname, mgmt_ifname)
            if not output:
                output = []
                raise SPyTestException("Failed to get the ip address of {}".format(mgmt_ifname))
            connection_param["mgmt-ip"] = output
            msg = "MGMT-IP({}) {}".format(mgmt_ifname, connection_param["mgmt-ip"])
            self.dut_log(devname, msg)
            self.rest_init(devname, access.get("username"), access.get("password"), access.get("altpassword"), True)
            self._gnmi_init(devname, True)
            self.check_pending_downloads(devname)
        except Exception:
            msg1 = "Failed to read ip address of {}".format(mgmt_ifname)
            msg2 = "Failed to read ip address of {}..Retrying".format(mgmt_ifname)
            msg = msg2 if try_again > 0 else msg1
            self.dut_warn(devname, msg)
            connection_param["mgmt-ip"] = None
            if try_again > 0:
                if wait_for_ip > 0 or len(output) == 0:
                    # output is present but there is no IP address
                    self.wait(wait_for_ip)
                    try_again = try_again - 1
                    self._fetch_mgmt_ip2(devname, try_again, wait_for_ip)
                    return
            if self.abort_without_mgmt_ip:
                msg = "Cannot proceed without management IP address"
                self._node_fail(devname, None, msg)

    def connect_all_devices(self, faster_init=False, on_except="abort"):

        retry_count = env.get("SPYTEST_CONNECT_DEVICES_RETRY", "10")
        retry_count = utils.parse_integer(retry_count, 10)
        rvs, exps = putils.exec_foreach2(faster_init, on_except, self.topo.duts,
                                         self.connect_to_device, retry_count)[:2]
        failed_devices = []
        for devname in self.topo.duts:
            connected = rvs.pop(0)
            exception = exps.pop(0)
            if not connected:
                msg = "Failed to connect to device"
            elif exception:
                msg = "Error connecting to device"
            else:
                continue
            self.dut_err(devname, msg)
            failed_devices.append(devname)
        if not failed_devices:
            self.logger.info("Connected to All devices")
        return failed_devices

    def _report_error(self, devname, matched_result, cmd):
        if not matched_result:
            return False
        if isinstance(matched_result, list):
            result = matched_result[0]
            if len(matched_result) > 1:
                msgid = matched_result[1]
            else:
                msgid = "config_cmd_error"
        else:
            result = "Fail"
            msgid = matched_result
        if result == "DUTFail":
            self.wa.report_dut_fail_int(devname, True, msgid, cmd)
        elif result == "EnvFail":
            self.wa.report_env_fail_int(devname, True, msgid, cmd)
        elif result == "TGenFail":
            self.wa.report_tgen_fail_int(devname, True, msgid, cmd)
        else:
            self.wa.report_fail_int(devname, True, msgid, cmd)
        return True

    def _report_cmd_fail(self, devname, cmd, line, skip_error_report=False):
        cmd_fail_support = env.get("SPYTEST_CMD_FAIL_RESULT_SUPPORT", "0")
        # 0: disable 1: only in modules 2: session init + modules
        if cmd_fail_support != "0" and not skip_error_report:
            if self.module_start_time or self.tc_start_time or cmd_fail_support != "1":
                self.wa.set_last_report_line(line)
                msg = utils.stack_trace(None, True)
                self.dut_warn(devname, msg)
                self.wa.report_cmd_fail_int(devname, True, "config_cmd_error", cmd)
        msg = "CMDFAIL: {} Ref: {}/{}/{}/{}".format(cmd, cmd_fail_support,
                                                    bool(self.module_start_time), bool(self.tc_start_time), skip_error_report)
        self.dut_dbg(devname, msg)
        raise SPyTestCmdException(cmd)

    def _check_error(self, access, cmd, output, skip_raise, line, skip_error_report=False):
        devname = access["devname"]
        actions = []
        matched_result = None
        matched_err = ""
        matched_severity = None

        # handle strip action
        for err, errinfo in list(access["errors"].items()):
            if not re.compile(errinfo.command).match(cmd): continue
            for action in utils.make_list(errinfo.action):
                if action != "strip": continue
                output = re.sub(errinfo.search, "", output)

        # handle other actions
        for err, errinfo in list(access["errors"].items()):
            if not re.compile(errinfo.command).match(cmd): continue
            actions = []
            for action in utils.make_list(errinfo.action):
                if action != "strip": actions.append(action)
            if re.search(errinfo.search, output):
                matched_err = err
                matched_result = errinfo.get("result", None)
                matched_severity = errinfo.get("severity", None)
                break

        if not matched_err:
            return output

        # check if core-dump and tech-support are needed
        for action in actions:
            if action == "core-dump":
                self.tc_fetch_core_files = True
            if action == "tech-support":
                self.tc_get_tech_support = True
            self.wa.set_module_lvl_action_flags(action)
        for action in actions:
            if action == "reboot":
                self.dut_warn(devname, output)
                self.recover(devname, "Rebooting match {} action".format(matched_err))
                self._report_error(devname, matched_result, cmd)
            elif action == "raise":
                if not self.wa.session_init_completed:
                    msg = "Skipped error checking in session init but detected pattern: {} command: {}".format(matched_err, cmd)
                    self.dut_warn(devname, msg)
                    self.wa.alert(msg, type="IGNORED SESSION INIT ERROR", lvl=logging.WARNING)
                    return output
                if skip_raise:
                    if env.get("SPYTEST_CHECK_SKIP_ERROR", "0") == "0":
                        msg = "Skipped error checking but detected pattern: {} command: {}".format(matched_err, cmd)
                        self.dut_warn(devname, msg)
                        self.wa.alert(msg, type="IGNORED ERROR", lvl=logging.WARNING)
                        return output
                    else:
                        skip_flag = 1
                        if matched_severity is not None and matched_severity <= 3:
                            skip_flag = 0
                        if skip_flag == 1:
                            msg = "Skipped error checking but detected pattern:: {} command: {}".format(matched_err, cmd)
                            self.dut_warn(devname, msg)
                            self.wa.alert(msg, type="IGNORED ERROR", lvl=logging.WARNING)
                            return output
                msg = "Error: failed to execute '{}'".format(cmd)
                self.dut_warn(devname, msg)
                self.dut_warn(devname, output)
                if not self._report_error(devname, matched_result, cmd):
                    cmd2 = cmd.replace("\n", "\\n")
                    msg = "detected pattern: {} executing '{}'".format(matched_err, cmd2)
                    self.dut_err(devname, msg)
                    self.wa.alert(msg, type="ERROR", lvl=logging.ERROR)
                    self._report_cmd_fail(devname, cmd2, line, skip_error_report)

        return ""

    def _trace_cli(self, access, cmd):
        if "spytest-helper.py" in cmd: return
        if cmd.startswith("date -u +"): return
        # trace the CLI commands in CSV file, to be used to measure coverage
        # module,function,cli-mode,command
        try: self.wa._trace_cli(access["dut_name"], access["current_prompt_mode"], cmd)
        except Exception: pass

    def _cli_lock(self, access, cmd, line=None, delay_factor=1, suffix="cli", trace=True):
        detect = env.get("SPYTEST_DETECT_CONCURRENT_ACCESS")
        if detect == "0":
            return True
        cmd = self.cmd_fmt(cmd)
        line = line or utils.get_line_number()
        devname = access["devname"]
        thid = putils.get_thread_name()
        lock_data = access["{}_lock".format(suffix)]
        if not lock_data.lock.acquire(False) and thid != lock_data.thread:
            hindex = self._get_handle_index(devname)
            msg = "Thread '{}' is already executing '{}' @{} handle: {}"
            msg = msg.format(lock_data.thread, lock_data.cmd, line, hindex)
            msgs = [msg, utils.get_call_stack_all(0, "CurrentCallStack:"), lock_data.stack]
            for msg in msgs: self.dut_warn(devname, msg, cond=trace)
            timeout = utils.max(lock_data.max_time, 300)
            if not lock_data.lock.acquire(timeout=timeout):
                msg = "CLI LOCK NOT Acquired even after {} secs for '{}' @{}"
                msgs.insert(0, msg.format(timeout, cmd, line))
                for msg in msgs: self.dut_err(devname, msg, cond=bool(not trace))
                return False
        if detect != "1": self.dut_dbg(devname, "CLI LOCK Acquired for '{}' @{}".format(cmd, line))
        self._cli_lock_data_set(access, 1, cmd, delay_factor, suffix=suffix)
        return True

    def _cli_unlock(self, access, cmd, line=None, suffix="cli"):
        detect = env.get("SPYTEST_DETECT_CONCURRENT_ACCESS")
        if detect == "0":
            return True
        line = line or utils.get_line_number(1)
        devname = access["devname"]
        self._cli_lock_data_set(access, 0, suffix=suffix)
        try:
            access["{}_lock".format(suffix)].lock.release()
            if detect != "1": self.dut_dbg(devname, "CLI LOCK Released after '{}' @{}".format(cmd, line))
        except Exception:
            if detect != "1": self.dut_dbg(devname, "CLI LOCK Release Failed '{}' @{}".format(cmd, line))
        return True

    def _cli_lock_data_set(self, access, phase, cmd="", delay_factor=0, suffix="cli"):
        name = "{}_lock".format(suffix)
        if name not in access:
            access[name] = SpyTestDict(thread="", cmd="", max_time=0, stack=[], lock=putils.Lock())
        lock_data = access[name]
        if phase == 0:
            lock_data.thread = ""
            lock_data.cmd = ""
            lock_data.stack = []
            lock_data.max_time = 0
        else:
            thid = putils.get_thread_name()
            lock_data.thread = thid
            lock_data.cmd = cmd
            lock_data.stack = utils.get_call_stack_all(1, "PreviousCallStack:{}".format(thid))
            lock_data.max_time = max_time_from_delay_factor(delay_factor)
        return cmd

    @staticmethod
    def _traceback_exception(devname, entries, line=None, ex=None, msg=None):
        line1 = line or utils.get_line_number()
        msg1 = [msg or "Exception at {}".format(line1)]
        msg1.extend(utils.stack_trace(entries))
        return msg1

    def _log_exception(self, devname, attempt, ex2, msg, prefix, line, cmd):
        if msg: self.dut_warn(devname, msg)
        t = "Exception: {} occurred {} attempt: {} line: {}\n cmd: {}\n exception: {}"
        msg = t.format(type(ex2).__name__, prefix, attempt, line, cmd, ex2)
        self.dut_warn(devname, msg)

    def _try_send_cr(self, devname, hndl, cmd, attempt, line=None):
        line = line or utils.get_line_number()
        msg = "Trying CR #{} @{} for '{}'".format(attempt, line, cmd)
        self.dut_warn(devname, msg)
        hndl.send_command_timing("")

    def _try_send_ctrl_c(self, devname, hndl, attempt, line=None):
        line = line or utils.get_line_number(1)
        msg = "Trying CTRL+C #{} @{}".format(attempt, line)
        self.dut_warn(devname, msg)
        try:
            hndl.send_command_timing("\x03")
            hndl.clear_buffer()
        except Exception: pass

    def _try_recover_ctrl_c(self, devname, hndl, cmd, attempt, expect_disc, ctrl_c_used, line):
        try:
            if env.get("SPYTEST_RECOVERY_CTRL_C", "1") == "1":
                msg = "Trying CTRL+C: attempt {}..".format(attempt)
                self.dut_warn(devname, msg)
                ctrl_c_used = True
                hndl.send_command_timing("\x03")
                hndl.clear_buffer()
                return True, True
        except Exception as ex2:
            if self.wa.is_shutting_down() or expect_disc:
                return "", ctrl_c_used
            msg = utils.stack_trace(None, True)
            self._log_exception(devname, attempt, ex2, msg, "even after CTRL+C", line, cmd)
        return False, ctrl_c_used

    def _try_recover_cr(self, devname, hndl, cmd, attempt, expect_string,
                        unexpected_prompt, trace_dump, line):
        if attempt != 0: return False, unexpected_prompt
        try:
            self._try_send_cr(devname, hndl, cmd, attempt)
            output1 = self._handle_find_prompt(devname, hndl, attempt, use_cache=False)
            hndl.clear_buffer()
            if self.verify_prompt(devname, hndl, output1)[0]:
                output2 = output1.replace("\\", "")
                msg = "Got the prompt '{}' after trying CR ..".format(output2)
                self.dut_warn(devname, msg)
                line2 = utils.get_line_number()
                self._trace_received(devname, "", hndl, None, None, line2, trace_dump)
                if self.fix_sonic_51743:
                    unexpected_prompt = True
                elif not re.search(expect_string, output2):
                    msg = "Got a prompt '{}' other than required prompt '{}' after trying CR ..".format(output2, expect_string)
                    self.dut_warn(devname, msg)
                    unexpected_prompt = True
                return True, unexpected_prompt
        except Exception as cr_ex:
            msg = "Unable to find prompt even after trying CR .."
            self._log_exception(devname, attempt, cr_ex, msg, "while trying CR", line, cmd)
            line2 = utils.get_line_number()
            self._trace_received(devname, "", hndl, None, None, line2, trace_dump)
        return False, unexpected_prompt

    def _try_prepare(self, devname, attempt, cmd, line):
        reconnect_wait = 5
        if not self._get_handle(devname):
            self.connect_to_device_current(devname)
        if attempt != 0:
            msg = "cmd: {} attempt {} ref: {}".format(cmd, attempt, line)
            self.dut_warn(devname, msg)
            msg = "Disconnecting the device {} connection ..".format(devname)
            self.dut_warn(devname, msg)
            self._disconnect_device(devname)
            msg = "Reconnecting to the device {} ..".format(devname)
            self.dut_warn(devname, msg)
            self.wait(reconnect_wait)
            self.connect_to_device_current(devname)
        hndl = self._get_handle(devname)
        if not hndl:
            msg = "Device not connected: attempt {}..".format(attempt)
            self.dut_warn(devname, msg)
            msg = "Waiting for {} secs before re-attempting connection to Device {}..".format(reconnect_wait, devname)
            self.dut_warn(devname, msg)
            self.wait(reconnect_wait, check_max_timeout=False)
        return hndl

    def _try(self, access, line, fcli, cmd, expect_string,
             delay_factor, expect_disc, try_again, opts, **kwargs):

        devname = access["devname"]
        if self.devices_used_collection:
            self.devices_used_in_tc[devname] = True

        cr_used, ctrl_c_used, unexpected_prompt, silent_crash = False, False, False, False
        output, trace_dump = "", []
        for attempt in range(3):
            try:
                hndl = self._try_prepare(devname, attempt, cmd, line)
                if not hndl: continue
                if attempt != 0:
                    self._try_send_cr(devname, hndl, cmd, attempt)
                    hndl.clear_buffer()
                    break
                if not opts.new_line:
                    output = hndl.send_command_timing(cmd, normalize=False)
                    hndl.clear_buffer()
                    break
                try:
                    self._cli_lock(access, cmd, delay_factor=delay_factor)
                    strip_prompt = kwargs.pop("strip_prompt", opts.strip_prompt)
                    strip_command = kwargs.pop("strip_command", opts.strip_command)
                    normalize = kwargs.pop("normalize", opts.normalize)
                    remove_prompt = kwargs.pop("remove_prompt", opts.remove_prompt)
                    for rm in ["use_timing", "on_cr_recover", "use_send_bytes", "conf_terminal", "skip_error_report", "log_file", "new_line"]:
                        kwargs.pop(rm, None)
                    if opts.use_send_bytes:
                        output = hndl.send_bytes(cmd, normalize=normalize,
                                                 expect_string=expect_string, **kwargs)
                    elif opts.use_timing:
                        output = hndl.send_command_timing(cmd, delay_factor,
                                                          strip_prompt=strip_prompt,
                                                          strip_command=strip_command,
                                                          normalize=normalize, **kwargs)
                    else:
                        new_cmd = self._simulate_errors(devname, cmd)
                        output = hndl.send_command_new(fcli, new_cmd, expect_string,
                                                       delay_factor, remove_prompt=remove_prompt,
                                                       strip_prompt=strip_prompt,
                                                       strip_command=strip_command,
                                                       normalize=normalize, **kwargs)
                    self._trace_cli(access, cmd)
                    self._cli_unlock(access, cmd)
                    hndl.clear_buffer()
                    break
                except Exception as exp:
                    self._cli_unlock(access, cmd)
                    if self.wa.is_shutting_down() or expect_disc: return ""
                    msg = utils.stack_trace(None, True)
                    self._log_exception(devname, attempt, exp, msg, "", line, cmd)
                    self.wa.alert(msg, type="WARN", lvl=logging.ERROR)
                    if "connection closed" in str(exp):
                        self.dut_err(devname, "Remote Connection Closed {}".format(attempt))
                        self._set_handle(devname, None)
                        continue
            except Exception as ex:
                if self.wa.is_shutting_down() or expect_disc: return ""
                msg = utils.stack_trace(None, True)
                self._log_exception(devname, attempt, ex, msg, "", line, cmd)
                if "connection closed" in str(ex):
                    self.dut_err(devname, "Remote connection closed {}".format(attempt))
                    self._set_handle(devname, None)
                    continue

            # verify handle before trying to recover
            hndl = self._get_handle(devname)
            if not hndl: continue

            # try again without faster-cli when we see 'Invalid input detected'
            line2 = utils.get_line_number()
            tmp_trace_dump = self._trace_received(devname, cmd, hndl, None, None, line2)
            if """% Error: Invalid input detected at "^" marker.""" in tmp_trace_dump:
                if attempt == 0:
                    msg = "Retry to rule out any sluggish terminal server issue"
                    self.dut_warn(devname, msg)
                    fcli = 0
                    continue
            trace_dump.append(tmp_trace_dump)

            # count prompt not found
            profile.prompt_nfound(cmd)

            # recover using CR
            cr_used = bool(env.get("SPYTEST_RECOVERY_CR_FAIL", "0") == "1")
            rv, unexpected_prompt = self._try_recover_cr(devname, hndl, cmd, attempt, expect_string,
                                                         unexpected_prompt, trace_dump, line)
            if rv:
                if cmd in ["\n", "\r\n", ""]:
                    cr_used = False  # treat recovery as normal for just new line
                break

            # detect silent crash
            for tmp_trace_dump in trace_dump:
                if unexpected_prompt and "Kernel panic" in tmp_trace_dump:
                    silent_crash = True

            # recover using CTRL+C
            rv, ctrl_c_used = self._try_recover_ctrl_c(devname, hndl, cmd, attempt, expect_disc, ctrl_c_used, line)
            if rv == "": return rv

        if trace_dump:
            self._check_error(access, cmd, nl.join(trace_dump), False, line)

        if cr_used or ctrl_c_used or unexpected_prompt or silent_crash:
            scope = self._get_scope()
            short_cmd = (cmd[:75] + '...') if len(cmd) > 75 else cmd
            msg = "{}: CMD '{}' failed to give prompt try:{} recovered using ".format(scope, short_cmd, try_again)
            if silent_crash:
                mid = "command_failed_silent_crash"
                msg = "{} {} in {}".format(msg, "CTRL+C" if ctrl_c_used else "CR", devname)
            elif ctrl_c_used:
                mid = "command_failed_recovered_using_ctrlc"
                msg = "{} {} in {}".format(msg, "CTRL+C", devname)
            else:
                mid = "command_failed_recovered_using_cr"
                msg = "{} {} in {}".format(msg, "CR", devname)

            # default: check with feature API 0 fail: bailout ignore: ignore
            # retry/retry<num>: retry once or given number of times and fall back to default
            # retry-fail/retry<num>-fail: retry once or given number of times and fall back to fail
            if env.match("SPYTEST_RECOVERY_CR_PER_CMD_POST_OP", "1", "1"):
                on_cr_recover = opts.on_cr_recover
                match1 = re.match(r'retry(\d+)-fail', on_cr_recover)
                match2 = re.match(r'retry(\d+)', on_cr_recover)
                match3 = re.match(r'retry(\d+)-ignore', on_cr_recover)
                if on_cr_recover == "retry0":
                    app_direction = self.wa.hooks.post_cli_recovery(devname, scope, cmd, try_again)
                    opts.on_cr_recover = "default"
                elif on_cr_recover == "retry0-fail":
                    app_direction = True
                elif match1:
                    app_direction = None
                    opts.on_cr_recover = "retry{}-fail".format(int(match1.group(1)) - 1)
                elif match2:
                    app_direction = None
                    opts.on_cr_recover = "retry{}".format(int(match2.group(1)) - 1)
                elif match3:
                    app_direction = True
                    opts.on_cr_recover = "retry{}-ignore".format(int(match3.group(1)) - 1)
                elif on_cr_recover == "ignore":
                    app_direction = False
                elif on_cr_recover == "fail":
                    app_direction = True
                elif on_cr_recover == "retry":
                    app_direction = None
                    opts.on_cr_recover = "default"
                elif on_cr_recover == "retry-fail":
                    app_direction = None
                    opts.on_cr_recover = "fail"
                else:
                    app_direction = self.wa.hooks.post_cli_recovery(devname, scope, cmd, try_again)
            else:
                app_direction = self.wa.hooks.post_cli_recovery(devname, scope, cmd, try_again)

            self.dut_dbg(devname, "{} direction:{}".format(msg, app_direction))
            if app_direction is False:
                self.dut_warn(devname, "{} -- Ignoring".format(msg))
            elif app_direction is None:
                self.dut_warn(devname, "{} -- Retrying".format(msg))
                return self._try(access, line, fcli, cmd, expect_string,
                                 delay_factor, expect_disc, try_again + 1, opts, **kwargs)
            elif self.module_start_time:
                if not self.flagit(devname, "get-tech-support", True, True):
                    self.dut_warn(devname, "{} -- SKIP Reporting".format(msg))
                else:
                    self.dut_err(devname, "{} -- Reporting".format(msg))
                    self.wa.report_config_fail_int(devname, True, mid, cmd)
            elif self.wa.session_init_completed:
                if not self.flagit(devname, "get-tech-support", True, True):
                    self.dut_warn(devname, "{} -- SKIP reporting".format(msg))
                else:
                    self.dut_err(devname, "{} -- reporting".format(msg))
                    self.wa.report_fail_int(devname, True, mid, cmd)
            else:
                if self.wa.is_tech_support_onerror("on_cr_recover"):
                    self.generate_tech_support(devname, "cmdfail")
                self.dut_err(devname, "{} -- DEAD".format(msg))
                self._node_fail(devname, mid, msg)

        return output

    def _get_scope(self):
        if not self.wa.session_init_completed: return "session"
        if self.module_start_time: return "module"
        return "function"

    def run_opts(self, opts, **kwargs):
        opts = opts or SpyTestDict()
        # opts.line = kwargs.get("line", opts.get("line", None))
        # opts.fcli = kwargs.get("fcli", opts.get("fcli", True))
        # opts.try_again = kwargs.get("try_again", opts.get("try_again", 0))
        opts.log_file = kwargs.get("log_file", opts.get("log_file", None))
        opts.remove_prompt = kwargs.get("remove_prompt", opts.get("remove_prompt", False))
        opts.on_cr_recover = kwargs.get("on_cr_recover", opts.get("on_cr_recover", "default"))
        opts.use_timing = kwargs.get("use_timing", opts.get("use_timing", False))
        opts.use_send_bytes = kwargs.get("use_send_bytes", opts.get("use_send_bytes", False))
        opts.strip_prompt = kwargs.get("strip_prompt", opts.get("strip_prompt", True))
        opts.strip_command = kwargs.get("strip_command", opts.get("strip_command", True))
        opts.new_line = kwargs.get("new_line", opts.get("new_line", True))
        opts.normalize = kwargs.get("normalize", opts.get("normalize", True))
        opts.skip_error_report = kwargs.get("skip_error_report", opts.get("skip_error_report", False))
        opts.conf_terminal = kwargs.get("conf_terminal", opts.get("conf_terminal", False))
        return opts

    def _send_command_confirm(self, access, cmd, expect, **kwargs):
        confirm_info = self._parse_confirm(kwargs.pop("confirm", None))
        if not confirm_info:
            return self._send_command(access, cmd, expect, **kwargs)
        op_lines = []
        expect_prompts = [expect]
        expect_prompts.extend(list(confirm_info.keys()))
        expect_confirm = "|".join(expect_prompts)
        op = self._send_command(access, cmd, expect_confirm, **kwargs)
        op_lines.append(op)
        match_again = True
        while match_again:
            match_again = False
            for prompt, confirm in confirm_info.items():
                confirm_cmd = str(confirm)
                if not re.match(prompt, op.strip(), re.IGNORECASE | re.DOTALL):
                    continue
                match_again = True
                op = self._send_command(access, confirm_cmd, expect,
                                        strip_prompt=False, strip_command=False,
                                        normalize=True, **kwargs)
                op_lines.append(op)
        return nl.join(op_lines)

    def _send_command(self, access, cmd, expect=None, skip_error_check=False,
                      delay_factor=0, trace_log=None, ufcli=True, line=None,
                      expect_disc=False, opts=None, **kwargs):
        output = ""

        opts = opts or self.run_opts(None, **kwargs)
        trace_log = trace_log or self.default_trace_log

        # use default delay factor if not specified
        delay_factor = 2 if delay_factor == 0 else delay_factor
        fcli = self.get_fcli() if ufcli else 0
        line = line or utils.get_line_number()

        devname = access["devname"]

        if access["conf_session"] or access["force_conf_session"]:
            if not access["force_conf_terminal"] and not opts.conf_terminal:
                cmd = cmd.replace("configure terminal", "configure session")

        if trace_log in [1, 3]:
            trace_cmd = self.cmd_fmt(cmd)

            # disable faster-cli if there are new lines or with higher timeout
            if not fcli or is_scmd(delay_factor):
                self.cmd_log(devname, False, trace_cmd, opts.log_file)
            elif cmd.count(nl) > 0:
                self.cmd_log(devname, False, trace_cmd, opts.log_file)
                fcli = 0
            else:
                self.cmd_log(devname, True, trace_cmd, opts.log_file)

        if not self.is_filemode(devname):
            expect = expect or self._get_param(devname, "prompt")

            pid = profile.start(cmd, access["dut_name"])
            # self.dut_log(devname, "EXPECT: {}".format(expect))
            output = self._try(access, line, fcli, cmd, expect,
                               delay_factor, expect_disc, 0, opts, **kwargs)
            self.profiling_stop(pid, False)

            if trace_log in [2, 3]:
                self.cli_log(devname, output, opts.log_file)

            self.check_timeout(access)

        else:
            self._trace_cli(access, cmd)
            if self.dry_run_cmd_delay > 0:
                time.sleep(self.dry_run_cmd_delay)

        output = self._check_error(access, cmd, output, skip_error_check, line,
                                   skip_error_report=opts.skip_error_report)

        return output

    def do_pre_rps(self, devname, op):
        self.tryssh_switch(devname)

    def do_post_rps(self, devname, op, dead=False):
        if op not in ["off"]:
            self.dut_warn(devname, "Reconnecting after RPS reboot")
            rps_flag = False
            index = 0
            rps_reboot_static_wait = 30
            while index < 3:
                if self.reconnect(devname, recover=False):
                    rps_flag = True
                    break
                msg = "Waiting for '{}' secs after RPS reboot.".format(rps_reboot_static_wait)
                self.dut_warn(devname, msg)
                self.wait(rps_reboot_static_wait)
                index = index + 1
            if not rps_flag:
                msg = "Failed to reconnect after RPS reboot"
                if dead:
                    self._node_fail(devname, "console_hang_node_dead", msg)
                else:
                    self.dut_err(devname, msg)
                return rps_flag
            self._enter_linux(devname)
            self.do_common_init(devname)
            self.tryssh_switch(devname, True)
        return True

    def reconnect(self, devname=None, retry=0, recover=True):
        if not devname or isinstance(devname, list):
            if not devname:
                devlist = self.topo.duts
            else:
                devlist = devname

            for _devname in devlist:
                connected = self.reconnect(_devname, retry, recover)
                if not connected:
                    msg = "Error reconnecting to device"
                    self.dut_log(_devname, msg)
                    return False
        elif devname in self.topo.duts:
            hndl = self._get_handle(devname)
            if hndl:
                hndl.disconnect()
                self._set_handle(devname, None)
            connected = self.connect_to_device_current(devname, retry, recover)
            if not connected:
                msg = "Error reconnecting to device"
                self.dut_log(devname, msg)
                return False
        return True

    def _abort_klish(self, devname, prompt=None):
        devname = self._check_devname(devname)
        access = self._get_dev_access(devname)
        value = access["conf_session"]
        # enter into configure session and abort
        access["conf_session"] = True
        self._enter_linux(devname)
        self._config(devname, "abort no-prompt", type="klish", conf=True, expect_mode="mgmt-user")
        access["conf_session"] = value

    def _exit_klish(self, devname, prompt=None):
        access = self._get_dev_access(devname)
        if self.is_filemode(devname):
            return True

        dbg = self.debug_find_prompt

        prompt = self._find_prompt(access)
        if not prompt:
            prompt = self._find_prompt(access, use_cache=False)
        prompt2 = prompt.replace("\\", "")
        self.dut_log(devname, "prompt = '{}'".format(prompt), cond=dbg)
        self.dut_log(devname, "prompt2 = '{}'".format(prompt2), cond=dbg)
        hndl = self._get_handle(devname)

        msg = "Trying to change from prompt({})".format(prompt2)
        self.dut_dbg(devname, msg)

        new_prompt = None
        try:
            for cmd in ["end", "exit"]:
                if env.get("SPYTEST_RECOVERY_CTRL_C", "1") == "1":
                    hndl.send_command_timing("\x03")
                self.dut_dbg(devname, "> {}".format(cmd))
                hndl.send_command_timing(cmd)
            new_prompt = self._find_prompt(access, use_cache=False)
        except Exception:
            pass

        msg = "prompt after change({})".format(new_prompt.replace("\\", ""))
        self.dut_dbg(devname, msg)
        self._set_last_prompt(access, new_prompt)
        return new_prompt

    def _net_login(self, devname, hndl):
        self._set_handle(devname, hndl)
        self._enter_linux(devname)

    def _enter_linux(self, devname, prompt=None, dbg=None):
        for _ in range(10):
            rv, known_prompt = self._enter_linux_once(devname, prompt, dbg)
            if rv: return known_prompt
            prompt = known_prompt
        return None

    def _enter_linux_once(self, devname, prompt=None, dbg=None):
        access = self._get_dev_access(devname)
        if self.is_filemode(devname):
            return True, None

        dbg = dbg or self.debug_find_prompt

        if not prompt:
            prompt = self._find_prompt(access, use_cache=False)
        prompt2 = prompt.replace("\\", "")
        msg = "prompt = '{}' prompt2 = '{}'".format(prompt, prompt2)
        self.dut_log(devname, msg, cond=dbg)

        cli_prompt = self._get_cli_prompt(devname)
        self.dut_log(devname, "cli_prompt = {}".format(cli_prompt), cond=dbg)
        self.dut_log(devname, "list prompt = {}".format([prompt, prompt2]), cond=dbg)
        if cli_prompt in [prompt, prompt2]:
            self._set_last_prompt(access, cli_prompt)
            return True, None

        if re.compile(lldp_prompt).match(prompt2):
            try:
                cli_prompt = self._get_cli_prompt(devname)
                self._send_command(access, "exit", cli_prompt)
                self._set_last_prompt(access, cli_prompt)
            except Exception:
                self._set_last_prompt(access, None)
            return True, None

        if sonic_mgmt_hostname in prompt2:
            try:
                self._exit_klish(devname, prompt)
            except Exception:
                self._set_last_prompt(access, None)
            return True, None

        if self.is_vtysh_prompt(access, prompt2):
            try:
                self._exit_vtysh(devname)
            except Exception:
                self._set_last_prompt(access, None)
            return True, None

        rv, known_prompt, auth, sent_pass = True, None, [], None
        regex_login = self.wa.hooks.get_regex(devname, "login")
        regex_anyprompt = self.wa.hooks.get_regex(devname, "anyprompt")
        default_pass = self.wa.hooks.get_default_pass(devname)
        expect = [regex_login, regex_password, regex_anyprompt, r"\(current\) UNIX password:\s*"]
        expect = "|".join(expect)
        auth.append([access["username"], access["password"]])
        auth.append([access["username"], access["altpassword"]])
        if access.get("oniepassword", None) is not None:
            auth.append(["root", access["oniepassword"]])
        if default_pass is not None:
            auth.append([access["username"], default_pass])
        for index in range(len(auth)):
            if re.compile(regex_login).match(prompt2):
                self.dut_log(devname, "enter username {}".format(auth[index][0]), cond=dbg)
                output = self._send_command(access, auth[index][0], expect,
                                            strip_prompt=False, ufcli=False, use_cache=False,
                                            on_cr_recover="ignore")
                if prompt2 in output: return False, known_prompt
                self.dut_log(devname, "enter password {}".format(auth[index][1]), cond=dbg)
                sent_pass = auth[index][1]
                output = self._send_command(access, auth[index][1], expect, ufcli=False,
                                            skip_error_check=True, strip_prompt=False,
                                            use_cache=False, on_cr_recover="ignore")
                self.dut_log(devname, "login output:='{}'".format(output), cond=dbg)
                if "bash: {}: command not found".format(auth[index][1]) in output:
                    self.dut_warn(devname, "Logged into system without password")
                    self._set_last_prompt(access, None)
                    self.init_normal_prompt(devname)
                    break
                if prompt2 not in output:
                    if index == 0 or auth[index][1] == default_pass:
                        rv, rv2, output = self._change_default_pwd(devname, auth[0][1], auth[1][1], output)
                    elif index == 1:
                        rv, rv2, output = self._change_default_pwd(devname, auth[1][1], auth[0][1], output)
                    else:
                        rv2 = False
                    self._set_last_prompt(access, None)
                    self.dut_log(devname, "login output='{}'".format(output), cond=dbg)
                    if rv2 or (prompt2 not in output and not re.search(regex_password_anywhere, output)):
                        self.init_normal_prompt(devname)
                        break
            elif re.compile(regex_password).match(prompt2):
                self.dut_log(devname, "enter password {}".format(auth[index][1]), cond=dbg)
                sent_pass = auth[index][1]
                output = self._send_command(access, auth[index][1], expect, ufcli=False,
                                            strip_prompt=False, use_cache=False,
                                            on_cr_recover="ignore")
                self.dut_log(devname, "password output:='{}'".format(output), cond=dbg)
                if index == 0 or auth[index][1] == default_pass:
                    rv, rv2, output = self._change_default_pwd(devname, auth[0][1], auth[1][1], output)
                elif index == 1:
                    rv, rv2, output = self._change_default_pwd(devname, auth[1][1], auth[0][1], output)
                else:
                    rv2 = False
                self._set_last_prompt(access, None)
                self.dut_log(devname, "password output='{}'".format(output), cond=dbg)
                if rv2 or (prompt2 not in output and not re.search(regex_password_anywhere, output)):
                    self.init_normal_prompt(devname)
                    break
            else:
                self.dut_log(devname, "neither username nor password", cond=dbg)
                output = ""
                known_prompt = prompt

        # check if the password is entered
        if sent_pass:
            self.dut_log(devname, "Authenticated using '{}'".format(sent_pass))
            if sent_pass in [access["password"], access["altpassword"]]:
                self.post_login(devname)

        msg = "prompt2 is not seen in output '{}'"
        self.dut_log(devname, msg.format(output), cond=dbg)
        return rv, known_prompt

    def _change_default_pwd(self, devname, pwd, altpwd, output):
        access = self._get_dev_access(devname)
        device = access["devname"]
        line = utils.get_line_number()

        try:
            hndl = self._get_handle(device)
            hndl.password = pwd
            hndl.altpassword = altpwd
            rv, output = hndl.extended_login(output)
            return True, rv, output
        except Exception:
            msg1 = utils.stack_trace(None, True)
            msg2 = "Failed to change default password."
            msg2 = msg2 + " Unexpected messages on console - trying to recover"
            self._trace_received(device, "change_default_pwd", hndl, msg1, msg2, line)
            return False, False, ""

    @staticmethod
    def is_vtysh_prompt(access, prompt):
        hostname = access.get("hostname", "sonic")
        for pattern in [r'(sonic|{})#', r'(sonic|{})\(config[^)]*\)#']:
            if re.compile(pattern.format(hostname)).match(prompt):
                return True
        return False

    def _exit_vtysh(self, devname, onconnect=0, prompt=None):
        if self.is_filemode(devname):
            return

        access = self._get_dev_access(devname)
        prompt_terminator = self.wa.hooks.get_regex(devname, "anyprompt")
        if onconnect:
            self._send_command(access, end_exit, prompt_terminator, use_cache=False)
            self._set_last_prompt(access, None)
            return

        prompt = self._find_prompt(access)
        if not prompt:
            prompt = self._find_prompt(access, use_cache=False)

        prompt2 = prompt.replace("\\", "")
        if re.compile(regex_password).match(prompt2):
            self._send_command(access, access["password"], prompt_terminator, ufcli=False)

        if self.is_vtysh_prompt(access, prompt2):
            self._send_command(access, end_exit, prompt_terminator)
            self._set_last_prompt(access, None)

    def _set_last_prompt(self, access, prompt, mode=None):
        access["last-prompt"] = prompt
        if mode and "vtysh" in mode:
            access["last-prompt"] = None  # TEMP#
        if prompt:
            self._set_current_prompt_mode(access, prompt)

    def _set_current_prompt_mode(self, access, prompt):
        try:
            devname = access["devname"]
            access["current_prompt_mode"] = self.get_mode_for_prompt(devname, prompt)
        except Exception:
            access["current_prompt_mode"] = "unknown-prompt"

    def _exec_mode_change(self, devname, l_cmd, to_prompt, from_prompt):
        devname = self._check_devname(devname)
        access = self._get_dev_access(devname)
        expect = "|".join([from_prompt, to_prompt])
        self._send_command(access, l_cmd, expect, True, ufcli=False)
        prompt = self._find_prompt(access, use_cache=False)
        if prompt == from_prompt:
            raise SPyTestException("Failed to change mode")

    def change_prompt(self, devname, tomode=None, **kwargs):
        devname = self._check_devname(devname)
        access = self._get_dev_access(devname)
        access["force_conn_index"] = kwargs.get("conn_index", None)
        access["force_conf_session"] = kwargs.get("conf_session", False)
        access["force_conf_terminal"] = kwargs.get("conf_terminal", False)
        access["force_confirm"] = kwargs.get("confirm", None)
        self.last_mode[devname] = self._change_prompt(devname, tomode, None, **kwargs)
        return self.last_mode[devname]

    def _send_mode_command(self, access, cmd, expected_prompt, from_prompt, ident, tomode=None):
        line = utils.get_line_number()
        confirm = access["force_confirm"]
        self.trace_callback_set_debug(access["devname"], True)
        opts = self.addl_mode_change_kwargs.get(tomode, {})
        output = self._send_command_confirm(access, cmd, expected_prompt, line=line, confirm=confirm, **opts)
        cmd = self.addl_mode_change_cmds.get(tomode, "")
        if cmd:
            msg = "Change Mode({}) cmd: {} expected: {} tomode: {}, opts: {}"
            self.dut_dbg(access["devname"], msg.format(ident, cmd, expected_prompt, tomode, opts))
            self._send_command_confirm(access, cmd, expected_prompt, line=line, confirm=confirm, **opts)
        self.trace_callback_set_debug(access["devname"], False)
        return output

    def get_prompt_for_mode(self, devname, mode, ifname_type=None, index=None):
        devname = self._check_devname(devname)
        access = self._get_dev_access(devname)
        index = self._check_handle_index(devname, index)
        role = self.get_user_role(devname, conn_index=index)
        retval = access["prompts"].get_prompt_for_mode(mode, ifname_type, index, role)
        if self.debug_find_prompt:
            msg = "Prompt={} for mode={} index={} role={}"
            self.dut_dbg(devname, msg.format(retval, mode, index, role))
        return retval

    def get_mode_for_prompt(self, devname, prompt, index=None):
        devname = self._check_devname(devname)
        access = self._get_dev_access(devname)
        index = self._check_handle_index(devname, index)
        role = self.get_user_role(devname, conn_index=index)
        retval = access["prompts"].get_mode_for_prompt(prompt, index, role)
        if self.debug_find_prompt:
            msg = "Mode={} for prompt={} index={} role={}"
            self.dut_dbg(devname, msg.format(retval, prompt, index, role))
        return retval

    def _change_prompt(self, devname, tomode=None, startmode=None, **kwargs):
        devname = self._check_devname(devname)
        access = self._get_dev_access(devname)
        prompts = access["prompts"]
        ifname_type = self.wa.get_ifname_type(devname)

        dbg = self.debug_find_prompt

        if self.is_filemode(devname):
            self.dut_log(devname, tomode)
            return None

        # Identify the current prompt
        if startmode:
            prompt = self.get_prompt_for_mode(devname, startmode, ifname_type)
        else:
            prompt = None

        # Identify the current mode
        if not prompt or prompt == "unknown-mode":
            for _ in range(3):
                prompt = self._find_prompt(access, use_cache=False)
                last_prompt = None
                if self.last_mode.get(devname):
                    last_prompt = self.get_prompt_for_mode(devname, self.last_mode.get(devname), ifname_type)
                if last_prompt and re.match(last_prompt, prompt.replace("\\", "")):
                    startmode = self.last_mode.get(devname)
                else:
                    startmode = self.get_mode_for_prompt(devname, prompt)
                if startmode != "unknown-prompt":
                    break

        if startmode == "unknown-prompt":
            msg = "Current prompt pattern ({}) not found in patterns dict."
            self.dut_err(devname, msg.format(prompt))
            return "unknown-prompt"

        check_modes_movement_for_default_mode = False
        abort_on_missing_req_args = True

        # Return current mode when no prompt is given for change.
        if not tomode:
            if not check_modes_movement_for_default_mode:
                msg = "Returning current mode {} as provided tomode is None.".format(startmode)
                self.dut_dbg(devname, msg, cond=dbg)
                access["current_prompt_mode"] = startmode
                return startmode
            abort_on_missing_req_args = False
            tomode = startmode

        # Return invalid if given prompt is not present.
        if tomode not in prompts.patterns:
            msg = "Prompt '{}' pattern not found.".format(tomode)
            self.dut_err(devname, msg)
            return "unknown-mode"

        # Check whether the arguments given for prompt change are valid or not?
        prompts.check_args_for_req_mode(abort_on_missing_req_args, tomode, **kwargs)

        # Check whether do we need to move previous level to come back to same prompt with different values.
        if startmode == "login_prompt":
            start_prompt = self.get_prompt_for_mode(devname, startmode, ifname_type)
            msg = "DUT enterted into '{}({})'. Recovering to normal mode.".format(startmode, start_prompt)
            self.dut_err(devname, msg)
            self._enter_linux(devname)
            prompt = self._find_prompt(access, use_cache=False)
            startmode = self.get_mode_for_prompt(devname, prompt)
            if startmode == "unknown-prompt":
                return "unknown-prompt"
            self.set_login_timeout(devname)

        # Check whether do we need to move previous level to come back to same prompt with different values.
        if startmode == tomode:
            change_required = prompts.check_move_for_parent_of_from_mode(prompt, startmode, **kwargs)
            if change_required:
                cmd, expected_prompt = prompts.get_backward_command_and_prompt(startmode, ifname_type)
                ident = "re-enter with different value"
                self._send_mode_command(access, cmd, expected_prompt, prompt, ident, tomode)
                startmode = prompts.get_mode(startmode, ifname_type)[0]
            else:
                msg = "Returning as current mode is equal to required mode."
                self.dut_dbg(devname, msg, cond=dbg)
                access["current_prompt_mode"] = tomode
                return tomode
        else:
            # Check whether do we need to go back to parent for both the modes.
            change_required = prompts.check_move_for_parent_of_to_mode(prompt, tomode, ifname_type, **kwargs)
            if change_required:
                if startmode != prompts.get_mode(tomode, ifname_type)[0]:
                    required_mode = prompts.get_mode(tomode, ifname_type)[0]
                else:
                    required_mode = prompts.get_mode(startmode, ifname_type)[0]
                while startmode != required_mode and prompts.get_mode(startmode, ifname_type)[0] != "":
                    cmd, expected_prompt = prompts.get_backward_command_and_prompt(startmode, ifname_type)
                    ident = "goto parent mode"
                    self._send_mode_command(access, cmd, expected_prompt, prompt, ident, required_mode)
                    startmode = prompts.get_mode(startmode, ifname_type)[0]

        # Identify the list of backward and forward modes we need to move.
        modeslist_1 = []
        srcMode = startmode
        while srcMode != "":
            modeslist_1.append(srcMode)
            if srcMode in prompts.modes:
                srcMode = prompts.get_mode(srcMode, ifname_type)[0]
                continue
            srcMode = ""

        modeslist_2 = []
        dstMode = tomode
        while dstMode != "":
            modeslist_2.insert(0, dstMode)
            if dstMode in prompts.modes:
                dstMode = prompts.get_mode(dstMode, ifname_type)[0]
                continue
            dstMode = ""

        backward_modes = []
        forward_modes = copy.copy(modeslist_2)
        for mode in modeslist_1:
            if mode in forward_modes:
                forward_modes.remove(mode)
                continue
            backward_modes.append(mode)

        if dbg:
            self.dut_log(devname, "Modes_1: {}".format(modeslist_1))
            self.dut_log(devname, "Modes_2: {}".format(modeslist_2))
            self.dut_log(devname, "backward_modes: {}".format(backward_modes))
            self.dut_log(devname, "forward_modes: {}".format(forward_modes))

        # Add alt_port_names when arg 'range' in used
        if 'range' in kwargs:
            kwargs['alt_port_names'] = self.wa.alt_port_names[devname]

        # Move back for each backward mode.
        for mode in backward_modes:
            cmd, expected_prompt = prompts.get_backward_command_and_prompt(mode, ifname_type)
            if not cmd.strip() or not expected_prompt.strip():
                continue
            self._send_mode_command(access, cmd, expected_prompt, prompt, "backward")

        # Move ahead for each forward mode.
        # Get the command by substituting with required values from the given arguments.
        for mode in forward_modes:
            cmd, expected_prompt = prompts.get_forward_command_and_prompt_with_values(mode, ifname_type, **kwargs)
            if not cmd.strip() or not expected_prompt.strip():
                continue
            self._send_mode_command(access, cmd, expected_prompt, prompt, "forward", mode)

        # Identify the current prompt, check and return appropriately.
        for _ in range(3):
            prompt = self._find_prompt(access, use_cache=False).replace("\\", "")
            expected_prompt = self.get_prompt_for_mode(devname, tomode, ifname_type)
            if re.match(expected_prompt, prompt):
                endmode = tomode
            else:
                endmode = self.get_mode_for_prompt(devname, prompt)
            if endmode != "unknown-prompt":
                break

        if endmode == tomode:
            msg = "Successfully changed the prompt from {} to {}.".format(startmode, endmode)
            self.dut_dbg(devname, msg)
            access["current_prompt_mode"] = tomode
            return tomode
        return "unknown-mode"

    def cli_config(self, devname, cmd, mode=None, skip_error_check=False, delay_factor=0, **kwargs):
        devname = self._check_devname(devname)
        access = self._get_dev_access(devname)
        prompts = access["prompts"]
        ifname_type = self.wa.get_ifname_type(devname)

        if self.is_filemode(devname):
            self.dut_log(devname, cmd)
            return ""

        frommode = self.change_prompt(devname, mode, **kwargs)
        if frommode not in ["unknown-mode", "unknown-prompt"]:
            if frommode in prompts.sudo_include_prompts:
                if not cmd.startswith("sudo "):
                    cmd = "sudo " + cmd
            expected_prompt = self.get_prompt_for_mode(devname, frommode, ifname_type)
            output = self._send_command(access, cmd, expected_prompt, skip_error_check, delay_factor=delay_factor)
            return output
        msg = "Unable to change the prompt mode to {}.".format(mode)
        self.dut_err(devname, msg)
        raise ValueError(msg)

    def _add_no_more(self, cmd):
        if self.use_no_more and not re.search(r"\| no-more$", cmd.strip()):
            if cmd.startswith("show ") or cmd.startswith("do show "):
                cmd = cmd + " | no-more"
        return cmd

    def cli_show(self, devname, cmd, mode=None, skip_tmpl=False, skip_error_check=False, delay_factor=0, yes_no='y', **kwargs):
        line = utils.get_line_number(3)
        return self._cli_show(line, devname, cmd, mode, skip_tmpl, skip_error_check, delay_factor, yes_no, **kwargs)

    def _cli_show(self, line, devname, cmd, mode=None, skip_tmpl=False, skip_error_check=False, delay_factor=0, yes_no='y', **kwargs):
        devname = self._check_devname(devname)
        access = self._get_dev_access(devname)
        prompts = access["prompts"]
        ifname_type = self.wa.get_ifname_type(devname)

        if self.is_filemode(devname):
            self.dut_log(devname, cmd)
            return ""

        frommode = self.change_prompt(devname, mode, **kwargs)
        if frommode not in ["unknown-mode", "unknown-prompt"]:
            actual_cmd = cmd
            if frommode.startswith("mgmt"):
                cmd = self._add_no_more(cmd)
            if frommode not in prompts.do_exclude_prompts:
                if not cmd.startswith("do "):
                    cmd = "do " + cmd
            expected_prompt = self.get_prompt_for_mode(devname, frommode, ifname_type)
            output = self._send_command(access, cmd, expected_prompt,
                                        skip_error_check, delay_factor=delay_factor)
            if '[y/N]:' in output:
                output += self._send_command(access, yes_no, expected_prompt,
                                             skip_error_check, delay_factor=delay_factor)
            output = self._fill_sample_data(devname, cmd, skip_error_check,
                                            skip_tmpl, output, line)
            if skip_tmpl:
                return output
            return self._tmpl_apply(devname, actual_cmd, output)
        msg = "Unable to change the prompt mode to {}.".format(mode)
        self.dut_err(devname, msg)
        raise ValueError(msg)

    def _check_devname(self, devname):
        if devname != "":
            # todo verify
            return devname
        for d in self.topo.duts:
            return d
        return None

    def _trace_tmpl(self, cmd, tmpl):
        msg = "TEMPLATE USED: {}: {}".format(tmpl, cmd)
        if cmd not in self.cmd_tmpl_cache:
            self.wa._ftrace(msg)
        self.cmd_tmpl_cache[cmd] = tmpl
        return msg

    def _tmpl_apply(self, devname, cmd, output, tmpl=None):
        try:
            if tmpl is not None:
                _, parsed = self.tmpl[devname].apply_textfsm(tmpl, output)
            else:
                tmpl, parsed = self.tmpl[devname].apply(output, cmd)
            msg = self._trace_tmpl(cmd, tmpl)
            self.dut_log(devname, msg, lvl=LEVEL_TXTFSM)
            self.dut_log(devname, str(parsed), lvl=LEVEL_TXTFSM)
            if env.get("SPYTEST_SAVE_TEMPLATE_SAMPLES", "0") != "0":
                path = self.get_logs_path(devname, "templates")
                self.tmpl[devname].save_sample(tmpl, cmd, output, parsed, path)
            return parsed
        except Exception:
            if cmd.startswith("sudo -s "):
                return self._tmpl_apply(devname, cmd[8:], output, tmpl)
            if cmd.startswith("sudo "):
                return self._tmpl_apply(devname, cmd[5:], output, tmpl)
            self.dut_err(devname, utils.stack_trace(None, True))
            return output

    def _fill_sample_data(self, devname, cmd, skip_error_check,
                          skip_tmpl, output, line):
        if self.cfg.filemode and not output and self.use_sample_data:
            tmpl, output = self.tmpl[devname].read_sample(cmd)
            if not output and cmd.startswith("sudo -s "):
                tmpl, output = self.tmpl[devname].read_sample(cmd[8:])
            elif not output and cmd.startswith("sudo "):
                tmpl, output = self.tmpl[devname].read_sample(cmd[5:])
            if output:
                self.dut_log(devname, output)
                access = self._get_dev_access(devname)
                output = self._check_error(access, cmd, output, skip_error_check, line)
            elif cmd not in self.cmd_tmpl_cache:
                if skip_tmpl:
                    msg = "SKIP SAMPLE DATA: {}: {}".format(tmpl, cmd)
                else:
                    msg = "ADD SAMPLE DATA: {}: {}".format(tmpl, cmd)
                self.wa._ftrace(msg)
                self.dut_warn(devname, msg)
            self._trace_tmpl(cmd, tmpl)
        return output or ""

    def erase_config(self, devname, erase=True, reboot=True):
        self._set_config_erase(devname)
        if erase:
            self._config(devname, "config erase install -y")
        if reboot:
            self.reboot(devname)
        return True

    def clear_config(self, devname, method="reload"):
        return self.apply_remote(devname, "apply-base-config", [method])

    def config_db_reload(self, devname, save=False, max_time=0):
        devname = self._check_devname(devname)
        access = self._get_dev_access(devname)

        save_cmd = 'sudo config save -y'
        reload_cmd = 'sudo config reload -y'

        if env.get("SPYTEST_HELPER_CONFIG_DB_RELOAD", "yes") != "no":
            largs = ["yes" if save else "no", max_time]
            output = self.apply_remote(devname, "config-reload", largs)
            return output

        if self.is_filemode(devname):
            if save:
                self.dut_log(devname, save_cmd)
            self.dut_log(devname, reload_cmd)
            return True

        # ensure we are in sonic mode
        self._enter_linux(devname)

        prompt = self._get_cli_prompt(devname)
        if save:
            self._send_command(access, save_cmd, prompt, False, 1)

        output = self._send_command(access, reload_cmd, prompt, True, 9)

        return output

    def apply_script(self, devname, cmdlist):
        devname = self._check_devname(devname)
        if self.is_filemode(devname):
            for cmd in cmdlist:
                self.dut_log(devname, cmd)
            return

        # ensure we are in sonic mode
        self._enter_linux(devname)

        mode_flag = ""
        for cmd in cmdlist:
            if not cmd.strip():
                continue

            if cmd == "vtysh" or cmd == "sudo vtysh":
                mode_flag = "vtysh"
                continue
            elif cmd.startswith("sonic-cli"):
                mode_flag = "klish"
                continue
            elif cmd.startswith("sudo sonic-cli"):
                mode_flag = "klish"
                continue
            elif cmd == "configure terminal" and mode_flag == "vtysh":
                mode_flag = "vtysh-config"
                continue
            elif cmd == "configure terminal" and mode_flag == "klish":
                mode_flag = "klish-config"
                continue

            if mode_flag == "vtysh-config":
                self._config(devname, cmd, type="vtysh", conf=True, conf_terminal=True)
            elif mode_flag == "vtysh":
                self._config(devname, cmd, type="vtysh", conf=False)
            elif mode_flag == "klish-config":
                self._config(devname, cmd, type="klish", conf=True)
            elif mode_flag == "klish":
                self._config(devname, cmd, type="klish", conf=False)
            else:
                self._config(devname, cmd)

            current_mode = self._change_prompt(devname)
            if current_mode == "mgmt-user":
                mode_flag = "klish"
            elif current_mode.startswith("mgmt"):
                mode_flag = "klish-config"
            elif current_mode == "vtysh-user":
                mode_flag = "vtysh"
            elif current_mode.startswith("vtysh"):
                mode_flag = "vtysh-config"
            elif current_mode.startswith("normal"):
                mode_flag = ""

        # ensure we are in sonic mode after we exit
        if mode_flag == "":
            self._exit_vtysh(devname)
        else:
            self._exit_klish(devname)

    def apply_json(self, devname, data, **kwargs):
        devname = self._check_devname(devname)
        try:
            obj = json.loads(data)
            indented = json.dumps(obj, indent=4)
        except Exception:
            self.logger.warning("invalid json - trying to fix")
            # remove trailing object comma
            regex = re.compile(
                r'(,)\s*}(?=([^"\\]*(\\.|"([^"\\]*\\.)*[^"\\]*"))*[^"]*$)')
            data = regex.sub("}", data)
            # remove trailing array comma
            regex = re.compile(
                r'(,)\s*\](?=([^"\\]*(\\.|"([^"\\]*\\.)*[^"\\]*"))*[^"]*$)')
            data = regex.sub("]", data)
            try:
                obj = json.loads(data)
                indented = json.dumps(obj, indent=4)
            except Exception:
                raise ValueError("invalid json data")

        # write json content into file
        for _ in range(3):
            src_file = self.wa.mktemp()
            src_fp = open(src_file, "w")
            src_fp.write(indented)
            src_fp.close()
            if os.path.exists(src_file) and os.path.getsize(src_file) != 0:
                msg = "Created temp json file {} of size {} ..".format(src_file, os.path.getsize(src_file))
                self.dut_warn(devname, msg)
                break
            else:
                msg = "Failed to create temp json file {}.. Retrying again..".format(src_file)
                self.dut_warn(devname, msg)

        applied = False
        for _ in range(3):
            # transfer the file
            access = self._get_dev_access(devname)
            dst_file = self._upload_file(access, src_file)

            # issue config load
            if self.is_filemode(devname):
                applied = True
                break

            # ensure we are in sonic mode
            self._enter_linux(devname)

            check_file_cmd = "ls -lrt {}".format(dst_file)
            self._config(devname, check_file_cmd, skip_error_check=True)

            # execute the command.
            config_cmd = "config load -y {}".format(dst_file)
            output = self._config(devname, config_cmd, skip_error_check=True, **kwargs)
            if 'Path "{}" does not exist.'.format(dst_file) not in output:
                applied = True
                break
            msg = "Failed to find the transfered destination file retry again in 3 sec"
            self.dut_warn(devname, msg)
            time.sleep(3)

        # remove temp file
        os.remove(src_file)

        # try apply_json2 as last resort
        if not applied:
            msg = "Failed to find the transfered destination file even after retries - try using echo"
            self.dut_warn(devname, msg)
            self.apply_json2(devname, data, **kwargs)

    def apply_json2(self, devname, data, **kwargs):
        if not self.is_filemode(devname):
            dst_file = "/tmp/apply_json2.json"
            self._save_json_to_remote_file(devname, data, dst_file)
            config_cmd = "config load -y {}".format(dst_file)
            self._config(devname, config_cmd, **kwargs)

    def _set_config_erase(self, devname):
        devname = self._check_devname(devname)

        # mark to download helper files again
        self.skip_trans_helper[devname] = dict()

        # mark to read the mgmt ip again
        self._clear_mgmt_ip(devname)

    def recover_from_grub_rescue(self, devname, install):
        msg = "Device Stuck in 'grub rescue' prompt"
        self.dut_err(devname, msg)
        if not self.moveto_grub_mode(devname):
            dut_label = self._get_dut_label(devname)
            msg = "Failed to bring the device {} to GRUB mode".format(dut_label)
            self._node_fail(devname, None, msg)
            return False

    def moveto_grub_mode(self, devname):
        dut_label = self._get_dut_label(devname)
        msg = "Performing RPS reboot and taking the DUT '{}' to ONIE mode".format(dut_label)
        self.dut_log(devname, msg)
        if not self.wa.moveto_grub_mode(devname):
            msg = "Failed to bring the device {} to GRUB mode".format(dut_label)
            self.dut_err(devname, msg)
            return False
        msg = "Successfully got the device {} to GRUB mode".format(dut_label)
        self.dut_log(devname, msg)
        return True

    def reboot_and_onie_grub_rescue(self, devname):
        devname = self._check_devname(devname)
        access = self._get_dev_access(devname)
        msg = "Trying to recover from ONIE with reboot"
        msg = "{} @{}".format(msg, utils.get_line_numbers())
        self.dut_warn(devname, msg)
        regex_login = self.wa.hooks.get_regex(devname, "login")
        for _ in range(2):
            expect = "|".join([regex_login, regex_onie, regex_onie_sleep, regex_grub_rescue])
            self.trace_callback_set(devname, True)
            self._send_command(access, "reboot", expect, True, 3)
            self.trace_callback_set(devname, False)
            prompt2 = self._find_prompt(access, use_cache=False).replace("\\", "")
            if re.compile(regex_login).match(prompt2):
                return 1
            if re.compile(regex_onie).match(prompt2):
                return 2
            if re.compile(regex_onie_sleep).match(prompt2):
                return 3
            msg = "Trying to recover from grub rescue with reboot"
            self.dut_warn(devname, msg)
            self.recover_from_grub_rescue(devname, True)
        return 4

    def recover_from_onie(self, devname, install, stop_disc=True, prompt="ONIE"):
        devname = self._check_devname(devname)
        access = self._get_dev_access(devname)
        if stop_disc:
            self._onie_stop_discovery(devname)

        if install and self.wa.get_cfg_load_image(devname) == "none":
            msg = "Skip install from {}".format(prompt)
            self.dut_warn(devname, msg)
            return False

        if not install:
            try:
                self.reboot_and_onie_grub_rescue(devname)
                if self.wait_onie_or_login(devname) == 2:
                    # reboot took the device into login prompt
                    msg = "logged into device from ONIE"
                    self.dut_log(devname, msg)
                    return True
                msg = "Failed to take device into login/usermode - try loading image"
                self.dut_err(devname, msg)
                # pass through installation
            except Exception:
                msg = "Failed to recover from {} with reboot".format(prompt)
                self._node_fail(devname, None, msg)
                return False

        # installing
        if self.cfg.build_url:
            onie_image = self.cfg.build_url
        else:
            onie_image = access["onie_image"]
        if not onie_image:
            msg = "No image is specified to load from {}".format(prompt)
            self.dut_err(devname, msg)
            return False
        if not self.onie_nos_install(devname, onie_image):
            if env.get("SPYTEST_RECOVERY_MECHANISMS", "1") == "0":
                return False
            self.reboot_and_onie_grub_rescue(devname)
            if self.wait_onie_or_login(devname) != 1:
                return False
            if not self.onie_nos_install(devname, onie_image, 1):
                return False
        if not self.wa.session_init_completed:
            self.image_install_status[devname] = True
        return True

    def _onie_stop_discovery(self, devname):

        msg = "Stopping ONIE discovery"
        msg = "{} @{}".format(msg, utils.get_line_numbers())
        self.dut_log(devname, msg)

        devname = self._check_devname(devname)
        access = self._get_dev_access(devname)
        expect = self.wa.hooks.get_regex(devname, "anyprompt")

        for use_timing in [True, False]:
            self._send_command(access, "", expect, on_cr_recover="retry5",
                               use_timing=use_timing)
            self._send_command(access, "onie-discovery-stop", expect,
                               skip_error_check=True, on_cr_recover="retry5",
                               use_timing=use_timing)
            self._send_command(access, "onie-stop", expect,
                               skip_error_check=True, on_cr_recover="retry5",
                               use_timing=use_timing)
        self._send_command(access, "ifconfig", expect, skip_error_check=True,
                           on_cr_recover="retry5-ignore")

    def _onie_debug(self, devname):
        devname = self._check_devname(devname)
        access = self._get_dev_access(devname)
        expect = self.wa.hooks.get_regex(devname, "anyprompt")

        self._send_command(access, "ifconfig eth0 up", expect, skip_error_check=True,
                           on_cr_recover="ignore")
        self._send_command(access, "ps | grep dhcp", expect, skip_error_check=True,
                           on_cr_recover="retry5-ignore")
        self._send_command(access, "ifconfig", expect, skip_error_check=True,
                           on_cr_recover="retry5-ignore")
        self._send_command(access, "udhcpc -nq -t 30", expect, skip_error_check=True,
                           on_cr_recover="retry5-ignore")

    def _onie_nos_install(self, devname, url, index):
        devname = self._check_devname(devname)
        access = self._get_dev_access(devname)

        # indicate config getting erased
        self._set_config_erase(devname)

        # issue command
        self._onie_stop_discovery(devname)
        cmd = "ZTP=n onie-nos-install {}".format(url)
        self.dut_log(devname, "Try-{} {}".format((index + 1), cmd))
        regex_login = self.wa.hooks.get_regex(devname, "login")
        sys_ready = r"\S+\s+System is ready\s*$"
        expect = "|".join([regex_login, regex_onie, sys_ready])
        self.trace_callback_set(devname, True)
        output = self._send_command(access, cmd, expect, True, 18)
        self.trace_callback_set(devname, False)

        # wait for login prompt
        ptype = self.wait_onie_or_login(devname)

        # check for all the success messages in onie installation output
        if self.is_sonic_device(devname) and ptype in [2]:
            onie_msg_not_found = 0
            for onie_msg in onie_success_patterns:
                if onie_msg not in output:
                    onie_msg_not_found = 1
                    self.dut_log(devname, "Pattern '{}' NOT found in onie-nos-install output ".format(onie_msg))
                else:
                    self.dut_log(devname, "Pattern '{}' found in onie-nos-install output ".format(onie_msg))

            if onie_msg_not_found:
                msg = "Unable to find the ONIE success message(s) in onie-nos-install output. Device Onie Installation Failed"
                self.dut_err(devname, msg)
                return False

        if ptype == 1:
            msg = "Device Onie Install Failed - TRY {}".format(index + 1)
            self.dut_warn(devname, msg)
            return False
        elif ptype in [2, 3]:
            msg = "Device Onie Install Completed"
            msg = "{} {}".format(msg, utils.get_line_numbers())
            self.dut_log(devname, msg)
            self.init_normal_prompt(devname)
            return True

        msg = "Failed to get login prompt after ONIE upgrade - TRY {}".format(index + 1)
        self.dut_err(devname, msg)
        return False

    def onie_nos_install(self, devname, url, max_try=3):
        for index in range(max_try):
            if self._onie_nos_install(devname, url, index):
                return True
        return False

    def wait_onie_or_login(self, devname):
        if self.is_filemode(devname):
            return 3
        devname = self._check_devname(devname)
        access = self._get_dev_access(devname)
        regex_login = self.wa.hooks.get_regex(devname, "login")
        non_onie_retval = None
        for attempt in range(10):
            prompt = self._find_prompt(access, use_cache=False)
            prompt2 = prompt.replace("\\", "")
            if re.compile(regex_onie).match(prompt2):
                if attempt == 0:
                    # try again as ONIE some times just throws the prompt
                    time.sleep(5)
                    continue
                return 1
            elif non_onie_retval is not None:
                return non_onie_retval
            if re.compile(regex_login).match(prompt2):
                self._enter_linux(devname, prompt)
                non_onie_retval = 2
                # check for onie prompt again
                continue
            msg = "Unexpected Prompt {}".format(prompt2)
            self.dut_warn(devname, msg)
            self.wait(1)
        return 0

    def update_onie_grub_config(self, devname, mode):

        # Grub commands for image download.
        cmds, errs = self.wa.hooks.get_onie_grub_config(devname, mode)
        if not cmds: return ""

        # Issue the grub commands.
        skip_error_check = False if self.wa.session_init_completed else True
        cli_prompt = self._get_cli_prompt(devname)
        access = self._get_dev_access(devname)
        upgrade_image_cmd = ";".join(cmds)
        self.trace_callback_set(devname, True)
        output = self._send_command(access, upgrade_image_cmd, cli_prompt,
                                    skip_error_check, 18)
        self.trace_callback_set(devname, False)

        for err_pattern in errs:
            if err_pattern in output:
                msg = "ONIE GRUB config failed matching error '{}' in mode {}".format(err_pattern, mode)
                self.dut_err(devname, msg)
                return msg

        return output

    def get_image_install_status(self, devname):
        return self.image_install_status.get(devname, False)

    def upgrade_onie_image1(self, devname, url, max_ready_wait=0):
        devname = self._check_devname(devname)

        if not self.wa.session_init_completed:
            if self.get_image_install_status(devname):
                self.dut_log(devname, "Image already upgraded during the time of DUT connect using ONIE process.")
                return True

        self.dut_log(devname, "Upgrading image from onie1 '{}'.".format(url))
        self.upgrade_onie_image1_prep(devname)

        for try_index in range(0, 5):
            if self._onie_nos_install(devname, url, try_index): break
            if self.is_filemode(devname): break
            msg = "Image download failed using onie-nos-install try {}.".format(try_index + 1)
            self.dut_err(devname, msg)

            if try_index >= 1 and self.onie_noip_recover:
                self._onie_debug(devname)

            if try_index >= 2 and self.onie_noip_recover:
                # reboot and try again
                prompt_type = self.reboot_and_onie_grub_rescue(devname)
                if prompt_type == 2:
                    # reboot took the device back into ONIE
                    continue
                self.upgrade_onie_image1_prep(devname)

            if try_index >= 4:
                raise ValueError(msg)

        self.do_common_init(devname, max_ready_wait=max_ready_wait, phase=1)
        self._show_version(devname, "reading version after upgrade")
        self._fetch_mgmt_ip(devname, 5, 2)
        return True

    def upgrade_onie_image1_prep(self, devname):
        devname = self._check_devname(devname)

        # ensure we are in sonic mode
        self._enter_linux(devname)

        # update ONIE configuration
        self.dut_log(devname, "Upgrading GRUB Config for rescue mode")
        self.update_onie_grub_config(devname, "rescue")

        # we need to download the helper files again
        self.skip_trans_helper[devname] = dict()

        # Issue reboot command and look for ONIE rescue mode.
        self.dut_log(devname, "Rebooting to enter ONIE rescue mode")
        if not self.reboot(devname, onie=True):
            msg = "Reboot failed as unable to get the onie rescue mode."
            self.dut_err(devname, msg)
            raise ValueError(msg)

    def _upgrade_onie_image(self, devname, url, max_ready_wait=0):
        devname = self._check_devname(devname)
        access = self._get_dev_access(devname)

        if not self.wa.session_init_completed:
            if self.get_image_install_status(devname):
                self.dut_log(devname, "Image already upgraded during the time of DUT connect using ONIE process.")
                return True

        self.dut_log(devname, "Upgrading image from onie '{}'.".format(url))
        dut_image_location = "/host/onie-installer-x86_64"

        # ensure we are in sonic mode
        self._enter_linux(devname)

        # Download the image from url to /host/onie-installer-x86_64 location.
        download_image_cmd = "sudo curl --retry 15 -o {} {}".format(dut_image_location, url)

        download_delay_factor = 18
        # Issue the download_image_cmd command.
        for count in range(3):
            skip_error_check = False if self.wa.session_init_completed else True
            cli_prompt = self._get_cli_prompt(devname)
            self.dut_log(devname, "Trying image download using curl command, iteration {}".format(count + 1))
            start_time = time.time()
            self.trace_callback_set(devname, True)
            output = self._send_command(access, download_image_cmd, cli_prompt,
                                        skip_error_check, delay_factor=download_delay_factor,
                                        trace_log=3)
            self.trace_callback_set(devname, False)
            end_time = time.time()

            if re.search(r"curl:\s+\(\d+\)", output):
                errorline = [m for m in output.split(nl) if re.search(r"curl:\s+\(\d+\)", m)]
                errorline = str("".join(errorline))
                msg = "Image download to host location failed using curl command. Error: '{}'"
                msg = msg.format(errorline)
                self.dut_err(devname, msg)
                if count >= 2:
                    return msg
                continue

            if (end_time - start_time) > (download_delay_factor * 100):
                msg = "Image download to host location failed. Error: 'Took more than 30 mins to download'"
                self.dut_err(devname, msg)
                if count >= 2:
                    return msg
                continue

            # Check for the downloaded file type.
            filetype_cmd = "sudo file {}".format(dut_image_location)
            file_output = self._send_command(access, filetype_cmd, cli_prompt,
                                             skip_error_check, delay_factor=1)
            if not self.is_filemode(devname) and not re.search(r"binary\s+data", file_output):
                errorline = file_output.split(nl)[0]
                msg = "Image downloaded to host location is not a proper image type. File type: '{}'"
                msg = msg.format(errorline)
                self.dut_err(devname, msg)
                return msg

            self.dut_log(devname, "Image downloaded to host location successfully.")
            break

        # Get the version info from the downloaded file.
        if env.get("SPYTEST_ABORT_ON_VERSION_MISMATCH", "2") == "2" and not self.wa.session_init_completed:
            cli_prompt = self._get_cli_prompt(devname)
            image_version_grep_cmd = "sudo grep -a 'image_version=\"' {}".format(dut_image_location)
            output = self._send_command(access, image_version_grep_cmd, cli_prompt,
                                        skip_error_check, 3)
            output = nl.join(output.split(nl)[:-1])
            image_versionname = re.sub(r"image_version=|\"", "", output)

            image_nosname_grep_cmd = "sudo grep -a '^NOS_NAME=' {}".format(dut_image_location)
            output = self._send_command(access, image_nosname_grep_cmd, cli_prompt,
                                        skip_error_check, 3)
            output = nl.join(output.split(nl)[:-1])
            image_nosname = re.sub(r"NOS_NAME=|\"", "", output)

            next_loading_img_ver = None
            if image_versionname and image_nosname:
                next_loading_img_ver = image_nosname + "-" + image_versionname
                msg = "Software Version details identified in the downloaded file '{}'."
                msg = msg.format(next_loading_img_ver)
                self.dut_log(devname, msg)
            else:
                msg = "Unable to get the Software Version from the downloaded file '{}'."
                msg = msg.format(dut_image_location)
                self.dut_warn(devname, msg)

        # update ONIE configuration
        self.update_onie_grub_config(devname, "install")

        # we need to download the helper files again
        self.skip_trans_helper[devname] = dict()

        # Issue reboot command.
        reboot_flag = False
        if not self._is_console_connection(devname):
            reboot_flag = self.reboot(devname, onie=True)
        else:
            reboot_flag = self.reboot(devname)
        if not reboot_flag:
            msg = "Reboot failed after the image download using onie install."
            self.dut_err(devname, msg)
            return msg

        loaded_image_version_dict = self._show_version(devname, "reading version after upgrade") or {}
        loaded_image_version = loaded_image_version_dict.get("version", None)
        if loaded_image_version:
            loaded_image_version = loaded_image_version.strip("'")
        if env.get("SPYTEST_ABORT_ON_VERSION_MISMATCH", "2") == "2" and not self.wa.session_init_completed:
            if next_loading_img_ver and next_loading_img_ver != loaded_image_version:
                if loaded_image_version not in next_loading_img_ver:
                    msg = "Downloaded file version '{}' and loaded image version '{}' are different."
                    msg = msg.format(next_loading_img_ver, loaded_image_version)
                    self.dut_err(devname, msg)
                    return msg

        self.do_common_init(devname, max_ready_wait=max_ready_wait, phase=1)
        self._fetch_mgmt_ip(devname, 5, 2)
        return True

    def upgrade_onie_image(self, devname, url, max_ready_wait=0):
        rv = self._upgrade_onie_image(devname, url, max_ready_wait)
        if rv in [False, True, None]:
            return rv
        if "failed using curl command" in str(rv):
            msg = "Failed to upgrade the image using curl, try using ONIE directly"
            self.dut_err(devname, msg)
            return self.upgrade_onie_image1(devname, url, max_ready_wait)
        raise ValueError(rv)

    def upgrade_image(self, devname, url, skip_reboot=False, migartion=True, max_ready_wait=0, max_attempts=1):
        """
        Upgrade the software in the given DUT from given URL
        :param devname:
        :type devname:
        :param url: URL string used to upgrade
        :type url: String
        :param skip_reboot: Flag to avoid rebooting device after upgrade
        :type url: boolean (default False)
        :return:
        :rtype:
        """
        devname = self._check_devname(devname)

        if not self.wa.session_init_completed:
            if self.get_image_install_status(devname):
                self.dut_log(devname, "Image already upgraded during the time of DUT connect using ONIE process.")
                return True

        self.dut_log(devname, "Upgrading image from sonic-installer '{}'.".format(url))

        # verify URL
        urlip = utils.parse_url(url)["ip"]
        if not utils.ipcheck(urlip):
            raise ValueError("image upgrade failed - URL not reachable")

        # ensure we are in sonic mode
        self._enter_linux(devname)

        skip_error_check = False if self.wa.session_init_completed else True
        for attempt in range(1, max_attempts + 1):
            retval = self.wa.hooks.upgrade_image(devname, url, 1800, skip_error_check, migartion)
            if self.is_filemode(devname): retval = "success"
            if self.finish_upgrade_image(devname, url, retval, skip_reboot, max_ready_wait):
                return True
            if attempt >= max_attempts:
                self.dut_warn(devname, "retry {} after 300 seconds".format(attempt))
                self.wait(300)
        raise ValueError("image upgrade failed")
        # return False

    def finish_upgrade_image(self, devname, url, retval, skip_reboot, max_ready_wait):

        # mark to download helper files again
        self.skip_trans_helper[devname] = dict()

        devname = self._check_devname(devname)
        if retval == "success":
            if skip_reboot:
                msg = "Image upgraded successfully."
                self.dut_log(devname, msg)
            elif self.reboot(devname, max_ready_wait=max_ready_wait, try_count=2):
                self._enter_linux(devname)
                msg = "Image upgraded and rebooted successfully."
                self.dut_log(devname, msg)
            else:
                msg = "Reboot failed after the image download."
                self.dut_err(devname, msg)
                raise ValueError(msg)
        elif retval == "aborted":
            msg = "Did not receive a response from remote machine"
            self.dut_err(devname, msg)
            return False
        elif retval == "skipped":
            msg = "No need to upgrade as the image is already of same version."
            self.dut_log(devname, msg)
        else:
            msg = "Image not loaded on to the device using URL: {}".format(url)
            self.dut_err(devname, msg)
            raise ValueError(msg)
        return True

    def recover(self, devname, msg, method="normal"):
        self.dut_log(devname, msg)
        if self.reboot(devname, method):
            self._enter_linux(devname)
            self.dut_log(devname, "{} - Successful".format(msg))
        else:
            self.logger.error("{} - Failed".format(msg))
            raise ValueError(msg)

    def recover_hard(self, devname, msg):
        try: return self.recover(devname, msg, "normal")
        except: return self.recover(devname, msg, "rps")

    def reboot(self, devname, method=None, skip_port_wait=False,
               onie=False, skip_exception=False, skip_fallback=False,
               ret_logs=False, max_ready_wait=0, internal=True,
               line=None, try_count=1, abort_on_fail=False, **kwargs):

        line = line or utils.get_line_number()
        method = method or env.get("SPYTEST_DEFAULT_REBOOT_METHOD", "normal")
        for try_index in range(1, try_count + 1):
            try:
                self.tryssh_switch(devname)
                rv = self._reboot(devname, method, skip_port_wait, onie,
                                  skip_exception, skip_fallback, ret_logs=ret_logs,
                                  max_ready_wait=max_ready_wait, internal=internal,
                                  line=line, abort_on_fail=abort_on_fail, **kwargs)
                if not onie:
                    if self.cfg.save_warmboot and method in ["warm", "warm-reboot"]:
                        self.apply_remote(devname, "fetch-warmboot")
                    self.tryssh_switch(devname, True)
            except Exception as e:
                msg = utils.stack_trace(None, True)
                self.dut_warn(devname, msg)
                self.tryssh_switch(devname, False)
                if not skip_exception and try_index == try_count:
                    raise e
                rv = False

        return rv

    def _wait_mgmt(self, devname, dut_mgmt_ip, reboot_polling_time):
        time_left = reboot_polling_time
        while time_left > 0:
            retval = utils.ipcheck(dut_mgmt_ip)
            msg = "Pinging IP : '{}' : {}".format(dut_mgmt_ip, retval)
            self.dut_log(devname, msg)
            if retval:
                break
            time_left = time_left - 2
        if time_left == 0:
            msg = "DUT IP '{}' is not reachable even after pinging for '{}' secs"
            msg = msg.format(dut_mgmt_ip, reboot_polling_time)
            self.dut_err(devname, msg)
            return False
        return True

    def _send_reboot(self, devname, cmd, expect, skip_error_check,
                     delay_factor, confirm, **kwargs):
        devname = self._check_devname(devname)
        access = self._get_dev_access(devname)

        if self.wa.hooks.is_reboot_confirm(devname):
            cmd = "{} -y".format(cmd)
        self.trace_callback_set(devname, True)
        output = self._send_command_confirm(access, cmd, expect, skip_error_check=skip_error_check,
                                            delay_factor=delay_factor, use_cache=False, confirm=confirm, **kwargs)
        self.trace_callback_set(devname, False)
        return output

    def _reboot(self, devname, method="normal", skip_port_wait=False,
                onie=False, skip_exception=False, skip_fallback=False,
                ret_logs=False, max_ready_wait=0, internal=True, line=None,
                abort_on_fail=False, **kwargs):

        devname = self._check_devname(devname)
        reboot_cmd, reboot_confirm = self.wa.hooks.get_command(devname, "reboot", method)
        if self.is_filemode(devname):
            self.dut_log(devname, "Reboot command '{}'.".format(reboot_cmd))
            return True

        # Issue reboot command.
        self.wa.instrument(devname, "pre-reboot")
        reboot_delay_factor = 10

        line = line or utils.get_line_number()
        access = self._get_dev_access(devname)
        user_mode = self._get_cli_prompt(devname)

        # SSH specific handling
        if not self._is_console_connection(devname):
            if method == "rps":
                self._do_rps_reset(devname, debug=False)
                output = ""
            else:
                output = self.wa.hooks.dut_reboot(devname, method=method, max_time=120, **kwargs)

            if not onie:
                # wait for the PING to start failing to know reboot started
                dut_mgmt_ip = str(access["connection_param"]["ip"])
                if not self._wait_mgmt(devname, dut_mgmt_ip, 120):
                    return False

            # disconnect the device and wait for PING to start passing
            self._disconnect_device(devname)
            wait_after_ping = 30
            msg = "Waiting for '{}' secs before attempting connection via SSH.".format(wait_after_ping)
            self.dut_log(devname, msg)
            self.wait(wait_after_ping)
            retry_count = 0
            while retry_count < 10:
                retval = self.connect_to_device(devname)
                msg = "Connection attempt : '{}', Status: '{}'".format(retry_count, retval)
                self.dut_log(devname, msg)
                if retval:
                    break
                retry_count = retry_count + 1
                self.wait(10)
            return True

        # ONIE specific handling - box is already in Linux prompt
        if onie:
            regex_login = self.wa.hooks.get_regex(devname, "login")
            prompts = [regex_onie_resque_anywhere]
            prompts.extend([regex_onie_install, regex_onie_fetch])
            use_onie_password = False
            if access.get("oniepassword", None) is not None:
                use_onie_password = True
                prompts.append(regex_login)
            prompts.append(regex_onie)
            try:
                output = self._send_reboot(devname, reboot_cmd, "|".join(prompts), True,
                                           reboot_delay_factor, reboot_confirm,
                                           on_cr_recover="ignore")
            except Exception as e:
                output = ""
                self.logger.error(e)
            prompt = self._find_prompt(access, use_cache=False)
            prompt2 = prompt.replace("\\", "")
            if use_onie_password:
                msg = "use oniepassword if needed from {}".format(prompt2)
                self.dut_log(devname, msg)
            msg = "Reboot completed @{}".format(line)
            if env.get("SPYTEST_ONIE_FAIL_ON_NORMAL_PROMPT", "0") != "0":
                if prompt == self._get_cli_prompt(devname):
                    msg = msg + " but normal user prompt is seen instead of ONIE prompt"
                    self.dut_err(devname, msg)
                    return False
            if re.compile(regex_login).match(prompt2):
                if not use_onie_password:
                    msg = msg + " but login prompt is seen instead of ONIE prompt"
                    self.dut_err(devname, msg)
                    return False
                self._enter_linux(devname, prompt)
                self.wait(60)
            msg = msg + " and Activate/ONIE Prompt is seen"
            self.dut_log(devname, msg)
            self._update_device_start(devname)

            return True

        if method == "rps":
            self._do_rps_reset(devname, debug=False)
            output = ""
        elif not internal:
            output = self.wa.hooks.dut_reboot(devname, method=method, **kwargs)
        else:
            output = self.wa.hooks.dut_reboot(devname, method=method, reboot_wait=600, cli_type="click")

        if not internal and not abort_on_fail:
            if self.cfg.reboot_wait:
                msg = "Waiting for '{}' secs after reboot.".format(self.cfg.reboot_wait)
                self.dut_log(devname, msg)
                self.wait(self.cfg.reboot_wait)
            if "INFRA_SYS_CHK: system status is not online" in output:
                err_msg = "INFRA_SYS_CHK: system status is not online even after waiting for {} sec".format(self.cfg.port_init_wait)
                self.dut_log(devname, err_msg)
                return False
            self._update_device_start(devname)
            return output if ret_logs else True

        # check for needed prompts
        user_mode = self._get_cli_prompt(devname)  # read again
        msg = "Checking for login or usermode '{}' prompt"
        self.dut_log(devname, msg.format(user_mode))
        reboot_status = False
        result_set = ["DUTFail", "reboot_failed"]
        try_count = 3
        regex_login = self.wa.hooks.get_regex(devname, "login")
        regex_login_anywhere = self.wa.hooks.get_regex(devname, "login_anywhere")
        skip_post_reboot = kwargs.get("skip_post_reboot", False)
        while try_count > 0:
            prompt = self._find_prompt(access, use_cache=False)
            prompt2 = prompt.replace("\\", "")
            if re.compile(user_mode).match(prompt2):
                msg = "Device Reboot ({}) Completed..".format(reboot_cmd)
                self.dut_log(devname, msg)
                self._update_device_start(devname)
                if skip_post_reboot:
                    reboot_status = True
                else:
                    reboot_status = self.wa.wait_system_status(devname, max_time=max_ready_wait)
                if not abort_on_fail:
                    reboot_status = True
                break

            if re.compile(regex_login).match(prompt2):
                msg = "Device Reboot ({}) Completed.".format(reboot_cmd)
                self.dut_log(devname, msg)
                self._update_device_start(devname)
                self.wait(5)  # wait for any kernel messages to show up
                self._enter_linux(devname, prompt)
                if skip_post_reboot:
                    reboot_status = True
                else:
                    reboot_status = self.do_common_init(devname, max_ready_wait=max_ready_wait)
                if not abort_on_fail:
                    reboot_status = True
                break

            if re.compile(regex_login_anywhere).match(prompt2):
                msg = "Device Reboot ({}) May Be Completed - confirming".format(reboot_cmd)
                self.dut_log(devname, msg)
                continue

            msg = "Prompt '{}' is neither login nor usermode '{}'."
            msg = msg.format(prompt, user_mode)
            self.dut_err(devname, msg)
            try_count = try_count - 1

        if not reboot_status:
            self._report_error(devname, result_set, reboot_cmd)
        elif skip_post_reboot:
            pass
        elif self.cfg.reboot_wait:
            msg = "Waiting for '{}' secs after reboot.".format(self.cfg.reboot_wait)
            self.dut_log(devname, msg)
            self.wait(self.cfg.reboot_wait)

        self._update_device_start(devname)
        return output if ret_logs else reboot_status

    def wait_system_reboot(self, devname):
        self.tryssh_switch(devname)
        devname = self._check_devname(devname)
        access = self._get_dev_access(devname)
        regex_login = self.wa.hooks.get_regex(devname, "login")
        regex_anyprompt = self.wa.hooks.get_regex(devname, "anyprompt")
        prompt_terminator = "|".join([regex_anyprompt, regex_login])
        cli_prompt = self._get_cli_prompt(devname)
        self._send_command(access, nl, prompt_terminator, True, 6)
        try_count = 3
        while try_count > 0:
            prompt = self._find_prompt(access, use_cache=False)
            prompt2 = prompt.replace("\\", "")
            if re.compile(regex_login).match(prompt2):
                msg = "Device Reboot Completed."
                self.dut_log(devname, msg)
                self._update_device_start(devname)
                self._enter_linux(devname)
                break
            elif cli_prompt in [prompt, prompt2]:
                break
            else:
                try_count = try_count - 1

        if try_count > 0:
            self._enter_linux(devname)
            retval = self.do_common_init(devname)
            self._fetch_mgmt_ip(devname, 5, 2)
        else:
            retval = False

        self.tryssh_switch(devname, True, True)
        return retval

    def _transfer_base64(self, access, src_file, dst_file):
        devname = access["devname"]
        self._enter_linux(devname)
        prompt = self._get_cli_prompt(devname)
        script_cmd = "rm -f {0}.tmp {0}".format(dst_file)
        self._send_command(access, script_cmd, prompt)
        redir = ">"
        lines = utils.b64encode(src_file)
        count, split = len(lines), self.max_cmds_once
        for i in range(0, count, split):
            script_cmds = []
            for j in range(i, i + split):
                if j >= count:
                    break
                script_cmds.append(lines[j])
            if script_cmds:
                line = "".join(script_cmds)
                script_cmd = "echo {} {} {}.tmp".format(line, redir, dst_file)
                self._send_command(access, script_cmd, prompt, True)
                redir = ">>"
        script_cmd = "base64 -d {0}.tmp > {0}".format(dst_file)
        self._send_command(access, script_cmd, prompt)

    def _save_json_to_remote_file(self, devname, data, dst_file, do_indent=False):
        devname = self._check_devname(devname)
        try:
            obj = json.loads(data)
            indented = json.dumps(obj, indent=4) if do_indent else data
        except Exception:
            self.logger.warning("invalid json - trying to fix")
            # remove trailing object comma
            regex = re.compile(
                r'(,)\s*}(?=([^"\\]*(\\.|"([^"\\]*\\.)*[^"\\]*"))*[^"]*$)')
            data = regex.sub("}", data)
            # remove trailing array comma
            regex = re.compile(
                r'(,)\s*\](?=([^"\\]*(\\.|"([^"\\]*\\.)*[^"\\]*"))*[^"]*$)')
            data = regex.sub("]", data)
            try:
                obj = json.loads(data)
                indented = json.dumps(obj, indent=4) if do_indent else data
            except Exception:
                raise ValueError("invalid json data")

        access = self._get_dev_access(devname)
        if not self.is_filemode(devname):
            # ensure we are in sonic mode
            self._enter_linux(devname)
            # echo data to remote file
            self._echo_text_to_file(access, indented, dst_file)

    def _echo_text_to_file(self, access, content, dst_file, prefix=""):
        str_list = content.split(nl)
        if prefix:
            str_list.insert(0, prefix)
        return self._echo_list_to_file(access, str_list, dst_file)

    def _echo_list_to_file(self, access, str_list, dst_file, split=None):
        l_split = self.max_cmds_once if not split else split
        devname = access["devname"]
        msg = "Creating: DST: {}".format(dst_file)
        self.dut_log(devname, msg)
        redir = ">"
        cli_prompt = self._get_cli_prompt(devname)
        for clist in utils.split_list(str_list, l_split):
            content = nl.join(clist)
            script_cmd = "printf '{}\n' {} {}\n".format(content, redir, dst_file)
            self._send_command(access, script_cmd, cli_prompt, ufcli=False, trace_log=1)
            redir = ">>"

        return dst_file

    def _upload_file(self, access, src_file, dst_file=None, cft=0):
        cft = cft or self.console_file_transfer
        return self._upload_file1(access, src_file, dst_file, cft)

    def _upload_file1(self, access, src_file, dst_file=None, cft=1, abort=True, fallback=True):
        if not dst_file:
            dst_file = "/tmp/{}".format(os.path.basename(src_file))
        devname = access["devname"]
        msg = "Transfer: SRC({}): {} DST({}): {}".format("SVR/VDI", src_file, devname, dst_file)
        self.dut_log(devname, msg)
        if not os.path.exists(src_file):
            self.dut_err(devname, "File {} not found".format(src_file))
        if self.is_filemode(devname):
            return dst_file

        if cft == 2:
            self._transfer_base64(access, src_file, dst_file)
            return dst_file

        try:
            cinfo = access["connection_param"]
            if access["current_handle"] == 0 and not cinfo["mgmt-ip"]:
                self._fetch_mgmt_ip(devname, 10, 2)
            if not cinfo.get("mgmt-ip", ""):
                self.dut_err(devname, "No mgmt IP")
                # self.wa.report_env_fail_int(devname, True, "dut_not_getting_ip_address")
            msg = "Doing SFTP transfer {}".format(self.connection_param_string(cinfo))
            self.dut_log(devname, msg)
            if access["current_handle"] != 0:
                cinfo = copy.copy(cinfo)
                cinfo["mgmt-ip"] = ""
            net_handle = self._get_handle(devname)
            DeviceFileUpload(net_handle, src_file, dst_file, logger=self.logger, devname=devname, **cinfo)
        except Exception as e:
            errmsg = str(e)
            if "AttributeError: 'NetmikoConnection' object has no attribute" in errmsg:
                errmsg = ""
            if cft == 1 and fallback:
                self.dut_warn(devname, "SFTP Failed - Doing Console transfer {}".format(errmsg))
                self._transfer_base64(access, src_file, dst_file)
            else:
                self.dut_err(devname, "SFTP {} Failed {}".format(src_file, errmsg))
                if errmsg:
                    msg = utils.stack_trace(None, True)
                    self.dut_warn(devname, msg)
                if abort:
                    raise e
                return None

        return dst_file

    def _check_md5(self, devname, access, prompt, src_file, remote_file):

        skip_transfer = False
        script_cmd = "sudo md5sum {}".format(remote_file)
        output = self._send_command(access, script_cmd, prompt, False, on_cr_recover="retry5")
        try:
            dst_md5 = re.findall(r"([a-fA-F\d]{32})", output)
            if dst_md5: dst_md5 = dst_md5[0].strip()
            src_md5 = utils.md5(src_file)
            if src_md5 == dst_md5:
                skip_transfer = True
                self.skip_trans_helper[devname][src_file] = remote_file
            else:
                self.dut_log(devname, "MD5 different SRC: {} DST: {}".format(src_md5, dst_md5))
        except Exception as e:
            self.logger.error(e)

        return skip_transfer

    def _upload_file2(self, devname, access, src_file, md5check=True):
        remote_dir = "/etc/spytest"

        if devname not in self.skip_trans_helper:
            self.skip_trans_helper[devname] = dict()

        remote_file = self.skip_trans_helper[devname].get(src_file, None)
        if remote_file: return remote_file

        prompt = self._get_cli_prompt(devname)
        src_file2 = "%s/%s" % (os.path.basename(os.path.dirname(src_file)),
                               os.path.basename(src_file))
        remote_file = os.path.join(remote_dir, src_file2)
        skip_transfer, dry_run = False, self.is_filemode(devname)
        if md5check:
            skip_transfer = self._check_md5(devname, access, prompt, src_file, remote_file)
        if skip_transfer:
            return remote_file

        done = False
        self.skip_trans_helper[devname][src_file] = None
        max_iters = 1 if dry_run else 6
        for i in range(1, max_iters):
            self.dut_log(devname, "Trying to upload file '{}'. attempt '{}'".format(src_file, i))
            abort = bool(i == (max_iters - 1))
            if self.console_file_transfer == 1:
                cft = 2 if (i == (max_iters - 1)) else 1
            else:
                cft = self.console_file_transfer
            dst_file = self._upload_file1(access, src_file, cft=cft, abort=abort, fallback=False)
            if not dst_file:
                pass
            elif self._check_md5(devname, access, prompt, src_file, dst_file):
                done = True
                break
        if not done and not dry_run:
            self._send_command(access, "sudo df", prompt, False)
            self.dut_err(devname, "Failed to upload '{}'".format(src_file))
            return None

        # uploaded to temp copy to needed location
        if dry_run:
            dst_file = "/tmp/{}".format(os.path.basename(src_file))
        script_cmd = "sudo mkdir -p {} && sudo cp -f {} {}".format(
            os.path.dirname(remote_file), dst_file, remote_file)
        done = False
        for i in range(1, max_iters):
            self.dut_log(devname, "Trying to copy file to '{}'. attempt '{}'".format(remote_file, i))
            output = self._send_command(access, script_cmd, prompt, False, 6)
            if "No such file or directory" not in output and "command not found" not in output:
                done = True
                break
        if not done and not dry_run:
            self.dut_log(devname, "Failed to execute '{}'".format(script_cmd))
        else:
            self.skip_trans_helper[devname][src_file] = remote_file
        return remote_file

    def _upload_file3(self, access, src_file, dst_file, cft):
        remote_dir = os.path.dirname(dst_file)

        devname = access["devname"]
        prompt = self._get_cli_prompt(devname)
        max_iters = 1 if self.is_filemode(devname) else 6
        for i in range(1, max_iters):
            self.dut_log(devname, "Trying to upload file '{}'. attempt '{}'".format(src_file, i))
            tmp_file = self._upload_file(access, src_file, cft=cft)
            if not tmp_file:
                pass
            else:
                ls_script_cmd = "sudo ls -lrt {}".format(tmp_file)
                output = self._send_command(access, ls_script_cmd, prompt, False)
                if "No such file or directory" not in output and "command not found" not in output:
                    break

        if remote_dir:
            script_cmd = "sudo mkdir -p {} && sudo cp -f {} {}".format(
                remote_dir, tmp_file, dst_file)
            devname = access["devname"]
            cli_prompt = self._get_cli_prompt(devname)
            done = False
            for i in range(1, max_iters):
                self.dut_log(devname, "Trying to copy file to '{}'. attempt '{}'".format(dst_file, i))
                output = self._send_command(access, script_cmd, cli_prompt, False, 6, on_cr_recover="retry5")
                if "No such file or directory" not in output and "command not found" not in output:
                    done = True
                    break
            if not done:
                self.dut_log(devname, "Failed to execute '{}'".format(script_cmd))

    def _download_file_try(self, access, src_file, dst_file, is_txt=True):
        devname = access["devname"]
        msg = "Download: SRC({}): {} DST({}): {}".format(devname, src_file, "SVR/VDI", dst_file)
        self.dut_log(devname, msg)
        if self.is_filemode(devname):
            return "SUCCESS"
        cinfo = access["connection_param"]
        try:
            msg = "Doing SFTP download {}".format(cinfo["mgmt-ip"])
            self.dut_log(devname, msg)
            try:
                DeviceFileDownload(self._get_handle(devname), src_file, dst_file, logger=self.logger, **cinfo)
            except Exception:
                self.dut_log(devname, "SFTP Failed - Try again after reading mgmt-ip")
                self._fetch_mgmt_ip(devname)
                msg = "Doing SFTP download {}".format(cinfo["mgmt-ip"])
                self.dut_log(devname, msg)
                DeviceFileDownload(self._get_handle(devname), src_file, dst_file, logger=self.logger, **cinfo)

            if os.path.exists(dst_file):
                tmp_filesize = str(os.stat(dst_file).st_size)
                msg = "Downloaded file '{}' exists with size '{}' on SVR/VDI".format(dst_file, tmp_filesize)
                self.dut_log(devname, msg)
            else:
                msg = "Downloaded file '{}' not-exists on SVR/VDI".format(dst_file)
                self.dut_log(devname, msg)
                return "FAIL"
        except Exception as e:
            if not is_txt:
                self.dut_log(devname, "SFTP Failed")
                return "FAIL"
            try:
                self.dut_log(devname, "SFTP Failed - Doing transfer using filedata on console")
                cmd = "file {}".format(src_file)
                line = utils.get_line_number()
                output = self._show(line, devname, cmd, skip_tmpl=True, skip_error_check=True)
                if "ASCII" in output:
                    cmd = "cat {}".format(src_file)
                    line = utils.get_line_number()
                    output = self._show(line, devname, cmd, skip_tmpl=True, skip_error_check=True)
                    content = output[:output.rfind(nl)]
                    dst_fp = open(dst_file, "w")
                    dst_fp.write(content)
                    dst_fp.close()
                else:
                    if "No such file or directory" in output:
                        self.dut_log(devname, "File {} not found".format(src_file))
                    else:
                        self.dut_log(devname, "Only text based files can be transferred using console")
                    self.logger.info(e)
                    return "FAIL"
            except Exception as e1:
                self.logger.info(e1)
                return "FAIL"
        return "SUCCESS"

    def _download_file(self, access, src_file, dst_file, is_txt=True):
        for i in range(3):
            rv = self._download_file_try(access, src_file, dst_file, is_txt)
            if rv == "SUCCESS" or i >= 2:
                return rv
            self.dut_log(access["devname"], "Waiting for 5 seconds and trying again")
            time.sleep(5)
        return "FAIL"

    def add_pending_download(self, devname, remote_file_path, local_file_path):
        if devname not in self.pending_downloads:
            self.pending_downloads[devname] = []
        self.pending_downloads[devname].append([remote_file_path, local_file_path])

    def check_pending_downloads(self, devname):
        # TODO: download the pending files
        self.pending_downloads[devname] = []

    def _get_routing_mode(self, devname):
        if self.wa.is_feature_supported("routing-mode-separated-by-default", devname):
            routing_mode = "separated"
        else:
            routing_mode = "split"
        return os.getenv("SPYTEST_ROUTING_CONFIG_MODE", routing_mode)

    def _add_swss_copp_config(self, devname, args_str):
        if not self.wa.is_feature_supported("swss-copp-config", devname):
            return args_str + " --no-swss-copp-config"
        return args_str

    def _add_config_method(self, devname, args_str):
        load_config_method = self.cfg.load_config_method
        if load_config_method in ["none"]:
            if self._get_routing_mode(devname) in ["separated"]:
                load_config_method = "force-reload"
            else:
                load_config_method = "reload"
        return args_str + " --load-config-method {}".format(load_config_method)

    @staticmethod
    def _add_core_dump_flags(args_str, value_list):
        core_flag = value_list[0]
        dump_flag = value_list[1]
        clear_flag = value_list[2]
        misc_flag = value_list[3]
        core_flag = "YES" if core_flag else "NO"
        dump_flag = "YES" if dump_flag else "NO"
        clear_flag = "YES" if clear_flag else "NO"
        misc_flag = "YES" if misc_flag else "NO"
        args_str = ",".join([core_flag, dump_flag, clear_flag, misc_flag])
        return args_str

    def _port_breakout_options(self, devname):
        breakout = self.tb.get_device_param(devname, "breakout", None)

        # indicate port breakout native type
        retval = ""
        if breakout and "native" in breakout:
            native = breakout["native"]
            if "{}".format(native) == "1":
                retval = " --breakout-native"

        # handle case when breakout is not specified
        if not retval and self.cfg.breakout_mode != "script":
            retval = " --breakout-native"

        # custom port breakout
        if breakout and \
           "name" in breakout and \
           "ports" in breakout and \
           "options" in breakout:
            name = breakout["name"]
            ports = breakout["ports"]
            options = breakout["options"]
            cust_platform_dict = SpyTestDict()
            cust_platform_dict[name] = SpyTestDict()
            cust_platform_dict[name]["breakout"] = SpyTestDict()
            cust_platform_dict[name]["breakout"][",".join(map(str, ports))] = options
            devname = self._check_devname(devname)
            access = self._get_dev_access(devname)
            cust_platform_json = json.dumps(cust_platform_dict, indent=4)
            dst_file = "/tmp/custom_breakout.json"
            self._echo_text_to_file(access, cust_platform_json, dst_file)
            retval = retval + " --breakout-file {}".format(dst_file)

        return retval

    def make_local_file_path(self, devname=None, filepath=None, suffix=None,
                             ts=None, prefix=None, ext=None, dut_label=None):
        parts = []
        if prefix: parts.append(prefix)
        parts.append(time.strftime("%Y%m%d%H%M%S") if not ts else ts)
        if dut_label or devname: parts.append(dut_label or self._get_dut_label(devname))
        if filepath: parts.append(filepath.replace(".py", "").replace("/", "_"))
        if suffix: parts.append(suffix)
        return os.path.join(self.logger.logdir, "{}{}".format("_".join(parts), ext or ""))

    def _upload_helper_file(self, devname, filename):
        if not filename:
            self._upload_helper_file(devname, "port_breakout.py")
            self._upload_helper_file(devname, "click-helper.py")
            self._upload_helper_file(devname, "gcov-helper.sh")
            self._upload_helper_file(devname, "asan.bashrc")
            helper = self._upload_helper_file(devname, "spytest-helper.py")
        else:
            helper = os.path.join(os.path.dirname(__file__), "remote", filename)
            helper = os.path.abspath(helper)
            access = self._get_dev_access(devname)
            helper = self._upload_file2(devname, access, helper, md5check=True)
        if not helper and not self.is_filemode(devname):
            msg = "Failed to upload helper file(s)"
            raise ValueError(msg)
        return helper

    def init_clean(self, devname, core, dump, misc=False):
        largs = [core, dump, self.cfg.clear_tech_support, misc]
        self.apply_remote(devname, "init-clean", largs)

    def check_config_reloaded(self, option_type, output):
        config_ops = ["port-defaults", "config-reload"]
        config_ops.extend(["apply-init-config", "apply-base-config", "apply-module-config"])
        if option_type in config_ops:
            if re.search("CONFIG-RELOAD-ISSUED", output):
                return True
        return False

    def _add_env(self, args_str, name, default, value=None):
        value = value or env.get(name, default)
        if value != default:
            args_str = "{} --env {} {}".format(args_str, name, value)
        return args_str

    def apply_remote(self, devname, option_type, value_list=None, **kwargs):
        value_list = value_list or []
        devname = self._check_devname(devname)
        access = self._get_dev_access(devname)

        # ensure we are in sonic mode
        self._enter_linux(devname)

        # transfer the python file, which is used to apply the files remotely.
        change_in_tryssh = self.tryssh_switch(devname)
        helper = self._upload_helper_file(devname, "spytest-helper.py")
        if change_in_tryssh: self.tryssh_switch(devname, True)

        if option_type == "port-defaults" and value_list[0]:
            self._upload_helper_file(devname, "port_breakout.py")

        if option_type == "dump-click-cmds":
            helper = self._upload_helper_file(devname, "click-helper.py")

        if option_type == "asan-config":
            self._upload_helper_file(devname, "asan.bashrc")

        if option_type == "service-start":
            service_name = value_list[0]
            self._upload_helper_file(devname, "service-{}".format(service_name))

        args_str = ""
        script_cmd = None
        skip_error_check = False
        execute_in_console = env.match("SPYTEST_HELPER_FORCE_CONSOLE", "1", "0")
        delay_factor = 6
        live_tracing = True
        live_tracing_force = False
        check_signature = env.get("SPYTEST_CHECK_HELPER_SIGNATURE", "0")

        # Depending on the option value, do the pre tasks.
        if option_type == "apply-configs":
            execute_in_console = True
            # transfer the config files
            dst_file_list = []
            method = value_list[0]
            for name in value_list[1:]:
                for src_file in utils.make_list(name):
                    dst_file = self._upload_file2(devname, access, src_file)
                    if dst_file: dst_file_list.append(dst_file)
            args_str = '"' + '" "'.join(dst_file_list) + '"'
            args_str = args_str + " --apply-file-method " + method
            args_str = self._add_swss_copp_config(devname, args_str)
            self.dut_log(devname, "Applying config files remotely '{}'".format(args_str))
            skip_error_check = True
        elif option_type == "run-test":
            timeout = value_list[0]
            args_str = " ".join(value_list[1:])
            delay_factor = int(math.ceil((timeout * 1.0) / 100))
        elif option_type == "init-ta-config":
            # execute_in_console = True
            profile_name = value_list[-1].lower()
            args_str = self._add_core_dump_flags(args_str, value_list[:-1])
            args_str = args_str + " --config-profile {}".format(profile_name)
            args_str = self._add_env(args_str, "SPYTEST_BASE_CONFIG_RETAIN_FDB_AGETIME", "0")
            args_str = self._add_env(args_str, "SPYTEST_NTP_CONFIG_INIT", "0")
            args_str = self._add_env(args_str, "SPYTEST_CLEAR_MGMT_INTERFACE", "0")
            args_str = self._add_env(args_str, "SPYTEST_CLEAR_DEVICE_METADATA_HOSTNAME", "0")
            args_str = self._add_env(args_str, "SPYTEST_CLEAR_DEVICE_METADATA_BGP_ASN", "0")
            args_str = self._add_env(args_str, "SPYTEST_ONINIT_CLEAR", "sairedis")
            routing_mode = self._get_routing_mode(devname)
            args_str = self._add_env(args_str, "SPYTEST_ROUTING_CONFIG_MODE", "", routing_mode)
            args_str = self._add_swss_copp_config(devname, args_str)
        elif option_type in ["save-base-config", "save-module-config"]:
            # execute_in_console = True
            # no arguments are required to create ta config
            args_str = ""
            args_str = self._add_swss_copp_config(devname, args_str)
        elif option_type in ["apply-init-config"]:
            execute_in_console = True
            args_str = self._add_config_method(devname, "")
            args_str = self._add_swss_copp_config(devname, args_str)
        elif option_type in ["apply-base-config", "apply-module-config"]:
            execute_in_console = True
            args_str = self._add_config_method(devname, "")
            args_str = self._add_swss_copp_config(devname, args_str)
            skip_error_check = True
        elif option_type == "disable-debug":
            # no arguments are required to disabling debug messages on to console
            args_str = ""
        elif option_type == "enable-debug":
            # no arguments are required to enabling debug messages on to console
            args_str = ""
        elif option_type == "syslog-check":
            live_tracing = False
            args_str = value_list[0]
            args_str = args_str + " --phase {}".format(value_list[1])
            if value_list[2]:
                args_str = args_str + " --identity '{}'".format(value_list[2])
            skip_error_check = True
            delay_factor = 9
        elif option_type == "sairedis":
            args_str = value_list[0]
            skip_error_check = True
            delay_factor = 9
        elif option_type == "fetch-warmboot":
            args_str = ""
            skip_error_check = True
            delay_factor = 9
        elif option_type == "set-mgmt-ip":
            execute_in_console = True
            args_str = " {} ".format(value_list[0])
            args_str = args_str + " --ip-addr-mask {}".format(value_list[1])
            args_str = args_str + " --gw-addr {}".format(value_list[2])
        elif option_type == "fetch-core-files":
            live_tracing_force = True
            if self.wa.hooks.is_kdump_supported(devname):
                args_str = "collect_kdump"
            else:
                args_str = "none"
            skip_error_check = True
            delay_factor = 12
        elif option_type == "fetch-gcov-files":
            live_tracing_force = True
            execute_in_console = env.match("SPYTEST_GCOV_COLLECTION_USING_CONSOLE", "1", "1")
            self._upload_helper_file(devname, "gcov-helper.sh")
            skip_error_check = True
            delay_factor = 18
            args_str = "none"
        elif option_type == "get-tech-support":
            live_tracing_force = True
            if not self.wa.is_feature_supported("show-tech-support-since", devname):
                args_str = 0
            else:
                args_str = access["num_tech_support"]
            access["num_tech_support"] = access["num_tech_support"] + 1
            skip_error_check = True
            max_time = utils.max(env.getint("SPYTEST_SHOWTECH_MAXTIME", 1200), 1200)
            delay_factor = max_time_to_delay_factor(max_time)
        elif option_type == "init-clean":
            # execute_in_console = True
            args_str = self._add_core_dump_flags(args_str, value_list)
        elif option_type == "update-reserved-ports":
            live_tracing = False
            args_str = ' '.join(value_list[0])
        elif option_type == "port-defaults":
            execute_in_console = True
            args_str = ""
            if value_list[0]:
                args_str = args_str + " --breakout {}".format(' '.join(value_list[0]))
                args_str = args_str + self._port_breakout_options(devname)
            if value_list[1]:
                args_str = args_str + " --speed {}".format(' '.join(map(str, value_list[1])))
            args_str = self._add_config_method(devname, args_str)
            skip_error_check = True
        elif option_type == "config-reload":
            execute_in_console = True
            args_str = value_list[0]
            args_str = self._add_config_method(devname, args_str)
            delay_factor = int(math.ceil((value_list[1] * 1.0) / 100))
            delay_factor = 9 if delay_factor < 9 else delay_factor
            skip_error_check = True
        elif option_type == "wait-for-ports":
            args_str = value_list[0]
        elif option_type == "dump-click-cmds":
            check_signature = "0"
            option_type = ""
            args_str = env.get("SPYTEST_CLICK_HELPER_ARGS", "")
        elif option_type == "asan-config":
            pass
        elif option_type == "service-start":
            args_str = value_list[0]
            count = int((len(value_list) - 1) / 2)
            for index in range(1, count, 2):
                name = value_list[index * 2 + 1]
                value = value_list[index * 2 + 2]
                args_str = args_str + " --env {} {}".format(name, value)
        elif option_type == "service-stop":
            args_str = value_list[0]
        elif option_type == "service-get":
            args_str = value_list[0]
        else:
            msg = "Unknown option {} for remote operation".format(option_type)
            self.dut_err(devname, msg)
            raise ValueError(msg)

        # adjust the delay factor if too low
        delay_factor = 3 if delay_factor < 3 else delay_factor

        ############################################################
        # Construct the command that need to be executed on the DUT.
        ############################################################
        if env.get("SPYTEST_HELPER_DEBUG", "0") != "0":
            args_str = "{} --debug".format(args_str)
        if option_type:
            script_cmd = "sudo python {} --{} {}  ".format(helper, option_type, args_str)
        else:
            script_cmd = "sudo python {} {}  ".format(helper, args_str)
        # self.dut_log(devname, "Using command: {}".format(script_cmd))
        ############################################################

        try:
            # switch to console if we expect management connection loss
            change_in_tryssh = False
            if execute_in_console:
                change_in_tryssh = self.tryssh_switch(devname)
                if not self.is_filemode(devname):
                    cli_prompt = self._get_cli_prompt(devname)
                    curr_prompt = self._find_prompt(access, use_cache=False)
                    # ensure we are in sonic mode
                    if curr_prompt != cli_prompt:
                        msg = "Console prompt mode '{}' is not correct .. Trying to enter the correct mode '{}'."
                        msg = msg.format(curr_prompt.replace("\\", ""), cli_prompt.replace("\\", ""))
                        self.dut_warn(devname, msg)
                        self._enter_linux(devname)

            # enable live tracing for debugging
            self.trace_callback_set(devname, live_tracing, live_tracing_force)

            ################## Execute script and verify Signature #############
            signature = "################ SPYTEST-HELPER ####################"
            missing_file_errno = "Errno 2"
            invalid_or_unknown_args = "Error: Invalid/Unknown arguments"
            output, failed, dbg_ipaddr = "", True, False
            for i in range(3):
                cli_prompt = self._get_cli_prompt(devname)
                if delay_factor > 5:
                    max_time = max_time_from_delay_factor(delay_factor)
                    msg = "Execute '{}' with timeout {} sec -- TRY {}".format(script_cmd.strip(), max_time, (i + 1))
                    self.dut_warn(devname, msg)

                # add login to the expected prompts to detect silent reboots
                regex_login = self.wa.hooks.get_regex(devname, "login")
                regex_login_anywhere = self.wa.hooks.get_regex(devname, "login_anywhere")
                prompt_list = [cli_prompt, regex_login, regex_login_anywhere]
                expect = "|".join(prompt_list)
                output = self._send_command(access, script_cmd, expect,
                                            skip_error_check, delay_factor,
                                            trace_log=1)
                if self.is_filemode(devname):
                    failed = False
                    break
                if regex_login_anywhere.replace("\\", "") in output:
                    msg = "Unexpected Login prompt seen while executing: {}".format(script_cmd)
                    self.dut_err(devname, msg)
                    break
                if re.search(missing_file_errno, output):
                    self.dut_warn(devname, "trying again as '{}' seen".format(missing_file_errno))
                    dbg_ipaddr = True
                    continue
                if re.search(invalid_or_unknown_args, output):
                    self.dut_warn(devname, "trying again as '{}' seen".format(invalid_or_unknown_args))
                    dbg_ipaddr = True
                    continue
                if check_signature == "0" or re.search(signature, output):
                    failed = False
                    break
                msg = "Failed to execute the command {} Try: {}".format(script_cmd, i)
                self.dut_err(devname, msg)
            if failed:
                self.dut_log(devname, output)
                if dbg_ipaddr:
                    try: self.read_mgmt_ip(devname, self.get_mgmt_ifname(devname))
                    except Exception: pass
                self._report_cmd_fail(devname, script_cmd, utils.get_line_number())
            output = output.replace(signature, "")
            ####################################################################

            # disable live tracing
            self.trace_callback_set(devname, False, live_tracing_force)

            # trace output
            if self.default_trace_log in [2, 3]:
                self.dut_log(devname, output)

            # login again to detect any prompt changes
            if self.check_config_reloaded(option_type, output):
                if execute_in_console:
                    if self.relogin_on_config_reload:
                        self.login_again(devname)

            # restore to tryssh if we switched to console before executing
            if change_in_tryssh: self.tryssh_switch(devname, True)

        except Exception as exp:
            msg = utils.stack_trace(None, True)
            self.dut_warn(devname, msg)
            if execute_in_console:
                self.tryssh_switch(devname, False)
            raise exp

        if option_type in ["run-test", ""]:
            return output

        if self.check_config_reloaded(option_type, output):
            self.wa.hooks.post_config_reload(devname)

        if option_type == "syslog-check":
            if re.search("NO-SYSLOGS-CAPTURED", output):
                return output
            elif re.search("SYSLOGS_CAPTURED_FILE", output):
                # Get the remote file name from the output data.
                remote_file_path = ""
                for line in output.strip().split("\n"):
                    match = re.match(r'SYSLOGS_CAPTURED_FILE:\s+(/etc/spytest/syslog.txt)', str(line).strip())
                    if match:
                        remote_file_path = match.group(1)
                        break
                if remote_file_path:
                    # Construct the local file name.
                    local_file_path = self.make_local_file_path(devname, "_".join(value_list[1:]),
                                                                "syslog.txt", value_list[0])
                    # Perform the file download if any files found.
                    retval = self._download_file(access, remote_file_path, local_file_path)
                    if re.search("FAIL", retval):
                        self.add_pending_download(devname, remote_file_path, local_file_path)
                        msg = "Downloading syslog file - Failed."
                        self.dut_err(devname, msg)
                        raise ValueError(msg)
                    msg = "Downloaded the captured syslog data to the file '{}'."
                    self.dut_log(devname, msg.format(local_file_path))

                    try:
                        cmdlist = utils.read_lines(local_file_path)
                        lines = [line.strip() for line in cmdlist if syslog.match(value_list[0], line)]
                        retval = nl.join(lines)
                        if len(lines) >= 1000:
                            msg = "lot of syslog messages - refer to {}".format(local_file_path)
                            self.dut_warn(devname, msg)
                        elif len(lines) > 0:
                            self.dut_log(devname, "=" * 17 + " MATCHED SYSLOG " + "=" * 17)
                            self.dut_log(devname, retval)
                            self.dut_log(devname, "=" * 50)
                    except Exception:
                        retval = "Error: Exception occurred while reading the syslog captured file '{}'".format(local_file_path)
                        self.dut_warn(devname, retval)
                    return retval
                else:
                    msg = "Failed to get the syslog file '/etc/spytest/syslog.txt'"
                    self.dut_err(devname, msg)
            else:
                return output

        process_apply_config = True
        fetch_mgmt_ip = False
        if re.search("Error", output) or re.search("No such file or directory", output):
            msg = "Failed to execute the command {}".format(script_cmd)
            self.dut_err(devname, msg)
            if option_type in ["apply-init-config"]:
                self.wa.hooks.dump_config_db(devname)
            if option_type not in ["apply-base-config", "apply-module-config", "port-defaults"]:
                raise ValueError(msg)
            msg = "Recovering the devices by rebooting"
            self.dut_err(devname, msg)
            process_apply_config = False
            self.recover(devname, "Recovering the devices")

        if option_type in ["apply-base-config", "apply-module-config"] and process_apply_config:
            if not re.search("Config, FRR, COPP are same as TA files", output):
                fetch_mgmt_ip = True
                if option_type in ["apply-module-config"] and self.prev_testcase:
                    pc_msg = "***** TESTCASE '{}' CONFIG CLEANUP NOT DONE *****".format(self.prev_testcase)
                    self.dut_warn(devname, pc_msg)
                if re.search("RPS REBOOT REQUIRED", output):
                    self.recover(devname, "RPS Reboot after applying TA configuration", method="rps")
                elif re.search("REBOOT REQUIRED", output):
                    self.recover(devname, "Reboot after applying TA configuration")

        if option_type == "dump-click-cmds":
            file_name = "results_{0}_{1}_build_cmds.txt".format(
                time.strftime("%Y_%m_%d_%H_%M"), devname)
            local_file_path = str(os.path.join(self.logger.logdir, file_name))
            utils.write_file(local_file_path, "")
            for line in output.strip().split(nl)[:-1]:
                utils.write_file(local_file_path, "{}\n".format(line), "a")

        if option_type == "fetch-warmboot":
            if re.search("NO-WARMBOOT-FILES", output):
                msg = "No WARMBOOT files found on the DUT."
                self.dut_log(devname, msg)
            else:
                # Get the remote file name from the output data.
                remote_file_path = ""
                for line in output.strip().split(nl):
                    match = re.match(r'WARMBOOT-FILES:\s+(\S+.tar.gz)', str(line).strip())
                    if match:
                        remote_file_path = match.group(1)
                        break
                if remote_file_path:
                    # Construct the local file name.
                    local_file_path = self.make_local_file_path(devname, None, "warmboot.tar.gz")
                    # Perform the file download if any files found.
                    retval = self._download_file(access, remote_file_path, local_file_path, False)
                    if re.search("FAIL", retval):
                        self.add_pending_download(devname, remote_file_path, local_file_path)
                        msg = "Downloading warmboot files - Failed."
                        self.dut_err(devname, msg)
                        raise ValueError(msg)

        if option_type == "fetch-gcov-files":
            if re.search("NO-GCOV-FILES", output):
                msg = "No GCOV files found on the DUT."
                self.dut_log(devname, msg)
            elif self.is_filemode(devname):
                local_file_path = self.make_local_file_path(devname, value_list[0], "gcov.tar.gz", dut_label=devname)
                utils.write_file(local_file_path, "")
            else:
                # Get the remote file name from the output data.
                remote_file_path = ""
                for line in output.strip().split(nl):
                    match = re.match(r'GCOV-FILES:\s+(\S+.tgz)', str(line).strip())
                    if match:
                        remote_file_path = match.group(1)
                        break
                if remote_file_path:
                    # Construct the local file name.
                    local_file_path = self.make_local_file_path(devname, value_list[0], "gcov.tar.gz", dut_label=devname)
                    # Perform the file download if any files found.
                    retval = self._download_file(access, remote_file_path, local_file_path, False)
                    if re.search("FAIL", retval):
                        self.add_pending_download(devname, remote_file_path, local_file_path)
                        msg = "Downloading GCOV files - Failed."
                        self.dut_err(devname, msg)
                        raise ValueError(msg)

        if option_type == "fetch-core-files":
            if re.search("NO-CORE-FILES", output):
                msg = "No Core files found on the DUT."
                self.dut_log(devname, msg)
            else:
                # Get the remote file name from the output data.
                remote_file_path = ""
                for line in output.strip().split(nl):
                    match = re.match(r'CORE-FILES:\s+(\S+.tar.gz)', str(line).strip())
                    if match:
                        remote_file_path = match.group(1)
                        break
                if remote_file_path:
                    # Construct the local file name.
                    local_file_path = self.make_local_file_path(devname,
                                                                value_list[0], "corefiles.tar.gz")
                    # Perform the file download if any files found.
                    retval = self._download_file(access, remote_file_path, local_file_path, False)
                    if re.search("FAIL", retval):
                        self.add_pending_download(devname, remote_file_path, local_file_path)
                        msg = "Downloading core files - Failed."
                        self.dut_err(devname, msg)
                        raise ValueError(msg)
            if self.wa.hooks.is_kdump_supported(devname):
                if re.search("NO-KDUMP-FILES", output):
                    msg = "No kdump files found on the DUT."
                    self.dut_log(devname, msg)
                else:
                    # Get the remote file name from the output data.
                    # remote_file_path = "/tmp/allcorefiles.tar.gz"
                    remote_file_path = ""
                    for line in output.strip().split(nl):
                        match = re.match(r'KDUMP-FILES:\s+(\S+.tar.gz)', str(line).strip())
                        if match:
                            remote_file_path = match.group(1)
                            break
                    if remote_file_path:
                        # Construct the local file name.
                        local_file_path = self.make_local_file_path(devname,
                                                                    value_list[0], "kdumpfiles.tar.gz")
                        # Perform the file download if any files found.
                        retval = self._download_file(access, remote_file_path, local_file_path, False)
                        if re.search("FAIL", retval):
                            self.add_pending_download(devname, remote_file_path, local_file_path)
                            msg = "Downloading kdump files - Failed."
                            self.dut_err(devname, msg)
                            raise ValueError(msg)

        if option_type == "get-tech-support":
            if re.search("NO-DUMP-FILES", output):
                self.dut_log(devname, output)
                output = self._show(line, devname, "cat /tmp/show_tech_support.log",
                                    skip_error_check=True, skip_tmpl=True)
                self.dut_log(devname, output)
                raise ValueError("Failed to fetch tech support")

            # Get the remote file name from the output data.
            remote_file_path = ""
            for line in output.strip().split(nl):
                match = re.match(r'DUMP-FILES:\s+(\S+.tar.gz)', str(line).strip())
                if match:
                    remote_file_path = match.group(1)
                    break

            # download the file to local path
            if remote_file_path:
                # Construct the local file name.
                local_file_name = os.path.basename(remote_file_path).replace("sonic_dump_sonic_", "")
                local_file_path = self.make_local_file_path(devname, value_list[0], local_file_name, "techsupport")
                # Perform the file download if any files found.
                for _ in range(2):
                    retval = self._download_file(access, remote_file_path, local_file_path, False)
                    if re.search("FAIL", retval):
                        fail_flag = True
                        continue
                    fail_flag = False
                    break
                # is downloaded ?
                if fail_flag:
                    self.add_pending_download(devname, remote_file_path, local_file_path)
                    msg = "Downloading tech-support files - Failed."
                    self.dut_err(devname, msg)
                    raise ValueError(msg)
                # all is well
                if env.get("SPYTEST_TECH_SUPPORT_DELETE_ON_DUT", "0") == "1":
                    self.dut_log(devname, "Removing the generated tech-support file on the DUT.")
                    self._config(devname, "rm -f {}".format(remote_file_path), sudo=True, skip_error_check=True)
                profile.tech_support(local_file_path)
            elif not self.is_filemode(devname):
                self.dut_err(devname, "Failed to read DUMP File")
            else:
                current_datetime = utils.get_current_datetime("%Y%m%d_%H%M%S")
                local_file_name = "{}.tar.gz".format(current_datetime)
                local_file_path = self.make_local_file_path(devname, value_list[0], local_file_name, "techsupport")
                utils.write_file(local_file_path, "")
                self.dut_log(devname, "Created {}".format(local_file_path))

        if option_type == "sairedis" and value_list[0] == "read":
            if re.search("NO-SAIREDIS-FILE", output):
                self.dut_log(devname, output)
            else:
                # Get the remote file name from the output data.
                remote_file_path = ""
                for line in output.strip().split(nl):
                    match = re.match(r'SAI-REDIS-FILE:\s+(/etc/spytest/sairedis.txt)', str(line).strip())
                    if match:
                        remote_file_path = match.group(1)
                        break
                if remote_file_path:
                    # Construct the local file name.
                    local_file_path = self.make_local_file_path(devname,
                                                                value_list[1], ".log", "sairedis")
                    # Perform the file download if any files found.
                    retval = self._download_file(access, remote_file_path, local_file_path)
                    if re.search("FAIL", retval):
                        self.add_pending_download(devname, remote_file_path, local_file_path)
                        msg = "Downloading sai radis files - Failed."
                        self.dut_err(devname, msg)
                        raise ValueError(msg)
                elif not self.is_filemode(devname):
                    msg = "Failed to read sai radis File"
                    self.dut_err(devname, msg)

        # fetch the management IP again
        if fetch_mgmt_ip:
            self._fetch_mgmt_ip(devname)

        return True

    def flagit(self, devname, name, value, probe=False):
        devname = self._check_devname(devname)
        access = self._get_dev_access(devname)
        retval = bool(name not in access["flags"] or value != access["flags"][name])
        if not probe: access["flags"][name] = value
        if not retval and value and not probe:
            self.dut_dbg(devname, "{} already in progress".format(name))
        return retval

    def clear_all_flags(self, devname):
        if devname is not None:
            devname = self._check_devname(devname)
            access = self._get_dev_access(devname)
            access["flags"].clear()
            return
        for _devname in self.topo.duts:
            self.clear_all_flags(_devname)

    def get_access_param(self, devname, name, default=None):
        devname = self._check_devname(devname)
        access = self._get_dev_access(devname)
        return access.get(name, default)

    def generate_tech_support(self, devname, name):
        which = "get-tech-support"
        for scope in ["module", "function"]:
            if not self.get_access_param(devname, scope + "-" + which):
                return
        if not self.flagit(devname, which, True):
            return
        try:
            output = self.wa.hooks.read_tech_support(devname, name)
            if output is None:
                self.apply_remote(devname, which, [name])
        except Exception: self.dut_err(devname, "Failed {} {}".format(which, name))
        self.flagit(devname, which, False)

    def collect_core_files(self, devname, name):
        which = "fetch-core-files"
        for scope in ["module", "function"]:
            if not self.get_access_param(devname, scope + "-" + which):
                return
        if not self.flagit(devname, which, True):
            return
        try:
            output = self.wa.hooks.read_core(devname, name)
            if output is None:
                output = self.apply_remote(devname, which, [name])
        except Exception: self.dut_err(devname, "Failed {} {}".format(which, name))
        self.flagit(devname, which, False)

    def fetch_gcov_files_try(self, devname, name):
        if not self.flagit(devname, "fetch-gcov-files", True): return
        retval = True
        try: self.apply_remote(devname, "fetch-gcov-files", [name])
        except Exception: retval = False
        self.flagit(devname, "fetch-gcov-files", False)
        return retval

    def fetch_gcov_files(self, devname, name):
        if self.fetch_gcov_files_try(devname, name): return
        self.dut_err(devname, "Failed to collect GCOV data {} retry after recovery".format(name))
        try: self.recover_hard(devname, "Recovering the devices")
        except Exception: return
        if self.fetch_gcov_files_try(devname, name): return
        self.dut_err(devname, "Failed to collect GCOV data {} even after recovery".format(name))

    def syslog_check(self, devname, phase, lvl, name):

        if phase == "post-module-prolog":
            msgtype = "Module Prolog"
        elif phase == "pre-module-epilog":
            msgtype = "Module Epilog"
        elif phase == "post-module-epilog":
            msgtype = "Module Epilog"
        elif phase == "post-function-epilog":
            msgtype = name
        else:
            msgtype = ""

        output = self.wa.hooks.read_syslog(devname, lvl, phase, name)
        if output is None:
            output = self.apply_remote(devname, "syslog-check", [lvl, phase, name])
        dut_name = self._get_dut_label(devname)
        access = self._get_dev_access(devname)
        entries = syslog.parse(phase, lvl, msgtype, dut_name, output, access["filemode"])
        failmsg = syslog.store(phase, self.syslogs[devname], entries)
        retval = failmsg
        for scope in ["module", "function"]:
            if not self.get_access_param(devname, scope + "-syslog-check"):
                retval = None
        if not retval and failmsg:
            msg = "Skip reporting syslog error: {}".format(failmsg)
            self.dut_warn(devname, msg)
        return retval

    def get_fcli(self):
        return 1 if self.module_faster_cli and self.function_faster_cli else 0

    def get_tryssh(self):
        return self.tryssh

    def get_syslogs(self, clear=True):
        retval = []
        for devname in self.topo.duts:
            retval.extend(self.syslogs[devname])
            if clear:
                self.syslogs[devname] = []
        return retval

    def apply_files(self, devname, file_list, method="incremental"):
        if not file_list:
            return
        devname = self._check_devname(devname)
        for filepath in file_list:
            if isinstance(filepath, list):
                val_list = [method]
                val_list.extend(filepath)
                self.apply_remote(devname, "apply-configs", val_list)
            elif filepath == "__reboot__":
                msg = "Applying __reboot__"
                self.dut_warn(devname, msg)
                self.reboot(devname, skip_port_wait=True)
            elif filepath.endswith('.cmds'):
                msg = "Applying commands from {}".format(filepath)
                self.dut_log(devname, msg)
                cmdlist = utils.read_lines(filepath)
                self.apply_script(devname, cmdlist)
            else:
                self.apply_remote(devname, "apply-configs", [method, filepath])

        # Get the vtysh hostname from DUT as the config may have changed
        self.update_prompts_hostname(devname)
        # set required environment variables as the config may have reset
        self.set_login_timeout(devname)

    def run_script(self, devname, timeout, script_path, *args):
        val_list = [timeout, script_path]
        for arg in args:
            val_list.append(arg)
        return self.apply_remote(devname, "run-test", val_list)

    def read_mgmt_ip(self, devname, mgmt_ifname=None):
        mgmt_ifname = mgmt_ifname or self.get_mgmt_ifname(devname)
        output = self.wa.hooks.get_mgmt_ip(devname, mgmt_ifname)
        return output

    def _clear_mgmt_ip(self, devname):
        devname = self._check_devname(devname)
        access = self._get_dev_access(devname)
        access["connection_param"]["mgmt-ip"] = None

    def _get_mgmt_ip(self, devname):
        devname = self._check_devname(devname)
        access = self._get_dev_access(devname)
        if self.is_filemode(devname):
            return ""

        connection_param = access["connection_param"]
        if self._is_console_connection(devname):
            return connection_param["mgmt-ip"]
        return connection_param['ip']

    def get_mgmt_ifname(self, devname):
        devname = self._check_devname(devname)
        access = self._get_dev_access(devname)
        return access.get("mgmt_ifname", "eth0")

    def get_mgmt_ip(self, devname):
        addr = self._get_mgmt_ip(devname)
        if not addr or addr == "0.0.0.0":
            # eth0 IP is not available, try to read it now
            try:
                self._fetch_mgmt_ip(devname)
                addr = self._get_mgmt_ip(devname)
            except Exception:
                addr = ""
        return addr

    def get_login_password(self, devname):
        devname = self._check_devname(devname)
        access = self._get_dev_access(devname)
        return access.get("password")

    def exec_ssh(self, devname, username=None, password=None, cmdlist=None):
        devname = self._check_devname(devname)
        access = self._get_dev_access(devname)

        if self.is_filemode(devname):
            return ""

        ip = self.get_mgmt_ip(devname)

        device = dict()
        if not username and not password:
            device = copy.copy(access["connection_param"])
            if "mgmt-ip" in device:
                del device["mgmt-ip"]
        elif not password:
            device["username"] = username
            device["password"] = access["password"]
            device["altpassword"] = access["altpassword"]
        elif not username:
            device["username"] = access["username"]
            device["password"] = password
        else:
            device["username"] = username
            device["password"] = password
        device["ip"] = ip
        device["port"] = 22
        device["blocking_timeout"] = 30
        device["access_model"] = "sonic_ssh"

        msgs = []
        net_connect = self._do_connect_cinfo(device, 0, msgs, devname)
        if not net_connect:
            msg = nl.join(msgs)
            self.dut_warn(devname, msg)
            return None

        output = []
        nc_prompt = self._find_prompt(access, net_connect, use_cache=False)
        for cmd in cmdlist or []:
            output.append(cmd)
            try:
                output.append(net_connect.send_command(cmd, nc_prompt))
            except Exception as e:
                output.append("Exception: {}".format(e))

        net_connect.disconnect()
        access["last-prompt"] = None
        output = nl.join(output)
        self.dut_log(devname, output)
        return output

    def _do_ssh_ip(self, ipaddress, username, password, altpassword=None, port=22,
                   devname=None, blocking_timeout=30, access_model="sonic_ssh"):

        # Construct the dict for connection
        cinfo = dict()
        cinfo["ip"] = ipaddress
        cinfo["username"] = username
        cinfo["password"] = password
        if altpassword is not None:
            cinfo["altpassword"] = altpassword
        cinfo["port"] = port
        cinfo["blocking_timeout"] = blocking_timeout
        cinfo["access_model"] = access_model

        # Check the reach-ability
        msgs = []
        check_type = "SSH " if not devname else "{} SSH ".format(devname)
        if not utils.ipcheck(ipaddress, 10, self.logger.warning, check_type):
            msgs.append("Unable to reach the remote machine '{}'".format(ipaddress))
            return None, msgs, cinfo

        # Connect to ssh server
        net_connect = self._do_connect_cinfo(cinfo, 0, msgs, devname=devname)
        if not net_connect:
            msg = "Unable to connect {}/{}/{}"
            msg = msg.format(ipaddress, username, password)
            if altpassword:
                msg = "{}|{}".format(msg, altpassword)
            self.logger.error(msg)
            msgs.append(msg)

        return net_connect, msgs, cinfo

    def exec_remote(self, ipaddress, username, password, scriptpath, wait_factor=2):

        net_connect, msgs, cinfo = self._do_ssh_ip(ipaddress, username, password)
        if not net_connect:
            raise ValueError(msgs)

        # Construct the temp location filename.
        dst_file = "/tmp/{}".format(os.path.basename(scriptpath))

        # mgmt-ip should not be assigned during the connection initiation.
        cinfo["mgmt-ip"] = None

        # Upload the script to Linux server.
        try:
            self.logger.info("Doing SCP transfer of file '{}' to '{}'".format(scriptpath, ipaddress))
            DeviceFileUpload(net_connect, scriptpath, dst_file, logger=self.logger, **cinfo)
        except Exception:
            msg = "SCP transfer of file '{}' failed to the server '{}'".format(scriptpath, ipaddress)
            self.logger.error(msg)
            raise ValueError(msg)

        linux_prompt = net_connect.find_prompt()
        self.logger.debug("LINUX_PROMPT: {}".format(linux_prompt))

        # Change the permissions of the uploaded file
        self.logger.info("Changing permissions for '{}'".format(dst_file))
        cmd = "chmod 755 {} ".format(dst_file)
        net_connect.send_command(cmd, expect_string=linux_prompt, delay_factor=wait_factor)
        net_connect.clear_buffer()

        # Execute the script
        self.logger.info("Executing script '{}'".format(dst_file))
        output = net_connect.send_command(dst_file, expect_string=linux_prompt, delay_factor=wait_factor)
        net_connect.clear_buffer()

        # Disconnect the connection
        net_connect.disconnect()

        # Check for error
        if re.search("Error", output) or re.search("No such file or directory", output):
            msg = "Failed to execute the script: '{}' on remote machine '{}'".format(scriptpath, ipaddress)
            self.logger.error(msg)
            raise ValueError(msg)

        # Return the output
        return output

    def change_passwd(self, devname, username, password):
        devname = self._check_devname(devname)
        access = self._get_dev_access(devname)
        cli_prompt = self._get_cli_prompt(devname)

        if self.is_filemode(devname):
            return ""

        err_flag = 0
        self._enter_linux(devname)

        for _ in range(0, 3):
            delay_factor = 3  # so that --faster-cli is not used
            prompt_terminator = r"Enter new UNIX password:\s*$|New password:\s*$|{}\s*$".format(cli_prompt)
            output = self._send_command(access, "sudo passwd {}".format(username), prompt_terminator,
                                        delay_factor=delay_factor, use_cache=False)
            self.logger.debug("OUTPUT: {}".format(output))
            if re.search("Enter new UNIX password:", output):
                output = self._send_command(access, password, r"Retype new UNIX password:\s*$",
                                            delay_factor=delay_factor, use_cache=False)
                self.logger.debug("OUTPUT: {}".format(output))
                if re.search(".*NIX password:", output):
                    output = self._send_command(access, password, cli_prompt,
                                                delay_factor=delay_factor, use_cache=False)
                    self.logger.debug("OUTPUT: {}".format(output))
                    if not re.search("password updated successfully", output):
                        err_flag = 1
                else:
                    err_flag = 1
            if re.search("New password:", output):
                output = self._send_command(access, password, r"Retype new password:\s*$",
                                            delay_factor=delay_factor, use_cache=False)
                self.logger.debug("OUTPUT: {}".format(output))
                if re.search(".*assword:", output):
                    output = self._send_command(access, password, cli_prompt,
                                                delay_factor=delay_factor, use_cache=False)
                    self.logger.debug("OUTPUT: {}".format(output))
                    if not re.search("password updated successfully", output):
                        err_flag = 1
                else:
                    err_flag = 1
            elif re.search("does not exist", output):
                err_flag = 2
            else:
                err_flag = 1

            # Handling for worst case when required prompts didn't match.
            self._send_command(access, "\n\n\n", cli_prompt)

            if err_flag == 0: break

        if err_flag == 2:
            return "user not found"

        if err_flag == 1:
            return "Password updation failed"

        return "Password updated successfully"

    def upload_file_to_dut(self, devname, src_file, dst_file, cft):
        devname = self._check_devname(devname)
        access = self._get_dev_access(devname)

        if self.is_filemode(devname):
            return ""

        # ensure we are in sonic mode
        self._enter_linux(devname)

        return self._upload_file3(access, src_file, dst_file, cft)

    def download_file_from_dut(self, devname, src_file, dst_file=None):
        devname = self._check_devname(devname)
        access = self._get_dev_access(devname)

        if self.is_filemode(devname):
            return ""

        # ensure we have management IP address
        self._fetch_mgmt_ip(devname)

        dst_file = dst_file or self.get_logs_path(os.path.basename(src_file))
        return self._download_file(access, src_file, dst_file)

    def run_ansible_script(self, playbook, hosts, username, password, filemode=False, **kwargs):

        hosts = utils.make_list(hosts)

        msg = "Using call: ansible_playbook({}, {}, {}, {})"
        msg = msg.format(playbook, hosts, username, password)
        self.logger.info(msg)
        if filemode:
            return ""

        output = ""
        try:
            output = ansible_playbook(playbook, hosts, username, password,
                                      self.get_logs_path(), **kwargs)
        except Exception as e:
            self.logger.error(e)
            raise ValueError(e)

        if isinstance(output, bytes):
            output = output.decode('ascii')

        if re.search("Error", output) or re.search("No such file or directory", output):
            self.logger.error(output)
            raise ValueError(output)
        self.logger.info(output)
        return output

    def ansible_dut(self, devname, playbook, **kwargs):
        devname = self._check_devname(devname)
        access = self._get_dev_access(devname)
        host = None
        if self.is_filemode(devname) or not self._is_console_connection(devname):
            host = access["ip"]
        else:
            host = access["connection_param"]["mgmt-ip"]
        if not host:
            msg = "No management ip for device: '{}'".format(devname)
            self.dut_err(devname, msg)
            raise ValueError(msg)
        username = access["username"]
        password = access["password"]

        # self._get_server_envs(devname)

        # Issue echo command.
        self._check_dut_home(devname)

        tmp_home_path = os.environ['HOME']
        if os.environ['HOME'] != self.get_logs_path():
            os.environ['HOME'] = self.get_logs_path()

        output = ""
        try:
            output = self.run_ansible_script(playbook, host, username, password, access["filemode"], **kwargs)
        except Exception:
            password = access["altpassword"]
            output = self.run_ansible_script(playbook, host, username, password, access["filemode"], **kwargs)

        os.environ['HOME'] = tmp_home_path

        return output

    def ansible_service(self, service_data, playbook, **kwargs):
        host = service_data["ip"]
        username = service_data["username"]
        password = service_data["password"]

        return self.run_ansible_script(playbook, host, username, password, service_data["filemode"], **kwargs)

    def _get_server_envs(self, devname):
        devname = self._check_devname(devname)

        self.dut_log(devname, "Environmental variables in Server")
        for k, v in sorted(os.environ.items()):
            self.dut_log(devname, k + ':' + v)

    def _check_dut_home(self, devname):
        devname = self._check_devname(devname)
        access = self._get_dev_access(devname)

        cmd = "echo $HOME"
        if self.is_filemode(devname):
            self.dut_log(devname, "Command '{}'.".format(cmd))
            return True

        # ensure we are in sonic mode
        self._enter_linux(devname)

        # Issue command.
        try:
            cli_prompt = self._get_cli_prompt(devname)
            self._send_command(access, cmd, cli_prompt, True, 1)
            prompt = self._find_prompt(access, use_cache=False)
            if prompt == cli_prompt:
                return True
        except Exception:
            return False
        return False

    def add_addl_auth(self, devname, username, password, reset=False):
        devname = self._check_devname(devname)
        access = self._get_dev_access(devname)

        if "addl_auth" not in access or reset:
            access["addl_auth"] = []

        testbed_auth = access.get("testbed_auth", None)
        if testbed_auth and isinstance(testbed_auth, list):
            count = int(len(testbed_auth) / 2)
            for index in range(0, count, 2):
                tb_username = testbed_auth[index * 2]
                tb_password = testbed_auth[index * 2 + 1]
                found = False
                for au_username, au_password in access["addl_auth"]:
                    if tb_username == au_username and tb_password == au_password:
                        found = True
                        break
                if not found:
                    access["addl_auth"].append([tb_username, tb_password])
                    # msg = "Auth From Testbed {}/{}".format(tb_username, tb_password)
                    # self.dut_log(devname, msg)

        if username:
            access["addl_auth"].append([username, password])

        oniepassword = access.get("oniepassword", None)
        if oniepassword is not None:
            access["addl_auth"].append(["root", oniepassword])

        if "connection_param" in access:
            access["connection_param"]["addl_auth"] = access["addl_auth"]

    def module_init_start(self, max_timeout, fcli, tryssh):
        msg = "Net Module Init {} {} {}".format(max_timeout, fcli, tryssh)
        self.logger.info(msg)
        self.session_start_time = None
        self.module_start_time = get_timenow()
        self.module_max_timeout = max_timeout
        self.module_max_timeout_triggered = False
        self.module_faster_cli = fcli
        self.tryssh = tryssh
        self.tc_start_time = None
        self.clear_prevent()
        self.set_console_only(bool(not self.tryssh))
        self._reset_device_aliases()
        self._reset_prompt_hostname()
        self._set_config_session(None, conf_session=0)
        for devname in self.topo.duts:
            self.set_access_param(devname, "module-get-tech-support", "ts", 1)
            self.set_access_param(devname, "module-fetch-core-files", "core", 1)
            self.set_access_param(devname, "module-syslog-check", "syslog", 1)

    def set_module_params(self, devname, **kwargs):
        fcli = kwargs.get("faster_cli", self.module_faster_cli)
        fcli = utils.parse_integer(fcli, self.module_faster_cli)
        self.module_faster_cli = 1 if fcli else 0
        tryssh = utils.parse_integer(kwargs.get("tryssh", self.tryssh), self.tryssh)
        tryssh = 1 if tryssh else 0
        if tryssh != self.tryssh:
            self.tryssh = tryssh
            self.set_console_only(bool(not self.tryssh))
        self._set_config_session(devname, **kwargs)
        for devname in utils.make_list(devname or list(self.topo.duts.keys())):
            self.set_access_param(devname, "module-get-tech-support", "ts", 1, **kwargs)
            self.set_access_param(devname, "module-fetch-core-files", "core", 1, **kwargs)
            self.set_access_param(devname, "module-syslog-check", "syslog", 1, **kwargs)

    def set_access_param(self, devname, name, key, default, **kwargs):
        devname = self._check_devname(devname)
        access = self._get_dev_access(devname)
        access[name] = utils.parse_integer(kwargs.get(key, access[name]), default)

    def _set_config_session(self, devname, **kwargs):
        if "conf_session" not in kwargs: return
        if devname is None:
            putils.exec_foreach(self.cfg.faster_init, self.topo.duts,
                                self._set_config_session, **kwargs)
            return
        devname = self._check_devname(devname)
        access = self._get_dev_access(devname)
        value = bool(kwargs.get("conf_session"))
        if access["conf_session"] != value:
            msg = "conf_session from {} to {}".format(access["conf_session"], value)
            self.dut_warn(devname, "Changing {}".format(msg))
            self._abort_klish(devname)
            access["conf_session"] = value
            self.dut_warn(devname, "Changed {}".format(msg))

    def clear_devices_usage_list(self):
        self.devices_used_in_tc.clear()

    def get_devices_usage_list(self):
        return list(self.devices_used_in_tc.keys())

    def set_device_usage_collection(self, collect_flag):
        self.devices_used_collection = collect_flag

    def function_init_start(self, tc_max_timeout):
        msg = "Net Function Init {}".format(tc_max_timeout)
        self.logger.info(msg)
        self.module_start_time = None
        self.tc_max_timeout = tc_max_timeout
        self.tc_max_timeout_triggered = False
        self.tc_get_tech_support = False
        self.function_faster_cli = self.module_faster_cli
        for devname in self.topo.duts:
            self.init_per_test(devname)

    def set_function_params(self, devname, **kwargs):
        fcli = kwargs.get("faster_cli", self.function_faster_cli)
        fcli = utils.parse_integer(fcli, self.function_faster_cli)
        self.function_faster_cli = 1 if fcli else 0
        for devname in utils.make_list(devname or list(self.topo.duts.keys())):
            self.set_access_param(devname, "function-syslog-check", "syslog", 1, **kwargs)

    def _session_close_dut(self, devname):
        self.wa.hooks.post_session(devname)

    def session_close(self):
        putils.exec_foreach(self.cfg.faster_init, self.topo.duts,
                            self._session_close_dut)

    def init_per_test(self, devname):

        # remove additional auth
        self.add_addl_auth(devname, None, None, reset=True)
        self.set_access_param(devname, "function-syslog-check", "syslog", 1)
        self._cmd_unlock(devname, "")

    def set_workarea(self, waobj=None):
        self.wa = waobj

    def _set_tryssh(self, devname, tryssh_val, switch):
        access = self._get_dev_access(devname)
        access["tryssh"] = tryssh_val
        if not switch:
            pass
        elif access["tryssh"]:
            self.tryssh_switch(devname, True, check=False)
        else:
            self.tryssh_switch(devname, check=False)

    def set_console_only(self, val, switch=True):
        tryssh_val = bool(self.tryssh and not val)
        putils.exec_foreach(self.cfg.faster_init, self.topo.duts,
                            self._set_tryssh, tryssh_val, switch)

    def tc_start(self, start_time=None):
        self.tc_start_time = start_time
        profile.init()

        # ensure devices are in sonic mode at test start
        if start_time:
            for devname in self.topo.duts:
                access = self._get_dev_access(devname)
                if self.is_filemode(devname):
                    continue
                self._set_last_prompt(access, None)
                self._enter_linux(devname)

    def clear_prevent(self):
        self.prevent_list = []

    def add_prevent(self, what):
        self.prevent_list.append(what)

    @staticmethod
    def get_stats():
        return profile.get_stats()

    def set_prev_tc(self, prev_tc=None):
        self.prev_testcase = prev_tc
        for devname in self.topo.duts:
            access = self._get_dev_access(devname)
            if self.is_filemode(devname):
                continue
            self._set_last_prompt(access, None)

    def tg_wait(self, val):
        self.wait(val, True)

    def wait(self, val, is_tg=False, check_max_timeout=True):
        profile.wait(val, is_tg)
        if self.cfg.filemode:
            return
        if not check_max_timeout:
            self.orig_time_sleep(val)
            return
        self.check_timeout(None, val)
        left = val
        while left > 0:
            self.check_timeout(None)
            if left <= 5:
                self.orig_time_sleep(left)
                break
            self.orig_time_sleep(5)
            left = left - 5

    def report_timeout(self, msgid, *args):
        self.clear_all_flags(None)
        self.wa.report_timeout(msgid, *args)

    def check_timeout(self, access, add_time=0):
        retval = None
        if self.session_max_timeout and self.session_start_time:
            time_taken = get_elapsed(self.session_start_time, False)
            time_taken = time_taken + add_time
            if time_taken > self.session_max_timeout:
                msg = "Max Time '{}' reached. Exiting the session init"
                msg = msg.format(self.session_max_timeout)
                if access:
                    self.dut_log(access["devname"], msg)
                else:
                    self.logger.error(msg)
                self.abort_run(15, msg, False)
            retval = self.session_max_timeout - time_taken
        elif self.module_max_timeout and self.module_start_time:
            time_taken = get_elapsed(self.module_start_time, False)
            time_taken = time_taken + add_time
            if self.module_max_timeout_triggered:
                self.logger.warning("spare somemore time to cleanup")
                time_taken = time_taken + 180
            if time_taken > self.module_max_timeout:
                msg = "Max Time '{}' reached. Exiting the module init"
                msg = msg.format(self.module_max_timeout)
                if access:
                    self.dut_log(access["devname"], msg)
                else:
                    self.logger.error(msg)
                if self.wa:
                    self.module_max_timeout_triggered = True
                    self.report_timeout("module_init_max_timeout")
                sys.exit(0)
            retval = self.module_max_timeout - time_taken
        elif self.tc_max_timeout and self.tc_start_time:
            time_taken = get_elapsed(self.tc_start_time, False)
            time_taken = time_taken + add_time
            if self.tc_max_timeout_triggered:
                self.logger.warning("spare somemore time to cleanup.")
                time_taken = time_taken + 180
            if time_taken > self.tc_max_timeout:
                msg = "Max Time '{}' reached. Exiting the testcase"
                msg = msg.format(self.tc_max_timeout)
                if access:
                    self.dut_log(access["devname"], msg)
                else:
                    self.logger.error(msg)
                if self.wa:
                    self.tc_max_timeout_triggered = True
                    self.report_timeout("test_case_max_timeout")
                sys.exit(0)
            retval = self.tc_max_timeout - time_taken
        return retval

    def _timeout_handler(self, signum, frame):
        self.logger.debug("Timeout Handler signal={}".format(signum))
        if signum != signal.SIGALRM:  # do we need this check?
            return
        if self.profile_max_timeout_msg:
            if self.profile_skip_report:
                raise ValueError(self.profile_max_timeout_msg)
            if self.wa:
                self.report_timeout("operation_max_timeout", self.profile_max_timeout_msg)
            sys.exit(0)
        if self.module_max_timeout and self.module_start_time:
            if self.wa:
                self.report_timeout("module_init_max_timeout")
            sys.exit(0)
        elif self.tc_max_timeout and self.tc_start_time:
            if self.wa:
                self.report_timeout("test_case_max_timeout")
            sys.exit(0)

    def _timeout_cancel(self, left):
        if left is not None:
            self.logger.debug("Cancelling timer LEFT={}".format(left))
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, signal.SIG_DFL)

    def profiling_start(self, msg, max_time, skip_report=False):
        self.profile_max_timeout_msg = None
        self.profile_skip_report = skip_report
        left = self.check_timeout(None)
        if left is None:
            return profile.start(msg, data=left)
        if max_time == 0:
            timeout = left
        elif left > max_time:
            timeout = max_time
            self.profile_max_timeout_msg = "{}-{}".format(msg, max_time)
        else:
            timeout = left
        self.logger.debug("Start timer MAX={} LEFT={} TIMEOUT={}".format(max_time, left, timeout))
        signal.signal(signal.SIGALRM, self._timeout_handler)
        signal.setitimer(signal.ITIMER_REAL, timeout)
        return profile.start(msg, data=left)

    def profiling_stop(self, pid, cancel=True):
        try:
            left = profile.stop(pid)
            if cancel:
                self._timeout_cancel(left)
        except Exception as exp:
            self.logger.error(exp)

    def open_config(self, devname, template, var=None, action=None, method=None, data=None, json=None, encoding=None, **kwargs):
        var = var or {}
        from spytest.gnmi.translator import toRest, toGNMI
        ocType = env.get("SPYTEST_OPENCONFIG_API", "GNMI").lower()
        if 'gnmi' in ocType:
            path, action, data = toGNMI(template, var, action or method, data=data or json)
            if 'proto' in ocType and encoding is None:
                encoding = 'PROTO' if action.lower() == 'get' else 'ANY'
            return self._gnmi_send(devname, path, action=action, data=data, encoding=encoding, **kwargs)
        path, method, json = toRest(template, var, method or action, json=json or data)
        return self.rest_send(devname, api=path, method=method, json=json, retAs='', verify=False, **kwargs)

    def _gnmi_init(self, devname, cached=False):
        if not cached:
            self._fetch_mgmt_ip(devname)
        ip = self.get_mgmt_ip(devname)
        self.gnmi[devname].reinit(ip)

    def _gnmi_send(self, devname, path, *args, **kwargs):
        return self.gnmi[devname].send(path, *args, **kwargs)

    def rest_init(self, devname, username, password, altpassword, cached=False, ip_changed=False):
        access = self._get_dev_access(devname)

        # check for test case timeout
        self.check_timeout(access)
        if ip_changed:
            self.dut_log(devname, "Observed connectivity issue with the device")
            cached = False  # Overwriting cached variable to fetch the fresh ip from the device in case of ip change.
        if access.get("curr_pwd") and not ip_changed:
            self.dut_log(devname, "Rest Init: Current Password is already set to {}".format(access.get("curr_pwd")))
            return
        access["curr_pwd"] = None
        if not self.wa.is_feature_supported("rest", devname):
            return
        if not cached:
            self._fetch_mgmt_ip(devname)
        ip = self._get_mgmt_ip(devname)
        self.dut_log(devname, "Rest Init: IP Address {}".format(ip))
        if self.is_filemode(devname) or ip == "0.0.0.0":
            return

        # check if we can avoid ssh connection just to find the password
        if not ip_changed:
            if self._get_handle_index(devname) != 0 or not self._is_console_connection(devname):
                try:
                    hndl = self._get_handle(devname)
                    access["curr_pwd"] = hndl.password
                    return
                except Exception:
                    pass
        # Re-init rest object by passing  ip and check ssh for curr_pwd.
        try:
            conn_obj, msgs = self._do_ssh_ip(ip, username, password, devname=devname)[:2]
            if not conn_obj:
                conn_obj, msgs = self._do_ssh_ip(ip, username, altpassword, devname=devname)[:2]
                if conn_obj:
                    access["curr_pwd"] = altpassword
                else:
                    access["curr_pwd"] = None
                    self.dut_err(devname, msgs)
            else:
                access["curr_pwd"] = password
            if conn_obj: conn_obj.disconnect()
            self.rest[devname]._set_curr_pwd(access.get("curr_pwd"))
            self.rest[devname].reinit(ip, username, password, altpassword, self.cfg.ui_type)
        except Exception as e:
            self.logger.error(e)
            raise e

    def _auto_rest_init(self, devname, **kwargs):
        """
        This triggeres Rest Re-Init only when MGMT IP change detected.
        """
        if kwargs.get('expect_reboot', False):
            return
        old = self.rest[devname].ip
        new = self._get_mgmt_ip(devname)
        if old and new and old == new:
            return
        self.dut_log(devname, "Detected IP change from {} to {}, Rest Re-init triggered.".format(old, new))
        access = self._get_dev_access(devname)
        self.rest_init(devname, access.get("username"), access.get("password"), access.get("altpassword"), cached=False,
                       ip_changed=True)

    def reset_restinit(self, devname):
        access = self._get_dev_access(devname)
        access["curr_pwd"] = None
        self.rest[devname].reset_curr_pwd()

    def rest_create(self, devname, path, data, *args, **kwargs):
        self._auto_rest_init(devname, **kwargs)
        return self.rest[devname].post(path, data, *args, **kwargs)

    def rest_update(self, devname, path, data, *args, **kwargs):
        self._auto_rest_init(devname, **kwargs)
        return self.rest[devname].put(path, data, *args, **kwargs)

    def rest_modify(self, devname, path, data, *args, **kwargs):
        self._auto_rest_init(devname, **kwargs)
        return self.rest[devname].patch(path, data, *args, **kwargs)

    def rest_read(self, devname, path, *args, **kwargs):
        self._auto_rest_init(devname, **kwargs)
        return self.rest[devname].get(path, *args, **kwargs)

    def rest_delete(self, devname, path, *args, **kwargs):
        self._auto_rest_init(devname, **kwargs)
        return self.rest[devname].delete(path, *args, **kwargs)

    def rest_parse(self, devname, filepath=None, all_sections=False, paths=None, **kwargs):
        self._auto_rest_init(devname, **kwargs)
        return self.rest[devname].parse(filepath, all_sections, paths or [], **kwargs)

    def rest_apply(self, devname, data):
        self._auto_rest_init(devname)
        return self.rest[devname].apply(data)

    def rest_send(self, devname, api='', method='get', params=None, data=None, retAs='json', **kwargs):
        self._auto_rest_init(devname, **kwargs)
        return self.rest[devname].send(devname, method=method, api=api, params=params, data=data, retAs=retAs, **kwargs)

    def get_credentials(self, devname):
        access = self._get_dev_access(devname)
        retList = [access.get("username")]
        pwdlist = [access.get("password"), access.get("altpassword"), access.get("curr_pwd")]
        retList.extend(pwdlist)
        return retList

    def _parse_confirm(self, value):
        retval = {}
        for confirm in utils.make_list(value or []):
            if isinstance(confirm, list):
                retval[confirm[0]] = confirm[1]
            else:
                retval[r"(.*y\/n[\]|\)](\:)*\s*)$"] = confirm
                retval[r"(.*y\/N[\]|\)](\:)*\s*)$"] = confirm
                retval[r"(.*Y\/n[\]|\)](\:)*\s*)$"] = confirm
                retval[r"(.*Y\/N[\]|\)](\:)*\s*)$"] = confirm
        return retval

    def _parse_cli_opts(self, devname, cmd, **kwargs):
        opts = SpyTestDict()
        opts.ctype = kwargs.get("type", "click")
        if opts.ctype == "gnmi": opts.ctype = "klish"
        opts.exec_mode = kwargs.get("exec_mode", None)
        opts.expect_mode = kwargs.get("expect_mode", None)
        if opts.ctype == "click" and opts.exec_mode is not None:
            if opts.exec_mode.startswith("mgmt"):
                opts.ctype = "klish"
            elif opts.exec_mode.startswith("vtysh"):
                opts.ctype = "vtysh"
            elif opts.exec_mode.startswith("lldp"):
                opts.ctype = "lldp"
        opts.skip_tmpl = kwargs.get("skip_tmpl", False)
        opts.skip_error_check = kwargs.get("skip_error_check", False)
        opts.skip_error_report = kwargs.get("skip_error_report", False)
        opts.expect_reboot = kwargs.get("expect_reboot", False)
        opts.expect_ipchange = kwargs.get("expect_ipchange", False)
        opts.max_time = kwargs.get("max_time", 0)
        opts.min_time = kwargs.get("min_time", 0)
        opts.reboot_wait = kwargs.get("reboot_wait", 300)
        sudoshell = bool(env.get("SPYTEST_SUDO_SHELL", "1") == "1")
        opts.sudoshell = kwargs.get("sudoshell", sudoshell)
        config_sudo = env.get("SPYTEST_CONFIG_SUDO", None)
        if config_sudo is not None: config_sudo = bool(config_sudo != '0')
        opts.sudo = kwargs.get("sudo", config_sudo)
        if opts.sudo is None:
            opts.sudo = True if opts.ctype == "click" else False
        if self.is_any_fastpath_device(devname) or opts.ctype != "click":
            opts.sep = nl
        else:
            opts.sep = ";"
        opts.conf = kwargs.get("conf", True)
        opts.confirm = self._parse_confirm(kwargs.get("confirm", []))
        opts.split_cmds = kwargs.get("split_cmds", True)
        opts.faster_cli = bool(kwargs.get("faster_cli", not bool(opts.confirm)))
        opts.trace_log = int(kwargs.get("trace_log", self.default_trace_log))
        opts.delay_factor = max_time_to_delay_factor(opts.max_time)
        opts.cmds_delay_factor = 3 if opts.delay_factor <= 3 else opts.delay_factor
        opts.log_file = kwargs.get("log_file", None)
        opts.remove_prompt = kwargs.get("remove_prompt", False)
        opts.strip_prompt = kwargs.get("strip_prompt", True)
        opts.strip_command = kwargs.get("strip_command", True)
        opts.use_timing = kwargs.get("use_timing", False)
        opts.use_send_bytes = kwargs.get("use_send_bytes", False)
        opts.new_line = kwargs.get("new_line", True)
        opts.on_cr_recover = kwargs.get("on_cr_recover", "default")
        opts.confirm_cr = kwargs.get("confirm_cr", True)
        opts.audit = kwargs.get("audit", True)
        opts.normalize = True
        opts.conn_index = kwargs.get("conn_index", None)
        opts.conf_session = kwargs.get("conf_session", False)
        opts.conf_terminal = kwargs.get("conf_terminal", False)
        opts.skip_post_reboot = kwargs.get("skip_post_reboot", False)

        opts.ctype = self.wa.hooks.verify_ui_support(devname, opts.ctype, cmd)

        return opts

    # prepare list of commands
    @staticmethod
    def _build_cmd_list(cmd, opts):
        cmd_list = []
        for l_cmd in utils.string_list(cmd):
            if l_cmd == "su":
                continue
            if opts.sudo and not l_cmd.startswith("sudo "):
                if opts.sudoshell:
                    l_cmd = "sudo -s " + l_cmd
                else:
                    l_cmd = "sudo " + l_cmd
            cmd_list.append(l_cmd)
        return cmd_list

    def _change_mode(self, devname, is_show, cmd, opts, dbg=False):
        if self.is_filemode(devname):
            return "", "", ""
        if not dbg:
            return self._change_mode_try(devname, is_show, cmd, opts)
        opts2 = copy.deepcopy(opts)
        opts2.on_cr_recover = "retry3-ignore"
        opts2.skip_error_check = True
        prefix, op, mode = self._change_mode_try(devname, is_show, cmd, opts2)
        return prefix, op, mode

    def _change_mode_try(self, devname, is_show, cmd, opts):
        devname = self._check_devname(devname)

        prefix, op = "", ""
        access = self._get_dev_access(devname)
        normal_user_mode = access["normal_user_mode"]

        # check if the current prompt satisfies show/config command
        current_mode = self._change_prompt(devname)
        if current_mode.startswith("mgmt"):
            if opts.ctype == "klish":
                if is_show:
                    if current_mode == "mgmt-user":
                        return "", op, current_mode
                    if cmd.startswith("do "):
                        return "", op, "mgmt-any-config"
                    return "do ", op, "mgmt-any-config"
                else:
                    if current_mode == "mgmt-user":
                        if cmd in ["exit"]:
                            return "", op, normal_user_mode
                        if not opts.conf:
                            return "", op, "mgmt-user"
                    elif current_mode == "mgmt-config":
                        if cmd in ["end", "exit"]:
                            return "", op, "mgmt-user"
                        if opts.conf:
                            return "", op, "mgmt-any-config"
                    else:
                        if cmd in ["end"]:
                            return "", op, "mgmt-user"
                        if opts.conf:
                            return "", op, "mgmt-any-config"
        elif current_mode.startswith("vtysh"):
            if opts.ctype == "vtysh":
                if is_show:
                    if current_mode == "vtysh-user":
                        return "", op, current_mode
                    if cmd.startswith("do "):
                        return "", op, "vtysh-any-config"
                    return "do ", op, "vtysh-any-config"
                else:
                    if current_mode == "vtysh-user":
                        if cmd in ["exit"]:
                            return "", op, normal_user_mode
                        if not opts.conf:
                            return "", op, "vtysh-user"
                    elif current_mode == "vtysh-config":
                        if cmd in ["end", "exit"]:
                            return "", op, "vtysh-user"
                        if opts.conf:
                            return "", op, "vtysh-any-config"
                    else:
                        if cmd in ["end"]:
                            return "", op, "vtysh-user"
                        if opts.conf:
                            return "", op, "vtysh-any-config"

        # change the mode
        if opts.ctype == "click":
            op = self._change_prompt(devname, normal_user_mode, startmode=current_mode)
            return "", op, normal_user_mode
        elif opts.ctype == "vtysh" and (is_show or not opts.conf):
            op = self._change_prompt(devname, "vtysh-user", startmode=current_mode)
            return "", op, "vtysh-user"
        elif opts.ctype == "vtysh":
            op = self._change_prompt(devname, "vtysh-config", startmode=current_mode, conf_terminal=True)
            return "", op, "vtysh-any-config"
        elif opts.ctype == "klish" and (is_show or not opts.conf):
            op = self._change_prompt(devname, "mgmt-user", startmode=current_mode)
            return "", op, "mgmt-user"
        elif opts.ctype == "klish":
            op = self._change_prompt(devname, "mgmt-config", startmode=current_mode)
            return "", op, "mgmt-any-config"
        elif opts.ctype == "lldp":
            op = self._change_prompt(devname, "lldp-user", startmode=current_mode)
            return "", op, "lldp-user"

        return prefix, op, "unknown-mode"

    def parse_show(self, devname, cmd, output, tmpl=None):
        return self._tmpl_apply(devname, cmd, output, tmpl)

    def remove_prompt(self, devname, output):
        access = self._get_dev_access(devname)
        if access["last-prompt"]:
            output = re.sub(access["last-prompt"], '', output)
        return output

    def _simulate_errors(self, devname, cmd=None):
        # applicable bits 1:session 2:module 3:function 4:abort 5:command
        val = env.getint("SPYTEST_SIMULATE_ERRORS", 0)
        if val == 0: return cmd
        scope = self._get_scope()
        if scope == "session" and not (val & (1 << 1)): return cmd
        if scope == "module" and not (val & (1 << 2)): return cmd
        if scope == "function" and not (val & (1 << 3)): return cmd
        rand_value = randint(0, 100)
        if rand_value > 98:
            if (rand_value % 2) == 0 and cmd and (val & (1 << 5)) != 0:
                msg = "simulating termserv issue {}".format(cmd)
                index = randint(0, len(cmd) - 1)
                cmd = cmd[:index] + cmd[index + 1:]
            if (rand_value % 2) == 1 and (val & (1 << 4)) != 0:
                msg = "simulating abort {}".format(cmd)
                self.dut_err(devname, msg)
                self.abort_run(15, msg, False)
        return cmd

    def show(self, devname, cmd, **kwargs):
        if not self._cmd_lock(devname, cmd): return None
        line = utils.get_line_number(3)
        retval = self._show(line, devname, cmd, **kwargs)
        self._cmd_unlock(devname, cmd)
        return retval

    def _show(self, line, devname, cmd, **kwargs):
        opts = self._parse_cli_opts(devname, cmd, **kwargs)

        cmd = self.wa.hooks.verify_command(devname, cmd, opts.ctype)

        if opts.audit:
            self.wa.hooks.audit("show", devname, cmd, **kwargs)

        self._simulate_errors(devname)

        devname = self._check_devname(devname)
        access = self._get_dev_access(devname)
        access["force_conn_index"] = opts.conn_index
        access["force_conf_session"] = opts.conf_session
        access["force_conf_terminal"] = opts.conf_terminal
        access["force_confirm"] = kwargs.get("confirm", None)

        # switch to console if the command can cause IP change
        if opts.expect_ipchange or opts.expect_reboot:
            change_in_tryssh = self.tryssh_switch(devname)
            access["force_conn_index"] = 0
            self._clear_mgmt_ip(devname)
        else:
            change_in_tryssh = False

        prompts = access["prompts"]
        ifname_type = self.wa.get_ifname_type(devname)

        prefix = ""
        if opts.exec_mode:
            frommode = self.change_prompt(devname, opts.exec_mode, **kwargs)
            if frommode in ["unknown-mode", "unknown-prompt"]:
                msg = "Unable to change the prompt mode to {}.".format(opts.exec_mode)
                self.dut_err(devname, msg)
                raise ValueError(msg)
            expected_prompt = self.get_prompt_for_mode(devname, frommode, ifname_type)
            if frommode not in prompts.do_exclude_prompts:
                if not cmd.startswith("do "):
                    prefix = "do "
        else:
            prefix, _, expect_mode = self._change_mode(devname, True, cmd, opts)
            if expect_mode in ["unknown-mode", "unknown-prompt"]:
                msg = "Unknown prompt/mode for ctype: {}".format(opts.ctype)
                self.dut_err(devname, msg)
                raise ValueError(msg)
            expected_prompt = self.get_prompt_for_mode(devname, expect_mode, ifname_type)

        if opts.expect_mode:
            expected_prompt = self.get_prompt_for_mode(devname, opts.expect_mode, ifname_type)

        actual_cmd = cmd
        if opts.ctype == "klish":
            cmd = self._add_no_more(cmd)

        cmd = prefix + cmd

        # add confirmation prompts if specified
        confirm_prompts = []
        all_prompts = [expected_prompt]
        confirm_prompts = list(opts.confirm.keys())
        all_prompts.extend(confirm_prompts)
        expected_prompt_with_confirm = "|".join(all_prompts)

        if opts.confirm:
            op_lines = []
            op = self._send_cmd_opts(devname, cmd, expected_prompt_with_confirm, opts)
            op_lines.append(op)
            match_again = True
            opts.strip_prompt = False
            opts.strip_command = False
            opts.normalize = opts.confirm_cr
            while match_again:
                match_again = False
                for prompt, confirm in opts.confirm.items():
                    confirm_cmd = str(confirm)
                    if re.match(prompt, op.strip(), re.IGNORECASE | re.DOTALL):
                        match_again = True
                        if opts.expect_reboot:
                            op = self._send_cmd_expect_reboot(devname, confirm_cmd, [expected_prompt], None, opts)
                            op_lines.append(op)
                        else:
                            op = self._send_cmd_opts(devname, confirm_cmd, expected_prompt, opts)
                            op_lines.append(op)
            output = nl.join(op_lines)
        elif opts.expect_reboot:
            output = self._send_cmd_expect_reboot(devname, cmd, [expected_prompt], None, opts)
        else:
            output = self._send_cmd_opts(devname, cmd, expected_prompt, opts)

        # switch back from console
        if change_in_tryssh: self.tryssh_switch(devname, True, True)

        output = self._fill_sample_data(devname, cmd, opts.skip_error_check,
                                        opts.skip_tmpl, output, line)
        if opts.skip_tmpl:
            return output

        return self._tmpl_apply(devname, actual_cmd, output)

    def _cmd_unlock(self, devname, cmd):
        if not self.cmd_lock_support: return True
        access = self._get_dev_access(devname)
        return self._cli_unlock(access, cmd, suffix="cmd")

    def _cmd_lock(self, devname, cmd):
        if not self.cmd_lock_support: return True
        access = self._get_dev_access(devname)
        return self._cli_lock(access, cmd, suffix="cmd", trace=False)

    def config(self, devname, cmd, **kwargs):
        if not self._cmd_lock(devname, cmd): return None
        retval = self._config(devname, cmd, **kwargs)
        self._cmd_unlock(devname, cmd)
        return retval

    def _config(self, devname, cmd, **kwargs):
        opts = self._parse_cli_opts(devname, cmd, **kwargs)

        cmd = self.wa.hooks.verify_command(devname, cmd, opts.ctype)

        if opts.audit:
            self.wa.hooks.audit("config", devname, cmd, **kwargs)

        if opts.split_cmds:
            cmd_list = self._build_cmd_list(cmd, opts)
        else:
            cmd_list = [cmd]
        if not cmd_list: return ""

        devname = self._check_devname(devname)
        access = self._get_dev_access(devname)
        access["force_conn_index"] = opts.conn_index
        access["force_conf_session"] = opts.conf_session
        access["force_conf_terminal"] = opts.conf_terminal
        access["force_confirm"] = kwargs.get("confirm", None)
        ifname_type = self.wa.get_ifname_type(devname)

        self._simulate_errors(devname)

        if self.is_filemode(devname):
            self.dut_log(devname, cmd)
            return ""

        # switch to console if the command can cause IP change
        if opts.expect_ipchange or opts.expect_reboot:
            change_in_tryssh = self.tryssh_switch(devname)
            access["force_conn_index"] = 0
            self._clear_mgmt_ip(devname)
        else:
            change_in_tryssh = False

        if opts.exec_mode:
            frommode = self.change_prompt(devname, opts.exec_mode, **kwargs)
            if frommode in ["unknown-mode", "unknown-prompt"]:
                msg = "Unable to change the prompt mode to {}.".format(opts.exec_mode)
                self.dut_err(devname, msg)
                raise SPyTestException(msg)
            expected_prompt = self.get_prompt_for_mode(devname, frommode, ifname_type)
        else:
            op, expect_mode = self._change_mode(devname, False, cmd, opts)[1:3]
            if expect_mode in ["unknown-mode", "unknown-prompt"]:
                msg = "Unknown prompt/mode."
                self.dut_err(devname, msg)
                raise SPyTestException(msg)
            expected_prompt = self.get_prompt_for_mode(devname, expect_mode, ifname_type)

        if opts.expect_mode:
            expected_prompt = self.get_prompt_for_mode(devname, opts.expect_mode, ifname_type)

        if opts.split_cmds and not opts.confirm and not opts.expect_reboot and not opts.expect_ipchange:
            if len(cmd_list) > 10 and opts.ctype == "click":
                self._enter_linux(devname)
                # execute the command.
                cmd_list.insert(0, "#!/bin/bash\n")
                self._echo_list_to_file(access, cmd_list, "/tmp/config.sh")
                max_run_time = len(cmd_list) * 2
                return self.run_script(devname, max_run_time, "/tmp/config.sh")

            if env.get("SPYTEST_SPLIT_COMMAND_LIST", "0") == "0":
                if opts.ctype != "klish": cmd_list = [opts.sep.join(cmd_list)]

        # to bailout early when klish crashed
        if opts.ctype != "click":
            incorrect_mode = self._get_cli_prompt(devname)
        else:
            incorrect_mode = None

        # add confirmation prompts if specified
        expected_prompts = [expected_prompt]
        if incorrect_mode: expected_prompts.append(incorrect_mode)
        confirm_prompts = []
        all_prompts = [prompt for prompt in expected_prompts]
        confirm_prompts = list(opts.confirm.keys())
        all_prompts.extend(confirm_prompts)
        expected_prompt_with_confirm = "|".join(all_prompts)

        # execute individual commands
        op_lines = []
        for l_cmd in cmd_list:
            if opts.confirm:
                op = self._send_cmd_opts(devname, l_cmd, expected_prompt_with_confirm, opts)

                # do we really get list?
                if isinstance(op, list):
                    op_lines.extend(op)
                    continue

                # store the output
                op_lines.append(op)

                # can't do any thing in case of errors
                if re.search("Syntax error:", op): continue

                ## handle the case of no confirmation
                # if expected_prompt_re.match(op): continue
                # op2 = op.replace("\\", "")
                # if expected_prompt_re.match(op2): continue

                # match with the confirmation prompt
                match_again = True
                opts.strip_prompt = False
                opts.strip_command = False
                opts.normalize = opts.confirm_cr
                while match_again:
                    match_again = False
                    for prompt, confirm in opts.confirm.items():
                        confirm_cmd = str(confirm)
                        op = op.strip().split(nl)[-1]
                        if re.match(prompt, op.strip(), re.IGNORECASE | re.DOTALL):
                            match_again = True
                            if opts.expect_reboot:
                                op = self._send_cmd_expect_reboot(devname, confirm_cmd,
                                                                  expected_prompts, confirm_prompts, opts)
                                op_lines.append(op)
                            else:
                                op = self._send_cmd_opts(devname, confirm_cmd, expected_prompt_with_confirm, opts)
                                op_lines.append(op)
            elif opts.expect_reboot:
                op = self._send_cmd_expect_reboot(devname, l_cmd, [expected_prompt], None, opts)
                op_lines.append(op)
            else:
                op = self._send_cmd_opts(devname, l_cmd, expected_prompt, opts)
                op_lines.append(op)

        # switch back from console
        if change_in_tryssh: self.tryssh_switch(devname, True, True)

        return nl.join(op_lines)

    def _send_cmd_opts(self, devname, cmd, expected_prompt, opts):
        devname = self._check_devname(devname)
        access = self._get_dev_access(devname)
        self.trace_callback_set_debug(devname, True)
        output = self._send_command(access, cmd, expected_prompt,
                                    opts.skip_error_check, ufcli=opts.faster_cli,
                                    trace_log=opts.trace_log,
                                    delay_factor=opts.delay_factor,
                                    opts=opts)
        self.trace_callback_set_debug(devname, False)
        return output

    # This API should not be called from tryssh
    def _send_cmd_expect_reboot(self, devname, cmd, expected_prompts, confirm_prompts, opts):
        devname = self._check_devname(devname)
        access = self._get_dev_access(devname)
        output = ""

        # adjust delay and prompt when expecting reboot
        regex_login = self.wa.hooks.get_regex(devname, "login")
        regex_login_anywhere = self.wa.hooks.get_regex(devname, "login_anywhere")
        prompt_list = [prompt for prompt in expected_prompts]
        prompt_list.extend([regex_login, regex_login_anywhere])
        if env.get("SPYTEST_RECOVER_FROM_ONIE_ON_REBOOT", "0") != "0":
            prompt_list.append(regex_onie_resque)
            prompt_list.extend([regex_onie_install, regex_onie_fetch])
        expect = "|".join(prompt_list)

        # quickly come up while executing from ssh
        expect_disc = bool(not self._is_console_connection(devname))
        if not expect_disc:
            opts.delay_factor = utils.max(6, opts.delay_factor)

        # TODO: Move skip_waiting to cmd options
        skip_waiting = False
        exclude_cmds = ["show", "do show"]
        exclude_cmds.extend(["sudo show", "sudo -s show"])
        exclude_cmds.extend(["sudo ztp status", "sudo -s ztp status"])
        for pattern in exclude_cmds:
            if cmd.startswith(pattern):
                skip_waiting = True

        try:
            cmd_starttime = get_timenow()
            output = self._send_command(access, cmd, expect, True,
                                        ufcli=opts.faster_cli,
                                        trace_log=opts.trace_log,
                                        delay_factor=opts.delay_factor,
                                        expect_disc=expect_disc,
                                        opts=opts)
            if not output and expect_disc:
                return output
            cmd_timetaken = get_elapsed(cmd_starttime, False)

            # let the caller handle confirmation
            for prompt in confirm_prompts or []:
                op = output.strip().split(nl)[-1]
                if re.match(prompt, op.strip(), re.IGNORECASE | re.DOTALL):
                    return output

            # match the prompt
            known_prompts = [prompt.replace("\\", "") for prompt in expected_prompts]
            known_prompts.append(self._get_cli_prompt(devname).replace("\\", ""))
            matches = [ele for ele in known_prompts if ele in output]
            prompt = matches[0] if matches else None
            if not prompt:
                prompt = self._find_prompt(access, use_cache=False)
                if env.get("SPYTEST_RECOVER_FROM_ONIE_ON_REBOOT", "0") != "0":
                    self._check_prompt_onie(devname, prompt)
            if not skip_waiting:
                if prompt in known_prompts and cmd_timetaken < 100:
                    msg = "Identified the same/user prompt {} Vs {} with in '{}' secs."
                    msg = msg.format(prompt, str(known_prompts), cmd_timetaken)
                elif opts.min_time and cmd_timetaken < opts.min_time:
                    msg = "Command completed in '{}' secs before min time {}."
                    msg = msg.format(cmd_timetaken, opts.min_time)
                else:
                    msg = None
                if msg:
                    wait_time = utils.max(opts.reboot_wait, opts.min_time)
                    msg = msg + " So waiting for a static period of {} seconds.".format(wait_time)
                    self.dut_warn(devname, msg)
                    self.wa._ftrace("static-wait-debug {} {}".format(devname, output))
                    self.wait(wait_time)
                    prompt = self._find_prompt(access, use_cache=False)
                    self.dut_log(devname, prompt.replace("\\", ""))
            if prompt not in known_prompts:
                self._enter_linux(devname, prompt)
                if not opts.skip_post_reboot and not self.do_common_init(devname):
                    err_msg = "INFRA_SYS_CHK: system status is not online even after waiting for {} sec".format(self.cfg.port_init_wait)
                    output = output + "\n" + err_msg + "\n"
        except Exception as exp:
            raise exp
        return output

    def exec_ssh_remote_dut(self, devname, ipaddress, username, password, command=None, timeout=30, **kwargs):
        devname = self._check_devname(devname)
        if self.is_filemode(devname): return ""
        return self.wa.hooks.exec_ssh_remote_dut(devname, ipaddress, username, password, command, timeout, **kwargs)

    def set_hostname(self, devname, hname=None):
        devname = self._check_devname(devname)
        access = self._get_dev_access(devname)
        if self.is_filemode(devname): return ""
        if hname: access["prompts"].add_user_hostname(hname)
        self.wa.hooks.set_hostname(devname, hname)

    def do_ssh(self, ipaddress, username, password, **kwargs):
        altpassword = kwargs.pop("altpassword", None)
        port = kwargs.pop("port", 22)
        blocking_timeout = kwargs.pop("blocking_timeout", 30)
        access_model = kwargs.pop("access_model", "sonic_ssh")
        conn_index = kwargs.pop("conn_index", "sonic_ssh")
        devname = kwargs.pop("dut", None)
        user_role = kwargs.pop("user_role", "admin")
        if devname is not None:
            devname = self._check_devname(devname)
            access = self._get_dev_access(devname)
            if ipaddress is None: ipaddress = self.get_mgmt_ip(devname)
            if username is None: username = access["username"]
            if password is None: password = self.get_login_password(devname)
        if ipaddress is None or username is None or password is None:
            return None
        retval = self._do_ssh_ip(ipaddress, username, password, altpassword, port, devname, blocking_timeout, access_model)[0]
        if not devname: return retval
        self.dut_log(devname, "Additional SSH session to DUT with index {} Created".format(conn_index))
        conn_index = utils.parse_integer(conn_index, 0)
        if conn_index <= 1: return retval
        access["user_role"][conn_index] = user_role
        access["user_conn"][conn_index] = retval
        access["user_conn"][retval] = conn_index
        if access["username"] != username:
            access["prompts"].add_user_hostname(None, username)
        self._set_handle(devname, retval, conn_index)
        self.post_login(devname, conn_index=conn_index)
        return retval

    def do_ssh_disconnect(self, devname, conn_index):
        conn_index = utils.parse_integer(conn_index, 0)
        if conn_index <= 1: return
        self.dut_log(devname, "Additional SSH session to DUT with index {} Closed".format(conn_index))
        devname = self._check_devname(devname)
        access = self._get_dev_access(devname)
        hndl = access["user_conn"].pop(conn_index, None)
        access["user_conn"].pop(hndl, None)
        self._disconnect_device(devname, conn_index)

    def dump_all_commands(self, devname, type='click'):
        self.apply_remote(devname, "dump-click-cmds")
