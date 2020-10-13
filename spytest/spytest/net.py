from __future__ import unicode_literals, print_function
import os
import sys
import json
import re
import tempfile
import logging
import traceback
import random
import signal
import time
import copy
import math
import shlex
import threading
import subprocess
from inspect import currentframe
from collections import OrderedDict

import utilities.common as utils

from spytest import profile
from spytest.dicts import SpyTestDict
from spytest.logger import Logger
from spytest.template import Template
from spytest.access.connection import DeviceConnection, DeviceConnectionTimeout
from spytest.access.connection import DeviceFileUpload, DeviceFileDownload
from spytest.access.connection import initDeviceConnectionDebug
from spytest.ansible import ansible_playbook
from spytest.prompts import Prompts
from spytest.rest import Rest
from spytest.ordyaml import OrderedYaml
from spytest.uicli import UICLI
from spytest.uirest import UIRest
from spytest.st_time import get_timenow
from spytest.st_time import get_elapsed
from spytest.uignmi import UIGnmi


lldp_prompt = r"\[lldpcli\]\s*#\s*$"
regex_login = r"\S+\s+login:\s*$"
regex_login_anywhere = r"\S+\s+login:\s*"
regex_password = r"[Pp]assword:\s*$"
regex_password_anywhere = r"[Pp]assword:\s*"
regex_onie = r"\s*ONIE:/ #\s*$"
regex_onie_sleep = r"\s*Info: Sleeping for [0-9]+ seconds\s*"
regex_onie_resque = r"\s+Please press Enter to activate this console.\s*$"
sonic_mgmt_hostname = "--sonic-mgmt--"

class Net(object):

    def __init__(self, cfg, file_prefix=None, logger=None, testbed=None):
        """
        initialization of Net
        :param logger:
        :type logger:
        """
        initDeviceConnectionDebug(file_prefix)
        self.cfg = cfg
        self.logger = logger or Logger()
        self.tb = testbed
        self.topo = SpyTestDict({"duts": OrderedDict()})
        self.tmpl = dict()
        self.rest = dict()
        self.syslogs = dict()
        self.is_vsonic_cache = dict()
        self.memory_checks = dict()
        self.skip_trans_helper = dict()
        self.image_install_status = OrderedDict()
        self.devices_used_in_tc = OrderedDict()
        self.devices_used_collection = False
        self.abort_without_mgmt_ip = False
        self.trace_callback_support = False
        self.module_start_time = None
        self.module_max_timeout = self.cfg.module_max_timeout
        self.tc_start_time = None
        self.tc_max_timeout = self.cfg.tc_max_timeout
        self.tc_get_tech_support = False
        self.tc_fetch_core_files = False
        self.fcli = 1 if self.cfg.faster_cli else 0
        self.tryssh = 1 if self.cfg.tryssh else 0
        self.use_last_prompt = False
        self.profile_max_timeout_msg = None
        self.prevent_list = []
        self.wa = None
        self.prev_testcase = None
        if os.getenv("SPYTEST_LIVE_TRACE_OUTPUT"):
            self.trace_callback_support = True
        self.use_sample_data = os.getenv("SPYTEST_USE_SAMPLE_DATA", None)
        self.debug_find_prompt = bool(os.getenv("SPYTEST_DEBUG_FIND_PROMPT"))
        self.dry_run_cmd_delay = os.getenv("SPYTEST_DRYRUN_CMD_DELAY", "0")
        self.dry_run_cmd_delay = int(self.dry_run_cmd_delay)
        self.connect_retry_delay = 5
        self.orig_time_sleep = time.sleep
        #time.sleep = self.wait
        self.force_console_transfer = False
        self.max_cmds_once = 100
        self.kdump_supported = bool(os.getenv("SPYTEST_KDUMP_ENABLE", "1") == "1")
        self.pending_downloads = dict()
        self.log_dutid_fmt = os.getenv("SPYTEST_LOG_DUTID_FMT", "LABEL")
        self.dut_log_lock = threading.Lock()

    def is_use_last_prompt(self):
        fcli = os.getenv("SPYTEST_FASTER_CLI_OVERRIDE", None)
        if fcli is not None:
            self.fcli = 1 if fcli != "0" else 0
        fcli_last_prompt = os.getenv("SPYTEST_FASTER_CLI_LAST_PROMPT", "1")
        self.use_last_prompt = True if fcli_last_prompt != "0" else False
        return self.use_last_prompt

    def _init_dev(self, devname):
        if devname not in self.topo["duts"]:
            self.topo["duts"].update({devname: {}})
            self.syslogs.update({devname: []})

        access = self._get_dev_access(devname)
        access["type"] = "unknown"
        access["errors"] = SpyTestDict()
        access["current_handle"] = 0
        access["tryssh"] = False
        access["filemode"] = False
        access["current_prompt_mode"] = "unknown-prompt"

        return access

    def set_device_alias(self, devname, name):
        access = self._get_dev_access(devname)
        access["alias"] = name

    def _reset_device_aliases(self):
        for _devname in self.topo["duts"]:
            access = self._get_dev_access(_devname)
            access["alias"] = access["alias0"]

    def _get_dut_label(self, devname):
        access = self._get_dev_access(devname)
        if access["dut_name"] == access["alias"]:
            return access["dut_name"]
        return "{}-{}".format(access["dut_name"], access["alias"])

    def _get_dev_access(self, devname):
        return self.topo["duts"][devname]

    def _get_handle(self, devname, index=None):
        if index is None:
            index = self._get_handle_index(devname)
        return self._get_param(devname, "handle", index)

    def _set_handle(self, devname, handle, index=None):
        if index is None:
            index = self._get_handle_index(devname)
        self._set_param(devname, "handle", handle, index)

    def _get_handle_index(self, devname):
        access = self._get_dev_access(devname)
        return access["current_handle"]

    def _get_param(self, devname, name, index=0):
        name2 = "{}.{}".format(name, index)
        access = self._get_dev_access(devname)
        if name2 in access:
            return access[name2]
        if name in access:
            return access[name]
        return None

    def _set_param(self, devname, name, value, index=0):
        access = self._get_dev_access(devname)
        access["{}.{}".format(name, index)] = value
        access[name] = value

    def _set_prompt(self, devname, name, value):
        access = self._get_dev_access(devname)
        access["prompts"].patterns[name] = value

    def _get_cli_prompt(self, devname, index=0):
        return self._get_param(devname, "normal-user-cli-prompt", index)

    def _switch_connection(self, devname, index=0):
        access = self._get_dev_access(devname)
        old = access["current_handle"]
        if old != index:
            msg = "switching from handle {} to {}".format(old, index)
            self.dut_log(devname, msg, lvl=logging.WARNING)
            access["current_handle"] = index
            self._set_last_prompt(access, None)
            return True
        return False

    def is_sonic_device(self, devname):
        access = self._get_dev_access(devname)
        if access["filemode"]: return True
        connection_param = access["connection_param"]
        return bool(connection_param["access_model"].startswith("sonic_"))

    def is_vsonic_device(self, devname):
        return bool(self.tb.get_device_type(devname) in ["vsonic"])

    def _is_console_connection(self, devname, connection_param=None):
        if not connection_param:
            access = self._get_dev_access(devname)
            if access["filemode"]: return True
            connection_param = access["connection_param"]
        if connection_param["access_model"].endswith("_terminal"):
            return True
        if connection_param["access_model"].endswith("_sshcon"):
            return True
        return False

    def _tryssh_switch(self, devname, recover=None, reconnect=True, check=True):

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
        if recover == False:
            return self._switch_connection(devname, 1)

        # reconnect? and switch to ssh
        if not reconnect:
            return self._switch_connection(devname, 1)

        # reconnect and switch to ssh
        hndl = self._get_handle(devname, 1)
        if hndl: hndl.disconnect()
        return self._tryssh_init(devname, False)

    def dut_log(self, devname, msg, skip_general=False, lvl=logging.INFO, cond=True):
        if not cond:
            return
        if self.dut_log_lock: self.dut_log_lock.acquire()
        try:
            access = self._get_dev_access(devname)
            conn = "SSH" if access["current_handle"] != 0 else None
            log_dutid_fmt = self.log_dutid_fmt.upper()
            if log_dutid_fmt == "ID":
                dut_name = access["dut_name"]
            elif log_dutid_fmt == "ALIAS":
                dut_name = access["alias"]
            else:
                dut_name = self._get_dut_label(devname)
            self.logger.dut_log(dut_name, msg, lvl,
                                skip_general, True, conn=conn)
        except Exception as e:
            print("dut_log", e)
        finally:
            if self.dut_log_lock: self.dut_log_lock.release()

    def _copy_value(self, from_dict, to_dict, names):
        for name in names:
            if name in from_dict:
                to_dict[name] = from_dict[name]

    def register_devices(self, _topo):
        for devname in _topo["duts"]:
            device_model = "sonic"
            dut = _topo["duts"][devname]
            self._init_dev(devname)
            self.set_console_only(bool(not self.tryssh), False)
            access = self._get_dev_access(devname)
            self._copy_value(dut, access, ["sshcon_username", "sshcon_password"])
            if "dut_name" in dut:
                access.update({"dut_name": dut["dut_name"]})
            if "alias" in dut:
                access.update({"alias0": dut["alias"]})
                access.update({"alias": dut["alias"]})
            if "access_model" in dut:
                access.update({"access_model": dut["access_model"]})
            if "device_model" in dut:
                device_model = dut["device_model"]
                access.update({"device_model": device_model})
            if "username" in dut:
                access.update({"username": dut["username"]})
            if "password" in dut:
                access.update({"password": dut["password"]})
            if "altpassword" in dut:
                access.update({"altpassword": dut["altpassword"]})
            if "onie_image" in dut:
                access.update({"onie_image": dut["onie_image"]})
            if "errors" in dut:
                access.update({"errors": dut["errors"]})
            if "mgmt_ipmask" in dut:
                access.update({"mgmt_ipmask": dut["mgmt_ipmask"]})
            if "mgmt_gw" in dut:
                access.update({"mgmt_gw": dut["mgmt_gw"]})
            if "port" in dut:
                access.update({"port": dut["port"]})
            if "ip" in dut:
                access.update({"ip": dut["ip"]})
            else:
                msg = "'ipaddr' parameter missing in topology input"
                raise ValueError(msg)
            if os.getenv("SPYTEST_SWAP_PASSWORD"):
                if "password" in access and "altpassword" in access:
                    password = access["password"]
                    access["password"] = access["altpassword"]
                    access["altpassword"] = password
            self.tmpl.update({devname: Template(device_model)})
            self.rest.update({devname: Rest(logger=self.logger)})

    def unregister_devices(self):
        for _devname in self.topo["duts"]:
            self._disconnect_device(_devname)

        self.topo["duts"] = {}

    def _trace_received(self, devname, cmd, hndl, msg1, msg2, line):
        if msg1:
            self.dut_log(devname, msg1, lvl=logging.WARNING)
        if msg2:
            self.dut_log(devname, "{}: {}".format(line, msg2))
        profile.prompt_nfound(cmd)
        try:
            self.dut_log(devname, "============={}: DATA Rcvd ============".format(line))
            for msg in "".join(hndl.get_cached_read_data()).split("\n"):
                if not msg: continue
                msg = msg.strip()
                if not msg: continue
                self.dut_log(devname, "'{}'".format(msg))
            self.dut_log(devname, "======================================")
        except:
            self.dut_log(devname, "{}: DATA Rcvd: {}".format(line, "UNKNOWN"))

    def _find_prompt(self, access, net_connect=None, count=15, sleep=2, recovering=False):
        device = access["devname"]
        hndl = self._get_handle(device) if not net_connect else net_connect
        line = currentframe().f_back.f_lineno
        for i in range(count):
            try:
                ########### Try connecting again #####################
                if not self._is_console_connection(device):
                    if (i > 0 and not net_connect) or not hndl:
                        self.dut_log(device, "Trying to read prompt after reconnecting")
                        if not self.reconnect(devname=device):
                            if sleep > 0:
                                time.sleep(sleep)
                            continue
                        hndl = self._get_handle(device)
                ########### Try connecting again #####################
                if not hndl:
                    self.dut_log(device, "Failed to read prompt: Null handle")
                else:
                    for j in range(5):
                        output = hndl.find_prompt()
                        access["last-prompt"] = output
                        if hndl.verify_prompt(output):
                            break
                        self.dut_log(device, "{}: invalid-prompt: {}".format(line, output))
                        self._check_error(access, "\n", output)
                    output = utils.to_string(output)
                    if self.debug_find_prompt:
                        self.dut_log(device, "find-prompt({}): {}".format(line, output))
                    try:
                        prompts = access["prompts"]
                        access["current_prompt_mode"] = prompts.get_mode_for_prompt(output)
                    except:
                        access["current_prompt_mode"] = "unknown-prompt"
                    return output
            except:
                msg1 = utils.stack_trace(traceback.format_exc())
                msg2 = "Failed to read prompt .. handle: '{}', try: {}".format(hndl, i)
                self._trace_received(device, "find_prompt", hndl, msg1, msg2, line)
            if not hndl: break
            if not hndl.is_alive():
                hndl = None
            if sleep > 0: time.sleep(sleep)

        # dump sysrq traces
        if hndl and os.getenv("SPYTEST_SYSRQ_ENABLE"):
            try:
                output = hndl.sysrq_trace()
                if output:
                    self.dut_log(device, output, lvl=logging.WARNING)
            except Exception as exp:
                print(exp)

        # recover using RPS and report result
        if self.wa:
            try:
                if self._get_handle_index(device) == 0:
                    msg = "Console hang proceeding with RPS Reboot"
                    self.dut_log(device, msg, lvl=logging.WARNING)
                    self.wa.do_rps(device, "reset")
                    if not self.wa.session_init_completed:
                        if not recovering:
                            # try finding the prompt once again
                            # as the session init is not completed
                            return self._find_prompt(access, recovering=True)
                        msg = "Failed to recover the DUT even after RPS reboot"
                        self.dut_log(device, msg, lvl=logging.ERROR)
                        os._exit(15)
                else:
                    # Disconnect the handle
                    if hndl: hndl.disconnect()
                    # Set the ssh handle in access as None
                    self._set_handle(device, None, 1)
                    # tryssh as False
                    access["tryssh"] = False
                    # Switch connection to console handle
                    self._switch_connection(device, 0)
                    # Find Prompt on console handle
                    self._find_prompt(access)
            except Exception as exp:
                print(exp)
            self.wa.report_env_fail("console_hang_observed")
        sys.exit(0)

    def _connect_to_device2(self, device, retry, msgs):
        connected = False
        net_connect = None
        count = 0
        while True:
            try:
                if count > 0:
                    if self.connect_retry_delay > 0:
                        time.sleep(self.connect_retry_delay)
                    msgs.append("Re-Trying %d.." % (count + 1))
                net_connect = DeviceConnection(logger=self.logger, **device)
                connected = True
                break
            except DeviceConnectionTimeout:
                msgs.append("Timed-out..")
                count += 1
                if count > retry:
                    break
            except Exception as e:
                self.logger.warning(e)
                count += 1
                if count > retry:
                    break

        if connected:
            net_connect.set_logger(self.logger)
            return net_connect

        msgs.append("Cannot connect: {}:{}".format(device["ip"], device["port"]))

        return None

    def _connect_to_device(self, device, access, retry=0):
        msgs = []
        net_connect = self._connect_to_device2(device, retry, msgs)
        devname = access["devname"]
        for msg in msgs:
            self.dut_log(devname, msg)
        if net_connect:
            self.dut_log(devname, "Connected ...", lvl=logging.DEBUG)
            prompt = self._find_prompt(access, net_connect)
            self._set_param(devname, "prompt", prompt)
        return net_connect

    def _disconnect_device(self, devname):
        if devname in self.topo["duts"]:
            hndl = self._get_handle(devname)
            if hndl:
                try:
                    hndl.send_command_timing("\x03")
                except:
                    pass
                hndl.disconnect()
                self._set_handle(devname, None)

    def trace_callback_set(self, devname, val):
        def trace_callback(self, msg):
            try:
                print(msg)
            except:
                pass
        if not self.trace_callback_support:
            return
        access = self._get_dev_access(devname)
        if access["filemode"]:
            return
        if not self._is_console_connection(devname):
            return
        func = getattr(self._get_handle(devname), "trace_callback_set")
        if func:
            if val:
                func(trace_callback, self)
            else:
                func(None, None)

    def disable_ztp(self, devname):
        if self.cfg.pde or self.cfg.community_build:
            pass # nothing to be done
        elif "ztp" not in self.prevent_list:
            self._exec(devname, "sudo ztp disable -y", None,
                       "normal-user", delay_factor=6)

    def show_dut_time(self, devname):
        date=self._exec(devname, "date -u +'%Y-%m-%d %H:%M:%S'", None, "normal-user", trace_dut_log=2)
        self.dut_log(devname, "=== UTC Date on the device {}".format(date))

    def is_vsonic(self, dut):
        if dut in self.is_vsonic_cache:
            return self.is_vsonic_cache[dut]
        output = self.show_new(dut,'ls /etc/sonic/bcmsim.cfg',skip_tmpl=True)
        val = not bool(re.search(r'No such file or directory',output))
        self.is_vsonic_cache[dut] = val
        return val

    def set_login_timeout(self, devname):
        if self.is_vsonic_device(devname):
            self._exec(devname, "echo 3 | sudo tee /proc/sys/kernel/printk", None, "normal-user")
        if self.is_sonic_device(devname):
            self._exec(devname, "export TMOUT=0", None, "normal-user")
            self._exec(devname, "stty cols 5000", None, "normal-user")

    def read_vtysh_hostname(self, devname, retry=10):
        devname = self._check_devname(devname)
        access = self._get_dev_access(devname)
        prompts = access["prompts"]
        if self.cfg.pde:
            access["hostname"] = "sonic"
            return access["hostname"]

        hostname_cmd = "sudo vtysh -c 'show running-config | include hostname'"
        cli_prompt = self._get_param(devname, "normal-user-cli-prompt")
        output = self._send_command(access, hostname_cmd, cli_prompt,
                                    skip_error_check=True)
        if "Error response from daemon" in output or \
           "failed to connect to any daemons" in output:
            if retry <= 0:
                msg = "Failed to read hostname from vtysh - assuming sonic"
                access["hostname"] = "sonic"
                self.dut_log(devname, msg, lvl=logging.WARNING)
                return access["hostname"]
            msg = "Failed to read hostname from vtysh retry again in 5 sec"
            self.dut_log(devname, msg, lvl=logging.WARNING)
            self.wait(5)
            retry = retry - 1
            return self.read_vtysh_hostname(devname, retry)

        access["hostname"] = "sonic"
        for line in [_f for _f in str(output).split("\n") if _f]:
            if line.startswith("hostname"):
                access["hostname"] = line.replace("hostname", "").strip()
        msg = "Hostname in vtysh: {}".format(access["hostname"])
        self.dut_log(devname, msg)
        prompts.update_with_hostname(access["hostname"])
        return access["hostname"]

    # phase 0: init 1: upgrade 2: reboot
    def do_post_reboot(self, devname, phase=2, ifa=True, kdump=True, max_ready_wait=0):
        self.set_login_timeout(devname)
        if self.is_sonic_device(devname):
            self.disable_ztp(devname)
            self.read_vtysh_hostname(devname)
            self.wa.wait_system_status(devname, max_time=max_ready_wait)
        self._set_mgmt_ip(devname)
        if phase in [0, 1]:
            self.reset_restinit(devname)
        self._fetch_mgmt_ip(devname, 5, 2)
        self.wa.instrument(devname, "post-reboot")

        if os.getenv("SPYTEST_DATE_SYNC", "0") != "0":
            cmd_date = "sudo date --set='{}'".format(get_timenow().strftime("%c"))
            self._exec(devname, cmd_date, None, "normal-user")

        ##################################################################
        # tasks after every upgrade
        if phase in [0, 1]:
            self.wa.hooks.ensure_upgrade(devname)
        ##################################################################

        # show date on the device
        self.show_dut_time(devname)

        (exec_reboot, reboot_ifa, reboot_kdump) = (False, ifa, kdump)
        if ifa and os.getenv("SPYTEST_IFA_ENABLE"):
            try:
                self.config_new(devname, "ifa -config -enable -y", expect_reboot=True)
                exec_reboot = True
                reboot_ifa = False
            except Exception as exp:
                msg = "Failed enable IFA ({})".format(exp)
                self.dut_log(devname, msg, lvl=logging.WARNING)
        if kdump and self.kdump_supported and not self.is_vsonic_device(devname):
            try:
                cmd = "sudo show kdump status"
                output = self.show_new(devname, cmd, skip_tmpl=True, skip_error_check=True)
                if (("Kdump Administrative Mode:  Enabled" not in output) or
                    ("Kdump Operational State:    Ready" not in output)):
                    self.config_new(devname, "config kdump enable")
                    self.config_new(devname, "config save -y")
                    exec_reboot = True
                    reboot_kdump = False
            except Exception as exp:
                msg = "Failed to enable KDUMP ({})".format(exp)
                self.dut_log(devname, msg, lvl=logging.WARNING)
        if exec_reboot:
            self.do_post_reboot(devname, phase, reboot_ifa, reboot_kdump, max_ready_wait)

    def connect_to_device_current(self, devname, retry=0):
        access = self._get_dev_access(devname)
        if access["current_handle"] == 0:
            return self.connect_to_device(devname, retry, True)
        return self._tryssh_init(devname, False)

    def init_normal_prompt(self, devname, index=0):
        devname = self._check_devname(devname)
        access = self._get_dev_access(devname)
        prompt = self._find_prompt(access)
        prompt2 = prompt.replace("\\", "")
        self._set_param(devname, "prompt", prompt, index)
        self._set_param(devname, "normal-user-cli-prompt", prompt, index)
        self._set_prompt(devname, "normal-user", prompt)
        return prompt2

    def connect_to_device(self, devname, retry=0, recon=False):
        connection_param = {
            'access_model': 'sonic_ssh',
            'username': 'admin',
            'password': 'YourPaSsWoRd',
            'blocking_timeout': 30,
            'keepalive': 1,
            'port': 22
        }
        access = self._get_dev_access(devname)

        if "access_model" in access:
            connection_param.update({"access_model": access["access_model"]})
        if "username" in access:
            connection_param.update({"username": access["username"]})
        if "password" in access:
            connection_param.update({"password": access["password"]})
        if "altpassword" in access:
            connection_param.update({"altpassword": access["altpassword"]})
        if "verbose" in access:
            connection_param.update({"verbose": access["verbose"]})
        if "port" in access:
            connection_param.update({"port": access["port"]})
        if "mgmt_ipmask" in access:
            connection_param.update({"mgmt_ipmask": access["mgmt_ipmask"]})
        if "mgmt_gw" in access:
            connection_param.update({"mgmt_gw": access["mgmt_gw"]})
        if "addl_auth" in access:
            connection_param.update({"addl_auth": access["addl_auth"]})

        self._copy_value(access, connection_param, ["sshcon_username", "sshcon_password"])
        connection_param['net_devname'] = devname
        connection_param['net_login'] = self._net_login

        connection_param['ip'] = access["ip"]

        access["filemode"] = self.cfg.filemode
        access["devname"] = devname
        access["last-prompt"] = None
        if "device_model" in access:
            access["prompts"] = Prompts(access["device_model"])
        else:
            access["prompts"] = Prompts()

        self.dut_log(devname, "Connecting to device (%s): %s: %s:%s .." %
                     (access["alias"], connection_param["access_model"],
                      connection_param['ip'], connection_param['port']))

        if not self.cfg.filemode:
            access["connection_param"] = connection_param
            net_connect = self._connect_to_device(connection_param,
                                                  access, retry=retry)
            if not net_connect:
                dut_label = self._get_dut_label(devname)
                msg = "Failed to connect to device {}".format(dut_label)
                self.dut_log(devname, msg, lvl=logging.ERROR)

                if os.getenv("SPYTEST_RECOVERY_MECHANISMS", "0") != "0":
                    if not self.wa.session_init_completed and \
                            self._is_console_connection(devname, connection_param) and \
                            self.is_sonic_device(devname):
                        msg = "Trying RPS Reboot to recover the device {}".format(dut_label)
                        self.dut_log(devname, msg, lvl=logging.WARNING)
                        self.wa.do_rps(devname, "reset", recon=False)
                        net_connect = self._connect_to_device(connection_param,
                                                              access, retry=retry)
                        if not net_connect:
                            msg = "Failed to connect to device {} even after RPS reboot".format(dut_label)
                            self.dut_log(devname, msg, lvl=logging.ERROR)
                            return False
                    else:
                        return False
                else:
                    return False

            self._set_handle(devname, net_connect)
            prompt2 = self.init_normal_prompt(devname)
            msg = "Prompt at the connection start: '{}' ".format(prompt2)
            self.dut_log(devname, msg)

            if not self.wa.session_init_completed:
                self.image_install_status[devname] = False

            ##################################################################
            # detect if we are in ONIE discovery prompt
            if self._is_console_connection(devname, connection_param):
                if "ONIE" in self._get_param(devname, "prompt"):
                    if not self.recover_from_onie(devname, True):
                        if not self.recover_from_onie(devname, False):
                            return False
                    self.init_normal_prompt(devname)
            ##################################################################
            # Ensure that we are at normal user mode to be able to
            # continue after reboot from test scripts
            if self._is_console_connection(devname, connection_param) and \
                self.is_sonic_device(devname):
                try:
                    prompt = self._get_param(devname, "normal-user-cli-prompt")
                    output = self._send_command(access, "?", ufcli=False,
                                                trace_dut_log=0, skip_error_check=True)
                    if "command not found" not in output:
                        prompt = self._exit_docker(devname, prompt)

                    prompt2 = prompt.replace("\\", "")
                    if re.compile(lldp_prompt).match(prompt2) or sonic_mgmt_hostname in prompt2:
                        prompt = self._exit_docker(devname, prompt)

                    self._enter_linux(devname, prompt)
                    prompt = self.init_normal_prompt(devname)
                    output = self._send_command(access, "whoami", skip_error_check=True, ufcli=False)
                    if "Unknown command" in output:
                        self._exit_vtysh(devname, onconnect=1)
                        prompt = self.init_normal_prompt(devname)
                        output = self._send_command(access, "whoami")
                    whoami = output.split("\n")[0].strip()
                    if connection_param["username"] != whoami:
                        msg = "current user {} is not same in testbed {}"
                        msg = msg.format(whoami, connection_param["username"])
                        self.dut_log(devname, msg, lvl=logging.WARNING)
                        prompt_terminator = r"([#|\$]\s*$|{})".format(regex_login)
                        self._send_command(access, "exit", prompt_terminator)
                        self._enter_linux(devname)
                        prompt = self.init_normal_prompt(devname)
                except Exception as exp:
                    msg = "Please report this issue ({})".format(exp)
                    self.logger.error(msg)
                    msg = utils.stack_trace(traceback.format_exc())
                    self.dut_log(devname, msg, lvl=logging.WARNING)

            # perform post reboot operations
            connection_param["mgmt-ip"] = None

            # wait for short time when we are going to upgrade
            max_ready_wait = 0 if self.cfg.skip_load_image else 1
            if not recon:
                if not self.cfg.community_build:
                    self.config_new(devname, "sonic-clear logging", skip_error_check=True)
                self.dut_log(devname, "reading initial version")
                self.show_new(devname, "show version", skip_tmpl=True, skip_error_check=True)
                self.do_post_reboot(devname, phase=0, max_ready_wait=max_ready_wait)
            else:
                self.set_login_timeout(devname)

            # open ssh connection to switch execution to
            self._tryssh_init(devname)

        else:
            self._set_param(devname, "normal-user-cli-prompt", "dummy")

        prompt = self._get_param(devname, "normal-user-cli-prompt")
        msg = "Prompt at the connection finish: '{}' ".format(prompt.replace("\\", ""))
        self.dut_log(devname, msg)
        self.show_dut_time(devname)

        return True

    def _tryssh_init(self, devname, init=True):
        access = self._get_dev_access(devname)
        if not access["tryssh"] and not access.get("static-mgmt-ip"):
            return True

        if access["filemode"]:
            return True

        old = access["connection_param"].get("mgmt-ip")
        if access["tryssh"] and not init:
            self._fetch_mgmt_ip(devname, 5, 2)
            new = access["connection_param"].get("mgmt-ip")
            if old != new:
                self.dut_log(devname, "IP address changed from {} to {}".format(old, new))

        if init and not old:
            self.dut_log(devname, "Trying to get the device mgmt-ip..")
            self._fetch_mgmt_ip(devname, 5, 2)

        [hndl, ipaddr] = self._connect_to_device_ssh(devname)
        if hndl:
            self._set_handle(devname, hndl, 1)
            self.init_normal_prompt(devname, 1)
            self._switch_connection(devname, 1)
            self.set_login_timeout(devname)
            return True
        self.dut_log(devname, "Failed to ssh connect {}".format(ipaddr))
        access["tryssh"] = False
        self._set_handle(devname, None, 1)
        return False

    def _connect_to_device_ssh(self, devname):
        access = self._get_dev_access(devname)
        device = copy.copy(access["connection_param"])
        if not device["mgmt-ip"]:
            return [None, None]
        device["ip"] = device["mgmt-ip"]
        device["port"] = 22
        device["blocking_timeout"] = 30
        device["access_model"] = "sonic_ssh"
        del device["mgmt-ip"]
        msgs = []
        self.dut_log(devname, "initiate ssh to {}".format(device["ip"]))
        hndl = self._connect_to_device2(device, 0, msgs)
        return [hndl, device["ip"]]

    def _set_mgmt_ip(self, devname):
        access = self._get_dev_access(devname)
        access["static-mgmt-ip"] = False
        if access["filemode"]:
            return

        # no need to set static mgmt ip if not run from terminal
        connection_param = access["connection_param"]
        if not self._is_console_connection(devname):
            return

        # check if mgmt option is specified in testbed
        mgmt_ipmask = connection_param.get("mgmt_ipmask", None)
        mgmt_gw = connection_param.get("mgmt_gw", None)
        if not mgmt_ipmask or not mgmt_gw:
            return

        # TODO: check if mgmt is already used in network
        #utils.ipcheck(mgmt)

        prompt = self._enter_linux_exit_vtysh(devname)
        if prompt is None:
            prompt = self._find_prompt(access)
        self._set_param(devname, "prompt", prompt)
        cmd = "sudo /sbin/ifconfig eth0 {}".format(mgmt_ipmask)
        cmd = "{};sudo /sbin/route add default gw {}".format(cmd, mgmt_gw)
        self._send_command(access, cmd)
        access["static-mgmt-ip"] = True
        self.rest_init(devname, True, access.get("username"), access.get("password"), access.get("altpassword"))

        #self._apply_remote(devname, "set-mgmt-ip", ["static", mgmt_ipmask, mgmt_gw])

    def _fetch_mgmt_ip(self, devname, try_again=3, wait_for_ip=0):
        if not self.is_sonic_device(devname): return
        access = self._get_dev_access(devname)
        if access["filemode"]: return

        (switched, reconnect) = (False, True)
        try:
            switched = self._tryssh_switch(devname)
            old = access["connection_param"].get("mgmt-ip")
            self._fetch_mgmt_ip2(devname, try_again, wait_for_ip)
            new = access["connection_param"].get("mgmt-ip")
            if old and new and old == new:
                # no need to reconnect to SSH
                reconnect = False
            if switched: self._tryssh_switch(devname, True, reconnect)
        except Exception as e:
            msg = utils.stack_trace(traceback.format_exc())
            self.dut_log(devname, msg, lvl=logging.WARNING)
            if switched: self._tryssh_switch(devname, False)
            raise e

    def _fetch_mgmt_ip2(self, devname, try_again=3, wait_for_ip=0):
        access = self._get_dev_access(devname)

        # if the device type is terminal issue ifconfig to get eth0 ipaddress
        connection_param = access["connection_param"]
        if not self._is_console_connection(devname):
            connection_param["mgmt-ip"] = None
            self.rest_init(devname, access.get("username"), access.get("password"), access.get("altpassword"), True)
            return

        prompt = self._enter_linux_exit_vtysh(devname)
        if prompt is None:
            prompt = self._find_prompt(access)
        self._set_param(devname, "prompt", prompt)
        no_ifconfig = True
        try:
            if not no_ifconfig:
                output = self._send_command(access, "/sbin/ifconfig eth0")
                data = self._textfsm_apply(devname, "unix_ifcfg.tmpl", output)[0]
                access["connection_param"]["mgmt-ip"] = data[4][0].encode('ascii')
                self._send_command(access, "/sbin/ip route list dev eth0", skip_error_check=True)
            else:
                try:
                    output = self._send_command(access, "/sbin/ip route list dev eth0", skip_error_check=True)
                    data = self._textfsm_apply(devname, "linux/ip_route_list_dev.tmpl", output)[0]
                    access["connection_param"]["mgmt-ip"] = data[1].encode('ascii')
                except:
                    msg = "Unable to get the ip address of eth0 from '/sbin/ip route list'. Falling back to 'ifconfig'.."
                    self.dut_log(devname, msg, lvl=logging.WARNING)
                    output = self._send_command(access, "/sbin/ifconfig eth0")
                    data = self._textfsm_apply(devname, "unix_ifcfg.tmpl", output)[0]
                    access["connection_param"]["mgmt-ip"] = data[4][0].encode('ascii')
            msg = "eth0: {}".format(access["connection_param"]["mgmt-ip"])
            self.dut_log(devname, msg)
            self.rest_init(devname, access.get("username"), access.get("password"), access.get("altpassword"), True)
            self.check_pending_downloads(devname)
        except:
            msg1 = "Failed to read ip address of eth0"
            msg2 = "Failed to read ip address of eth0..Retrying"
            msg = msg2 if try_again > 0 else msg1
            self.dut_log(devname, msg, lvl=logging.WARNING)
            self.dut_log(devname, "{}: Rcvd: '{}'".format(try_again, output))
            if try_again > 0:
                if wait_for_ip > 0 or len(output) == 0:
                    # output is present but there is no IP address
                    self.wait(wait_for_ip)
                    try_again = try_again - 1
                    self._fetch_mgmt_ip2(devname, try_again, wait_for_ip)
                    return
            if self.abort_without_mgmt_ip:
                msg = "Cannot proceed without management IP address"
                self.dut_log(devname, msg, lvl=logging.ERROR)
                os._exit(15)
            connection_param["mgmt-ip"] = None

    def connect_all_devices(self, faster_init=False):
        [retvals, exceptions] = utils.exec_foreach(faster_init, self.topo["duts"],
                                     self.connect_to_device, 10)

        for devname in self.topo["duts"]:
            connected = retvals.pop(0)
            exception = exceptions.pop(0)
            if not connected:
                msg = "Failed to connect to device"
            elif exception:
                msg = "Error connecting to device"
            else:
                continue
            self.dut_log(devname, msg)
            return False
        self.logger.info("Connected to All devices")
        return True

    def _report_error(self, matched_result, cmd):
        if not matched_result:
            return False
        if isinstance(matched_result, list):
            result = matched_result[0]
            msgid = matched_result[1]
        else:
            result = "Fail"
            msgid = matched_result
        if result == "DUTFail":
            self.wa.report_dut_fail(msgid, cmd)
        elif result == "EnvFail":
            self.wa.report_env_fail(msgid, cmd)
        elif result == "TGenFail":
            self.wa.report_tgen_fail(msgid, cmd)
        else:
            self.wa.report_fail(msgid, cmd)
        return True

    def _check_error(self, access, cmd, output, skip_raise=False):
        devname = access["devname"]
        actions = []
        matched_result = None
        matched_err = ""
        for err, errinfo in list(access["errors"].items()):
            #self.logger.debug("COMPARE-CMD: {} vs {}".format(errinfo.command, cmd))
            if re.compile(errinfo.command).match(cmd):
                #self.logger.debug("COMPARE-OUT: {} vs {}".format(errinfo.search, output))
                if re.search(errinfo.search, output):
                    #self.logger.debug("MATCHED-OUT: {} ACTION: {} {}/{}".format(
                        #output, errinfo.action, skip_raise, self.wa.session_init_completed))
                    actions = utils.make_list(errinfo.action)
                    matched_err = err
                    matched_result = errinfo.get("result", None)
                    break
        if not matched_err:
            return output
        new_output = []
        # check if coredump and techsupport are needed
        for action in actions:
            if action == "core-dump":
                self.tc_fetch_core_files = True
            if action == "tech-support":
                self.tc_get_tech_support = True
            self.wa.set_module_lvl_action_flags(action)
        for action in actions:
            if action == "reboot":
                self.dut_log(devname, output, lvl=logging.WARNING)
                out = self.recover(devname, "Rebooting match {} action".format(matched_err))
                new_output.append(out)
                self._report_error(matched_result, cmd)
            elif action == "raise":
                if not self.wa.session_init_completed:
                    return output
                if skip_raise:
                    msg = "Skipped error checking. Even though detected pattern: '{}'".format(matched_err)
                    self.dut_log(devname, msg, lvl=logging.WARNING)
                    return output
                msg = "Error: failed to execute '{}'".format(cmd)
                self.dut_log(devname, msg, lvl=logging.WARNING)
                self.dut_log(devname, output, lvl=logging.WARNING)
                if not self._report_error(matched_result, cmd):
                    self.dut_log(devname, "detected pattern: {}".format(matched_err))
                    raise ValueError("Command '{}' returned error".format(cmd))
        return '\n'.join(new_output)

    def _trace_cli(self, access, cmd):
        # trace the CLI commands in CSV file, to be used to measure coverage
        # module,function,cli-mode,command
        #pass
        try: self.wa._trace_cli(access["devname"], access["current_prompt_mode"], cmd)
        except: pass

    def _try(self, access, line, new_line, fcli, cmd, expect_string, delay_factor, **kwargs):
        output = ""
        attempt = 0
        devname = access["devname"]

        if self.devices_used_collection:
            self.devices_used_in_tc[devname] = True

        ctrl_c_used = False
        while attempt < 3:
            try:
                if not self._get_handle(devname):
                    self.connect_to_device_current(devname)
                if attempt != 0:
                    msg = "cmd: {} attempt {}..".format(cmd, attempt)
                    self.dut_log(devname, msg, lvl=logging.WARNING)
                    msg = "Disconnecting the device {} connection ..".format(devname)
                    self.dut_log(devname, msg, lvl=logging.WARNING)
                    self._disconnect_device(devname)
                    msg = "Reconnecting to the device {} ..".format(devname)
                    self.dut_log(devname, msg, lvl=logging.WARNING)
                    self.connect_to_device_current(devname)
                hndl = self._get_handle(devname)
                if not hndl:
                    msg = "Device not connected: attempt {}..".format(attempt)
                    self.dut_log(devname, msg, lvl=logging.WARNING)
                    reconnect_wait = 5
                    msg = "Waiting for {} secs before re-attempting connection to Device {}..".format(reconnect_wait, devname)
                    self.dut_log(devname, msg, lvl=logging.WARNING)
                    self.wait(reconnect_wait)
                    attempt += 1
                    continue
                if attempt != 0:
                    msg = "Trying CR: attempt {}.. cmd '{}' ..".format(attempt, cmd)
                    self.dut_log(devname, msg, lvl=logging.WARNING)
                    hndl.send_command_timing("")
                elif new_line:
                    output = hndl.send_command_new(fcli, cmd, expect_string, delay_factor, **kwargs)
                    self._trace_cli(access, cmd)
                else:
                    output = hndl.send_command_timing(cmd, normalize=False)
                hndl.clear_buffer()
                break
            except Exception as ex:
                if self.wa.is_shutting_down():
                    return ""
                msg = utils.stack_trace(traceback.format_exc())
                self.dut_log(devname, msg, lvl=logging.WARNING)
                t = "Exception {} occurred.. (attempt {}) line: {} cmd: {}"
                msg = t.format(type(ex).__name__, attempt, line, cmd)
                self.dut_log(devname, msg)
                if self._get_handle(devname):
                    hndl = self._get_handle(devname)
                    line = currentframe().f_back.f_lineno
                    self._trace_received(devname, cmd, hndl, None, None, line)
                    try:
                        if attempt == 0:
                            msg = "Trying CR: attempt {}.. cmd '{}' ..".format(attempt, cmd)
                            self.dut_log(devname, msg, lvl=logging.WARNING)
                            #output = hndl.send_command(fcli, "", expect_string)
                            hndl.send_command_timing("")
                            output = hndl.find_prompt()
                            hndl.clear_buffer()
                            if hndl.verify_prompt(output):
                                break
                    except Exception as cr_ex:
                        msg = "Unable to find prompt even after trying CR .."
                        self.dut_log(devname, msg, lvl=logging.WARNING)
                        t = "Exception {} occurred while trying CR.. (attempt {}) line: {} cmd: {} exception: {}"
                        msg = t.format(type(cr_ex).__name__, attempt, line, cmd, cr_ex)
                        self.dut_log(devname, msg)
                        line = currentframe().f_back.f_lineno
                        self._trace_received(devname, "", hndl, None, None, line)
                    try:
                        msg = "Trying CTRL+C: attempt {}..".format(attempt)
                        self.dut_log(devname, msg, lvl=logging.WARNING)
                        hndl.send_command_timing("\x03")
                        hndl.clear_buffer()
                        ctrl_c_used = True
                        # TODO: Need to check for both testcase and module on result setting.
                        #if self.tc_start_time:
                        #    self.wa.report_scripterror("command_failed_recovered_using_ctrlc", cmd)
                    except Exception as ex2:
                        if self.wa.is_shutting_down():
                            self.dut_log(devname, "run shutting down", lvl=logging.WARNING)
                            return ""
                        msg = utils.stack_trace(traceback.format_exc())
                        self.dut_log(devname, msg, lvl=logging.WARNING)
                        t = "Exception occurred even after CTRL+C.. (attempt {0}) type {1} args:\n{2!r}"
                        msg = t.format(attempt, type(ex2).__name__, ex2.args)
                        self.dut_log(devname, msg, lvl=logging.WARNING)
                attempt += 1

        if ctrl_c_used:
            if self.tc_start_time:
                self.wa.report_fail("command_failed_recovered_using_ctrlc", cmd)
            elif self.module_start_time:
                msg = "Command '{}' failed to give prompt during module config, recovered using CTRL+C".format(cmd)
                self.wa.report_config_fail("module_config_failed", msg)

        return output

    def _send_command(self, access, cmd, expect=None, skip_error_check=False,
                      delay_factor=0, trace_dut_log=3, new_line=True,
                      ufcli=True, **kwargs):
        output = ""

        # use default delay factor if not specified
        delay_factor = 2 if delay_factor == 0 else delay_factor
        fcli = self.fcli if ufcli else 0

        devname = access["devname"]

        if trace_dut_log in [1, 3]:
            cmd_log = cmd.replace("\r", "")
            cmd_log = cmd_log.replace("\n", "\\n")

            # disable faster-cli if there are new lines
            if not fcli or delay_factor > 2:
                self.dut_log(devname, "SCMD: {}".format(cmd_log))
            elif cmd.count("\n") > 0:
                self.dut_log(devname, "SCMD: {}".format(cmd_log))
                fcli = 0
            else:
                self.dut_log(devname, "FCMD: {}".format(cmd_log))

        if not access["filemode"]:
            if not expect:
                expect_string = self._get_param(devname, "prompt")
            else:
                expect_string = expect

            pid = profile.start(cmd, access["dut_name"])
            line = currentframe().f_back.f_lineno
            #self.dut_log(devname, "EXPECT: {}".format(expect_string))
            output = self._try(access, line, new_line, fcli,
                               cmd, expect_string, delay_factor, **kwargs)
            profile.stop(pid)

            if trace_dut_log in [2, 3]:
                self.dut_log(devname, output)

            self._check_tc_timeout(access)

        elif self.dry_run_cmd_delay > 0:
            time.sleep(self.dry_run_cmd_delay)

        output = self._check_error(access, cmd, output, skip_error_check)

        return output

    def do_pre_rps(self, devname, op):
        self._tryssh_switch(devname)

    def do_post_rps(self, devname, op):
        if op not in ["off"]:
            self.dut_log(devname, "Reconnecting after RPS reboot", lvl=logging.WARNING)
            rps_flag = False
            index = 0
            rps_reboot_static_wait = 30
            while index < 3:
                if self.reconnect(devname):
                    rps_flag = True
                    break
                msg = "Waiting for '{}' secs after RPS reboot.".format(rps_reboot_static_wait)
                self.dut_log(devname, msg, lvl=logging.WARNING)
                self.wait(rps_reboot_static_wait)
                index = index + 1
            if not rps_flag:
                return rps_flag
            self._enter_linux(devname)
            self.do_post_reboot(devname)
            self._tryssh_switch(devname, True)
        return True

    def reconnect(self, devname=None):
        if not devname or isinstance(devname, list):
            if not devname:
                devlist = self.topo["duts"]
            else:
                devlist = devname

            for _devname in devlist:
                connected = self.reconnect(devname=_devname)
                if not connected:
                    msg = "Error reconnecting to device"
                    self.dut_log(_devname, msg)
                    return False
        elif devname in self.topo["duts"]:
            hndl = self._get_handle(devname)
            if hndl:
                hndl.disconnect()
                self._set_handle(devname, None)
            connected = self.connect_to_device_current(devname, retry=3)
            if not connected:
                msg = "Error, reconnecting to device"
                self.dut_log(devname, msg)
                return False
        return True

    ######################### SPYTEST additions #########################
    def _exit_docker(self, devname, prompt=None):
        access = self._get_dev_access(devname)
        if access["filemode"]:
            return True

        dbg = self.debug_find_prompt

        if self.is_use_last_prompt():
            if not prompt:
                prompt = access["last-prompt"]
            elif prompt != access["last-prompt"]:
                prompt = None

        if not prompt:
            prompt = self._find_prompt(access)
        prompt2 = prompt.replace("\\", "")
        self.dut_log(devname, "prompt = '{}'".format(prompt), cond=dbg)
        self.dut_log(devname, "prompt2 = '{}'".format(prompt2), cond=dbg)
        hndl = self._get_handle(devname)

        msg = "trying to change from prompt({})".format(prompt2)
        self.dut_log(devname, msg, lvl=logging.DEBUG)

        new_prompt = None
        if re.compile(lldp_prompt).match(prompt2):
            try:
                hndl.send_command_timing("exit")
                new_prompt = self._find_prompt(access)
            except:
                pass
        else:
            try:
                hndl.send_command_timing("\x03")
                hndl.send_command_timing("end")
                hndl.send_command_timing("\x03")
                hndl.send_command_timing("exit")
                new_prompt = self._find_prompt(access)
            except:
                pass

        msg = "prompt after recovery({})".format(new_prompt.replace("\\", ""))
        self.dut_log(devname, msg, lvl=logging.DEBUG)
        self._set_last_prompt(access, new_prompt)
        return new_prompt

    def _net_login(self, devname, hndl):
        self._set_handle(devname, hndl)
        #self.debug_find_prompt = True
        self._enter_linux(devname)

    def _enter_linux(self, devname, prompt=None):
        for i in range(10):
            (rv, known_prompt) = self._enter_linux_once(devname, prompt)
            if rv:
                return known_prompt
            prompt = known_prompt
        return None

    def _enter_linux_once(self, devname, prompt=None):
        access = self._get_dev_access(devname)
        if access["filemode"]:
            return (True, None)

        dbg = self.debug_find_prompt

        if self.is_use_last_prompt():
            if not prompt:
                prompt = access["last-prompt"]
            elif prompt != access["last-prompt"]:
                prompt = None

        if not prompt:
            prompt = self._find_prompt(access)
        prompt2 = prompt.replace("\\", "")
        msg = "prompt = '{}' prompt2 = '{}'".format(prompt, prompt2)
        self.dut_log(devname, msg, cond=dbg)

        if re.compile(lldp_prompt).match(prompt2):
            try:
                cli_prompt = self._get_param(devname, "normal-user-cli-prompt")
                output = self._send_command(access, "exit", cli_prompt)
                self._set_last_prompt(access, cli_prompt)
            except:
                output = ""
                self._set_last_prompt(access, None)
            return (True, None)

        if sonic_mgmt_hostname in prompt2:
            try:
                cli_prompt = self._get_param(devname, "normal-user-cli-prompt")
                prompt = self._exit_docker(devname, prompt)
                self._set_last_prompt(access, cli_prompt)
            except:
                output = ""
                self._set_last_prompt(access, None)
            return (True, None)

        (rv, known_prompt) = (True, None)
        prompt_terminator = r"(\S+\s+login:\s*$|[Pp]assword:\s*$|\(current\) UNIX password:\s*|[#|\$]\s*$)"
        #prompt_terminators = [regex_login, regex_password, "\(current\) UNIX password:\s*", "[#|\$]\s*$"]
        #prompt_terminator = "|".join(prompt_terminators)
        if re.compile(regex_login).match(prompt2):
            self.dut_log(devname, "enter username", cond=dbg)
            output = self._send_command(access, access["username"], prompt_terminator, strip_prompt=False)
            if prompt2 in output:
                return (False, known_prompt)
            self.dut_log(devname, "enter password", cond=dbg)
            output = self._send_command(access, access["password"], prompt_terminator,
                         ufcli=False, skip_error_check=True, strip_prompt=False)
            self.dut_log(devname, "login output:='{}'".format(output), cond=dbg)
            if "bash: {}: command not found".format(access["password"]) in output:
                self.dut_log(devname, "Logged into system without password", lvl=logging.WARNING)
                self._set_last_prompt(access, None)
                self.init_normal_prompt(devname)
            elif prompt2 not in output:
                (rv, output) = self._change_default_pwd(devname, access["password"], access["altpassword"], output)
                self._set_last_prompt(access, None)
                if prompt2 not in output and not re.search(regex_password_anywhere, output):
                    self.init_normal_prompt(devname)
                self.dut_log(devname, "login output='{}'".format(output), cond=dbg)
        elif re.compile(regex_password).match(prompt2):
            self.dut_log(devname, "enter password", cond=dbg)
            output = self._send_command(access, access["password"],
                                        prompt_terminator, ufcli=False, strip_prompt=False)
            self.dut_log(devname, "password output:='{}'".format(output), cond=dbg)
            (rv, output) = self._change_default_pwd(devname, access["password"], access["altpassword"], output)
            self._set_last_prompt(access, None)
            if prompt2 not in output and not re.search(regex_password_anywhere, output):
                self.init_normal_prompt(devname)
            self.dut_log(devname, "password output='{}'".format(output), cond=dbg)
        else:
            self.dut_log(devname, "neither username nor password", cond=dbg)
            output = ""
            known_prompt = prompt

        if prompt2 in output:
            output = self._send_command(access, access["username"], prompt_terminator, strip_prompt=False)
            if prompt2 in output:
                return (False, known_prompt)
            output = self._send_command(access, access["altpassword"],
                                        prompt_terminator, ufcli=False, strip_prompt=False)
            self.dut_log(devname, "login2 output:='{}'".format(output), cond=dbg)
            (rv, output) = self._change_default_pwd(devname, access["altpassword"], access["password"], output)
            self._set_last_prompt(access, None)
            if prompt2 not in output and not re.search(regex_password_anywhere, output):
                self.init_normal_prompt(devname)
            self.dut_log(devname, "login2 output='{}'".format(output), cond=dbg)
            known_prompt = None
            return (False, known_prompt)
        else:
            msg = "prompt2 is not seen in output '{}'"
            self.dut_log(devname, msg.format(output), cond=dbg)

        return (rv, known_prompt)

    def _change_default_pwd(self, devname, pwd, altpwd, output):
        access = self._get_dev_access(devname)
        device = access["devname"]
        line = currentframe().f_back.f_lineno

        try:
            hndl = self._get_handle(device)
            hndl.password = pwd
            hndl.altpassword = altpwd
            output = hndl.extended_login(output)
            return (True, output)
        except:
            msg1 = utils.stack_trace(traceback.format_exc())
            msg2 = "Failed to change default password"
            msg2 = "Unexpected messages on console - trying to recover"
            self._trace_received(device, "change_default_pwd", hndl, msg1, msg2, line)
            return (False, "")

    def _exit_vtysh(self, devname, onconnect=0, prompt=None):
        access = self._get_dev_access(devname)
        if access["filemode"]:
            return

        hostname = "sonic"
        if "hostname" in access and access["hostname"]:
            hostname = access["hostname"]

        prompt_terminator = r"([#|\$]\s*$)"
        if onconnect:
            self._send_command(access, "end\r\nexit", prompt_terminator)
            self._set_last_prompt(access, None)
            return

        if self.is_use_last_prompt():
            if not prompt:
                prompt = access["last-prompt"]
            elif prompt != access["last-prompt"]:
                prompt = None

        if not prompt:
            prompt = self._find_prompt(access)
        prompt2 = prompt.replace("\\", "")
        if re.compile(regex_password).match(prompt2):
            self._send_command(access, access["password"], prompt_terminator, ufcli=False)
        if prompt.startswith(hostname):
            self._send_command(access, "end\r\nexit", prompt_terminator)
            self._set_last_prompt(access, None)

    def _enter_linux_exit_vtysh(self, devname, prompt=None):
        prompt = self._enter_linux(devname, prompt)
        return self._exit_vtysh(devname, onconnect=0, prompt=prompt)

    def _set_last_prompt(self, access, prompt, mode=None):
        access["last-prompt"] = prompt
        if mode and "vtysh" in mode:
            access["last-prompt"] = None #TEMP#

    def _exec_mode_change(self, devname, l_cmd, to_prompt, from_prompt):
        devname = self._check_devname(devname)
        access = self._get_dev_access(devname)
        expect = "|".join([from_prompt, to_prompt])
        self._send_command(access, l_cmd, expect, True, ufcli=False)
        prompt = self._find_prompt(access)
        if prompt == from_prompt:
            raise Exception("Failed to change mode")

    def _exec(self, devname, cmd, expect=None, mode=None,
              skip_error_check=False, delay_factor=0,
              expect_reboot=False, trace_dut_log=3, ufcli=True):
        devname = self._check_devname(devname)
        access = self._get_dev_access(devname)
        if access["filemode"]:
            pid = profile.start(cmd, access["dut_name"])
            profile.stop(pid)
            self.dut_log(devname, cmd)
            if self.dry_run_cmd_delay > 0:
                time.sleep(self.dry_run_cmd_delay)
            return ""

        if not mode:
            return self._send_command(access, cmd, expect, skip_error_check,
                                      trace_dut_log=trace_dut_log,
                                      delay_factor=delay_factor, ufcli=ufcli)

        # get current prompt or reuse the prompt
        last_prompt = access["last-prompt"]
        if self.is_use_last_prompt():
            prompt = last_prompt
        else:
            prompt = None
        if prompt is None:
            prompt = self._find_prompt(access)
            prompt2 = prompt.replace("\\", "")
            prompt = self._enter_linux(devname, prompt)
            if prompt is None:
                prompt = self._find_prompt(access)
        prompt2 = prompt.replace("\\", "")

        # arrive at vtysh prompt based on hostname
        hostname = "sonic"
        if "hostname" in access and access["hostname"]:
            hostname = access["hostname"]
        vtysh_prompt = "{}#".format(hostname)
        vtysh_config_prompt = "{}(config)#".format(hostname)
        vtysh_maybe_config_prompt = r"{}#|{}\(config.*\)#".format(hostname, hostname)

        # lldp shell commands
        if mode == "lldp-user":
            if prompt2.startswith(sonic_mgmt_hostname):
                msg = "trying to change from sonic-mgmt({}) while executing {}"
                msg = msg.format(prompt, cmd)
                self.dut_log(devname, msg)
                try:
                    prompt = self._exit_docker(devname, prompt)
                    prompt2 = prompt.replace("\\", "")
                except:
                    pass
                self._set_last_prompt(access, prompt)
            elif prompt.startswith(hostname):
                msg = "trying to change from vtysh({}) while executing {}"
                msg = msg.format(prompt, cmd)
                self.dut_log(devname, msg)
                try:
                    cli_prompt = self._get_param(devname, "normal-user-cli-prompt")
                    self._send_command(access, "end\r\nexit", cli_prompt)
                    self._set_last_prompt(access, cli_prompt)
                    prompt = self._find_prompt(access)
                    prompt2 = prompt.replace("\\", "")
                except:
                    self._set_last_prompt(access, None)

            if prompt == self._get_param(devname, "normal-user-cli-prompt"):
                self.dut_log(devname, "trying to enter into lldpcli({}) while executing {}".format(prompt, cmd))
                self._send_command(access, "docker exec -it lldp lldpcli", lldp_prompt)
                self._set_last_prompt(access, lldp_prompt, "lldp")
                prompt2 = prompt = lldp_prompt

            if prompt2 == lldp_prompt and cmd == "exit":
                try:
                    cli_prompt = self._get_param(devname, "normal-user-cli-prompt")
                    output = self._send_command(access, "exit", cli_prompt)
                    self._set_last_prompt(access, cli_prompt, "lldp")
                except:
                    output = ""
                    self._set_last_prompt(access, None)
                return output

            if prompt == lldp_prompt or prompt2 == lldp_prompt:
                output = self._send_command(access, cmd, lldp_prompt,
                                            skip_error_check, ufcli=ufcli)
                self._set_last_prompt(access, lldp_prompt, "lldp")
                return output

            # import pdb; pdb.set_trace()
            print("unhandled - 4", cmd, hostname, prompt2)
            return ""

        # sonic shell commands
        if mode == "normal-user":
            if prompt == lldp_prompt or prompt2 == lldp_prompt:
                msg = "trying to change from lldp({}) while executing {}"
                msg = msg.format(prompt, cmd)
                self.dut_log(devname, msg)
                try:
                    cli_prompt = self._get_param(devname, "normal-user-cli-prompt")
                    self._send_command(access, "exit", cli_prompt)
                    self._set_last_prompt(access, cli_prompt)
                except:
                    self._set_last_prompt(access, None)
            elif prompt2.startswith(sonic_mgmt_hostname):
                msg = "trying to change from sonic-mgmt({}) while executing {}"
                msg = msg.format(prompt, cmd)
                self.dut_log(devname, msg)
                try:
                    prompt = self._exit_docker(devname, prompt)
                    prompt2 = prompt.replace("\\", "")
                except:
                    pass
                self._set_last_prompt(access, prompt)
            elif prompt.startswith(hostname):
                msg = "trying to change from vtysh({}) while executing {}"
                msg = msg.format(prompt, cmd)
                self.dut_log(devname, msg)
                try:
                    cli_prompt = self._get_param(devname, "normal-user-cli-prompt")
                    self._send_command(access, "end\r\nexit", cli_prompt)
                    self._set_last_prompt(access, cli_prompt)
                except:
                    self._set_last_prompt(access, None)
            if not expect_reboot:
                return self._send_command(access, cmd, expect, skip_error_check,
                                          trace_dut_log=trace_dut_log,
                                          delay_factor=delay_factor, ufcli=ufcli)
            # special case where the show may result into reboot
            expect = "|".join([self._get_param(devname, "prompt"), regex_login])
            delay_factor = 6 if delay_factor < 6 else delay_factor

            try:
                self._tryssh_switch(devname)
                output = self._send_command(access, cmd, expect, True,
                                            delay_factor=delay_factor, ufcli=ufcli)
                prompt = self._find_prompt(access)
                if prompt != self._get_param(devname, "prompt"):
                    self._enter_linux(devname, prompt)
                    self.do_post_reboot(devname)
                    self._tryssh_switch(devname, True)
                else:
                    self._tryssh_switch(devname, False)
            except Exception as exp:
                self._tryssh_switch(devname, False)
                raise exp
            return output

        if prompt2.startswith(sonic_mgmt_hostname):
            msg = "trying to change from sonic-mgmt({}) while executing {}"
            msg = msg.format(prompt, cmd)
            self.dut_log(devname, msg)
            try:
                prompt = self._exit_docker(devname, prompt)
                prompt2 = prompt.replace("\\", "")
            except:
                pass
            self._set_last_prompt(access, prompt)

        # we need to go to vtysh for below cases
        if prompt == self._get_param(devname, "normal-user-cli-prompt"):
            self.dut_log(devname, "trying to enter into vtysh({}) while executing {}".format(prompt, cmd))
            self._exec_mode_change(devname, "sudo vtysh\r\nterminal length 0", vtysh_prompt, prompt)
            self._set_last_prompt(access, vtysh_prompt)
            prompt2 = prompt = vtysh_prompt

        # vty shell commands
        if mode == "vtysh-user":
            if cmd == "end":
                output = self._exec(devname, cmd, vtysh_prompt)
                self._set_last_prompt(access, vtysh_prompt)
                return output
            if prompt2 == vtysh_prompt and cmd == "exit":
                try:
                    cli_prompt = self._get_param(devname, "normal-user-cli-prompt")
                    output = self._send_command(access, "exit", cli_prompt)
                    self._set_last_prompt(access, cli_prompt)
                except:
                    output = ""
                    self._set_last_prompt(access, None)
                return output

            if prompt == vtysh_prompt or prompt2 == vtysh_prompt:
                output = self._send_command(access, cmd, vtysh_prompt,
                                            skip_error_check, ufcli=ufcli)
                self._set_last_prompt(access, vtysh_prompt, "vtysh-user")
                return output
            if prompt.startswith(r"{}\(".format(hostname)):
                output = self._send_command(access, "do " + cmd,
                                            r"{}\(.*\)#".format(hostname),
                                            skip_error_check, ufcli=ufcli)
                print("see if this can be removed-1", prompt2, cmd, prompt, re.escape(prompt2))
                self._set_last_prompt(access, None)
                return output
            # import pdb; pdb.set_trace()
            print("unhandled - 1", cmd, hostname, prompt2)
            return ""

        # we need to go to vtysh config for below cases
        if prompt == vtysh_prompt or prompt2 == vtysh_prompt:
            self._exec(devname, "configure terminal", r"{}\(config\)#".format(hostname))
            prompt2 = prompt = vtysh_config_prompt
            self._set_last_prompt(access, prompt)

        # vty shell config commands
        if mode == "vtysh-config":
            if cmd == "end":
                output = self._exec(devname, cmd, vtysh_prompt)
                self._set_last_prompt(access, vtysh_prompt)
                return output
            if cmd == "exit":
                output = self._exec(devname, cmd, vtysh_maybe_config_prompt)
                self._set_last_prompt(access, None)
                return output
            if re.compile(r"{}\(.*\)#".format(hostname)).match(prompt2):
                output = self._send_command(access, cmd, r"{}\(.*\)#".format(hostname),
                                            skip_error_check, ufcli=ufcli)
                self._set_last_prompt(access, re.escape(prompt2), "vtysh-config")
                return output

            # import pdb; pdb.set_trace()
            print("unhandled - 2", cmd, hostname, prompt2)
            return ""

        # what should we do here
        # import pdb; pdb.set_trace()
        print("unhandled - 3", mode, cmd, prompt2)
        return ""

    def change_prompt(self, devname, tomode=None, **kwargs):
        return self._change_prompt(devname, tomode, None, **kwargs)

    def _change_prompt(self, devname, tomode=None, startmode=None, **kwargs):
        devname = self._check_devname(devname)
        access = self._get_dev_access(devname)
        prompts = access["prompts"]

        dbg = self.debug_find_prompt

        if access["filemode"]:
            self.dut_log(devname, tomode)
            return None

        # Identify the current prompt
        if startmode:
            prompt = prompts.get_prompt_for_mode(startmode)
        else:
            prompt = None

        # Identify the current mode
        if not prompt or prompt == "unknown-mode":
            for i in range(3):
                prompt = self._find_prompt(access)
                startmode = prompts.get_mode_for_prompt(prompt)
                if startmode != "unknown-prompt":
                    break

        if startmode == "unknown-prompt":
            msg = "Current prompt pattern not found in patterns dict."
            self.dut_log(devname, msg, lvl=logging.ERROR)
            return "unknown-prompt"

        # Return current mode when no prompt is given for change.
        if not tomode:
            msg = "Returning current mode {} as provided tomode is None.".format(startmode)
            self.dut_log(devname, msg, lvl=logging.DEBUG, cond=dbg)
            return startmode

        # Return invalid if given prompt is not present.
        if tomode not in prompts.patterns:
            msg = "Prompt pattern not found."
            self.dut_log(devname, msg, lvl=logging.ERROR)
            return "unknown-mode"

        # Check whether the arguments given for prompt change are valid or not?
        prompts.check_args_for_req_mode(tomode, **kwargs)

        # Check whether do we need to move previous level to come back to same prompt with different values.
        if startmode == "login_prompt":
            start_prompt = prompts.get_prompt_for_mode(startmode)
            msg = "DUT enterted into '{}({})'. Recovering to normal mode.".format(startmode, start_prompt)
            self.dut_log(devname, msg, lvl=logging.ERROR)
            self._enter_linux(devname)
            prompt = self._find_prompt(access)
            startmode = prompts.get_mode_for_prompt(prompt)
            if startmode == "unknown-prompt":
                return "unknown-prompt"
            self.set_login_timeout(devname)

        # Check whether do we need to move previous level to come back to same prompt with different values.
        if startmode == tomode:
            change_required = prompts.check_move_for_parent_of_frommode(prompt, startmode, **kwargs)
            if change_required:
                [cmd, expected_prompt] = prompts.get_backward_command_and_prompt(startmode)
                self._send_command(access, cmd, expected_prompt)
                startmode = prompts.modes[startmode][0]
            else:
                msg = "Returning as current mode is equal to required mode."
                self.dut_log(devname, msg, lvl=logging.DEBUG, cond=dbg)
                return tomode
        else:
            # Check whether do we need to go back to parent for both the modes.
            change_required = prompts.check_move_for_parent_of_tomode(prompt, tomode, **kwargs)
            if change_required:
                if startmode != prompts.modes[tomode][0]:
                    required_mode = prompts.modes[tomode][0]
                else:
                    required_mode = prompts.modes[startmode][0]
                while startmode != required_mode and prompts.modes[startmode][0] != "":
                    [cmd, expected_prompt] = prompts.get_backward_command_and_prompt(startmode)
                    self._send_command(access, cmd, expected_prompt)
                    startmode = prompts.modes[startmode][0]

        # Identify the list of backward and forward modes we need to move.
        modeslist_1 = []
        srcMode = startmode
        while srcMode != "":
            modeslist_1.append(srcMode)
            if srcMode in prompts.modes:
                srcMode = prompts.modes[srcMode][0]
                continue
            srcMode = ""

        modeslist_2 = []
        dstMode = tomode
        while dstMode != "":
            modeslist_2.insert(0, dstMode)
            if dstMode in prompts.modes:
                dstMode = prompts.modes[dstMode][0]
                continue
            dstMode = ""

        backward_modes = []
        forward_modes = copy.copy(modeslist_2)
        for mode in modeslist_1:
            if mode in forward_modes:
                forward_modes.remove(mode)
                continue
            backward_modes.append(mode)

        #self.dut_log(devname, "Modes_1: {}".format(modeslist_1))
        #self.dut_log(devname, "Modes_2: {}".format(modeslist_2))
        #self.dut_log(devname, "backward_modes: {}".format(backward_modes))
        #self.dut_log(devname, "forward_modes: {}".format(forward_modes))

        # Move back for each backward mode.
        for mode in backward_modes:
            [cmd, expected_prompt] = prompts.get_backward_command_and_prompt(mode)
            if cmd.strip() == "" or expected_prompt.strip() == "":
                continue
            msg = "Backward command to execute: {} ; Expected Prompt: {}".format(cmd, expected_prompt)
            #self.dut_log(devname, msg)
            self._send_command(access, cmd, expected_prompt)

        # Move ahead for each forward mode.
        # Get the command by substituting with required values from the given arguments.
        for mode in forward_modes:
            [cmd, expected_prompt] = prompts.get_forward_command_and_prompt_with_values(mode, **kwargs)
            if cmd.strip() == "" or expected_prompt.strip() == "":
                continue
            msg = "Forward command to execute: {} ; Expected Prompt: {}".format(cmd, expected_prompt)
            #self.dut_log(devname, msg)
            self._send_command(access, cmd, expected_prompt)

        # Identify the current prompt, check and return appropriately.
        for i in range(3):
            prompt = self._find_prompt(access)
            endmode = prompts.get_mode_for_prompt(prompt)
            if endmode != "unknown-prompt":
                break

        if endmode == tomode:
            msg = "Successfully changed the prompt from {} to {}.".format(startmode, endmode)
            self.dut_log(devname, msg, lvl=logging.DEBUG)
            return tomode
        return "unknown-mode"

    def cli_config(self, devname, cmd, mode=None, skip_error_check=False, delay_factor=0, **kwargs):
        devname = self._check_devname(devname)
        access = self._get_dev_access(devname)
        prompts = access["prompts"]

        if access["filemode"]:
            self.dut_log(devname, cmd)
            return ""

        frommode = self.change_prompt(devname, mode, **kwargs)
        if frommode not in ["unknown-mode", "unknown-prompt"]:
            if frommode in prompts.sudo_include_prompts:
                if not cmd.startswith("sudo "):
                    cmd = "sudo " + cmd
            expected_prompt = prompts.get_prompt_for_mode(frommode)
            output = self._send_command(access, cmd, expected_prompt, skip_error_check, delay_factor=delay_factor)
            return output
        msg = "Unable to change the prompt mode to {}.".format(mode)
        self.dut_log(devname, msg, lvl=logging.ERROR)
        raise ValueError(msg)

    def cli_show(self, devname, cmd, mode=None, skip_tmpl=False, skip_error_check=False, delay_factor=0, **kwargs):
        devname = self._check_devname(devname)
        access = self._get_dev_access(devname)
        prompts = access["prompts"]

        if access["filemode"]:
            self.dut_log(devname, cmd)
            return ""

        frommode = self.change_prompt(devname, mode, **kwargs)
        if frommode not in ["unknown-mode", "unknown-prompt"]:
            actual_cmd = cmd
            if not re.search(r"\| no-more$", cmd.strip()) and frommode.startswith("mgmt"):
                cmd = cmd + " | no-more"
            if frommode not in prompts.do_exclude_prompts:
                if not cmd.startswith("do "):
                    cmd = "do " + cmd
            expected_prompt = prompts.get_prompt_for_mode(frommode)
            output = self._send_command(access, cmd, expected_prompt, skip_error_check, delay_factor=delay_factor)
            if skip_tmpl:
                return output
            return self._tmpl_apply(devname, actual_cmd, output)
        msg = "Unable to change the prompt mode to {}.".format(mode)
        self.dut_log(devname, msg, lvl=logging.ERROR)
        raise ValueError(msg)

    def _check_devname(self, devname):
        if devname != "":
            # todo verify
            return devname
        for d in self.topo["duts"]:
            return d
        return None

    def _tmpl_apply(self, devname, cmd, output):
        try:
            parsed = self.tmpl[devname].apply(output, cmd)
            self.logger.debug(parsed)
            return parsed
        except Exception as e:
            self.logger.exception(e)
            return output

    def _textfsm_apply(self, devname, tmpl_file, output):
        return self.tmpl[devname].apply_textfsm(tmpl_file, output)

    def _fill_sample_data(self, devname, cmd, skip_error_check, output):
        if self.cfg.filemode and not output and self.use_sample_data:
            output = self.tmpl[devname].read_sample(cmd)
            self.dut_log(devname, output)
            access = self._get_dev_access(devname)
            output = self._check_error(access, cmd, output, skip_error_check)
        return output

    def clear_config(self, devname, method="reload"):
        """
        This API method executes the clear config on the device

        :param devname: name of the device under test (DUT)
        :type devname:
        :return:
        """
        largs = [method]
        if devname:
            return self._apply_remote(devname, "apply-base-config", largs)
        else:
            for dev_name in self.topo["duts"]:
                self._apply_remote(dev_name, "apply-base-config", largs)
            return True

    def config_db_reload(self, devname, save=False):
        """
        todo: Update Documentation
        :param dut:
        :type dut:
        :param save:
        :type save:
        :return:
        :rtype:
        """

        devname = self._check_devname(devname)
        access = self._get_dev_access(devname)

        save_cmd = 'sudo config save -y'
        reload_cmd = 'sudo config reload -y'

        if os.getenv("SPYTEST_HELPER_CONFIG_DB_RELOAD", "yes") != "no":
            largs = ["yes" if save else "no"]
            output = self._apply_remote(devname, "config-reload", largs)
            return output

        if access["filemode"]:
            if save:
                self.dut_log(devname, save_cmd)
            self.dut_log(devname, reload_cmd)
            return True

        # ensure we are in sonic mode
        self._enter_linux_exit_vtysh(devname)

        prompt = self._get_param(devname, "normal-user-cli-prompt")
        if save:
            self._send_command(access, save_cmd, prompt, False, 1)

        output = self._send_command(access, reload_cmd, prompt, True, 3)

        return output

    def apply_script(self, devname, cmdlist):
        devname = self._check_devname(devname)
        access = self._get_dev_access(devname)
        if access["filemode"]:
            for cmd in cmdlist:
                self.dut_log(devname, cmd)
            return

        vtysh_mode_flag = False
        vtysh_config_mode_flag = False

        hostname = "sonic"
        if "hostname" in access and access["hostname"]:
            hostname = access["hostname"]
        vtysh_prompt = "{}#".format(hostname)

        # ensure we are in sonic mode
        self._enter_linux_exit_vtysh(devname)

        for cmd in cmdlist:
            if not cmd.strip():
                #self.logger.warning("skipping empty line")
                continue

            if cmd == "vtysh" or cmd == "sudo vtysh":
                vtysh_mode_flag = True
                continue

            if cmd == "configure terminal" and vtysh_mode_flag:
                vtysh_config_mode_flag = True
                continue

            if vtysh_config_mode_flag:
                self.config_new(devname, cmd, type="vtysh", conf=True)
            elif vtysh_mode_flag:
                self.config_new(devname, cmd, type="vtysh", conf=False)
            else:
                self.config_new(devname, cmd)

            prompt = self._find_prompt(access)
            prompt2 = prompt.replace("\\", "")

            if prompt == self._get_param(devname, "normal-user-cli-prompt"):
                vtysh_mode_flag = False
                vtysh_config_mode_flag = False

            if prompt == vtysh_prompt or prompt2 == vtysh_prompt:
                vtysh_mode_flag = True
                vtysh_config_mode_flag = False

            if re.compile(r"{}\(.*\)#".format(hostname)).match(prompt2):
                vtysh_mode_flag = True
                vtysh_config_mode_flag = True

        # ensure we are in sonic mode after we exit
        self._exit_vtysh(devname)

    def apply_json(self, devname, data):
        """
        todo: Update Documentation
        :param devname:
        :type devname:
        :param data:
        :type data:
        :return:
        :rtype:
        """
        devname = self._check_devname(devname)
        try:
            obj = json.loads(data)
            indented = json.dumps(obj, indent=4)
        except:
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
            except:
                raise ValueError("invalid json data")

        # write json content into file
        for retry in range(3):
            src_file = tempfile.mktemp()
            src_fp = open(src_file, "w")
            src_fp.write(indented)
            src_fp.close()
            if os.path.exists(src_file) and os.path.getsize(src_file) != 0:
                msg = "Created a tmp file {}. Size of the file {} ..".format(src_file, os.path.getsize(src_file))
                self.dut_log(devname, msg, lvl=logging.WARNING)
                break
            else:
                msg = "Failed to create a tmp file {}.. Retrying again..".format(src_file)
                self.dut_log(devname, msg, lvl=logging.WARNING)

        applied = False
        for retry in range(3):
            # transfer the file
            access = self._get_dev_access(devname)
            dst_file = self._upload_file(access, src_file)

            # issue config load
            if access["filemode"]:
                applied = True
                break

            # ensure we are in sonic mode
            self._enter_linux_exit_vtysh(devname)

            check_file_cmd = "ls -lrt {}".format(dst_file)
            output = self.config_new(devname, check_file_cmd, skip_error_check=True)

            # execute the command.
            config_cmd = "config load -y {}".format(dst_file)
            output = self.config_new(devname, config_cmd, skip_error_check=True)
            if 'Path "{}" does not exist.'.format(dst_file) not in output:
                applied = True
                break
            msg = "Failed to find the transfered destination file retry again in 3 sec"
            self.dut_log(devname, msg, lvl=logging.WARNING)
            time.sleep(3)

        # remove temp file
        os.remove(src_file)

        # try apply_json2 as last resort
        if not applied:
            msg = "Failed to find the transfered destination file even after retries - try using echo"
            self.dut_log(devname, msg, lvl=logging.WARNING)
            self.apply_json2(devname, data)

    def apply_json2(self, devname, data):
        access = self._get_dev_access(devname)
        if not access["filemode"]:
            dst_file = "/tmp/apply_json2.json"
            self._save_json_to_remote_file(devname, data, dst_file)
            config_cmd = "config load -y {}".format(dst_file)
            self.config_new(devname, config_cmd)

    def recover_from_onie(self, devname, install):
        devname = self._check_devname(devname)
        access = self._get_dev_access(devname)
        self._send_command(access, "onie-discovery-stop")
        self._send_command(access, "onie-stop")

        if install and self.cfg.skip_load_image:
            msg = "Skip install from ONIE"
            self.dut_log(devname, msg, lvl=logging.WARNING)
            return False

        if not install:
            try:
                msg = "Trying to recover from ONIE with reboot"
                self.dut_log(devname, msg, lvl=logging.WARNING)
                expect = "|".join([regex_login, regex_onie, regex_onie_sleep])
                self._send_command(access, "reboot", expect, True, 3)
                if self.wait_onie_or_login(devname) == 2:
                    # reboot took the device into login prompt
                    return True
                msg = "Failed to take device into login - try loading image"
                self.dut_log(devname, msg, lvl=logging.ERROR)
                # pass through installation
            except:
                msg = "Failed to recover from ONIE with reboot"
                self.dut_log(devname, msg, lvl=logging.ERROR)
                os._exit(15)
                return False

        # installing
        if self.cfg.build_url:
            onie_image = self.cfg.build_url
        else:
            onie_image = access["onie_image"]
        if not onie_image:
            msg = "No image is specified to load from ONIE"
            self.dut_log(devname, msg, lvl=logging.ERROR)
            return False
        if not self.onie_nos_install(devname, onie_image):
            if os.getenv("SPYTEST_RECOVERY_MECHANISMS", "0") != "0":
                expect = "|".join([regex_login, regex_onie, regex_onie_sleep])
                msg = "Trying to recover from ONIE with reboot as it failed to download the image"
                self.dut_log(devname, msg, lvl=logging.WARNING)
                self._send_command(access, "reboot", expect, True, 3)
                if self.wait_onie_or_login(devname) == 1:
                    if not self.onie_nos_install(devname, onie_image):
                        return False
                else:
                    return False
            else:
                return False
        if not self.wa.session_init_completed:
            self.image_install_status[devname] = True
        return True

    def onie_nos_install(self, devname, url):
        devname = self._check_devname(devname)
        access = self._get_dev_access(devname)

        cmd = "onie-nos-install {}".format(url)
        self.dut_log(devname, "trying {}".format(cmd))
        self.trace_callback_set(devname, True)
        expect = "|".join([regex_login, regex_onie])
        self._send_command(access, cmd, expect, True, 18)
        self.trace_callback_set(devname, False)

        ptype = self.wait_onie_or_login(devname)
        if ptype == 1:
            msg = "Device Onie Install Failed"
            self.dut_log(devname, msg, lvl=logging.WARNING)
            return False
        elif ptype == 2:
            msg = "Device Onie Install Completed"
            self.dut_log(devname, msg)
            self.init_normal_prompt(devname)
            return True

        msg = "Failed to get login prompt after ONIE upgrade"
        self.dut_log(devname, msg, lvl=logging.ERROR)
        return False

    def wait_onie_or_login(self, devname):
        devname = self._check_devname(devname)
        access = self._get_dev_access(devname)
        for attempt in range(10):
            prompt = self._find_prompt(access)
            prompt2 = prompt.replace("\\", "")
            if re.compile(regex_onie).match(prompt2):
                if attempt == 0:
                    # try again as ONIE some times just throws the prompt
                    time.sleep(5)
                    continue
                return 1
            if re.compile(regex_login).match(prompt2):
                self._enter_linux(devname, prompt)
                return 2
            msg = "Unexpected Prompt {}".format(prompt2)
            self.dut_log(devname, msg, lvl=logging.WARNING)
            self.wait(1)
        return 0

    def upgrade_onie_image1(self, devname, url, max_ready_wait=0):
        devname = self._check_devname(devname)
        access = self._get_dev_access(devname)

        if not self.wa.session_init_completed:
            if devname in self.image_install_status and self.image_install_status[devname]:
                self.dut_log(devname, "Image already upgraded during the time of DUT connect using ONIE process.")
                return True

        upgrade_image_cmd = ";".join("""
        sudo apt-get -f install -y grub-common
        sudo mkdir -p /mnt/onie-boot/
        sudo mount /dev/sda2 /mnt/onie-boot/
        sudo /mnt/onie-boot/onie/tools/bin/onie-boot-mode -o rescue
        sudo grub-editenv /mnt/onie-boot/grub/grubenv set diag_mode=none
        sudo grub-editenv /mnt/onie-boot/grub/grubenv set onie_mode=rescue
        sudo grub-editenv /host/grub/grubenv set next_entry=ONIE
        sudo grub-reboot --boot-directory=/host/ ONIE
        sudo umount /mnt/onie-boot/
        """.strip().splitlines())

        self.dut_log(devname, "Upgrading image from onie '{}'.".format(url))

        if access["filemode"]:
            return

        # ensure we are in sonic mode
        self._enter_linux_exit_vtysh(devname)

        # Issue sonic installer command.
        skip_error_check = False if self.wa.session_init_completed else True
        self.trace_callback_set(devname, True)
        cli_prompt = self._get_param(devname, "normal-user-cli-prompt")
        self._send_command(access, upgrade_image_cmd, cli_prompt, skip_error_check, 18)
        self.trace_callback_set(devname, False)

        # we need to download the helper files again
        self.skip_trans_helper[devname] = dict()

        # Issue reboot command and look for ONIE rescue mode.
        if not self.reboot(devname, onie=True):
            msg = "Reboot failed as unable to get the onie rescue mode."
            self.dut_log(devname, msg, False, logging.ERROR)
            raise ValueError(msg)

        self._send_command(access, "\r\n", regex_onie)
        if not self.onie_nos_install(devname, url):
            msg = "Image download failed using onie-nos-install."
            self.dut_log(devname, msg, False, logging.ERROR)
            raise ValueError(msg)

        self.dut_log(devname, "reading version after upgrade")
        self.show_new(devname, "show version", skip_tmpl=True, skip_error_check=True)
        self.do_post_reboot(devname, max_ready_wait=max_ready_wait, phase=1)
        return True

    def upgrade_onie_image2(self, devname, url, max_ready_wait=0):
        devname = self._check_devname(devname)
        access = self._get_dev_access(devname)

        if not self.wa.session_init_completed:
            if devname in self.image_install_status and self.image_install_status[devname]:
                self.dut_log(devname, "Image already upgraded during the time of DUT connect using ONIE process.")
                return True

        self.dut_log(devname, "Upgrading image from '{}'.".format(url))
        dut_image_location = "/host/onie-installer-x86_64"

        if access["filemode"]:
            return

        # ensure we are in sonic mode
        self._enter_linux_exit_vtysh(devname)

        # Download the image from url to /host/onie-installer-x86_64 location.
        download_image_cmd = "sudo curl --retry 15 -o {} {}".format(dut_image_location, url)

        # Issue the download_image_cmd command.
        for count in range(3):
            skip_error_check = False if self.wa.session_init_completed else True
            self.trace_callback_set(devname, True)
            cli_prompt = self._get_param(devname, "normal-user-cli-prompt")
            self.dut_log(devname, "Trying image download using curl command, iteration {}".format(count+1))
            output = self._send_command(access, download_image_cmd, cli_prompt,
                                        skip_error_check, delay_factor=18,
                                        trace_dut_log=1)
            self.trace_callback_set(devname, False)

            if re.search(r"curl:\s+\(\d+\)", output):
                errorline = [m for m in output.split("\n") if re.search(r"curl:\s+\(\d+\)", m)]
                errorline = str("".join(errorline))
                msg = "Image download to host location failed using curl command. Error: '{}'"
                msg = msg.format(errorline)
                self.dut_log(devname, msg, False, logging.ERROR)
                if count >=2:
                    raise ValueError(msg)
                continue

            # Check for the downloaded file type.
            filetype_cmd = "file {}".format(dut_image_location)
            file_output = self._send_command(access, filetype_cmd, cli_prompt,
                                        skip_error_check, delay_factor=1)
            if not re.search(r"binary\s+data", file_output):
                errorline = file_output.split("\n")[0]
                msg = "Image downloaded to host location is not a proper image type. File type: '{}'"
                msg = msg.format(errorline)
                self.dut_log(devname, msg, False, logging.ERROR)
                raise ValueError(msg)

            self.dut_log(devname, "Image downloaded to host location successfully.")
            break

        # Grub commands for image download.
        upgrade_image_cmd = ";".join("""
        sudo apt-get -f install -y grub-common
        sudo mkdir -p /mnt/onie-boot/
        sudo mount /dev/sda2 /mnt/onie-boot/
        sudo /mnt/onie-boot/onie/tools/bin/onie-boot-mode -o install
        sudo grub-editenv /mnt/onie-boot/grub/grubenv set diag_mode=none
        sudo grub-editenv /mnt/onie-boot/grub/grubenv set onie_mode=install
        sudo grub-editenv /host/grub/grubenv set next_entry=ONIE
        sudo grub-reboot --boot-directory=/host/ ONIE
        sudo umount /mnt/onie-boot/
        """.strip().splitlines())

        # Issue the grub commands.
        skip_error_check = False if self.wa.session_init_completed else True
        self.trace_callback_set(devname, True)
        cli_prompt = self._get_param(devname, "normal-user-cli-prompt")
        output = self._send_command(access, upgrade_image_cmd, cli_prompt,
                                    skip_error_check, 18)
        self.trace_callback_set(devname, False)

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
            self.dut_log(devname, msg, False, logging.ERROR)
            raise ValueError(msg)

        self.dut_log(devname, "reading version after upgrade")
        self.show_new(devname, "show version", skip_tmpl=True, skip_error_check=True)
        self.do_post_reboot(devname, max_ready_wait=max_ready_wait, phase=1)
        return True

    def upgrade_image(self, devname, url, skip_reboot=False, migartion=True, max_ready_wait=0):
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
        access = self._get_dev_access(devname)

        if not self.wa.session_init_completed:
            if devname in self.image_install_status and self.image_install_status[devname]:
                self.dut_log(devname, "Image already upgraded during the time of DUT connect using ONIE process.")
                return True

        if migartion:
            upgrade_image_cmd = "sudo sonic_installer install {} -y".format(url)
        else:
            upgrade_image_cmd = "sudo sonic_installer install --skip_migration {} -y".format(url)
        self.dut_log(devname, "Upgrading image from '{}'.".format(url))

        if access["filemode"]:
            return

        # ensure we are in sonic mode
        self._enter_linux_exit_vtysh(devname)

        # Issue sonic installer command.
        skip_error_check = False if self.wa.session_init_completed else True
        self.trace_callback_set(devname, True)
        cli_prompt = self._get_param(devname, "normal-user-cli-prompt")
        output = self._send_command(access, upgrade_image_cmd, cli_prompt,
                                    skip_error_check, 18)
        self.trace_callback_set(devname, False)

        if re.search("Installed SONiC base image SONiC-OS successfully", output):
            prompt = self._find_prompt(access)
            if prompt == self._get_param(devname, "normal-user-cli-prompt"):
                if skip_reboot:
                    msg = "Image upgraded successfully."
                    self.dut_log(devname, msg)
                elif self.reboot(devname, max_ready_wait=max_ready_wait):
                    self._enter_linux(devname, prompt)
                    msg = "Image upgraded and rebooted successfully."
                    self.dut_log(devname, msg)
                else:
                    msg = "Reboot failed after the image download."
                    self.dut_log(devname, msg, False, logging.ERROR)
                    raise ValueError(msg)
        elif re.search("Not installing SONiC version", output) and \
                re.search("as current running SONiC has the same version", output):
            msg = "No need to upgrade as the image is already of same version."
            self.dut_log(devname, msg)
        else:
            msg = "Image not loaded on to the device using URL: {}".format(url)
            self.dut_log(devname, msg, False, logging.ERROR)
            raise ValueError(msg)
        return True

    def recover(self, devname, msg):
        self.dut_log(devname, msg)
        if self.reboot(devname):
            self._enter_linux(devname)
            self.dut_log(devname, "{} - Successful".format(msg))
        else:
            self.logger.error("{} - Failed".format(msg))
            raise ValueError(msg)

    def reboot(self, devname, method="normal", skip_port_wait=False,
               onie=False, skip_exception=False, skip_fallback=False,
               max_ready_wait=0):

        try:
            self._tryssh_switch(devname)
            rv = self._reboot(devname, method, skip_port_wait, onie,
                              skip_exception, skip_fallback, max_ready_wait)
            self._tryssh_switch(devname, True)
        except Exception as e:
            msg = utils.stack_trace(traceback.format_exc())
            self.dut_log(devname, msg, lvl=logging.WARNING)
            self._tryssh_switch(devname, False)
            if not skip_exception:
                raise e
            rv = False

        return rv

    def _reboot(self, devname, method="normal", skip_port_wait=False,
                onie=False, skip_exception=False, skip_fallback=False,
                max_ready_wait=0):

        devname = self._check_devname(devname)
        access = self._get_dev_access(devname)

        flag_fast_warm_reboot = 0
        if method in ["normal", "reboot"]:
            reboot_cmd = "sudo reboot"
        elif method in ["fast", "fast-reboot"]:
            reboot_cmd = "sudo fast-reboot"
            flag_fast_warm_reboot = 1
        elif method in ["warm", "warm-reboot"]:
            reboot_cmd = "sudo warm-reboot"
            flag_fast_warm_reboot = 1
        else:
            reboot_cmd = "sudo reboot"

        if access["filemode"]:
            self.dut_log(devname, "Reboot command '{}'.".format(reboot_cmd))
            return True

        # ensure we are in sonic mode
        self._enter_linux_exit_vtysh(devname)

        # just incase if we are in SSH mode
        self._switch_connection(devname, 0)
        # just incase if we are in SSH mode

        user_mode = self._get_param(devname, "normal-user-cli-prompt")

        # check if the reboot needs confirmation and handle accordingly
        output = self._send_command(access, "fast-reboot -h", user_mode,
                                    skip_error_check=True)
        if "skip the user confirmation" in output:
            reboot_cmd = "{} -y".format(reboot_cmd)

        # negative test for API
        if method in ["fast-reboot-fail"]:
            flag_fast_warm_reboot = 1
            reboot_cmd = "echo sudo fast-reboot"

        # Issue reboot command.
        self.wa.instrument(devname, "pre-reboot")
        self.trace_callback_set(devname, True)
        if not self._is_console_connection(devname):
            reboot_static_wait = 120
            if onie:
                reboot_static_wait = 600
            ssh_patterns = r"(systemctl daemon-reload|requested COLD shutdown|[#|\$]\s*$)"
            output = self._send_command(access, reboot_cmd, ssh_patterns, True, 1)
            msg = "Waiting for '{}' secs after reboot on SSH.".format(reboot_static_wait)
            self.dut_log(devname, msg, False)
            self.wait(reboot_static_wait)
            if not onie:
                reboot_polling_time = 120
                time_left = reboot_polling_time
                dut_mgmt_ip = str(access["connection_param"]["ip"])
                while time_left > 0:
                    retval = utils.ipcheck(dut_mgmt_ip)
                    msg = "Pinging IP : '{}' : {}".format(dut_mgmt_ip, retval)
                    self.dut_log(devname, msg, False)
                    if retval:
                        break
                    time_left = time_left - 2
                if time_left == 0:
                    msg = "Dut IP '{}' is not reachable even after pinging for '{}' secs after reboot on SSH"
                    msg = msg.format(dut_mgmt_ip, reboot_polling_time)
                    self.dut_log(devname, msg, False, logging.ERROR)
                    return False
            self._disconnect_device(devname)
            wait_after_ping = 30
            msg = "Waiting for '{}' secs before attempting connection via SSH.".format(wait_after_ping)
            self.dut_log(devname, msg, False)
            self.wait(wait_after_ping)
            retry_count = 0
            while retry_count < 10:
                retval = self.connect_to_device(devname)
                msg = "Connection attempt : '{}', Status: '{}'".format(retry_count, retval)
                self.dut_log(devname, msg, False)
                if retval:
                    break
                retry_count = retry_count + 1
                self.wait(10)
        elif onie:
            output = self._send_command(access, reboot_cmd, regex_onie_resque, True, 6)
            return True
        else:
            expect = "|".join([user_mode, regex_login, regex_login_anywhere])
            output = self._send_command(access, reboot_cmd, expect, True, 6)
        self.trace_callback_set(devname, False)

        reboot_status = False
        result_set = ["DUTFail", "reboot_failed"]
        try_count = 3
        while try_count > 0:
            prompt = self._find_prompt(access)
            prompt2 = prompt.replace("\\", "")
            if re.compile(regex_login).match(prompt2):
                msg = "Device Reboot ({}) Completed.".format(reboot_cmd)
                self.dut_log(devname, msg)
                self.wait(5) # wait for any kernel messages to show up
                self._enter_linux(devname, prompt)
                self.do_post_reboot(devname, max_ready_wait=max_ready_wait)
                reboot_status = True
                break

            if re.compile(regex_login_anywhere).match(prompt2):
                msg = "Device Reboot ({}) May Be Completed - confirming".format(reboot_cmd)
                self.dut_log(devname, msg)
                continue

            if prompt == user_mode:
                if not self._is_console_connection(devname):
                    msg = "Device Reboot ({}) Completed..".format(reboot_cmd)
                    self.dut_log(devname, msg)
                    self.do_post_reboot(devname, max_ready_wait=max_ready_wait)
                    reboot_status = True
                    break
                msg = "Device Reboot ({}) Failed.".format(reboot_cmd)
                self.dut_log(devname, msg, False, logging.ERROR)
                if flag_fast_warm_reboot and not skip_fallback:
                    msg = "Performing normal Reboot as ({}) failed.".format(reboot_cmd)
                    self.dut_log(devname, msg)
                    self.reboot(devname, skip_exception=True)
                    result_set = ["DUTFail", "fast_or_warm_reboot_failed"]
                    break
                if not skip_exception:
                    raise ValueError(msg)

            msg = "Prompt '{}' is neither login nor usermode."
            msg = msg.format(prompt)
            self.dut_log(devname, msg, False, logging.ERROR)
            try_count = try_count - 1

        if not reboot_status:
            self._report_error(result_set, reboot_cmd)
        elif self.cfg.reboot_wait:
            msg = "Waiting for '{}' secs after reboot.".format(self.cfg.reboot_wait)
            self.dut_log(devname, msg, False)
            self.wait(self.cfg.reboot_wait)

        return reboot_status

    def wait_system_reboot(self, devname):
        devname = self._check_devname(devname)
        access = self._get_dev_access(devname)
        self._send_command(access, "\n", regex_login, True, 6)
        try_count = 3
        while try_count > 0:
            prompt = self._find_prompt(access)
            prompt2 = prompt.replace("\\", "")
            if re.compile(regex_login).match(prompt2):
                msg = "Device Reboot Completed."
                self.dut_log(devname, msg)
                self._enter_linux(devname, prompt)
                self.do_post_reboot(devname)
                return True
            try_count = try_count - 1

        return False

    def _transfer_base64(self, access, src_file, dst_file):
        devname = access["devname"]
        prompt = self._get_param(devname, "normal-user-cli-prompt")
        script_cmd = "rm -f {}.tmp {}".format(dst_file, dst_file)
        self._exec(devname, script_cmd, prompt)
        redir = ">"
        lines = utils.b64encode(src_file)
        (count, split) = (len(lines), self.max_cmds_once)
        for i in range(0, count, split):
            script_cmds = []
            for j in range(i, i+split):
                if j >= count:
                    break
                script_cmds.append(lines[j])
            if script_cmds:
                line = "".join(script_cmds)
                script_cmd = "echo {} {} {}.tmp".format(line, redir, dst_file)
                self._send_command(access, script_cmd, prompt, True)
                redir = ">>"
        script_cmd = "base64 -d {}.tmp > {}".format(dst_file, dst_file)
        self._exec(devname, script_cmd, prompt)

    def _transfer_base64_small(self, access, src_file, dst_file):
        script_cmds = []
        script_cmd = "rm -f {}.tmp {}".format(dst_file, dst_file)
        script_cmds.append(script_cmd)
        redir = ">"
        lines = utils.b64encode(src_file)
        for line in lines:
            script_cmd = "echo {} {} {}.tmp".format(line, redir, dst_file)
            script_cmds.append(script_cmd)
            redir = ">>"
        script_cmd = "base64 -d {}.tmp > {}".format(dst_file, dst_file)
        script_cmds.append(script_cmd)

        script_cmd = ";".join(script_cmds)
        devname = access["devname"]
        cli_prompt = self._get_param(devname, "normal-user-cli-prompt")
        self._exec(devname, script_cmd, cli_prompt)

    def _save_json_to_remote_file(self, devname, data, dst_file):
        devname = self._check_devname(devname)
        do_indent = False
        try:
            if do_indent:
                obj = json.loads(data)
                indented = json.dumps(obj, indent=4)
            else:
                indented = data
        except:
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
            except:
                raise ValueError("invalid json data")

        access = self._get_dev_access(devname)
        if not access["filemode"]:
            # ensure we are in sonic mode
            self._enter_linux_exit_vtysh(devname)
            # echo data to remote file
            self._echo_text_to_file(access, indented, dst_file)

    def _echo_text_to_file(self, access, content, dst_file, prefix=""):
        str_list = content.split("\n")
        if prefix:
            str_list.insert(0, prefix)
        return self._echo_list_to_file(access, str_list, dst_file)

    def _echo_list_to_file(self, access, str_list, dst_file, split=None):
        l_split = self.max_cmds_once if not split else split
        devname = access["devname"]
        msg = "Creating: DST: {}".format(dst_file)
        self.dut_log(devname, msg)
        redir = ">"
        for clist in utils.split_list(str_list, l_split):
            content = "\n".join(clist)
            script_cmd = "printf '{}\n' {} {}\n".format(content, redir, dst_file)
            cli_prompt = self._get_param(devname, "normal-user-cli-prompt")
            self._exec(devname, script_cmd, cli_prompt, ufcli=False, trace_dut_log=1)
            redir = ">>"

        return dst_file

    def _upload_file(self, access, src_file, dst_file=None):
        if not dst_file:
            dst_file = "/tmp/{}".format(os.path.basename(src_file))
        msg = "Transfer: SRC: {} DST: {}".format(src_file, dst_file)
        devname = access["devname"]
        self.dut_log(devname, msg)
        if access["filemode"]:
            return dst_file
        if self.force_console_transfer:
            self._transfer_base64(access, src_file, dst_file)
            return dst_file
        try:
            connection_param = access["connection_param"]
            msg = "Doing SFTP transfer {}".format(connection_param["mgmt-ip"])
            self.dut_log(devname, msg)
            self._fetch_mgmt_ip(devname)
            DeviceFileUpload(self._get_handle(devname), src_file,
                             dst_file, connection_param)
        except Exception as e:
            print(e)
            self.dut_log(devname, "SFTP Failed - Doing Console transfer")
            self._transfer_base64(access, src_file, dst_file)
        return dst_file

    def _upload_file2(self, devname, access, src_file, md5check=False):
        remote_dir = "/etc/spytest"

        if devname not in self.skip_trans_helper:
            self.skip_trans_helper[devname] = dict()

        if src_file not in self.skip_trans_helper[devname]:
            prompt = self._get_param(devname, "normal-user-cli-prompt")
            src_file2 = "%s/%s" % (os.path.basename(os.path.dirname(src_file)),
                                   os.path.basename(src_file))
            remote_file = os.path.join(remote_dir, src_file2)
            skip_transfer = False
            if md5check:
                script_cmd = "sudo md5sum {}".format(remote_file)
                output = self._send_command(access, script_cmd, prompt, False)
                try:
                    md5sum2 = output.split("\n")[0].strip()
                    if utils.md5(src_file) == md5sum2.split(" ")[0].strip():
                        skip_transfer = True
                except:
                    pass
            if not skip_transfer:
                dst_file = self._upload_file(access, src_file)
                script_cmd = "sudo mkdir -p {} && sudo cp -f {} {}".format(
                    os.path.dirname(remote_file), dst_file, remote_file)
                output = self._send_command(access, script_cmd, prompt, False, 6)
            self.skip_trans_helper[devname][src_file] = remote_file

        return self.skip_trans_helper[devname][src_file]

    def _upload_file3(self, access, src_file, dst_file):
        remote_dir = os.path.dirname(dst_file)

        tmp_file = self._upload_file(access, src_file)
        if remote_dir:
            script_cmd = "sudo mkdir -p {} && sudo cp -f {} {}".format(
                remote_dir, tmp_file, dst_file)
            devname = access["devname"]
            cli_prompt = self._get_param(devname, "normal-user-cli-prompt")
            self._send_command(access, script_cmd, cli_prompt, False, 6)

    def _download_file(self, access, src_file, dst_file):
        devname = access["devname"]
        msg = "Download: SRC: {} DST: {}".format(src_file, dst_file)
        self.dut_log(devname, msg)
        if not access["filemode"]:
            connection_param = access["connection_param"]
            try:
                msg = "Doing SFTP download {}".format(
                    connection_param["mgmt-ip"])
                self.dut_log(devname, msg)
                DeviceFileDownload(self._get_handle(devname), src_file,
                                   dst_file, connection_param)
            except Exception as e:
                try:
                    self.dut_log(devname, "SFTP Failed - Doing transfer using filedata on console")
                    cmd = "file {}".format(src_file)
                    output = self.show_new(devname, cmd, skip_tmpl=True, skip_error_check=True)
                    if "ASCII" in output:
                        cmd = "cat {}".format(src_file)
                        output = self.show_new(devname, cmd, skip_tmpl=True, skip_error_check=True)
                        content =output[:output.rfind('\n')]
                        dst_fp = open(dst_file, "w")
                        dst_fp.write(content)
                        dst_fp.close()
                    else:
                        if "No such file or directory" in output:
                            self.dut_log(devname, "File {} not found".format(src_file))
                        else :
                            self.dut_log(devname, "Only text based files can be transferred using console")
                        self.logger.info(e)
                        return "FAIL"
                except Exception as e1:
                    self.logger.info(e1)
                    return "FAIL"
        return "SUCCESS"

    def add_pending_download(self, devname, remote_file_path, local_file_path):
        if devname not in self.pending_downloads:
            self.pending_downloads[devname] = []
        self.pending_downloads[devname].append([remote_file_path, local_file_path])

    def check_pending_downloads(self, devname):
        # TODO: download the pending files
        self.pending_downloads[devname] = []

    def _add_port_wait(self, args_str, wait, poll, is_community):
        args_str = args_str + " --port-init-wait {}".format(wait)
        if poll:
            args_str = args_str + " --poll-for-ports yes"
        else:
            args_str = args_str + " --poll-for-ports no"
        if is_community:
            args_str = args_str + " --community-build"
        return args_str

    def _add_core_dump_flags(self, args_str, value_list):
        core_flag = value_list.pop(0)
        dump_flag = value_list.pop(0)
        if core_flag != "none":
            core_flag = "YES"
        else:
            core_flag = "NO"
        if dump_flag != "none":
            dump_flag = "YES"
        else:
            dump_flag = "NO"
        if value_list:
            clear_flag = value_list.pop(0)
        else:
            clear_flag = False
        if clear_flag:
            clear_flag = "YES"
        else:
            clear_flag = "NO"
        args_str = ",".join([core_flag, dump_flag, clear_flag])
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
        if not retval and self.cfg.native_port_breakout:
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

    def make_local_file_path(self, devname, filepath, suffix, ts=None):
        access = self._get_dev_access(devname)
        dut_label = self._get_dut_label(devname)
        if ts is None: ts = time.strftime("%Y%m%d%H%M")
        if filepath:
            name = filepath.replace(".py", "").replace("/", "_")
            file_name = "{0}_{1}_{2}_{3}".format(ts, dut_label, name, suffix)
        else:
            file_name = "{0}_{1}_{2}".format(ts, dut_label, suffix)
        return str(os.path.join(self.logger.logdir, file_name))

    def _apply_remote(self, devname, option_type, value_list=[]):
        devname = self._check_devname(devname)
        access = self._get_dev_access(devname)

        # ensure we are in sonic mode
        self._enter_linux_exit_vtysh(devname)

        if option_type == "port-defaults" and value_list[0]:
            helper = os.path.join(os.path.dirname(__file__),
                              "remote", "port_breakout.py")
            helper = os.path.abspath(helper)
            helper = self._upload_file2(devname, access, helper, md5check=True)

        if option_type == "dump-click-cmds":
            helper = os.path.join(os.path.dirname(__file__),
                              "remote", "click-helper.py")
            helper = os.path.abspath(helper)
            helper = self._upload_file2(devname, access, helper, md5check=True)

        # transfer the python file, which is used to apply the files remotely.
        helper = os.path.join(os.path.dirname(__file__),
                              "remote", "spytest-helper.py")
        helper = os.path.abspath(helper)
        helper = self._upload_file2(devname, access, helper, md5check=True)

        args_str = ""
        script_cmd = None
        skip_error_check = False
        execute_in_console = False
        delay_factor = 6

        # Depending on the option value, do the pre tasks.
        if option_type == "apply-configs":
            # transfer the cfg files
            dst_file_list = []
            method = value_list.pop(0)
            for name in value_list:
                for src_file in utils.make_list(name):
                    dst_file = self._upload_file2(devname, access, src_file)
                    dst_file_list.append(dst_file)
            args_str = '"' + '" "'.join(dst_file_list) + '"'
            args_str = args_str + " --apply-file-method " + method
            self.dut_log(devname, "Applying config files remotely '{}'".format(args_str))
            skip_error_check = True
        elif option_type == "run-test":
            timeout = value_list.pop(0)
            args_str = " ".join(value_list)
            delay_factor = int(math.ceil((timeout * 1.0) / 100))
        elif option_type == "init-ta-config":
            profile_name = value_list.pop(-1).lower()
            args_str = self._add_core_dump_flags(args_str, value_list)
            args_str = args_str + " --config-profile {}".format(profile_name)
            if os.getenv("SPYTEST_NTP_CONFIG_INIT", "0") != "0":
                args_str = args_str + " --env SPYTEST_NTP_CONFIG_INIT 1"
            if os.getenv("SPYTEST_CLEAR_MGMT_INTERFACE", "0") != "0":
                args_str = args_str + " --env SPYTEST_CLEAR_MGMT_INTERFACE 1"
            if os.getenv("SPYTEST_CLEAR_DEVICE_METADATA_HOSTNAME", "0") != "0":
                args_str = args_str + " --env SPYTEST_CLEAR_DEVICE_METADATA_HOSTNAME 1"
        elif option_type in ["save-base-config", "save-module-config"]:
            # no arguments are required to create ta config
            args_str = ""
        elif option_type in ["apply-base-config", "apply-module-config"]:
            execute_in_console = True
            apply_ta_config_method = value_list[0]
            args_str = " {}".format(apply_ta_config_method)
            skip_error_check = True
        elif option_type == "disable-debug":
            # no arguments are required to disabling debug messages on to console
            args_str = ""
        elif option_type == "enable-debug":
            # no arguments are required to enabling debug messages on to console
            args_str = ""
        elif option_type == "syslog-check":
            args_str = value_list[0]
            args_str = args_str + " --phase '{} {}'".format(value_list[1], value_list[2])
            skip_error_check = True
            delay_factor = 3
        elif option_type == "sairedis":
            args_str = value_list[0]
            skip_error_check = True
            delay_factor = 3
        elif option_type == "set-mgmt-ip":
            args_str = " {} ".format(value_list[0])
            args_str = args_str + " --ip-addr-mask {}".format(value_list[1])
            args_str = args_str + " --gw-addr {}".format(value_list[2])
        elif option_type == "fetch-core-files":
            if self.kdump_supported:
                args_str = "collect_kdump"
            else:
                args_str = "none"
            skip_error_check = True
            delay_factor = 12
        elif option_type == "get-tech-support":
            # no arguments are required to fetching tech support data from dut to logs dir
            args_str = ""
            skip_error_check = True
            delay_factor = 12
        elif option_type == "init-clean":
            args_str = self._add_core_dump_flags(args_str, value_list)
        elif option_type == "update-reserved-ports":
            port_list = value_list.pop(0)
            args_str = ' '.join(port_list)
        elif option_type == "port-defaults":
            execute_in_console = True
            args_str = ""
            if value_list[0]:
                args_str = args_str + " --breakout {}".format(' '.join(value_list[0]))
                args_str = args_str + self._port_breakout_options(devname)
            if value_list[1]:
                args_str = args_str + " --speed {}".format(' '.join(map(str,value_list[1])))
            skip_error_check = True
        elif option_type == "config-reload":
            execute_in_console = True
            args_str = value_list[0]
        elif option_type == "wait-for-ports":
            args_str = self._add_port_wait(args_str, value_list[0], value_list[1], value_list[2])
        elif option_type == "config-profile":
            args_str = value_list.pop(0).lower()
            execute_in_console = bool(args_str != "na")
        elif option_type == "dump-click-cmds":
            pass
        else:
            msg = "Unknown option {} for remote operation".format(option_type)
            self.dut_log(devname, msg, lvl=logging.ERROR)
            raise ValueError(msg)

        # Construct the command that need to be executed on the DUT.
        if self.cfg.community_build and "--community-build" not in args_str:
            args_str = args_str + " --community-build"
        if self.cfg.load_config_method == "replace": args_str = args_str + " --use-config-replace"
        script_cmd = "sudo python {} --{} {}  ".format(helper, option_type, args_str)
        #self.dut_log(devname, "Using command: {}".format(script_cmd))

        try:
            if execute_in_console:
                self._tryssh_switch(devname)
            self.trace_callback_set(devname, True)
            cli_prompt = self._get_param(devname, "normal-user-cli-prompt")
            output = self._send_command(access, script_cmd, cli_prompt,
                                        skip_error_check, delay_factor,
                                        trace_dut_log=1)
            self.trace_callback_set(devname, False)
            self.dut_log(devname, output)
            if execute_in_console:
                self._tryssh_switch(devname, True)
        except Exception as exp:
            msg = utils.stack_trace(traceback.format_exc())
            self.dut_log(devname, msg, lvl=logging.WARNING)
            if execute_in_console:
                self._tryssh_switch(devname, False)
            raise exp

        if option_type in ["run-test", "syslog-check"]:
            return output

        process_apply_config = True
        fetch_mgmt_ip = True
        if re.search("Error", output) or re.search("No such file or directory", output):
            msg = "Failed to execute the command {}".format(script_cmd)
            self.dut_log(devname, msg, lvl=logging.ERROR)
            if option_type not in ["apply-base-config", "apply-module-config", "port-defaults"]:
                raise ValueError(msg)
            msg = "Recovering the devices by rebooting"
            self.dut_log(devname, msg, lvl=logging.ERROR)
            process_apply_config = False
            self.recover(devname, "Recovering the devices")

        if option_type in ["apply-base-config", "apply-module-config"] and process_apply_config:
            if not re.search("Config, FRR, COPP are same as TA files", output):
                fetch_mgmt_ip = True
                if option_type in ["apply-module-config"] and self.prev_testcase:
                    pc_msg = "***** TESTCASE '{}' CONFIG CLEANUP NOT DONE *****".format(self.prev_testcase)
                    self.logger.warning(pc_msg)
                if re.search("REBOOT REQUIRED", output) or \
                        apply_ta_config_method in ["reboot", "force_reboot"]:
                    self.recover(devname, "Reboot after applying TA configuration")

        if option_type == "dump-click-cmds":
            file_name = "results_{0}_{1}_build_cmds.txt".format(
                time.strftime("%Y_%m_%d_%H_%M"), devname)
            local_file_path = str(os.path.join(self.logger.logdir, file_name))
            utils.write_file(local_file_path, "")
            for line in output.strip().split("\n")[:-1]:
                utils.write_file(local_file_path, "{}\n".format(line), "a")

        if option_type == "fetch-core-files":
            if re.search("NO-CORE-FILES", output):
                msg = "No Core files found on the DUT."
                self.dut_log(devname, msg)
            else:
                # Get the remote file name from the output data.
                #remote_file_path = "/tmp/allcorefiles.tar.gz"
                remote_file_path = ""
                for line in output.strip().split("\n"):
                    match = re.match(r'CORE-FILES:\s+(\S+.tar.gz)', str(line).strip())
                    if match:
                        remote_file_path = match.group(1)
                        break
                if remote_file_path:
                    # Construct the local file name.
                    local_file_path = self.make_local_file_path(devname,
                                             value_list[0], "corefiles.tar.gz")
                    # Perform the file download if any files found.
                    retval = self._download_file(access, remote_file_path, local_file_path)
                    if re.search("FAIL", retval):
                        self.add_pending_download(devname, remote_file_path, local_file_path)
                        msg = "Downloading core files - Failed."
                        self.dut_log(devname, msg, lvl=logging.ERROR)
                        raise ValueError(msg)
            if self.kdump_supported:
                if re.search("NO-KDUMP-FILES", output):
                    msg = "No kdump files found on the DUT."
                    self.dut_log(devname, msg)
                else:
                    # Get the remote file name from the output data.
                    #remote_file_path = "/tmp/allcorefiles.tar.gz"
                    remote_file_path = ""
                    for line in output.strip().split("\n"):
                        match = re.match(r'KDUMP-FILES:\s+(\S+.tar.gz)', str(line).strip())
                        if match:
                            remote_file_path = match.group(1)
                            break
                    if remote_file_path:
                        # Construct the local file name.
                        local_file_path = self.make_local_file_path(devname,
                                                 value_list[0], "kdumpfiles.tar.gz")
                        # Perform the file download if any files found.
                        retval = self._download_file(access, remote_file_path, local_file_path)
                        if re.search("FAIL", retval):
                            self.add_pending_download(devname, remote_file_path, local_file_path)
                            msg = "Downloading kdump files - Failed."
                            self.dut_log(devname, msg, lvl=logging.ERROR)
                            raise ValueError(msg)

        if option_type == "get-tech-support":
            if re.search("NO-DUMP-FILES", output):
                self.dut_log(devname, output)
                output = self.show_new(devname, "cat /tmp/show_tech_support.log",
                                       skip_error_check=True, skip_tmpl=True)
                self.dut_log(devname, output)
                raise ValueError("Failed to fetch tech support")
            else:
                # Get the remote file name from the output data.
                remote_file_path = ""
                for line in output.strip().split("\n"):
                    match = re.match(r'DUMP-FILES:\s+(\S+.tar.gz)', str(line).strip())
                    if match:
                        remote_file_path = match.group(1)
                        break
                if remote_file_path:
                    # Construct the local file name.
                    local_file_path = self.make_local_file_path(devname, value_list[0],
                                             os.path.basename(remote_file_path))
                    # Perform the file download if any files found.
                    retval = self._download_file(access, remote_file_path, local_file_path)
                    if re.search("FAIL", retval):
                        self.add_pending_download(devname, remote_file_path, local_file_path)
                        msg = "Downloading tech-support files - Failed."
                        self.dut_log(devname, msg, lvl=logging.ERROR)
                        raise ValueError(msg)
                else:
                    msg = "Failed to read DUMP File"
                    self.dut_log(devname, msg, lvl=logging.ERROR)

        if option_type == "sairedis" and value_list[0] == "read":
            if re.search("NO-SAIREDIS-FILE", output):
                self.dut_log(devname, output)
            else:
                # Get the remote file name from the output data.
                remote_file_path = ""
                for line in output.strip().split("\n"):
                    match = re.match(r'SAI-REDIS-FILE:\s+(/etc/spytest/sairedis.txt)', str(line).strip())
                    if match:
                        remote_file_path = match.group(1)
                        break
                if remote_file_path:
                    # Construct the local file name.
                    local_file_path = self.make_local_file_path(devname,
                                             value_list[1], "sai.log", "tests_")
                    # Perform the file download if any files found.
                    retval = self._download_file(access, remote_file_path, local_file_path)
                    if re.search("FAIL", retval):
                        self.add_pending_download(devname, remote_file_path, local_file_path)
                        msg = "Downloading sai radis files - Failed."
                        self.dut_log(devname, msg, lvl=logging.ERROR)
                        raise ValueError(msg)
                else:
                    msg = "Failed to read sai radis File"
                    self.dut_log(devname, msg, lvl=logging.ERROR)

        # fetch the management IP again
        if fetch_mgmt_ip:
            self._fetch_mgmt_ip(devname)

        return True

    def generate_tech_support(self, devname, name):
        for retry in range(2):
            try:
                self._apply_remote(devname, "get-tech-support", [name])
                break
            except:
                continue

    def save_sairedis(self, devname, phase, name):
        if self.cfg.save_sairedis in ["none"]:
            return ""

        msg = "save-sairedis {} {}".format(phase, name)
        self.dut_log(devname, msg, lvl=logging.DEBUG)

        if phase == "pre-module-prolog":
            if self.cfg.save_sairedis in ["module"]:
                self._apply_remote(devname, "sairedis", ["clean", name])
        elif phase == "post-module-epilog":
            if self.cfg.save_sairedis in ["module"]:
                self._apply_remote(devname, "sairedis", ["read", name])
        elif phase == "pre-test":
            if self.cfg.save_sairedis in ["test"]:
                self._apply_remote(devname, "sairedis", ["clear", name])
        elif phase == "post-test":
            if self.cfg.save_sairedis in ["test"]:
                self._apply_remote(devname, "sairedis", ["read", name])

    def do_memory_checks(self, devname, phase, name):
        if self.cfg.memory_check in ["none"]:
            return

        if phase == "pre-module-prolog":
            show = True
        elif phase == "post-module-prolog":
            show = True
        elif phase == "post-module-epilog":
            show = True
        elif phase == "pre-test":
            show = bool(self.cfg.memory_check in ["test"])
        elif phase == "post-test":
            show = bool(self.cfg.memory_check in ["test"])
        else:
            show = False

        if not show:
            msg = "memory check {}".format(phase)
            self.dut_log(devname, msg, lvl=logging.DEBUG)
        else:
            if devname in self.memory_checks:
                file_path = self.memory_checks[devname]
            else:
                file_path = self.make_local_file_path(devname, "", "all.log",
                                                      "memory_utilization")
                self.memory_checks[devname] = file_path
                utils.write_file(file_path, "")
            utils.write_file(file_path, "\n================ {} {} =================\n".format(phase, name), "a")
            output = self._exec(devname, "cat /proc/meminfo", mode="normal-user", skip_error_check=True, trace_dut_log=1)
            utils.write_file(file_path, output, "a")
            utils.write_file(file_path, "\n --------------------------------\n", "a")
            output = self._exec(devname, "docker stats -a --no-stream", mode="normal-user", skip_error_check=True, trace_dut_log=1)
            utils.write_file(file_path, output, "a")
            utils.write_file(file_path, "\n --------------------------------\n", "a")
            output = self._exec(devname, "top -b -n 1", mode="normal-user", skip_error_check=True, trace_dut_log=1)
            utils.write_file(file_path, output, "a")
            utils.write_file(file_path, "\n --------------------------------\n", "a")
            output = self._exec(devname, "pstree -p", mode="normal-user", skip_error_check=True, trace_dut_log=1)
            utils.write_file(file_path, output, "a")
            utils.write_file(file_path, "\n --------------------------------\n", "a")
            output = self._exec(devname, "free -mlh", mode="normal-user", skip_error_check=True, trace_dut_log=1)
            utils.write_file(file_path, output, "a")

    def do_syslog_checks(self, devname, phase, name):
        if self.cfg.syslog_check in ["none"]:
            return ""

        msg = "syslog check {}".format(phase)
        self.dut_log(devname, msg, lvl=logging.DEBUG)

        (msgtype) = ("")
        if phase == "pre-module-prolog":
            lvl = "none"
        elif phase == "post-module-prolog":
            lvl = self.cfg.syslog_check
            msgtype = "Module Prolog"
        elif phase == "post-module-epilog":
            lvl = self.cfg.syslog_check
            msgtype = "Module Epilog"
        elif phase == "pre-test":
            lvl = "none"
        elif phase == "post-test":
            lvl = self.cfg.syslog_check
        else:
            lvl = "none"

        output = self._apply_remote(devname, "syslog-check", [lvl, phase, name])
        syslog_levels = self.wa.syslog_levels
        if lvl in syslog_levels:
            index = syslog_levels.index(lvl)
            needed = "|".join(syslog_levels[:index+1])
            regex = r"^\S+\s+\d+\s+\d+:\d+:\d+(\.\d+){{0,1}}\s+\S+\s+({})\s+"
            cre = re.compile(regex.format(needed.upper()))
            for line in output.split("\n"):
                if cre.search(line):
                    self.syslogs[devname].append([devname, msgtype, line])

        access = self._get_dev_access(devname)
        if access["filemode"]:
            if lvl != "none":
                val = random.randint(1, 1000)
                val = len(self.syslogs[devname])
                self.syslogs[devname].append([devname, msgtype, "test syslog {}".format(val)])

        return output

    def get_fcli(self):
        return self.fcli

    def get_tryssh(self):
        return self.tryssh

    def get_syslogs(self, clear=True):
        retval = []
        for devname in self.topo["duts"]:
            retval.extend(self.syslogs[devname])
            if clear:
                self.syslogs[devname] = []
        return retval

    def do_audit(self, phase, dut, func_name, res):
        if phase != "post-test": return
        if self.tc_get_tech_support and self.cfg.get_tech_support in ["onerror"]:
            self.generate_tech_support(dut, func_name)
            self._apply_remote(dut, "init-clean", ["none", self.cfg.get_tech_support, self.cfg.clear_tech_support])
        elif self.cfg.get_tech_support in ["always"]:
            self.generate_tech_support(dut, func_name)
            self._apply_remote(dut, "init-clean", ["none", self.cfg.get_tech_support, self.cfg.clear_tech_support])
        elif self.cfg.get_tech_support in ["onfail"] and \
           res.lower() in ["fail", "xfail", "dutfail"]:
            self.generate_tech_support(dut, func_name)
            self._apply_remote(dut, "init-clean", ["none", self.cfg.get_tech_support, self.cfg.clear_tech_support])

        if self.tc_fetch_core_files and self.cfg.fetch_core_files in ["onerror"]:
            self._apply_remote(dut, "fetch-core-files", [func_name])
            self._apply_remote(dut, "init-clean", [self.cfg.fetch_core_files, "none", self.cfg.clear_tech_support])
        elif self.cfg.fetch_core_files in ["always"]:
            self._apply_remote(dut, "fetch-core-files", [func_name])
            self._apply_remote(dut, "init-clean", [self.cfg.fetch_core_files, "none", self.cfg.clear_tech_support])
        elif self.cfg.fetch_core_files in ["onfail"] and \
           res.lower() in ["fail", "xfail", "dutfail"]:
            self._apply_remote(dut, "fetch-core-files", [func_name])
            self._apply_remote(dut, "init-clean", [self.cfg.fetch_core_files, "none", self.cfg.clear_tech_support])

    def apply_files(self, devname, file_list, method="incremental"):
        """
        todo: Update Documentation
        :param devname:
        :param file_list: list of the files
        :return:
        """
        if not file_list:
            return
        devname = self._check_devname(devname)
        for filepath in file_list:
            if isinstance(filepath, list):
                val_list = [method]
                val_list.extend(filepath)
                self._apply_remote(devname, "apply-configs", val_list)
            elif filepath.endswith('.cmds'):
                msg = "Applying commands from {}".format(filepath)
                self.dut_log(devname, msg)
                cmdlist = utils.read_lines(filepath)
                self.apply_script(devname, cmdlist)
            else:
                self._apply_remote(devname, "apply-configs", [method, filepath])

        # Get the vtysh hostname from DUT as the config may have changed
        self.read_vtysh_hostname(devname)
        # set required environment variables as the config may have reset
        self.set_login_timeout(devname)

    def run_script(self, devname, timeout, script_path, *args):
        """
        todo: Update Documentation
        :param dut:
        :type dut:
        :param timeout: in secs
        :type timeout:
        :param script_path:
        :type script_path:
        :return:
        :rtype:
        """
        val_list = [timeout, script_path]
        for arg in args:
            val_list.append(arg)
        return self._apply_remote(devname, "run-test", val_list)

    def enable_disable_console_debug_msgs(self, devname, flag):
        """
        todo: Update Documentation
        :param devname:
        :type devname:
        :param flag:
        :type flag:
        :return:
        :rtype:
        """
        if flag:
            self._apply_remote(devname, "enable-debug")
        else:
            self._apply_remote(devname, "disable-debug")

    def _get_mgmt_ip(self, devname):
        devname = self._check_devname(devname)
        access = self._get_dev_access(devname)
        if access["filemode"]:
            return ""

        connection_param = access["connection_param"]
        if self._is_console_connection(devname):
            return connection_param["mgmt-ip"]
        return connection_param['ip']

    def get_mgmt_ip(self, devname):
        addr = self._get_mgmt_ip(devname)
        if not addr:
            # eth0 IP is not available, try to read it now
            try:
                self._fetch_mgmt_ip(devname)
                addr = self._get_mgmt_ip(devname)
            except:
                addr = ""
        return addr

    def exec_ssh(self, devname, username=None, password=None, cmdlist=[]):
        devname = self._check_devname(devname)
        access = self._get_dev_access(devname)

        if access["filemode"]:
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
        net_connect = self._connect_to_device2(device, 0, msgs)
        if not net_connect:
            return None

        output = []
        nc_prompt = self._find_prompt(access, net_connect)
        for cmd in cmdlist:
            output.append(cmd)
            try:
                output.append(net_connect.send_command(cmd,nc_prompt))
            except Exception as e:
                output.append("Exception: {}".format(e))

        net_connect.disconnect()
        return "\n".join(output)

    def exec_remote(self, ipaddress, username, password, scriptpath, wait_factor=2):
        # Check the reachability
        if not utils.ipcheck(ipaddress):
            msg = "Unable to reach the remote machine '{}'".format(ipaddress)
            self.logger.error(msg)
            raise ValueError(msg)

        # Construct the dict for connection
        device = dict()
        device["ip"] = ipaddress
        device["username"] = username
        device["password"] = password
        device["port"] = 22
        device["blocking_timeout"] = 30
        device["access_model"] = "sonic_ssh"

        # Connect to linux server
        msgs = []
        net_connect = self._connect_to_device2(device, 0, msgs)
        if not net_connect:
            msg = "Unable to connect to the server '{}' using the given credentials.".format(ipaddress)
            self.logger.error(msg)
            raise ValueError(msg)

        # Construct the tmp location filename.
        dst_file = "/tmp/{}".format(os.path.basename(scriptpath))

        # mgmt-ip shpuld not be assigned during the connection initiation.
        device["mgmt-ip"] = None

        # Upload the script to linux server.
        try:
            self.logger.info("Doing SCP transfer of file '{}' to '{}'".format(scriptpath, ipaddress))
            DeviceFileUpload(net_connect, scriptpath, dst_file, device)
        except Exception as e:
            print(e)
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
        cli_prompt = self._get_param(devname, "normal-user-cli-prompt")

        if access["filemode"]:
            return ""

        err_flag = 0
        self._enter_linux_exit_vtysh(devname)

        delay_factor = 3 # so that --faster-cli is not used
        prompt_terminator = r"Enter new UNIX password:\s*$|{}\s*$".format(cli_prompt)
        output = self._send_command(access, "sudo passwd {}".format(username), prompt_terminator, delay_factor=delay_factor)
        self.logger.debug("OUTPUT: {}".format(output))
        if re.search("Enter new UNIX password:", output):
            output = self._send_command(access, password, r"Retype new UNIX password:\s*$", delay_factor=delay_factor)
            self.logger.debug("OUTPUT: {}".format(output))
            if re.search(".*UNIX password:", output):
                output = self._send_command(access, password, cli_prompt, delay_factor=delay_factor)
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

        if err_flag == 2:
            return "user not found"

        if err_flag == 1:
            return "Password updation failed"

        return "Password updated successfully"

    def upload_file_to_dut(self, devname, src_file, dst_file):
        devname = self._check_devname(devname)
        access = self._get_dev_access(devname)

        if access["filemode"]:
            return ""

        # ensure we are in sonic mode
        self._enter_linux_exit_vtysh(devname)

        return self._upload_file3(access, src_file, dst_file)

    def download_file_from_dut(self, devname, src_file, dst_file):
        devname = self._check_devname(devname)
        access = self._get_dev_access(devname)

        if access["filemode"]:
            return ""

        # ensure we have management IP address
        self._fetch_mgmt_ip(devname)

        return self._download_file(access, src_file, dst_file)

    def _run_ansible_script(self, playbook, hosts, username, password, filemode=False):

        hosts = utils.make_list(hosts)

        msg = "Using call: ansible_playbook({}, {}, {}, {})"
        msg = msg.format(playbook, hosts, username, password)
        self.logger.info(msg)
        if filemode:
            return ""

        try: logs_path = self.wa.get_logs_path()
        except: logs_path = None

        output = ""
        try:
            output = ansible_playbook(playbook, hosts, username, password, logs_path)
        except Exception as e:
            self.logger.error(e)
            raise ValueError(e)

        if re.search("Error", output) or re.search("No such file or directory", output):
            self.logger.error(output)
            raise ValueError(output)
        self.logger.info(output)
        return output

    def ansible_dut(self, devname, playbook):
        devname = self._check_devname(devname)
        access = self._get_dev_access(devname)
        host = None
        if access["filemode"] or not self._is_console_connection(devname):
            host = access["ip"]
        else:
            host = access["connection_param"]["mgmt-ip"]
        if not host:
            msg = "No management ip for device: '{}'".format(devname)
            self.dut_log(devname, msg, lvl=logging.ERROR)
            raise ValueError(msg)
        username = access["username"]
        password = access["password"]

        output = ""
        try:
            output = self._run_ansible_script(playbook, host, username, password, access["filemode"])
        except:
            password = access["altpassword"]
            output = self._run_ansible_script(playbook, host, username, password, access["filemode"])
        return output

    def ansible_service(self, service_data, playbook):
        host = service_data["ip"]
        username = service_data["username"]
        password = service_data["password"]

        return self._run_ansible_script(playbook, host, username, password, service_data["filemode"])

    def _check_dut_state(self, devname):
        devname = self._check_devname(devname)
        access = self._get_dev_access(devname)

        cmd = "show uptime"
        if access["filemode"]:
            self.dut_log(devname, "Command '{}'.".format(cmd))
            return True

        # ensure we are in sonic mode
        self._enter_linux_exit_vtysh(devname)

        # Issue command.
        try:
            cli_prompt = self._get_param(devname, "normal-user-cli-prompt")
            output = self._send_command(access, cmd, cli_prompt, True, 1)

            prompt = self._find_prompt(access)
            if prompt == cli_prompt and re.search("^up", output):
                return True
        except:
            return False
        return False

    def add_addl_auth(self, devname, username, password):
        devname = self._check_devname(devname)
        access = self._get_dev_access(devname)
        if "addl_auth" not in access:
            access["addl_auth"] = []
        access["addl_auth"].append([username, password])
        if "connection_param" in access:
            access["connection_param"]["addl_auth"] = access["addl_auth"]

    def module_init_start(self, module_max_timeout, fcli, tryssh):
        self.module_start_time = get_timenow()
        self.module_max_timeout = module_max_timeout
        self.fcli = fcli
        self.tryssh = tryssh
        self.tc_start_time = None
        self.clear_prevent()
        self.set_console_only(bool(not self.tryssh))
        self._reset_device_aliases()

    def clear_devices_usage_list(self):
        self.devices_used_in_tc.clear()

    def get_devices_usage_list(self):
        return list(self.devices_used_in_tc.keys())

    def set_device_usage_collection(self, collect_flag):
        self.devices_used_collection = collect_flag

    def function_init_start(self, tc_max_timeout):
        self.module_start_time = None
        self.tc_max_timeout = tc_max_timeout
        self.tc_get_tech_support = False
        self.tc_fetch_core_files = False
        for devname in self.topo["duts"]:
            self.init_per_test(devname)

    def _session_close_dut(self, devname):
        self._exec(devname, "stty cols 80", None, "normal-user")

    def session_close(self):
        utils.exec_foreach(self.cfg.faster_init, self.topo["duts"],
                           self._session_close_dut)

    def init_per_test(self, devname):
        devname = self._check_devname(devname)
        access = self._get_dev_access(devname)
        if "addl_auth" in access:
            del access["addl_auth"]
        if "connection_param" in access:
            if "addl_auth" in access["connection_param"]:
                del access["connection_param"]["addl_auth"]

    def set_workarea(self, waobj=None):
        self.wa = waobj

    def _set_tryssh(self, devname, tryssh_val, switch):
        access = self._get_dev_access(devname)
        old = access["tryssh"]
        access["tryssh"] = tryssh_val
        if not switch or old == access["tryssh"]:
            return
        if access["tryssh"]:
            self._tryssh_switch(devname, True, check=False)
        else:
            self._tryssh_switch(devname, check=False)

    def set_console_only(self, val, switch=True):
        tryssh_val = bool(self.tryssh and not val)
        utils.exec_foreach(self.cfg.faster_init, self.topo["duts"],
                           self._set_tryssh, tryssh_val, switch)

    def tc_start(self, start_time=None):
        self.tc_start_time = start_time
        profile.init()

        # ensure devices are in sonic mode at test start
        if start_time:
            for devname in self.topo["duts"]:
                access = self._get_dev_access(devname)
                if access["filemode"]:
                    continue
                self._set_last_prompt(access, None)
                self._enter_linux_exit_vtysh(devname)

    def clear_prevent(self):
        self.prevent_list = []

    def add_prevent(self, what):
        self.prevent_list.append(what)

    def get_stats(self):
        return profile.get_stats()

    def set_prev_tc(self, prev_tc=None):
        self.prev_testcase = prev_tc

    def tg_wait(self, val):
        self.wait(val, True)

    def wait(self, val, is_tg=False):
        profile.wait(val, is_tg)
        if self.cfg.filemode:
            return
        self._check_tc_timeout(None, val)
        left = val
        while left > 0:
            self._check_tc_timeout(None)
            if left <= 5:
                self.orig_time_sleep(left)
                break
            self.orig_time_sleep(5)
            left = left - 5

    def _check_tc_timeout(self, access, add_time=0):
        retval = None
        if self.module_max_timeout and self.module_start_time:
            time_taken = get_elapsed(self.module_start_time, False)
            time_taken = time_taken + add_time
            if time_taken > self.module_max_timeout:
                msg = "Max time '{}' reached. Exiting the module init"
                msg = msg.format(self.module_max_timeout)
                if access:
                    self.dut_log(access["devname"], msg)
                else:
                    self.logger.error(msg)
                if self.wa:
                    self.wa.report_timeout("module_init_max_timeout")
                sys.exit(0)
            retval = self.module_max_timeout - time_taken
        elif self.tc_max_timeout and self.tc_start_time:
            time_taken = get_elapsed(self.tc_start_time, False)
            time_taken = time_taken + add_time
            if time_taken > self.tc_max_timeout:
                msg = "Max time '{}' reached. Exiting the testcase"
                msg = msg.format(self.tc_max_timeout)
                if access:
                    self.dut_log(access["devname"], msg)
                else:
                    self.logger.error(msg)
                if self.wa:
                    self.wa.report_timeout("test_case_max_timeout")
                sys.exit(0)
            retval = self.tc_max_timeout - time_taken
        return retval

    def _timeout_handler(self, signum, frame):
        self.logger.debug("Timeout Handler signal={}".format(signum))
        if signum != signal.SIGALRM: # do we need this check?
            return
        if self.profile_max_timeout_msg:
            if self.wa:
                self.wa.report_timeout("operation_max_timeout", self.profile_max_timeout_msg)
            sys.exit(0)
        if self.module_max_timeout and self.module_start_time:
            if self.wa:
                self.wa.report_timeout("module_init_max_timeout")
            sys.exit(0)
        elif self.tc_max_timeout and self.tc_start_time:
            if self.wa:
                self.wa.report_timeout("test_case_max_timeout")
            sys.exit(0)

    def _timeout_cancel(self, left):
        if left is not None:
            self.logger.debug("Cancelling timer LEFT={}".format(left))
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, signal.SIG_DFL)

    def profiling_start(self, msg, max_time):
        self.profile_max_timeout_msg = None
        left = self._check_tc_timeout(None)
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

    def profiling_stop(self, pid):
        left = profile.stop(pid)
        self._timeout_cancel(left)

    def rest_init(self, dut, username, password, altpassword, cached=False):
        access = self._get_dev_access(dut)
        access["curr_pwd"] = None
        if not cached:
            self._fetch_mgmt_ip(dut)
        ip = self._get_mgmt_ip(dut)
        self.rest[dut].reinit(ip, username, password, altpassword)
        access["curr_pwd"] = self.rest[dut]._get_credentials()[1]

    def reset_restinit(self, dut):
        access = self._get_dev_access(dut)
        access["curr_pwd"] = None
        self.rest[dut].reset_curr_pwd()

    def rest_create(self, dut, path, data, *args, **kwargs):
        return self.rest[dut].post(path, data, *args, **kwargs)

    def rest_update(self, dut, path, data, *args, **kwargs):
        return self.rest[dut].put(path, data, *args, **kwargs)

    def rest_modify(self, dut, path, data, *args, **kwargs):
        return self.rest[dut].patch(path, data, *args, **kwargs)

    def rest_read(self, dut, path, *args, **kwargs):
        return self.rest[dut].get(path, *args, **kwargs)

    def rest_delete(self, dut, path, *args, **kwargs):
        return self.rest[dut].delete(path, *args, **kwargs)

    def rest_parse(self, dut, filepath=None, all_sections=False, paths=[], **kwargs):
        return self.rest[dut].parse(filepath, all_sections, paths, **kwargs)

    def rest_apply(self, dut, data):
        return self.rest[dut].apply(data)

    def get_credentials(self, dut):
        access = self._get_dev_access(dut)
        retList = [access.get("username")]
        pwdlist = [access.get("password"), access.get("altpassword"), access.get("curr_pwd")]
        retList.extend(pwdlist)
        return retList

    def _parse_cli_opts(self, **kwargs):
        opts = SpyTestDict()
        opts.ctype = kwargs.get("type", "click")
        opts.skip_tmpl = kwargs.get("skip_tmpl", False)
        opts.skip_error_check = kwargs.get("skip_error_check", False)
        opts.expect_reboot = kwargs.get("expect_reboot", False)
        opts.max_time = kwargs.get("max_time", 0)
        opts.sudo = kwargs.get("sudo", None)
        if opts.sudo is None:
            opts.sudo = True if opts.ctype == "click" else False
        opts.sep = ";" if opts.ctype == "click" else "\n"
        opts.conf = kwargs.get("conf", True)
        opts.confirm = kwargs.get("confirm", None)
        opts.faster_cli = bool(kwargs.get("faster_cli", True))
        opts.delay_factor = int(math.ceil((opts.max_time * 1.0) / 100))
        opts.cmds_delay_factor = 3 if opts.delay_factor <=3 else opts.delay_factor
        return opts

    # prepare list of commands
    def _build_cmd_list(self, cmd, opts):
        cmd_list = []
        for l_cmd in utils.string_list(cmd):
            if l_cmd == "su":
                continue
            if opts.sudo and not l_cmd.startswith("sudo "):
                l_cmd = "sudo " + l_cmd
            cmd_list.append(l_cmd)
        return cmd_list

    def _change_mode(self, devname, is_show, cmd, opts):
        devname = self._check_devname(devname)
        access = self._get_dev_access(devname)
        if access["filemode"]:
            return ("", "", "")

        (prefix, op) = ("", "")

        # check if the current prompt satisfies show/config command
        current_mode = self._change_prompt(devname)
        if current_mode.startswith("mgmt"):
            if opts.ctype == "klish":
                if is_show:
                    if current_mode == "mgmt-user":
                        return ("", op, current_mode)
                    return ("do ", op, "mgmt-any-config")
                else:
                    if current_mode == "mgmt-user":
                        if cmd in ["exit"]:
                            return ("", op, "normal-user")
                        if not opts.conf:
                            return ("", op, "mgmt-user")
                    elif current_mode == "mgmt-config":
                        if cmd in ["end", "exit"]:
                            return ("", op, "mgmt-user")
                        if opts.conf:
                            return ("", op, "mgmt-any-config")
                    else:
                        if cmd in ["end"]:
                            return ("", op, "mgmt-user")
                        if opts.conf:
                            return ("", op, "mgmt-any-config")
        elif current_mode.startswith("vtysh"):
            if opts.ctype == "vtysh":
                if is_show:
                    if current_mode == "vtysh-user":
                        return ("", op, current_mode)
                    return ("do ", op, "vtysh-any-config")
                else:
                    if current_mode == "vtysh-user":
                        if cmd in ["exit"]:
                            return ("", op, "normal-user")
                        if not opts.conf:
                            return ("", op, "vtysh-user")
                    elif current_mode == "vtysh-config":
                        if cmd in ["end", "exit"]:
                            return ("", op, "vtysh-user")
                        if opts.conf:
                            return ("", op, "vtysh-any-config")
                    else:
                        if cmd in ["end"]:
                            return ("", op, "vtysh-user")
                        if opts.conf:
                            return ("", op, "vtysh-any-config")

        # change the mode
        if opts.ctype == "click":
            op = self._change_prompt(devname, "normal-user", startmode=current_mode)
            return ("", op, "normal-user")
        elif opts.ctype == "vtysh" and (is_show or not opts.conf):
            op = self._change_prompt(devname, "vtysh-user", startmode=current_mode)
            return ("", op, "vtysh-user")
        elif opts.ctype == "vtysh":
            op = self._change_prompt(devname, "vtysh-config", startmode=current_mode)
            return ("", op, "vtysh-any-config")
        elif opts.ctype == "klish" and (is_show or not opts.conf):
            op = self._change_prompt(devname, "mgmt-user", startmode=current_mode)
            return ("", op, "mgmt-user")
        elif opts.ctype == "klish":
            op = self._change_prompt(devname, "mgmt-config", startmode=current_mode)
            return ("", op, "mgmt-any-config")
        elif opts.ctype == "lldp":
            op = self._change_prompt(devname, "lldp-user", startmode=current_mode)
            return ("", op, "lldp-user")

        return (prefix, op, "unknown-mode")

    def parse_show(self, devname, cmd, output):
        return self._tmpl_apply(devname, cmd, output)

    def show_new(self, devname, cmd, **kwargs):
        opts = self._parse_cli_opts(**kwargs)
        (prefix, op, expect_mode) = self._change_mode(devname, True, cmd, opts)

        devname = self._check_devname(devname)
        access = self._get_dev_access(devname)
        prompts = access["prompts"]
        if access["filemode"]:
            self.dut_log(devname, cmd)
            return ""

        if expect_mode in ["unknown-mode", "unknown-prompt"]:
            msg = "Unknown prompt/mode."
            self.dut_log(devname, msg, lvl=logging.ERROR)
            raise ValueError(msg)

        actual_cmd = cmd
        if opts.ctype == "klish" and not re.search(r"\| no-more$", cmd.strip()):
            cmd = cmd + " | no-more"

        cmd = prefix + cmd

        expected_prompt = prompts.get_prompt_for_mode(expect_mode)

        if opts.expect_reboot:
            # adjust delay and prompt when expecting reboot
            expect = "|".join([expected_prompt, regex_login])
            opts.delay_factor = utils.max(6, opts.delay_factor)
            try:
                self._tryssh_switch(devname)
                output = self._send_command(access, cmd, expect, True,
                                            ufcli=opts.faster_cli,
                                            delay_factor=opts.delay_factor)
                prompt = self._find_prompt(access)
                if prompt != expected_prompt:
                    self._enter_linux(devname, prompt)
                    self.do_post_reboot(devname)
                    self._tryssh_switch(devname, True)
                else:
                    self._tryssh_switch(devname, False)
            except Exception as exp:
                self._tryssh_switch(devname, False)
                raise exp
        else:
            output = self._send_command(access, cmd, expected_prompt,
                        opts.skip_error_check, ufcli=opts.faster_cli,
                        delay_factor=opts.delay_factor)

        if opts.skip_tmpl:
            return output

        return self._tmpl_apply(devname, actual_cmd, output)

    def config_new(self, devname, cmd, **kwargs):
        opts = self._parse_cli_opts(**kwargs)
        cmd_list = self._build_cmd_list(cmd, opts)
        if not cmd_list: return ""

        (prefix, op, expect_mode) = self._change_mode(devname, False, cmd, opts)

        devname = self._check_devname(devname)
        access = self._get_dev_access(devname)
        prompts = access["prompts"]

        if expect_mode in ["unknown-mode", "unknown-prompt"]:
            msg = "Unknown prompt/mode."
            self.dut_log(devname, msg, lvl=logging.ERROR)
            raise ValueError(msg)

        if len(cmd_list) > 10 and opts.ctype == "click":
            self._enter_linux_exit_vtysh(devname)
            # execute the command.
            cmd_list.insert(0, "#!/bin/bash\n")
            self._echo_list_to_file(access, cmd_list, "/tmp/config.sh")
            max_run_time = len(cmd_list) * 2
            return self.run_script(devname, max_run_time, "/tmp/config.sh")

        # need to revisit if klish support multiple commands
        expected_prompt = prompts.get_prompt_for_mode(expect_mode)
        if opts.ctype != "klish": cmd_list = [opts.sep.join(cmd_list)]

        # add confirmation prompts if specified
        confirm_prompts = []
        all_prompts = [expected_prompt]
        if opts.confirm:
            confirm_prompts.append(r"(.*y\/n\](\:)*\s*)$")
            confirm_prompts.append(r"(.*y\/N\](\:)*\s*)$")
            confirm_prompts.append(r"(.*Y\/n\](\:)*\s*)$")
            confirm_prompts.append(r"(.*Y\/N\](\:)*\s*)$")
            all_prompts.extend(confirm_prompts)
        expected_prompt_with_confirm = "|".join(all_prompts)
        expected_prompt_re = re.compile(expected_prompt)

        # execute individual commands
        op_lines = []
        for l_cmd in cmd_list:
            if opts.confirm:
                op = self._send_command(access, l_cmd, expected_prompt_with_confirm,
                                        opts.skip_error_check, ufcli=opts.faster_cli,
                                        delay_factor=opts.delay_factor)

                # do we really get list?
                if isinstance(op, list):
                    op_lines.extend(op)
                    continue

                # store the output
                op_lines.append(op)

                # can't do any thing in case of errors
                if re.search("Syntax error:", op): continue

                ## handle the case of no confirmation
                #if expected_prompt_re.match(op): continue
                #op2 = op.replace("\\", "")
                #if expected_prompt_re.match(op2): continue

                # matched with the confirmation prompt
                op = self._send_command(access, str(opts.confirm), expected_prompt,
                                        opts.skip_error_check, new_line=False,
                                        ufcli=opts.faster_cli,
                                        delay_factor=opts.delay_factor)
                op_lines.append(op)
                op = self._send_command(access, "", expected_prompt,
                                        opts.skip_error_check, new_line=True,
                                        ufcli=opts.faster_cli,
                                        delay_factor=opts.delay_factor)
                op_lines.append(op)
            else:
                op = self._send_command(access, l_cmd, expected_prompt,
                        opts.skip_error_check, ufcli=opts.faster_cli,
                        delay_factor=opts.delay_factor)
                op_lines.append(op)
        return "\n".join(op_lines)

    def exec_ssh_remote_dut(self, devname, ipaddress, username, password, command=None, timeout=30):
        devname = self._check_devname(devname)
        access = self._get_dev_access(devname)

        if access["filemode"]:
            return ""

        if not command:
            command = "uptime"

        check_cmd = "which sshpass"
        update_install_cmd = "sudo apt-get update;sudo apt-get -f install -y sshpass"
        cli_prompt = self._get_param(devname, "normal-user-cli-prompt")

        # Check if sshpass exists, if not update and install
        output = self._send_command(access, check_cmd, cli_prompt,
                                    skip_error_check=True)
        self.dut_log(devname, "Command '{}' Output: '{}'.".format(check_cmd, output))
        if "sshpass" not in output:
            output = self._send_command(access, update_install_cmd, cli_prompt, ufcli=False,
                                        skip_error_check=True)
            self.dut_log(devname, "Command '{}' Output: '{}'.".format(check_cmd, update_install_cmd))

        # Construct the sshpass command.
        exec_command = "sshpass -p '{}' ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o ConnectTimeout={} {}@{} {}"
        exec_command = exec_command.format(password, timeout, username, ipaddress, command)

        # Execute the command
        output = self._send_command(access, exec_command, cli_prompt)

        # Return the output
        return output

    def run_uicli_script(self, devname, scriptname):
        devname = self._check_devname(devname)
        access = self._get_dev_access(devname)

        if access["filemode"]:
            return [False, 0, 0, [], []]

        msg = "Using script: script({})".format(scriptname)
        self.logger.info(msg)

        output = ""
        data = None
        script_module = os.path.splitext(os.path.basename(scriptname))[0]
        try:
            with open(scriptname) as json_file:
                data = json.load(json_file)
        except Exception as e:
            self.logger.error(e)
            raise ValueError(e)

        pass_count = 0
        fail_count = 0
        invalid_count = 0

        mappings_root = os.path.join(os.path.dirname(__file__), '..', "datastore", "ui_cli", "mappings")
        uicli_scripts_root = os.path.join(os.path.dirname(__file__), '..', "datastore", "ui_cli", "json_scripts")

        autogen_params_file = os.path.join(os.path.abspath(uicli_scripts_root), "all_params.json")
        manual_params_file = os.path.join(os.path.abspath(mappings_root), "param_mappings.yaml")

        commands_mapfile = os.path.join(os.path.abspath(mappings_root), "command_mappings.yaml")
        cmds_oyaml = OrderedYaml(commands_mapfile, [])
        cmd_mapfile_data = cmds_oyaml.get_data() or dict()
        confirmation_mappings = cmd_mapfile_data.confirmation_mappings if "confirmation_mappings" in cmd_mapfile_data else SpyTestDict()
        non_config_mode_mappings = cmd_mapfile_data.non_config_mode_mappings if "non_config_mode_mappings" in cmd_mapfile_data else SpyTestDict()
        ignore_commands = cmd_mapfile_data.ignore_commands if "ignore_commands" in cmd_mapfile_data else SpyTestDict()

        msg = "Using autogen params file: params_file({})".format(autogen_params_file)
        self.logger.info(msg)
        msg = "Using manual params file: params_file({})".format(manual_params_file)
        self.logger.info(msg)
        msg = "Using command mappings file: commands_mappings_file({})".format(commands_mapfile)
        self.logger.info(msg)

        try:
            with open(autogen_params_file) as json_file:
                all_params = json.load(json_file)
        except Exception as e:
            self.logger.error(e)
            raise ValueError(e)

        try:
            params_oyaml = OrderedYaml(manual_params_file, [])
            params_mapfile_data = params_oyaml.get_data() or dict()
        except Exception as e:
            self.logger.error(e)
            raise ValueError(e)

        if params_mapfile_data:
            all_params.update(params_mapfile_data)

        error_patterns = []
        for err, errinfo in list(access["errors"].items()):
            error_patterns.append(errinfo.search)
        error_patterns.extend([".*No such file or directory.*", ".*can't open file .*"])

        tb_vars = SpyTestDict()
        tb_vars["connected_ports"] = []
        for each_link in self.wa.get_links(devname):
            tb_vars["connected_ports"].append(each_link[0])
        tb_vars["free_ports"] = self.wa.get_free_ports(devname)
        tb_vars["all_ports"] = self.wa.get_all_ports(devname)

        uicli = UICLI(self.logger, tb_vars, script_module)

        missing_actions_cfg_cmds = []
        commands_and_results = []
        passed_list = []
        failed_list = []
        index = 0
        for step_entry in data["Steps"]:
            replaced_mode_values = SpyTestDict()
            replaced_cmd_params = SpyTestDict()

            index += 1

            # Get updated pre-configs section mode args and command args
            uicli._uicli_get_preconfig_mode_arg_values_dict(all_params, step_entry, replaced_mode_values)
            uicli._uicli_get_preconfig_cmd_param_values_list(all_params, step_entry, replaced_cmd_params)

            # Get updated configs section mode args and command args
            uicli._uicli_get_config_mode_arg_values_dict(all_params, step_entry, replaced_mode_values)
            uicli._uicli_get_config_cmd_param_values_list(all_params, step_entry, replaced_cmd_params)

            # Get updated actions section mode args and command args
            uicli._uicli_get_action_mode_arg_values_dict(all_params, step_entry, replaced_mode_values)
            uicli._uicli_get_action_cmd_param_values_list(all_params, step_entry, replaced_cmd_params)

            # Get list of command params to check
            changed_steps = uicli._uicli_substitute_args_params(all_params, step_entry, replaced_mode_values, replaced_cmd_params)

            tmp_configs_section = step_entry.get("configs", None)
            tmp_config_step = tmp_configs_section[0]
            tmp_config_step_cfg = tmp_config_step.get("config", None)
            tmp_config_step_cmd = tmp_config_step_cfg.get("command", None)

            try:
                all_step_results = []
                for changed_step in changed_steps:
                    single_steps_results = self._execute_uicli_step(uicli, devname, changed_step, error_patterns,
                                 ignore_commands, confirmation_mappings, non_config_mode_mappings, missing_actions_cfg_cmds)
                    #uicli.uicli_log(",".join(single_steps_results))
                    all_step_results.extend(single_steps_results)

                if "FAIL" in all_step_results:
                    fail_count += 1
                    failed_list.append([index, tmp_config_step_cmd])
                    commands_and_results.append(",".join([script_module, tmp_config_step_cmd, "FAIL"]))
                    continue

                pass_count += 1
                passed_list.append([index, tmp_config_step_cmd])
                commands_and_results.append(",".join([script_module, tmp_config_step_cmd, "PASS"]))

            except Exception as e:
                self.logger.error(e)
                fail_count += 1
                failed_list.append([index, tmp_config_step_cmd])
                commands_and_results.append(",".join([script_module, tmp_config_step_cmd, "FAIL"]))
                #raise ValueError(e)

        if missing_actions_cfg_cmds:
            uicli.uicli_log("Missing 'actions' section for config command(s)", footer=False)
            uicli.uicli_log(missing_actions_cfg_cmds, header=False)

        if commands_and_results:
            uicli.uicli_log("Commands and Results", footer=False)
            uicli.uicli_log(commands_and_results, header=False)

        res_list = [["PASS", pass_count], ["FAIL", fail_count], ["INVALID", invalid_count]]
        uicli.uicli_log(res_list)

        if fail_count > 0:
            return [False, pass_count, fail_count, passed_list, failed_list]

        return [True, pass_count, fail_count, passed_list, failed_list]

    def _execute_uicli_step(self, uicli, devname, stepentry, error_patterns, ignore_commands,
                            confirmation_mappings, non_config_mode_mappings, missing_actions_cfg_cmds):
        steps_results = []
        cfg_cmds = []
        each_step_cmds_results = []

        preconfigs_section = stepentry.get("pre-configs", None)
        configs_section = stepentry.get("configs", None)
        actions_section = stepentry.get("actions", None)

        # Execute pre-configs section
        if preconfigs_section:
            for config_step in preconfigs_section:
                config_step_type = config_step.get("type", None)
                config_step_mode = config_step.get("mode", None)
                config_step_cfg = config_step.get("pre-config", None)

                current_cmd = None
                current_res = "PASS"
                if config_step_type == "klish":
                    if config_step_mode:
                        command_mode = config_step_mode[0]

                        if len(config_step_mode) == 2:
                            command_mode_args = config_step_mode[1]
                            prompt = self.change_prompt(devname, command_mode, **command_mode_args)
                        elif len(config_step_mode) == 1:
                            prompt = self.change_prompt(devname, command_mode)

                        config_step_cmd = config_step_cfg.get("command", None)
                        config_step_match = config_step_cfg.get("match", None)
                        config_step_isvalid = config_step_cfg.get("valid", 1)

                        if not config_step_cmd: continue

                        if any(re.match(key, config_step_cmd) for key in ignore_commands.keys()): continue

                        if config_step_match:
                            cmd_matches = config_step_match
                        else:
                            cmd_matches = []

                        is_step_conf = True
                        if any(re.match(key, config_step_cmd) for key in non_config_mode_mappings.keys()):
                            is_step_conf = False

                        is_show_cmd = False
                        if config_step_cmd.startswith("show"):
                            is_show_cmd = True
                            if not re.search(r"\| no-more$", config_step_cmd.strip()):
                                config_step_cmd = config_step_cmd + " | no-more"

                        cfg_cmds.append(config_step_cmd)
                        current_cmd = config_step_cmd

                        if prompt in ["unknown-mode", "unknown-prompt"]:
                            steps_results.append("FAIL")
                            current_res = "FAIL"
                            self.logger.error("Step Pre-Config Section Failed. Unable to change to the required mode")
                            each_step_cmds_results.append([current_cmd, current_res])
                            continue

                        confirm_command = False
                        if any(re.match(key, current_cmd) for key in confirmation_mappings.keys()):
                            confirm_command = next((confirmation_mappings.get(key) \
                                 for key in confirmation_mappings.keys() if re.match(key, current_cmd)), 'N')

                        #import pdb; pdb.set_trace()
                        #try:
                        #    output = self.config_new(devname, config_step_cmd, type="klish",
                        #                             skip_error_check=True, conf=is_step_conf)
                        #except:
                        #    pass
                        hndl_before_cmd = self._get_handle(devname)
                        output = self.config_new(devname, current_cmd, type="klish",
                                                 skip_error_check=True, conf=is_step_conf, confirm=confirm_command)

                        if not isinstance(output, list) and re.search("Syntax error:", output):
                            hndl = self._get_handle(devname)
                            hndl.send_command_timing("\x03")

                        hndl_after_cmd = self._get_handle(devname)

                        if hndl_before_cmd != hndl_after_cmd:
                            steps_results.append("FAIL")
                            current_res = "FAIL"
                            self.logger.debug("Handles- Before: {}, After: {}".format(hndl_before_cmd, hndl_after_cmd))
                            self.logger.error("Step Config section Failed. Got console hang or prompt not found pattern")
                        elif cmd_matches:
                            for match in cmd_matches:
                                found_match = False
                                if isinstance(match, dict):
                                    for entry in output:
                                        keys_matched = 0
                                        for key in match.keys():
                                            if key in entry.keys() and match[key] == entry[key]:
                                                keys_matched += 1
                                            if len(match.keys()) == keys_matched:
                                                found_match = True
                                                break
                                        if found_match: break
                                else:
                                    if match.strip() != "" and re.search(match, output):
                                        found_match = True

                                if not config_step_isvalid:
                                    found_match = not found_match

                                if not found_match:
                                    steps_results.append("FAIL")
                                    current_res = "FAIL"
                                    self.logger.error("Step Pre-Config Section Failed. Match not found")
                                    self.logger.error("Output: {}".format(output))
                                    self.logger.error("Dict Pattern: {}".format(match))
                                    break
                        else:
                            found_error = False
                            #skip_patterns = [".*Error: Entry not found.*", ".*Error: OID info not found in.*", ".*Error: Exceeds.*"]
                            skip_patterns = [".*Error: Entry not found.*", ".*Error: OID info not found in.*", ".*Error: Exceeds.*",
                                             ".*Error: Invalid VLAN.*", ".*Error: mclag not configured.*",
                                             ".*Error: L3 Configuration exists for Interface.*", ".*Error:.*It's not a L2 interface.*",
                                             ".*Error: Not supported prefix length.*", ".*Error: Untagged VLAN.*configuration.*exist for Interface:.*",
                                             ".*Error: Priority value should be multiple of.*", ".*Error: PortChannel does not exist:.*", ".*Error: Invalid PortChannel:.*",
                                             ".*Error: This object is not supported in this build.*", ".*Error: This object is not supported in this platform.*",
                                             ".*Error: Retrieving data from VLAN table for VLAN:.*", ".*Error: Neighbor.*not found.*",
                                             ".*Error: Retrieving data from LOOPBACK_INTERFACE table for Loopback:.*",
                                             ".*Error: Fallback option cannot be configured for an already existing PortChannel:.*",
                                             ".*Error: Cannot configure Mode for an existing PortChannel.*"]
                            for err_patt in error_patterns:
                                if (is_show_cmd and re.search(".*Error:.*", err_patt)):
                                    continue
                                is_skippable = False
                                for skip_patt in skip_patterns:
                                    if re.search(skip_patt, output):
                                        is_skippable = True
                                if is_skippable: continue
                                if re.search(err_patt, output):
                                    found_error = True
                                    break

                            if not config_step_isvalid:
                                found_error = not found_error

                            if found_error:
                                steps_results.append("FAIL")
                                current_res = "FAIL"
                                self.logger.error("Step Pre-Config section Failed. Got error pattern")
                                self.logger.error("Output: {}".format(output))
                each_step_cmds_results.append([current_cmd, current_res])

        # Execute configs section
        if configs_section:
            for config_step in configs_section:
                config_step_type = config_step.get("type", None)
                config_step_mode = config_step.get("mode", None)
                config_step_cfg = config_step.get("config", None)

                current_cmd = None
                current_res = "PASS"
                if config_step_type == "klish":
                    if config_step_mode:
                        command_mode = config_step_mode[0]

                        if len(config_step_mode) == 2:
                            command_mode_args = config_step_mode[1]
                            prompt = self.change_prompt(devname, command_mode, **command_mode_args)
                        elif len(config_step_mode) == 1:
                            prompt = self.change_prompt(devname, command_mode)

                        config_step_cmd = config_step_cfg.get("command", None)
                        config_step_match = config_step_cfg.get("match", None)
                        config_step_isvalid = config_step_cfg.get("valid", 1)

                        if not config_step_cmd: continue

                        if any(re.match(key, config_step_cmd) for key in ignore_commands.keys()): continue

                        if config_step_match:
                            cmd_matches = config_step_match
                        else:
                            cmd_matches = []

                        is_step_conf = True
                        if any(re.match(key, config_step_cmd) for key in non_config_mode_mappings.keys()):
                            is_step_conf = False

                        is_show_cmd = False
                        if config_step_cmd.startswith("show"):
                            is_show_cmd = True
                            if not re.search(r"\| no-more$", config_step_cmd.strip()):
                                config_step_cmd = config_step_cmd + " | no-more"

                        cfg_cmds.append(config_step_cmd)
                        current_cmd = config_step_cmd

                        if prompt in ["unknown-mode", "unknown-prompt"]:
                            steps_results.append("FAIL")
                            current_res = "FAIL"
                            self.logger.error("Step Config Section Failed. Unable to change to the required mode")
                            each_step_cmds_results.append([current_cmd, current_res])
                            continue

                        confirm_command = False
                        if any(re.match(key, current_cmd) for key in confirmation_mappings.keys()):
                            confirm_command = next((confirmation_mappings.get(key) \
                                 for key in confirmation_mappings.keys() if re.match(key, current_cmd)), 'N')

                        #import pdb; pdb.set_trace()
                        #try:
                        #    output = self.config_new(devname, config_step_cmd, type="klish",
                        #                             skip_error_check=True, conf=is_step_conf)
                        #except:
                        #    pass
                        hndl_before_cmd = self._get_handle(devname)
                        output = self.config_new(devname, current_cmd, type="klish",
                                                 skip_error_check=True, conf=is_step_conf, confirm=confirm_command)

                        if not isinstance(output, list) and re.search("Syntax error:", output):
                            hndl = self._get_handle(devname)
                            hndl.send_command_timing("\x03")

                        hndl_after_cmd = self._get_handle(devname)

                        if hndl_before_cmd != hndl_after_cmd:
                            steps_results.append("FAIL")
                            current_res = "FAIL"
                            self.logger.debug("Handles- Before: {}, After: {}".format(hndl_before_cmd, hndl_after_cmd))
                            self.logger.error("Step Config section Failed. Got console hang or prompt not found pattern")
                        elif cmd_matches:
                            for match in cmd_matches:
                                found_match = False
                                if isinstance(match, dict):
                                    for entry in output:
                                        keys_matched = 0
                                        for key in match.keys():
                                            if key in entry.keys() and match[key] == entry[key]:
                                                keys_matched += 1
                                            if len(match.keys()) == keys_matched:
                                                found_match = True
                                                break
                                        if found_match: break
                                else:
                                    if match.strip() != "" and re.search(match, output):
                                        found_match = True

                                if not config_step_isvalid:
                                    found_match = not found_match

                                if not found_match:
                                    steps_results.append("FAIL")
                                    current_res = "FAIL"
                                    self.logger.error("Step Config Section Failed. Match not found")
                                    self.logger.error("Output: {}".format(output))
                                    self.logger.error("Dict Pattern: {}".format(match))
                                    break
                        else:
                            found_error = False
                            #skip_patterns = [".*Error: Entry not found.*", ".*Error: OID info not found in.*", ".*Error: Exceeds.*"]
                            skip_patterns = [".*Error: Entry not found.*", ".*Error: OID info not found in.*", ".*Error: Exceeds.*",
                                             ".*Error: Invalid VLAN.*", ".*Error: mclag not configured.*",
                                             ".*Error: L3 Configuration exists for Interface.*", ".*Error:.*It's not a L2 interface.*",
                                             ".*Error: Not supported prefix length.*", ".*Error: Untagged VLAN.*configuration.*exist for Interface:.*",
                                             ".*Error: Priority value should be multiple of.*", ".*Error: PortChannel does not exist:.*", ".*Error: Invalid PortChannel:.*",
                                             ".*Error: This object is not supported in this build.*", ".*Error: This object is not supported in this platform.*",
                                             ".*Error: Retrieving data from VLAN table for VLAN:.*", ".*Error: Neighbor.*not found.*",
                                             ".*Error: Retrieving data from LOOPBACK_INTERFACE table for Loopback:.*",
                                             ".*Error: Fallback option cannot be configured for an already existing PortChannel:.*",
                                             ".*Error: Cannot configure Mode for an existing PortChannel.*"]
                            for err_patt in error_patterns:
                                if (is_show_cmd and re.search(".*Error:.*", err_patt)):
                                    continue
                                is_skippable = False
                                for skip_patt in skip_patterns:
                                    if re.search(skip_patt, output):
                                        is_skippable = True
                                if is_skippable: continue
                                if re.search(err_patt, output):
                                    found_error = True
                                    break

                            if not config_step_isvalid:
                                found_error = not found_error

                            if found_error:
                                steps_results.append("FAIL")
                                current_res = "FAIL"
                                self.logger.error("Step Config section Failed. Got error pattern")
                                self.logger.error("Output: {}".format(output))
                each_step_cmds_results.append([current_cmd, current_res])

        # Execute actions section
        if actions_section:
            for action_step in actions_section:
                action_step_type = action_step.get("type", None)
                action_step_mode = action_step.get("mode", None)
                action_step_act = action_step.get("action", None)

                current_cmd = None
                current_res = "PASS"
                if action_step_type == "klish":
                    if action_step_mode:
                        action_mode = action_step_mode[0]

                        if len(action_step_mode) == 2:
                            action_mode_args = action_step_mode[1]
                            prompt = self.change_prompt(devname, action_mode, **action_mode_args)
                        elif len(action_step_mode) == 1:
                            prompt = self.change_prompt(devname, action_mode)

                        action_step_cmd = action_step_act.get("command", None)
                        action_step_match = action_step_act.get("match", None)
                        action_step_isvalid = action_step_act.get("valid", 1)

                        if not action_step_cmd: continue

                        if action_step_match:
                            action_matches = action_step_match
                        else:
                            action_matches = []

                        skip_tmpl_value = False
                        for match in action_matches:
                            if not isinstance(match, dict):
                                skip_tmpl_value = True
                                break

                        current_cmd = action_step_cmd

                        if prompt in ["unknown-mode", "unknown-prompt"]:
                            steps_results.append("FAIL")
                            current_res = "FAIL"
                            self.logger.error("Step Action Section Failed. Unable to change to the required mode")
                            each_step_cmds_results.append([current_cmd, current_res])
                            continue

                        #import pdb; pdb.set_trace()
                        #try:
                        #    output = self.show_new(devname, action_step_cmd, type="klish",
                        #                           skip_error_check=True, skip_tmpl=skip_tmpl_value)
                        #except:
                        #    pass
                        hndl_before_cmd = self._get_handle(devname)
                        output = self.show_new(devname, action_step_cmd, type="klish",
                                               skip_error_check=True, skip_tmpl=True)

                        if not isinstance(output, list) and re.search("Syntax error:", output):
                            hndl = self._get_handle(devname)
                            hndl.send_command_timing("\x03")

                        if not skip_tmpl_value:
                            output = self._tmpl_apply(devname, action_step_cmd, output)

                        hndl_after_cmd = self._get_handle(devname)

                        if hndl_before_cmd != hndl_after_cmd:
                            steps_results.append("FAIL")
                            current_res = "FAIL"
                            self.logger.debug("Handles- Before: {}, After: {}".format(hndl_before_cmd, hndl_after_cmd))
                            self.logger.error("Step Config section Failed. Got console hang or prompt not found pattern")
                        elif action_matches:
                            for match in action_matches:
                                found_match = False
                                if not skip_tmpl_value:
                                    for entry in output:
                                        keys_matched = 0
                                        for key in match.keys():
                                            if key in entry.keys() and match[key] == entry[key]:
                                                keys_matched += 1
                                            if len(match.keys()) == keys_matched:
                                                found_match = True
                                                break
                                        if found_match: break
                                else:
                                    if match.strip() != "" and re.search(match, output):
                                        found_match = True

                                if not action_step_isvalid:
                                    found_match = not found_match

                                if not found_match:
                                    steps_results.append("FAIL")
                                    current_res = "FAIL"
                                    self.logger.error("Step Action Section Failed. Match not found")
                                    self.logger.error("Output: {}".format(output))
                                    self.logger.error("Dict Pattern: {}".format(match))
                                    break
                        else:
                            found_error = False
                            for err_patt in error_patterns:
                                if re.search(err_patt, output):
                                    found_error = True
                                    break

                            if not action_step_isvalid:
                                found_error = not found_error

                            if found_error:
                                steps_results.append("FAIL")
                                current_res = "FAIL"
                                self.logger.error("Step Action section Failed. Got error pattern")
                                self.logger.error("Output: {}".format(output))
                each_step_cmds_results.append([current_cmd, current_res])
        else:
            missing_actions_cfg_cmds.append(",".join(cfg_cmds))

        if each_step_cmds_results:
            uicli.uicli_log(each_step_cmds_results)

        return steps_results

    def run_uirest_script(self, devname, scriptname):
        devname = self._check_devname(devname)
        access = self._get_dev_access(devname)

        if access["filemode"]:
            return [False, 0, 0]

        msg = "Using script: script({})".format(scriptname)
        self.logger.info(msg)

        json_name = os.path.basename(scriptname)
        script_module = os.path.splitext(os.path.basename(scriptname))[0]

        try:
            with open(scriptname) as json_file:
                data = json.load(json_file)
        except Exception as e:
            self.logger.error(e)
            raise ValueError(e)

        pass_count = 0
        fail_count = 0
        invalid_count = 0

        uicli_scripts_root = os.path.join(os.path.dirname(__file__), '..', "datastore", "ui_cli", "json_scripts")
        autogen_params_file = os.path.join(os.path.abspath(uicli_scripts_root), "all_params.json")

        mappings_root = os.path.join(os.path.dirname(__file__), '..', "datastore", "ui_rest", "mappings")
        uirest_scripts_root = os.path.join(os.path.dirname(__file__), '..', "datastore", "ui_rest", "json_scripts")
        #uirest_scripts_root = os.path.join(os.path.dirname(__file__), '..', "datastore", "ui_rest", "json_scripts_test")

        path_args_file = os.path.join(os.path.abspath(uirest_scripts_root), "path_args.json")
        data_args_file = os.path.join(os.path.abspath(uirest_scripts_root), "data_args.json")

        msg = "Using path args file: params_file({})".format(path_args_file)
        self.logger.info(msg)
        msg = "Using data args file: params_file({})".format(data_args_file)
        self.logger.info(msg)
        msg = "Using autogen params file: params_file({})".format(autogen_params_file)
        self.logger.info(msg)

        try:
            with open(path_args_file) as json_file:
                all_path_args = json.load(json_file)
        except Exception as e:
            self.logger.error(e)
            raise ValueError(e)

        try:
            with open(data_args_file) as json_file:
                all_data_args = json.load(json_file)
        except Exception as e:
            self.logger.error(e)
            raise ValueError(e)

        try:
            with open(autogen_params_file) as json_file:
                all_params = json.load(json_file)
        except Exception as e:
            self.logger.error(e)
            raise ValueError(e)

        error_patterns = []
        for err, errinfo in list(access["errors"].items()):
            error_patterns.append(errinfo.search)

        tb_vars = SpyTestDict()
        tb_vars["connected_ports"] = []
        for each_link in self.wa.get_links(devname):
            tb_vars["connected_ports"].append(each_link[0])
        tb_vars["free_ports"] = self.wa.get_free_ports(devname)
        tb_vars["all_ports"] = self.wa.get_all_ports(devname)

        uirest = UIRest(self.logger, tb_vars)

        commands_and_results = []
        passed_list = []
        failed_list = []
        index = 0

        for step_entry in data["Steps"]:
            replaced_mode_values = SpyTestDict()
            replaced_cmd_params = SpyTestDict()

            index += 1

            # Get updated pre-configs section path args and data values
            uirest._uirest_get_preconfig_mode_path_values(all_path_args, all_params, step_entry, replaced_mode_values)
            uirest._uirest_get_preconfig_mode_data_values(all_data_args, all_params, step_entry, replaced_mode_values, replaced_cmd_params)

            # Get updated configs section path args and data values
            uirest._uirest_get_config_mode_path_values(all_path_args, all_params, step_entry, replaced_mode_values)
            uirest._uirest_get_config_mode_data_values(all_data_args, all_params, step_entry, replaced_mode_values, replaced_cmd_params)

            # Get updated actions section path args and data values
            uirest._uirest_get_action_mode_arg_values(all_path_args, all_params, step_entry, replaced_mode_values)
            uirest._uirest_get_action_cmd_param_values(all_data_args, all_params, step_entry, replaced_mode_values, replaced_cmd_params)

            # Get list of command params to check
            changed_steps = uirest._uirest_substitute_path_data_params(step_entry, all_data_args, all_params, replaced_mode_values, replaced_cmd_params)

            tmp_configs_section = step_entry.get("configs", None)
            tmp_config_step = tmp_configs_section[0]
            tmp_config_step_cmd = tmp_config_step.get("path", None)
            tmp_config_step_opt = tmp_config_step.get("operation", None)
            tmp_cmd_call = "{};{}".format(tmp_config_step_cmd, tmp_config_step_opt)

            try:
                all_step_results = []
                for changed_step in changed_steps:
                    single_steps_results = self._execute_uirest_step(uirest, devname, json_name, changed_step)
                    all_step_results.extend(single_steps_results)

                if "FAIL" in all_step_results:
                    fail_count += 1
                    failed_list.append([index, tmp_cmd_call])
                    commands_and_results.append(",".join([script_module, tmp_cmd_call, "FAIL"]))
                    continue

                pass_count += 1
                passed_list.append([index, tmp_cmd_call])
                commands_and_results.append(",".join([script_module, tmp_cmd_call, "PASS"]))

            except Exception as e:
                self.logger.error(e)
                fail_count += 1
                failed_list.append([index, tmp_cmd_call])
                commands_and_results.append(",".join([script_module, tmp_cmd_call, "FAIL"]))

        if commands_and_results:
            uirest.uirest_log("Commands and Results", footer=False)
            uirest.uirest_log(commands_and_results, header=False)

        res_list = [["PASS", pass_count], ["FAIL", fail_count], ["INVALID", invalid_count]]
        uirest.uirest_log(res_list)

        if fail_count > 0:
            return [False, pass_count, fail_count, passed_list, failed_list]

        return [True, pass_count, fail_count, passed_list, failed_list]

    def _execute_uirest_step(self, uirest, devname, filename, stepentry):
        steps_results = []
        each_step_cmds_results = []

        preconfigs_section = stepentry.get("pre-configs", None)
        configs_section = stepentry.get("configs", None)
        actions_section = stepentry.get("actions", None)

        # Execute pre-configs section
        if preconfigs_section:
            for config_step in preconfigs_section:
                step_name = config_step["name"]
                step_op = config_step["operation"]
                msg = "{}::{} {}".format(filename, step_name, step_op)
                utils.banner(msg, tnl=False)

                retval = self.rest_apply(devname, config_step)

                if not isinstance(retval, dict):
                    current_res = "FAIL"
                    steps_results.append(current_res)
                    each_step_cmds_results.append([msg, current_res])
                elif step_name not in retval:
                    current_res = "FAIL"
                    steps_results.append(current_res)
                    each_step_cmds_results.append([msg, current_res])
                else:
                    result_data = retval[step_name]
                    is_failed = False
                    if isinstance(result_data, list):
                        if not result_data[0]:
                            is_failed = True
                    elif isinstance(result_data, dict):
                        if "operation" not in result_data or "status" not in result_data or "output" not in result_data:
                            is_failed = True
                        elif "status" in result_data and result_data["status"] not in [200, 201, 202, 203, 204, 205, 404, 405]:
                            is_failed = True
                    else:
                        is_failed = True
                    if is_failed:
                        current_res = "FAIL"
                        steps_results.append(current_res)
                        each_step_cmds_results.append([msg, current_res])

        # Execute configs section
        if configs_section:
            for config_step in configs_section:
                step_name = config_step["name"]
                step_op = config_step["operation"]
                msg = "{}::{} {}".format(filename, step_name, step_op)
                utils.banner(msg, tnl=False)

                retval = self.rest_apply(devname, config_step)

                if not isinstance(retval, dict):
                    current_res = "FAIL"
                    steps_results.append(current_res)
                    each_step_cmds_results.append([msg, current_res])
                elif step_name not in retval:
                    current_res = "FAIL"
                    steps_results.append(current_res)
                    each_step_cmds_results.append([msg, current_res])
                else:
                    result_data = retval[step_name]
                    is_failed = False
                    if isinstance(result_data, list):
                        if not result_data[0]:
                            is_failed = True
                    elif isinstance(result_data, dict):
                        if "operation" not in result_data or "status" not in result_data or "output" not in result_data:
                            is_failed = True
                        elif "status" in result_data and result_data["status"] not in [200, 201, 202, 203, 204, 205, 404, 405]:
                            is_failed = True
                    else:
                        is_failed = True
                    if is_failed:
                        current_res = "FAIL"
                        steps_results.append(current_res)
                        each_step_cmds_results.append([msg, current_res])

        # Execute actions section
        if actions_section:
            for action_step in actions_section:
                step_name = action_step["name"]
                step_op = action_step["operation"]
                msg = "{}::{} {}".format(filename, step_name, step_op)
                utils.banner(msg, tnl=False)

                retval = self.rest_apply(devname, action_step)

                if not isinstance(retval, dict):
                    current_res = "FAIL"
                    steps_results.append(current_res)
                    each_step_cmds_results.append([msg, current_res])
                elif step_name not in retval:
                    current_res = "FAIL"
                    steps_results.append(current_res)
                    each_step_cmds_results.append([msg, current_res])
                else:
                    result_data = retval[step_name]
                    is_failed = False
                    if isinstance(result_data, list):
                        if not result_data[0]:
                            is_failed = True
                    elif isinstance(result_data, dict):
                        if "operation" not in result_data or "status" not in result_data or "output" not in result_data:
                            is_failed = True
                        elif "status" in result_data and result_data["status"] not in [200, 201, 202, 203, 204, 205, 404, 405]:
                            is_failed = True
                    else:
                        is_failed = True
                    if is_failed:
                        current_res = "FAIL"
                        steps_results.append(current_res)
                        each_step_cmds_results.append([msg, current_res])

        if each_step_cmds_results:
            uirest.uirest_log(each_step_cmds_results)

        return steps_results

    def run_uignmi_script(self, devname, scriptname, **kwargs):
        devname = self._check_devname(devname)
        access = self._get_dev_access(devname)

        if access["filemode"]:
            return ""

        msg = "Using script: script({})".format(scriptname)
        self.logger.info(msg)

        json_name = os.path.basename(scriptname)
        script_module = os.path.splitext(os.path.basename(scriptname))[0]

        try:
            with open(scriptname) as json_file:
                data = json.load(json_file)
        except Exception as e:
            self.logger.error(e)
            raise ValueError(e)

        pass_count = 0
        fail_count = 0
        invalid_count = 0

        uicli_scripts_root = os.path.join(os.path.dirname(__file__), '..', "datastore", "ui_cli", "json_scripts")
        autogen_params_file = os.path.join(os.path.abspath(uicli_scripts_root), "all_params.json")

        mappings_root = os.path.join(os.path.dirname(__file__), '..', "datastore", "ui_gnmi", "mappings")
        uignmi_scripts_root = os.path.join(os.path.dirname(__file__), '..', "datastore", "ui_rest", "json_scripts")

        path_args_file = os.path.join(os.path.abspath(uignmi_scripts_root), "path_args.json")
        data_args_file = os.path.join(os.path.abspath(uignmi_scripts_root), "data_args.json")

        msg = "Using path args file: params_file({})".format(path_args_file)
        self.logger.info(msg)
        msg = "Using data args file: params_file({})".format(data_args_file)
        self.logger.info(msg)
        msg = "Using autogen params file: params_file({})".format(autogen_params_file)
        self.logger.info(msg)

        try:
            with open(path_args_file) as json_file:
                all_path_args = json.load(json_file)
        except Exception as e:
            self.logger.error(e)
            raise ValueError(e)

        try:
            with open(data_args_file) as json_file:
                all_data_args = json.load(json_file)
        except Exception as e:
            self.logger.error(e)
            raise ValueError(e)

        try:
            with open(autogen_params_file) as json_file:
                all_params = json.load(json_file)
        except Exception as e:
            self.logger.error(e)
            raise ValueError(e)

        error_patterns = []
        for err, errinfo in list(access["errors"].items()):
            error_patterns.append(errinfo.search)

        tb_vars = SpyTestDict()
        tb_vars["connected_ports"] = []
        for each_link in self.wa.get_links(devname):
            tb_vars["connected_ports"].append(each_link[0])
        tb_vars["free_ports"] = self.wa.get_free_ports(devname)
        tb_vars["all_ports"] = self.wa.get_all_ports(devname)

        uignmi = UIGnmi(self.logger, tb_vars)

        commands_and_results = []
        passed_list = []
        failed_list = []
        index = 0
        for step_entry in data["Steps"]:
            replaced_mode_values = SpyTestDict()
            replaced_cmd_params = SpyTestDict()

            index += 1

            # Get updated pre-configs section path args and data values
            uignmi._uignmi_get_preconfig_mode_path_values(all_path_args, all_params, step_entry,
                                                          replaced_mode_values)
            uignmi._uignmi_get_preconfig_mode_data_values(all_data_args, all_params, step_entry,
                                                          replaced_mode_values, replaced_cmd_params)

            # Get updated configs section path args and data values
            uignmi._uignmi_get_config_mode_path_values(all_path_args, all_params, step_entry, replaced_mode_values)
            uignmi._uignmi_get_config_mode_data_values(all_data_args, all_params, step_entry, replaced_mode_values,
                                                       replaced_cmd_params)

            # Get updated actions section path args and data values
            uignmi._uignmi_get_action_mode_arg_values(all_path_args, all_params, step_entry, replaced_mode_values)
            uignmi._uignmi_get_action_cmd_param_values(all_data_args, all_params, step_entry, replaced_mode_values,
                                                       replaced_cmd_params)

            # Get list of command params to check
            changed_steps = uignmi._uignmi_substitute_path_data_params(step_entry, all_data_args, all_params,
                                                                       replaced_mode_values, replaced_cmd_params)

            tmp_configs_section = step_entry.get("configs", None)
            tmp_config_step = tmp_configs_section[0]
            tmp_config_step_cmd = tmp_config_step.get("path", None)
            tmp_config_step_opt = tmp_config_step.get("operation", None)
            tmp_cmd_call = "{};{}".format(tmp_config_step_cmd, tmp_config_step_opt)
            if tmp_config_step_opt not in ["get", "patch", "delete"]: continue
            try:
                all_step_results = []
                kwargs.update({"mgmt_ip":access["connection_param"].get("mgmt-ip")})
                for changed_step in changed_steps:
                    single_steps_results = self._execute_uignmi_step(uignmi, devname, json_name, changed_step,
                                                                     **kwargs)
                    all_step_results.extend(single_steps_results)

                if "FAIL" in all_step_results:
                    fail_count += 1
                    failed_list.append([index, tmp_cmd_call])
                    commands_and_results.append(",".join([script_module, tmp_cmd_call, "FAIL"]))
                    continue

                pass_count += 1
                passed_list.append([index, tmp_cmd_call])
                commands_and_results.append(",".join([script_module, tmp_cmd_call, "PASS"]))

            except Exception as e:
                self.logger.error(e)
                fail_count += 1
                failed_list.append([index, tmp_cmd_call])
                commands_and_results.append(",".join([script_module, tmp_cmd_call, "FAIL"]))

        if commands_and_results:
            uignmi.uignmi_log("Commands and Results", footer=False)
            uignmi.uignmi_log(commands_and_results, header=False)

        res_list = [["PASS", pass_count], ["FAIL", fail_count], ["INVALID", invalid_count]]
        uignmi.uignmi_log(res_list)

        if fail_count > 0:
            return [False, pass_count, fail_count, passed_list, failed_list]

        return [True, pass_count, fail_count, passed_list, failed_list]

    def _execute_uignmi_step(self, uignmi, devname, filename, stepentry, **kwargs):
        steps_results = []
        each_step_cmds_results = []

        preconfigs_section = stepentry.get("pre-configs", None)
        configs_section = stepentry.get("configs", None)
        actions_section = stepentry.get("actions", None)

        # Execute pre-configs section
        if preconfigs_section:
            for config_step in preconfigs_section:
                step_name = config_step["name"]
                step_op = config_step["operation"]
                if step_op not in ["get", "patch", "delete"]: continue
                msg = "{}::{} {}".format(filename, step_name, step_op)
                utils.banner(msg, tnl=False)

                retval = self.gnmi_apply(devname, config_step, **kwargs)

                if (step_op != "get" and not retval) or (step_op == "get" and not isinstance(retval, dict)):
                    current_res = "FAIL"
                    steps_results.append(current_res)
                    each_step_cmds_results.append([msg, current_res])

        # Execute configs section
        if configs_section:
            for config_step in configs_section:
                step_name = config_step["name"]
                step_op = config_step["operation"]
                if step_op not in ["get", "patch", "delete"]: continue
                msg = "{}::{} {}".format(filename, step_name, step_op)
                utils.banner(msg, tnl=False)

                retval = self.gnmi_apply(devname, config_step, **kwargs)

                if (step_op != "get" and not retval) or (step_op == "get" and not isinstance(retval, dict)):
                    current_res = "FAIL"
                    steps_results.append(current_res)
                    each_step_cmds_results.append([msg, current_res])

        # Execute actions section
        if actions_section:
            for action_step in actions_section:
                step_name = action_step["name"]
                step_op = action_step["operation"]
                if step_op not in ["get", "patch", "delete"]: continue
                msg = "{}::{} {}".format(filename, step_name, step_op)
                utils.banner(msg, tnl=False)

                retval = self.gnmi_apply(devname, config_step, **kwargs)

                if (step_op != "get" and not retval) or (step_op == "get" and not isinstance(retval, dict)):
                    current_res = "FAIL"
                    steps_results.append(current_res)
                    each_step_cmds_results.append([msg, current_res])

        if each_step_cmds_results:
            uignmi.uignmi_log(each_step_cmds_results)
        return steps_results

    def _gnmi_set(self, devname, xpath, **kwargs):
        """
        API to set GNMI configuration
        Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
        :param dut:
        :param xpath:
        :param json_content:
        :param kwargs:
        :return:
        """
        self.logger.info("Performing GNMI SET OPERATION ...")
        json_content = kwargs.get("json_content")

        if json_content:
            temp_dir = tempfile.gettempdir()
            current_datetime = utils.get_current_datetime()
            file_name = "sonic_uignmi_{}.json".format(current_datetime)
            tmp_path = "{}/{}".format(temp_dir, file_name)
            rm_cmds = ['rm {}'.format(tmp_path)]
            kwargs.update({"devname": devname})
            kwargs.update({"json_content": json_content})
            kwargs.update({"data_file_path": tmp_path})
            command = self._prepare_gnmi_command(xpath, **kwargs)
            file_operation = utils.write_to_json_file(json_content, tmp_path)
            if not file_operation:
                self.logger.error("File operation failed.")
                return False
            container_crash_err_strngs = ["transport is closing", "connection refused", "Error response from daemon:"]
            docker_crash = False
            docker_status_cmd = "docker inspect -f '{{.State.Running}}' telemetry"
            # output = self.config_new(devname, command, skip_error_check=True)
            output = self._run_gnmi_command(command)
            self.logger.debug("OUTPUT : {}".format(output))
            for rm_cmd in rm_cmds:
                self._run_gnmi_command(rm_cmd)
            if output.get("error"):
                for err_code_str in container_crash_err_strngs:
                    if err_code_str in output.get("error"):
                        self.logger.info("Observed {} error, may be telemetry docker got crashed".format(err_code_str))
                        docker_crash = True
                        break
                if not docker_crash:
                    self.logger.info(output.get("error"))
                    return False
                if docker_crash:
                    timeout = 300
                    curr_time = 0
                    wait_time = 10
                    iteration = 1
                    check_flag = True
                    itr_msg = "ITERATION {} : Observed that telemetry docker is not running or crashed, hence waiting for {} secs"
                    while curr_time < timeout:
                        status_output = self.config_new(devname, docker_status_cmd, skip_error_check=True)
                        self.logger.info(itr_msg.format(iteration, wait_time))
                        if ("true" not in status_output) or ("transport is closing" in output.get("error") and "true" in status_output):
                            self.wait(wait_time)
                            curr_time += wait_time
                            check_flag = False
                            iteration +=1
                            if iteration > 3 and "true" in status_output:
                                return False
                            continue
                        else:
                            check_flag = True
                            break
                    if not check_flag:
                        self.logger.info("ERROR code observed with telemetry docker...")
                        return False
                    if curr_time >= timeout:
                        self.logger.info("Max retries reached")
                        return False
                else:
                    self.logger.info(output.get("error"))
                    return False
            return output
        else:
            self.logger.info("Could not find JSON CONTENT for SET operation")
            return False

    def _gnmi_get(self, devname, xpath, **kwargs):
        """
        API to do GNMI get operations
        Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
        :param dut:
        :param xpath:
        :param kwargs:
        :return:
        """
        self.logger.info("Performing GNMI GET OPERATION ...")
        skip_tmpl = kwargs.get('skip_tmpl', False)

        result = dict()
        try:
            kwargs.update({"devname": devname})
            command = self._prepare_gnmi_command(xpath, **kwargs)
            docker_status_cmd = "docker inspect -f '{{.State.Running}}' telemetry"
            container_crash_err_strngs = ["transport is closing", "connection refused", "Error response from daemon:"]
            docker_crash = False
            output = self._run_gnmi_command(command)
            # output = self.show(devname, command, skip_tmpl=skip_tmpl, skip_error_check=True)
            if output.get("error"):
                for err_code_str in container_crash_err_strngs:
                    if err_code_str in output.get("error"):
                        self.logger.info("Observed {} error, may be telemetry docker got crashed".format(err_code_str))
                        docker_crash = True
                        break
                if not docker_crash:
                    self.logger.info(output.get("error"))
                    return False
                if docker_crash:
                    timeout = 300
                    curr_time = 0
                    wait_time = 10
                    iteration = 1
                    check_flag = True
                    itr_msg = "ITERATION {} : Observed that telemetry docker is not running or crashed, hence waiting for {} secs"
                    while curr_time < timeout:
                        status_output = self.config_new(devname, docker_status_cmd, skip_error_check=True)
                        self.logger.info(itr_msg.format(iteration, wait_time))
                        if ("true" not in status_output) or (
                                "transport is closing" in output.get("error") and "true" in status_output):
                            self.wait(wait_time)
                            curr_time += wait_time
                            check_flag = False
                            iteration += 1
                            if iteration > 3 and "true" in status_output:
                                return False
                            continue
                        else:
                            check_flag = True
                            break
                    if not check_flag:
                        self.logger.info("ERROR code observed with telemetry docker...")
                        return False
                    if curr_time >= timeout:
                        self.logger.info("Max retries reached")
                        return False
                else:
                    self.logger.info(output.get("error"))
                    return False
            else:
                return output
        except Exception as e:
            self.logger.error(e)
            return False

    def _gnmi_delete(self, devname, xpath, **kwargs):
        """
        API to do GNMI get operations
        Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
        :param dut:
        :param xpath:
        :param kwargs:
        :return:
        """
        self.logger.info("Performing GNMI DELETE OPERATION ...")
        try:
            kwargs.update({"devname":devname})
            command = self._prepare_gnmi_command(xpath, **kwargs)
            container_crash_err_strngs = ["transport is closing", "connection refused", "Error response from daemon:"]
            docker_crash = False
            docker_status_cmd = "docker inspect -f '{{.State.Running}}' telemetry"
            output = self._run_gnmi_command(command)
            # output = self.config_new(devname, command, skip_error_check=True)
            self.logger.debug("OUTPUT : {}".format(output))
            if output.get("error"):
                for err_code_str in container_crash_err_strngs:
                    if err_code_str in output.get("error"):
                        self.logger.info("Observed {} error, may be telemetry docker got crashed".format(err_code_str))
                        docker_crash = True
                        break
                if not docker_crash:
                    self.logger.info(output.get("error"))
                    return False
                if docker_crash:
                    timeout = 300
                    curr_time = 0
                    wait_time = 10
                    iteration = 1
                    check_flag = True
                    itr_msg = "ITERATION {} : Observed that telemetry docker is not running or crashed, hence waiting for {} secs"
                    while curr_time < timeout:
                        status_output = self.config_new(devname, docker_status_cmd, skip_error_check=True)
                        self.logger.info(itr_msg.format(iteration, wait_time))
                        if ("true" not in status_output) or ("transport is closing" in output.get("error") and "true" in status_output):
                            self.wait(wait_time)
                            curr_time += wait_time
                            check_flag = False
                            iteration +=1
                            if iteration > 3 and "true" in status_output:
                                return False
                            continue
                        else:
                            check_flag = True
                            break
                    if not check_flag:
                        self.logger.info("ERROR code observed with telemetry docker...")
                        return False
                    if curr_time >= timeout:
                        self.logger.info("Max retries reached")
                        return False
                else:
                    self.logger.info(output.get("error"))
                    return False
            return output
        except Exception as e:
            self.logger.error(e)
            return False

    def _prepare_gnmi_command(self, xpath, **kwargs):
        credentials = self.get_credentials(kwargs.get("devname"))
        ip_address = kwargs.get('mgmt_ip', '127.0.0.1')
        port = kwargs.get('port', '8080')
        insecure = kwargs.get('insecure', '')
        username = kwargs.get('username', credentials[0])
        password = kwargs.get('password', credentials[3])
        # gnmi_utils_path = kwargs.get("gnmi_utils_path", ".")
        gnmi_utils_path = "/tmp"
        cert = kwargs.get('cert')
        action = kwargs.get("action", "get")
        pretty = kwargs.get('pretty')
        logstostderr = kwargs.get('logstostderr')
        mode = kwargs.get('mode', '--update')
        docker_path = kwargs.get("docker_path")
        docker_command = "docker exec -it telemetry bash"
        if action == "get":
            gnmi_command = 'gnmi_get -xpath {} -target_addr {}:{}'.format(xpath, ip_address, port)
            """
            if username:
                gnmi_command += " --username {}".format(username)
            if password:
                gnmi_command += " --password {}".format(password)
            if cert:
                gnmi_command += " --cert {}".format(cert)
            gnmi_command += " --insecure {}".format(insecure)
            gnmi_command += " --logtostderr"
            command = '{}/{}'.format(gnmi_utils_path, gnmi_command)
            return command
            """
        elif action == "set":
            gnmi_command = 'gnmi_set {} {}:@{} --target_addr {}:{}'.format(mode, xpath, kwargs.get("data_file_path"), ip_address, port)
            if pretty:
                gnmi_command += " --pretty"
            """
            if username:
                gnmi_command += " --username {}".format(username)
            if password:
                gnmi_command += " --password {}".format(password)
            if cert:
                gnmi_command += " --cert {}".format(cert)
            if pretty:
                gnmi_command += " --pretty"
            gnmi_command += " --insecure {}".format(insecure)
            gnmi_command += " --logtostderr"
            command = '{}/{}'.format(gnmi_utils_path, gnmi_command)
            return command
            """
        elif action == "delete":
            gnmi_command = 'gnmi_set --delete {} --target_addr {}:{}'.format(xpath, ip_address, port)
            """
            if username:
                gnmi_command += " --username {}".format(username)
            if password:
                gnmi_command += " --password {}".format(password)
            if cert:
                gnmi_command += " --cert {}".format(cert)
            gnmi_command += " --insecure {}".format(insecure)
            gnmi_command += " --logtostderr"
            command = '{}/{}'.format(gnmi_utils_path, gnmi_command)
            return command
            """
        if username:
            gnmi_command += " --username {}".format(username)
        if password:
            gnmi_command += " --password {}".format(password)
        if cert:
            gnmi_command += " --cert {}".format(cert)
        gnmi_command += " --insecure {}".format(insecure)
        gnmi_command += " --logtostderr"
        command = '{}/{}'.format(gnmi_utils_path, gnmi_command)
        return command

    def gnmi_apply(self, devname, config_step, **kwargs):
        operation = config_step["operation"]
        if operation == "patch":
            action = "set"
        elif operation == "delete":
            action = "delete"
        else:
            action = "get"
        xpath = config_step["path"]
        gnmi_utils_path = os.path.join(os.path.dirname(__file__), "..","tests", "ui_gnmi","utilities")
        gnmi_utils_abs_path = os.path.abspath(gnmi_utils_path)
        self.logger.info("GNMI UTILS PATH - {}".format(gnmi_utils_abs_path))
        kwargs.update({"gnmi_utils_path":gnmi_utils_abs_path})
        kwargs.update({"json_content":config_step["data"]})
        kwargs.update({"action":action})
        kwargs.update({"skip_tmpl":True})
        if action == "get":
            return self._gnmi_get(devname, xpath, **kwargs)
        elif action == "set":
            return self._gnmi_set(devname, xpath, **kwargs)
        elif action == "delete":
            return self._gnmi_delete(devname, xpath, **kwargs)
        else:
            self.logger.info("Invalid operation for GNMI -- {}".format(action))
            return False

    def _run_gnmi_command(self, command):
        result = dict()
        self.logger.info("CMD: {}".format(command))
        process = subprocess.Popen(shlex.split(command), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        data, error = process.communicate()
        rc = process.poll()
        result.update({"output": data})
        result.update({"rc": rc})
        result.update({"error": error})
        self.logger.info("RESULT {}".format(result))
        return result

    def dump_all_commands(self, devname, type='click'):
        self._apply_remote(devname, "dump-click-cmds")

