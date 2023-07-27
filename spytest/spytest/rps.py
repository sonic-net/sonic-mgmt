import os
import sys
import time
import logging
import telnetlib
import requests
import getpass
import subprocess

from utilities import ctrl_chars
from utilities.common import write_file
from utilities.common import make_list
from utilities.common import parse_integer


class RPS(object):

    def __init__(self, model, ip, port, outlet, username, password, logger=None,
                 dbg_lvl=0, dut="", console_ip=None, console_port=None):
        """
        Construction of the RPS object
        :param model: RPS Model Raritan/ServerTech/Avocent/AvocentRoot/PX3/APCMIB
        :type model: basestring
        :param ip: IPv4 Address to Telnet
        :type ip:
        :param port: IPv4 Port to Telnet
        :type port:
        :param outlet:
        :type outlet:
        :param username:
        :type username: basestring
        :param password:
        :type password: basestring
        :param logger:
        :type logger:
        """
        self._grub_prompt = "grub>"
        self._grub_rescue_prompt = "grub rescue>"
        self._grub_prompts = [self._grub_rescue_prompt, self._grub_prompt]
        self.logger = logger or logging.getLogger()
        self.tn = None
        self.model = model
        self.ip = ip
        self.port = port
        self.outlet = outlet
        self.pdu_id = None
        self.username = username
        self.password = password
        self.dut = dut
        self.console_ip = console_ip
        self.console_port = console_port
        self.timeout = 600
        self.dbg_lvl = dbg_lvl
        self.off_delay = 5
        self.on_delay = 90
        self.disc_delay = 0
        self.max_connect_try = 5
        self.login_prompt_timeout = 60
        self.multi_support = False
        self.rest_url = None
        self.rest_method = 'get'
        self.rest_auth = None
        self.rest_params = {}
        self.rest_headers = {'accept': 'text/html,application/json'}
        self.protocol = "telnet"
        self.use_linux_connection = True
        self.use_native_netmiko = False
        self.use_paramiko = False
        self.send_prefix = " >>> "
        self.recv_prefix = " <<< "
        if self.model == "Raritan":
            self.login_prompt = "Login:"
            self.password_prompt = "Password:"
            self.base_prompt = ">"
            self.base_prompt = "clp:/->"
            self.fail_msg = "Login failed."
            self.disc_delay = 10
        elif self.model == "PX3":
            self.login_prompt = "Login for PX3 CLI"
            self.login_prompt = "Username:"
            self.password_prompt = "Password:"
            self.base_prompt = "#"
            self.fail_msg = "Login failed."
            self.disc_delay = 10
            self.off_delay = 30
            self.on_delay = 120
        elif self.model == "APCMIB":
            pass
        elif self.model == "ServerTech":
            self.login_prompt = "Username:"
            self.password_prompt = "Password:"
            self.base_prompt = "Sentry:|Switched CDU:|Switched PDU:"
            self.fail_msg = "Access denied"
            self.disc_delay = 10
            self.off_delay = 10
        elif self.model == "Avocent":
            self.login_prompt = "login:"
            self.password_prompt = "Password:"
            self.base_prompt = "cli->"
            self.base_prompt2 = "cli->"
            self.confirm_prompt = " (yes, no)"
            self.fail_msg = "Access denied"
            self.off_delay = 30
            self.on_delay = 120
            self.multi_support = True
        elif self.model == "AvocentRoot":
            self.login_prompt = "login:"
            self.password_prompt = "Password:"
            self.base_prompt2 = "#"
            self.base_prompt = "cli->"
            self.confirm_prompt = " (yes, no)"
            self.fail_msg = "Access denied"
            self.off_delay = 30
            self.on_delay = 120
            self.multi_support = True
        elif self.model == "pConnect":
            self.rest_url = 'http://{}/tool/connect.php'.format(ip)
            self.rest_params = {'device': outlet, 'as': username or getpass.getuser()}
            self.on_delay = 120
        elif self.model in ["vsh", "svsh", "lxc", "virsh"]:
            self.protocol = "telnet" if self.model == "vsh" else "ssh"
            self.login_prompt = ""
            self.password_prompt = ""
            self.base_prompt2 = "#"
            self.base_prompt = "#"
            self.confirm_prompt = ""
            self.fail_msg = "Access denied"
            self.off_delay = 30
            self.on_delay = 120
        else:
            msg = "TODO: model={}".format(self.model)
            self.logmsg(msg, lvl=logging.WARNING)
            self.multi_support = False

        self.on_delay = parse_integer(os.getenv("SPYTEST_RPS_ON_DELAY", str(self.on_delay)))
        self.off_delay = parse_integer(os.getenv("SPYTEST_RPS_OFF_DELAY", str(self.off_delay)))
        self.disc_delay = parse_integer(os.getenv("SPYTEST_RPS_DISC_DELAY", str(self.disc_delay)))

    def bldmsg(self, msg, prefix=""):
        lines = []
        if self.dut:
            prefix2 = "RPS({}):{} ".format(self.dut, prefix)
        else:
            prefix2 = "RPS:{} ".format(prefix)
        for line in msg.splitlines():
            lines.append("{}{}".format(prefix2, line))
        return lines

    def logmsg(self, msg, lvl=logging.INFO, prefix=""):
        for line in self.bldmsg(msg, prefix=prefix):
            self.logger.log(lvl, line)

    def has_multi_support(self):
        return self.multi_support

    def set_pdu_id(self, pdu_id):
        self.pdu_id = pdu_id

    def merge_dict(self, d1, d2):
        retval = {}
        retval.update(d1)
        retval.update(d2)
        return retval

    def _rest_send(self, method=None, url=None, params=None, data=None, auth=None, headers=None):
        params = params or {}
        headers = headers or {}
        method = method or self.rest_method
        url = url or self.rest_url
        auth = auth or (requests.auth.HTTPBasicAuth(self.username, self.password)
                        if self.username and self.password else self.rest_auth)
        self.logmsg("requesting : {}".format(url))
        new_params = self.merge_dict(params, self.rest_params)
        new_headers = self.merge_dict(headers, self.rest_headers)
        func = getattr(requests, method)
        res = func(url, params=new_params, data=data, auth=auth, headers=new_headers, timeout=300)
        self.logmsg(res.text)
        if res.status_code != 200:
            self.logmsg("Request Error: {}".format(res.status_code), lvl=logging.WARNING)
        else:
            self.logmsg("Request completed!", lvl=logging.WARNING)
        return res

    def connect(self, base_prompt=None):

        if self.model in ["APCMIB"]: return True

        # no need to connect if we are using rest
        if self.rest_url: return True

        if self.protocol == "ssh":
            for retry in range(1, self.max_connect_try + 1):
                msg = "connect {}:{} try {}".format(self.ip, self.port, retry)
                self.logmsg(msg, lvl=logging.WARNING)
                try:
                    rps_server = {'device_type': "linux", 'ip': self.ip, 'port': self.port,
                                  'username': self.username, 'password': self.password,
                                  "global_delay_factor": 10}
                    if self.use_linux_connection:
                        from spytest.access.linux_connection import LinuxConnection as LinuxDeviceConnection
                        self.tn = LinuxDeviceConnection(logger=self.logger, **rps_server)
                        self.base_prompt = self.tn.init_prompt()
                    elif self.use_native_netmiko:
                        from netmiko import ConnectHandler
                        self.tn = ConnectHandler(**rps_server)
                        self.base_prompt = self.tn.find_prompt()
                    elif not self.use_paramiko:
                        from spytest.access.connection import DeviceConnection as NetmikoDeviceConnection
                        self.tn = NetmikoDeviceConnection(devname=None, logger=self.logger, **rps_server)
                        self.base_prompt = self.tn.init_prompt()
                    else:
                        from spytest.access.paramiko_connection import DeviceConnection as ParamikoDeviceConnection
                        self.tn = ParamikoDeviceConnection("ssh", self.ip, self.port,
                                                           self.username, self.password)
                        self.tn.set_logger(self.logger)
                        # self.tn.set_log_level(None, True)
                        self.tn.connect()
                        self.base_prompt = self.tn.init_prompt()
                    return True
                except Exception as e:
                    msg = "connection failed {}".format(e)
                    self.logmsg(msg, lvl=logging.ERROR)
                    self.tn = None
                    if retry >= self.max_connect_try:
                        return False
                    self._wait(5)

        for retry in range(1, self.max_connect_try + 1):
            msg = "connect {}:{} try {}".format(self.ip, self.port, retry)
            self.logmsg(msg, lvl=logging.WARNING)
            try:
                self.tn = telnetlib.Telnet(self.ip, port=self.port)
                break
            except Exception as e:
                msg = "connection failed {}".format(e)
                self.logmsg(msg, lvl=logging.ERROR)
                self.tn = None
                if retry >= self.max_connect_try:
                    return False
                self._wait(5)

        self.tn.set_debuglevel(self.dbg_lvl)

        if len(self.username) == 0 or len(self.login_prompt) == 0:
            self._write("", self.base_prompt)
            return True

        try:
            self.tn_read_until(self.tn, self.login_prompt, self.login_prompt_timeout)
        except EOFError as e:
            msg = "connection closed {}".format(e)
            self.logmsg(msg, lvl=logging.ERROR)
            return False

        if not base_prompt:
            if self.model == "AvocentRoot":
                base_prompt = self.base_prompt2
            else:
                base_prompt = self.base_prompt

        if self.password:
            self._write(self.username, self.password_prompt)
            if not self._write(self.password, base_prompt, self.fail_msg):
                self.logmsg("Invalid username/password", lvl=logging.WARNING)
                return False
        else:
            self._write(self.username, base_prompt)

        if self.model == "AvocentRoot":
            self._write("cli", self.base_prompt)

        return True

    def disconnect(self):
        self.logmsg("disconnect", lvl=logging.WARNING)
        try: self.tn.disconnect()
        except Exception: pass
        self.tn = None
        if self.disc_delay > 0:
            self._wait(self.disc_delay)

    def _wait(self, val):
        self.logmsg("wait {}".format(val), lvl=logging.WARNING)
        time.sleep(val)

    def _encode(self, s):
        if sys.version_info[0] >= 3:
            s = str.encode(s)
        return s

    def _decode(self, s):
        if sys.version_info[0] >= 3:
            if s is not None:
                s = s.decode(errors='ignore')
        return s

    def _write(self, cmd, pass_msg=None, fail_msg=None, timeout=10, log_file=None, prompt=None):
        self.logmsg("sending '{}'".format(cmd))

        if self.protocol == "ssh":
            rv, max_attempts = "", 3
            for attempt in range(max_attempts):
                try:
                    if self.use_native_netmiko:
                        rv = self.tn.send_command(cmd, strip_prompt=False)
                    elif self.use_paramiko:
                        rv = self.tn.send_command(cmd, prompt, timeout=timeout, wait_time=5)
                    else:
                        rv = self.tn.send_command(cmd, prompt or self.base_prompt,
                                                  strip_prompt=False, strip_command=False)
                    break
                except Exception as e:
                    msg = "failed to execute {}: {}/{} {}".format(cmd, attempt, max_attempts, e)
                    for line in self.bldmsg(msg):
                        try: self.tn.log_exception(line, dump=True, prefix="")
                        except Exception: self.logmsg(line, lvl=logging.ERROR)
                    if attempt >= max_attempts:
                        return None
                    self._wait(60)
        else:
            rv = self.tn_write(self.tn, cmd + "\r\n")
            if pass_msg:
                try:
                    rv = self.tn_read_until(self.tn, pass_msg, timeout)
                except EOFError as e:
                    msg = "connection closed {}".format(e)
                    self.logmsg(msg, lvl=logging.ERROR)
                    return None

        rv2 = ctrl_chars.tostring(rv)
        if log_file is None:
            rv2 = rv2.lstrip()
            self.logmsg(rv2, prefix=self.recv_prefix)
        else:
            write_file(log_file, rv2)

        if fail_msg and fail_msg in rv:
            msg = "UnExpected text '{}' is seen".format(fail_msg)
            self.logmsg(msg, lvl=logging.ERROR)
            self.logmsg(rv, lvl=logging.ERROR)
            return None

        if pass_msg:
            for msg in make_list(pass_msg):
                if msg in rv:
                    return rv
            for msg in make_list(pass_msg):
                msg = "Expected text '{}' not seen".format(msg)
                self.logmsg(msg, lvl=logging.ERROR)
            self.logmsg(rv, lvl=logging.ERROR)
            return None

        return rv

    def do_op(self, op, on_delay=None, off_delay=None, outlet=None, disc=True, log_file=None):
        op = op.lower()
        if op == "on":
            return self.on(disc, on_delay, outlet, log_file=log_file)
        elif op == "off":
            return self.off(disc, off_delay, outlet, log_file=log_file)
        elif op == "reset":
            return self.reset(disc, on_delay, off_delay, outlet, log_file=log_file)
        elif op in ["debug", "dbg"]:
            return self.debug(disc, outlet, log_file=log_file, op=op)
        else:
            return False

    def off_on(self, disc=True, on_delay=None, off_delay=None, outlet=None, log_file=None):

        if not self.tn: self.connect()
        if not self.tn: return False
        rv1 = self.off(False, off_delay, outlet)
        rv2 = self.on(False, on_delay, outlet)
        if disc: self.disconnect()

        return bool(rv1 and rv2)

    def snmp_set(self, outlet, val):
        cmd = "snmpset -v1 -c private {} iso.3.6.1.4.1.318.1.1.4.4.2.1.3.{} i {}".format(self.ip, outlet, val)
        pprocess = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    universal_newlines=True)
        stdout, stderr = pprocess.communicate()
        self.logmsg("SNMP stdout: {}".format(stdout))
        self.logmsg("SNMP stderr: {}".format(stderr))

    def reset(self, disc=True, on_delay=None, off_delay=None, outlet=None, log_file=None):

        self.logmsg("powering reboot", lvl=logging.WARNING)

        try:
            pre_wait = int(os.getenv("SPYTEST_RPS_PRE_RESET_WAIT", "0"))
            if pre_wait > 0: self._wait(pre_wait)
        except Exception:
            self.logmsg("Exception in pre-reset wait", lvl=logging.WARNING)

        if self.model == 'pConnect':
            res = self._rest_send(params={'action': 'reboot'})
            retval = bool('exit code: 0' in res.text)
            if retval:
                self._wait(self.on_delay)
            return retval

        # use defaults if not specified
        if outlet is None: outlet = self.outlet
        if off_delay is None: off_delay = self.off_delay
        if on_delay is None: on_delay = self.on_delay

        # connect if not already done
        if not self.tn:
            if not self.connect():
                self.logmsg("failed to connect", lvl=logging.WARNING)
                return False

        retval = True
        if self.model == "Raritan":
            retval = self.off_on(False, 0, off_delay, outlet)
        elif self.model == "PX3":
            self._write("power outlets {} cycle /y".format(outlet), self.base_prompt)
        elif self.model == "APCMIB":
            self.snmp_set(outlet, 3)
        elif self.model == "ServerTech":
            self._write("reboot {}".format(outlet), self.base_prompt)
            # retval = self.off_on(False, 0, off_delay, outlet)
        elif self.model == "Avocent" or self.model == "AvocentRoot":
            retval = self.off_on(False, 0, off_delay, outlet)
        elif self.model in ["vsh", "svsh", "lxc", "virsh"]:
            retval = self.off_on(False, 0, off_delay, outlet)
        else:
            msg = "TODO: off {}".format(self.model)
            self.logmsg(msg, lvl=logging.WARNING)

        # wait for on delay
        if retval and on_delay > 0: self._wait(on_delay)

        # disconnect if required
        if disc: self.disconnect()

        return retval

    def off(self, disc=True, off_delay=None, outlet=None, log_file=None):

        # use defaults if not specified
        if outlet is None: outlet = self.outlet
        if off_delay is None: off_delay = self.off_delay

        self.logmsg("powering off {}".format(outlet), lvl=logging.WARNING)

        # connect if not already done
        if not self.tn:
            if not self.connect():
                self.logmsg("failed to connect", lvl=logging.WARNING)
                return False

        retval = True
        if self.model == "Raritan":
            cmd = "set /system1/outlet{} powerstate=off".format(outlet)
            self._write(cmd, self.base_prompt)
        elif self.model == "PX3":
            self._write("power outlets {} off /y".format(outlet), self.base_prompt)
        elif self.model == "APCMIB":
            self.snmp_set(outlet, 2)
        elif self.model == "ServerTech":
            self._write("off {}".format(outlet), self.base_prompt)
        elif self.model == "Avocent" or self.model == "AvocentRoot":
            if not self.pdu_id:
                self.logmsg("PDU_ID must be set for Avocent", lvl=logging.ERROR)
            else:
                self._cmd_avocent("off", disc, outlet)
        elif self.model == 'pConnect':
            res = self._rest_send(params={'action': 'off'})
            retval = bool('exit code: 0' in res.text)
        elif self.model in ["vsh"]:
            cmd = "vsh-rps off {}".format(outlet)
            self._write("", self.base_prompt.replace("\\", ""))
            self._write(cmd, "The device is powered off successfully", timeout=300)
            self._write("", self.base_prompt.replace("\\", ""))
        elif self.model in ["svsh"]:
            cmd = "vsh-rps off {}".format(outlet)
            expected = ["The device is powered off successfully"]
            expected.append("The device is not on")
            self._write("", self.base_prompt.replace("\\", ""))
            retval = self._write(cmd, expected, timeout=300, prompt=self.base_prompt)
        elif self.model in ["lxc"]:
            cmd = "lxc-rps off {}".format(outlet)
            expected = ["The device is powered off successfully"]
            expected.append("The device is not on")
            self._write("", self.base_prompt.replace("\\", ""))
            retval = self._write(cmd, expected, timeout=300, prompt=self.base_prompt)
        elif self.model in ["virsh"]:
            cmd = "virsh-rps off {}".format(outlet)
            expected = ["The device is powered off successfully"]
            expected.append("The device is not on")
            self._write("", self.base_prompt.replace("\\", ""))
            retval = self._write(cmd, expected, timeout=300, prompt=self.base_prompt)
        else:
            msg = "TODO: off {}".format(self.model)
            self.logmsg(msg, lvl=logging.WARNING)

        # wait for off delay
        if retval and off_delay > 0: self._wait(off_delay)

        # disconnect if required
        if disc: self.disconnect()

        return retval

    def on(self, disc=True, on_delay=None, outlet=None, log_file=None):

        # use defaults if not specified
        if outlet is None: outlet = self.outlet
        if on_delay is None: on_delay = self.on_delay

        self.logmsg("powering on {}".format(outlet), lvl=logging.WARNING)

        # connect if not already done
        if not self.tn:
            if not self.connect():
                self.logmsg("failed to connect", lvl=logging.WARNING)
                return False

        retval = True
        if self.model == "Raritan":
            cmd = "set /system1/outlet{} powerstate=on".format(outlet)
            self._write(cmd, self.base_prompt)
        elif self.model == "PX3":
            self._write("power outlets {} on /y".format(outlet), self.base_prompt)
        elif self.model == "APCMIB":
            self.snmp_set(outlet, 1)
        elif self.model == "ServerTech":
            self._write("on {}".format(outlet), self.base_prompt)
        elif self.model == "Avocent" or self.model == "AvocentRoot":
            if not self.pdu_id:
                self.logmsg("PDU_ID must be set for Avocent", lvl=logging.ERROR)
            else:
                self._cmd_avocent("on", disc, outlet)
        elif self.model == 'pConnect':
            res = self._rest_send(params={'action': 'on'})
            retval = bool('exit code: 0' in res.text)
        elif self.model in ["vsh"]:
            cmd = "vsh-rps on {}".format(outlet)
            self._write("", self.base_prompt.replace("\\", ""))
            self._write(cmd, "The device is powered on successfully", timeout=30)
            self._write("", self.base_prompt.replace("\\", ""))
        elif self.model in ["svsh"]:
            cmd = "vsh-rps on {}".format(outlet)
            self._write("", self.base_prompt.replace("\\", ""))
            self._write(cmd, "The device is powered on successfully", timeout=30, prompt=self.base_prompt)
        elif self.model in ["lxc"]:
            cmd = "lxc-rps on {}".format(outlet)
            self._write("", self.base_prompt.replace("\\", ""))
            self._write(cmd, "The device is powered on successfully", timeout=30, prompt=self.base_prompt)
        elif self.model in ["virsh"]:
            cmd = "virsh-rps on {}".format(outlet)
            self._write("", self.base_prompt.replace("\\", ""))
            self._write(cmd, "The device is powered on successfully", timeout=30, prompt=self.base_prompt)
        else:
            msg = "TODO: on {}".format(self.model)
            self.logmsg(msg, lvl=logging.WARNING)

        # wait for on delay
        if retval and on_delay > 0: self._wait(on_delay)

        # disconnect if required
        if disc: self.disconnect()

        return retval

    def debug(self, disc=True, outlet=None, log_file=None, op="debug"):

        self.logmsg("powering debug", lvl=logging.WARNING)

        # use defaults if not specified
        if outlet is None: outlet = self.outlet

        # connect if not already done
        if not self.tn:
            if not self.connect():
                self.logmsg("failed to connect", lvl=logging.WARNING)
                return False

        retval = True
        if self.model in ["vsh"]:
            cmd = "vsh-rps {} {}".format(op, outlet)
            self._write("", self.base_prompt.replace("\\", ""))
            self._write(cmd, "# VSH DEBUG END #", timeout=300, log_file=log_file)
            self._write("", self.base_prompt.replace("\\", ""))
        elif self.model in ["svsh"]:
            cmd = "vsh-rps {} {}".format(op, outlet)
            self._write("", self.base_prompt.replace("\\", ""))
            self._write(cmd, "# VSH DEBUG END #", timeout=300, log_file=log_file, prompt=self.base_prompt)
        elif self.model in ["lxc"]:
            cmd = "lxc-rps {} {}".format(op, outlet)
            self._write("", self.base_prompt.replace("\\", ""))
            self._write(cmd, "# VSH DEBUG END #", timeout=300, log_file=log_file, prompt=self.base_prompt)
        elif self.model in ["virsh"]:
            cmd = "virsh-rps {} {}".format(op, outlet)
            self._write("", self.base_prompt.replace("\\", ""))
            self._write(cmd, "# VSH DEBUG END #", timeout=300, log_file=log_file, prompt=self.base_prompt)
        else:
            msg = "TODO: on {}".format(self.model)
            self.logmsg(msg, lvl=logging.WARNING)

        # disconnect if required
        if disc: self.disconnect()

        return retval

    def _cmd_avocent(self, s, disc, outlet):
        if isinstance(outlet, list):
            outlet = ",".join(map(str, outlet))
        cmd = "cd /access/{}".format(self.pdu_id)
        rv = self._write(cmd, self.base_prompt)
        if "Error: Invalid path:" in rv:
            self.logmsg(rv, lvl=logging.ERROR)
            return
        self._write("{} {}".format(s, outlet), self.confirm_prompt)
        rv = self._write("yes", self.base_prompt)
        if "Error: Invalid Target name" in rv:
            self.logmsg(rv, lvl=logging.ERROR)

    def _grub_connect(self, ip, port):
        msg = "grub connect {}:{}".format(ip, port)
        self.logmsg(msg, lvl=logging.WARNING)
        try:
            tn = telnetlib.Telnet(ip, port=port)
            tn.set_debuglevel(self.dbg_lvl)
            return tn
        except Exception as e:
            msg = "grub connection failed {}".format(e)
            self.logmsg(msg, lvl=logging.ERROR)
            return None

    def _grub_wait_prompt(self, tn, prompt, time):
        rv = self.tn_read_until(tn, prompt, time)
        for p in self._grub_prompts:
            if p in rv:
                msg = "Device stuck in {}".format(p)
                self.logmsg(msg, lvl=logging.ERROR)
                return True, p
        if "Minimal BASH-like" in rv:
            p = self._grub_prompt
            msg = "Device stuck in {}".format(p)
            self.logmsg(msg, lvl=logging.ERROR)
            return True, p
        return False, rv

    def _grub_wait(self, tn, ip, port, after_reset=True):
        try:
            if not after_reset:
                for _ in range(2):
                    self.tn_write(tn, "\r\n", 2)
                    stuck, rv = self._grub_wait_prompt(tn, self._grub_rescue_prompt, 10)
                    if stuck: return rv
            stuck, rv = self._grub_wait_prompt(tn, "GNU GRUB  version", 120)
            if stuck: return rv

            tok = "The highlighted entry will be executed automatically"
            stuck, rv = self._grub_wait_prompt(tn, tok, 10)
            if stuck: return rv
            if tok not in rv:
                pass

            for phase in [0, 1]:
                # move the cursor to stop the timer by changing the selection
                self.tn_write(tn, 'v^v^v^v^')
                tok = "Press enter to boot the selected OS"
                stuck, rv = self._grub_wait_prompt(tn, tok, 2)
                if stuck: return rv
                rescued = False
                for i in range(5):
                    self.tn_write(tn, 'v')  # select next entry
                    stuck, rv = self._grub_wait_prompt(tn, tok, 2)
                    if stuck: return rv
                    if "*ONIE: Rescue" in rv:
                        self.tn_write(tn, '\r\n')
                        rescued = True  # break outer loop
                        msg = "ONIE: Rescue seen {}/{}".format(phase, i)
                        self.logmsg(msg, lvl=logging.DEBUG)
                        break
                    if "*ONIE " in rv:
                        self.tn_write(tn, '\r\n')
                        break  # break inner loop
                    self.logmsg(rv, prefix=" ********** ")
                if rescued:
                    break

            stuck, rv = self._grub_wait_prompt(tn, "Please press Enter to activate this console", 30)
            if stuck: return rv
        except EOFError as e:
            msg = "grub connection closed {}".format(e)
            self.logmsg(msg, lvl=logging.ERROR)
            return "grub connection closed"

        return None

    def grub_wait(self, ip, port, after_reset=True):
        ip = ip or self.console_ip
        port = port or self.console_port
        tn = self._grub_connect(ip, port)
        msg = self._grub_wait(tn, ip, port, after_reset)
        if msg in self._grub_prompts:
            rv = self.recover_from_grub(tn, msg, ip, port)
        else:
            rv = bool(msg is None)
        try: tn.close()
        except Exception: pass
        return rv

    def recover_from_grub(self, tn, prompt, ip=None, port=0):
        msg = "Recovering Device stuck in {}".format(prompt)
        self.logmsg(msg, lvl=logging.ERROR)
        if not tn:
            tn = self._grub_connect(ip, port)
        split_wait, wr_wait = True, 0.5
        self.tn_write(tn, "\r", wr_wait, split_wait)
        self.tn_read_until(tn, prompt, 10)
        self.tn_write(tn, "insmod ext2\r", wr_wait, split_wait)
        self.tn_write(tn, "insmod part_gpt\r", wr_wait, split_wait)
        self.tn_write(tn, "set root=(hd0,gpt2)\r", wr_wait, split_wait)
        self.tn_write(tn, "set prefix=(hd0,gpt2)/grub\r", wr_wait, split_wait)
        if prompt == self._grub_rescue_prompt:
            self.tn_write(tn, "insmod normal\r", wr_wait, split_wait)
            self.tn_write(tn, "normal\r", wr_wait, split_wait)
            return self._wait_for_onie_prompt(tn)
        self.tn_write(tn, "configfile /grub/grub.cfg.copy\r", wr_wait, split_wait)
        rv = self._wait_for_onie_prompt(tn)
        if rv:
            cmd = "cp {0}.copy {0}\r".format("/mnt/onie-boot/grub/grub.cfg")
            self.tn_write(tn, cmd, wr_wait, split_wait)
        return rv

    def _wait_for_onie_prompt(self, tn):
        self._wait(10)
        for _ in range(5):
            rv = self.tn_read_until(tn, "ONIE:/ #", 30)
            if "onie-installer" in rv: return True
            if "ONIE:" in rv: return True
        return False

    def tn_read_until(self, tn, msg, time, log_file=None):
        self.logmsg("Waiting (max: {} sec) for: '{}'".format(time, msg))
        rv1 = tn.read_until(self._encode(msg), time)
        rv1 = self._decode(rv1)
        rv2 = ctrl_chars.tostring(rv1)
        if log_file is None:
            rv2 = rv2.lstrip()
            self.logmsg(rv2, prefix=self.recv_prefix)
        else:
            write_file(log_file, rv2)
        return rv1

    def tn_write(self, tn, msg, wait=0, split_wait=None):
        msg2 = msg.replace("\n", "<LF>").replace("\r", "<CR>")
        self.logmsg(msg2, prefix=self.send_prefix)
        msg2 = self._encode(msg)
        if not split_wait:
            tn.write(msg2)
        else:
            for ch in msg:
                time.sleep(split_wait)
                tn.write(ch)
        if wait > 0: self._wait(wait)
        return None
