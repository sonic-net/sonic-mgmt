import re
import sys
import time
import logging
import telnetlib
import requests
import getpass

class RPS(object):

    def __init__(self, model, ip, port, outlet, username, password, logger=None,
                 dbg_lvl=0, dut="", console_ip=None, console_port=None):
        """
        Construction of the RPS object
        :param model: RPS Model Rariron/ServerTech/Avocent/AvocentRoot/PX3
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
        elif self.model == "vsonic":
            self.login_prompt = ""
            self.password_prompt = ""
            self.base_prompt2 = "#"
            self.base_prompt = "#"
            self.confirm_prompt = ""
            self.fail_msg = "Access denied"
            self.off_delay = 10
            self.on_delay = 10
        else:
            msg = "TODO: model={}".format(self.model)
            self.logger.log(msg, lvl=logging.WARNING)
            self.multi_support = False

    def logmsg(self, msg, lvl=logging.INFO):
        if self.dut:
            prefix = "RPS({}): ".format(self.dut)
        else:
            prefix = "RPS: "
        msg2 = "{}{}".format(prefix, msg)
        try: self.logger.dut_log(self.dut, msg2, lvl)
        except Exception: self.logger.log(lvl, msg2)

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
        res = func(url, params=new_params, data=data, auth=auth, headers=new_headers)
        self.logmsg(res.text)
        if res.status_code != 200:
            self.logmsg("Request Error: {}".format(res.status_code), lvl=logging.WARNING)
        else:
            self.logmsg("Request completed!", lvl=logging.WARNING)
        return res

    def _connect(self, base_prompt=None):

        # no need to connect if we are using rest
        if self.rest_url: return True

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

        if len(self.username) == 0:
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

    def _disconnect(self):
        self.logmsg("disconnect", lvl=logging.WARNING)
        if self.tn:
            self.tn.close()
            self.tn = None
        if self.disc_delay > 0:
            self._wait(self.disc_delay)

    def _wait(self, val):
        self.logmsg("wait {}".format(val), lvl=logging.WARNING)
        time.sleep(val)

    def _encode(self, s):
        if sys.version_info[0] >= 3:
            rv = str.encode(s)
            return rv
        return s

    def _decode(self, s):
        if sys.version_info[0] >= 3:
            rv = s.decode() if s else s
            return rv
        return s

    def _write(self, cmd, prompt=None, fail_msg=None, timeout=10):
        self.logmsg("sending {}".format(cmd))
        rv = self.tn_write(self.tn, cmd + "\r\n")
        if prompt:
            try:
                rv = self.tn_read_until(self.tn, prompt, timeout)
                rv = self._decode(rv)
                return None if (fail_msg and fail_msg in rv) else rv
            except EOFError as e:
                msg = "connection closed {}".format(e)
                self.logmsg(msg, lvl=logging.ERROR)
                return None
        return rv

    def do_op(self, op, on_delay=None, off_delay=None, outlet=None):
        op = op.lower()
        if op == "on":
            self.on(True, on_delay, outlet)
        elif op == "off":
            self.off(True, off_delay, outlet)
        elif op == "reset":
            self.reset(True, on_delay, off_delay, outlet)
        else:
            return False
        return True

    def off_on(self, disc=True, on_delay=None, off_delay=None, outlet=None):

        if not self.tn: self._connect()
        if not self.tn: return False
        rv1 = self.off(False, off_delay, outlet)
        rv2 = self.on(False, on_delay, outlet)
        if disc: self._disconnect()

        return bool(rv1 and rv2)

    def reset(self, disc=True, on_delay=None, off_delay=None, outlet=None):

        self.logmsg("powering reboot", lvl=logging.WARNING)

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
            if not self._connect():
                self.logmsg("failed to connect", lvl=logging.WARNING)
                return False

        retval = True
        if self.model == "Raritan":
            retval = self.off_on(False, 0, off_delay, outlet)
        elif self.model == "PX3":
            self._write("power outlets {} cycle /y".format(outlet), self.base_prompt)
        elif self.model == "ServerTech":
            self._write("reboot {}".format(outlet), self.base_prompt)
            #retval = self.off_on(False, 0, off_delay, outlet)
        elif self.model == "Avocent" or self.model == "AvocentRoot":
            retval = self.off_on(False, 0, off_delay, outlet)
        elif self.model == "vsonic":
            retval = self.off_on(False, 0, off_delay, outlet)
        else:
            msg = "TODO: off {}".format(self.model)
            self.logmsg(msg, lvl=logging.WARNING)

        # wait for on delay
        if retval and on_delay > 0: self._wait(on_delay)

        # disconnected if required
        if disc: self._disconnect()

        return retval

    def off(self, disc=True, off_delay=None, outlet=None):
        self.logmsg("powering off", lvl=logging.WARNING)

        # use defaults if not specified
        if outlet is None: outlet = self.outlet
        if off_delay is None: off_delay = self.off_delay

        # connect if not already done
        if not self.tn:
            if not self._connect():
                self.logmsg("failed to connect", lvl=logging.WARNING)
                return False

        retval = True
        if self.model == "Raritan":
            cmd = "set /system1/outlet{} powerstate=off".format(outlet)
            self._write(cmd, self.base_prompt)
        elif self.model == "PX3":
            self._write("power outlets {} off /y".format(outlet), self.base_prompt)
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
        elif self.model == "vsonic":
            cmd = "vsh sgconf poweroff G {}".format(outlet)
            self._write(cmd, "The device is powered off successfully", timeout=120)
            self._write("", self.base_prompt)
        else:
            msg = "TODO: off {}".format(self.model)
            self.logmsg(msg, lvl=logging.WARNING)

        # wait for off delay
        if retval and off_delay > 0: self._wait(off_delay)

        # disconnected if required
        if disc: self._disconnect()

        return retval

    def on(self, disc=True, on_delay=None, outlet=None):

        self.logmsg("powering on", lvl=logging.WARNING)

        # use defaults if not specified
        if outlet is None: outlet = self.outlet
        if on_delay is None: on_delay = self.on_delay

        # connect if not already done
        if not self.tn:
            if not self._connect():
                self.logmsg("failed to connect", lvl=logging.WARNING)
                return False

        retval = True
        if self.model == "Raritan":
            cmd = "set /system1/outlet{} powerstate=on".format(outlet)
            self._write(cmd, self.base_prompt)
        elif self.model == "PX3":
            self._write("power outlets {} on /y".format(outlet), self.base_prompt)
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
        elif self.model == "vsonic":
            cmd = "vsh sgconf poweron G {}".format(outlet)
            self._write(cmd, "The device is powered on successfully", timeout=30)
            self._write("", self.base_prompt)
        else:
            msg = "TODO: on {}".format(self.model)
            self.logmsg(msg, lvl=logging.WARNING)

        # wait for on delay
        if retval and on_delay > 0: self._wait(on_delay)

        # disconnected if required
        if disc: self._disconnect()

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
            if self._encode(p) in rv:
                msg = "Device stuck in {}".format(p)
                self.logmsg(msg, lvl=logging.ERROR)
                return p
        if self._encode("Minimal BASH-like") in rv:
            p = self._grub_prompt
            msg = "Device stuck in {}".format(p)
            self.logmsg(msg, lvl=logging.ERROR)
            return p
        return None

    def _grub_wait(self, tn, ip, port, after_reset=True):
        try:
            if not after_reset:
                for _ in range(2):
                    self.tn_write(tn, "\r\n", 2)
                    rv = self._grub_wait_prompt(tn, self._grub_rescue_prompt, 10)
                    if rv: return rv
            rv = self._grub_wait_prompt(tn, "GNU GRUB  version", 120)
            if rv: return rv
            rv = self._grub_wait_prompt(tn, "The highlighted entry will be executed automatically", 10)
            if rv: return rv
            self.tn_write(tn, '\x1b[B\r\n')
            rv = self._grub_wait_prompt(tn, "The highlighted entry will be executed automatically", 10)
            if rv: return rv
            self.tn_write(tn, '\x1b[B\r\n')
            rv = self._grub_wait_prompt(tn, "Please press Enter to activate this console", 30)
            if rv: return rv
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
            return self.recover_from_grub(tn, msg, ip, port)
        return bool(msg is None)

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

    def tn_read_until(self, tn, msg, time):
        self.logmsg("Waiting for: '{}'".format(msg))
        rv = rv0 = tn.read_until(self._encode(msg), time)
        rv = self._tostring(rv)
        self.logmsg("Rcvd: {}".format(rv))
        return rv0

    def tn_write(self, tn, msg, wait=0, split_wait=None):
        msg2 = msg.replace("\n", "<LF>").replace("\r", "<CR>")
        self.logmsg("Send: {}".format(msg2))
        msg2 = self._encode(msg)
        if not split_wait:
            tn.write(msg2)
        else:
            for ch in msg:
                time.sleep(split_wait)
                tn.write(ch)
        if wait > 0: self._wait(wait)
        return None

    def _tostring(self, msg):
        msg = re.sub(r'(\x9B|\x1B\[)[0-?]*[ -\/]*[@-~]', ' ', msg)
        msg = re.sub(r'[^\x00-\x7F]+', ' ', msg)
        try:
            return msg.encode('ascii', 'ignore').decode('ascii')
        except Exception as exp:
            self.logmsg(str(exp), lvl=logging.ERROR)
        return "non-ascii characters"

