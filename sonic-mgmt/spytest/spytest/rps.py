import time
import logging
import telnetlib

class RPS(object):

    def __init__(self, model, ip, port, outlet, username, password,
                 logger=None, dbg_lvl=0, desc=""):
        """
        Construction of the RPS object
        :param model: RPS Model Rariron/ServerTech/Avocent/AvocentRoot
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
        self.logger = logger or logging.getLogger()
        self.tn = None
        self.model = model
        self.ip = ip
        self.port = port
        self.outlet = outlet
        self.pdu_id = None
        self.username = username
        self.password = password
        self.desc = desc
        self.timeout = 600
        self.dbg_lvl = dbg_lvl
        self.off_delay = 5
        self.on_delay = 90
        self.disc_delay = 0
        self.login_prompt_timeout = 60
        if self.model == "Raritan":
            self.login_prompt = "Login:"
            self.password_prompt = "Password:"
            self.base_prompt = ">"
            self.base_prompt = "clp:/->"
            self.fail_msg = "Login failed."
            self.multi_support = False
            self.disc_delay = 10
        elif self.model == "ServerTech":
            self.login_prompt = "Username:"
            self.password_prompt = "Password:"
            self.base_prompt = "Sentry:|Switched CDU:|Switched PDU:"
            self.fail_msg = "Access denied"
            self.multi_support = False
            self.disc_delay = 10
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
        elif self.model == "vsonic":
            self.login_prompt = ""
            self.password_prompt = ""
            self.base_prompt2 = "#"
            self.base_prompt = "#"
            self.confirm_prompt = ""
            self.fail_msg = "Access denied"
            self.off_delay = 10
            self.on_delay = 10
            self.multi_support = False
        else:
            msg = "TODO: model={}".format(self.model)
            self.logger.log(msg, lvl=logging.WARNING)
            self.multi_support = False

    def logmsg(self, msg, lvl=logging.INFO):
        if self.desc:
            prefix = "RPS({}): ".format(self.desc)
        else:
            prefix = "RPS: "
        msg2 = "{}{}".format(prefix, msg)
        self.logger.log(lvl, msg2)

    def has_multi_support(self):
        return self.multi_support

    def set_pdu_id(self, pdu_id):
        """
        todo: Update Documentation
        :param pdu_id:
        :type pdu_id:
        :return:
        :rtype:
        """
        self.pdu_id = pdu_id

    def _connect(self, base_prompt=None):
        self.logmsg("connect", lvl=logging.WARNING)
        self.tn = telnetlib.Telnet(self.ip, port=self.port)
        self.tn.set_debuglevel(self.dbg_lvl)

        if len(self.username) == 0:
            self._write("", self.base_prompt)
            return True

        try:
            self.logmsg("wait for login prompt")
            self.tn.read_until(self.login_prompt, self.login_prompt_timeout)
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
                self.logmsg("Invalid password", lvl=logging.WARNING)
                return False
        else:
            self._write(self.username, base_prompt)

        if self.model == "AvocentRoot":
            self._write("cli", self.base_prompt)

        return True

    def _disconnect(self):
        self.logmsg("disconnect", lvl=logging.WARNING)
        self.tn.close()
        self.tn = None
        if self.disc_delay > 0:
            self._wait(self.disc_delay)

    def _wait(self, val):
        time.sleep(val)

    def _write(self, cmd, prompt=None, fail_msg=None, timeout=10):
        self.logmsg("sending {}".format(cmd))
        rv = self.tn.write(cmd + "\r\n")
        if prompt:
            try:
                self.logmsg("wait for prompt {}".format(prompt))
                rv = self.tn.read_until(prompt, timeout)
                if fail_msg:
                    if rv.strip() == fail_msg:
                        return None
                return rv
            except EOFError as e:
                msg = "connection closed {}".format(e)
                self.logmsg(msg, lvl=logging.ERROR)
                return None
        return rv

    def do_op(self, op, on_delay=None, off_delay=None, outlet=None):
        """
        todo: Update Documentation
        :param op:
        :type op:
        :return:
        :rtype:
        """
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

    def reset(self, disc=True, on_delay=None, off_delay=None, outlet=None):
        """
        todo: Update Documentation
        :param disc:
        :type disc:
        :param on_delay:
        :type on_delay:
        :param off_delay:
        :type off_delay:
        :param outlet:
        :type outlet:
        :return:
        :rtype:
        """
        if not self.tn:
            self._connect()
        self.off(False, off_delay, outlet)
        self.on(False, on_delay, outlet)
        if disc:
            self._disconnect()

    def off(self, disc=True, off_delay=None, outlet=None):
        """
        todo: Update Documentation
        :param disc:
        :type disc:
        :param off_delay:
        :type off_delay:
        :param outlet:
        :type outlet:
        :return:
        :rtype:
        """
        self.logmsg("powering off", lvl=logging.WARNING)
        if outlet is None:
            outlet = self.outlet
        if not self.tn:
            if not self._connect():
                self.logmsg("failed to connect", lvl=logging.WARNING)
                return
        if self.model == "Raritan":
            cmd = "set /system1/outlet{} powerstate=off".format(outlet)
            self._write(cmd, self.base_prompt)
        elif self.model == "ServerTech":
            self._write("off {}".format(outlet), self.base_prompt)
        elif self.model == "Avocent" or self.model == "AvocentRoot":
            if not self.pdu_id:
                self.logmsg("PDU_ID must be set for Avocent", lvl=logging.ERROR)
            else:
                self._cmd_avocent("off", disc, outlet)
        elif self.model == "vsonic":
            cmd = "vsh sgconf poweroff G {}".format(outlet)
            self._write(cmd, "The device is powered off successfully", timeout=120)
            self._write("", self.base_prompt)
        else:
            msg = "TODO: off {}".format(self.model)
            self.logmsg(msg, lvl=logging.WARNING)
        if off_delay is None:
            self._wait(self.off_delay)
        elif off_delay > 0:
            self._wait(off_delay)
        if disc:
            self._disconnect()

    def on(self, disc=True, on_delay=None, outlet=None):
        """
        todo: Update Documentation
        :param disc:
        :type disc:
        :param on_delay:
        :type on_delay:
        :param outlet:
        :type outlet:
        :return:
        :rtype:
        """
        if outlet is None:
            outlet = self.outlet
        self.logmsg("powering on", lvl=logging.WARNING)
        if not self.tn:
            if not self._connect():
                self.logmsg("failed to connect", lvl=logging.WARNING)
                return
        if self.model == "Raritan":
            cmd = "set /system1/outlet{} powerstate=on".format(outlet)
            self._write(cmd, self.base_prompt)
        elif self.model == "ServerTech":
            self._write("on {}".format(outlet), self.base_prompt)
        elif self.model == "Avocent" or self.model == "AvocentRoot":
            if not self.pdu_id:
                self.logmsg("PDU_ID must be set for Avocent", lvl=logging.ERROR)
            else:
                self._cmd_avocent("on", disc, outlet)
        elif self.model == "vsonic":
            cmd = "vsh sgconf poweron G {}".format(outlet)
            self._write(cmd, "The device is powered on successfully", timeout=30)
            self._write("", self.base_prompt)
        else:
            msg = "TODO: on {}".format(self.model)
            self.logmsg(msg, lvl=logging.WARNING)
        if on_delay is None:
            self._wait(self.on_delay)
        elif on_delay > 0:
            self._wait(on_delay)
        if disc:
            self._disconnect()

    def _cmd_avocent(self, s, disc, outlet):
        if isinstance(outlet, list):
            outlet = ",".join(map(str, outlet))
        cmd = "cd /access/{}".format(self.pdu_id)
        self._write(cmd, self.base_prompt)
        self._write("{} {}".format(s, outlet), self.confirm_prompt)
        rv = self._write("yes", self.base_prompt)
        if "RPS: Error: Invalid Target name" in rv:
            self.logmsg(rv, lvl=logging.ERROR)


if __name__ == "__main__":
    logging.basicConfig()
    rps = RPS("vsonic", "10.0.3.150", 7002, "D1", "", "", dbg_lvl=1, desc="VS")
    rps.reset()
    #rps = RPS("Avocent", "1.1.1.1", 23, 2, "user", "pass")
    #rps = RPS("AvocentRoot", "1.1.1.1", 23, 12, "root", "rootpwd")
    # rps = RPS("Avocent", "1.1.1.1", 23, 111, "user", "pass")
    # rps.set_pdu_id("1b-3b-23P0_1")
    # rps.set_pdu_id("12-81-b2P0_1")
    #rps = RPS("Raritan", "1.2.3.4", 23, 10, "admin", "admin")
    # rps.off()
    # rps.on()
    # rps.reset()

