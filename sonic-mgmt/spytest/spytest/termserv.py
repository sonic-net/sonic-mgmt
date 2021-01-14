import logging

from netmiko import Netmiko

class TermServ(object):

    def __init__(self, model, ip, cid, username=None,
                 password=None, logger=None, desc=""):
        self.logger = logger or logging.getLogger()
        self.model = model
        self.ip = ip
        self.cid = cid
        self.desc = desc
        if self.model.lower() == "digi":
            self.username = username or "admin"
            self.password = password or "admin"
            self.base_cmd = ""
            self.base_prompt = "---->"
            self._connect = self._connect_digi
            self._show = self._show_digi
            self._kill = self._kill_digi
        elif self.model.lower() == "avocent":
            self.username = username or "root"
            self.password = password or "stratax120"
            self.base_cmd = "CLI"
            self.base_prompt = "cli>"
            self._connect = self._connect_avocent
            self._show = self._show_avocent
            self._kill = self._kill_avocent
        else:
            msg = "TODO: model={}".format(self.model)
            self.logger.log(msg, lvl=logging.WARNING)

    def _get_cids(self, cid):
        if cid is None:
            cids = [self.cid]
        elif isinstance(cid, list):
            cids = cid
        else:
            cids = [cid]
        return cids

    def do_op(self, op, cid=None):
        retval = False
        msg = "Failed to perform {}".format(op)
        try:
            if not self._connect():
                msg = "Failed to connect"
            elif op == "show":
                retval = self._show()
            elif op == "kill":
                cids = self._get_cids(cid)
                retval = self._kill(cids)
            elif op == "show-kill":
                retval = self._show()
                cids = self._get_cids(cid)
                retval = self._kill(cids)
        except Exception as e:
            msg = "Failed to perform {}: {}".format(op, e)

        if not retval:
            self._log(msg, lvl=logging.ERROR)
        return retval

    def _log(self, msg, lvl=logging.INFO):
        if self.desc:
            prefix = "TS({}): ".format(self.desc)
        else:
            prefix = "TS: "
        msg2 = "{}{}".format(prefix, msg)
        self.logger.log(lvl, msg2)
        return msg2

    def _send_escape(self, count=5):
        for _ in range(count):
            self.hndl.send_command("\x1B")

    def _connect_digi(self):
        self.hndl = Netmiko(self.ip, username=self.username,
                            password=self.password, device_type="cisco_ios")
        self.hndl.send_command(self.base_cmd)
        self.hndl.base_prompt = self.hndl.find_prompt()
        self._log("============== INITIAL PROMPT =================")
        self._log(self.hndl.find_prompt())
        self._log("===============================================")
        return self.hndl

    def _show_digi(self):
        self.hndl.send_command("6")
        output = self.hndl.send_command_timing("3")
        self.hndl.send_command("")
        self._log(output)
        return output

    def _kill_digi(self, ports):
        self._send_escape()
        if not isinstance(ports, list):
            ports = [ports]
        output = self.hndl.send_command("2")
        self._log(output)
        for port in ports:
            self.hndl.send_command(str(port))
            self.hndl.send_command("a")
            output = self.hndl.send_command("1", expect_string="has been reset successfully")
            self._log("\n" + output)
            self.hndl.send_command("")
            self._send_escape(2)
        return True

    def _connect_avocent(self):
        self.hndl = Netmiko(self.ip, username=self.username,
                            password=self.password, device_type="linux")
        if self.hndl:
            self.hndl.send_command("CLI", self.base_prompt)
            self.hndl.base_prompt = self.hndl.find_prompt()
        return self.hndl

    def _show_avocent(self):
        output = self.hndl.send_command("administration sessions list")
        self.hndl.send_command_timing("")
        self._log("\n" + output)
        return output

    def _kill_avocent(self, ports):
        for port in ports:
            self._log("------ Kill Session on {} ------".format(port))
            output = self.hndl.send_command("administration sessions kill {}".format(port))
            self._log(output)
            self.hndl.send_command_timing("")
        return True

