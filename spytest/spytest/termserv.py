import logging

from netmiko import Netmiko


class TermServ(object):

    def __init__(self, model, ip, cid, username=None,
                 password=None, logger=None, desc=""):
        self.logger = logger or logging.getLogger()
        self.model = model.lower()
        self.ip = ip
        self.cid = cid
        self.desc = desc
        self.hndl = None
        if self.model == "digi":
            self.username = username or "admin"
            self.password = password or "admin"
            self.base_cmd = "configmenu"
            self.base_prompt = "---->"
            self._connect = self._connect_digi
            self._show = self._show_digi_menu
            self._kill = self._kill_digi_menu
        elif self.model == "digipassport":
            self.username = username or "admin"
            self.password = password or "admin"
            self.base_cmd = ""
            self.base_prompt = "$"
            self._connect = self._connect_digi
            self._show = self._show_digi_cli
            self._kill = self._kill_digi_cli
        elif self.model == "avocent":
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
        cids = self._get_cids(cid)
        msg = "Failed to perform {}".format(op)
        try:
            if not self._connect():
                msg = "Failed to connect"
            elif op == "show":
                retval = self._show()
            elif op == "kill":
                retval = self._kill(cids)
            elif op == "show-kill":
                self._show()
                retval = self._kill(cids)
                self._show()
        except Exception as e:
            msg = "Failed to perform {}: {}".format(op, e)

        if not retval:
            self._log(msg, lvl=logging.ERROR)

        if self.hndl:
            self.hndl.disconnect()
            self.hndl = None
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
            self._send_cmd("\x1B", cr=False, msg="<ESC>")

    def _send_cmd(self, cmd, expect_string=None, cr=True, msg="RECV:"):
        self._log("SEND({}): {}".format(cr, cmd))
        if cr:
            output = self.hndl.send_command(cmd, expect_string)
        else:
            output = self.hndl.send_command_timing(cmd)
        self._log("{}\n{}".format(msg, output))
        return output

    def _connect_digi(self):
        try:
            self.hndl = Netmiko(self.ip, username=self.username,
                                password=self.password, device_type="autodetect",
                                global_delay_factor=5)
        except Exception:
            self._log("Failed to connect to {}".format(self.ip), lvl=logging.ERROR)
            self.hndl = None

        if self.hndl:
            prompt = self.hndl.find_prompt(delay_factor=3)
            self._log("Initial Prompt: {}".format(prompt))
            if self.base_cmd:
                self._log("Send base command: {}".format(self.base_cmd))
            self._send_cmd(self.base_cmd, self.base_prompt, msg="Initial Ouput:")
            self.hndl.set_base_prompt(self.base_prompt)
            prompt = self.hndl.find_prompt()
            self._log("Base Prompt: {}".format(prompt))
        return self.hndl

    def _show_digi_cli(self):
        return ""

    def _show_digi_menu(self):
        self._send_cmd("6", cr=False, msg="Select System Status & Log")
        return self._send_cmd("3", cr=False)

    def _kill_digi_cli(self, ports):
        for port in ports:
            self._send_cmd("portset reset {}".format(port))
        return True

    def _kill_digi_menu(self, ports):
        self._send_escape()
        if not isinstance(ports, list):
            ports = [ports]
        self._send_cmd("2", cr=False)
        for port in ports:
            self._send_cmd(str(port))
            self._send_cmd("a", cr=False)
            self._send_cmd("1", expect_string="has been reset successfully")
            self._send_escape(2)
        return True

    def _connect_avocent(self):
        self.hndl = Netmiko(self.ip, username=self.username,
                            password=self.password, device_type="linux")
        if self.hndl:
            self._send_cmd(self.base_cmd, self.base_prompt)
            self.hndl.base_prompt = self.hndl.find_prompt()
        return self.hndl

    def _show_avocent(self):
        output = self._send_cmd("administration sessions list")
        self._send_cmd("", cr=False)
        return output

    def _kill_avocent(self, ports):
        for port in ports:
            self._log("------ Kill Session on {} ------".format(port))
            self._send_cmd("administration sessions kill {}".format(port))
            self._send_cmd("", cr=False)
        return True
