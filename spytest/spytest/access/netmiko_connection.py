
import os
import re
import time
import socket
import logging
import telnetlib

import netmiko

from utilities import ctrl_chars
from utilities.common import stack_trace
from utilities.exceptions import DeviceConnectionError
from utilities.exceptions import DeviceConnectionTimeout
from utilities.exceptions import DeviceAuthenticationFailure

from spytest.access.utils import get_delay_factor
from spytest.access.utils import check_console_ip
from spytest.access.utils import is_scmd

is_netmiko2 = bool(netmiko.__version__.split(".")[0] == '2')


def get_trace_lvl():
    return int(os.getenv("SPYTEST_DEBUG_DEVICE_CONNECTION", "0"))


def init_trace(val):
    if val <= 0: return None
    logger = logging.getLogger('netmiko_connection')
    logger.setLevel(logging.DEBUG)
    return logger


logger = init_trace(get_trace_lvl())


def trace(msg):
    show_trace = get_trace_lvl()
    if show_trace <= 0:
        return
    if show_trace > 1 and logger:
        logger.info(msg)
    else:
        print(msg)


def dtrace(*args):
    if get_trace_lvl() > 2:
        print(args)


class NetmikoConnection(netmiko.cisco_base_connection.CiscoBaseConnection):

    def __init__(self, **kwargs):
        self.trace_callback = None
        self.trace_callback_arg1 = None
        self.trace_callback_arg2 = None
        self.cached_read_data = []
        self.net_login = kwargs.pop("net_login", None)
        self.net_devname = kwargs.pop("net_devname", None)
        self.parent = kwargs.pop("parent", None)
        self.logger = kwargs.pop("logger", None)
        self.auth_failmsg = None
        self.pri_prompt_terminator1 = '$'
        self.pri_prompt_terminator2 = '>'
        self.alt_prompt_terminator = '#'
        self.alt_telnet_prompt = r'[\$|>|#]\s*$'
        self.change_pwd_ok_prompt = None
        self.confirm_new_password_prompt = None
        self.prompt_unix_password = None
        self.in_login = False
        self.check_live_connection = bool(os.getenv("SPYTEST_CHECK_DEVICE_LIVE_CONNECTION", "0") != "0")
        self.fix_control_chars = bool(os.getenv("SPYTEST_FIX_DEVICE_CONTROL_CHARS", "0") != "0")
        self.product = kwargs.pop("product", "sonic")
        self.username = kwargs.get("username", None)
        self.use_keys = kwargs.get("use_keys", False)
        self.altpassword = kwargs.pop("altpassword", None)
        self.change_pass = kwargs.pop("change_pass", None)
        self.update_prompt_terminator()

        logf = logger.warning if logger else None
        access_ip = kwargs.get("ip", None)
        if not check_console_ip(access_ip, logf):
            raise DeviceConnectionTimeout("Access IP {} Not Reachable".format(access_ip))

        for try_index in range(5):
            try:
                super(NetmikoConnection, self).__init__(**kwargs)
                break
            except netmiko.ssh_exception.NetMikoTimeoutException:
                msg = "Connection Timeout Error.."
                self.log_warn(msg)
                if try_index >= 4:
                    time.sleep(try_index + 1)
                    continue
                self.disconnect()
                raise DeviceConnectionTimeout(msg)
            except netmiko.ssh_exception.NetMikoAuthenticationException:
                msg = "Connection Authentication Error.."
                self.log_warn(msg)
                self.disconnect()
                raise DeviceAuthenticationFailure(msg)
            except DeviceAuthenticationFailure:
                msg = "Connection Device Authentication Error.."
                self.log_warn(msg)
                self.disconnect()
                raise DeviceAuthenticationFailure(msg)
            except Exception as e:
                msg = "Connection " + self.check_exception(e)
                self.log_exception(msg, call_stack=True, dump=True)
                if "Unknown Error" in msg and try_index >= 4:
                    time.sleep(try_index + 1)
                    continue
                self.disconnect()
                raise DeviceConnectionError(msg)

    def check_exception(self, e):
        try: msg = repr(e)
        except Exception: pass
        if "Connection refuse" in msg:
            msg = "Refused.."
        else:
            msg = "Unknown Error.."
        return msg

    def set_product(self, product="sonic"):
        self.product = product
        self.update_prompt_terminator()

    def is_any_fastpath_product(self):
        return bool(self.product in ["fastpath", "icos"])

    def update_prompt_terminator(self):
        patterns0, patterns1, patterns2 = [], [], []
        patterns0.append(self.alt_prompt_terminator)
        if self.product == "sonic":
            self.pri_prompt_terminator1 = '$'
            self.pri_prompt_terminator1 = '$'
            self.pri_prompt_terminator2 = '>'
            patterns0.append(r"\$")
            patterns1.append(r"\(current\) UNIX password:")
            patterns1.append("Current password:")
        else:
            self.pri_prompt_terminator1 = '>'
            self.pri_prompt_terminator2 = '$'
            patterns0.append(">")
            if self.product == "icos":
                patterns0.append(r"\$")
            self.auth_failmsg = "User '{}' authentication failure".format(self.username)
            patterns1.append(self.auth_failmsg)
            patterns1.append("Enter old password:")
            patterns2.append("Confirm new password:")
            patterns2.append("Incorrect password!")
        patterns1.extend(patterns0); patterns2.extend(patterns0)
        self.change_pwd_ok_prompt = r"({})\s*".format("|".join(patterns0))
        self.prompt_unix_password = r"({})\s*".format("|".join(patterns1))
        self.confirm_new_password_prompt = r"({})\s*".format("|".join(patterns2))

    def set_logger(self, logger):
        self.logger = logger

    def log_lvl(self, lvl, msg, rmctrl=True, dump=False):
        if isinstance(msg, list):
            for line in msg:
                self.log_warn(line)
            return
        msg1 = ctrl_chars.remove(msg) if rmctrl else msg
        if dump:
            msg2 = "\n".join(self.get_cached_read_lines())
            if msg2:
                msg1 += "\n--------------------------------------------\n"
                msg1 += msg2
                msg1 += "\n--------------------------------------------\n"
        for msg2 in msg1.splitlines():
            if self.parent and self.net_devname:
                self.parent.dut_log(self.net_devname, msg2)
                continue
            if self.net_devname:
                msg2 = "{}: {}".format(self.net_devname, msg2)
            elif self.logger:
                self.logger.log(lvl, msg2)
            else:
                print(msg2)

    def log_warn(self, msg, rmctrl=True, dump=False):
        self.log_lvl(logging.WARNING, msg, rmctrl, dump)

    def log_info(self, msg, rmctrl=True, dump=False):
        self.log_lvl(logging.INFO, msg, rmctrl, dump)

    def log_exception(self, msg, call_stack=True, dump=False):
        self.log_warn("======== Connection: {} ======".format(msg))
        self.log_warn(stack_trace(None, call_stack))
        if dump:
            self.log_warn("--------------------------------------------")
            self.log_warn(self.get_cached_read_lines(), rmctrl=False)
        self.log_warn("============================================")

    def session_preparation(self):
        trace("============================== session_preparation ============================")
        self.ansi_escape_codes = True
        if self.protocol == "ssh":
            return self.ssh_session_preparation()
        else:
            return super(NetmikoConnection, self).session_preparation()

    def ssh_session_preparation(self):
        """
        Added extended_login to the base function for handling the password change in ssh scenario.
        """
        output = self._test_channel_read()
        self.extended_login(output)
        self.set_base_prompt()
        self.disable_paging()
        self.set_terminal_width()

        # Clear the read buffer
        time.sleep(0.3 * self.global_delay_factor)
        self.clear_buffer()

    def _enter_shell(self):
        return ''

    def _return_cli(self):
        return ''

    # pylint: disable=arguments-differ
    def disable_paging(self, **kwargs):
        return ""

    def _set_base_prompt(self, pri_prompt_terminator, alt_prompt_terminator, delay_factor):
        return super(NetmikoConnection, self).set_base_prompt(
            pri_prompt_terminator=pri_prompt_terminator,
            alt_prompt_terminator=alt_prompt_terminator or self.alt_prompt_terminator,
            delay_factor=delay_factor)

    def set_base_prompt(self, pri_prompt_terminator=None,
                        alt_prompt_terminator=None, delay_factor=1):
        if pri_prompt_terminator is None:
            try: return self._set_base_prompt(self.pri_prompt_terminator1, alt_prompt_terminator, delay_factor)
            except Exception: pass
            return self._set_base_prompt(self.pri_prompt_terminator2, alt_prompt_terminator, delay_factor)
        return self._set_base_prompt(pri_prompt_terminator, alt_prompt_terminator, delay_factor)

    def log_send(self, cmd):
        msg = ">>> {}".format(cmd)
        self.log_info(msg)
        return msg

    def log_recv(self, output):
        self.log_info(output)
        return output

    def change_password(self, username, new_password, output=None):
        retype_expect = self.change_pwd_ok_prompt
        retval = output or ""
        if output is None:
            retype_expect = r"passwd: password updated successfully\s*"
            prompt_terminator = r"Enter new UNIX password:|New password:"
            cmd = "sudo passwd {}".format(username)
            retval += self.log_send(cmd)
            output = self.send_command(cmd, expect_string=prompt_terminator,
                                       strip_command=False, strip_prompt=False)
            retval += self.log_recv(output)

        while True:
            if "Enter new UNIX password:" in output:
                retval += self.log_send(new_password)
                output = self.send_command(new_password, expect_string="Retype new UNIX password:",
                                           strip_command=False, strip_prompt=False)
                retval += self.log_recv(output)
                continue
            if "Retype new UNIX password:" in output:
                retval += self.log_send(new_password)
                output = self.send_command(new_password, expect_string=retype_expect,
                                           strip_command=False, strip_prompt=False)
                retval += self.log_recv(output)
                return [True, retval]
            break

        while True:
            if "New password:" in output:
                retval += self.log_send(new_password)
                output = self.send_command(new_password, expect_string="Retype new password:",
                                           strip_command=False, strip_prompt=False)
                retval += self.log_recv(output)
                continue
            if "Retype new password:" in output:
                retval += self.log_send(new_password)
                output = self.send_command(new_password, expect_string=retype_expect,
                                           strip_command=False, strip_prompt=False)
                retval += self.log_recv(output)
                return [True, retval]
            break

        while True:
            if "Enter new password:" in output:
                retval += self.log_send(new_password)
                prompt_terminator = self.confirm_new_password_prompt
                output = self.send_bytes(new_password, expect_string=prompt_terminator,
                                         strip_command=False, strip_prompt=False)
                retval += self.log_recv(output)
                if "Incorrect password!" in output:
                    os._exit(0)
                continue
            if "Confirm new password:" in output:
                retval += self.log_send(new_password)
                output = self.send_bytes(new_password, expect_string="User:",
                                         strip_command=False, strip_prompt=False)
                retval += self.log_recv(output)
                if "User:" in output:
                    retval += self.log_send(self.username)
                    output = self.send_bytes(self.username, expect_string="Password:",
                                             strip_command=False, strip_prompt=False)
                    retval += self.log_recv(output)
                if "Password:" in output:
                    retval += self.log_send(new_password)
                    output = self.send_bytes(new_password, expect_string=retype_expect,
                                             strip_command=False, strip_prompt=False)
                    retval += self.log_recv(output)
                return [True, retval]
            break

        return [False, retval]

    def extended_login(self, output):
        retval = output or ""
        if self.device_type == "sonic_sshcon":
            if self.net_login and self.net_devname:
                self.net_login(self.net_devname, self)
        rv = bool("(current) UNIX password:" in output or "Current password:" in output)
        if rv:
            prompt_terminator = r"Enter new UNIX password:|New password:"
            retval += self.log_send(self.password)
            output = self.send_command(self.password, expect_string=prompt_terminator,
                                       strip_command=False, strip_prompt=False)
            self.log_recv(output)
            rv2, output = self.change_password(self.username, self.altpassword, output)
            retval += output
            if rv2:
                if self.protocol == "ssh" and "passwd: password updated successfully" in output:
                    self.disconnect()
                    raise socket.error("Spytest: socket is closed abruptly")
                _, output = self.change_password(self.username, self.password)
                retval += output
        elif "Enter old password:" in output:
            prompt_terminator = "Enter new password:"
            output = self.send_command("", expect_string=prompt_terminator,
                                       strip_command=False, strip_prompt=False)
            self.log_recv(output)
            rv2, output = self.change_password(self.username, self.change_pass, output)
            retval += output

        return rv, retval

    def telnet_login(self, pri_prompt_terminator=None, alt_prompt_terminator=None,
                     username_pattern=r"(?:[Uu]ser:|sername|ogin|User Name)",
                     pwd_pattern=r"assword", delay_factor=1, max_loops=20):
        trace("============================== telnet_login ============================")
        self.in_login = True
        output = ""
        try:
            if self.is_any_fastpath_product():
                delay_factor = delay_factor * 2
            output = super(NetmikoConnection, self).telnet_login(
                self.prompt_unix_password, self.alt_telnet_prompt,
                username_pattern, pwd_pattern, delay_factor, max_loops)
            output = ctrl_chars.remove(output)
            self.log_info(output)
            if self.auth_failmsg and self.auth_failmsg in output:
                raise DeviceAuthenticationFailure("")
            _, output = self.extended_login(output)
        except netmiko.ssh_exception.NetMikoTimeoutException as e:
            self.in_login = False
            self.log_warn("Telnet Timeout Error", dump=True)
            raise e
        except netmiko.ssh_exception.NetMikoAuthenticationException as e:
            self.in_login = False
            msg = "Telnet Authentication Error.."
            self.log_warn(msg, dump=True)
            raise e
        except DeviceAuthenticationFailure:
            msg = "Telnet Device Authentication Error.."
            self.log_warn(msg, dump=True)
            raise DeviceAuthenticationFailure(msg)
        except Exception as e:
            msg = "Telnet Connection " + self.check_exception(e)
            self.log_exception(msg, call_stack=False, dump=True)
            self.in_login = False
            raise e
        self.in_login = False
        trace("========= telnet_login: '{}' =========".format(output))
        return output

    def format_output(self, lines, fmt=False, rmctrl=True):
        retval = []
        for line in lines:
            if rmctrl: line = ctrl_chars.remove(line)
            if fmt: line = self.dmsg_fmt(line)
            for msg in re.split('\r|\n', line):
                msg = msg.strip()
                if not msg: continue
                retval.append(msg)
        return retval

    def add_cached_read_data(self, output):
        if output:
            for line in self.format_output([output]):
                dtrace(line)
            self.cached_read_data.append(output)

    def clear_cached_read_data(self):
        self.cached_read_data = []

    def get_cached_read_lines(self, clear=True, fmt=False, rmctrl=True):
        retval = self.format_output(self.cached_read_data, fmt, rmctrl)
        if clear: self.cached_read_data = []
        return retval

    def sysrq_trace(self):
        trace("============================== sysrq_trace ============================")
        if self.remote_conn is None:
            return None
        if self.protocol != "telnet":
            return None
        self.remote_conn.sock.sendall(telnetlib.IAC + telnetlib.BRK)
        time.sleep(1)
        self.remote_conn.sock.sendall(chr(108))
        output = self.send_command_timing("", delay_factor=1)
        trace(output)
        return output

    def write_channel(self, out_data):
        trace("============================== write_channel ============================")
        trace(self.dmsg_fmt(out_data))
        super(NetmikoConnection, self).write_channel(out_data)

    def read_channel(self):
        output = super(NetmikoConnection, self).read_channel()
        if output:
            trace("============================== read_channel ============================")
            self.add_cached_read_data(output)
        if not self.in_login:
            return output
        if re.search("1 - Assume the main session", output, flags=re.I):
            self.log_warn("Terminal server is used by someone else '{}'".format(output))
            self.log_warn("===== Sending 1 =========================")
            self.write_channel("1")
        elif re.search("1 - Initiate a regular session", output, flags=re.I):
            self.log_warn("Terminal server is used by someone else '{}'".format(output))
            self.log_warn("===== Sending 4 =========================")
            self.write_channel("4")
        elif re.search("Enter session PID or 'all'", output, flags=re.I):
            self.log_warn("Terminal server is used by someone else '{}'".format(output))
            self.log_warn("===== Sending all =========================")
            self.write_channel("all")
            self.write_channel("\n")
        elif re.search(r"Assumed the main session\(open_rw_session\)", output, flags=re.I):
            self.log_warn("Terminal server is used by someone else '{}'".format(output))
            self.log_warn("===== Sending new line =========================")
            self.write_channel("\n")
        elif re.search("WARNING: New user connected to this port", output, flags=re.I):
            self.log_warn("Terminal server is used by someone else '{}'".format(output))
        return output

    def verify_prompt(self, prompt2):
        regex_onie_resque = r"Please press Enter to activate this console.\s*$"
        prompt = prompt2.replace("\\", "")
        if re.compile(r"(.*[#|\$]\s*$)").match(prompt) and self.product == "sonic":
            return True
        if re.compile(r"(.*[#|>]\s*$)").match(prompt) and self.product != "sonic":
            return True
        if re.compile(r".*\(config.*\)#\s*$").match(prompt):
            return True
        if re.compile(r"\S+\s+login:\s*$").match(prompt):
            return True
        if re.compile(r"User:\s*$").match(prompt):
            return True
        if re.compile(r"^\s*ONIE:/ #\s*$").match(prompt):
            return True
        if re.compile(r"^\s*grub rescue>\s*$").match(prompt):
            return True
        if re.compile(regex_onie_resque).match(prompt):
            return True
        if re.compile(r"[Pp]assword:\s*$").match(prompt):
            return True
        if self.is_any_fastpath_product():
            if re.compile(r"\(dhcp-\d+-\d+-\d+-\d+\)\s*[#|>]\s*$").match(prompt):
                return True
            if re.compile(r"\(localhost\)\s*[#|>]\s*$").match(prompt):
                return True
        if "Waiting for the reboot operation to complete" in prompt:
            time.sleep(60)
            return False
        return False

    def disconnect(self):
        try: self.clear_buffer()
        except Exception: pass
        try: super(NetmikoConnection, self).disconnect()
        except Exception: pass
        trace("================== disconnect ============================")

    def init_prompt(self, attempts=5):
        for _ in range(attempts):
            output = self.find_prompt()
            if self.verify_prompt(output):
                return output
        return None

    def find_prompt_super(self, delay_factor=1):
        return super(NetmikoConnection, self).find_prompt(delay_factor)

    def find_prompt_new(self, delay_factor=1, use_cache=False):
        return self.find_prompt(delay_factor)

    def find_prompt(self, delay_factor=1):
        trace("============================== find_prompt ============================")
        max_try = 3
        for index in range(1, max_try + 1):
            try:
                self.clear_cached_read_data()
                delay_factor = get_delay_factor(delay_factor)
                rv = super(NetmikoConnection, self).find_prompt(delay_factor)
                rv = re.escape(rv)
                self.clear_cached_read_data()
                return rv
            except Exception as exp:
                delay_factor = delay_factor + 1
                exp_type = type(exp).__name__
                dbg_msg = ["Exception {} finding prompt try {}".format(exp_type, index)]
                dbg_msg = self.dmsg_str(dbg_msg, header="FIND-PROMPT-DBG")
                self.log_warn(dbg_msg)
                if index >= max_try:
                    raise IOError(dbg_msg)
                time.sleep(1)

    def strip_ansi_escape_codes(self, string_buffer):
        rv = super(NetmikoConnection, self).strip_ansi_escape_codes(string_buffer)
        if not self.fix_control_chars:
            rv = ctrl_chars.remove(rv)
            if rv: trace("================== strip_ansi_escape_codes ============================")
            try: self.trace_callback(self.trace_callback_arg1, self.trace_callback_arg2, rv)
            except Exception: trace(rv)
            if rv: trace("=======================================================================")
        return rv

    def trace_callback_set(self, callback, arg1, arg2):
        self.trace_callback = callback
        self.trace_callback_arg1 = arg1
        self.trace_callback_arg2 = arg2

    def is_strip_prompt(self, strip_prompt):
        if self.in_login:
            return False
        return strip_prompt

    def remove_prompt(self, output, expect_string, duplicate_only=False):
        if not output: return output
        if not expect_string: return output
        response_list = output.split(self.RESPONSE_RETURN)
        if len(response_list) < 2: return output
        last_line, before_line = response_list[-1], response_list[-2]
        if not re.match(expect_string, last_line): return output
        if duplicate_only:
            if not re.match(expect_string, before_line): return output
        return self.RESPONSE_RETURN.join(response_list[:-1])

    def remove_duplicate_prompt(self, output, expect_string):
        if os.getenv("SPYTEST_NETMIKO_REMOVE_DUPLICATE_PROMPT", "0") == "0": return output
        return self.remove_prompt(output, expect_string, True)

    def send_bytes(self, command_string, **kwargs):
        for c in command_string:
            self.write_channel(str(c))
            time.sleep(0.2)
        return self.send_command("", **kwargs)

    # pylint: disable=arguments-differ
    def send_command_timing(self, command_string, delay_factor=1, **kwargs):
        kwargs.pop("expect_string", None); kwargs.pop("auto_find_prompt", None)
        return super(NetmikoConnection, self).send_command_timing(command_string, **kwargs)

    # pylint: disable=arguments-differ
    def send_command(self, command_string, expect_string=None, delay_factor=1,
                     max_loops=500, auto_find_prompt=True, strip_prompt=True,
                     remove_prompt=False, **kwargs):
        kwargs.pop("use_cache", None)
        kwargs.pop("on_cr_recovery", None)
        if not is_netmiko2:
            kwargs["cmd_verify"] = False
        strip_prompt = self.is_strip_prompt(strip_prompt)
        self.clear_cached_read_data()
        delay_factor = get_delay_factor(delay_factor)
        retval = super(NetmikoConnection, self).send_command(command_string,
                                                             expect_string, delay_factor, max_loops, auto_find_prompt,
                                                             strip_prompt, **kwargs)
        self.clear_cached_read_data()
        retval = self.remove_duplicate_prompt(retval, expect_string)
        return self.remove_prompt(retval, expect_string) if remove_prompt else retval

    def send_command_new(self, fcli, command_string, expect_string, delay_factor,
                         max_loops=500, auto_find_prompt=True, strip_prompt=True,
                         remove_prompt=False, **kwargs):
        kwargs.pop("use_cache", None)
        if is_scmd(delay_factor) or fcli == 0 or expect_string is None:
            if "\n" in command_string and kwargs.get('normalize', True):
                cmd_list = []
                for cmd in command_string.split("\n"):
                    cmd_list.append(self.normalize_cmd(cmd))
                command_string = "\n".join(cmd_list)
            return self.send_command(command_string, expect_string,
                                     delay_factor, max_loops, auto_find_prompt,
                                     strip_prompt, remove_prompt, **kwargs)

        search_pattern = expect_string
        self.clear_cached_read_data()

        # Time to delay in each read loop
        loop_delay = 0.2

        # Default to making loop time be roughly equivalent to self.timeout (support old max_loops
        # and delay_factor arguments for backwards compatibility).
        delay_factor = get_delay_factor(delay_factor)
        delay_factor = self.select_delay_factor(delay_factor)
        if delay_factor == 1 and max_loops == 500:
            # Default arguments are being used; use self.timeout instead
            max_loops = int(self.timeout / loop_delay)

        self.clear_buffer()

        # remove multiple spaces and normalize
        command_string = self.remove_spaces(command_string)
        command_string = self.normalize_cmd(command_string)
        self.write_channel(command_string)

        # trying to use agressive loop delay
        loop_delay = loop_delay / 4
        max_loops = max_loops * 4
        # trying to use agressive loop delay

        # loop_sleep = loop_delay * delay_factor

        # trying to use constant loop sleep
        loop_sleep = loop_delay
        max_loops = max_loops * delay_factor
        # trying to use constant loop sleep

        i = 1
        output = ""
        cmd_issued = False

        # Keep reading data until search_pattern is found or until max_loops is reached.
        dbg_msg = []
        command_string = self.normalize_linefeeds(command_string)
        self.dmsg_append(dbg_msg, "command_string:", self.dmsg_fmt(command_string))
        self.dmsg_append(dbg_msg, "search_pattern:", self.dmsg_fmt(search_pattern))
        cmp_output_index = 0
        while i <= max_loops:
            new_data = self.read_channel()
            if not new_data:
                # check if the connection is live after 5 sec once in 5 seconds
                if self.check_live_connection and (i % 100 == 99):
                    if not self.is_alive():
                        for msg2 in self.get_cached_read_lines(clear=False):
                            self.dmsg_append(dbg_msg, "Read Data:", self.dmsg_fmt(msg2))
                        raise IOError(self.dmsg_str(dbg_msg, "Connection Lost"))
            else:
                if not self.fix_control_chars:
                    new_data = self.normalize_linefeeds(new_data)
                    new_data = self.strip_ansi_escape_codes(new_data)
                output += new_data
                self.dmsg_append(dbg_msg, "cmd_issued:", cmd_issued)

                # add debug log when the output matches without new line
                # this case arises when the command is not echoed and new line is also missing
                if not cmd_issued and "\n" not in output:
                    if re.search(search_pattern, output):
                        self.dmsg_append(dbg_msg, "MATCH-0")

                if not cmd_issued and "\n" in output:
                    self.dmsg_append(dbg_msg, "CMP-OUT:", self.dmsg_fmt(output))
                    self.dmsg_append(dbg_msg, "CMP-CMD:", self.dmsg_fmt(command_string))
                    if command_string in output:
                        parts = output.partition(command_string)
                        cmd_issued = True
                        output = "".join(parts[2:])
                        self.dmsg_append(dbg_msg, "ECHOED", "OUTPUT:", self.dmsg_fmt(output))
                        out_lines = []
                    else:
                        out_lines = output.split("\r\n")
                    for index, line in enumerate(out_lines):
                        line2 = line.strip()
                        if not line2:
                            self.dmsg_append(dbg_msg, "BLANK LINE")
                            continue
                        if re.match(search_pattern, line2):
                            self.dmsg_append(dbg_msg, "MATCH PROMPT LINE: ", line2)
                            continue
                        if not re.search(search_pattern, line2):
                            cmd_issued = True
                            output = "\r\n".join(out_lines[index:])
                            self.dmsg_append(dbg_msg, "NON-PROMPT ", "INDEX:", index,
                                             "OUTPUT:", self.dmsg_fmt(output))
                            break
                        self.dmsg_append(dbg_msg, "HAS-PROMPT?", self.dmsg_fmt(line2))

                if cmd_issued:
                    # Check if we have already found our pattern
                    cmp_out_lines = self.dmsg_fmt(output).split("<LF>")
                    self.dmsg_append(dbg_msg, "CMP-PROMPT:", self.dmsg_fmt(search_pattern))
                    for index in range(cmp_output_index, len(cmp_out_lines)):
                        self.dmsg_append(dbg_msg, "CMP-OUTPUT:", cmp_out_lines[index])
                    cmp_output_index = len(cmp_out_lines) - 1
                    if re.search(search_pattern, output):
                        self.dmsg_append(dbg_msg, "MATCH-1")
                        break

                    output2 = re.sub(r"\r", repl="", string=output)
                    if re.search(search_pattern, output2):
                        self.dmsg_append(dbg_msg, "MATCH-2")
                        break

            time.sleep(loop_sleep)
            i += 1
        else:  # nobreak
            msg1 = "Prompt Not Detected in DF {}: '{}'"
            msg1 = msg1.format(delay_factor, search_pattern)
            for msg2 in self.get_cached_read_lines(clear=False):
                self.dmsg_append(dbg_msg, "Read Data:", self.dmsg_fmt(msg2))
            raise IOError(self.dmsg_str(dbg_msg, msg1))

        self.clear_cached_read_data()

        output = self.normalize_linefeeds(output)

        retval = self.remove_duplicate_prompt(output, expect_string)
        return self.remove_prompt(retval, expect_string) if remove_prompt else retval

    def dmsg_fmt(self, data):
        msg = ctrl_chars.tostring(data)
        msg = msg.replace("\n", "<LF>")
        msg = msg.replace("\r", "<CR>")
        return msg

    def dmsg_hex(self, data):
        msg = ":".join("{:02x}".format(ord(c)) for c in data)
        return "'{}'".format(msg)

    def dmsg_str(self, dbg_msg, s="", header="FASTER-CLI-DBG"):
        s = s + "\n======================={}===================".format(header)
        s = s + "\n" + "\n".join(dbg_msg)
        s = s + "\n=========================================================="
        return s

    def dmsg_append(self, dbg_msg, *args):
        msg = ctrl_chars.remove(*args)
        dtrace(msg)
        dbg_msg.append(msg)

    def remove_spaces(self, cmd):
        retlist, inq, prev = [], False, None
        for ch in list(cmd):
            if ch in ["'", "\""]:
                inq = bool(not inq)
            if prev and not inq:
                if ch in [" ", "\t"]:
                    if prev == ch:
                        continue
            prev = ch
            retlist.append(ch)
        return "".join(retlist)

    def put_file(self, local_path, remote_path):
        scp_conn = netmiko.SCPConn(self)
        scp_conn.scp_put_file(local_path, remote_path)
        scp_conn.close()

    def get_file(self, remote_path, local_path):
        scp_conn = netmiko.SCPConn(self)
        scp_conn.scp_get_file(remote_path, local_path)
        scp_conn.close()
