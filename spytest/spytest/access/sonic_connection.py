from __future__ import unicode_literals

import os
import re
import time
import socket
import logging
import telnetlib
from netmiko.cisco_base_connection import CiscoBaseConnection

import sys
if sys.version_info[0] >= 3:
    unicode = str

show_trace = 0
def init_trace(val):
    if val <= 0: return None
    logger = logging.getLogger('netmiko_connection')
    logger.setLevel(logging.DEBUG)
    return logger
logger = init_trace(show_trace)

def trace(fmt, *args):
    if show_trace <= 0:
        return
    msg = fmt % args
    if show_trace > 1 and logger:
        logger.info(msg)
    else:
        print(msg)

def dtrace(*args):
    if show_trace > 2:
        print(args)

def get_delay_factor(current):
    try: factor = float(os.getenv("SPYTEST_NETMIKO_DELAY_FACTOR", "1"))
    except Exception: factor = 1.0
    return current * factor

class SonicBaseConnection(CiscoBaseConnection):

    def __init__(self, **kwargs):
        self.trace_callback = None
        self.trace_callback_arg1 = None
        self.trace_callback_arg2 = None
        self.cached_read_data = []
        self.net_login = kwargs.pop("net_login", None)
        self.net_devname = kwargs.pop("net_devname", None)
        self.logger = kwargs.pop("logger", None)
        self.pri_prompt_terminator = '$'
        self.alt_prompt_terminator = '#'
        self.prompt_terminator = r"(#|\$)\s*$"
        self.prompt_unix_password = r"(#|\$|\(current\) UNIX password:)\s*$"
        self.alt_telnet_prompt = r'\$\s*$'
        self.in_sonic_login = False
        self.product = "sonic"
        if "product" in kwargs:
            self.product = kwargs["product"]
            del kwargs["product"]
        if "altpassword" in kwargs:
            self.altpassword = kwargs["altpassword"]
            del kwargs["altpassword"]
        self.update_prompt_terminator()
        try:
            super(SonicBaseConnection, self).__init__(**kwargs)
        except Exception as exp:
            self.log_warn("============= Connection Failed ============")
            self.log_warn(str(exp))
            for msg in "".join(self.get_cached_read_data()).split("\n"):
                msg = re.sub(r'(\x9B|\x1B\[)[0-?]*[ -\/]*[@-~]', ' ', msg)
                msg = re.sub(r'[^\x00-\x7F]+', ' ', msg)
                if not msg: continue
                msg = msg.strip()
                if not msg: continue
                self.log_warn(msg)
            self.log_warn("============================================")
            raise exp

    def set_product(self, product="sonic"):
        self.product = product
        self.update_prompt_terminator()

    def update_prompt_terminator(self):
        if self.product == "sonic0":
            self.pri_prompt_terminator = '$'
            self.alt_prompt_terminator = '#'
            self.prompt_terminator = r"(#|\$)\s*$"
            self.prompt_unix_password = r"(#|\$|\(current\) UNIX password:)\s*$"
        elif self.product == "sonic":
            self.pri_prompt_terminator = '$'
            self.alt_prompt_terminator = '#'
            self.prompt_terminator = r"(#|>|\$)\s*$"
            self.prompt_unix_password = r"(#|>|\$|\(current\) UNIX password:)\s*$"
        else:
            self.pri_prompt_terminator = '>'
            self.alt_prompt_terminator = '#'
            self.prompt_terminator = r"(#|>)\s*$"
            self.prompt_unix_password = r"(#|>|\(current\) UNIX password:)\s*$"

    def set_logger(self, logger):
        self.logger = logger

    def log_warn(self, msg):
        if self.net_devname:
            msg2 = "{}: {}".format(self.net_devname, msg)
        else:
            msg2 = msg
        if self.logger:
            self.logger.warning(msg2)
        else:
            print(msg2)

    def session_preparation(self):
        trace("============================== session_preparation ============================")
        self.ansi_escape_codes = True
        if self.protocol == "ssh":
            return self.ssh_session_preparation()
        else:
            return super(SonicBaseConnection, self).session_preparation()

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

    def disable_paging(self, command="terminal length 0", delay_factor=1):
        return ""

    def set_base_prompt(self, pri_prompt_terminator=None,
                        alt_prompt_terminator=None, delay_factor=1):
        if pri_prompt_terminator is None: pri_prompt_terminator = self.pri_prompt_terminator
        if alt_prompt_terminator is None: alt_prompt_terminator = self.alt_prompt_terminator
        trace("============================== set_base_prompt ============================")
        return super(SonicBaseConnection, self).set_base_prompt(
            pri_prompt_terminator=pri_prompt_terminator,
            alt_prompt_terminator=alt_prompt_terminator,
            delay_factor=delay_factor)

    def change_password(self, username, new_password, output=None):
        retype_expect = self.prompt_terminator
        if output is None:
            retype_expect = r"passwd: password updated successfully\s*"
            output = self.send_command("sudo passwd {}".format(username),
                                       expect_string="Enter new UNIX password:",
                                       strip_command=False, strip_prompt=False)
        trace("========= change_password_1: {} =========".format(output))
        if "Enter new UNIX password:" in output:
            output += self.send_command(new_password, expect_string="Retype new UNIX password:",
                                        strip_command=False, strip_prompt=False)
        trace("========= change_password_2: {} =========".format(output))
        if "Retype new UNIX password:" in output:
            output += self.send_command(new_password, expect_string=retype_expect,
                                        strip_command=False, strip_prompt=False)
            trace("========= change_password_3: {} =========".format(output))
            return [True, output]
        return [False, output]

    def extended_login(self, output):
        trace("========= extended_login_1: {} =========".format(output))
        if self.device_type == "sonic_sshcon":
            if self.net_login and self.net_devname:
                self.net_login(self.net_devname, self)
        if "(current) UNIX password:" in output:
            output = self.send_command(self.password, expect_string="Enter new UNIX password:",
                                       strip_command=False, strip_prompt=False)
            retval = self.change_password(self.username, self.altpassword, output)
            output += retval[1]
            if retval[0]:
                if self.protocol == "ssh" and "passwd: password updated successfully" in retval[1]:
                    self.disconnect()
                    raise socket.error("Spytest: socket is closed abruptly")
                else:
                    retval2 = self.change_password(self.username, self.password)
                    output += retval2[1]
        trace("========= extended_login_2: {} =========".format(output))
        return output

    def telnet_login(self, pri_prompt_terminator=None, alt_prompt_terminator=None,
                     username_pattern=r"(?:[Uu]ser:|sername|ogin|User Name)",
                     pwd_pattern=r"assword",
                     delay_factor=1, max_loops=20):
        trace("============================== telnet_login ============================")
        self.in_sonic_login = True
        try:
            output = super(SonicBaseConnection, self).telnet_login(
                self.prompt_unix_password, self.alt_telnet_prompt,
                username_pattern, pwd_pattern, delay_factor, max_loops)
            output = self.extended_login(output)
        except Exception as exp:
            trace("========= telnet_failed: {} =========".format(str(exp)))
            self.in_sonic_login = False
            raise exp
        self.in_sonic_login = False
        trace("========= telnet_login: {} =========".format(output))
        return output

    def add_cached_read_data(self, output):
        if not output:
            return
        try:
            self.cached_read_data.append(output)
        except Exception:
            self.cached_read_data = [output]

    def clear_cached_read_data(self):
        self.cached_read_data = []

    def get_cached_read_data(self):
        retval = self.cached_read_data
        self.cached_read_data = []
        return retval

    def get_cached_read_lines(self):
        retval, data = [], "".join(self.get_cached_read_data())
        for msg in self.dmsg_fmt(data).split("\n"):
            if not msg: continue
            msg = msg.strip()
            if not msg: continue
            retval.append(msg)
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

    def read_channel(self):
        trace("============================== read_channel ============================")
        output = super(SonicBaseConnection, self).read_channel()
        self.add_cached_read_data(output)
        if not self.in_sonic_login:
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
        regex_onie_resque = r"\s+Please press Enter to activate this console.\s*$"
        prompt = prompt2.replace("\\", "")
        if re.compile(r"(.*[#|\$]\s*$)").match(prompt) and self.product == "sonic":
            return True
        if re.compile(r"(.*[#|>]\s*$)").match(prompt) and self.product != "sonic":
            return True
        if re.compile(r".*\(config.*\)#\s*$").match(prompt):
            return True
        if re.compile(r"\S+\s+login:\s*$").match(prompt):
            return True
        if re.compile(r"^\s*ONIE:/ #\s*$").match(prompt):
            return True
        if re.compile(r"^\s*grub rescue>\s*$").match(prompt):
            return True
        if re.compile(regex_onie_resque).match(prompt):
            return True
        if re.compile(r"[Pp]assword:\s*$").match(prompt):
            return True
        return False

    def find_prompt(self, delay_factor=1):
        trace("============================== find_prompt ============================")
        try:
            self.clear_cached_read_data()
            delay_factor = get_delay_factor(delay_factor)
            rv = super(SonicBaseConnection, self).find_prompt(delay_factor)
            rv = re.escape(rv)
            self.clear_cached_read_data()
            return rv
        except Exception as exp:
            dbg_msg = ["Exception occured while trying to find the prompt"]
            raise IOError(self.dmsg_str(dbg_msg, str(exp), header="FIND-PROMPT-DBG"))

    def strip_ansi_escape_codes(self, string_buffer):
        rv = super(SonicBaseConnection, self).strip_ansi_escape_codes(string_buffer)
        trace("================== strip_ansi_escape_codes ============================")
        try:
            self.trace_callback(self.trace_callback_arg1, self.trace_callback_arg2, rv)
        except Exception:
            trace(rv)
        trace("=======================================================================")
        return rv

    def trace_callback_set(self, callback, arg1, arg2):
        self.trace_callback = callback
        self.trace_callback_arg1 = arg1
        self.trace_callback_arg2 = arg2

    def is_strip_prompt(self, strip_prompt):
        if self.in_sonic_login:
            return False
        return strip_prompt

    def send_command(self, command_string, expect_string=None, delay_factor=1,
                     max_loops=500, auto_find_prompt=True, strip_prompt=True,
                     strip_command=True, normalize=True, use_textfsm=False,
                     use_genie=False):
        strip_prompt = self.is_strip_prompt(strip_prompt)
        self.clear_cached_read_data()
        delay_factor = get_delay_factor(delay_factor)
        retval = super(SonicBaseConnection, self).send_command(command_string,
                   expect_string, delay_factor, max_loops, auto_find_prompt,
                   strip_prompt, strip_command, normalize, use_textfsm)
        self.clear_cached_read_data()
        return retval

    def send_command_new(self, fcli, command_string, expect_string, delay_factor,
                     max_loops=500, auto_find_prompt=True, strip_prompt=True,
                     strip_command=True, normalize=True, use_textfsm=False):

        if delay_factor > 2 or fcli == 0 or expect_string is None:
            if "\n" in command_string:
                cmd_list = []
                for cmd in command_string.split("\n"):
                    cmd_list.append(self.normalize_cmd(cmd))
                command_string = "\n".join(cmd_list)
            return self.send_command(command_string,
                   expect_string, delay_factor, max_loops, auto_find_prompt,
                   strip_prompt, strip_command, normalize, use_textfsm)

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

        # remove multiple spaces
        command_string = self.remove_spaces(command_string)

        command_string = self.normalize_cmd(command_string)
        self.write_channel(command_string)

        # trying to use agressive loop delay
        loop_delay = loop_delay/4
        max_loops = max_loops * 4
        # trying to use agressive loop delay

        #loop_sleep = loop_delay * delay_factor

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
        #self.dmsg_append(dbg_msg, "command_string_hex:", self.dmsg_hex(command_string))
        #self.dmsg_append(dbg_msg, "search_pattern_hex:", self.dmsg_hex(search_pattern))
        while i <= max_loops:
            new_data = self.read_channel()
            if new_data:
                new_data = self.normalize_linefeeds(new_data)
                new_data = self.strip_ansi_escape_codes(new_data)
                output += new_data
                output = self.strip_ansi_escape_codes(output)
                output = self.normalize_linefeeds(output)

                self.dmsg_append(dbg_msg, "cmd_issued:", cmd_issued)
                if not cmd_issued and "\n" in output:
                    self.dmsg_append(dbg_msg, "CMP-OUT:", self.dmsg_fmt(output))
                    self.dmsg_append(dbg_msg, "CMP-CMD:", self.dmsg_fmt(command_string))
                    #self.dmsg_append(dbg_msg, "CMP-OUT:", self.dmsg_hex(output))
                    #self.dmsg_append(dbg_msg, "CMP-CMD:", self.dmsg_hex(command_string))
                    if command_string in output:
                        parts = output.partition(command_string)
                        cmd_issued = True
                        output = "".join(parts[2:])
                        self.dmsg_append(dbg_msg, "ECHOED ", "output:", self.dmsg_fmt(output))
                        out_lines = []
                    else:
                        out_lines = output.split("\r\n")
                    for index,line in enumerate(out_lines):
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
                                             "output:", self.dmsg_fmt(output))
                            break
                        self.dmsg_append(dbg_msg, "HAS-PROMPT?", self.dmsg_fmt(line2))

                if cmd_issued:
                    # Check if we have already found our pattern
                    self.dmsg_append(dbg_msg, "CMP-PROMPT:", self.dmsg_fmt(search_pattern))
                    self.dmsg_append(dbg_msg, "CMP-OUTPUT:", self.dmsg_fmt(output))
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
            msg1 = "Search pattern: '{}' never detected".format(search_pattern)
            for msg2 in "".join(self.cached_read_data).split("\n"):
                self.dmsg_append(dbg_msg, "Read Data: ", self.dmsg_fmt(msg2, ""))
            raise IOError(self.dmsg_str(dbg_msg, msg1))

        self.clear_cached_read_data()

        output = self.normalize_linefeeds(output)

        return output


    def _tostring(self, msg):
        msg = re.sub(r'(\x9B|\x1B\[)[0-?]*[ -\/]*[@-~]', ' ', msg)
        msg = re.sub(r'[^\x00-\x7F]+', ' ', msg)
        try:
            return msg.encode('ascii', 'ignore').decode('ascii')
        except Exception as exp:
            print(str(exp))
        return "non-ascii characters"

    def dmsg_fmt(self, data, nl="\n"):
        msg = self._tostring(data)
        #msg = msg.replace("\r\n", "<CR><LF>MY_SPYTEST_DELIM")
        #msg = msg.replace("\n", "<LF>MY_SPYTEST_DELIM")
        #msg = msg.replace("\r", "<CR>MY_SPYTEST_DELIM")
        #msg = msg.replace("MY_SPYTEST_DELIM", nl)
        msg = msg.replace("\n", "<LF>")
        msg = msg.replace("\r", "<CR>")
        return msg

    def dmsg_hex(self, data):
        msg = ":".join("{:02x}".format(ord(c)) for c in data)
        return "'{}'".format(msg)

    def dmsg_str(self, dbg_msg, s = "", header="FASTER-CLI-DBG"):
        s = s + "\n======================={}===================".format(header)
        s = s + "\n" + "\n".join(dbg_msg)
        s = s + "\n=========================================================="
        return s

    def dmsg_append(self, dbg_msg, *args):
        try:
            msg = " ".join(map(str,args))
        except UnicodeEncodeError:
            msg = " ".join(map(unicode,args))
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


class SonicSshConnection(SonicBaseConnection):
    pass

