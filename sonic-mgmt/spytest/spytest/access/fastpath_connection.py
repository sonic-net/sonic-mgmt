from __future__ import unicode_literals

import re
import time
import logging
import socket
from netmiko.cisco_base_connection import CiscoBaseConnection

show_trace = 0
if show_trace > 1:
    logger = logging.getLogger('netmiko_connection')
    logger.setLevel(logging.DEBUG)

def trace(fmt, *args):
    if show_trace <= 0:
        return
    msg = fmt % args
    if show_trace > 1:
        logger.info(msg)
    else:
        print(msg)

def dtrace(*args):
    if show_trace > 2:
        print(args)

class FastpathBaseConnection(CiscoBaseConnection):

    def __init__(self, **kwargs):
        self.net_login = kwargs.pop("net_login", None)
        self.net_devname = kwargs.pop("net_devname", None)
        if "altpassword" in kwargs:
            self.altpassword = kwargs["altpassword"]
            del kwargs["altpassword"]
        super(FastpathBaseConnection, self).__init__(**kwargs)

    def set_logger(self, logger):
        self.logger = logger

    def log_warn(self, msg):
        if not getattr(self, "logger", None):
            print(msg)
        else:
            self.logger.warning(msg)

    def session_preparation(self):
        trace("============================== session_preparation ============================")
        self.ansi_escape_codes = True
        if self.protocol == "ssh":
            return self.ssh_session_preparation()
        else:
            return super(FastpathBaseConnection, self).session_preparation()


    def ssh_session_preparation(self):
        """
        Added extended_login to the base function for handling the password change in ssh scenario.
        """
        output = self._test_channel_read()
        output = self.extended_login(output)
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

    def set_base_prompt(self, pri_prompt_terminator='>',
                        alt_prompt_terminator='#', delay_factor=1):
        trace("============================== set_base_prompt ============================")
        return super(FastpathBaseConnection, self).set_base_prompt(
            pri_prompt_terminator=pri_prompt_terminator,
            alt_prompt_terminator=alt_prompt_terminator,
            delay_factor=delay_factor)

    def change_password(self, username, new_password, output=None):
        if output is None:
            output = self.send_command("sudo passwd {}".format(username), expect_string="Enter new UNIX password:", strip_command=False, strip_prompt=False)
        if "Enter new UNIX password:" in output:
            output += self.send_command(new_password, expect_string="Retype new UNIX password:", strip_command=False, strip_prompt=False)
        if "Retype new UNIX password:" in output:
            pri_prompt_terminator_new = r"(#|\$|passwd: password updated successfully)\s*$"
            output += self.send_command(new_password, expect_string=pri_prompt_terminator_new, strip_command=False, strip_prompt=False)
            return [True, output]
        return [False, output]

    def extended_login(self, output):
        if "(current) UNIX password:" in output:
            output = self.send_command(self.password, expect_string="Enter new UNIX password:", strip_command=False, strip_prompt=False)
            retval = self.change_password(self.username, self.altpassword, output)
            output += retval[1]
            if retval[0]:
                if self.protocol == "ssh" and "passwd: password updated successfully" in retval[1]:
                    self.disconnect()
                    raise socket.error("Spytest: socket is closed abruptly")
                else:
                    retval2 = self.change_password(self.username, self.password)
                    output += retval2[1]
        return output

    def telnet_login(self, pri_prompt_terminator=r'#\s*$', alt_prompt_terminator=r'>\s*$',
                     username_pattern=r"(?:[Uu]ser:|sername|ogin|User Name)",
                     pwd_pattern=r"assword",
                     delay_factor=1, max_loops=20):
        trace("============================== telnet_login ============================")
        setattr(self, "in_sonic_login", 1)
        pri_prompt_terminator_new = r"(#|>|\(current\) UNIX password:)\s*$"
        output = super(FastpathBaseConnection, self).telnet_login(
            pri_prompt_terminator_new, alt_prompt_terminator, username_pattern,
            pwd_pattern, delay_factor, max_loops)
        output = self.extended_login(output)
        setattr(self, "in_sonic_login", None)
        return output

    def add_cached_read_data(self, output):
        if not output:
            return
        try:
            self.cached_read_data.append(output)
        except:
            self.cached_read_data = [output]

    def clear_cached_read_data(self):
        self.cached_read_data = []

    def get_cached_read_data(self):
        retval = self.cached_read_data
        self.cached_read_data = []
        return retval

    def sysrq_trace(self):
        trace("============================== sysrq_trace ============================")
        if self.remote_conn is None:
            return None
        if self.protocol != "telnet":
            return None
        import telnetlib
        self.remote_conn.sock.sendall(telnetlib.IAC + telnetlib.BRK)
        time.sleep(1)
        self.remote_conn.sock.sendall(chr(108))
        output = self.send_command_timing("", delay_factor=1)
        trace(output)
        return output

    def read_channel(self):
        trace("============================== read_channel ============================")
        output = super(FastpathBaseConnection, self).read_channel()
        self.add_cached_read_data(output)
        if not getattr(self, "in_sonic_login", None):
            return output
        if re.search("1 - Assume the main session", output, flags=re.I):
            self.log_warn("Terminal server is used by someone else '{}'".format(output))
            self.write_channel("1")
        elif re.search("1 - Initiate a regular session", output, flags=re.I):
            self.log_warn("Terminal server is used by someone else '{}'".format(output))
            #self.write_channel("1")
            self.write_channel("4")
        elif re.search("Enter session PID or 'all'", output, flags=re.I):
            self.log_warn("Terminal server is used by someone else '{}'".format(output))
            self.write_channel("all")
            self.write_channel("\n")
        elif re.search(r"Assumed the main session\(open_rw_session\)", output, flags=re.I):
            self.log_warn("Terminal server is used by someone else '{}'".format(output))
            self.write_channel("\n")
        elif re.search("WARNING: New user connected to this port", output, flags=re.I):
            self.log_warn("Terminal server is used by someone else '{}'".format(output))
        return output

    def verify_prompt(self, prompt2):
        regex_onie_resque = r"\s+Please press Enter to activate this console.\s*$"
        prompt = prompt2.replace("\\", "")
        if re.compile(r"(.*[#|\$]\s*$)").match(prompt):
            return True
        if re.compile(r".*\(config.*\)#\s*$").match(prompt):
            return True
        if re.compile(r"\S+\s+login:\s*$").match(prompt):
            return True
        if re.compile(r"^\s*ONIE:/ #\s*$").match(prompt):
            return True
        if re.compile(regex_onie_resque).match(prompt):
            return True
        if re.compile(r"[Pp]assword:\s*$").match(prompt):
            return True
        if re.compile(r"\(Broadcom FASTPATH Routing\)\s*>\s*$").match(prompt):
            return True
        if re.compile(r"\(dhcp-\d+-\d+-\d+-\d+\)\s*>\s*$").match(prompt):
            return True
        return False

    def find_prompt(self, delay_factor=1):
        trace("============================== find_prompt ============================")
        try:
            self.clear_cached_read_data()
            rv = super(FastpathBaseConnection, self).find_prompt(delay_factor)
            rv = re.escape(rv)
            self.clear_cached_read_data()
            return rv
        except Exception as exp:
            raise exp

    def strip_ansi_escape_codes(self, string_buffer):
        rv = super(FastpathBaseConnection, self).strip_ansi_escape_codes(string_buffer)
        trace("================== strip_ansi_escape_codes ============================")
        try:
            callback, arg = getattr(self, "trace_callback", [None, None])
            if callback:
                callback(arg, rv)
            else:
                trace(rv)
        except:
            pass
        trace("=======================================================================")
        return rv

    def trace_callback_set(self, callback, arg):
        setattr(self, "trace_callback", [callback, arg])

    def send_command(self, command_string, expect_string=None, delay_factor=1,
                     max_loops=500, auto_find_prompt=True, strip_prompt=True,
                     strip_command=True, normalize=True, use_textfsm=False,
                     use_genie=False):
        self.clear_cached_read_data()
        retval = super(FastpathBaseConnection, self).send_command(command_string,
                   expect_string, delay_factor, max_loops, auto_find_prompt,
                   strip_prompt, strip_command, normalize, use_textfsm)
        self.clear_cached_read_data()
        return retval

    def send_command_new(self, fcli, command_string, expect_string=None, delay_factor=1,
                     max_loops=500, auto_find_prompt=True, strip_prompt=True,
                     strip_command=True, normalize=True, use_textfsm=False):

        if delay_factor > 2 or fcli == 0:
            if "\n" in command_string:
                cmd_list = []
                for cmd in command_string.split("\n"):
                    cmd_list.append(self.normalize_cmd(cmd))
                command_string = "".join(cmd_list)
            return self.send_command(command_string,
                   expect_string, delay_factor, max_loops, auto_find_prompt,
                   strip_prompt, strip_command, normalize, use_textfsm)

        self.clear_cached_read_data()
        # Time to delay in each read loop
        loop_delay = 0.2

        # Default to making loop time be roughly equivalent to self.timeout (support old max_loops
        # and delay_factor arguments for backwards compatibility).
        delay_factor = self.select_delay_factor(delay_factor)
        if delay_factor == 1 and max_loops == 500:
            # Default arguments are being used; use self.timeout instead
            max_loops = int(self.timeout / loop_delay)

        # Find the current router prompt
        if expect_string is None:
            if auto_find_prompt:
                try:
                    prompt = self.find_prompt(delay_factor=delay_factor)
                except ValueError:
                    prompt = self.base_prompt
            else:
                prompt = self.base_prompt
            search_pattern = re.escape(prompt.strip())
        else:
            search_pattern = expect_string

        if normalize:
            command_string = self.normalize_cmd(command_string)

        self.clear_buffer()

        self.write_channel(command_string)

        # trying to use agressive loop delay
        loop_delay = loop_delay/4
        max_loops = max_loops * 4
        # trying to use agressive loop delay

        loop_sleep = loop_delay * delay_factor

        # trying to use constant loop sleep
        loop_sleep = loop_delay
        max_loops = max_loops * delay_factor
        # trying to use constant loop sleep

        i = 1
        output = ""
        mark_seen = False

        # Keep reading data until search_pattern is found or until max_loops is reached.
        dbg_msg = []
        dtrace("command_string:", command_string)
        while i <= max_loops:
            new_data = self.read_channel()
            if new_data:
                if self.ansi_escape_codes:
                    new_data = self.strip_ansi_escape_codes(new_data)

                output += new_data

                dtrace("output", mark_seen, output)
                dbg_msg.append("{}:{}".format(mark_seen, output))

                if not mark_seen:
                    if re.search(command_string, output):
                        parts = output.partition(command_string)
                        dtrace("Mark-1", parts)
                        mark_seen = True
                        output = "".join(parts[2:])
                        dbg_msg.append("Mark-1:'{}'".format(output))
                        out_lines = []
                    else:
                        out_lines = output.split("\r\n")
                    for index,line in enumerate(out_lines):
                        line2 = line.strip()
                        dtrace("LINE", line, line2, search_pattern, re.search(search_pattern, line2))
                        if not line2:
                            dtrace("BLANK LINE")
                            continue
                        if re.match(search_pattern, line2):
                            dtrace("PROMPT LINE")
                            continue
                        dtrace("NON PROMPT LINE", line2)
                        if not re.search(search_pattern, line2):
                            mark_seen = True
                            output = "\r\n".join(out_lines[index:])
                            dtrace("Mark-2", index, output)
                            dbg_msg.append("Mark-2:'{}'".format(output))
                            break
                    if not mark_seen:
                        time.sleep(loop_sleep)
                        i += 1
                        continue

                # Check if we have already found our pattern
                dtrace("CMP-1", expect_string, search_pattern, output)
                if re.search(search_pattern, output):
                    dtrace("MATCH-1")
                    break

                output2 = re.sub(r"\r", repl="", string=output)
                if re.search(search_pattern, output2):
                    dtrace("MATCH-2")
                    break

            time.sleep(loop_sleep)
            i += 1
        else:  # nobreak
            msg = "Search pattern: '{}' never detected CMD: '{}'\nDBG: '{}'"
            msg = msg.format(search_pattern, command_string, "\n".join(dbg_msg))
            raise IOError(msg)

        self.clear_cached_read_data()

        output = self.normalize_linefeeds(output)

        return output

class FastpathSshConnection(FastpathBaseConnection):
    pass

