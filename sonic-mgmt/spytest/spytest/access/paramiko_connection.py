
import os
import re
import time
import socket
import logging

import telnetlib
try: from time import monotonic as _time
except Exception: from monotonic import monotonic as _time

import paramiko

from spytest.dlog import DebugLogger
from spytest.access.utils import max_time_from_delay_factor

from utilities import ctrl_chars
from utilities.common import stack_trace
from utilities.exceptions import DeviceConnectionError
# from utilities.exceptions import DeviceConnectionTimeout
from utilities.exceptions import DeviceAuthenticationFailure
from utilities.exceptions import DeviceNotConnectedError
from utilities.exceptions import DeviceConnectionLostError

live_trace = bool(os.getenv("SPYTEST_LIVE_TRACE_OUTPUT", "0") != "0")
mylog = DebugLogger(None, name="paramiko", en_log=live_trace)

show_trace = int(os.getenv("SPYTEST_DEBUG_DEVICE_CONNECTION", "0"))


def init_trace(val):
    if val <= 0: return None
    logger = logging.getLogger('paramiko_connection')
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


class ParamikoConnection:

    def __init__(self, **kwargs):
        self.trace_callback = None
        self.trace_callback_arg1 = None
        self.trace_callback_arg2 = None
        device_type = kwargs.get("device_type", None)
        if device_type.endswith("_terminal"):
            kwargs['device_type'] = "{}_telnet".format(device_type)
        self.net_login = kwargs.pop("net_login", None)
        self.net_devname = kwargs.pop("net_devname", None)
        self.logger = kwargs.pop("logger", None)
        self.pri_prompt_terminator = '$'
        self.alt_prompt_terminator = '#'
        self.prompt_terminator = r"(#|\$)\s*$"
        self.prompt_unix_password = r"(#|\$|\(current\) UNIX password:|Current password:)\s*$"
        self.alt_telnet_prompt = r'\$\s*$'
        self.in_login = False
        self.product = "sonic"
        if "product" in kwargs:
            self.product = kwargs["product"]
            del kwargs["product"]
        if "altpassword" in kwargs:
            self.altpassword = kwargs["altpassword"]
            del kwargs["altpassword"]
        self.update_prompt_terminator()

        self.username = kwargs["username"]
        self.password = kwargs["password"]
        self.device_type = kwargs["device_type"]
        self.is_telnet = bool("_telnet" in self.device_type)
        self.protocol = "telnet" if self.is_telnet else "ssh"
        self.conn = None
        try:
            self.conn = self.make_connection(self.is_telnet, **kwargs)
        except paramiko.AuthenticationException:
            msg = "Connection Authentication Error"
            self.log_warn(msg)
            raise DeviceAuthenticationFailure(msg)
        except DeviceAuthenticationFailure:
            msg = "Connection Authentication Error"
            self.log_warn(msg)
            raise DeviceAuthenticationFailure(msg)
        except Exception as e:
            msg = "Connection " + self.check_exception(e)
            self.log_exception(msg, call_stack=True)
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

    def update_prompt_terminator(self):
        if self.product == "sonic0":
            self.pri_prompt_terminator = '$'
            self.alt_prompt_terminator = '#'
            self.prompt_terminator = r"(#|\$)\s*$"
            self.prompt_unix_password = r"(#|\$|\(current\) UNIX password:|Current password:)\s*$"
        elif self.product == "sonic":
            self.pri_prompt_terminator = '$'
            self.alt_prompt_terminator = '#'
            self.prompt_terminator = r"(#|>|\$)\s*$"
            self.prompt_unix_password = r"(#|>|\$|\(current\) UNIX password:|Current password:)\s*$"
        else:
            self.pri_prompt_terminator = '>'
            self.alt_prompt_terminator = '#'
            self.prompt_terminator = r"(#|>)\s*$"
            self.prompt_unix_password = r"(#|>|\(current\) UNIX password:|Current password:)\s*$"

    def set_logger(self, logger):
        self.logger = logger
        if self.conn:
            self.conn.set_logger(logger)

    def set_log_level(self, en_trace, en_log):
        if self.conn:
            self.conn.set_log_level(en_trace, en_log)

    def log_warn(self, msg, rmctrl=True):
        if isinstance(msg, list):
            for line in msg:
                self.log_warn(line)
            return
        msg1 = ctrl_chars.remove(msg) if rmctrl else msg
        for msg2 in msg1.splitlines():
            if self.net_devname:
                msg2 = "{}: {}".format(self.net_devname, msg2)
            if self.logger:
                self.logger.warning(msg2)
            else:
                print(msg2)

    def log_exception(self, msg, dump=None, call_stack=True):
        self.log_warn("======== Connection: {} ======".format(msg))
        self.log_warn(stack_trace(None, call_stack))
        if dump is not None:
            self.log_warn("--------------------------------------------")
            self.log_warn(self.get_cached_read_lines(), rmctrl=False)
        self.log_warn("============================================")

    def change_password(self, username, new_password, output=None):
        retype_expect = self.prompt_terminator
        if output is None:
            retype_expect = r"passwd: password updated successfully\s*"
            prompt_terminator = r"Enter new UNIX password:|New password:"
            output = self.send_command("sudo passwd {}".format(username),
                                       expect_string=prompt_terminator,
                                       strip_command=False, strip_prompt=False,
                                       use_cache=False)
        trace("========= change_password_1: {} =========".format(output))
        if "Enter new UNIX password:" in output:
            output += self.send_command(new_password, expect_string="Retype new UNIX password:",
                                        strip_command=False, strip_prompt=False,
                                        use_cache=False)
        trace("========= change_password_2: {} =========".format(output))
        if "Retype new UNIX password:" in output:
            output += self.send_command(new_password, expect_string=retype_expect,
                                        strip_command=False, strip_prompt=False,
                                        use_cache=False)
            trace("========= change_password_3: {} =========".format(output))
            return [True, output]
        trace("========= change_password_4: {} =========".format(output))
        if "New password:" in output:
            output += self.send_command(new_password, expect_string="Retype new password:",
                                        strip_command=False, strip_prompt=False,
                                        use_cache=False)
        trace("========= change_password_5: {} =========".format(output))
        if "Retype new password:" in output:
            output += self.send_command(new_password, expect_string=retype_expect,
                                        strip_command=False, strip_prompt=False,
                                        use_cache=False)
            trace("========= change_password_6: {} =========".format(output))
            return [True, output]
        return [False, output]

    def extended_login(self, output):
        trace("========= extended_login_1: {} =========".format(output))
        if self.device_type == "sonic_sshcon":
            if self.net_login and self.net_devname:
                self.net_login(self.net_devname, self)
        rv = bool("(current) UNIX password:" in output or "Current password:" in output)
        if rv:
            prompt_terminator = r"Enter new UNIX password:|New password:"
            output = self.send_command(self.password, expect_string=prompt_terminator,
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
        trace("========= extended_login_2: {} {} =========".format(rv, output))
        return rv, output

    def clear_cached_read_data(self):
        if self.conn:
            self.conn.clear_cached_read_data()

    def get_cached_read_lines(self, clear=True, fmt=False, rmctrl=True):
        retval, lines = [], []
        if self.conn:
            for line in self.conn.get_cached_read_lines(clear):
                if rmctrl: line = ctrl_chars.remove(line)
                lines.append(line)
            for line in re.split('\r|\n', "".join(lines)):
                if fmt: line = self.dmsg_fmt(line)
                if not line: continue
                line = line.strip()
                if not line: continue
                retval.append(line)
        return retval

    def sysrq_trace(self):
        trace("============================== sysrq_trace ============================")
        """
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
        """
        return None

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
        if re.compile(r"^\s*ONIE:/ #\s*$").match(prompt):
            return True
        if re.compile(r"^\s*grub rescue>\s*$").match(prompt):
            return True
        if re.compile(regex_onie_resque).match(prompt):
            return True
        if re.compile(r"[Pp]assword:\s*$").match(prompt):
            return True
        if re.compile(r"(.*y\/n\](\:)*\s*)$").match(prompt):
            return True
        if re.compile(r"(.*y\/N\](\:)*\s*)$").match(prompt):
            return True
        if re.compile(r"(.*Y\/n\](\:)*\s*)$").match(prompt):
            return True
        if re.compile(r"(.*Y\/N\](\:)*\s*)$").match(prompt):
            return True
        return False

    def clear_buffer(self):
        trace("================== clear_buffer ============================")

    def disconnect(self):
        trace("================== disconnect ============================")
        return self.conn.close()

    def init_prompt(self, attempts=5):
        for _ in range(attempts):
            output = self.conn.init_prompt()
            if self.verify_prompt(output):
                return output
        return None

    def find_prompt_super(self, delay_factor=1):
        return self.conn.find_prompt(use_cache=False)

    def find_prompt_new(self, delay_factor=1, use_cache=True):
        return self.conn.find_prompt(use_cache=use_cache)

    def find_prompt(self, delay_factor=1):
        return self.conn.find_prompt(use_cache=False)

    def trace_callback_set(self, callback, arg1, arg2):
        self.trace_callback = callback
        self.trace_callback_arg1 = arg1
        self.trace_callback_arg2 = arg2

    def is_strip_prompt(self, strip_prompt):
        if self.in_login:
            return False
        return strip_prompt

    def normalize_cmd(self, command):
        command = command.rstrip()
        command += "\r\n" if self.is_telnet else "\n"
        return command

    def send_command_timing(self, command_string, delay_factor=0.01,
                            max_loops=150, strip_prompt=True, **kwargs):
        timeout = max_time_from_delay_factor(delay_factor)
        use_cache = kwargs.get("use_cache", True)
        wait_time = kwargs.get("wait_time", 0)
        return self.conn.send_command_timing(command_string, timeout=timeout,
                                             use_cache=use_cache, wait_time=wait_time)

    def send_command(self, command_string, expect_string=None, delay_factor=1,
                     max_loops=500, auto_find_prompt=True, strip_prompt=True,
                     **kwargs):
        timeout = max_time_from_delay_factor(delay_factor)
        timeout = kwargs.get("timeout", timeout)
        use_cache = kwargs.get("use_cache", True)
        wait_time = kwargs.get("wait_time", 0)
        return self.conn.send_command(command_string, expect_string,
                                      timeout=timeout, use_cache=use_cache,
                                      wait_time=wait_time)

    def send_command_new(self, fcli, command_string, expect_string, delay_factor,
                         max_loops=500, auto_find_prompt=True, strip_prompt=True,
                         **kwargs):
        if "\n" in command_string and kwargs.get('normalize', True):
            cmd_list = []
            for cmd in command_string.split("\n"):
                cmd_list.append(self.normalize_cmd(cmd))
            command_string = "\n".join(cmd_list)
        return self.send_command(command_string, expect_string,
                                 delay_factor, max_loops, auto_find_prompt,
                                 strip_prompt, **kwargs)

    def dmsg_fmt(self, data, nl="\n"):
        msg = ctrl_chars.tostring(data)
        msg = msg.replace("\n", "<LF>")
        msg = msg.replace("\r", "<CR>")
        return msg

    def put_file(self, local_path, remote_path):
        self.conn.put_file(local_path, remote_path)

    def get_file(self, remote_path, local_path):
        self.conn.get_file(remote_path, local_path)

    def make_connection(self, is_telnet, **kwargs):
        ip, port = kwargs.pop("ip"), kwargs.pop("port")
        user, pwd = kwargs.pop("username"), kwargs.pop("password")
        if is_telnet:
            conn = DeviceConnection(BaseConnection.TELNET, ip, port, user, pwd, **kwargs)
        else:
            conn = DeviceConnection(BaseConnection.SSH, ip, port, user, pwd, **kwargs)

        # initiate connection
        conn.connect()

        # fill the last prompt
        conn.find_prompt()

        return conn


class DeviceConnection:

    def __init__(self, con_type, ip_addr, port, username, password, **kwargs):
        if con_type == "ssh":
            self.con_type = BaseConnection.SSH
        elif con_type == "telnet":
            self.con_type = BaseConnection.TELNET
        else:
            self.con_type = con_type
        self.port = port
        self.username = username
        self.password = password
        self.__is_connected = False
        self.patterns_1 = [r'login:$', r'Password:$', r'.*\$', r'.*#']
        self.patterns_2 = ['Enter your option :']
        self.patterns_2.append('Type the hot key to suspend the connection: <CTRL>Z')
        self.patterns_2.append('Login incorrect')
        self.patterns_2.extend([r'.*login:', r'Password:', r'.*\$', r'.*#', r'.*>'])
        self.conn = BaseConnection.new(self.con_type, self, ip_addr, port, 60)
        self.__last_tn_write = ''
        self.last_prompt = ''

    def clear_cached_read_data(self):
        self.conn.clear_cached_read_data()

    def get_cached_read_lines(self, clear=True):
        return self.conn.get_cached_read_lines(clear)

    def __decode_telnet_data(self, data):
        output, _ = self.conn.decode_output(data, self.__last_tn_write)
        self.log("RECV: ", output)
        return output

    def __telnet_write(self, command):
        self.__last_tn_write = command
        self.log("SEND: ", command)
        self.conn.send('{}\n'.format(command))
        return

    def set_logger(self, logger):
        if self.conn:
            self.conn.set_logger(logger)

    def set_log_level(self, en_trace, en_log):
        if self.conn:
            self.conn.set_log_level(en_trace, en_log)

    def log(self, which, text):
        mylog.info("{}{}".format(which, text))

    def init_prompt(self):
        return self.conn.find_prompt(self.patterns_1, False)

    def find_prompt(self, use_cache=True):
        self.log("REMOVE-ME: ", "find_prompt: expect: {} use_cache: {}".format(self.patterns_1, use_cache))
        return self.conn.find_prompt(self.patterns_1, use_cache)

    def send_command_timing(self, command_string, timeout=5, use_cache=True, wait_time=0):
        self.log("REMOVE-ME: ", "send_command_timing: {} expect: {} use_cache: {}".format(command_string, self.patterns_1, use_cache))
        _, output = self.conn.send_cmd_raw(command_string, self.patterns_1, ignore_timeout=True,
                                           use_cache=use_cache, wait_time=wait_time)
        return output

    def send_command(self, command_string, expect_string, timeout=10, use_cache=True, wait_time=0):
        if not expect_string:
            expect_string = self.conn.get_last_prompt()
            expect_string = re.escape(expect_string)

        self.log("REMOVE-ME: ", "send_command: {} expect: {} timeout: {}".format(command_string, expect_string, timeout))
        prompt, output = self.conn.send_cmd_cli(command_string.strip(), [re.compile(expect_string)],
                                                timeout=timeout, ignore_timeout=False,
                                                use_cache=use_cache, wait_time=wait_time)
        return "{}\n{}".format(output, prompt)

    def close(self):
        self.conn.close()

    def disconnect(self):
        self.close()

    def get_file(self, remote_path, local_path):
        self.conn.get_file(remote_path, local_path)

    def put_file(self, local_path, remote_path):
        self.conn.put_file(local_path, remote_path)

    def connect(self, reconnect=False):
        if self.con_type == BaseConnection.SSH:
            self.conn.connect(self.username, self.password)
            return

        self.conn.connect()
        all_patterns = self.patterns_2
        max_retry, timeout = 4, 2
        last, autherr = None, False
        while max_retry > 0:
            max_retry -= 1
            data = self.conn.expect(all_patterns, timeout=timeout, silent=False)
            output = self.__decode_telnet_data(data)
            if data[0] == -1:
                time.sleep(1)
                if last is None or last == '^C':
                    self.conn.send('\n')
                    last = '\n'
                elif last == '\n':
                    self.conn.send('\x03')
                    last = '^C'
            elif data[0] == 0:
                self.__telnet_write('1')
            elif data[0] == 1:
                self.conn.send('\n')
            elif data[0] == 2:
                self.log("AUTH: ", "invalid password!")
                autherr = True
                self.log("AUTH: ", "send username")
                self.__telnet_write(self.username)
            elif data[0] == 3:
                if 'Last login:' not in output:
                    self.log("AUTH: ", "send username")
                    self.__telnet_write(self.username)
                else:
                    self.log("OK: ", 'Console connection done')
                    self.__is_connected = True
                    break
            elif data[0] == 4:
                self.log("AUTH: ", "send password")
                self.__telnet_write(self.password)
            else:
                self.log("OK: ", 'Console connection done')
                self.__is_connected = True
                break

        if not self.__is_connected:
            self.log("Fail: ", 'Console connection failed')
            if autherr:
                self.close()
                raise DeviceAuthenticationFailure("invalid password!")


class BaseConnection(object):
    CMD_TYPE_CLI = 1
    CMD_TYPE_RAW = 2

    SSH = "ssh"
    TELNET = "telnet"

    ANSI_ESCAPE_REGEX = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

    def __init__(self, device, ip_addr, port, timeout):
        self.device = device
        self.ip_addr = ip_addr
        self.port = port
        self.timeout = timeout
        self.last_prompt = ''
        self.enter_char = '\n'
        self.cached_read_data = []

    def add_cached_read_data(self, output):
        if output: self.cached_read_data.append(output)

    def clear_cached_read_data(self):
        self.cached_read_data = []

    def get_cached_read_lines(self, clear=True):
        retval = []
        for line in self.cached_read_data:
            retval.append(line)
        if clear: self.cached_read_data = []
        return retval

    @staticmethod
    def new(conn_type, device, ip_addr, port, timeout=10):
        if conn_type == BaseConnection.SSH:
            return SshConnection(device, ip_addr, port, timeout)
        elif conn_type == BaseConnection.TELNET:
            return TelnetConnection(device, ip_addr, port, timeout)

    @property
    def is_connected(self):
        return self.is_active()

    @property
    def name(self):
        return self.device.name

    def is_active(self):
        pass

    def connect(self, username=None, password=None):
        pass

    def close(self):
        pass

    def send(self, send_str, raw=False):
        pass

    def set_logger(self, logger):
        mylog.set_logger(logger)

    def set_log_level(self, en_trace, en_log):
        mylog.set_log_level(en_trace, en_log)

    def recv(self):
        return None

    def recv_flush(self):
        return None

    def decode_recv(self, data):
        ignore_patterns = [r"\[.*\]\s*serial\d+: too much work for irq\d+"]
        if data:
            data = data.decode("utf-8", "ignore")
            data = data.replace('\r', '')
            data = data.replace('\x1bE', '')
            for pattern in ignore_patterns:
                data = re.sub(pattern, '', data)
            mylog.verbose("REMOVE-ME: decode_recv: {}".format(data))
        else:
            data = ""
        return data

    def check_timeout(self, timeout, deadline):
        if timeout is not None:
            timeout = deadline - _time()
            if timeout < 0:
                return True
        return False

    def expect(self, exp_list, send_str=None, timeout=120, silent=False, skip_first_line=True):
        if type(exp_list) is not list:
            exp_list = [exp_list]

        indices = range(len(exp_list))
        cooked, text = '', ''
        num_match = 1
        first_line_found = False
        first_line_trace = False

        for i in indices:
            if not hasattr(exp_list[i], "search"):
                exp_list[i] = re.compile(exp_list[i])
            if send_str is None:
                continue
            if exp_list[i].search(send_str):
                num_match = 2

        deadline = _time() + timeout
        poll_time = float(1.0 / 200)

        while True:
            data = self.recv()
            if not data:
                time.sleep(poll_time)
                if self.check_timeout(timeout, deadline):
                    break
                else:
                    continue

            text += data

            if skip_first_line and not first_line_found:
                if '\n' in text:
                    text = '\n' + text.split('\n', 1)[1]
                    first_line_found = True
                else:
                    continue

            if not silent or mylog.no_silent:
                decoded_data = self.decode_string(data)
                if skip_first_line and not first_line_trace:
                    if '\n' in decoded_data:
                        decoded_data = '\n' + decoded_data.split('\n', 1)[1]
                        first_line_trace = True
                    else:
                        continue

                mylog.recv(self.device, decoded_data)

            for i in indices:
                m = exp_list[i].search(text)
                if m:
                    num_match = num_match - 1
                    cooked = text[:m.end()]
                    text = text[m.end():]
                    if num_match == 0:
                        return i, m, cooked + text

            if self.check_timeout(timeout, deadline):
                break

        return -1, None, cooked + text

    def decode_string(self, string):
        try: string = string.decode("ascii", "ignore")
        except Exception: pass
        return ctrl_chars.remove(string)

    def decode_output(self, data, command, remove_command=True):
        if not data[2]:
            return '', False

        output = self.decode_string(data[2])
        output = output.replace('\r', '')
        cmd_found, output0 = False, output
        # Replace the first occurrence only which is the command
        if remove_command and command and '\n' in output:
            cmd_found, output = output.split('\n', 1)
            mylog.verbose('decode_output: Cmd:{} Found:{} orig:{}'.format(command, cmd_found, output0))
        output = re.sub(self.ANSI_ESCAPE_REGEX, '', output)

        return output, cmd_found

    def send_cmd(self, cmd_type, command, expect, timeout=3, silent=True,
                 ignore_timeout=False, use_cache=True, wait_time=0):

        mylog.verbose('type:{} cmd:{} timeout:{} silent:{}'.format(cmd_type, command, timeout, silent))
        mylog.verbose('expect:{} ignore_tmout:{}'.format(expect, ignore_timeout))

        if not self.is_connected:
            msg = 'Not able execute "{}". Not connected to device'.format(command)
            mylog.not_run(msg)
            raise DeviceNotConnectedError(msg)

        output = None
        retry = 0
        data = (-1, None, None)
        cmd_stripped = command.strip()
        while retry < 20:
            retry += 1
            mylog.verbose("retry {}".format(retry))
            if not silent or mylog.no_silent:
                mylog.send(self, command)

            try:
                mylog.verbose('Write Cmd={}'.format(command))
                self.recv_flush()
                if wait_time > 0:
                    time.sleep(wait_time)
                self.send('{}{}'.format(command, self.enter_char))
                data = self.expect(expect, send_str=command, timeout=timeout, silent=silent)
            except Exception as e:
                mylog.exception(e)
                # self.close()
                raise DeviceConnectionLostError('Connection lost to {} {} '.format(self.ip_addr, self.port))

            mylog.verbose('Output [{}] [{}] [{}]'.format(data[0], data[1], self.decode_string(data[2])))
            output, _ = self.decode_output(data, cmd_stripped)
            mylog.verbose('Silent:{} Out:{}'.format(silent, output))

            if data[0] != -1 or ignore_timeout:
                break

            mylog.fail("Command '{}' timed out".format(command))
            if not self.is_connected:
                raise DeviceConnectionLostError('Connection to {} {} lost '.format(self.ip_addr, self.port))
            else:
                raise DeviceConnectionLostError('Session to {} {} stuck/closed '.format(self.ip_addr, self.port))

        if cmd_type != self.CMD_TYPE_RAW:
            mylog.verbose('Last Prompt Match:{} Group:{}'.format(data[1], data[1].group))
            cmd_prompt = data[1].group()  # .decode()

            if use_cache and timeout < 300:
                self.last_prompt = cmd_prompt
            else:
                self.last_prompt = ''
            cmd_output = output.replace(cmd_prompt, '')
            if len(cmd_output) and cmd_output[-1] == '\n':
                cmd_output = cmd_output[:-1]
            mylog.verbose('Output is {}'.format(cmd_output))
            mylog.verbose('last line is {}'.format(cmd_prompt))
        else:
            cmd_output = output
            cmd_prompt = ''
            self.last_prompt = output

        return cmd_prompt, cmd_output

    def send_cmd_raw(self, command, expect, timeout=3, silent=True,
                     ignore_timeout=False, use_cache=True, wait_time=0):
        self.clear_cached_read_data()
        rv = self.send_cmd(self.CMD_TYPE_RAW, command, expect, timeout,
                           silent, ignore_timeout, use_cache, wait_time)
        self.clear_cached_read_data()
        return rv

    def send_cmd_cli(self, command, expect, timeout=3, silent=True,
                     ignore_timeout=False, use_cache=True, wait_time=0):
        self.clear_cached_read_data()
        rv = self.send_cmd(self.CMD_TYPE_CLI, command, expect, timeout,
                           silent, ignore_timeout, use_cache, wait_time)
        self.clear_cached_read_data()
        return rv

    def find_prompt(self, expect, use_cache=True):
        if self.last_prompt and use_cache:
            return re.escape(self.last_prompt)
        output = self.send_cmd_raw('', expect, ignore_timeout=True)[1] or ""
        prompt = output.strip().split("\n")[-1]
        if prompt: self.set_last_prompt(prompt)
        mylog.verbose("==== find_prompt({}) {} -- {}".format('', prompt, output))
        return re.escape(prompt)

    def get_last_prompt(self):
        return self.last_prompt

    def set_last_prompt(self, prompt):
        self.last_prompt = prompt

    def get_file(self, remote_path, local_path):
        pass

    def put_file(self, local_path, remote_path):
        pass


class TelnetConnection(BaseConnection):
    def __init__(self, device, ip_addr, port=23, timeout=10):
        super(TelnetConnection, self).__init__(device, ip_addr, port, timeout)
        self.enter_char = "\r\n"
        self.enter_char = "\n"
        self.__telnet = None
        self._is_connected = None

    def connect(self, username=None, password=None):
        # nosemgrep-next-line
        self.__telnet = telnetlib.Telnet(self.ip_addr, self.port, self.timeout)
        self._is_connected = True
        # self.__telnet.set_debuglevel(10)

    def close(self):
        self._is_connected = False
        self.__telnet.close()

    def is_active(self):
        return self._is_connected

    def send(self, send_str, raw=False):
        if raw:
            self.__telnet.write(send_str)
        else:
            self.__telnet.write(send_str.encode('ascii'))

    def recv(self):
        data = self.__telnet.read_very_eager()
        data = self.decode_recv(data)
        self.add_cached_read_data(data)
        return data


class SshConnection(BaseConnection):

    def __init__(self, device, ip_addr, port=22, timeout=10):
        super(SshConnection, self).__init__(device, ip_addr, port, timeout)
        self.enter_char = "\n"
        self.__ssh = None
        self.__ssh_channel = None

    def connect(self, username=None, password=None):
        self.__ssh = paramiko.SSHClient()
        self.__ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        if username and password:
            self.__ssh.connect(self.ip_addr, self.port, username, password, look_for_keys=False)
        else:
            self.__ssh.connect(self.ip_addr, self.port, username, password)
        self.__ssh.get_transport().set_keepalive(60)
        self.__ssh_channel = self.__ssh.invoke_shell(term='vt100', width=300, height=3000)

    def close(self):
        if self.__ssh:
            self.__ssh.close()
            self.__ssh = None
            self.__ssh_channel = None

    def is_active(self):
        if self.__ssh is not None and self.__ssh.get_transport() is not None:
            return self.__ssh.get_transport().is_active()

        return False

    def send(self, send_str, raw=False):
        self.__ssh_channel.sendall(send_str)

    def recv(self):
        data = b""
        while self.__ssh_channel.recv_ready():
            data = data + self.__ssh_channel.recv(65533)
        data = self.decode_recv(data)
        self.add_cached_read_data(data)
        return data

    def recv_flush(self):
        while self.__ssh_channel.recv_ready():
            self.__ssh_channel.recv(65533)

    def get_file(self, remote_path, local_path):
        sftp = paramiko.SFTPClient.from_transport(self.__ssh.get_transport())
        try:
            sftp.get(remote_path, local_path)
            retval = True
            mylog.success('File copy done from {} to {}'.format(remote_path, local_path))
        except IOError:
            retval = False
            mylog.fail('File copy failed from {} to {}'.format(remote_path, local_path))

        sftp.close()
        return retval

    def put_file(self, local_path, remote_path):
        sftp = paramiko.SFTPClient.from_transport(self.__ssh.get_transport())
        try:
            sftp.put(local_path, remote_path)
            retval = True
            mylog.success('File copy done from {} to {}'.format(local_path, remote_path))
        except IOError:
            retval = False
            mylog.fail('File copy failed from {} to {}'.format(local_path, remote_path))

        sftp.close()
        return retval
