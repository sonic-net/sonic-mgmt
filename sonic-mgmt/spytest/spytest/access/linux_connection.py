
import os
import re
import time
import logging

import netmiko

from utilities import ctrl_chars
from utilities.common import stack_trace
from utilities.exceptions import DeviceConnectionError
from utilities.exceptions import DeviceConnectionTimeout
from utilities.exceptions import DeviceAuthenticationFailure

from spytest.access.utils import get_delay_factor
from spytest.access.utils import check_console_ip

is_netmiko2 = bool(netmiko.__version__.split(".")[0] == '2')


def get_trace_lvl():
    return int(os.getenv("SPYTEST_DEBUG_DEVICE_CONNECTION", "0"))


def init_trace(val):
    if val <= 0: return None
    logger = logging.getLogger('netmiko_connection')
    logger.setLevel(logging.DEBUG)
    return logger


logger = init_trace(get_trace_lvl())
logger = None


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


class LinuxConnection(netmiko.cisco_base_connection.CiscoSSHConnection):

    def __init__(self, **kwargs):
        self.trace_callback = None
        self.trace_callback_arg1 = None
        self.trace_callback_arg2 = None
        self.cached_read_data = []
        self.logger = kwargs.pop("logger", None)
        self.altpassword = kwargs.pop("altpassword", None)
        self.parent = kwargs.pop("parent", None)
        self.net_devname = kwargs.pop("net_devname", None)
        self.net_login = kwargs.pop("net_login", None)
        self.change_pass = kwargs.pop("change_pass", None)
        self.fix_control_chars = bool(os.getenv("SPYTEST_FIX_DEVICE_CONTROL_CHARS", "0") != "0")

        logf = logger.warning if logger else None
        access_ip = kwargs.get("ip", None)
        if not check_console_ip(access_ip, logf):
            raise DeviceConnectionTimeout("Access IP {} Not Reachable".format(access_ip))

        for try_index in range(5):
            try:
                super(LinuxConnection, self).__init__(**kwargs)
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
            if self.logger:
                self.logger.log(lvl, msg2)
            else:
                print(msg2)

    def log_warn(self, msg, rmctrl=True, dump=False):
        self.log_lvl(logging.WARNING, msg, rmctrl, dump)

    def log_info(self, msg, rmctrl=True, dump=False):
        self.log_lvl(logging.INFO, msg, rmctrl, dump)

    def log_exception(self, msg, call_stack=True, dump=False, prefix="Connection: {}"):
        self.log_warn("======== {} {} ======".format(msg, prefix))
        self.log_warn(stack_trace(None, call_stack))
        if dump:
            self.log_warn("--------------------------------------------")
            self.log_warn(self.get_cached_read_lines(), rmctrl=False)
        self.log_warn("============================================")

    def session_preparation(self):
        self._test_channel_read()
        self.set_base_prompt()
        time.sleep(0.3 * self.global_delay_factor)
        self.clear_buffer()
        self.base_prompt = self.init_prompt()

    def set_base_prompt(self, pri_prompt_terminator=None,
                        alt_prompt_terminator=None, delay_factor=1):
        return super(LinuxConnection, self).set_base_prompt(
            pri_prompt_terminator=pri_prompt_terminator or "$",
            alt_prompt_terminator=alt_prompt_terminator or "#",
            delay_factor=delay_factor)

    def log_send(self, cmd):
        msg = ">>> {}".format(cmd)
        self.log_info(msg)
        return msg

    def log_recv(self, output):
        self.log_info(output)
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

    def write_channel(self, out_data):
        trace("============================== write_channel ============================")
        trace(self.dmsg_fmt(out_data))
        super(LinuxConnection, self).write_channel(out_data)

    def read_channel(self):
        output = super(LinuxConnection, self).read_channel()
        if output:
            trace("============================== read_channel ============================")
            self.add_cached_read_data(output)
        return output

    def disconnect(self):
        try: self.clear_buffer()
        except Exception: pass
        try: super(LinuxConnection, self).disconnect()
        except Exception: pass
        trace("================== disconnect ============================")

    def init_prompt(self, attempts=5):
        return self.find_prompt()

    def find_prompt_new(self, delay_factor=1, use_cache=False):
        return self.find_prompt(delay_factor)

    def find_prompt(self, delay_factor=1):
        trace("============================== find_prompt ============================")
        max_try = 3
        for index in range(1, max_try + 1):
            try:
                self.clear_cached_read_data()
                delay_factor = get_delay_factor(delay_factor)
                rv = super(LinuxConnection, self).find_prompt(delay_factor)
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
        rv = super(LinuxConnection, self).strip_ansi_escape_codes(string_buffer)
        if not self.fix_control_chars:
            trace("================== strip_ansi_escape_codes ============================")
            rv = ctrl_chars.remove(rv)
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

    # pylint: disable=arguments-differ
    def send_command(self, command_string, expect_string=None, delay_factor=1,
                     max_loops=500, auto_find_prompt=True, strip_prompt=True,
                     remove_prompt=False, **kwargs):
        kwargs.pop("use_cache", None)
        kwargs.pop("on_cr_recovery", None)
        if not is_netmiko2:
            kwargs["cmd_verify"] = False
        self.clear_cached_read_data()
        delay_factor = get_delay_factor(delay_factor)
        retval = super(LinuxConnection, self).send_command(command_string,
                                                           expect_string, delay_factor, max_loops, auto_find_prompt,
                                                           strip_prompt, **kwargs)
        self.clear_cached_read_data()
        return self.remove_prompt(retval, expect_string) if remove_prompt else retval

    def send_command_new(self, fcli, command_string, expect_string, delay_factor,
                         max_loops=500, auto_find_prompt=True, strip_prompt=True,
                         remove_prompt=False, **kwargs):
        kwargs.pop("use_cache", None)
        if "\n" in command_string:
            cmd_list = []
            for cmd in command_string.split("\n"):
                cmd_list.append(self.normalize_cmd(cmd))
            command_string = "\n".join(cmd_list)
        return self.send_command(command_string, expect_string,
                                 delay_factor, max_loops, auto_find_prompt,
                                 strip_prompt, remove_prompt, **kwargs)

    def dmsg_fmt(self, data):
        msg = ctrl_chars.tostring(data)
        msg = msg.replace("\n", "<LF>")
        msg = msg.replace("\r", "<CR>")
        return msg

    def dmsg_str(self, dbg_msg, s="", header="FASTER-CLI-DBG"):
        s = s + "\n======================={}===================".format(header)
        s = s + "\n" + "\n".join(dbg_msg)
        s = s + "\n=========================================================="
        return s

    def put_file(self, local_path, remote_path):
        scp_conn = netmiko.SCPConn(self)
        scp_conn.scp_put_file(local_path, remote_path)
        scp_conn.close()

    def get_file(self, remote_path, local_path):
        scp_conn = netmiko.SCPConn(self)
        scp_conn.scp_get_file(remote_path, local_path)
        scp_conn.close()
