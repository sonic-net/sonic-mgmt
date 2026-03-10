import re
import os
import sys

from spytest import st

username_regex = r"[a-z_]([a-z0-9_-]{0,31}|[a-z0-9_-]{0,30}\$)"
hostname_regex = r"(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])"


class LinuxHooks(object):

    def get_vars(self, dut, phase=None):
        retval = dict()
        retval["mgmt_ifname"] = st.get_mgmt_ifname(dut)
        retval["mgmt_ipv4"] = st.get_mgmt_ip(dut)
        retval["version"] = self.show_version(dut)
        retval["hwsku"] = "Linux"
        return retval

    def is_kdump_supported(self, dut):
        return False

    def pre_load_image(self, dut):
        return False

    def post_cli_recovery(self, scope, dut, cmd, attempt=0):
        # scope is session/module/function
        # return True to bail-out, False to ignore, None to retry
        return True

    def post_reboot(self, dut, is_upgrade=False):
        return False

    def post_config_reload(self, dut):
        return False

    def post_login(self, dut, **kwargs):
        commands = ["export TMOUT=0", "stty cols 5000", "uptime"]
        kwargs.setdefault("on_cr_recover", "retry5")
        kwargs.setdefault("sudo", False)
        st.config(dut, commands, **kwargs)

    def post_session(self, dut):
        return False

    def init_config(self, dut, type, hwsku=None, profile="na"):
        return False

    def extend_config(self, dut, type, ifname_type="none"):
        return False

    def verify_config(self, dut, type):
        return True

    def save_config(self, dut, type):
        return True

    def apply_config(self, dut, phase):
        return True

    def clear_config(self, dut, **kwargs):
        return True

    def shutdown(self, dut, portlist):
        st.log("TODO: shutdown {}".format(portlist), dut=dut)
        for port in portlist:
            cmd = "ifconfig {} down".format(port)
            st.config(dut, cmd, on_cr_recover="retry5")
        return True

    def noshutdown(self, dut, portlist):
        st.log("TODO: noshutdown {}".format(portlist), dut=dut)
        for port in portlist:
            cmd = "ifconfig {} up".format(port)
            st.config(dut, cmd, on_cr_recover="retry5")
        return True

    def fill_kwargs(self, **kwargs):
        kwargs.setdefault("strip_prompt", True)
        kwargs.setdefault("remove_prompt", True)
        kwargs.setdefault("skip_tmpl", True)
        kwargs.setdefault("skip_error_check", True)
        kwargs.setdefault("on_cr_recover", "retry5")
        return kwargs

    def get_status(self, dut, port_csv):
        retval, kwargs = [], self.fill_kwargs()
        for port in port_csv.split(","):
            output = st.show(dut, "cat /sys/class/net/{}/operstate".format(port), **kwargs)
            retval.append({"interface": port, "oper": output, "admin": "up"})
        return retval

    def get_interface_status(self, dut, port_csv):
        retval = self.get_status(dut, port_csv)
        return retval[0]["oper"] if retval else None

    def show_version(self, dut, **kwargs):
        kwargs = self.fill_kwargs(**kwargs)
        return st.show(dut, "lsb_release -d -s", **kwargs)

    def get_system_status(self, dut, service=None, **kwargs):
        return True

    def verify_topology(self, hooks, check_type, threads=True, skip_tgen=False):
        from apis.common import checks
        return checks.verify_topology(hooks, check_type, threads, skip_tgen)

    def set_port_defaults(self, dut, breakout, speed):
        return True

    def clear_logging(self, dut, **kwargs):
        pass

    def fetch_syslogs(self, dut, severity=None, since=None):
        pass

    def ifa_enable(self, dut):
        pass

    def ztp_disable(self, dut, **kwargs):
        pass

    def kdump_enable(self, dut):
        return True

    def upgrade_image(self, dut, url, max_time=1800, skip_error_check=False, migartion=True):
        return "success"

    def set_mgmt_ip_gw(self, dut, ipmask, gw, **kwargs):
        pass

    def get_mgmt_ip(self, dut, interface, **kwargs):
        mgmt_ifname = st.get_mgmt_ifname(dut)
        cmd = "ifconfig {}".format(mgmt_ifname)
        output = st.show(dut, cmd, on_cr_recover="retry5")
        ipaddr = output[0]['ip_address']
        return ipaddr

    def renew_mgmt_ip(self, dut, interface, **kwargs):
        st.log("TODO: renew_mgmt_ip {}".format(interface), dut=dut)

    def upgrade_libsai(self, dut, url):
        pass

    def get_ifname_type(self, dut):
        return st.get_ifname_type(dut)

    def set_ifname_type(self, dut, ifname_type):
        pass

    def get_physical_ifname_map(self, dut):
        return None

    def debug_system_status(self, dut, log_file=None):
        pass

    def dut_reboot(self, dut, **kwargs):
        return True

    def get_onie_grub_config(self, dut, mode):
        return "", []

    def init_features(self, fgroup, fsupp=None, funsupp=None):
        from apis.common.sonic_features import Feature
        return Feature(fgroup, fsupp, funsupp)

    def init_support(self, hooks, cfg, dut=None):
        from apis.common.support import Support
        return Support(hooks, cfg, dut)

    def init_prompts(self, model=None, logger=None, normal_user_mode=None):
        from apis.common.linux_prompts import Prompts
        return Prompts("linux", logger, normal_user_mode)

    def exec_ssh_remote_dut(self, dut, ipaddress, username, password, command=None, timeout=30, **kwargs):
        pass

    def verify_prompt(self, dut, prompt):
        prompt = prompt.replace("\\", "")
        if re.compile(r"{}@{}:.*[#|\$]\s*$".format(username_regex, hostname_regex)).match(prompt):
            return True, False
        return False, False

    def get_base_prompt(self, dut, **kwargs):
        return "Linux"

    def get_hostname(self, dut, **kwargs):
        return "Linux"

    def set_hostname(self, dut, name):
        pass

    def verify_device_info(self, dut, phase):
        return True

    def dump_config_db(self, dut):
        pass

    def show_sai_profile(self, dut):
        pass

    def is_reboot_confirm(self, dut):
        return False

    def show_dut_time(self, dut):
        pass

    def gnmi_cert_config_ensure(self, dut):
        pass

    def get_mode(self, dut, which):
        if which == "normal-user":
            return "normal-user"
        return "unknown-mode"

    def get_regex(self, dut, which, *args):
        if which == "sudopass":
            return r"\[sudo\] password for {}:".format(*args)
        if which == "login":
            return r"User:\s*$"
        if which == "login_anywhere":
            return r"User:\s*"
        if which == "anyprompt":
            if st.get_device_type(dut) in ["icos"]:
                return r"[#|>|\$]\s*$"
            return r"[#|>]\s*$"
        return "unknown"

    def get_default_pass(self, dut):
        return ""

    def get_templates_info(self, dut, model):
        return "templates", "sonic"

    def get_custom_ui(self, dut):
        return "click"

    def get_cli_type_record(self, dut, cli_type):
        file_name = sys._getframe(5).f_code.co_filename
        file_name = os.path.basename(file_name)
        func_name = sys._getframe(5).f_code.co_name
        return "{}::{},{}".format(file_name, func_name, cli_type)

    def verify_ui_support(self, dut, cli_type, cmd):
        return cli_type

    def audit(self, atype, dut, *args, **kwargs):
        return None

    def read_syslog(self, dut, lvl, phase, name):
        return ""

    def read_core(self, dut, name):
        return ""

    def read_tech_support(self, dut, name):
        return ""

    def read_sysinfo(self, dut, scope, name):
        return {}

    def check_kdump_files(self, dut):
        return False

    def clear_kdump_files(self, dut):
        return False

    def check_core_files(self, dut):
        return False

    def clear_core_files(self, dut):
        return False

    def save_config_db(self, dut, scope, name):
        return False

    def save_running_config(self, dut, scope, name):
        return False

    def verify_config_replace(self, dut, scope, res, desc):
        return res, desc

    def verify_command(self, dut, cmd, cli_type):
        return cmd
