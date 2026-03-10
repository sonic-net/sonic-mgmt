import re
import os
import sys
import datetime

from spytest import st, cutils

from apis.system import port, basic, ntp
from apis.system import logging, interface, reboot
from apis.common import checks
from apis.common import redis
from apis.common import sonic_config as config
from apis.switching import mac


class SonicHooks(object):

    def get_vars(self, dut, phase=None):

        if phase:
            st.banner("get_vars({}-{})".format(dut, phase))

        retval = dict()

        # not connecting to non-sonic devices
        if not st.is_sonic_device(dut):
            retval["version"] = "unknown"
            return retval

        # try to read the version info
        for _ in range(3):
            try:
                version_data = self.show_version(dut)
                break
            except Exception:
                st.error("Failed to read version info")
                version_data = {}
                if st.is_dry_run():
                    version_data["version"] = 'unknown'
                    break
                st.wait(1)

        # use default values when the show _version is failed
        if not version_data:
            st.error("Failed to read version info even after retries")

        for name in ["product", "platform", "hwsku", "asic",
                     "version", "kernel", "serial_number"]:
            retval[name] = version_data.get(name, 'unknown')

        retval["constants"] = st.get_datastore(dut, "constants")
        retval["redis_db_cli"] = redis.db_cli_init(dut)
        retval["mgmt_ifname"] = st.get_mgmt_ifname(dut)
        retval["mgmt_ipv4"] = st.get_mgmt_ip(dut)
        try:
            retval["mgmt_mac"] = mac.get_sbin_intf_mac(dut, retval["mgmt_ifname"], on_cr_recover="retry5")
        except Exception:
            retval["mgmt_mac"] = "unknown"

        command = 'ls /etc/sonic/bcmsim.cfg'
        output = st.show(dut, command, skip_tmpl=True, on_cr_recover="retry5")
        is_vsonic = not bool(re.search(r'No such file or directory', output))
        retval["is_vsonic"] = is_vsonic
        # retval["ifname_type"] = self.get_ifname_type(dut)

        return retval

    def is_kdump_supported(self, dut):
        if st.getenv("SPYTEST_KDUMP_ENABLE", "1") == "1":
            if st.is_feature_supported("show-kdump-status-command", dut):
                return True
        return False

    def pre_load_image(self, dut):
        self.set_mgmt_vrf(dut)
        # simulate device with ifname-type=std-ext on connect -- comment-me
        # self.set_ifname_type(dut, "std-ext")
        return False

    def post_cli_recovery(self, scope, dut, cmd, attempt=0):
        # scope is session/module/function
        # return True to bail-out, False to ignore, None to retry
        if attempt == 0:
            if cmd == "configure terminal":
                return None
            if "terminal length 0" in cmd:
                return None
            if "sonic-cli prompt=--sonic-mgmt--" in cmd:
                return None
            if scope == "session":
                return None
            if "show runningconfiguration all" in cmd:
                return None
            # if cmd.startswith("show"): return None
        else:
            if scope == "session":
                return False
        return True

    def post_reboot(self, dut, is_upgrade=False):
        self.post_login(dut)

        if is_upgrade:
            basic.ensure_hwsku_config(dut)
            if st.getenv("SPYTEST_NTP_CONFIG_INIT", "0") != "0":
                ntp.ensure_ntp_config(dut)
        if st.getenv("SPYTEST_GENERATE_CERTIFICATE", "0") != "0":
            basic.ensure_certificate(dut)
        if st.getenv("SPYTEST_DATE_SYNC", "1") != "0":
            datestr = datetime.datetime.utcnow().strftime("%c")
            cmd_date = "date --set='{}'".format(datestr)
            st.config(dut, cmd_date, on_cr_recover="retry5", audit=False)

        config.post_reboot(dut, is_upgrade=is_upgrade)
        if not is_upgrade:
            return False

        reboot_again = False

        if st.getenv("SPYTEST_IFA_ENABLE", "0") != "0":
            self.ifa_enable(dut)
            reboot_again = True

        if self.is_kdump_supported(dut):
            if self.kdump_enable(dut):
                reboot_again = True

        return reboot_again

    def post_config_reload(self, dut):
        config.post_config_reload(dut)

    def post_login(self, dut, **kwargs):
        if kwargs.get("type", "click") == "click":
            commands = ["export TMOUT=0", "stty cols 5000", "uptime"]
        else:
            commands = ["terminal timeout 0", "terminal length 0", "show uptime"]
        kwargs.setdefault("skip_error_check", True)
        kwargs.setdefault("on_cr_recover", "retry5")
        kwargs.setdefault("sudo", False)
        kwargs.setdefault("conf", False)
        st.config(dut, commands, **kwargs)

    def post_session(self, dut):
        commands = ["stty cols 80"]
        st.config(dut, commands, sudo=False, on_cr_recover="retry5")

    def init_config(self, dut, type, hwsku=None, profile="na"):
        if hwsku:
            basic.set_hwsku(dut, hwsku)
        if profile != "na":
            basic.set_config_profiles(dut, profile, False, True)
            self.dump_config_db(dut)
        config.init(dut, type)

    def extend_config(self, dut, type, ifname_type="none"):
        if type in ["base"]:
            self.set_mgmt_vrf(dut)
        if ifname_type not in ["none"]:
            if not self.set_ifname_type(dut, ifname_type) or not self.get_ifname_type(dut) == ifname_type:
                if not st.is_dry_run():
                    st.report_fail("failed_to_config_ifname_type")
        config.extend(dut, type)

    def verify_config(self, dut, type):
        return config.verify(dut, type)

    def save_config(self, dut, type="base"):
        config.save(dut, type)

    def apply_config(self, dut, phase):
        config.apply(dut, phase)

    def clear_config(self, dut, **kwargs):
        return config.clear(dut, **kwargs)

    def _change_portlist(self, dut, portlist, cli_type):
        ifname_type = self.get_ifname_type(dut)
        change = bool(cli_type == "klish" and ifname_type in ['std-ext', "alias"])
        change = change or bool(cli_type == "click" and ifname_type == 'std-ext')
        if change:
            portlist = st.get_other_names(dut, portlist)
        return portlist

    def shutdown(self, dut, portlist):
        cli_type = st.getenv("SPYTEST_HOOKS_PORT_ADMIN_STATE_UITYPE", "click")
        # portlist = self._change_portlist(dut, portlist, cli_type)
        port.shutdown(dut, portlist, cli_type=cli_type, ifname_type_oper=True)

    def noshutdown(self, dut, portlist):
        cli_type = st.getenv("SPYTEST_HOOKS_PORT_ADMIN_STATE_UITYPE", "click")
        # portlist = self._change_portlist(dut, portlist, cli_type)
        port.noshutdown(dut, portlist, cli_type=cli_type, ifname_type_oper=True)

    def get_status(self, dut, port_csv):
        cli_type = st.getenv("SPYTEST_HOOKS_PORT_STATUS_UITYPE", "click")
        return port.get_status(dut, port_csv, cli_type=cli_type)

    def get_interface_status(self, dut, port_csv):
        cli_type = st.getenv("SPYTEST_HOOKS_PORT_STATUS_UITYPE", "click")
        return port.get_interface_status(dut, port_csv, cli_type=cli_type)

    def show_version(self, dut, **kwargs):
        cli_type = st.getenv("SPYTEST_HOOKS_VERSION_UITYPE", "click")
        kwargs.setdefault("on_cr_recover", "retry5")
        return basic.show_version(dut, cli_type=cli_type, report=False, **kwargs)

    def get_system_status(self, dut, service=None, **kwargs):
        pending_image_load = kwargs.pop("pending_image_load", False)
        cli_type = "click" if pending_image_load else ""
        cli_type = st.getenv("SPYTEST_HOOKS_SYSTEM_STATUS_UITYPE", cli_type)
        if cli_type:
            kwargs["cli_type"] = cli_type
        return basic.get_system_status(dut, service, **kwargs)

    def verify_topology(self, hooks, check_type, threads=True, skip_tgen=False):
        return checks.verify_topology(hooks, check_type, threads, skip_tgen)

    def set_port_defaults(self, dut, breakout, speed):
        rv1, rv2 = True, True
        if breakout:
            dpb_type = st.getenv("SPYTEST_HOOKS_BREAKOUT_TYPE", "static")
            cli_type = st.getenv("SPYTEST_HOOKS_BREAKOUT_UITYPE", "klish")
            redo = bool(st.getenv("SPYTEST_REDO_BREAKOUT", "1") != "0")
            rv1 = port.breakout(dut, breakout, cli_type=cli_type, redo=redo, dpb_type=dpb_type)
        if speed:
            cli_type = st.getenv("SPYTEST_HOOKS_SPEED_UITYPE", "")
            rv2 = port.set_speed(dut, speed, cli_type=cli_type, on_cr_recover="retry5", ifname_type_oper=True)
        return bool(rv1 and rv2)

    def clear_logging(self, dut, **kwargs):
        kwargs.setdefault("on_cr_recover", "retry3")
        logging.sonic_clear(dut, **kwargs)

    def fetch_syslogs(self, dut, severity=None, since=None):
        # TODO
        severity = severity or ["ERR"]
        # show logging | sed -n '/Aug 06 06:27:57/ , /Aug 06 06:30:58/p' | grep severity

    def ifa_enable(self, dut):
        st.config(dut, "ifa -config -enable -y", expect_reboot=True)

    def ztp_disable(self, dut, **kwargs):
        from apis.system.ztp import ztp_operations
        cli_type = st.getenv("SPYTEST_HOOKS_ZTP_UITYPE", "click")
        kwargs.setdefault("on_cr_recover", "retry3")
        ztp_operations(dut, "disable", cli_type=cli_type, max_time=1200, **kwargs)

    def kdump_enable(self, dut):
        cmd = "sudo show kdump status"
        output = st.show(dut, cmd, skip_tmpl=True, skip_error_check=True)
        if "Kdump Administrative Mode:  Enabled" in output and \
           "Kdump Operational State:    Ready" in output:
            return False
        st.config(dut, "config kdump enable")
        st.config(dut, "config save -y")
        return True

    def upgrade_image(self, dut, url, max_time=1800, skip_error_check=False, migartion=True):
        from apis.system.boot_up import sonic_installer_install2
        cli_type = st.getenv("SPYTEST_HOOKS_INSTALLER_UITYPE", "")
        return sonic_installer_install2(dut, url, max_time, skip_error_check, migartion, cli_type=cli_type)

    def set_mgmt_ip_gw(self, dut, ipmask, gw, **kwargs):
        kwargs.setdefault("on_cr_recover", "retry5")
        return basic.set_mgmt_ip_gw(dut, ipmask, gw, **kwargs)

    def get_mgmt_ip(self, dut, interface, **kwargs):
        force = st.getenv("SPYTEST_HOOKS_MGMT_IP_FORCE_IFCONFIG", "0")
        kwargs.setdefault("on_cr_recover", "retry5")
        return basic.get_mgmt_ip(dut, interface, bool(force != "0"), **kwargs)

    def renew_mgmt_ip(self, dut, interface, **kwargs):
        kwargs.setdefault("on_cr_recover", "retry5")
        return basic.renew_mgmt_ip(dut, interface, **kwargs)

    def upgrade_libsai(self, dut, url):
        path = "/libsai.so"
        st.config(dut, "curl --retry 15 -o {} {}".format(path, url))
        st.config(dut, "docker cp {} syncd:/usr/lib/libsai.so.1.0".format(path))
        st.reboot(dut)
        st.config(dut, "rm -f {}".format(path))

    def get_ifname_type(self, dut):
        if not st.is_feature_supported("ifname-type", dut):
            st.warn("ifname-type is not supported", dut=dut)
            return "native"
        ifname_type = st.get_ifname_type(dut)
        retval = interface.show_ifname_type(dut, cli_type='klish')
        if retval:
            ifname_type = retval[0]['oper_mode'] or retval[0]['mode']
            if ifname_type == "standard-extended":
                ifname_type = "std-ext"
            elif ifname_type == "standard":
                ifname_type = "alias"
            st.debug("ifname-type read {}".format(ifname_type), dut=dut)
        return ifname_type

    def set_ifname_type(self, dut, ifname_type):
        if not st.is_feature_supported("ifname-type", dut):
            st.warn("ifname-type is not supported", dut=dut)
            return True
        cli_type = st.getenv("SPYTEST_IFNAME_TYPE_UITYPE", "klish")
        config = "yes" if ifname_type in ["alias", "std-ext"] else "no"
        intfname_type = "native" if not ifname_type else ifname_type
        for attempt in range(3):
            retval = interface.config_ifname_type(dut, config, faster_cli=False, skip_error_check=True,
                                                  ifname_type=intfname_type, cli_type=cli_type, on_cr_recover="retry3")
            if retval:
                break
            st.wait(2, "Failed to set ifname type {} - try {}".format(ifname_type, attempt + 1))
        return retval

    def get_physical_ifname_map(self, dut):
        cli_type = st.getenv("SPYTEST_IFNAME_MAP_UITYPE", "click")
        return interface.get_physical_ifname_map(dut, cli_type)

    def set_mgmt_vrf(self, dut):
        mgmt_vrf = st.get_run_arg("mgmt_vrf", 0)
        if mgmt_vrf:
            basic.set_mgmt_vrf(dut, mgmt_vrf)
        return True

    def debug_system_status(self, dut, log_file=None):
        st.banner("DEBUG SYSTEM STATUS", dut=dut)
        st.config(dut, "ps -ef", skip_error_check=True, log_file=log_file)
        st.config(dut, "systemctl --no-pager -a status", skip_error_check=True, log_file=log_file)
        st.config(dut, "systemctl --no-pager list-dependencies docker.service",
                  skip_error_check=True, log_file=log_file)
        st.config(dut, "systemctl --no-pager list-unit-files", skip_error_check=True, log_file=log_file)
        st.config(dut, "ls -l /var/run/docker*", skip_error_check=True, log_file=log_file)

    def dut_reboot(self, dut, **kwargs):
        cli_type0 = st.getenv("SPYTEST_HOOKS_REBOOT_UITYPE", "")
        cli_type = kwargs.pop("cli_type", cli_type0)
        if st.getenv("SPYTEST_SYSLOG_ANALYSIS", "0") == "2":
            name = st.get_current_testid()
            failmsg = st.syslog_check(dut, "pre-reboot", "err", name)
            if failmsg:
                st.report("unexpected_syslog_msg", failmsg, dut=dut,
                          support=False, abort=False, type="dutfail")
        return reboot.dut_reboot(dut, cli_type=cli_type, **kwargs)

    def get_onie_grub_config(self, dut, mode):
        from apis.system.boot_up import get_onie_grub_config as get_onie_grub_config_impl
        return get_onie_grub_config_impl(dut, mode)

    def init_features(self, fgroup, fsupp=None, funsupp=None):
        from apis.common.sonic_features import Feature
        return Feature(fgroup, fsupp, funsupp)

    def init_support(self, hooks, cfg, dut=None):
        from apis.common.support import Support
        return Support(hooks, cfg, dut)

    def init_prompts(self, model=None, logger=None, normal_user_mode=None):
        from apis.common.sonic_prompts import Prompts
        return Prompts(model, logger, normal_user_mode)

    def exec_ssh_remote_dut(self, dut, ipaddress, username, password, command=None, timeout=30, **kwargs):
        return basic.exec_ssh_remote_dut(dut, ipaddress, username, password, command, timeout, **kwargs)

    def verify_prompt(self, dut, value):
        return None, False

    def get_base_prompt(self, dut, **kwargs):
        return self.get_hostname(dut, **kwargs)

    def get_hostname(self, dut, **kwargs):
        default_hostname = "sonic"
        hostname_cmd = "sudo vtysh -c 'show running-config | include hostname'"
        for _ in range(20):
            skip_error_check = kwargs.pop("skip_error_check", True)
            output = st.config(dut, hostname_cmd, skip_error_check=skip_error_check, **kwargs)
            if "Error response from daemon" not in output and \
               "Error: No such container: bgp" not in output and \
               "failed to connect to any daemons" not in output:
                hostname = default_hostname
                for line in [_f for _f in str(output).split("\n") if _f]:
                    if line.startswith("hostname"):
                        hostname = line.replace("hostname", "").strip()
                return hostname
            msg = "Failed to read hostname from vtysh retry again in 5 sec"
            st.warn(msg, dut=dut)
            st.wait(5)

        msg = "Failed to read hostname from vtysh - assuming sonic"
        st.error(msg, dut=dut)
        return default_hostname

    def set_hostname(self, dut, name):
        return basic.set_hostname(dut, name)

    def verify_device_info(self, dut, phase):
        return basic.verify_device_info(dut, phase)

    def dump_config_db(self, dut):
        cmd = "sudo cat /etc/sonic/config_db.json"
        st.config(dut, cmd, skip_error_check=True)

    def show_sai_profile(self, dut):
        config.show_sai_profile(dut)

    def is_reboot_confirm(self, dut):
        return basic.is_reboot_confirm(dut)

    def show_dut_time(self, dut):
        date = st.config(dut, "date -u +'%Y-%m-%d %H:%M:%S'", sudo=False, audit=False, on_cr_recover="retry5")
        st.dut_log(dut, "=== UTC Date on the device {}".format(date))

    def gnmi_cert_config_ensure(self, dut):
        config.gnmi_cert_config_ensure(dut)

    def get_mode(self, dut, which):
        return which

    def get_regex(self, dut, which, *args):
        if which == "sudopass":
            return None
        if which == "login":
            return r"\S+\s+login:\s*$"
        if which == "login_anywhere":
            return r"\S+\s+login:\s*"
        if which == "anyprompt":
            return r"[#|\$]\s*$"
        return "unknown"

    def get_default_pass(self, dut):
        return None

    def get_templates_info(self, dut, model):
        return "templates", "sonic"

    def get_custom_ui(self, dut):
        return config.get_custom_ui(dut)

    def get_cli_type_record(self, dut, cli_type):
        file_name = sys._getframe(5).f_code.co_filename
        file_name = os.path.basename(file_name)
        func_name = sys._getframe(5).f_code.co_name
        if file_name in ["bgp.py"] and func_name in ["get_cfg_cli_type", "get_show_cli_type"]:
            func_name = sys._getframe(6).f_code.co_name
            file_name = sys._getframe(6).f_code.co_filename
            file_name = os.path.basename(file_name)
        elif file_name in ["ospf.py"] and func_name in ["get_ospf_cli_type"]:
            func_name = sys._getframe(6).f_code.co_name
            file_name = sys._getframe(6).f_code.co_filename
            file_name = os.path.basename(file_name)
        elif file_name in ["ospf.py"] and func_name in ["check_if_klish_unconfig"]:
            func_name = sys._getframe(7).f_code.co_name
            file_name = sys._getframe(7).f_code.co_filename
            file_name = os.path.basename(file_name)
        return "{}::{},{}".format(file_name, func_name, cli_type)

    def verify_ui_support(self, dut, cli_type, cmd):
        if cli_type in ["klish"] and not st.is_feature_supported("klish", dut):
            for msg in cutils.stack_trace(None, True):
                st.debug(msg, dut=dut)
            st.report_unsupported("ui_unsupported", "klish", cmd or "")
        return cli_type

    def audit(self, atype, dut, *args, **kwargs):
        msg = " ".join(map(str, args))
        if dut:
            msg = "[{}-{}] {}".format(st.get_device_alias(dut, True, True), dut, msg)
        return st.audit(msg)

    def read_syslog(self, dut, lvl, phase, name):
        return None

    def read_core(self, dut, name):
        return None

    def read_tech_support(self, dut, name):
        return None

    def read_sysinfo(self, dut, scope, name):
        trace_log = 3
        MemAvailable, CpuUtilization = "ERROR", "ERROR"
        output0 = "================ {} {} =================".format(scope, name)
        output1 = st.config(dut, "cat /proc/meminfo", sudo=False, skip_error_check=True, trace_log=trace_log)
        for line in output1.split("\n"):
            z = re.match(r"\s*MemAvailable:\s*(\d+)\s*kB", line)
            if not z:
                continue
            try:
                MemAvailable = int(z.groups()[0])
            except Exception:
                MemAvailable = "ERROR"
            break
        output3 = st.config(dut, "top -b -n 1", sudo=False, skip_error_check=True, trace_log=trace_log)
        for line in output3.split("\n"):
            z = re.match(r"\s*%Cpu\(s\):.*,\s+([-+]?\d*\.\d+|\d+)\s+id,\s+", line)
            if not z:
                continue
            try:
                CpuUtilization = round(100.0 - float(z.groups()[0]), 2)
            except Exception:
                CpuUtilization = "ERROR"
            break
        output2 = st.config(dut, "docker stats -a --no-stream", sudo=False, skip_error_check=True, trace_log=trace_log)
        output4 = st.config(dut, "pstree -p", sudo=False, skip_error_check=True, trace_log=trace_log)
        output5 = st.config(dut, "free -mlh", sudo=False, skip_error_check=True, trace_log=trace_log)
        output = "--------------------------------\n".join([output0, output1, output2, output3, output4, output5])
        if st.get_args("filemode"):
            MemAvailable = cutils.random_integer(10000, 20000)
            CpuUtilization = cutils.random_integer(10, 100)
            if MemAvailable < 11000:
                MemAvailable = "ERROR"
            if CpuUtilization < 20:
                CpuUtilization = "ERROR"
        return {"MemAvailable": MemAvailable, "CpuUtilization": CpuUtilization, "output": output}

    def get_command(self, dut, which, *args):
        if which != "reboot":
            return None, None
        for method in args:
            if method in ["normal", "reboot"]:
                return "sudo reboot", None
            if method in ["fast", "fast-reboot"]:
                return "sudo fast-reboot", None
            if method in ["warm", "warm-reboot"]:
                return "sudo warm-reboot", None
            return "sudo reboot", None
        return None, None

    def check_kdump_files(self, dut):
        return basic.check_core_files(dut)

    def clear_kdump_files(self, dut):
        return basic.clear_core_files(dut)

    def check_core_files(self, dut):
        return basic.check_core_files(dut)

    def clear_core_files(self, dut):
        return basic.clear_core_files(dut)

    def save_vtysh_running_config(self, dut, scope, name):
        filename = "/tmp/vtysh-runcfg-{}-{}-{}.txt".format(dut, scope, name.replace("/", "-"))
        st.config(dut, "sudo vtysh -c 'show running-config' > {}".format(filename), skip_error_check=True)
        st.config(dut, "chmod 777 {}".format(filename), skip_error_check=True)
        st.download_file_from_dut(dut, filename)
        return True

    def save_config_db(self, dut, scope, name):
        filename = "/tmp/config-db-{}-{}-{}.json".format(dut, scope, name.replace("/", "-"))
        st.config(dut, "config save {} -y".format(filename), skip_error_check=True)
        st.config(dut, "chmod 777 {}".format(filename), skip_error_check=True)
        st.download_file_from_dut(dut, filename)
        return self.save_vtysh_running_config(dut, scope, name)

    def save_running_config(self, dut, scope, name):
        filename = "running-config-{}-{}-{}.txt".format(dut, scope, name.replace("/", "-"))
        st.show(dut, "show running-configuration | save {}".format(filename), skip_tmpl=True,
                skip_error_check=True, type="klish", confirm="y")
        st.download_file_from_dut(dut, "/home/admin/{}".format(filename))
        return True

    def verify_config_replace(self, dut, scope, res, desc):
        if res not in ["pass"]:
            return res, desc
        # read previous config-db.json and running-config - 1
        # read current config-db.json and running-config - 2
        # issue config-replace to go to config-db.json-1
        # read running-config and compare with running-config-1
        # issue config-replace to go to config-db.json-2
        # read running-config and compare with running-config-2
        # modify the res and desc when failed
        return res, desc

    def verify_command(self, dut, cmd, cli_type):
        if cli_type not in ["click"]:
            return cmd
        if not st.is_feature_supported("sudo-show-interfaces-status", dut):
            return cmd
        if isinstance(cmd, list):
            return cmd
        if cmd.startswith("show interfaces status"):
            return "sudo {}".format(cmd)
        return cmd
