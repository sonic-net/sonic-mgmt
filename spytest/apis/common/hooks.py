from spytest import st, env


class Hooks(object):

    def __init__(self):
        self.cache = {}

    def _impl(self, dut):
        if not dut:
            for d in self.cache:
                if d:
                    dut = d
                    break
        if dut not in self.cache:
            def_dtype = env.get("SPYTEST_DEFAULT_DEVICE_TYPE", "sonic")
            try:
                if not dut:
                    dtype = def_dtype
                else:
                    dtype = st.get_device_type(dut)
            except Exception:
                dtype, dut = def_dtype, None
            if dtype in ["fastpath", "icos"]:
                from apis.common.fastpath_hooks import FastpathHooks
                self.cache[dut] = FastpathHooks()
            elif dtype in ["linux"]:
                from apis.common.linux_hooks import LinuxHooks
                self.cache[dut] = LinuxHooks()
            elif dtype in ["poe"]:
                from apis.common.poe_hooks import PoeHooks
                self.cache[dut] = PoeHooks()
            else:
                from apis.common.sonic_hooks import SonicHooks
                self.cache[dut] = SonicHooks()
        return self.cache[dut]

    def get_vars(self, dut, phase=None):
        return self._impl(dut).get_vars(dut, phase)

    def is_kdump_supported(self, dut):
        return self._impl(dut).is_kdump_supported(dut)

    def pre_load_image(self, dut):
        return self._impl(dut).pre_load_image(dut)

    def post_cli_recovery(self, scope, dut, cmd, attempt=0):
        return self._impl(dut).post_cli_recovery(scope, dut, cmd, attempt)

    def post_reboot(self, dut, is_upgrade=False):
        return self._impl(dut).post_reboot(dut, is_upgrade)

    def post_config_reload(self, dut):
        return self._impl(dut).post_config_reload(dut)

    def post_login(self, dut, **kwargs):
        return self._impl(dut).post_login(dut, **kwargs)

    def post_session(self, dut):
        return self._impl(dut).post_session(dut)

    def init_config(self, dut, type, hwsku=None, profile="na"):
        return self._impl(dut).init_config(dut, type, hwsku, profile)

    def extend_config(self, dut, type, ifname_type="none"):
        return self._impl(dut).extend_config(dut, type, ifname_type)

    def verify_config(self, dut, type):
        return self._impl(dut).verify_config(dut, type)

    def save_config(self, dut, type):
        return self._impl(dut).save_config(dut, type)

    def apply_config(self, dut, phase):
        return self._impl(dut).apply_config(dut, phase)

    def clear_config(self, dut, **kwargs):
        return self._impl(dut).clear_config(dut, **kwargs)

    def shutdown(self, dut, portlist):
        return self._impl(dut).shutdown(dut, portlist)

    def noshutdown(self, dut, portlist):
        return self._impl(dut).noshutdown(dut, portlist)

    def get_status(self, dut, port_csv):
        return self._impl(dut).get_status(dut, port_csv)

    def get_interface_status(self, dut, port_csv):
        return self._impl(dut).get_interface_status(dut, port_csv)

    def show_version(self, dut, **kwargs):
        return self._impl(dut).show_version(dut, **kwargs)

    def get_system_status(self, dut, service=None, **kwargs):
        return self._impl(dut).get_system_status(dut, service, **kwargs)

    def verify_topology(self, check_type, threads=True, skip_tgen=False):
        return self._impl(None).verify_topology(self, check_type, threads, skip_tgen)

    def set_port_defaults(self, dut, breakout, speed):
        return self._impl(dut).set_port_defaults(dut, breakout, speed)

    def clear_logging(self, dut, **kwargs):
        return self._impl(dut).clear_logging(dut, **kwargs)

    def fetch_syslogs(self, dut, severity=None, since=None):
        return self._impl(dut).fetch_syslogs(dut, severity, since)

    def ifa_enable(self, dut):
        return self._impl(dut).ifa_enable(dut)

    def ztp_disable(self, dut, **kwargs):
        return self._impl(dut).ztp_disable(dut, **kwargs)

    def kdump_enable(self, dut):
        return self._impl(dut).kdump_enable(dut)

    def upgrade_image(self, dut, url, max_time=1800, skip_error_check=False, migartion=True):
        return self._impl(dut).upgrade_image(dut, url, max_time, skip_error_check, migartion)

    def set_mgmt_ip_gw(self, dut, ipmask, gw, **kwargs):
        return self._impl(dut).set_mgmt_ip_gw(dut, ipmask, gw, **kwargs)

    def get_mgmt_ip(self, dut, interface, **kwargs):
        return self._impl(dut).get_mgmt_ip(dut, interface, **kwargs)

    def renew_mgmt_ip(self, dut, interface, **kwargs):
        return self._impl(dut).renew_mgmt_ip(dut, interface, **kwargs)

    def upgrade_libsai(self, dut, url):
        return self._impl(dut).upgrade_libsai(dut, url)

    def get_ifname_type(self, dut):
        return self._impl(dut).get_ifname_type(dut)

    def set_ifname_type(self, dut, ifname_type):
        return self._impl(dut).set_ifname_type(dut, ifname_type)

    def get_physical_ifname_map(self, dut):
        return self._impl(dut).get_physical_ifname_map(dut)

    def debug_system_status(self, dut, log_file=None):
        return self._impl(dut).debug_system_status(dut, log_file)

    def dut_reboot(self, dut, **kwargs):
        return self._impl(dut).dut_reboot(dut, **kwargs)

    def get_onie_grub_config(self, dut, mode):
        return self._impl(dut).get_onie_grub_config(dut, mode)

    def init_features(self, fgroup, fsupp=None, funsupp=None):
        return self._impl(None).init_features(fgroup, fsupp, funsupp)

    def init_support(self, cfg, dut=None):
        return self._impl(dut).init_support(self, cfg, dut)

    def init_prompts(self, model=None, logger=None, dut=None, normal_user_mode=None):
        return self._impl(dut).init_prompts(model, logger, normal_user_mode)

    def exec_ssh_remote_dut(self, dut, ipaddress, username, password, command=None, timeout=30, **kwargs):
        return self._impl(dut).exec_ssh_remote_dut(dut, ipaddress, username, password, command, timeout, **kwargs)

    def verify_prompt(self, dut, value):
        return self._impl(dut).verify_prompt(dut, value)

    def get_base_prompt(self, dut, **kwargs):
        return self._impl(dut).get_base_prompt(dut, **kwargs)

    def get_hostname(self, dut, **kwargs):
        return self._impl(dut).get_hostname(dut, **kwargs)

    def set_hostname(self, dut, name):
        return self._impl(dut).set_hostname(dut, name)

    def verify_device_info(self, dut, phase):
        return self._impl(dut).verify_device_info(dut, phase)

    def dump_config_db(self, dut):
        return self._impl(dut).dump_config_db(dut)

    def show_sai_profile(self, dut):
        return self._impl(dut).show_sai_profile(dut)

    def is_reboot_confirm(self, dut):
        return self._impl(dut).is_reboot_confirm(dut)

    def show_dut_time(self, dut):
        return self._impl(dut).show_dut_time(dut)

    def gnmi_cert_config_ensure(self, dut):
        return self._impl(dut).gnmi_cert_config_ensure(dut)

    def get_mode(self, dut, which):
        return self._impl(dut).get_mode(dut, which)

    def get_regex(self, dut, which, *args):
        return self._impl(dut).get_regex(dut, which, *args)

    def get_default_pass(self, dut):
        return self._impl(dut).get_default_pass(dut)

    def get_templates_info(self, dut, model):
        return self._impl(dut).get_templates_info(dut, model)

    def get_custom_ui(self, dut):
        return self._impl(dut).get_custom_ui(dut)

    def get_cli_type_record(self, dut, cli_type):
        return self._impl(dut).get_cli_type_record(dut, cli_type)

    def verify_ui_support(self, dut, cli_type, cmd):
        return self._impl(dut).verify_ui_support(dut, cli_type, cmd)

    def audit(self, atype, dut, *args, **kwargs):
        return self._impl(dut).audit(atype, dut, *args, **kwargs)

    def read_syslog(self, dut, lvl, phase, name):
        return self._impl(dut).read_syslog(dut, lvl, phase, name)

    def read_core(self, dut, name):
        return self._impl(dut).read_core(dut, name)

    def read_tech_support(self, dut, name):
        return self._impl(dut).read_tech_support(dut, name)

    def read_sysinfo(self, dut, scope, name):
        return self._impl(dut).read_sysinfo(dut, scope, name)

    def get_command(self, dut, which, *args):
        return self._impl(dut).get_command(dut, which, *args)

    def check_kdump_files(self, dut):
        return self._impl(dut).check_kdump_files(dut)

    def clear_kdump_files(self, dut):
        return self._impl(dut).clear_kdump_files(dut)

    def check_core_files(self, dut):
        return self._impl(dut).check_core_files(dut)

    def clear_core_files(self, dut):
        return self._impl(dut).clear_core_files(dut)

    def save_config_db(self, dut, scope, name):
        return self._impl(dut).save_config_db(dut, scope, name)

    def save_running_config(self, dut, scope, name):
        return self._impl(dut).save_running_config(dut, scope, name)

    def verify_config_replace(self, dut, scope, res, desc):
        return self._impl(dut).verify_config_replace(dut, scope, res, desc)

    def verify_command(self, dut, cmd, cli_type):
        return self._impl(dut).verify_command(dut, cmd, cli_type)
