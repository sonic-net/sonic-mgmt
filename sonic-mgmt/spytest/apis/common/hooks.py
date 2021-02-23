import re

from spytest import st

from apis.system import port, basic, ntp
from apis.system import logging, interface, reboot
from apis.common import checks, verifiers
from apis.common import redis
from apis.common import base_config
from apis.switching import mac

class Hooks(object):

    def get_vars(self, dut):

        # try to read the version info
        for _ in range(3):
            try:
                version_data = self.show_version(dut)
                break
            except Exception:
                st.error("Failed to read version info")
                version_data = ""
                st.wait(1)
                continue

        # use default values when the show _version is failed
        if not version_data:
            st.error("Failed to read version info even after retries")
            version_data = {
                'product' : 'unknown',
                'hwsku'   : 'unknown',
                'version' : 'unknown',
            }

        retval = dict()
        retval["product"] = version_data['product']
        retval["hwsku"] = version_data['hwsku']
        retval["version"] = version_data['version']
        retval["constants"] = st.get_datastore(dut, "constants")

        retval["redis_db_cli"] = redis.db_cli_init(dut)

        retval["mgmt_ifname"] = st.get_mgmt_ifname(dut)
        retval["mgmt_ipv4"] = st.get_mgmt_ip(dut)
        try:
            retval["mgmt_mac"] = mac.get_sbin_intf_mac(dut, retval["mgmt_ifname"])
        except Exception:
            retval["mgmt_mac"] = "unknown"

        output = st.show(dut,'ls /etc/sonic/bcmsim.cfg',skip_tmpl=True)
        is_vsonic = not bool(re.search(r'No such file or directory',output))
        retval["is_vsonic"] = is_vsonic

        output = st.config(dut, "fast-reboot -h", skip_error_check=True)
        if "skip the user confirmation" in output:
            retval["reboot-confirm"] = True
        else:
            retval["reboot-confirm"] = False

        return retval

    def post_reboot(self, dut, is_upgrade=False):
        if is_upgrade:
            basic.ensure_hwsku_config(dut)
            if st.getenv("SPYTEST_NTP_CONFIG_INIT", "0") != "0":
                ntp.ensure_ntp_config(dut)
        if st.getenv("SPYTEST_GENERATE_CERTIFICATE", "0") != "0":
            basic.ensure_certificate(dut)
        base_config.post_reboot(dut, is_upgrade=is_upgrade)

    def init_base_config(self, dut):
        base_config.init(dut)

    def extend_base_config(self, dut):
        base_config.extend(dut)

    def shutdown(self, dut, portlist):
        cli_type = st.getenv("SPYTEST_HOOKS_PORT_ADMIN_STATE_UITYPE", "click")
        port.shutdown(dut, portlist, cli_type=cli_type)

    def noshutdown(self, dut, portlist):
        cli_type = st.getenv("SPYTEST_HOOKS_PORT_ADMIN_STATE_UITYPE", "click")
        port.noshutdown(dut, portlist, cli_type=cli_type)

    def get_status(self, dut, port_csv):
        cli_type = st.getenv("SPYTEST_HOOKS_PORT_STATUS_UITYPE", "click")
        return port.get_status(dut, port_csv, cli_type=cli_type)

    def get_interface_status(self, dut, port_csv):
        cli_type = st.getenv("SPYTEST_HOOKS_PORT_STATUS_UITYPE", "click")
        return port.get_interface_status(dut, port_csv, cli_type=cli_type)

    def show_version(self, dut):
        cli_type = st.getenv("SPYTEST_HOOKS_VERSION_UITYPE", "click")
        return basic.show_version(dut, cli_type=cli_type)

    def get_system_status(self, dut, service=None, skip_error_check=False):
        return basic.get_system_status(dut, service, skip_error_check)

    def verify_topology(self, check_type, threads=True):
        return checks.verify_topology(self, check_type, threads)

    def get_verifiers(self):
        return verifiers.get_verifiers()

    def set_port_defaults(self, dut, breakout, speed):
        rv1, rv2 = True, True
        if breakout:
            cli_type = st.getenv("SPYTEST_HOOKS_BREAKOUT_UITYPE", "klish")
            rv1 = port.breakout(dut, breakout, cli_type=cli_type)
        if speed:
            cli_type = st.getenv("SPYTEST_HOOKS_SPEED_UITYPE", "")
            rv2 = port.set_speed(dut, speed, cli_type=cli_type)
        return bool(rv1 and rv2)

    def set_hwsku(self, dut, hwsku):
        return basic.set_hwsku(dut, hwsku)

    def sonic_clear_logging(self, dut):
        logging.sonic_clear(dut)

    def ifa_enable(self, dut):
        st.config(dut, "ifa -config -enable -y", expect_reboot=True)

    def ztp_disable(self, dut):
        from apis.system.ztp import ztp_operations
        cli_type = st.getenv("SPYTEST_HOOKS_ZTP_UITYPE", "click")
        ztp_operations(dut, "disable", cli_type=cli_type, max_time=1200)

    def kdump_enable(self, dut):
        cmd = "sudo show kdump status"
        output = st.show(dut, cmd, skip_tmpl=True, skip_error_check=True)
        if "Kdump Administrative Mode:  Enabled" in output and \
           "Kdump Operational State:    Ready"   in output:
            return False
        st.config(dut, "config kdump enable")
        st.config(dut, "config save -y")
        return True

    def upgrade_image(self, dut, url, max_time=1800, skip_error_check=False, migartion=False):
        from apis.system.boot_up import sonic_installer_install2
        return sonic_installer_install2(dut, url, max_time, skip_error_check, migartion)

    def set_mgmt_ip_gw(self, dut, ipmask, gw):
        return basic.set_mgmt_ip_gw(dut, ipmask, gw)

    def get_mgmt_ip(self, dut, interface):
        return basic.get_mgmt_ip(dut, interface)

    def renew_mgmt_ip(self, dut, interface):
        return basic.renew_mgmt_ip(dut, interface)

    def upgrade_libsai(self, dut, url):
        path = "/libsai.so"
        st.config(dut, "sudo curl --retry 15 -o {} {}".format(path, url))
        st.config(dut, "docker cp {} syncd:/usr/lib/libsai.so.1.0".format(path))
        st.reboot(dut)
        st.config(dut, "rm -f {}".format(path))

    def config_ifname_type(self, dut, ifname_type):
        config = "yes" if ifname_type == "alias" else "no"
        return interface.config_ifname_type(dut, config)

    def get_physical_ifname_map(self, dut):
        cli_type = st.getenv("SPYTEST_IFNAME_MAP_UITYPE", "click")
        return interface.get_physical_ifname_map(dut, cli_type)

    def set_mgmt_vrf(self, dut, mgmt_vrf):
        return basic.set_mgmt_vrf(dut, mgmt_vrf)

    def debug_system_status(self, dut):
        st.config(dut, "ps -ef", skip_error_check=True)
        st.config(dut, "systemctl --no-pager -a status", skip_error_check=True)
        st.config(dut, "systemctl --no-pager list-dependencies docker.service", skip_error_check=True)
        st.config(dut, "systemctl --no-pager list-unit-files", skip_error_check=True)
        st.config(dut, "ls -l /var/run/docker*", skip_error_check=True)

    def dut_reboot(self, dut, method='normal',cli_type=''):
        return reboot.dut_reboot(dut, method, cli_type)

    def get_onie_grub_config(self, dut, mode):
        from apis.system.boot_up import get_onie_grub_config
        return get_onie_grub_config(dut, mode)

