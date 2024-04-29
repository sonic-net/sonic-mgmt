from functools import lru_cache
import pytest


@lru_cache(maxsize=None)
class GNMIEnvironment(object):
    TELEMETRY_MODE = 0
    GNMI_MODE = 1

    def __init__(self, duthost, mode):
        if mode == self.TELEMETRY_MODE:
            ret = self.generate_telemetry_config(duthost)
            if ret:
                return
            ret = self.generate_gnmi_config(duthost)
            if ret:
                return
        elif mode == self.GNMI_MODE:
            ret = self.generate_gnmi_config(duthost)
            if ret:
                return
            ret = self.generate_telemetry_config(duthost)
            if ret:
                return
        pytest.fail("Can't generate GNMI/TELEMETRY configuration, mode %d" % mode)

    def generate_gnmi_config(self, duthost):
        cmd = "docker images | grep -w sonic-gnmi"
        if duthost.shell(cmd, module_ignore_errors=True)['rc'] == 0:
            cmd = "docker ps | grep -w gnmi"
            if duthost.shell(cmd, module_ignore_errors=True)['rc'] == 0:
                self.gnmi_config_table = "GNMI"
                self.gnmi_container = "gnmi"
                self.gnmi_program = "gnmi-native"
                # GNMI process is gnmi or telemetry
                res = duthost.shell("docker exec gnmi ps -ef", module_ignore_errors=True)
                if '/usr/sbin/gnmi' in res['stdout']:
                    self.gnmi_process = "gnmi"
                else:
                    self.gnmi_process = "telemetry"
                self.gnmi_port = 50052
                return True
            else:
                pytest.fail("GNMI is not running")
        return False

    def generate_telemetry_config(self, duthost):
        cmd = "docker images | grep -w sonic-telemetry"
        if duthost.shell(cmd, module_ignore_errors=True)['rc'] == 0:
            cmd = "docker ps | grep -w telemetry"
            if duthost.shell(cmd, module_ignore_errors=True)['rc'] == 0:
                self.gnmi_config_table = "TELEMETRY"
                self.gnmi_container = "telemetry"
                # GNMI program is telemetry or gnmi-native
                res = duthost.shell("docker exec %s supervisorctl status" % self.gnmi_container,
                                    module_ignore_errors=True)
                if 'telemetry' in res['stdout']:
                    self.gnmi_program = "telemetry"
                else:
                    self.gnmi_program = "gnmi-native"
                self.gnmi_process = "telemetry"
                self.gnmi_port = 50051
                return True
            else:
                pytest.fail("Telemetry is not running")
        return False
