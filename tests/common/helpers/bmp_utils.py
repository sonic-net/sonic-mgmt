from functools import lru_cache
import pytest


@lru_cache(maxsize=None)
class BMPEnvironment(object):

    def __init__(self, duthost):
        ret = self.generate_bmp_config(duthost)
        if ret:
            return
        pytest.fail("Can't generate BMP configuration")

    def generate_bmp_config(self, duthost):
        cmd = "docker images | grep -w sonic-bmp"
        if duthost.shell(cmd, module_ignore_errors=True)['rc'] == 0:
            cmd = "docker ps | grep -w bmp"
            if duthost.shell(cmd, module_ignore_errors=True)['rc'] == 0:
                self.bmp_config_table = "BMP"
                self.bmp_container = "bmp"
                self.bmp_program = "openbmpd"
                res = duthost.shell("docker exec bmp ps -ef", module_ignore_errors=True)
                if '/usr/bin/openbmpd' in res['stdout']:
                    self.bmp_process = "bmp"
                return True
            else:
                pytest.fail("BMP service is not running")
        return False
