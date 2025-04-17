import logging
import re

import pytest

from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer,  # disable automatic loganalyzer
    pytest.mark.topology('any')
]


def test_fips(duthosts, enum_rand_one_per_hwsku_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    # check if the fips feature enabled on image level:
    fips_status = duthost.shell("sudo sonic-installer get-fips")["stdout"]
    if "FIPS is enabled" not in fips_status:
        logger.info("Ignore test because FIPS no enabled")
        return

    # check kernel parameter
    kernel_cmdline = duthost.shell("cat /proc/cmdline")["stdout"]
    logger.warning("Kernel cmdline: {}".format(kernel_cmdline))
    pytest_assert("sonic_fips=1" in kernel_cmdline,
                  "Not found sonic_fips enable flag: {}".format(kernel_cmdline))

    # check FIPS package and symcrypt package installed
    fips_packages = duthost.shell("sudo apt list --installed | grep fips")["stdout"]
    logger.warning("Fips package: {}".format(fips_packages))
    pytest_assert(re.search("libk5crypto3.*fips", fips_packages),
                  "libk5crypto3 missing: {}".format(fips_packages))
    pytest_assert(re.search("libssl-dev.*fips", fips_packages),
                  "libssl missing: {}".format(fips_packages))
    pytest_assert(re.search("libssl3.*fips", fips_packages),
                  "libssl3 missing: {}".format(fips_packages))
    pytest_assert(re.search("openssh-client.*fips", fips_packages),
                  "openssh client missing: {}".format(fips_packages))
    pytest_assert(re.search("openssh-server.*fips", fips_packages),
                  "openssh server missing: {}".format(fips_packages))
    pytest_assert(re.search("openssh-sftp-server.*fips", fips_packages),
                  "openssh sftp server missing: {}".format(fips_packages))
    pytest_assert(re.search("openssl.*fips", fips_packages),
                  "openssl missing: {}".format(fips_packages))
    pytest_assert(re.search("ssh.*fips", fips_packages),
                  "ssh missing: {}".format(fips_packages))
    pytest_assert(re.search("libpython3.*fips", fips_packages),
                  "libpython3 missing: {}".format(fips_packages))

    symcrypt_packages = duthost.shell("sudo apt list --installed | grep symcrypt")["stdout"]
    logger.warning("symcrypt package: {}".format(symcrypt_packages))
    pytest_assert(re.search("symcrypt-openssl.*", symcrypt_packages),
                  "symcrypt-openssl missing: {}".format(symcrypt_packages))

    # check symcrypt engine loaded
    openssl_engines = duthost.shell("openssl engine -vv | grep -i symcrypt")["stdout"]
    logger.warning("openssl engines: {}".format(openssl_engines))
    pytest_assert("(symcrypt) SCOSSL (SymCrypt engine for OpenSSL)" in openssl_engines,
                  "Symcrypt engine missing: {}".format(openssl_engines))

    # check ssh loaded symcrypt
    sshd_pid = duthost.shell("pidof -s /usr/sbin/sshd")["stdout"]
    loaded_symcrypt_lib = duthost.shell("sudo cat /proc/{}/maps | grep symcrypt".format(sshd_pid))["stdout"]
    logger.warning("sshd loaded symcrypt lib: {}".format(loaded_symcrypt_lib))
    pytest_assert("libsymcrypt.so" in loaded_symcrypt_lib,
                  "Symcrypt lib not load by ssh: {}".format(loaded_symcrypt_lib))

    # check golang enabled symcrypt by check telemetry service, which is a golang project
    telemetry_pid = duthost.shell("pidof -s /usr/sbin/telemetry")["stdout"]
    loaded_symcrypt_lib = duthost.shell("sudo cat /proc/{}/maps | grep symcrypt".format(telemetry_pid))["stdout"]
    logger.warning("telemetry loaded symcrypt lib: {}".format(loaded_symcrypt_lib))
    pytest_assert("libsymcrypt.so" in loaded_symcrypt_lib,
                  "Symcrypt lib not load by golang: {}".format(loaded_symcrypt_lib))

    # check python3 enabled symcrypt by check sonic_ax_impl
    python_pid = duthost.shell("pgrep -f  'python3 -m sonic_ax_impl' -o")["stdout"]
    loaded_symcrypt_lib = duthost.shell("sudo cat /proc/{}/maps | grep symcrypt".format(python_pid))["stdout"]
    logger.warning("python3 loaded symcrypt lib: {}".format(loaded_symcrypt_lib))
    pytest_assert("libsymcrypt.so" in loaded_symcrypt_lib,
                  "Symcrypt lib not load by python3: {}".format(loaded_symcrypt_lib))
