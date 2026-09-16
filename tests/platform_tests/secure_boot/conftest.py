import os

import pexpect
import pytest

from tests.common.helpers.assertions import pytest_assert as _pytest_assert


CONSOLE_CAPTURE_TIMEOUT = 180
CONSOLE_CONNECT_TIMEOUT = 15


class KvmSerialConsole:
    RETURN = "\r"

    def __init__(self, vm_host, vm_user, serial_port):
        self._session = pexpect.spawn(
            "ssh",
            [
                "-q",
                "-tt",
                "-o",
                "BatchMode=yes",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "{}@{}".format(vm_user, vm_host),
                "telnet 127.0.0.1 {}".format(serial_port),
            ],
            encoding="utf-8",
            codec_errors="ignore",
            echo=False,
            timeout=CONSOLE_CAPTURE_TIMEOUT,
        )
        try:
            self._session.expect(
                r"Connected to (?:127\.0\.0\.1|localhost)",
                timeout=CONSOLE_CONNECT_TIMEOUT,
            )
        except (pexpect.EOF, pexpect.TIMEOUT):
            self._session.close(force=True)
            raise

    def read_until_pattern(self, pattern, read_timeout):
        self._session.expect(pattern, timeout=read_timeout)
        return self._session.before + self._session.after

    def read_until_pattern_or_timeout(self, pattern, read_timeout):
        try:
            self._session.expect(pattern, timeout=read_timeout)
            return self._session.before + self._session.after, True
        except (pexpect.EOF, pexpect.TIMEOUT):
            return self._session.before, False

    def write_channel(self, data):
        self._session.send(data)

    def disconnect(self):
        if self._session.isalive():
            self._session.close(force=True)


def _get_inventory_vars(host):
    inventory_manager = host.host.options["inventory_manager"]
    variable_manager = host.host.options["variable_manager"]
    inventory_host = inventory_manager.get_host(host.hostname)
    return variable_manager.get_vars(host=inventory_host)


@pytest.fixture
def kvm_serial_console(duthost, vmhost):
    """Connect to the KVM serial socket through the VM host."""
    if duthost.facts["asic_type"] != "vs":
        pytest.skip("The Secure Boot serial-console tests support KVM only")
    if not vmhost:
        pytest.skip("The KVM host is unavailable")

    dut_vars = _get_inventory_vars(duthost)
    vmhost_vars = _get_inventory_vars(vmhost)
    serial_port = dut_vars.get("serial_port")
    _pytest_assert(serial_port, "serial_port is not defined for {}".format(duthost.hostname))

    vm_host = vmhost_vars.get("ansible_host")
    vm_user = os.getenv("SONIC_MGMT_VM_HOST_USER")
    if not vm_user:
        vm_user = vmhost_vars.get("ansible_user") or vmhost_vars.get("ansible_ssh_user")
    _pytest_assert(
        vm_user and "{{" not in str(vm_user),
        "Set SONIC_MGMT_VM_HOST_USER to the VM host SSH username",
    )
    _pytest_assert(vm_host and vm_user, "VM host SSH connection details are unavailable")

    console = KvmSerialConsole(vm_host, vm_user, serial_port)
    try:
        yield console
    finally:
        console.disconnect()


def pytest_addoption(parser):
    parser.addoption(
        "--secure_boot_second_image_url",
        action="store",
        default=None,
        help=(
            "URL of the signed second image used by Secure Boot kernel "
            "rejection tests."
        ),
    )
