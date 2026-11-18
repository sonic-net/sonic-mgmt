"""Reboots started on the Switch-Host must not reset the paired BMC."""

import logging

import pytest
from ansible.errors import AnsibleConnectionFailure
from pytest_ansible.errors import AnsibleConnectionFailure as PytestAnsibleConnectionFailure

from tests.common.helpers.assertions import pytest_assert
from tests.common.platform.bmc_utils import get_host_boot_id, get_switch_host_or_skip_test
from tests.common.platform.daemon_utils import check_pmon_daemon_status
from tests.common.platform.processes_utils import wait_critical_processes
from tests.common.reboot import (
    REBOOT_TYPE_COLD,
    REBOOT_TYPE_KERNEL_PANIC,
    REBOOT_TYPE_WATCHDOG,
    check_reboot_cause,
    reboot_ctrl_dict,
)
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('bmc'),
]

HOST_BOOT_TIMEOUT = 900
HOST_POLL_INTERVAL = 10


def _host_boot_id(host):
    """Return the Switch-Host boot id, or None while it is unreachable."""
    try:
        res = host.command("cat /proc/sys/kernel/random/boot_id", module_ignore_errors=True)
    except (AnsibleConnectionFailure, PytestAnsibleConnectionFailure):
        return None
    if res.get("rc", 1) != 0:
        return None
    return res.get("stdout", "").strip() or None


def _reboot_host(host, reboot_type):
    """Start the reboot detached and wait for the Switch-Host to answer on a new boot id."""
    boot_id = _host_boot_id(host)
    cmd = reboot_ctrl_dict[reboot_type]["command"]
    logger.info("Switch-Host %s: running %r", host.hostname, cmd)
    host.shell(f"nohup bash -c 'sleep 2; {cmd}' >/dev/null 2>&1 &")
    pytest_assert(
        wait_until(HOST_BOOT_TIMEOUT, HOST_POLL_INTERVAL, 0,
                   lambda: _host_boot_id(host) not in (None, boot_id)),
        f"Switch-Host did not come back on a new boot within {HOST_BOOT_TIMEOUT}s of {cmd!r}")


def _switch_host_online(duthost):
    rows = duthost.show_and_parse("show chassis module status")
    return any((row.get('name') or '').startswith('SWITCH-HOST')
               and (row.get('oper-status') or '').strip().lower() == 'online'
               for row in rows or [])


@pytest.mark.parametrize("reboot_types", [
    pytest.param([REBOOT_TYPE_COLD], id="reboot"),
    pytest.param([REBOOT_TYPE_KERNEL_PANIC], id="kernel_panic"),
    pytest.param([REBOOT_TYPE_WATCHDOG], id="watchdog"),
    # second reboot as soon as ssh answers, before services have settled
    pytest.param([REBOOT_TYPE_COLD, REBOOT_TYPE_COLD], id="reboot_twice"),
])
def test_switch_host_reboot_keeps_bmc_up(duthosts, enum_rand_one_per_hwsku_hostname, reboot_types):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    if not duthost.is_bmc():
        pytest.skip("Device is not a BMC")
    host = get_switch_host_or_skip_test(duthost)

    bmc_boot_id = get_host_boot_id(duthost)
    pytest_assert(bmc_boot_id, "Could not read the BMC boot id")
    host_boot_id = _host_boot_id(host)
    pytest_assert(host_boot_id, "Could not read the Switch-Host boot id")

    try:
        for reboot_type in reboot_types:
            _reboot_host(host, reboot_type)
    finally:
        # an armed watchdog that never fired would reset the host after the test
        if REBOOT_TYPE_WATCHDOG in reboot_types and _host_boot_id(host) == host_boot_id:
            host.shell("watchdogutil disarm", module_ignore_errors=True)

    pytest_assert(get_host_boot_id(duthost) == bmc_boot_id,
                  "BMC rebooted while the Switch-Host rebooted")

    wait_critical_processes(host)
    pytest_assert(wait_until(300, 20, 0, check_pmon_daemon_status, host),
                  "Not all pmon daemons running on the Switch-Host")
    pytest_assert(wait_until(120, 20, 0, check_reboot_cause, host, reboot_types[-1]),
                  f"Switch-Host reboot cause is not {reboot_types[-1]!r}")
    pytest_assert(wait_until(120, 10, 0, _switch_host_online, duthost),
                  "BMC does not report SWITCH-HOST online")
