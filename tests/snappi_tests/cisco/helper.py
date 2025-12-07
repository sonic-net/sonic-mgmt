# Helper functions to be used only for cisco platforms.
from tests.common.utilities import wait_until
from tests.common.cisco_data import copy_set_voq_watchdog_script_cisco_8000, check_dshell_ready
import pytest


@pytest.fixture(scope='module', autouse=True)
def disable_voq_watchdog(duthosts):
    if duthosts[0].facts['asic_type'] != "cisco-8000":
        yield
        return

    for duthost in duthosts:
        modify_voq_watchdog_cisco_8000(duthost, False)

    yield

    for duthost in duthosts:
        modify_voq_watchdog_cisco_8000(duthost, True)


def modify_voq_watchdog_cisco_8000(duthost, enable):
    asics = duthost.get_asic_ids()
    if not wait_until(300, 20, 0, check_dshell_ready, duthost):
        raise RuntimeError("Debug shell is not ready on {}".format(duthost.hostname))

    # Enable when T0/T1 supports voq_watchdog
    if asics == [None]:
        copy_set_voq_watchdog_script_cisco_8000(duthost, "", enable=enable)
        duthost.shell("sudo show platform npu script -s set_voq_watchdog.py")
        return

    for asic in asics:
        copy_set_voq_watchdog_script_cisco_8000(duthost, asic, enable=enable)
        duthost.shell(f"sudo show platform npu script -n asic{asic} -s set_voq_watchdog.py")
