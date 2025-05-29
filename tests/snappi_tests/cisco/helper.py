# Helper functions to be used only for cisco platforms.
from tests.common.cisco_data import copy_set_voq_watchdog_script_cisco_8000
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

    '''
    # Enable when T0/T1 supports voq_watchdog
    #if not asics:
    #    copy_set_voq_watchdog_script_cisco_8000(duthost, "", enable=enable)
    '''

    for asic in asics:
        copy_set_voq_watchdog_script_cisco_8000(duthost, asic, enable=enable)
        duthost.shell(f"sudo show platform npu script -n asic{asic} -s set_voq_watchdog.py")
