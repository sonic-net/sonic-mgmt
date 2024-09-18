import allure
import logging
import pytest
from tests.common.reboot import REBOOT_TYPE_BIOS, REBOOT_TYPE_ASIC, check_reboot_cause
from tests.common.helpers.thermal_control_test_helper import mocker_factory  # noqa: F401

pytestmark = [
    pytest.mark.asic('mellanox'),
    pytest.mark.topology('any')
]

logger = logging.getLogger(__name__)

mocker = None
REBOOT_CAUSE_TYPES = [REBOOT_TYPE_BIOS, REBOOT_TYPE_ASIC]


@pytest.mark.parametrize("reboot_cause", REBOOT_CAUSE_TYPES)
def test_reboot_cause(rand_selected_dut, mocker_factory, reboot_cause):  # noqa: F811
    """
    Validate reboot cause from cpu/bios/asic
    :param rand_selected_dut: The fixture returns a randomly selected DUT
    :param mocker_factory: The fixture returns a mocker
    :param reboot_cause: The specific reboot cause
    """
    duthost = rand_selected_dut
    with allure.step('Create mocker - RebootCauseMocker'):
        mocker = mocker_factory(duthost, 'RebootCauseMocker')

    with allure.step('Mock reset from {}'.format(reboot_cause)):
        if reboot_cause == REBOOT_TYPE_BIOS:
            mocker.mock_reset_reload_bios()
        elif reboot_cause == REBOOT_TYPE_ASIC:
            mocker.mock_reset_from_asic()

    with allure.step('Restart determine-reboot-cause service'):
        duthost.restart_service('determine-reboot-cause')

    with allure.step('Check Reboot cause is {}'.format(reboot_cause)):
        check_reboot_cause(duthost, reboot_cause)
