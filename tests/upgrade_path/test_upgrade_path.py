import pytest
import logging
from tests.common.helpers.assertions import pytest_assert
from tests.common import reboot
from tests.common.reboot import get_reboot_cause
from tests.common.reboot import REBOOT_TYPE_COLD
from tests.upgrade_path.upgrade_helpers import check_services, install_sonic, check_sonic_version, get_reboot_command
from tests.upgrade_path.upgrade_helpers import restore_image            # noqa F401
from tests.common.fixtures.advanced_reboot import get_advanced_reboot   # noqa F401
from tests.platform_tests.verify_dut_health import verify_dut_health    # noqa F401
from tests.common.fixtures.duthost_utils import backup_and_restore_config_db    # noqa F401

from tests.platform_tests.conftest import advanceboot_loganalyzer, advanceboot_neighbor_restore  # noqa F401
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory   # noqa F401
from tests.common.fixtures.ptfhost_utils import change_mac_addresses      # noqa F401
from tests.common.fixtures.ptfhost_utils import remove_ip_addresses      # noqa F401
from tests.common.fixtures.ptfhost_utils import copy_arp_responder_py     # noqa F401

from tests.platform_tests.warmboot_sad_cases import get_sad_case_list, SAD_CASE_LIST


pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer,
    pytest.mark.skip_check_dut_health
]

logger = logging.getLogger(__name__)


def pytest_generate_tests(metafunc):
    if "sad_case_type" in metafunc.fixturenames:
        sad_cases = SAD_CASE_LIST
        metafunc.parametrize("sad_case_type", sad_cases, scope="module")


@pytest.fixture(scope="module")
def upgrade_path_lists(request):
    upgrade_type = request.config.getoption('upgrade_type')
    from_list = request.config.getoption('base_image_list')
    to_list = request.config.getoption('target_image_list')
    restore_to_image = request.config.getoption('restore_to_image')
    return upgrade_type, from_list, to_list, restore_to_image


@pytest.mark.device_type('vs')
def test_upgrade_path(localhost, duthosts, ptfhost, rand_one_dut_hostname,
                      nbrhosts, fanouthosts, tbinfo, restore_image,                     # noqa F811
                      get_advanced_reboot, verify_dut_health, advanceboot_loganalyzer,  # noqa F811
                      upgrade_path_lists):
    duthost = duthosts[rand_one_dut_hostname]
    upgrade_type, from_list_images, to_list_images, _ = upgrade_path_lists
    from_list = from_list_images.split(',')
    to_list = to_list_images.split(',')
    assert (from_list and to_list)
    for from_image in from_list:
        for to_image in to_list:
            logger.info("Test upgrade path from {} to {}".format(from_image, to_image))
            # Install base image
            logger.info("Installing {}".format(from_image))
            target_version = install_sonic(duthost, from_image, tbinfo)
            # Perform a cold reboot
            logger.info("Cold reboot the DUT to make the base image as current")
            reboot(duthost, localhost)
            check_sonic_version(duthost, target_version)

            # Install target image
            logger.info("Upgrading to {}".format(to_image))
            install_sonic(duthost, to_image, tbinfo)
            if upgrade_type == REBOOT_TYPE_COLD:
                # advance-reboot test (on ptf) does not support cold reboot yet
                reboot(duthost, localhost)
            else:
                advancedReboot = get_advanced_reboot(rebootType=get_reboot_command(duthost, upgrade_type),
                                                     advanceboot_loganalyzer=advanceboot_loganalyzer)
                advancedReboot.runRebootTestcase()
            reboot_cause = get_reboot_cause(duthost)
            logger.info("Check reboot cause. Expected cause {}".format(upgrade_type))
            pytest_assert(reboot_cause == upgrade_type,
                          "Reboot cause {} did not match the trigger - {}".format(reboot_cause, upgrade_type))
            check_services(duthost)


@pytest.mark.device_type('vs')
def test_warm_upgrade_sad_path(localhost, duthosts, ptfhost, rand_one_dut_hostname,
                               nbrhosts, fanouthosts, vmhost, tbinfo, restore_image,                # noqa F811
                               get_advanced_reboot, verify_dut_health, advanceboot_loganalyzer,     # noqa F811
                               upgrade_path_lists, backup_and_restore_config_db,                    # noqa F811
                               advanceboot_neighbor_restore, sad_case_type):                        # noqa F811
    duthost = duthosts[rand_one_dut_hostname]
    upgrade_type, from_list_images, to_list_images, _ = upgrade_path_lists
    from_list = from_list_images.split(',')
    to_list = to_list_images.split(',')
    assert (from_list and to_list)
    for from_image in from_list:
        for to_image in to_list:
            logger.info("Test upgrade path from {} to {}".format(from_image, to_image))
            # Install base image
            logger.info("Installing {}".format(from_image))
            target_version = install_sonic(duthost, from_image, tbinfo)
            # Perform a cold reboot
            logger.info("Cold reboot the DUT to make the base image as current")
            reboot(duthost, localhost)
            check_sonic_version(duthost, target_version)

            # Install target image
            logger.info("Upgrading to {}".format(to_image))
            install_sonic(duthost, to_image, tbinfo)
            advancedReboot = get_advanced_reboot(rebootType=get_reboot_command(duthost, "warm"),
                                                 advanceboot_loganalyzer=advanceboot_loganalyzer)
            sad_preboot_list, sad_inboot_list = get_sad_case_list(
                duthost, nbrhosts, fanouthosts, vmhost, tbinfo, sad_case_type)
            advancedReboot.runRebootTestcase(
                prebootList=sad_preboot_list,
                inbootList=sad_inboot_list
            )
            reboot_cause = get_reboot_cause(duthost)
            logger.info("Check reboot cause. Expected cause {}".format(upgrade_type))
            pytest_assert(reboot_cause == upgrade_type,
                          "Reboot cause {} did not match the trigger - {}".format(reboot_cause, upgrade_type))
            check_services(duthost)
