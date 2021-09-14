import pytest
import logging
from datetime import datetime
from tests.ptf_runner import ptf_runner
from tests.common.helpers.assertions import pytest_assert
from tests.common.platform.ssh_utils import prepare_testbed_ssh_keys
from tests.common import reboot
from tests.common.reboot import get_reboot_cause, reboot_ctrl_dict
from tests.common.reboot import REBOOT_TYPE_COLD
from tests.upgrade_path.upgrade_helpers import check_services, install_sonic, check_sonic_version, get_reboot_command
from tests.upgrade_path.upgrade_helpers import ptf_params, setup  # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory   # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import change_mac_addresses      # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import remove_ip_addresses      # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import copy_arp_responder_py     # lgtm[py/unused-import]

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer
]

logger = logging.getLogger(__name__)


# upgrade_path pytest arguments
def pytest_addoption(parser):
    options_group = parser.getgroup("Upgrade_path test suite options")

    options_group.addoption(
        "--upgrade_type",
        default="warm",
        help="Specify the type (warm/fast/cold) of upgrade that is needed from source to target image",
    )

    options_group.addoption(
        "--base_image_list",
        default="",
        help="Specify the base image(s) for upgrade (comma seperated list is allowed)",
    )

    options_group.addoption(
        "--target_image_list",
        default="",
        help="Specify the target image(s) for upgrade (comma seperated list is allowed)",
    )

    options_group.addoption(
        "--restore_to_image",
        default="",
        help="Specify the target image to restore to, or stay in target image if empty",
    )

@pytest.fixture(scope="module")
def upgrade_path_lists(request):
    upgrade_type = request.config.getoption('upgrade_type')
    from_list = request.config.getoption('base_image_list')
    to_list = request.config.getoption('target_image_list')
    restore_to_image = request.config.getoption('restore_to_image')
    return upgrade_type, from_list, to_list, restore_to_image


@pytest.mark.device_type('vs')
def test_upgrade_path(localhost, duthosts, rand_one_dut_hostname, ptfhost, upgrade_path_lists, ptf_params, setup, tbinfo):
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
            target_version = install_sonic(duthost, to_image, tbinfo)
            test_params = ptf_params
            test_params['target_version'] = target_version
            test_params['reboot_type'] = get_reboot_command(duthost, upgrade_type)
            prepare_testbed_ssh_keys(duthost, ptfhost, test_params['dut_username'])
            log_file = "/tmp/advanced-reboot.ReloadTest.{}.log".format(datetime.now().strftime('%Y-%m-%d-%H:%M:%S'))
            if test_params['reboot_type'] == reboot_ctrl_dict.get(REBOOT_TYPE_COLD).get("command"):
                # advance-reboot test (on ptf) does not support cold reboot yet
                reboot(duthost, localhost)
            else:
                ptf_runner(ptfhost,
                        "ptftests",
                        "advanced-reboot.ReloadTest",
                        platform_dir="ptftests",
                        params=test_params,
                        platform="remote",
                        qlen=10000,
                        log_file=log_file)
            reboot_cause = get_reboot_cause(duthost)
            logger.info("Check reboot cause. Expected cause {}".format(upgrade_type))
            pytest_assert(reboot_cause == upgrade_type, "Reboot cause {} did not match the trigger - {}".format(reboot_cause, upgrade_type))
            check_services(duthost)
