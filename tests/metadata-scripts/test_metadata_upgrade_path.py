import pytest
import os
import logging
from datetime import datetime
from tests.ptf_runner import ptf_runner
from tests.common.helpers.assertions import pytest_assert
from tests.common.platform.ssh_utils import prepare_testbed_ssh_keys
from tests.common import reboot
from tests.common.reboot import get_reboot_cause, reboot_ctrl_dict
from tests.common.reboot import REBOOT_TYPE_COLD
from tests.upgrade_path.upgrade_helpers import install_sonic, check_sonic_version, get_reboot_command, check_reboot_cause, check_services
from tests.upgrade_path.upgrade_helpers import ptf_params, setup  # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory   # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import change_mac_addresses      # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import remove_ip_addresses      # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import copy_arp_responder_py     # lgtm[py/unused-import]
from tests.platform_tests.verify_dut_health import verify_dut_health      # lgtm[py/unused-import]
from tests.platform_tests.verify_dut_health import add_fail_step_to_reboot # lgtm[py/unused-import]
from tests.common.utilities import wait_until

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer
]
SYSTEM_STABILIZE_MAX_TIME = 300
logger = logging.getLogger(__name__)


@pytest.fixture(scope="module")
def upgrade_path_lists(request):
    upgrade_type = request.config.getoption('upgrade_type')
    from_list = request.config.getoption('base_image_list')
    to_list = request.config.getoption('target_image_list')
    restore_to_image = request.config.getoption('restore_to_image')
    if not from_list or not to_list:
        pytest.skip("base_image_list or target_image_list is empty")
    return upgrade_type, from_list, to_list, restore_to_image


def sonic_update_firmware(duthost, image_url, upgrade_type):
    base_path = os.path.dirname(__file__)
    metadata_scripts_path = os.path.join(base_path, "../../../sonic-metadata/scripts")
    pytest_assert(os.path.exists(metadata_scripts_path), "SONiC Metadata scripts not found in {}"\
            .format(metadata_scripts_path))

    logger.info("Step 1 Copy the scripts to the DUT")
    duthost.command("mkdir /tmp/anpscripts")
    duthost.copy(src=metadata_scripts_path + "/", dest="/tmp/anpscripts/")

    logger.info("Step 2 Copy the image to /tmp/")
    image_name = image_url.split("/")[-1]
    image_path = "/tmp/" + image_name
    duthost.command("curl -o {} {}".format(image_path, image_url))
    out = duthost.command("sonic_installer binary_version {}".format(image_path))

    logger.info("Step 3 Install image")
    UPDATE_MLNX_CPLD_FW = 1 if upgrade_type == REBOOT_TYPE_COLD else 0
    duthost.command("chmod +x /tmp/anpscripts/update_firmware")
    duthost.command("/usr/bin/sudo /tmp/anpscripts/update_firmware {} UPDATE_MLNX_CPLD_FW={}".format(
        image_name, UPDATE_MLNX_CPLD_FW))

    return out['stdout'].rstrip('\n')


def run_upgrade_test(duthost, localhost, ptfhost,  ptf_params, from_image, to_image,
        tbinfo, metadata_process, upgrade_type, modify_reboot_script=None, allow_fail=False):
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
    if metadata_process:
        target_version = sonic_update_firmware(duthost, to_image, upgrade_type)
    else:
        target_version = install_sonic(duthost, to_image, tbinfo)
    test_params = ptf_params
    test_params['target_version'] = target_version
    test_params['reboot_type'] = get_reboot_command(duthost, upgrade_type)
    prepare_testbed_ssh_keys(duthost, ptfhost, test_params['dut_username'])
    log_file = "/tmp/advanced-reboot.ReloadTest.{}.log".format(datetime.now().strftime('%Y-%m-%d-%H:%M:%S'))
    if allow_fail and modify_reboot_script:
        # add fail step to reboot script
        modify_reboot_script(upgrade_type)

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
                log_file=log_file,
                module_ignore_errors=allow_fail)


def test_cancelled_upgrade_path(localhost, duthosts, rand_one_dut_hostname, ptfhost,
        upgrade_path_lists, ptf_params, setup, tbinfo, request, add_fail_step_to_reboot, verify_dut_health):
    duthost = duthosts[rand_one_dut_hostname]
    upgrade_type, from_list_images, to_list_images, _ = upgrade_path_lists
    modify_reboot_script = add_fail_step_to_reboot
    metadata_process = request.config.getoption('metadata_process')
    from_list = from_list_images.split(',')
    to_list = to_list_images.split(',')
    assert (from_list and to_list)
    for from_image in from_list:
        for to_image in to_list:
            run_upgrade_test(duthost, localhost, ptfhost, ptf_params,
                from_image, to_image, tbinfo, metadata_process, upgrade_type,
                modify_reboot_script=modify_reboot_script, allow_fail=True)


def test_upgrade_path(localhost, duthosts, rand_one_dut_hostname, ptfhost,
        upgrade_path_lists, ptf_params, setup, tbinfo, request):
    duthost = duthosts[rand_one_dut_hostname]
    upgrade_type, from_list_images, to_list_images, _ = upgrade_path_lists
    metadata_process = request.config.getoption('metadata_process')
    from_list = from_list_images.split(',')
    to_list = to_list_images.split(',')
    assert (from_list and to_list)
    for from_image in from_list:
        for to_image in to_list:
            run_upgrade_test(duthost, localhost, ptfhost, ptf_params,
                from_image, to_image, tbinfo, metadata_process, upgrade_type)
            logger.info("Check reboot cause. Expected cause {}".format(upgrade_type))
            networking_uptime = duthost.get_networking_uptime().seconds
            timeout = max((SYSTEM_STABILIZE_MAX_TIME - networking_uptime), 1)
            pytest_assert(wait_until(timeout, 5, check_reboot_cause, duthost, upgrade_type),
                "Reboot cause {} did not match the trigger - {}".format(get_reboot_cause(duthost), upgrade_type))
            check_services(duthost)
