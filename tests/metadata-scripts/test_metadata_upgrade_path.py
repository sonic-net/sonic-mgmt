import pytest
import os
import logging
from datetime import datetime
from tests.ptf_runner import ptf_runner
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.dut_utils import patch_rsyslog
from tests.common.platform.ssh_utils import prepare_testbed_ssh_keys
from tests.common import reboot
from tests.common.reboot import get_reboot_cause, reboot_ctrl_dict
from tests.common.reboot import REBOOT_TYPE_COLD, REBOOT_TYPE_SOFT
from tests.upgrade_path.upgrade_helpers import install_sonic, check_sonic_version, get_reboot_command, check_reboot_cause, check_services
from tests.upgrade_path.upgrade_helpers import setup_ferret  # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory   # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import change_mac_addresses      # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import remove_ip_addresses      # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import copy_arp_responder_py     # lgtm[py/unused-import]
from tests.common.fixtures.advanced_reboot import get_advanced_reboot
from tests.common.fixtures.duthost_utils import backup_and_restore_config_db
from tests.platform_tests.conftest import advanceboot_loganalyzer, advanceboot_neighbor_restore  # lgtm[py/unused-import]
from tests.platform_tests.warmboot_sad_cases import get_sad_case_list, SAD_CASE_LIST
from tests.platform_tests.verify_dut_health import verify_dut_health, check_neighbors      # lgtm[py/unused-import]
from tests.platform_tests.verify_dut_health import add_fail_step_to_reboot # lgtm[py/unused-import]
from tests.common.utilities import wait_until

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer,
    pytest.mark.skip_check_dut_health
]
SYSTEM_STABILIZE_MAX_TIME = 300
logger = logging.getLogger(__name__)


@pytest.fixture(scope="module")
def upgrade_path_lists(request, upgrade_type_params, base_image, target_image):
    restore_to_image = request.config.getoption('restore_to_image')
    if not base_image or not target_image:
        pytest.skip("base_image_list or target_image_list is empty")
    return upgrade_type_params, base_image, target_image, restore_to_image


@pytest.fixture
def skip_cancelled_case(request, upgrade_type_params):
    if "test_cancelled_upgrade_path" in request.node.name\
        and upgrade_type_params not in ["warm", "fast"]:
        pytest.skip("Cancelled upgrade path test supported only for fast and warm reboot types.")


def pytest_generate_tests(metafunc):
    base_image_list = metafunc.config.getoption("base_image_list")
    base_image_list = base_image_list.split(',')
    target_image_list = metafunc.config.getoption("target_image_list")
    target_image_list = target_image_list.split(',')
    base_branch_names = list()
    target_branch_names = list()
    for base_image in base_image_list:
        url_parts = base_image.split("/")
        for part in url_parts:
            if "internal-" in part:
                branch = part.split("internal-")[-1]
                base_branch_names.append(branch + "-to")
            if "public" in part:
                target_branch_names.append("master")
    for target_image in target_image_list:
        url_parts = target_image.split("/")
        for part in url_parts:
            if "internal-" in part:
                branch = part.split("internal-")[-1]
                target_branch_names.append(branch)
            if "public" in part:
                target_branch_names.append("master")
    metafunc.parametrize("base_image", base_image_list, scope="module", ids=base_branch_names)
    metafunc.parametrize("target_image", target_image_list, scope="module", ids=target_branch_names)

    upgrade_types = metafunc.config.getoption("upgrade_type")
    upgrade_types = upgrade_types.split(",")
    input_sad_cases = metafunc.config.getoption("sad_case_list")
    input_sad_list = list()
    for input_case in input_sad_cases.split(","):
        input_case = input_case.strip()
        if input_case.lower() not in SAD_CASE_LIST:
            logging.warn("Unknown SAD case ({}) - skipping it.".format(input_case))
            continue
        input_sad_list.append(input_case.lower())
    if "upgrade_type_params" in metafunc.fixturenames:
        if "sad_case_type" not in metafunc.fixturenames:
            params = upgrade_types
            metafunc.parametrize("upgrade_type_params", params, scope="module")
        else:
            metafunc.parametrize("upgrade_type_params", ["warm"], scope="module")
            metafunc.parametrize("sad_case_type", input_sad_list, scope="module")


def cleanup_prev_images(duthost):
    logger.info("Cleaning up previously installed images on DUT")
    current_os_version = duthost.shell('sonic_installer list | grep Current | cut -f2 -d " "')['stdout']
    duthost.shell("sonic_installer set_next_boot {}".format(current_os_version), module_ignore_errors=True)
    duthost.shell("sonic_installer set-next-boot {}".format(current_os_version), module_ignore_errors=True)
    duthost.shell("sonic_installer cleanup -y", module_ignore_errors=True)


def sonic_update_firmware(duthost, image_url, upgrade_type):
    base_path = os.path.dirname(__file__)
    metadata_scripts_path = os.path.join(base_path, "../../../sonic-metadata/scripts")
    pytest_assert(os.path.exists(metadata_scripts_path), "SONiC Metadata scripts not found in {}"\
            .format(metadata_scripts_path))

    current_os_version = duthost.shell('sonic_installer list | grep Current | cut -f2 -d " "')['stdout']
    cleanup_prev_images(duthost)
    logger.info("Step 1 Copy the scripts to the DUT")
    duthost.command("mkdir /tmp/anpscripts")
    duthost.copy(src=metadata_scripts_path + "/", dest="/tmp/anpscripts/")

    logger.info("perform a purge based on manifest.json to make sure it is correct")
    duthost.command("python /tmp/anpscripts/tests/purge.py")

    logger.info("Step 2 Copy the image to /tmp/")
    image_name = image_url.split("/")[-1]
    image_path = "/tmp/" + image_name
    duthost.command("curl -o {} {}".format(image_path, image_url))
    out = duthost.command("md5sum {}".format(image_path))
    md5sum = out['stdout'].split()

    duthost.command("chmod +x /tmp/anpscripts/preload_firmware")
    logger.info("execute preload_firmware {} {} {}".format(image_name, image_url, md5sum[0]))
    duthost.command("/usr/bin/sudo /tmp/anpscripts/preload_firmware {} {} {}".format(image_name, image_url, md5sum[0]))

    out = duthost.command("sonic_installer binary_version {}".format(image_path))

    logger.info("Step 3 Install image")
    if (upgrade_type == REBOOT_TYPE_COLD or upgrade_type == REBOOT_TYPE_SOFT):
        UPDATE_MLNX_CPLD_FW = 1
    else:
        UPDATE_MLNX_CPLD_FW = 0

    duthost.command("chmod +x /tmp/anpscripts/update_firmware")
    duthost.command("/usr/bin/sudo /tmp/anpscripts/update_firmware {} UPDATE_MLNX_CPLD_FW={}".format(
        image_name, UPDATE_MLNX_CPLD_FW))
    patch_rsyslog(duthost)

    return out['stdout'].rstrip('\n')


def run_postupgrade_actions(duthost, tbinfo, metadata_process):
    if not metadata_process:
        return
    base_path = os.path.dirname(__file__)
    postupgrade_actions_data_dir_path = os.path.join(base_path, "../../../sonic-metadata/scripts/postupgrade_actions_data")
    postupgrade_actions_path = os.path.join(base_path, "../../../sonic-metadata/scripts/postupgrade_actions")
    pytest_assert(os.path.exists(postupgrade_actions_path), "SONiC Metadata postupgrade_action script not found in {}"\
            .format(postupgrade_actions_path))
    pytest_assert(os.path.exists(postupgrade_actions_data_dir_path), "SONiC Metadata postupgrade_action data directory not found in {}"\
            .format(postupgrade_actions_data_dir_path))

    logger.info("Step 1 Copy the scripts and data directory to the DUT")
    duthost.command("rm -rf /tmp/anpscripts", module_ignore_errors=True)
    duthost.command("mkdir /tmp/anpscripts")
    duthost.copy(src=postupgrade_actions_path, dest="/tmp/anpscripts/")
    duthost.copy(src=postupgrade_actions_data_dir_path, dest="/tmp/anpscripts/")

    duthost.command("chmod +x /tmp/anpscripts/postupgrade_actions")
    result = duthost.command("/usr/bin/sudo /tmp/anpscripts/postupgrade_actions")
    logger.info("Postupgrade_actions result: {}".format(str(result)))
    if "stderr" in result:
        errors = result.get("stderr")
        pytest_assert(not errors, "Failed executing postupgrade_actions. Errors: {}".format(errors))
    duthost.command("rm -rf /tmp/anpscripts", module_ignore_errors=True)

    check_services(duthost)
    check_neighbors(duthost, tbinfo)


def setup_upgrade_test(duthost, localhost, from_image, to_image,
        tbinfo, metadata_process, upgrade_type,
        modify_reboot_script=None, allow_fail=False):
    logger.info("Test upgrade path from {} to {}".format(from_image, to_image))
    cleanup_prev_images(duthost)
    # Install base image
    logger.info("Installing {}".format(from_image))
    target_version = install_sonic(duthost, from_image, tbinfo)
    # Perform a cold reboot
    logger.info("Cold reboot the DUT to make the base image as current")
    # for 6100 devices, sometimes cold downgrade will not work, use soft-reboot here
    reboot_type = 'soft' if "6100" in duthost.facts["hwsku"] else 'cold'
    reboot(duthost, localhost, reboot_type=reboot_type)
    check_sonic_version(duthost, target_version)

    # Install target image
    logger.info("Upgrading to {}".format(to_image))
    if metadata_process:
        target_version = sonic_update_firmware(duthost, to_image, upgrade_type)
    else:
        target_version = install_sonic(duthost, to_image, tbinfo)

    if allow_fail and modify_reboot_script:
        # add fail step to reboot script
        modify_reboot_script(upgrade_type)

def run_upgrade_test(duthost, localhost, ptfhost, from_image, to_image,
        tbinfo, metadata_process, upgrade_type, get_advanced_reboot, advanceboot_loganalyzer,
        modify_reboot_script=None, allow_fail=False,
        sad_preboot_list=None, sad_inboot_list=None, first_upgrade=True):

    reboot_type = get_reboot_command(duthost, upgrade_type)
    if "warm-reboot" in reboot_type:
        # always do warm-reboot with CPA enabled
        setup_ferret(duthost, ptfhost, tbinfo)
        ptf_ip = ptfhost.host.options['inventory_manager'].get_host(ptfhost.hostname).vars['ansible_host']
        reboot_type = reboot_type + " -c {}".format(ptf_ip)

    if first_upgrade:
        preboot_setup = lambda: setup_upgrade_test(duthost, localhost,
                from_image, to_image, tbinfo, metadata_process, upgrade_type)
    else:
        preboot_setup = None

    if upgrade_type == REBOOT_TYPE_COLD:
        # advance-reboot test (on ptf) does not support cold reboot yet
        setup_upgrade_test(duthost, localhost,
            from_image, to_image, tbinfo, metadata_process, upgrade_type)
        reboot(duthost, localhost)
        run_postupgrade_actions(duthost, tbinfo, metadata_process)
    else:
        advancedReboot = get_advanced_reboot(rebootType=reboot_type,\
            advanceboot_loganalyzer=advanceboot_loganalyzer, allow_fail=allow_fail)
        advancedReboot.runRebootTestcase(prebootList=sad_preboot_list, inbootList=sad_inboot_list,
        preboot_setup=preboot_setup,
        postboot_setup=lambda: run_postupgrade_actions(duthost, tbinfo, metadata_process))

    patch_rsyslog(duthost)

    if "warm-reboot" in reboot_type:
        ptfhost.shell('supervisorctl stop ferret')


def test_cancelled_upgrade_path(localhost, duthosts, rand_one_dut_hostname, ptfhost,
        upgrade_path_lists, skip_cancelled_case, tbinfo, request,
        get_advanced_reboot, advanceboot_loganalyzer,
        add_fail_step_to_reboot, verify_dut_health):
    duthost = duthosts[rand_one_dut_hostname]
    upgrade_type, from_image, to_image, _ = upgrade_path_lists
    modify_reboot_script = add_fail_step_to_reboot
    metadata_process = request.config.getoption('metadata_process')

    run_upgrade_test(duthost, localhost, ptfhost,
        from_image, to_image, tbinfo, metadata_process, upgrade_type,
        get_advanced_reboot, advanceboot_loganalyzer,
        modify_reboot_script=modify_reboot_script, allow_fail=True)


def test_upgrade_path(localhost, duthosts, rand_one_dut_hostname, ptfhost,
        upgrade_path_lists, tbinfo, request, get_advanced_reboot, advanceboot_loganalyzer,
        verify_dut_health):
    duthost = duthosts[rand_one_dut_hostname]
    upgrade_type, from_image, to_image, _ = upgrade_path_lists
    metadata_process = request.config.getoption('metadata_process')

    run_upgrade_test(duthost, localhost, ptfhost,
        from_image, to_image, tbinfo, metadata_process, upgrade_type,
        get_advanced_reboot, advanceboot_loganalyzer)
    logger.info("Check reboot cause. Expected cause {}".format(upgrade_type))
    networking_uptime = duthost.get_networking_uptime().seconds
    timeout = max((SYSTEM_STABILIZE_MAX_TIME - networking_uptime), 1)
    pytest_assert(wait_until(timeout, 5, 0, check_reboot_cause, duthost, upgrade_type),
        "Reboot cause {} did not match the trigger - {}".format(get_reboot_cause(duthost), upgrade_type))


def test_double_upgrade_path(localhost, duthosts, rand_one_dut_hostname, ptfhost,
        upgrade_path_lists, tbinfo, request, get_advanced_reboot, advanceboot_loganalyzer,
        verify_dut_health):
    duthost = duthosts[rand_one_dut_hostname]
    upgrade_type, from_image, to_image, _ = upgrade_path_lists
    metadata_process = request.config.getoption('metadata_process')

    for first_upgrade in [True, False]:
        run_upgrade_test(duthost, localhost, ptfhost,
            from_image, to_image, tbinfo, metadata_process, upgrade_type,
            get_advanced_reboot, advanceboot_loganalyzer,
            first_upgrade=first_upgrade)
        logger.info("Check reboot cause. Expected cause {}".format(upgrade_type))
        networking_uptime = duthost.get_networking_uptime().seconds
        timeout = max((SYSTEM_STABILIZE_MAX_TIME - networking_uptime), 1)
        pytest_assert(wait_until(timeout, 5, 0, check_reboot_cause, duthost, upgrade_type),
            "Reboot cause {} did not match the trigger - {}".format(get_reboot_cause(duthost), upgrade_type))


def test_warm_upgrade_sad_path(localhost, duthosts, rand_one_dut_hostname, ptfhost,
        upgrade_path_lists, tbinfo, request, get_advanced_reboot, advanceboot_loganalyzer,
        verify_dut_health, nbrhosts, fanouthosts, vmhost, backup_and_restore_config_db,
        advanceboot_neighbor_restore, sad_case_type):
    duthost = duthosts[rand_one_dut_hostname]
    upgrade_type, from_image, to_image, _ = upgrade_path_lists
    metadata_process = request.config.getoption('metadata_process')
    sad_preboot_list, sad_inboot_list = get_sad_case_list(duthost, nbrhosts,
        fanouthosts, vmhost, tbinfo, sad_case_type)

    run_upgrade_test(duthost, localhost, ptfhost,
        from_image, to_image, tbinfo, metadata_process, upgrade_type,
        get_advanced_reboot, advanceboot_loganalyzer,
        sad_preboot_list=sad_preboot_list, sad_inboot_list=sad_inboot_list)
    logger.info("Check reboot cause. Expected cause {}".format(upgrade_type))
    networking_uptime = duthost.get_networking_uptime().seconds
    timeout = max((SYSTEM_STABILIZE_MAX_TIME - networking_uptime), 1)
    pytest_assert(wait_until(timeout, 5, 0, check_reboot_cause, duthost, upgrade_type),
        "Reboot cause {} did not match the trigger - {}".format(
            get_reboot_cause(duthost), upgrade_type))
