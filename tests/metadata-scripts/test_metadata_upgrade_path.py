import pytest
import os
import logging
import re
from postupgrade_helper import run_postupgrade_actions
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.dut_utils import patch_rsyslog
from tests.common import reboot
from tests.common.reboot import REBOOT_TYPE_COLD, REBOOT_TYPE_SOFT
from tests.upgrade_path.upgrade_helpers import install_sonic, check_sonic_version,\
    upgrade_test_helper
from tests.common.fixtures.advanced_reboot import get_advanced_reboot
from tests.common.fixtures.duthost_utils import backup_and_restore_config_db
from tests.platform_tests.conftest import advanceboot_loganalyzer, advanceboot_neighbor_restore
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory   # noqa F401
from tests.platform_tests.warmboot_sad_cases import get_sad_case_list, SAD_CASE_LIST
from tests.platform_tests.verify_dut_health import verify_dut_health        # lgtm[py/unused-import]
from tests.platform_tests.verify_dut_health import add_fail_step_to_reboot  # lgtm[py/unused-import]
from tests.common.errors import RunAnsibleModuleFail

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer,
    pytest.mark.skip_check_dut_health
]
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


def sonic_update_firmware(duthost, localhost, image_url, upgrade_type):
    base_path = os.path.dirname(__file__)
    metadata_scripts_path = os.path.join(base_path, "../../../sonic-metadata/scripts")
    pytest_assert(os.path.exists(metadata_scripts_path), "SONiC Metadata scripts not found in {}"
            .format(metadata_scripts_path))

    cleanup_prev_images(duthost)
    logger.info("Step 1 Copy the scripts to the DUT")
    duthost.file(path="/tmp/anpscripts", state="absent")
    duthost.file(path="/tmp/anpscripts", state="directory")
    localhost.archive(path=metadata_scripts_path + "/", dest="metadata.tar.gz", exclusion_patterns=[".git"])
    duthost.copy(src="metadata.tar.gz", dest="/host/metadata.tar.gz")
    duthost.unarchive(src="/host/metadata.tar.gz", dest="/tmp/anpscripts/", remote_src="yes")

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

def setup_upgrade_test(duthost, localhost, from_image, to_image,
                       tbinfo, metadata_process, upgrade_type,
                       modify_reboot_script=None, allow_fail=False):
    logger.info("Test upgrade path from {} to {}".format(from_image, to_image))
    cleanup_prev_images(duthost)
    # Install base image
    logger.info("Installing {}".format(from_image))
    try:
        target_version = install_sonic(duthost, from_image, tbinfo)
    except RunAnsibleModuleFail as err:
        migration_err_regexp = r"Traceback.*migrate_sonic_packages.*SonicRuntimeException"
        msg = err.results['msg'].replace('\n', '')
        if re.search(migration_err_regexp, msg):
            logger.info(
                "Ignore the package migration error when downgrading to from_image")
            target_version = duthost.shell(
                "cat /tmp/downloaded-sonic-image-version")['stdout']
        else:
            raise err
    # Remove old config_db before rebooting the DUT in case it is not successfully
    # removed in install_sonic due to migration error
    logger.info("Remove old config_db file if exists, to load minigraph from scratch")
    if duthost.shell("ls /host/old_config/minigraph.xml", module_ignore_errors=True)['rc'] == 0:
        duthost.shell("rm -f /host/old_config/config_db.json")
    # Perform a cold reboot
    logger.info("Cold reboot the DUT to make the base image as current")
    # for 6100 devices, sometimes cold downgrade will not work, use soft-reboot here
    reboot_type = 'hard' if "s6100" in duthost.facts["platform"] else 'cold'
    reboot(duthost, localhost, reboot_type=reboot_type)
    check_sonic_version(duthost, target_version)

    # Install target image
    logger.info("Upgrading to {}".format(to_image))
    if metadata_process:
        target_version = sonic_update_firmware(duthost, localhost, to_image, upgrade_type)
    else:
        target_version = install_sonic(duthost, to_image, tbinfo)

    if allow_fail and modify_reboot_script:
        # add fail step to reboot script
        modify_reboot_script(upgrade_type)


def test_cancelled_upgrade_path(localhost, duthosts, rand_one_dut_hostname, ptfhost,
                                upgrade_path_lists, skip_cancelled_case, tbinfo, request,
                                get_advanced_reboot, advanceboot_loganalyzer,
                                add_fail_step_to_reboot, verify_dut_health):
    duthost = duthosts[rand_one_dut_hostname]
    upgrade_type, from_image, to_image, _ = upgrade_path_lists
    modify_reboot_script = add_fail_step_to_reboot
    metadata_process = request.config.getoption('metadata_process')
    skip_postupgrade_actions = request.config.getoption('skip_postupgrade_actions')

    def upgrade_path_preboot_setup():
        setup_upgrade_test(duthost, localhost, from_image, to_image, tbinfo,
                           metadata_process, upgrade_type, modify_reboot_script=modify_reboot_script, allow_fail=True)

    def upgrade_path_postboot_setup():
        run_postupgrade_actions(duthost, tbinfo, metadata_process, skip_postupgrade_actions)
        patch_rsyslog(duthost)

    upgrade_test_helper(duthost, localhost, ptfhost, from_image,
                        to_image, tbinfo, upgrade_type, get_advanced_reboot,
                        advanceboot_loganalyzer=advanceboot_loganalyzer,
                        preboot_setup=upgrade_path_preboot_setup,
                        postboot_setup=upgrade_path_postboot_setup,
                        allow_fail=True)


def test_upgrade_path(localhost, duthosts, rand_one_dut_hostname, ptfhost,
                      upgrade_path_lists, tbinfo, request, get_advanced_reboot,
                      advanceboot_loganalyzer, verify_dut_health):
    duthost = duthosts[rand_one_dut_hostname]
    upgrade_type, from_image, to_image, _ = upgrade_path_lists
    metadata_process = request.config.getoption('metadata_process')
    skip_postupgrade_actions = request.config.getoption('skip_postupgrade_actions')

    def upgrade_path_preboot_setup():
        setup_upgrade_test(duthost, localhost, from_image, to_image, tbinfo,
                           metadata_process, upgrade_type)

    def upgrade_path_postboot_setup():
        run_postupgrade_actions(duthost, tbinfo, metadata_process, skip_postupgrade_actions)
        patch_rsyslog(duthost)

    # Disable CPA for Arista 7260 as its currently unsupported
    enable_cpa = duthost.facts['platform'] != 'x86_64-arista_7260cx3_64'

    upgrade_test_helper(duthost, localhost, ptfhost, from_image,
                        to_image, tbinfo, upgrade_type, get_advanced_reboot,
                        advanceboot_loganalyzer=advanceboot_loganalyzer,
                        preboot_setup=upgrade_path_preboot_setup,
                        postboot_setup=upgrade_path_postboot_setup, enable_cpa=enable_cpa)


def test_double_upgrade_path(localhost, duthosts, rand_one_dut_hostname, ptfhost,
                            upgrade_path_lists, tbinfo, request, get_advanced_reboot,
                            advanceboot_loganalyzer, verify_dut_health):
    duthost = duthosts[rand_one_dut_hostname]
    upgrade_type, from_image, to_image, _ = upgrade_path_lists
    metadata_process = request.config.getoption('metadata_process')
    skip_postupgrade_actions = request.config.getoption('skip_postupgrade_actions')

    def upgrade_path_preboot_setup():
        setup_upgrade_test(duthost, localhost, from_image, to_image, tbinfo,
                           metadata_process, upgrade_type)

    def upgrade_path_postboot_setup():
        run_postupgrade_actions(duthost, tbinfo, metadata_process, skip_postupgrade_actions)
        patch_rsyslog(duthost)

    # Disable CPA for Arista 7260 as its currently unsupported
    enable_cpa = duthost.facts['platform'] != 'x86_64-arista_7260cx3_64'

    upgrade_test_helper(duthost, localhost, ptfhost, from_image,
                        to_image, tbinfo, upgrade_type, get_advanced_reboot,
                        advanceboot_loganalyzer=advanceboot_loganalyzer,
                        preboot_setup=upgrade_path_preboot_setup,
                        postboot_setup=upgrade_path_postboot_setup,
                        reboot_count=2, enable_cpa=enable_cpa)


def test_warm_upgrade_sad_path(localhost, duthosts, rand_one_dut_hostname, ptfhost,
                               upgrade_path_lists, tbinfo, request, get_advanced_reboot, advanceboot_loganalyzer,
                               verify_dut_health, nbrhosts, fanouthosts, vmhost, backup_and_restore_config_db,
                               advanceboot_neighbor_restore, sad_case_type):
    duthost = duthosts[rand_one_dut_hostname]
    upgrade_type, from_image, to_image, _ = upgrade_path_lists
    metadata_process = request.config.getoption('metadata_process')
    skip_postupgrade_actions = request.config.getoption('skip_postupgrade_actions')
    sad_preboot_list, sad_inboot_list = get_sad_case_list(duthost, nbrhosts,
        fanouthosts, vmhost, tbinfo, sad_case_type)

    def upgrade_path_preboot_setup():
        setup_upgrade_test(duthost, localhost, from_image, to_image, tbinfo,
                           metadata_process, upgrade_type)

    def upgrade_path_postboot_setup():
        run_postupgrade_actions(duthost, tbinfo, metadata_process, skip_postupgrade_actions)
        patch_rsyslog(duthost)

    # Disable CPA for Arista 7260 as its currently unsupported
    enable_cpa = duthost.facts['platform'] != 'x86_64-arista_7260cx3_64'

    upgrade_test_helper(duthost, localhost, ptfhost, from_image,
                        to_image, tbinfo, upgrade_type, get_advanced_reboot,
                        advanceboot_loganalyzer=advanceboot_loganalyzer,
                        preboot_setup=upgrade_path_preboot_setup,
                        postboot_setup=upgrade_path_postboot_setup,
                        sad_preboot_list=sad_preboot_list,
                        sad_inboot_list=sad_inboot_list, enable_cpa=enable_cpa)
