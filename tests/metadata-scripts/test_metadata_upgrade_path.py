import pytest
import logging
from utilities import set_base_image_a, cleanup_prev_images, sonic_update_firmware
from postupgrade_helper import run_postupgrade_actions
from tests.common.helpers.dut_utils import patch_rsyslog
from tests.common import reboot
from tests.upgrade_path.upgrade_helpers import install_sonic, upgrade_test_helper, add_pfc_storm_table
from tests.common.fixtures.advanced_reboot import get_advanced_reboot
from tests.common.fixtures.duthost_utils import backup_and_restore_config_db
from tests.platform_tests.conftest import advanceboot_loganalyzer, advanceboot_neighbor_restore
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory   # noqa F401
from tests.platform_tests.warmboot_sad_cases import get_sad_case_list, SAD_CASE_LIST
from tests.platform_tests.verify_dut_health import verify_dut_health        # lgtm[py/unused-import]
from tests.platform_tests.verify_dut_health import add_fail_step_to_reboot  # lgtm[py/unused-import]

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
    if metafunc.config.getoption("multi_hop_upgrade_path"):
        # This pytest execution is for multi-hop upgrade path - don't parametrize for A->B upgrade
        return
    
    # Parametrize for A->B upgrade
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


def setup_upgrade_test(duthost, localhost, from_image, to_image,
                       tbinfo, metadata_process, upgrade_type,
                       modify_reboot_script=None, allow_fail=False):
    """Sets up the test environment for an A->B upgrade test."""
    logger.info("Test upgrade path from {} to {}".format(from_image, to_image))
    cleanup_prev_images(duthost)
    
    # Install and reboot into base image
    set_base_image_a(duthost, localhost, from_image, tbinfo)

    # Install target image
    logger.info("Upgrading to {}".format(to_image))
    if metadata_process:
        sonic_update_firmware(duthost, localhost, to_image, upgrade_type)
    else:
        install_sonic(duthost, to_image, tbinfo)

    logger.info("Add pfc storm table to duthost.")
    add_pfc_storm_table(duthost)

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
