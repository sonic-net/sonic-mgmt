import pytest
import logging
from utilities import boot_into_base_image, boot_into_base_image_t2, cleanup_prev_images, sonic_update_firmware
from postupgrade_helper import run_postupgrade_actions, run_bgp_neighbor
from tests.common.helpers.dut_utils import patch_rsyslog
from tests.common.reboot import REBOOT_TYPE_COLD
from tests.common.helpers.upgrade_helpers import install_sonic, upgrade_test_helper, add_pfc_storm_table
from tests.common.helpers.multi_thread_utils import SafeThreadPoolExecutor
from tests.common.fixtures.advanced_reboot import get_advanced_reboot                                   # noqa F401
from tests.common.fixtures.duthost_utils import backup_and_restore_config_db                            # noqa F401
from tests.common.fixtures.consistency_checker.consistency_checker import consistency_checker_provider  # noqa F401
from tests.common.platform.device_utils import advanceboot_loganalyzer, advanceboot_neighbor_restore, \
    verify_dut_health, verify_testbed_health                                                            # noqa F401
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory                                 # noqa F401
from tests.common.platform.warmboot_sad_cases import get_sad_case_list, SAD_CASE_LIST
from tests.platform_tests.verify_dut_health import add_fail_step_to_reboot  # lgtm[py/unused-import]    # noqa F401

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer,
    pytest.mark.disable_memory_utilization,
    pytest.mark.skip_check_dut_health
]
logger = logging.getLogger(__name__)


@pytest.fixture(scope="module")
def upgrade_path_lists(request, upgrade_type_params, base_image, target_image):
    restore_to_image = request.config.getoption('restore_to_image')
    enable_cpa = request.config.getoption('enable_cpa')
    if not base_image or not target_image:
        pytest.skip("base_image_list or target_image_list is empty")
    return upgrade_type_params, base_image, target_image, restore_to_image, enable_cpa


@pytest.fixture
def skip_cancelled_case(request, upgrade_type_params):
    if "test_cancelled_upgrade_path" in request.node.name and \
            upgrade_type_params not in ["warm", "fast"]:
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
    logger.info("Test upgrade path from {} to {} on {}".format(from_image, to_image, duthost.hostname))

    # Install and reboot into base image
    if tbinfo['topo']['type'] != 't2':  # We do this all at once seperately for T2
        cleanup_prev_images(duthost)
        boot_into_base_image(duthost, localhost, from_image, tbinfo)

    # Install target image
    logger.info("Upgrading {} to {}".format(duthost.hostname, to_image))
    if metadata_process:
        sonic_update_firmware(duthost, localhost, to_image, upgrade_type)
    else:
        install_sonic(duthost, to_image, tbinfo)

    logger.info("Add pfc storm table to {}.".format(duthost.hostname))
    add_pfc_storm_table(duthost)

    if allow_fail and modify_reboot_script:
        # add fail step to reboot script
        modify_reboot_script(upgrade_type)


def test_cancelled_upgrade_path(localhost, duthosts, rand_one_dut_hostname, ptfhost,
                                upgrade_path_lists, skip_cancelled_case, tbinfo, request,
                                get_advanced_reboot, advanceboot_loganalyzer,  # noqa: F811
                                add_fail_step_to_reboot, verify_dut_health,    # noqa: F811
                                consistency_checker_provider):                 # noqa: F811
    duthost = duthosts[rand_one_dut_hostname]
    upgrade_type, from_image, to_image, _, _ = upgrade_path_lists
    modify_reboot_script = add_fail_step_to_reboot
    metadata_process = request.config.getoption('metadata_process')
    skip_postupgrade_actions = request.config.getoption('skip_postupgrade_actions')

    def upgrade_path_preboot_setup():
        setup_upgrade_test(duthost, localhost, from_image, to_image, tbinfo,
                           metadata_process, upgrade_type, modify_reboot_script=modify_reboot_script, allow_fail=True)

    def upgrade_path_postboot_setup():
        run_postupgrade_actions(duthost, localhost, tbinfo, metadata_process, skip_postupgrade_actions,
                                check_failed=False)
        patch_rsyslog(duthost)

    upgrade_test_helper(duthost, localhost, ptfhost, from_image,
                        to_image, tbinfo, upgrade_type, get_advanced_reboot,
                        advanceboot_loganalyzer=advanceboot_loganalyzer,
                        preboot_setup=upgrade_path_preboot_setup,
                        postboot_setup=upgrade_path_postboot_setup,
                        consistency_checker_provider=consistency_checker_provider,
                        allow_fail=True)


def test_upgrade_path(localhost, duthosts, rand_one_dut_hostname, ptfhost,
                      upgrade_path_lists, tbinfo, request, get_advanced_reboot,  # noqa: F811
                      advanceboot_loganalyzer, verify_dut_health,                # noqa: F811
                      consistency_checker_provider):                             # noqa: F811
    duthost = duthosts[rand_one_dut_hostname]
    upgrade_type, from_image, to_image, _, enable_cpa = upgrade_path_lists
    metadata_process = request.config.getoption('metadata_process')
    skip_postupgrade_actions = request.config.getoption('skip_postupgrade_actions')

    def upgrade_path_preboot_setup():
        setup_upgrade_test(duthost, localhost, from_image, to_image, tbinfo,
                           metadata_process, upgrade_type)

    def upgrade_path_postboot_setup():
        run_postupgrade_actions(duthost, localhost, tbinfo, metadata_process, skip_postupgrade_actions,
                                check_failed=False)
        patch_rsyslog(duthost)

    upgrade_test_helper(duthost, localhost, ptfhost, from_image,
                        to_image, tbinfo, upgrade_type, get_advanced_reboot,
                        advanceboot_loganalyzer=advanceboot_loganalyzer,
                        preboot_setup=upgrade_path_preboot_setup,
                        postboot_setup=upgrade_path_postboot_setup,
                        consistency_checker_provider=consistency_checker_provider,
                        enable_cpa=enable_cpa)


def test_upgrade_path_t2(localhost, duthosts, ptfhost, upgrade_path_lists,
                         tbinfo, request, verify_testbed_health):            # noqa: F811
    _, from_image, to_image, _, _ = upgrade_path_lists
    # Only cold reboot is supported for T2
    upgrade_type = REBOOT_TYPE_COLD
    metadata_process = request.config.getoption('metadata_process')
    skip_postupgrade_actions = request.config.getoption('skip_postupgrade_actions')

    # Boot whole chassis into base image first
    for duthost in duthosts:
        cleanup_prev_images(duthost)
    boot_into_base_image_t2(duthosts, localhost, from_image, tbinfo)

    def upgrade_path_preboot_setup(dut):
        setup_upgrade_test(dut, localhost, from_image, to_image, tbinfo,
                           metadata_process, upgrade_type)

    def upgrade_path_postboot_setup(dut):
        run_postupgrade_actions(dut, localhost, tbinfo, metadata_process, skip_postupgrade_actions)
        run_bgp_neighbor(dut, localhost, tbinfo, metadata_process)
        patch_rsyslog(dut)

    suphost = duthosts.supervisor_nodes[0]
    upgrade_test_helper(suphost, localhost, ptfhost, from_image,
                        to_image, tbinfo, upgrade_type,
                        get_advanced_reboot=None,               # Not needed as only cold reboot supported to T2
                        advanceboot_loganalyzer=None,           # Not needed as only cold reboot supported to T2
                        preboot_setup=lambda: upgrade_path_preboot_setup(suphost),
                        postboot_setup=lambda: upgrade_path_postboot_setup(suphost),
                        consistency_checker_provider=None,
                        enable_cpa=False)

    with SafeThreadPoolExecutor(max_workers=8) as executor:
        for dut in duthosts.frontend_nodes:
            executor.submit(upgrade_test_helper, dut, localhost, ptfhost, from_image,
                            to_image, tbinfo, upgrade_type,
                            get_advanced_reboot=None,           # Not needed as only cold reboot supported to T2
                            advanceboot_loganalyzer=None,       # Not needed as only cold reboot supported to T2
                            preboot_setup=lambda dut=dut: upgrade_path_preboot_setup(dut),
                            postboot_setup=lambda dut=dut: upgrade_path_postboot_setup(dut),
                            consistency_checker_provider=None,  # Not needed as only cold reboot supported to T2
                            enable_cpa=False)


def test_double_upgrade_path(localhost, duthosts, rand_one_dut_hostname, ptfhost,
                             upgrade_path_lists, tbinfo, request, get_advanced_reboot,  # noqa: F811
                             advanceboot_loganalyzer, verify_dut_health,                # noqa: F811
                             consistency_checker_provider):                             # noqa: F811
    duthost = duthosts[rand_one_dut_hostname]
    upgrade_type, from_image, to_image, _, enable_cpa = upgrade_path_lists
    metadata_process = request.config.getoption('metadata_process')
    skip_postupgrade_actions = request.config.getoption('skip_postupgrade_actions')

    def upgrade_path_preboot_setup():
        setup_upgrade_test(duthost, localhost, from_image, to_image, tbinfo,
                           metadata_process, upgrade_type)

    def upgrade_path_postboot_setup():
        run_postupgrade_actions(duthost, localhost, tbinfo, metadata_process, skip_postupgrade_actions,
                                check_failed=False)
        patch_rsyslog(duthost)

    upgrade_test_helper(duthost, localhost, ptfhost, from_image,
                        to_image, tbinfo, upgrade_type, get_advanced_reboot,
                        advanceboot_loganalyzer=advanceboot_loganalyzer,
                        preboot_setup=upgrade_path_preboot_setup,
                        postboot_setup=upgrade_path_postboot_setup,
                        consistency_checker_provider=consistency_checker_provider,
                        reboot_count=2, enable_cpa=enable_cpa)


def test_warm_upgrade_sad_path(localhost, duthosts, rand_one_dut_hostname, ptfhost,
                               upgrade_path_lists, tbinfo, request, get_advanced_reboot,                   # noqa: F811
                               advanceboot_loganalyzer, verify_dut_health, nbrhosts, fanouthosts, vmhost,  # noqa: F811
                               backup_and_restore_config_db, consistency_checker_provider,                 # noqa: F811
                               advanceboot_neighbor_restore, sad_case_type):                               # noqa: F811
    duthost = duthosts[rand_one_dut_hostname]
    upgrade_type, from_image, to_image, _, enable_cpa = upgrade_path_lists
    metadata_process = request.config.getoption('metadata_process')
    skip_postupgrade_actions = request.config.getoption('skip_postupgrade_actions')
    sad_preboot_list, sad_inboot_list = get_sad_case_list(duthost, nbrhosts,
                                                          fanouthosts, vmhost, tbinfo, sad_case_type)

    def upgrade_path_preboot_setup():
        setup_upgrade_test(duthost, localhost, from_image, to_image, tbinfo,
                           metadata_process, upgrade_type)

    def upgrade_path_postboot_setup():
        run_postupgrade_actions(duthost, localhost, tbinfo, metadata_process, skip_postupgrade_actions,
                                check_failed=False)
        patch_rsyslog(duthost)

    upgrade_test_helper(duthost, localhost, ptfhost, from_image,
                        to_image, tbinfo, upgrade_type, get_advanced_reboot,
                        advanceboot_loganalyzer=advanceboot_loganalyzer,
                        preboot_setup=upgrade_path_preboot_setup,
                        postboot_setup=upgrade_path_postboot_setup,
                        consistency_checker_provider=consistency_checker_provider,
                        sad_preboot_list=sad_preboot_list,
                        sad_inboot_list=sad_inboot_list, enable_cpa=enable_cpa)
