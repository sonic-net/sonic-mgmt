import pytest
import logging
from tests.common.helpers.upgrade_helpers import install_sonic, upgrade_test_helper
from tests.common.helpers.upgrade_helpers import restore_image            # noqa: F401
from tests.common.helpers.multi_thread_utils import SafeThreadPoolExecutor
from tests.upgrade_path.utilities import cleanup_prev_images, boot_into_base_image, boot_into_base_image_t2
from tests.common.fixtures.advanced_reboot import get_advanced_reboot   # noqa: F401
from tests.common.fixtures.consistency_checker.consistency_checker import consistency_checker_provider  # noqa: F401
from tests.common.platform.device_utils import verify_dut_health, verify_testbed_health    # noqa: F401
from tests.common.fixtures.duthost_utils import backup_and_restore_config_db    # noqa: F401
from tests.common.platform.device_utils import advanceboot_loganalyzer, advanceboot_neighbor_restore  # noqa: F401
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory   # noqa: F401
from tests.common.fixtures.ptfhost_utils import change_mac_addresses      # noqa: F401
from tests.common.fixtures.ptfhost_utils import remove_ip_addresses      # noqa: F401
from tests.common.fixtures.ptfhost_utils import copy_arp_responder_py     # noqa: F401
from tests.common.platform.warmboot_sad_cases import get_sad_case_list, SAD_CASE_LIST
from tests.common.reboot import REBOOT_TYPE_COLD


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
        # multi_sad = sad_bgp + sad_lag, no need to duplicate the sad type, it will reduce 3-4 hrs run time.
        if "multi_sad" in sad_cases and "sad_bgp" in sad_cases and "sad_lag" in sad_cases:
            sad_cases.remove("multi_sad")
        metafunc.parametrize("sad_case_type", sad_cases, scope="module")


@pytest.fixture(scope="module")
def upgrade_path_lists(request):
    upgrade_type = request.config.getoption('upgrade_type')
    from_list = request.config.getoption('base_image_list')
    to_list = request.config.getoption('target_image_list')
    restore_to_image = request.config.getoption('restore_to_image')
    enable_cpa = request.config.getoption('enable_cpa')
    return upgrade_type, from_list, to_list, restore_to_image, enable_cpa


def setup_upgrade_test(duthost, localhost, from_image, to_image, tbinfo,
                       upgrade_type, modify_reboot_script=None, allow_fail=False):
    logger.info("Test upgrade path from {} to {}".format(from_image, to_image))
    if tbinfo['topo']['type'] != 't2':  # We do this all at once seperately for T2
        cleanup_prev_images(duthost)
        # Install base image
        boot_into_base_image(duthost, localhost, from_image, tbinfo)

    # Install target image
    logger.info("Upgrading to {}".format(to_image))
    install_sonic(duthost, to_image, tbinfo)

    if allow_fail and modify_reboot_script:
        # add fail step to reboot script
        modify_reboot_script(upgrade_type)


@pytest.mark.device_type('vs')
def test_double_upgrade_path(localhost, duthosts, ptfhost, rand_one_dut_hostname,
                             nbrhosts, fanouthosts, tbinfo, request, restore_image,            # noqa: F811
                             get_advanced_reboot, verify_dut_health, advanceboot_loganalyzer,  # noqa: F811
                             consistency_checker_provider, upgrade_path_lists):                # noqa: F811
    duthost = duthosts[rand_one_dut_hostname]
    upgrade_type, from_image, to_image, _, enable_cpa = upgrade_path_lists
    logger.info("Test upgrade path from {} to {}".format(from_image, to_image))

    def upgrade_path_preboot_setup():
        setup_upgrade_test(duthost, localhost, from_image, to_image, tbinfo,
                           upgrade_type)

    upgrade_test_helper(duthost, localhost, ptfhost, from_image,
                        to_image, tbinfo, upgrade_type, get_advanced_reboot,
                        advanceboot_loganalyzer=advanceboot_loganalyzer,
                        preboot_setup=upgrade_path_preboot_setup,
                        consistency_checker_provider=consistency_checker_provider,
                        enable_cpa=enable_cpa,
                        reboot_count=2)


@pytest.mark.device_type('vs')
def test_upgrade_path(localhost, duthosts, ptfhost, rand_one_dut_hostname,
                      nbrhosts, fanouthosts, tbinfo, request, restore_image,            # noqa: F811
                      get_advanced_reboot, verify_dut_health, advanceboot_loganalyzer,  # noqa: F811
                      consistency_checker_provider, upgrade_path_lists):                # noqa: F811
    duthost = duthosts[rand_one_dut_hostname]
    upgrade_type, from_image, to_image, _, enable_cpa = upgrade_path_lists
    logger.info("Test upgrade path from {} to {}".format(from_image, to_image))

    def upgrade_path_preboot_setup():
        setup_upgrade_test(duthost, localhost, from_image, to_image, tbinfo,
                           upgrade_type)

    upgrade_test_helper(duthost, localhost, ptfhost, from_image,
                        to_image, tbinfo, upgrade_type, get_advanced_reboot,
                        advanceboot_loganalyzer=advanceboot_loganalyzer,
                        preboot_setup=upgrade_path_preboot_setup,
                        consistency_checker_provider=consistency_checker_provider,
                        enable_cpa=enable_cpa)


@pytest.mark.device_type('t2')
def test_upgrade_path_t2(localhost, duthosts, ptfhost, upgrade_path_lists,
                         tbinfo, request, verify_testbed_health):                     # noqa: F811

    _, from_image, to_image, _, _ = upgrade_path_lists
    upgrade_type = REBOOT_TYPE_COLD
    logger.info("Test upgrade path from {} to {}".format(from_image, to_image))

    for duthost in duthosts:
        cleanup_prev_images(duthost)
    boot_into_base_image_t2(duthosts, localhost, from_image, tbinfo)

    def upgrade_path_preboot_setup(dut):
        setup_upgrade_test(dut, localhost, from_image, to_image, tbinfo, upgrade_type)

    def upgrade_path_postboot_setup(dut):
        dut.shell("config bgp startup all")

    # get_advanced_reboot=None and advanceboot_loganalyzer=None as only cold reboot needed for T2
    suphost = duthosts.supervisor_nodes[0]
    upgrade_test_helper(suphost, localhost, ptfhost, from_image,
                        to_image, tbinfo, upgrade_type,
                        get_advanced_reboot=None,               # Not needed as only cold reboot supported to T2
                        advanceboot_loganalyzer=None,           # Not needed as only cold reboot supported to T2
                        preboot_setup=lambda: upgrade_path_preboot_setup(suphost),
                        postboot_setup=lambda: upgrade_path_postboot_setup(suphost),
                        consistency_checker_provider=None,      # Not needed as only cold reboot supported to T2
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


@pytest.mark.device_type('vs')
def test_warm_upgrade_sad_path(localhost, duthosts, ptfhost, rand_one_dut_hostname,
                               nbrhosts, fanouthosts, vmhost, tbinfo, request, restore_image,       # noqa: F811
                               get_advanced_reboot, verify_dut_health, advanceboot_loganalyzer,     # noqa: F811
                               upgrade_path_lists, backup_and_restore_config_db,                    # noqa: F811
                               advanceboot_neighbor_restore, consistency_checker_provider,          # noqa: F811
                               sad_case_type):                                                      # noqa: F811
    duthost = duthosts[rand_one_dut_hostname]
    upgrade_type, from_image, to_image, _, enable_cpa = upgrade_path_lists
    logger.info("Test upgrade path from {} to {}".format(from_image, to_image))

    def upgrade_path_preboot_setup():
        setup_upgrade_test(duthost, localhost, from_image, to_image, tbinfo,
                           upgrade_type)

    sad_preboot_list, sad_inboot_list = get_sad_case_list(
        duthost, nbrhosts, fanouthosts, vmhost, tbinfo, sad_case_type)
    upgrade_test_helper(duthost, localhost, ptfhost, from_image,
                        to_image, tbinfo, "warm", get_advanced_reboot,
                        advanceboot_loganalyzer=advanceboot_loganalyzer,
                        preboot_setup=upgrade_path_preboot_setup,
                        consistency_checker_provider=consistency_checker_provider,
                        sad_preboot_list=sad_preboot_list,
                        sad_inboot_list=sad_inboot_list, enable_cpa=enable_cpa)
