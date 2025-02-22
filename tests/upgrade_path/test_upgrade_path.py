import pytest
import logging
from tests.common.helpers.upgrade_helpers import install_sonic, upgrade_test_helper, check_asic_and_db_consistency
from tests.common.helpers.upgrade_helpers import restore_image, restore_image_to_first_boot           # noqa F401
from tests.upgrade_path.utilities import cleanup_prev_images, boot_into_base_image, install_and_boot_into_base_image
from tests.common.fixtures.advanced_reboot import get_advanced_reboot   # noqa F401
from tests.common.fixtures.consistency_checker.consistency_checker import consistency_checker_provider  # noqa F401
from tests.common.platform.device_utils import verify_dut_health    # noqa F401
from tests.common.fixtures.duthost_utils import backup_and_restore_config_db    # noqa F401
from tests.common.platform.device_utils import advanceboot_loganalyzer, advanceboot_neighbor_restore # noqa F401
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory   # noqa F401
from tests.common.fixtures.ptfhost_utils import change_mac_addresses      # noqa F401
from tests.common.fixtures.ptfhost_utils import remove_ip_addresses      # noqa F401
from tests.common.fixtures.ptfhost_utils import copy_arp_responder_py     # noqa F401
from tests.common.platform.warmboot_sad_cases import get_sad_case_list, SAD_CASE_LIST


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

    base_image_list = metafunc.config.getoption("base_image_list").split(',')
    base_image_version_list = metafunc.config.getoption("base_image_version_list")
    if base_image_version_list:
        base_image_version_list = base_image_version_list.split(',')
    else:
        base_image_version_list = [''] * len(base_image_list)
    target_image_list = metafunc.config.getoption("target_image_list").split(',')
    target_image_version_list = metafunc.config.getoption("target_image_version_list")
    if target_image_version_list:
        target_image_version_list = target_image_version_list.split(',')
    else:
        target_image_version_list = [''] * len(target_image_list)

    if len(base_image_list) != len(base_image_version_list):
        pytest.fail("Number of base images doesn't match the number of base image versions")

    if len(target_image_list) != len(target_image_version_list):
        pytest.fail("Number of target images doesn't match the number of target image versions")

    pytest_params = []
    for i in range(len(base_image_list)):
        for j in range(len(target_image_list)):
            pytest_params.append(pytest.param(base_image_list[i], base_image_version_list[i],
                                 target_image_list[j], target_image_version_list[j],
                                 id="{}-to-{}".format(base_image_list[i], target_image_list[j])))

    metafunc.parametrize("base_image,base_image_version,target_image,target_image_version",
                         pytest_params, scope="module")


@pytest.fixture(scope="module")
def upgrade_path_lists(request, base_image, base_image_version, target_image, target_image_version):
    upgrade_type = request.config.getoption('upgrade_type')
    restore_to_image = request.config.getoption('restore_to_image')
    enable_cpa = request.config.getoption('enable_cpa')
    return upgrade_type, base_image, base_image_version, target_image, target_image_version, \
        restore_to_image, enable_cpa


def setup_upgrade_test(duthost, localhost, from_image, from_image_version, to_image, to_image_version, tbinfo,
                       upgrade_type, modify_reboot_script=None, allow_fail=False):
    logger.info("Test upgrade path from {} ({}) to {} ({})".format(from_image, from_image_version,
                                                                   to_image, to_image_version))
    if from_image_version and restore_image_to_first_boot(duthost, from_image_version):
        logger.info("Restored existing {} to first boot state".format(from_image_version))
        boot_into_base_image(duthost, localhost, from_image_version, tbinfo)
    else:
        cleanup_prev_images(duthost)
        # Install base image
        install_and_boot_into_base_image(duthost, localhost, from_image, tbinfo)

    # Install target image
    logger.info("Upgrading to {}".format(to_image))
    if to_image_version and restore_image_to_first_boot(duthost, to_image_version):
        logger.info("Restored existing {} to first boot state".format(to_image_version))
    else:
        install_sonic(duthost, to_image, tbinfo)

    if allow_fail and modify_reboot_script:
        # add fail step to reboot script
        modify_reboot_script(upgrade_type)


@pytest.mark.device_type('vs')
def test_double_upgrade_path(localhost, duthosts, ptfhost, rand_one_dut_hostname,
                      tbinfo, request, restore_image,                                   # noqa F811
                      get_advanced_reboot, verify_dut_health, advanceboot_loganalyzer,  # noqa F811
                      consistency_checker_provider, upgrade_path_lists):                # noqa F811
    duthost = duthosts[rand_one_dut_hostname]
    upgrade_type, from_image, from_image_version, to_image, to_image_version, _, enable_cpa = upgrade_path_lists
    logger.info("Test upgrade path from {} to {}".format(from_image, to_image))

    def upgrade_path_preboot_setup():
        setup_upgrade_test(duthost, localhost, from_image, from_image_version, to_image, to_image_version, tbinfo,
                           upgrade_type)

    def upgrade_path_postboot_setup():
        check_asic_and_db_consistency(request.config, duthost, consistency_checker_provider)

    upgrade_test_helper(duthost, localhost, ptfhost, from_image,
                        to_image, tbinfo, upgrade_type, get_advanced_reboot,
                        advanceboot_loganalyzer=advanceboot_loganalyzer,
                        preboot_setup=upgrade_path_preboot_setup,
                        postboot_setup=upgrade_path_postboot_setup,
                        enable_cpa=enable_cpa,
                        reboot_count=2)


@pytest.mark.device_type('vs')
def test_upgrade_path(localhost, duthosts, ptfhost, rand_one_dut_hostname,
                      tbinfo, request, restore_image,                                   # noqa F811
                      get_advanced_reboot, verify_dut_health, advanceboot_loganalyzer,  # noqa F811
                      consistency_checker_provider, upgrade_path_lists):                # noqa F811
    duthost = duthosts[rand_one_dut_hostname]
    upgrade_type, from_image, from_image_version, to_image, to_image_version, _, enable_cpa = upgrade_path_lists
    logger.info("Test upgrade path from {} to {}".format(from_image, to_image))

    def upgrade_path_preboot_setup():
        setup_upgrade_test(duthost, localhost, from_image, from_image_version, to_image, to_image_version, tbinfo,
                           upgrade_type)

    def upgrade_path_postboot_setup():
        check_asic_and_db_consistency(request.config, duthost, consistency_checker_provider)

    upgrade_test_helper(duthost, localhost, ptfhost, from_image,
                        to_image, tbinfo, upgrade_type, get_advanced_reboot,
                        advanceboot_loganalyzer=advanceboot_loganalyzer,
                        preboot_setup=upgrade_path_preboot_setup,
                        postboot_setup=upgrade_path_postboot_setup,
                        enable_cpa=enable_cpa)


@pytest.mark.device_type('vs')
def test_warm_upgrade_sad_path(localhost, duthosts, ptfhost, rand_one_dut_hostname,
                               nbrhosts, fanouthosts, vmhost, tbinfo, request, restore_image,       # noqa F811
                               get_advanced_reboot, verify_dut_health, advanceboot_loganalyzer,     # noqa F811
                               upgrade_path_lists, backup_and_restore_config_db,                    # noqa F811
                               advanceboot_neighbor_restore, consistency_checker_provider,          # noqa F811
                               sad_case_type):                                                      # noqa F811
    duthost = duthosts[rand_one_dut_hostname]
    upgrade_type, from_image, from_image_version, to_image, to_image_version, _, enable_cpa = upgrade_path_lists
    logger.info("Test upgrade path from {} to {}".format(from_image, to_image))

    def upgrade_path_preboot_setup():
        setup_upgrade_test(duthost, localhost, from_image, from_image_version, to_image, to_image_version, tbinfo,
                           upgrade_type)

    def upgrade_path_postboot_setup():
        check_asic_and_db_consistency(request.config, duthost, consistency_checker_provider)

    sad_preboot_list, sad_inboot_list = get_sad_case_list(
        duthost, nbrhosts, fanouthosts, vmhost, tbinfo, sad_case_type)
    upgrade_test_helper(duthost, localhost, ptfhost, from_image,
                        to_image, tbinfo, "warm", get_advanced_reboot,
                        advanceboot_loganalyzer=advanceboot_loganalyzer,
                        preboot_setup=upgrade_path_preboot_setup,
                        postboot_setup=upgrade_path_postboot_setup,
                        sad_preboot_list=sad_preboot_list,
                        sad_inboot_list=sad_inboot_list, enable_cpa=enable_cpa)
