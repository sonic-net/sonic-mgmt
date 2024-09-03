import pytest
import logging
import re
from tests.common import reboot
from tests.upgrade_path.upgrade_helpers import install_sonic, check_sonic_version,\
    upgrade_test_helper, check_asic_and_db_consistency
from tests.upgrade_path.upgrade_helpers import restore_image            # noqa F401
from tests.common.fixtures.advanced_reboot import get_advanced_reboot   # noqa F401
from tests.common.fixtures.consistency_checker.consistency_checker import consistency_checker_provider  # noqa F401
from tests.platform_tests.verify_dut_health import verify_dut_health    # noqa F401
from tests.common.fixtures.duthost_utils import backup_and_restore_config_db    # noqa F401

from tests.platform_tests.conftest import advanceboot_loganalyzer, advanceboot_neighbor_restore  # noqa F401
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory   # noqa F401
from tests.common.fixtures.ptfhost_utils import change_mac_addresses      # noqa F401
from tests.common.fixtures.ptfhost_utils import remove_ip_addresses      # noqa F401
from tests.common.fixtures.ptfhost_utils import copy_arp_responder_py     # noqa F401
from tests.common.errors import RunAnsibleModuleFail

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
    enable_cpa = request.config.getoption('enable_cpa')
    return upgrade_type, from_list, to_list, restore_to_image, enable_cpa


def cleanup_prev_images(duthost):
    logger.info("Cleaning up previously installed images on DUT")
    current_os_version = duthost.shell('sonic_installer list | grep Current | cut -f2 -d " "')['stdout']
    duthost.shell("sonic_installer set_next_boot {}".format(current_os_version), module_ignore_errors=True)
    duthost.shell("sonic_installer set-next-boot {}".format(current_os_version), module_ignore_errors=True)
    duthost.shell("sonic_installer cleanup -y", module_ignore_errors=True)


def setup_upgrade_test(duthost, localhost, from_image, to_image, tbinfo,
                       upgrade_type, modify_reboot_script=None, allow_fail=False):
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
    reboot_type = 'soft' if "s6100" in duthost.facts["platform"] else 'cold'
    reboot(duthost, localhost, reboot_type=reboot_type)
    check_sonic_version(duthost, target_version)

    # Install target image
    logger.info("Upgrading to {}".format(to_image))
    target_version = install_sonic(duthost, to_image, tbinfo)

    if allow_fail and modify_reboot_script:
        # add fail step to reboot script
        modify_reboot_script(upgrade_type)


@pytest.mark.device_type('vs')
def test_double_upgrade_path(localhost, duthosts, ptfhost, rand_one_dut_hostname,
                      nbrhosts, fanouthosts, tbinfo, request, restore_image,            # noqa F811
                      get_advanced_reboot, verify_dut_health, advanceboot_loganalyzer,  # noqa F811
                      upgrade_path_lists):                                              # noqa F811
    duthost = duthosts[rand_one_dut_hostname]
    upgrade_type, from_image, to_image, _, enable_cpa = upgrade_path_lists
    logger.info("Test upgrade path from {} to {}".format(from_image, to_image))

    def upgrade_path_preboot_setup():
        setup_upgrade_test(duthost, localhost, from_image, to_image, tbinfo,
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
                      nbrhosts, fanouthosts, tbinfo, request, restore_image,            # noqa F811
                      get_advanced_reboot, verify_dut_health, advanceboot_loganalyzer,  # noqa F811
                      upgrade_path_lists):
    duthost = duthosts[rand_one_dut_hostname]
    upgrade_type, from_image, to_image, _, enable_cpa = upgrade_path_lists
    logger.info("Test upgrade path from {} to {}".format(from_image, to_image))

    def upgrade_path_preboot_setup():
        setup_upgrade_test(duthost, localhost, from_image, to_image, tbinfo,
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
                               advanceboot_neighbor_restore, sad_case_type):                        # noqa F811
    duthost = duthosts[rand_one_dut_hostname]
    upgrade_type, from_image, to_image, _, enable_cpa = upgrade_path_lists
    logger.info("Test upgrade path from {} to {}".format(from_image, to_image))

    def upgrade_path_preboot_setup():
        setup_upgrade_test(duthost, localhost, from_image, to_image, tbinfo,
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
