import pytest
import logging
from tests.common.fixtures.advanced_reboot import get_advanced_reboot
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.dut_utils import patch_rsyslog
from tests.common.reboot import get_reboot_cause
from tests.common.utilities import wait_until
from tests.common.helpers.upgrade_helpers import SYSTEM_STABILIZE_MAX_TIME, check_copp_config, check_reboot_cause, \
    check_services, install_sonic, multi_hop_warm_upgrade_test_helper
from tests.platform_tests.conftest import multihop_advanceboot_loganalyzer_factory
from tests.platform_tests.verify_dut_health import verify_dut_health, check_neighbors   # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory   # noqa F401
from postupgrade_helper import run_postupgrade_actions
from utilities import cleanup_prev_images, set_base_image_a, sonic_update_firmware

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer,
    pytest.mark.skip_check_dut_health
]
logger = logging.getLogger(__name__)

def test_multi_hop_upgrade_path(localhost, duthosts, rand_one_dut_hostname, ptfhost,
                           tbinfo, request, get_advanced_reboot,
                           multihop_advanceboot_loganalyzer_factory, verify_dut_health):
    duthost = duthosts[rand_one_dut_hostname]
    metadata_process = request.config.getoption('metadata_process')
    skip_postupgrade_actions = request.config.getoption('skip_postupgrade_actions')
    multi_hop_upgrade_path = request.config.getoption('multi_hop_upgrade_path')
    upgrade_type = request.config.getoption('upgrade_type')
    assert upgrade_type == "warm", "test_multi_hop_upgrade_path only supports warm upgrade"

    # Disable CPA for Arista 7260 as its currently unsupported
    enable_cpa = duthost.facts['platform'] != 'x86_64-arista_7260cx3_64'

    upgrade_path_urls = multi_hop_upgrade_path.split(",")
    if len(upgrade_path_urls) < 2:
        pytest.skip("Need atleast 2 URLs to test multi-hop upgrade path")

    def base_image_setup():
        """Run only once, to boot the device into the base image"""
        base_image = upgrade_path_urls[0]
        logger.info("Setting up base image {}".format(base_image))
        cleanup_prev_images(duthost)
        
        # Install base image
        set_base_image_a(duthost, localhost, base_image, tbinfo)
        logger.info("Base image setup complete")

    def pre_hop_setup(hop_index):
        """Run before each hop in the multi-hop upgrade path"""
        # Install target image
        to_image = upgrade_path_urls[hop_index]
        logger.info("Installing hop {} image {}".format(hop_index, to_image))
        if metadata_process:
            sonic_update_firmware(duthost, localhost, to_image, upgrade_type)
        else:
            install_sonic(duthost, to_image, tbinfo)
        logger.info("Finished setup for hop {} image {}".format(hop_index, to_image))

    def post_hop_teardown(hop_index):
        """Run after each hop in the multi-hop upgrade path"""
        to_image = upgrade_path_urls[hop_index]
        logger.info("Starting post hop teardown for hop {} image {}".format(hop_index, to_image))
        run_postupgrade_actions(duthost, tbinfo, metadata_process, skip_postupgrade_actions)
        patch_rsyslog(duthost)
        
        logger.info("Check reboot cause of hop {}. Expected cause {}".format(hop_index, upgrade_type))
        networking_uptime = duthost.get_networking_uptime().seconds
        timeout = max((SYSTEM_STABILIZE_MAX_TIME - networking_uptime), 1)
        if "6100" not in duthost.facts["hwsku"]:
            pytest_assert(wait_until(timeout, 5, 0, check_reboot_cause, duthost, upgrade_type),
                            "Reboot cause {} did not match the trigger - {}".format(get_reboot_cause(duthost),
                                                                                    upgrade_type))
        check_services(duthost)
        check_neighbors(duthost, tbinfo)
        check_copp_config(duthost)
        logger.info("Finished post hop teardown for hop {} image {}".format(hop_index, to_image))

    multi_hop_warm_upgrade_test_helper(duthost, localhost, ptfhost,
                        tbinfo, get_advanced_reboot, upgrade_type, upgrade_path_urls,
                        multihop_advanceboot_loganalyzer_factory=multihop_advanceboot_loganalyzer_factory,
                        base_image_setup=base_image_setup, pre_hop_setup=pre_hop_setup,
                        post_hop_teardown=post_hop_teardown,
                        enable_cpa=enable_cpa)
