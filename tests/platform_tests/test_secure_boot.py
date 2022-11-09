"""
this tests checks secure boot upgrade
"""
import logging
import pytest
from tests.common.errors import RunAnsibleModuleFail
from tests.common import reboot
from tests.common.helpers.assertions import pytest_assert
from tests.upgrade_path.upgrade_helpers import check_services, check_sonic_version, \
     install_sonic, check_reboot_cause
from tests.upgrade_path.test_upgrade_path import upgrade_path_lists

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer,
    pytest.mark.skip_check_dut_health
]

logger = logging.getLogger(__name__)


def test_non_secure_boot_upgrade_failure(duthosts, enum_rand_one_per_hwsku_hostname, localhost, upgrade_path_lists, tbinfo, capsys):
    """
    @summary: This test case validates non successful upgrade of a given non secure image
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    upgrade_type, _, non_secure_img, _ = upgrade_path_lists
    logger.info("get current version installed")
    current_version = duthost.image_facts()['ansible_facts']['ansible_image_facts']['current']
    # install non secure image
    logger.info("install non secure image - expect fail, image url = {}".format(non_secure_img))
    result = "image install failure" # because we expect fail
    try:
        # in case of success result will return target image name
        result = install_sonic(duthost, non_secure_img, tbinfo)
    except RunAnsibleModuleFail as err:
        err_msg = str(err.results._check_key("module_stdout"))
        logger.info("Expected fail, msg : {}".format(err_msg))
        pytest_assert("Failure: CMS signature verification failed" in str(err_msg), "failure was not due to security limitations")
    finally:
        pytest_assert(result=="image install failure", "install non secure image should not succeed")
        logger.info("Cold reboot the DUT")
        reboot(duthost, localhost)
        logger.info("Check version has not changed after reboot")
        check_sonic_version(duthost, current_version)
        check_reboot_cause(duthost, upgrade_type)
        check_services(duthost)
