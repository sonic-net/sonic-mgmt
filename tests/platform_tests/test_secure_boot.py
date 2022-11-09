"""
this tests checks secure boot upgrade

In order to run this test, you need to specify the following argument:
	1. --target_image_list (to contain your non secure image path e.g. /tmp/images/my_non_secure_img.bin)
e.g.:
(from tests dir)
	pytest platform_tests/test_secure_boot.py <regular arguments> --target_image_list non_secure_image.bin
"""
import logging
import pytest
import re
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


def get_current_version(duthost):
    '''
    @summary: extract the current version installed as shown in the "show boot" output.
    :param duthost: device under test
    :return: the version currently installed
    '''
    output = duthost.shell("show boot")['stdout']
    results = re.findall("Current\s*\:\s*(.*)\n", output)
    pytest_assert(len(results) > 0, "Current image is empty!")
    return results[0]


def test_non_secure_boot_upgrade_failure(duthosts, enum_rand_one_per_hwsku_hostname, upgrade_path_lists, tbinfo):
    """
    @summary: This test case validates non successful upgrade of a given non secure image
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    upgrade_type, _, non_secure_img, _ = upgrade_path_lists
    current_version = get_current_version(duthost)
    logger.info("current version installed is {}".format(current_version))
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
        logger.info("reset the image installed back to original image - {}".format(current_version))
        duthost.shell("sonic-installer set-default {}",format(current_version))
        pytest_assert(result=="image install failure", "install non secure image should not succeed")
        logger.info("Check version has not changed after reboot")
        check_sonic_version(duthost, current_version)
