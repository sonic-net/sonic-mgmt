"""
This test checks secure upgrade feature. If we have a secure system with secured image installed
on it, the system is expected to install only secured images on it. So trying to install non-secure image
will cause fail and a print of failure message to console indicating it is not a secured image.
This test case validates the error flow mentioned above.

In order to run this test, you need to specify the following argument:

    --target_image_list (to contain one non-secure image path e.g. /tmp/images/my_non_secure_img.bin)

Example run from tests directory:
    "pytest platform_tests/test_secure_upgrade.py <regular arguments> --target_image_list non_secure_image.bin"
"""
import logging
import pytest
import re
from tests.common.errors import RunAnsibleModuleFail
from tests.common.helpers.assertions import pytest_assert
from tests.upgrade_path.upgrade_helpers import install_sonic

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer,
]

logger = logging.getLogger(__name__)


@pytest.fixture(scope='function', autouse=True)
def keep_same_version_installed(duthost):
    '''
    @summary: extract the current version installed as shown in the "show boot" output
    and restore original image installed after the test run
    :param duthost: device under test
    '''
    output = duthost.shell("show boot")['stdout']
    results = re.findall(r"Current\s*\:\s*(.*)\n", output)
    pytest_assert(len(results) > 0, "Current image is empty!")
    current_version = results[0]
    yield
    duthost.shell("sudo sonic-installer set-default {}", format(current_version))


@pytest.fixture(scope='session')
def non_secure_image_path(request):
    '''
    @summary: will extract the non secure image path from --target_image_list parameter
    :return: given non secure image path
    '''
    non_secure_img_path = request.config.getoption('target_image_list')
    return str(non_secure_img_path)


def test_non_secure_boot_upgrade_failure(duthost, non_secure_image_path, tbinfo):
    """
    @summary: This test case validates non successful upgrade of a given non secure image
    """
    # install non secure image
    logger.info("install non secure image - expect fail, image path = {}".format(non_secure_image_path))
    result = "image install failure"  # because we expect fail
    try:
        # in case of success result will take the target image name
        result = install_sonic(duthost, non_secure_image_path, tbinfo)
    except RunAnsibleModuleFail as err:
        output_msg = str(err.results._check_key("module_stdout"))
        err_msg = str(err.results._check_key("msg"))
        logger.info("Expected fail, err msg is : {}\n\noutput_msg is {}".format(err_msg, output_msg))
        pytest_assert(
            "Failure: CMS signature verification failed" in str(output_msg),
            "failure was not due to security limitations")
    finally:
        pytest_assert(result == "image install failure", "non-secure image was successfully installed")
