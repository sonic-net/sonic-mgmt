import pytest
import logging
import time
import pexpect
from tests.platform_tests.test_first_time_boot_password_change.manufacture import manufacture
from tests.platform_tests.test_first_time_boot_password_change.default_consts import DefaultConsts


def pytest_addoption(parser):
    parser.addoption("--feature_enabled", action="store", default='False', help="set to True if the feature is enabled")


class CurrentConfigurations:
    '''
    @summary: this class will act as a global database to save current configurations and changes the test made.
    It will help us track the current state of the system,
    and we will be used as part of cleanup fixtures.
    '''
    def __init__(self):
        self.currentPassword = DefaultConsts.DEFAULT_PASSWORD  # initial password


currentConfigurations = CurrentConfigurations()
logger = logging.getLogger(__name__)


@pytest.fixture(scope='module', autouse=True)
def dut_hostname(request):
    '''
    @summary: this function returns the hostname of the dut from the 'host-pattern'
    '''
    hostname = request.config.getoption('--host-pattern')
    logger.info("Hostname is {}".format(hostname))
    return hostname


@pytest.fixture(scope='module', autouse=True)
def is_feature_disabled(request):
    '''
    @summary: this fixture will be responsible for
    skipping the test if the feature is disabled
    '''
    feature_enabled = request.config.getoption("feature_enabled")
    if feature_enabled == 'False':
        pytest.skip("Feature is disabled, will not run the test")


@pytest.fixture(scope='module', autouse=True)
def prepare_system_for_first_boot(request, dut_hostname):
    '''
    @summary: will manufacture the dut device to the given image in the parameter --base_image_list,
    by installing the image given from ONIE. for detailed information read the documentation
    of the manufacture script.
    '''
    base_image = request.config.getoption('base_image_list')
    if not base_image:
        pytest.skip("base_image_list param is empty")
    manufacture(dut_hostname, base_image)


def change_password(dut_hostname, username, current_password, new_password):
    '''
    @summary: this function changes the password for the user given
    :param dut_hostname: host name of the dut
    :param dut_ip: device under test
    :param username: user name to change the password for
    :param current_password: current password
    :param new_password: new password
    '''
    logger.info("Changing password for username:{} to password: {}".format(username, new_password))
    try:
        # create a new ssh connection
        engine = pexpect.spawn(DefaultConsts.SSH_COMMAND.format(username) + dut_hostname, timeout=15)
        # because of race condition
        engine.delaybeforesend = 0.2
        engine.delayafterclose = 0.5
        engine.expect(DefaultConsts.PASSWORD_REGEX)
        engine.sendline(current_password + '\r')
        engine.expect(DefaultConsts.SONIC_PROMPT)
        engine.sendline('sudo usermod -p $(openssl passwd -1 {}) {}'.format(new_password, username) + '\r')
        engine.expect(DefaultConsts.SONIC_PROMPT)
        logger.info("Sleeping for {} secs to apply password change".format(DefaultConsts.APPLY_CONFIGURATIONS))
        time.sleep(DefaultConsts.APPLY_CONFIGURATIONS)
        engine.sendline('exit')
        engine.close()
    except Exception as err:
        logger.info('Got an exception while changing the password')
        logger.info(str(err))


@pytest.fixture(scope='function', autouse=True)
def restore_original_password(dut_hostname):
    '''
    @summary: this function will restore the original password to the default one to allow
    the next test to use default password to login to dut.
    '''
    yield
    logger.info("Sleep {} secs for system stabilization".format(DefaultConsts.STABILIZATION_TIME))
    time.sleep(DefaultConsts.STABILIZATION_TIME)
    logger.info("Restore original password")
    change_password(dut_hostname,
                    DefaultConsts.DEFAULT_USER,
                    currentConfigurations.currentPassword,
                    DefaultConsts.DEFAULT_PASSWORD)
