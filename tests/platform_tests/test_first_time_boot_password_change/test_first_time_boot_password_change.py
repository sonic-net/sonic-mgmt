'''
This test case checks default password change after initial reboot.
Due to new law passed in California, each default user must change their default password.

Important Note:
    Please run this test from sonic-mgmt/tests folder, otherwise it will fail.
'''
import pexpect
import time
import pytest
from tests.platform_tests.test_first_time_boot_password_change.default_consts import DefaultConsts
from tests.platform_tests.test_first_time_boot_password_change.conftest import logger, currentConfigurations
from tests.platform_tests.test_first_time_boot_password_change.manufacture import ping_till_down, ping_till_alive

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer,
    pytest.mark.skip_check_dut_health,
    pytest.mark.default_password_change_after_initial_boot
]


def test_default_password_change_after_first_boot(dut_hostname):
    '''
    @summary: in this test case we want to validate the mandatory request of
    password change after the first boot of the given image.
    According to a new law passed on the united states, default passwords
    such as: "admin", "root", "12345", etc. are no longer accepted.
    Test Flow:
        1.A message should appear after initial boot, requesting password change for default user.
        2.Password change, it will be tested by relogin to dut with new password and expecting no expire message again
        3. reboot and login again and expect no expiring message
    :param dut_hostname: name of device under test
    '''
    logger.info("------ STAGE 1 ------")
    logger.info("create ssh connection to device after initial boot")
    engine = pexpect.spawn(DefaultConsts.SSH_COMMAND.format(DefaultConsts.DEFAULT_USER) + dut_hostname)
    # to prevent race condition
    engine.delaybeforesend = 0.2
    engine.delayafterclose = 0.5
    # it should require password so password will be sent
    engine.expect(DefaultConsts.PASSWORD_REGEX)
    engine.sendline(DefaultConsts.DEFAULT_PASSWORD)
    # we should expect the expired password regex to appear
    logger.info("Expecting expired message printed")
    index = engine.expect([DefaultConsts.EXPIRED_PASSWORD_MSG, pexpect.TIMEOUT])
    if index != 0:
        engine.close()
        raise Exception("We did not catch the message of expired password after initial boot!\n"
                        "Consider this as a bug or a degradation")
    logger.info('Entering current password after the expired message appeared')
    engine.sendline(DefaultConsts.DEFAULT_PASSWORD + '\r')
    # suggest new password
    logger.info('Entering a new password, password used is {}'.format(DefaultConsts.NEW_PASSWORD))
    engine.expect(DefaultConsts.NEW_PASSWORD_REGEX)
    engine.sendline(DefaultConsts.NEW_PASSWORD + '\r')
    logger.info('Retyping the new password')
    engine.expect(DefaultConsts.RETYPE_PASSWORD_REGEX)
    engine.sendline(DefaultConsts.NEW_PASSWORD + '\r')
    engine.expect(DefaultConsts.DEFAULT_PROMPT)
    # update global configuration database, it will be used in cleanup later
    currentConfigurations.currentPassword = DefaultConsts.NEW_PASSWORD
    logger.info("Exit cli for the default user and re-enter again and expect no password expire message")
    # close the session
    engine.close()
    logger.info("Sleeping for {} secs to allow system update password".format(DefaultConsts.STABILIZATION_TIME))
    time.sleep(DefaultConsts.STABILIZATION_TIME)
    logger.info("create a new ssh connection to device")
    engine = pexpect.spawn(DefaultConsts.SSH_COMMAND.format(DefaultConsts.DEFAULT_USER) + dut_hostname)
    engine.delaybeforesend = 0.2
    engine.delayafterclose = 0.5
    # expect password
    engine.expect(DefaultConsts.PASSWORD_REGEX)
    # enter new password
    engine.sendline(DefaultConsts.NEW_PASSWORD + '\r')
    # we should not expect the expired password regex to appear again
    index = engine.expect([DefaultConsts.EXPIRED_PASSWORD_MSG] + DefaultConsts.DEFAULT_PROMPT)
    if index == 0:
        engine.close()
        raise Exception("We captured the expiring message again after updating a new password!\n")
    engine.close()

    logger.info("------ STAGE 2 ------")
    logger.info("Performing reboot to the switch, expecting no expiring password message after reboot")
    logger.info("create a new ssh connection to device")
    engine = pexpect.spawn(DefaultConsts.SSH_COMMAND.format(DefaultConsts.DEFAULT_USER) + dut_hostname)
    engine.delaybeforesend = 0.2
    engine.delayafterclose = 0.5
    # expect password
    engine.expect(DefaultConsts.PASSWORD_REGEX)
    # enter new password
    engine.sendline(DefaultConsts.NEW_PASSWORD + '\r')
    # we should get the default prompt
    engine.expect(DefaultConsts.DEFAULT_PROMPT)
    engine.sendline('sudo reboot')
    engine.expect('firmware is up to date')
    # pinging till down
    ping_till_down(dut_hostname)
    engine.close()
    # ping till alive
    ping_till_alive(dut_hostname)
    logger.info("Sleeping {} secs to after reboot".format(DefaultConsts.STABILIZATION_TIME))
    time.sleep(DefaultConsts.STABILIZATION_TIME)
    # connect to device
    logger.info("create a new ssh connection to device")
    engine = pexpect.spawn(DefaultConsts.SSH_COMMAND + dut_hostname)
    # expect password
    engine.expect(DefaultConsts.PASSWORD_REGEX)
    # enter new password
    engine.sendline(DefaultConsts.NEW_PASSWORD + '\r')
    # we should not expect the expired password regex to appear again
    index = engine.expect([DefaultConsts.EXPIRED_PASSWORD_MSG] + DefaultConsts.DEFAULT_PROMPT)
    if index == 0:
        engine.close()
        raise Exception("We captured the expiring message again after reboot\n")
    engine.close()
