import allure
import logging
import pytest
import random

from tests.common.helpers.assertions import pytest_assert
from tests.common.reboot import reboot
from tests.common.mellanox_data import is_mellanox_device, SED_Change_Password_Mellanox

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer,
]


@pytest.fixture(scope='module')
def vendor_sed_class(duthosts, enum_rand_one_per_hwsku_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    if is_mellanox_device(duthost):
        return SED_Change_Password_Mellanox()
    else:
        pytest.skip("SED password change tests are only supported for Mellanox devices")


def test_change_sed_password(duthosts, enum_rand_one_per_hwsku_hostname, vendor_sed_class):
    """
    Test changing the SED password.
    Steps:
        1. Set a new SED password.
        2. Verify the password is working via sed util.
        3. Check that tpm primary and secondary bank have this password.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    min_len, max_len = vendor_sed_class.get_min_and_max_pass_len(duthost)
    new_sed_pass = vendor_sed_class.generate_pass_with_len(duthost, min_len=min_len, max_len=max_len)

    with allure.step(f"Setting new SED password: {new_sed_pass}"):
        vendor_sed_class.change_sed_pass_via_cli(duthost, new_sed_pass)

    with allure.step("Verifying SED password works via sed util"):
        pytest_assert(
            vendor_sed_class.verify_sed_pass_works(duthost, new_sed_pass),
            f"SED password verification failed for password: {new_sed_pass}"
        )
    with allure.step("Verifying TPM banks have the new password"):
        vendor_sed_class.verify_pass_saved(duthost, new_sed_pass)


def test_set_default_pass(duthosts, enum_rand_one_per_hwsku_hostname, localhost, vendor_sed_class):
    """
    Test setting the SED password to default.
    Steps:
        1. Set a SED with random password with config password command.
        2. Set a SED with default password with reset password command.
        3. Verify default password via sed.
        4. Check that TPM primary and secondary bank have the default SED password.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    min_len, max_len = vendor_sed_class.get_min_and_max_pass_len(duthost)
    rand_pass = vendor_sed_class.generate_pass_with_len(duthost, min_len=min_len, max_len=max_len)

    with allure.step(f"Setting SED password to: {rand_pass}"):
        vendor_sed_class.change_sed_pass_via_cli(duthost, rand_pass)
        pytest_assert(
            vendor_sed_class.verify_sed_pass_works(duthost, rand_pass),
            f"SED password verification failed for some password: {rand_pass}"
        )

    with allure.step("Resetting SED password"):
        default_pass = vendor_sed_class.reset_sed_pass_via_cli(duthost, localhost)
        logger.info("Password was set to default")

    with allure.step("Verifying default password"):
        pytest_assert(
            vendor_sed_class.verify_sed_pass_works(duthost, default_pass) and rand_pass != default_pass,
            "SED password verification failed for default password"
        )

    with allure.step("Verifying the default password saved properly"):
        vendor_sed_class.verify_pass_saved(duthost, default_pass)


def test_password_length_negative(duthosts, enum_rand_one_per_hwsku_hostname, vendor_sed_class):
    """
    Test changing the SED password to verify password length validation.
    Steps:
        1. Try to set a new SED password with a password length greater than the maximum length.
        2. Try to set a new SED password with a password length less than the minimum length.
        3. Verify that the password change fails.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    min_len, max_len = vendor_sed_class.get_min_and_max_pass_len(duthost)
    max_len_addition = 30
    min_len_thld = 3
    long_pass_offset = random.randint(1, max_len_addition)
    short_pass_offset = random.randint(1, min(min_len_thld, min_len - 1))

    long_pass = vendor_sed_class.generate_pass_with_len(
        duthost, min_len=max_len + 1, max_len=max_len + long_pass_offset)
    short_pass = vendor_sed_class.generate_pass_with_len(
        duthost, min_len=max(1, min_len - short_pass_offset), max_len=min_len - 1)

    with allure.step(f"Attempting to set password longer than maximum ({len(long_pass)} chars)"):
        result = vendor_sed_class.change_sed_pass_via_cli(duthost, long_pass, expect_success=False)
        pytest_assert(not result, f"Password change should have failed for long password ({len(long_pass)} chars)")

    with allure.step(f"Attempting to set password shorter than minimum ({len(short_pass)} chars)"):
        result = vendor_sed_class.change_sed_pass_via_cli(duthost, short_pass, expect_success=False)
        pytest_assert(not result, f"Password change should have failed for short password ({len(short_pass)} chars)")


def test_reboot_recovery_password(duthosts, enum_rand_one_per_hwsku_hostname, localhost, vendor_sed_class):
    """
    Test SED password recovery when primary TPM bank is corrupted.
    Steps:
        1. Set a new SED password.
        2. Change primary TPM bank to new negative password.
        3. Reboot the system.
        4. Check that tpm primary and secondary bank have old SED password.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    min_len, max_len = vendor_sed_class.get_min_and_max_pass_len(duthost)

    new_sed_pass = vendor_sed_class.generate_pass_with_len(
        duthost, min_len=min_len, max_len=max_len)
    neg_pass = vendor_sed_class.generate_pass_with_len(
        duthost, min_len=min_len, max_len=max_len, exclude_passwords=[new_sed_pass])
    primary_sed_tpm_bank = vendor_sed_class.get_primary_sed_tpm_bank()

    with allure.step(f"Setting new SED password: {new_sed_pass}"):
        vendor_sed_class.change_sed_pass_via_cli(duthost, new_sed_pass)
        vendor_sed_class.verify_pass_saved(duthost, new_sed_pass)

    with allure.step(f"Setting primary TPM bank to wrong password: {neg_pass}"):
        vendor_sed_class.set_sed_pass_in_tpm_bank(duthost, primary_sed_tpm_bank, neg_pass)
        primary_pass = vendor_sed_class.get_sed_pass_from_tpm_bank(duthost, primary_sed_tpm_bank)
        pytest_assert(
            primary_pass == neg_pass,
            f"Failed to set wrong password in primary bank. Got: {primary_pass}"
        )

    with allure.step("Rebooting the system"):
        reboot(duthost, localhost, reboot_type='cold', safe_reboot=False)

    with allure.step(f"Verifying TPM banks have recovered to the {new_sed_pass} password"):
        vendor_sed_class.verify_pass_saved(duthost, new_sed_pass)
