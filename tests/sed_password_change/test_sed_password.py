import allure
import logging
import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.sed_password_helper import SED_RECOVERY_SERVICE
from tests.common.reboot import reboot
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
]

PASS_LENGTH_ERROR = "SED password length is not valid: {}."
RECOVERY_BANK_A_MESSAGE = "Stored PW from Bank 2 to Bank 1 succeed"
RECOVERY_SERVICE_TIMEOUT = 300


@pytest.mark.parametrize("pass_len_type", ["min", "max", "random"])
def test_change_sed_password(duthosts, enum_rand_one_per_hwsku_hostname, vendor_sed_class, pass_len_type):
    """
    Test changing the SED password.
    Steps:
        1. Set a new SED password with the minimal, the maximal or a random valid length.
        2. Verify the password is working via sed util.
        3. Check that tpm primary and secondary bank have this password.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    min_len, max_len = vendor_sed_class.get_min_and_max_pass_len(duthost)
    if pass_len_type == "min":
        max_len = min_len
    elif pass_len_type == "max":
        min_len = max_len
    new_sed_pass = vendor_sed_class.generate_pass_with_len(min_len=min_len, max_len=max_len)

    with allure.step(f"Setting new {len(new_sed_pass)}-character SED password"):
        vendor_sed_class.change_sed_pass_via_cli(duthost, new_sed_pass)

    with allure.step("Verifying SED password works via sed util"):
        pytest_assert(
            vendor_sed_class.verify_sed_pass_works(duthost, new_sed_pass),
            "SED password verification failed for the new password"
        )
    with allure.step("Verifying TPM banks have the new password"):
        vendor_sed_class.verify_pass_saved(duthost, new_sed_pass)


def test_set_default_pass(duthosts, enum_rand_one_per_hwsku_hostname, vendor_sed_class):
    """
    Test setting the SED password to default.
    Steps:
        1. Set a SED with random password with config password command.
        2. Set a SED with default password with reset password command.
        3. Verify on the DUT that the default password unlocks the disk and both TPM banks hold it.
        4. Verify the random password no longer works.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    min_len, max_len = vendor_sed_class.get_min_and_max_pass_len(duthost)
    rand_pass = vendor_sed_class.generate_pass_with_len(min_len=min_len, max_len=max_len)

    with allure.step(f"Setting a random {len(rand_pass)}-character SED password"):
        vendor_sed_class.change_sed_pass_via_cli(duthost, rand_pass)
        pytest_assert(
            vendor_sed_class.verify_sed_pass_works(duthost, rand_pass),
            "SED password verification failed for the random password"
        )

    with allure.step("Resetting SED password and verifying the default password"):
        vendor_sed_class.reset_sed_pass_via_cli(duthost)

    with allure.step("Verifying the random password no longer works"):
        pytest_assert(
            not vendor_sed_class.verify_sed_pass_works(duthost, rand_pass),
            "The random SED password still works after the reset to default"
        )


def test_password_length_negative(duthosts, enum_rand_one_per_hwsku_hostname, vendor_sed_class, loganalyzer):
    """
    Test changing the SED password to verify password length validation.
    Steps:
        1. Try to set a new SED password one character longer than the maximum length.
        2. Try to set a new SED password one character shorter than the minimum length.
        3. Verify that each change fails with the length error in syslog,
           and that the default password still works and is in both TPM banks.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    if loganalyzer:
        loganalyzer[duthost.hostname].ignore_regex.append(".*SED password length is not valid.*")
    min_len, max_len = vendor_sed_class.get_min_and_max_pass_len(duthost)

    for desc, pass_len in (("longer than maximum", max_len + 1), ("shorter than minimum", min_len - 1)):
        invalid_pass = vendor_sed_class.generate_pass_with_len(min_len=pass_len, max_len=pass_len)

        with allure.step(f"Attempting to set password {desc} ({pass_len} chars)"):
            syslog_start = vendor_sed_class.get_syslog_line_count(duthost)
            result = vendor_sed_class.change_sed_pass_via_cli(duthost, invalid_pass, expect_success=False)
            pytest_assert(not result, f"Password change should have failed for a {pass_len}-character password")
            pytest_assert(
                wait_until(10, 1, 0, vendor_sed_class.syslog_has_message,
                           duthost, PASS_LENGTH_ERROR.format(pass_len), syslog_start),
                f"Syslog has no length error for the {pass_len}-character password"
            )

        with allure.step("Verifying the default password is unchanged"):
            vendor_sed_class.verify_default_pass(duthost)


@pytest.mark.disable_loganalyzer
def test_reboot_recovery_password(duthosts, enum_rand_one_per_hwsku_hostname, localhost, vendor_sed_class):
    """
    Test SED password recovery when primary TPM bank is corrupted.
    Steps:
        1. Set a new SED password.
        2. Change primary TPM bank to new negative password.
        3. Reboot the system.
        4. Check that the recovery service repaired the primary bank.
        5. Check that tpm primary and secondary bank have the new SED password and it unlocks the disk.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    min_len, max_len = vendor_sed_class.get_min_and_max_pass_len(duthost)

    new_sed_pass = vendor_sed_class.generate_pass_with_len(
        min_len=min_len, max_len=max_len)
    neg_pass = vendor_sed_class.generate_pass_with_len(
        min_len=min_len, max_len=max_len, exclude_passwords=[new_sed_pass])
    primary_sed_tpm_bank = vendor_sed_class.get_primary_sed_tpm_bank(duthost)

    with allure.step(f"Setting new {len(new_sed_pass)}-character SED password"):
        vendor_sed_class.change_sed_pass_via_cli(duthost, new_sed_pass)
        vendor_sed_class.verify_pass_saved(duthost, new_sed_pass)

    reboot_started = False
    try:
        with allure.step(f"Setting primary TPM bank {primary_sed_tpm_bank} to a wrong password"):
            vendor_sed_class.set_sed_pass_in_tpm_bank(duthost, primary_sed_tpm_bank, neg_pass)
            primary_pass = vendor_sed_class.get_sed_pass_from_tpm_bank(duthost, primary_sed_tpm_bank)
            pytest_assert(
                primary_pass == neg_pass,
                f"Primary TPM bank {primary_sed_tpm_bank} does not hold the wrong password that was just written"
            )

        with allure.step("Rebooting the system"):
            reboot_started = True
            reboot(duthost, localhost, reboot_type='cold', safe_reboot=True)
    finally:
        if not reboot_started:
            logger.info(f"Restoring primary TPM bank {primary_sed_tpm_bank} from the secondary bank value")
            vendor_sed_class.set_sed_pass_in_tpm_bank(duthost, primary_sed_tpm_bank, new_sed_pass)

    with allure.step(f"Verifying {SED_RECOVERY_SERVICE} repaired the primary TPM bank"):
        pytest_assert(
            wait_until(RECOVERY_SERVICE_TIMEOUT, 10, 0, vendor_sed_class.is_recovery_service_done, duthost),
            f"{SED_RECOVERY_SERVICE} did not finish with Result=success"
        )
        pytest_assert(
            vendor_sed_class.recovery_service_logged(duthost, RECOVERY_BANK_A_MESSAGE),
            f"{SED_RECOVERY_SERVICE} did not log '{RECOVERY_BANK_A_MESSAGE}'"
        )

    with allure.step("Verifying TPM banks have recovered to the new SED password"):
        vendor_sed_class.verify_pass_saved(duthost, new_sed_pass)

    with allure.step("Verifying the new SED password still unlocks the disk after the reboot"):
        pytest_assert(
            vendor_sed_class.verify_sed_pass_works(duthost, new_sed_pass),
            "SED password verification failed for the new password after the reboot"
        )


def test_recovery_service_configured(duthosts, enum_rand_one_per_hwsku_hostname, vendor_sed_class):
    """
    Test that the TPM recovery service is installed and enabled, and that its config points at existing TPM banks.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    with allure.step(f"Verifying {SED_RECOVERY_SERVICE} is enabled"):
        enabled = duthost.shell(f"systemctl is-enabled {SED_RECOVERY_SERVICE}", module_ignore_errors=True)
        pytest_assert(enabled['stdout'].strip() == "enabled",
                      f"{SED_RECOVERY_SERVICE} is not enabled: {enabled['stdout']} {enabled['stderr']}")

    with allure.step("Verifying the TPM banks in the SED config exist"):
        handles = duthost.shell("tpm2_getcap handles-persistent")['stdout'].lower()
        for tpm_bank in (vendor_sed_class.get_primary_sed_tpm_bank(duthost),
                         vendor_sed_class.get_secondary_sed_tpm_bank(duthost)):
            pytest_assert(tpm_bank.lower() in handles, f"TPM bank {tpm_bank} from the SED config is not defined")
