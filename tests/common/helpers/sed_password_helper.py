import logging
import random
import string

import pytest

from tests.common.helpers.assertions import pytest_assert as assertion

logger = logging.getLogger(__name__)


class SED_Change_Password_General:
    """Base class for vendor-specific SED password change implementations."""

    def get_disk_name(self, duthost):
        """
        Return The disk device path
        """
        pytest.skip("TODO: Implement for each vendor")

    def verify_sed_pass_works(self, duthost, password):
        """
        Verify that the given SED password works by listing locking ranges.
        Returns True if password works, False otherwise.
        """
        disk_name = self.get_disk_name(duthost)

        logger.info(f"Verifying SED password works on disk {disk_name}")
        cmd = f"sudo sedutil-cli --listLockingRanges '{password}' '{disk_name}'"
        result = duthost.shell(cmd, module_ignore_errors=True)

        if result['rc'] == 0:
            logger.info("SED password verification successful")
            return True

        logger.warning(f"SED password verification failed: {result['stderr']}")
        return False

    def change_sed_pass_via_cli(self, duthost, new_pass, expect_success=True):
        """
        Change the SED password using the SONiC CLI command.

        Args:
            duthost: DUT host object
            new_pass: The new SED password to set
        """
        logger.info(f"Changing SED password to: {new_pass}")
        result = duthost.shell(f"sudo config sed change-password -p '{new_pass}'", module_ignore_errors=True)
        success = 'error' not in result['stdout'].lower()
        if expect_success:
            assertion(success, f"Failed to change SED password: {result['stdout']}")

        return success

    def reset_sed_pass_via_cli(self, duthost, localhost):
        """
        Reset the SED password to default using the SONiC CLI command.
        """
        logger.info("Resetting SED password to default")
        result = duthost.shell("sudo config sed reset-password & wait", module_ignore_errors=True)
        assertion('error' not in result['stdout'].lower(), f"Failed to reset SED password: {result['stdout']}")

        default_pass_primary = self.verify_default_pass(duthost, localhost, self.verify_sed_pass_works)

        return default_pass_primary

    def generate_pass_with_len(self, duthost, min_len, max_len, exclude_passwords=None):
        if exclude_passwords is None:
            exclude_passwords = []
        characters = string.ascii_letters + string.digits
        while True:
            rand_len = random.randint(min_len, max_len)
            new_pass = "".join(random.choices(characters, k=rand_len))
            if new_pass not in exclude_passwords:
                return new_pass

    def verify_default_pass(self, duthost, localhost, verify_sed_pass_method=None):
        """
        Verify that the default SED password is set correctly.
        """
        pytest.skip("TODO: Implement for each vendor")

    def get_min_and_max_pass_len(self, duthost):
        """
        Get the minimal and maximum password length for the device.
        """
        pytest.skip("TODO: Implement for each vendor")

    def generate_pass_with_leng(self, duthost, min_len, max_len):
        pytest.skip("TODO: Implement for each vendor")

    def verify_sed_pass_change_feature_enabled(self, duthost):
        """Verify SED password change feature is enabled on the device."""
        pytest.skip("TODO: Implement for each vendor")

    def verify_pass_saved(self, duthost, expected_pass):
        pytest.skip("TODO: Implement for each vendor")
