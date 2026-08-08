import logging
import random
import string

import pytest

from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)

TIME_INSERT_SED_PASSWORD = 2


class SED_Change_Password_General:
    """Base class for vendor-specific SED password change implementations."""

    def get_disk_name(self, duthost):
        """
        Return The disk device path
        """
        result = duthost.shell("sudo sedutil-cli --scan", module_ignore_errors=True)
        pytest_assert(result['rc'] == 0, f"Failed to scan for SED disks: {result['stderr']}")

        output = result['stdout']
        if '/dev/' in output:
            # Find /dev/xxx pattern
            start = output.find("/dev/")
            if start != -1:
                end = output.find(" ", start)
                if end != -1:
                    return output[start:end]
                return output[start:].split()[0]

        pytest_assert(False, "Cannot find SED-enabled disk device")

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
        cli_cmd = 'sudo config sed change-password'
        pass_change_cmd = (
            f"( sleep {TIME_INSERT_SED_PASSWORD}; printf '%s\\n' {new_pass}; "
            f"sleep {TIME_INSERT_SED_PASSWORD}; printf '%s\\n' {new_pass} ) | "
            f"script -q -c '{cli_cmd}' /dev/null"
        )
        result = duthost.shell(pass_change_cmd, module_ignore_errors=True)
        output = ((result.get("stdout") or "") + (result.get("stderr") or "")).lower()
        success = result.get("rc") == 0 and "error" not in output
        if expect_success:
            pytest_assert(success, f"Failed to change SED password: {result.get('stdout', '')}")

        return success

    def reset_sed_pass_via_cli(self, duthost, localhost):
        """
        Reset the SED password to default using the SONiC CLI command.
        """
        logger.info("Resetting SED password to default")
        result = duthost.shell("sudo config sed reset-password & wait", module_ignore_errors=True)
        pytest_assert('error' not in result['stdout'].lower(), f"Failed to reset SED password: {result['stdout']}")

        default_pass_primary = self.verify_default_pass(duthost, localhost)

        return default_pass_primary

    def generate_pass_with_len(self, min_len, max_len, exclude_passwords=None):
        if exclude_passwords is None:
            exclude_passwords = []
        characters = string.ascii_letters + string.digits
        while True:
            rand_len = random.randint(min_len, max_len)
            new_pass = "".join(random.choices(characters, k=rand_len))
            if new_pass not in exclude_passwords:
                return new_pass

    def verify_default_pass(self, duthost, localhost):
        """
        Verify that the default SED password is set correctly.
        """
        real_default_pass = self.get_default_sed_pass(duthost)

        if (not self.verify_pass_saved(duthost, real_default_pass) or
                not self.verify_sed_pass_works(duthost, real_default_pass)):
            logger.warning(
                "TPM banks/SED password mismatch with the default SED password. "
                "Attempting cold reboot to recover."
            )
            from tests.common.reboot import reboot
            reboot(duthost, localhost, reboot_type='cold', safe_reboot=True)
            raise Exception("TPM banks/SED password mismatch with the default SED password.")

        return real_default_pass

    def verify_sed_pass_change_feature_enabled(self, duthost):
        """
        Verify SED password change feature is enabled on the device by checking:
        1. LockingEnabled=Y
        2. Both TPM banks configured
        """
        logger.info("Check LockingEnabled=Y")
        disk = self.get_disk_name(duthost)
        locking = duthost.shell(f"sedutil-cli --query {disk} | grep 'LockingEnabled = Y'",
                                module_ignore_errors=True)
        if locking['rc'] != 0:
            pytest.skip("SED LockingEnabled is not Y")

        logger.info("Check both TPM banks configured")
        tpm = duthost.shell("tpm2_getcap handles-persistent", module_ignore_errors=True)
        if tpm['rc'] != 0:
            pytest.skip("Failed to query TPM handles")

        primary_bank = self.get_primary_sed_tpm_bank()
        secondary_bank = self.get_secondary_sed_tpm_bank()

        if primary_bank not in tpm['stdout'] or secondary_bank not in tpm['stdout']:
            pytest.skip("Required TPM banks not configured")

    def get_sed_pass_from_tpm_bank(self, duthost, tpm_bank, tpm_auth_pass=None):
        """
        Retrieve the SED password from the specified TPM bank.
        """
        tpm_auth_arg = f'-p "{tpm_auth_pass}"' if tpm_auth_pass else ""
        result = duthost.shell(
            f"sudo tpm2_unseal -c '{tpm_bank}' {tpm_auth_arg}",
            module_ignore_errors=True
        )
        if result['rc'] == 0:
            return result['stdout'].strip()
        logger.warning(
            f"Failed to get SED password from TPM bank {tpm_bank}: {result['stderr']}"
        )
        return None

    def verify_pass_saved(self, duthost, expected_pass):
        """
        Verify that both TPM banks (primary and secondary) have the expected password.
        """
        logger.info(f"Verifying TPM banks have password: {expected_pass}")

        password_primary = self.get_sed_pass_from_tpm_bank(duthost, self.get_primary_sed_tpm_bank())
        assert password_primary == expected_pass, (
            f"Primary TPM bank password mismatch. Expected: '{expected_pass}', "
            f"Got: '{password_primary}'"
        )

        password_secondary = self.get_sed_pass_from_tpm_bank(
            duthost, self.get_secondary_sed_tpm_bank()
        )
        assert password_secondary == expected_pass, (
            f"Secondary TPM bank password mismatch. Expected: '{expected_pass}', "
            f"Got: '{password_secondary}'"
        )
        return True

    def set_sed_pass_in_tpm_bank(self, duthost, tpm_bank, password, tpm_auth_pass=None):
        """
        Store a new SED password in the specified TPM bank.
        """
        tpm_auth_arg = f'-p "{tpm_auth_pass}"' if tpm_auth_pass else ""
        logger.info(f"Setting SED password in TPM bank {tpm_bank}")
        tpm_create_cmd = (
            f'echo "{password}" | sudo tpm2_create -g sha256 -u seal.pub -r seal.priv '
            f'-C prim.ctx {tpm_auth_arg} -i - > /dev/null 2>&1'
        )
        commands = [
            'sudo rm -f seal.* prim.ctx',
            f'sudo tpm2_evictcontrol -C o -c "{tpm_bank}" > /dev/null 2>&1',
            'sudo tpm2_createprimary -C o --key-algorithm=rsa --key-context=prim.ctx > /dev/null 2>&1',
            tpm_create_cmd,
            'sudo tpm2_load -C prim.ctx -u seal.pub -r seal.priv -n seal.name -c seal.ctx',
            f'sudo tpm2_evictcontrol -C o -c seal.ctx "{tpm_bank}"',
            'sudo rm -f seal.* prim.ctx',
        ]
        for command in commands:
            result = duthost.shell(command, module_ignore_errors=True)
            pytest_assert(
                result['rc'] == 0,
                f"Failed to execute command: {command}\nError: {result['stderr']}"
            )

    def get_default_sed_pass(self, duthost):
        """
        Get the default SED password from the device.
        """
        pytest.skip("TODO: Implement for each vendor")

    def get_primary_sed_tpm_bank(self):
        pytest.skip("TODO: Implement for each vendor")

    def get_secondary_sed_tpm_bank(self):
        pytest.skip("TODO: Implement for each vendor")

    def get_min_and_max_pass_len(self, duthost):
        """
        Get the minimal and maximum password length for the device.
        """
        pytest.skip("TODO: Implement for each vendor")
