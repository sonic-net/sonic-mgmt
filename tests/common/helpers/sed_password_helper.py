import logging
import random
import shlex
import string

import pytest

from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)

REDACTED = '<redacted>'
SED_CONFIG_PATH = '/etc/sonic/sed_config.conf'
SED_PW_UTILS = '/usr/local/bin/sed_pw_utils.sh'
SED_RECOVERY_SERVICE = 'sed-pw-tpm-recovery.service'
CLI_TIMEOUT = 120

# Sourcing sed_pw_utils.sh gives the TPM auth in $tpm_sed_auth and the same unseal flow the platform scripts use.
# The auth value is expanded inside the root shell, so it never reaches the sudo command line or the Ansible log.
TPM_SCRIPT_PREAMBLE = """
source %s || exit 10
get_tpm_sed_auth
unseal() {
    if [ -n "$tpm_sed_auth" ]; then
        tpm2_unseal -c "$1" -p "$tpm_sed_auth" 2>/dev/null
    else
        tpm2_unseal -c "$1" 2>/dev/null
    fi
}
""" % SED_PW_UTILS

VERIFY_DEFAULT_PASS_SCRIPT = """
default_pass=$(%(default_pass_cmd)s)
[ -n "$default_pass" ] || exit 11
[ "$(unseal %(bank_a)s)" = "$default_pass" ] || exit 12
[ "$(unseal %(bank_b)s)" = "$default_pass" ] || exit 13
sedutil-cli --listLockingRanges "$default_pass" %(disk)s > /dev/null 2>&1 || exit 14
exit 0
"""

SET_TPM_BANK_SCRIPT = """
set -e
work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT
cd "$work_dir"
password=%(password)s
tpm2_createprimary -C o --key-algorithm=rsa --key-context=prim.ctx > /dev/null 2>&1
if [ -n "$tpm_sed_auth" ]; then
    echo "$password" | tpm2_create -g sha256 -u seal.pub -r seal.priv -C prim.ctx -p "$tpm_sed_auth" \
        -i - > /dev/null 2>&1
else
    echo "$password" | tpm2_create -g sha256 -u seal.pub -r seal.priv -C prim.ctx -i - > /dev/null 2>&1
fi
tpm2_load -C prim.ctx -u seal.pub -r seal.priv -n seal.name -c seal.ctx > /dev/null 2>&1
if tpm2_getcap handles-persistent | grep -qi %(bank)s; then
    tpm2_evictcontrol -C o -c %(bank)s > /dev/null 2>&1
fi
tpm2_evictcontrol -C o -c seal.ctx %(bank)s > /dev/null 2>&1
"""

# Exit codes of the DUT-side default password check
DEFAULT_PASS_CHECK_ERRORS = {
    10: f"cannot source {SED_PW_UTILS}",
    11: "the default SED password cannot be read",
    12: "the primary TPM bank does not hold the default SED password",
    13: "the secondary TPM bank does not hold the default SED password",
    14: "the default SED password does not unlock the disk",
}

CHANGE_PASS_SCRIPT = """
import sys
import pexpect

password = {password!r}
child = pexpect.spawn("config sed change-password", encoding="utf-8", timeout={timeout})
try:
    for prompt in ("New SED password", "Repeat for confirmation"):
        child.expect(prompt)
        child.sendline(password)
    child.expect(pexpect.EOF)
except (pexpect.EOF, pexpect.TIMEOUT):
    print(child.before)
    sys.exit(2)
print(child.before)
sys.exit(0 if "completed successfully" in child.before else 1)
"""


def redact(text, *secrets):
    """Return text with every non-empty secret replaced, so it is safe to log or put in an assertion message."""
    text = text or ""
    for secret in secrets:
        if secret:
            text = text.replace(secret, REDACTED)
    return text


def run_as_root(duthost, script, module_ignore_errors=True):
    """
    Run a bash script as root in a single DUT-side command.
    Variables that the script expands stay inside the root shell. The output is not logged.
    """
    return duthost.shell(f"sudo bash -c {shlex.quote(script)}",
                         module_ignore_errors=module_ignore_errors, verbose=False)


class SED_Change_Password_General:
    """
    Base class for vendor-specific SED password change implementations.

    SED passwords, including the persistent default one, must never reach logs, assertion messages or Allure
    steps: every shell call that carries or returns a password uses verbose=False, and the default password
    is only handled by DUT-side scripts.
    """

    def __init__(self):
        self._sed_config = None
        self._pass_len_limits = None

    def get_sed_config(self, duthost):
        """
        Return the key=value pairs of /etc/sonic/sed_config.conf, the file the platform scripts read the TPM banks from.
        """
        if self._sed_config is None:
            result = duthost.shell(f"cat {SED_CONFIG_PATH}", module_ignore_errors=True)
            pytest_assert(result['rc'] == 0, f"Failed to read {SED_CONFIG_PATH}: {result['stderr']}")
            config = {}
            for line in result['stdout_lines']:
                key, sep, value = line.strip().partition('=')
                if sep:
                    config[key] = value.strip()
            for key in ('tpm_bank_a', 'tpm_bank_b'):
                pytest_assert(config.get(key), f"{key} is missing in {SED_CONFIG_PATH}")
            self._sed_config = config
        return self._sed_config

    def get_primary_sed_tpm_bank(self, duthost):
        return self.get_sed_config(duthost)['tpm_bank_a']

    def get_secondary_sed_tpm_bank(self, duthost):
        return self.get_sed_config(duthost)['tpm_bank_b']

    def get_min_and_max_pass_len(self, duthost):
        """
        Get the minimal and maximum password length from the platform SedMgmt object.
        """
        if self._pass_len_limits is None:
            cmd = ("sudo python3 -c 'from sonic_platform import platform; "
                   "sed_mgmt = platform.Platform().get_chassis().get_sed_mgmt(); "
                   "print(sed_mgmt.get_min_sed_password_len(), sed_mgmt.get_max_sed_password_len())'")
            result = duthost.shell(cmd, module_ignore_errors=True)
            pytest_assert(result['rc'] == 0, f"Failed to read the SED password length limits: {result['stderr']}")
            min_len, max_len = (int(value) for value in result['stdout'].split())
            self._pass_len_limits = (min_len, max_len)
        return self._pass_len_limits

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
        result = duthost.shell(cmd, module_ignore_errors=True, verbose=False)

        if result['rc'] == 0:
            logger.info("SED password verification successful")
            return True

        logger.warning(f"SED password verification failed: {redact(result['stderr'], password)}")
        return False

    def change_sed_pass_via_cli(self, duthost, new_pass, expect_success=True):
        """
        Change the SED password using the SONiC CLI command.
        Each password line is sent only after its prompt is shown.

        Args:
            duthost: DUT host object
            new_pass: The new SED password to set
        """
        logger.info(f"Changing SED password to a {len(new_pass)}-character password")
        script = CHANGE_PASS_SCRIPT.format(password=new_pass, timeout=CLI_TIMEOUT)
        result = duthost.shell(f"sudo python3 -c {shlex.quote(script)}", module_ignore_errors=True, verbose=False)
        success = result['rc'] == 0
        if expect_success:
            pytest_assert(success, f"Failed to change SED password: {redact(result['stdout'], new_pass)}")

        return success

    def reset_sed_pass_via_cli(self, duthost):
        """
        Reset the SED password to default using the SONiC CLI command.
        """
        logger.info("Resetting SED password to default")
        result = duthost.shell("sudo config sed reset-password & wait", module_ignore_errors=True)
        pytest_assert('error' not in result['stdout'].lower(), f"Failed to reset SED password: {result['stdout']}")

        self.verify_default_pass(duthost)

    def generate_pass_with_len(self, min_len, max_len, exclude_passwords=None):
        if exclude_passwords is None:
            exclude_passwords = []
        characters = string.ascii_letters + string.digits
        while True:
            rand_len = random.randint(min_len, max_len)
            new_pass = "".join(random.choices(characters, k=rand_len))
            if new_pass not in exclude_passwords:
                return new_pass

    def get_default_sed_pass_cmd(self):
        """
        Return a shell command that prints the default SED password on the DUT.
        It runs inside the TPM script, so it can use the unseal() function.
        """
        pytest.skip("TODO: Implement for each vendor")

    def verify_default_pass(self, duthost):
        """
        Verify on the DUT that both TPM banks hold the default SED password and that it unlocks the disk.
        The default password stays on the DUT, only the exit status comes back.
        On a mismatch, run the TPM recovery service to repair the banks, then fail.
        """
        script = TPM_SCRIPT_PREAMBLE + VERIFY_DEFAULT_PASS_SCRIPT % {
            'default_pass_cmd': self.get_default_sed_pass_cmd(),
            'bank_a': shlex.quote(self.get_primary_sed_tpm_bank(duthost)),
            'bank_b': shlex.quote(self.get_secondary_sed_tpm_bank(duthost)),
            'disk': shlex.quote(self.get_disk_name(duthost)),
        }
        result = run_as_root(duthost, script)
        if result['rc'] != 0:
            reason = DEFAULT_PASS_CHECK_ERRORS.get(result['rc'], f"the check exited with {result['rc']}")
            logger.warning(f"Default SED password check failed: {reason}. Running {SED_RECOVERY_SERVICE} to recover.")
            duthost.shell(f"sudo systemctl start {SED_RECOVERY_SERVICE}", module_ignore_errors=True)
            pytest_assert(False, f"Default SED password check failed: {reason}")

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

        primary_bank = self.get_primary_sed_tpm_bank(duthost)
        secondary_bank = self.get_secondary_sed_tpm_bank(duthost)

        if primary_bank not in tpm['stdout'] or secondary_bank not in tpm['stdout']:
            pytest.skip("Required TPM banks not configured")

    def get_sed_pass_from_tpm_bank(self, duthost, tpm_bank):
        """
        Retrieve the SED password from the specified TPM bank.
        """
        result = run_as_root(duthost, TPM_SCRIPT_PREAMBLE + f"unseal {tpm_bank}")
        if result['rc'] == 0:
            return result['stdout'].strip()
        logger.warning(f"Failed to get SED password from TPM bank {tpm_bank}")
        return None

    def is_pass_saved(self, duthost, expected_pass):
        """
        Return True if both TPM banks (primary and secondary) hold the expected password, False otherwise.
        A bank that cannot be unsealed counts as a mismatch.
        """
        logger.info("Checking that both TPM banks hold the expected SED password")
        saved = True
        for bank_role, tpm_bank in (("Primary", self.get_primary_sed_tpm_bank(duthost)),
                                    ("Secondary", self.get_secondary_sed_tpm_bank(duthost))):
            password = self.get_sed_pass_from_tpm_bank(duthost, tpm_bank)
            if password is None:
                logger.warning(f"{bank_role} TPM bank {tpm_bank} could not be unsealed")
                saved = False
            elif password != expected_pass:
                logger.warning(f"{bank_role} TPM bank {tpm_bank} does not hold the expected SED password")
                saved = False
        return saved

    def verify_pass_saved(self, duthost, expected_pass):
        """
        Assert that both TPM banks (primary and secondary) hold the expected password.
        """
        pytest_assert(
            self.is_pass_saved(duthost, expected_pass),
            "TPM primary/secondary bank does not hold the expected SED password, see the warnings above"
        )

    def set_sed_pass_in_tpm_bank(self, duthost, tpm_bank, password):
        """
        Store a new SED password in the specified TPM bank.
        The new sealed object is created and loaded first. The old object is then evicted and the new one
        persisted in the same DUT-side command, so a failure in between cannot leave the bank undefined.
        """
        logger.info(f"Setting SED password in TPM bank {tpm_bank}")
        script = TPM_SCRIPT_PREAMBLE + SET_TPM_BANK_SCRIPT % {
            'password': shlex.quote(password),
            'bank': shlex.quote(tpm_bank),
        }
        result = run_as_root(duthost, script)
        pytest_assert(result['rc'] == 0,
                      f"Failed to store a SED password in TPM bank {tpm_bank}: {redact(result['stderr'], password)}")

    def get_syslog_line_count(self, duthost):
        return int(duthost.shell("sudo wc -l < /var/log/syslog")['stdout'].strip())

    def syslog_has_message(self, duthost, message, start_line):
        """
        Return True if the message appears in /var/log/syslog after the line number start_line.
        """
        cmd = f"sudo tail -n +{start_line + 1} /var/log/syslog | grep -c -F {shlex.quote(message)}"
        result = duthost.shell(cmd, module_ignore_errors=True)
        return result['rc'] == 0 and int(result['stdout'].strip() or 0) > 0

    def is_recovery_service_done(self, duthost):
        """
        Return True once the oneshot TPM recovery service has run in this boot and exited with success.
        """
        result = duthost.shell(
            f"systemctl show {SED_RECOVERY_SERVICE} -p Result -p ExecMainExitTimestampMonotonic",
            module_ignore_errors=True)
        props = dict(line.split('=', 1) for line in result['stdout_lines'] if '=' in line)
        return props.get('Result') == 'success' and props.get('ExecMainExitTimestampMonotonic', '0') != '0'

    def recovery_service_logged(self, duthost, message):
        """
        Return True if the TPM recovery service logged the message in this boot.
        """
        cmd = f"sudo journalctl -b --no-pager | grep -c -F {shlex.quote(message)}"
        result = duthost.shell(cmd, module_ignore_errors=True)
        return result['rc'] == 0 and int(result['stdout'].strip() or 0) > 0


class SED_Change_Password_Mellanox(SED_Change_Password_General):
    DEFAULT_SED_TPM_BANK = '0x81010003'

    def get_default_sed_pass_cmd(self):
        return f"unseal {self.DEFAULT_SED_TPM_BANK}"

    def verify_sed_pass_change_feature_enabled(self, duthost):
        """Verify SED password change feature is enabled.
            1. Check SED-enabled NVME disk exists
            2. Check LockingEnabled=Y
            3. Check default TPM bank is configured
            Skips test if not.
        """
        logger.info("Check SED-enabled NVME disk exists")
        scan = duthost.shell("sedutil-cli --scan | grep -q '/dev/nvme'", module_ignore_errors=True)
        if scan['rc'] != 0:
            pytest.skip("No SED-enabled NVME disk found")

        super().verify_sed_pass_change_feature_enabled(duthost)

        logger.info("Check default TPM bank configured")
        tpm = duthost.shell("tpm2_getcap handles-persistent", module_ignore_errors=True)
        if tpm['rc'] != 0:
            pytest.skip("Failed to query TPM handles")

        if self.DEFAULT_SED_TPM_BANK not in tpm['stdout']:
            pytest.skip("Required default TPM bank not configured")
