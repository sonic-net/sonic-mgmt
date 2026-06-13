import pytest
import paramiko
import logging
from tests.common.constants import DEFAULT_SSH_CONNECT_PARAMS
from tests.common.utilities import get_image_type

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology("any")
]

logger = logging.getLogger(__name__)


@pytest.fixture(autouse=True)
def disable_tacacs_for_test(duthost):
    """Temporarily disable TACACS+ in PAM so local password auth works.

    TACACS may be configured in PAM (common-auth-sonic) even when 'show aaa'
    reports local auth. This fixture comments out pam_tacplus lines directly
    to ensure password auth falls through to pam_unix.
    It also resets the admin password to the expected default to handle
    testbeds where the password was changed by deployment scripts.
    """
    default_username_password = DEFAULT_SSH_CONNECT_PARAMS[get_image_type(
        duthost=duthost)]
    expected_password = default_username_password["password"]
    expected_username = default_username_password["username"]

    pam_file = "/etc/pam.d/common-auth-sonic"
    backup_file = pam_file + ".bak"
    has_tacacs = duthost.shell(
        "grep -q '^auth.*pam_tacplus' {} && echo yes || echo no".format(pam_file)
    )["stdout"].strip() == "yes"

    if has_tacacs:
        duthost.shell("sudo cp {} {}".format(pam_file, backup_file))
        duthost.shell("sudo sed -i 's/^auth.*pam_tacplus/#&/' {}".format(pam_file))

    # Ensure the expected default password is set
    duthost.shell("echo '{}:{}' | sudo chpasswd".format(expected_username, expected_password))

    yield

    # Restore original password so subsequent tests using TACACS creds still work
    duthost.shell("echo '{}:password' | sudo chpasswd".format(expected_username))

    if has_tacacs:
        duthost.shell("sudo cp {} {}".format(backup_file, pam_file))


def test_ssh_default_password(duthost):
    """verify the initial SSH password is always expected.

    Args:
        duthost: AnsibleHost instance for DUT
    """
    # Check SONiC image type and get default username and password to SSH connect
    default_username_password = DEFAULT_SSH_CONNECT_PARAMS[get_image_type(
        duthost=duthost)]

    logger.info("current login params:\tusername={}, password={}".format(default_username_password["username"],
                                                                         default_username_password["password"]))

    # Test SSH connect with expected username and password
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(duthost.mgmt_ip, username=default_username_password["username"],
                    password=default_username_password["password"], allow_agent=False,
                    look_for_keys=False)
    except paramiko.AuthenticationException:
        logger.info(
            "SSH connect failed. Make sure use the expected password according to the SONiC image.")
        raise
