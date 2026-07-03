import pytest
import paramiko
import logging
from tests.common.constants import DEFAULT_SSH_CONNECT_PARAMS
from tests.common.utilities import get_image_type
from tests.common.fixtures.tacacs import get_aaa_sub_options_value

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology("any")
]

logger = logging.getLogger(__name__)


@pytest.fixture(autouse=True)
def disable_tacacs_for_test(duthost):
    """Temporarily disable TACACS+ so local password auth works.

    If AAA authentication is set to tacacs+, disable it to allow local user
    login. This follows the same pattern as test_ssh_limit.py (line 129-130).
    Also resets the admin password to the expected default to handle testbeds
    where the password was changed by deployment scripts.
    """
    default_username_password = DEFAULT_SSH_CONNECT_PARAMS[get_image_type(
        duthost=duthost)]
    expected_password = default_username_password["password"]
    expected_username = default_username_password["username"]

    # Capture the pre-test password so we can restore it in teardown
    hostvars = duthost.host.options['variable_manager']._hostvars[duthost.hostname]
    original_password = hostvars.get('ansible_password', hostvars.get('ansible_ssh_pass', 'password'))

    aaa_login_disabled = False
    aaa_login_value = get_aaa_sub_options_value(duthost, "authentication", "login")
    if aaa_login_value.startswith("tacacs+"):
        duthost.shell("sudo config aaa authentication login default")
        aaa_login_disabled = True

    # Ensure the expected default password is set
    duthost.shell("echo '{}:{}' | sudo chpasswd".format(expected_username, expected_password))

    yield

    # Restore pre-test password and TACACS state
    try:
        duthost.shell("echo '{}:{}' | sudo chpasswd".format(expected_username, original_password))
    finally:
        if aaa_login_disabled:
            duthost.shell("sudo config aaa authentication login tacacs+")


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
