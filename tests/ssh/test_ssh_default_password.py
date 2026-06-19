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
