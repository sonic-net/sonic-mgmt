import pytest
import paramiko
import logging

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology("any")
]

logger = logging.getLogger(__name__)

DEFAULT_USERNAME = "admin"
DEFAULT_PASSWORD_PUBLIC = "YourPaSsWoRd"
DEFAULT_PASSWORD_NON_PUBLIC = "password"


def test_ssh_default_password(duthost):
    """verify the initial SSH password is always expected.

    When connecting SONiC via SSH, there are two kind of passwords:
    1. if SONiC was built from public image, SSH password is YourPaSsWoRd.
    2. if SONiC was built from non-public image, SSH password is password.

    Args:
        duthost: AnsibleHost instance for DUT
    """

    # set default value with public

    default_password = DEFAULT_PASSWORD_PUBLIC

    # 1. check SONiC version
    # If SONiC was built from non-public image, there should be information which has the key word 'sonic-dri' in motd
    res = duthost.shell("cat /etc/motd | grep sonic-dri",module_ignore_errors=True)["stdout"]

    if res:
        default_password = DEFAULT_PASSWORD_NON_PUBLIC

    logger.info("current login params:\tusername={}, password={}".format(DEFAULT_USERNAME, default_password))

    # 2. re-connect SONiC via SSH with expected password
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(duthost.mgmt_ip, username=DEFAULT_USERNAME, password=default_password, allow_agent=False,
                    look_for_keys=False)
    except paramiko.AuthenticationException:
        logger.info("SSH connect failed. Make sure use the expected password according to the SONiC image.")
        raise
    except Exception:
        raise
