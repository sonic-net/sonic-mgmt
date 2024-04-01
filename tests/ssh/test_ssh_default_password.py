import pytest
import paramiko
import logging

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology("any")
]

logger = logging.getLogger(__name__)


def test_ssh_default_password(duthost, creds):
    """verify the initial SSH password is always expected.

    Args:
        duthost: AnsibleHost instance for DUT
    """
    # Check SONiC image type and get default username and password to SSH connect
    sonic_username = creds['sonicadmin_user']

    sonic_admin_alt_password = duthost.host.options['variable_manager']._hostvars[duthost.hostname].get(
        "ansible_altpassword")
    sonic_admin_alt_passwords = creds["ansible_altpasswords"]

    default_username_password = {
        "username": sonic_username,
        "password": [creds['sonicadmin_password'], sonic_admin_alt_password] + sonic_admin_alt_passwords
    }

    # Test SSH connect with expected username and password
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    for password in default_username_password["password"]:
        try:
            ssh.connect(duthost.mgmt_ip, username=default_username_password["username"],
                        password=password, allow_agent=False,
                        look_for_keys=False)
            ssh.close()
            return
        except paramiko.AuthenticationException:
            continue

    logger.info(
        "SSH connect failed. Make sure use the expected password according to the SONiC image.")
    raise paramiko.AuthenticationException
