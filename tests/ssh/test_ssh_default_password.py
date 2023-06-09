import pytest
import paramiko
import logging

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology("any")
]

logger = logging.getLogger(__name__)

DEFAULT_LOGIN_PARAMS_DICT = {
    "public": {"username": "admin",
               "password": "YourPaSsWoRd"},
    "nokia": {"username": "admin",
              "password": "123"}
}


def test_ssh_default_password(duthost):
    """verify the initial SSH password is always expected.

    Args:
        duthost: AnsibleHost instance for DUT
    """

    # 1. define the default params in global value `DEFAULT_LOGIN_PARAMS_DICT`
    # and the specific approach to get the image type in `get_image_type()`

    # 2. check SONiC version and get default username and password
    default_username_password = DEFAULT_LOGIN_PARAMS_DICT[get_image_type(duthost=duthost)]

    logger.info("current login params:\tusername={}, password={}".format(default_username_password["username"],
                                                                         default_username_password["password"]))

    # 3. re-connect SONiC via SSH with expected password
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(duthost.mgmt_ip, username=default_username_password["username"],
                    password=default_username_password["password"], allow_agent=False,
                    look_for_keys=False)
    except paramiko.AuthenticationException:
        logger.info("SSH connect failed. Make sure use the expected password according to the SONiC image.")
        raise


def get_image_type(duthost):
    """get the SONiC image type

    It might be public/microsoft/...or any other type.
    Different vendors can define their different types by checking the specific information from the build image.

    Args:
        duthost: AnsibleHost instance for DUT

    Returns: image type. Str. It should be the right key in DEFAULT_LOGIN_PARAMS_DICT.

    """

    return "nokia"
