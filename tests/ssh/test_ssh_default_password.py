import pytest
import logging
from tests.common.utilities import get_default_dut_username_and_passwords, duthost_ssh

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology("any")
]

logger = logging.getLogger(__name__)


def test_ssh_default_password(duthost, creds):
    """
        verify the initial SSH password is always expected.
    """
    # Get default username and passwords for the duthost
    default_username_and_passwords = get_default_dut_username_and_passwords(duthost, creds)

    # Test ssh connection
    duthost_ssh(duthost=duthost, sonic_username=default_username_and_passwords["username"],
                sonic_passwords=default_username_and_passwords["passwords"], sonic_ip=duthost.mgmt_ip)
