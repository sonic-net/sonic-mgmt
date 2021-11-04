import pytest
import crypt

from .test_ro_user import ssh_remote_run
from .utils import check_output

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any'),
    pytest.mark.device_type('vs')
]


def test_rw_user(localhost, duthosts, enum_rand_one_per_hwsku_hostname, creds_all_duts, check_tacacs):
    """test tacacs rw user
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    dutip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']
    res = ssh_remote_run(localhost, dutip, creds_all_duts[duthost]['tacacs_rw_user'],
                         creds_all_duts[duthost]['tacacs_rw_user_passwd'], "cat /etc/passwd")

    check_output(res, 'testadmin', 'remote_user_su')

def test_rw_user_ipv6(localhost, duthosts, enum_rand_one_per_hwsku_hostname, creds_all_duts, check_tacacs_v6):
    """test tacacs rw user
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    dutip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']
    res = ssh_remote_run(localhost, dutip, creds_all_duts[duthost]['tacacs_rw_user'],
                         creds_all_duts[duthost]['tacacs_rw_user_passwd'], "cat /etc/passwd")

    check_output(res, 'testadmin', 'remote_user_su')

def test_backward_compatibility_enable_authorization_rw(localhost, duthosts, enum_rand_one_per_hwsku_hostname, creds_all_duts,ptfhost, check_tacacs, check_tacacs_v6):
    # Enable per-command authorization.
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    duthost.shell("sudo config aaa authorization local")

    # Test all current UT.
    test_rw_user(localhost, duthosts, enum_rand_one_per_hwsku_hostname, creds_all_duts, check_tacacs)
    test_rw_user_ipv6(localhost, duthosts, enum_rand_one_per_hwsku_hostname, creds_all_duts, check_tacacs_v6)