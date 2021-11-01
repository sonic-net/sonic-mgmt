import pytest
import crypt

from .test_ro_user import ssh_remote_run
from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any'),
    pytest.mark.device_type('vs')
]


def check_command_output(res, exp_val, cmd_failed):
    pytest_assert(res['failed'] == cmd_failed)
    pytest_assert(len(res['stderr_lines']) == 0)
    content_exist = False
    for l in res['stdout_lines']:
        logger.warning(l)
        if exp_val in l:
            content_exist = True
            break
    pytest_assert(content_exist)

def check_command_error(res, exp_val):
    pytest_assert(res['failed'] == True)
    content_exist = False
    for l in res['stderr_lines']:
        if exp_val in l:
            content_exist = True
            break
    pytest_assert(content_exist)

def test_authorization_tacacs_only(localhost, duthosts, enum_rand_one_per_hwsku_hostname, creds_all_duts, check_tacacs):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    duthost.shell("sudo config aaa authorization tacacs+")
    dutip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']
    
    """
        Verify TACACS+ user run command in server side whitelist:
            If command have local permission, user can run command.
    """
    res = ssh_remote_run(localhost, dutip, creds_all_duts[duthost]['tacacs_authorization_user'],
                         creds_all_duts[duthost]['tacacs_authorization_user_passwd'], "show aaa")

    check_command_output(res, 'AAA authentication', False)

    """
        Verify TACACS+ user run command in server side whitelist:
            If command not have local permission, user can't run command.
    """
    res = ssh_remote_run(localhost, dutip, creds_all_duts[duthost]['tacacs_authorization_user'],
                         creds_all_duts[duthost]['tacacs_authorization_user_passwd'], "config aaa")

    check_command_error(res, 'Root privileges are required for this operation')

    """
        Verify TACACS+ user can't run command not in server side whitelist.
    """
    res = ssh_remote_run(localhost, dutip, creds_all_duts[duthost]['tacacs_authorization_user'],
                         creds_all_duts[duthost]['tacacs_authorization_user_passwd'], "cat /etc/passwd")

    check_command_output(res, '/usr/bin/cat authorize failed by TACACS+ with given arguments, not executing', True)

    """
        Verify Local user can't login.
    """
    res = ssh_remote_run(localhost, dutip, creds_all_duts[duthost]['tacacs_local_user'],
                         creds_all_duts[duthost]['tacacs_local_user_passwd'], "cat /etc/passwd")

    check_command_error(res, 'Permission denied, please try again.')
