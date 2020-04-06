import pytest
import crypt

pytestmark = [
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer
]

def test_rw_user(duthost, creds, setup_tacacs):
    """test tacacs rw user
    """

    duthost.host.options['variable_manager'].extra_vars.update(
        {'ansible_user':creds['tacacs_rw_user'], 'ansible_password':creds['tacacs_rw_user_passwd']})

    res = duthost.shell("cat /etc/passwd")
    
    for l in res['stdout_lines']:
        fds = l.split(':')
        if fds[0] == "testadmin":
            assert fds[4] == "remote_user_su"
