import pytest
import crypt

from .test_ro_user import ssh_remote_run

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any'),
    pytest.mark.device_type('vs')
]


def test_rw_user(localhost, duthosts, rand_one_dut_hostname, creds, test_tacacs):
    """test tacacs rw user
    """
    duthost = duthosts[rand_one_dut_hostname]
    dutip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']
    res = ssh_remote_run(localhost, dutip, creds['tacacs_rw_user'], creds['tacacs_rw_user_passwd'], "cat /etc/passwd")

    for l in res['stdout_lines']:
        fds = l.split(':')
        if fds[0] == "testadmin":
            assert fds[4] == "remote_user_su"

def test_rw_user_ipv6(localhost, duthosts, rand_one_dut_hostname, creds, test_tacacs_v6):
    """test tacacs rw user
    """
    duthost = duthosts[rand_one_dut_hostname]
    dutip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']
    res = ssh_remote_run(localhost, dutip, creds['tacacs_rw_user'], creds['tacacs_rw_user_passwd'], "cat /etc/passwd")

    for l in res['stdout_lines']:
        fds = l.split(':')
        if fds[0] == "testadmin":
            assert fds[4] == "remote_user_su"
