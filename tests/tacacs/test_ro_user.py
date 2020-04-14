import pytest

pytestmark = [
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer,
]

def test_ro_user(testbed_devices, duthost, creds, setup_tacacs):

    localhost = localhost = testbed_devices['localhost']
    dutip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']
    res = localhost.shell("sshpass -p {} ssh "\
                          "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "\
                          "{}@{} cat /etc/passwd".format(
            creds['tacacs_ro_user_passwd'], creds['tacacs_ro_user'], dutip))

    for l in res['stdout_lines']:
        fds = l.split(':')
        if fds[0] == "test":
            assert fds[4] == "remote_user"
