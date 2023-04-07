import pytest
import pexpect


def assert_expect_text(client, text, target_line, timeout_sec=0.1):
    index = client.expect_exact([text, pexpect.EOF, pexpect.TIMEOUT], timeout=timeout_sec)
    if index == 1:
        pytest.fail("Encounter early EOF during testing line {}".format(target_line))
    elif index == 2:
        pytest.fail("Not able to get expected text in {}s".format(timeout_sec))


def create_ssh_client(ip, user, pwd):
    # Set 'echo=False' is very important since pexpect will echo back all inputs to buffer by default
    client = pexpect.spawn('ssh {}@{} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null'.format(user, ip),
                           echo=False)
    client.expect('[Pp]assword:')
    client.sendline(pwd)
    return client


def ensure_console_session_up(client, line):
    client.expect_exact('Successful connection to line [{}]'.format(line))
    client.expect_exact('Press ^A ^X to disconnect')
