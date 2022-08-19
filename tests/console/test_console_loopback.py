import pytest
import pexpect
import string


from tests.common.helpers.assertions import pytest_assert

pytestmark = [
    pytest.mark.topology('any')
]

@pytest.mark.parametrize("target_line", [str(i) for i in range(1, 17)])
def test_console_loopback_echo(duthost, creds, target_line):
    """
    Test data transfer are working as expect.
    Verify data can go out through the console switch and come back through the console switch
    """
    dutip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']
    dutuser = creds['sonicadmin_user']
    dutpass = creds['sonicadmin_password']

    console_facts = duthost.console_facts()['ansible_facts']['console_facts']

    packet_size  = 64
    delay_factor = 2.0

    # Estimate a reasonable data transfer time based on configured baud rate
    if target_line not in console_facts['lines']:
        pytest.skip("Target line {} has not configured".format(target_line))

    timeout_sec = (packet_size << 3) * delay_factor / int(console_facts['lines'][target_line]['baud_rate'])
    ressh_user  = "{}:{}".format(dutuser, target_line)

    try:
        client = create_ssh_client(dutip, ressh_user, dutpass)
        ensure_console_session_up(client, target_line)

        # Generate a random strings to send
        text = generate_random_string(packet_size)
        client.sendline(text)
        assert_expect_text(client, text, target_line, timeout_sec)
    except Exception as e:
        pytest.fail("Not able to communicate DUT via reverse SSH: {}".format(e))

@pytest.mark.parametrize("src_line,dst_line", [('17', '19'),
                                               ('18', '20'),
                                               ('21', '27'),
                                               ('22', '28'),
                                               ('23', '25'),
                                               ('24', '26'),
                                               ('29', '35'),
                                               ('30', '36'),
                                               ('31', '33'),
                                               ('32', '34')])
def test_console_loopback_pingpong(duthost, creds, src_line, dst_line):
    """
    Test data transfer are working as expect.
    Verify data can go out through the console switch and come back through the console switch
    """
    dutip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']
    dutuser = creds['sonicadmin_user']
    dutpass = creds['sonicadmin_password']

    console_facts = duthost.console_facts()['ansible_facts']['console_facts']

    if src_line not in console_facts['lines']:
        pytest.skip("Source line {} has not configured".format(src_line))
    if dst_line not in console_facts['lines']:
        pytest.skip("Destination line {} has not configured".format(dst_line))

    try:
        sender   = create_ssh_client(dutip, "{}:{}".format(dutuser, src_line), dutpass)
        receiver = create_ssh_client(dutip, "{}:{}".format(dutuser, dst_line), dutpass)

        ensure_console_session_up(sender,   src_line)
        ensure_console_session_up(receiver, dst_line)

        sender.sendline('ping')
        assert_expect_text(receiver, 'ping', dst_line)
        receiver.sendline('pong')
        assert_expect_text(sender, 'pong', src_line)
    except Exception as e:
        pytest.fail("Not able to communicate DUT via reverse SSH")

def create_ssh_client(ip, user, pwd):
    # Set 'echo=False' is very important since pexpect will echo back all inputs to buffer by default
    client = pexpect.spawn('ssh {}@{} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null'.format(user, ip), echo=False)
    client.expect('[Pp]assword:')
    client.sendline(pwd)
    return client

def ensure_console_session_up(client, line):
    client.expect_exact('Successful connection to line [{}]'.format(line))
    client.expect_exact('Press ^A ^X to disconnect')

def assert_expect_text(client, text, target_line, timeout_sec=0.1):
    index = client.expect_exact([text, pexpect.EOF, pexpect.TIMEOUT], timeout=timeout_sec)
    if index == 1:
        pytest.fail("Encounter early EOF during testing line {}".format(target_line))
    elif index == 2:
        pytest.fail("Not able to get expected text in {}s".format(timeout_sec))

def generate_random_string(length):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(length))
