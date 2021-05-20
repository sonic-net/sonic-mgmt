import pytest
import pexpect

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

        text = generate_random_string(packet_size)
        client.sendline(text)
        index = client.expect([text, pexpect.EOF, pexpect.TIMEOUT], timeout=timeout_sec)
        if index == 1:
            pytest.fail("Encounter early EOF during testing line {}".format(target_line))
        elif index == 2:
            pytest.fail("Not able to get echo in {}s".format(timeout_sec))
    except Exception as e:
        pytest.fail("Not able to communicate DUT via reverse SSH")

def create_ssh_client(ip, user, pwd):
    # Set 'echo=False' is very important since pexpect will echo back all inputs to buffer by default
    client = pexpect.spawn('ssh {}@{}'.format(user, ip), echo=False)

    while True:
        index = client.expect([
            '[Pp]assword:',
            'Are you sure you want to continue connecting (yes/no)?'])

        if index == 0:
            client.sendline(pwd)
            return client
        elif index == 1:
            client.sendline('yes')
        else:
            raise Exception("Unexpect pattern encountered")

def ensure_console_session_up(client, line):
    client.expect('Successful connection to line [{}]'.format(line))
    client.expect('Press ^A ^X to disconnect')

def generate_random_string(length):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(length))
