import pytest
import string
import random
from tests.common.helpers.console_helper import assert_expect_text, create_ssh_client, ensure_console_session_up

pytestmark = [
    pytest.mark.topology('c0', 'c0-lo')
]


console_lines = list(map(str, range(1, 49)))


@pytest.mark.parametrize("target_line", console_lines)
@pytest.mark.parametrize("baud_rate", ["9600", "115200"])
def test_console_loopback_echo(setup_c0, creds, target_line, baud_rate):
    """
    Test data transfer is working as expect.
    Verify data can go out through the console switch and come back through the console switch
    """
    duthost, console_fanout = setup_c0
    duthost.command("config console baud {} {}".format(target_line, baud_rate))
    duthost.shell("show line | awk '$1 == \"{}\" {{ print $2 }}' | grep {}".format(target_line, baud_rate))
    # c0-lo
    if duthost.hostname == console_fanout.hostname:
        duthost.command("config console flow_control enable {}".format(target_line))
    # c0
    else:
        duthost.command("config console flow_control disable {}".format(target_line))
        console_fanout.command("config console flow_control disable {}".format(target_line))
        console_fanout.set_loopback(target_line, baud_rate, False)

    dutip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']
    dutuser = creds['sonicadmin_user']
    dutpass = creds['sonicadmin_password']

    packet_size = 64
    delay_factor = 64.0

    # Estimate a reasonable data transfer time based on configured baud rate
    timeout_sec = (packet_size << 3) * delay_factor / int(baud_rate)
    ressh_user = "{}:{}".format(dutuser, target_line)

    try:
        client = create_ssh_client(dutip, ressh_user, dutpass)
        ensure_console_session_up(client, target_line)

        # Generate a random strings to send
        text = generate_random_string(packet_size)
        client.sendline(text)
        assert_expect_text(client, text, target_line, timeout_sec)

        client.sendcontrol('a')
        client.sendcontrol('x')
    except Exception as e:
        pytest.fail("Not able to communicate DUT via reverse SSH: {}".format(e))

    if duthost.hostname != console_fanout.hostname:
        console_fanout.unset_loopback(target_line)


@pytest.mark.topology('c0')
@pytest.mark.parametrize("src_line,dst_line", [random.sample(console_lines, 2) for _ in range(4)])
@pytest.mark.parametrize("baud_rate", ["9600", "115200"])
def test_console_loopback_pingpong(setup_c0, creds, src_line, dst_line, baud_rate):
    """
    Test data transfer is working as expect.
    Verify data can go out through the console switch and come back through the console switch
    """
    duthost, console_fanout = setup_c0
    duthost.command("config console baud {} {}".format(src_line, baud_rate))
    duthost.command("config console baud {} {}".format(dst_line, baud_rate))
    duthost.command("config console flow_control disable {}".format(src_line))
    duthost.command("config console flow_control disable {}".format(dst_line))
    console_fanout.bridge(src_line, dst_line, baud_rate, False)

    dutip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']
    dutuser = creds['sonicadmin_user']
    dutpass = creds['sonicadmin_password']

    try:
        sender = create_ssh_client(dutip, "{}:{}".format(dutuser, src_line), dutpass)
        receiver = create_ssh_client(dutip, "{}:{}".format(dutuser, dst_line), dutpass)

        ensure_console_session_up(sender, src_line)
        ensure_console_session_up(receiver, dst_line)

        sender.sendline('ping')
        assert_expect_text(receiver, 'ping', dst_line, timeout_sec=1)
        receiver.sendline('pong')
        assert_expect_text(sender, 'pong', src_line, timeout_sec=1)

        sender.sendcontrol('a')
        sender.sendcontrol('x')
        receiver.sendcontrol('a')
        receiver.sendcontrol('x')
    except Exception:
        pytest.fail("Not able to communicate DUT via reverse SSH")

    console_fanout.unbridge(src_line, dst_line)


def generate_random_string(length):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(length))
