import pytest
import string
import random
from tests.common.helpers.console_helper import assert_expect_text, create_ssh_client, ensure_console_session_up

pytestmark = [
    pytest.mark.topology('c0')
]


console_lines = list(map(str, range(1, 49)))


@pytest.mark.parametrize("target_line", console_lines)
@pytest.mark.parametrize("baud_rate", ["9600", "115200"])
def test_console_link_wiring(setup_c0, creds, target_line, baud_rate):
    """
    Test data transfer is working as expect between dut and fanout.
    Verify data can go out through the dut console port and go in through the fanout console port
    """
    duthost, console_fanout = setup_c0
    duthost.command("config console baud {} {}".format(target_line, baud_rate))
    console_fanout.command("config console baud {} {}".format(target_line, baud_rate))
    duthost.command("config console flow_control disable {}".format(target_line))
    console_fanout.command("config console flow_control disable {}".format(target_line))

    dutip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']
    dutuser = creds['sonicadmin_user']
    dutpass = creds['sonicadmin_password']

    fanoutip = console_fanout.host.options['inventory_manager'].get_host(console_fanout.hostname).vars['ansible_host']
    fanoutuser = creds['sonicadmin_user']
    fanoutpass = creds['sonicadmin_password']

    packet_size = 64
    delay_factor = 2.0

    # Estimate a reasonable data transfer time based on configured baud rate
    timeout_sec = (packet_size << 3) * delay_factor / int(baud_rate)
    dut_ressh_user = "{}:{}".format(dutuser, target_line)
    fanout_ressh_user = "{}:{}".format(fanoutuser, target_line)

    try:
        dut_client = create_ssh_client(dutip, dut_ressh_user, dutpass)
        ensure_console_session_up(dut_client, target_line)

        fanout_client = create_ssh_client(fanoutip, fanout_ressh_user, fanoutpass)
        ensure_console_session_up(fanout_client, target_line)

        # Generate a random strings to send
        text = generate_random_string(packet_size)
        dut_client.sendline(text)
        assert_expect_text(fanout_client, text, target_line, timeout_sec)

        dut_client.sendcontrol('a')
        dut_client.sendcontrol('x')
        fanout_client.sendcontrol('a')
        fanout_client.sendcontrol('x')
    except Exception as e:
        pytest.fail("Not able to communicate DUT via reverse SSH: {}".format(e))


def generate_random_string(length):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(length))
