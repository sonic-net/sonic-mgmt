import pytest
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.console_helper import assert_expect_text, create_ssh_client, ensure_console_session_up
from tests.common.helpers.console_helper import generate_random_string, check_target_line_status

pytestmark = [
    pytest.mark.topology('c0')
]


console_lines = list(map(str, range(1, 49)))


@pytest.mark.parametrize("target_line", console_lines)
def test_console_link_wiring(setup_c0, creds, target_line):
    """
    Test data transfer is working as expect between dut and fanout.
    Verify data can go out through the dut console port and go in through the fanout console port
    """
    duthost, console_fanout = setup_c0
    # In the c0-lo topology, setup_c0 returns the same object for both
    # `duthost` and `console_fanout` (the DUT loops its own console lines).
    # Treat that case specially so we don't duplicate config, don't try to
    # open a second reverse-SSH session to the same line (which would
    # collide with the first one), and don't duplicate cleanup.
    same_host = duthost is console_fanout

    baud_rate = 9600  # The default baud rate for console lines, we will set it explicitly just in case
    duthost.command("config console baud {} {}".format(target_line, baud_rate))
    duthost.command("config console flow_control disable {}".format(target_line))
    if not same_host:
        console_fanout.command("config console baud {} {}".format(target_line, baud_rate))
        console_fanout.command("config console flow_control disable {}".format(target_line))

    dutip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']
    dutuser = creds['sonicadmin_user']
    dutpass = creds['sonicadmin_password']

    if not same_host:
        fanoutip = console_fanout.host.options['inventory_manager'].get_host(
            console_fanout.hostname).vars['ansible_host']
        fanoutuser = creds['sonicadmin_user']
        fanoutpass = creds['sonicadmin_password']

    packet_size = 64
    delay_factor = 3.2
    if duthost.facts['platform'] in ["arm64-c8220tg_48a_o"]:
        delay_factor *= 25.0

    # Estimate a reasonable data transfer time based on configured baud rate
    timeout_sec = (packet_size * 10) * delay_factor / int(baud_rate)
    dut_ressh_user = "{}:{}".format(dutuser, target_line)
    if not same_host:
        fanout_ressh_user = "{}:{}".format(fanoutuser, target_line)

    dut_client = None
    fanout_client = None
    try:
        dut_client = create_ssh_client(dutip, dut_ressh_user, dutpass)
        ensure_console_session_up(dut_client, target_line)

        if same_host:
            # On c0-lo the line is looped back to itself; opening a second
            # reverse-SSH session against the same line on the same host
            # would always fail because the DUT side is already attached.
            # Reuse the existing client to receive the looped-back data.
            fanout_client = dut_client
        else:
            fanout_client = create_ssh_client(fanoutip, fanout_ressh_user, fanoutpass)
            ensure_console_session_up(fanout_client, target_line)

        # Generate a random strings to send
        text = generate_random_string(packet_size)
        dut_client.sendline(text)
        assert_expect_text(fanout_client, text, target_line, timeout_sec)

    except Exception as e:
        pytest.fail("Not able to communicate DUT via reverse SSH: {}".format(e))
    finally:
        if dut_client is not None:
            dut_client.sendcontrol('a')
            dut_client.sendcontrol('x')
        if fanout_client is not None and not same_host:
            fanout_client.sendcontrol('a')
            fanout_client.sendcontrol('x')
        pytest_assert(
            check_target_line_status(duthost, target_line, "IDLE"),
            "Target line {} of dut is busy after exited reverse SSH session".format(target_line))
        if not same_host:
            pytest_assert(
                check_target_line_status(console_fanout, target_line, "IDLE"),
                "Target line {} of fanout is busy after exited reverse SSH session".format(target_line))
