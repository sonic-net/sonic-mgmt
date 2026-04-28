import pytest

from tests.common.fixtures.conn_graph_facts import conn_graph_facts  # noqa: F401
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.console_helper import (
    assert_expect_text,
    configure_console_line,
    create_ssh_client,
    disconnect_console_client,
    ensure_console_session_up,
    generate_random_string,
    get_dut_console_lines,
    get_host_ip_and_creds,
    wait_for_line_idle,
)

pytestmark = [
    pytest.mark.topology('c0', 'c0-lo')
]


@pytest.mark.parametrize("baud_rate", ["9600", "115200"])
@pytest.mark.parametrize("flow_control", ["enable", "disable"])
def test_console_loopback_echo(setup_c0, creds, conn_graph_facts, baud_rate, flow_control,  # noqa: F811
                               cleanup_modules):
    """
    Verify data sent over a reverse-SSH console session is echoed back through
    the console switch on the same line. The lowest-numbered console line
    recorded for the DUT in ``*_serial_links.csv`` is used.
    """
    duthost, console_fanout = setup_c0
    same_host = duthost is console_fanout

    lines = get_dut_console_lines(conn_graph_facts, duthost)
    pytest_assert(
        len(lines) >= 1,
        "Echo test requires at least 1 console line for DUT '{}', got none in *_serial_links.csv".format(
            duthost.hostname),
    )
    target_line = lines[0]
    flow_control_bool = (flow_control == "enable")

    configure_console_line(duthost, target_line, baud_rate, flow_control)
    if same_host:
        delay_factor = 1.6
    else:
        console_fanout.command("config console flow_control {} {}".format(flow_control, target_line))
        console_fanout.set_loopback(target_line, baud_rate, flow_control_bool)
        delay_factor = 3.2
    if duthost.facts['platform'] in ['arm64-c8220tg_48a_o-r0']:
        delay_factor *= 25.0

    dutip, dutuser, dutpass = get_host_ip_and_creds(duthost, creds)

    packet_size = 64

    # Estimate a reasonable data transfer time based on configured baud rate
    timeout_sec = (packet_size * 10) * delay_factor / int(baud_rate)
    ressh_user = "{}:{}".format(dutuser, target_line)

    client = None
    try:
        client = create_ssh_client(dutip, ressh_user, dutpass)
        ensure_console_session_up(client, target_line)

        text = generate_random_string(packet_size)
        client.sendline(text)
        assert_expect_text(client, text, target_line, timeout_sec)

    except Exception as e:
        pytest.fail("Not able to communicate DUT via reverse SSH: {}".format(e))
    finally:
        disconnect_console_client(client)
        wait_for_line_idle(
            duthost, target_line,
            error_msg="Target line {} is busy after exited reverse SSH session".format(target_line))
        if not same_host:
            console_fanout.unset_loopback(target_line)


@pytest.mark.topology('c0')
@pytest.mark.parametrize("baud_rate", ["9600", "115200"])
@pytest.mark.parametrize("flow_control", ["enable", "disable"])
def test_console_loopback_pingpong(setup_c0, creds, conn_graph_facts, baud_rate, flow_control,  # noqa: F811
                                   cleanup_modules):
    """
    Verify two reverse-SSH console sessions can exchange data through the
    console switch (sender writes, receiver reads, then vice versa). The two
    lowest-numbered console lines recorded for the DUT in
    ``*_serial_links.csv`` are used as ``src_line`` and ``dst_line``.
    """
    duthost, console_fanout = setup_c0
    if duthost is console_fanout:
        pytest.skip(
            "ping-pong test requires a separate console fanout; on DUT '{}' the console fanout is the DUT itself, "
            "so the bridging socat process and the reverse-SSH picocom would contend for the same tty device".format(
                duthost.hostname))

    lines = get_dut_console_lines(conn_graph_facts, duthost)
    if len(lines) < 2:
        pytest.skip("Not enough console ports to run the ping-pong test on DUT '{}' (need at least 2, got {})".format(
            duthost.hostname, len(lines)))
    src_line, dst_line = lines[0], lines[1]
    flow_control_bool = (flow_control == "enable")

    configure_console_line(duthost, src_line, baud_rate, flow_control)
    configure_console_line(duthost, dst_line, baud_rate, flow_control)
    console_fanout.bridge(src_line, dst_line, baud_rate, flow_control_bool)

    dutip, dutuser, dutpass = get_host_ip_and_creds(duthost, creds)

    sender = None
    receiver = None
    try:
        sender = create_ssh_client(dutip, "{}:{}".format(dutuser, src_line), dutpass)
        receiver = create_ssh_client(dutip, "{}:{}".format(dutuser, dst_line), dutpass)

        ensure_console_session_up(sender, src_line)
        ensure_console_session_up(receiver, dst_line)

        sender.sendline('ping')
        assert_expect_text(receiver, 'ping', dst_line, timeout_sec=1)
        receiver.sendline('pong')
        assert_expect_text(sender, 'pong', src_line, timeout_sec=1)

    except Exception:
        pytest.fail("Not able to communicate DUT via reverse SSH")
    finally:
        disconnect_console_client(sender)
        disconnect_console_client(receiver)
        wait_for_line_idle(
            duthost, src_line,
            error_msg="Target line {} of dut is busy after exited reverse SSH session".format(src_line))
        wait_for_line_idle(
            console_fanout, dst_line,
            error_msg="Target line {} of fanout is busy after exited reverse SSH session".format(dst_line))
        console_fanout.unbridge(src_line, dst_line)
