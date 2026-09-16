import logging

import pytest
from tests.common.fixtures.conn_graph_facts import conn_graph_facts  # noqa: F401
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.console_helper import (
    assert_expect_text,
    check_target_line_status,
    configure_console_line,
    create_ssh_client,
    disconnect_console_client,
    ensure_console_session_up,
    generate_random_string,
    get_dut_console_lines,
    get_host_ip_and_creds,
)

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('c0')
]


def _verify_one_line(duthost, console_fanout, creds, target_line, same_host):
    """Configure, exercise via reverse-SSH, and clean up a single console line.

    Raises if either the data path or the post-test cleanup fails for this
    line. Always restores the line to IDLE before returning.
    """
    baud_rate = 9600  # The default baud rate for console lines, we will set it explicitly just in case
    configure_console_line(duthost, target_line, baud_rate, "disable")
    if not same_host:
        configure_console_line(console_fanout, target_line, baud_rate, "disable")

    dutip, dutuser, dutpass = get_host_ip_and_creds(duthost, creds)

    if not same_host:
        fanoutip, fanoutuser, fanoutpass = get_host_ip_and_creds(console_fanout, creds)

    packet_size = 64
    delay_factor = 3.2
    if duthost.facts['platform'].startswith("arm64-c8220tg_48a"):
        delay_factor *= 2

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
    finally:
        disconnect_console_client(dut_client)
        if not same_host:
            disconnect_console_client(fanout_client)
        pytest_assert(
            check_target_line_status(duthost, target_line, "IDLE"),
            "Target line {} of dut is busy after exited reverse SSH session".format(target_line))
        if not same_host:
            pytest_assert(
                check_target_line_status(console_fanout, target_line, "IDLE"),
                "Target line {} of fanout is busy after exited reverse SSH session".format(target_line))


def test_console_link_wiring(setup_c0, creds, conn_graph_facts):  # noqa: F811
    """
    Test data transfer is working as expect between dut and fanout for every
    console line wired in the lab's ``*_serial_links.csv``.

    The list of console lines is sourced from
    ``conn_graph_facts['device_serial_link']`` via ``get_dut_console_lines``
    instead of a hardcoded port range, so the test adapts to whatever wiring
    is recorded for the DUT under test.

    Each line is configured, exercised, and cleaned up independently. Per-line
    failures are collected and reported together so that one bad line does not
    mask failures on the rest.
    """
    duthost, console_fanout = setup_c0
    # In the c0-lo topology, setup_c0 returns the same object for both
    # `duthost` and `console_fanout` (the DUT loops its own console lines).
    # Treat that case specially so we don't duplicate config, don't try to
    # open a second reverse-SSH session to the same line (which would
    # collide with the first one), and don't duplicate cleanup.
    same_host = duthost is console_fanout

    target_lines = get_dut_console_lines(conn_graph_facts, duthost)
    pytest_assert(
        target_lines,
        "No console lines wired to DUT '{}' in serial_links.csv; "
        "cannot verify link wiring.".format(duthost.hostname),
    )
    logger.info("Verifying %d console line(s) for DUT %s: %s",
                len(target_lines), duthost.hostname, target_lines)

    failures = []
    for target_line in target_lines:
        try:
            _verify_one_line(duthost, console_fanout, creds, target_line, same_host)
            logger.info("Line %s: OK", target_line)
        except Exception as e:
            failures.append((target_line, str(e)))

    pytest_assert(
        not failures,
        "Console wiring verification failed for {} of {} lines: {}".format(
            len(failures), len(target_lines),
            "; ".join("line {} -> {}".format(ln, msg) for ln, msg in failures),
        ),
    )
