"""
Console large payload transfer test.

Validates serial console data integrity by transmitting large payloads
from DUT to console fanout via SONiC reverse-SSH console sessions and
measuring the byte error rate.

Payload is filled with lowercase 'f' (0x66 = 01100110) which has equal
1/0 bit distribution.  Error detection is simple: any received byte that
is not 'f' is a corruption error, and any missing bytes are loss errors.

Parameterized by baud rate, payload size, flow control, and allowed
error rate.  Skips when no console fanout is available (including c0-lo).
"""

import logging

import pexpect
import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.console_helper import (
    create_ssh_client,
    ensure_console_session_up,
    check_target_line_status,
)
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('c0'),
]

CHUNK_SIZE = 1024
FILL_CHAR = 'f'  # 0x66 = 01100110, equal 1s and 0s


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def console_setup(request, duthost, tbinfo):
    """
    Discover console fanout and select the last console line.
    Skip if no fanout is available or topology is c0-lo.
    Returns (duthost, console_fanout, target_line).
    """
    if tbinfo["topo"]["name"] != "c0":
        pytest.skip("Test requires c0 topology with a console fanout "
                     "(got '{}')".format(tbinfo["topo"]["name"]))

    fanouthosts = request.getfixturevalue("fanouthosts")
    console_fanouts = [
        fh for fh in fanouthosts.values()
        if fh.get_fanout_os() == 'sonic' and fh.is_console_switch()
    ]
    if not console_fanouts:
        pytest.skip("No console fanout available in testbed")
    console_fanout = console_fanouts[0]

    # Select the last console line from console_facts
    console_facts = duthost.console_facts()['ansible_facts']['console_facts']
    lines = sorted(console_facts['lines'].keys(), key=int)
    pytest_assert(len(lines) > 0, "No console lines configured on DUT")
    target_line = lines[-1]
    logger.info("Selected console line %s (last of %d lines)",
                target_line, len(lines))

    return duthost, console_fanout, target_line


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_host_ip(host):
    """Get the management IP of a host."""
    return host.host.options['inventory_manager'].get_host(
        host.hostname
    ).vars['ansible_host']


def _disconnect_console(client):
    """Send picocom exit sequence ^A ^X."""
    try:
        client.sendcontrol('a')
        client.sendcontrol('x')
    except Exception as e:
        logger.warning("Failed to disconnect console session: %s", e)


# ---------------------------------------------------------------------------
# Test
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "baud_rate, payload_size, flow_control, allowed_err_rate",
    [
        ("9600",   1 * 1024 * 1024, False, 0),
        ("9600",   1 * 1024 * 1024, True,  0),
        ("115200", 10 * 1024 * 1024, False, 0.000001),
        ("115200", 10 * 1024 * 1024, True,  0.000001),
    ],
    ids=[
        "9600-1M-nofc-0",
        "9600-1M-hwfc-0",
        "115200-10M-nofc-0.000001",
        "115200-10M-hwfc-0.000001",
    ]
)
def test_console_large_payload_transfer(
    console_setup, creds, cleanup_modules,
    baud_rate, payload_size, flow_control, allowed_err_rate
):
    """
    Send a large payload of 'f' characters from DUT to console fanout
    via reverse-SSH console sessions.  Count corrupted and lost bytes
    and verify the error rate is within the allowed threshold.
    """
    duthost, console_fanout, target_line = console_setup

    # -- Configure baud rate and flow control on both sides --
    duthost.command("config console baud {} {}".format(target_line, baud_rate))
    console_fanout.command("config console baud {} {}".format(
        target_line, baud_rate))

    fc_cmd = "enable" if flow_control else "disable"
    duthost.command("config console flow_control {} {}".format(
        fc_cmd, target_line))
    console_fanout.command("config console flow_control {} {}".format(
        fc_cmd, target_line))

    # -- Connection details --
    dutip = _get_host_ip(duthost)
    fanoutip = _get_host_ip(console_fanout)
    user = creds['sonicadmin_user']
    password = creds['sonicadmin_password']

    dut_ressh_user = "{}:{}".format(user, target_line)
    fanout_ressh_user = "{}:{}".format(user, target_line)

    # -- Payload setup --
    num_chunks = payload_size // CHUNK_SIZE
    total_bytes = num_chunks * CHUNK_SIZE
    expected_chunk = FILL_CHAR * CHUNK_SIZE

    delay_factor = 3.2
    chunk_timeout = max((CHUNK_SIZE * 10) * delay_factor / int(baud_rate), 1.0)

    logger.info(
        "Starting large payload transfer: baud=%s, payload=%d bytes, "
        "chunks=%d, flow_control=%s, allowed_err_rate=%f, "
        "chunk_timeout=%.2fs, target_line=%s",
        baud_rate, total_bytes, num_chunks, flow_control,
        allowed_err_rate, chunk_timeout, target_line
    )

    sender = None
    receiver = None
    try:
        # -- Attach to console lines via reverse SSH --
        sender = create_ssh_client(dutip, dut_ressh_user, password)
        ensure_console_session_up(sender, target_line)

        receiver = create_ssh_client(fanoutip, fanout_ressh_user, password)
        ensure_console_session_up(receiver, target_line)

        # -- Send chunks and verify --
        total_errors = 0
        chunks_ok = 0
        chunks_failed = 0

        for seq in range(num_chunks):
            sender.sendline(expected_chunk)

            try:
                idx = receiver.expect_exact(
                    [expected_chunk, pexpect.TIMEOUT],
                    timeout=chunk_timeout
                )
                if idx == 0:
                    # Perfect match
                    chunks_ok += 1
                else:
                    # Timeout — count errors in whatever was received
                    received = receiver.before
                    if isinstance(received, bytes):
                        received = received.decode(errors='replace')
                    received = received or ""

                    # Count corrupted bytes (non-'f' chars)
                    corrupt = sum(1 for c in received if c != FILL_CHAR)
                    # Count lost bytes (expected - received length)
                    lost = max(0, CHUNK_SIZE - len(received))
                    total_errors += corrupt + lost
                    chunks_failed += 1

            except pexpect.TIMEOUT:
                total_errors += CHUNK_SIZE
                chunks_failed += 1
            except pexpect.EOF:
                logger.error("EOF on receiver at chunk %d/%d",
                             seq + 1, num_chunks)
                total_errors += CHUNK_SIZE
                chunks_failed += 1

            # Log progress every 100 chunks
            if (seq + 1) % 100 == 0:
                logger.info(
                    "Progress: %d/%d chunks (%d ok, %d failed, "
                    "%d byte errors)",
                    seq + 1, num_chunks, chunks_ok,
                    chunks_failed, total_errors
                )

        # -- Calculate and verify error rate --
        error_rate = total_errors / total_bytes if total_bytes > 0 else 0
        logger.info(
            "Transfer complete: %d/%d chunks OK, %d failed, "
            "%d byte errors, error_rate=%.10f (allowed=%.10f)",
            chunks_ok, num_chunks, chunks_failed,
            total_errors, error_rate, allowed_err_rate
        )

        pytest_assert(
            error_rate <= allowed_err_rate,
            "Byte error rate {:.10f} exceeds threshold {:.10f} "
            "(errors={}, total={}, chunks_failed={})".format(
                error_rate, allowed_err_rate,
                total_errors, total_bytes, chunks_failed)
        )

    except Exception as e:
        pytest.fail(
            "Console large payload transfer failed: {}".format(e))

    finally:
        if sender:
            _disconnect_console(sender)
        if receiver:
            _disconnect_console(receiver)

        # Wait for lines to return to IDLE
        pytest_assert(
            wait_until(10, 1, 0, check_target_line_status,
                       duthost, target_line, "IDLE"),
            "DUT line {} busy after test".format(target_line))
        pytest_assert(
            wait_until(10, 1, 0, check_target_line_status,
                       console_fanout, target_line, "IDLE"),
            "Fanout line {} busy after test".format(target_line))
