"""Console loopback stress test for cisco-8000 on c0 topology.

Overview:
    This test validates console-loopback stability across all DUT console lines
    discovered from the testbed serial-links inventory (``*_serial_links.csv``).
    It coordinates both DUT and console-fanout roles using the platform utility
    at ``/usr/local/bin/console_loopback.py``.

Scope:
    - Topology: ``c0`` only.
    - Platform: cisco-8000 only.

Pre-checks:
    - At least one DUT console line must be wired in the testbed inventory.
    - ``/usr/local/bin/console_loopback.py`` must exist on both DUT and fanout.

Workflow:
    1. Configure console settings on DUT and fanout:
       - ``sudo config console enable``
       - For lines 1..48:
         - ``sudo config console baud "$line" 115200``
         - ``sudo config console flow_control disable "$line"``
    2. Start fanout loopback server:
       - ``python3 /usr/local/bin/console_loopback.py fanout start --baud 115200``
    3. Run DUT stress client:
       - ``python3 /usr/local/bin/console_loopback.py dut 115200 --continue-on-fail --delay-factor 12.8``
    4. Stop fanout loopback server in teardown (always):
       - ``python3 /usr/local/bin/console_loopback.py fanout stop``

Pass criteria:
    DUT client exits with ``rc == 0``.
"""

import logging

import pytest

from tests.common.fixtures.conn_graph_facts import conn_graph_facts  # noqa: F401
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.console_helper import get_dut_console_lines

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('c0'),
]

# Baud rate used for both the fanout server and the DUT stress client.
_BAUD_RATE = 115200

# Absolute path of the cisco-8000 console loopback utility.
_SCRIPT_PATH = "/usr/local/bin/console_loopback.py"


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _find_console_loopback_script(host):
    """Return the absolute path of ``console_loopback.py`` on *host*, or None if not found."""
    check = host.shell("test -f {}".format(_SCRIPT_PATH), module_ignore_errors=True)
    if check['rc'] == 0:
        return _SCRIPT_PATH

    return None


def _is_supported_platform(host):
    """Return True if DUT platform starts with the required platform prefix."""
    platform = str(host.facts.get('platform', '')).lower()
    return platform.startswith('arm64-c8220tg_48a')


# ---------------------------------------------------------------------------
# Test
# ---------------------------------------------------------------------------

def test_console_cisco8000_loopback_stress(setup_c0, conn_graph_facts, cleanup_modules):  # noqa: F811
    """Stress-test all wired console lines on the DUT using the platform
    ``console_loopback.py`` utility.

    The test is skipped (not failed) when the required platform utility is
    unavailable on the DUT or fanout.

    Steps (c0 topology):
    1. Skip unless DUT platform starts with ``arm64-c8220tg_48a``.
    2. Verify at least one console line is wired for the DUT.
    3. Locate ``console_loopback.py`` on both the DUT and the fanout.
     4. Configure console settings on DUT and fanout:
         - ``config console enable``
         - Set 115200 baud and disable flow control on lines 1..48.
     5. Start the fanout loopback server (``fanout start``).
     6. Run the DUT loopback stress client (``dut <baud>``).
     7. Stop the fanout server unconditionally in teardown.
     8. Assert the DUT client exited with rc=0.
    """
    duthost, console_fanout = setup_c0

    if not _is_supported_platform(duthost):
        pytest.skip(
            "Skipping: DUT '{}' platform '{}' does not start with required prefix 'arm64-c8220tg_48a'.".format(
                duthost.hostname,
                duthost.facts.get('platform', ''),
            )
        )

    # ------------------------------------------------------------------ #
    # Verify console lines are wired                                       #
    # ------------------------------------------------------------------ #
    lines = get_dut_console_lines(conn_graph_facts, duthost)
    pytest_assert(
        lines,
        "No console lines found for DUT '{}' in *_serial_links.csv. "
        "At least one console line must be wired for the stress test.".format(duthost.hostname),
    )
    logger.info(
        "[cisco8000_stress] DUT '%s': %d console line(s) found: %s",
        duthost.hostname, len(lines), lines,
    )

    # ------------------------------------------------------------------ #
    # Locate the platform script on both hosts                             #
    # ------------------------------------------------------------------ #
    dut_script = _find_console_loopback_script(duthost)
    if dut_script is None:
        pytest.skip(
            "Skipping: '{}' not found on DUT '{}'. "
            "Ensure the cisco-8000 platform package (PR #4525) is installed.".format(
                _SCRIPT_PATH, duthost.hostname
            )
        )
    fanout_script = _find_console_loopback_script(console_fanout)
    if fanout_script is None:
        pytest.skip(
            "Skipping: '{}' not found on fanout '{}'. "
            "Ensure the cisco-8000 platform package (PR #4525) is installed.".format(
                _SCRIPT_PATH, console_fanout.hostname
            )
        )
    logger.info(
        "[cisco8000_stress] DUT script path    : %s (host: %s)",
        dut_script, duthost.hostname,
    )
    logger.info(
        "[cisco8000_stress] Fanout script path : %s (host: %s)",
        fanout_script, console_fanout.hostname,
    )

    # ------------------------------------------------------------------ #
    # Run the stress test                                                  #
    # ------------------------------------------------------------------ #
    console_config_cmd = (
        "sudo config console enable && "
        "for line in $(seq 1 48); do "
        "sudo config console baud \"$line\" 115200; "
        "sudo config console flow_control disable \"$line\"; "
        "done"
    )
    fanout_start_cmd = (
        "python3 {} fanout start --baud {}".format(
            fanout_script, _BAUD_RATE
        )
    )
    dut_cmd = "python3 {} dut {} --continue-on-fail --delay-factor 12.8".format(dut_script, _BAUD_RATE)

    try:
        # Step 1 – configure console on DUT and fanout
        logger.info(
            "[cisco8000_stress] Configuring console on DUT '%s': %s",
            duthost.hostname, console_config_cmd,
        )
        dut_config_result = duthost.shell(console_config_cmd, module_ignore_errors=True)
        pytest_assert(
            dut_config_result['rc'] == 0,
            "Failed to configure console on DUT '{}'. stdout: '{}' stderr: '{}'".format(
                duthost.hostname,
                dut_config_result.get('stdout', ''),
                dut_config_result.get('stderr', ''),
            ),
        )

        logger.info(
            "[cisco8000_stress] Configuring console on fanout '%s': %s",
            console_fanout.hostname, console_config_cmd,
        )
        fanout_config_result = console_fanout.shell(console_config_cmd, module_ignore_errors=True)
        pytest_assert(
            fanout_config_result['rc'] == 0,
            "Failed to configure console on fanout '{}'. stdout: '{}' stderr: '{}'".format(
                console_fanout.hostname,
                fanout_config_result.get('stdout', ''),
                fanout_config_result.get('stderr', ''),
            ),
        )

        # Step 2 – start fanout loopback server
        logger.info(
            "[cisco8000_stress] Starting fanout loopback server on '%s': %s",
            console_fanout.hostname, fanout_start_cmd,
        )
        fanout_result = console_fanout.shell(fanout_start_cmd, module_ignore_errors=True)
        pytest_assert(
            fanout_result['rc'] == 0,
            "Failed to start fanout loopback server on '{}'. "
            "stdout: '{}' stderr: '{}'".format(
                console_fanout.hostname,
                fanout_result.get('stdout', ''),
                fanout_result.get('stderr', ''),
            ),
        )
        logger.info(
            "[cisco8000_stress] Fanout server started. Output: %s",
            fanout_result.get('stdout', '').strip(),
        )

        # Step 3 – run DUT loopback stress client (tests all wired lines)
        logger.info(
            "[cisco8000_stress] Running DUT loopback stress on '%s' (%d line(s) @ %s baud): %s",
            duthost.hostname, len(lines), _BAUD_RATE, dut_cmd,
        )
        dut_result = duthost.shell(dut_cmd, module_ignore_errors=True)
        logger.info(
            "[cisco8000_stress] DUT client finished (rc=%d). Output:\n%s",
            dut_result['rc'],
            dut_result.get('stdout', '').strip(),
        )
        if dut_result.get('stderr', '').strip():
            logger.warning(
                "[cisco8000_stress] DUT client stderr:\n%s",
                dut_result['stderr'].strip(),
            )

        pytest_assert(
            dut_result['rc'] == 0,
            "Console loopback stress FAILED on DUT '{}' (lines={}, baud={}). "
            "stdout: '{}' stderr: '{}'".format(
                duthost.hostname,
                lines,
                _BAUD_RATE,
                dut_result.get('stdout', ''),
                dut_result.get('stderr', ''),
            ),
        )
        logger.info(
            "[cisco8000_stress] All %d console line(s) passed loopback stress on DUT '%s'.",
            len(lines), duthost.hostname,
        )

    finally:
        # Step 4 – stop the fanout server regardless of test outcome
        fanout_stop_cmd = "python3 {} fanout stop".format(fanout_script)
        logger.info(
            "[cisco8000_stress] Stopping fanout server on '%s': %s",
            console_fanout.hostname, fanout_stop_cmd,
        )
        stop_result = console_fanout.shell(fanout_stop_cmd, module_ignore_errors=True)
        if stop_result['rc'] != 0:
            logger.warning(
                "[cisco8000_stress] fanout stop returned rc=%d. "
                "stdout: '%s' stderr: '%s'",
                stop_result['rc'],
                stop_result.get('stdout', '').strip(),
                stop_result.get('stderr', '').strip(),
            )
