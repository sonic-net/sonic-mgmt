import logging
import re
import uuid

import pytest

from tests.transceiver.utils.cli_parser_helper import (
    parse_read_eeprom,
    RC_FAILURE,
    CMIS_PAGE_01_CDB_CAP_PAGE,
    CMIS_PAGE_01_CDB_CAP_OFFSET,
    CMIS_PAGE_01_CDB_BG_MODE_BIT,
)

logger = logging.getLogger(__name__)

CMD_SFP_READ_EEPROM_SFPUTIL = "sudo sfputil read-eeprom"
CMD_SFP_FWVERSION_SFPUTIL = "sudo sfputil show fwversion"

# Number of CDB firmware version read iterations used in the TC13 stress test
STRESS_TEST_ITERATIONS = 10

# Maximum tolerated background EEPROM read failure rate during the TC13 stress test.
# Some transient failures are acceptable while CDB occupies the I2C bus; failures
# exceeding this fraction of total attempts indicate a structural problem.
STRESS_EEPROM_MAX_FAIL_RATE = 0.5

# Number of I2C kernel-log errors tolerated before aborting a stress-test iteration
# loop.  A small number of transient errors can appear during normal background-mode
# operation; only a sustained burst warrants an early abort.
STRESS_TEST_I2C_ERROR_THRESHOLD = 3

# How often (in background EEPROM read iterations) the remote bash loop flushes its
# counters to the temp files.  Lower values give more accurate mid-run snapshots at
# the cost of extra file I/O; the final flush-on-EXIT trap is always executed.
STRESS_BG_FLUSH_INTERVAL = 100


def test_cdb_background_mode_support_test(duthost, port_attributes_dict):
    """Verify CMIS CDB background mode hardware capability against inventory configuration.

    Prerequisites per port (both must be satisfied or the port is silently skipped):
    - EEPROM_ATTRIBUTES: is_non_dac_and_cmis = True  (non-DAC CMIS module)
    - EEPROM_ATTRIBUTES: cdb_background_mode_supported is defined (True or False)

    For qualifying ports, reads CMIS Page 01h at sfputil offset 0xA3 (= CMIS global
    byte 163 decimal, absolute address 0xA3 in the 256-byte page view) using:
        sfputil read-eeprom -p <port> -n 0x01 -o 0xA3 -s 1

    Extracts bit 5 of the returned byte and validates against expected configuration:
        cdb_background_mode_supported = True  → bit 5 must be 1 (hardware supports it)
        cdb_background_mode_supported = False → bit 5 must be 0 (hardware does not)

    Aggregates all failures for reporting.

    CMIS reference:
        Page 01h (Capabilities Advertising), CMIS global byte 163 (decimal) = 0xA3, bit 5:
        CDB background mode support advertisement.
        sfputil: -n 0x01 -o 0xA3  (upper page, 0xA3 - 0x80 = 0x23 = 35 bytes from page start)
    """
    if duthost.facts.get("asic_type") == "vs":
        pytest.skip("Skipping CDB background mode verification on virtual switch testbed")

    all_failures = []

    for port, port_attrs in port_attributes_dict.items():
        # Only test stem (parent) ports.  In a breakout deployment a single
        # physical transceiver is represented as Ethernet0, Ethernet8, Ethernet16, …
        # (port-number divisible by 8).  Sub-ports (Ethernet1, Ethernet2, …) share
        # the same EEPROM and do not independently carry a CMIS module, so running
        # CDB read commands against them is redundant and can cause false failures on
        # some ASIC drivers.  This assumption holds for standard 8-lane OSFP/QSFP-DD
        # breakout; update the modulus if your hardware uses a different lane count.
        port_match = re.match(r"^Ethernet(\d+)$", port)
        if not port_match:
            logger.debug("Port %s is not a physical Ethernet port name, skipping", port)
            continue
        if (int(port_match.group(1)) % 8) != 0:
            logger.debug("Port %s is a breakout sub-port, skipping CDB check", port)
            continue
        if not port_attrs:
            logger.debug("Port %s has no attributes, skipping", port)
            continue

        eeprom_attrs = port_attrs.get("EEPROM_ATTRIBUTES", {})

        # Prerequisite 1: port must be a non-DAC CMIS module
        if not eeprom_attrs.get("is_non_dac_and_cmis"):
            logger.debug("Port %s: is_non_dac_and_cmis is not True, skipping CDB check", port)
            continue

        # Prerequisite 2: expected CDB background mode support must be defined
        expected_cdb_bg_mode = eeprom_attrs.get("cdb_background_mode_supported")
        if expected_cdb_bg_mode is None:
            logger.debug("Port %s: cdb_background_mode_supported not defined, skipping", port)
            continue

        # Read CMIS Page 01h, CMIS global byte 163 (decimal) = 0xA3 (sfputil offset 0xA3)
        cmd = (
            f"{CMD_SFP_READ_EEPROM_SFPUTIL} -p {port}"
            f" -n 0x{CMIS_PAGE_01_CDB_CAP_PAGE:02X}"
            f" -o {CMIS_PAGE_01_CDB_CAP_OFFSET} -s 1"
        )
        result = duthost.command(cmd, module_ignore_errors=True)
        if result.get('rc', RC_FAILURE) != 0:
            all_failures.append(
                f"{port}: sfputil read-eeprom page 0x{CMIS_PAGE_01_CDB_CAP_PAGE:02X} failed "
                f"with rc={result.get('rc')}, stderr: {result.get('stderr', '')}"
            )
            continue

        stdout_lines = result.get('stdout_lines', [])
        if not stdout_lines:
            all_failures.append(
                f"{port}: sfputil read-eeprom page 0x{CMIS_PAGE_01_CDB_CAP_PAGE:02X} "
                f"returned empty output"
            )
            continue

        byte_map = parse_read_eeprom(stdout_lines)
        if not byte_map:
            all_failures.append(
                f"{port}: no parseable byte found in sfputil read-eeprom output "
                f"(page 0x{CMIS_PAGE_01_CDB_CAP_PAGE:02X}, "
                f"offset 0x{CMIS_PAGE_01_CDB_CAP_OFFSET:02X})"
            )
            continue

        # Extract bit 5 from the single returned byte
        raw_byte = next(iter(byte_map.values()))
        actual_bit = (raw_byte >> CMIS_PAGE_01_CDB_BG_MODE_BIT) & 0x01
        expected_bit = 1 if expected_cdb_bg_mode else 0

        if actual_bit != expected_bit:
            all_failures.append(
                f"{port}: CDB background mode mismatch: "
                f"expected bit {CMIS_PAGE_01_CDB_BG_MODE_BIT} = {expected_bit} "
                f"(cdb_background_mode_supported={expected_cdb_bg_mode}), "
                f"got bit {CMIS_PAGE_01_CDB_BG_MODE_BIT} = {actual_bit} "
                f"(raw byte: 0x{raw_byte:02X}, "
                f"page 0x{CMIS_PAGE_01_CDB_CAP_PAGE:02X} "
                f"offset 0x{CMIS_PAGE_01_CDB_CAP_OFFSET:02X})"
            )
        else:
            logger.debug(
                "Port %s CDB background mode verified: bit %d = %d "
                "(cdb_background_mode_supported=%s, raw byte: 0x%02X)",
                port, CMIS_PAGE_01_CDB_BG_MODE_BIT, actual_bit, expected_cdb_bg_mode, raw_byte,
            )

    if all_failures:
        pytest.fail("CDB background mode verification failures:\n" + "\n".join(all_failures))


def test_cdb_background_mode_stress_test(duthost, port_attributes_dict):
    """CDB background mode stress test for CMIS transceivers.

    Prerequisites per port (both must be satisfied or the port is silently skipped):
    - EEPROM_ATTRIBUTES: is_non_dac_and_cmis = True  (non-DAC CMIS module)
    - EEPROM_ATTRIBUTES: cdb_background_mode_supported = True

    For each qualifying port the test:
    1. Records a dmesg watermark before the stress run begins.
    2. Starts a background thread that continuously reads the EEPROM identifier byte
       via 'sfputil read-eeprom -p <port> -n 0 -o 0 -s 1', simulating concurrent
       I2C bus traffic against the running CDB operations.
    3. Reads the CDB firmware version via 'sfputil show fwversion <port>' for
       STRESS_TEST_ITERATIONS (10) iterations.
    4. After each iteration, scans dmesg for new I2C error messages (errors, failures,
       timeouts, NACKs) since the watermark; aborts the loop early on first detection.
    5. Stops the background EEPROM thread (joins with a 10 s timeout).
    6. Reports a failure if the background EEPROM fail rate exceeds
       STRESS_EEPROM_MAX_FAIL_RATE (50 %), indicating structural I2C bus disruption.

    Expected result: all STRESS_TEST_ITERATIONS CDB firmware version reads complete
    successfully and no I2C error messages appear in the kernel log throughout the run.

    Aggregates all failures for reporting.
    """
    if duthost.facts.get("asic_type") == "vs":
        pytest.skip("Skipping CDB background mode stress test on virtual switch testbed")

    all_failures = []

    for port, port_attrs in port_attributes_dict.items():
        # Only test stem ports — see TC12 for the full rationale.
        port_match = re.match(r"^Ethernet(\d+)$", port)
        if not port_match:
            logger.debug("Port %s is not a physical Ethernet port name, skipping", port)
            continue
        if (int(port_match.group(1)) % 8) != 0:
            logger.debug("Port %s is a breakout sub-port, skipping stress test", port)
            continue

        if not port_attrs:
            logger.debug("Port %s has no attributes, skipping", port)
            continue

        eeprom_attrs = port_attrs.get("EEPROM_ATTRIBUTES", {})

        # Prerequisite 1: non-DAC CMIS module
        if not eeprom_attrs.get("is_non_dac_and_cmis"):
            logger.debug("Port %s: is_non_dac_and_cmis is not True, skipping", port)
            continue

        # Prerequisite 2: CDB background mode must be supported
        if not eeprom_attrs.get("cdb_background_mode_supported"):
            logger.debug(
                "Port %s: cdb_background_mode_supported is not True, skipping", port
            )
            continue

        logger.info(
            "Port %s: starting CDB background mode stress test (%d iterations)",
            port, STRESS_TEST_ITERATIONS,
        )

        # ------------------------------------------------------------------ #
        # Step 1 – Record dmesg watermark before the stress test begins       #
        # ------------------------------------------------------------------ #
        wm_result = duthost.shell("sudo dmesg | wc -l", module_ignore_errors=True)
        try:
            dmesg_start = int(wm_result.get('stdout_lines', ['0'])[0].strip())
        except (ValueError, IndexError):
            dmesg_start = 0

        # ------------------------------------------------------------------ #
        # Step 2 – Start background EEPROM reader via a remote shell process  #
        # A long-lived bash loop runs directly on the DUT (not as a Python    #
        # thread) so there is no Python-level concurrency and no contention   #
        # on the duthost connection object during the stress loop below.      #
        # Mutable single-element lists carry the final counters back to the   #
        # caller after the remote process is stopped.                         #
        # ------------------------------------------------------------------ #
        eeprom_fail_count = [0]
        eeprom_total_count = [0]

        class _RemoteEepromReader(object):
            """Manage a background EEPROM polling loop running on the DUT.

            Temp-file names include a short UUID fragment so that concurrent
            test runs (e.g. parallel tox invocations) cannot collide on the
            same DUT files.
            """

            def __init__(self, host, sfp_port, fail_count, total_count):
                safe_port = re.sub(r"[^A-Za-z0-9_.-]", "_", str(sfp_port))
                run_id = uuid.uuid4().hex[:8]
                self.host = host
                self.port = sfp_port
                self.fail_count = fail_count
                self.total_count = total_count
                self.pid = None
                self.fail_file = f"/tmp/test_cmis_{safe_port}_{run_id}_fail"
                self.total_file = f"/tmp/test_cmis_{safe_port}_{run_id}_total"

            def start(self):
                cmd = (
                    "nohup bash -c '"
                    f"fail_file=\"{self.fail_file}\"; "
                    f"total_file=\"{self.total_file}\"; "
                    "fail_count=0; "
                    "total_count=0; "
                    "write_counts() { "
                    "echo \"$fail_count\" > \"$fail_file\"; "
                    "echo \"$total_count\" > \"$total_file\"; "
                    "}; "
                    "trap \"write_counts; exit 0\" TERM INT EXIT; "
                    "while true; do "
                    "total_count=$((total_count + 1)); "
                    f"{CMD_SFP_READ_EEPROM_SFPUTIL} -p {self.port} -n 0 -o 0 -s 1 >/dev/null 2>&1 || "
                    "fail_count=$((fail_count + 1)); "
                    # Flush counters periodically so the main thread can read
                    # reasonably fresh values even if the loop runs for a long
                    # time before receiving SIGTERM.
                    f"[ $((total_count % {STRESS_BG_FLUSH_INTERVAL})) -eq 0 ] && write_counts; "
                    "done' >/dev/null 2>&1 & echo $!"
                )
                result = self.host.shell(cmd, module_ignore_errors=True)
                if result.get('rc', RC_FAILURE) == 0:
                    try:
                        pid_str = result.get('stdout', '').strip()
                        self.pid = int(pid_str)
                        if self.pid <= 0:
                            raise ValueError(f"non-positive PID: {pid_str!r}")
                    except (TypeError, ValueError) as exc:
                        logger.error(
                            "Port %s: failed to parse background reader PID: %s",
                            self.port, exc,
                        )
                        self.pid = None

            def join(self, timeout=10):
                """Stop the background loop and retrieve the final counters.

                Args:
                    timeout: maximum seconds to wait for the remote process to
                             exit after receiving SIGTERM (default 10 s).
                             The wait loop polls every 0.1 s.
                """
                wait_iterations = max(1, int(timeout / 0.1))
                if self.pid is not None:
                    self.host.shell(f"kill {self.pid}", module_ignore_errors=True)
                    self.host.shell(
                        f"for _ in $(seq 1 {wait_iterations}); do "
                        f"kill -0 {self.pid} 2>/dev/null || break; "
                        f"sleep 0.1; "
                        f"done",
                        module_ignore_errors=True,
                    )
                fail_result = self.host.shell(
                    f"cat {self.fail_file} 2>/dev/null || echo 0",
                    module_ignore_errors=True,
                )
                total_result = self.host.shell(
                    f"cat {self.total_file} 2>/dev/null || echo 0",
                    module_ignore_errors=True,
                )
                self.host.shell(
                    f"rm -f {self.fail_file} {self.total_file}",
                    module_ignore_errors=True,
                )
                try:
                    self.fail_count[0] = int(fail_result.get('stdout', '0').strip())
                except (TypeError, ValueError):
                    self.fail_count[0] = 0
                try:
                    self.total_count[0] = int(total_result.get('stdout', '0').strip())
                except (TypeError, ValueError):
                    self.total_count[0] = 0

        eeprom_thread = _RemoteEepromReader(
            duthost,
            port,
            eeprom_fail_count,
            eeprom_total_count,
        )
        eeprom_thread.start()

        port_failures = []

        # Cumulative I2C error count across all iterations for this port.
        # We tolerate a small number of transient errors (see STRESS_TEST_I2C_ERROR_THRESHOLD)
        # before aborting the loop — a single spurious kernel message should not
        # fail an otherwise healthy stress run.
        cumulative_i2c_errors = []

        try:
            # ------------------------------------------------------------------ #
            # Step 3 – CDB firmware version read loop                            #
            # ------------------------------------------------------------------ #
            for iteration in range(1, STRESS_TEST_ITERATIONS + 1):
                logger.debug(
                    "Port %s: CDB stress iteration %d/%d",
                    port, iteration, STRESS_TEST_ITERATIONS,
                )

                cmd = f"{CMD_SFP_FWVERSION_SFPUTIL} {port}"
                result = duthost.command(cmd, module_ignore_errors=True)
                if result.get('rc', RC_FAILURE) != 0:
                    port_failures.append(
                        f"Iteration {iteration}/{STRESS_TEST_ITERATIONS}: "
                        f"sfputil show fwversion failed with rc={result.get('rc')}, "
                        f"stderr: {result.get('stderr', '')}"
                    )

                # -------------------------------------------------------------- #
                # Step 4 – Check kernel dmesg for new I2C errors                 #
                # '|| true' ensures the shell command always exits 0 so that     #
                # module_ignore_errors=True is sufficient and grep's exit-1-on-  #
                # no-match never looks like a command failure.                   #
                # Only abort the loop when the cumulative error count exceeds    #
                # STRESS_TEST_I2C_ERROR_THRESHOLD — transient single errors can  #
                # appear during normal background-mode operation and should not  #
                # cause a hard failure on their own.                             #
                # -------------------------------------------------------------- #
                dmesg_check = duthost.shell(
                    f"sudo dmesg 2>&1 | tail -n +{dmesg_start + 1} | "
                    f"grep -iE 'i2c.*(error|fail|timeout|nack)|(error|fail).*i2c' || true",
                    module_ignore_errors=True,
                )
                new_i2c_errors = [
                    ln for ln in dmesg_check.get('stdout_lines', []) if ln.strip()
                ]
                if new_i2c_errors:
                    cumulative_i2c_errors.extend(new_i2c_errors)
                    logger.warning(
                        "Port %s: %d I2C error(s) in dmesg after iteration %d "
                        "(%d cumulative, threshold=%d)",
                        port, len(new_i2c_errors), iteration,
                        len(cumulative_i2c_errors), STRESS_TEST_I2C_ERROR_THRESHOLD,
                    )
                    if len(cumulative_i2c_errors) > STRESS_TEST_I2C_ERROR_THRESHOLD:
                        port_failures.append(
                            f"I2C kernel errors exceeded threshold "
                            f"({len(cumulative_i2c_errors)} > {STRESS_TEST_I2C_ERROR_THRESHOLD}) "
                            f"after iteration {iteration}/{STRESS_TEST_ITERATIONS}:\n    "
                            + "\n    ".join(cumulative_i2c_errors[:10])
                        )
                        logger.warning(
                            "Port %s: I2C error threshold exceeded — aborting stress loop",
                            port,
                        )
                        break

        finally:
            # ------------------------------------------------------------------ #
            # Step 5 – Stop background EEPROM process unconditionally            #
            # ------------------------------------------------------------------ #
            eeprom_thread.join(timeout=10)

        # ------------------------------------------------------------------ #
        # Step 6 – Evaluate background EEPROM read failure rate               #
        # ------------------------------------------------------------------ #
        total = eeprom_total_count[0]
        failed = eeprom_fail_count[0]
        if total > 0:
            fail_rate = failed / total
            logger.info(
                "Port %s: background EEPROM reads — %d total, %d failed (%.0f%%)",
                port, total, failed, fail_rate * 100,
            )
            if fail_rate > STRESS_EEPROM_MAX_FAIL_RATE:
                port_failures.append(
                    f"Background EEPROM read failure rate too high: "
                    f"{failed}/{total} ({fail_rate * 100:.0f}%) reads failed "
                    f"(threshold: {STRESS_EEPROM_MAX_FAIL_RATE * 100:.0f}%)"
                )
        else:
            logger.warning("Port %s: background EEPROM thread made no attempts", port)

        if port_failures:
            all_failures.append(f"{port}:\n  " + "\n  ".join(port_failures))
        else:
            logger.info(
                "Port %s: CDB background mode stress test passed (%d iterations, "
                "%d/%d background EEPROM reads succeeded)",
                port, STRESS_TEST_ITERATIONS, total - failed, total,
            )

    if all_failures:
        pytest.fail(
            "CDB background mode stress test failures:\n" + "\n".join(all_failures)
        )
