"""Unit tests for ``tests/transceiver/common/dmesg_helpers.py``.

Pure logic tests: they drive the scanner against a fake duthost whose ``shell``
returns canned dmesg output, so no DUT / network is required.  They cover the
three behaviors that make the scanner correct as the reusable kernel-log-scan
primitive: the seconds-since-boot watermark filtering, the ``seen_errors``
cumulative de-dup, and the "unparseable timestamp is kept" fail-open rule.
"""
from tests.transceiver.common import dmesg_helpers

# Same error class the transceiver stress/firmware tests scan for.
I2C_PATTERN = r"i2c.*(error|fail|timeout|nack)|(error|fail).*i2c"


class _FakeDut(object):
    """Minimal duthost stand-in whose ``shell`` returns a fixed stdout_lines."""

    def __init__(self, stdout_lines):
        self._stdout_lines = list(stdout_lines)
        self.last_cmd = None

    def shell(self, cmd, module_ignore_errors=False):
        self.last_cmd = cmd
        return {"stdout_lines": list(self._stdout_lines)}


def test_scan_drops_lines_before_watermark():
    dut = _FakeDut([
        "[  100.000000] i2c i2c-1: error -110",
        "[  200.000000] i2c i2c-2: error -110",
    ])
    new = dmesg_helpers.scan_new_dmesg_errors(dut, 150.0, set(), I2C_PATTERN)
    assert new == ["[  200.000000] i2c i2c-2: error -110"]


def test_scan_keeps_lines_at_or_after_watermark():
    dut = _FakeDut([
        "[  150.000000] i2c i2c-1: error -110",
        "[  151.500000] i2c i2c-2: timeout",
    ])
    new = dmesg_helpers.scan_new_dmesg_errors(dut, 150.0, set(), I2C_PATTERN)
    assert len(new) == 2


def test_scan_dedups_via_seen_errors():
    line = "[  200.000000] i2c i2c-1: error -110"
    dut = _FakeDut([line])
    seen = set()

    first = dmesg_helpers.scan_new_dmesg_errors(dut, 0.0, seen, I2C_PATTERN)
    assert first == [line]
    assert line in seen

    # A second scan of the identical dmesg output yields nothing new, because
    # the cumulative de-dup remembers the already-reported line.
    second = dmesg_helpers.scan_new_dmesg_errors(dut, 0.0, seen, I2C_PATTERN)
    assert second == []


def test_scan_keeps_line_with_unparseable_timestamp():
    # No leading [<seconds>] stamp -> cannot be placed relative to the watermark,
    # so it is conservatively kept (fail open) even with a watermark far ahead.
    line = "i2c i2c-1: error -110 (no leading timestamp)"
    new = dmesg_helpers.scan_new_dmesg_errors(_FakeDut([line]), 99999.0, set(), I2C_PATTERN)
    assert new == [line]


def test_scan_skips_blank_lines():
    dut = _FakeDut(["", "   ", "[  200.000000] i2c i2c-1: error -110"])
    new = dmesg_helpers.scan_new_dmesg_errors(dut, 0.0, set(), I2C_PATTERN)
    assert new == ["[  200.000000] i2c i2c-1: error -110"]


def test_scan_command_bounds_severity_and_uses_pattern():
    dut = _FakeDut([])
    dmesg_helpers.scan_new_dmesg_errors(dut, 0.0, set(), I2C_PATTERN)
    assert "--level=" in dut.last_cmd
    assert I2C_PATTERN in dut.last_cmd


def test_capture_watermark_parses_first_field():
    # /proc/uptime is "<uptime> <idle>"; only the first field is the watermark.
    assert dmesg_helpers.capture_dmesg_uptime_watermark(_FakeDut(["12345.67 89.01"])) == 12345.67


def test_capture_watermark_falls_back_to_zero_on_empty_output():
    assert dmesg_helpers.capture_dmesg_uptime_watermark(_FakeDut([])) == 0.0


def test_capture_watermark_falls_back_to_zero_on_garbage():
    assert dmesg_helpers.capture_dmesg_uptime_watermark(_FakeDut(["not-a-number"])) == 0.0
