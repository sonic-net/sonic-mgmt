import datetime

from tests.performance_meter.success_criteria import _select_syslog_window


START_MARK = "create: request switch create with context 0"
END_MARK = "main: Create a switch, id:"
BASELINE = datetime.datetime(2026, 8, 21, 5, 0, 0)


class FakeDutHost:
    hostname = "dut"


def test_selects_last_start_before_end():
    """Verify the final start marker selects the successful create cycle."""
    output = "\n".join([
        "2026 Aug 21 05:01:00.000000 dut NOTICE {}".format(START_MARK),
        "2026 Aug 21 05:02:39.000000 dut NOTICE {}".format(START_MARK),
        "2026 Aug 21 05:03:50.000000 dut NOTICE {}".format(END_MARK),
    ])

    window = _select_syslog_window(
        FakeDutHost(), output, BASELINE, START_MARK, END_MARK, "last"
    )

    assert (window["end"] - window["start"]).total_seconds() == 71
    assert window["start_count"] == 2


def test_first_policy_preserves_legacy_semantics():
    """Verify that the opt-in helper can preserve first-marker behavior."""
    output = "\n".join([
        "2026 Aug 21 05:01:00.000000 dut NOTICE {}".format(START_MARK),
        "2026 Aug 21 05:02:39.000000 dut NOTICE {}".format(START_MARK),
        "2026 Aug 21 05:03:50.000000 dut NOTICE {}".format(END_MARK),
    ])

    window = _select_syslog_window(
        FakeDutHost(), output, BASELINE, START_MARK, END_MARK, "first"
    )

    assert (window["end"] - window["start"]).total_seconds() == 170


def test_ignores_markers_before_baseline():
    """Verify prior reload markers are excluded from the current sample."""
    output = "\n".join([
        "2026 Aug 21 04:59:00.000000 dut NOTICE {}".format(START_MARK),
        "2026 Aug 21 04:59:40.000000 dut NOTICE {}".format(END_MARK),
        "2026 Aug 21 05:01:00.000000 dut NOTICE {}".format(START_MARK),
        "2026 Aug 21 05:02:25.000000 dut NOTICE {}".format(END_MARK),
    ])

    window = _select_syslog_window(
        FakeDutHost(), output, BASELINE, START_MARK, END_MARK, "last"
    )

    assert (window["end"] - window["start"]).total_seconds() == 85
    assert window["start_count"] == 1
    assert window["end_count"] == 1


def test_waits_until_both_markers_exist():
    """Verify that an incomplete marker window does not pass the criterion."""
    output = "2026 Aug 21 05:01:00.000000 dut NOTICE {}".format(START_MARK)

    window = _select_syslog_window(
        FakeDutHost(), output, BASELINE, START_MARK, END_MARK, "last"
    )

    assert window is None
