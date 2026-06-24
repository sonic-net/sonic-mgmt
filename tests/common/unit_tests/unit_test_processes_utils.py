import pytest
from tests.common.platform.processes_utils import check_pmon_uptime_minutes


@pytest.mark.parametrize("status, minimal_runtime, expected", [
    # 1. Up 30 seconds
    ("Up 30 seconds", 6, False),
    ("Up 30 seconds", 1, False),  # 0.5 min < 1 min
    # 2. Up 6 minutes
    ("Up 6 minutes", 6, True),
    ("Up 6 minutes", 10, False),
    # 3. Up 3 hours
    ("Up 3 hours", 6, True),
    ("Up 3 hours", 180, True),
    ("Up 3 hours", 181, False),
    # 4. Up 4 days
    ("Up 4 days", 6, True),
    ("Up 4 days", 5760, True),
    ("Up 4 days", 5761, False),
    # 5. Up 3 weeks
    ("Up 3 weeks", 6, True),
    # 6. Up 2 months
    ("Up 2 months", 6, True),
    # 7. Up 1 year
    ("Up 1 year", 6, True),
    # Edge case and fallback matching:
    ("Up About an hour", 6, True),
    ("Up About an hour", 60, True),
    ("Up About an hour", 61, False),
    ("", 6, False),
])
def test_check_pmon_uptime_minutes(status, minimal_runtime, expected):
    # Pass None as duthost since status is pre-fetched and supplied via
    # pmon_status
    assert (
        check_pmon_uptime_minutes(
            None,
            minimal_runtime=minimal_runtime,
            pmon_status=status
        )
        == expected
    )
