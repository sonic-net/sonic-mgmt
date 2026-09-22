"""Unit tests for console validator conflict handling."""

from pathlib import Path
import sys

import pytest


META_DIR = Path(__file__).resolve().parents[2]
if str(META_DIR) not in sys.path:
    sys.path.insert(0, str(META_DIR))

from validators.console_validator import ConsoleValidator  # noqa: E402


@pytest.mark.parametrize(
    "testbed_entry, expected",
    [
        ({"bmc_host": "switch01", "duts": ["switch01-bmc"]}, True),
        ({"bmc_host": "switch01", "dut": ["switch01-bmc"]}, True),
        ({"bmc_host": "switch01", "duts": [], "dut": ["switch01-bmc"]}, True),
        ({"bmc_host": "switch01", "duts": None, "dut": "switch01-bmc"}, True),
        ({"bmc_host": "switch01", "duts": ["other-dut"]}, False),
    ],
)
def test_build_bmc_host_pairs_supports_duts_and_dut_fields(testbed_entry, expected):
    pairs = ConsoleValidator._build_bmc_host_pairs([{"conf-name": "tb1", **testbed_entry}])

    if expected:
        assert {"switch01", "switch01-bmc"} in pairs
    else:
        assert {"switch01", "switch01-bmc"} not in pairs


def test_console_port_conflict_ignored_for_bmc_host_pair():
    from validators.base_validator import ValidatorContext

    validator = ConsoleValidator()
    context = ValidatorContext(
        "global",
        [{"conf-name": "tb1", "bmc_host": "switch01", "dut": ["switch01-bmc"]}],
        all_groups_data={
            "g1": {
                "conn_graph": {
                    "devices": {
                        "switch01": {"Type": "DevSonic"},
                        "switch01-bmc": {"Type": "DevSonic"},
                        "cs1": {"Type": "ConsoleServer"},
                    },
                    "console_links": {
                        "switch01": {"ConsolePort": {"peerdevice": "cs1", "peerport": "1"}},
                        "switch01-bmc": {"ConsolePort": {"peerdevice": "cs1", "peerport": "1"}},
                    },
                }
            }
        },
    )

    result = validator.validate(context)

    assert result.success
    assert all(issue.issue_id != "E3005" for issue in result.issues)
