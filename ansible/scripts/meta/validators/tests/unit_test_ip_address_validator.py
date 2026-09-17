"""Unit tests for IPv4/IPv6 mismatch exclusions."""

from pathlib import Path
import sys


META_DIR = Path(__file__).resolve().parents[2]
if str(META_DIR) not in sys.path:
    sys.path.insert(0, str(META_DIR))

from validators.base_validator import ValidatorContext  # noqa: E402
from validators.ip_address_validator import IpAddressValidator  # noqa: E402


def _validate(device_name, connection_graph_ip, inventory_ip):
    validator = IpAddressValidator(
        {
            "exclude_ipv4_ipv6_mismatch_devices": [
                "^switch-with-independent-addresses$"
            ]
        }
    )
    context = ValidatorContext(
        "global",
        [{"conf-name": "unused", "topo": "tgen"}],
        all_groups_data={
            "str3": {
                "conn_graph": {
                    "devices": {
                        device_name: {
                            "ManagementIp": connection_graph_ip,
                        }
                    }
                },
                "inventory_devices": {
                    device_name: {
                        "ansible_host": inventory_ip,
                        "ansible_hostv6": "2a01:111:e210:b7::3",
                    }
                },
            }
        },
    )

    return validator.validate(context)


def test_device_exclusion_skips_only_ipv4_ipv6_relationship():
    result = _validate(
        "switch-with-independent-addresses",
        "10.3.144.68/27",
        "10.3.144.67",
    )

    assert all(issue.issue_id != "E2005" for issue in result.issues)
    assert any(issue.issue_id == "E2004" for issue in result.issues)


def test_non_excluded_device_still_reports_ipv4_ipv6_mismatch():
    result = _validate(
        "switch-without-exclusion",
        "10.3.144.67/27",
        "10.3.144.67",
    )

    assert any(issue.issue_id == "E2005" for issue in result.issues)
