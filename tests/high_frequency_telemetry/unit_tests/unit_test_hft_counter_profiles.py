from pathlib import Path

import yaml

from tests.high_frequency_telemetry.counter_profiles import (
    CounterObjectType,
    get_support_counter_list,
)


class DutHost:
    def __init__(self, **facts):
        self.facts = facts


def test_vpp_uses_asic_type_instead_of_shared_kvm_platform():
    host = DutHost(platform="x86_64-kvm_x86_64-r0", asic_type="vpp")

    assert get_support_counter_list(host, CounterObjectType.PORT) == (
        "IF_IN_OCTETS",
        "IF_IN_DISCARDS",
        "IF_OUT_OCTETS",
        "IF_IN_UCAST_PKTS",
        "IF_OUT_ERRORS",
        "IF_OUT_UCAST_PKTS",
    )
    assert get_support_counter_list(host, CounterObjectType.QUEUE) == ()
    assert get_support_counter_list(
        host, CounterObjectType.INGRESS_PRIORITY_GROUP
    ) == ()
    assert get_support_counter_list(host, CounterObjectType.BUFFER_POOL) == ()


def test_non_vpp_kvm_platform_remains_unsupported():
    host = DutHost(platform="x86_64-kvm_x86_64-r0", asic_type="vs")

    assert get_support_counter_list(host, CounterObjectType.PORT) == ()


def test_t0_vpp_manifest_runs_both_hft_modules():
    root = Path(__file__).parents[3]
    profiles = yaml.safe_load(
        (root / ".azure-pipelines" / "pr_test_scripts.yaml").read_text()
    )

    assert "high_frequency_telemetry/test_hft_end_to_end.py" in profiles[
        "t0-vpp"
    ]
    assert (
        "high_frequency_telemetry/test_high_frequency_telemetry.py"
        in profiles["t0-vpp"]
    )
