import pytest

from tests.conftest import _neighbor_type_option_provided, _resolve_neighbor_type_for_testbed


@pytest.mark.parametrize(
    "requested,testbed_name,provided,expected",
    [
        ("eos", "vms-kvm-t0", False, "eos"),
        ("eos", "vms-kvm-t0-csonic", False, "csonic"),
        ("eos", "vms-kvm-t0-csonic", True, "eos"),
        ("csonic", "vms-kvm-t0-csonic", True, "csonic"),
        ("sonic", "vms-kvm-t0-csonic", True, "sonic"),
    ],
)
def test_resolve_neighbor_type_for_csonic_testbed(requested, testbed_name, provided, expected):
    tbinfo = {"conf-name": testbed_name}

    assert _resolve_neighbor_type_for_testbed(requested, tbinfo, provided) == expected


@pytest.mark.parametrize(
    "args,expected",
    [
        (["bgp/test_bgp_session.py"], False),
        (["--neighbor_type", "csonic"], True),
        (["--neighbor_type=csonic"], True),
    ],
)
def test_neighbor_type_option_provided(args, expected):
    assert _neighbor_type_option_provided(args) == expected
