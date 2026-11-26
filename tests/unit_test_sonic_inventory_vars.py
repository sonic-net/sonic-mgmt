"""Unit tests for per-neighbor SONiC inventory settings.

Run with:
    python3 -m pytest --noconftest \
        tests/unit_test_sonic_inventory_vars.py -v
"""

import pytest

from tests.common.sonic_inventory import get_sonic_neighbor_vars
from tests.common.sonic_inventory import register_neighbor_inventory_host


class ContainerHost:
    hostname = "csonic_vms-kvm-t0_VM0100"


def test_uses_neighbor_inventory_hostname_not_logical_or_container_name():
    nbrhosts = {}
    register_neighbor_inventory_host(
        nbrhosts, "ARISTA01T1", {"host": ContainerHost()}, "VM0100")
    communities = {
        "vlab-01": "dut-community",
        "VM0100": "neighbor-community",
        "csonic_vms-kvm-t0_VM0100": "container-community",
    }
    lookups = []

    def visible_vars(inv_files, inventory_hostname):
        lookups.append((inv_files, inventory_hostname))
        return {"snmp_rocommunity": communities[inventory_hostname]}

    result = get_sonic_neighbor_vars(
        ["inventory"], nbrhosts, "ARISTA01T1", visible_vars)

    assert result == {"snmp_rocommunity": "neighbor-community"}
    assert lookups == [(["inventory"], "VM0100")]


@pytest.mark.parametrize("nbrhosts, neighbor_name, message", [
    ({}, "ARISTA01T1", "Unable to resolve inventory host"),
    ({"ARISTA01T1": {}}, "ARISTA01T1", "Unable to resolve inventory host"),
])
def test_rejects_missing_inventory_hostname(nbrhosts, neighbor_name, message):
    with pytest.raises(ValueError, match=message):
        get_sonic_neighbor_vars(
            ["inventory"], nbrhosts, neighbor_name, lambda *_: {})


def test_rejects_missing_community_for_neighbor_inventory_host():
    nbrhosts = {
        "ARISTA01T1": {"inventory_hostname": "VM0100"},
    }

    with pytest.raises(ValueError, match="VM0100.*no SONiC SNMP"):
        get_sonic_neighbor_vars(
            ["inventory"], nbrhosts, "ARISTA01T1", lambda *_: {})
