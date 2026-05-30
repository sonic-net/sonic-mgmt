import logging
import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any')
]


@pytest.fixture
def shutdown_interface(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    """Fixture to shutdown an interface and guarantee it is brought back up on cleanup."""
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    intf_to_restore = None

    def do_shutdown(intf):
        nonlocal intf_to_restore
        intf_to_restore = intf
        duthost.shutdown_interface(intf)

    yield do_shutdown

    if intf_to_restore is not None:
        duthost.no_shutdown_interface(intf_to_restore)


def _pick_neighbor(asichost):
    """Pick a routed interface with an IPv4 or IPv6 peer.

    Returns a tuple (dut_intf, neighbor_ip, is_ipv6) or (None, None, None) if no
    suitable neighbor is found. IPv4 is preferred for backward compatibility; if
    no IPv4 peer is present (e.g. IPv6-only topologies) we fall back to IPv6.
    """
    # Prefer IPv4 peers when available
    ip_interfaces = asichost.show_ip_interface()["ansible_facts"]["ip_interfaces"]
    for intf, attrs in ip_interfaces.items():
        peer = attrs.get("peer_ipv4")
        if peer and peer != "N/A":
            return intf, peer, False

    # Fall back to IPv6 peers
    ipv6_interfaces = asichost.show_ipv6_interface()["ansible_facts"].get("ipv6_interfaces", {})
    for intf, attrs in ipv6_interfaces.items():
        peer = attrs.get("peer_ipv6")
        if peer and peer != "N/A":
            return intf, peer, True

    return None, None, None


class TestNeighborMacAging:
    def testNeighborMacAgingAfterIntfDown(self, duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                                          enum_rand_one_frontend_asic_index, shutdown_interface):
        """
            Test whether neighbor MAC is aged out after interface down
        """
        duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        asichost = duthost.asic_instance(enum_rand_one_frontend_asic_index)

        dut_intf, neighbor_ip, is_ipv6 = _pick_neighbor(asichost)
        if dut_intf is None:
            pytest.skip("No IPv4 or IPv6 routed neighbor found on DUT; nothing to age out")
        logger.info("DUT interface: %s, neighbor IP: %s (ipv6=%s)", dut_intf, neighbor_ip, is_ipv6)

        neigh_cmd = "{} {} neigh show {}".format(
            asichost.ip_cmd, "-6" if is_ipv6 else "-4", neighbor_ip)
        asic_db_cmd = ("{} ASIC_DB KEYS "
                       "\"ASIC_STATE:SAI_OBJECT_TYPE_NEIGHBOR_ENTRY*\\\"{}\\\"*\"").format(
            asichost.sonic_db_cli, neighbor_ip)

        # Verify that the MAC address is present in the neighbor table and ASIC_DB
        arp_entry = duthost.command(neigh_cmd)['stdout_lines']
        redis_entry = duthost.command(asic_db_cmd)['stdout_lines']
        pytest_assert(arp_entry, "Neighbor entry not found for {}".format(neighbor_ip))
        pytest_assert(redis_entry, "Redis ASIC_DB entry not found for {}".format(neighbor_ip))

        # Shutdown the interface on DUT
        shutdown_interface(dut_intf)

        def check_neighbor_aged_out():
            arp_lines = duthost.command(neigh_cmd)['stdout_lines']
            redis_lines = duthost.command(asic_db_cmd)['stdout_lines']
            return len(arp_lines) == 0 and len(redis_lines) == 0

        # Verify that the neighbor entry is aged out from the table and ASIC_DB
        pytest_assert(wait_until(120, 10, 0, check_neighbor_aged_out),
                      "Neighbor/Redis entry not aged out after interface down")
