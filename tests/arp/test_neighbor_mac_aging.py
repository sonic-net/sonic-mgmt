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


class TestNeighborMacAging:
    def testNeighborMacAgingAfterIntfDown(self, duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                                          enum_rand_one_frontend_asic_index, shutdown_interface):
        """
            Test whether neighbor MAC is aged out after interface down
        """
        duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        asichost = duthost.asic_instance(enum_rand_one_frontend_asic_index)
        ip_interfaces = asichost.show_ip_interface()["ansible_facts"]['ip_interfaces']
        logger.debug("ip_interfaces: " + str(ip_interfaces))

        dut_intf = None
        neighbor_ip = None
        for intf in ip_interfaces.keys():
            if "peer_ipv4" in ip_interfaces[intf] and ip_interfaces[intf]["peer_ipv4"] != "N/A":
                dut_intf = intf
                neighbor_ip = ip_interfaces[intf]["peer_ipv4"]
                break
        pytest_assert(dut_intf is not None, "No IP interface found on DUT")
        logger.debug("DUT interface: {}, neighbor IP: {}".format(dut_intf, neighbor_ip))

        # Verify that the MAC address is present in the ARP table and ASIC_DB
        arp_entry = duthost.command("{} neigh show {}".format(asichost.ip_cmd, neighbor_ip))['stdout_lines'][0]
        redis_entry = duthost.command("{} ASIC_DB KEYS \"ASIC_STATE:SAI_OBJECT_TYPE_NEIGHBOR_ENTRY*\\\"{}\\\"*\""
                                      .format(asichost.sonic_db_cli, neighbor_ip))['stdout_lines'][0]
        pytest_assert(arp_entry, "ARP entry not found")
        pytest_assert(redis_entry, "Redis entry not found")

        # Shutdown the interface on DUT
        shutdown_interface(dut_intf)

        def check_neighbor_aged_out():
            arp_lines = duthost.command("{} neigh show {}".format(
                asichost.ip_cmd, neighbor_ip))['stdout_lines']
            redis_lines = duthost.command("{} ASIC_DB KEYS \"ASIC_STATE:SAI_OBJECT_TYPE_NEIGHBOR_ENTRY*{}*\"".format(
                asichost.sonic_db_cli, neighbor_ip))['stdout_lines']
            return len(arp_lines) == 0 and len(redis_lines) == 0

        # Verify that the MAC address is aged out from the ARP table and ASIC_DB
        pytest_assert(wait_until(120, 10, 0, check_neighbor_aged_out),
                      "ARP/Redis entry not aged out after interface down")
