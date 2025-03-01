import logging
import pytest
import random
import time

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import skip_release, wait_until
from tests.common.platform.interface_utils import get_fec_eligible_interfaces
from tests.common.platform.interface_utils import get_port_map

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any')
]

@pytest.fixture(autouse=True)
def is_supported_platform(duthost):
    """
    Skip test if the platform is not '7060X6' or if the SONiC image is older than 202412.
    """
    platform = duthost.facts['platform']
    sonic_version = int(duthost.facts['image_version'].split('-')[0])  # Extracts numeric part

    if platform != "x86_64-arista_7060x6_64pe":
        pytest.skip("Unsupported platform: {}. Test only runs on 7060X6.".format(platform))
    
    if sonic_version < 202412:
        pytest.skip("Unsupported SONiC version: {}. Test requires image >= 202412.".format(sonic_version))


def get_mac_fault_count(dut, interface, fault_type):
    """
    Retrieve MAC fault count (local or remote) for a given interface
    :param dut: DUT instance
    :param interface: Interface to check
    :param fault_type: 'mac local fault' or 'mac remote fault'
    """
    output = dut.show_and_parse("show int errors {}".format(interface))
    logging.info("Raw output for show int errors on {}: {}".format(interface, output))

    fault_count = 0
    for error_info in output:
        if error_info['port errors'] == fault_type:
            fault_count = int(error_info['count'])
            break
    
    logging.info("{} count on {}: {}".format(fault_type, interface, fault_count))
    return fault_count


def get_interface_status(dut, interface):
    """Retrieve the operational status of an interface"""
    return dut.show_and_parse("show interfaces status {}".format(interface))[0].get("oper", "unknown")


@pytest.fixture
def select_random_interface(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    """Fixture to select a random interface for testing"""
    dut = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    interfaces = list(dut.show_and_parse("show interfaces status"))
    return dut, random.choice(interfaces)["interface"]


def test_mac_local_fault_increment(select_random_interface):
    """
    @Summary: Verify MAC local fault count increments when toggling low-power mode on DUT.
    """
    dut, interface = select_random_interface

    # Get initial MAC local fault count
    local_fault_before = get_mac_fault_count(dut, interface, "mac local fault")
    logging.info("Initial MAC local fault count on {}: {}".format(interface, local_fault_before))

    # Toggle low-power mode ON (on the DUT itself)
    dut.shell("sudo sfputil lpmode on {}".format(interface))
    time.sleep(5)
    pytest_assert(get_interface_status(dut, interface) == "down", 
                  "Interface {} did not go down after enabling low-power mode".format(interface))

    # Toggle low-power mode OFF
    dut.shell("sudo sfputil lpmode off {}".format(interface))
    time.sleep(20)
    pytest_assert(get_interface_status(dut, interface) == "up", 
                  "Interface {} did not come up after disabling low-power mode".format(interface))

    # Get new MAC local fault count
    local_fault_after = get_mac_fault_count(dut, interface, "mac local fault")
    logging.info("MAC local fault count after toggling low-power mode on {}: {}".format(interface, local_fault_after))

    # Verify local fault count incremented
    pytest_assert(local_fault_after > local_fault_before, 
                  "MAC local fault count did not increment after toggling low-power mode")


def test_mac_remote_fault_increment(select_random_interface, rand_one_dut_hostname, nbrhosts):
    """
    @Summary: Verify MAC remote fault count increments when toggling low-power mode on the remote neighbor.
    """
    dut, interface = select_random_interface
    remote_host = nbrhosts[rand_one_dut_hostname]  # Remote device connected to DUT

    # Get initial MAC remote fault count on DUT
    remote_fault_before = get_mac_fault_count(dut, interface, "mac remote fault")
    logging.info("Initial MAC remote fault count on {}: {}".format(interface, remote_fault_before))

    # Toggle low-power mode ON on the remote device (not the DUT)
    remote_host.shell("sudo sfputil lpmode on {}".format(interface))
    time.sleep(5)

    # Toggle low-power mode OFF on the remote device
    remote_host.shell("sudo sfputil lpmode off {}".format(interface))
    time.sleep(20)

    # Get new MAC remote fault count on DUT
    remote_fault_after = get_mac_fault_count(dut, interface, "mac remote fault")
    logging.info("MAC remote fault count after toggling low-power mode on {}: {}".format(interface, remote_fault_after))

    # Verify remote fault count incremented
    pytest_assert(remote_fault_after > remote_fault_before, 
                  "MAC remote fault count did not increment after toggling low-power mode on remote device")

