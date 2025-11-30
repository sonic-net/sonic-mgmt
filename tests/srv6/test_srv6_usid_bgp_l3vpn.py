"""
SRv6 uSID BGP L3VPN Test Suite

This module tests the configuration and operation of SRv6 uSID in BGP L3VPN scenarios
between DUT and neighbor devices.

Test coverage includes:
- BGP SRv6 uSID L3VPN setup and configuration
- Route propagation verification in APPL_DB
- SRv6 SID list and MY_SID table validation
- Configuration cleanup and verification
"""

import logging
import time

import pytest
from tests.common.config_reload import config_reload
from tests.common.helpers.assertions import pytest_assert as py_assert
from tests.common.utilities import wait_until
from srv6_utils import (
    verify_appl_db_route_entry_exist,
    verify_appl_db_sid_entry_exist,
    verify_appl_db_sid_list_entry_exist,
)

# Test topology markers
pytestmark = [
    pytest.mark.topology('t0', 't0-sonic')
]

logger = logging.getLogger(__name__)

# IPv6 prefix constants for test network configuration
V6_PREFIX_NBR = "2001:db8:1::"  # Neighbor IPv6 prefix
V6_MASK_NBR = "64"              # Neighbor subnet mask

V6_PREFIX_DUT = "2001:db8:2::"  # DUT IPv6 prefix
V6_MASK_DUT = "64"              # DUT subnet mask

# SRv6 locator configuration constants
SRV6_LOCATOR_NAME = "MAIN"
NBR_LOCATOR_PREFIX = "fcbb:bbbb:1::/48"
DUT_LOCATOR_PREFIX = "fcbb:bbbb:2::/48"
NBR_LOOPBACK_IP = "fcbb:bbbb:1::1/48"
DUT_LOOPBACK_IP = "fcbb:bbbb:2::1/48"
SRV6_SID_FORMAT = "usid-f3216"

# VRF and BGP constants
VRF_NAME = "Vrf10"
RT_VPNV6 = "99:99"
RD_NBR = "1:10"
RD_DUT = "2:10"

# Timeout and retry settings
VERIFICATION_TIMEOUT = 60  # seconds
VERIFICATION_INTERVAL = 2  # seconds


@pytest.fixture(scope="module")
def setup_teardown(nbrhosts, duthosts, enum_frontend_dut_hostname, request):
    """
    Fixture to set up the test environment for SRv6 uSID BGP L3VPN testing.
    
    This fixture:
    - Validates the neighbor type is 'sonic'
    - Selects the DUT and a T1 neighbor for testing
    - Provides the neighbor and DUT hosts to test functions
    - Restores original configuration after test completion
    
    Args:
        nbrhosts: Dictionary of neighbor hosts
        duthosts: Dictionary of DUT hosts
        enum_frontend_dut_hostname: Hostname of the frontend DUT
        request: Pytest request object
        
    Yields:
        tuple: (neighbor_host, duthost) pair for test execution
        
    Raises:
        pytest.skip: If neighbor_type is not 'sonic'
        AssertionError: If no T1 neighbor is found
    """
    logger.info("=" * 80)
    logger.info("FIXTURE SETUP: Initializing SRv6 uSID test environment")
    logger.info("=" * 80)

    # Verify neighbors are type sonic (required for this test)
    neighbor_type = request.config.getoption("neighbor_type")
    logger.info(f"Verifying neighbor type: {neighbor_type}")
    if neighbor_type != "sonic":
        logger.warning(f"Skipping test - unsupported neighbor type: {neighbor_type}")
        pytest.skip(f"Unsupported neighbor type: {neighbor_type}. This test requires 'sonic' neighbors.")

    # Select the DUT from available hosts
    logger.info(f"Selecting DUT: {enum_frontend_dut_hostname}")
    duthost = duthosts[enum_frontend_dut_hostname]
    logger.info(f"DUT selected successfully: {duthost.hostname}")

    # Select a T1 neighbor for the test
    nbr = None
    nbrnames = list(nbrhosts.keys())
    logger.info(f"Available neighbors: {nbrnames}")
    for name in nbrnames:
        if 'T1' in name:
            logger.info(f"Selected T1 neighbor: {name}")
            nbr = nbrhosts[name]
            break
    
    py_assert(nbr is not None, f"No T1 neighbors found in: {nbrnames}")

    logger.info("Fixture setup completed successfully")
    logger.info(f"Test pair: DUT={duthost.hostname}, Neighbor={nbr['host'].hostname}")

    yield (nbr, duthost)

    logger.info("=" * 80)
    logger.info("FIXTURE TEARDOWN: Restoring original configuration")
    logger.info("=" * 80)

    # Restore original config on both devices to ensure clean state
    try:
        logger.info("Reloading neighbor configuration...")
        nbr['host'].shell("config reload -y")
        logger.info("Reloading DUT configuration...")
        config_reload(duthost, wait_for_bgp=True)
        logger.info("Configuration restore completed successfully")
    except Exception as e:
        logger.error(f"Error during configuration restore: {str(e)}")
        raise


def setup_bgp_srv6_usid_l3vpn(duthost, nbr):
    """
    Configure BGP SRv6 uSID L3VPN between DUT and neighbor device.
    
    This function performs comprehensive configuration including:
    - VRF creation on both devices
    - Loopback interface configuration
    - SRv6 locator setup
    - BGP address families (IPv6 unicast and VPNv6)
    - Route targets and route distinguishers
    - VPN import/export policies
    
    Args:
        duthost: DUT host object with shell command capabilities
        nbr: Neighbor host dictionary with 'host' and 'conf' keys
        
    Raises:
        Exception: If any configuration command fails
    """
    logger.info("=" * 80)
    logger.info("SETUP: Configuring BGP SRv6 uSID L3VPN")
    logger.info("=" * 80)
    start_time = time.time()

    # ========== NEIGHBOR CONFIGURATION ==========
    logger.info(f"Step 1/2: Configuring neighbor device - {nbr['host'].hostname}")
    
    # Create VRF on neighbor
    logger.info(f"  -> Creating VRF '{VRF_NAME}' on neighbor")
    nbr['host'].shell(f"config vrf add {VRF_NAME}")
    
    # Configure loopback interface on neighbor
    logger.info(f"  -> Configuring Loopback0 interface: {NBR_LOOPBACK_IP}")
    nbr['host'].shell(f"config interface ip add Loopback0 {NBR_LOOPBACK_IP}")

    # Configure BGP and SRv6 on neighbor via vtysh
    logger.info("  -> Configuring BGP and SRv6 via vtysh")
    peer_ip = nbr['conf']['bgp']['peers'][next(iter(nbr['conf']['bgp']['peers']))][1]
    asn = nbr['conf']['bgp']['asn']
    logger.info(f"     - BGP ASN: {asn}")
    logger.info(f"     - BGP Peer IPv6: {peer_ip}")
    logger.info(f"     - SRv6 Locator: {SRV6_LOCATOR_NAME} ({NBR_LOCATOR_PREFIX})")
    logger.info(f"     - VRF Network: {V6_PREFIX_NBR}/{V6_MASK_NBR}")
    logger.info(f"     - Route Target: {RT_VPNV6}")
    logger.info(f"     - Route Distinguisher: {RD_NBR}")

    cmd = (
        "vtysh"
        " -c 'configure'"
        " -c 'no ipv6 protocol bgp route-map RM_SET_SRC6'"
        " -c 'segment-routing'"
        " -c 'srv6'"
        " -c 'locators'"
        f" -c 'locator {SRV6_LOCATOR_NAME}'"
        f" -c 'prefix {NBR_LOCATOR_PREFIX}'"
        f" -c 'format {SRV6_SID_FORMAT}'"
        " -c 'behavior usid'"
        " -c 'exit'"
        " -c 'exit'"
        " -c 'exit'"
        " -c 'exit'"
        f" -c 'router bgp {asn}'"
        " -c 'bgp disable-ebgp-connected-route-check'"
        " -c 'address-family ipv6 unicast'"
        f" -c 'network {NBR_LOCATOR_PREFIX}'"
        " -c 'exit-address-family'"
        " -c 'address-family ipv6 vpn'"
        f" -c 'neighbor {peer_ip} activate'"
        " -c 'exit-address-family'"
        " -c 'segment-routing srv6'"
        f" -c 'locator {SRV6_LOCATOR_NAME}'"
        " -c 'exit'"
        f" -c 'router bgp {asn} vrf {VRF_NAME}'"
        " -c 'no bgp network import-check'"
        " -c 'address-family ipv6 unicast'"
        f" -c 'network {V6_PREFIX_NBR}/{V6_MASK_NBR}'"
        " -c 'sid vpn export auto'"
        f" -c 'rd vpn export {RD_NBR}'"
        f" -c 'rt vpn both {RT_VPNV6}'"
        " -c 'import vpn'"
        " -c 'export vpn'"
        " -c 'exit'"
        " -c 'exit'"
    )

    logger.debug(f"  -> Executing vtysh command ({len(cmd)} bytes)")
    nbr['host'].shell(cmd)
    logger.info("  -> Neighbor BGP/SRv6 configuration completed successfully")

    # ========== DUT CONFIGURATION ==========
    logger.info(f"Step 2/2: Configuring DUT device - {duthost.hostname}")
    
    # Create VRF on DUT
    logger.info(f"  -> Creating VRF '{VRF_NAME}' on DUT")
    duthost.shell(f"config vrf add {VRF_NAME}")
    
    # Configure loopback interface on DUT
    logger.info(f"  -> Configuring Loopback0 interface: {DUT_LOOPBACK_IP}")
    duthost.shell(f"config interface ip add Loopback0 {DUT_LOOPBACK_IP}")

    # Configure BGP and SRv6 on DUT via vtysh
    logger.info("  -> Configuring BGP and SRv6 via vtysh")
    dut_asn = list(nbr['conf']['bgp']['peers'].keys())[0]
    dut_peer_ip = nbr['conf']['interfaces']['Port-Channel1']['ipv6'].split('/')[0]
    logger.info(f"     - BGP ASN: {dut_asn}")
    logger.info(f"     - BGP Peer IPv6: {dut_peer_ip}")
    logger.info(f"     - SRv6 Locator: {SRV6_LOCATOR_NAME} ({DUT_LOCATOR_PREFIX})")
    logger.info(f"     - VRF Network: {V6_PREFIX_DUT}/{V6_MASK_DUT}")
    logger.info(f"     - Route Target: {RT_VPNV6}")
    logger.info(f"     - Route Distinguisher: {RD_DUT}")
    cmd = (
        "vtysh"
        " -c 'configure'"
        " -c 'no ipv6 protocol bgp route-map RM_SET_SRC6'"
        " -c 'segment-routing'"
        " -c 'srv6'"
        " -c 'locators'"
        f" -c 'locator {SRV6_LOCATOR_NAME}'"
        f" -c 'prefix {DUT_LOCATOR_PREFIX}'"
        f" -c 'format {SRV6_SID_FORMAT}'"
        " -c 'behavior usid'"
        " -c 'exit'"
        " -c 'exit'"
        " -c 'exit'"
        " -c 'exit'"
        f" -c 'router bgp {dut_asn}'"
        " -c 'bgp disable-ebgp-connected-route-check'"
        " -c 'address-family ipv6 unicast'"
        f" -c 'network {DUT_LOCATOR_PREFIX}'"
        " -c 'exit-address-family'"
        " -c 'address-family ipv6 vpn'"
        f" -c 'neighbor {dut_peer_ip} activate'"
        " -c 'exit-address-family'"
        " -c 'segment-routing srv6'"
        f" -c 'locator {SRV6_LOCATOR_NAME}'"
        " -c 'exit'"
        f" -c 'router bgp {dut_asn} vrf {VRF_NAME}'"
        " -c 'no bgp network import-check'"
        " -c 'address-family ipv6 unicast'"
        f" -c 'network {V6_PREFIX_DUT}/{V6_MASK_DUT}'"
        " -c 'sid vpn export auto'"
        f" -c 'rd vpn export {RD_DUT}'"
        f" -c 'rt vpn both {RT_VPNV6}'"
        " -c 'import vpn'"
        " -c 'export vpn'"
        " -c 'exit'"
        " -c 'exit'"
    )

    logger.debug(f"  -> Executing vtysh command ({len(cmd)} bytes)")
    duthost.shell(cmd)
    logger.info("  -> DUT BGP/SRv6 configuration completed successfully")
    
    elapsed_time = time.time() - start_time
    logger.info("=" * 80)
    logger.info(f"SETUP COMPLETED in {elapsed_time:.2f} seconds")
    logger.info("=" * 80)


def cleanup_bgp_srv6_usid_l3vpn(duthost, nbr):
    """
    Remove BGP SRv6 uSID L3VPN configuration from DUT and neighbor.
    
    This function reverses all configuration changes made by setup_bgp_srv6_usid_l3vpn,
    including:
    - BGP VPNv6 and SRv6 configuration removal
    - SRv6 locator deletion
    - Loopback interface removal
    - VRF deletion
    
    Args:
        duthost: DUT host object with shell command capabilities
        nbr: Neighbor host dictionary with 'host' and 'conf' keys
        
    Raises:
        Exception: If any cleanup command fails
    """
    logger.info("=" * 80)
    logger.info("CLEANUP: Removing BGP SRv6 uSID L3VPN configuration")
    logger.info("=" * 80)
    start_time = time.time()

    # ========== NEIGHBOR CLEANUP ==========
    logger.info(f"Step 1/2: Cleaning up neighbor device - {nbr['host'].hostname}")
    
    # Remove BGP and SRv6 configuration via vtysh
    logger.info("  -> Removing BGP and SRv6 configuration via vtysh")
    peer_ip = nbr['conf']['bgp']['peers'][next(iter(nbr['conf']['bgp']['peers']))][1]
    asn = nbr['conf']['bgp']['asn']

    cmd = (
        "vtysh"
        " -c 'configure'"
        " -c 'ipv6 protocol bgp route-map RM_SET_SRC6'"
        " -c 'segment-routing'"
        " -c 'srv6'"
        " -c 'locators'"
        f" -c 'no locator {SRV6_LOCATOR_NAME}'"
        " -c 'exit'"
        " -c 'exit'"
        " -c 'exit'"
        f" -c 'router bgp {asn}'"
        " -c 'no bgp disable-ebgp-connected-route-check'"
        " -c 'address-family ipv6 unicast'"
        f" -c 'no network {NBR_LOCATOR_PREFIX}'"
        " -c 'exit-address-family'"
        " -c 'address-family ipv6 vpn'"
        f" -c 'no neighbor {peer_ip} activate'"
        " -c 'exit-address-family'"
        " -c 'segment-routing srv6'"
        f" -c 'no locator {SRV6_LOCATOR_NAME}'"
        " -c 'exit'"
        f" -c 'router bgp {asn} vrf {VRF_NAME}'"
        " -c 'bgp network import-check'"
        " -c 'address-family ipv6 unicast'"
        f" -c 'no network {V6_PREFIX_NBR}/{V6_MASK_NBR}'"
        " -c 'no sid vpn export auto'"
        f" -c 'no rd vpn export {RD_NBR}'"
        f" -c 'no rt vpn both {RT_VPNV6}'"
        " -c 'no import vpn'"
        " -c 'no export vpn'"
        " -c 'exit'"
        " -c 'exit'"
    )
    logger.debug(f"  -> Executing vtysh cleanup command ({len(cmd)} bytes)")
    nbr['host'].shell(cmd)
    
    # Remove loopback interface
    logger.info(f"  -> Removing Loopback0 interface: {NBR_LOOPBACK_IP}")
    nbr['host'].shell(f"config interface ip remove Loopback0 {NBR_LOOPBACK_IP}")
    
    # Remove VRF
    logger.info(f"  -> Removing VRF '{VRF_NAME}'")
    nbr['host'].shell(f"config vrf del {VRF_NAME}")
    logger.info("  -> Neighbor cleanup completed successfully")

    # ========== DUT CLEANUP ==========
    logger.info(f"Step 2/2: Cleaning up DUT device - {duthost.hostname}")
    
    # Remove BGP and SRv6 configuration via vtysh
    logger.info("  -> Removing BGP and SRv6 configuration via vtysh")
    dut_asn = list(nbr['conf']['bgp']['peers'].keys())[0]
    dut_peer_ip = nbr['conf']['interfaces']['Port-Channel1']['ipv6'].split('/')[0]

    cmd = (
        "vtysh"
        " -c 'configure'"
        " -c 'ipv6 protocol bgp route-map RM_SET_SRC6'"
        " -c 'segment-routing'"
        " -c 'srv6'"
        " -c 'locators'"
        f" -c 'no locator {SRV6_LOCATOR_NAME}'"
        " -c 'exit'"
        " -c 'exit'"
        " -c 'exit'"
        f" -c 'router bgp {dut_asn}'"
        " -c 'no bgp disable-ebgp-connected-route-check'"
        " -c 'address-family ipv6 unicast'"
        f" -c 'no network {DUT_LOCATOR_PREFIX}'"
        " -c 'exit-address-family'"
        " -c 'address-family ipv6 vpn'"
        f" -c 'no neighbor {dut_peer_ip} activate'"
        " -c 'exit-address-family'"
        " -c 'segment-routing srv6'"
        f" -c 'no locator {SRV6_LOCATOR_NAME}'"
        " -c 'exit'"
        f" -c 'router bgp {dut_asn} vrf {VRF_NAME}'"
        " -c 'no bgp network import-check'"
        " -c 'address-family ipv6 unicast'"
        f" -c 'no network {V6_PREFIX_DUT}/{V6_MASK_DUT}'"
        " -c 'no sid vpn export auto'"
        f" -c 'no rd vpn export {RD_DUT}'"
        f" -c 'no rt vpn both {RT_VPNV6}'"
        " -c 'no import vpn'"
        " -c 'no export vpn'"
        " -c 'exit'"
        " -c 'exit'"
    )

    logger.debug(f"  -> Executing vtysh cleanup command ({len(cmd)} bytes)")
    duthost.shell(cmd)
    
    # Remove loopback interface
    logger.info(f"  -> Removing Loopback0 interface: {DUT_LOOPBACK_IP}")
    duthost.shell(f"config interface ip remove Loopback0 {DUT_LOOPBACK_IP}")
    
    # Remove VRF
    logger.info(f"  -> Removing VRF '{VRF_NAME}'")
    duthost.shell(f"config vrf del {VRF_NAME}")
    logger.info("  -> DUT cleanup completed successfully")
    
    elapsed_time = time.time() - start_time
    logger.info("=" * 80)
    logger.info(f"CLEANUP COMPLETED in {elapsed_time:.2f} seconds")
    logger.info("=" * 80)


def run_srv6_usid_bgp_l3vpn(enum_frontend_dut_hostname, hosts):
    """
    Execute the main test logic for SRv6 uSID BGP L3VPN functionality.
    
    This function orchestrates the complete test workflow:
    1. Setup: Configure BGP SRv6 uSID L3VPN on both DUT and neighbor
    2. Verification: Validate route propagation and SRv6 table entries
    3. Cleanup: Remove all configuration
    4. Cleanup Verification: Ensure all entries are properly removed
    
    The test validates:
    - ROUTE_TABLE entries with correct segment information
    - SRV6_SID_LIST_TABLE entries with proper path configuration
    - SRV6_MY_SID_TABLE entries with udt6 action and VRF binding
    - Complete cleanup of all SRv6-related entries
    
    Args:
        enum_frontend_dut_hostname: Hostname of the frontend DUT
        hosts: Tuple containing (neighbor_host, duthost)
        
    Raises:
        AssertionError: If any verification step fails
    """
    nbr = hosts[0]
    duthost = hosts[1]

    logger.info("")
    logger.info("#" * 80)
    logger.info("# TEST EXECUTION: SRv6 uSID BGP L3VPN Route Propagation")
    logger.info("#" * 80)
    logger.info("")

    # ========== SETUP PHASE ==========
    setup_bgp_srv6_usid_l3vpn(duthost, nbr)

    # ========== VERIFICATION PHASE ==========
    logger.info("")
    logger.info("=" * 80)
    logger.info("VERIFICATION PHASE: Checking DUT APPL_DB entries")
    logger.info("=" * 80)
    logger.info("")

    # Test 1: Verify ROUTE_TABLE entry
    route_key = f"ROUTE_TABLE:{VRF_NAME}:{V6_PREFIX_NBR}/{V6_MASK_NBR}"
    expected_segment = "fcbb:bbbb:1:e000::"
    
    logger.info("Test 1: Verifying ROUTE_TABLE entry")
    logger.info(f"  Route key: {route_key}")
    logger.info(f"  Expected segment: {expected_segment}")
    
    assert wait_until(
        VERIFICATION_TIMEOUT, VERIFICATION_INTERVAL, 0,
        verify_appl_db_route_entry_exist, duthost, "sonic-db-cli", route_key, True
    ), f"Route entry '{route_key}' is missing in APPL_DB after {VERIFICATION_TIMEOUT}s"
    logger.info("  ✓ Route entry exists in ROUTE_TABLE")
    
    actual_segment = duthost.command(
        f"sonic-db-cli APPL_DB hget {route_key} segment"
    )["stdout"]
    assert actual_segment == expected_segment, \
        f"Route segment mismatch: expected '{expected_segment}', got '{actual_segment}'"
    logger.info(f"  ✓ Route segment verified: {actual_segment}")
    logger.info("Test 1: PASSED ✓")

    # Test 2: Verify SRV6_SID_LIST_TABLE entry
    sid_list_key = f"SRV6_SID_LIST_TABLE:{expected_segment}"
    
    logger.info("")
    logger.info("Test 2: Verifying SRV6_SID_LIST_TABLE entry")
    logger.info(f"  SID list key: {sid_list_key}")
    
    assert wait_until(
        VERIFICATION_TIMEOUT, VERIFICATION_INTERVAL, 0,
        verify_appl_db_sid_list_entry_exist, duthost, "sonic-db-cli", sid_list_key, True
    ), f"SID list entry '{sid_list_key}' is missing in APPL_DB after {VERIFICATION_TIMEOUT}s"
    logger.info("  ✓ SID list entry exists in SRV6_SID_LIST_TABLE")
    
    actual_path = duthost.command(
        f"sonic-db-cli APPL_DB hget {sid_list_key} path"
    )["stdout"]
    assert actual_path == expected_segment, \
        f"SID list path mismatch: expected '{expected_segment}', got '{actual_path}'"
    logger.info(f"  ✓ SID list path verified: {actual_path}")
    logger.info("Test 2: PASSED ✓")

    # Test 3: Verify SRV6_MY_SID_TABLE entry
    my_sid_key = "SRV6_MY_SID_TABLE:32:16:16:0:fcbb:bbbb:2:e000::"
    expected_action = "udt6"
    expected_vrf = VRF_NAME
    
    logger.info("")
    logger.info("Test 3: Verifying SRV6_MY_SID_TABLE entry")
    logger.info(f"  MY_SID key: {my_sid_key}")
    logger.info(f"  Expected action: {expected_action}")
    logger.info(f"  Expected VRF: {expected_vrf}")
    
    assert wait_until(
        VERIFICATION_TIMEOUT, VERIFICATION_INTERVAL, 0,
        verify_appl_db_sid_entry_exist, duthost, "sonic-db-cli", my_sid_key, True
    ), f"MY_SID entry '{my_sid_key}' is missing in APPL_DB after {VERIFICATION_TIMEOUT}s"
    logger.info("  ✓ MY_SID entry exists in SRV6_MY_SID_TABLE")
    
    actual_action = duthost.command(
        f"sonic-db-cli APPL_DB hget {my_sid_key} action"
    )["stdout"]
    assert actual_action == expected_action, \
        f"MY_SID action mismatch: expected '{expected_action}', got '{actual_action}'"
    logger.info(f"  ✓ MY_SID action verified: {actual_action}")
    
    actual_vrf = duthost.command(
        f"sonic-db-cli APPL_DB hget {my_sid_key} vrf"
    )["stdout"]
    assert actual_vrf == expected_vrf, \
        f"MY_SID VRF mismatch: expected '{expected_vrf}', got '{actual_vrf}'"
    logger.info(f"  ✓ MY_SID VRF verified: {actual_vrf}")
    logger.info("Test 3: PASSED ✓")

    # ========== CLEANUP PHASE ==========
    logger.info("")
    cleanup_bgp_srv6_usid_l3vpn(duthost, nbr)

    # ========== CLEANUP VERIFICATION PHASE ==========
    logger.info("")
    logger.info("=" * 80)
    logger.info("CLEANUP VERIFICATION: Ensuring all entries are removed from APPL_DB")
    logger.info("=" * 80)
    logger.info("")

    # Test 4: Verify ROUTE_TABLE cleanup
    logger.info("Test 4: Verifying ROUTE_TABLE cleanup")
    logger.info(f"  Checking removal of: {route_key}")
    
    assert wait_until(
        VERIFICATION_TIMEOUT, VERIFICATION_INTERVAL, 0,
        verify_appl_db_sid_entry_exist, duthost, "sonic-db-cli", route_key, False
    ), f"Route entry '{route_key}' was not properly cleaned up from APPL_DB"
    logger.info("  ✓ Route successfully removed from ROUTE_TABLE")
    logger.info("Test 4: PASSED ✓")

    # Test 5: Verify SRV6_SID_LIST_TABLE cleanup
    logger.info("")
    logger.info("Test 5: Verifying SRV6_SID_LIST_TABLE cleanup")
    logger.info(f"  Checking removal of: {sid_list_key}")
    
    assert wait_until(
        VERIFICATION_TIMEOUT, VERIFICATION_INTERVAL, 0,
        verify_appl_db_sid_entry_exist, duthost, "sonic-db-cli", sid_list_key, False
    ), f"SID list entry '{sid_list_key}' was not properly cleaned up from APPL_DB"
    logger.info("  ✓ SID list successfully removed from SRV6_SID_LIST_TABLE")
    logger.info("Test 5: PASSED ✓")

    # Test 6: Verify SRV6_MY_SID_TABLE cleanup
    logger.info("")
    logger.info("Test 6: Verifying SRV6_MY_SID_TABLE cleanup")
    logger.info(f"  Checking removal of: {my_sid_key}")
    
    assert wait_until(
        VERIFICATION_TIMEOUT, VERIFICATION_INTERVAL, 0,
        verify_appl_db_sid_entry_exist, duthost, "sonic-db-cli", my_sid_key, False
    ), f"MY_SID entry '{my_sid_key}' was not properly cleaned up from APPL_DB"
    logger.info("  ✓ MY_SID successfully removed from SRV6_MY_SID_TABLE")
    logger.info("Test 6: PASSED ✓")
    
    # ========== TEST SUMMARY ==========
    logger.info("")
    logger.info("#" * 80)
    logger.info("# TEST SUITE COMPLETED SUCCESSFULLY")
    logger.info("# All 6 tests passed:")
    logger.info("#   - 3 configuration verification tests")
    logger.info("#   - 3 cleanup verification tests")
    logger.info("#" * 80)
    logger.info("")


def test_srv6_usid_bgp_l3vpn(enum_frontend_dut_hostname, setup_teardown):
    """
    Pytest entry point for SRv6 uSID BGP L3VPN test.
    
    This is the main test function invoked by pytest. It delegates to
    run_srv6_usid_bgp_l3vpn() for the actual test execution.
    
    Args:
        enum_frontend_dut_hostname: Hostname of the frontend DUT (from pytest fixture)
        setup_teardown: Test environment fixture providing (neighbor, duthost) tuple
        
    Raises:
        AssertionError: If any test verification fails
    """
    logger.info("=" * 80)
    logger.info("Starting test: test_srv6_usid_bgp_l3vpn")
    logger.info(f"DUT: {enum_frontend_dut_hostname}")
    logger.info("=" * 80)
    
    try:
        run_srv6_usid_bgp_l3vpn(enum_frontend_dut_hostname, setup_teardown)
    except Exception as e:
        logger.error(f"Test failed with error: {str(e)}")
        raise
    finally:
        logger.info("=" * 80)
        logger.info("Test execution completed: test_srv6_usid_bgp_l3vpn")
        logger.info("=" * 80)
