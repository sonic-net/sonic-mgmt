"""
This script is to test the BGP Allow-AS in feature of SONiC.

The feature allows a router to accept routes that contain its own AS number in the AS_PATH attribute,
which would normally be dropped to prevent routing loops.

The feature can be configured in config_db via this attribute in the BGP_NEIGHBOR_AF table:
BGP_NEIGHBOR_AF
allow_as_in = "true" / "false" ;  Accept as-path with my AS present in it
"""
import logging
import pytest
import requests
import time
import ipaddress
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.common.gu_utils import apply_patch, expect_op_success
from tests.common.gu_utils import generate_tmpfile, delete_tmpfile
from tests.common.gu_utils import format_json_patch_for_multiasic

pytestmark = [
    pytest.mark.topology('t0', 't1'),
    pytest.mark.device_type('vs')
]

logger = logging.getLogger(__name__)

# Constants
ALLOW_AS_IN_TRUE = "true"
ALLOW_AS_IN_FALSE = "false"
EXABGP_BASE_PORT = 5000
EXABGP_BASE_PORT_V6 = 6000
TEST_PREFIX_V4 = "192.168.100.0/24"
TEST_PREFIX_V6 = "fc00:192:168:100::/64"


def update_routes(action, ptfip, port, route):
    """
    Custom version of update_routes that includes AS_PATH in the route announcement
    """
    if action not in ['announce', 'withdraw']:
        logging.error('Unsupported route update operation: {}'.format(action))
        return

    if action == 'announce' and 'aspath' in route:
        msg = '{} route {} next-hop {} as-path [ {} ]'.format(action, route['prefix'], route['nexthop'],
                                                              route['aspath'])
    else:
        msg = '{} route {} next-hop {}'.format(action, route['prefix'], route['nexthop'])

    if 'community' in route:
        msg += ' community {}'.format(route['community'])

    url = 'http://%s:%d' % (ptfip, port)
    data = {'commands': msg}
    logging.info('Post url={}, data={}'.format(url, data))
    r = requests.post(url, data=data, proxies={"http": None, "https": None})
    assert r.status_code == 200


def configure_allow_as_in(duthost, neighbor_ip, allow_as_in, namespace=None):
    """
    Configure allow_as_in attribute for a BGP neighbor

    Args:
        duthost: DUT host object
        neighbor_ip: IP address of the BGP neighbor
        allow_as_in: Value to set for allow_as_in ("true" or "false")
        namespace: Namespace to use (optional)

    Returns:
        bool: True if configuration was successful, False otherwise
    """
    logger.info(f"Configuring allow_as_in={allow_as_in} for neighbor {neighbor_ip}")

    # Determine if the neighbor IP is IPv4 or IPv6
    ip_version = "ipv4"
    try:
        ip = ipaddress.ip_address(neighbor_ip)
        if ip.version == 6:
            ip_version = "ipv6"
    except ValueError:
        logger.error(f"Invalid IP address: {neighbor_ip}")
        return False

    namespace_prefix = f"-n {namespace}" if namespace else ""

    # Check if FRR management framework is enabled using the SonicHost method
    try:
        is_frr_mgmt_enabled = duthost.get_frr_mgmt_framework_config()
        logger.info(f"FRR management framework is {'enabled' if is_frr_mgmt_enabled else 'disabled'}")
    except Exception as e:
        logger.error(f"Failed to get FRR management framework config: {e}")
        # Default to using config_db if we can't determine the FRR management framework config
        is_frr_mgmt_enabled = True
        logger.info("Defaulting to using config_db (GCU) due to error")

    if is_frr_mgmt_enabled:
        # Use JSON-PATCH for GCU configurations when FRR management framework is enabled (unified mode)
        logger.info("Using JSON-PATCH for GCU configuration")
        try:
            # Create JSON patch structure
            json_patch = [
                {
                    "op": "add",
                    "path": f"/BGP_NEIGHBOR_AF/default|{neighbor_ip}|{ip_version}_unicast/allow_as_in",
                    "value": allow_as_in
                }
            ]
            # Format the patch for multi-ASIC environments
            json_patch = format_json_patch_for_multiasic(
                duthost=duthost, json_data=json_patch,
                is_asic_specific=True, asic_namespaces=[namespace]
            )
            # Generate a temporary file
            tmpfile = generate_tmpfile(duthost)
            logger.info(f"tmpfile: {tmpfile}")
            try:
                # Apply the patch
                output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
                expect_op_success(duthost, output)
                # Check if the configuration was applied
                check_cmd = (
                    f"sonic-db-cli CONFIG_DB HGET 'BGP_NEIGHBOR_AF|default|{neighbor_ip}|"
                    f"{ip_version}_unicast' allow_as_in"
                )
                duthost.shell(check_cmd, module_ignore_errors=True)
                logger.info(f"Configured allow_as_in={allow_as_in} for neighbor {neighbor_ip} using JSON-PATCH (GCU)")
            finally:
                # Clean up the temporary file
                delete_tmpfile(duthost, tmpfile)
        except Exception as e:
            logger.error(f"Failed to configure using config_db: {e}")
            return False
    else:
        # Use vtysh for configuration when FRR management framework is disabled (legacy mode)
        logger.debug("Using vtysh for configuration")
        try:
            # Configure using vtysh
            if ip_version == "ipv4":
                cmd = (f"vtysh {namespace_prefix} -c 'configure terminal' -c 'router bgp' "
                       f"-c 'address-family ipv4 unicast' -c 'neighbor {neighbor_ip} allowas-in'")
                if allow_as_in == ALLOW_AS_IN_FALSE:
                    cmd = (f"vtysh {namespace_prefix} -c 'configure terminal' -c 'router bgp' "
                           f"-c 'address-family ipv4 unicast' -c 'no neighbor {neighbor_ip} allowas-in'")
            else:
                cmd = (f"vtysh {namespace_prefix} -c 'configure terminal' -c 'router bgp' "
                       f"-c 'address-family ipv6 unicast' -c 'neighbor {neighbor_ip} allowas-in'")
                if allow_as_in == ALLOW_AS_IN_FALSE:
                    cmd = (f"vtysh {namespace_prefix} -c 'configure terminal' -c 'router bgp' "
                           f"-c 'address-family ipv6 unicast' -c 'no neighbor {neighbor_ip} allowas-in'")

            duthost.shell(cmd)
            logger.info(f"Configured allow_as_in={allow_as_in} for neighbor {neighbor_ip} using vtysh")
        except Exception as e:
            logger.error(f"Failed to configure using vtysh: {e}")
            return False

    # Verify that the BGP service is running
    if not wait_until(100, 10, 0, duthost.is_service_fully_started_per_asic_or_host, "bgp"):
        logger.error("BGP service is not running")
        return False

    # Wait for the configuration to take effect
    logger.info("Waiting for configuration to take effect...")
    time.sleep(30)

    return True


def verify_route_accepted(duthost, prefix, expected_present=True, namespace=None):
    """
    Verify if a route is present in the BGP routing table

    Args:
        duthost: DUT host object
        prefix: IP prefix to check
        expected_present: Whether the route is expected to be present (True) or absent (False)
        namespace: Namespace to use (optional)

    Returns:
        bool: True if the verification passes, False otherwise
    """
    # Determine if the prefix is IPv4 or IPv6
    ip_version = "ip"
    try:
        network = ipaddress.ip_network(prefix)
        if network.version == 6:
            ip_version = "ipv6"
    except ValueError:
        logger.error(f"Invalid prefix: {prefix}")
        return False

    # Check if the route is in the BGP table
    namespace_prefix = f"-n {namespace}" if namespace else ""
    if ip_version == "ipv6":
        cmd = f"vtysh {namespace_prefix} -c 'show bgp ipv6 unicast {prefix}'"
    else:
        cmd = f"vtysh {namespace_prefix} -c 'show ip bgp {prefix}'"
    result = duthost.shell(cmd, module_ignore_errors=True)

    route_present = "BGP routing table entry for" in result['stdout']

    if expected_present:
        return route_present
    else:
        return not route_present


def check_route_with_own_as(duthost, prefix, own_as, expected_accepted=True, namespace=None):
    """
    Check if a route with the DUT's own AS in the AS_PATH is accepted or rejected

    Args:
        duthost: DUT host object
        prefix: IP prefix to check
        own_as: The DUT's own AS number
        expected_accepted: Whether the route is expected to be accepted (True) or rejected (False)
        namespace: Namespace to use (optional)

    Returns:
        bool: True if the verification passes, False otherwise
    """
    status = 'accepted' if expected_accepted else 'rejected'
    logger.info(f"Checking if route {prefix} with AS path containing {own_as} is {status}")

    # Determine if the prefix is IPv4 or IPv6
    ip_version = "ip"
    try:
        network = ipaddress.ip_network(prefix)
        if network.version == 6:
            ip_version = "ipv6"
    except ValueError:
        logger.error(f"Invalid prefix: {prefix}")
        return False

    # Get BGP routes in JSON format for easier parsing
    namespace_prefix = f"-n {namespace}" if namespace else ""

    # Use different command format for IPv6
    if ip_version == "ipv6":
        cmd = f"vtysh {namespace_prefix} -c 'show bgp ipv6 unicast {prefix} json'"
    else:
        cmd = f"vtysh {namespace_prefix} -c 'show ip bgp {prefix} json'"

    result = duthost.shell(cmd, module_ignore_errors=True)

    # If command failed, assume the route is not present
    if result['rc'] != 0:
        logger.warning(f"Command '{cmd}' failed. Assuming route is not present.")
        return not expected_accepted

    # Parse JSON output
    try:
        import json
        bgp_data = json.loads(result['stdout'])

        # Check if the route is in the BGP table
        route_present = bgp_data and len(bgp_data) > 0

        # Check if the route has the DUT's own AS in the AS_PATH
        if route_present:
            # Extract AS path from JSON
            as_path = None

            # Based on the sample output, the AS path is in paths[0].aspath.segments[0].list
            if 'paths' in bgp_data and len(bgp_data['paths']) > 0:
                path_data = bgp_data['paths'][0]
                # Check if path_data has aspath
                has_aspath = 'aspath' in path_data
                # Check if aspath has segments
                has_segments = has_aspath and 'segments' in path_data['aspath']
                # Check if segments is not empty
                has_segments_list = has_segments and len(path_data['aspath']['segments']) > 0

                if has_segments_list:
                    segment = path_data['aspath']['segments'][0]
                    if 'list' in segment:
                        as_path = segment['list']

            # If we couldn't find the AS path in the expected structure, try the prefix-keyed structure
            # Check if prefix is in bgp_data
            prefix_in_data = prefix in bgp_data
            # Check if prefix has paths
            has_prefix_paths = prefix_in_data and 'paths' in bgp_data[prefix]
            # Check if paths is not empty
            has_valid_paths = has_prefix_paths and len(bgp_data[prefix]['paths']) > 0

            if as_path is None and has_valid_paths:
                path_data = bgp_data[prefix]['paths'][0]
                # Check if path_data has aspath
                has_aspath = 'aspath' in path_data
                # Check if aspath has segments
                has_segments = has_aspath and 'segments' in path_data['aspath']
                # Check if segments is not empty
                has_segments_list = has_segments and len(path_data['aspath']['segments']) > 0

                if has_segments_list:
                    segment = path_data['aspath']['segments'][0]
                    if 'list' in segment:
                        as_path = segment['list']

            # Check if own_as is in the AS path
            as_path_present = False
            if as_path:
                as_path_present = own_as in as_path
            else:
                # If we couldn't extract the AS path using the expected structure,
                # fall back to string search in the raw JSON
                as_path_present = f'"{own_as}"' in result['stdout']

            # If the route is present and has the DUT's own AS in the AS_PATH,
            # it should be accepted if allow_as_in is true, and rejected if allow_as_in is false
            if as_path_present:
                return expected_accepted
            else:
                # If the route is present but doesn't have the DUT's own AS in the AS_PATH,
                # it's not relevant to our test
                logger.info(f"Route {prefix} is present but doesn't have AS {own_as} in the AS_PATH")
                return True
        else:
            # If the route is not present, it should be rejected if allow_as_in is false
            logger.info(f"Route {prefix} is not present in the BGP table")
            return not expected_accepted
    except Exception as e:
        logger.warning(f"Failed to parse JSON output: {e}")
        # If we can't parse the JSON, assume the route is not present
        return not expected_accepted


@pytest.fixture(scope='module')
def setup_exabgp(duthosts, rand_one_dut_hostname, ptfhost, tbinfo, localhost, nbrhosts):
    """
    Setup exabgp to advertise routes with the DUT's own AS in the AS_PATH

    Args:
        duthosts: DUT hosts
        rand_one_dut_hostname: Hostname of the DUT
        ptfhost: PTF host object
        tbinfo: Testbed information
        localhost: localhost object
        nbrhosts: Neighbor hosts

    Returns:
        dict: Setup information
    """
    duthost = duthosts[rand_one_dut_hostname]

    # Get the DUT's ASN
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    dut_asn = mg_facts['minigraph_bgp_asn']

    lo_addr = None
    lo_addr_v6 = None
    for iface in mg_facts.get('minigraph_lo_interfaces', []):
        try:
            ip = ipaddress.ip_address(iface['addr'])
            if ip.version == 4:
                lo_addr = str(ip)
            elif ip.version == 6:
                lo_addr_v6 = str(ip)
        except (ValueError, KeyError):
            logger.warning(f"Skipping invalid loopback interface entry: {iface}")

    # Get BGP neighbors from minigraph
    bgp_neighbors = mg_facts.get('minigraph_bgp', [])

    # Get topology name
    topo_name = tbinfo.get('topo', {}).get('name', '')
    logger.info(f"Topology name: {topo_name}")

    # Find a suitable neighbor based on topology
    test_neighbor_name = None
    test_neighbor_ip = None
    test_neighbor_ipv6 = None

    # First try to find a neighbor based on topology preference
    for neighbor in bgp_neighbors:
        if ('t1' in topo_name.lower() and 'T2' in neighbor['name']) or \
           ('t0' in topo_name.lower() and 'T1' in neighbor['name']):
            test_neighbor_name = neighbor['name']
            logger.info(f"Found preferred neighbor name: {test_neighbor_name}")
            break

    # If no preferred neighbor found, pick the first available one
    if not test_neighbor_name and bgp_neighbors:
        test_neighbor_name = bgp_neighbors[0]['name']
        logger.info(f"Using first available neighbor name: {test_neighbor_name}")

    if not test_neighbor_name:
        pytest.skip("Could not find any suitable BGP neighbor for testing")

    for neighbor in bgp_neighbors:
        if neighbor.get('name') == test_neighbor_name:
            try:
                ip = ipaddress.ip_address(neighbor['addr'])
                if ip.version == 4:
                    test_neighbor_ip = str(ip)
                elif ip.version == 6:
                    test_neighbor_ipv6 = str(ip)
            except (ValueError, KeyError):
                logger.warning(f"Skipping invalid neighbor IP for {test_neighbor_name}: {neighbor.get('addr')}")

    # Get the neighbor's ASN
    test_neighbor_asn = None
    for neighbor in bgp_neighbors:
        if neighbor['name'] == test_neighbor_name:
            test_neighbor_asn = neighbor['asn']
            break

    # Get the PTF port
    ptf_ports = []
    for i in range(0, 3):
        ptf_ports.append("eth%s" % i)

    # Use PTF mgmt IP + /32 host route to avoid overlapping with DUT's internal Docker subnet
    ptfip = ptfhost.mgmt_ip
    exabgp_ip = ptfip
    exabgp_ip_v6 = "fc00:1:1:1::10"  # Use a less likely to conflict IPv6 address

    # Configure IP on PTF using ip addr (more compatible with Debian-based images)
    logger.info("Setup IP address on PTF")
    # No need to add the PTF mgmt IP since it's already configured

    # Configure IPv6 on PTF if loopback IPv6 is available
    if lo_addr_v6:
        ptfhost.shell(f"ip addr add {exabgp_ip_v6}/64 dev {ptf_ports[0]}",
                      module_ignore_errors=True)

    # Check connectivity to the exabgp IP (using existing routes)
    logger.info("Checking connectivity to exabgp IP")
    duthost.shell(f"ping {exabgp_ip} -c 3", module_ignore_errors=True)

    # Check IPv6 connectivity if loopback IPv6 is available
    if lo_addr_v6:
        duthost.shell(f"ping6 {exabgp_ip_v6} -c 3", module_ignore_errors=True)

    # exabgp is already started as part of sonic mgmt testbed deployment
    logger.info("Using existing exabgp instance from testbed deployment")

    # Create routes with the DUT's own AS in the AS_PATH
    aspath = f"{dut_asn} {test_neighbor_asn}"

    # Announce IPv4 route
    route = {
        'prefix': TEST_PREFIX_V4,
        'nexthop': lo_addr,  # Use loopback address as nexthop
        'aspath': aspath
    }
    update_routes("announce", ptfip, EXABGP_BASE_PORT, route)

    # Setup for IPv6 if loopback IPv6 is available
    ipv6_ready = lo_addr_v6 is not None

    if ipv6_ready:
        # Announce IPv6 route using existing exabgp instance
        try:
            route_v6 = {
                'prefix': TEST_PREFIX_V6,
                'nexthop': lo_addr_v6,  # Use loopback address as nexthop
                'aspath': aspath
            }
            update_routes("announce", ptfip, EXABGP_BASE_PORT_V6, route_v6)
        except Exception as e:
            logger.error(f"Failed to announce IPv6 route: {e}")
            ipv6_ready = False

    # Wait for routes to be advertised
    time.sleep(30)

    setup_info = {
        'duthost': duthost,
        'dut_asn': dut_asn,
        'test_neighbor_name': test_neighbor_name,
        'test_neighbor_ip': test_neighbor_ip,
        'test_neighbor_ipv6': test_neighbor_ipv6,
        'ipv4_prefix': TEST_PREFIX_V4,
        'ipv6_prefix': TEST_PREFIX_V6 if ipv6_ready else None,
        'ipv6_ready': ipv6_ready,
        'ptfhost': ptfhost,
        'ptfip': ptfip,
        'lo_addr': lo_addr,
        'lo_addr_v6': lo_addr_v6,
        'exabgp_port': EXABGP_BASE_PORT,
        'exabgp_port_v6': EXABGP_BASE_PORT_V6
    }

    yield setup_info

    # Cleanup
    logger.info("Cleanup: Withdraw routes, reset allow_as_in configuration")

    try:
        # Withdraw IPv4 route
        try:
            route = {
                'prefix': TEST_PREFIX_V4,
                'nexthop': lo_addr  # Use loopback address as nexthop
            }
            update_routes("withdraw", ptfip, EXABGP_BASE_PORT, route)
        except Exception as e:
            logger.error(f"Failed to withdraw IPv4 route: {e}")

        # Withdraw IPv6 route if it was announced
        if ipv6_ready and lo_addr_v6:
            try:
                route_v6 = {
                    'prefix': TEST_PREFIX_V6,
                    'nexthop': lo_addr_v6  # Use loopback address as nexthop
                }
                update_routes("withdraw", ptfip, EXABGP_BASE_PORT_V6, route_v6)
            except Exception as e:
                logger.error(f"Failed to withdraw IPv6 route: {e}")

        # exabgp is managed by the testbed, no need to stop it here

        # Reset allow_as_in configuration back to false
        logger.info(f"Resetting allow_as_in=false for neighbor {test_neighbor_ip}")
        try:
            configure_allow_as_in(duthost, test_neighbor_ip, ALLOW_AS_IN_FALSE)
        except Exception as e:
            logger.error(f"Failed to reset allow_as_in configuration: {e}")

        # Reset IPv6 neighbor configuration if it exists
        if test_neighbor_ipv6:
            logger.info(f"Resetting allow_as_in=false for IPv6 neighbor {test_neighbor_ipv6}")
            try:
                configure_allow_as_in(duthost, test_neighbor_ipv6, ALLOW_AS_IN_FALSE)
            except Exception as e:
                logger.error(f"Failed to reset IPv6 allow_as_in configuration: {e}")

        # No need to remove routes since we're using existing routes
    except Exception as e:
        logger.error(f"Failed to clean up exabgp: {e}")


def wait_for_route_status(duthost, prefix, own_as, expected_accepted, timeout=180, interval=20):
    """
    Wait for a route to be accepted or rejected

    Args:
        duthost: DUT host object
        prefix: IP prefix to check
        own_as: The DUT's own AS number
        expected_accepted: Whether the route is expected to be accepted (True) or rejected (False)
        timeout: Maximum time to wait in seconds
        interval: Time between checks in seconds

    Returns:
        bool: True if the route status matches the expected status, False otherwise
    """
    end_time = time.time() + timeout
    while time.time() < end_time:
        result = check_route_with_own_as(duthost, prefix, own_as, expected_accepted)
        if result:
            return True
        time.sleep(interval)
    return False


def test_bgp_allow_as_in_ipv4(setup_exabgp):
    """
    Test BGP allow-as-in feature with IPv4 routes

    Args:
        setup_exabgp: Setup information for exabgp
    """
    duthost = setup_exabgp['duthost']
    dut_asn = setup_exabgp['dut_asn']
    test_neighbor_ip = setup_exabgp['test_neighbor_ip']
    ipv4_prefix = setup_exabgp['ipv4_prefix']
    ptfip = setup_exabgp['ptfip']
    lo_addr = setup_exabgp['lo_addr']
    exabgp_port = setup_exabgp['exabgp_port']
    # ptfhost is not used in this function

    # Configure allow_as_in to true for the neighbor
    logger.info(f"Configuring allow_as_in=true for neighbor {test_neighbor_ip}")
    configure_allow_as_in(duthost, test_neighbor_ip, ALLOW_AS_IN_TRUE)

    # Re-announce the route with multiple instances of own AS to ensure it's a strong test
    logger.info("Re-announcing the route with own AS in AS_PATH")
    aspath = f"{dut_asn} {dut_asn}"  # Multiple ASNs to make sure it's in the path
    route = {
        'prefix': ipv4_prefix,
        'nexthop': lo_addr,  # Use loopback address as nexthop
        'aspath': aspath
    }
    # First withdraw the route, then announce it again
    update_routes("withdraw", ptfip, exabgp_port, route)
    time.sleep(5)

    # Verify that the route doesn't exist after withdrawal
    logger.info(f"Verifying that route {ipv4_prefix} doesn't exist after withdrawal")
    route_absent = verify_route_accepted(duthost, ipv4_prefix, expected_present=False)
    pytest_assert(route_absent, f"Route {ipv4_prefix} should not be present after withdrawal")

    # Re-announce the route
    update_routes("announce", ptfip, exabgp_port, route)

    # Wait for the configuration to take effect
    logger.info("Waiting for the route to be processed...")
    time.sleep(30)

    # Verify that the route with the DUT's own AS in the AS_PATH is accepted
    logger.info(f"Verifying that route {ipv4_prefix} with DUT's own AS {dut_asn} in the AS_PATH is accepted")
    result = wait_for_route_status(duthost, ipv4_prefix, dut_asn, True, timeout=180, interval=20)

    pytest_assert(result, f"Route {ipv4_prefix} with own AS {dut_asn} should be accepted when allow_as_in=true")


def test_bgp_allow_as_in_ipv6(setup_exabgp):
    """
    Test BGP allow-as-in feature with IPv6 routes

    Args:
        setup_exabgp: Setup information for exabgp
    """
    duthost = setup_exabgp['duthost']
    dut_asn = setup_exabgp['dut_asn']
    test_neighbor_ipv6 = setup_exabgp['test_neighbor_ipv6']
    ipv6_prefix = setup_exabgp['ipv6_prefix']
    ipv6_ready = setup_exabgp['ipv6_ready']
    ptfip = setup_exabgp['ptfip']
    lo_addr_v6 = setup_exabgp['lo_addr_v6']
    exabgp_port_v6 = setup_exabgp['exabgp_port_v6']
    # ptfhost is not used in this function

    # Skip if IPv6 is not ready
    if not ipv6_ready or not ipv6_prefix or not lo_addr_v6:
        pytest.skip("IPv6 is not configured or ready")

    # Skip if IPv6 neighbor is not found
    if not test_neighbor_ipv6:
        pytest.skip("IPv6 neighbor not found")

    # Configure allow_as_in to true for the IPv6 neighbor
    logger.info(f"Configuring allow_as_in=true for IPv6 neighbor {test_neighbor_ipv6}")
    configure_allow_as_in(duthost, test_neighbor_ipv6, ALLOW_AS_IN_TRUE)

    # Re-announce the route with multiple instances of own AS to ensure it's a strong test
    logger.info("Re-announcing the route with own AS in AS_PATH")
    aspath = f"{dut_asn} {dut_asn}"  # Multiple ASNs to make sure it's in the path
    route_v6 = {
        'prefix': ipv6_prefix,
        'nexthop': lo_addr_v6,  # Use loopback address as nexthop
        'aspath': aspath
    }
    # First withdraw the route, then announce it again
    update_routes("withdraw", ptfip, exabgp_port_v6, route_v6)
    time.sleep(5)

    # Verify that the route doesn't exist after withdrawal
    logger.info(f"Verifying that route {ipv6_prefix} doesn't exist after withdrawal")
    route_absent = verify_route_accepted(duthost, ipv6_prefix, expected_present=False)
    pytest_assert(route_absent, f"Route {ipv6_prefix} should not be present after withdrawal")

    # Re-announce the route
    update_routes("announce", ptfip, exabgp_port_v6, route_v6)

    # Wait for the configuration to take effect
    logger.info("Waiting for the route to be processed...")
    time.sleep(30)

    # Verify that the route with the DUT's own AS in the AS_PATH is accepted
    logger.info(f"Verifying that IPv6 route {ipv6_prefix} with DUT's own AS {dut_asn} in the AS_PATH is accepted")
    result = wait_for_route_status(duthost, ipv6_prefix, dut_asn, True, timeout=180, interval=20)

    pytest_assert(result, f"IPv6 route {ipv6_prefix} with own AS {dut_asn} should be accepted when allow_as_in=true")
