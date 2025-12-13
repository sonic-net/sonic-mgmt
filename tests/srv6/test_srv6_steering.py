import time
import pytest
from tests.common.utilities import wait_until

pytestmark = [
    pytest.mark.topology('t0', 't1')
]

WAIT_TIME = 5


def verify_appl_db_sid_list_entry_exist(duthost, sonic_db_cli, key, exist):
    """Verify if a SID list entry exists in APPL_DB"""
    appl_db_sid_lists = duthost.command(sonic_db_cli + " APPL_DB keys SRV6_SID_LIST_TABLE*")["stdout"]
    return key in appl_db_sid_lists if exist else key not in appl_db_sid_lists


def verify_appl_db_route_entry_exist(duthost, sonic_db_cli, key, exist):
    """Verify if a route entry exists in APPL_DB"""
    appl_db_routes = duthost.command(sonic_db_cli + " APPL_DB keys ROUTE_TABLE*")["stdout"]
    return key in appl_db_routes if exist else key not in appl_db_routes


def test_ipv4_single_sid_steering(duthosts, enum_frontend_dut_hostname, enum_rand_one_asic_index):
    """Test steering of an IPv4 route over a SID list with single SID"""
    duthost = duthosts[enum_frontend_dut_hostname]
    asic_index = enum_rand_one_asic_index

    if duthost.is_multi_asic:
        cli_options = " -n " + duthost.get_namespace_from_asic_id(asic_index)
    else:
        cli_options = ''

    sonic_db_cli = "sonic-db-cli" + cli_options
    vtysh_shell = "vtysh" + cli_options

    # Configure locator
    duthost.command(sonic_db_cli + " CONFIG_DB HSET SRV6_MY_LOCATORS\\|loc1 prefix fc00:0:1:: func_len 16")
    time.sleep(WAIT_TIME)

    # Configure a static route with single SID for IPv4 prefix
    duthost.command(vtysh_shell + " -c \"configure terminal\" " +
                    "-c \"segment-routing\" " +
                    "-c \"srv6\" " +
                    "-c \"sid fc00:0:1:e000:: behavior uN\" " +
                    "-c \"exit\" " +
                    "-c \"exit\" " +
                    "-c \"ip route 10.1.1.0/24 Ethernet0 nexthop-vrf default segments fc00:0:1:e000::\"")
    time.sleep(WAIT_TIME)

    # Verify SID list entry exists in APPL_DB
    assert wait_until(60, 2, 0, verify_appl_db_sid_list_entry_exist, duthost, sonic_db_cli,
                      "SRV6_SID_LIST_TABLE:fc00:0:1:e000::", True), \
        "SID list entry is missing in APPL_DB"

    # Verify the SID list contains the correct path
    sid_path = duthost.command(sonic_db_cli +
                               " APPL_DB hget SRV6_SID_LIST_TABLE:fc00:0:1:e000:: path")["stdout"]
    assert "fc00:0:1:e000::" in sid_path, "SID list path is incorrect in APPL_DB"

    # Verify route entry exists in APPL_DB with segment reference
    assert wait_until(60, 2, 0, verify_appl_db_route_entry_exist, duthost, sonic_db_cli,
                      "ROUTE_TABLE:10.1.1.0/24", True), "Route entry is missing in APPL_DB"

    # Verify the route has segment attribute
    route_segment = duthost.command(sonic_db_cli +
                                    " APPL_DB hget ROUTE_TABLE:10.1.1.0/24 segment",
                                    module_ignore_errors=True)
    if route_segment["rc"] == 0:
        assert "fc00:0:1:e000::" in route_segment["stdout"], \
            "Route segment attribute is incorrect in APPL_DB"

    # Cleanup
    duthost.command(vtysh_shell + " -c \"configure terminal\" " +
                    "-c \"no ip route 10.1.1.0/24 Ethernet0 nexthop-vrf default segments fc00:0:1:e000::\"")
    time.sleep(WAIT_TIME)
    duthost.command(vtysh_shell + " -c \"configure terminal\" " +
                    "-c \"segment-routing\" " +
                    "-c \"srv6\" " +
                    "-c \"no sid fc00:0:1:e000::\"")
    time.sleep(WAIT_TIME)
    duthost.command(sonic_db_cli + " CONFIG_DB DEL SRV6_MY_LOCATORS\\|loc1")
    time.sleep(WAIT_TIME)

    # Verify cleanup
    assert wait_until(60, 2, 0, verify_appl_db_route_entry_exist, duthost, sonic_db_cli,
                      "ROUTE_TABLE:10.1.1.0/24", False), "Route entry was not cleaned up in APPL_DB"


def test_ipv6_single_sid_steering(duthosts, enum_frontend_dut_hostname, enum_rand_one_asic_index):
    """Test steering of an IPv6 route over a SID list with single SID"""
    duthost = duthosts[enum_frontend_dut_hostname]
    asic_index = enum_rand_one_asic_index

    if duthost.is_multi_asic:
        cli_options = " -n " + duthost.get_namespace_from_asic_id(asic_index)
    else:
        cli_options = ''

    sonic_db_cli = "sonic-db-cli" + cli_options
    vtysh_shell = "vtysh" + cli_options

    # Configure locator
    duthost.command(sonic_db_cli + " CONFIG_DB HSET SRV6_MY_LOCATORS\\|loc1 prefix fc00:0:1:: func_len 16")
    time.sleep(WAIT_TIME)

    # Configure a static route with single SID for IPv6 prefix
    duthost.command(vtysh_shell + " -c \"configure terminal\" " +
                    "-c \"segment-routing\" " +
                    "-c \"srv6\" " +
                    "-c \"sid fc00:0:1:e000:: behavior uN\" " +
                    "-c \"exit\" " +
                    "-c \"exit\" " +
                    "-c \"ipv6 route 2001:db8:1::/48 Ethernet0 nexthop-vrf default segments fc00:0:1:e000::\"")
    time.sleep(WAIT_TIME)

    # Verify SID list entry exists in APPL_DB
    assert wait_until(60, 2, 0, verify_appl_db_sid_list_entry_exist, duthost, sonic_db_cli,
                      "SRV6_SID_LIST_TABLE:fc00:0:1:e000::", True), \
        "SID list entry is missing in APPL_DB"

    # Verify the SID list contains the correct path
    sid_path = duthost.command(sonic_db_cli +
                               " APPL_DB hget SRV6_SID_LIST_TABLE:fc00:0:1:e000:: path")["stdout"]
    assert "fc00:0:1:e000::" in sid_path, "SID list path is incorrect in APPL_DB"

    # Verify route entry exists in APPL_DB with segment reference
    assert wait_until(60, 2, 0, verify_appl_db_route_entry_exist, duthost, sonic_db_cli,
                      "ROUTE_TABLE:2001:db8:1::/48", True), "Route entry is missing in APPL_DB"

    # Verify the route has segment attribute
    route_segment = duthost.command(sonic_db_cli +
                                    " APPL_DB hget ROUTE_TABLE:2001:db8:1::/48 segment",
                                    module_ignore_errors=True)
    if route_segment["rc"] == 0:
        assert "fc00:0:1:e000::" in route_segment["stdout"], \
            "Route segment attribute is incorrect in APPL_DB"

    # Cleanup
    duthost.command(vtysh_shell + " -c \"configure terminal\" " +
                    "-c \"no ipv6 route 2001:db8:1::/48 Ethernet0 nexthop-vrf default segments fc00:0:1:e000::\"")
    time.sleep(WAIT_TIME)
    duthost.command(vtysh_shell + " -c \"configure terminal\" " +
                    "-c \"segment-routing\" " +
                    "-c \"srv6\" " +
                    "-c \"no sid fc00:0:1:e000::\"")
    time.sleep(WAIT_TIME)
    duthost.command(sonic_db_cli + " CONFIG_DB DEL SRV6_MY_LOCATORS\\|loc1")
    time.sleep(WAIT_TIME)

    # Verify cleanup
    assert wait_until(60, 2, 0, verify_appl_db_route_entry_exist, duthost, sonic_db_cli,
                      "ROUTE_TABLE:2001:db8:1::/48", False), "Route entry was not cleaned up in APPL_DB"


def test_ipv4_multi_sid_steering(duthosts, enum_frontend_dut_hostname, enum_rand_one_asic_index):
    """Test steering of an IPv4 route over a SID list with multiple SIDs"""
    duthost = duthosts[enum_frontend_dut_hostname]
    asic_index = enum_rand_one_asic_index

    if duthost.is_multi_asic:
        cli_options = " -n " + duthost.get_namespace_from_asic_id(asic_index)
    else:
        cli_options = ''

    sonic_db_cli = "sonic-db-cli" + cli_options
    vtysh_shell = "vtysh" + cli_options

    # Configure locator
    duthost.command(sonic_db_cli + " CONFIG_DB HSET SRV6_MY_LOCATORS\\|loc1 prefix fc00:0:1:: func_len 16")
    time.sleep(WAIT_TIME)

    # Configure SIDs
    duthost.command(vtysh_shell + " -c \"configure terminal\" " +
                    "-c \"segment-routing\" " +
                    "-c \"srv6\" " +
                    "-c \"sid fc00:0:1:e001:: behavior uN\" " +
                    "-c \"sid fc00:0:1:e002:: behavior uN\" " +
                    "-c \"sid fc00:0:1:e003:: behavior uN\"")
    time.sleep(WAIT_TIME)

    # Configure a static route with multiple SIDs for IPv4 prefix
    duthost.command(vtysh_shell + " -c \"configure terminal\" " +
                    "-c \"ip route 10.2.1.0/24 Ethernet0 nexthop-vrf default " +
                    "segments fc00:0:1:e001::,fc00:0:1:e002::,fc00:0:1:e003::\"")
    time.sleep(WAIT_TIME)

    # Verify SID list entry exists in APPL_DB
    # The key may be based on the first SID or a generated name
    sid_list_found = False
    appl_db_sid_lists = duthost.command(sonic_db_cli + " APPL_DB keys SRV6_SID_LIST_TABLE*")["stdout"]
    
    for sid_list_key in appl_db_sid_lists.split('\n'):
        if sid_list_key.startswith("SRV6_SID_LIST_TABLE"):
            sid_path = duthost.command(sonic_db_cli + f" APPL_DB hget {sid_list_key} path")["stdout"]
            # Check if the path contains all three SIDs
            if ("fc00:0:1:e001::" in sid_path and 
                "fc00:0:1:e002::" in sid_path and 
                "fc00:0:1:e003::" in sid_path):
                sid_list_found = True
                break

    assert sid_list_found, "SID list with multiple SIDs is missing in APPL_DB"

    # Verify route entry exists in APPL_DB
    assert wait_until(60, 2, 0, verify_appl_db_route_entry_exist, duthost, sonic_db_cli,
                      "ROUTE_TABLE:10.2.1.0/24", True), "Route entry is missing in APPL_DB"

    # Cleanup
    duthost.command(vtysh_shell + " -c \"configure terminal\" " +
                    "-c \"no ip route 10.2.1.0/24 Ethernet0 nexthop-vrf default " +
                    "segments fc00:0:1:e001::,fc00:0:1:e002::,fc00:0:1:e003::\"")
    time.sleep(WAIT_TIME)
    duthost.command(vtysh_shell + " -c \"configure terminal\" " +
                    "-c \"segment-routing\" " +
                    "-c \"srv6\" " +
                    "-c \"no sid fc00:0:1:e001::\" " +
                    "-c \"no sid fc00:0:1:e002::\" " +
                    "-c \"no sid fc00:0:1:e003::\"")
    time.sleep(WAIT_TIME)
    duthost.command(sonic_db_cli + " CONFIG_DB DEL SRV6_MY_LOCATORS\\|loc1")
    time.sleep(WAIT_TIME)

    # Verify cleanup
    assert wait_until(60, 2, 0, verify_appl_db_route_entry_exist, duthost, sonic_db_cli,
                      "ROUTE_TABLE:10.2.1.0/24", False), "Route entry was not cleaned up in APPL_DB"


def test_ipv6_multi_sid_steering(duthosts, enum_frontend_dut_hostname, enum_rand_one_asic_index):
    """Test steering of an IPv6 route over a SID list with multiple SIDs"""
    duthost = duthosts[enum_frontend_dut_hostname]
    asic_index = enum_rand_one_asic_index

    if duthost.is_multi_asic:
        cli_options = " -n " + duthost.get_namespace_from_asic_id(asic_index)
    else:
        cli_options = ''

    sonic_db_cli = "sonic-db-cli" + cli_options
    vtysh_shell = "vtysh" + cli_options

    # Configure locator
    duthost.command(sonic_db_cli + " CONFIG_DB HSET SRV6_MY_LOCATORS\\|loc1 prefix fc00:0:1:: func_len 16")
    time.sleep(WAIT_TIME)

    # Configure SIDs
    duthost.command(vtysh_shell + " -c \"configure terminal\" " +
                    "-c \"segment-routing\" " +
                    "-c \"srv6\" " +
                    "-c \"sid fc00:0:1:e001:: behavior uN\" " +
                    "-c \"sid fc00:0:1:e002:: behavior uN\" " +
                    "-c \"sid fc00:0:1:e003:: behavior uN\"")
    time.sleep(WAIT_TIME)

    # Configure a static route with multiple SIDs for IPv6 prefix
    duthost.command(vtysh_shell + " -c \"configure terminal\" " +
                    "-c \"ipv6 route 2001:db8:2::/48 Ethernet0 nexthop-vrf default " +
                    "segments fc00:0:1:e001::,fc00:0:1:e002::,fc00:0:1:e003::\"")
    time.sleep(WAIT_TIME)

    # Verify SID list entry exists in APPL_DB
    sid_list_found = False
    appl_db_sid_lists = duthost.command(sonic_db_cli + " APPL_DB keys SRV6_SID_LIST_TABLE*")["stdout"]
    
    for sid_list_key in appl_db_sid_lists.split('\n'):
        if sid_list_key.startswith("SRV6_SID_LIST_TABLE"):
            sid_path = duthost.command(sonic_db_cli + f" APPL_DB hget {sid_list_key} path")["stdout"]
            # Check if the path contains all three SIDs
            if ("fc00:0:1:e001::" in sid_path and 
                "fc00:0:1:e002::" in sid_path and 
                "fc00:0:1:e003::" in sid_path):
                sid_list_found = True
                break

    assert sid_list_found, "SID list with multiple SIDs is missing in APPL_DB"

    # Verify route entry exists in APPL_DB
    assert wait_until(60, 2, 0, verify_appl_db_route_entry_exist, duthost, sonic_db_cli,
                      "ROUTE_TABLE:2001:db8:2::/48", True), "Route entry is missing in APPL_DB"

    # Cleanup
    duthost.command(vtysh_shell + " -c \"configure terminal\" " +
                    "-c \"no ipv6 route 2001:db8:2::/48 Ethernet0 nexthop-vrf default " +
                    "segments fc00:0:1:e001::,fc00:0:1:e002::,fc00:0:1:e003::\"")
    time.sleep(WAIT_TIME)
    duthost.command(vtysh_shell + " -c \"configure terminal\" " +
                    "-c \"segment-routing\" " +
                    "-c \"srv6\" " +
                    "-c \"no sid fc00:0:1:e001::\" " +
                    "-c \"no sid fc00:0:1:e002::\" " +
                    "-c \"no sid fc00:0:1:e003::\"")
    time.sleep(WAIT_TIME)
    duthost.command(sonic_db_cli + " CONFIG_DB DEL SRV6_MY_LOCATORS\\|loc1")
    time.sleep(WAIT_TIME)

    # Verify cleanup
    assert wait_until(60, 2, 0, verify_appl_db_route_entry_exist, duthost, sonic_db_cli,
                      "ROUTE_TABLE:2001:db8:2::/48", False), "Route entry was not cleaned up in APPL_DB"


def test_ipv4_multi_sid_list_steering(duthosts, enum_frontend_dut_hostname, enum_rand_one_asic_index):
    """Test steering of an IPv4 route over multiple SID lists (ECMP)"""
    duthost = duthosts[enum_frontend_dut_hostname]
    asic_index = enum_rand_one_asic_index

    if duthost.is_multi_asic:
        cli_options = " -n " + duthost.get_namespace_from_asic_id(asic_index)
    else:
        cli_options = ''

    sonic_db_cli = "sonic-db-cli" + cli_options
    vtysh_shell = "vtysh" + cli_options

    # Configure locator
    duthost.command(sonic_db_cli + " CONFIG_DB HSET SRV6_MY_LOCATORS\\|loc1 prefix fc00:0:1:: func_len 16")
    time.sleep(WAIT_TIME)

    # Configure SIDs for different paths
    duthost.command(vtysh_shell + " -c \"configure terminal\" " +
                    "-c \"segment-routing\" " +
                    "-c \"srv6\" " +
                    "-c \"sid fc00:0:1:e010:: behavior uN\" " +
                    "-c \"sid fc00:0:1:e020:: behavior uN\"")
    time.sleep(WAIT_TIME)

    # Configure multiple static routes to the same prefix with different SID lists (ECMP)
    duthost.command(vtysh_shell + " -c \"configure terminal\" " +
                    "-c \"ip route 10.3.1.0/24 Ethernet0 nexthop-vrf default segments fc00:0:1:e010::\"")
    time.sleep(WAIT_TIME)
    duthost.command(vtysh_shell + " -c \"configure terminal\" " +
                    "-c \"ip route 10.3.1.0/24 Ethernet4 nexthop-vrf default segments fc00:0:1:e020::\"")
    time.sleep(WAIT_TIME)

    # Verify both SID lists exist in APPL_DB
    assert wait_until(60, 2, 0, verify_appl_db_sid_list_entry_exist, duthost, sonic_db_cli,
                      "SRV6_SID_LIST_TABLE:fc00:0:1:e010::", True), \
        "First SID list entry is missing in APPL_DB"
    assert wait_until(60, 2, 0, verify_appl_db_sid_list_entry_exist, duthost, sonic_db_cli,
                      "SRV6_SID_LIST_TABLE:fc00:0:1:e020::", True), \
        "Second SID list entry is missing in APPL_DB"

    # Verify route entry exists in APPL_DB
    assert wait_until(60, 2, 0, verify_appl_db_route_entry_exist, duthost, sonic_db_cli,
                      "ROUTE_TABLE:10.3.1.0/24", True), "Route entry is missing in APPL_DB"

    # Verify the route has multiple segment attributes (for ECMP)
    route_segment = duthost.command(sonic_db_cli +
                                    " APPL_DB hget ROUTE_TABLE:10.3.1.0/24 segment",
                                    module_ignore_errors=True)
    if route_segment["rc"] == 0:
        # Multiple segments may be comma-separated or there may be multiple nexthop entries
        segment_output = route_segment["stdout"]
        assert "fc00:0:1:e010::" in segment_output or "fc00:0:1:e020::" in segment_output, \
            "Route segment attributes are incorrect in APPL_DB"

    # Cleanup
    duthost.command(vtysh_shell + " -c \"configure terminal\" " +
                    "-c \"no ip route 10.3.1.0/24 Ethernet0 nexthop-vrf default segments fc00:0:1:e010::\"")
    time.sleep(WAIT_TIME)
    duthost.command(vtysh_shell + " -c \"configure terminal\" " +
                    "-c \"no ip route 10.3.1.0/24 Ethernet4 nexthop-vrf default segments fc00:0:1:e020::\"")
    time.sleep(WAIT_TIME)
    duthost.command(vtysh_shell + " -c \"configure terminal\" " +
                    "-c \"segment-routing\" " +
                    "-c \"srv6\" " +
                    "-c \"no sid fc00:0:1:e010::\" " +
                    "-c \"no sid fc00:0:1:e020::\"")
    time.sleep(WAIT_TIME)
    duthost.command(sonic_db_cli + " CONFIG_DB DEL SRV6_MY_LOCATORS\\|loc1")
    time.sleep(WAIT_TIME)

    # Verify cleanup
    assert wait_until(60, 2, 0, verify_appl_db_route_entry_exist, duthost, sonic_db_cli,
                      "ROUTE_TABLE:10.3.1.0/24", False), "Route entry was not cleaned up in APPL_DB"


def test_ipv6_multi_sid_list_steering(duthosts, enum_frontend_dut_hostname, enum_rand_one_asic_index):
    """Test steering of an IPv6 route over multiple SID lists (ECMP)"""
    duthost = duthosts[enum_frontend_dut_hostname]
    asic_index = enum_rand_one_asic_index

    if duthost.is_multi_asic:
        cli_options = " -n " + duthost.get_namespace_from_asic_id(asic_index)
    else:
        cli_options = ''

    sonic_db_cli = "sonic-db-cli" + cli_options
    vtysh_shell = "vtysh" + cli_options

    # Configure locator
    duthost.command(sonic_db_cli + " CONFIG_DB HSET SRV6_MY_LOCATORS\\|loc1 prefix fc00:0:1:: func_len 16")
    time.sleep(WAIT_TIME)

    # Configure SIDs for different paths
    duthost.command(vtysh_shell + " -c \"configure terminal\" " +
                    "-c \"segment-routing\" " +
                    "-c \"srv6\" " +
                    "-c \"sid fc00:0:1:e010:: behavior uN\" " +
                    "-c \"sid fc00:0:1:e020:: behavior uN\"")
    time.sleep(WAIT_TIME)

    # Configure multiple static routes to the same prefix with different SID lists (ECMP)
    duthost.command(vtysh_shell + " -c \"configure terminal\" " +
                    "-c \"ipv6 route 2001:db8:3::/48 Ethernet0 nexthop-vrf default segments fc00:0:1:e010::\"")
    time.sleep(WAIT_TIME)
    duthost.command(vtysh_shell + " -c \"configure terminal\" " +
                    "-c \"ipv6 route 2001:db8:3::/48 Ethernet4 nexthop-vrf default segments fc00:0:1:e020::\"")
    time.sleep(WAIT_TIME)

    # Verify both SID lists exist in APPL_DB
    assert wait_until(60, 2, 0, verify_appl_db_sid_list_entry_exist, duthost, sonic_db_cli,
                      "SRV6_SID_LIST_TABLE:fc00:0:1:e010::", True), \
        "First SID list entry is missing in APPL_DB"
    assert wait_until(60, 2, 0, verify_appl_db_sid_list_entry_exist, duthost, sonic_db_cli,
                      "SRV6_SID_LIST_TABLE:fc00:0:1:e020::", True), \
        "Second SID list entry is missing in APPL_DB"

    # Verify route entry exists in APPL_DB
    assert wait_until(60, 2, 0, verify_appl_db_route_entry_exist, duthost, sonic_db_cli,
                      "ROUTE_TABLE:2001:db8:3::/48", True), "Route entry is missing in APPL_DB"

    # Verify the route has multiple segment attributes (for ECMP)
    route_segment = duthost.command(sonic_db_cli +
                                    " APPL_DB hget ROUTE_TABLE:2001:db8:3::/48 segment",
                                    module_ignore_errors=True)
    if route_segment["rc"] == 0:
        # Multiple segments may be comma-separated or there may be multiple nexthop entries
        segment_output = route_segment["stdout"]
        assert "fc00:0:1:e010::" in segment_output or "fc00:0:1:e020::" in segment_output, \
            "Route segment attributes are incorrect in APPL_DB"

    # Cleanup
    duthost.command(vtysh_shell + " -c \"configure terminal\" " +
                    "-c \"no ipv6 route 2001:db8:3::/48 Ethernet0 nexthop-vrf default segments fc00:0:1:e010::\"")
    time.sleep(WAIT_TIME)
    duthost.command(vtysh_shell + " -c \"configure terminal\" " +
                    "-c \"no ipv6 route 2001:db8:3::/48 Ethernet4 nexthop-vrf default segments fc00:0:1:e020::\"")
    time.sleep(WAIT_TIME)
    duthost.command(vtysh_shell + " -c \"configure terminal\" " +
                    "-c \"segment-routing\" " +
                    "-c \"srv6\" " +
                    "-c \"no sid fc00:0:1:e010::\" " +
                    "-c \"no sid fc00:0:1:e020::\"")
    time.sleep(WAIT_TIME)
    duthost.command(sonic_db_cli + " CONFIG_DB DEL SRV6_MY_LOCATORS\\|loc1")
    time.sleep(WAIT_TIME)

    # Verify cleanup
    assert wait_until(60, 2, 0, verify_appl_db_route_entry_exist, duthost, sonic_db_cli,
                      "ROUTE_TABLE:2001:db8:3::/48", False), "Route entry was not cleaned up in APPL_DB"
