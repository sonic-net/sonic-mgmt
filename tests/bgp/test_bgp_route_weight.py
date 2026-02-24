"""
Test to verify that BGP-learned routes in APPL_DB ROUTE_TABLE have the
'weight' attribute set for their nexthops.

Addresses test gap issue #18208.

Without the weight attribute, weighted ECMP cannot function correctly
as routes may be added to the ASIC without any weight for their nexthops.
"""
import logging
import pytest

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0', 't1', 't2'),
    pytest.mark.device_type('vs')
]


def test_bgp_route_weight_ipv4(duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                               enum_frontend_asic_index):
    """Verify that IPv4 BGP-learned routes have the 'weight' attribute set
    in APPL_DB ROUTE_TABLE.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asic = duthost.asic_instance(enum_frontend_asic_index)

    # Get all ROUTE_TABLE keys from APPL_DB
    route_keys_output = asic.shell(
        "sonic-db-cli APPL_DB keys 'ROUTE_TABLE:*'")['stdout'].strip()
    assert route_keys_output, "No routes found in APPL_DB ROUTE_TABLE"

    route_keys = route_keys_output.split('\n')

    # Filter for IPv4 BGP routes (exclude default, link-local, directly connected)
    ipv4_bgp_routes = []
    for key in route_keys:
        prefix = key.replace('ROUTE_TABLE:', '')
        # Skip non-IPv4, default route, and link-local
        if ':' in prefix or prefix == '0.0.0.0/0' or prefix.startswith('169.254.'):
            continue
        # Check if this is a BGP-learned route
        entry = asic.shell(
            "sonic-db-cli APPL_DB hgetall '{}'".format(key))['stdout']
        if "'protocol': 'bgp'" in entry:
            ipv4_bgp_routes.append((key, entry))

    assert ipv4_bgp_routes, "No IPv4 BGP-learned routes found in APPL_DB ROUTE_TABLE"
    logger.info("Found %d IPv4 BGP routes to check", len(ipv4_bgp_routes))

    # Sample up to 10 routes for detailed checking
    routes_to_check = ipv4_bgp_routes[:10]
    missing_weight = []

    for key, entry in routes_to_check:
        if "'weight'" not in entry:
            missing_weight.append(key)
            continue

        # Verify weight has values matching the number of nexthops
        # Parse weight and nexthop counts from the entry string
        if "'nexthop':" in entry and "'weight':" in entry:
            try:
                # Extract nexthop count
                nh_start = entry.index("'nexthop': '") + len("'nexthop': '")
                nh_end = entry.index("'", nh_start)
                nexthops = entry[nh_start:nh_end]
                nh_count = len(nexthops.split(',')) if nexthops else 0

                # Extract weight count
                w_start = entry.index("'weight': '") + len("'weight': '")
                w_end = entry.index("'", w_start)
                weights = entry[w_start:w_end]
                w_count = len(weights.split(',')) if weights else 0

                if nh_count > 0:
                    assert w_count == nh_count, (
                        "Weight count ({}) does not match nexthop count ({}) "
                        "for route {}".format(w_count, nh_count, key)
                    )
                    # Verify each weight is a positive integer
                    for w in weights.split(','):
                        assert w.strip().isdigit() and int(w.strip()) > 0, (
                            "Invalid weight value '{}' for route {}".format(w, key)
                        )
            except (ValueError, IndexError) as e:
                logger.warning("Could not parse entry for %s: %s", key, e)

    prefix = routes_to_check[0][0].replace('ROUTE_TABLE:', '')
    logger.info("Sample route %s entry: %s", prefix, routes_to_check[0][1][:200])

    assert not missing_weight, (
        "The following IPv4 BGP routes are missing the 'weight' attribute: {}".format(
            [k.replace('ROUTE_TABLE:', '') for k in missing_weight])
    )
    logger.info("All %d sampled IPv4 BGP routes have valid weight attributes", len(routes_to_check))


def test_bgp_route_weight_ipv6(duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                               enum_frontend_asic_index):
    """Verify that IPv6 BGP-learned routes have the 'weight' attribute set
    in APPL_DB ROUTE_TABLE.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asic = duthost.asic_instance(enum_frontend_asic_index)

    # Get all ROUTE_TABLE keys from APPL_DB
    route_keys_output = asic.shell(
        "sonic-db-cli APPL_DB keys 'ROUTE_TABLE:*'")['stdout'].strip()
    assert route_keys_output, "No routes found in APPL_DB ROUTE_TABLE"

    route_keys = route_keys_output.split('\n')

    # Filter for IPv6 BGP routes (exclude default, link-local)
    ipv6_bgp_routes = []
    for key in route_keys:
        prefix = key.replace('ROUTE_TABLE:', '')
        # Must contain ':' for IPv6, skip default and link-local
        if ':' not in prefix or prefix == '::/0' or prefix.startswith('fe80'):
            continue
        # Check if this is a BGP-learned route
        entry = asic.shell(
            "sonic-db-cli APPL_DB hgetall '{}'".format(key))['stdout']
        if "'protocol': 'bgp'" in entry:
            ipv6_bgp_routes.append((key, entry))

    assert ipv6_bgp_routes, "No IPv6 BGP-learned routes found in APPL_DB ROUTE_TABLE"
    logger.info("Found %d IPv6 BGP routes to check", len(ipv6_bgp_routes))

    # Sample up to 10 routes for detailed checking
    routes_to_check = ipv6_bgp_routes[:10]
    missing_weight = []

    for key, entry in routes_to_check:
        if "'weight'" not in entry:
            missing_weight.append(key)
            continue

        # Verify weight has values matching the number of nexthops
        if "'nexthop':" in entry and "'weight':" in entry:
            try:
                nh_start = entry.index("'nexthop': '") + len("'nexthop': '")
                nh_end = entry.index("'", nh_start)
                nexthops = entry[nh_start:nh_end]
                nh_count = len(nexthops.split(',')) if nexthops else 0

                w_start = entry.index("'weight': '") + len("'weight': '")
                w_end = entry.index("'", w_start)
                weights = entry[w_start:w_end]
                w_count = len(weights.split(',')) if weights else 0

                if nh_count > 0:
                    assert w_count == nh_count, (
                        "Weight count ({}) does not match nexthop count ({}) "
                        "for route {}".format(w_count, nh_count, key)
                    )
                    for w in weights.split(','):
                        assert w.strip().isdigit() and int(w.strip()) > 0, (
                            "Invalid weight value '{}' for route {}".format(w, key)
                        )
            except (ValueError, IndexError) as e:
                logger.warning("Could not parse entry for %s: %s", key, e)

    prefix = routes_to_check[0][0].replace('ROUTE_TABLE:', '')
    logger.info("Sample route %s entry: %s", prefix, routes_to_check[0][1][:200])

    assert not missing_weight, (
        "The following IPv6 BGP routes are missing the 'weight' attribute: {}".format(
            [k.replace('ROUTE_TABLE:', '') for k in missing_weight])
    )
    logger.info("All %d sampled IPv6 BGP routes have valid weight attributes", len(routes_to_check))
