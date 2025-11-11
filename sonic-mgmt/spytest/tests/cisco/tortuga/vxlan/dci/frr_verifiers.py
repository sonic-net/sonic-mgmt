from spytest import st
from typing import List


def verify_type_5_routes_are_not_reoriginated(dut, next_hops: List[str]) -> bool:
    """
    Verify that BGP L2VPN EVPN type 5 routes with specified next hops are not present.
    If any type 5 routes are found with the prohibited next hops, log all matching routes and return False.

    Args:
        dut (WorkArea): Device under test
        next_hops (List[str]): List of next hop IP addresses that should NOT appear in type 5 routes

    Returns:
        bool: True if no prohibited next hops are found in type 5 routes, False if any are found
    """
    command = "show bgp l2vpn evpn route type 5"
    output = st.vtysh_show(dut, command, skip_tmpl=True, skip_error_check=True)
    parsed_output = st.parse_show(dut, command, output=output, tmpl="show_bgp_l2vpn_evpn_route_type_5.tmpl")

    if not parsed_output:
        st.warn(f"No BGP L2VPN EVPN type 5 routes found on DUT {dut}")
        return True

    st.log(f"Checking for prohibited next hops {next_hops} in type 5 routes on DUT {dut}")

    found_prohibited_routes = []

    # Check each parsed route entry
    for route_entry in parsed_output:
        route_nexthop = route_entry.get("nexthop", "").strip()
        route_distinguisher = route_entry.get("routedistinguisher", "").strip()
        route_prefix = route_entry.get("prefix", "").strip()

        # Check if this route's next hop matches any prohibited next hop
        if route_nexthop in next_hops:
            found_prohibited_routes.append(
                {
                    "next_hop": route_nexthop,
                    "route_distinguisher": route_distinguisher,
                    "prefix": route_prefix,
                    "metric": route_entry.get("metric", ""),
                    "weight": route_entry.get("weight", ""),
                    "path": route_entry.get("path", ""),
                    "extended_community": route_entry.get("extendedcommunity", ""),
                }
            )

    if found_prohibited_routes:
        st.error(f"FAILED: Found {len(found_prohibited_routes)} type 5 routes with prohibited next hops on DUT {dut}:")
        for i, route in enumerate(found_prohibited_routes, 1):
            st.log(f"Route {i}:")
            st.log(f"  Next Hop: {route['next_hop']}")
            st.log(f"  Route Distinguisher: {route['route_distinguisher']}")
            st.log(f"  Prefix: {route['prefix']}")
            st.log(f"  Metric: {route['metric']}")
            st.log(f"  Weight: {route['weight']}")
            st.log(f"  Path: {route['path']}")
            st.log(f"  Extended Community: {route['extended_community']}")
        return False
    else:
        st.log(f"SUCCESS: No type 5 routes found with prohibited next hops {next_hops} on DUT {dut}")
        return True


def verify_type_1_routes_are_not_reoriginated(dut, origin_ips: List[str]) -> bool:
    """
    Verify that BGP L2VPN EVPN type 1 routes with specified origin values are not present.
    If any type 1 routes are found with the prohibited origin values, log all matching routes and return False.

    Args:
        dut (WorkArea): Device under test
        origin_ips (List[str]): List of origin values that should NOT appear in type 1 routes

    Returns:
        bool: True if no prohibited origin values are found in type 1 routes, False if any are found
    """
    command = "show bgp l2vpn evpn route type 1"
    output = st.vtysh_show(dut, command, skip_tmpl=True, skip_error_check=True)
    parsed_output = st.parse_show(dut, command, output=output, tmpl="show_bgp_l2vpn_evpn_route_type_1.tmpl")

    if not parsed_output:
        st.warn(f"No BGP L2VPN EVPN type 1 routes found on DUT {dut}")
        return True

    st.log(f"Checking for prohibited origin values {origin_ips} in type 1 routes on DUT {dut}")

    found_prohibited_routes = []

    # Check each parsed route entry
    for route_entry in parsed_output:
        route_origin = route_entry.get("origin", "").strip()
        route_distinguisher = route_entry.get("route_distinguisher", "").strip()
        route_nexthop = route_entry.get("next_hop", "").strip()
        route_esi = route_entry.get("esi", "").strip()
        route_eth_tag = route_entry.get("eth_tag", "").strip()
        route_vtep_ip = route_entry.get("vtep_ip", "").strip()

        # Check if this route's origin matches any prohibited origin
        if route_origin in origin_ips:
            found_prohibited_routes.append(
                {
                    "origin": route_origin,
                    "route_distinguisher": route_distinguisher,
                    "next_hop": route_nexthop,
                    "esi": route_esi,
                    "eth_tag": route_eth_tag,
                    "vtep_ip": route_vtep_ip,
                    "weight": route_entry.get("weight", ""),
                    "path": route_entry.get("path", ""),
                    "rt": route_entry.get("rt", ""),
                    "et": route_entry.get("et", ""),
                }
            )

    if found_prohibited_routes:
        st.error(
            f"FAILED: Found {len(found_prohibited_routes)} type 1 routes with prohibited origin values on DUT {dut}:"
        )
        for i, route in enumerate(found_prohibited_routes, 1):
            st.log(f"Route {i}:")
            st.log(f"  Origin: {route['origin']}")
            st.log(f"  Route Distinguisher: {route['route_distinguisher']}")
            st.log(f"  Next Hop: {route['next_hop']}")
            st.log(f"  ESI: {route['esi']}")
            st.log(f"  Ethernet Tag: {route['eth_tag']}")
            st.log(f"  VTEP IP: {route['vtep_ip']}")
            st.log(f"  Weight: {route['weight']}")
            st.log(f"  Path: {route['path']}")
            st.log(f"  RT: {route['rt']}")
            st.log(f"  ET: {route['et']}")
        return False
    else:
        st.log(f"SUCCESS: No type 1 routes found with prohibited origin values {origin_ips} on DUT {dut}")
        return True


def verify_type_4_routes_are_not_reoriginated(dut, next_hops: List[str]) -> bool:
    """
    Verify that BGP L2VPN EVPN type 4 routes with specified next hops are not present.
    Type 4 routes are Ethernet Segment (ES) routes used for multi-homing in EVPN.
    If any type 4 routes are found with the prohibited next hops, log all matching routes and return False.

    Args:
        dut (WorkArea): Device under test
        next_hops (List[str]): List of next hop IP addresses that should NOT appear in type 4 routes

    Returns:
        bool: True if no prohibited next hops are found in type 4 routes, False if any are found
    """
    command = "show bgp l2vpn evpn route type 4"
    output = st.vtysh_show(dut, command, skip_tmpl=True, skip_error_check=True)
    parsed_output = st.parse_show(dut, command, output=output, tmpl="show_bgp_l2vpn_evpn_route_type_4.tmpl")

    if not parsed_output:
        st.warn(f"No BGP L2VPN EVPN type 4 routes found on DUT {dut}")
        return True

    st.log(f"Checking for prohibited next hops {next_hops} in type 4 routes on DUT {dut}")

    found_prohibited_routes = []

    # Check each parsed route entry
    for route_entry in parsed_output:
        route_nexthop = route_entry.get("next_hop", "").strip()
        route_distinguisher = route_entry.get("route_distinguisher", "").strip()
        route_esi = route_entry.get("esi", "").strip()
        route_ip = route_entry.get("ip", "").strip()
        route_ip_len = route_entry.get("ip_len", "").strip()

        # Check if this route's next hop matches any prohibited next hop
        if route_nexthop in next_hops:
            found_prohibited_routes.append(
                {
                    "next_hop": route_nexthop,
                    "route_distinguisher": route_distinguisher,
                    "esi": route_esi,
                    "ip": route_ip,
                    "ip_len": route_ip_len,
                    "status_code": route_entry.get("status_code", ""),
                    "route_type": route_entry.get("route_type", ""),
                    "attributes": route_entry.get("attributes", ""),
                    "et": route_entry.get("et", ""),
                    "es_imp_rt": route_entry.get("es_imp_rt", ""),
                    "df_alg": route_entry.get("df_alg", ""),
                    "df_pref": route_entry.get("df_pref", ""),
                }
            )

    if found_prohibited_routes:
        st.error(f"FAILED: Found {len(found_prohibited_routes)} type 4 routes with prohibited next hops on DUT {dut}:")
        for i, route in enumerate(found_prohibited_routes, 1):
            st.log(f"Route {i}:")
            st.log(f"  Next Hop: {route['next_hop']}")
            st.log(f"  Route Distinguisher: {route['route_distinguisher']}")
            st.log(f"  ESI: {route['esi']}")
            st.log(f"  IP: {route['ip']}")
            st.log(f"  IP Length: {route['ip_len']}")
            st.log(f"  Status Code: {route['status_code']}")
            st.log(f"  Route Type: {route['route_type']}")
            st.log(f"  Attributes: {route['attributes']}")
            st.log(f"  ET: {route['et']}")
            st.log(f"  ES Import RT: {route['es_imp_rt']}")
            st.log(f"  DF Algorithm: {route['df_alg']}")
            st.log(f"  DF Preference: {route['df_pref']}")
        return False
    else:
        st.log(f"SUCCESS: No type 4 routes found with prohibited next hops {next_hops} on DUT {dut}")
        return True
