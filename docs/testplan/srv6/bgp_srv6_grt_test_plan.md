# BGP SRv6 GRT system test plan

## Objective

Verify the SONiC integration for BGP SRv6 Global Routing Table (GRT) service SID
advertisement and forwarding described by the
[BGP SRv6 GRT HLD](https://github.com/cscarpitta/SRv6-SONiC/blob/bgp_srv6_grt/doc/srv6/srv6_grt_hld.md).

The test suite exercises both supported CONFIG_DB-to-FRR implementations:
frrcfgd and bgpcfgd. A module-scoped fixture switches the endpoint devices to
each mode, restarts BGP, runs that mode's cases, then restores the original
mode. Control-plane and dataplane cases are separate modules so they can be
selected independently while sharing the same backend matrix.

The tests configure `BGP_GLOBALS|default.srv6_locator`,
`BGP_GLOBALS_AF|default|<AF>.srv6_sid_advertise` and the optional
`srv6_sid_advertise_route_map`, `BGP_NEIGHBOR_AF|default|<peer>|<AF>` fields,
and `STATIC_ROUTE` entries. Route-map cases create family-specific prefix sets
and maps in CONFIG_DB.

## Testbed and prerequisites

- Control-plane tests run on `ciscovs-7nodes` and `force10-7nodes`.
- Dataplane tests run on `ciscovs-7nodes`, whose PTF attachment provides the
  GRT ingress port used by this test.
- The 7-node topology provides the logical path ingress PE1 (the DUT P1) →
  transit P (P3) → egress PE2 (neighbor PE1). The existing BGP session carries
  the service route; dataplane tests install a temporary CONFIG_DB static route
  for the service SID through P3, forcing the packet path through the transit
  router.
- Control-plane coverage is limited to the two currently provisioned 7-node
  topologies with the required PE1/P3 neighbor inventory. Dataplane coverage is
  limited to ciscovs-7nodes because its PTF port mapping is used for injection.
- The egress PE must provide the `lsid1` SRv6 locator. P3 must have IPv6
  reachability to the egress PE's locator.
- Temporary GRT routes are created through `STATIC_ROUTE` CONFIG_DB entries.
  No test configures BGP, static routes, or SRv6 settings by invoking vtysh.

## Test cases

Each case below runs once with frrcfgd and once with bgpcfgd.

| Coverage | Test | Expected result |
| --- | --- | --- |
| IPv4 SID advertisement | `test_bgp_srv6_grt_sid_advertisement[ipv4]` | Ingress PE installs the route with `vpn_sid` and seg6 FIB action; egress PE programs uDT46. |
| IPv6 SID advertisement | `test_bgp_srv6_grt_sid_advertisement[ipv6]` | Same checks for an IPv6 GRT route. |
| IPv4 route-map policy | `test_bgp_srv6_grt_sid_advertise_route_map_policy[ipv4]` | Permitted route has `vpn_sid`; denied route is received without it. |
| IPv6 route-map policy | `test_bgp_srv6_grt_sid_advertise_route_map_policy[ipv6]` | Permitted route has `vpn_sid`; denied route is received without it. |
| IPv4 forwarding | `test_bgp_srv6_grt_data_plane_forwarding[ipv4]` | P3 observes the outer packet with the service SID destination on ingress and egress; PE2 decapsulates and forwards the IPv4 packet toward P3. |
| IPv6 forwarding | `test_bgp_srv6_grt_data_plane_forwarding[ipv6]` | Same path checks for an IPv6 inner packet. |

Route-map cases use family-specific prefix sets and maps. Both inner packet
families are covered by the same forwarding scenario.

Tests restore modified CONFIG_DB state and the original config-daemon mode;
dataplane tests also remove the temporary service-SID route through P3.
