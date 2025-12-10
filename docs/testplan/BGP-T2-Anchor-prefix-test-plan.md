# BGP T2 Anchor Prefix test plan

## Overview

The purpose of this test is to test Anchor prefix in T2, make sure the Anchor prefix would be installed correctly in DUT and advertised to BGP neighbor with correct community.

## Scope

This test is targeted in T2 SONiC switch

## Test Case

### Common Verification Functions

#### verify_prefix_list_in_db

Run `prefix_list status` to confirm prefixes are added to CONFIG_DB

#### verify_prefix_in_table

Based on parameters `table` and `present` to verify whether prefixes in fib / bgp table
- fib table: check `ROUTE_TABLE` in APPL_DB
- bgp table: use cmd `vtysh -n {asic_index} -c 'show bgp {ip_version} {prefix}'`

#### verify_prefix_announce_to_neighbor

Based on parameters `advertised_neighbor_list` and `no_advertised_neighbor_list` to verify whether prefixes advertised to correct neighbor or not.
- For iBGP neighbor, make sure it wouldn't receive local Anchor route by vtysh in any scenario
- For eBGP neighbor, login to the neighbor host and use `show {ip_version} bgp {prefix}` to check whether routes are advertised to neighbor with correct community or not. Notice: maybe need `neighbor {neighbor_ip} send community` in DUT to enable sending community

### Test Module

#### test_anchor_prefix_list_cli

- Use `prefix_list add` cmd to add Anchor prefix list
- Invoke above common verification functions to verify
    - Anchor prefix in DB
    - Anchor prefix in bgp table but not in fib table
    - Prefix routes are not advertised to iBGP neighbors but to eBGP neighbors
- Use `prefix_list remove` cmd to delete Anchor prefix list
- Invoke above common verification functions to verify
    - Anchor prefix not in DB
    - Anchor prefix not in bgp and fib table
    - Prefix routes are not advertised to all BGP neighbors

#### test_anchor_prefix_list_TSA

- Use `prefix_list add` cmd to add Anchor list
- Invoke above common verification functions to verify
    - Anchor prefix in DB
    - Anchor prefix in bgp table but not in fib table
    - Prefix routes are not advertised to iBGP neighbors but to eBGP neighbors
- Use `TSA` cmd to TSA device
- Invoke above common verification functions to verify
    - Anchor prefix in DB
    - Anchor prefix in bgp table but not in fib table
    - Prefix routes are not advertised to all BGP neighbors
- Use `TSB` cmd to TSB device
- Invoke above common verification functions to verify
    - Anchor prefix in DB
    - Anchor prefix in bgp table but not in fib table
    - Prefix routes are not advertised to iBGP neighbors but to eBGP neighbors
- Use `prefix_list remove` cmd to delete Anchor prefix list

#### test_anchor_prefix_list_golden_config

- Generate golden_config_db.json with prefix list, then run `sudo config load_minigraph -o -y` to load minigraph with golden config
- Invoke above common verification functions to verify
    - Anchor prefix in DB
    - Anchor prefix in bgp table but not in fib table
    - Prefix routes are not advertised to iBGP neighbors but to eBGP neighbors
- Use `prefix_list remove` cmd to delete Anchor prefix list

#### test_anchor_prefix_specific_route

- Add a Anchor prefix which doesn't have specific routes by `prefix_list add` cmd
- Invoke verify_prefix_announce_to_neighbor to verify whether the prefix is advertised to neighbor (It's expected not to advertise Anchor prefix to neighbor)
- Announce a specific route under Anchor prefix from downstream neighbor by function `announce_routes`
- Invoke verify_prefix_announce_to_neighbor to verify whether the prefix is advertised to neighbor (It's expected to advertise anchor prefix to neighbor)
- Use `prefix_list remove` cmd to delete Anchor prefix list
- Withdraw previous specific route by function `announce_routes` with parameter `withdraw`

#### test_anchor_prefix_stress

- Generate a GCU patch with a large number of Anchor prefixes (10k for now)
- Invoke above common verification functions to verify
    - All Anchor prefixes in DB
    - All Anchor prefixes in bgp table but not in fib table
    - All prefixes routes are advertised to all BGP neighbors
- Restart bgp container, check whether BGP session can be established and be stable
- Invoke above common verification functions to verify
    - All Anchor prefixes in DB
    - All Anchor prefixes in bgp table but not in fib table
    - All prefixes routes are advertised to all BGP neighbors
- Invoke `config reload` to recover
