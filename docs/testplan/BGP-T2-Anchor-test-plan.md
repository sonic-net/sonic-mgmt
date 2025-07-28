# BGP T2 Anchor test plan

## Overview

The purpose of this test is to test Anchor in T2, make sure the aggregate routes would be installed correctly in DUT and advertised to BGP neighbor with correct community.

## Scope

This test is target in T2 SONiC switch

## Test Case

### Common Verification Functions

#### verify_prefix_list_in_db

Run `prefix_list status` to confirm prefixes are added to CONFIG_DB

#### verify_prefix_in_table

Verify whether prefixes in fib / bgp table
- fib table: use cmd `vtysh -n {asic_index} -c 'show {ip_version} route {prefix}'` and local Anchor route is not expected to be installed in fib table
- bgp table: use cmd `vtysh -n {asic_index} -c 'show bgp {ip_version} {prefix}'` and local Anchor route is expected to be installed in fib table

#### verify_prefix_announce_to_neighbor

- For iBGP neighbor, make sure it wouldn't receive Anchor route by vtysh
- For eBGP neighbor, login to the neighbor host and use `show {ip_version} bgp {prefix}` to check whether routes are advertised to neighbor with correct community. Notice: maybe need `neighbor {neighbor_ip} send community` in DUT to enable sending community

### Test Module

#### test_anchor_prefix_list_cli

Use `prefix_list add` cmd to add aggregate route list, then invoke above common verification functions to verify.

#### test_anchor_prefix_list_golden_config

Generate golden_config_db.json with prefix list, then run `sudo config load_minigraph -o -y` to load minigraph with golden config, then invoke above common verification functions to verify.
