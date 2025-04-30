# IPv4 Port Based DHCP Server Test Plan

## Related Documents
|**Document Name**|**Link**|
|-----------------|--------|
|BGP Router ID Explicitly Configured|[BGP Router ID Explicitly Configured HLD](https://github.com/sonic-net/SONiC/blob/master/doc/BGP/BGP-router-id.md)|

## Overview

With the feature **BGP Router ID Explicitly Configured**, we can decouple BGP sessions with Loopback IPv4 address in device.

## Scope

### Test Scenario

The tests will include:

1. Verify router ID specifying has higher priority than Loopback IP.
2. Verify BGP would work well without Loopback IP.

This feature has been supported in multi-asic and single-asic, and using logic is similar. But for now, this test plan only covers single-asic scenario, multi-asic part would be added in the future if needed.

### Supported Topology

Test cases should run on all topologies.

## Test Case

### Common function

#### verify_bgp
1. Verify BGP router ID in DUT by parsing output of `show ip bgp sum`
2. Verify peer BGP router ID (DUT) in BGP neighbor side by parsing output of `show ip bgp neighbors <remote p2p ip>`
3. Verify BGP sessions are established and align with running config

### Test module test_bgp_router_id.py
This module is to test BGP router ID in single asic.

#### test_bgp_router_id_default

* **Test objective**

  To test in default scenario (BGP router ID is not specified explicitly), BGP router ID would be set as IPv4 address of Loopback0.

* **Test detail**
  * `verify_bgp` to check BGP router ID and sessions status.

#### test_bgp_router_id_set

* **Test objective**

  To test when BGP router ID is set and Loopback0 IPv4 address is configured, BGP router ID would be set as router ID in CONFIG_DB rather than IPv4 address of Loopback0 and BGP would work well.

* **Setup**
  * Add BGP router ID to CONFIG_DB.
  * Restart BGP container.
* **Teardown**
  * Remove BGP router ID in CONFIG_DB.
  * Restart BGP container.

* **Test detail**
  * `verify_bgp` to check BGP router ID and sessions status.
  * Verify IPv4 address of Loopback0 has been advertised to neighbors.

#### test_bgp_router_id_set_without_loopback_ipv4

* **Test objective**

  To test when BGP router ID is set and Loopback0 IPv4 address is not configured, BGP router ID would be set as router ID in CONFIG_DB and BGP would work well

* **Setup**
  * Add BGP router ID to CONFIG_DB.
  * Remove IPv4 address of Loopback0.
  * Restart BGP container.
* **Teardown**
  * Remove BGP router ID in CONFIG_DB.
  * Add IPv4 address of Loopback back.
  * Restart BGP container.

* **Test detail**
  * `verify_bgp` to check BGP router ID and sessions status.
