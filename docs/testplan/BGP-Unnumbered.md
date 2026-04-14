# BGP Unnumbered Test Plan

- [Overview](#overview)
    - [Scope](#scope)
    - [Testbed](#testbed)
- [Setup configuration](#setup-configuration)
- [Test cases](#test-cases)


## Overview

The goal of this test is to verify that the BGP Unnumbered feature works as expected.  It tests both peer group and individual neighbor configurations.

### Scope

The test is targeting a running SONIC system with fully functioning configuration. The purpose of the test is to test BGP Unnumbered feature, which includes peer group and individual neighbor implementation.

### Related DUT CLI commands

| Command | Comment |
| ------- | ------- |
|Configuration commands|
| router bgp <ASN> | Enter BGP config mode |
| neighbor <interface_name> interface remote-as <remote_as>| neighbor level |
| neighbor <group_name> peer-group| specify group |
| neighbor <interface_name> peer-group <group_name>| binding interface neighbor to peer group |
|Show commands|
| show run bgp | Display the current running BGP configuration |
| show ip bgp summary | Dispaly current neighbor relationships, can be done with ipv6 too |

### Sample DUT configuration files
Neighbor level configs:
router bgp 65001
 neighbor Ethernet0 interface remote-as 65000

Peer group level configs:
router bgp 65001
 bgp router-id 1.1.1.1

 neighbor SPINE peer-group
 neighbor SPINE remote-as 65000
 neighbor SPINE capability extended-nexthop

 neighbor Ethernet0 interface
 neighbor Ethernet0 peer-group SPINE

 address-family ipv4 unicast
  neighbor SPINE activate
 exit-address-family

 address-family ipv6 unicast
  neighbor SPINE activate
 exit-address-family
 
## Test structure
### Setup configuration

The default configuration of DUT is fine.

## Test cases
### Test case #1 - Peer Group

#### Test objective

Configure peer group passwords for IPv4 and IPv6 for specified neighbor and ensure relationship is established.
1. Configure peer group passwords for both IPv4 and IPv6 on DUT
2. Verify neighbor is not up
3. Configure password on neighbor
4. Verify neighbor is up
5. Set a mismatched password on DUT
6. Verify neighbor is not up
7. Turn off passwords on DUT and neighbor

### Test case #2 - Individual Neighbor

#### Test objective
Configure individual passwords for IPv4 and IPv6 for specified neighbor and ensure relationship is established.
1. Configure neighbor passwords for IPv4 and IPv6 on DUT
2. Verify neighbor is not up
3. Configure password on neighbor
4. Verify neighbor is up
5. Set a mismatched password on DUT
6. Verify neighbor is not up
7. Turn off passwords on DUT and neighbor
