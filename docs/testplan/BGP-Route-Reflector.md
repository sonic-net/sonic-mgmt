# BGP Route Reflector Test Plan

- [Overview](#overview)
    - [Scope](#scope)
    - [Testbed](#testbed)
- [Setup configuration](#setup-configuration)
- [Test cases](#test-cases)


## Overview

The goal of this test is to verify that the BGP Route Reflector (RR) feature works as expected. It validates route reflection behavior, loop prevention, and correct route propagation between iBGP clients.

### Scope
This test targets a running SONiC system with a valid configuration.

The purpose is to validate BGP Route Reflector functionality, including:
iBGP session establishment between RR and clients
Route reflection between clients via RR
Proper handling of BGP attributes (next-hop, originator-id, cluster-id)
Behavior when RR configuration is missing

### Testbed
Minimum topology:

Client1 -------- RR -------- Client2

    All devices are in the same ASN (iBGP)
    RR is configured with route-reflector-client
    No direct peering between clients

### Related DUT CLI commands

| Command | Comment |
| ------- | ------- |
|Configuration commands|
| router bgp <ASN> | Enter BGP config mode |
| neighbor <IP> remote-as <ASN>| Configure iBGP neighbor |
| neighbor <IP> route-reflector-client| Enable RR client |
| neighbor <IP> next-hop-self| Set next-hop self (optional) |
|Show commands|
| show run bgp | Display the current running BGP configuration |
| show ip bgp summary | Dispaly current neighbor relationships, can be done with ipv6 too |
| show bgp ipv4 unicast | Show IPv4 routes |
| show bgp ipv6 unicast | Show IPv6 routes |

### Sample DUT configuration files
Route Reflector Configuration

    router bgp 65001
     bgp router-id 1.1.1.1
    
     neighbor 10.0.0.1 remote-as 65001
     neighbor 10.0.0.1 route-reflector-client
    
     neighbor 10.0.0.2 remote-as 65001
     neighbor 10.0.0.2 route-reflector-client
    
     address-family ipv4 unicast
      neighbor 10.0.0.1 activate
      neighbor 10.0.0.2 activate
 
## Test structure
### Setup configuration

    Ensure all nodes are reachable
    Configure iBGP sessions between RR and clients
    Do not configure client-to-client peering

## Test cases
### Test case #1 - RR Neighbor Establishment 

#### Test objective

Verify iBGP sessions form between RR and clients

Steps:
1. Configure RR with route-reflector-client
2. Configure iBGP neighbors on clients toward RR

Expected Result:
1. All sessions (RR ↔ clients) are Established
2. No direct client-to-client sessions exist

### Test case #2 - Route Reflection

#### Test objective

Verify RR reflects routes between clients

Steps:
1. Advertise a prefix from Client1
2. Ensure no direct peering between Client1 and Client2

Expected Result:
1. Client2 receives the route from Client1 via RR
2. Route is present in BGP table on Client2
3. Next-hop is:
   . RR (if next-hop-self configured), or
   . original next-hop (default behavior)

### Test case #3 - No Reflection Without RR Config 

#### Test objective

Ensure routes are not reflected if RR config is missing

Steps:
1. Remove route-reflector-client from RR
2. Advertise a prefix from Client1

Expected Result:
1. Route is NOT received by Client2

### Test case #4 - Next-Hop Handling 

#### Test objective

Verify correct next-hop behavior in RR topology

Steps:
1. Advertise a prefix from Client1
2. Check route attributes on Client2

Expected Result:
1. Next-hop behavior matches config:
    unchanged OR
    RR address if next-hop-self is configured
