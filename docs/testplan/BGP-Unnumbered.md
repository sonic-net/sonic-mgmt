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
### Test case #1 - BGP Unnumbered 

#### Test objective

Verify that a BGP Unnumbered session forms successfully between DUT and peer

Steps:
1. Configure BGP Unnumbered on DUT and peer using interface-based neighbors
2. Enable required address-family (IPv4/IPv6)
3. Check BGP session state

Expected Result:
1. Session state is Established
2. Neighbor uses IPv6 link-local address


### Test case #2 - Route Advertisement and Learning

#### Test objective

Verify routes are exchanged over BGP Unnumbered session

Steps:
1. Configure BGP Unnumbered on DUT and peer using interface-based neighbors
2. Enable required address-family (IPv4/IPv6)
3. Check BGP session state
4. Advertise routes (e.g., loopback prefixes) from DUT
5. Advertise routes from peer

Expected Result:
1. Routes are learned from peer and installed in routing table

### Test case #3 - Traffic Forwarding 

#### Test objective

Verify data-plane traffic using learned routes

Steps:
1. Establish BGP session and exchange routes
2. Send traffic between DUT and peer loopbacks

Expected Result:
1. Traffic successfully reaches destination
2. No packet loss after convergence

### Test case #4 - Link Flap Recovery 

#### Test objective

Verify BGP session resiliency to interface flaps

Steps:
1. Establish BGP session
2. Shutdown DUT interface
3. Bring interface back up

Expected Result:
1. Session transitions: Established → Idle → Established
2. Routes withdrawn and reinstalled correctly

### Test case #5 - Warm Reboot/Fast Reboot/Cold Reboot

#### Test objective

Verify BGP Unnumbered behavior during warm reboot

Steps:
1. Establish BGP session and traffic flow
2. Perform warm/Fast/Cold reboot on DUT

Expected Result:
1. Session recovers automatically
2. Minimal traffic disruption
3. Routes preserved or quickly relearned

### Test case #6 - Peer-Group Neighbor Establishment

#### Test objective

Verify BGP Unnumbered sessions form using peer-group configuration

Steps:
1. Configure peer-group on DUT and peer
2. Associate interface neighbors with peer-group
3. Activate address-family

Expected Result:
1. All sessions are Established
2. Peer-group applied correctly

### Test case #7 - Route Exchange via Peer-Group

#### Test objective

Verify route exchange works correctly with peer-group

Steps:
1. Advertise routes from DUT
2. Advertise routes from peers

Expected Result:
1. Routes learned from all peers and installed in routing table

### Test case #8 - Link Flap with Peer-Group

#### Test objective

Verify only affected sessions reset within a peer-group

Steps:
1. Establish multiple peer-group sessions
2. Flap one interface

Expected Result:
1. Only that neighbor resets
2. Other sessions remain stable
3. Routes reconverge correctly

### Test case #9 - Traffic Forwarding with Peer-Group

#### Test objective

Verify traffic forwarding across multiple peer-group neighbors

Steps:
1. Establish sessions and exchange routes
2. Send traffic

Expected Result:
1. Traffic successfully reaches destination
2. No packet loss after convergence

### Test case #10 - Warm Reboot/Fast Reboot/Cold Reboot

#### Test objective

Verify BGP Unnumbered peer-group behavior during warm reboot

Steps:
1. Establish BGP session and traffic flow
2. Perform warm/Fast/Cold reboot on DUT

Expected Result:
1. Session recovers automatically
2. Minimal traffic disruption
3. Routes preserved or quickly relearned
