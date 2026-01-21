# SRv6 test plan

## Rev 0.1

- [Revision](#revision)
- [Definition/Abbrevation](#definition/abbrevation)
- [Overview](#overview)
  - [Scope](#scope)
  - [Testbed](#testbed)
- [Setup configuration](#setup-configuration)
- [Test cases](#test-cases)
  - [SIDs distribution test](#SIDs-distribution-test)
  - [END function test. DUT as a Transit node](##END-function-test.-DUT-as-a-Transit-node)
  - [END function test. DUT as a destination node](#END-function-test.-DUT-as-a-destination-node)
  - [END.DT46 function test. IPv4 packet](#END.DT46-function-test.-IPv4-packet)
  - [END.DT46 function test. IPv6 packet](#END.DT46-function-test.-IPv6-packet)
  - [END.DT46 function test. IPv4 packet with END.DT46 assigned for Transit node](#END.DT46-function-test.-IPv4-packet-with-END.DT46-assigned-for-Transit-node)

## Revision

| Rev |     Date    |       Author            |     Change Description      |
|:---:|:-----------:|:------------------------|:----------------------------|
| 0.1 |  19/01/2022 | Intel : Anton Ptashnik  |       Initial version       |

## Definition/Abbrevation

| **Term**     | **Meaning**                            |
|--------------|----------------------------------------|
|    SRv6      | Serment Routing over IPv6                 |
| SID          | Segment ID  |
| SRH          | Segment Routing Header      |
| SL| Segments Left (next active segment)|
|VRF|	Virtual Routing and Forwarding|

## Overview

The purpose is to test the SRv6 feature on SONiC switch intruduced by the corresponding [HLD](https://github.com/Azure/SONiC/blob/9fc2a68b215452d658b6bdd5188092c1b6ee8b01/doc/srv6/srv6-hld-v19.md)

## Scope

Current version is aimed to cover Phase 1 SRv6 functionality defined in the HLD. The plan will be extented as feature development progress made

## Testbed

Supported topologies: t1

## Setup configuration

No changes in testbed hardware config required.
Tests will handle setup/cleanup of needed SRv6 functions on DUT. 

## Used notations

SRv6 operates on packets based on an inserted IPv6 Routing Header (SRH) and packet destination address. Tests use a special short notation to refer to SRH, IP source and destination addresses as:

```
(S0,S2) <S1,S2...SN; SL=N>; (SA,DA)

S0 - IP address of the source SR node that encapsulated the packet
<S1,S2...SN> - SRH segment list with items representing segments
SL - Segments Left
SA - source address of the inner (encapsulated) packet
DA - destination address of the inner (encapsulated) packet
```


## Test cases


## H.Encaps.Red function test. IPv4 packet encapsulation

### Test objective

Verify IPv4 packets get encapsulated in SRv6 with a properly built SRH

### Test steps
1. make sure DUT is configured as follows
```
- H.Encaps.Red is setup
segment list = <S1,S2,S3>
source address = S0
dest IPv4 mask for encap = DA

- route to S1 is set via neighbor N
```
2. send a IPv4 packet to DUT
```
(SA, DA)
payload - any
```
3. verify the packet get forwarded to N and its data as follows
```
(S0, S1) <S2, S3; SL=2>;  (SA, DA)
```

## H.Encaps.Red function test. IPv6 packet encapsulation

### Test objective

Verify IPv6 packets get encapsulated in SRv6 with a properly built SRH

### Test steps
1. make sure DUT is configured as follows
```
- H.Encaps.Red is setup
segment list = <S1,S2,S3>
source address = S0
dest IPv6 mask for encap = DA
- route to S1 is set via neighbor N
```
2. send a IPv6 packet to DUT
```
(SA, DA)
payload - any
```
3. verify the packet get forwarded to N and its data as follows
```
(S0, S1) <S2, S3; SL=2>;  (SA, DA)
```

## END.DT46 function test. IPv4 packet

### Test objective

Verify an end node decapsulates and forwards original IPv4 packets to destination

### Test steps
1. make sure DUT is configured as follows
```
- Vrf "VrfDt46" is created
- Dt46 SID (SLAST) is setup and assigned to VrfDt46
- route via N is setup for inner packet destination (DA)
```
2. send a SRv6-encapsulated IPv4 packet
```
(S0,SLAST) <S1,S2,SLAST; SL=0> (SA, DA)
Next hop count = 10
```
3. verify the decapsulated IPv4 packet is routed to via N
4. verify packet's data (except Ether layer) is the same it was before SRv6 encapsulation

## END.DT46 function test. IPv6 packet

### Test objective

Verify an end node decapsulates and forwards original IPv6 packets to destination

### Test steps
1. make sure DUT is configured as follows
```
- Vrf "VrfDt46" is created
- Dt46 SID (SLAST) is setup and assigned to VrfDt46
- route via N is setup for inner packet destination (DA) 
```

2. send a SRv6-encapsulated IPv6 packet
```
(S0, SLAST) <S1,S2,SLAST; SRL=0> (SA, DA)
Next hop count = 10
```
3. verify the decapsulated IPv4 packet is routed to via N
4. verify packet's data (except Ether layer) is the same it was before SRv6 encapsulation

## END.DT46 function test. IPv4 packet with END.DT46 assigned for Transit node

### Test objective

Verify a switch responds with an error when END.DT46 is not the last node in the packet's SR path

### Test steps
1. make sure DUT is configured as follows
```
- Vrf "VrfDt46" is created
- Dt46 SID (S2) is setup and assigned to VrfDt46
- route via neighbor N is setup for inner packet destination (DA)
- route to S0 is setup via neighbor N
```

2. send a SRv6-encapsulated IPv4 packet
```
(S0,S2) <S1,S2,S3> (SA,DA)
SRL = 2
Next hop count = 64
```
3. verify N does not receive the packet
4. verify DUT responds to S0 with ICMP error code 0 
