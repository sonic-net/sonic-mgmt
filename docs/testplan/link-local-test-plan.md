- [Overview](#overview)
    - [Scope](#scope)
    - [Testbed](#testbed)
- [Setup configuration](#setup-configuration)
- [Test cases](#test-cases)

# Forwarded Link-local traffic on MSFT Hwskus 

## Overview

The goal of this test is to verify that MSFT hwsku will allow packets with link-local source/destination IP to be forwarded by the dut.

### Scope

The test is targeting a running SONIC system with fully functioning configuration. The purpose of the test is to test that traffic with link-local source/destination IP is recived and routed by the dut.

### Related DUT CLI commands

| Configuration Command | Comment |
| ------- | ------- |
| config interface ip add | To add link local addres to DUT interface |

| Show Command | Comment |
| ------- | ------- |
| show interfaces counters | Display the interfaces counters |
| show ip route | Dispaly rounting on DUT |

### Related DUT configuration files

N/A

### Related SAI APIs

N/A

## Test structure
### Setup configuration

This test requires a running SONIC system with fully functioning configuration. 
This capability is only supported on systems that have SAI_NOT_DROP_SIP_DIP_LINK_LOCAL=1 in sai.profile.
the tests are supported on all topologies and are covering router portes, port channel and ports in vlan.

### Configuration scripts

N/A

## Test cases
### Test case #1 and #2 - IPv4 and IPv6 Link-Local Source IP Traffic

#### Test objective

Verify that traffic sent from PTF with IPv4/IPv6 source IP is being forwaded.
1. send packets via scapy from PTF with Link local source ip address
2. Verify packets are routed
3. Verify Counters have increased for both links.

### Test case #3 - IPv4 Link-Local Destination IP Traffic

#### Test objective
Verify that traffic sent from PTF with IPv4 destination IP is being forwarded by DUT.
1. Add an Ipv4 Link-local address to PTF interfaces.
2. Add dut interfaces to Vlan.
3. Send traffic via scapy from PTF with Link local destination ip address
4. Verify packets are routed
5. Verify Counters have increased for both links.

### Test case #4 - IPv6 Link-Local Destination IP Traffic

#### Test objective
Verify that traffic sent from PTF with IPv6 destination IP is being forwarded by DUT.
1. Add dut interfaces to Vlan.
2. Send traffic via scapy from PTF with Link local destination ip address
3. Verify packets are routed
4. Verify Counters have increased for both links.

