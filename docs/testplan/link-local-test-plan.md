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
This capability is only supported on MSFT hwskus.

### Configuration scripts

N/A

## Test cases
### Test case #1 and #2 - IPv4 and IPv6 Link-Local Source IP Traffic

#### Test objective

Verify that traffic sent from PTF with IPv4/IPv6 source IP is being forwaded from downlinks to uplink.
1. sent packets via scapy from PTF with Link local source ip address
2. Verify packets are routed
3. Verify Counters have increased for both up and down links.

### Test case #3 - IPv4 Link-Local Destination IP Traffic

#### Test objective
Verify that traffic sent from PTF with IPv4 destination IP is being recived by the dut port.
1. Add an Ipv4 Link-local address to DUT interface (remove interface from vlan if need be).
2. Send traffic to the DUT interface IPv4 link-local address. The packet is to be sent directly to the port interface.
3. Verify Counters have increased for the inteface on dut

### Test case #4 - IPv6 Link-Local Destination IP Traffic

#### Test objective
Verify that traffic sent from PTF with IPv6 destination IP is being recived by the dut port.
1. Send traffic to the DUT interface IPv6 link-local address (the interfaces has an IPv6 Link-local IP by default). The packet is to be sent directly to the port interface.
2. Verify Counters have increased for the inteface on dut

