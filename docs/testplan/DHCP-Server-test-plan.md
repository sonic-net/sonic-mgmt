# DHCP Server Test Plan

- [Overview](#overview)
  - [Scope](#scope)
  - [Testbed](#testbed)
- [Setup configuration](#setup-configuration)
- [Test Cases](#test-cases)
  - [Server/Relay test case](#serverrelay-test-case)
  - [Default test case](#default-test-case)
  - [Emulate port change](#emulate-port-change)
  - [Multi-Vlan](#multi-vlan)

## Overview

The purpose is to test the functionality of dnsmasq DHCP Server on SONiC switch DUT.

## Scope

The test is targeting a running SONiC system with dhcp server configured.
Purpose of the test is to verify a DHCP Server on SONiC successfully distributed expected IP addresses to clients

## Testbed

Supported topologies: t0, t0-52

## Setup configuration

    1. Configure DHCP server option in config_db. DHCP Relay will be disabled if DHCP server is enabled.
	2. Start dnsmasq using dnsmasq -p 0 --conf-dir=/etc/dnsmasq.d/ -z. 
	3. Update desired subnet ip in updateHostAddresses.py. Start the python script using updateHostAddresses.py.

## Test cases

## Server/Relay test case

If dhcp_server flag is enabled:
- dnsmasq is enabled
- dhcrelay is disabled
- dhcp6relay is enabled

If dhcp_server flag is disabled:
- dnsmasq is disabled
- dhcrelay is enabled
- dhcp6relay is enabled

### Test objective

Verify that DHCP Server/DHCP Relay is running accordingly based on dhcp_server flag in config_db

## Default test case

For every port in ptf docker:
- client broadcasts DISCOVER message
- server sends back OFFER message containing client IP
- client broadcasts REQUEST message
- server sends back ACK message, transaction complete

### Test objective

Mock DHCP client packets and verify that server sends back expected messages.
Verify transactions between DHCP client and server are valid. Client is assigned a valid IP address

## Emulate port change

Once all clients are assigned an IP:
- Change the MAC address of the interface in the ptf container
- Sends DISCOVER packet from the changed MAC interface
- Offer received from DHCP Server should retain the same IP address

### Test objective

This test simluates a device being unplugged from a port and replaced with a new device. New device should expect the same address as before.

## Multi-Vlan

Run default tests on 3 Vlans
- Add two more Vlans
- At least one ptf port is mapped to each Vlan
- Check that the ports that's mapped'to each VLAN receive the corresponding expected IP Addresses

Expected response from dhcp server:
- ip address
- subnet mask
- gateway ip address (should match vlan interface ip)

### Test objective

This test checks that dnsmasq distributes corresponding IP depending on the subnet mapped to each VLAN in minigraph to the ports in ptf
