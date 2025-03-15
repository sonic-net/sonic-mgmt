# DHCP Server Test Plan

- [Overview](#overview)
  - [Scope](#scope)
  - [Testbed](#testbed)
- [Setup configuration](#setup-configuration)
- [Test Cases](#test-cases)
  - [Test Address Add](#Test-Address-Add)
  - [Test Address Remove](#Test-Address-Remove)
  - [Test Parameter Update](#Test-Parameter-Update)
  - [Test With Random Operations](#Test-With-Random-Operations)
  - [Test BBR Features State Change](#Test-BBR-Features-State-Change)
  - [Test BGP Route Announcement](#Test-BGP-Route-Announcement)
  - [Test BGP Container Restart](#Test-BGP-Container-Restart)
  - [Test Config Reload](#Test-Config-Reload)

## Overview

This test plan is for feature bgp aggregate address with BBR awareness

## Scope

This test plan include test cases aggregate address remove/add/update with various parameters.
Besides, This test plan will cover multiple scenarios including state change of BBR feature, BGP container restart and config reload.

## Testbed

Supported topologies: T1*

## Setup configuration

This test requires DUT has port, vlan and portchannel, the default configuration of DUT is ok.

## Test cases
### Test Address Add
Add address with random parameters and random value, and check bgpd running config and state db.

### Test Address Remove
Remove address and check bgpd running config and state db.

### Test Parameter Update
Update a random parameter of address, and check bgpd running config and state db.

### Test With Random Operations
Generate a sequence of operations including add and remove, execute those operation one by one and check bgpd running config and state db.

### Test BBR Features State Change
1. enabled to disabled
2. disabled to enabled
3. exist to not exist

### Test BGP Route Announcement
Inspect route table on peer to validate if parameters take effect.
1. summary-only: only aggregated should in route table of peers.
2. as-set: as set of aggregate address should exist in route table of peers.
3. prefix-list: route maps applied on aggregate address in prefix list should work.

### Test BGP Container Restart
Validate when bgp container restarted, the aggregate address in bgpd configuration won't loss.

### Test Config Reload
Validate when config was reload, aggregate address in config db will be syncd to bgpd running config and state db.
