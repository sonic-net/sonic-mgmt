# DHCP Server Test Plan

- [Overview](#overview)
  - [Scope](#scope)
- [Setup configuration](#setup-configuration)
- [Test Cases](#test-cases)
  - [Common Validator for Every Case](#Common-Validator-for-Every-Case)
  - [Test with A Sequcen of Operations](#Test-with-A-Sequcen-of-Operations)
  - [Test with parameters Combination](#Test-with-parameters-Combination)
  - [Test Address Add](#Test-Address-Add)
  - [Test Address Remove](#Test-Address-Remove)
  - [Test Parameter Update](#Test-Parameter-Update)
  - [Test BBR Features State Change](#Test-BBR-Features-State-Change)
  - [Test BGP Container Restart](#Test-BGP-Container-Restart)
  - [Test Config Reload](#Test-Config-Reload)
  - [Capacity Test](#Capacity-Test)
  - [Stress Test](#Stress-Test)
  - [Link Flapping Test](#Link-Flapping-Test)

## Overview

This test plan is for feature bgp aggregate address with BBR awareness, HLD link: https://github.com/sonic-net/SONiC/blob/master/doc/BGP/BGP-route-aggregation-with-bbr-awareness.md.

## Scope

This test plan include test cases aggregate address remove/add/update with various parameters.
Besides, This test plan will cover multiple scenarios including state change of BBR feature, BGP container restart and config reload.

## Setup configuration

The default configuration of DUT is fine.

## Test cases
### Common Validator for Every Case
When run test cases, we need to validate the config db, the state db and bgp running config to make sure this feature works as expected.

### Test with A Sequcen of Operations
To put some test stress on this feature, we will generate a seuqence of operations, including add, remove, update, change bbr state, and apply those operations one by one and validate config after each operation.

### Test with parameters Combination
Test the feature with all parameters combination to validate the feature as much as possible.

### Test Address Add
Add address with random parameters and random value by GCU and validate.

### Test Address Remove
Remove address by GCU and validate.

### Test Parameter Update
Update a random parameter of address by GCU and validate.

### Test BBR Features State Change
During device up, the BBR state may change, and this feature should take action accordingly, we need test case to cover scenarios like:
1. BBR state turn to disabled.
2. BBR state turn to enabled.

### Test BGP Container Restart
Validate when bgp container restarted, the aggregate address in bgpd configuration won't loss.

### Test Config Reload
Validate when config was reload, aggregate address in config db will be syncd to bgpd running config and state db.

### Capacity Test
Add as many aggregate addresses as possible on 202505 image to get a baseline capacity.
Write test to add an equal number of aggregate addresses as baseline capactiy and validate there is no any error log and down container.

### Stress Test
After capacity test, start ptf traffic thread to validate dataplane works fine and query dut resources to validate managment plane works fine.

### Link Flapping Test
Add some aggregate addresses, randomly select a interface contains sub-address of aggregate as object, shutdown the interface, verify dataplane and management plane work fine, starup the interface, verify dataplen and management plane work fine.