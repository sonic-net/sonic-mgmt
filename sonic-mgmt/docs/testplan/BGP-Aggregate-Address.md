# BGP Aggregate Address Test Plan

- [Overview](#overview)
  - [Scope](#scope)
- [Setup configuration](#setup-configuration)
- [Test Cases](#test-cases)
  - [Common Validator for Every Case](#Common-Validator-for-Every-Case)
  - [Test with parameters Combination](#Test-with-parameters-Combination)
  - [Test BBR Features State Change](#Test-BBR-Features-State-Change)
  - [Test BGP Container Restart](#Test-BGP-Container-Restart)
  - [Capacity Test and Stress Test](#Capacity-Test-and-Stress-Test)
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
1. Query config db to get the aggregate addresses configuration and BBR status.
2. Query state db to get all state for each aggregate addresses.
3. Query bgp runing config to get aggregate addresses.
4. When BBR is enabled, check if all aggregate addresses in config are in state db and having active state, check if all aggregate addresses are in bgp running config.
5. When BBR is disable, check if all aggregate addresses in config with bbr required true are in state db and having inactive state, and make sure they are not in bgp running config. check if all aggregate addresses in config with brr required false are in state db and having active state, check if all aggregate addresses are in bgp running config. 

### Test with parameters Combination
Test the feature with all parameters combination to validate the feature as much as possible.
1. Leverage the pytest parameters to combinate all possible config of aggregate address.
2. Generate config for address adding and removing.
3. Apply address adding config by GCU.
4. Validate state by Common Validator metion above.
5. Apply address removing config by GCU.
6. Validate state by Common Validator metion above.

### Test BBR Features State Change
During device up, the BBR state may change, and this feature should take action accordingly.
1. Enable BBR feature on device.
2. Generate config for address adding and removing with bbr required true.
3. Apply address adding config by GCU.
5. Validate state by Common Validator metion above.
5. Disable BBR feature on device.
6. Validate state by Common Validator metion above.
7. Enable BBR feature on device again.
8. Validate state by Common Validator metion above.
9. Apply address removing config by GCU.

### Test BGP Container Restart
Validate when bgp container restarted, the aggregate address in bgpd configuration won't loss.
1. Generate config for address adding and removing with bbr required true.
2. Apply address adding config by GCU.
3. Validate state by Common Validator metion above.
4. Restart bgpd container on host.
5. Wait util bgpd container is up.
7. Validate state by Common Validator metion above.
8. Apply address removing config by GCU.

### Capacity Test and Stress Test
Add as many aggregate addresses as possible on 202505 image to get a baseline capacity.
Write test to add an equal number of aggregate addresses as baseline capactiy and validate there is no any error log and down container. After capacity test, start ptf traffic thread to validate dataplane works fine and query dut resources to validate managment plane works fine.
1. Generate config for 1000 different addresses adding and removing.
2. Apply 1000 address adding config by GCU.
3. Validate state by Common Validator metion above.
4. Start ptf traffic thread and count packets sent and received to make sure dataplane works fine.
5. Apply 1000 address removing config by GCU.
6. Validate state by Common Validator metion above.

### Link Flapping Test
Add some aggregate addresses, randomly select a interface contains sub-address of aggregate as object, shutdown the interface, verify dataplane and management plane work fine, starup the interface, verify dataplen and management plane work fine.
1. Generate config for address adding and removing.
2. Apply address adding config by GCU.
3. Validate state by Common Validator metion above.
4. Randomly select a interface contains sub-address of aggregate as object.
5. Shutdown the interface
6. Start ptf traffic thread and count packets sent and received to make sure dataplane works fine.
7. Apply address removing config by GCU.
8. Validate state by Common Validator metion above.