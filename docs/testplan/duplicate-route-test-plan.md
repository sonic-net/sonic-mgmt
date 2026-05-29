# Duplicate-routes test plan

* [Overview](#Overview)
   * [Scope](#Scope)
   * [Testbed](#Testbed)
* [Setup configuration](#Setup%20configuration)
* [Test cases](#Test%20cases)

## Overview
The purpose is to make sure that duplicate routes matching an existing loopback IP or vlan IP prefix does not cause orchagent to crash or restart.
The test expects that the device is configured with a baseline configuration that has both loopback and vlan interfaces with valid IPv4 and IPv6 addresses.

### Scope
The test is targeting a running SONiC system with fully functioning configuration. The purpose of the test is to verify that SAI error SAI_STATUS_ITEM_ALREADY_EXISTS for route objects are gracefully handled by orchagent.
The expectation is that orchagent should not crash or restart in such cases.

### Testbed
The test could run on T0/M0 testbeds that have both loopback and vlan interface configurations.

## Setup configuration
This test requires that loopback and vlan interfaces are configured with valid IPv4 and IPv6 addresses. All other required configurations are added dynamically at the beginning of the test and restored at the end of the test.

## Test
The test will verify that routes matching a loopback IP prefix or vlan IP prefix does not cause orchagent to crash or restart.


## Test cases

### Test case # 1 – Duplicate Loopback IPv4 route

#### Test objective
Verify that adding a duplicate IPv4 route that matches a Loopback interface IPv4 address does not cause orchagent crash/restart

#### Test steps
* Setup valid interface IPv4 addresses and neighbors on any of the UP interfaces on the device
* Generate route with prefix that matches a Loopback IPv4 address on the device and nexthop via one of the neighbors configured before.
* Save PID of orchagent before configuring the routes generated in the step before
* Configure the generated route in APP_DB using swssconfig utlity
* Make sure that expected log messages are seen using loganalyzer to confirm that the functionality is being tested as intended
* Confirm that orchagent is still running and verify that newly obtained PID of orchagent matches the previously saved PID
* Restore the DUT configuration by removing the previouly configured route, IP addresses and neighbors

### Test case # 2 – Duplicate Loopback IPv6 route

#### Test objective
Verify that adding a duplicate IPv6 route that matches a Loopback interface IPv6 address does not cause orchagent crash/restart

#### Test steps
* Setup valid interface IPv6 addresses and neighbors on any of the UP interfaces on the device
* Generate route with prefix that matches a Loopback IPv6 address on the device and nexthop via one of the neighbors configured before.
* Save PID of orchagent before configuring the routes generated in the step before
* Configure the generated route in APP_DB using swssconfig utlity
* Make sure that expected log messages are seen using loganalyzer to confirm that the functionality is being tested as intended
* Confirm that orchagent is still running and verify that newly obtained PID of orchagent matches the previously saved PID
* Restore the DUT configuration by removing the previouly configured route, IP addresses and neighbors

### Test case # 3 – Duplicate Vlan IPv4 route

#### Test objective
Verify that adding a duplicate IPv4 route that matches a Vlan interface IPv4 address does not cause orchagent crash/restart

#### Test steps
* Setup valid interface IPv4 addresses and neighbors on any of the UP interfaces on the device
* Generate route with prefix that matches a Vlan IPv4 address on the device and nexthop via one of the neighbors configured before.
* Save PID of orchagent before configuring the routes generated in the step before
* Configure the generated route in APP_DB using swssconfig utlity
* Make sure that expected log messages are seen using loganalyzer to confirm that the functionality is being tested as intended
* Confirm that orchagent is still running and verify that newly obtained PID of orchagent matches the previously saved PID
* Restore the DUT configuration by removing the previouly configured route, IP addresses and neighbors

### Test case # 4 – Duplicate Vlan IPv6 route

#### Test objective
Verify that adding a duplicate IPv6 route that matches a Vlan interface IPv6 address does not cause orchagent crash/restart

#### Test steps
* Setup valid interface IPv6 addresses and neighbors on any of the UP interfaces on the device
* Generate route with prefix that matches a Vlan IPv6 address on the device and nexthop via one of the neighbors configured before.
* Save PID of orchagent before configuring the routes generated in the step before
* Configure the generated route in APP_DB using swssconfig utlity
* Make sure that expected log messages are seen using loganalyzer to confirm that the functionality is being tested as intended
* Confirm that orchagent is still running and verify that newly obtained PID of orchagent matches the previously saved PID
* Restore the DUT configuration by removing the previouly configured route, IP addresses and neighbors
