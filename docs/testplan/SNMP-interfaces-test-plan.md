# SNMP interfaces test plan

* [Overview](#Overview)
   * [Scope](#Scope)
   * [Testbed](#Testbed)
* [Setup configuration](#Setup%20configuration)
* [Test cases](#Test%20cases)

## Overview
The purpose is to test that SNMP port MIB objects are functioning properly on the SONIC switch DUT.

### Scope
The test is targeting a running SONIC system with fully functioning configuration. The purpose of the test is not to test specific API, but functional testing of SNMP on SONIC system.

### Testbed
The test will run on any testbeds.

## Setup configuration
This test requires no specific setup.

## Test
Retrieve facts for a device using SNMP, and compare it to system values received from DUT.
Verify correct behaviour of port MIBs ifIndex, ifMtu, ifSpeed, ifAdminStatus, ifOperStatus, ifAlias, ifHighSpeed, ifType

## Test cases
### Test case test_snmp_intefaces
#### Test steps
* Retrieve facts for a device using SNMP
* Get expected values for a device from DUT per each port.
* Compare that facts received by SNMP are equal to values received from system.
