# DASH CRM test plan

* [Overview](#Overview)
   * [Scope](#Scope)
   * [Testbed](#Testbed)
   * [Setup configuration](#Setup%20configuration)
* [Test](#Test)
* [Test cases](#Test%20cases)
* [TODO](#TODO)
* [Open questions](#Open%20questions)

## Overview
The purpose is to test the functionality of CRM on the SONIC DPU DUT, closely resembling the production environment.

### Scope
The test is targeting a running SONIC system with a fully functioning configuration. The purpose of the test is not to test specific API, but to functional testing of CRM on SONIC DASH system.

### Testbed
The test will run on all DASH testbeds.

### Setup configuration
No setup pre-configuration is required, the test will configure and clean up all the configuration.

Common tests configuration:
- Test will set polling interval to be 1 second
- Test will get used/available CRM counters
- Test will configure CRM resources by applying swss config
- Test will get used/available CRM counters after applying CRM resources config

Common tests cleanup:
- Remove CRM resources by applying swss config
- Restore thresholds configuration

## Test

## Test cases

### Test case # 1 – CRM default config
#### Test objective
Verify CRM default config
#### Test steps
* Verify CRM default thresholds for all resources:
  * Default HIGH threshold should be set to 85%
  * Default LOW threshold should be set to 70%.

### Test case # 2 – VNET
#### Test objective
Verify "VNET" CRM resource.
#### Test steps
* Check CRM resources used/available
* Perform the following steps for all threshold types ("used", "free"):
	* Set low and high thresholds according to current usage and type.
	* Verify that "EXCEEDED" message is logged (using log analyzer).
	* Set low and high thresholds to default values.
	* Verify that "CLEAR" message is logged (using log analyzer).

### Test case # 3 – ENI
#### Test objective
Verify "ENI" CRM resource.
#### Test steps
* Check CRM resources used/available
* Perform the following steps for all threshold types ("percentage", "used", "free"):
	* Set low and high thresholds according to current usage and type.
	* Verify that "EXCEEDED" message is logged (using log analyzer).
	* Set low and high thresholds to default values.
	* Verify that "CLEAR" message is logged (using log analyzer).

### Test case # 4 – ENI Ethernet Addresses
#### Test objective
Verify "ENI Ethernet Addresses" CRM resource.
#### Test steps
* Check CRM resources used/available
* Perform the following steps for all threshold types ("used", "free"):
	* Set low and high thresholds according to current usage and type.
	* Verify that "EXCEEDED" message is logged (using log analyzer).
	* Set low and high thresholds to default values.
	* Verify that "CLEAR" message is logged (using log analyzer).

### Test case # 5 – IPv4 Inbound Routes
#### Test objective
Verify "IPv4 Inbound Routes" CRM resource.
#### Test steps
* Check CRM resources used/available
* Perform the following steps for all threshold types ("used", "free"):
	* Set low and high thresholds according to current usage and type.
	* Verify that "EXCEEDED" message is logged (using log analyzer).
	* Set low and high thresholds to default values.
	* Verify that "CLEAR" message is logged (using log analyzer).

### Test case # 6 – IPv6 Inbound Routes
#### Test objective
Verify "IPv6 Inbound Routes" CRM resource.
#### Test steps
* Check CRM resources used/available
* Perform the following steps for all threshold types ("used", "free"):
	* Set low and high thresholds according to current usage and type.
	* Verify that "EXCEEDED" message is logged (using log analyzer).
	* Set low and high thresholds to default values.
	* Verify that "CLEAR" message is logged (using log analyzer).

### Test case # 7 – IPv4 Outbound Routes
#### Test objective
Verify "IPv4 Outbound Routes" CRM resource.
#### Test steps
* Check CRM resources used/available
* Perform the following steps for all threshold types ("used", "free"):
	* Set low and high thresholds according to current usage and type.
	* Verify that "EXCEEDED" message is logged (using log analyzer).
	* Set low and high thresholds to default values.
	* Verify that "CLEAR" message is logged (using log analyzer).

### Test case # 8 – IPv6 Outbound Routes
#### Test objective
Verify "IPv6 Outbound Routes" CRM resource.
#### Test steps
* Check CRM resources used/available
* Perform the following steps for all threshold types ("used", "free"):
	* Set low and high thresholds according to current usage and type.
	* Verify that "EXCEEDED" message is logged (using log analyzer).
	* Set low and high thresholds to default values.
	* Verify that "CLEAR" message is logged (using log analyzer).

### Test case # 9 – IPv4 Outbound CA to PA
#### Test objective
Verify "IPv4 Outbound CA to PA" CRM resource.
#### Test steps
* Check CRM resources used/available
* Perform the following steps for all threshold types ("used", "free"):
	* Set low and high thresholds according to current usage and type.
	* Verify that "EXCEEDED" message is logged (using log analyzer).
	* Set low and high thresholds to default values.
	* Verify that "CLEAR" message is logged (using log analyzer).

### Test case # 10 – IPv6 Outbound CA to PA
#### Test objective
Verify "IPv6 Outbound CA to PA" CRM resource.
#### Test steps
* Check CRM resources used/available
* Perform the following steps for all threshold types ("used", "free"):
	* Set low and high thresholds according to current usage and type.
	* Verify that "EXCEEDED" message is logged (using log analyzer).
	* Set low and high thresholds to default values.
	* Verify that "CLEAR" message is logged (using log analyzer).

### Test case # 11 – IPv4 PA Validation
#### Test objective
Verify "IPv4 PA Validation" CRM resource.
#### Test steps
* Check CRM resources used/available
* Perform the following steps for all threshold types ("used", "free"):
	* Set low and high thresholds according to current usage and type.
	* Verify that "EXCEEDED" message is logged (using log analyzer).
	* Set low and high thresholds to default values.
	* Verify that "CLEAR" message is logged (using log analyzer).

### Test case # 12 – IPv6 PA Validation
#### Test objective
Verify "IPv6 PA Validation" CRM resource.
#### Test steps
* Check CRM resources used/available
* Perform the following steps for all threshold types ("used", "free"):
	* Set low and high thresholds according to current usage and type.
	* Verify that "EXCEEDED" message is logged (using log analyzer).
	* Set low and high thresholds to default values.
	* Verify that "CLEAR" message is logged (using log analyzer).

### Test case # 13 – IPV4 ACL Groups
#### Test objective
Verify "IPV4 ACL Groups" CRM resource.
#### Test steps
* Check CRM resources used/available
* Perform the following steps for all threshold types ("used", "free"):
	* Set low and high thresholds according to current usage and type.
	* Verify that "EXCEEDED" message is logged (using log analyzer).
	* Set low and high thresholds to default values.
	* Verify that "CLEAR" message is logged (using log analyzer).

### Test case # 14 – IPV6 ACL Groups
#### Test objective
Verify "IPV6 ACL Groups" CRM resource.
#### Test steps
* Check CRM resources used/available
* Perform the following steps for all threshold types ("used", "free"):
	* Set low and high thresholds according to current usage and type.
	* Verify that "EXCEEDED" message is logged (using log analyzer).
	* Set low and high thresholds to default values.
	* Verify that "CLEAR" message is logged (using log analyzer).

### Test case # 15 – IPv4 ACL Rules
#### Test objective
Verify "IPv4 ACL Rules" CRM resource.
#### Test steps
* Set polling interval to 1 sec.
* Configure 1 "IPv4 ACL Rules" and observe that counters were updated as expected.
* Remove 1 "IPv4 ACL Rules" and observe that counters were updated as expected.
* Perform the following steps for all threshold types ("used", "free"):
	* Set low and high thresholds according to current usage and type.
	* Verify that "EXCEEDED" message is logged (using log analyzer).
	* Set low and high thresholds to default values.
	* Verify that "CLEAR" message is logged (using log analyzer).
* Restore default configuration.

### Test case # 16 – IPv6 ACL Rules
#### Test objective
Verify "IPv6 ACL Rules" CRM resource.
#### Test steps
* Check CRM resources used/available
* Perform the following steps for all threshold types ("used", "free"):
	* Set low and high thresholds according to current usage and type.
	* Verify that "EXCEEDED" message is logged (using log analyzer).
	* Set low and high thresholds to default values.
	* Verify that "CLEAR" message is logged (using log analyzer).

### Test case # 17 – Cleanup
#### Test objective
Verify cleanup for CRM resources.
#### Test steps
* Remove CRM resources by applying swss config
* Check CRM resources used/available

## TODO

## Open questions
