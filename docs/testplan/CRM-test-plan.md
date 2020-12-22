# CRM test plan

* [Overview](#Overview)
   * [Scope](#Scope)
   * [Testbed](#Testbed)
* [Setup configuration](#Setup%20configuration)
   * [Ansible scripts to setup and run test](#Ansible%20scripts%20to%20setup%20and%20run%20test)
     * [crm.yml](#crm.yml)
* [Test](#Test)
* [Test cases](#Test%20cases)
* [TODO](#TODO)
* [Open questions](#Open%20questions)

## Overview
The purpose is to test functionality of CRM on the SONIC switch DUT, closely resembling production environment.

### Scope
The test is targeting a running SONIC system with fully functioning configuration. The purpose of the test is not to test specific API, but functional testing of CRM on SONIC system.

### Testbed
The test will run on the all testbeds.

## Setup configuration
No setup pre-configuration is required, test will configure and clean-up all the configuration.
### Ansible scripts to setup and run test
#### crm.yml
crm.yml when run with tag “crm” will do the following for each CRM resource:
1. Apply required configuration.
2. Verify "used" and "free" counters.
3. Verify "EXCEEDED" and "CLEAR" messages using all  types of thresholds.
4. Restore configuration.

## Test

## Test cases

### Test case # 1 – IPv4 route
#### Test objective
Verify "IPv4 route" CRM resource.
#### Test steps
* Set polling interval to 1 minute.
* Configure 1 route and observe that counters were updated as expected.
* Remove 1 route and observe that counters were updated as expected.
* Perform the following steps for all threshold types ("percentage", "used", "free"):
	* Set low and high thresholds according to current usage and type.
	* Verify that "EXCEEDED" message is logged (using log analyzer).
	* Set low and high thresholds to default values.
	* Verify that "CLEAR" message is logged (using log analyzer).
* Restore default configuration.

### Test case # 2 – IPv6 route
#### Test objective
Verify "IPv6 route" CRM resource.
#### Test steps
* Set polling interval to 1 minute.
* Configure 1 route and observe that counters were updated as expected.
* Remove 1 route and observe that counters were updated as expected.
* Perform the following steps for all threshold types ("percentage", "used", "free"):
	* Set low and high thresholds according to current usage and type.
	* Verify that "EXCEEDED" message is logged (using log analyzer).
	* Set low and high thresholds to default values.
	* Verify that "CLEAR" message is logged (using log analyzer).
* Restore default configuration.

### Test case # 3 – IPv4 nexthop
#### Test objective
Verify "IPv4 nexthop" CRM resource.
#### Test steps
* Set polling interval to 1 minute.
* Add 1 nexthop and observe that counters were updated as expected.
* Remove 1 nexthop and observe that counters were updated as expected.
* Perform the following steps for all threshold types ("percentage", "used", "free"):
	* Set low and high thresholds according to current usage and type.
	* Verify that "EXCEEDED" message is logged (using log analyzer).
	* Set low and high thresholds to default values.
	* Verify that "CLEAR" message is logged (using log analyzer).
* Restore default configuration.

### Test case # 4 – IPv6 nexthop
#### Test objective
Verify "IPv6 nexthop" CRM resource.
#### Test steps
* Set polling interval to 1 minute.
* Add 1 nexthop and observe that counters were updated as expected.
* Remove 1 nexthop and observe that counters were updated as expected.
* Perform the following steps for all threshold types ("percentage", "used", "free"):
	* Set low and high thresholds according to current usage and type.
	* Verify that "EXCEEDED" message is logged (using log analyzer).
	* Set low and high thresholds to default values.
	* Verify that "CLEAR" message is logged (using log analyzer).
* Restore default configuration.

### Test case # 5 – IPv4 neighbor
#### Test objective
Verify "IPv4 neighbor" CRM resource.
#### Test steps
* Set polling interval to 1 minute.
* Configure 1 neighbor and observe that counters were updated as expected.
* Remove 1 neighbor and observe that counters were updated as expected.
* Perform the following steps for all threshold types ("percentage", "used", "free"):
	* Set low and high thresholds according to current usage and type.
	* Verify that "EXCEEDED" message is logged (using log analyzer).
	* Set low and high thresholds to default values.
	* Verify that "CLEAR" message is logged (using log analyzer).
* Restore default configuration.

### Test case # 6 – IPv6 neighbor
#### Test objective
Verify "IPv6 neighbor" CRM resource.
#### Test steps
* Set polling interval to 1 minute.
* Configure 1 neighbor and observe that counters were updated as expected.
* Remove 1 neighbor and observe that counters were updated as expected.
* Perform the following steps for all threshold types ("percentage", "used", "free"):
	* Set low and high thresholds according to current usage and type.
	* Verify that "EXCEEDED" message is logged (using log analyzer).
	* Set low and high thresholds to default values.
	* Verify that "CLEAR" message is logged (using log analyzer).
* Restore default configuration.

### Test case # 7 – Nexthop group object
#### Test objective
Verify "nexthop group object" CRM resource.
#### Test steps
* Set polling interval to 1 minute.
* Configure 1 ECMP route and observe that counters were updated as expected.
* Remove 1 ECMP route and observe that counters were updated as expected.
* Perform the following steps for all threshold types ("percentage", "used", "free"):
	* Set low and high thresholds according to current usage and type.
	* Verify that "EXCEEDED" message is logged (using log analyzer).
	* Set low and high thresholds to default values.
	* Verify that "CLEAR" message is logged (using log analyzer).
* Restore default configuration.

### Test case # 8 – Nexthop group member
#### Test objective
Verify "nexthop group member" CRM resource.
#### Test steps
* Set polling interval to 1 minute.
* Configure 1 ECMP route and observe that counters were updated as expected.
* Remove 1 ECMP route and observe that counters were updated as expected.
* Perform the following steps for all threshold types ("percentage", "used", "free"):
	* Set low and high thresholds according to current usage and type.
	* Verify that "EXCEEDED" message is logged (using log analyzer).
	* Set low and high thresholds to default values.
	* Verify that "CLEAR" message is logged (using log analyzer).
* Restore default configuration.

### Test case # 9 – FDB entry
#### Test objective
Verify "FDB entry" CRM resource.
#### Test steps
* Set polling interval to 1 minute.
* Configure 1 FDB entry and observe that counters were updated as expected.
* Remove 1 FDB entry and observe that counters were updated as expected.
* Perform the following steps for all threshold types ("percentage", "used", "free"):
	* Set low and high thresholds according to current usage and type.
	* Verify that "EXCEEDED" message is logged (using log analyzer).
	* Set low and high thresholds to default values.
	* Verify that "CLEAR" message is logged (using log analyzer).
* Restore default configuration.

### Test case # 10 – ACL group
#### Test objective
Verify "ACL group" CRM resource.
#### Test steps
* Set polling interval to 1 minute.
* Configure 1 ACL and observe that counters were updated as expected.
* Remove 1 ACL and observe that counters were updated as expected.
* Perform the following steps for all threshold types ("percentage", "used", "free"):
	* Set low and high thresholds according to current usage and type.
	* Verify that "EXCEEDED" message is logged (using log analyzer).
	* Set low and high thresholds to default values.
	* Verify that "CLEAR" message is logged (using log analyzer).
* Restore default configuration.

### Test case # 11 – ACL table
#### Test objective
Verify "ACL table" CRM resource.
#### Test steps
* Set polling interval to 1 minute.
* Configure 1 ACL and observe that counters were updated as expected.
* Remove 1 ACL and observe that counters were updated as expected.
* Perform the following steps for all threshold types ("percentage", "used", "free"):
	* Set low and high thresholds according to current usage and type.
	* Verify that "EXCEEDED" message is logged (using log analyzer).
	* Set low and high thresholds to default values.
	* Verify that "CLEAR" message is logged (using log analyzer).
* Restore default configuration.

### Test case # 12 – ACL entry
#### Test objective
Verify "ACL entry" CRM resource.
#### Test steps
* Set polling interval to 1 minute.
* Configure 1 ACL rule and observe that counters were updated as expected.
* Remove 1 ACL rule and observe that counters were updated as expected.
* Perform the following steps for all threshold types ("percentage", "used", "free"):
	* Set low and high thresholds according to current usage and type.
	* Verify that "EXCEEDED" message is logged (using log analyzer).
	* Set low and high thresholds to default values.
	* Verify that "CLEAR" message is logged (using log analyzer).
* Restore default configuration.

### Test case # 13 – ACL counter
#### Test objective
Verify "ACL entry" CRM resource.
#### Test steps
* Set polling interval to 1 minute.
* Configure 1 ACL rule and observe that counters were updated as expected.
* Remove 1 ACL rule and observe that counters were updated as expected.
* Perform the following steps for all threshold types ("percentage", "used", "free"):
	* Set low and high thresholds according to current usage and type.
	* Verify that "EXCEEDED" message is logged (using log analyzer).
	* Set low and high thresholds to default values.
	* Verify that "CLEAR" message is logged (using log analyzer).
* Restore default configuration.

## TODO

## Open questions
