# DASH ACL Tag test plan

* [Overview](#overview)
   * [Scope](#scope)
   * [Testbed](#testbed)
   * [Setup configuration](#setup-configuration)
* [Test](#test)
* [Test cases](#test-cases)
* [TODO](#todo)
* [Open questions](#open-questions)

## Overview
The purpose is to test the functionality of ACL Tag on the SONIC DUT, closely resembling the production environment.

### Scope
The test targets a running SONIC system with a fully functioning configuration. The test's purpose is not to test specific API but to functional testing of ACL Tag on the SONIC DASH system.

### Testbed
The test will run on all DASH testbeds.

### Setup configuration
The tests are based on existing DASH ACL tests and extend their functionality.

No setup pre-configuration is required, the tests will configure and clean up all the configuration.
The configured IP addresses used in the test will be randomized.
All test configurations will be done at the beginning and all test clean-ups will be after the end of test executions.

Common tests configuration:
- Create base vnet configurations
- Create base ACL group, all tests ACL Tags, all tests ACL rules
- Bind ACL in/out tables to ENI and ACL group

Common tests cleanup:
- Remove ACL binding
- Remove ACL Tags, rules, group
- Remove vnet configurations

## Test

## Test cases

Each test case will be additionally tested by the loganalizer and core dump validation.

### Test case \#1 - ACL Tag

#### Test objective

Verify functionality of ACL Tag configuration with 2 IPs.

#### Test steps

- setup
    - Create src_addr Tag with 2 IP addresses.
    - Create dst_addr Tag with 2 IP addresses.
    - Create a Rule with these Tags.
- validation
    - Send 3 packets. Two of them should be received as matched by IP address.
- teardown
    - Remove Rule.
    - Remove Tag.

### Test case \#2 - ACL Multi Tag

#### Test objective

Verify functionality of ACL Tag, where Rule contains 2 Tags.

#### Test steps

- setup
    - Create 2 src_addr Tags with a single IP address each.
    - Create 2 dst_addr Tags with a single IP address each.
    - Create a Rule with these Tags.
- validation
    - Send 2 packets, which should be received as matched by IP address.
- teardown
    - Remove Rule.
    - Remove Tags.

### Test case \#3 - ACL Tag Order

#### Test objective

Verify functionality of ACL Tag configuration where Rule created before Tag.

#### Test steps

- setup
    - Create a Rule with a Tag.
    - Create src_addr Tag with 2 IP addresses.
- validation
    - Send packet, which should be received as matched by IP address.
- teardown
    - Remove Tag.
    - Remove Rule.

### Test case \#4 - ACL Multi Tag Order

#### Test objective

Verify functionality of ACL Tag configuration where Rule created before Tags.

#### Test steps

- setup
    - Create a Rule with 2 Tags.
    - Create 2 src_addr Tags with a single IP address each.
- validation
    - Send 2 packets, which should be received as matched by IP address.
- teardown
    - Remove Tags.
    - Remove Rule.

### Test case \#5 - ACL Tag Update

#### Test objective

Verify functionality of ACL Tag configuration where Tag updated.

#### Test steps

- setup
    - Create src_addr Tag with IP address.
    - Create a Rule with this Tag.
    - Update src_addr Tag with another IP address.
- validation
    - Send packet, which should be received as matched by IP address.
- teardown
    - Remove Rule.
    - Remove Tag.

### Test case \#6 - ACL Tags Scale

#### Test objective

Verify scale functionality of ACL Tag. 1 rule, 4k tags with 24k prefixes each.

#### Test steps

- setup
    - Create 4k Tags with 24k IP addresses each.
    - Create a Rule with these Tags.
- validation
    - Send packet to random IP, which should be received as matched by IP address.
- teardown
    - Remove Rule.
    - Remove Tags.

### Test case \#6 - ACL Tags Negative

#### Test objective

Verify the negative configuration of the ACL Tag.
Expected errors in the log, but no crashes.

Invalid IP address will be random from:
- address that begins with a 0.
- address with a number above 255.
- address that has more than 3 dots.

#### Test steps

- setup
    - Create a tag with an incorrect IP address.
    - Create a tag with an empty string as a name.
- validation
    - validating by loganalyzer and core dump checker

## TODO

## Open questions
