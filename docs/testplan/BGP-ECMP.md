# Multipath BGP Route Advertisement Test Plan

- [Overview](#overview)
    - [Scope](#scope)
    - [Out of Scope](#out-of-scope)
    - [Testbed](#testbed)
- [Setup configuration](#setup-configuration)
- [Test cases](#test-cases)

## Overview
This regression test plan is designed to verify the fix for a multipath BGP route advertisement issue in SONiC. The issue, as described in GitHub issue #17183(https://github.com/sonic-net/sonic-buildimage/issues/17183), involves scenarios where routes advertised through BGP network commands from multiple neighbors are not properly recognized in ECMP (Equal-Cost Multi-Path) configurations. Specifically, only one path was being chosen instead of all available paths.

The primary goal of this test plan is to ensure that the fix correctly implements multipath route selection and maintains stability across various BGP operations and scenarios.

### Scope
The test plan includes the following scenarios:

* Verification of correct multipath route advertisement and selection in BGP.
* Testing of route persistence and stability over time.
* Validation of route updates and removals in multipath scenarios.
* Confirmation of correct behavior during BGP clear operations.
* Scale testing to ensure performance with a large number of routes.
* Verification of correct behavior during BGP session flaps.
* Negative testing to ensure proper handling of misconfigured routes.
* Performance testing to check for any regression in route convergence time.
* The test plan covers various aspects of BGP functionality related to multipath routing, focusing on the specific issue reported and its fix. It aims to provide comprehensive coverage of potential scenarios that could be affected by the changes made to address the original issue.

### Out of Scope
The following scenarios are not covered by this test plan:

* Detailed testing of other BGP features not directly related to multipath route advertisement.
* Extensive interoperability testing with non-SONiC devices.
* Long-term stability testing (beyond the durations specified in the test cases).
* Testing of BGP security features.

### Testbed
The test could run on t0 testbed with at least 2 leaf routers.

## Setup configuration
This test doesn't require any configuration.

## Test
