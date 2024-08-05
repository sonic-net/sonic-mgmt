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

This test case specifically addresses the core issue reported in GitHub issue #17183, where only one path was chosen instead of all available paths.

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

## Test Cases
### Test Case 1: Verify multipath route advertisement

#### Objective:
To verify that when the same route is advertised from multiple BGP neighbors using the network command, all valid paths are correctly installed in the routing table of the receiving router (ToR in this case).

#### Prerequisites:
A topology with at least one ToR switch and two leaf switches.
BGP is properly configured between the ToR and leaf switches.
All links between the ToR and leaf switches are up and operational.
ECMP is enabled on the ToR switch.

#### Test Steps:
On Leaf Switch 1:

a. Configure BGP to advertise a test route (e.g., 20.0.0.1/32) using the network command.

b. Verify the route is in the BGP table and marked for advertisement.

On Leaf Switch 2:

a. Configure BGP to advertise the same test route (20.0.0.1/32) using the network command.

b. Verify the route is in the BGP table and marked for advertisement.

On the ToR switch:

a. Wait for BGP convergence (typically a few seconds).

b. Use the command "show ip bgp 20.0.0.1/32" to view the BGP table entry for the test route.

c. Verify that the BGP table shows multiple paths for the route, one via each leaf switch.

d. Use the command "show ip route 20.0.0.1/32" to view the IP routing table entry.

e. Verify that the IP routing table shows multiple next-hops for the route, one for each leaf switch.

f. Check that the route is marked as a BGP route and that all expected next-hops are present.

The BGP table on the ToR switch should show multiple paths for the advertised route, one for each advertising leaf switch.
The IP routing table on the ToR switch should show the advertised route with multiple next-hops, one for each leaf switch.
All expected next-hops should be present in the routing table entry.

#### Pass/Fail Criteria:

Pass: All expected paths are correctly installed in both the BGP and IP routing tables, and traffic is evenly distributed.
Fail: One or more paths are missing from either the BGP or IP routing tables, or traffic distribution is not even.
