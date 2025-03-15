# SONiC Switch Loss Threshold Test

- [SONiC Switch Loss Threshold Test](#sonic-switch-loss-threshold-test)
  - [Test Objective](#test-objective)
  - [Test Setup](#test-setup)
  - [Test Steps](#test-steps)

## Test Objective

This test aimes to determine the maximum traffic rate that results in 0% packet loss across different packet sizes. By identifying this threshold, we can assess the switch's forwarding capability and validate its performance under various traffic conditions.

## Test Setup

The test is designed to be topology-agnostic, meaning it does not assume or impose a specific network connection. The only requirement is that the DUT is fully connected to handle full traffic loads under stress. Plus all traffic generators in the testbed must be time synchronized.

## Test Steps

1. Establish the required IPv6 BGP sessions and IPv6 routes by following the procedures outlined in the Snappi BGP test plan and the IPv6 route scaling test plan.
2. Define full-mesh traffic flows on the traffic generators.
3. Set packet size to 8192 bytes and begin testing. Start with 100% of the line rate and check for packet loss. If any traffic flow experiences packet loss, reduce the traffic rate to 10% of the line rate and test again. Continue adjusting the traffic rate using a binary search approach to determine the maximum rate at which 0% packet loss is observed.
4. Repeat step 3 for packet sizes of 86 bytes, 1536 bytes, and 4096 bytes.
5. For each of the above results, save the percentile figures to a database via the telemetry interface provided by the SONiC team. An example of how to use the interface is provided in telemetry folder.
