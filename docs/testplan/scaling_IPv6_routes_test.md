# SONiC Switch Scaling IPv6 Routes Test

- [SONiC Switch Scaling IPv6 Routes Test](#sonic-switch-scaling-ipv6-routes-test)
  - [Test Objective](#test-objective)
  - [Test Setup](#test-setup)
  - [Test Steps](#test-steps)
  - [Key Test Cases](#key-test-cases)
    - [One BGP Session Flap and Traffic Convergence Test](#one-bgp-session-flap-and-traffic-convergence-test)
    - [All BGP Sessions Down and Up Test](#all-bgp-sessions-down-and-up-test)
    - [Nexthop Reduction and Restoration Test](#nexthop-reduction-and-restoration-test)

## Test Objective

This test aims to evaluate SONiC switches’ ability to handle scaling number of IPv6 routes efficiently while analyzing the impact of route scaling on network performance. It verifies the scalability, stability, and forwarding efficiency of IPv6 route processing under various conditions.

## Test Setup

This test builds upon the **SONiC Switch BGP IPv6 Test**. Before running this test, ensure that the **SONiC Switch BGP IPv6 Test** has been completed up to step 3.

## Test Steps

1. Execute "SONiC Switch BGP IPv6 Test" till step 3.

2. On each neighboring switch: Configure a vlan, assign 4*X/Y IPv6 addresses with the specified prefix length and add all the Ethernet ports connected to a traffic generator to the vlan.

3. Monitor the BGP route learning on the DUT by running `show ipv6 route bgp`. Verify that the DUT successfully learns and installs all routes.

4. Using traffic generator's application or web interface, create one topology per traffic generator. In each topology, add the Ethernet ports connected to its neighboring T0, apply IPv6 protocol to emulate 4*X/Y IPv6 hosts with the specified prefix length.

5. On each traffic generator, define a unidirectional traffic item at 100% line rate. Distribute traffic destinations evenly across all traffic generators. Start the traffic and verify interface counters on the switches to ensure expected behavior.

6. Validate the DUT’s ability to distribute traffic evenly across multiple equal-cost paths.

7. Scale up the total number of routes by 10 times. Repeat steps 3 through 6 to analyze the impact of route scaling on performance.

## Key Test Cases

There are three key test cases that require comprehensive descriptions, so we elevate them to individual test cases and emphasize their aspects more thoroughly.

### One BGP Session Flap and Traffic Convergence Test

Convergence is the process by which a network adapts to changes in topology, link states, trigger events, or routing information. Fast convergence is crucial to ensuring the network quickly recovers from failures or topology changes, minimizing service disruptions.

This test case evaluates the impact of a single BGP session going down and up, analyzing traffic convergence behavior and recovery time. The interface connected to a BGP peer is administratively taken down and then brought up to measure packet loss duration and traffic stabilization. This test validates the DUT efficiently reroutes traffic upon BGP session failures and restores normal operation upon recovery.

1. There are X/Y BGP sessions between the DUT and its neighbor switches. Set the Tx traffic rate under (X/Y-1)/(X/Y)% of the line rate, to ensure the total traffic rate remains under the total line rate after one session goes down. Record the Rx traffic rate as a baseline.
2. Shut down one interface on the DUT. Measure the convergence time, defined as is the packet loss duration, to evaluate how quickly the affected flows re-route via alternate paths. There should be no packet loss once the flows stabilize.
3. Bring the interface back up. Measure the time taken for the Rx traffic rate to return to its original value. Repeat the three steps for other BGP-connected interfaces and calculate the average convergence time.
4. Next we test the traffic overload scenario. Set the Tx traffic rate to 100% of the line rate. Record the Rx traffic rate as a baseline.
5. Shut down one interface on the DUT. Since the total traffic rate exceeds the total line rate, packet loss is expected. Measure the time it takes for the traffic rate to stabilize.
6. Bring up the interface. Measure the convergence time. Repeat steps 4-6 with other for other  BGP-connected interfaces and calculate the average convergence time.

### All BGP Sessions Down and Up Test

This test aims to evaluate the impact of a complete BGP session loss on traffic and measure the recovery time required for full traffic restoration after restarting the BGP container. The objective is to assess the DUT's convergence efficiency and stability when all BGP routes are withdrawn and then re-established.

1. Set the Tx traffic rate to 100% of the line rate. Record the Rx traffic rate as a baseline.
2. Stop the BGP container on the DUT. Wait till all BGP routes are withdrawn.
3. Start the BGP container and measure the time taken for traffic restoration.
4. Repeat the process multiple times and calculate the average traffic restoration time.

### Nexthop Reduction and Restoration Test

The objective of this test is to evaluate the impact of nexthop reduction and restoration on traffic flow and convergence time in both normal and traffic overload scenarios. The goal is to measure how quickly the DUT can adapt to changes in the network topology (by removing and restoring nexthops) while maintaining traffic stability and minimizing packet loss.

1. On one of the T0 switches, run the command `show ipv6 bgp network <ipv6>/<prefix>` and determin the number of nexthops available for reaching `<ipv6>/<prefix>`.
2. Set the Tx traffic rate to 50% of the line rate, to ensure that the total traffic rate stays under the total line rate after performing nexthop reduction.
3. On the DUT, randomly remove half of the nexthops. Measure the convergence time, defined as is the packet loss duration, to assess how quickly the affected flows re-route via alternate paths. The packet loss should approach its original value once the flows stabilize.
4. Restore the removed nexthops. Measure the time taken for the Rx traffic rate to return to its baseline value. Repeat the three steps for the other half of the nexthops and calculate the average convergence time.
5. Next we test the traffic overload scenario by setting the Tx traffic rate to 100% of the line rate. Record the Rx traffic rate as a baseline.
6. On the DUT, randomly remove half of the nexthops. Given the total traffic rate exceeds the total line rate, packet loss is expected. Measure the time it takes for the traffic rate to stabilize.
7. Restore the removed nexthops. Measure the convergence time. Repeat steps 5-7 for the other half of the nexthops and calculate the average convergence time.
