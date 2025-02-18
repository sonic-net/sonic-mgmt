# SONiC Switch Scaling IPv6 Routes Test

## Table of Contents

- [Test Objective](#test-objective)
- [Test Setup](#test-setup)
- [Test Steps](#test-steps)

## Test Objective

This test aims to evaluate SONiC switches’ ability to handle scaling number of IPv6 routes efficiently while analyzing the impact of route scaling on network performance. It verifies the scalability, stability, and forwarding efficiency of IPv6 route processing under various conditions.

## Test Setup

This test builds upon the **SONiC Switch BGP IPv6 Test**. Before running this test, ensure that the **SONiC Switch BGP IPv6 Test** has been completed up to step 3.

## Test Steps

1. Execute "SONiC Switch BGP IPv6 Test" till step 3.

2. On each neighboring switch: Configure a vlan, assign 4*X/Y IPv6 addresses with the specified prefix length and add all the Ethernet ports connected to a traffic generator to the vlan.

3. Monitor the BGP route learning on the DUT by running `show ipv6 route bgp`. Verify that the DUT successfully learns and installs all routes.

4. Using traffic generator's application or web interface, create one topology per traffic generator. In each topology, add the Ethernet ports connected to its neighboring T0, apply IPv6 protocol to emulate 4*X/Y IPv6 hosts with the specified prefix length.

5. On each traffic generator, Define a unidirectional traffic item at 80% line rate. Distribute traffic destinations evenly across all traffic generators. Start the traffic and verify interface counters on the switches to ensure expected behavior.

6. Meaure the packet forwarding latency data.

7. Scale up the total number of routes by 10 times. Repeat steps 3 through 6 to analyze the impact of route scaling on performance.

8. One session down and up: Shut down one interface on the DUT. Verify that impacted flows quickly recover via alternative paths. Measure the convergence time, which is the packet loss duration. Please note the link-down also reduces the total line rate. Ensure the total ttraffic rate does not exceed the total line rate, otherwise the packet loss will not be recovered util link-up. Now bring up the interface and measure the convergence time again.

9. All sessions down and up: Stop the BGP container on the DUT. Wait till all BGP routes are removed. Now bring up the BGP container and measure the traffic restoration time for. Repeat this process and calculate the average traffic restoration time of this scenario.

10. Nexthop reduction and restoration: In one of the T0 switches, run `show ipv6 bgp network <ipv6>/<prefix>` and find the number of nexthops that can be used to reach <ipv6>/<prefix>. Randomly pick half of the next hops and remove them. Measure the convergence time, which is the packet loss duration. Similar to step 8, some of the links can not be used in this case, bringing down the total line rate. Ensure the total traffic rate does not exceed the total line rate, otherwise the packet loss will not be recovered. Restore the removed nexthops and record the convergence time again. Repeat this process and calculate the average convergence time of this scenario.
