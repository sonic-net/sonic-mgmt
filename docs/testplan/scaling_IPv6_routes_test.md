# SONiC Switch Scaling IPv6 Routes Test

## Test Objective

This test aims to evaluate SONiC switches’ ability to handle scaling number of IPv6 routes efficiently while analyzing the impact of route scaling on network performance. It verifies the scalability, stability, and forwarding efficiency of IPv6 route processing under various conditions.

## Test Setup

This test builds upon the **SONiC Switch BGP IPv6 Test**. Before running this test, ensure that the **SONiC Switch BGP IPv6 Test** has been completed up to step 3.

## Test Steps

1. Execute "SONiC Switch BGP IPv6 Test" till step 3.

2. On each neighboring switch: Configure a vlan, assign 4*X/Y IPv6 addresses with the specified prefix length and add all the Ethernet ports connected to a traffic generator to the vlan.

3. Monitor the BGP route learning on the DUT by running “show ipv6 route bgp”. Verify that the DUT successfully learns and installs all routes.

4. Using traffic generator's application or web interface, create one topology per traffic generator. In each topology, add the Ethernet ports connected to its neighboring T0, apply IPv6 protocol to emulate 4*X/Y IPv6 hosts with the specified prefix length.

5. On each traffic generator, Define a unidirectional traffic item at 80% line rate. Distribute traffic destinations evenly across all traffic generators. Start the traffic and verify interface counters on the switches to ensure expected behavior.

6. Meaure the packet forwarding latency data.

7. On the DUT, shut down one interface. Verify that impacted flows quickly recover via alternative paths. Measure the convergence time, which is the packet loss duration. Evaluate the packet loss.

8. Scale up the total number of routes by 10×. Repeat steps 3 through 7 to analyze the impact of route scaling on performance.
