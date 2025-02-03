# Test Objective
This test aims to verify the scalability and stability of 256 BGP sessions and 10K IPv6 routes in a 2-tier network. It evaluates the DUT’s ability to establish and maintain BGP sessions, ensures proper route learning, and measures BGP update convergence time under various conditions.

# Test Setup
![Test Setup](./2TierNetwork.png)

1.	The testbed consists of four IXIA traffic generators (synchronized using a time-sync metronome) and five SONiC switches, where the BT1 switch is the Device Under Test (DUT).
2.	Each of the four BT0 switches is connected to the DUT via eight DAC cables. There are no direct connections between any two BT0 switches.
3.	Each BT0 switch is also connected to one IXIA traffic generator via eight optical cables. Similarly, there are no direct connections between any two IXIA devices.
4.	Both switches and IXIAs support four port breakout modes: 8x100Gbps, 4x200Gbps, 2x400Gbps, and 1x800Gbps. However, they must operate in the same mode. In 8x100Gbps mode, each cable supports eight links. In 4x200Gbps mode, each cable supports four links. So on and so forth.
5.	The routing configuration of the BT0 switches should ensure that all data traffic go through the DUT.

# Test Steps
1. Assign a unique AS number to each of the five switches.

2. Between each of the four BT0 switches and the DUT: Configure 64 BGP sessions. Each BGP session should have a dedicated pair of Ethernet ports (one on BT0 and the other on the DUT) whose IPv6 addresses are on the same subnet. Set up the BGP neighbors, device neighbors, and port IPv6 addresses for each BGP session.

3. Monitor the BGP session establishment on the DUT using command “show ipv6 bgp summary”. Ensure all 256 BGP sessions are established without errors.

4. In each BT0 switch: Configure a vlan,  assign 2500 IPv6 addresses with the specified prefix length and add all the Ethernet ports connected to IXIA to the vlan.

5. Monitor the BGP route learning on the DUT by running “show ipv6 route bgp”. Verify the DUT learns and installs all 10,000 routes.

6. Shut down one interface on the DUT. Wait till all routes advertised by the impacted BGP session are removed. Now bring up the interface and measure the time for BGP session and route reestablishment. Repeat this process and calculate the average update time of this scenario.

7. Stop the BGP container on the DUT. Wait till all BGP routes are removed. Now bring up the BGP container and measure the time for BGP session and route reestablishment. Repeat this process and calculate the average update time of this scenario.

8. Using IXIA management application IxNetwork, create four topologies, one for each IXIA devices. In each topology, add the Ethernet ports connected to one BT0, apply IPv6 protocol so that it emulates 2500 IPv6 hosts with the specified prefix length.

9. In one IXIA, define a unidirectional 100% line-rate traffic item. Ensure the destinations are evenly distributed across the other three IXIA devices. Start the traffic. Check the interface counters on the five switches if they are expected. On the DUT, shut down one interface not connected to the source IXIA. The impacted flows are expected to quickly recover because the packets are routed to alternative paths. Measure the packet loss duration and number.

10. In all the 4 IXIAs, define 80% line-rate fully meshed traffic items so that all 10,000 routes can be exercised on the DUT. Shut down an interface on the DUT. In this case, we expect packet loss for a short time. Measure the convergence time, which is the packet loss duration. Next, increase the traffic rate to 99% line-rate. Bring up the interface and measure the convergence time, which is the traffic loss duration.
