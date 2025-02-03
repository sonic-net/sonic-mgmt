# Test Objective
This test aims to measure the latency introduced by a switch under the fully loaded condition.

# Test Setup
![Test Setup](./2TierNetwork.png)

1.	The testbed consists of four IXIA traffic generators (synchronized using a time-sync metronome) and five SONiC switches, where the BT1 switch is the Device Under Test (DUT).
2.	Each of the four BT0 switches is connected to the DUT via eight DAC cables. There are no direct connections between any two BT0 switches.
3.	Each BT0 switch is also connected to one IXIA traffic generator via eight optical cables. Similarly, there are no direct connections between any two IXIA devices.
4.	Both switches and IXIAs support four port breakout modes: 8x100Gbps, 4x200Gbps, 2x400Gbps, and 1x800Gbps. However, they must operate in the same mode. In 8x100Gbps mode, each cable supports eight links. In 4x200Gbps mode, each cable supports four links. So on and so forth.
5.	The routing configuration of the BT0 switches should ensure that all data traffic go through the DUT.

# Background
In Broadcom architecture, the Memory Management Unit (MMU) handles packet buffering and traffic management within the device. Each MMU consists of two Ingress Traffic Managers (ITMs). The first and last quarters of the ports reside in one ITM, while the second and third quarters reside in the other ITM. We will test the latency of traffic managed within a single ITM as well as traffic that traverses between the two ITMs.

Cut-through packet forwarding mode is unsupported in SONiC. Store-and-forward is supported, but it can only be set in SAI. Config_db support is not in place. So no packet forwarding requirement in latency test. In IXIA, we use store-and-forward packet forwarding mode.

# Test Steps

1. Switch wiring: Connect the upper links of BT0-1, BT0-2, BT0-3, and BT0-4 to the first, second, third, and fourth quarters of BT1’s ports, respectively.

2. For each of the four IXIA devices: define two topologies, each containing four **physical** ports. Configure and bring up Layer 2 and Layer 3 protocols for both topologies. Define two uni-directional traffic items: one remains within a single ITM on BT1 (intra-ITM), the other flows cross the two ITMs on BT1 (inter-ITM). For example, in IXIA-1, one traffic item is destined for IXIA-2 (intra-ITM), the other traffic item is destined for IXIA-4 (inter-ITM). Set each traffic item’s rate to 80% of the line rate, with a packet size of 1024 bytes.

3. Start all the eight traffic items simultaneously and run them for 1 minute. Record latency statistics and compare latency differences between intra-ITM and inter-ITM traffic.

4. Repeat the test with packet sizes ranging from 86 bytes to 8096 bytes to analyze how packet size impacts latency.

5. Vary traffic rates from 50% to 100% of the line rate. Observe how latency changes in relation to packet loss. Note: Latency measurements may be skewed due to packet loss, as lost packets are counted as having infinite latency. This issue should be addressed to ensure accurate results.

6. Categorize latency results into multiple bins based on time intervals. Count the number of packets within the following latency ranges: under 1500ns, between 1500ns and 1600ns, between 1600ns and 1700ns, ... ..., between 3900ns and 4000ns, above 4000ns. Analyze the distribution to better understand latency characteristics.
