# SONiC Switch Latency Test

## Test Objective

This test aims to measure the latency introduced by a switch under the fully loaded condition.

## Test Setup

The test is designed to be topology-agnostic, meaning it does not assume or impose a specific network connection. The only requirement is that the DUT is fully connected to handle full traffic loads under stress. Plus all traffic generators in the testbed must be time synchronized.

## Background

In Broadcom architecture, the Memory Management Unit (MMU) handles packet buffering and traffic management within the device. Each MMU consists of two Ingress Traffic Managers (ITMs). The first and last quarters of the ports reside in one ITM, while the second and third quarters reside in the other ITM. We will test the latency of traffic managed within a single ITM as well as traffic that traverses between the two ITMs.

Cut-through packet forwarding mode is unsupported in SONiC. Store-and-forward is supported, but it can only be set in SAI. Config_db support is not in place. So no packet forwarding requirement in latency test.

## Test Steps

1. Switch wiring: All DUT ports are connected to traffic generators, directly or indirectly.

2. Configure traffic items on traffic genrators so that traffic flow through all the DUT ports and both inter-ITM & intra-ITM are tested. For example, For each of the four traffic generators: define two topologies, each containing four **physical** ports. Configure and bring up Layer 2 and Layer 3 protocols for both topologies. Define two uni-directional traffic items: one's path stay within a single ITM on the DUT (intra-ITM), the other flows cross the two ITMs on the DUT (inter-ITM). e.g., in IXIA-1, one traffic item is destined for IXIA-2 (intra-ITM), the other traffic item is destined for IXIA-4 (inter-ITM). Set each traffic item’s rate to 80% of the line rate, with a packet size of 1024 bytes.
3. Start all the traffic items simultaneously and run them for 1 minute. Record latency statistics and compare latency differences between intra-ITM and inter-ITM traffic.

4. Repeat the test with packet sizes ranging from 86 bytes to 8096 bytes to analyze how packet size impacts latency.

5. Vary traffic rates from 50% to 100% of the line rate. Observe how latency changes in relation to packet loss. Note: Latency measurements may be skewed due to packet loss, as lost packets are counted as having infinite latency. This issue should be addressed to ensure accurate results.

6. Categorize latency results into multiple bins based on time intervals. Count the number of packets within the following latency ranges: under 1500ns, between 1500ns and 1600ns, between 1600ns and 1700ns, ... ..., between 3900ns and 4000ns, above 4000ns. Analyze the distribution to better understand latency characteristics.
