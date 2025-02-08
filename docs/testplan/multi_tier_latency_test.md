# SONiC Switch Latency Test

## Test Objective

This test aims to measure the latency introduced by a switch under the fully loaded condition.

## Test Setup

The test is designed to be topology-agnostic, meaning it does not assume or impose a specific network connection. The only requirement is that the DUT is fully connected to handle full traffic loads under stress. Plus all traffic generators in the testbed must be time synchronized.

## Background

Cut-through packet forwarding mode is unsupported in SONiC. Store-and-forward is supported, but it can only be set in SAI. Config_db support is not in place. So no packet forwarding requirement in latency test.

## Test Steps

1. Switch wiring: All DUT ports are connected to traffic generators, directly or indirectly.

2. Configure traffic items on traffic genrators so that traffic flow through all the DUT ports. For example, For each of the four traffic generators: define two topologies, each containing four **physical** ports. Configure and bring up Layer 2 and Layer 3 protocols for both topologies. Define two uni-directional traffic items in IXIA-1, one traffic item is destined for IXIA-2, the other traffic item is destined for IXIA-4. Set each traffic item’s rate to 80% of the line rate, with a packet size of 1024 bytes.
3. Start all the traffic items simultaneously and run them for 1 minute. Record latency statistics and compare latency differences between the two traffic items sourced from each traffic generator.

4. Repeat the test with packet sizes ranging from 86 bytes to 8096 bytes to analyze how packet size impacts latency.

5. Vary traffic rates from 50% to 100% of the line rate. Observe how latency changes in relation to packet loss. Note: Latency measurements may be skewed due to packet loss, as lost packets are counted as having infinite latency. This issue should be addressed to ensure accurate results.

6. Categorize latency results into multiple bins based on time intervals. Count the number of packets within the following latency ranges: under 1500ns, between 1500ns and 1600ns, between 1600ns and 1700ns, ... ..., between 3900ns and 4000ns, above 4000ns. Analyze the distribution to better understand latency characteristics.
