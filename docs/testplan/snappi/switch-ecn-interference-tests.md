# Snappi-based ECN Interference Tests

1. [1. Test Objective](#1-test-objective)
2. [2. Testbed Topology](#2-testbed-topology)
   1. [2.1. Test port configuration](#21-test-port-configuration)
   2. [2.2. Route announcement](#22-route-announcement)
3. [3. Common test parameters](#3-common-test-parameters)
4. [4. Test Cases](#4-test-cases)
   1. [4.1. Test setup](#41-test-setup)
      1. [4.1.1. Port allocation](#411-port-allocation)
      2. [4.1.2. QoS config discovery](#412-qos-config-discovery)
      3. [4.1.3. Traffic stream setup](#413-traffic-stream-setup)
   2. [4.2. Test case 1: Cross-queue interference test](#42-test-case-1-cross-queue-interference-test)
   3. [4.3. Test case 2: Mixed ECN codepoint test](#43-test-case-2-mixed-ecn-codepoint-test)

## 1. Test Objective

In production, traffic with different DSCP values and ECN codepoints flows through the switch at the same time, while the [Basic ECN marking tests](switch-ecn-marking-tests.md) only test one queue and one ECN codepoint at a time. This test aims to verify that the ECN marking is properly isolated when different kinds of traffic are mixed together:

- ECN marking on one queue must not affect the packet handling of other queues on the same port.
- Within the same queue, ECN marking on the ECN-capable (ECT) packets must not affect the handling of the Non-ECT and CE packets.

## 2. Testbed Topology

The test is designed to be topology-agnostic. It expects the testbed to be built following the [Multi-device multi-tier testbed HLD](../../testbed/README.testbed.NUT.md), which allows us to test the ECN marking behavior of either a single switch or a multi-tier network.

### 2.1. Test port configuration

The test port configuration is the same as the [Basic ECN marking tests](switch-ecn-marking-tests.md). Based on the test parameter `rx_port_count`, the available ports are split into TX ports and RX ports, where the number of TX ports is 2 times the number of RX ports. The TX ports are further split into 2 equal groups, where each group has the same number of ports as the RX ports. The traffic is configured as all-to-all from each TX port group to the RX ports, so a single group alone does not create congestion, while both groups together oversubscribe every RX port.

The test will read the port configuration from the testbed and device config and use it to configurate the traffic generator ports accordingly, such as speed, fec and so on.

### 2.2. Route announcement

During the pretest phase, the test will leverage the traffic generator or the device connected directly to the traffic generator to inject the routes into the testbed. This facilitates the traffic routing and allows us to inject the any number of routes into the testbed for testing purposes.

## 3. Common test parameters

The test needs to support the following parameters:

- `ip_version`: IPv4 or IPv6, which supports `ipv4` and `ipv6`.
- `rx_port_count`: The number of RX ports to use. The number of TX ports will be 2 times this value. The rest of the available ports will not be used.
- `frame_bytes`: The sizes of the packets to be sent in the traffic. This is a list parameter, which currently only needs 64 bytes.
- `test_duration`: The duration of each traffic run in seconds, which supports 60 seconds by default.
- `traffic_rate`: The rate of the traffic for each traffic stream, which is set to 70% of the line rate by default.

## 4. Test Cases

### 4.1. Test setup

#### 4.1.1. Port allocation

Same as the [Basic ECN marking tests](switch-ecn-marking-tests.md), the test splits all the available ports on the traffic generator as below:

- RX ports: The last `rx_port_count` ports.
- TX port group 1: The first `rx_port_count` ports.
- TX port group 2: The next `rx_port_count` ports.

If the testbed does not have at least `3 * rx_port_count` ports available, the test will be skipped.

#### 4.1.2. QoS config discovery

Same as the [Basic ECN marking tests](switch-ecn-marking-tests.md), the test walks through the QoS configuration on the SONiC switch (`DSCP_TO_TC_MAP`, `TC_TO_QUEUE_MAP`, `QUEUE` and `WRED_PROFILE` tables) to build a list of `(dscp, tc, queue, ecn_enabled)` tuples, and selects one representative DSCP value for each queue.

On top of this list, the test builds queue pairs for the cross-queue interference test: each pair consists of one ECN-enabled queue and one queue without ECN that land on the same egress ports. If the switch config does not have any queue without ECN, the cross-queue test case will be skipped.

#### 4.1.3. Traffic stream setup

Same as the [Basic ECN marking tests](switch-ecn-marking-tests.md), the test creates 2 all-to-all traffic streams, one from each TX port group to all RX ports, where a single stream does not create congestion and both streams together create congestion on all RX ports. Each stream runs at `traffic_rate` (70% of the line rate by default) with the frame size set to `frame_bytes`.

Different from the basic tests, the packets within each traffic stream are not uniform. The DSCP and ECN fields of the packets are set per test case as described below.

### 4.2. Test case 1: Cross-queue interference test

This test case verifies that ECN marking on one queue does not affect the packet handling of other queues. For each queue pair (queue A with ECN enabled, queue B without ECN) learned in the QoS config discovery step, the test runs the following steps:

1. Configure both traffic streams to send a 50/50 mix of 2 kinds of packets: packets with the DSCP value of queue A and packets with the DSCP value of queue B, both with the ECN field set to ECT(1).
2. Start traffic stream 1 only and run it for `test_duration` seconds. Assert that the ECN field of all received packets stays unchanged, since there is no congestion.
3. Start traffic stream 2, so both streams are running and congestion happens on both queues of every RX port, and run them for `test_duration` seconds.
4. Check the received packets on the RX ports:
   1. Assert that the packets of queue A are marked with CE.
   2. Assert that the packets of queue B are never marked with CE, even though queue A on the same port is actively marking. The packets of queue B should be handled by its own WRED config only, e.g. dropped or trimmed following its configured congestion action.
5. Stop all traffic streams, clear the counters on the traffic generator and the switch, then move on to the next queue pair.

### 4.3. Test case 2: Mixed ECN codepoint test

This test case verifies that within the same queue, the ECN marking on the ECT packets does not affect the handling of the packets with other ECN codepoints. For each ECN-enabled queue learned in the QoS config discovery step, the test runs the following steps:

1. Configure both traffic streams to send an even mix (25% each) of packets with all 4 ECN codepoints: Non-ECT (00), ECT(0) (10), ECT(1) (01) and CE (11), all with the DSCP value of the queue under test.
2. Start traffic stream 1 only and run it for `test_duration` seconds. Assert that the ECN field of all received packets stays unchanged, since there is no congestion.
3. Start traffic stream 2, so both streams are running and congestion happens on every RX port, and run them for `test_duration` seconds.
4. Check the received packets on the RX ports:
   1. Assert that the ECT(0) and ECT(1) packets are marked with CE.
   2. Assert that the CE packets pass through with the CE codepoint unchanged.
   3. Assert that the Non-ECT packets are never marked with CE. They should keep the codepoint 00 and be handled by the congestion action in the WRED config only (dropped or trimmed), not affected by the ECN marking happening on the ECT packets in the same queue.
5. Stop all traffic streams, clear the counters on the traffic generator and the switch, then move on to the next queue.

> NOTE: Since the RX ports are oversubscribed when both traffic streams are running, packet loss is expected, no matter how the WRED profile is configured. Hence, the test does not check the TX frame count against the RX frame count. It only checks the ECN field of the received packets and whether it follows the WRED profile config on the switch.

This test is a functional test with clear pass/fail criteria, so it does not collect or report any metrics. If any assertion above fails, the test fails for that queue or queue pair.
