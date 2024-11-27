# Overview

This document captures the test plan for QoS for the CPU Punt path.

Below is list of QoS functionalities that will be covered:

-   No punt flows to the CPU when the switch is not configured.
-   Queue assignment using DSCP for traffic to Loopback IP
-   Scheduler Rate limit per CPU queue
-   Queue assignment by punt flows
-   Policer rate limits per punt flow

# Strategy

-   blackbox / focus on observable behaviors / minimize trust
-   property-based

# Testbed

Our testbed consists of a single switch under test (SUT), as well as an IXIA connected to the SUT on multiple ports for injecting packets. To make things portable and blackbox.For some tests, the IXIA can be replaced by a control switch.

# Openconfig paths covered

#### OpenConfig Config Paths

<table>
  <thead>
    <tr>
      <th><strong>config PATHs</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>/qos/forwarding-groups/</td>
    </tr>
    <tr>
      <td>/qos/classifiers/</td>
    </tr>
    <tr>
      <td>/qos/interfaces/interface[interface-id=CPU]/input/classifiers</td>
    </tr>
    <tr>
      <td>/qos/interfaces/interface[interface-id=CPU]/output/queues/</td>
    </tr>
    <tr>
      <td>/qos/queues/</td>
    </tr>
    <tr>
      <td>/qos/scheduler-policies/scheduler-policy</td>
    </tr>
  </tbody>
</table>

#### OpenConfig Telemetry Paths

<table>
  <thead>
    <tr>
      <th><strong>state PATHs</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>/qos/interfaces/interface[interface-id=CPU]/output/queues/queue[name=AF1]/state/transmit-pkts</td>
    </tr>
    <tr>
      <td>/qos/interfaces/interface[interface-id=CPU]/output/queues/queue[name=AF1]/state/dropped-pkts</td>
    </tr>
  </tbody>
</table>

# Test Cases

## Test Case 1: No packets reach CPU in pristine state

**Purpose**: Verify that no packets reach the CPU unless the switch has explicitly been configured otherwise, either by configuring punt flows (via P4RT) or a loopback IP (via gNMI).

We send various test packets to a SUT in pristine state, and verify that the packets don't make it to the CPU.

### Test Details

Step 1: Bring up SUT with bootstrap config.\
Step 2: GNMI-get on CPU queues to verify CPU queue stats are at 0.\
Step 2: Send unicast (ICMP, SSH) packets (TTL=0, 1, 2, 3).\
Step 3: Send Broadcast (DMAC: ff:ff:ff:ff:ff:ff).\
Step 4: Send a Multicast protocol packet (e.g., LLDP packet).\
Step 5: GNMI-get on CPU queues to verify CPU queue stats are at 0.\
Step 6: Verify no packets were punted to the controller (via P4Runtime PacketIO)

## Test Case 2: Per-entry ACL counters increment

**Purpose**: Verify that per-entry counters read via P4Runtime increment when entries get hit by packets.

We install an ACL entry, inject a packet that hits the entry, read back the entry and its counters via P4Runtime, and verify that the counters have incremented.

### Test Details

-   Start from a clean switch state by pushing gNMI config and P4Info and clearing all tables.
-   Install an ACL table entry.
-   Read back the entry and confirm that the counters are initially zero.
-   Inject a test packet tailored to hit the ACL entry.
-   Verify that the counters (`byte_count` and `packet_count`) increment as expected within 15 seconds.

## Test Case 3: Traffic to Loopback IP

**Purpose**: Verify protocol-to-queue mapping for traffic to switch loopback IP.

We send test packets with various DSCP values whose destination IP is the loopback IP of the switch. We use gNMI queue stats to validate that the packets are put into the correct queue, based on their DSCP value.

Note: Test for validity/integrity of gNMI is verified in subsequent Test cases 3 and 4.

### Test Details

Step 1: Push QoS config via gNMI with DSCP-to-queue mappings and scheduler config.\
Step 2: Get CPU queue stats for baseline.\
Step 3: Send IP packets to the SUT's loopback IP, with DSCP value set to one of the DSCP values from a set of DSCP values determined from pushed config, such that we test classification to each of the queues. Also pick an unconfigured DSCP value if available and verify this traffic default priority (TC=0) queue.\
Step 4: Get CPU queue stats (tx and drop) and confirm we see increment against expected queue\
Step 5: Repeat 2 - 4 for different DSCP values.

##

## Test Case 4 : Punt flow to Controller with flow-specific rate limit

**Purpose**: Verify CPU queue classification and rate limits for punt flows to controller

### Test Details

Step 1: Push QoS config with scheduler config via gNMI.\
Step 2: Push punt flow table entry with rate limit via P4RT.\
Step 3: Get CPU queue stats for baseline.\
Step 4: Send traffic from Ixia to hit a punt flow at line rate for 10 seconds\
Step 5: Verify flow counters (Packets and bytes) match the number of packets and bytes sent by Ixia flow.\
Step 6: Verify rate received at tester complies with rate configured for the flow or queue whichever is lower.\
Step 7: Get CPU queue stats (tx and drop) and confirm we see correct increments \
ASSERT (Tx packets in gNMI stats == packets received at Tester)\
ASSERT (Tx packets + Drop Packets  in gNMI stats == Total packets sent by Ixia)

## Test Case 5 : Punt flow to Controller with queue-specific rate limit

**Purpose**: Verify CPU queue rate limits the punt flow to controller

### Test Details

Step 1: Push QoS config with scheduler config via gNMI.\
Step 2: Push 2 punt flows with action trap and ***no*** rate limit via P4RT.\
Step 3: Get CPU queue stats for baseline.\
Step 4: Send traffic from Ixia to hit the punt flows at line rate for 10 seconds\
Step 5: Verify rate received at tester complies with rate configured for the queue.\
Step 6: Get CPU queue stats (tx and drop) and confirm we see correct increments:\
ASSERT (Tx packets in gNMI stats == packets received at Tester)\
ASSERT (Tx packets + Drop Packets  in gNMI stats == Total packets sent by Ixia)

# Library requirements

-   Traffic generator (for sending traffic and reading traffic stats)
-   gNMI library
