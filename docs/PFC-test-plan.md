# RDMA PFC test plan

- [RDMA PFC test plan](#rdma-pfc-test-plan)
  - [Overview](#overview)
    - [Scope](#scope)
    - [Testbed](#testbed)
  - [Setup configuration](#setup-configuration)
    - [DUT configuration](#dut-configuration)
    - [Keysight configuration](#keysight-configuration)
  - [Test cases](#test-cases)
    - [Test Case #1 - PFC PAUSE with single lossless priority](#test-case-1---pfc-pause-with-single-lossless-priority)
      - [Test Objective](#test-objective)
      - [Test Configuration](#test-configuration)
      - [Test Steps](#test-steps)
    - [Test Case #2 - PFC PAUSE with multiple lossless priorities](#test-case-2---pfc-pause-with-multiple-lossless-priorities)
      - [Test Objective](#test-objective-1)
      - [Test Configuration](#test-configuration-1)
      - [Test Steps](#test-steps-1)
    - [Test Case #3 - PFC PAUSE with lossy priorities](#test-case-3---pfc-pause-with-lossy-priorities)
      - [Test Objective](#test-objective-2)
      - [Test Configuration](#test-configuration-2)
      - [Test Steps](#test-steps-2)

## Overview

Traditional IEEE 802.3 Ethernet defines an unreliable communication
medium. In a network path that normally consists of multiple hops
between a source and destination, lack of feedback between transmitters
and receivers at each hop is one of the main reasons that causes network
unreliability. Transmitters can send packets faster than receivers can
accept packets. As a result the receivers\' buffer keeps growing and
beyond a threshold it starts silently dropping incoming packets. Flow
control functions at Layer 2 offers a solution to this problem. Flow
control enables feedback from a receiver to its sender to communicate
buffer availability. IEEE 802.3x PAUSE control frames are introduced to
achieve Layer 2 flow control. A receiver can send a PAUSE request to a
sender when it senses potential buffer overflow. Upon receiving it, the
sender stops transmission of any new packets on the wire until the
receiver is ready to accept them again.

IEEE 802.3x PAUSE works as designed but imposes certain limitations.
Once a link is paused, the sender cannot send any traffic on that. As a
result, an Ethernet Segment that carries multiple application flows with
different QoS requirement, gets entirely blocked irrespective of their
QoS. Thus enabling PAUSE for one application can affect the performance
of the other network applications sharing the same Ethernet segment.
IEEE 802.1Qbb PFC (Priority Flow Control) extends the basic PAUSE
mechanism for multiple CoS, thus enabling coexistence of flows which
needs flow control with other flows which performs better without it.
Upto 8 CoSs can be used. PFC uses the same 64Byte MAC Control frame
format that PAUSE frames do. It has a two byte Class-Enable vector to
mention the CoS value for which the PAUSE should apply. As PFC acts
independently on eight different CoSs, the frame describes the PAUSE
duration for each CoS. The pause duration for each priority is a 2-byte
value that expresses time as a number of quanta, where each quanta
represents the time needed to transmit 512 bits at the current network
speed. For user data traffic, the CoS maps to either CoS values defined
in 802.1Q VLAN tag or the IP DSCP values.

The purpose of this test plan is to test the PFC PAUSE processing
behavior of a SONiC DUT. The test assumes all necessary configuration is
already pre-configured on the SONIC DUT before test runs.

SONiC has two lossless priorities: 3 and 4, by default. It is to be
noted that only the lossless priorities can react to or generate PFC
frames. In other words, PFC frames should not have any impact on traffic
on lossy priorities. Packets with Differentiated Services Code Point
(DSCP) 3 and 4 are mapped to priority 3 and 4, respectively.

### Scope

The test is targeting a running SONIC system with fully functioning
configuration. The purpose of the test is not to test specific API, but
functional testing of SONiC DUT on receiving a PFC pause frame, making
sure that traffic are getting paused or unpaused on correct priorities.

### Testbed

```
+-------------+      +--------------+      +-------------+
| Keysight TX |------|   SONiC DUT  |------| Keysight RX |
+-------------+      +--------------+      +-------------+

Keysight ports are connected via SONiC switch as shown in the illustration above.

The test will run on the following testbed: T0-64
```

## Setup configuration

### DUT configuration

- PFC watch dog is disabled

### Keysight configuration

- All Keysight ports should have the same bandwidth capacity.

## Test cases

### Test Case #1 - PFC PAUSE with single lossless priority

#### Test Objective

Verify DUT processes the PFC PAUSE frame with single lossless CoS
properly.

#### Test Configuration

- On SONiC DUT configure a single lossless CoS value Pi. (0 \<= i \<= 7).
- Configure following traffic items on the Keysight device:
  1. Test data traffic: A traffic item from the Keysight Tx port to
        the Keysight Rx port with lossless priority (DSCP value == Pi).
        Traffic should be configured with 50% of line rate.
  2. Background data traffic: A traffic item from the Keysight Tx
        port to the Keysight Rx port with lossy priorities (DSCP value
        != Pi). Traffic should be configured with 50% of line rate.
  3. PFC PAUSE storm: Persistent PFC pause frames from the Keysight
        Rx port to the Keysight Tx port. The priorities of PFC pause
        frames should be same as that of 'Test data traffic'. And the
        inter-frame transmission interval should be smaller than
        per-frame pause duration.

#### Test Steps

1. Start PFC PAUSE storm to fully block the lossless priority at the
    DUT.
2. After a fixed duration (eg. 1 sec), start the Test data traffic and
    Background data traffic simultaneously.
3. Keep the Test and Background traffic running for a fixed duration
    and then stop both the traffic items.
4. Verify the following:
   * Keysight Rx port should receive all the Background data traffic with DSCP != Pi.
   * Keysight Rx port should not receive any Test data traffic with DSCP == Pi, as these frames should not be transmitted by the DUT due to the PFC PAUSE storm received from Keysight Rx port.
5. Stop the PFC PAUSE storm.
6. Now start the Test data traffic again for a fixed duration.
7. Verify as there is no PFC PAUSE received by DUT, the Keysight Rx port should receive all the Test data packets.
8. Repeat the test with a different Lossless priority (!=Pi).

### Test Case #2 - PFC PAUSE with multiple lossless priorities

#### Test Objective

Verify DUT processes the PFC PAUSE frame for multiple lossless CoSs
properly.

#### Test Configuration

- On SONiC DUT configure two lossless CoS values Pi and Pm. (0 \<= i,m
    \<= 7).
- Configure following traffic items on the Keysight device:
    1. Test data traffic: A traffic item from the Keysight Tx port to
        the Keysight Rx port with two lossless priorities (DSCP value ==
        Pi, Pm). Traffic should be configured with 50% line rate.
    2. Background data traffic: A traffic item from the Keysight Tx
        port to the Keysight Rx port with lossy priorities (DSCP value
        != Pi, Pm). Traffic should be configured with 50% line rate.
    3. PFC PAUSE storm: Persistent PFC pause frames from the Keysight
        Rx port to the Keysight Tx port. The priorities of PFC pause
        frames should be same as that of 'Test data traffic'. And the
        inter-frame transmission interval should be smaller than
        per-frame pause duration.

#### Test Steps

1. Start PFC PAUSE storm to fully block the lossless priorities at the DUT.
2. After a fixed duration (eg. 1 sec), start the Test data traffic and Background data traffic simultaneously.
3. Keep the Test and Background traffic running for a fixed duration and then stop both the traffic items.
4. Verify the following:
   * Keysight Rx port should receive all the Background data traffic
        with DSCP != Pi, Pm.
   * Keysight Rx port should not receive any Test data traffic with
        DSCP == Pi, Pm as these frames should not be transmitted by the
        DUT due to the PFC PAUSE storm received from Keysight Rx port.
5. Stop the PFC PAUSE storm.
6. Now start the Test data traffic again for a fixed duration.
7. Verify as there is no PFC PAUSE received by DUT, the Keysight Rx port should receive all the Test data packets.

### Test Case #3 - PFC PAUSE with lossy priorities

#### Test Objective

Verify DUT processes the PFC PAUSE frame with lossy CoSs properly.

#### Test Configuration

- On SONiC DUT configure a single lossless CoS value Pi (0 \<= i \<=
    7).
- Configure following traffic items on the Keysight device:
  1. Test data traffic: A traffic item from the Keysight Tx port to
        the Keysight Rx port with the lossy priorities (DSCP value !=
        Pi). Traffic should be configured with 50% line rate.
  2. Background data traffic: A traffic item from the Keysight Tx
        port to the Keysight Rx port with the lossless priority (DSCP
        value == Pi). Traffic should be configured with 50% line rate.
  3. PFC PAUSE storm: Persistent PFC pause frames from the Keysight
        Rx port to the Keysight Tx port. The priorities of PFC pause
        frames should be same as that of 'Test data traffic'. And the
        inter-frame transmission interval should be smaller than
        per-frame pause duration.

#### Test Steps

1. Start PFC PAUSE storm.
2. After a fixed duration (eg. 1 sec), start the Test data traffic and Background data traffic simultaneously.
3. Keep the Test and Background traffic running for a fixed duration and then stop both the traffic items.
4. Verify the following:
   * Keysight Rx port should receive all the 'Background data traffic' as well as 'Test data traffic'. There should not be any loss observed.
5. Stop the PFC PAUSE storm.
6. Repeat the test with a different lossless priority value (!=Pi).
