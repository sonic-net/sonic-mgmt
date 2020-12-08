# PFC test plan

- [PFC test plan](#pfc-test-plan)
  - [Overview](#overview)
    - [Scope](#scope)
    - [Testbed](#testbed)
  - [Setup configuration](#setup-configuration)
    - [Device Under Test (DUT) configuration](#device-under-test-dut-configuration)
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
    - [Test Case #4 - GLOBAL PAUSE (IEEE 802.3x link level Flow Control)](#test-case-4---global-pause-ieee-8023x-link-level-flow-control)
      - [Test Objective](#test-objective-3)
      - [Test Configuration](#test-configuration-3)
      - [Test Steps](#test-steps-3)
  
 Revision of the Document

| Rev |     Date       |       Author         | Change Description               |
|:---:|:---------------|:---------------------|:-----------------------------------|
| 0.1 |        Aug-28-2020     | Wei Bai, Microsoft<br>                Suvendu Mozumdar, Keysight     | Initial version of test plan <br> More test in subsequent version |
| 0.2 |        Sep-10-2020     | Wei Bai, Microsoft<br>               Suvendu Mozumdar, Keysight     | Inclusion of test case - 802.3x GLOBAL PAUSE |

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
mechanism for multiple priorities, thus enabling coexistence of flows which
needs flow control with other flows which performs better without it.
Upto 8 priorities can be used. PFC uses the same 64Byte MAC Control frame
format that PAUSE frames do. It has a two byte Class-Enable vector to
mention the priority value for which the PAUSE should apply. As PFC acts
independently on eight different priorities, the frame describes the PAUSE
duration for each priority. The pause duration for each priority is a 2-byte
value that expresses time as a number of quanta, where each quanta
represents the time needed to transmit 512 bits at the current network
speed. For user data traffic, the priority maps to either priority values defined
in 802.1Q VLAN tag or the IP DSCP values. PFC is widely used to enable RoCE deployments.

The PFC PAUSE frame :
```
+-------------------------+
| Destination Address     |    6 octets
+-------------------------+
+-------------------------+
| Source address          |    6 octets
+-------------------------+
+-------------------------+
| Ethertype               |    2 octets
+-------------------------+
+-------------------------+
| Control opcode = 01-01  |    2 octets
+-------------------------+                     ms octet          1st octet
+-------------------------+                  +-------------------------------------+
| Priority enable vector  |    2 octets ---> |    0       | e(7)... e(n)..e(0)     |
+-------------------------+                  +-------------------------------------+
+-------------------------+
| Time(0)                 |    2 octets
+-------------------------+     
            |              -----+
+-------------------------+     |
| Time(n)                 |     | 12 ( 6X2 ) octets
+-------------------------+     |
            |              -----+
+-------------------------+     
| Time(7)                 |    2 octets
+-------------------------+
+-------------------------+
|  Pad                    |    26 octets
+-------------------------+
+-------------------------+
|  CRC                    |    4 octets
+-------------------------+

Priority enable vector : e[n] = 1 => time (n) valid 
                         e[n] =0 => time (n)invalid

Time (n) is defined as the pause timer for priority n.

```


SONiC has two lossless priorities: 3 and 4, by default. It is to be
noted that only the lossless priorities can react to or generate PFC
frames. In other words, PFC frames should not have any impact on traffic
on lossy priorities. Packets with Differentiated Services Code Point
(DSCP) 3 and 4 are mapped to priority 3 and 4, respectively. SONiC does not react to IEEE 802.3x PAUSE.



### Scope

The purpose of this test plan is to test the PFC PAUSE processing behavior of a SONiC Device Under Test ( DUT) and its capability to pause or un-pause traffic with right priorities. The test assumes all necessary configuration is already pre-configured on the SONIC Device Under Test (DUT) before test runs.

### Testbed

```
+-------------+      +------------------------------------+      +-------------+
| Keysight TX |------|   SONiC Device Under Test (DUT)    |------| Keysight RX |
+-------------+      +------------------------------------+      +-------------+

Keysight ports are connected with SONiC switch as shown in the illustration above.
```
## Setup configuration

### Device Under Test (DUT) configuration

- [PFC watchdog](https://github.com/Azure/SONiC/wiki/PFC-Watchdog-Design) is disabled. We need to disable PFC watchdog as if a queue has been paused for long time (e.g., several hundreds of milliseconds), PFC watchdog will be triggered to disable PFC and drop packets. Since we will generate continuous PFC pause frames (which is unlikely to happen in production) to test PFC functionality, we decide to disable PFC watchdog.
   

### Keysight configuration

- All Keysight ports should have the same bandwidth capacity.

## Test cases

### Test Case #1 - PFC PAUSE with single lossless priority

#### Test Objective

Verify Device Under Test (DUT) processes the PFC PAUSE frame with single lossless priority
properly.

#### Test Configuration

- On SONiC Device Under Test (DUT) configure a single lossless priority value Pi. (0 \<= i \<= 7).
- Configure following traffic items on the Keysight device:
  1. Test data traffic: A traffic item from the Keysight Tx port to
        the Keysight Rx port with lossless priority (DSCP value == Pi).
        Traffic should be configured with 50% of line rate.
  2. Background data traffic: A traffic item from the Keysight Tx
        port to the Keysight Rx port with lossy priorities (DSCP value
        != Pi). Traffic should be configured with 50% of line rate.
  3. PFC PAUSE storm: Persistent PFC pause frames from the Keysight
        Rx port to the connected DUT port. The priorities of PFC pause
        frames should be same as that of 'Test data traffic'. And the
        inter-frame transmission interval should be smaller than
        per-frame pause duration.

#### Test Steps

1. Start PFC PAUSE storm to fully block the lossless priority at the
    Device Under Test (DUT).
2. After a fixed duration (eg. 1 sec), start the Test data traffic and
    Background data traffic simultaneously.
3. Keep the Test and Background traffic running for a fixed duration
    and then stop both the traffic items.
4. Verify the following:
   * Keysight Rx port should receive all the Background data traffic with DSCP != Pi.
   * Keysight Rx port should not receive any Test data traffic with DSCP == Pi, as these frames should not be transmitted by the Device Under Test (DUT) due to the PFC PAUSE storm received from Keysight Rx port.
5. Stop the PFC PAUSE storm.
6. Now start the Test data traffic again for a fixed duration.
7. Verify as there is no PFC PAUSE received by Device Under Test (DUT), the Keysight Rx port should receive all the Test data packets.
8. Repeat the test with a different Lossless priority (!=Pi).

### Test Case #2 - PFC PAUSE with multiple lossless priorities

#### Test Objective

Verify Device Under Test (DUT) processes the PFC PAUSE frame for multiple lossless priorities
properly.

#### Test Configuration

- On SONiC Device Under Test (DUT) configure multiple lossless priority values, eg. Pi, Pm (0 <= Pi, Pm, Pn <= 7). Maximum seven lossless priorities can be configured.
- Configure following traffic items on the Keysight device:
    1. Test data traffic: A traffic item from the Keysight Tx port to
        the Keysight Rx port with two lossless priorities (DSCP value ==
        Pi, Pm). Traffic should be configured with 50% line rate.
    2. Background data traffic: A traffic item from the Keysight Tx
        port to the Keysight Rx port with lossy priorities (DSCP value
        != Pi, Pm). Traffic should be configured with 50% line rate.
    3. PFC PAUSE storm: Persistent PFC pause frames from the Keysight
        Rx port to the connected DUT port. The priorities of PFC pause
        frames should be same as that of 'Test data traffic'. And the
        inter-frame transmission interval should be smaller than
        per-frame pause duration.

#### Test Steps

1. Start PFC PAUSE storm to fully block the lossless priorities at the Device Under Test (DUT).
2. After a fixed duration (eg. 1 sec), start the Test data traffic and Background data traffic simultaneously.
3. Keep the Test and Background traffic running for a fixed duration and then stop both the traffic items.
4. Verify the following:
   * Keysight Rx port should receive all the Background data traffic
        with DSCP != Pi, Pm.
   * Keysight Rx port should not receive any Test data traffic with
        DSCP == Pi, Pm as these frames should not be transmitted by the
        Device Under Test (DUT) due to the PFC PAUSE storm received from Keysight Rx port.
5. Stop the PFC PAUSE storm.
6. Now start the Test data traffic again for a fixed duration.
7. Verify as there is no PFC PAUSE received by Device Under Test (DUT), the Keysight Rx port should receive all the Test data packets.
8. Repeat the test with a different set of lossless priority values

### Test Case #3 - PFC PAUSE with lossy priorities

#### Test Objective

Verify Device Under Test (DUT) processes the PFC PAUSE frame with lossy priorities properly.

#### Test Configuration

- On SONiC Device Under Test (DUT) configure a single lossless priority value Pi (0 \<= i \<=
7).
- Configure following traffic items on the Keysight device:
  1. Test data traffic: A traffic item from the Keysight Tx port to
        the Keysight Rx port with the lossy priorities (DSCP value !=
        Pi). Traffic should be configured with 50% line rate.
  2. Background data traffic: A traffic item from the Keysight Tx
        port to the Keysight Rx port with the lossless priority (DSCP
        value == Pi). Traffic should be configured with 50% line rate.
  3. PFC PAUSE storm: Persistent PFC pause frames from the Keysight
        Rx port to the connected DUT port. The priorities of PFC pause
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
   
### Test Case #4 - GLOBAL PAUSE (IEEE 802.3x link level Flow Control)

<b>Note</b> : 802.3x link level Flow Control is different than IEEE 802.1Qbb PFC (Priority-based Flow Control)

#### Test Objective
Verify Device Under Test (DUT) processes the GLOBAL PAUSE frame.

#### Test Configuration
- On SONiC Device Under Test (DUT) configure lossless priority of required values Pi ( e.g., 3 and 4. )
- Configure following traffic items on the Keysight device:
  1. Test data traffic: A traffic item from the Keysight Tx port to Rx port. The traffic item uses all the 64 DSCP values (0-63). PFC is enabled at all the 8 priorities of Tx port. The traffic demand is 100% line rate.
  2. GLOBAL PAUSE storm: Persistent Global pause frames from the Keysight Rx port to the connected DUT port. And the inter-frame transmission interval should be smaller than per-frame pause duration.
   
#### Test Steps

1. Start GLOBAL PAUSE storm.
2. After a fixed duration (eg. 1 sec), start the Test data traffic.
3. Keep the Test data traffic running for a fixed duration (eg 5 sec) and then stop the traffic item.
4. Stop the GLOBAL PAUSE storm.
5. Verify the following:
   * Keysight Rx port should receive all the 'Test data traffic'. There should not be any loss observed. Throughput should be close to link capacity.
   