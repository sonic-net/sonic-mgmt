# ECN test plan

## Overview

Explicit Congestion Notification (ECN) allows end-to-end notification of network congestion without dropping packets. ECN is an optional feature that may be used between two ECN-enabled endpoints when the underlying network infrastructure also supports it.

Conventionally, TCP/IP networks signal congestion by dropping packets. When ECN is successfully negotiated, an ECN-aware router may set a mark in the IP header instead of dropping a packet, in order to signal impending congestion. The receiver of the packet echoes the congestion indication to the sender, which reduces its transmission rate as if it detected a dropped packet.

Commodity switches typically use Random Early Detection (RED) algorithm to perform ECN marking. RED algorithm has at least three parameters: the minimum threshold Kmin, the maximum threshold Kmax, and the maximum marking (or dropping) probability Pmax. When the instantaneous queue length is smaller than the minimum marking threshold, the marking probability is 0%. When the instantaneous queue length is larger than the maximum marking threshold, the marking probability is 100%. Otherwise, the marking probability varies as ((queue_length - Kmin) / (Kmax - Kmin)) * Pmax.

Commodity switches can run RED at ingress (enqueue packet to the switch buffer) or egress (dequeue packet from the switch buffer). Compared to ingress RED/ECN, egress RED/ECN can achieve lower feedback delay.

### Scope

The test cases depicted in this document aim to do functional testing of ECN behavior of SONiC DUT as per RED (Random Early Detection) algorithm.

### Testbed

```
+-------------+      +--------------+      +-------------+       
| Keysight TX |------|   SONiC DUT  |------| Keysight RX | 
+-------------+      +--------------+      +-------------+ 

Keysight ports are connected via SONiC switch as shown in the illustration above.
```
## Setup configuration

### DUT Configuration
•	PFC watch dog is disabled

•	Enable ECN at queue 3:
```
        $ ecnconfig -q 3 on
```
•	Configure minimum threshold to Kmin (in bytes):
```
        $ ecnconfig -p [profile_name] -gmin [Kmin in byte]
```
•	Configure maximum threshold to Kmax (in bytes):
```
    $ ecnconfig -p [profile_name] -gmax [Kmax in byte]
```
•	Configure marking probability Pmax:
```
    $ ecnconfig -p [profile_name] -gdrop [Pmax in %]
```
•	To check current ECN configuration:
```
    $ ecnconfig -l 
```
•	To check if ECN is enabled at queue 3:
```
   $ ecnconfig -q 3
```
### Keysight configuration
•	All Keysight ports should have the same bandwidth capacity.

•	Test specific configurations are mentioned in respective test cases.

## Test Cases

### Test Case #1 - ECN marking at egress

#### Test Objective

This test aims to verify the DUT’s dequeue based ECN marking behavior (Egress marking) for data packets configured with lossless priority, when minimum and maximum threshold values are configured with equal value.

#### Test Configuration

- On SONiC DUT configure the following:
  1. A single lossless priority value Pi. (0 <= i <= 7).
  2. Configure minimum and maximum ECN marking threshold of the lossless priority Pi to N KB (eg. 100 KB).
  3. DUT should have enough buffer to hold 2N KB packets.

- Configure following traffic items on the Keysight device:
  1. Test data traffic: A traffic item from the Keysight Tx port to
        the Keysight Rx port with lossless priority (DSCP value == Pi).
        Number of packets should be fixed to 2N (200), size of each packet should be 1KB each.
  2. PFC PAUSE storm: Persistent PFC pause frames from the Keysight
        Rx port to the Keysight Tx port. The priorities of PFC pause
        frames should be same as that of 'Test data traffic'. And the
        inter-frame transmission interval should be lesser than
        per-frame pause duration.

#### Test Steps

1. Start PFC PAUSE storm to fully block the lossless priority at the
    DUT.
2. From the Keysight Tx port, send 2N data packets to the receiver. The packets should be mapped to priority Pi on the DUT.
3. After all the test data packets are sent, start data capture on the Keysight Rx port. Then, stop PFC PAUSE.
4. Stop capture after all packets are received.
5. Verify the following:
   * Keysight Rx port must receive 2N test data packets.
   * The first test data packet received by Keysight Rx port should be ECN marked.
   * The last test data packet received by Keysight Rx port should not be ECN marked.
5. Repeat the test with a different lossless priority (!=Pi).


### Test Case #2 - ECN marking accuracy

#### Test Objective

This test aims to verify the DUT’s dequeue based ECN marking behavior (Egress marking) for data packets configured with lossless priority, when minimum threshold < maximum threshold.

#### Test Configuration

- On SONiC DUT configure the following:
  1. A single lossless priority value Pi. (0 <= i <= 7).
  2. Configure the minimum ECN marking threshold, the maximum ECN marking threshold, and the maximum marking probability of the Priority Pi to Kmin KB, Kmax KB, and Pmax % respectively. Let the Kmin, Kmax, and Pmax be 500 KB, 2000 KB, and 5% for first iteration.
  3. DUT should have enough buffer to hold (Kmax+10) packets each of 1KB size.

- Configure following traffic items on the Keysight device:
  1. Test data traffic: A traffic item from the Keysight Tx port to
        the Keysight Rx port with the lossless priority (DSCP value == Pi).
        Should have fixed number of packets, Kmax+10 (2010), each having 1KB frame size.
  2. PFC PAUSE storm: Persistent PFC pause frames from the Keysight
        Rx port to the Keysight Tx port. The priorities of PFC pause
        frames should be the same as that of 'Test data traffic'. And the
        inter-frame transmission interval should be lesser than the 
        per-frame pause duration.

#### Test Steps

1. Start PFC PAUSE storm to fully block the lossless priority at the
    DUT.
2. Start the Test data traffic, it will send total 2010 packets as per the configuration.
3. After all the test data packets are sent, start data capture on the Keysight Rx port. Then, stop PFC PAUSE storm from Keysight Rx port.
4. Stop capture after all packets are received.
5. Verify the following:
   * All 2010 packets must be received at the Rx port.
   * As per RED ECN egress marking algorithm, the queue length associated with the data packet i (i = 1, 2, … Kmax + 10) is (Kmax + 10 – i) KB.
   * If instantaneous queue length is q, then, for the first 10 packets, q >= 2000. Hence, all the first 10 packets should be ECN marked.
   * For the next 1500 packets, 500 <= q < 2000, so, 5% of these packets should be ECN marked.
   * For the last 500 packets, q<500, so, none of them should be ECN marked.
6. Repeat steps 1 to 4 at least 200 times.
7. After 200 iterations, compare between theoretical probability of ECN marking with the actual ECN marking yielded as test results against queue length.